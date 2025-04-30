use std::collections::HashMap;
use std::rc::Rc;
use std::cell::RefCell;
use std::io::{stdout, Write}; // Use stdout for default output
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::error::Error as StdError; // Alias standard Error trait

// Import local modules
mod utils;
mod builtins;

use crate::utils::*; // Bring utils types/functions into scope
use crate::builtins::*; // Bring builtins types/functions into scope

// --- Query Definitions ---
// These functions now return Result<OpCreator, Error> or Result<DblOpCreator, Error>
// Or directly Result<Operator, Error> if they are the final step.
// They take the *next* operator factory as input.

// Helper to simplify chaining: applies creator B to the output of creator A
fn chain(
    creator_a: OpCreator,
    creator_b: OpCreator,
) -> Result<OpCreator, Error> {
    Ok(Box::new(move |final_op: Operator| -> Result<Operator, Error> {
        let op_b = creator_b(final_op)?;
        creator_a(op_b)
    }))
}

// Helper for chaining Double creators (like join output)
// Applies a function `f` to the output of the join before passing to next_op_creator
fn chain_dbl<F>(
    dbl_creator: DblOpCreator,
    f: F,
    next_op_creator: OpCreator,
) -> Result<(OpCreator, OpCreator), Error>
where
    F: Fn(Operator) -> Result<Operator, Error> + 'static, // Function applied after join
{
     // We need to create two OpCreators that, when called, will execute the full chain
    let dbl_creator_rc = Rc::new(dbl_creator);
    let f_rc = Rc::new(f);
    let next_op_creator_rc = Rc::new(next_op_creator);

    let create_left = Box::new(move |final_op: Operator| -> Result<Operator, Error> {
        let next_op_for_join = (f_rc)(final_op)?; // Apply intermediate op
        let next_op_for_final = (Rc::unwrap_or_clone(next_op_creator_rc.clone()))(next_op_for_join)?; // Apply final creator

        let (op1, _op2) = (Rc::unwrap_or_clone(dbl_creator_rc.clone()))(next_op_for_final)?; // Create join ops
        Ok(op1) // Return the left op from join
    });

     let create_right = Box::new(move |final_op: Operator| -> Result<Operator, Error> {
         let next_op_for_join = (f_rc)(final_op)?;
         let next_op_for_final = (Rc::unwrap_or_clone(next_op_creator_rc.clone()))(next_op_for_join)?;

         let (_op1, op2) = (Rc::unwrap_or_clone(dbl_creator_rc.clone()))(next_op_for_final)?; // Create join ops
         Ok(op2) // Return the right op from join
     });

     Ok((create_left, create_right))


    // Simpler conceptual version (less efficient due to repeated calls):
    // Ok(Box::new(move |final_op: Operator| -> Result<(Operator, Operator), Error> {
    //     let intermediate_op = f(final_op)?;
    //     let next_op_for_join = next_op_creator(intermediate_op)?;
    //     dbl_creator(next_op_for_join)
    // }))

}


// Identity (removes eth fields)
fn ident() -> Result<OpCreator, Error> {
    Ok(Box::new(|next_op: Operator| -> Result<Operator, Error> {
        map(
            Box::new(|mut tup: Tuple| -> Result<Tuple, Error> {
                tup.remove("eth.src");
                tup.remove("eth.dst");
                Ok(tup)
            }),
            next_op,
        )
    }))
}

// Count packets per epoch
fn count_pkts() -> Result<OpCreator, Error> {
    let creator_epoch = Box::new(|next: Operator| epoch(1.0, "eid".to_string(), next));
    let creator_group = Box::new(|next: Operator| groupby(single_group(), counter(), "pkts".to_string(), next));
    chain(creator_epoch, creator_group)
}

// Packets per src/dst per epoch
fn pkts_per_src_dst() -> Result<OpCreator, Error> {
    let creator_epoch = Box::new(|next: Operator| epoch(1.0, "eid".to_string(), next));
    let creator_group = Box::new(|next: Operator| {
        groupby(
            filter_groups(vec!["ipv4.src".to_string(), "ipv4.dst".to_string()]),
            counter(),
            "pkts".to_string(),
            next,
        )
    });
    chain(creator_epoch, creator_group)
}

// Count distinct source IPs per epoch
fn distinct_srcs() -> Result<OpCreator, Error> {
     let creator_epoch = Box::new(|next: Operator| epoch(1.0, "eid".to_string(), next));
     let creator_distinct = Box::new(|next: Operator| {
         distinct(
             filter_groups(vec!["ipv4.src".to_string()]),
             next,
         )
     });
     let creator_group = Box::new(|next: Operator| {
         groupby(single_group(), counter(), "srcs".to_string(), next)
     });

     let chain1 = chain(creator_epoch, creator_distinct)?;
     chain(chain1, creator_group)
}


// Sonata 1: TCP New Connections
fn tcp_new_cons() -> Result<OpCreator, Error> {
    let threshold = 40;
    let creator_epoch = Box::new(|next: Operator| epoch(1.0, "eid".to_string(), next));
    let creator_filter_syn = Box::new(|next: Operator| {
        filter(
            Box::new(|tup: &Tuple| -> bool {
                get_mapped_int("ipv4.proto", tup).map_or(false, |p| p == 6) &&
                get_mapped_int("l4.flags", tup).map_or(false, |f| f == 2) // SYN flag = 2
            }),
            next,
        )
    });
     let creator_group = Box::new(|next: Operator| {
         groupby(
             filter_groups(vec!["ipv4.dst".to_string()]),
             counter(),
             "cons".to_string(),
             next,
         )
     });
     let creator_filter_thresh = Box::new(|next: Operator| {
        filter(key_geq_int("cons".to_string(), threshold), next)
     });

     let chain1 = chain(creator_epoch, creator_filter_syn)?;
     let chain2 = chain(chain1, creator_group)?;
     chain(chain2, creator_filter_thresh)
}


// Sonata 2: SSH Brute Force
fn ssh_brute_force() -> Result<OpCreator, Error> {
     let threshold = 40;
     let creator_epoch = Box::new(|next: Operator| epoch(1.0, "eid".to_string(), next));
     let creator_filter_ssh = Box::new(|next: Operator| {
         filter(
             Box::new(|tup: &Tuple| -> bool {
                 get_mapped_int("ipv4.proto", tup).map_or(false, |p| p == 6) &&
                 get_mapped_int("l4.dport", tup).map_or(false, |p| p == 22)
             }),
             next,
         )
     });
     let creator_distinct = Box::new(|next: Operator| {
         distinct(
             filter_groups(vec![
                 "ipv4.src".to_string(),
                 "ipv4.dst".to_string(),
                 "ipv4.len".to_string(), // Distinct includes packet length
             ]),
             next,
         )
     });
      let creator_group = Box::new(|next: Operator| {
          groupby(
              filter_groups(vec![
                  "ipv4.dst".to_string(),
                  "ipv4.len".to_string(), // Group by destination and length
              ]),
              counter(), // Count distinct sources for each dst/len pair
              "srcs".to_string(),
              next,
          )
      });
      let creator_filter_thresh = Box::new(|next: Operator| {
         filter(key_geq_int("srcs".to_string(), threshold), next)
      });

     let chain1 = chain(creator_epoch, creator_filter_ssh)?;
     let chain2 = chain(chain1, creator_distinct)?;
     let chain3 = chain(chain2, creator_group)?;
     chain(chain3, creator_filter_thresh)
}

// Sonata 3: Super Spreader
fn super_spreader() -> Result<OpCreator, Error> {
     let threshold = 40;
     let creator_epoch = Box::new(|next: Operator| epoch(1.0, "eid".to_string(), next));
     let creator_distinct = Box::new(|next: Operator| {
         distinct(
             filter_groups(vec!["ipv4.src".to_string(), "ipv4.dst".to_string()]),
             next,
         )
     });
      let creator_group = Box::new(|next: Operator| {
          groupby(
              filter_groups(vec!["ipv4.src".to_string()]), // Group by source
              counter(), // Count distinct destinations
              "dsts".to_string(),
              next,
          )
      });
       let creator_filter_thresh = Box::new(|next: Operator| {
          filter(key_geq_int("dsts".to_string(), threshold), next)
       });

     let chain1 = chain(creator_epoch, creator_distinct)?;
     let chain2 = chain(chain1, creator_group)?;
     chain(chain2, creator_filter_thresh)
}

// Sonata 4: Port Scan
fn port_scan() -> Result<OpCreator, Error> {
     let threshold = 40;
     let creator_epoch = Box::new(|next: Operator| epoch(1.0, "eid".to_string(), next));
     let creator_distinct = Box::new(|next: Operator| {
         distinct(
             filter_groups(vec!["ipv4.src".to_string(), "l4.dport".to_string()]),
             next,
         )
     });
      let creator_group = Box::new(|next: Operator| {
          groupby(
              filter_groups(vec!["ipv4.src".to_string()]), // Group by source
              counter(), // Count distinct ports
              "ports".to_string(),
              next,
          )
      });
       let creator_filter_thresh = Box::new(|next: Operator| {
          filter(key_geq_int("ports".to_string(), threshold), next)
       });

     let chain1 = chain(creator_epoch, creator_distinct)?;
     let chain2 = chain(chain1, creator_group)?;
     chain(chain2, creator_filter_thresh)
}

// Sonata 5: DDoS
fn ddos() -> Result<OpCreator, Error> {
     let threshold = 45;
     let creator_epoch = Box::new(|next: Operator| epoch(1.0, "eid".to_string(), next));
     let creator_distinct = Box::new(|next: Operator| {
         distinct(
             filter_groups(vec!["ipv4.src".to_string(), "ipv4.dst".to_string()]),
             next,
         )
     });
      let creator_group = Box::new(|next: Operator| {
          groupby(
              filter_groups(vec!["ipv4.dst".to_string()]), // Group by destination
              counter(), // Count distinct sources
              "srcs".to_string(),
              next,
          )
      });
       let creator_filter_thresh = Box::new(|next: Operator| {
          filter(key_geq_int("srcs".to_string(), threshold), next)
       });

     let chain1 = chain(creator_epoch, creator_distinct)?;
     let chain2 = chain(chain1, creator_group)?;
     chain(chain2, creator_filter_thresh)
}


// Sonata 6: SYN Flood (Sonata version) - Complex Join
// Returns Vec<OpCreator> because join produces multiple inputs
fn syn_flood_sonata() -> Result<Vec<OpCreator>, Error> {
    let threshold: i64 = 3;
    let epoch_dur: f64 = 1.0;
    let eid_key = "eid".to_string();

    // --- Define the pipeline segments ---

    // SYN counter segment creator
    let syns_creator = |next_op: Operator| -> Result<Operator, Error> {
        let c1 = Box::new(|next| epoch(epoch_dur, eid_key.clone(), next));
        let c2 = Box::new(|next| filter(
            Box::new(|tup: &Tuple| -> bool {
                get_mapped_int("ipv4.proto", tup).map_or(false, |p| p == 6) &&
                get_mapped_int("l4.flags", tup).map_or(false, |f| f == 2) // SYN
            }),
            next,
        ));
        let c3 = Box::new(|next| groupby(
            filter_groups(vec!["ipv4.dst".to_string()]),
            counter(),
            "syns".to_string(),
            next,
        ));
        let chain_1 = chain(c1, c2)?;
        let chain_2 = chain(chain_1, c3)?;
        chain_2(next_op)
    };

    // SYN+ACK counter segment creator
    let synacks_creator = |next_op: Operator| -> Result<Operator, Error> {
        let c1 = Box::new(|next| epoch(epoch_dur, eid_key.clone(), next));
        let c2 = Box::new(|next| filter(
             Box::new(|tup: &Tuple| -> bool {
                 get_mapped_int("ipv4.proto", tup).map_or(false, |p| p == 6) &&
                 get_mapped_int("l4.flags", tup).map_or(false, |f| f == 18) // SYN+ACK = 16 + 2
             }),
             next,
         ));
        let c3 = Box::new(|next| groupby(
             filter_groups(vec!["ipv4.src".to_string()]), // Group by source (sender of SYN+ACK)
             counter(),
             "synacks".to_string(),
             next,
         ));
        let chain_1 = chain(c1, c2)?;
        let chain_2 = chain(chain_1, c3)?;
        chain_2(next_op)
    };

    // ACK counter segment creator
    let acks_creator = |next_op: Operator| -> Result<Operator, Error> {
        let c1 = Box::new(|next| epoch(epoch_dur, eid_key.clone(), next));
        let c2 = Box::new(|next| filter(
             Box::new(|tup: &Tuple| -> bool {
                 get_mapped_int("ipv4.proto", tup).map_or(false, |p| p == 6) &&
                 get_mapped_int("l4.flags", tup).map_or(false, |f| f == 16) // ACK
             }),
             next,
         ));
        let c3 = Box::new(|next| groupby(
             filter_groups(vec!["ipv4.dst".to_string()]), // Group by destination (receiver of ACK)
             counter(),
             "acks".to_string(),
             next,
         ));
        let chain_1 = chain(c1, c2)?;
        let chain_2 = chain(chain_1, c3)?;
        chain_2(next_op)
    };

    // --- Define the joins ---

    // Join 1: Join (SYN + SYNACK results) with ACK results
    // Key: host (ipv4.dst for SYNs/ACKs, ipv4.src for SYNACKs - requires renaming)
    // Value left: syns+synacks count
    // Value right: acks count
    let join1_creator = Box::new(|next_op: Operator| -> Result<(Operator, Operator), Error> {
        join(
            eid_key.clone(),
             // Left Input (from Join 2): expects key=("host"), value=("syns+synacks")
            make_key_extractor(eid_key.clone(), vec!["host".to_string()], vec!["syns+synacks".to_string()]),
             // Right Input (from ACK stream): key=rename("ipv4.dst"->"host"), value=("acks")
            make_renaming_key_extractor(eid_key.clone(), vec![("ipv4.dst".to_string(), "host".to_string())], vec!["acks".to_string()]),
            next_op,
        )
    });

    // Join 2: Join SYN results with SYNACK results
    // Key: host (requires renaming: ipv4.dst -> host for SYNs, ipv4.src -> host for SYNACKs)
    // Value left: syns count
    // Value right: synacks count
    let join2_creator = Box::new(|next_op: Operator| -> Result<(Operator, Operator), Error> {
        join(
            eid_key.clone(),
             // Left Input (from SYN stream): key=rename("ipv4.dst"->"host"), value=("syns")
            make_renaming_key_extractor(eid_key.clone(), vec![("ipv4.dst".to_string(), "host".to_string())], vec!["syns".to_string()]),
            // Right Input (from SYNACK stream): key=rename("ipv4.src"->"host"), value=("synacks")
            make_renaming_key_extractor(eid_key.clone(), vec![("ipv4.src".to_string(), "host".to_string())], vec!["synacks".to_string()]),
            next_op,
        )
    });

    // --- Define post-join processing ---

    // Map after Join 2: Calculate "syns+synacks"
    let map_join2 = |next_op: Operator| -> Result<Operator, Error> {
        map(
            Box::new(|mut tup: Tuple| -> Result<Tuple, Error> {
                let syns = get_mapped_int("syns", &tup)?;
                let synacks = get_mapped_int("synacks", &tup)?;
                tup.insert("syns+synacks".to_string(), OpResult::Int(syns + synacks));
                Ok(tup)
            }),
            next_op,
        )
    };

    // Map after Join 1: Calculate "syns+synacks-acks"
    let map_join1 = |next_op: Operator| -> Result<Operator, Error> {
         map(
             Box::new(|mut tup: Tuple| -> Result<Tuple, Error> {
                 let syns_synacks = get_mapped_int("syns+synacks", &tup)?;
                 let acks = get_mapped_int("acks", &tup)?;
                 tup.insert("syns+synacks-acks".to_string(), OpResult::Int(syns_synacks - acks));
                 Ok(tup)
             }),
             next_op,
         )
    };

    // Filter after Join 1: Check threshold
     let filter_final = |next_op: Operator| -> Result<Operator, Error> {
         filter(key_geq_int("syns+synacks-acks".to_string(), threshold), next_op)
     };


    // --- Connect the pipeline ---
    // Working backwards: final_filter takes the output of map_join1
    let final_processing_creator = Box::new(move |final_op: Operator| -> Result<Operator, Error> {
        let op1 = filter_final(final_op)?;
        map_join1(op1)
    });


    // Build the creators for the inputs to Join 1
    // Input 1 (Left): Comes from map_join2 applied to Join 2's output
    // Input 2 (Right): Comes from the acks_creator stream
    let (join1_input1_creator_factory, join1_input2_creator_factory) = chain_dbl(
         join1_creator, // The join we are providing inputs for
         map_join1, // Function applied AFTER join1
         final_processing_creator // Creator applied AFTER map_join1
    )?;


    // Build the creators for the inputs to Join 2
    // Input 1 (Left): Comes from syns_creator stream
    // Input 2 (Right): Comes from synacks_creator stream
    let (join2_input1_creator_factory, join2_input2_creator_factory) = chain_dbl(
         join2_creator, // The join we are providing inputs for
         map_join2, // Function applied AFTER join2
         join1_input1_creator_factory // The creator for join1's left input
    )?;


    // Now, create the final list of OpCreators that need direct input streams
    Ok(vec![
        Box::new(move |final_op: Operator| syns_creator(join2_input1_creator_factory(final_op)?)), // SYN stream -> Join2 Left Input
        Box::new(move |final_op: Operator| synacks_creator(join2_input2_creator_factory(final_op)?)),// SYNACK stream -> Join2 Right Input
        Box::new(move |final_op: Operator| acks_creator(join1_input2_creator_factory(final_op)?)), // ACK stream -> Join1 Right Input
    ])

}


// --- Main Execution Logic ---

// Generates sample data similar to the OCaml example
fn generate_sample_data(count: usize) -> Result<Vec<Tuple>, Error> {
    let mut data = Vec::with_capacity(count);
    let base_time = 0.0f64; // Example start time
    let mac1 = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    let mac2 = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
    let ip1 = Ipv4Addr::from_str("127.0.0.1")?;
    let ip2 = Ipv4Addr::from_str("192.168.1.100")?; // Different IP for variety

    for i in 0..count {
        let mut tup = HashMap::new();
        let time = base_time + (i as f64 * 0.1); // Increment time

        tup.insert("time".to_string(), OpResult::Float(time));

        tup.insert("eth.src".to_string(), OpResult::MAC(mac1));
        tup.insert("eth.dst".to_string(), OpResult::MAC(mac2));
        tup.insert("eth.ethertype".to_string(), OpResult::Int(0x0800)); // IPv4

        tup.insert("ipv4.hlen".to_string(), OpResult::Int(20));
        tup.insert("ipv4.proto".to_string(), OpResult::Int(6)); // TCP
        tup.insert("ipv4.len".to_string(), OpResult::Int(60 + (i as i64 % 10))); // Vary length slightly
        tup.insert("ipv4.src".to_string(), OpResult::IPv4(ip1));
        tup.insert("ipv4.dst".to_string(), OpResult::IPv4(ip2));

        tup.insert("l4.sport".to_string(), OpResult::Int(44000 + (i as i64 % 100))); // Vary source port
        tup.insert("l4.dport".to_string(), OpResult::Int(if i % 3 == 0 { 22 } else { 80 } )); // Alternate dest port (SSH/HTTP)
         // Vary flags: SYN, SYN+ACK, ACK, PSH+ACK
        let flags = match i % 4 {
            0 => 2, // SYN
            1 => 18,// SYN+ACK
            2 => 16,// ACK
            _ => 24,// PSH+ACK
        };
        tup.insert("l4.flags".to_string(), OpResult::Int(flags));

        data.push(tup);
    }
    Ok(data)
}


// Runs the defined queries on sample data
fn run_queries(queries: &mut Vec<Operator>, data: Vec<Tuple>) -> Result<(), Error> {
     if queries.is_empty() {
         println!("No queries to run.");
         return Ok(());
     }

     println!("Running {} queries on {} tuples...", queries.len(), data.len());

    for tup in data {
        for query_op in queries.iter_mut() {
             // Clone tuple if multiple queries might modify/consume it,
             // but here 'next' takes ownership conceptually. Let's clone.
            let tup_clone = tup.clone();
            (query_op.next)(tup_clone).map_err(|e| {
                 // Print error but continue processing other tuples/queries?
                 eprintln!("Error processing tuple in query: {}", e);
                 e // Propagate error to stop execution? Depends on desired behavior.
            })?;
        }
    }

     // After processing all data, send a final reset signal (e.g., with an empty tuple or specific EID)
     // This is crucial for stateful operators like groupby, distinct, epoch, join to flush their state.
     // We need a way to determine the final epoch ID or use a marker tuple.
     // Let's simulate a final reset with a dummy tuple indicating end-of-stream.
     println!("Sending final reset signal...");
     let mut final_reset_tup = HashMap::new();
     // Add a high epoch ID or a special marker if needed by operators like join/epoch
     final_reset_tup.insert("eid".to_string(), OpResult::Int(99999)); // Example final EID
     final_reset_tup.insert("_final_reset_".to_string(), OpResult::Empty);

     for query_op in queries.iter_mut() {
         (query_op.reset)(final_reset_tup.clone()).map_err(|e| {
              eprintln!("Error during final reset: {}", e);
              e
         })?;
     }

    Ok(())
}


// Main entry point
fn main() -> Result<(), Box<dyn StdError>> {
    println!("Starting Rust stream processor simulation...");

    // Get a handle to stdout, wrapped for sharing
    let stdout_handle = Rc::new(RefCell::new(stdout()));

    // --- Define the query pipeline(s) ---
    // Example: Simple count_pkts query dumping to stdout CSV
    let final_op_creator_csv = Box::new(|_: Operator| -> Result<Operator, Error> { // Final op doesn't take a 'next'
         dump_as_csv(stdout_handle.clone(), None, true)
    });

    let count_pkts_pipeline = count_pkts()?; // Get the OpCreator
    let mut pipeline1 = vec![count_pkts_pipeline(final_op_creator_csv(Operator{ next: Box::new(|_| Ok(())), reset: Box::new(|_| Ok(()))})?)?]; // Build the operator chain


    // Example: Sonata 3 (Super Spreader) dumping tuples
    let final_op_creator_dump = Box::new(|_: Operator| -> Result<Operator, Error> {
        dump_op(stdout_handle.clone(), true) // Show resets
    });
    let spreader_pipeline = super_spreader()?;
    let mut pipeline2 = vec![spreader_pipeline(final_op_creator_dump(Operator{ next: Box::new(|_| Ok(())), reset: Box::new(|_| Ok(()))})?)?];

    // --- Generate Data ---
    let sample_data = generate_sample_data(50)?; // Generate 50 sample tuples

    // --- Run Queries ---
    println!("\n--- Running Pipeline 1 (Count Pkts CSV) ---");
    run_queries(&mut pipeline1, sample_data.clone())?; // Pass mutable ref

    println!("\n--- Running Pipeline 2 (Super Spreader Dump) ---");
    run_queries(&mut pipeline2, sample_data)?; // Pass mutable ref


    // --- Example using read_walts_csv (requires CSV files) ---
    /*
    let csv_files = vec!["input1.csv".to_string(), "input2.csv".to_string()];
    // Create two identical pipelines dumping to different files for demonstration
    let final_op1 = dump_walts_csv("output1_rust.csv".to_string())?;
    let final_op2 = dump_walts_csv("output2_rust.csv".to_string())?;

    // Define the processing pipeline creator (e.g., pkts_per_src_dst)
    let pipeline_creator = pkts_per_src_dst()?;

    let op1 = pipeline_creator(final_op1)?;
    let op2 = pipeline_creator(final_op2)?; // Assuming pipeline_creator can be called multiple times

    println!("\n--- Reading Walt's CSV Files ---");
    match read_walts_csv(csv_files, vec![op1, op2], "epoch_id".to_string()) {
        Ok(_) => println!("Finished processing CSV files."),
        Err(e) => eprintln!("Error processing CSV files: {}", e),
    }
    */


    println!("\nRust simulation finished.");
    Ok(())
}