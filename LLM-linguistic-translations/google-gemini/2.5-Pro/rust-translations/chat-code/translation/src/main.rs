use std::{
    io::{stdout, Write},
    net::Ipv4Addr,
    str::FromStr,
    rc::Rc,
    cell::RefCell
};

// Modules defined in other files
mod utils;
mod builtins;

// Use items from modules
use utils::{
    OpResult, Tuple, Operator, chain, chain_dbl,
    single_group, counter, sum_ints, filter_groups,
    get_mapped_int, get_mapped_float, lookup_int, // Add lookup_* if needed directly
};
use builtins::{
    epoch, groupby, filter, map, distinct, split, join, dump_tuple, dump_as_csv,
    meta_meter, key_geq_int, rename_filtered_keys, dump_walts_csv, read_walts_csv, // Add read/write CSV if needed
};

// --- Query Definitions ---
// These functions construct operator pipelines.

// Identity (removes MAC addresses) -> Dump
fn ident(next_op: Box<dyn Operator>) -> Box<dyn Operator> {
     let map_fn = map(Box::new(|mut tup: Tuple| -> Tuple {
         tup.remove("eth.src");
         tup.remove("eth.dst");
         tup
     }), next_op);
     map_fn // Return the created map operator directly
}

// Count packets per epoch -> Next
fn count_pkts(next_op: Box<dyn Operator>) -> Box<dyn Operator> {
    let group_op = groupby(
        Box::new(single_group),
        Box::new(counter),
        "pkts".to_string(),
        next_op,
    );
    epoch(1.0, "eid".to_string(), group_op)
}

// Count packets per src/dst pair per epoch -> Next
fn pkts_per_src_dst(next_op: Box<dyn Operator>) -> Box<dyn Operator> {
     let group_op = groupby(
        Box::new(|tup| filter_groups(&["ipv4.src", "ipv4.dst"], tup)),
        Box::new(counter),
        "pkts".to_string(),
        next_op,
     );
     epoch(1.0, "eid".to_string(), group_op)
}

// Count distinct source IPs per epoch -> Next
fn distinct_srcs(next_op: Box<dyn Operator>) -> Box<dyn Operator> {
     let group_op = groupby(
        Box::new(single_group),
        Box::new(counter),
        "srcs".to_string(),
        next_op
     );
     let distinct_op = distinct(
        Box::new(|tup| filter_groups(&["ipv4.src"], tup)),
        group_op
     );
    epoch(1.0, "eid".to_string(), distinct_op)
}

// Sonata 1: TCP New Connections (Heavy Hitters)
fn tcp_new_cons(next_op: Box<dyn Operator>) -> Box<dyn Operator> {
    let threshold = 40;
     let filter_conns = filter(
        key_geq_int("cons".to_string(), threshold),
        next_op
     );
     let group_op = groupby(
         Box::new(|tup| filter_groups(&["ipv4.dst"], tup)),
         Box::new(counter),
         "cons".to_string(),
         filter_conns
     );
     let filter_syn = filter(
         Box::new(|tup| {
             get_mapped_int("ipv4.proto", tup).map_or(false, |p| p == 6) &&
             get_mapped_int("l4.flags", tup).map_or(false, |f| f == 2) // SYN flag = 2
         }),
         group_op
     );
     epoch(1.0, "eid".to_string(), filter_syn)
}


// Sonata 2: SSH Brute Force
fn ssh_brute_force(next_op: Box<dyn Operator>) -> Box<dyn Operator> {
     let threshold = 40;
     let filter_srcs = filter(
        key_geq_int("srcs".to_string(), threshold),
        next_op
     );
      let group_op = groupby(
         Box::new(|tup| filter_groups(&["ipv4.dst", "ipv4.len"], tup)), // Group by dst and length
         Box::new(counter),
         "srcs".to_string(),
         filter_srcs
     );
      let distinct_op = distinct(
         Box::new(|tup| filter_groups(&["ipv4.src", "ipv4.dst", "ipv4.len"], tup)), // Distinct src trying a specific length to a dst
         group_op
     );
     let filter_ssh = filter(
         Box::new(|tup| {
             get_mapped_int("ipv4.proto", tup).map_or(false, |p| p == 6) &&
             get_mapped_int("l4.dport", tup).map_or(false, |p| p == 22)
         }),
         distinct_op
     );
     epoch(1.0, "eid".to_string(), filter_ssh) // Consider longer epoch?
}

// Sonata 3: Super Spreader
fn super_spreader(next_op: Box<dyn Operator>) -> Box<dyn Operator> {
     let threshold = 40;
     let filter_dsts = filter(
        key_geq_int("dsts".to_string(), threshold),
        next_op
     );
     let group_op = groupby(
        Box::new(|tup| filter_groups(&["ipv4.src"], tup)), // Group by source
        Box::new(counter),
        "dsts".to_string(),
        filter_dsts
     );
     let distinct_op = distinct(
        Box::new(|tup| filter_groups(&["ipv4.src", "ipv4.dst"], tup)), // Distinct src/dst pairs
        group_op
     );
     epoch(1.0, "eid".to_string(), distinct_op)
}

// Sonata 4: Port Scan
fn port_scan(next_op: Box<dyn Operator>) -> Box<dyn Operator> {
    let threshold = 40;
     let filter_ports = filter(
        key_geq_int("ports".to_string(), threshold),
        next_op
     );
     let group_op = groupby(
         Box::new(|tup| filter_groups(&["ipv4.src"], tup)), // Group by source
         Box::new(counter),
         "ports".to_string(),
         filter_ports
     );
     let distinct_op = distinct(
         Box::new(|tup| filter_groups(&["ipv4.src", "l4.dport"], tup)), // Distinct ports tried by a source
         group_op
     );
     epoch(1.0, "eid".to_string(), distinct_op)
}

// Sonata 5: DDoS Target
fn ddos(next_op: Box<dyn Operator>) -> Box<dyn Operator> {
     let threshold = 45;
     let filter_srcs = filter(
         key_geq_int("srcs".to_string(), threshold),
         next_op
     );
     let group_op = groupby(
         Box::new(|tup| filter_groups(&["ipv4.dst"], tup)), // Group by destination
         Box::new(counter),
         "srcs".to_string(),
         filter_srcs
     );
     let distinct_op = distinct(
         Box::new(|tup| filter_groups(&["ipv4.src", "ipv4.dst"], tup)), // Distinct src/dst pairs
         group_op
     );
     epoch(1.0, "eid".to_string(), distinct_op)
}

// Sonata 6: SYN Flood (Sonata semantics)
// Returns a Vec of operators because it uses join
fn syn_flood_sonata(next_op: Box<dyn Operator>) -> Vec<Box<dyn Operator>> {
    let threshold: i64 = 3;
    let epoch_dur: f64 = 1.0;
    let eid_key = "eid".to_string();

    // --- Define the final stages after the joins ---
    let filter_final = filter(
        key_geq_int("syns+synacks-acks".to_string(), threshold),
        next_op
    );
    let map_final = map(Box::new(|mut tup: Tuple| {
        let syn_ack_res = get_mapped_int("syns+synacks", &tup);
        let ack_res = get_mapped_int("acks", &tup);
        if let (Ok(sa), Ok(a)) = (syn_ack_res, ack_res) {
            tup.insert("syns+synacks-acks".to_string(), OpResult::Int(sa - a));
        } else {
            eprintln!("Error calculating syns+synacks-acks");
            // Maybe insert an error marker or default value?
            tup.insert("syns+synacks-acks".to_string(), OpResult::Int(-1)); // Indicate error
        }
        tup
    }), filter_final);

    // --- Define the first join (SYN+SYNACK vs ACK) ---
    let (join1_left_in, join1_right_in) = join(
        eid_key.clone(),
        // Left Extractor (from SYN+SYNACK stream)
        Box::new(|tup: Tuple| {
            let key = filter_groups(&["host"], &tup);
            let val = filter_groups(&["syns+synacks"], &tup);
            (key, val)
        }),
        // Right Extractor (from ACK stream)
        Box::new(|tup: Tuple| {
            // Rename ipv4.dst to host for the key
            let key = rename_filtered_keys(&[("ipv4.dst".to_string(), "host".to_string())], &tup);
             let val = filter_groups(&["acks"], &tup);
             (key, val)
         }),
         map_final // Output of this join goes to the final map/filter
    );

    // --- Define the second join (SYN vs SYNACK) ---
     let map_join2 = map(Box::new(|mut tup: Tuple| {
         let syn_res = get_mapped_int("syns", &tup);
         let synack_res = get_mapped_int("synacks", &tup);
         if let (Ok(s), Ok(sa)) = (syn_res, synack_res) {
            tup.insert("syns+synacks".to_string(), OpResult::Int(s + sa));
         } else {
             eprintln!("Error calculating syns+synacks");
            tup.insert("syns+synacks".to_string(), OpResult::Int(-1)); // Error marker
         }
         tup
     }), join1_left_in); // Output of this join goes to the *left input* of join 1


    let (join2_left_in, join2_right_in) = join(
        eid_key.clone(),
         // Left Extractor (from SYN stream)
         Box::new(|tup: Tuple| {
             let key = rename_filtered_keys(&[("ipv4.dst".to_string(), "host".to_string())], &tup);
             let val = filter_groups(&["syns"], &tup);
             (key, val)
         }),
          // Right Extractor (from SYNACK stream)
          Box::new(|tup: Tuple| {
             let key = rename_filtered_keys(&[("ipv4.src".to_string(), "host".to_string())], &tup);
             let val = filter_groups(&["synacks"], &tup);
             (key, val)
         }),
         map_join2 // Output of this join goes to map_join2
    );


    // --- Define the initial streams ---
    let syns_stream = {
        let group_op = groupby(
            Box::new(|tup| filter_groups(&["ipv4.dst"], tup)),
            Box::new(counter),
            "syns".to_string(),
            join2_left_in, // Goes to left input of join 2
        );
        let filter_op = filter(
            Box::new(|tup| {
                get_mapped_int("ipv4.proto", tup).map_or(false, |p| p == 6) &&
                get_mapped_int("l4.flags", tup).map_or(false, |f| f == 2) // SYN
            }),
            group_op
        );
        epoch(epoch_dur, eid_key.clone(), filter_op)
    };

    let synacks_stream = {
         let group_op = groupby(
            Box::new(|tup| filter_groups(&["ipv4.src"], tup)),
            Box::new(counter),
            "synacks".to_string(),
            join2_right_in, // Goes to right input of join 2
        );
        let filter_op = filter(
            Box::new(|tup| {
                 get_mapped_int("ipv4.proto", tup).map_or(false, |p| p == 6) &&
                 get_mapped_int("l4.flags", tup).map_or(false, |f| f == 18) // SYN+ACK = 18
             }),
             group_op
        );
        epoch(epoch_dur, eid_key.clone(), filter_op)
    };

    let acks_stream = {
        let group_op = groupby(
            Box::new(|tup| filter_groups(&["ipv4.dst"], tup)),
            Box::new(counter),
            "acks".to_string(),
            join1_right_in, // Goes to right input of join 1
        );
        let filter_op = filter(
            Box::new(|tup| {
                 get_mapped_int("ipv4.proto", tup).map_or(false, |p| p == 6) &&
                 get_mapped_int("l4.flags", tup).map_or(false, |f| f == 16) // ACK = 16
             }),
             group_op
        );
        epoch(epoch_dur, eid_key.clone(), filter_op)
    };

    // Return the three starting points of the streams
    vec![syns_stream, synacks_stream, acks_stream]
}


// Sonata 7: Completed Flows Imbalance
// Returns a Vec of operators because it uses join
fn completed_flows(next_op: Box<dyn Operator>) -> Vec<Box<dyn Operator>> {
     let threshold: i64 = 1;
     let epoch_dur: f64 = 30.0; // Longer epoch
     let eid_key = "eid".to_string();

     let filter_final = filter(
        key_geq_int("diff".to_string(), threshold),
        next_op
     );
     let map_final = map(Box::new(|mut tup: Tuple| {
        let syn_res = get_mapped_int("syns", &tup);
        let fin_res = get_mapped_int("fins", &tup);
        if let (Ok(s), Ok(f)) = (syn_res, fin_res) {
            tup.insert("diff".to_string(), OpResult::Int(s - f));
        } else {
            eprintln!("Error calculating syns-fins diff");
            tup.insert("diff".to_string(), OpResult::Int(-1)); // Error marker
        }
        tup
     }), filter_final);

     let (join_left_in, join_right_in) = join(
        eid_key.clone(),
        // Left Extractor (SYNs)
        Box::new(|tup: Tuple| {
             let key = rename_filtered_keys(&[("ipv4.dst".to_string(), "host".to_string())], &tup);
             let val = filter_groups(&["syns"], &tup);
             (key, val)
         }),
         // Right Extractor (FINs)
         Box::new(|tup: Tuple| {
            let key = rename_filtered_keys(&[("ipv4.src".to_string(), "host".to_string())], &tup);
             let val = filter_groups(&["fins"], &tup);
             (key, val)
         }),
         map_final
     );


      let syns_stream = {
        let group_op = groupby(
            Box::new(|tup| filter_groups(&["ipv4.dst"], tup)),
            Box::new(counter),
            "syns".to_string(),
            join_left_in,
        );
        let filter_op = filter(
            Box::new(|tup| {
                 get_mapped_int("ipv4.proto", tup).map_or(false, |p| p == 6) &&
                 get_mapped_int("l4.flags", tup).map_or(false, |f| f == 2) // SYN
             }),
             group_op
        );
        epoch(epoch_dur, eid_key.clone(), filter_op)
    };

      let fins_stream = {
          let group_op = groupby(
             Box::new(|tup| filter_groups(&["ipv4.src"], tup)),
             Box::new(counter),
             "fins".to_string(),
             join_right_in,
         );
         let filter_op = filter(
             Box::new(|tup| {
                  get_mapped_int("ipv4.proto", tup).map_or(false, |p| p == 6) &&
                  get_mapped_int("l4.flags", tup).map_or(false, |f| (f & 1) == 1) // FIN flag is set
              }),
              group_op
         );
         epoch(epoch_dur, eid_key.clone(), filter_op)
     };

     vec![syns_stream, fins_stream]
}


// Sonata 8: Slowloris Attack
// Returns a Vec of operators because it uses join
fn slowloris(next_op: Box<dyn Operator>) -> Vec<Box<dyn Operator>> {
     let t1_n_conns: i64 = 5;
     let t2_n_bytes: i64 = 500;
     let t3_bytes_per_conn: i64 = 90;
     let epoch_dur: f64 = 1.0;
     let eid_key = "eid".to_string();

     let filter_final = filter(
        Box::new(move |tup: &Tuple| -> bool { // Use move closure for t3
            get_mapped_int("bytes_per_conn", tup).map_or(false, |bpc| bpc <= t3_bytes_per_conn)
        }),
        next_op
     );
     let map_final = map(Box::new(|mut tup: Tuple| {
         let bytes_res = get_mapped_int("n_bytes", &tup);
         let conns_res = get_mapped_int("n_conns", &tup);
         if let (Ok(b), Ok(c)) = (bytes_res, conns_res) {
             if c > 0 { // Avoid division by zero
                tup.insert("bytes_per_conn".to_string(), OpResult::Int(b / c));
             } else {
                 tup.insert("bytes_per_conn".to_string(), OpResult::Int(0)); // Or some other indicator
             }
         } else {
            eprintln!("Error calculating bytes_per_conn");
            tup.insert("bytes_per_conn".to_string(), OpResult::Int(-1)); // Error marker
         }
         tup
     }), filter_final);

     let (join_left_in, join_right_in) = join(
        eid_key.clone(),
        // Left Extractor (from n_conns stream)
        Box::new(|tup: Tuple| {
            let key = filter_groups(&["ipv4.dst"], &tup);
            let val = filter_groups(&["n_conns"], &tup);
            (key, val)
        }),
        // Right Extractor (from n_bytes stream)
        Box::new(|tup: Tuple| {
            let key = filter_groups(&["ipv4.dst"], &tup);
            let val = filter_groups(&["n_bytes"], &tup);
            (key, val)
        }),
        map_final
     );

     // Stream 1: Calculate n_conns >= t1
     let n_conns_stream = {
         let filter_t1 = filter(
            Box::new(move |tup: &Tuple| -> bool { // move closure for t1
                 get_mapped_int("n_conns", tup).map_or(false, |nc| nc >= t1_n_conns)
            }),
            join_left_in // Goes to left input of join
         );
         let group_op = groupby(
            Box::new(|tup| filter_groups(&["ipv4.dst"], tup)),
            Box::new(counter),
            "n_conns".to_string(),
            filter_t1
         );
         let distinct_op = distinct(
            Box::new(|tup| filter_groups(&["ipv4.src", "ipv4.dst", "l4.sport"], tup)), // Distinct connections
            group_op
         );
         let filter_tcp = filter(
            Box::new(|tup| get_mapped_int("ipv4.proto", tup).map_or(false, |p| p == 6)),
            distinct_op
         );
         epoch(epoch_dur, eid_key.clone(), filter_tcp)
     };

    // Stream 2: Calculate n_bytes >= t2
    let n_bytes_stream = {
        let filter_t2 = filter(
            Box::new(move |tup: &Tuple| -> bool { // move closure for t2
                 get_mapped_int("n_bytes", tup).map_or(false, |nb| nb >= t2_n_bytes)
            }),
            join_right_in // Goes to right input of join
        );
        let group_op = groupby(
            Box::new(|tup| filter_groups(&["ipv4.dst"], tup)),
            sum_ints("ipv4.len".to_string()), // Use sum_ints reduction
            "n_bytes".to_string(),
            filter_t2
        );
         let filter_tcp = filter(
            Box::new(|tup| get_mapped_int("ipv4.proto", tup).map_or(false, |p| p == 6)),
            group_op
         );
        epoch(epoch_dur, eid_key.clone(), filter_tcp)
    };


     vec![n_conns_stream, n_bytes_stream]
}

// Simple Join Test
fn join_test(next_op: Box<dyn Operator>) -> Vec<Box<dyn Operator>> {
     let epoch_dur: f64 = 1.0;
     let eid_key = "eid".to_string();

     let (join_left_in, join_right_in) = join(
        eid_key.clone(),
         // Left Extractor (SYN)
         Box::new(|tup: Tuple| {
             let key = rename_filtered_keys(&[("ipv4.src".to_string(), "host".to_string())], &tup);
             let val = rename_filtered_keys(&[("ipv4.dst".to_string(), "remote".to_string())], &tup);
             (key, val)
         }),
         // Right Extractor (SYNACK)
         Box::new(|tup: Tuple| {
             let key = rename_filtered_keys(&[("ipv4.dst".to_string(), "host".to_string())], &tup);
             let val = filter_groups(&["time"], &tup); // Just keep time from SYNACK
             (key, val)
         }),
         next_op // Output goes directly to next_op
     );

      let syns_stream = {
         let filter_op = filter(
            Box::new(|tup| {
                 get_mapped_int("ipv4.proto", tup).map_or(false, |p| p == 6) &&
                 get_mapped_int("l4.flags", tup).map_or(false, |f| f == 2) // SYN
             }),
            join_left_in
         );
        epoch(epoch_dur, eid_key.clone(), filter_op)
    };

     let synacks_stream = {
         let filter_op = filter(
             Box::new(|tup| {
                  get_mapped_int("ipv4.proto", tup).map_or(false, |p| p == 6) &&
                  get_mapped_int("l4.flags", tup).map_or(false, |f| f == 18) // SYNACK
              }),
             join_right_in
         );
         epoch(epoch_dur, eid_key.clone(), filter_op)
     };

     vec![syns_stream, synacks_stream]
}

// Query 3: Distinct src/dst pairs over 100s
fn q3(next_op: Box<dyn Operator>) -> Box<dyn Operator> {
    let distinct_op = distinct(
        Box::new(|tup| filter_groups(&["ipv4.src", "ipv4.dst"], tup)),
        next_op
    );
    epoch(100.0, "eid".to_string(), distinct_op)
}

// Query 4: Packet count per destination over 10000s
fn q4(next_op: Box<dyn Operator>) -> Box<dyn Operator> {
     let group_op = groupby(
        Box::new(|tup| filter_groups(&["ipv4.dst"], tup)),
        Box::new(counter),
        "pkts".to_string(),
        next_op
     );
    epoch(10000.0, "eid".to_string(), group_op)
}

// --- Main Execution ---

// Generates simple test data like the OCaml example
fn generate_test_data(count: usize) -> Vec<Tuple> {
    let mut data = Vec::with_capacity(count);
    let src_mac: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    let dst_mac: [u8; 6] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
    let ip_addr = Ipv4Addr::new(127, 0, 0, 1);

    for i in 0..count {
        let time = 0.000000 + i as f64 * 0.001; // Small time increment
        let mut tup = Tuple::new();
        tup.insert("time".to_string(), OpResult::Float(time));

        tup.insert("eth.src".to_string(), OpResult::MAC(src_mac));
        tup.insert("eth.dst".to_string(), OpResult::MAC(dst_mac));
        tup.insert("eth.ethertype".to_string(), OpResult::Int(0x0800)); // IPv4

        tup.insert("ipv4.hlen".to_string(), OpResult::Int(20));
        tup.insert("ipv4.proto".to_string(), OpResult::Int(6)); // TCP
        tup.insert("ipv4.len".to_string(), OpResult::Int(60));
        tup.insert("ipv4.src".to_string(), OpResult::IPv4(ip_addr));
        tup.insert("ipv4.dst".to_string(), OpResult::IPv4(ip_addr));

        tup.insert("l4.sport".to_string(), OpResult::Int(44000 + i as i64)); // Vary source port
        tup.insert("l4.dport".to_string(), OpResult::Int(50000));
        // Vary flags slightly for testing different queries
        let flags = match i % 4 {
            0 => 2,  // SYN
            1 => 18, // SYNACK
            2 => 16, // ACK
            _ => 17, // FIN+ACK (or just FIN=1)
        };
        tup.insert("l4.flags".to_string(), OpResult::Int(flags));

        data.push(tup);
    }
    data
}


fn run_queries() {
    println!("Setting up queries...");

    // --- Define the final sink/output operator ---
    // Let's use a simple tuple dump to stdout for demonstration
    // We wrap it in Rc<RefCell> because some queries (joins) need shared access to the sink.
    let final_sink = Rc::new(RefCell::new(dump_tuple(stdout(), false)));


    // --- Instantiate queries ---
    // Queries that return a single operator
    let mut single_op_queries: Vec<Box<dyn Operator>> = vec![
        ident(final_sink.borrow().clone()), // Requires clone because dump_tuple isn't Copy
        count_pkts(final_sink.borrow().clone()),
        pkts_per_src_dst(final_sink.borrow().clone()),
        distinct_srcs(final_sink.borrow().clone()),
        tcp_new_cons(final_sink.borrow().clone()),
        ssh_brute_force(final_sink.borrow().clone()),
        super_spreader(final_sink.borrow().clone()),
        port_scan(final_sink.borrow().clone()),
        ddos(final_sink.borrow().clone()),
        q3(final_sink.borrow().clone()),
        q4(final_sink.borrow().clone()),
    ];

    // Queries that return multiple operators (due to joins)
    let mut multi_op_queries_starts: Vec<Vec<Box<dyn Operator>>> = vec![
        syn_flood_sonata(final_sink.borrow().clone()),
        completed_flows(final_sink.borrow().clone()),
        slowloris(final_sink.borrow().clone()),
        join_test(final_sink.borrow().clone()),
    ];

    // Flatten the multi-op starts into the main list
    for mut starts in multi_op_queries_starts {
         single_op_queries.append(&mut starts);
    }


    println!("Generating test data...");
    let test_data = generate_test_data(200); // Increase data size for better testing

    println!("Running data through queries...");
    // --- Process Data ---
    for tup in test_data {
        for query in single_op_queries.iter_mut() {
            // Clone tuple for each independent query pipeline
            query.next(tup.clone());
        }
    }

    // --- Final Resets ---
    // Send a final reset signal, e.g., with the last known epoch or a special marker.
    // This is important for stateful operators like groupby, distinct, join to flush.
    // We'll use a simple empty tuple with a final epoch ID (can be arbitrary if time isn't tracked)
    println!("Sending final resets...");
    let final_reset_tup = utils::tuple_of_list(vec![("eid".to_string(), OpResult::Int(999))]); // Example EID
    for query in single_op_queries.iter_mut() {
        query.reset(final_reset_tup.clone());
    }

}


fn main() {
    run_queries();
    println!("Done");
}