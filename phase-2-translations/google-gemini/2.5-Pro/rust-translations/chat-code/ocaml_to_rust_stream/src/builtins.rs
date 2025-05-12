use crate::utils::*; // Import from utils module
use std::collections::HashMap;
use std::rc::Rc;
use std::cell::RefCell;
use std::io::{Write, BufReader, BufRead, stdout}; // Use stdout() for default output
use std::fs::{File, OpenOptions}; // Needs file operations
use std::net::Ipv4Addr;
use std::str::FromStr;


pub const INIT_TABLE_SIZE: usize = 10000;

// --- Operator Implementations ---

// Dump all fields of all tuples to the given output channel (Write trait object)
// Uses Rc<RefCell<>> to allow the Write trait object to be shared mutably by closures
pub fn dump_op(outc: Rc<RefCell<dyn Write>>, show_reset: bool) -> Result<Operator, Error> {
    Ok(Operator {
        next: Box::new(move |tup: Tuple| -> Result<(), Error> {
            let mut writer = outc.borrow_mut();
            dump_tuple(&mut *writer, &tup)?;
            writer.flush()?; // Ensure output is written
            Ok(())
        }),
        reset: Box::new(move |tup: Tuple| -> Result<(), Error> {
            if show_reset {
                let mut writer = outc.borrow_mut();
                dump_tuple(&mut *writer, &tup)?;
                writeln!(*writer, "[reset]")?;
                writer.flush()?;
            }
            Ok(())
        }),
    })
}

// Dump tuples as CSV to the given output channel
pub fn dump_as_csv(
    outc: Rc<RefCell<dyn Write>>,
    static_field: Option<(String, String)>,
    header: bool,
) -> Result<Operator, Error> {
    let first = Rc::new(RefCell::new(header));

    Ok(Operator {
        next: Box::new(move |tup: Tuple| -> Result<(), Error> {
            let mut writer = outc.borrow_mut();
            let is_first = *first.borrow();

            if is_first {
                if let Some((ref key, _)) = static_field {
                    write!(*writer, "{},", key)?;
                }
                // Get keys from the tuple - HashMap iteration order is not guaranteed!
                // For consistent header order, you might need a fixed list of keys.
                let mut keys: Vec<&String> = tup.keys().collect();
                keys.sort(); // Sort keys for consistent header order
                for key in keys {
                    write!(*writer, "{},", key)?;
                }
                writeln!(*writer)?; // End header line
                *first.borrow_mut() = false;
            }

            // Write static field value if present
            if let Some((_, ref value)) = static_field {
                write!(*writer, "{},", value)?;
            }

            // Write tuple values - Ensure consistent order matching the header
            let mut keys: Vec<&String> = tup.keys().collect();
            keys.sort(); // Sort keys again for value order consistency
            for key in keys {
                 // Use OpResult's Display impl
                write!(*writer, "{},", tup.get(key).unwrap_or(&OpResult::Empty))?;
            }
            writeln!(*writer)?; // End data line
            writer.flush()?;
            Ok(())
        }),
        reset: Box::new(|_tup: Tuple| -> Result<(), Error> {
            // Typically CSV reset does nothing unless explicitly needed
            Ok(())
        }),
    })
}


// Dump in Walt's specific CSV format
pub fn dump_walts_csv(filename: String) -> Result<Operator, Error> {
    // Lazily open file on first `next` call
    let file_handle: Rc<RefCell<Option<File>>> = Rc::new(RefCell::new(None));
    let filename_rc = Rc::new(filename); // Clone filename into Rc for closure

    Ok(Operator {
        next: Box::new(move |tup: Tuple| -> Result<(), Error> {
            // Ensure file is open
            if file_handle.borrow().is_none() {
                let f = OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true) // Overwrite if exists
                    .open(filename_rc.as_str())?;
                *file_handle.borrow_mut() = Some(f);
            }

            let mut writer = file_handle.borrow_mut();
            if let Some(ref mut file) = *writer {
                // Find values, using Empty or default if not found (or return Error)
                let src_ip = tup.get("src_ip").unwrap_or(&OpResult::Int(0));
                let dst_ip = tup.get("dst_ip").unwrap_or(&OpResult::Int(0));
                let src_l4_port = tup.get("src_l4_port").unwrap_or(&OpResult::Int(0));
                let dst_l4_port = tup.get("dst_l4_port").unwrap_or(&OpResult::Int(0));
                let packet_count = tup.get("packet_count").unwrap_or(&OpResult::Int(0));
                let byte_count = tup.get("byte_count").unwrap_or(&OpResult::Int(0));
                let epoch_id = tup.get("epoch_id").unwrap_or(&OpResult::Int(0)); // Or specific key

                writeln!(
                    file,
                    "{},{},{},{},{},{},{}",
                    src_ip,
                    dst_ip,
                    src_l4_port,
                    dst_l4_port,
                    packet_count,
                    byte_count,
                    epoch_id
                )?;
                file.flush()?; // Flush after write
            } else {
                 // Should not happen if file opening logic is correct
                return Err(Error::Other("File handle is unexpectedly None".to_string()));
            }
            Ok(())
        }),
        reset: Box::new(|_tup: Tuple| -> Result<(), Error> {
            // Reset in this specific CSV format does nothing
            Ok(())
        }),
    })
}

// Helper to parse IP or return Int(0)
fn get_ip_or_zero(input: &str) -> Result<OpResult, Error> {
    if input == "0" {
        Ok(OpResult::Int(0))
    } else {
        Ok(OpResult::IPv4(Ipv4Addr::from_str(input)?))
    }
}

// Reads Walt's CSV format - Complex function, uses manual parsing
// NOTE: Using the `csv` crate is highly recommended for robustness.
pub fn read_walts_csv(
    file_names: Vec<String>,
    ops: Vec<Operator>, // Expects operators corresponding to files
    epoch_id_key: String,
) -> Result<(), Error> {
    if file_names.len() != ops.len() {
        return Err(Error::Other(format!(
            "Mismatch between number of files ({}) and operators ({})",
            file_names.len(), ops.len()
        )));
    }

    // Combine files, operators, and state into tuples
    let mut processors: Vec<_> = file_names.into_iter().zip(ops.into_iter()).map(|(name, op)| {
        let file = File::open(&name)?;
        let reader = BufReader::new(file);
        Ok((
            reader, // BufReader<File>
            op,     // Operator
            Rc::new(RefCell::new(0i64)), // eid (current epoch for this file)
            Rc::new(RefCell::new(0i64)), // tup_count (tuples in current epoch)
            Rc::new(RefCell::new(true)), // active flag
            name,   // Keep filename for error messages
        ))
    }).collect::<Result<Vec<_>, Error>>()?;


    let mut active_count = processors.len();

    while active_count > 0 {
        let mut next_active_count = 0;
        for (reader, op, eid_ref, tup_count_ref, active_ref, filename) in processors.iter_mut() {
            if !*active_ref.borrow() { continue; } // Skip inactive processors

            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) => { // End of file
                    // Trigger final reset for the last epoch
                    let last_eid = *eid_ref.borrow();
                    let final_tup_count = *tup_count_ref.borrow();
                    let mut reset_tup = HashMap::new();
                    reset_tup.insert(epoch_id_key.clone(), OpResult::Int(last_eid));
                     // OCaml added tuple count to reset, Rust equivalent:
                    reset_tup.insert("tuples".to_string(), OpResult::Int(final_tup_count));

                    op.reset(reset_tup)?; // Call reset

                    *active_ref.borrow_mut() = false; // Mark as inactive
                    println!("Finished processing file: {}", filename);
                    // Don't increment next_active_count
                }
                Ok(_) => { // Successfully read a line
                    next_active_count += 1; // This processor is still active
                    line.pop(); // Remove trailing newline if present
                    let parts: Vec<&str> = line.split(',').collect();
                    if parts.len() == 7 {
                        // Parse fields - add error handling!
                        let src_ip_str = parts[0];
                        let dst_ip_str = parts[1];
                        let src_l4_port: i64 = parts[2].parse()?;
                        let dst_l4_port: i64 = parts[3].parse()?;
                        let packet_count: i64 = parts[4].parse()?;
                        let byte_count: i64 = parts[5].parse()?;
                        let epoch_id: i64 = parts[6].parse()?;

                        // Check for epoch boundary
                        let mut current_eid = eid_ref.borrow_mut();
                        let mut current_tup_count = tup_count_ref.borrow_mut();

                        if epoch_id > *current_eid {
                            // Process resets for skipped epochs
                            while epoch_id > *current_eid {
                                let mut reset_tup = HashMap::new();
                                reset_tup.insert(epoch_id_key.clone(), OpResult::Int(*current_eid));
                                // Add tuple count for the completed epoch
                                reset_tup.insert("tuples".to_string(), OpResult::Int(*current_tup_count));

                                op.reset(reset_tup)?;

                                *current_tup_count = 0; // Reset tuple count for the new epoch
                                *current_eid += 1; // Move to next epoch
                            }
                        }

                        // Build the tuple
                        let mut p: Tuple = HashMap::new();
                        p.insert("ipv4.src".to_string(), get_ip_or_zero(src_ip_str)?);
                        p.insert("ipv4.dst".to_string(), get_ip_or_zero(dst_ip_str)?);
                        p.insert("l4.sport".to_string(), OpResult::Int(src_l4_port));
                        p.insert("l4.dport".to_string(), OpResult::Int(dst_l4_port));
                        p.insert("packet_count".to_string(), OpResult::Int(packet_count));
                        p.insert("byte_count".to_string(), OpResult::Int(byte_count));
                        p.insert(epoch_id_key.clone(), OpResult::Int(epoch_id));

                        *current_tup_count += 1;
                        // Add current tuple count to the tuple being passed
                        p.insert("tuples".to_string(), OpResult::Int(*current_tup_count));

                        op.next(p)?; // Process the tuple

                    } else {
                        eprintln!("Warning: Malformed line in {}: {}", filename, line);
                        // Decide how to handle malformed lines (skip, error?)
                    }
                    line.clear(); // Reuse the string buffer
                }
                Err(e) => { // Read error
                    eprintln!("Error reading file {}: {}", filename, e);
                    *active_ref.borrow_mut() = false; // Mark as inactive on error
                }
            }
        }
        active_count = next_active_count; // Update active count for next loop iteration
    }

    println!("Done reading all files.");
    Ok(())
}


// Meta-meter operator: Logs tuple counts per epoch
pub fn meta_meter(
    name: String,
    outc: Rc<RefCell<dyn Write>>,
    static_field: Option<String>,
    next_op: Operator,
) -> Result<Operator, Error> {
    let epoch_count = Rc::new(RefCell::new(0i64));
    let tups_count = Rc::new(RefCell::new(0i64));
    let mut next_op_mut = next_op; // Shadow to make mutable for FnMut

    Ok(Operator {
        next: Box::new(move |tup: Tuple| -> Result<(), Error> {
            *tups_count.borrow_mut() += 1;
            (next_op_mut.next)(tup) // Call the next operator's 'next'
        }),
        reset: Box::new(move |tup: Tuple| -> Result<(), Error> {
            let mut writer = outc.borrow_mut();
            let static_val = static_field.as_deref().unwrap_or("");
            writeln!(
                *writer,
                "{},{},{},{}",
                *epoch_count.borrow(),
                name,
                *tups_count.borrow(),
                static_val
            )?;
            writer.flush()?;

            *tups_count.borrow_mut() = 0; // Reset tuple count
            *epoch_count.borrow_mut() += 1; // Increment epoch count

            (next_op_mut.reset)(tup) // Call the next operator's 'reset'
        }),
    })
}

// Epoch operator: Divides stream into time-based epochs
pub fn epoch(
    epoch_width: f64,
    key_out: String,
    next_op: Operator,
) -> Result<Operator, Error> {
    let epoch_boundary = Rc::new(RefCell::new(0.0f64));
    let eid = Rc::new(RefCell::new(0i64));
    let mut next_op_mut = next_op;

    Ok(Operator {
        next: Box::new(move |mut tup: Tuple| -> Result<(), Error> {
            // Assume "time" field exists and is float
            let time = lookup_float("time", &tup)?;

            let mut boundary = epoch_boundary.borrow_mut();
            let mut current_eid = eid.borrow_mut();

            if *boundary == 0.0 { // First tuple seen
                *boundary = time + epoch_width;
            } else if time >= *boundary {
                // Crossed epoch boundary(s)
                while time >= *boundary {
                    let mut reset_tup = HashMap::new();
                    reset_tup.insert(key_out.clone(), OpResult::Int(*current_eid));
                    (next_op_mut.reset)(reset_tup)?; // Pass reset signal

                    *boundary += epoch_width;
                    *current_eid += 1;
                }
            }
            // Add epoch ID to the current tuple
            tup.insert(key_out.clone(), OpResult::Int(*current_eid));
            (next_op_mut.next)(tup) // Pass tuple downstream
        }),
        reset: Box::new(move |mut tup: Tuple| -> Result<(), Error> {
            // Propagate reset, potentially adding the last known eid
            let last_eid = *eid.borrow();
             // OCaml added eid to reset tuple, Rust equivalent:
            tup.insert(key_out.clone(), OpResult::Int(last_eid));

            (next_op_mut.reset)(tup)?;

            // Reset internal state for the next stream segment
            *epoch_boundary.borrow_mut() = 0.0;
            *eid.borrow_mut() = 0;
            Ok(())
        }),
    })
}


// Filter operator: Passes tuples matching the predicate
pub fn filter(
    predicate: Box<dyn Fn(&Tuple) -> bool>, // Predicate function
    next_op: Operator,
) -> Result<Operator, Error> {
    let mut next_op_mut = next_op;
    Ok(Operator {
        next: Box::new(move |tup: Tuple| -> Result<(), Error> {
            if predicate(&tup) {
                (next_op_mut.next)(tup)
            } else {
                Ok(()) // Filtered out, do nothing
            }
        }),
        reset: Box::new(move |tup: Tuple| -> Result<(), Error> {
            (next_op_mut.reset)(tup) // Always propagate reset
        }),
    })
}


// Filter utility: Check if key >= threshold (integer)
pub fn key_geq_int(key: String, threshold: i64) -> Box<dyn Fn(&Tuple) -> bool> {
    Box::new(move |tup: &Tuple| -> bool {
        match lookup_int(&key, tup) {
            Ok(val) => val >= threshold,
            Err(_) => false, // Key not found or not an int -> filter out
        }
    })
}

// Filter utility: Looks up key and converts to Int (panics on failure in OCaml)
// Rust version returns Result
pub fn get_mapped_int(key: &str, tup: &Tuple) -> Result<i64, Error> {
    lookup_int(key, tup)
}

// Filter utility: Looks up key and converts to Float (panics on failure in OCaml)
// Rust version returns Result
pub fn get_mapped_float(key: &str, tup: &Tuple) -> Result<f64, Error> {
    lookup_float(key, tup)
}

// Map operator: Applies a function to transform each tuple
pub fn map(
    // Function takes ownership and returns ownership
    transform_fn: Box<dyn Fn(Tuple) -> Result<Tuple, Error>>,
    next_op: Operator,
) -> Result<Operator, Error> {
    let mut next_op_mut = next_op;
    Ok(Operator {
        next: Box::new(move |tup: Tuple| -> Result<(), Error> {
            let transformed_tup = transform_fn(tup)?;
            (next_op_mut.next)(transformed_tup)
        }),
        reset: Box::new(move |tup: Tuple| -> Result<(), Error> {
            (next_op_mut.reset)(tup) // Always propagate reset
        }),
    })
}


// Type aliases for groupby functions
// Grouping function: Extracts a hashable key from a tuple
pub type GroupingFunc = Box<dyn Fn(&Tuple) -> GroupKey>; // Returns HASHABLE key
// Reduction function: Accumulates state based on current value and tuple
pub type ReductionFunc = Box<dyn Fn(OpResult, &Tuple) -> OpResult>;

// Groupby operator
pub fn groupby(
    groupby_fn: GroupingFunc,
    reduce_fn: ReductionFunc,
    out_key: String,
    next_op: Operator,
) -> Result<Operator, Error> {
    // State table: Key must be hashable (GroupKey), value is accumulated OpResult
    let h_tbl: Rc<RefCell<HashMap<GroupKey, OpResult>>> =
        Rc::new(RefCell::new(HashMap::with_capacity(INIT_TABLE_SIZE)));
    let mut next_op_mut = next_op;

    Ok(Operator {
        next: Box::new(move |tup: Tuple| -> Result<(), Error> {
            let grouping_key = groupby_fn(&tup);
            let mut table = h_tbl.borrow_mut();

            // Get current accumulated value or Empty, then apply reduction
            let current_val = table.get(&grouping_key).cloned().unwrap_or(OpResult::Empty);
            let next_val = reduce_fn(current_val, &tup);

            table.insert(grouping_key, next_val);
            Ok(())
        }),
        reset: Box::new(move |reset_tup: Tuple| -> Result<(), Error> {
            let table = h_tbl.borrow(); // Read-only borrow for iteration
            for (grouping_key_obj, accumulated_val) in table.iter() {
                // The grouping_key_obj (GroupKey) needs to be convertible back
                // to tuple fields if they are needed downstream. This logic depends
                // heavily on the GroupKey definition.
                // Assuming GroupKey doesn't directly contain the fields needed for merge:
                // This part is tricky - OCaml merged the reset_tup, the grouping_key tuple,
                // and the result. In Rust, GroupKey might just be a hashable representation.
                // We might need the original tuple associated with the key, which groupby
                // doesn't store by default.
                //
                // Simplification: Create output tuple from reset_tup and the result.
                // If grouping fields are needed, the GroupKey definition or
                // the groupby logic must preserve them.
                let mut output_tup = reset_tup.clone();

                // How to add grouping_key fields back? Requires GroupKey design.
                // Placeholder: If GroupKey has a method to reconstruct parts of the tuple:
                // output_tup = merge_tuples(output_tup, grouping_key_obj.to_tuple_fragment());

                output_tup.insert(out_key.clone(), accumulated_val.clone());

                // Pass the combined tuple downstream for this group
                 (next_op_mut.next)(output_tup)?;
            }

            // Propagate the original reset tuple after processing all groups
            (next_op_mut.reset)(reset_tup)?;

            // Clear the table for the next epoch
            h_tbl.borrow_mut().clear();
            Ok(())
        }),
    })
}


// (groupby utility: key_extractor) -> Rust version returns GroupKey
// Creates a GroupKey containing only specified fields.
pub fn filter_groups(incl_keys: Vec<String>) -> GroupingFunc {
    Box::new(move |tup: &Tuple| -> GroupKey {
        // Implementation depends on GroupKey definition. Using string repr:
        let key_string = incl_keys.iter()
            .map(|k| tup.get(k).map_or("".to_string(), |v| v.to_string()))
            .collect::<Vec<String>>()
            .join("|");
        GroupKey { repr: key_string }
    })
}

// (groupby utility: key_extractor) -> Single group uses a constant key
pub fn single_group() -> GroupingFunc {
    Box::new(|_tup: &Tuple| -> GroupKey {
        // Constant key for the single group
        GroupKey { repr: "_SINGLE_GROUP_".to_string() }
    })
}

// (groupby utility: reduction_func) -> Counts tuples
pub fn counter() -> ReductionFunc {
    Box::new(|val: OpResult, _tup: &Tuple| -> OpResult {
        match val {
            OpResult::Empty => OpResult::Int(1),
            OpResult::Int(i) => OpResult::Int(i + 1),
            _ => OpResult::Int(1), // Or handle error/unexpected type
        }
    })
}


// (groupby utility: reduction_func) -> Sums integer values of a field
pub fn sum_ints(search_key: String) -> ReductionFunc {
    Box::new(move |init_val: OpResult, tup: &Tuple| -> OpResult {
        let current_sum = match init_val {
            OpResult::Empty => 0,
            OpResult::Int(i) => i,
             // Or handle error/unexpected type
            _ => return OpResult::Int(0), // Or propagate error
        };

        match lookup_int(&search_key, tup) {
            Ok(n) => OpResult::Int(current_sum + n),
             // Field not found or not int, return current sum or handle error
            Err(_) => OpResult::Int(current_sum), // Or return Error OpResult?
        }
    })
}

// Distinct operator: Emits distinct tuples based on grouping key each epoch
pub fn distinct(
    groupby_fn: GroupingFunc,
    next_op: Operator,
) -> Result<Operator, Error> {
    // Table stores the GroupKey -> original Tuple mapping (or just a marker)
    // Using Tuple as value to reconstruct output easily
    let h_tbl: Rc<RefCell<HashMap<GroupKey, Tuple>>> =
        Rc::new(RefCell::new(HashMap::with_capacity(INIT_TABLE_SIZE)));
    let mut next_op_mut = next_op;

    Ok(Operator {
        next: Box::new(move |tup: Tuple| -> Result<(), Error> {
            let grouping_key = groupby_fn(&tup);
            let mut table = h_tbl.borrow_mut();
            // Insert/replace tuple associated with the key
            table.insert(grouping_key, tup);
            Ok(())
        }),
        reset: Box::new(move |reset_tup: Tuple| -> Result<(), Error> {
            let table = h_tbl.borrow();
            for (_group_key, distinct_tup) in table.iter() {
                 // Merge the reset tuple info with the distinct tuple found
                 // Prioritize distinct_tup fields over reset_tup fields? OCaml's union did.
                let merged_tup = merge_tuples_prefer_primary(distinct_tup.clone(), reset_tup.clone());
                (next_op_mut.next)(merged_tup)?;
            }

            // Propagate the original reset tuple
            (next_op_mut.reset)(reset_tup)?;

            // Clear table for next epoch
            h_tbl.borrow_mut().clear();
            Ok(())
        }),
    })
}


// Split operator: Sends data to two downstream operators
pub fn split(left_op: Operator, right_op: Operator) -> Result<Operator, Error> {
    let mut left_op_mut = left_op;
    let mut right_op_mut = right_op;

    Ok(Operator {
        next: Box::new(move |tup: Tuple| -> Result<(), Error> {
            // Need to clone tuple if both downstream operators consume it
            let tup_for_right = tup.clone();
            (left_op_mut.next)(tup)?;
            (right_op_mut.next)(tup_for_right)?;
            Ok(())
        }),
        reset: Box::new(move |tup: Tuple| -> Result<(), Error> {
            // Need to clone tuple if both downstream operators consume it
            let tup_for_right = tup.clone();
            (left_op_mut.reset)(tup)?;
            (right_op_mut.reset)(tup_for_right)?;
            Ok(())
        }),
    })
}


// Type alias for join key extractor
// Extracts a hashable JoinKey and the value tuple to store
pub type KeyExtractor = Box<dyn Fn(&Tuple) -> Result<(JoinKey, Tuple), Error>>;

// Join operator: Stateful join based on keys and epoch IDs
// Returns two operators, one for each input stream (left and right)
pub fn join(
    eid_key: String, // Key holding the epoch ID
    left_extractor: KeyExtractor,
    right_extractor: KeyExtractor,
    next_op: Operator,
) -> Result<(Operator, Operator), Error> {
    // State tables: JoinKey -> Value Tuple
    let h_tbl1: Rc<RefCell<HashMap<JoinKey, Tuple>>> =
        Rc::new(RefCell::new(HashMap::with_capacity(INIT_TABLE_SIZE)));
    let h_tbl2: Rc<RefCell<HashMap<JoinKey, Tuple>>> =
        Rc::new(RefCell::new(HashMap::with_capacity(INIT_TABLE_SIZE)));

    // Current epoch processed by each side
    let left_curr_epoch = Rc::new(RefCell::new(0i64));
    let right_curr_epoch = Rc::new(RefCell::new(0i64));

    // Share the next operator and eid key
    let next_op_rc = Rc::new(RefCell::new(next_op));
    let eid_key_rc = Rc::new(eid_key);

    // --- Helper function to create one side of the join ---
    fn handle_join_side(
        curr_h_tbl: Rc<RefCell<HashMap<JoinKey, Tuple>>>,
        other_h_tbl: Rc<RefCell<HashMap<JoinKey, Tuple>>>,
        curr_epoch_ref: Rc<RefCell<i64>>,
        other_epoch_ref: Rc<RefCell<i64>>,
        extractor: KeyExtractor,
        next_op_rc: Rc<RefCell<Operator>>,
        eid_key_rc: Rc<String>,
    ) -> Operator {
        Operator {
            next: Box::new(move |tup: Tuple| -> Result<(), Error> {
                let (key, vals) = extractor(&tup)?;
                 // Epoch ID must be present in the key or extracted separately
                // Assuming extractor includes eid in JoinKey or it's passed explicitly
                // Let's re-lookup EID for epoch advancement logic.
                let tup_epoch = get_mapped_int(eid_key_rc.as_str(), &tup)?;

                let mut current_epoch = curr_epoch_ref.borrow_mut();
                let other_epoch = *other_epoch_ref.borrow();
                let mut next_op = next_op_rc.borrow_mut();

                // Advance current epoch and trigger resets if needed
                 while tup_epoch > *current_epoch {
                     // Only reset if the *other* side has also processed this epoch
                     if other_epoch > *current_epoch {
                        let mut reset_tup = HashMap::new();
                        reset_tup.insert(eid_key_rc.to_string(), OpResult::Int(*current_epoch));
                        (next_op.reset)(reset_tup)?;
                     }
                     *current_epoch += 1;
                 }


                // Try to find match in the *other* table
                let mut other_table = other_h_tbl.borrow_mut();
                if let Some(other_vals) = other_table.remove(&key) {
                    // Match found: merge and send downstream
                    // Merge vals from current tuple + stored vals from other tuple
                    // OCaml: union use_left new_tup (union use_left vals_ val_)
                    // Rust: Merge `key` fields (implicitly in `key`), `vals` (current), `other_vals`
                     // This merging logic needs care. Assuming key object doesn't store the tuple fields directly:
                    let mut joined_tup = tup.clone(); // Start with current tuple
                    joined_tup = merge_tuples(joined_tup, other_vals); // Add matched values

                    // The key object might need reconstruction if its fields are required
                    // joined_tup = merge_tuples(joined_tup, key.to_tuple_fragment());

                    (next_op.next)(joined_tup)?;
                } else {
                    // No match: store current vals in *this* side's table
                    curr_h_tbl.borrow_mut().insert(key, vals);
                }
                Ok(())
            }),
            reset: Box::new(move |tup: Tuple| -> Result<(), Error> {
                 // Handle epoch advancement on reset signal
                 let reset_epoch = get_mapped_int(eid_key_rc.as_str(), &tup)?;
                 let mut current_epoch = curr_epoch_ref.borrow_mut();
                 let other_epoch = *other_epoch_ref.borrow();
                 let mut next_op = next_op_rc.borrow_mut();

                 while reset_epoch > *current_epoch {
                     if other_epoch > *current_epoch {
                         let mut epoch_tup = HashMap::new();
                         epoch_tup.insert(eid_key_rc.to_string(), OpResult::Int(*current_epoch));
                         (next_op.reset)(epoch_tup)?;
                     }
                     *current_epoch += 1;
                 }
                 // Note: Unlike OCaml, the original reset tuple isn't automatically propagated
                 // downstream by the join logic here, only epoch boundary resets.
                 // If the original reset tuple needs propagation, it should be done explicitly
                 // after the epoch advancement loop if *current_epoch == reset_epoch*.
                 if reset_epoch >= *current_epoch && other_epoch >= reset_epoch {
                     // Propagate the original reset if both sides reached it
                     (next_op.reset)(tup)?;
                 }

                Ok(())
            }),
        }
    }
    // --- Create the two operators ---
    let left_op = handle_join_side(
        h_tbl1.clone(), h_tbl2.clone(),
        left_curr_epoch.clone(), right_curr_epoch.clone(),
        left_extractor,
        next_op_rc.clone(), eid_key_rc.clone(),
    );
    let right_op = handle_join_side(
        h_tbl2.clone(), h_tbl1.clone(),
        right_curr_epoch.clone(), left_curr_epoch.clone(),
        right_extractor,
        next_op_rc.clone(), eid_key_rc.clone(),
    );

    Ok((left_op, right_op))
}


// (join utility) -> Creates a new tuple by renaming and filtering keys
pub fn rename_filtered_keys(
    renaming_pairs: Vec<(String, String)>, // List of (old_key, new_key)
) -> Box<dyn Fn(&Tuple) -> Tuple> { // Returns function for use in map etc.
    Box::new(move |in_tup: &Tuple| -> Tuple {
        let mut new_tup = HashMap::new();
        for (old_key, new_key) in &renaming_pairs {
            if let Some(val) = in_tup.get(old_key) {
                new_tup.insert(new_key.clone(), val.clone());
            }
        }
        new_tup
    })
}

// Helper join extractor function (like OCaml's `fun tup -> (key_tup, val_tup)`)
// Combines key extraction (e.g., filter_groups or rename_filtered_keys) and value extraction
pub fn make_key_extractor(
    eid_key: String, // Needed to build the JoinKey
    key_def_keys: Vec<String>,    // Keys defining the group for JoinKey
    val_def_keys: Vec<String>,    // Keys defining the value tuple
) -> KeyExtractor {
    Box::new(move |tup: &Tuple| -> Result<(JoinKey, Tuple), Error> {
        // Create the hashable JoinKey
        let join_key = create_join_key(&eid_key, &key_def_keys.iter().map(|s| s.as_str()).collect::<Vec<&str>>(), tup)?;

        // Create the value tuple
        let val_tup = val_def_keys.iter()
            .filter_map(|k| tup.get(k).map(|v| (k.clone(), v.clone())))
            .collect::<HashMap<String, OpResult>>();

        Ok((join_key, val_tup))
    })
}
// Example extractor using renaming for the key part
pub fn make_renaming_key_extractor(
     eid_key: String,
     key_renamings: Vec<(String, String)>, // Renamings define the key's *identity* for hashing
     val_def_keys: Vec<String>,
 ) -> KeyExtractor {
     Box::new(move |tup: &Tuple| -> Result<(JoinKey, Tuple), Error> {
         // Create key tuple fragment by renaming
         let key_tup_fragment = rename_filtered_keys(key_renamings.clone())(tup);

         // Create a hashable JoinKey from the key_tup_fragment + eid
         // This requires a way to serialize key_tup_fragment or use its fields
         let eid = lookup_int(&eid_key, tup)?;
         let key_string = key_tup_fragment.iter()
                             .map(|(k,v)| format!("{}:{}", k, v)) // Example serialization
                             .collect::<Vec<_>>()
                             .join("|");
         let join_key = JoinKey { repr: format!("{}-{}", eid, key_string) };


         // Create the value tuple
         let val_tup = val_def_keys.iter()
             .filter_map(|k| tup.get(k).map(|v| (k.clone(), v.clone())))
             .collect::<HashMap<String, OpResult>>();

         Ok((join_key, val_tup))
     })
}