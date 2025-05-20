Prompt: base prompt

```rust
use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// Common utilities

// Operators act on named "tuples" which are maps from strings to OpResult types
//*************************************************************************************

#[derive(Debug, Clone, PartialEq)]
pub enum OpResult {
    Float(f64),      // Tag for floating point vals
    Int(i64),        // Tag for int vals
    IPv4(Ipv4Addr),  // Tag for IPv4 address
    MAC(Vec<u8>),    // Tag for a MAC address
    Empty,           // Tag for empty/missing val, possibly end of something
}

impl fmt::Display for OpResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OpResult::Float(val) => write!(f, "{}", val),
            OpResult::Int(val) => write!(f, "{}", val),
            OpResult::IPv4(addr) => write!(f, "{}", addr),
            OpResult::MAC(bytes) => write!(
                f,
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
            ),
            OpResult::Empty => write!(f, "Empty"),
        }
    }
}

pub type Tuple = HashMap<String, OpResult>; // Defines tuple as a map from strings to OpResults

// Defines a data processing unit in a stream processing pipeline;
// contains two functions
pub struct Operator { // Record type
    pub next: Box<dyn FnMut(&mut Tuple)>, // Takes in HashMap<String, OpResult>, processes it in some way, most likely a side effect
    pub reset: Box<dyn FnMut(&mut Tuple)>, // Takes same thing, performs a reset op on it after processing
}

pub type OpCreator = Box<dyn FnOnce(Operator) -> Operator>;
pub type DblOpCreator = Box<dyn FnOnce(Operator) -> (Operator, Operator)>;

// Right associative "chaining" operator
// for passing output of one operator to the next under cps-style operator constructors
pub fn op_chain(op_creator_func: OpCreator, next_op: Operator) -> Operator {
    op_creator_func(next_op)
}

// e.g.
// (epoch 1.0 "eid").chain(groupby(single_group, count, "pkts")).chain(next_op)
// instead of:
// epoch(1.0, "eid", groupby(single_group, count, "pkts", next_op))

pub fn dbl_op_chain(op_creator_func: DblOpCreator, op: Operator) -> (Operator, Operator) {
    op_creator_func(op)
}

// Conversion utilities
//*************************************************************************************

// Formats the 6 bytes of the MAC address as a colon-separated string in hex
pub fn string_of_mac(buf: &[u8]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]
    )
}

// Converts TCP flags into a human-readable string representation by matching
// flags to formatted output
pub fn tcp_flags_to_strings(flags: i64) -> String {
    let tcp_flags_map = HashMap::from([
        ("FIN", 1 << 0),
        ("SYN", 1 << 1),
        ("RST", 1 << 2),
        ("PSH", 1 << 3),
        ("ACK", 1 << 4),
        ("URG", 1 << 5),
        ("ECE", 1 << 6),
        ("CWR", 1 << 7),
    ]);

    tcp_flags_map
        .iter()
        .filter_map(|(key, value)| {
            if flags & value != 0 {
                Some(*key)
            } else {
                None
            }
        })
        .collect::<Vec<&str>>()
        .join("|")
}

// Checks if input is an Int OpResult, panics otherwise
pub fn int_of_op_result(input: &OpResult) -> i64 {
    match input {
        OpResult::Int(i) => *i,
        _ => panic!("Trying to extract int from non-int result"),
    }
}

// Checks if input is a Float OpResult, panics otherwise
pub fn float_of_op_result(input: &OpResult) -> f64 {
    match input {
        OpResult::Float(f) => *f,
        _ => panic!("Trying to extract float from non-float result"),
    }
}

// Returns the human-readable version of each OpResult value
pub fn string_of_op_result(input: &OpResult) -> String {
    match input {
        OpResult::Float(f) => format!("{}", f),
        OpResult::Int(i) => format!("{}", i),
        OpResult::IPv4(a) => format!("{}", a),
        OpResult::MAC(m) => string_of_mac(m),
        OpResult::Empty => "Empty".to_string(),
    }
}

// Outputs the tuple in a human-readable form e.g.
// "ipv4.src" => 192.168.1.1, "packet_count" => 10,
pub fn string_of_tuple(input_tuple: &Tuple) -> String {
    input_tuple
        .iter()
        .map(|(key, val)| format!("\"{}\" => {}, ", key, string_of_op_result(val)))
        .collect::<String>()
}

// Creates a Tuple (HashMap<String, OpResult>) out of a list of tuples
pub fn tuple_of_list(tup_list: Vec<(String, OpResult)>) -> Tuple {
    tup_list.into_iter().collect()
}

// Prints formatted representation of a Tuple
pub fn dump_tuple(out: &mut impl std::io::Write, tup: &Tuple) -> std::io::Result<()> {
    writeln!(out, "{}", string_of_tuple(tup))
}

// Retrieves the int value of the OpResult associated with a given key
// in the given Tuple (HashMap<String, OpResult>)
pub fn lookup_int(key: &str, tup: &Tuple) -> i64 {
    int_of_op_result(tup.get(key).expect("Key not found in tuple"))
}

// Retrieves the float value of the OpResult associated with a given key
// in the given Tuple (HashMap<String, OpResult>)
pub fn lookup_float(key: &str, tup: &Tuple) -> f64 {
    float_of_op_result(tup.get(key).expect("Key not found in tuple"))
}

// Built-in operator definitions
// and common utilities for readability

// Assume Utils and Printf equivalents are available in Rust's standard library

const INIT_TABLE_SIZE: usize = 10000;

// Dump all fields of all tuples to the given output channel
// Note that dump is terminal in that it does not take a continuation operator
// as argument
// Returns an Operator record with two functions:
//     next: dumps a given Tuple to the given output
//     reset: prints a reset message if the given show_reset is true
pub fn dump_tuple_op(show_reset: bool, out: &mut impl std::io::Write) -> Operator {
    Operator {
        next: Box::new(move |tup: &mut Tuple| {
            dump_tuple(out, tup).expect("Error dumping tuple");
        }),
        reset: Box::new(move |tup: &mut Tuple| {
            if show_reset {
                dump_tuple(out, tup).expect("Error dumping tuple");
                writeln!(out, "[reset]").expect("Error writing reset message");
            }
        }),
    }
}

// Tries to dump a nice csv-style output
// Assumes all tuples have the same fields in the same order...
// Writes tuples to an output channel in CSV format
// Constructs Operator record with two fields:
//     next: process tuples
//     reset: does nothing
pub fn dump_as_csv_op(
    static_field: Option<(&str, &str)>,
    header: bool,
    out: &mut impl std::io::Write,
) -> Operator {
    let first = std::cell::RefCell::new(header);
    Operator {
        next: Box::new(move |tup: &mut Tuple| {
            if *first.borrow() {
                if let Some((key, _)) = static_field {
                    write!(out, "{},", key).expect("Error writing CSV header");
                }
                for key in tup.keys() {
                    write!(out, "{},", key).expect("Error writing CSV header");
                }
                writeln!(out).expect("Error writing CSV header");
                *first.borrow_mut() = false;
            }
            if let Some((_, value)) = static_field {
                write!(out, "{},", value).expect("Error writing CSV row");
            }
            for value in tup.values() {
                write!(out, "{},", value).expect("Error writing CSV row");
            }
            writeln!(out).expect("Error writing CSV row");
        }),
        reset: Box::new(|_| {}),
    }
}

// Dumps csv in Walt's canonical csv format: src_ip, dst_ip, src_l4_port,
// dst_l4_port, packet_count, byte_count, epoch_id
// Unused fields are zeroed, map packet length to src_l4_port for ssh brute
// force
pub fn dump_walts_csv(filename: &str) -> Operator {
    let outfile = std::cell::RefCell::new(std::fs::File::create(filename).expect("Error opening file"));
    let first = std::cell::RefCell::new(true);
    Operator {
        next: Box::new(move |tup: &mut Tuple| {
            if *first.borrow() {
                *first.borrow_mut() = false;
            }
            let src_ip = tup.get("ipv4.src").expect("Key not found");
            let dst_ip = tup.get("ipv4.dst").expect("Key not found");
            let src_l4_port = tup.get("l4.sport").expect("Key not found");
            let dst_l4_port = tup.get("l4.dport").expect("Key not found");
            let packet_count = tup.get("packet_count").expect("Key not found");
            let byte_count = tup.get("byte_count").expect("Key not found");
            let epoch_id = tup.get("epoch_id").expect("Key not found");

            writeln!(
                outfile.borrow_mut(),
                "{},{},{},{},{},{},{}",
                src_ip, dst_ip, src_l4_port, dst_l4_port, packet_count, byte_count, epoch_id
            )
            .expect("Error writing to file");
        }),
        reset: Box::new(|_| {}),
    }
}

// Input is either "0" or an IPv4 address in string format,
// returns corresponding OpResult
pub fn get_ip_or_zero(input: &str) -> OpResult {
    match input {
        "0" => OpResult::Int(0),
        catchall => OpResult::IPv4(catchall.parse().expect("Invalid IPv4 address")),
    }
}

// Reads an intermediate result CSV in Walt's canonical format
// Injects epoch ids and incoming tuple counts into reset call
// TODO: read files in RR order...
// otherwise the whole file gets cached in joins
// Reads multiple CSV files, extracts their network flow data, processes it into
// tuples, and applies ops on the extracted data
pub fn read_walts_csv(
    epoch_id_key: &str,
    file_names: Vec<&str>,
    mut ops: Vec<Operator>,
) {
    let inchs_eids_tupcount: Vec<_> = file_names
        .iter()
        .map(|filename| {
            (
                std::fs::File::open(filename).expect("Error opening file"),
                std::cell::RefCell::new(0),
                std::cell::RefCell::new(0),
            )
        })
        .collect();

    let running = std::cell::RefCell::new(ops.len());

    while *running.borrow() > 0 {
        for (((in_file, eid, tup_count), op), _) in inchs_eids_tupcount.iter().zip(ops.iter_mut()).enumerate() {
            if *eid.borrow() >= 0 {
                let mut reader = std::io::BufReader::new(&in_file);
                let mut line = String::new();
                match reader.read_line(&mut line) {
                    Ok(bytes_read) if bytes_read > 0 => {
                        let parts: Vec<&str> = line.trim().split(',').collect();
                        if parts.len() == 7 {
                            let src_ip = parts[0];
                            let dst_ip = parts[1];
                            let src_l4_port: i64 = parts[2].parse().expect("Invalid port");
                            let dst_l4_port: i64 = parts[3].parse().expect("Invalid port");
                            let packet_count: i64 = parts[4].parse().expect("Invalid count");
                            let byte_count: i64 = parts[5].parse().expect("Invalid count");
                            let epoch_id: i64 = parts[6].parse().expect("Invalid epoch id");

                            let mut p: Tuple = HashMap::new();
                            p.insert("ipv4.src".to_string(), get_ip_or_zero(src_ip));
                            p.insert("ipv4.dst".to_string(), get_ip_or_zero(dst_ip));
                            p.insert("l4.sport".to_string(), OpResult::Int(src_l4_port));
                            p.insert("l4.dport".to_string(), OpResult::Int(dst_l4_port));
                            p.insert("packet_count".to_string(), OpResult::Int(packet_count));
                            p.insert("byte_count".to_string(), OpResult::Int(byte_count));
                            p.insert(epoch_id_key.to_string(), OpResult::Int(epoch_id));

                            *tup_count.borrow_mut() += 1;

                            if epoch_id > *eid.borrow() {
                                while epoch_id > *eid.borrow() {
                                    let mut reset_tup = HashMap::new();
                                    reset_tup.insert("tuples".to_string(), OpResult::Int(*tup_count.borrow()));
                                    reset_tup.insert(epoch_id_key.to_string(), OpResult::Int(*eid.borrow()));
                                    (op.reset)(&mut reset_tup);
                                    *tup_count.borrow_mut() = 0;
                                    *eid.borrow_mut() += 1;
                                }
                            }
                            let mut next_tup = HashMap::new();
                            next_tup.insert("tuples".to_string(), OpResult::Int(*tup_count.borrow()));
                            next_tup.extend(p);
                            (op.next)(&mut next_tup);
                        } else {
                            eprintln!("Failed to parse line: {}", line.trim());
                            panic!("Scan failure");
                        }
                    }
                    Ok(0) => {
                        let mut reset_tup = HashMap::new();
                        reset_tup.insert("tuples".to_string(), OpResult::Int(*tup_count.borrow()));
                        reset_tup.insert(epoch_id_key.to_string(), OpResult::Int(*eid.borrow() + 1));
                        (op.reset)(&mut reset_tup);
                        *running.borrow_mut() -= 1;
                        *eid.borrow_mut() = -1;
                    }
                    Err(e) => {
                        eprintln!("Error reading line: {}", e);
                        panic!("Scan failure");
                    }
                }
            }
        }
    }
    println!("Done.");
}

// Write the number of tuples passing through this operator each epoch
// to the out_channel
// Tracks how many tuples processed per epoch and logs it to outc
pub fn meta_meter_op(
    static_field: Option<&str>,
    name: &str,
    out: &mut impl std::io::Write,
    next_op: Operator,
) -> Operator {
    let epoch_count = std::cell::RefCell::new(0);
    let tups_count = std::cell::RefCell::new(0);
    Operator {
```

Prompt: continue the translation

```rust
        next: Box::new(move |tup: &mut Tuple| {
            *tups_count.borrow_mut() += 1;
            (next_op.next)(tup);
        }),
        reset: Box::new(move |tup: &mut Tuple| {
            writeln!(
                out,
                "{},{},{},{}",
                *epoch_count.borrow(),
                name,
                *tups_count.borrow(),
                static_field.unwrap_or("")
            )
            .expect("Error writing meta meter output");
            *tups_count.borrow_mut() = 0;
            *epoch_count.borrow_mut() += 1;
            (next_op.reset)(tup);
        }),
    }
}

// Passes tuples through to op
// Resets op every w seconds
// Adds epoch id to tuple under key_out
pub fn epoch_op(epoch_width: f64, key_out: &str, next_op: Operator) -> Operator {
    let epoch_boundary = std::cell::RefCell::new(0.0);
    let eid = std::cell::RefCell::new(0);
    Operator {
        next: Box::new(move |tup: &mut Tuple| {
            let time = float_of_op_result(tup.get("time").expect("Tuple missing 'time' key"));
            if *epoch_boundary.borrow() == 0.0 {
                *epoch_boundary.borrow_mut() = time + epoch_width;
            } else if time >= *epoch_boundary.borrow() {
                while time >= *epoch_boundary.borrow() {
                    let mut reset_tup = HashMap::new();
                    reset_tup.insert(key_out.to_string(), OpResult::Int(*eid.borrow()));
                    (next_op.reset)(&mut reset_tup);
                    *epoch_boundary.borrow_mut() += epoch_width;
                    *eid.borrow_mut() += 1;
                }
            }
            tup.insert(key_out.to_string(), OpResult::Int(*eid.borrow()));
            (next_op.next)(tup);
        }),
        reset: Box::new(move |_tup: &mut Tuple| {
            let mut reset_tup = HashMap::new();
            reset_tup.insert(key_out.to_string(), OpResult::Int(*eid.borrow()));
            (next_op.reset)(&mut reset_tup);
            *epoch_boundary.borrow_mut() = 0.0;
            *eid.borrow_mut() = 0;
        }),
    }
}

// Passes only tuples where f applied to the tuple returns true
// Creates a filtering operator, applying the given operator if this one
// returns true otherwise returning false
pub fn filter_op<F>(f: F, next_op: Operator) -> Operator
where
    F: Fn(&Tuple) -> bool + 'static,
{
    Operator {
        next: Box::new(move |tup: &mut Tuple| {
            if f(tup) {
                (next_op.next)(tup);
            }
        }),
        reset: Box::new(move |tup: &mut Tuple| {
            (next_op.reset)(tup);
        }),
    }
}

// (filter utility)
// Comparison function for testing int values against a threshold
pub fn key_geq_int(key: &str, threshold: i64, tup: &Tuple) -> bool {
    lookup_int(key, tup) >= threshold
}

// (filter utility)
// Looks up the given key and converts to Int OpResult
// if the key does not hold an int, this will panic
pub fn get_mapped_int(key: &str, tup: &Tuple) -> i64 {
    lookup_int(key, tup)
}

// (filter utility)
// Looks up the given key and converts to Float OpResult
// if the key does not hold an int, this will panic
pub fn get_mapped_float(key: &str, tup: &Tuple) -> f64 {
    lookup_float(key, tup)
}

// Operator which applied the given function on all tuples
// Passes resets, unchanged
// Applies the given operator to the result of this operator applied to the
// Tuple
pub fn map_op<F>(f: F, next_op: Operator) -> Operator
where
    F: Fn(Tuple) -> Tuple + 'static,
{
    Operator {
        next: Box::new(move |tup: &mut Tuple| {
            let new_tup = f(tup.clone());
            *tup = new_tup;
            (next_op.next)(tup);
        }),
        reset: Box::new(move |tup: &mut Tuple| {
            (next_op.reset)(tup);
        }),
    }
}

pub type GroupingFunc = Box<dyn Fn(&Tuple) -> Tuple + 'static>;
pub type ReductionFunc = Box<dyn Fn(&OpResult, &Tuple) -> OpResult + 'static>;

// Groups the input Tuples according to canonic members returned by
//   key_extractor : Tuple -> Tuple
// Tuples in each group are folded (starting with Empty) by
//   accumulate : OpResult -> Tuple -> OpResult
// When reset, op is passed a Tuple for each group containing the union of
//   (i) the reset argument tuple,
//   (ii) the result of g for that group, and
//   (iii) a mapping from out_key to the result of the fold for that group
pub fn groupby_op(
    groupby: GroupingFunc,
    reduce: ReductionFunc,
    out_key: &str,
    next_op: Operator,
) -> Operator {
    let h_tbl: std::cell::RefCell<HashMap<Tuple, OpResult>> =
        std::cell::RefCell::new(HashMap::with_capacity(INIT_TABLE_SIZE));
    let reset_counter = std::cell::RefCell::new(0);
    Operator {
        next: Box::new(move |tup: &mut Tuple| {
            let grouping_key = groupby(tup);
            let mut table = h_tbl.borrow_mut();
            let current_val = table.get(&grouping_key).cloned().unwrap_or(OpResult::Empty);
            table.insert(grouping_key, reduce(&current_val, tup));
        }),
        reset: Box::new(move |tup: &mut Tuple| {
            *reset_counter.borrow_mut() += 1;
            for (grouping_key, val) in h_tbl.borrow().iter() {
                let mut unioned_tup = tup.clone();
                for (key, value) in grouping_key.iter() {
                    unioned_tup.insert(key.clone(), value.clone());
                }
                unioned_tup.insert(out_key.to_string(), val.clone());
                (next_op.next)(&mut unioned_tup);
            }
            (next_op.reset)(tup);
            h_tbl.borrow_mut().clear();
        }),
    }
}

// (groupby utility : key_extractor)
// Returns a new tuple with only the keys included in the incl_keys list
pub fn filter_groups(incl_keys: &[&str], tup: &Tuple) -> Tuple {
    tup.iter()
        .filter(|(key, _)| incl_keys.contains(&key.as_str()))
        .map(|(key, val)| (key.clone(), val.clone()))
        .collect()
}

// (groupby utility : key_extractor)
// Grouping function (key_extractor) that forms a single group
pub fn single_group(_: &Tuple) -> Tuple {
    HashMap::new()
}

// (groupby utility : grouping_mech)
// Reduction function (f) to count tuples
pub fn counter(val: &OpResult, _: &Tuple) -> OpResult {
    match val {
        OpResult::Empty => OpResult::Int(1),
        OpResult::Int(i) => OpResult::Int(i + 1),
        _ => val.clone(),
    }
}

// (groupby utility)
// Reduction function (f) to sum values (assumed to be Int ()) of a given field
pub fn sum_ints(search_key: &str, init_val: &OpResult, tup: &Tuple) -> OpResult {
    match init_val {
        OpResult::Empty => OpResult::Int(0),
        OpResult::Int(i) => {
            match tup.get(search_key) {
                Some(OpResult::Int(n)) => OpResult::Int(n + i),
                _ => panic!(
                    "'sum_vals' function failed to find integer value mapped to \"{}\"",
                    search_key
                ),
            }
        }
        _ => init_val.clone(),
    }
}

// Returns a list of distinct elements (as determined by group_tup) each epoch
// removes duplicate Tuples based on group_tup
pub fn distinct_op(groupby: GroupingFunc, next_op: Operator) -> Operator {
    let h_tbl: std::cell::RefCell<HashMap<Tuple, bool>> =
        std::cell::RefCell::new(HashMap::with_capacity(INIT_TABLE_SIZE));
    let reset_counter = std::cell::RefCell::new(0);
    Operator {
        next: Box::new(move |tup: &mut Tuple| {
            let grouping_key = groupby(tup);
            h_tbl.borrow_mut().insert(grouping_key, true);
        }),
        reset: Box::new(move |tup: &mut Tuple| {
            *reset_counter.borrow_mut() += 1;
            for key in h_tbl.borrow().keys() {
                let mut merged_tup = tup.clone();
                for (k, v) in key.iter() {
                    merged_tup.insert(k.clone(), v.clone());
                }
                (next_op.next)(&mut merged_tup);
            }
            (next_op.reset)(tup);
            h_tbl.borrow_mut().clear();
        }),
    }
}

// Just sends both next and reset directly to two different downstream operators
// i.e. splits the stream processing in two
pub fn split_op(l: Operator, r: Operator) -> Operator {
    Operator {
        next: Box::new(move |tup: &mut Tuple| {
            let mut tup_clone_l = tup.clone();
            let mut tup_clone_r = tup.clone();
            (l.next)(&mut tup_clone_l);
            (r.next)(&mut tup_clone_r);
        }),
        reset: Box::new(move |tup: &mut Tuple| {
            let mut tup_clone_l = tup.clone();
            let mut tup_clone_r = tup.clone();
            (l.reset)(&mut tup_clone_l);
            (r.reset)(&mut tup_clone_r);
        }),
    }
}

pub type KeyExtractor = Box<dyn Fn(&Tuple) -> (Tuple, Tuple) + 'static>;

// Initial shot at a join semantic that doesn't require maintaining entire state
// Functions left and right transform input tuples into a key,value pair of tuples
// The key determines a canonical tuple against which the other stream will match
// The value determines extra fields which should be saved and added when a
// match is made
//
// Requires tuples to have epoch id as int value in field referenced by eid_key.
pub fn join_op(
    eid_key: &'static str,
    left_extractor: KeyExtractor,
    right_extractor: KeyExtractor,
    next_op: Operator,
) -> (Operator, Operator) {
    let h_tbl1: std::cell::RefCell<HashMap<Tuple, Tuple>> =
        std::cell::RefCell::new(HashMap::with_capacity(INIT_TABLE_SIZE));
    let h_tbl2: std::cell::RefCell<HashMap<Tuple, Tuple>> =
        std::cell::RefCell::new(HashMap::with_capacity(INIT_TABLE_SIZE));
    let left_curr_epoch = std::cell::RefCell::new(0);
    let right_curr_epoch = std::cell::RefCell::new(0);

    let handle_join_side = |curr_h_tble: &std::cell::RefCell<HashMap<Tuple, Tuple>>,
                            other_h_tbl: &std::cell::RefCell<HashMap<Tuple, Tuple>>,
                            curr_epoch_ref: &std::cell::RefCell<i64>,
                            other_epoch_ref: &std::cell::RefCell<i64>,
                            f: KeyExtractor| {
        Operator {
            next: Box::new(move |tup: &mut Tuple| {
                let (key, vals_) = f(tup);
                let curr_epoch = get_mapped_int(eid_key, tup);

                while curr_epoch > *curr_epoch_ref.borrow() {
                    if *other_epoch_ref.borrow() > *curr_epoch_ref.borrow() {
                        let mut reset_tup = HashMap::new();
                        reset_tup.insert(eid_key.to_string(), OpResult::Int(*curr_epoch_ref.borrow()));
                        (next_op.reset)(&mut reset_tup);
                    }
                    *curr_epoch_ref.borrow_mut() += 1;
                }
                let mut new_tup = key.clone();
                new_tup.insert(eid_key.to_string(), OpResult::Int(curr_epoch));

                if let Some(val_) = other_h_tbl.borrow_mut().remove(&new_tup) {
                    let mut use_left = |_: &String, a: &OpResult, _: &OpResult| Some(a.clone());
                    let mut merged = new_tup.clone();
                    for (k, v) in vals_.iter() {
                        merged.insert(k.clone(), v.clone());
                    }
                    for (k, v) in val_.iter() {
                        merged.insert(k.clone(), v.clone());
                    }
                    (next_op.next)(&mut merged);
                } else {
                    curr_h_tble.borrow_mut().insert(new_tup, vals_);
                }
            }),
            reset: Box::new(move |tup: &mut Tuple| {
                let curr_epoch = get_mapped_int(eid_key, tup);
                while curr_epoch > *curr_epoch_ref.borrow() {
                    if *other_epoch_ref.borrow() > *curr_epoch_ref.borrow() {
                        let mut reset_tup = HashMap::new();
                        reset_tup.insert(eid_key.to_string(), OpResult::Int(*curr_epoch_ref.borrow()));
                        (next_op.reset)(&mut reset_tup);
                    }
                    *curr_epoch_ref.borrow_mut() += 1;
                }
            }),
        }
    };

    (
        handle_join_side(&h_tbl1, &h_tbl2, &left_curr_epoch, &right_curr_epoch, left_extractor),
        handle_join_side(&h_tbl2, &h_tbl1, &right_curr_epoch, &left_curr_epoch, right_extractor),
    )
}

// (join utility)
// Returns a new tuple with only the keys included in the first of each pair in
// keys
// These keys are renamed to the second of each pair in keys
// Use in conjunction with the join implementation above to get the "join left
// with right on left.x = right.y" kind of thing
pub fn rename_filtered_keys(renamings_pairs: &[(&str, &str)], in_tup: &Tuple) -> Tuple {
    let mut new_tup = HashMap::new();
    for &(old_key, new_key) in renamings_pairs {
        if let Some(val_) = in_tup.get(old_key) {
            new_tup.insert(new_key.to_string(), val_.clone());
        }
    }
    new_tup
}

// Main entry point and implementation for simple header-dump operation

// See builtins.ml for definitions of building blocks used here
// '@=>' is just a right-associative application to avoid nasty nested parens

// Counts total number of packets observed in an epoch
pub fn ident_op(next_op: Operator) -> Operator {
    op_chain(
        Box::new(|op| {
            map_op(
                |tup| {
                    tup.into_iter()
                        .filter(|(key, _)| key != "eth.src" && key != "eth.dst")
                        .collect()
                },
                op,
            )
        }),
        next_op,
    )
}

// Assigns each tuple an epoch ID based on time by adding an eid key, counts
// the number of tuples in each epoch, then passes the processed tuples to the
// next_op
pub fn count_pkts_op(next_op: Operator) -> Operator {
```

prompt: continue the translation

```rust
    op_chain(
        Box::new(|op| {
            op_chain(
                Box::new(|op2| groupby_op(Box::new(single_group), Box::new(counter), "pkts", op2)),
                epoch_op(1.0, "eid", op),
            )
        }),
        next_op,
    )
}

// Assigns each tuple an epoch ID based on time by adding an eid key, groups
// them by source and dest ip, counts and stores the number of tuples in each
// group, and passes result to next_op
pub fn pkts_per_src_dst_op(next_op: Operator) -> Operator {
    op_chain(
        Box::new(|op| {
            op_chain(
                Box::new(|op2| {
                    groupby_op(
                        Box::new(|tup| filter_groups(&["ipv4.src", "ipv4.dst"], tup)),
                        Box::new(counter),
                        "pkts",
                        op2,
                    )
                }),
                epoch_op(1.0, "eid", op),
            )
        }),
        next_op,
    )
}

pub fn distinct_srcs_op(next_op: Operator) -> Operator {
    op_chain(
        Box::new(|op| {
            op_chain(
                Box::new(|op2| {
                    op_chain(
                        Box::new(|op3| groupby_op(Box::new(single_group), Box::new(counter), "srcs", op3)),
                        distinct_op(Box::new(|tup| filter_groups(&["ipv4.src"], tup)), op2),
                    )
                }),
                epoch_op(1.0, "eid", op),
            )
        }),
        next_op,
    )
}

// Sonata 1
pub fn tcp_new_cons_op(next_op: Operator) -> Operator {
    let threshold: i64 = 40;
    op_chain(
        Box::new(|op| {
            op_chain(
                Box::new(|op2| {
                    op_chain(
                        Box::new(|op3| {
                            filter_op(Box::new(move |tup| key_geq_int("cons", threshold, tup)), op3)
                        }),
                        groupby_op(
                            Box::new(|tup| filter_groups(&["ipv4.dst"], tup)),
                            Box::new(counter),
                            "cons",
                            op2,
                        ),
                    )
                }),
                filter_op(
                    Box::new(|tup| get_mapped_int("ipv4.proto", tup) == 6 && get_mapped_int("l4.flags", tup) == 2),
                    op,
                ),
            )
        }),
        epoch_op(1.0, "eid", next_op),
    )
}

// Sonata 2
pub fn ssh_brute_force_op(next_op: Operator) -> Operator {
    let threshold: i64 = 40;
    op_chain(
        Box::new(|op| {
            op_chain(
                Box::new(|op2| {
                    op_chain(
                        Box::new(|op3| {
                            filter_op(Box::new(move |tup| key_geq_int("srcs", threshold, tup)), op3)
                        }),
                        groupby_op(
                            Box::new(|tup| filter_groups(&["ipv4.dst", "ipv4.len"], tup)),
                            Box::new(counter),
                            "srcs",
                            op2,
                        ),
                    )
                }),
                distinct_op(
                    Box::new(|tup| filter_groups(&["ipv4.src", "ipv4.dst", "ipv4.len"], tup)),
                    filter_op(
                        Box::new(|tup| get_mapped_int("ipv4.proto", tup) == 6 && get_mapped_int("l4.dport", tup) == 22),
                        op,
                    ),
                ),
            )
        }),
        epoch_op(1.0, "eid", next_op), // might need to elongate epoch for this one...
    )
}

// Sonata 3
pub fn super_spreader_op(next_op: Operator) -> Operator {
    let threshold: i64 = 40;
    op_chain(
        Box::new(|op| {
            op_chain(
                Box::new(|op2| {
                    op_chain(
                        Box::new(|op3| {
                            filter_op(Box::new(move |tup| key_geq_int("dsts", threshold, tup)), op3)
                        }),
                        groupby_op(
                            Box::new(|tup| filter_groups(&["ipv4.src"], tup)),
                            Box::new(counter),
                            "dsts",
                            op2,
                        ),
                    )
                }),
                distinct_op(Box::new(|tup| filter_groups(&["ipv4.src", "ipv4.dst"], tup)), op),
            )
        }),
        epoch_op(1.0, "eid", next_op),
    )
}

// Sonata 4
pub fn port_scan_op(next_op: Operator) -> Operator {
    let threshold: i64 = 40;
    op_chain(
        Box::new(|op| {
            op_chain(
                Box::new(|op2| {
                    op_chain(
                        Box::new(|op3| {
                            filter_op(Box::new(move |tup| key_geq_int("ports", threshold, tup)), op3)
                        }),
                        groupby_op(
                            Box::new(|tup| filter_groups(&["ipv4.src"], tup)),
                            Box::new(counter),
                            "ports",
                            op2,
                        ),
                    )
                }),
                distinct_op(Box::new(|tup| filter_groups(&["ipv4.src", "l4.dport"], tup)), op),
            )
        }),
        epoch_op(1.0, "eid", next_op),
    )
}

// Sonata 5
pub fn ddos_op(next_op: Operator) -> Operator {
    let threshold: i64 = 45;
    op_chain(
        Box::new(|op| {
            op_chain(
                Box::new(|op2| {
                    op_chain(
                        Box::new(|op3| {
                            filter_op(Box::new(move |tup| key_geq_int("srcs", threshold, tup)), op3)
                        }),
                        groupby_op(
                            Box::new(|tup| filter_groups(&["ipv4.dst"], tup)),
                            Box::new(counter),
                            "srcs",
                            op2,
                        ),
                    )
                }),
                distinct_op(Box::new(|tup| filter_groups(&["ipv4.src", "ipv4.dst"], tup)), op),
            )
        }),
        epoch_op(1.0, "eid", next_op),
    )
}

// Sonata 6 --- Note this implements the Sonata semantic of this query
// *NOT* the intended semantic from NetQRE
pub fn syn_flood_sonata_op(next_op: Operator) -> Vec<Operator> {
    let threshold: i64 = 3;
    let epoch_dur: f64 = 1.0;

    let syns_op = |next: Operator| {
        op_chain(
            Box::new(|op| {
                op_chain(
                    Box::new(|op2| {
                        groupby_op(
                            Box::new(|tup| filter_groups(&["ipv4.dst"], tup)),
                            Box::new(counter),
                            "syns",
                            op2,
                        )
                    }),
                    filter_op(
                        Box::new(|tup| get_mapped_int("ipv4.proto", tup) == 6 && get_mapped_int("l4.flags", tup) == 2),
                        op,
                    ),
                )
            }),
            epoch_op(epoch_dur, "eid", next),
        )
    };

    let synacks_op = |next: Operator| {
        op_chain(
            Box::new(|op| {
                op_chain(
                    Box::new(|op2| {
                        groupby_op(
                            Box::new(|tup| filter_groups(&["ipv4.src"], tup)),
                            Box::new(counter),
                            "synacks",
                            op2,
                        )
                    }),
                    filter_op(
                        Box::new(|tup| get_mapped_int("ipv4.proto", tup) == 6 && get_mapped_int("l4.flags", tup) == 18),
                        op,
                    ),
                )
            }),
            epoch_op(epoch_dur, "eid", next),
        )
    };

    let acks_op = |next: Operator| {
        op_chain(
            Box::new(|op| {
                op_chain(
                    Box::new(|op2| {
                        groupby_op(
                            Box::new(|tup| filter_groups(&["ipv4.dst"], tup)),
                            Box::new(counter),
                            "acks",
                            op2,
                        )
                    }),
                    filter_op(
                        Box::new(|tup| get_mapped_int("ipv4.proto", tup) == 6 && get_mapped_int("l4.flags", tup) == 16),
                        op,
                    ),
                )
            }),
            epoch_op(epoch_dur, "eid", next),
        )
    };

    let (join_op1, join_op2) = dbl_op_chain(
        Box::new(|op| {
            op_chain(
                Box::new(|op2| {
                    filter_op(
                        Box::new(move |tup| key_geq_int("syns+synacks-acks", threshold, tup)),
                        map_op(
                            |mut tup| {
                                let syns_synacks = get_mapped_int("syns+synacks", &tup);
                                let acks = get_mapped_int("acks", &tup);
                                tup.insert("syns+synacks-acks".to_string(), OpResult::Int(syns_synacks - acks));
                                tup
                            },
                            op2,
                        ),
                    )
                }),
                join_op(
                    "eid",
                    Box::new(|tup| (filter_groups(&["host"], tup), filter_groups(&["syns+synacks"], tup))),
                    Box::new(|tup| (rename_filtered_keys(&[("ipv4.dst", "host")], tup), filter_groups(&["acks"], tup))),
                    op,
                ),
            )
        }),
        next_op,
    );

    let (join_op3, join_op4) = dbl_op_chain(
        Box::new(|op| {
            map_op(
                |mut tup| {
                    let syns = get_mapped_int("syns", &tup);
                    let synacks = get_mapped_int("synacks", &tup);
                    tup.insert("syns+synacks".to_string(), OpResult::Int(syns + synacks));
                    tup
                },
                op,
            )
        }),
        join_op(
            "eid",
            Box::new(|tup| (rename_filtered_keys(&[("ipv4.dst", "host")], tup), filter_groups(&["syns"], tup))),
            Box::new(|tup| (rename_filtered_keys(&[("ipv4.src", "host")], tup), filter_groups(&["synacks"], tup))),
            join_op1,
        ),
    );

    vec![syns_op(join_op3), synacks_op(join_op4), acks_op(join_op2)]
}

// Sonata 7
pub fn completed_flows_op(next_op: Operator) -> Vec<Operator> {
    let threshold: i64 = 1;
    let epoch_dur: f64 = 30.0;

    let syns_op = |next: Operator| {
        op_chain(
            Box::new(|op| {
                op_chain(
                    Box::new(|op2| {
                        groupby_op(
                            Box::new(|tup| filter_groups(&["ipv4.dst"], tup)),
                            Box::new(counter),
                            "syns",
                            op2,
                        )
                    }),
                    filter_op(
                        Box::new(|tup| get_mapped_int("ipv4.proto", tup) == 6 && get_mapped_int("l4.flags", tup) == 2),
                        op,
                    ),
                )
            }),
            epoch_op(epoch_dur, "eid", next),
        )
    };

    let fins_op = |next: Operator| {
        op_chain(
            Box::new(|op| {
                op_chain(
                    Box::new(|op2| {
                        groupby_op(
                            Box::new(|tup| filter_groups(&["ipv4.src"], tup)),
                            Box::new(counter),
                            "fins",
                            op2,
                        )
                    }),
                    filter_op(
                        Box::new(|tup| get_mapped_int("ipv4.proto", tup) == 6 && (get_mapped_int("l4.flags", tup) & 1) == 1),
                        op,
                    ),
                )
            }),
            epoch_op(epoch_dur, "eid", next),
        )
    };

    let (op1, op2) = dbl_op_chain(
        Box::new(|op| {
            op_chain(
                Box::new(|op2| {
                    filter_op(
                        Box::new(move |tup| key_geq_int("diff", threshold, tup)),
                        map_op(
                            |mut tup| {
                                let syns = get_mapped_int("syns", &tup);
                                let fins = get_mapped_int("fins", &tup);
                                tup.insert("diff".to_string(), OpResult::Int(syns - fins));
                                tup
                            },
                            op2,
                        ),
                    )
                }),
                join_op(
                    "eid",
                    Box::new(|tup| (rename_filtered_keys(&[("ipv4.dst", "host")], tup), filter_groups(&["syns"], tup))),
                    Box::new(|tup| (rename_filtered_keys(&[("ipv4.src", "host")], tup), filter_groups(&["fins"], tup))),
                    op,
                ),
            )
        }),
        next_op,
    );

    vec![syns_op(op1), fins_op(op2)]
}

// Sonata 8
pub fn slowloris_op(next_op: Operator) -> Vec<Operator> {
    let t1: i64 = 5;
    let t2: i64 = 500;
    let t3: i64 = 90;
    let epoch_dur: f64 = 1.0;

    let n_conns_op = |next: Operator| {
        op_chain(
            Box::new(|op| {
                op_chain(
                    Box::new(|op2| {
                        op_chain(
                            Box::new(|op3| {
                                filter_op(Box::new(move |tup| get_mapped_int("n_conns", tup) >= t1), op3)
                            }),
                            groupby_op(
                                Box::new(|tup| filter_groups(&["ipv4.dst"], tup)),
                                Box::new(counter),
                                "n_conns",
                                op2,
                            ),
                        )
                    }),
                    distinct_op(
                        Box::new(|tup| filter_groups(&["ipv4.src", "ipv4.dst", "l4.sport"], tup)),
                        filter_op(Box::new(|tup| get_mapped_int("ipv4.proto", tup) == 6), op),
                    ),
                )
            }),
            epoch_op(epoch_dur, "eid", next),
        )
    };

    let n_bytes_op = |next: Operator| {
        op_chain(
            Box::new(|op| {
                op_chain(
                    Box::new(|op2| {
                        filter_op(Box::new(move |tup| get_mapped_int("n_bytes", tup) >= t2), op2)
                    }),
                    groupby_op(
                        Box::new(|tup| filter_groups(&["ipv4.dst"], tup)),
                        Box::new(|acc, tup| sum_ints("ipv4.len", acc, tup)),
                        "n_bytes",
                        op,
                    ),
                )
            }),
            epoch_op(epoch
```

prompt: continue the translation

```rust
epoch_dur, "eid", next),
        )
    };

    let (op1, op2) = dbl_op_chain(
        Box::new(|op| {
            op_chain(
                Box::new(|op2| {
                    filter_op(
                        Box::new(move |tup| get_mapped_int("bytes_per_conn", tup) <= t3),
                        map_op(
                            |mut tup| {
                                let n_bytes = get_mapped_int("n_bytes", &tup);
                                let n_conns = get_mapped_int("n_conns", &tup);
                                tup.insert("bytes_per_conn".to_string(), OpResult::Int(n_bytes / n_conns));
                                tup
                            },
                            op2,
                        ),
                    )
                }),
                join_op(
                    "eid",
                    Box::new(|tup| (filter_groups(&["ipv4.dst"], tup), filter_groups(&["n_conns"], tup))),
                    Box::new(|tup| (filter_groups(&["ipv4.dst"], tup), filter_groups(&["n_bytes"], tup))),
                    op,
                ),
            )
        }),
        next_op,
    );

    vec![n_conns_op(op1), n_bytes_op(op2)]
}

pub fn join_test_op(next_op: Operator) -> Vec<Operator> {
    let epoch_dur: f64 = 1.0;

    let syns_op = |next: Operator| {
        op_chain(
            Box::new(|op| {
                filter_op(
                    Box::new(|tup| get_mapped_int("ipv4.proto", tup) == 6 && get_mapped_int("l4.flags", tup) == 2),
                    op,
                )
            }),
            epoch_op(epoch_dur, "eid", next),
        )
    };

    let synacks_op = |next: Operator| {
        op_chain(
            Box::new(|op| {
                filter_op(
                    Box::new(|tup| get_mapped_int("ipv4.proto", tup) == 6 && get_mapped_int("l4.flags", tup) == 18),
                    op,
                )
            }),
            epoch_op(epoch_dur, "eid", next),
        )
    };

    let (op1, op2) = dbl_op_chain(
        Box::new(|op| {
            join_op(
                "eid",
                Box::new(|tup| (rename_filtered_keys(&[("ipv4.src", "host")], tup), rename_filtered_keys(&[("ipv4.dst", "remote")], tup))),
                Box::new(|tup| (rename_filtered_keys(&[("ipv4.dst", "host")], tup), filter_groups(&["time"], tup))),
                op,
            )
        }),
        next_op,
    );

    vec![syns_op(op1), synacks_op(op2)]
}

pub fn q3_op(next_op: Operator) -> Operator {
    op_chain(
        Box::new(|op| {
            distinct_op(
                Box::new(|tup| filter_groups(&["ipv4.src", "ipv4.dst"], tup)),
                op,
            )
        }),
        epoch_op(100.0, "eid", next_op),
    )
}

pub fn q4_op(next_op: Operator) -> Operator {
    op_chain(
        Box::new(|op| {
            groupby_op(
                Box::new(|tup| filter_groups(&["ipv4.dst"], tup)),
                Box::new(counter),
                "pkts",
                op,
            )
        }),
        epoch_op(10000.0, "eid", next_op),
    )
}

pub fn get_queries() -> Vec<Operator> {
    let mut stdout = std::io::stdout();
    vec![op_chain(Box::new(ident_op), dump_tuple_op(false, &mut stdout))]
}

pub fn run_queries() {
    let queries = get_queries();
    for i in 0..20 {
        let mut initial_tuple: Tuple = HashMap::new();
        initial_tuple.insert("time".to_string(), OpResult::Float(0.000000 + i as f64));
        initial_tuple.insert("eth.src".to_string(), OpResult::MAC(vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55]));
        initial_tuple.insert("eth.dst".to_string(), OpResult::MAC(vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]));
        initial_tuple.insert("eth.ethertype".to_string(), OpResult::Int(0x0800));
        initial_tuple.insert("ipv4.hlen".to_string(), OpResult::Int(20));
        initial_tuple.insert("ipv4.proto".to_string(), OpResult::Int(6));
        initial_tuple.insert("ipv4.len".to_string(), OpResult::Int(60));
        initial_tuple.insert("ipv4.src".to_string(), OpResult::IPv4("127.0.0.1".parse().unwrap()));
        initial_tuple.insert("ipv4.dst".to_string(), OpResult::IPv4("127.0.0.1".parse().unwrap()));
        initial_tuple.insert("l4.sport".to_string(), OpResult::Int(440));
        initial_tuple.insert("l4.dport".to_string(), OpResult::Int(50000));
        initial_tuple.insert("l4.flags".to_string(), OpResult::Int(10));

        for query in &queries {
            let mut tuple_clone = initial_tuple.clone();
            (query.next)(&mut tuple_clone);
        }
    }
}

fn main() {
    run_queries();
    println!("Done");
}
```