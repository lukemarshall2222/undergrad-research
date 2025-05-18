Prompt: Base prompt

Translating the provided OCaml code to Rust requires careful consideration of the language's differences, particularly in handling types, memory management, and functional programming patterns. Below is the Rust translation, maintaining the core functionality of the OCaml code, including the data processing pipeline for network data analysis. The translation uses Rust's type system, ownership model, and standard library to replicate the OCaml behavior, with adjustments for Rust's stricter safety guarantees.

Key considerations in the translation:
- **Type System**: OCaml's variant types (`op_result`) are translated to Rust enums. OCaml's record types (`operator`) become Rust structs.
- **Maps**: OCaml's `Map.Make(String)` is replaced with Rust's `HashMap<String, _>`.
- **Functional Constructs**: OCaml's functional operators like `@=>` are implemented using Rust closures and function composition.
- **Error Handling**: OCaml's exceptions are replaced with Rust's `Result` and `Option` types where appropriate.
- **I/O**: File operations are handled with Rust's `std::fs` and `std::io`.
- **Dependencies**: The `ipaddr` crate is used to handle IP addresses, analogous to OCaml's `Ipaddr.V4`. MAC addresses are handled as byte arrays.
- **Thread Safety**: Rust enforces strict ownership, so some OCaml patterns (e.g., mutable references in closures) are adjusted to use `RefCell` or `Rc` where necessary.

The translated code is provided in a single Rust source file, assuming the use of the `ipaddr` crate for IP address handling. The structure mirrors the original OCaml code, with modules, types, and functions organized similarly.

```rust
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::rc::Rc;
use std::cell::RefCell;
use ipaddr::IpAddrV4;

// Enum to represent op_result variant type
#[derive(Clone, Debug, PartialEq)]
enum OpResult {
    Float(f64),
    Int(i32),
    IPv4(IpAddrV4),
    MAC([u8; 6]),
    Empty,
}

// Type alias for Tuple (HashMap<String, OpResult>)
type Tuple = HashMap<String, OpResult>;

// Struct to represent operator
#[derive(Clone)]
struct Operator {
    next: Rc<dyn Fn(&Tuple)>,
    reset: Rc<dyn Fn(&Tuple)>,
}

// Type aliases for operator creators
type OpCreator = fn(Operator) -> Operator;
type DblOpCreator = fn(Operator) -> (Operator, Operator);

// Chaining operator @=>
fn chain_op(op_creator: OpCreator, next_op: Operator) -> Operator {
    op_creator(next_op)
}

// Double chaining operator @==>
fn chain_dbl_op(op_creator: DblOpCreator, op: Operator) -> (Operator, Operator) {
    op_creator(op)
}

// Conversion utilities

// Format MAC address as colon-separated hex string
fn string_of_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

// Convert TCP flags to human-readable string
fn tcp_flags_to_strings(flags: i32) -> String {
    let tcp_flags = vec![
        ("FIN", 1 << 0),
        ("SYN", 1 << 1),
        ("RST", 1 << 2),
        ("PSH", 1 << 3),
        ("ACK", 1 << 4),
        ("URG", 1 << 5),
        ("ECE", 1 << 6),
        ("CWR", 1 << 7),
    ];
    let mut result = String::new();
    for (name, value) in tcp_flags {
        if flags & value == value {
            if !result.is_empty() {
                result.push('|');
            }
            result.push_str(name);
        }
    }
    result
}

// Extract int from OpResult
fn int_of_op_result(input: &OpResult) -> Result<i32, String> {
    match input {
        OpResult::Int(i) => Ok(*i),
        _ => Err("Trying to extract int from non-int result".to_string()),
    }
}

// Extract float from OpResult
fn float_of_op_result(input: &OpResult) -> Result<f64, String> {
    match input {
        OpResult::Float(f) => Ok(*f),
        _ => Err("Trying to extract float from non-float result".to_string()),
    }
}

// Convert OpResult to string
fn string_of_op_result(input: &OpResult) -> String {
    match input {
        OpResult::Float(f) => format!("{}", f),
        OpResult::Int(i) => i.to_string(),
        OpResult::IPv4(ip) => ip.to_string(),
        OpResult::MAC(m) => string_of_mac(m),
        OpResult::Empty => "Empty".to_string(),
    }
}

// Convert Tuple to string
fn string_of_tuple(input: &Tuple) -> String {
    let mut result = String::new();
    for (key, value) in input {
        result.push_str(&format!("\"{}\" => {}, ", key, string_of_op_result(value)));
    }
    result
}

// Create Tuple from list of key-value pairs
fn tuple_of_list(tup_list: Vec<(String, OpResult)>) -> Tuple {
    tup_list.into_iter().collect()
}

// Dump Tuple to output
fn dump_tuple(out: &mut dyn Write, tup: &Tuple) -> io::Result<()> {
    writeln!(out, "{}", string_of_tuple(tup))
}

// Lookup int from Tuple
fn lookup_int(key: &str, tup: &Tuple) -> Result<i32, String> {
    int_of_op_result(tup.get(key).ok_or_else(|| format!("Key {} not found", key))?)
}

// Lookup float from Tuple
fn lookup_float(key: &str, tup: &Tuple) -> Result<f64, String> {
    float_of_op_result(tup.get(key).ok_or_else(|| format!("Key {} not found", key))?)
}

// Built-in operator definitions

const INIT_TABLE_SIZE: usize = 10000;

// Dump all fields of all tuples
fn dump_tuple_op(show_reset: bool, mut out: Box<dyn Write>) -> Operator {
    Operator {
        next: Rc::new(move |tup| {
            let _ = dump_tuple(&mut *out, tup);
        }),
        reset: Rc::new(move |tup| {
            if show_reset {
                let _ = dump_tuple(&mut *out, tup);
                let _ = writeln!(&mut *out, "[reset]");
            }
        }),
    }
}

// Dump as CSV
fn dump_as_csv(static_field: Option<(String, String)>, header: bool, mut out: Box<dyn Write>) -> Operator {
    let first = Rc::new(RefCell::new(header));
    Operator {
        next: Rc::new(move |tup| {
            let mut first_borrow = first.borrow_mut();
            if *first_borrow {
                if let Some((key, _)) = &static_field {
                    let _ = write!(&mut *out, "{},", key);
                }
                for key in tup.keys() {
                    let _ = write!(&mut *out, "{},", key);
                }
                let _ = writeln!(&mut *out);
                *first_borrow = false;
            }
            if let Some((_, value)) = &static_field {
                let _ = write!(&mut *out, "{},", value);
            }
            for value in tup.values() {
                let _ = write!(&mut *out, "{},", string_of_op_result(value));
            }
            let _ = writeln!(&mut *out);
        }),
        reset: Rc::new(|_| {}),
    }
}

// Dump Walt's CSV
fn dump_walts_csv(filename: String) -> Operator {
    let out = Rc::new(RefCell::new(Box::new(io::stdout()) as Box<dyn Write>));
    let first = Rc::new(RefCell::new(true));
    Operator {
        next: Rc::new(move |tup| {
            let mut first_borrow = first.borrow_mut();
            if *first_borrow {
                let file = File::create(&filename).expect("Failed to create file");
                *out.borrow_mut() = Box::new(file);
                *first_borrow = false;
            }
            let fields = [
                "src_ip", "dst_ip", "src_l4_port", "dst_l4_port",
                "packet_count", "byte_count", "epoch_id",
            ];
            let values: Vec<String> = fields.iter().map(|&key| {
                string_of_op_result(tup.get(key).expect("Missing key"))
            }).collect();
            let _ = writeln!(out.borrow_mut(), "{}", values.join(","));
        }),
        reset: Rc::new(|_| {}),
    }
}

// Parse IP or return zero
fn get_ip_or_zero(input: &str) -> OpResult {
    if input == "0" {
        OpResult::Int(0)
    } else {
        OpResult::IPv4(IpAddrV4::from_str(input).expect("Invalid IPv4"))
    }
}

// Read Walt's CSV
fn read_walts_csv(epoch_id_key: &str, file_names: Vec<String>, ops: Vec<Operator>) {
    let mut inchs_eids_tupcount: Vec<_> = file_names.into_iter().map(|filename| {
        let file = File::open(filename).expect("Failed to open file");
        let reader = BufReader::new(file);
        (reader, Rc::new(RefCell::new(0)), Rc::new(RefCell::new(0)))
    }).collect();
    let running = Rc::new(RefCell::new(ops.len() as i32));
    while *running.borrow() > 0 {
        for ((mut reader, eid, tup_count), op) in inchs_eids_tupcount.iter_mut().zip(ops.iter()) {
            let mut eid_borrow = eid.borrow_mut();
            if *eid_borrow >= 0 {
                let mut line = String::new();
                match reader.read_line(&mut line) {
                    Ok(0) => {
                        let mut tup = HashMap::new();
                        tup.insert(epoch_id_key.to_string(), OpResult::Int(*eid_borrow + 1));
                        tup.insert("tuples".to_string(), OpResult::Int(*tup_count.borrow()));
                        op.reset(&tup);
                        *running.borrow_mut() -= 1;
                        *eid_borrow = -1;
                    }
                    Ok(_) => {
                        let parts: Vec<&str> = line.trim().split(',').collect();
                        if parts.len() != 7 {
                            panic!("Invalid CSV line: {}", line);
                        }
                        let (src_ip, dst_ip, src_l4_port, dst_l4_port, packet_count, byte_count, epoch_id) = (
                            parts[0],
                            parts[1],
                            parts[2].parse::<i32>().expect("Invalid port"),
                            parts[3].parse::<i32>().expect("Invalid port"),
                            parts[4].parse::<i32>().expect("Invalid count"),
                            parts[5].parse::<i32>().expect("Invalid count"),
                            parts[6].parse::<i32>().expect("Invalid epoch"),
                        );
                        let mut p = HashMap::new();
                        p.insert("ipv4.src".to_string(), get_ip_or_zero(src_ip));
                        p.insert("ipv4.dst".to_string(), get_ip_or_zero(dst_ip));
                        p.insert("l4.sport".to_string(), OpResult::Int(src_l4_port));
                        p.insert("l4.dport".to_string(), OpResult::Int(dst_l4_port));
                        p.insert("packet_count".to_string(), OpResult::Int(packet_count));
                        p.insert("byte_count".to_string(), OpResult::Int(byte_count));
                        p.insert(epoch_id_key.to_string(), OpResult::Int(epoch_id));
                        let mut tup_count_borrow = tup_count.borrow_mut();
                        *tup_count_borrow += 1;
                        if epoch_id > *eid_borrow {
                            while epoch_id > *eid_borrow {
                                let mut reset_tup = HashMap::new();
                                reset_tup.insert(epoch_id_key.to_string(), OpResult::Int(*eid_borrow));
                                reset_tup.insert("tuples".to_string(), OpResult::Int(*tup_count_borrow));
                                op.reset(&reset_tup);
                                *tup_count_borrow = 0;
                                *eid_borrow += 1;
                            }
                        }
                        let mut final_tup = p;
                        final_tup.insert("tuples".to_string(), OpResult::Int(*tup_count_borrow));
                        op.next(&final_tup);
                    }
                    Err(e) => panic!("Failed to read line: {}", e),
                }
            }
        }
    }
    println!("Done.");
}

// Meta meter
fn meta_meter(static_field: Option<String>, name: String, mut out: Box<dyn Write>, next_op: Operator) -> Operator {
    let epoch_count = Rc::new(RefCell::new(0));
    let tups_count = Rc::new(RefCell::new(0));
    Operator {
        next: Rc::new(move |tup| {
            *tups_count.borrow_mut() += 1;
            next_op.next(tup);
        }),
        reset: Rc::new(move |tup| {
            let epoch = *epoch_count.borrow();
            let tups = *tups_count.borrow();
            let static_val = static_field.as_ref().map_or("", |v| v);
            let _ = writeln!(out, "{},{},{},{}", epoch, name, tups, static_val);
            *tups_count.borrow_mut() = 0;
            *epoch_count.borrow_mut() += 1;
            next_op.reset(tup);
        }),
    }
}

// Epoch operator
fn epoch(epoch_width: f64, key_out: String, next_op: Operator) -> Operator {
    let epoch_boundary = Rc::new(RefCell::new(0.0));
    let eid = Rc::new(RefCell::new(0));
    Operator {
        next: Rc::new(move |tup| {
            let time = float_of_op_result(tup.get("time").expect("Missing time")).expect("Invalid time");
            let mut boundary = epoch_boundary.borrow_mut();
            let mut eid_val = eid.borrow_mut();
            if *boundary == 0.0 {
                *boundary = time + epoch_width;
            } else if time >= *boundary {
                while time >= *boundary {
                    let mut reset_tup = HashMap::new();
                    reset_tup.insert(key_out.clone(), OpResult::Int(*eid_val));
                    next_op.reset(&reset_tup);
                    *boundary += epoch_width;
                    *eid_val += 1;
                }
            }
            let mut new_tup = tup.clone();
            new_tup.insert(key_out.clone(), OpResult::Int(*eid_val));
            next_op.next(&new_tup);
        }),
        reset: Rc::new(move |tup| {
            let mut boundary = epoch_boundary.borrow_mut();
            let mut eid_val = eid.borrow_mut();
            let mut reset_tup = HashMap::new();
            reset_tup.insert(key_out.clone(), OpResult::Int(*eid_val));
            next_op.reset(&reset_tup);
            *boundary = 0.0;
            *eid_val = 0;
        }),
    }
}

// Filter operator
fn filter(f: fn(&Tuple) -> bool, next_op: Operator) -> Operator {
    Operator {
        next: Rc::new(move |tup| {
            if f(tup) {
                next_op.next(tup);
            }
        }),
        reset: Rc::new(move |tup| next_op.reset(tup)),
    }
}

// Filter utility: key >= int
fn key_geq_int(key: String, threshold: i32) -> impl Fn(&Tuple) -> bool {
    move |tup| {
        lookup_int(&key, tup).map_or(false, |val| val >= threshold)
    }
}

// Get mapped int
fn get_mapped_int(key: &str, tup: &Tuple) -> i32 {
    lookup_int(key, tup).expect("Failed to get mapped int")
}

// Get mapped float
fn get_mapped_float(key: &str, tup: &Tuple) -> f64 {
    lookup_float(key, tup).expect("Failed to get mapped float")
}

// Map operator
fn map(f: fn(&Tuple) -> Tuple, next_op: Operator) -> Operator {
    Operator {
        next: Rc::new(move |tup| next_op.next(&f(tup))),
        reset: Rc::new(move |tup| next_op.reset(tup)),
    }
}

// Grouping and reduction function types
type GroupingFunc = fn(&Tuple) -> Tuple;
type ReductionFunc = fn(&OpResult, &Tuple) -> OpResult;

// Groupby operator
fn groupby(groupby: GroupingFunc, reduce: ReductionFunc, out_key: String, next_op: Operator) -> Operator {
    let h_tbl: Rc<RefCell<HashMap<Tuple, OpResult>>> = Rc::new(RefCell::new(HashMap::with_capacity(INIT_TABLE_SIZE)));
    let reset_counter = Rc::new(RefCell::new(0));
    Operator {
        next: Rc::new(move |tup| {
            let grouping_key = groupby(tup);
            let mut tbl = h_tbl.borrow_mut();
            let new_val = match tbl.get(&grouping_key) {
                Some(val) => reduce(val, tup),
                None => reduce(&OpResult::Empty, tup),
            };
            tbl.insert(grouping_key, new_val);
        }),
        reset: Rc::new(move |tup| {
            *reset_counter.borrow_mut() += 1;
            let tbl = h_tbl.borrow();
            for (grouping_key, val) in tbl.iter() {
                let mut unioned_tup = tup.clone();
                for (k, v) in grouping_key {
                    unioned_tup.insert(k.clone(), v.clone());
                }
                unioned_tup.insert(out_key.clone(), val.clone());
                next_op.next(&unioned_tup);
            }
            next_op.reset(tup);
            h_tbl.borrow_mut().clear();
        }),
    }
}

// Filter groups
fn filter_groups(incl_keys: Vec<String>) -> impl Fn(&Tuple) -> Tuple {
    move |tup| {
        let mut new_tup = HashMap::new();
        for key in &incl_keys {
            if let Some(val) = tup.get(key) {
                new_tup.insert(key.clone(), val.clone());
            }
        }
        new_tup
    }
}

// Single group
fn single_group(_: &Tuple) -> Tuple {
    HashMap::new()
}

// Counter reduction
fn counter(val: &OpResult, _: &Tuple) -> OpResult {
    match val {
        OpResult::Empty => OpResult::Int(1),
        OpResult::Int(i) => OpResult::Int(i + 1),
        _ => val.clone(),
    }
}

// Sum ints reduction
fn sum_ints(search_key: String) -> impl Fn(&OpResult, &Tuple) -> OpResult {
    move |init_val, tup| {
        match init_val {
            OpResult::Empty => OpResult::Int(0),
            OpResult::Int(i) => {
                match tup.get(&search_key) {
                    Some(OpResult::Int(n)) => OpResult::Int(n + i),
                    _ => panic!("sum_ints failed to find integer value for key {}", search_key),
                }
            }
            _ => init_val.clone(),
        }
    }
}

// Distinct operator
fn distinct(groupby: GroupingFunc, next_op: Operator) -> Operator {
    let h_tbl: Rc<RefCell<HashMap<Tuple, bool>>> = Rc::new(RefCell::new(HashMap::with_capacity(INIT_TABLE_SIZE)));
    let reset_counter = Rc::new(RefCell::new(0));
    Operator {
        next: Rc::new(move |tup| {
            let grouping_key = groupby(tup);
            h_tbl.borrow_mut().insert(grouping_key, true);
        }),
        reset: Rc::new(move |tup| {
            *reset_counter.borrow_mut() += 1;
            let tbl = h_tbl.borrow();
            for (key, _) in tbl.iter() {
                let mut merged_tup = tup.clone();
                for (k, v) in key {
                    merged_tup.insert(k.clone(), v.clone());
                }
                next_op.next(&merged_tup);
            }
            next_op.reset(tup);
            h_tbl.borrow_mut().clear();
        }),
    }
}

// Split operator
fn split(l: Operator, r: Operator) -> Operator {
    Operator {
        next: Rc::new(move |tup| {
            l.next(tup);
            r.next(tup);
        }),
        reset: Rc::new(move |tup| {
            l.reset(tup);
            r.reset(tup);
        }),
    }
}

// Key extractor type
type KeyExtractor = fn(&Tuple) -> (Tuple, Tuple);

// Join operator
fn join(eid_key: String, left_extractor: KeyExtractor, right_extractor: KeyExtractor, next_op: Operator) -> (Operator, Operator) {
    let h_tbl1: Rc<RefCell<HashMap<Tuple, Tuple>>> = Rc::new(RefCell::new(HashMap::with_capacity(INIT_TABLE_SIZE)));
    let h_tbl2: Rc<RefCell<HashMap<Tuple, Tuple>>> = Rc::new(RefCell::new(HashMap::with_capacity(INIT_TABLE_SIZE)));
    let left_curr_epoch = Rc::new(RefCell::new(0));
    let right_curr_epoch = Rc::new(RefCell::new(0));
    let handle_join_side = move |curr_h_tbl: Rc<RefCell<HashMap<Tuple, Tuple>>>, other_h_tbl: Rc<RefCell<HashMap<Tuple, Tuple>>>, curr_epoch_ref: Rc<RefCell<i32>>, other_epoch_ref: Rc<RefCell<i32>>, f: KeyExtractor| -> Operator {
        Operator {
            next: Rc::new(move |tup| {
                let (key, vals) = f(tup);
                let curr_epoch = get_mapped_int(&eid_key, tup);
                let mut curr_epoch_val = curr_epoch_ref.borrow_mut();
                let other_epoch_val = other_epoch_ref.borrow();
                while curr_epoch > *curr_epoch_val {
                    if *other_epoch_val > *curr_epoch_val {
                        let mut reset_tup = HashMap::new();
                        reset_tup.insert(eid_key.clone(), OpResult::Int(*curr_epoch_val));
                        next_op.reset(&reset_tup);
                    }
                    *curr_epoch_val += 1;
                }
                let mut new_tup = key.clone();
                new_tup.insert(eid_key.clone(), OpResult::Int(curr_epoch));
                let mut other_tbl = other_h_tbl.borrow_mut();
                if let Some(val) = other_tbl.remove(&new_tup) {
                    let mut final_tup = new_tup.clone();
                    for (k, v) in vals.iter().chain(val.iter()) {
                        final_tup.insert(k.clone(), v.clone());
                    }
                    next_op.next(&final_tup);
                } else {
                    curr_h_tbl.borrow_mut().insert(new_tup, vals);
                }
            }),
            reset: Rc::new(move |tup| {
                let curr_epoch = get_mapped_int(&eid_key, tup);
                let mut curr_epoch_val = curr_epoch_ref.borrow_mut();
                let other_epoch_val = other_epoch_ref.borrow();
                while curr_epoch > *curr_epoch_val {
                    if *other_epoch_val > *curr_epoch_val {
                        let mut reset_tup = HashMap::new();
                        reset_tup.insert(eid_key.clone(), OpResult::Int(*curr_epoch_val));
                        next_op.reset(&reset_tup);
                    }
                    *curr_epoch_val += 1;
                }
            }),
        }
    };
    (
        handle_join_side(h_tbl1.clone(), h_tbl2.clone(), left_curr_epoch.clone(), right_curr_epoch.clone(), left_extractor),
        handle_join_side(h_tbl2, h_tbl1, right_curr_epoch, left_curr_epoch, right_extractor),
    )
}

// Rename filtered keys
fn rename_filtered_keys(renamings: Vec<(String, String)>) -> impl Fn(&Tuple) -> Tuple {
    move |in_tup| {
        let mut new_tup = HashMap::new();
        for (old_key, new_key) in &renamings {
            if let Some(val) = in_tup.get(old_key) {
                new_tup.insert(new_key.clone(), val.clone());
            }
        }
        new_tup
    }
}

// Query implementations

fn ident(next_op: Operator) -> Operator {
    chain_op(
        map(|tup| {
            let mut new_tup = HashMap::new();
            for (key, val) in tup.iter() {
                if key != "eth.src" && key != "eth.dst" {
                    new_tup.insert(key.clone(), val.clone());
                }
            }
            new_tup
        }),
        next_op,
    )
}

fn count_pkts(next_op: Operator) -> Operator {
    chain_op(
        |op| epoch(1.0, "eid".to_string(), groupby(single_group, counter, "pkts".to_string(), op)),
        next_op,
    )
}

fn pkts_per_src_dst(next_op: Operator) -> Operator {
    chain_op(
        |op| epoch(1.0, "eid".to_string(), groupby(
            filter_groups(vec!["ipv4.src".to_string(), "ipv4.dst".to_string()]),
            counter,
            "pkts".to_string(),
            op,
        )),
        next_op,
    )
}

fn distinct_srcs(next_op: Operator) -> Operator {
    chain_op(
        |op| epoch(1.0, "eid".to_string(), distinct(
            filter_groups(vec!["ipv4.src".to_string()]),
            groupby(single_group, counter, "srcs".to_string(), op),
        )),
        next_op,
    )
}

fn tcp_new_cons(next_op: Operator) -> Operator {
    let threshold = 40;
    chain_op(
        |op| epoch(1.0, "eid".to_string(), filter(
            |tup| get_mapped_int("ipv4.proto", tup) == 6 && get_mapped_int("l4.flags", tup) == 2,
            groupby(
                filter_groups(vec!["ipv4.dst".to_string()]),
                counter,
                "cons".to_string(),
                filter(key_geq_int("cons".to_string(), threshold), op),
            ),
        )),
        next_op,
    )
}

fn ssh_brute_force(next_op: Operator) -> Operator {
    let threshold = 40;
    chain_op(
        |op| epoch(1.0, "eid".to_string(), filter(
            |tup| get_mapped_int("ipv4.proto", tup) == 6 && get_mapped_int("l4.dport", tup) == 22,
            distinct(
                filter_groups(vec!["ipv4.src".to_string(), "ipv4.dst".to_string(), "ipv4.len".to_string()]),
                groupby(
                    filter_groups(vec!["ipv4.dst".to_string(), "ipv4.len".to_string()]),
                    counter,
                    "srcs".to_string(),
                    filter(key_geq_int("srcs".to_string(), threshold), op),
                ),
            ),
        )),
        next_op,
    )
}

fn super_spreader(next_op: Operator) -> Operator {
    let threshold = 40;
    chain_op(
        |op| epoch(1.0, "eid".to_string(), distinct(
            filter_groups(vec!["ipv4.src".to_string(), "ipv4.dst".to_string()]),
            groupby(
                filter_groups(vec!["ipv4.src".to_string()]),
                counter,
                "dsts".to_string(),
                filter(key_geq_int("dsts".to_string(), threshold), op),
            ),
        )),
        next_op,
    )
}

fn port_scan(next_op: Operator) -> Operator {
    let threshold = 40;
    chain_op(
        |op| epoch(1.0, "eid".to_string(), distinct(
            filter_groups(vec!["ipv4.src".to_string(), "l4.dport".to_string()]),
            groupby(
                filter_groups(vec!["ipv4.src".to_string()]),
                counter,
                "ports".to_string(),
                filter(key_geq_int("ports".to_string(), threshold), op),
            ),
        )),
        next_op,
    )
}

fn ddos(next_op: Operator) -> Operator {
    let threshold = 45;
    chain_op(
        |op| epoch(1.0, "eid".to_string(), distinct(
            filter_groups(vec!["ipv4.src".to_string(), "ipv4.dst".to_string()]),
            groupby(
                filter_groups(vec!["ipv4.dst".to_string()]),
                counter,
                "srcs".to_string(),
                filter(key_geq_int("srcs".to_string(), threshold), op),
            ),
        )),
        next_op,
    )
}

fn syn_flood_sonata(next_op: Operator) -> Vec<Operator> {
    let threshold = 3;
    let epoch_dur = 1.0;
    let syns = |next_op: Operator| {
        chain_op(
            |op| epoch(epoch_dur, "eid".to_string(), filter(
                |tup| get_mapped_int("ipv4.proto", tup) == 6 && get_mapped_int("l4.flags", tup) == 2,
                groupby(
                    filter_groups(vec!["ipv4.dst".to_string()]),
                    counter,
                    "syns".to_string(),
                    op,
                ),
            )),
            next_op,
        )
    };
    let synacks = |next_op: Operator| {
        chain_op(
            |op| epoch(epoch_dur, "eid".to_string(), filter(
                |tup| get_mapped_int("ipv4.proto", tup) == 6 && get_mapped_int("l4.flags", tup) == 18,
                groupby(
                    filter_groups(vec!["ipv4.src".to_string()]),
                    counter,
                    "synacks".to_string(),
                    op,
                ),
            )),
            next_op,
        )
    };
    let acks = |next_op: Operator| {
        chain_op(
            |op| epoch(epoch_dur, "eid".to_string(), filter(
                |tup| get_mapped_int("ipv4.proto", tup) == 6 && get_mapped_int("l4.flags", tup) == 16,
                groupby(
                    filter_groups(vec!["ipv4.dst".to_string()]),
                    counter,
                    "acks".to_string(),
                    op,
                ),
            )),
            next_op,
        )
    };
    let (join_op1, join_op2) = chain_dbl_op(
        |op| join(
            "eid".to_string(),
            |tup| (
                filter_groups(vec!["host".to_string()])(tup),
                filter_groups(vec!["syns+synacks".to_string()])(tup),
            ),
            |tup| (
                rename_filtered_keys(vec![("ipv4.dst".to_string(), "host".to_string())])(tup),
                filter_groups(vec!["acks".to_string()])(tup),
            ),
            map(
                |tup| {
                    let mut new_tup = tup.clone();
                    let diff = get_mapped_int("syns+synacks", tup) - get_mapped_int("acks", tup);
                    new_tup.insert("syns+synacks-acks".to_string(), OpResult::Int(diff));
                    new_tup
                },
                filter(key_geq_int("syns+synacks-acks".to_string(), threshold), op),
            ),
        ),
        next_op,
    );
    let (join_op3, join_op4) = chain_dbl_op(
        |op| join(
            "eid".to_string(),
            |tup| (
                rename_filtered_keys(vec![("ipv4.dst".to_string(), "host".to_string())])(tup),
                filter_groups(vec!["syns".to_string()])(tup),
            ),
            |tup| (
                rename_filtered_keys(vec![("ipv4.src".to_string(), "host".to_string())])(tup),
                filter_groups(vec!["synacks".to_string()])(tup),
            ),
            map(
                |tup| {
                    let mut new_tup = tup.clone();
                    let sum = get_mapped_int("syns", tup) + get_mapped_int("synacks", tup);
                    new_tup.insert("syns+synacks".to_string(), OpResult::Int(sum));
                    new_tup
                },
                join_op1.clone(),
            ),
        ),
        join_op2.clone(),
    );
    vec![syns(join_op3), synacks(join_op4), acks(join_op2)]
}

fn completed_flows(next_op: Operator) -> Vec<Operator> {
    let threshold = 1;
    let epoch_dur = 30.0;
    let syns = |next_op: Operator| {
        chain_op(
            |op| epoch(epoch_dur, "eid".to_string(), filter(
                |tup| get_mapped_int("ipv4.proto", tup) == 6 && get_mapped_int("l4.flags", tup) == 2,
                groupby(
                    filter_groups(vec!["ipv4.dst".to_string()]),
                    counter,
                    "syns".to_string(),
                    op,
                ),
            )),
            next_op,
        )
    };
    let fins = |next_op: Operator| {
        chain_op(
            |op| epoch(epoch_dur, "eid".to_string(), filter(
                |tup| get_mapped_int("ipv4.proto", tup) == 6 && (get_mapped_int("l4.flags", tup) & 1) == 1,
                groupby(
                    filter_groups(vec!["ipv4.src".to_string()]),
                    counter,
                    "fins".to_string(),
                    op,
                ),
            )),
            next_op,
        )
    };
    let (op1, op2) = chain_dbl_op(
        |op| join(
            "eid".to_string(),
            |tup| (
                rename_filtered_keys(vec![("ipv4.dst".to_string(), "host".to_string())])(tup),
                filter_groups(vec!["syns".to_string()])(tup),
            ),
            |tup| (
                rename_filtered_keys(vec![("ipv4.src".to_string(), "host".to_string())])(tup),
                filter_groups(vec!["fins".to_string()])(tup),
            ),
            map(
                |tup| {
                    let mut new_tup = tup.clone();
                    let diff = get_mapped_int("syns", tup) - get_mapped_int("fins", tup);
                    new_tup.insert("diff".to_string(), OpResult::Int(diff));
                    new_tup
                },
                filter(key_geq_int("diff".to_string(), threshold), op),
            ),
        ),
        next_op,
    );
    vec![syns(op1), fins(op2)]
}

fn slowloris(next_op: Operator) -> Vec<Operator> {
    let t1 = 5;
    let t2 = 500;
    let t3 = 90;
    let epoch_dur = 1.0;
    let n_conns = |next_op: Operator| {
        chain_op(
            |op| epoch(epoch_dur, "eid".to_string(), filter(
                |tup| get_mapped_int("ipv4.proto", tup) == 6,
                distinct(
                    filter_groups(vec!["ipv4.src".to_string(), "ipv4.dst".to_string(), "l4.sport".to_string()]),
                    groupby(
                        filter_groups(vec!["ipv4.dst".to_string()]),
                        counter,
                        "n_conns".to_string(),
                        filter(|tup| get_mapped_int("n_conns", tup) >= t1, op),
                    ),
                ),
            )),
            next_op,
        )
    };
    let n_bytes = |next_op: Operator| {
        chain_op(
            |op| epoch(epoch_dur, "eid".to_string(), filter(
                |tup| get_mapped_int("ipv4.proto", tup) == 6,
                groupby(
                    filter_groups(vec!["ipv4.dst".to_string()]),
                    sum_ints("ipv4.len".to_string()),
                    "n_bytes".to_string(),
                    filter(|tup| get_mapped_int("n_bytes", tup) >= t2, op),
                ),
            )),
            next_op,
        )
    };
    let (op1, op2) = chain_dbl_op(
        |op| join(
            "eid".to_string(),
            |tup| (
                filter_groups(vec!["ipv4.dst".to_string()])(tup),
                filter_groups(vec!["n_conns".to_string()])(tup),
            ),
            |tup| (
                filter_groups(vec!["ipv4.dst".to_string()])(tup),
                filter_groups(vec!["n_bytes".to_string()])(tup),
            ),
            map(
                |tup| {
                    let mut new_tup = tup.clone();
                    let bytes_per_conn = get_mapped_int("n_bytes", tup) / get_mapped_int("n_conns", tup);
                    new_tup.insert("bytes_per_conn".to_string(), OpResult::Int(bytes_per_conn));
                    new_tup
                },
                filter(|tup| get_mapped_int("bytes_per_conn", tup) <= t3, op),
            ),
        ),
        next_op,
    );
    vec![n_conns(op1), n_bytes(op2)]
}

fn join_test(next_op: Operator) -> Vec<Operator> {
    let epoch_dur = 1.0;
    let syns = |next_op: Operator| {
        chain_op(
            |op| epoch(epoch_dur, "eid".to_string(), filter(
                |tup| get_mapped_int("ipv4.proto", tup) == 6 && get_mapped_int("l4.flags", tup) == 2,
                op,
            )),
            next_op,
        )
    };
    let synacks = |next_op: Operator| {
        chain_op(
            |op| epoch(epoch_dur, "eid".to_string(), filter(
                |tup| get_mapped_int("ipv4.proto", tup) == 6 && get_mapped_int("l4.flags", tup) == 18,
                op,
            )),
            next_op,
        )
    };
    let (op1, op2) = chain_dbl_op(
        |op| join(
            "eid".to_string(),
            |tup| (
                rename_filtered_keys(vec![("ipv4.src".to_string(), "host".to_string())])(tup),
                rename_filtered_keys(vec![("ipv4.dst".to_string(), "remote".to_string())])(tup),
            ),
            |tup| (
                rename_filtered_keys(vec![("ipv4.dst".to_string(), "host".to_string())])(tup),
                filter_groups(vec!["time".to_string()])(tup),
            ),
            op,
        ),
        next_op,
    );
    vec![syns(op1), synacks(op2)]
}

fn q3(next_op: Operator) -> Operator {
    chain_op(
        |op| epoch(100.0, "eid".to_string(), distinct(
            filter_groups(vec!["ipv4.src".to_string(), "ipv4.dst".to_string()]),
            op,
        )),
        next_op,
    )
}

fn q4(next_op: Operator) -> Operator {
    chain_op(
        |op| epoch(10000.0, "eid".to_string(), groupby(
            filter_groups(vec!["ipv4.dst".to_string()]),
            counter,
            "pkts".to_string(),
            op,
        )),
        next_op,
    )
}

// Run queries
fn run_queries() -> Vec<()> {
    let queries = vec![ident(dump_tuple(false, Box::new(io::stdout())))];
    let tuples: Vec<Tuple> = (0..20).map(|i| {
        let mut tup = HashMap::new();
        tup.insert("time".to_string(), OpResult::Float(0.0 + i as f64));
        tup.insert("eth.src".to_string(), OpResult::MAC([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]));
        tup.insert("eth.dst".to_string(), OpResult::MAC([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]));
        tup.insert("eth.ethertype".to_string(), OpResult::Int(0x0800));
        tup.insert("ipv4.hlen".to_string(), OpResult::Int(20));
        tup.insert("ipv4.proto".to_string(), OpResult::Int(6));
        tup.insert("ipv4.len".to_string(), OpResult::Int(60));
        tup.insert("ipv4.src".to_string(), OpResult::IPv4(IpAddrV4::from_str("127.0.0.1").unwrap()));
        tup.insert("ipv4.dst".to_string(), OpResult::IPv4(IpAddrV4::from_str("127.0.0.1").unwrap()));
        tup.insert("l4.sport".to_string(), OpResult::Int(440));
        tup.insert("l4.dport".to_string(), OpResult::Int(50000));
        tup.insert("l4.flags".to_string(), OpResult::Int(10));
        tup
    }).collect();
    tuples.into_iter().map(|tup| {
        queries.iter().for_each(|query| query.next(&tup));
    }).collect()
}

fn main() {
    run_queries();
    println!("Done");
}
```