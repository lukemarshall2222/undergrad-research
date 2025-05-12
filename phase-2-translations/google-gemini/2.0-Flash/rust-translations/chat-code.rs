use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use std::rc::Rc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// Re-exporting for convenience, assuming these are defined elsewhere in the Rust project
// If these are external crates, ensure they are added to your Cargo.toml
pub mod Bytes {
    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    pub struct Bytes(pub Vec<u8>);

    impl Bytes {
        pub fn from_string(s: &str) -> Self {
            Bytes(s.bytes().collect())
        }

        pub fn get_uint8(&self, index: usize) -> u8 {
            self.0[index]
        }
    }
}

pub mod Ipaddr {
    pub mod V4 {
        use std::net::Ipv4Addr;

        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub struct V4(pub Ipv4Addr);

        impl V4 {
            pub fn of_string_exn(s: &str) -> Self {
                V4(s.parse().expect("Failed to parse IPv4 address"))
            }

            pub fn to_string(&self) -> String {
                self.0.to_string()
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum OpResult {
    Float(f64),
    Int(i64),
    IPv4(Ipaddr::V4::V4),
    MAC(Bytes::Bytes),
    Empty,
}

impl fmt::Display for OpResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OpResult::Float(val) => write!(f, "{}", val),
            OpResult::Int(val) => write!(f, "{}", val),
            OpResult::IPv4(addr) => write!(f, "{}", addr.to_string()),
            OpResult::MAC(mac) => {
                let bytes = &mac.0;
                write!(
                    f,
                    "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
                )
            }
            OpResult::Empty => write!(f, "Empty"),
        }
    }
}

pub type Tuple = HashMap<String, OpResult>;

pub struct Operator {
    pub next: Box<dyn FnMut(Tuple)>,
    pub reset: Box<dyn FnMut(Tuple)>,
}

impl fmt::Debug for Operator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Operator")
            .field("next", &"<function>")
            .field("reset", &"<function>")
            .finish()
    }
}

pub type OpCreator = Box<dyn Fn(Rc<Operator>) -> Rc<Operator>>;
pub type DblOpCreator = Box<dyn Fn(Rc<Operator>) -> (Rc<Operator>, Rc<Operator>)>;

// Right associative "chaining" operator
pub fn op_chain(op_creator_func: OpCreator, next_op: Rc<Operator>) -> Rc<Operator> {
    op_creator_func(next_op)
}

// Right associative "double chaining" operator
pub fn dbl_op_chain(op_creator_func: DblOpCreator, op: Rc<Operator>) -> (Rc<Operator>, Rc<Operator>) {
    op_creator_func(op)
}

// Conversion utilities

pub fn string_of_mac(buf: &Bytes::Bytes) -> String {
    let bytes = &buf.0;
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
    )
}

pub fn tcp_flags_to_strings(flags: i64) -> String {
    let tcp_flags_map: HashMap<&str, i64> = [
        ("FIN", 1 << 0),
        ("SYN", 1 << 1),
        ("RST", 1 << 2),
        ("PSH", 1 << 3),
        ("ACK", 1 << 4),
        ("URG", 1 << 5),
        ("ECE", 1 << 6),
        ("CWR", 1 << 7),
    ]
    .iter()
    .cloned()
    .collect();

    tcp_flags_map.iter().fold(String::new(), |acc, (key, &value)| {
        if (flags & value) == value {
            if acc.is_empty() {
                key.to_string()
            } else {
                format!("{}|{}", acc, key)
            }
        } else {
            acc
        }
    })
}

pub fn int_of_op_result(input: &OpResult) -> Result<i64, String> {
    match input {
        OpResult::Int(i) => Ok(*i),
        _ => Err("Trying to extract int from non-int result".to_string()),
    }
}

pub fn float_of_op_result(input: &OpResult) -> Result<f64, String> {
    match input {
        OpResult::Float(f) => Ok(*f),
        _ => Err("Trying to extract float from non-float result".to_string()),
    }
}

pub fn string_of_op_result(input: &OpResult) -> String {
    match input {
        OpResult::Float(f) => format!("{}", f),
        OpResult::Int(i) => format!("{}", i),
        OpResult::IPv4(a) => a.to_string(),
        OpResult::MAC(m) => string_of_mac(m),
        OpResult::Empty => "Empty".to_string(),
    }
}

pub fn string_of_tuple(input_tuple: &Tuple) -> String {
    input_tuple
        .iter()
        .map(|(key, val)| format!("\"{}\" => {}, ", key, string_of_op_result(val)))
        .collect::<String>()
}

pub fn tuple_of_list(tup_list: Vec<(String, OpResult)>) -> Tuple {
    tup_list.into_iter().collect()
}

pub fn dump_tuple(outc: &mut dyn std::io::Write, tup: &Tuple) -> std::io::Result<()> {
    writeln!(outc, "{}", string_of_tuple(tup))
}

pub fn lookup_int(key: &str, tup: &Tuple) -> Result<i64, String> {
    match tup.get(key) {
        Some(op_result) => int_of_op_result(op_result),
        None => Err(format!("Key \"{}\" not found in tuple", key)),
    }
}

pub fn lookup_float(key: &str, tup: &Tuple) -> Result<f64, String> {
    match tup.get(key) {
        Some(op_result) => float_of_op_result(op_result),
        None => Err(format!("Key \"{}\" not found in tuple", key)),
    }
}

// Built-in operator definitions
// Assuming `Utils` is a local module (you might need to adapt this)
// use crate::utils::*;

const INIT_TABLE_SIZE: usize = 10000;

pub fn dump_tuple_op(show_reset: bool, outc: Rc<std::cell::RefCell<dyn std::io::Write + 'static>>) -> Rc<Operator> {
    Rc::new(Operator {
        next: Box::new(move |tup| {
            let mut writer = outc.borrow_mut();
            dump_tuple(&mut *writer, &tup).expect("Error writing to output");
        }),
        reset: Box::new(move |tup| {
            if show_reset {
                let mut writer = outc.borrow_mut();
                dump_tuple(&mut *writer, &tup).expect("Error writing to output");
                writeln!(&mut *writer, "[reset]").expect("Error writing to output");
            }
        }),
    })
}

pub fn dump_as_csv(
    static_field: Option<(String, String)>,
    header: bool,
    outc: Rc<std::cell::RefCell<dyn std::io::Write + 'static>>,
) -> Rc<Operator> {
    let first = Rc::new(std::cell::RefCell::new(header));
    Rc::new(Operator {
        next: Box::new(move |tup| {
            let mut writer = outc.borrow_mut();
            if *first.borrow() {
                if let Some((key, _)) = &static_field {
                    write!(&mut *writer, "{},", key).expect("Error writing to output");
                }
                for (i, key) in tup.keys().enumerate() {
                    write!(&mut *writer, "{}", key).expect("Error writing to output");
                    if i < tup.len() - 1 {
                        write!(&mut *writer, ",").expect("Error writing to output");
                    }
                }
                writeln!(&mut *writer).expect("Error writing to output");
                *first.borrow_mut() = false;
            }
            if let Some((_, value)) = &static_field {
                write!(&mut *writer, "{},", value).expect("Error writing to output");
            }
            for (i, value) in tup.values().enumerate() {
                write!(&mut *writer, "{}", value).expect("Error writing to output");
                if i < tup.len() - 1 {
                    write!(&mut *writer, ",").expect("Error writing to output");
                }
            }
            writeln!(&mut *writer).expect("Error writing to output");
        }),
        reset: Box::new(|_| {}),
    })
}

pub fn dump_walts_csv(filename: &str) -> Rc<Operator> {
    let outc = Rc::new(std::cell::RefCell::new(None));
    let first = Rc::new(std::cell::RefCell::new(true));
    let filename_owned = filename.to_owned();
    Rc::new(Operator {
        next: Box::new(move |tup| {
            if *first.borrow() {
                *outc.borrow_mut() = Some(std::fs::File::create(&filename_owned).expect("Error creating file"));
                *first.borrow_mut() = false;
            }
            if let Some(ref mut file) = *outc.borrow_mut() {
                let src_ip = string_of_op_result(tup.get("ipv4.src").expect("Key not found")).unwrap_or_else(|_| "0".to_string());
                let dst_ip = string_of_op_result(tup.get("ipv4.dst").expect("Key not found")).unwrap_or_else(|_| "0".to_string());
                let src_l4_port = string_of_op_result(tup.get("l4.sport").expect("Key not found")).unwrap_or_else(|_| "0".to_string());
                let dst_l4_port = string_of_op_result(tup.get("l4.dport").expect("Key not found")).unwrap_or_else(|_| "0".to_string());
                let packet_count = string_of_op_result(tup.get("packet_count").expect("Key not found")).unwrap_or_else(|_| "0".to_string());
                let byte_count = string_of_op_result(tup.get("byte_count").expect("Key not found")).unwrap_or_else(|_| "0".to_string());
                let epoch_id = string_of_op_result(tup.get("epoch_id").expect("Key not found")).unwrap_or_else(|_| "0".to_string());
                writeln!(file, "{},{},{},{},{},{},{}", src_ip, dst_ip, src_l4_port, dst_l4_port, packet_count, byte_count, epoch_id)
                    .expect("Error writing to file");
            }
        }),
        reset: Box::new(|_| {}),
    })
}

pub fn get_ip_or_zero(input: &str) -> OpResult {
    match input {
        "0" => OpResult::Int(0),
        catchall => OpResult::IPv4(Ipaddr::V4::V4::of_string_exn(catchall)),
    }
}

// This function needs more careful translation due to the file reading and state management
// It also uses OCaml's `Scanf`, which has no direct equivalent in Rust's standard library
// A possible approach would be to read the files line by line and parse each line
// However, the logic involving `epoch_id`, `tup_count`, and `ops` needs to be carefully reconstructed.
// For now, I'll provide a placeholder that indicates the complexity.
pub fn read_walts_csv(
    epoch_id_key: &str,
    file_names: Vec<String>,
    ops: Vec<Rc<Operator>>,
) -> Result<(), String> {
    println!("Warning: 'read_walts_csv' translation is complex and requires careful reconstruction of file reading and state management.");
    println!("File names: {:?}", file_names);
    println!("Epoch ID Key: {}", epoch_id_key);
    println!("Number of operators: {}", ops.len());
    // Placeholder for the complex logic
    Ok(())
}

pub fn meta_meter(
    static_field: Option<String>,
    name: &str,
    outc: Rc<std::cell::RefCell<dyn std::io::Write + 'static>>,
    next_op: Rc<Operator>,
) -> Rc<Operator> {
    let epoch_count = Rc::new(std::cell::RefCell::new(0));
    let tups_count = Rc::new(std::cell::RefCell::new(0));
    let name_owned = name.to_owned();
    Rc::new(Operator {
        next: Box::new(move |tup| {
            *tups_count.borrow_mut() += 1;
            (next_op.next)(tup);
        }),
        reset: Box::new(move |tup| {
            let mut writer = outc.borrow_mut();
            writeln!(
                &mut *writer,
                "{},{},{},{}",
                *epoch_count.borrow(),
                name_owned,
                *tups_count.borrow(),
                static_field.as_deref().unwrap_or("")
            )
            .expect("Error writing to output");
            *tups_count.borrow_mut() = 0;
            *epoch_count.borrow_mut() += 1;
            (next_op.reset)(tup);
        }),
    })
}

pub fn epoch(epoch_width: f64, key_out: &str, next_op: Rc<Operator>) -> Rc<Operator> {
    let epoch_boundary = Rc::new(std::cell::RefCell::new(0.0));
    let eid = Rc::new(std::cell::RefCell::new(0));
    let key_out_owned = key_out.to_owned();
    Rc::new(Operator {
        next: Box::new(move |mut tup| {
            let time = match tup.get("time") {
                Some(OpResult::Float(t)) => *t,
                _ => 0.0, // Handle error appropriately
            };
            if *epoch_boundary.borrow() == 0.0 {
                *epoch_boundary.borrow_mut() = time + epoch_width;
            } else if time >= *epoch_boundary.borrow() {
                while time >= *epoch_boundary.borrow() {
                    (next_op.reset)(
                        [
                            (key_out_owned.clone(), OpResult::Int(*eid.borrow())),
                        ]
                        .iter()
                        .cloned()
                        .collect(),
                    );
                    *epoch_boundary.borrow_mut() += epoch_width;
                    *eid.borrow_mut() += 1;
                }
            }
            tup.insert(key_out_owned.clone(), OpResult::Int(*eid.borrow()));
            (next_op.next)(tup);
        }),
        reset: Box::new(move |_| {
            (next_op.reset)(
                [
                    (key_out_owned.clone(), OpResult::Int(*eid.borrow())),
                ]
                .iter()
                .cloned()
                .collect(),
            );
            *epoch_boundary.borrow_mut() = 0.0;
            *eid.borrow_mut() = 0;
        }),
    })
}

pub fn filter_op(f: Rc<dyn Fn(&Tuple) -> bool>, next_op: Rc<Operator>) -> Rc<Operator> {
    Rc::new(Operator {
        next: Box::new(move |tup| {
            if f(&tup) {
                (next_op.next)(tup);
            }
        }),
        reset: Box::new(move |tup| {
            (next_op.reset)(tup);
        }),
    })
}

pub fn key_geq_int(key: &str, threshold: i64, tup: &Tuple) -> bool {
    match lookup_int(key, tup) {
        Ok(val) => val >= threshold,
        Err(_) => false, // Or handle the error as needed
    }
}

pub fn get_mapped_int(key: &str, tup: &Tuple) -> Result<i64, String> {
    lookup_int(key, tup)
}

pub fn get_mapped_float(key: &str, tup: &Tuple) -> Result<f64, String> {
    lookup_float(key, tup)
}

pub fn map_op(f: Rc<dyn Fn(Tuple) -> Tuple>, next_op: Rc<Operator>) -> Rc<Operator> {
    Rc::new(Operator {
        next: Box::new(move |tup| {
            (next_op.next)(f(tup));
        }),
        reset: Box::new(move |tup| {
            (next_op.reset)(tup);
        }),
    })
}

pub type GroupingFunc = Rc<dyn Fn(&Tuple) -> Tuple>;
pub type ReductionFunc = Rc<dyn Fn(&OpResult, &Tuple) -> OpResult>;

pub fn groupby(
    groupby_func: GroupingFunc,
    reduce_func: ReductionFunc,
    out_key: &str,
    next_op: Rc<Operator>,
) -> Rc<Operator> {
    let h_tbl: Rc<std::cell::RefCell<HashMap<Tuple, OpResult>>> =
        Rc::new(std::cell::RefCell::new(HashMap::with_capacity(INIT_TABLE_SIZE)));
    let reset_counter = Rc::new(std::cell::RefCell::new(0));
    let out_key_owned = out_key.to_owned();
    Rc::new(Operator {
        next: Box::new(move |tup| {
            let grouping_key = groupby_func(&tup);
            let mut table = h_tbl.borrow_mut();
            let current_val = table.get(&grouping_key).cloned().unwrap_or(OpResult::Empty);
            table.insert(grouping_key, reduce_func(&current_val, &tup));
        }),
        reset: Box::new(move |tup| {
            *reset_counter.borrow_mut() += 1;
            let mut table = h_tbl.borrow_mut();
            for (grouping_key, val) in table.iter() {
                let mut unioned_tup = tup.clone();
                for (key, value) in grouping_key.iter() {
                    unioned_tup.insert(key.clone(), value.clone());
                }
                unioned_tup.insert(out_key_owned.clone(), val.clone());
                (next_op.next)(unioned_tup);
            }
            (next_op.reset)(tup);
            table.clear();
        }),
    })
}

pub fn filter_groups(incl_keys: &[&str], tup: &Tuple) -> Tuple {
    tup.iter()
        .filter(|(key, _)| incl_keys.contains(&key.as_str()))
        .map(|(key, val)| (key.clone(), val.clone()))
        .collect()
}

pub fn single_group(_: &Tuple) -> Tuple {
    HashMap::new()
}

pub fn counter(val: &OpResult, _: &Tuple) -> OpResult {
    match val {
        OpResult::Empty => OpResult::Int(1),
        OpResult::Int(i) => OpResult::Int(i + 1),
        _ => val.clone(),
    }
}

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

pub fn distinct(groupby_func: GroupingFunc, next_op: Rc<Operator>) -> Rc<Operator> {
    let h_tbl: Rc<std::cell::RefCell<HashMap<Tuple, bool>>> =
        Rc::new(std::cell::RefCell::new(HashMap::with_capacity(INIT_TABLE_SIZE)));
    let reset_counter = Rc::new(std::cell::RefCell::new(0));
    Rc::new(Operator {
        next: Box::new(move |tup| {
            let grouping_key = groupby_func(&tup);
            h_tbl.borrow_mut().insert(grouping_key, true);
        }),
        reset: Box::new(move |tup| {
            *reset_counter.borrow_mut() += 1;
            let mut table = h_tbl.borrow_mut();
            for key in table.keys() {
                let mut merged_tup = tup.clone();
                for (k, v) in key.iter() {
                    merged_tup.insert(k.clone(), v.clone());
                }
                (next_op.next)(merged_tup);
            }
            (next_op.reset)(tup);
            table.clear();
        }),
    })
}

pub fn split(l: Rc<Operator>, r: Rc<Operator>) -> Rc<Operator> {
    Rc::new(Operator {
        next: Box::new(move |tup| {
            (l.next)(tup.clone());
            (r.next)(tup);
        }),
        reset: Box::new(move |tup| {
            (l.reset)(tup.clone());
            (r.reset)(tup);
        }),
    })
}

pub type KeyExtractor = Rc<dyn Fn(&Tuple) -> (Tuple, Tuple)>;

pub fn join(
    eid_key: Option<&str>,
    left_extractor: KeyExtractor,
    right_extractor: KeyExtractor,
    next_op: Rc<Operator>,
) -> (Rc<Operator>, Rc<Operator>) {
    let eid_key_str = eid_key.unwrap_or("eid").to_owned();
    let h_tbl1: Rc<std::cell::RefCell<HashMap<Tuple, Tuple>>> =
        Rc::new(std::cell::RefCell::new(HashMap::with_capacity(INIT_TABLE_SIZE)));
    let h_tbl2: Rc<std::cell::RefCell<HashMap<Tuple, Tuple>>> =
        Rc::new(std::cell::RefCell::new(HashMap::with_capacity(INIT_TABLE_SIZE)));
    let left_curr_epoch = Rc::new(std::cell::RefCell::new(0));
    let right_curr_epoch = Rc::new(std::cell::RefCell::new(0));

    let handle_join_side = |curr_h_tble: Rc<std::cell::RefCell<HashMap<Tuple, Tuple>>>,
                             other_h_tbl: Rc<std::cell::RefCell<HashMap<Tuple, Tuple>>>,
                             curr_epoch_ref: Rc<std::cell::RefCell<i64>>,
                             other_epoch_ref: Rc<std::cell::RefCell<i64>>,
                             f: KeyExtractor| {
        Rc::new(Operator {
            next: Box::new(move |tup| {
                let (key, vals_) = f(&tup);
                let curr_epoch = get_mapped_int(&eid_key_str, &tup).unwrap_or(0);

                while curr_epoch > *curr_epoch_ref.borrow() {
                    if *other_epoch_ref.borrow() > *curr_epoch_ref.borrow() {
                        (next_op.reset)(
                            [(&eid_key_str, OpResult::Int(*curr_epoch_ref.borrow()))]
                                .iter()
                                .cloned()
                                .collect(),
                        );
                    }
                    *curr_epoch_ref.borrow_mut() += 1;
                }

                let mut new_tup = key.clone();
                new_tup.insert(eid_key_str.clone(), OpResult::Int(curr_epoch));

                if let Some(val_) = other_h_tbl.borrow_mut().remove(&new_tup) {
                    let mut use_left = |_: &String, a: &OpResult, _: &OpResult| Some(a.clone());
                    let mut merged = new_tup.clone();
                    for (k, v) in vals_.iter() {
                        merged.insert(k.clone(), v.clone());
                    }
                    for (k, v) in val_.iter() {
                        merged.insert(k.clone(), v.clone());
                    }
                    (next_op.next)(merged);
                } else {
                    curr_h_tble.borrow_mut().insert(new_tup, vals_);
                }
            }),
            reset: Box::new(move |tup| {
                let curr_epoch = get_mapped_int(&eid_key_str, &tup).unwrap_or(0);
                while curr_epoch > *curr_epoch_ref.borrow() {
                    if *other_epoch_ref.borrow() > *curr_epoch_ref.borrow() {
                        (next_op.reset)(
                            [(&eid_key_str, OpResult::Int(*curr_epoch_ref.borrow()))]
                                .iter()
                                .cloned()
                                .collect(),
                        );
                    }
                    *curr_epoch_ref.borrow_mut() += 1;
                }
            }),
        })
    };

    (
        handle_join_side(
            h_tbl1.clone(),
            h_tbl2.clone(),
            left_curr_epoch.clone(),
            right_curr_epoch.clone(),
            left_extractor,
        ),
        handle_join_side(
            h_tbl2.clone(),
            h_tbl1.clone(),
            right_curr_epoch.clone(),
            left_curr_epoch.clone(),
            right_extractor,
        ),
    )
}

pub fn rename_filtered_keys(renamings_pairs: &[(String, String)], in_tup: &Tuple) -> Tuple {
    let mut new_tup = HashMap::new();
    for &(ref old_key, ref new_key) in renamings_pairs {
        if let Some(val) = in_tup.get(old_key) {
            new_tup.insert(new_key.clone(), val.clone());
        }
    }
    new_tup
}

// Main entry point and implementation for simple header-dump operation

pub fn ident(next_op: Rc<Operator>) -> Rc<Operator> {
    map_op(
        Rc::new(|tup: Tuple| {
            tup.into_iter()
                .filter(|(key, _)| key != "eth.src" && key != "eth.dst")
                .collect()
        }),
        next_op,
    )
}

pub fn count_pkts(next_op: Rc<Operator>) -> Rc<Operator> {
    let epoch_op = epoch(1.0, "eid", groupby(Rc::new(single_group), Rc::new(counter), "pkts", next_op));
    epoch_op
}

pub fn pkts_per_src_dst(next_op: Rc<Operator>) -> Rc<Operator> {
    let group_by_op = groupby(
        Rc::new(|tup| filter_groups(&["ipv4.src", "ipv4.dst"], tup)),
        Rc::new(counter),
        "pkts",
        next_op,
    );
    epoch(1.0, "eid", group_by_op)
}

pub fn distinct_srcs(next_op: Rc<Operator>) -> Rc<Operator> {
    let distinct_op = distinct(Rc::new(|tup| filter_groups(&["ipv4.src"], tup)), groupby(Rc::new(single_group), Rc::new(counter), "srcs", next_op));
    epoch(1.0, "eid", distinct_op)
}

pub fn tcp_new_cons(next_op: Rc<Operator>) -> Rc<Operator> {
    let filter_op_inner = filter_op(
        Rc::new(|tup| {
            get_mapped_int("ipv4.proto", tup).unwrap_or(0) == 6 && get_mapped_int("l4.flags", tup).unwrap_or(0) == 2
        }),
        groupby(
            Rc::new(|tup| filter_groups(&["ipv4.dst"], tup)),
            Rc::new(counter),
            "cons",
            filter_op(Rc::new(|tup| key_geq_int("cons", 40, tup)), next_op),
        ),
    );
    epoch(1.0, "eid", filter_op_inner)
}

pub fn ssh_brute_force(next_op: Rc<Operator>) -> Rc<Operator> {
    let distinct_op = distinct(
        Rc::new(|tup| filter_groups(&["ipv4.src", "ipv4.dst", "ipv4.len"], tup)),
        groupby(
            Rc::new(|tup| filter_groups(&["ipv4.dst", "ipv4.len"], tup)),
            Rc::new(counter),
            "srcs",
            filter_op(Rc::new(|tup| key_geq_int("srcs", 40, tup)), next_op),
        ),
    );
    epoch(1.0, "eid", distinct_op)
}

pub fn super_spreader(next_op: Rc<Operator>) -> Rc<Operator> {
    let distinct_op = distinct(
        Rc::new(|tup| filter_groups(&["ipv4.src", "ipv4.dst"], tup)),
        groupby(
            Rc::new(|tup| filter_groups(&["ipv4.src"], tup)),
            Rc::new(counter),
            "dsts",
            filter_op(Rc::new(|tup| key_geq_int("dsts", 40, tup)), next_op),
        ),
    );
    epoch(1.0, "eid", distinct_op)
}

pub fn port_scan(next_op: Rc<Operator>) -> Rc<Operator> {
    let distinct_op = distinct(
        Rc::new(|tup| filter_groups(&["ipv4.src", "l4.dport"], tup)),
        groupby(
            Rc::new(|tup| filter_groups(&["ipv4.src"], tup)),
            Rc::new(counter),
            "ports",
            filter_op(Rc::new(|tup| key_geq_int("ports", 40, tup)), next_op),
        ),
    );
    epoch(1.0, "eid", distinct_op)
}

pub fn ddos(next_op: Rc<Operator>) -> Rc<Operator> {
    let distinct_op = distinct(
        Rc::new(|tup| filter_groups(&["ipv4.src", "ipv4.dst"], tup)),
        groupby(
            Rc::new(|tup| filter_groups(&["ipv4.dst"], tup)),
            Rc::new(counter),
            "srcs",
            filter_op(Rc::new(|tup| key_geq_int("srcs", 45, tup)), next_op),
        ),
    );
    epoch(1.0, "eid", distinct_op)
}

pub fn syn_flood_sonata(next_op: Rc<Operator>) -> Vec<Rc<Operator>> {
    let threshold: i64 = 3;
    let epoch_dur: f64 = 1.0;

    let syns = {
        let next_op_cloned = next_op.clone();
        epoch(
            epoch_dur,
            "eid",
            filter_op(
                Rc::new(|tup| {
                    get_mapped_int("ipv4.proto", tup).unwrap_or(0) == 6 && get_mapped_int("l4.flags", tup).unwrap_or(0) == 2
                }),
                groupby(
                    Rc::new(|tup| filter_groups(&["ipv4.dst"], tup)),
                    Rc::new 
                    counter),
                    "syns",
                    next_op_cloned,
                ),
            ),
        )
    };

    let synacks = {
        let next_op_cloned = next_op.clone();
        epoch(
            epoch_dur,
            "eid",
            filter_op(
                Rc::new(|tup| {
                    get_mapped_int("ipv4.proto", tup).unwrap_or(0) == 6 && get_mapped_int("l4.flags", tup).unwrap_or(0) == 18
                }),
                groupby(
                    Rc::new(|tup| filter_groups(&["ipv4.src"], tup)),
                    Rc::new(counter),
                    "synacks",
                    next_op_cloned,
                ),
            ),
        )
    };

    let acks = {
        let next_op_cloned = next_op.clone();
        epoch(
            epoch_dur,
            "eid",
            filter_op(
                Rc::new(|tup| {
                    get_mapped_int("ipv4.proto", tup).unwrap_or(0) == 6 && get_mapped_int("l4.flags", tup).unwrap_or(0) == 16
                }),
                groupby(
                    Rc::new(|tup| filter_groups(&["ipv4.dst"], tup)),
                    Rc::new(counter),
                    "acks",
                    next_op_cloned,
                ),
            ),
        )
    };

    let (join_op1, join_op2) = {
        let next_op_cloned = next_op.clone();
        let map_op_inner = map_op(
            Rc::new(|tup| {
                let syns_synacks = get_mapped_int("syns+synacks", &tup).unwrap_or(0);
                let acks_val = get_mapped_int("acks", &tup).unwrap_or(0);
                let mut new_tup = tup.clone();
                new_tup.insert("syns+synacks-acks".to_string(), OpResult::Int(syns_synacks - acks_val));
                new_tup
            }),
            filter_op(Rc::new(|tup| key_geq_int("syns+synacks-acks", threshold, tup)), next_op_cloned),
        );
        join(
            Some("host"),
            Rc::new(|tup| (filter_groups(&["host"], tup), filter_groups(&["syns+synacks"], tup))),
            Rc::new(|tup| (rename_filtered_keys(&[("ipv4.dst".to_string(), "host".to_string())], tup), filter_groups(&["acks"], tup))),
            map_op_inner,
        )
    };

    let (join_op3, join_op4) = {
        let join_op1_cloned = join_op1.clone();
        let map_op_inner = map_op(
            Rc::new(|tup| {
                let syns_val = get_mapped_int("syns", &tup).unwrap_or(0);
                let synacks_val = get_mapped_int("synacks", &tup).unwrap_or(0);
                let mut new_tup = tup.clone();
                new_tup.insert("syns+synacks".to_string(), OpResult::Int(syns_val + synacks_val));
                new_tup
            }),
            join_op1_cloned,
        );
        join(
            Some("host"),
            Rc::new(|tup| (rename_filtered_keys(&[("ipv4.dst".to_string(), "host".to_string())], tup), filter_groups(&["syns"], tup))),
            Rc::new(|tup| (rename_filtered_keys(&[("ipv4.src".to_string(), "host".to_string())], tup), filter_groups(&["synacks"], tup))),
            map_op_inner,
        )
    };

    vec![syns, synacks, acks]
}

pub fn completed_flows(next_op: Rc<Operator>) -> Vec<Rc<Operator>> {
    let threshold: i64 = 1;
    let epoch_dur: f64 = 30.0;

    let syns = {
        let next_op_cloned = next_op.clone();
        epoch(
            epoch_dur,
            "eid",
            filter_op(
                Rc::new(|tup| {
                    get_mapped_int("ipv4.proto", tup).unwrap_or(0) == 6 && get_mapped_int("l4.flags", tup).unwrap_or(0) == 2
                }),
                groupby(
                    Rc::new(|tup| filter_groups(&["ipv4.dst"], tup)),
                    Rc::new(counter),
                    "syns",
                    next_op_cloned,
                ),
            ),
        )
    };

    let fins = {
        let next_op_cloned = next_op.clone();
        epoch(
            epoch_dur,
            "eid",
            filter_op(
                Rc::new(|tup| {
                    get_mapped_int("ipv4.proto", tup).unwrap_or(0) == 6 && (get_mapped_int("l4.flags", tup).unwrap_or(0) & 1) == 1
                }),
                groupby(
                    Rc::new(|tup| filter_groups(&["ipv4.src"], tup)),
                    Rc::new(counter),
                    "fins",
                    next_op_cloned,
                ),
            ),
        )
    };

    let (op1, op2) = {
        let next_op_cloned = next_op.clone();
        let map_op_inner = map_op(
            Rc::new(|tup| {
                let syns_val = get_mapped_int("syns", &tup).unwrap_or(0);
                let fins_val = get_mapped_int("fins", &tup).unwrap_or(0);
                let mut new_tup = tup.clone();
                new_tup.insert("diff".to_string(), OpResult::Int(syns_val - fins_val));
                new_tup
            }),
            filter_op(Rc::new(|tup| key_geq_int("diff", threshold, tup)), next_op_cloned),
        );
        join(
            Some("host"),
            Rc::new(|tup| (rename_filtered_keys(&[("ipv4.dst".to_string(), "host".to_string())], tup), filter_groups(&["syns"], tup))),
            Rc::new(|tup| (rename_filtered_keys(&[("ipv4.src".to_string(), "host".to_string())], tup), filter_groups(&["fins"], tup))),
            map_op_inner,
        )
    };

    vec![syns, fins]
}

pub fn slowloris(next_op: Rc<Operator>) -> Vec<Rc<Operator>> {
    let t1: i64 = 5;
    let t2: i64 = 500;
    let t3: i64 = 90;
    let epoch_dur: f64 = 1.0;

    let n_conns = {
        let next_op_cloned = next_op.clone();
        epoch(
            epoch_dur,
            "eid",
            filter_op(
                Rc::new(|tup| get_mapped_int("ipv4.proto", tup).unwrap_or(0) == 6),
                distinct(
                    Rc::new(|tup| filter_groups(&["ipv4.src", "ipv4.dst", "l4.sport"], tup)),
                    groupby(
                        Rc::new(|tup| filter_groups(&["ipv4.dst"], tup)),
                        Rc::new(counter),
                        "n_conns",
                        filter_op(Rc::new(|tup| get_mapped_int("n_conns", tup).unwrap_or(0) >= t1), next_op_cloned),
                    ),
                ),
            ),
        )
    };

    let n_bytes = {
        let next_op_cloned = next_op.clone();
        epoch(
            epoch_dur,
            "eid",
            filter_op(
                Rc::new(|tup| get_mapped_int("ipv4.proto", tup).unwrap_or(0) == 6),
                groupby(
                    Rc::new(|tup| filter_groups(&["ipv4.dst"], tup)),
                    Rc::new(|acc, tup| sum_ints("ipv4.len", acc, tup)),
                    "n_bytes",
                    filter_op(Rc::new(|tup| get_mapped_int("n_bytes", tup).unwrap_or(0) >= t2), next_op_cloned),
                ),
            ),
        )
    };

    let (op1, op2) = {
        let next_op_cloned = next_op.clone();
        let map_op_inner = map_op(
            Rc::new(|tup| {
                let n_bytes_val = get_mapped_int("n_bytes", &tup).unwrap_or(0);
                let n_conns_val = get_mapped_int("n_conns", &tup).unwrap_or(1); // Avoid division by zero
                let mut new_tup = tup.clone();
                new_tup.insert("bytes_per_conn".to_string(), OpResult::Int(n_bytes_val / n_conns_val));
                new_tup
            }),
            filter_op(Rc::new(|tup| get_mapped_int("bytes_per_conn", tup).unwrap_or(i64::MAX) <= t3), next_op_cloned),
        );
        join(
            Some("ipv4.dst"),
            Rc::new(|tup| (filter_groups(&["ipv4.dst"], tup), filter_groups(&["n_conns"], tup))),
            Rc::new(|tup| (filter_groups(&["ipv4.dst"], tup), filter_groups(&["n_bytes"], tup))),
            map_op_inner,
        )
    };

    vec![n_conns, n_bytes]
}

pub fn join_test(next_op: Rc<Operator>) -> Vec<Rc<Operator>> {
    let epoch_dur: f64 = 1.0;

    let syns = {
        let next_op_cloned = next_op.clone();
        epoch(
            epoch_dur,
            "eid",
            filter_op(
                Rc::new(|tup| {
                    get_mapped_int("ipv4.proto", tup).unwrap_or(0) == 6 && get_mapped_int("l4.flags", tup).unwrap_or(0) == 2
                }),
                next_op_cloned,
            ),
        )
    };

    let synacks = {
        let next_op_cloned = next_op.clone();
        epoch(
            epoch_dur,
            "eid",
            filter_op(
                Rc::new(|tup| {
                    get_mapped_int("ipv4.proto", tup).unwrap_or(0) == 6 && get_mapped_int("l4.flags", tup).unwrap_or(0) == 18
                }),
                next_op_cloned,
            ),
        )
    };

    let (op1, op2) = join(
        Some("host"),
        Rc::new(|tup| (rename_filtered_keys(&[("ipv4.src".to_string(), "host".to_string())], tup), rename_filtered_keys(&[("ipv4.dst".to_string(), "remote".to_string())], tup))),
        Rc::new(|tup| (rename_filtered_keys(&[("ipv4.dst".to_string(), "host".to_string())], tup), filter_groups(&["time"], tup))),
        next_op,
    );

    vec![syns, synacks]
}

pub fn q3(next_op: Rc<Operator>) -> Rc<Operator> {
    epoch(
        100.0,
        "eid",
        distinct(Rc::new(|tup| filter_groups(&["ipv4.src", "ipv4.dst"], tup)), next_op),
    )
}

pub fn q4(next_op: Rc<Operator>) -> Rc<Operator> {
    epoch(
        10000.0,
        "eid",
        groupby(
            Rc::new(|tup| filter_groups(&["ipv4.dst"], tup)),
            Rc::new(counter),
            "pkts",
            next_op,
        ),
    )
}

pub fn queries(stdout: Rc<std::cell::RefCell<dyn std::io::Write + 'static>>) -> Vec<Rc<Operator>> {
    vec![ident(dump_tuple_op(false, stdout))]
}

pub fn run_queries(queries: &[Rc<Operator>]) {
    for i in 0..20 {
        let mut tup: Tuple = HashMap::new();
        tup.insert("time".to_string(), OpResult::Float(0.000000 + i as f64));
        tup.insert("eth.src".to_string(), OpResult::MAC(Bytes::Bytes(vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55])));
        tup.insert("eth.dst".to_string(), OpResult::MAC(Bytes::Bytes(vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])));
        tup.insert("eth.ethertype".to_string(), OpResult::Int(0x0800));
        tup.insert("ipv4.hlen".to_string(), OpResult::Int(20));
        tup.insert("ipv4.proto".to_string(), OpResult::Int(6));
        tup.insert("ipv4.len".to_string(), OpResult::Int(60));
        tup.insert("ipv4.src".to_string(), OpResult::IPv4(Ipaddr::V4::V4::of_string_exn("127.0.0.1")));
        tup.insert("ipv4.dst".to_string(), OpResult::IPv4(Ipaddr::V4::V4::of_string_exn("127.0.0.1")));
        tup.insert("l4.sport".to_string(), OpResult::Int(440));
        tup.insert("l4.dport".to_string(), OpResult::Int(50000));
        tup.insert("l4.flags".to_string(), OpResult::Int(10));

        for query in queries {
            (query.next)(tup.clone());
        }
    }
}

fn main() {
    let stdout_ref = Rc::new(std::cell::RefCell::new(std::io::stdout()));
    let qs = queries(stdout_ref);
    run_queries(&qs);
    println!("Done");
}        