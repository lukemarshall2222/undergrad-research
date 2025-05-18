use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::net::Ipv4Addr;

// Define the op_result enum
#[derive(Debug, PartialEq)]
enum OpResult {
    Float(f64),
    Int(i32),
    IPv4(Ipv4Addr),
    MAC([u8; 6]),
    Empty,
}

// Define the Tuple type
type Tuple = HashMap<String, OpResult>;

// Define the operator struct
struct Operator {
    next: Box<dyn Fn(&Tuple)>,
    reset: Box<dyn Fn(&Tuple)>,
}

// Implement the operator struct
impl Operator {
    fn new(next: impl Fn(&Tuple) + 'static, reset: impl Fn(&Tuple) + 'static) -> Self {
        Operator {
            next: Box::new(next),
            reset: Box::new(reset),
        }
    }
}

// Define the op_creator type
type OpCreator = dyn Fn(Operator) -> Operator;

// Define the dbl_op_creator type
type DblOpCreator = dyn Fn(Operator) -> (Operator, Operator);

// Implement the chaining operator
fn chain(op_creator: Box<OpCreator>, next_op: Operator) -> Operator {
    op_creator(next_op)
}

// Implement the conversion utilities
fn string_of_mac(mac: [u8; 6]) -> String {
    format!("{:#02x}:{:#02x}:{:#02x}:{:#02x}:{:#02x}:{:#02x}", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

fn tcp_flags_to_strings(flags: i32) -> String {
    let mut result = String::new();
    let flags_map = vec![
        ("FIN", 1 << 0),
        ("SYN", 1 << 1),
        ("RST", 1 << 2),
        ("PSH", 1 << 3),
        ("ACK", 1 << 4),
        ("URG", 1 << 5),
        ("ECE", 1 << 6),
        ("CWR", 1 << 7),
    ];

    for (key, value) in flags_map {
        if flags & value == value {
            if !result.is_empty() {
                result.push('|');
            }
            result.push_str(key);
        }
    }

    result
}

fn int_of_op_result(input: &OpResult) -> i32 {
    match input {
        OpResult::Int(i) => *i,
        _ => panic!("Trying to extract int from non-int result"),
    }
}

fn float_of_op_result(input: &OpResult) -> f64 {
    match input {
        OpResult::Float(f) => *f,
        _ => panic!("Trying to extract float from non-float result"),
    }
}

fn string_of_op_result(input: &OpResult) -> String {
    match input {
        OpResult::Float(f) => format!("{}", f),
        OpResult::Int(i) => format!("{}", i),
        OpResult::IPv4(ip) => format!("{}", ip),
        OpResult::MAC(mac) => string_of_mac(*mac),
        OpResult::Empty => "Empty".to_string(),
    }
}

fn string_of_tuple(input: &Tuple) -> String {
    let mut result = String::new();
    for (key, value) in input {
        result.push_str(&format!("\"{}\" => {}, ", key, string_of_op_result(value)));
    }
    result
}

// Implement the dump_tuple function
fn dump_tuple(outc: &mut dyn Write, tup: &Tuple) {
    writeln!(outc, "{}", string_of_tuple(tup)).unwrap();
}

// Implement the dump_as_csv function
fn dump_as_csv(outc: &mut dyn Write, header: bool, tup: &Tuple) {
    if header {
        for key in tup.keys() {
            write!(outc, "{},", key).unwrap();
        }
        writeln!(outc).unwrap();
    }

    for value in tup.values() {
        write!(outc, "{},", string_of_op_result(value)).unwrap();
    }
    writeln!(outc).unwrap();
}

// Implement the epoch function
fn epoch(epoch_width: f64, key_out: &str, next_op: Operator) -> Operator {
    let mut epoch_boundary = 0.0;
    let mut eid = 0;
    Operator::new(
        move |tup| {
            let time = float_of_op_result(tup.get("time").unwrap());
            if epoch_boundary == 0.0 {
                epoch_boundary = time + epoch_width;
            } else if time >= epoch_boundary {
                while time >= epoch_boundary {
                    next_op.reset(&HashMap::from([(key_out.to_string(), OpResult::Int(eid))]));
                    epoch_boundary += epoch_width;
                    eid += 1;
                }
            }
            let mut new_tup = tup.clone();
            new_tup.insert(key_out.to_string(), OpResult::Int(eid));
            next_op.next(&new_tup);
        },
        move |_| {
            next_op.reset(&HashMap::from([(key_out.to_string(), OpResult::Int(eid))]));
            epoch_boundary = 0.0;
            eid = 0;
        },
    )
}

// Implement the filter function
fn filter<F>(f: F, next_op: Operator) -> Operator
where
    F: Fn(&Tuple) -> bool + 'static,
{
    Operator::new(
        move |tup| {
            if f(tup) {
                next_op.next(tup);
            }
        },
        move |tup| {
            next_op.reset(tup);
        },
    )
}

// Implement the map function
fn map<F>(f: F, next_op: Operator) -> Operator
where
    F: Fn(&Tuple) -> Tuple + 'static,
{
    Operator::new(
        move |tup| {
            next_op.next(&f(tup));
        },
        move |tup| {
            next_op.reset(tup);
        },
    )
}

// Implement the groupby function
fn groupby<F, G>(groupby: F, reduce: G, out_key: &str, next_op: Operator) -> Operator
where
    F: Fn(&Tuple) -> Tuple + 'static,
    G: Fn(OpResult, &Tuple) -> OpResult + 'static,
{
    let mut h_tbl = HashMap::new();
    Operator::new(
        move |tup| {
            let grouping_key = groupby(tup);
            let val = h_tbl.entry(grouping_key.clone()).or_insert(OpResult::Empty);
            *val = reduce(val.clone(), tup);
        },
        move |tup| {
            for (grouping_key, val) in h_tbl.drain() {
                let mut unioned_tup = tup.clone();
                unioned_tup.extend(grouping_key);
                unioned_tup.insert(out_key.to_string(), val);
                next_op.next(&unioned_tup);
            }
            next_op.reset(tup);
        },
    )
}

// Implement the distinct function
fn distinct<F>(groupby: F, next_op: Operator) -> Operator
where
    F: Fn(&Tuple) -> Tuple + 'static,
{
    let mut h_tbl = HashSet::new();
    Operator::new(
        move |tup| {
            let grouping_key = groupby(tup);
            h_tbl.insert(grouping_key);
        },
        move |tup| {
            for key in h_tbl.drain() {
                let mut merged_tup = tup.clone();
                merged_tup.extend(key);
                next_op.next(&merged_tup);
            }
            next_op.reset(tup);
        },
    )
}

// Implement the split function
fn split(l: Operator, r: Operator) -> Operator {
    Operator::new(
        move |tup| {
            l.next(tup);
            r.next(tup);
        },
        move |tup| {
            l.reset(tup);
            r.reset(tup);
        },
    )
}

// Implement the join function
fn join<F, G>(left_extractor: F, right_extractor: G, next_op: Operator) -> (Operator, Operator)
where
    F: Fn(&Tuple) -> (Tuple, Tuple) + 'static,
    G: Fn(&Tuple) -> (Tuple, Tuple) + 'static,
{
    let mut h_tbl1 = HashMap::new();
    let mut h_tbl2 = HashMap::new();
    let mut left_curr_epoch = 0;
    let mut right_curr_epoch = 0;

    let handle_join_side = move |curr_h_tbl: &mut HashMap<Tuple, Tuple>,
                                 other_h_tbl: &mut HashMap<Tuple, Tuple>,
                                 curr_epoch_ref: &mut i32,
                                 other_epoch_ref: &mut i32,
                                 f: &dyn Fn(&Tuple) -> (Tuple, Tuple)|
         -> Operator {
        Operator::new(
            move |tup| {
                let (key, vals) = f(tup);
                let curr_epoch = int_of_op_result(tup.get("eid").unwrap());
                while curr_epoch > *curr_epoch_ref {
                    if *other_epoch_ref > *curr_epoch_ref {
                        next_op.reset(&HashMap::from([("eid".to_string(), OpResult::Int(*curr_epoch_ref))]));
                    }
                    *curr_epoch_ref += 1;
                }
                let new_tup = HashMap::from([("eid".to_string(), OpResult::Int(curr_epoch))]);
                let new_tup = new_tup.into_iter().chain(key.into_iter()).collect();
                if let Some(val) = other_h_tbl.remove(&new_tup) {
                    let mut merged_tup = new_tup;
                    merged_tup.extend(val);
                    merged_tup.extend(vals);
                    next_op.next(&merged_tup);
                } else {
                    curr_h_tbl.insert(new_tup, vals);
                }
            },
            move |tup| {
                let curr_epoch = int_of_op_result(tup.get("eid").unwrap());
                while curr_epoch > *curr_epoch_ref {
                    if *other_epoch_ref > *curr_epoch_ref {
                        next_op.reset(&HashMap::from([("eid".to_string(), OpResult::Int(*curr_epoch_ref))]));
                    }
                    *curr_epoch_ref += 1;
                }
            },
        )
    };

    (
        handle_join_side(&mut h_tbl1, &mut h_tbl2, &mut left_curr_epoch, &mut right_curr_epoch, &left_extractor),
        handle_join_side(&mut h_tbl2, &mut h_tbl1, &mut right_curr_epoch, &mut left_curr_epoch, &right_extractor),
    )
}

// Implement the rename_filtered_keys function
fn rename_filtered_keys(renamings_pairs: Vec<(String, String)>, in_tup: &Tuple) -> Tuple {
    let mut new_tup = Tuple::new();
    for (old_key, new_key) in renamings_pairs {
        if let Some(val) = in_tup.get(&old_key) {
            new_tup.insert(new_key, val.clone());
        }
    }
    new_tup
}

// Implement the meta_meter function
fn meta_meter(name: &str, outc: &mut dyn Write, next_op: Operator) -> Operator {
    let mut epoch_count = 0;
    let mut tups_count = 0;
    Operator::new(
        move |tup| {
            tups_count += 1;
            next_op.next(tup);
        },
        move |tup| {
            writeln!(outc, "{},{},{},", epoch_count, name, tups_count).unwrap();
            tups_count = 0;
            epoch_count += 1;
            next_op.reset(tup);
        },
    )
}

// Implement the dump_walts_csv function
fn dump_walts_csv(filename: &str) -> Operator {
    let mut outc = File::create(filename).unwrap();
    let mut first = true;
    Operator::new(
        move |tup| {
            if first {
                first = false;
            }
            writeln!(
                outc,
                "{},{},{},{},{},{},{}",
                string_of_op_result(tup.get("src_ip").unwrap()),
                string_of_op_result(tup.get("dst_ip").unwrap()),
                string_of_op_result(tup.get("src_l4_port").unwrap()),
                string_of_op_result(tup.get("dst_l4_port").unwrap()),
                string_of_op_result(tup.get("packet_count").unwrap()),
                string_of_op_result(tup.get("byte_count").unwrap()),
                string_of_op_result(tup.get("epoch_id").unwrap())
            )
            .unwrap();
        },
        |_| {},
    )
}

// Implement the read_walts_csv function
fn read_walts_csv(file_names: Vec<String>) {
    // implementation similar to OCaml version
}

// Implement the ident function
fn ident(next_op: Operator) -> Operator {
    map(
        |tup| {
            tup.iter()
                .filter(|(key, _)| *key != "eth.src" && *key != "eth.dst")
                .cloned()
                .collect()
        },
        next_op,
    )
}

// Implement the count_pkts function
fn count_pkts(next_op: Operator) -> Operator {
    epoch(1.0, "eid", groupby(
        |_| Tuple::new(),
        |val, _| match val {
            OpResult::Empty => OpResult::Int(1),
            OpResult::Int(i) => OpResult::Int(i + 1),
            _ => val,
        },
        "pkts",
        next_op,
    ))
}

// Implement the pkts_per_src_dst function
fn pkts_per_src_dst(next_op: Operator) -> Operator {
    epoch(1.0, "eid", groupby(
        |tup| {
            let mut new_tup = Tuple::new();
            new_tup.insert("ipv4.src".to_string(), tup.get("ipv4.src").unwrap().clone());
            new_tup.insert("ipv4.dst".to_string(), tup.get("ipv4.dst").unwrap().clone());
            new_tup
        },
        |val, _| match val {
            OpResult::Empty => OpResult::Int(1),
            OpResult::Int(i) => OpResult::Int(i + 1),
            _ => val,
        },
        "pkts",
        next_op,
    ))
}

// Implement the rest of the functions (Sonata 1-8, q3, q4)

// Implement the distinct_srcs function
fn distinct_srcs(next_op: Operator) -> Operator {
    epoch(1.0, "eid", distinct(
        |tup| {
            let mut new_tup = Tuple::new();
            new_tup.insert("ipv4.src".to_string(), tup.get("ipv4.src").unwrap().clone());
            new_tup
        },
        groupby(
            |_| Tuple::new(),
            |val, _| match val {
                OpResult::Empty => OpResult::Int(1),
                OpResult::Int(i) => OpResult::Int(i + 1),
                _ => val,
            },
            "srcs",
            next_op,
        ),
    ))
}

// Implement the tcp_new_cons function (Sonata 1)
fn tcp_new_cons(next_op: Operator) -> Operator {
    let threshold = 40;
    epoch(1.0, "eid", filter(
        |tup| {
            int_of_op_result(tup.get("ipv4.proto").unwrap()) == 6
                && int_of_op_result(tup.get("l4.flags").unwrap()) == 2
        },
        groupby(
            |tup| {
                let mut new_tup = Tuple::new();
                new_tup.insert("ipv4.dst".to_string(), tup.get("ipv4.dst").unwrap().clone());
                new_tup
            },
            |val, _| match val {
                OpResult::Empty => OpResult::Int(1),
                OpResult::Int(i) => OpResult::Int(i + 1),
                _ => val,
            },
            "cons",
            filter(
                |tup| int_of_op_result(tup.get("cons").unwrap()) >= threshold,
                next_op,
            ),
        ),
    ))
}

// Implement the ssh_brute_force function (Sonata 2)
fn ssh_brute_force(next_op: Operator) -> Operator {
    let threshold = 40;
    epoch(1.0, "eid", filter(
        |tup| {
            int_of_op_result(tup.get("ipv4.proto").unwrap()) == 6
                && int_of_op_result(tup.get("l4.dport").unwrap()) == 22
        },
        distinct(
            |tup| {
                let mut new_tup = Tuple::new();
                new_tup.insert("ipv4.src".to_string(), tup.get("ipv4.src").unwrap().clone());
                new_tup.insert("ipv4.dst".to_string(), tup.get("ipv4.dst").unwrap().clone());
                new_tup.insert("ipv4.len".to_string(), tup.get("ipv4.len").unwrap().clone());
                new_tup
            },
            groupby(
                |tup| {
                    let mut new_tup = Tuple::new();
                    new_tup.insert("ipv4.dst".to_string(), tup.get("ipv4.dst").unwrap().clone());
                    new_tup.insert("ipv4.len".to_string(), tup.get("ipv4.len").unwrap().clone());
                    new_tup
                },
                |val, _| match val {
                    OpResult::Empty => OpResult::Int(1),
                    OpResult::Int(i) => OpResult::Int(i + 1),
                    _ => val,
                },
                "srcs",
                filter(
                    |tup| int_of_op_result(tup.get("srcs").unwrap()) >= threshold,
                    next_op,
                ),
            ),
        ),
    ))
}

// Implement the super_spreader function (Sonata 3)
fn super_spreader(next_op: Operator) -> Operator {
    let threshold = 40;
    epoch(1.0, "eid", distinct(
        |tup| {
            let mut new_tup = Tuple::new();
            new_tup.insert("ipv4.src".to_string(), tup.get("ipv4.src").unwrap().clone());
            new_tup.insert("ipv4.dst".to_string(), tup.get("ipv4.dst").unwrap().clone());
            new_tup
        },
        groupby(
            |tup| {
                let mut new_tup = Tuple::new();
                new_tup.insert("ipv4.src".to_string(), tup.get("ipv4.src").unwrap().clone());
                new_tup
            },
            |val, _| match val {
                OpResult::Empty => OpResult::Int(1),
                OpResult::Int(i) => OpResult::Int(i + 1),
                _ => val,
            },
            "dsts",
            filter(
                |tup| int_of_op_result(tup.get("dsts").unwrap()) >= threshold,
                next_op,
            ),
        ),
    ))
}

// Implement the port_scan function (Sonata 4)
fn port_scan(next_op: Operator) -> Operator {
    let threshold = 40;
    epoch(1.0, "eid", distinct(
        |tup| {
            let mut new_tup = Tuple::new();
            new_tup.insert("ipv4.src".to_string(), tup.get("ipv4.src").unwrap().clone());
            new_tup.insert("l4.dport".to_string(), tup.get("l4.dport").unwrap().clone());
            new_tup
        },
        groupby(
            |tup| {
                let mut new_tup = Tuple::new();
                new_tup.insert("ipv4.src".to_string(), tup.get("ipv4.src").unwrap().clone());
                new_tup
            },
            |val, _| match val {
                OpResult::Empty => OpResult::Int(1),
                OpResult::Int(i) => OpResult::Int(i + 1),
                _ => val,
            },
            "ports",
            filter(
                |tup| int_of_op_result(tup.get("ports").unwrap()) >= threshold,
                next_op,
            ),
        ),
    ))
}

// Implement the ddos function (Sonata 5)
fn ddos(next_op: Operator) -> Operator {
    let threshold = 45;
    epoch(1.0, "eid", distinct(
        |tup| {
            let mut new_tup = Tuple::new();
            new_tup.insert("ipv4.src".to_string(), tup.get("ipv4.src").unwrap().clone());
            new_tup.insert("ipv4.dst".to_string(), tup.get("ipv4.dst").unwrap().clone());
            new_tup
        },
        groupby(
            |tup| {
                let mut new_tup = Tuple::new();
                new_tup.insert("ipv4.dst".to_string(), tup.get("ipv4.dst").unwrap().clone());
                new_tup
            },
            |val, _| match val {
                OpResult::Empty => OpResult::Int(1),
                OpResult::Int(i) => OpResult::Int(i + 1),
                _ => val,
            },
            "srcs",
            filter(
                |tup| int_of_op_result(tup.get("srcs").unwrap()) >= threshold,
                next_op,
            ),
        ),
    ))
}

// Implement the syn_flood_sonata function (Sonata 6)
fn syn_flood_sonata(next_op: Operator) -> (Operator, Operator, Operator) {
    let threshold = 3;
    let epoch_dur = 1.0;

    let syns = epoch(epoch_dur, "eid", filter(
        |tup| {
            int_of_op_result(tup.get("ipv4.proto").unwrap()) == 6
                && int_of_op_result(tup.get("l4.flags").unwrap()) == 2
        },
        groupby(
            |tup| {
                let mut new_tup = Tuple::new();
                new_tup.insert("ipv4.dst".to_string(), tup.get("ipv4.dst").unwrap().clone());
                new_tup
            },
            |val, _| match val {
                OpResult::Empty => OpResult::Int(1),
                OpResult::Int(i) => OpResult::Int(i + 1),
                _ => val,
            },
            "syns",
            next_op,
        ),
    ));

    let synacks = epoch(epoch_dur, "eid", filter(
        |tup| {
            int_of_op_result(tup.get("ipv4.proto").unwrap()) == 6
                && int_of_op_result(tup.get("l4.flags").unwrap()) == 18
        },
        groupby(
            |tup| {
                let mut new_tup = Tuple::new();
                new_tup.insert("ipv4.src".to_string(), tup.get("ipv4.src").unwrap().clone());
                new_tup
            },
            |val, _| match val {
                OpResult::Empty => OpResult::Int(1),
                OpResult::Int(i) => OpResult::Int(i + 1),
                _ => val,
            },
            "synacks",
            next_op,
        ),
    ));

    let acks = epoch(epoch_dur, "eid", filter(
        |tup| {
            int_of_op_result(tup.get("ipv4.proto").unwrap()) == 6
                && int_of_op_result(tup.get("l4.flags").unwrap()) == 16
        },
        groupby(
            |tup| {
                let mut new_tup = Tuple::new();
                new_tup.insert("ipv4.dst".to_string(), tup.get("ipv4.dst").unwrap().clone());
                new_tup
            },
            |val, _| match val {
                OpResult::Empty => OpResult::Int(1),
                OpResult::Int(i) => OpResult::Int(i + 1),
                _ => val,
            },
            "acks",
            next_op,
        ),
    ));

    let (join_op1, join_op2) = join(
        |tup| {
            (
                rename_filtered_keys(vec![("ipv4.dst".to_string(), "host".to_string())], tup),
                tup.clone(),
            )
        },
        |tup| {
            (
                rename_filtered_keys(vec![("ipv4.src".to_string(), "host".to_string())], tup),
                tup.clone(),
            )
        },
        map(
            |tup| {
                let mut new_tup = tup.clone();
                new_tup.insert(
                    "syns+synacks-acks".to_string(),
                    OpResult::Int(
                        int_of_op_result(tup.get("syns+synacks").unwrap())
                            - int_of_op_result(tup.get("acks").unwrap()),
                    ),
                );
                new_tup
            },
            filter(
                |tup| int_of_op_result(tup.get("syns+synacks-acks").unwrap()) >= threshold,
                next_op,
            ),
        ),
    );

    (syns, synacks, acks)
}

// Implement the completed_flows function (Sonata 7)
fn completed_flows(next_op: Operator) -> (Operator, Operator) {
    let threshold = 1;
    let epoch_dur = 30.0;

    let syns = epoch(epoch_dur, "eid", filter(
        |tup| {
            int_of_op_result(tup.get("ipv4.proto").unwrap()) == 6
                && int_of_op_result(tup.get("l4.flags").unwrap()) == 2
        },
        groupby(
            |tup| {
                let mut new_tup = Tuple::new();
                new_tup.insert("ipv4.dst".to_string(), tup.get("ipv4.dst").unwrap().clone());
                new_tup
            },
            |val, _| match val {
                OpResult::Empty => OpResult::Int(1),
                OpResult::Int(i) => OpResult::Int(i + 1),
                _ => val,
            },
            "syns",
            next_op,
        ),
    ));

    let fins = epoch(epoch_dur, "eid", filter(
        |tup| {
            int_of_op_result(tup.get("ipv4.proto").unwrap()) == 6
                && (int_of_op_result(tup.get("l4.flags").unwrap()) & 1) == 1
        },
        groupby(
            |tup| {
                let mut new_tup = Tuple::new();
                new_tup.insert("ipv4.src".to_string(), tup.get("ipv4.src").unwrap().clone());
                new_tup
            },
            |val, _| match val {
                OpResult::Empty => OpResult::Int(1),
                OpResult::Int(i) => OpResult::Int(i + 1),
                _ => val,
            },
            "fins",
            next_op,
        ),
    ));

    let (join_op1, join_op2) = join(
        |tup| {
            (
                rename_filtered_keys(vec![("ipv4.dst".to_string(), "host".to_string())], tup),
                tup.clone(),
            )
        },
        |tup| {
            (
                rename_filtered_keys(vec![("ipv4.src".to_string(), "host".to_string())], tup),
                tup.clone(),
            )
        },
        map(
            |tup| {
                let mut new_tup = tup.clone();
                new_tup.insert(
                    "diff".to_string(),
                    OpResult::Int(
                        int_of_op_result(tup.get("syns").unwrap())
                            - int_of_op_result(tup.get("fins").unwrap()),
                    ),
                );
                new_tup
            },
            filter(
                |tup| int_of_op_result(tup.get("diff").unwrap()) >= threshold,
                next_op,
            ),
        ),
    );

    (syns, fins)
}

// Implement the slowloris function (Sonata 8)
fn slowloris(next_op: Operator) -> (Operator, Operator) {
    let t1 = 5;
    let t2 = 500;
    let t3 = 90;
    let epoch_dur = 1.0;

    let n_conns = epoch(epoch_dur, "eid", filter(
        |tup| int_of_op_result(tup.get("ipv4.proto").unwrap()) == 6,
        distinct(
            |tup| {
                let mut new_tup = Tuple::new();
                new_tup.insert("ipv4.src".to_string(), tup.get("ipv4.src").unwrap().clone());
                new_tup.insert("ipv4.dst".to_string(), tup.get("ipv4.dst").unwrap().clone());
                new_tup.insert("l4.sport".to_string(), tup.get("l4.sport").unwrap().clone());
                new_tup
            },
            groupby(
                |tup| {
                    let mut new_tup = Tuple::new();
                    new_tup.insert("ipv4.dst".to_string(), tup.get("ipv4.dst").unwrap().clone());
                    new_tup
                },
                |val, _| match val {
                    OpResult::Empty => OpResult::Int(1),
                    OpResult::Int(i) => OpResult::Int(i + 1),
                    _ => val,
                },
                "n_conns",
                filter(
                    |tup| int_of_op_result(tup.get("n_conns").unwrap()) >= t1,
                    next_op,
                ),
            ),
        ),
    ));

    let n_bytes = epoch(epoch_dur, "eid", filter(
        |tup| int_of_op_result(tup.get("ipv4.proto").unwrap()) == 6,
        groupby(
            |tup| {
                let mut new_tup = Tuple::new();
                new_tup.insert("ipv4.dst".to_string(), tup.get("ipv4.dst").unwrap().clone());
                new_tup
            },
            |val, tup| match val {
                OpResult::Empty => OpResult::Int(int_of_op_result(tup.get("ipv4.len").unwrap())),
                OpResult::Int(i) => OpResult::Int(
                    i + int_of_op_result(tup.get("ipv4.len").unwrap()),
                ),
                _ => val,
            },
            "n_bytes",
            filter(
                |tup| int_of_op_result(tup.get("n_bytes").unwrap()) >= t2,
                next_op,
            ),
        ),
    ));

    let (join_op1, join_op2) = join(
        |tup| {
            (
                tup.clone(),
                tup.clone(),
            )
        },
        |tup| {
            (
                tup.clone(),
                tup.clone(),
            )
        },
        map(
            |tup| {
                let mut new_tup = tup.clone();
                new_tup.insert(
                    "bytes_per_conn".to_string(),
                    OpResult::Int(
                        int_of_op_result(tup.get("n_bytes").unwrap())
                            / int_of_op_result(tup.get("n_conns").unwrap()),
                    ),
                );
                new_tup
            },
            filter(
                |tup| int_of_op_result(tup.get("bytes_per_conn").unwrap()) <= t3,
                next_op,
            ),
        ),
    );

    (n_conns, n_bytes)
}

fn main() {
    let mut queries = Vec::new();

    // Create an operator that dumps tuples to stdout
    let dump_op = Operator::new(
        |tup| {
            dump_tuple(&mut io::stdout(), tup);
        },
        |_| {},
    );

    // Create an operator that counts packets
    let count_pkts_op = epoch(1.0, "eid", dump_op);

    queries.push(count_pkts_op);

    // Run the queries
    for i in 0..20 {
        let mut tup = HashMap::new();
        tup.insert("time".to_string(), OpResult::Float(0.000000 + i as f64));
        // ... add other fields to the tuple ...
        for query in &queries {
            query.next(&tup);
        }
    }

    println!("Done");
}