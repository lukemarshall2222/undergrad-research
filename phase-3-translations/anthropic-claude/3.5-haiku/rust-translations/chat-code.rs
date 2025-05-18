use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::net::Ipv4Addr;
use std::fmt;

// Enum to represent different types of operation results
#[derive(Clone, Debug)]
enum OpResult {
    Float(f64),
    Int(i64),
    IPv4(Ipv4Addr),
    MAC([u8; 6]),
    Empty,
}

// Trait for converting OpResult to string
impl fmt::Display for OpResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OpResult::Float(val) => write!(f, "{}", val),
            OpResult::Int(val) => write!(f, "{}", val),
            OpResult::IPv4(addr) => write!(f, "{}", addr),
            OpResult::MAC(mac) => write!(f, "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", 
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]),
            OpResult::Empty => write!(f, "Empty"),
        }
    }
}

// Tuple type as a HashMap of strings to OpResult
type Tuple = HashMap<String, OpResult>;

// Operator struct with next and reset methods
struct Operator {
    next: Box<dyn Fn(&Tuple)>,
    reset: Box<dyn Fn(&Tuple)>,
}

// Utility functions for converting OpResult
fn int_of_op_result(result: &OpResult) -> Result<i64, String> {
    match result {
        OpResult::Int(i) => Ok(*i),
        _ => Err("Trying to extract int from non-int result".to_string()),
    }
}

fn float_of_op_result(result: &OpResult) -> Result<f64, String> {
    match result {
        OpResult::Float(f) => Ok(*f),
        _ => Err("Trying to extract float from non-float result".to_string()),
    }
}

// Group by utility functions
fn filter_groups(incl_keys: &[&str], tup: &Tuple) -> Tuple {
    tup.iter()
        .filter(|(k, _)| incl_keys.contains(&k.as_str()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

fn single_group(_: &Tuple) -> Tuple {
    HashMap::new()
}

// Reduction functions
fn counter(val: &OpResult, _tup: &Tuple) -> OpResult {
    match val {
        OpResult::Empty => OpResult::Int(1),
        OpResult::Int(i) => OpResult::Int(i + 1),
        _ => val.clone(),
    }
}

fn sum_ints(search_key: &str, init_val: &OpResult, tup: &Tuple) -> OpResult {
    match init_val {
        OpResult::Empty => OpResult::Int(0),
        OpResult::Int(i) => {
            match tup.get(search_key) {
                Some(OpResult::Int(n)) => OpResult::Int(n + i),
                _ => panic!("Failed to find integer value for key '{}'", search_key),
            }
        }
        _ => init_val.clone(),
    }
}

// Join and filter utilities
fn key_geq_int(key: &str, threshold: i64, tup: &Tuple) -> bool {
    match tup.get(key) {
        Some(val) => int_of_op_result(val).map_or(false, |v| v >= threshold),
        None => false,
    }

fn get_mapped_int(key: &str, tup: &Tuple) -> i64 {
    int_of_op_result(tup.get(key).expect("Key not found")).unwrap()
}

// Example query functions following similar structure to OCaml code
fn ident(next_op: &Operator) -> Operator {
    Operator {
        next: Box::new(|tup| {
            let filtered_tup: Tuple = tup.iter()
                .filter(|(k, _)| k != "eth.src" && k != "eth.dst")
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            (next_op.next)(&filtered_tup);
        }),
        reset: Box::new(|tup| (next_op.reset)(tup)),
    }
}

fn count_pkts(next_op: &Operator) -> Operator {
    // Simplified version, as full epoch implementation would be complex
    let epoch_op = Operator {
        next: Box::new(|tup| {
            let mut new_tup = tup.clone();
            new_tup.insert("eid".to_string(), OpResult::Int(1));
            (next_op.next)(&new_tup);
        }),
        reset: Box::new(|tup| (next_op.reset)(tup)),
    };

    let groupby_op = Operator {
        next: Box::new(|tup| {
            let count_result = counter(&OpResult::Empty, tup);
            let mut new_tup = tup.clone();
            new_tup.insert("pkts".to_string(), count_result);
            (next_op.next)(&new_tup);
        }),
        reset: Box::new(|tup| (next_op.reset)(tup)),
    };

    // Chain operators similar to OCaml's @=> 
    // This would require more complex macro or trait implementation in real code
    groupby_op
}

// Continuing from the previous implementation...

// TCP Flags conversion utility
fn tcp_flags_to_strings(flags: i64) -> String {
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

    tcp_flags.iter()
        .filter(|&&(_, value)| flags & value == value)
        .map(|&(key, _)| key)
        .collect::<Vec<&str>>()
        .join("|")
}

// Distinct function
fn distinct(groupby: &dyn Fn(&Tuple) -> Tuple, next_op: &Operator) -> Operator {
    let mut seen = HashSet::new();
    
    Operator {
        next: Box::new(move |tup| {
            let grouping_key = groupby(tup);
            if seen.insert(grouping_key.clone()) {
                let merged_tup = tup.clone();
                (next_op.next)(&merged_tup);
            }
        }),
        reset: Box::new(move |tup| {
            seen.clear();
            (next_op.reset)(tup);
        }),
    }
}

// More complex queries
fn tcp_new_cons(next_op: &Operator) -> Operator {
    let threshold = 40;
    
    let filter_op = Operator {
        next: Box::new(|tup| {
            if get_mapped_int("ipv4.proto", tup) == 6 && 
               get_mapped_int("l4.flags", tup) == 2 {
                (next_op.next)(tup);
            }
        }),
        reset: Box::new(|tup| (next_op.reset)(tup)),
    };

    let groupby_op = Operator {
        next: Box::new(|tup| {
            let filtered_groups = filter_groups(&["ipv4.dst"], tup);
            let count_result = counter(&OpResult::Empty, tup);
            
            let mut new_tup = filtered_groups.clone();
            new_tup.insert("cons".to_string(), count_result);
            
            if key_geq_int("cons", threshold, &new_tup) {
                (next_op.next)(&new_tup);
            }
        }),
        reset: Box::new(|tup| (next_op.reset)(tup)),
    };

    groupby_op
}

fn ssh_brute_force(next_op: &Operator) -> Operator {
    let threshold = 40;
    
    let filter_op = Operator {
        next: Box::new(|tup| {
            if get_mapped_int("ipv4.proto", tup) == 6 && 
               get_mapped_int("l4.dport", tup) == 22 {
                (next_op.next)(tup);
            }
        }),
        reset: Box::new(|tup| (next_op.reset)(tup)),
    };

    let distinct_op = distinct(
        &|tup| filter_groups(&["ipv4.src", "ipv4.dst", "ipv4.len"], tup),
        &Operator {
            next: Box::new(|tup| {
                let groupby_result = counter(&OpResult::Empty, tup);
                let mut new_tup = filter_groups(&["ipv4.dst", "ipv4.len"], tup);
                new_tup.insert("srcs".to_string(), groupby_result);
                
                if key_geq_int("srcs", threshold, &new_tup) {
                    (next_op.next)(&new_tup);
                }
            }),
            reset: Box::new(|tup| (next_op.reset)(tup)),
        }
    );

    distinct_op
}

fn super_spreader(next_op: &Operator) -> Operator {
    let threshold = 40;
    
    let distinct_op = distinct(
        &|tup| filter_groups(&["ipv4.src", "ipv4.dst"], tup),
        &Operator {
            next: Box::new(|tup| {
                let groupby_result = counter(&OpResult::Empty, tup);
                let mut new_tup = filter_groups(&["ipv4.src"], tup);
                new_tup.insert("dsts".to_string(), groupby_result);
                
                if key_geq_int("dsts", threshold, &new_tup) {
                    (next_op.next)(&new_tup);
                }
            }),
            reset: Box::new(|tup| (next_op.reset)(tup)),
        }
    );

    distinct_op
}

// Join operation (simplified)
fn join<F1, F2>(
    left_extractor: F1, 
    right_extractor: F2, 
    next_op: &Operator
) -> (Operator, Operator) 
where 
    F1: Fn(&Tuple) -> (Tuple, Tuple) + 'static,
    F2: Fn(&Tuple) -> (Tuple, Tuple) + 'static,
{
    let mut left_table: HashMap<Tuple, Tuple> = HashMap::new();
    let mut right_table: HashMap<Tuple, Tuple> = HashMap::new();
    
    let left_join_op = Operator {
        next: Box::new(move |tup| {
            let (key, vals) = left_extractor(tup);
            
            if let Some(right_vals) = right_table.get(&key) {
                let mut merged_tup = key.clone();
                merged_tup.extend(vals.clone());
                merged_tup.extend(right_vals.clone());
                
                (next_op.next)(&merged_tup);
                right_table.remove(&key);
            } else {
                left_table.insert(key, vals);
            }
        }),
        reset: Box::new(|_| {}),
    };

    let right_join_op = Operator {
        next: Box::new(move |tup| {
            let (key, vals) = right_extractor(tup);
            
            if let Some(left_vals) = left_table.get(&key) {
                let mut merged_tup = key.clone();
                merged_tup.extend(vals.clone());
                merged_tup.extend(left_vals.clone());
                
                (next_op.next)(&merged_tup);
                left_table.remove(&key);
            } else {
                right_table.insert(key, vals);
            }
        }),
        reset: Box::new(|_| {}),
    };

    (left_join_op, right_join_op)
}

// Syn Flood detection (simplified Sonata-style)
fn syn_flood_sonata(next_op: &Operator) -> Vec<Operator> {
    let threshold = 3;
    
    let syns_op = Operator {
        next: Box::new(|tup| {
            if get_mapped_int("ipv4.proto", tup) == 6 && 
               get_mapped_int("l4.flags", tup) == 2 {
                let mut new_tup = filter_groups(&["ipv4.dst"], tup);
                new_tup.insert("syns".to_string(), counter(&OpResult::Empty, tup));
                (next_op.next)(&new_tup);
            }
        }),
        reset: Box::new(|_| {}),
    };

    let synacks_op = Operator {
        next: Box::new(|tup| {
            if get_mapped_int("ipv4.proto", tup) == 6 && 
               get_mapped_int("l4.flags", tup) == 18 {
                let mut new_tup = filter_groups(&["ipv4.src"], tup);
                new_tup.insert("synacks".to_string(), counter(&OpResult::Empty, tup));
                (next_op.next)(&new_tup);
            }
        }),
        reset: Box::new(|_| {}),
    };

    // Note: Full implementation of complex join logic would be more intricate
    vec![syns_op, synacks_op]
}

// Continuing from the previous implementation...

// Port Scan Query
fn port_scan(next_op: &Operator) -> Operator {
    let threshold = 40;
    
    let distinct_op = distinct(
        &|tup| filter_groups(&["ipv4.src", "l4.dport"], tup),
        &Operator {
            next: Box::new(|tup| {
                let groupby_result = counter(&OpResult::Empty, tup);
                let mut new_tup = filter_groups(&["ipv4.src"], tup);
                new_tup.insert("ports".to_string(), groupby_result);
                
                if key_geq_int("ports", threshold, &new_tup) {
                    (next_op.next)(&new_tup);
                }
            }),
            reset: Box::new(|tup| (next_op.reset)(tup)),
        }
    );

    distinct_op
}

// DDoS Detection Query
fn ddos(next_op: &Operator) -> Operator {
    let threshold = 45;
    
    let distinct_op = distinct(
        &|tup| filter_groups(&["ipv4.src", "ipv4.dst"], tup),
        &Operator {
            next: Box::new(|tup| {
                let groupby_result = counter(&OpResult::Empty, tup);
                let mut new_tup = filter_groups(&["ipv4.dst"], tup);
                new_tup.insert("srcs".to_string(), groupby_result);
                
                if key_geq_int("srcs", threshold, &new_tup) {
                    (next_op.next)(&new_tup);
                }
            }),
            reset: Box::new(|tup| (next_op.reset)(tup)),
        }
    );

    distinct_op
}

// Completed Flows Query
fn completed_flows(next_op: &Operator) -> Vec<Operator> {
    let threshold = 1;
    let epoch_dur = 30.0; // Simplified epoch management
    
    let syns_op = Operator {
        next: Box::new(|tup| {
            if get_mapped_int("ipv4.proto", tup) == 6 && 
               get_mapped_int("l4.flags", tup) == 2 {
                let mut new_tup = filter_groups(&["ipv4.dst"], tup);
                new_tup.insert("syns".to_string(), counter(&OpResult::Empty, tup));
                (next_op.next)(&new_tup);
            }
        }),
        reset: Box::new(|_| {}),
    };

    let fins_op = Operator {
        next: Box::new(|tup| {
            if get_mapped_int("ipv4.proto", tup) == 6 && 
               (get_mapped_int("l4.flags", tup) & 1) == 1 {
                let mut new_tup = filter_groups(&["ipv4.src"], tup);
                new_tup.insert("fins".to_string(), counter(&OpResult::Empty, tup));
                (next_op.next)(&new_tup);
            }
        }),
        reset: Box::new(|_| {}),
    };

    // Simplified join logic
    let join_op = Operator {
        next: Box::new(|tup| {
            let mut new_tup = tup.clone();
            let syns_count = get_mapped_int("syns", tup);
            let fins_count = get_mapped_int("fins", tup);
            
            new_tup.insert("diff".to_string(), OpResult::Int(syns_count - fins_count));
            
            if key_geq_int("diff", threshold, &new_tup) {
                (next_op.next)(&new_tup);
            }
        }),
        reset: Box::new(|_| {}),
    };

    vec![syns_op, fins_op]
}

// Slowloris Detection Query
fn slowloris(next_op: &Operator) -> Vec<Operator> {
    let t1 = 5;    // Minimum number of connections
    let t2 = 500;  // Minimum total bytes
    let t3 = 90;   // Maximum bytes per connection

    let n_conns_op = Operator {
        next: Box::new(|tup| {
            if get_mapped_int("ipv4.proto", tup) == 6 {
                let distinct_tup = filter_groups(&["ipv4.src", "ipv4.dst", "l4.sport"], tup);
                let mut new_tup = filter_groups(&["ipv4.dst"], tup);
                new_tup.insert("n_conns".to_string(), counter(&OpResult::Empty, &distinct_tup));
                
                if key_geq_int("n_conns", t1, &new_tup) {
                    (next_op.next)(&new_tup);
                }
            }
        }),
        reset: Box::new(|_| {}),
    };

    let n_bytes_op = Operator {
        next: Box::new(|tup| {
            if get_mapped_int("ipv4.proto", tup) == 6 {
                let mut new_tup = filter_groups(&["ipv4.dst"], tup);
                new_tup.insert("n_bytes".to_string(), 
                    sum_ints("ipv4.len", &OpResult::Empty, tup));
                
                if key_geq_int("n_bytes", t2, &new_tup) {
                    (next_op.next)(&new_tup);
                }
            }
        }),
        reset: Box::new(|_| {}),
    };

    // Simplified join logic
    let join_op = Operator {
        next: Box::new(|tup| {
            let mut new_tup = tup.clone();
            let n_conns = get_mapped_int("n_conns", tup);
            let n_bytes = get_mapped_int("n_bytes", tup);
            
            let bytes_per_conn = if n_conns > 0 { n_bytes / n_conns } else { 0 };
            new_tup.insert("bytes_per_conn".to_string(), OpResult::Int(bytes_per_conn));
            
            if bytes_per_conn <= t3 {
                (next_op.next)(&new_tup);
            }
        }),
        reset: Box::new(|_| {}),
    };

    vec![n_conns_op, n_bytes_op]
}

// Additional simple queries
fn q3(next_op: &Operator) -> Operator {
    let distinct_op = distinct(
        &|tup| filter_groups(&["ipv4.src", "ipv4.dst"], tup),
        &Operator {
            next: Box::new(|tup| {
                (next_op.next)(tup);
            }),
            reset: Box::new(|tup| (next_op.reset)(tup)),
        }
    );

    distinct_op
}

fn q4(next_op: &Operator) -> Operator {
    Operator {
        next: Box::new(|tup| {
            let mut new_tup = filter_groups(&["ipv4.dst"], tup);
            new_tup.insert("pkts".to_string(), counter(&OpResult::Empty, tup));
            (next_op.next)(&new_tup);
        }),
        reset: Box::new(|tup| (next_op.reset)(tup)),
    }
}

// Utility function to create a simple dump operator
fn create_dump_operator() -> Operator {
    Operator {
        next: Box::new(|tup| {
            for (key, value) in tup {
                println!("{}: {}", key, value);
            }
        }),
        reset: Box::new(|_| {}),
    }
}

fn main() {
    // Example of how to set up and run queries
    let dump_op = create_dump_operator();

    // Create sample tuples
    let mut tuples: Vec<Tuple> = Vec::new();
    
    for i in 0..20 {
        let mut tuple = HashMap::new();
        
        tuple.insert("time".to_string(), OpResult::Float(i as f64));
        tuple.insert("eth.src".to_string(), OpResult::MAC([0, 17, 34, 51, 68, 85]));
        tuple.insert("eth.dst".to_string(), OpResult::MAC([170, 187, 204, 221, 238, 255]));
        tuple.insert("eth.ethertype".to_string(), OpResult::Int(0x0800));
        
        tuple.insert("ipv4.hlen".to_string(), OpResult::Int(20));
        tuple.insert("ipv4.proto".to_string(), OpResult::Int(6));
        tuple.insert("ipv4.len".to_string(), OpResult::Int(60));
        tuple.insert("ipv4.src".to_string(), OpResult::IPv4("127.0.0.1".parse().unwrap()));
        tuple.insert("ipv4.dst".to_string(), OpResult::IPv4("127.0.0.1".parse().unwrap()));
        
        tuple.insert("l4.sport".to_string(), OpResult::Int(440));
        tuple.insert("l4.dport".to_string(), OpResult::Int(50000));
        tuple.insert("l4.flags".to_string(), OpResult::Int(10));
        
        tuples.push(tuple);
    }

    // Example of running a query
    let tcp_new_cons_query = tcp_new_cons(&dump_op);

    for tuple in &tuples {
        (tcp_new_cons_query.next)(tuple);
    }
}