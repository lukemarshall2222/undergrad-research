use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::net::Ipv4Addr;
use std::fmt;

// Equivalent to OCaml's op_result type
#[derive(Clone, Debug)]
enum OpResult {
    Float(f64),
    Int(i32),
    IPv4(Ipv4Addr),
    MAC([u8; 6]),
    Empty,
}

// Type alias for Tuple similar to OCaml's Map
type Tuple = HashMap<String, OpResult>;

// Operator struct to mimic OCaml's record type
struct Operator {
    next: Box<dyn Fn(&Tuple)>,
    reset: Box<dyn Fn(&Tuple)>,
}

// Utility functions similar to OCaml's utility functions

fn string_of_mac(mac: &[u8; 6]) -> String {
    format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

fn tcp_flags_to_string(flags: i32) -> String {
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

fn int_of_op_result(input: &OpResult) -> Result<i32, String> {
    match input {
        OpResult::Int(i) => Ok(*i),
        _ => Err("Trying to extract int from non-int result".to_string()),
    }
}

fn float_of_op_result(input: &OpResult) -> Result<f64, String> {
    match input {
        OpResult::Float(f) => Ok(*f),
        _ => Err("Trying to extract float from non-float result".to_string()),
    }
}

fn string_of_op_result(input: &OpResult) -> String {
    match input {
        OpResult::Float(f) => format!("{}", f),
        OpResult::Int(i) => i.to_string(),
        OpResult::IPv4(a) => a.to_string(),
        OpResult::MAC(m) => string_of_mac(m),
        OpResult::Empty => "Empty".to_string(),
    }
}

// Grouping and reduction function types
type GroupingFunc = Box<dyn Fn(&Tuple) -> Tuple>;
type ReductionFunc = Box<dyn Fn(&OpResult, &Tuple) -> OpResult>;

// Function to create a dummy operator for testing
fn ident(next_op: Operator) -> Operator {
    let next = Box::new(move |tup: &Tuple| {
        let filtered_tup: Tuple = tup.iter()
            .filter(|(key, _)| 
                *key != "eth.src" && *key != "eth.dst")
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        (next_op.next)(&filtered_tup);
    });

    let reset = Box::new(move |tup: &Tuple| {
        (next_op.reset)(tup);
    });

    Operator { next, reset }
}

use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::net::Ipv4Addr;
use std::fmt;

// [Previous code remains the same]

// Additional utility functions
fn lookup_int(key: &str, tup: &Tuple) -> Result<i32, String> {
    tup.get(key)
        .ok_or_else(|| format!("Key not found: {}", key))
        .and_then(int_of_op_result)
}

fn lookup_float(key: &str, tup: &Tuple) -> Result<f64, String> {
    tup.get(key)
        .ok_or_else(|| format!("Key not found: {}", key))
        .and_then(float_of_op_result)
}

// Join-related utilities
fn rename_filtered_keys(renamings: &[(String, String)], input_tup: &Tuple) -> Tuple {
    renamings.iter()
        .filter_map(|(old_key, new_key)| {
            input_tup.get(old_key)
                .map(|val| (new_key.clone(), val.clone()))
        })
        .collect()
}

// Grouping and filtering functions
fn filter_groups(incl_keys: &[String], tup: &Tuple) -> Tuple {
    tup.iter()
        .filter(|(key, _)| incl_keys.contains(key))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

fn single_group(_: &Tuple) -> Tuple {
    HashMap::new()
}

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
                Some(OpResult::Int(n)) => OpResult::Int(i + n),
                _ => panic!("Failed to find integer value"),
            }
        },
        _ => init_val.clone(),
    }
}

// Key extraction and comparison functions
fn key_geq_int(key: &str, threshold: i32, tup: &Tuple) -> bool {
    lookup_int(key, tup)
        .map(|val| val >= threshold)
        .unwrap_or(false)
}

// Epoch-based operators
fn epoch(epoch_width: f64, key_out: &str, next_op: Operator) -> Operator {
    let mut epoch_boundary = 0.0;
    let mut eid = 0;

    let next = Box::new(move |tup: &Tuple| {
        let time = match tup.get("time") {
            Some(OpResult::Float(t)) => *t,
            _ => return,
        };

        if epoch_boundary == 0.0 {
            epoch_boundary = time + epoch_width;
        } else if time >= epoch_boundary {
            while time >= epoch_boundary {
                let mut reset_tup = Tuple::new();
                reset_tup.insert(key_out.to_string(), OpResult::Int(eid));
                (next_op.reset)(&reset_tup);
                epoch_boundary += epoch_width;
                eid += 1;
            }
        }

        let mut processed_tup = tup.clone();
        processed_tup.insert(key_out.to_string(), OpResult::Int(eid));
        (next_op.next)(&processed_tup);
    });

    let reset = Box::new(move |_tup: &Tuple| {
        // Reset logic
    });

    Operator { next, reset }
}

// More complex query patterns
fn tcp_new_cons(next_op: Operator) -> Operator {
    let threshold = 40;

    let filter_fn = |tup: &Tuple| {
        lookup_int("ipv4.proto", tup).unwrap_or(0) == 6 &&
        lookup_int("l4.flags", tup).unwrap_or(0) == 2
    };

    // Implementing the full chain of operators would require more complex 
    // implementation of groupby, filter, etc.
    // This is a simplified representation
    Operator {
        next: Box::new(move |tup| {
            if filter_fn(tup) {
                (next_op.next)(tup);
            }
        }),
        reset: Box::new(move |tup| {
            (next_op.reset)(tup);
        }),
    }
}

// SSH brute force detection
fn ssh_brute_force(next_op: Operator) -> Operator {
    let threshold = 40;

    let filter_fn = |tup: &Tuple| {
        lookup_int("ipv4.proto", tup).unwrap_or(0) == 6 &&
        lookup_int("l4.dport", tup).unwrap_or(0) == 22
    };

    Operator {
        next: Box::new(move |tup| {
            if filter_fn(tup) {
                (next_op.next)(tup);
            }
        }),
        reset: Box::new(move |tup| {
            (next_op.reset)(tup);
        }),
    }
}

fn super_spreader(next_op: Operator) -> Operator {
    let threshold = 40;

    Operator {
        next: Box::new(move |tup| {
            // Simplified distinct and groupby logic
            let mut distinct_tup = Tuple::new();
            distinct_tup.insert("ipv4.src".to_string(), 
                tup.get("ipv4.src").cloned().unwrap_or(OpResult::Empty));
            distinct_tup.insert("ipv4.dst".to_string(), 
                tup.get("ipv4.dst").cloned().unwrap_or(OpResult::Empty));

            if let (Some(OpResult::IPv4(src)), Some(OpResult::IPv4(_))) = 
                (distinct_tup.get("ipv4.src"), distinct_tup.get("ipv4.dst")) {
                // Grouping and counting logic would be more complex in a full implementation
                (next_op.next)(&distinct_tup);
            }
        }),
        reset: Box::new(move |tup| {
            (next_op.reset)(tup);
        }),
    }
}

fn port_scan(next_op: Operator) -> Operator {
    let threshold = 40;

    Operator {
        next: Box::new(move |tup| {
            let mut distinct_tup = Tuple::new();
            distinct_tup.insert("ipv4.src".to_string(), 
                tup.get("ipv4.src").cloned().unwrap_or(OpResult::Empty));
            distinct_tup.insert("l4.dport".to_string(), 
                tup.get("l4.dport").cloned().unwrap_or(OpResult::Empty));

            if let (Some(OpResult::IPv4(src)), Some(OpResult::Int(dport))) = 
                (distinct_tup.get("ipv4.src"), distinct_tup.get("l4.dport")) {
                // Simplified port tracking logic
                (next_op.next)(&distinct_tup);
            }
        }),
        reset: Box::new(move |tup| {
            (next_op.reset)(tup);
        }),
    }
}

fn ddos(next_op: Operator) -> Operator {
    let threshold = 45;

    Operator {
        next: Box::new(move |tup| {
            let mut distinct_tup = Tuple::new();
            distinct_tup.insert("ipv4.src".to_string(), 
                tup.get("ipv4.src").cloned().unwrap_or(OpResult::Empty));
            distinct_tup.insert("ipv4.dst".to_string(), 
                tup.get("ipv4.dst").cloned().unwrap_or(OpResult::Empty));

            if let (Some(OpResult::IPv4(src)), Some(OpResult::IPv4(dst))) = 
                (distinct_tup.get("ipv4.src"), distinct_tup.get("ipv4.dst")) {
                // Simplified DDoS detection logic
                (next_op.next)(&distinct_tup);
            }
        }),
        reset: Box::new(move |tup| {
            (next_op.reset)(tup);
        }),
    }
}

// More complex join-based detection patterns
fn syn_flood_sonata() -> Vec<Operator> {
    let threshold = 3;
    let epoch_dur = 1.0;

    // Syns detection
    let syns = |next_op: Operator| {
        Operator {
            next: Box::new(move |tup| {
                if let (Ok(proto), Ok(flags)) = (
                    lookup_int("ipv4.proto", tup),
                    lookup_int("l4.flags", tup)
                ) {
                    if proto == 6 && flags == 2 {
                        (next_op.next)(tup);
                    }
                }
            }),
            reset: Box::new(move |tup| {
                (next_op.reset)(tup);
            }),
        }
    };

    // Similar pattern for synacks and acks
    let synacks = |next_op: Operator| {
        Operator {
            next: Box::new(move |tup| {
                if let (Ok(proto), Ok(flags)) = (
                    lookup_int("ipv4.proto", tup),
                    lookup_int("l4.flags", tup)
                ) {
                    if proto == 6 && flags == 18 {
                        (next_op.next)(tup);
                    }
                }
            }),
            reset: Box::new(move |tup| {
                (next_op.reset)(tup);
            }),
        }
    };

    let acks = |next_op: Operator| {
        Operator {
            next: Box::new(move |tup| {
                if let (Ok(proto), Ok(flags)) = (
                    lookup_int("ipv4.proto", tup),
                    lookup_int("l4.flags", tup)
                ) {
                    if proto == 6 && flags == 16 {
                        (next_op.next)(tup);
                    }
                }
            }),
            reset: Box::new(move |tup| {
                (next_op.reset)(tup);
            }),
        }
    };

    // In a full implementation, this would involve complex join logic
    vec![
        syns(Operator { 
            next: Box::new(|_| {}), 
            reset: Box::new(|_| {}) 
        }),
        synacks(Operator { 
            next: Box::new(|_| {}), 
            reset: Box::new(|_| {}) 
        }),
        acks(Operator { 
            next: Box::new(|_| {}), 
            reset: Box::new(|_| {}) 
        })
    ]
}

// Slowloris detection
fn slowloris(next_op: Operator) -> Vec<Operator> {
    let t1 = 5;
    let t2 = 500;
    let t3 = 90;
    let epoch_dur = 1.0;

    // Connection count detection
    let n_conns = |next_op: Operator| {
        Operator {
            next: Box::new(move |tup| {
                if let Ok(proto) = lookup_int("ipv4.proto", tup) {
                    if proto == 6 {
                        // Simplified distinct and grouping logic
                        (next_op.next)(tup);
                    }
                }
            }),
            reset: Box::new(move |tup| {
                (next_op.reset)(tup);
            }),
        }
    };

    // Bytes detection
    let n_bytes = |next_op: Operator| {
        Operator {
            next: Box::new(move |tup| {
                if let Ok(proto) = lookup_int("ipv4.proto", tup) {
                    if proto == 6 {
                        // Simplified bytes tracking
                        (next_op.next)(tup);
                    }
                }
            }),
            reset: Box::new(move |tup| {
                (next_op.reset)(tup);
            }),
        }
    };

    vec![
        n_conns(Operator { 
            next: Box::new(|_| {}), 
            reset: Box::new(|_| {}) 
        }),
        n_bytes(Operator { 
            next: Box::new(|_| {}), 
            reset: Box::new(|_| {}) 
        })
    ]
}

// Additional query functions
fn q3(next_op: Operator) -> Operator {
    Operator {
        next: Box::new(move |tup| {
            let mut distinct_tup = Tuple::new();
            distinct_tup.insert("ipv4.src".to_string(), 
                tup.get("ipv4.src").cloned().unwrap_or(OpResult::Empty));
            distinct_tup.insert("ipv4.dst".to_string(), 
                tup.get("ipv4.dst").cloned().unwrap_or(OpResult::Empty));

            (next_op.next)(&distinct_tup);
        }),
        reset: Box::new(move |tup| {
            (next_op.reset)(tup);
        }),
    }
}

fn q4(next_op: Operator) -> Operator {
    Operator {
        next: Box::new(move |tup| {
            let mut grouped_tup = Tuple::new();
            if let Some(dst) = tup.get("ipv4.dst") {
                grouped_tup.insert("ipv4.dst".to_string(), dst.clone());
                // Simplified counting logic
                (next_op.next)(&grouped_tup);
            }
        }),
        reset: Box::new(move |tup| {
            (next_op.reset)(tup);
        }),
    }
}


// Main query runner
fn run_queries() {
    let dump_tuple = Operator {
        next: Box::new(|tup| {
            println!("Tuple: {:?}", tup);
        }),
        reset: Box::new(|_| {}),
    };

    let queries: Vec<Operator> = vec![
        ident(dump_tuple)
    ];

    // Similar tuple generation as in previous example
    for i in 0..20 {
        let mut tup = HashMap::new();
        // ... [previous tuple generation code] ...

        for query in &queries {
            (query.next)(&tup);
        }
    }
}

fn main() {
    run_queries();
    println!("Done");
}