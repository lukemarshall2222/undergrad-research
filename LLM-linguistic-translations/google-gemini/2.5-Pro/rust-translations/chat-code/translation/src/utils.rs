use std::{
    collections::HashMap,
    fmt,
    io::Write,
    net::Ipv4Addr,
    rc::Rc,
    cell::RefCell,
    hash::{Hash, Hasher},
};

// --- Core Types ---

// Represents the possible data types in a tuple.
#[derive(Debug, Clone, PartialEq)]
pub enum OpResult {
    Float(f64),
    Int(i64),
    IPv4(Ipv4Addr),
    MAC([u8; 6]), // Fixed-size array for MAC addresses
    Empty,
}

// Custom Eq implementation needed because f64 doesn't implement Eq.
// For HashMap keys, we only care if non-float variants are equal,
// or if floats are bitwise identical. Use with caution if NaN is possible.
impl Eq for OpResult {}

// Custom Hash implementation needed because f64 doesn't implement Hash.
// Hash floats based on their bit representation.
impl Hash for OpResult {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            OpResult::Float(f) => f.to_bits().hash(state),
            OpResult::Int(i) => i.hash(state),
            OpResult::IPv4(ip) => ip.hash(state),
            OpResult::MAC(mac) => mac.hash(state),
            OpResult::Empty => 0.hash(state), // Consistent hash for Empty
        }
    }
}

// A "tuple" is a map from field names (String) to OpResult values.
pub type Tuple = HashMap<String, OpResult>;

// --- Operator Trait and Types ---

// Defines the interface for any data processing unit (operator).
// Operators are mutable as they often maintain internal state.
pub trait Operator {
    // Process a single tuple.
    fn next(&mut self, tup: Tuple);
    // Signal the end of a batch/epoch, potentially flushing state.
    fn reset(&mut self, tup: Tuple);
}

// Type alias for functions that create operators (taking the next operator).
// Uses dynamic dispatch (dyn) as creators can return different concrete operator types.
pub type OpCreator = Box<dyn FnOnce(Box<dyn Operator>) -> Box<dyn Operator>>;

// Type alias for functions that create two operators (e.g., for joins).
pub type DblOpCreator = Box<dyn FnOnce(Box<dyn Operator>) -> (Box<dyn Operator>, Box<dyn Operator>)>;

// Helper function to chain operator creators (replaces OCaml's @=>).
pub fn chain(creator: OpCreator, next_op: Box<dyn Operator>) -> Box<dyn Operator> {
    creator(next_op)
}

// Helper function to chain double operator creators (replaces OCaml's @==>).
pub fn chain_dbl(
    creator: DblOpCreator,
    next_op: Box<dyn Operator>,
) -> (Box<dyn Operator>, Box<dyn Operator>) {
    creator(next_op)
}


// --- Conversion & Utility Functions ---

impl OpResult {
    /// Attempts to extract an i64 value.
    pub fn as_int(&self) -> Result<i64, String> {
        match self {
            OpResult::Int(i) => Ok(*i),
            _ => Err(format!("Trying to extract int from non-int result: {:?}", self)),
        }
    }

    /// Attempts to extract an f64 value.
    pub fn as_float(&self) -> Result<f64, String> {
        match self {
            OpResult::Float(f) => Ok(*f),
            _ => Err(format!("Trying to extract float from non-float result: {:?}", self)),
        }
    }
}

// Implement Display for easy printing.
impl fmt::Display for OpResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OpResult::Float(fl) => write!(f, "{}", fl),
            OpResult::Int(i) => write!(f, "{}", i),
            OpResult::IPv4(ip) => write!(f, "{}", ip),
            OpResult::MAC(mac) => write!(
                f,
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
            ),
            OpResult::Empty => write!(f, "Empty"),
        }
    }
}

/// Formats the 6 bytes of the MAC address as a colon-separated hex string.
/// Note: This functionality is now part of the Display impl for OpResult::MAC.
pub fn string_of_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

/// Converts TCP flags (represented as an integer) into a human-readable string.
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

    let mut result = String::new();
    for (key, val) in &tcp_flags_map {
        if (flags & val) == *val {
            if !result.is_empty() {
                result.push('|');
            }
            result.push_str(key);
        }
    }
    result
}


/// Creates a string representation of a Tuple (HashMap).
pub fn string_of_tuple(input_tuple: &Tuple) -> String {
    let mut result = String::new();
    for (key, value) in input_tuple.iter() {
        result.push_str(&format!("\"{}\" => {}, ", key, value));
    }
    // Remove trailing ", " if not empty
    if !result.is_empty() {
        result.pop();
        result.pop();
    }
    result
}

/// Creates a Tuple (HashMap) from a vector of (String, OpResult) pairs.
pub fn tuple_of_list(tup_list: Vec<(String, OpResult)>) -> Tuple {
    tup_list.into_iter().collect()
}

/// Prints a formatted representation of a Tuple to a writer.
pub fn dump_tuple<W: Write>(outc: &mut W, tup: &Tuple) -> std::io::Result<()> {
    writeln!(outc, "{}", string_of_tuple(tup))
}


/// Looks up a key and attempts to convert the associated value to an i64.
/// Panics if the key is not found or the value is not an Int.
pub fn lookup_int(key: &str, tup: &Tuple) -> i64 {
    tup.get(key)
       .unwrap_or_else(|| panic!("Key '{}' not found in tuple", key))
       .as_int()
       .unwrap_or_else(|e| panic!("{}", e))
}

/// Looks up a key and attempts to convert the associated value to an f64.
/// Panics if the key is not found or the value is not a Float.
pub fn lookup_float(key: &str, tup: &Tuple) -> f64 {
     tup.get(key)
       .unwrap_or_else(|| panic!("Key '{}' not found in tuple", key))
       .as_float()
       .unwrap_or_else(|e| panic!("{}", e))
}


// Helper function to get an OpResult::IPv4 or OpResult::Int(0)
pub fn get_ip_or_zero(input: &str) -> Result<OpResult, String> {
    if input == "0" {
        Ok(OpResult::Int(0))
    } else {
        input.parse::<Ipv4Addr>()
             .map(OpResult::IPv4)
             .map_err(|e| format!("Failed to parse IP '{}': {}", input, e))
    }
}

// Helper function to look up a key and get the int value, returning Result
pub fn get_mapped_int(key: &str, tup: &Tuple) -> Result<i64, String> {
    match tup.get(key) {
        Some(op_result) => op_result.as_int(),
        None => Err(format!("Key '{}' not found for get_mapped_int", key)),
    }
}

// Helper function to look up a key and get the float value, returning Result
pub fn get_mapped_float(key: &str, tup: &Tuple) -> Result<f64, String> {
     match tup.get(key) {
        Some(op_result) => op_result.as_float(),
        None => Err(format!("Key '{}' not found for get_mapped_float", key)),
    }
}

// --- Common Grouping/Reduction Functions ---

/// Grouping function: Creates a new tuple containing only specified keys.
pub fn filter_groups(incl_keys: &[&str], tup: &Tuple) -> Tuple {
    let mut new_tup = Tuple::new();
    for key in incl_keys {
        if let Some(val) = tup.get(*key) {
            new_tup.insert(key.to_string(), val.clone());
        }
    }
    new_tup
}

/// Grouping function: Forms a single group (returns an empty tuple).
pub fn single_group(_tup: &Tuple) -> Tuple {
    Tuple::new()
}

/// Reduction function: Counts tuples.
pub fn counter(acc: OpResult, _tup: &Tuple) -> OpResult {
    match acc {
        OpResult::Empty => OpResult::Int(1),
        OpResult::Int(i) => OpResult::Int(i + 1),
        _ => {
            eprintln!("Warning: 'counter' received non-Int/Empty accumulator: {:?}", acc);
            acc // Propagate unexpected type
        }
    }
}

/// Reduction function: Sums integer values associated with `search_key`.
pub fn sum_ints(search_key: String) -> impl Fn(OpResult, &Tuple) -> OpResult {
    move |acc: OpResult, tup: &Tuple| -> OpResult {
        let current_sum = match acc {
            OpResult::Empty => 0, // Start count at 0 if accumulator is empty
            OpResult::Int(i) => i,
            _ => {
                eprintln!("Warning: 'sum_ints' received non-Int/Empty accumulator: {:?}", acc);
                return acc; // Propagate unexpected type
            }
        };

        match tup.get(&search_key).cloned() { // Clone OpResult if found
            Some(OpResult::Int(n)) => OpResult::Int(current_sum + n),
            Some(other) => {
                 eprintln!(
                    "Warning: 'sum_ints' found non-Int value {:?} for key '{}'",
                     other, search_key
                 );
                 OpResult::Int(current_sum) // Keep current sum if value is wrong type
            },
            None => {
                eprintln!(
                    "Warning: 'sum_ints' failed to find key '{}' in tuple",
                    search_key
                );
                OpResult::Int(current_sum) // Keep current sum if key is missing
            }
        }
    }
}