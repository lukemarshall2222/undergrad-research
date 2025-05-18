use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::rc::Rc;
use std::cell::RefCell;
use std::fmt;
use std::io::{Write, BufReader, BufRead}; // Added BufReader/BufRead for file reading
use std::fs::File; // Added for file handling

// --- Custom Error Type ---
#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Parse(String),
    NotFound(String),
    TypeError(String),
    Other(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "I/O Error: {}", e),
            Error::Parse(s) => write!(f, "Parse Error: {}", s),
            Error::NotFound(key) => write!(f, "Key not found: {}", key),
            Error::TypeError(s) => write!(f, "Type Error: {}", s),
            Error::Other(s) => write!(f, "Error: {}", s),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Io(err)
    }
}

impl From<std::num::ParseIntError> for Error {
    fn from(err: std::num::ParseIntError) -> Self {
        Error::Parse(format!("Failed to parse integer: {}", err))
    }
}

impl From<std::num::ParseFloatError> for Error {
    fn from(err: std::num::ParseFloatError) -> Self {
        Error::Parse(format!("Failed to parse float: {}", err))
    }
}

impl From<std::net::AddrParseError> for Error {
    fn from(err: std::net::AddrParseError) -> Self {
        Error::Parse(format!("Failed to parse IP address: {}", err))
    }
}


// --- Core Types ---

// op_result variant type
#[derive(Debug, Clone, PartialEq)] // Added PartialEq for potential key usage, Float needs care
pub enum OpResult {
    Float(f64),
    Int(i64), // Using i64 for potentially larger counts/values
    IPv4(Ipv4Addr),
    MAC([u8; 6]), // Fixed size array for MAC
    Empty,
}

// Implement Eq and Hash manually if OpResult needs to be part of a hash key
// Note: Hashing f64 is tricky. Usually, you'd hash its bit representation
// or disallow floats in keys.
// For simplicity, deriving Hash is omitted here, assuming GroupKey handles hashing.
impl Eq for OpResult {} // Placeholder Eq

// Placeholder Hash implementation - **AVOID HASHING f64 directly**
// A real implementation would handle f64 carefully (e.g., using u64 bits)
// or disallow Floats in hashable keys.
impl std::hash::Hash for OpResult {
     fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
         match self {
             OpResult::Float(f) => f.to_bits().hash(state), // Hash bit representation
             OpResult::Int(i) => i.hash(state),
             OpResult::IPv4(ip) => ip.hash(state),
             OpResult::MAC(mac) => mac.hash(state),
             OpResult::Empty => 0.hash(state), // Or some other constant
         }
     }
}


// Tuple is a map from strings to op_results
pub type Tuple = HashMap<String, OpResult>;

// Placeholder for hashable keys derived from Tuples in groupby/distinct/join
// This should be defined based on the actual keys used (e.g., a struct, a tuple).
// It MUST derive Eq and Hash.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GroupKey {
   // Example fields - adjust based on actual grouping logic
   // field1: Option<OpResult>,
   // field2: Option<OpResult>,
   // Or perhaps just a canonical string representation:
   repr: String,
}

// Placeholder for join keys
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct JoinKey {
   // Example: Often includes epoch ID and grouping fields
   // eid: i64,
   // key_tuple: GroupKey, // Re-use GroupKey or define specific join fields
   repr: String, // Simplistic string representation
}

// Operator structure holding processing functions (closures)
// Using Rc<RefCell<>> for mutable state captured by closures
pub struct Operator {
    // Processes a tuple, potentially with side effects or state changes
    pub next: Box<dyn FnMut(Tuple) -> Result<(), Error>>,
    // Performs reset operation, often at epoch boundaries
    pub reset: Box<dyn FnMut(Tuple) -> Result<(), Error>>,
}

// Type alias for functions that create operators (taking the next operator)
pub type OpCreator = Box<dyn FnOnce(Operator) -> Result<Operator, Error>>;

// Type alias for functions that create two operators (e.g., for join)
pub type DblOpCreator = Box<dyn FnOnce(Operator) -> Result<(Operator, Operator), Error>>;


// --- Conversion Utilities ---

// Formats MAC address as a colon-separated hex string
pub fn string_of_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

// Converts TCP flags integer into a human-readable string
pub fn tcp_flags_to_strings(flags: i64) -> String {
    const TCP_FLAGS: [(&str, i64); 8] = [
        ("FIN", 1 << 0),
        ("SYN", 1 << 1),
        ("RST", 1 << 2),
        ("PSH", 1 << 3),
        ("ACK", 1 << 4),
        ("URG", 1 << 5),
        ("ECE", 1 << 6),
        ("CWR", 1 << 7),
    ];

    TCP_FLAGS
        .iter()
        .filter(|&&(_, mask)| (flags & mask) == mask)
        .map(|&(name, _)| name)
        .collect::<Vec<&str>>()
        .join("|")
}

// Extracts int from OpResult, returns Error if not Int
pub fn int_of_op_result(input: &OpResult) -> Result<i64, Error> {
    match input {
        OpResult::Int(i) => Ok(*i),
        _ => Err(Error::TypeError(format!(
            "Trying to extract int from non-int result: {:?}", input
        ))),
    }
}

// Extracts float from OpResult, returns Error if not Float
pub fn float_of_op_result(input: &OpResult) -> Result<f64, Error> {
    match input {
        OpResult::Float(f) => Ok(*f),
        _ => Err(Error::TypeError(format!(
            "Trying to extract float from non-float result: {:?}", input
        ))),
    }
}

// Implement Display for OpResult for easy printing
impl fmt::Display for OpResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OpResult::Float(fl) => write!(f, "{}", fl),
            OpResult::Int(i) => write!(f, "{}", i),
            OpResult::IPv4(a) => write!(f, "{}", a),
            OpResult::MAC(m) => write!(f, "{}", string_of_mac(m)),
            OpResult::Empty => write!(f, "Empty"),
        }
    }
}

// Creates a string representation of a Tuple (HashMap)
pub fn string_of_tuple(input_tuple: &Tuple) -> String {
    input_tuple
        .iter()
        .map(|(key, value)| format!("\"{}\" => {}, ", key, value))
        .collect::<String>()
}

// Creates a Tuple (HashMap) from a Vec of (String, OpResult) pairs
pub fn tuple_of_list(tup_list: Vec<(String, OpResult)>) -> Tuple {
    tup_list.into_iter().collect()
}

// Prints a formatted representation of a Tuple to a Writer
pub fn dump_tuple<W: Write>(outc: &mut W, tup: &Tuple) -> Result<(), Error> {
    writeln!(outc, "{}", string_of_tuple(tup))?;
    Ok(())
}

// Retrieves the int value associated with a key in the Tuple
pub fn lookup_int(key: &str, tup: &Tuple) -> Result<i64, Error> {
    tup.get(key)
       .ok_or_else(|| Error::NotFound(key.to_string()))
       .and_then(int_of_op_result) // Use and_then to chain Result operations
}

// Retrieves the float value associated with a key in the Tuple
pub fn lookup_float(key: &str, tup: &Tuple) -> Result<f64, Error> {
    tup.get(key)
       .ok_or_else(|| Error::NotFound(key.to_string()))
       .and_then(float_of_op_result)
}

// Helper to create a canonical, hashable string key from specific tuple fields
// This is a *crucial* function you'll need to implement correctly for groupby/distinct/join
pub fn create_group_key(keys: &[&str], tup: &Tuple) -> GroupKey {
     // Implementation depends heavily on how you want to define equality and hashing
     // Option 1: Concatenate string representations (simple but potentially slow/fragile)
    let key_string = keys.iter()
        .map(|k| tup.get(*k).map_or("".to_string(), |v| v.to_string()))
        .collect::<Vec<String>>()
        .join("|"); // Use a separator

     // Option 2: Create a struct/tuple with Option<OpResult> if OpResult is hashable
     // Requires OpResult to implement Hash and Eq correctly (esp. for Float)

     // Option 3: Hash the relevant parts directly (more complex)

    // Using Option 1 for demonstration:
    GroupKey { repr: key_string }
}

// Helper to create a canonical join key (often includes epoch ID)
pub fn create_join_key(eid_key: &str, group_keys: &[&str], tup: &Tuple) -> Result<JoinKey, Error> {
    let eid = lookup_int(eid_key, tup)?;
    let group_part = group_keys.iter()
        .map(|k| tup.get(*k).map_or("".to_string(), |v| v.to_string()))
        .collect::<Vec<String>>()
        .join("|");

    Ok(JoinKey { repr: format!("{}-{}", eid, group_part) })
}

// Helper to merge two tuples (HashMaps). OCaml's union had a function for conflicts.
// This version prioritizes keys from the second tuple in case of overlap.
pub fn merge_tuples(tup1: Tuple, tup2: Tuple) -> Tuple {
    let mut result = tup1;
    for (key, value) in tup2 {
        result.insert(key, value);
    }
    result
}

// Helper to merge tuples, prioritizing keys from `tup_primary`
pub fn merge_tuples_prefer_primary(mut primary_tup: Tuple, secondary_tup: Tuple) -> Tuple {
    for (key, value) in secondary_tup {
        primary_tup.entry(key).or_insert(value);
    }
    primary_tup
}