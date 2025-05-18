Prompt: Base prompt

Okay, here's a translation of the provided OCaml code into Rust.

**Caveats & Design Choices:**

1.  **Error Handling:** OCaml uses exceptions (`Failure`). Rust prefers `Result<T, E>`. I've introduced a basic `Error` enum and used `Result` in functions that could fail (parsing, lookups, I/O). Functions that OCaml expected to potentially fail and raise exceptions now return `Result`. `unwrap()` or `expect()` could be used for brevity if you are certain an operation won't fail in specific contexts, but using `Result` is more robust.
2.  **Mutability & State:** OCaml's `ref` is used for mutable state shared across closures (like counters in `groupby`, `meta_meter`, state in `epoch`, `join`). In Rust, this requires shared ownership and interior mutability, typically `Rc<RefCell<T>>` (for single-threaded) or `Arc<Mutex<T>>` (for multi-threaded). I've used `Rc<RefCell<T>>` assuming a single-threaded stream processing model.
3.  **Closures:** OCaml functions readily capture environments. Rust closures (`Fn`, `FnMut`, `FnOnce`) require careful handling of captured variables. Operator functions return structs containing `Box<dyn FnMut(...)>` to store the closures on the heap. `move` is often needed in closure definitions to take ownership of captured variables (especially `Rc`s).
4.  **Tuples (Maps):** OCaml's `Map.Make(String)` becomes Rust's `std::collections::HashMap<String, OpResult>`.
5.  **Hashing `Tuple` Keys:** OCaml's `Hashtbl` could hash the `Map` structure itself (based on content). Rust's `HashMap` requires its keys to implement `Eq` and `Hash`. A `HashMap` itself cannot be directly used as a key in another `HashMap`.
    * **Solution:** The `grouping_func` and `key_extractor` functions in operators like `groupby`, `distinct`, and `join` *must* return a key type that *is* hashable. This typically means extracting the relevant key fields into a new, simpler struct or tuple that derives `Eq` and `Hash`, or creating a canonical string representation. I've modified the signatures and implementations slightly to reflect this, often returning `GroupKey` (you'd need to define `GroupKey` based on the specific fields used in `filter_groups` or similar). For simplicity in this direct translation, I'll use `Tuple` (the `HashMap`) as the key type *conceptually*, but **this needs refinement based on actual usage**. A common pattern is to have the grouping function return a tuple of `OpResult` values or a specific struct derived from the relevant fields. I'll add placeholder types like `GroupKey` and `JoinKey`.
6.  **External Crates:**
    * IP Addresses: Rust's standard library `std::net::Ipv4Addr` is used.
    * MAC Addresses: Represented as `[u8; 6]`.
    * CSV Parsing (`read_walts_csv`): OCaml uses `Scanf`. Rust would typically use the `csv` crate for robust CSV handling. I've sketched a manual line-by-line parsing approach using string splitting for a more direct translation, but the `csv` crate is strongly recommended for real-world use.
    * Time: OCaml doesn't explicitly use a time library here, but float timestamps are present. Rust might use `std::time::Instant` or the `chrono` crate for more complex time handling if needed.
7.  **Infix Operators (`@=>`, `@==>`):** Rust doesn't support custom infix operators like OCaml. These are replaced with regular function calls. Chaining like `a @=> b @=> c` becomes `a(b(c))`.
8.  **Modules:** OCaml modules (`Utils`, `Builtins`) translate to Rust modules (`mod utils { ... }`, `mod builtins { ... }`).
9.  **I/O:** OCaml's `out_channel` is replaced by types implementing `std::io::Write` (like `std::io::Stdout`, `std::fs::File`). `Scanf.Scanning.in_channel` is replaced by types implementing `std::io::BufRead` (like `std::io::BufReader<File>`).
10. **Completeness:** Some parts, especially `read_walts_csv` and the `join` implementation, are complex and depend heavily on the precise semantics and data flow. The provided Rust code aims to match the structure but might need adjustments based on real test cases. The `run_queries` part generating sample data is translated.

---

**`src/utils.rs`** (Corresponds to the first OCaml block)

```rust
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

```

---

**`src/builtins.rs`** (Corresponds to the second OCaml block)

```rust
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
```

---

**`src/main.rs`** (Corresponds to the third OCaml block and entry point)

```rust
use std::collections::HashMap;
use std::rc::Rc;
use std::cell::RefCell;
use std::io::{stdout, Write}; // Use stdout for default output
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::error::Error as StdError; // Alias standard Error trait

// Import local modules
mod utils;
mod builtins;

use crate::utils::*; // Bring utils types/functions into scope
use crate::builtins::*; // Bring builtins types/functions into scope

// --- Query Definitions ---
// These functions now return Result<OpCreator, Error> or Result<DblOpCreator, Error>
// Or directly Result<Operator, Error> if they are the final step.
// They take the *next* operator factory as input.

// Helper to simplify chaining: applies creator B to the output of creator A
fn chain(
    creator_a: OpCreator,
    creator_b: OpCreator,
) -> Result<OpCreator, Error> {
    Ok(Box::new(move |final_op: Operator| -> Result<Operator, Error> {
        let op_b = creator_b(final_op)?;
        creator_a(op_b)
    }))
}

// Helper for chaining Double creators (like join output)
// Applies a function `f` to the output of the join before passing to next_op_creator
fn chain_dbl<F>(
    dbl_creator: DblOpCreator,
    f: F,
    next_op_creator: OpCreator,
) -> Result<(OpCreator, OpCreator), Error>
where
    F: Fn(Operator) -> Result<Operator, Error> + 'static, // Function applied after join
{
     // We need to create two OpCreators that, when called, will execute the full chain
    let dbl_creator_rc = Rc::new(dbl_creator);
    let f_rc = Rc::new(f);
    let next_op_creator_rc = Rc::new(next_op_creator);

    let create_left = Box::new(move |final_op: Operator| -> Result<Operator, Error> {
        let next_op_for_join = (f_rc)(final_op)?; // Apply intermediate op
        let next_op_for_final = (Rc::unwrap_or_clone(next_op_creator_rc.clone()))(next_op_for_join)?; // Apply final creator

        let (op1, _op2) = (Rc::unwrap_or_clone(dbl_creator_rc.clone()))(next_op_for_final)?; // Create join ops
        Ok(op1) // Return the left op from join
    });

     let create_right = Box::new(move |final_op: Operator| -> Result<Operator, Error> {
         let next_op_for_join = (f_rc)(final_op)?;
         let next_op_for_final = (Rc::unwrap_or_clone(next_op_creator_rc.clone()))(next_op_for_join)?;

         let (_op1, op2) = (Rc::unwrap_or_clone(dbl_creator_rc.clone()))(next_op_for_final)?; // Create join ops
         Ok(op2) // Return the right op from join
     });

     Ok((create_left, create_right))


    // Simpler conceptual version (less efficient due to repeated calls):
    // Ok(Box::new(move |final_op: Operator| -> Result<(Operator, Operator), Error> {
    //     let intermediate_op = f(final_op)?;
    //     let next_op_for_join = next_op_creator(intermediate_op)?;
    //     dbl_creator(next_op_for_join)
    // }))

}


// Identity (removes eth fields)
fn ident() -> Result<OpCreator, Error> {
    Ok(Box::new(|next_op: Operator| -> Result<Operator, Error> {
        map(
            Box::new(|mut tup: Tuple| -> Result<Tuple, Error> {
                tup.remove("eth.src");
                tup.remove("eth.dst");
                Ok(tup)
            }),
            next_op,
        )
    }))
}

// Count packets per epoch
fn count_pkts() -> Result<OpCreator, Error> {
    let creator_epoch = Box::new(|next: Operator| epoch(1.0, "eid".to_string(), next));
    let creator_group = Box::new(|next: Operator| groupby(single_group(), counter(), "pkts".to_string(), next));
    chain(creator_epoch, creator_group)
}

// Packets per src/dst per epoch
fn pkts_per_src_dst() -> Result<OpCreator, Error> {
    let creator_epoch = Box::new(|next: Operator| epoch(1.0, "eid".to_string(), next));
    let creator_group = Box::new(|next: Operator| {
        groupby(
            filter_groups(vec!["ipv4.src".to_string(), "ipv4.dst".to_string()]),
            counter(),
            "pkts".to_string(),
            next,
        )
    });
    chain(creator_epoch, creator_group)
}

// Count distinct source IPs per epoch
fn distinct_srcs() -> Result<OpCreator, Error> {
     let creator_epoch = Box::new(|next: Operator| epoch(1.0, "eid".to_string(), next));
     let creator_distinct = Box::new(|next: Operator| {
         distinct(
             filter_groups(vec!["ipv4.src".to_string()]),
             next,
         )
     });
     let creator_group = Box::new(|next: Operator| {
         groupby(single_group(), counter(), "srcs".to_string(), next)
     });

     let chain1 = chain(creator_epoch, creator_distinct)?;
     chain(chain1, creator_group)
}


// Sonata 1: TCP New Connections
fn tcp_new_cons() -> Result<OpCreator, Error> {
    let threshold = 40;
    let creator_epoch = Box::new(|next: Operator| epoch(1.0, "eid".to_string(), next));
    let creator_filter_syn = Box::new(|next: Operator| {
        filter(
            Box::new(|tup: &Tuple| -> bool {
                get_mapped_int("ipv4.proto", tup).map_or(false, |p| p == 6) &&
                get_mapped_int("l4.flags", tup).map_or(false, |f| f == 2) // SYN flag = 2
            }),
            next,
        )
    });
     let creator_group = Box::new(|next: Operator| {
         groupby(
             filter_groups(vec!["ipv4.dst".to_string()]),
             counter(),
             "cons".to_string(),
             next,
         )
     });
     let creator_filter_thresh = Box::new(|next: Operator| {
        filter(key_geq_int("cons".to_string(), threshold), next)
     });

     let chain1 = chain(creator_epoch, creator_filter_syn)?;
     let chain2 = chain(chain1, creator_group)?;
     chain(chain2, creator_filter_thresh)
}


// Sonata 2: SSH Brute Force
fn ssh_brute_force() -> Result<OpCreator, Error> {
     let threshold = 40;
     let creator_epoch = Box::new(|next: Operator| epoch(1.0, "eid".to_string(), next));
     let creator_filter_ssh = Box::new(|next: Operator| {
         filter(
             Box::new(|tup: &Tuple| -> bool {
                 get_mapped_int("ipv4.proto", tup).map_or(false, |p| p == 6) &&
                 get_mapped_int("l4.dport", tup).map_or(false, |p| p == 22)
             }),
             next,
         )
     });
     let creator_distinct = Box::new(|next: Operator| {
         distinct(
             filter_groups(vec![
                 "ipv4.src".to_string(),
                 "ipv4.dst".to_string(),
                 "ipv4.len".to_string(), // Distinct includes packet length
             ]),
             next,
         )
     });
      let creator_group = Box::new(|next: Operator| {
          groupby(
              filter_groups(vec![
                  "ipv4.dst".to_string(),
                  "ipv4.len".to_string(), // Group by destination and length
              ]),
              counter(), // Count distinct sources for each dst/len pair
              "srcs".to_string(),
              next,
          )
      });
      let creator_filter_thresh = Box::new(|next: Operator| {
         filter(key_geq_int("srcs".to_string(), threshold), next)
      });

     let chain1 = chain(creator_epoch, creator_filter_ssh)?;
     let chain2 = chain(chain1, creator_distinct)?;
     let chain3 = chain(chain2, creator_group)?;
     chain(chain3, creator_filter_thresh)
}

// Sonata 3: Super Spreader
fn super_spreader() -> Result<OpCreator, Error> {
     let threshold = 40;
     let creator_epoch = Box::new(|next: Operator| epoch(1.0, "eid".to_string(), next));
     let creator_distinct = Box::new(|next: Operator| {
         distinct(
             filter_groups(vec!["ipv4.src".to_string(), "ipv4.dst".to_string()]),
             next,
         )
     });
      let creator_group = Box::new(|next: Operator| {
          groupby(
              filter_groups(vec!["ipv4.src".to_string()]), // Group by source
              counter(), // Count distinct destinations
              "dsts".to_string(),
              next,
          )
      });
       let creator_filter_thresh = Box::new(|next: Operator| {
          filter(key_geq_int("dsts".to_string(), threshold), next)
       });

     let chain1 = chain(creator_epoch, creator_distinct)?;
     let chain2 = chain(chain1, creator_group)?;
     chain(chain2, creator_filter_thresh)
}

// Sonata 4: Port Scan
fn port_scan() -> Result<OpCreator, Error> {
     let threshold = 40;
     let creator_epoch = Box::new(|next: Operator| epoch(1.0, "eid".to_string(), next));
     let creator_distinct = Box::new(|next: Operator| {
         distinct(
             filter_groups(vec!["ipv4.src".to_string(), "l4.dport".to_string()]),
             next,
         )
     });
      let creator_group = Box::new(|next: Operator| {
          groupby(
              filter_groups(vec!["ipv4.src".to_string()]), // Group by source
              counter(), // Count distinct ports
              "ports".to_string(),
              next,
          )
      });
       let creator_filter_thresh = Box::new(|next: Operator| {
          filter(key_geq_int("ports".to_string(), threshold), next)
       });

     let chain1 = chain(creator_epoch, creator_distinct)?;
     let chain2 = chain(chain1, creator_group)?;
     chain(chain2, creator_filter_thresh)
}

// Sonata 5: DDoS
fn ddos() -> Result<OpCreator, Error> {
     let threshold = 45;
     let creator_epoch = Box::new(|next: Operator| epoch(1.0, "eid".to_string(), next));
     let creator_distinct = Box::new(|next: Operator| {
         distinct(
             filter_groups(vec!["ipv4.src".to_string(), "ipv4.dst".to_string()]),
             next,
         )
     });
      let creator_group = Box::new(|next: Operator| {
          groupby(
              filter_groups(vec!["ipv4.dst".to_string()]), // Group by destination
              counter(), // Count distinct sources
              "srcs".to_string(),
              next,
          )
      });
       let creator_filter_thresh = Box::new(|next: Operator| {
          filter(key_geq_int("srcs".to_string(), threshold), next)
       });

     let chain1 = chain(creator_epoch, creator_distinct)?;
     let chain2 = chain(chain1, creator_group)?;
     chain(chain2, creator_filter_thresh)
}


// Sonata 6: SYN Flood (Sonata version) - Complex Join
// Returns Vec<OpCreator> because join produces multiple inputs
fn syn_flood_sonata() -> Result<Vec<OpCreator>, Error> {
    let threshold: i64 = 3;
    let epoch_dur: f64 = 1.0;
    let eid_key = "eid".to_string();

    // --- Define the pipeline segments ---

    // SYN counter segment creator
    let syns_creator = |next_op: Operator| -> Result<Operator, Error> {
        let c1 = Box::new(|next| epoch(epoch_dur, eid_key.clone(), next));
        let c2 = Box::new(|next| filter(
            Box::new(|tup: &Tuple| -> bool {
                get_mapped_int("ipv4.proto", tup).map_or(false, |p| p == 6) &&
                get_mapped_int("l4.flags", tup).map_or(false, |f| f == 2) // SYN
            }),
            next,
        ));
        let c3 = Box::new(|next| groupby(
            filter_groups(vec!["ipv4.dst".to_string()]),
            counter(),
            "syns".to_string(),
            next,
        ));
        let chain_1 = chain(c1, c2)?;
        let chain_2 = chain(chain_1, c3)?;
        chain_2(next_op)
    };

    // SYN+ACK counter segment creator
    let synacks_creator = |next_op: Operator| -> Result<Operator, Error> {
        let c1 = Box::new(|next| epoch(epoch_dur, eid_key.clone(), next));
        let c2 = Box::new(|next| filter(
             Box::new(|tup: &Tuple| -> bool {
                 get_mapped_int("ipv4.proto", tup).map_or(false, |p| p == 6) &&
                 get_mapped_int("l4.flags", tup).map_or(false, |f| f == 18) // SYN+ACK = 16 + 2
             }),
             next,
         ));
        let c3 = Box::new(|next| groupby(
             filter_groups(vec!["ipv4.src".to_string()]), // Group by source (sender of SYN+ACK)
             counter(),
             "synacks".to_string(),
             next,
         ));
        let chain_1 = chain(c1, c2)?;
        let chain_2 = chain(chain_1, c3)?;
        chain_2(next_op)
    };

    // ACK counter segment creator
    let acks_creator = |next_op: Operator| -> Result<Operator, Error> {
        let c1 = Box::new(|next| epoch(epoch_dur, eid_key.clone(), next));
        let c2 = Box::new(|next| filter(
             Box::new(|tup: &Tuple| -> bool {
                 get_mapped_int("ipv4.proto", tup).map_or(false, |p| p == 6) &&
                 get_mapped_int("l4.flags", tup).map_or(false, |f| f == 16) // ACK
             }),
             next,
         ));
        let c3 = Box::new(|next| groupby(
             filter_groups(vec!["ipv4.dst".to_string()]), // Group by destination (receiver of ACK)
             counter(),
             "acks".to_string(),
             next,
         ));
        let chain_1 = chain(c1, c2)?;
        let chain_2 = chain(chain_1, c3)?;
        chain_2(next_op)
    };

    // --- Define the joins ---

    // Join 1: Join (SYN + SYNACK results) with ACK results
    // Key: host (ipv4.dst for SYNs/ACKs, ipv4.src for SYNACKs - requires renaming)
    // Value left: syns+synacks count
    // Value right: acks count
    let join1_creator = Box::new(|next_op: Operator| -> Result<(Operator, Operator), Error> {
        join(
            eid_key.clone(),
             // Left Input (from Join 2): expects key=("host"), value=("syns+synacks")
            make_key_extractor(eid_key.clone(), vec!["host".to_string()], vec!["syns+synacks".to_string()]),
             // Right Input (from ACK stream): key=rename("ipv4.dst"->"host"), value=("acks")
            make_renaming_key_extractor(eid_key.clone(), vec![("ipv4.dst".to_string(), "host".to_string())], vec!["acks".to_string()]),
            next_op,
        )
    });

    // Join 2: Join SYN results with SYNACK results
    // Key: host (requires renaming: ipv4.dst -> host for SYNs, ipv4.src -> host for SYNACKs)
    // Value left: syns count
    // Value right: synacks count
    let join2_creator = Box::new(|next_op: Operator| -> Result<(Operator, Operator), Error> {
        join(
            eid_key.clone(),
             // Left Input (from SYN stream): key=rename("ipv4.dst"->"host"), value=("syns")
            make_renaming_key_extractor(eid_key.clone(), vec![("ipv4.dst".to_string(), "host".to_string())], vec!["syns".to_string()]),
            // Right Input (from SYNACK stream): key=rename("ipv4.src"->"host"), value=("synacks")
            make_renaming_key_extractor(eid_key.clone(), vec![("ipv4.src".to_string(), "host".to_string())], vec!["synacks".to_string()]),
            next_op,
        )
    });

    // --- Define post-join processing ---

    // Map after Join 2: Calculate "syns+synacks"
    let map_join2 = |next_op: Operator| -> Result<Operator, Error> {
        map(
            Box::new(|mut tup: Tuple| -> Result<Tuple, Error> {
                let syns = get_mapped_int("syns", &tup)?;
                let synacks = get_mapped_int("synacks", &tup)?;
                tup.insert("syns+synacks".to_string(), OpResult::Int(syns + synacks));
                Ok(tup)
            }),
            next_op,
        )
    };

    // Map after Join 1: Calculate "syns+synacks-acks"
    let map_join1 = |next_op: Operator| -> Result<Operator, Error> {
         map(
             Box::new(|mut tup: Tuple| -> Result<Tuple, Error> {
                 let syns_synacks = get_mapped_int("syns+synacks", &tup)?;
                 let acks = get_mapped_int("acks", &tup)?;
                 tup.insert("syns+synacks-acks".to_string(), OpResult::Int(syns_synacks - acks));
                 Ok(tup)
             }),
             next_op,
         )
    };

    // Filter after Join 1: Check threshold
     let filter_final = |next_op: Operator| -> Result<Operator, Error> {
         filter(key_geq_int("syns+synacks-acks".to_string(), threshold), next_op)
     };


    // --- Connect the pipeline ---
    // Working backwards: final_filter takes the output of map_join1
    let final_processing_creator = Box::new(move |final_op: Operator| -> Result<Operator, Error> {
        let op1 = filter_final(final_op)?;
        map_join1(op1)
    });


    // Build the creators for the inputs to Join 1
    // Input 1 (Left): Comes from map_join2 applied to Join 2's output
    // Input 2 (Right): Comes from the acks_creator stream
    let (join1_input1_creator_factory, join1_input2_creator_factory) = chain_dbl(
         join1_creator, // The join we are providing inputs for
         map_join1, // Function applied AFTER join1
         final_processing_creator // Creator applied AFTER map_join1
    )?;


    // Build the creators for the inputs to Join 2
    // Input 1 (Left): Comes from syns_creator stream
    // Input 2 (Right): Comes from synacks_creator stream
    let (join2_input1_creator_factory, join2_input2_creator_factory) = chain_dbl(
         join2_creator, // The join we are providing inputs for
         map_join2, // Function applied AFTER join2
         join1_input1_creator_factory // The creator for join1's left input
    )?;


    // Now, create the final list of OpCreators that need direct input streams
    Ok(vec![
        Box::new(move |final_op: Operator| syns_creator(join2_input1_creator_factory(final_op)?)), // SYN stream -> Join2 Left Input
        Box::new(move |final_op: Operator| synacks_creator(join2_input2_creator_factory(final_op)?)),// SYNACK stream -> Join2 Right Input
        Box::new(move |final_op: Operator| acks_creator(join1_input2_creator_factory(final_op)?)), // ACK stream -> Join1 Right Input
    ])

}


// --- Main Execution Logic ---

// Generates sample data similar to the OCaml example
fn generate_sample_data(count: usize) -> Result<Vec<Tuple>, Error> {
    let mut data = Vec::with_capacity(count);
    let base_time = 0.0f64; // Example start time
    let mac1 = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    let mac2 = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
    let ip1 = Ipv4Addr::from_str("127.0.0.1")?;
    let ip2 = Ipv4Addr::from_str("192.168.1.100")?; // Different IP for variety

    for i in 0..count {
        let mut tup = HashMap::new();
        let time = base_time + (i as f64 * 0.1); // Increment time

        tup.insert("time".to_string(), OpResult::Float(time));

        tup.insert("eth.src".to_string(), OpResult::MAC(mac1));
        tup.insert("eth.dst".to_string(), OpResult::MAC(mac2));
        tup.insert("eth.ethertype".to_string(), OpResult::Int(0x0800)); // IPv4

        tup.insert("ipv4.hlen".to_string(), OpResult::Int(20));
        tup.insert("ipv4.proto".to_string(), OpResult::Int(6)); // TCP
        tup.insert("ipv4.len".to_string(), OpResult::Int(60 + (i as i64 % 10))); // Vary length slightly
        tup.insert("ipv4.src".to_string(), OpResult::IPv4(ip1));
        tup.insert("ipv4.dst".to_string(), OpResult::IPv4(ip2));

        tup.insert("l4.sport".to_string(), OpResult::Int(44000 + (i as i64 % 100))); // Vary source port
        tup.insert("l4.dport".to_string(), OpResult::Int(if i % 3 == 0 { 22 } else { 80 } )); // Alternate dest port (SSH/HTTP)
         // Vary flags: SYN, SYN+ACK, ACK, PSH+ACK
        let flags = match i % 4 {
            0 => 2, // SYN
            1 => 18,// SYN+ACK
            2 => 16,// ACK
            _ => 24,// PSH+ACK
        };
        tup.insert("l4.flags".to_string(), OpResult::Int(flags));

        data.push(tup);
    }
    Ok(data)
}


// Runs the defined queries on sample data
fn run_queries(queries: &mut Vec<Operator>, data: Vec<Tuple>) -> Result<(), Error> {
     if queries.is_empty() {
         println!("No queries to run.");
         return Ok(());
     }

     println!("Running {} queries on {} tuples...", queries.len(), data.len());

    for tup in data {
        for query_op in queries.iter_mut() {
             // Clone tuple if multiple queries might modify/consume it,
             // but here 'next' takes ownership conceptually. Let's clone.
            let tup_clone = tup.clone();
            (query_op.next)(tup_clone).map_err(|e| {
                 // Print error but continue processing other tuples/queries?
                 eprintln!("Error processing tuple in query: {}", e);
                 e // Propagate error to stop execution? Depends on desired behavior.
            })?;
        }
    }

     // After processing all data, send a final reset signal (e.g., with an empty tuple or specific EID)
     // This is crucial for stateful operators like groupby, distinct, epoch, join to flush their state.
     // We need a way to determine the final epoch ID or use a marker tuple.
     // Let's simulate a final reset with a dummy tuple indicating end-of-stream.
     println!("Sending final reset signal...");
     let mut final_reset_tup = HashMap::new();
     // Add a high epoch ID or a special marker if needed by operators like join/epoch
     final_reset_tup.insert("eid".to_string(), OpResult::Int(99999)); // Example final EID
     final_reset_tup.insert("_final_reset_".to_string(), OpResult::Empty);

     for query_op in queries.iter_mut() {
         (query_op.reset)(final_reset_tup.clone()).map_err(|e| {
              eprintln!("Error during final reset: {}", e);
              e
         })?;
     }

    Ok(())
}


// Main entry point
fn main() -> Result<(), Box<dyn StdError>> {
    println!("Starting Rust stream processor simulation...");

    // Get a handle to stdout, wrapped for sharing
    let stdout_handle = Rc::new(RefCell::new(stdout()));

    // --- Define the query pipeline(s) ---
    // Example: Simple count_pkts query dumping to stdout CSV
    let final_op_creator_csv = Box::new(|_: Operator| -> Result<Operator, Error> { // Final op doesn't take a 'next'
         dump_as_csv(stdout_handle.clone(), None, true)
    });

    let count_pkts_pipeline = count_pkts()?; // Get the OpCreator
    let mut pipeline1 = vec![count_pkts_pipeline(final_op_creator_csv(Operator{ next: Box::new(|_| Ok(())), reset: Box::new(|_| Ok(()))})?)?]; // Build the operator chain


    // Example: Sonata 3 (Super Spreader) dumping tuples
    let final_op_creator_dump = Box::new(|_: Operator| -> Result<Operator, Error> {
        dump_op(stdout_handle.clone(), true) // Show resets
    });
    let spreader_pipeline = super_spreader()?;
    let mut pipeline2 = vec![spreader_pipeline(final_op_creator_dump(Operator{ next: Box::new(|_| Ok(())), reset: Box::new(|_| Ok(()))})?)?];

    // --- Generate Data ---
    let sample_data = generate_sample_data(50)?; // Generate 50 sample tuples

    // --- Run Queries ---
    println!("\n--- Running Pipeline 1 (Count Pkts CSV) ---");
    run_queries(&mut pipeline1, sample_data.clone())?; // Pass mutable ref

    println!("\n--- Running Pipeline 2 (Super Spreader Dump) ---");
    run_queries(&mut pipeline2, sample_data)?; // Pass mutable ref


    // --- Example using read_walts_csv (requires CSV files) ---
    /*
    let csv_files = vec!["input1.csv".to_string(), "input2.csv".to_string()];
    // Create two identical pipelines dumping to different files for demonstration
    let final_op1 = dump_walts_csv("output1_rust.csv".to_string())?;
    let final_op2 = dump_walts_csv("output2_rust.csv".to_string())?;

    // Define the processing pipeline creator (e.g., pkts_per_src_dst)
    let pipeline_creator = pkts_per_src_dst()?;

    let op1 = pipeline_creator(final_op1)?;
    let op2 = pipeline_creator(final_op2)?; // Assuming pipeline_creator can be called multiple times

    println!("\n--- Reading Walt's CSV Files ---");
    match read_walts_csv(csv_files, vec![op1, op2], "epoch_id".to_string()) {
        Ok(_) => println!("Finished processing CSV files."),
        Err(e) => eprintln!("Error processing CSV files: {}", e),
    }
    */


    println!("\nRust simulation finished.");
    Ok(())
}

```

**To Compile and Run:**

1.  **Set up Rust:** If you don't have it, install Rust: [https://www.rust-lang.org/tools/install](https://www.rust-lang.org/tools/install)
2.  **Create Project:**
    ```bash
    cargo new ocaml_to_rust_stream
    cd ocaml_to_rust_stream
    ```
3.  **Organize Files:**
    * Create `src/utils.rs` and paste the `utils.rs` code into it.
    * Create `src/builtins.rs` and paste the `builtins.rs` code into it.
    * Replace the contents of `src/main.rs` with the `main.rs` code.
4.  **Declare Modules:** Add module declarations to `src/main.rs` (as shown in the `main.rs` code above):
    ```rust
    mod utils;
    mod builtins;
    ```
5.  **Add Crates (if needed):** If you decide to use external crates like `csv` or `chrono`, add them to your `Cargo.toml` file:
    ```toml
    [dependencies]
    # csv = "1.1" # Example for csv crate
    # chrono = "0.4" # Example for chrono crate
    ```
6.  **Build:**
    ```bash
    cargo build
    ```
7.  **Run:**
    ```bash
    cargo run
    ```

This translation provides a solid starting point. Remember that the `GroupKey`/`JoinKey` handling and the specifics of `read_walts_csv` and `join` are the most complex parts and may require further refinement based on the exact semantics needed.