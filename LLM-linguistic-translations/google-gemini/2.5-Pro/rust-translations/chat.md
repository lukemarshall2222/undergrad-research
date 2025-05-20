Prompt: Base prompt

Okay, here's the Rust translation of the provided OCaml code.

I've aimed for idiomatic Rust, emphasizing:

1.  **Enums and Structs:** Replacing OCaml variants and records.
2.  **Traits:** Using a `Operator` trait instead of function records for defining processing units. This allows for both static and dynamic dispatch.
3.  **Ownership and Borrowing:** Using references (`&`, `&mut`) and ownership transfer where appropriate. `String` for owned keys, `&str` for borrowed keys.
4.  **Error Handling:** Using `Result` and `Option` instead of exceptions (`Failure`). Helper functions like `get_mapped_int` now return `Result`.
5.  **Collections:** Using `std::collections::HashMap` for maps/hashtables.
6.  **Standard Library:** Using `std::net::Ipv4Addr`, `std::io`, `std::time`.
7.  **Macros:** Using `format!`, `println!`, `writeln!`.
8.  **Closures:** Using closures for functions passed as arguments (like grouping and reduction functions).
9.  **Shared State:** Using `Rc<RefCell<...>>` for the shared state required by the `join` operator in a single-threaded context.
10. **Modules:** Organizing the code into `utils`, `builtins`, and `main`.

**Dependencies:**

You'll need to add the `chrono` crate for potentially more flexible time handling if needed (though the current translation uses `std::time` and `f64` matching the OCaml) and potentially the `csv` crate if you prefer a dedicated CSV library over manual formatting/parsing. This translation uses manual formatting/parsing like the original.

```toml
# Cargo.toml
[dependencies]
# chrono = "0.4" # Optional, if more advanced time features are needed
# csv = "1.1"   # Optional, for robust CSV handling
```

**`src/utils.rs`**

```rust
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
```

**`src/builtins.rs`**

```rust
use crate::utils::{
    self, // Bring utils functions into scope
    OpResult, Tuple, Operator,
    get_ip_or_zero, get_mapped_int, get_mapped_float, string_of_tuple,
    dump_tuple as util_dump_tuple, // Avoid name clash
};
use std::{
    collections::HashMap,
    io::{self, Write, BufReader, BufRead},
    fs::File,
    net::Ipv4Addr,
    str::FromStr,
    rc::Rc,
    cell::RefCell,
};

const INIT_TABLE_SIZE: usize = 10000; // Used for HashMap initial capacity hint

// --- Operator Implementations ---

// Operator that dumps tuples to a writer.
pub struct DumpTupleOp<W: Write> {
    out: W,
    show_reset: bool,
}

impl<W: Write> DumpTupleOp<W> {
    pub fn new(out: W, show_reset: bool) -> Self {
        Self { out, show_reset }
    }
}

impl<W: Write> Operator for DumpTupleOp<W> {
    fn next(&mut self, tup: Tuple) {
        if let Err(e) = util_dump_tuple(&mut self.out, &tup) {
            eprintln!("Error writing tuple: {}", e);
        }
    }

    fn reset(&mut self, tup: Tuple) {
        if self.show_reset {
            if let Err(e) = util_dump_tuple(&mut self.out, &tup) {
                 eprintln!("Error writing tuple during reset: {}", e);
            }
             if let Err(e) = writeln!(self.out, "[reset]") {
                 eprintln!("Error writing reset marker: {}", e);
             }
        }
         // Consume the tuple even if not shown
        drop(tup);
    }
}

/// Creates a `DumpTupleOp`.
pub fn dump_tuple<W: Write + 'static>(out: W, show_reset: bool) -> Box<dyn Operator> {
     Box::new(DumpTupleOp::new(out, show_reset))
}

// --- Dump as CSV Operator ---
pub struct DumpCsvOp<W: Write> {
    out: W,
    first: bool,
    static_field: Option<(String, String)>,
    header: bool,
    written_header_keys: Option<Vec<String>>, // Store header order
}

impl<W: Write> DumpCsvOp<W> {
     pub fn new(out: W, static_field: Option<(String, String)>, header: bool) -> Self {
        Self { out, first: true, static_field, header, written_header_keys: None }
    }
}

impl<W: Write> Operator for DumpCsvOp<W> {
    fn next(&mut self, tup: Tuple) {
        // Write header on the first tuple if requested
        if self.first && self.header {
            let mut header_keys = Vec::new();
            if let Some((key, _)) = &self.static_field {
                 if let Err(e) = write!(self.out, "{},", key) {
                    eprintln!("Error writing static field header: {}", e);
                    return; // Stop processing if write fails
                 }
                 header_keys.push(key.clone());
            }
            // Sort keys for consistent header order
            let mut keys: Vec<_> = tup.keys().collect();
            keys.sort();
            for key in &keys {
                if let Err(e) = write!(self.out, "{},", key) {
                     eprintln!("Error writing header key {}: {}", key, e);
                     return;
                }
                 header_keys.push(key.to_string());
            }
             if let Err(e) = writeln!(self.out) { // End header line
                 eprintln!("Error writing header newline: {}", e);
                 return;
             }
            self.written_header_keys = Some(header_keys);
            self.first = false;
        }

        // Write static field value if present
        if let Some((_, value)) = &self.static_field {
             if let Err(e) = write!(self.out, "{},", value) {
                 eprintln!("Error writing static field value: {}", e);
                 return;
             }
        }

        // Write tuple values, respecting header order if written
        let keys_to_iterate: Vec<String> = self.written_header_keys
            .as_ref()
            .map(|hk| hk.iter().filter(|k| self.static_field.as_ref().map_or(true, |(sfk, _)| *k != sfk)).cloned().collect()) // Use stored header keys (excluding static if present)
            .unwrap_or_else(|| { // Otherwise, sort current tuple keys
                let mut keys: Vec<_> = tup.keys().cloned().collect();
                keys.sort();
                keys
            });

        for key in keys_to_iterate {
            let value_str = tup.get(&key).map_or("", |v| &v.to_string()); // Handle missing keys gracefully?
            if let Err(e) = write!(self.out, "{},", value_str) {
                eprintln!("Error writing value for key {}: {}", key, e);
                return;
            }
        }

         if let Err(e) = writeln!(self.out) { // End data line
             eprintln!("Error writing data newline: {}", e);
             // Don't return here, just report error
         }
    }

    fn reset(&mut self, _tup: Tuple) {
        // CSV dump typically doesn't do anything special on reset
        // Might flush the writer if it's buffered
        let _ = self.out.flush();
    }
}

/// Creates a `DumpCsvOp`.
pub fn dump_as_csv<W: Write + 'static>(
    out: W,
    static_field: Option<(String, String)>,
    header: bool,
) -> Box<dyn Operator> {
    Box::new(DumpCsvOp::new(out, static_field, header))
}


// --- Dump Walt's CSV Operator ---
// Specific CSV format operator
pub struct DumpWaltsCsvOp {
    out: Option<std::io::BufWriter<File>>, // Option to handle lazy opening
    filename: String,
    first: bool,
}

impl DumpWaltsCsvOp {
    pub fn new(filename: String) -> Self {
        Self { out: None, filename, first: true }
    }

    // Helper to ensure the output file is open
    fn ensure_open(&mut self) -> io::Result<()> {
        if self.out.is_none() {
            let file = File::create(&self.filename)?;
            self.out = Some(io::BufWriter::new(file));
        }
        Ok(())
    }
}

impl Operator for DumpWaltsCsvOp {
     fn next(&mut self, tup: Tuple) {
        if self.first {
            if let Err(e) = self.ensure_open() {
                 eprintln!("Failed to open or create Walt's CSV file '{}': {}", self.filename, e);
                 return; // Cannot proceed if file can't be opened
            }
            self.first = false;
        }

         if let Some(writer) = self.out.as_mut() {
             // Extract fields, providing default/error values if missing or wrong type
             let src_ip = tup.get("src_ip").map_or("0.0.0.0".to_string(), |v| v.to_string());
             let dst_ip = tup.get("dst_ip").map_or("0.0.0.0".to_string(), |v| v.to_string());
             let src_l4 = tup.get("src_l4_port").and_then(|v| v.as_int().ok()).map_or("0".to_string(), |v| v.to_string());
             let dst_l4 = tup.get("dst_l4_port").and_then(|v| v.as_int().ok()).map_or("0".to_string(), |v| v.to_string());
             let pkts = tup.get("packet_count").and_then(|v| v.as_int().ok()).map_or("0".to_string(), |v| v.to_string());
             let bytes = tup.get("byte_count").and_then(|v| v.as_int().ok()).map_or("0".to_string(), |v| v.to_string());
             let epoch = tup.get("epoch_id").and_then(|v| v.as_int().ok()).map_or("0".to_string(), |v| v.to_string());

             if let Err(e) = writeln!(writer, "{},{},{},{},{},{},{}", src_ip, dst_ip, src_l4, dst_l4, pkts, bytes, epoch) {
                 eprintln!("Error writing Walt's CSV line: {}", e);
             }
         }
     }

    fn reset(&mut self, _tup: Tuple) {
        // Flush the writer on reset
         if let Some(writer) = self.out.as_mut() {
             let _ = writer.flush();
         }
    }
}

/// Creates a `DumpWaltsCsvOp`.
pub fn dump_walts_csv(filename: String) -> Box<dyn Operator> {
    Box::new(DumpWaltsCsvOp::new(filename))
}


// --- Read Walt's CSV Function ---
// This function *drives* operators, it doesn't return one.
// Reads multiple CSV files and pushes data to corresponding operators.
pub fn read_walts_csv(
    file_names: Vec<String>,
    mut ops: Vec<Box<dyn Operator>>, // Takes ownership
    epoch_id_key: &str,
) -> io::Result<()> {
    if file_names.len() != ops.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Number of files and operators must match"));
    }

    let mut readers: Vec<_> = file_names.iter().map(|fname| -> io::Result<_>{
        let file = File::open(fname)?;
        Ok(BufReader::new(file))
    }).collect::<Result<_,_>>()?; // Propagate file opening errors

    let mut current_eids: Vec<i64> = vec![0; ops.len()];
    let mut tup_counts: Vec<i64> = vec![0; ops.len()];
    let mut active_readers: Vec<bool> = vec![true; ops.len()];
    let mut running = ops.len();

    while running > 0 {
        for i in 0..ops.len() {
            if !active_readers[i] { continue; } // Skip finished readers

            let mut line = String::new();
            match readers[i].read_line(&mut line) {
                Ok(0) => { // EOF
                    // Send final reset for the last epoch
                     let reset_tup = utils::tuple_of_list(vec![
                         (epoch_id_key.to_string(), OpResult::Int(current_eids[i])),
                         ("tuples".to_string(), OpResult::Int(tup_counts[i])),
                     ]);
                    ops[i].reset(reset_tup);

                    active_readers[i] = false;
                    running -= 1;
                    println!("Finished reading file: {}", file_names[i]);
                }
                Ok(_) => { // Successfully read a line
                    let parts: Vec<&str> = line.trim().split(',').collect();
                    if parts.len() == 7 {
                        // Simple parsing, assumes valid format and types
                        let src_ip_res = get_ip_or_zero(parts[0]);
                        let dst_ip_res = get_ip_or_zero(parts[1]);
                        let src_port_res = parts[2].parse::<i64>();
                        let dst_port_res = parts[3].parse::<i64>();
                        let pkts_res = parts[4].parse::<i64>();
                        let bytes_res = parts[5].parse::<i64>();
                        let epoch_id_res = parts[6].parse::<i64>();

                        // Check if all parts parsed correctly
                        if let (Ok(src_ip), Ok(dst_ip), Ok(src_port), Ok(dst_port), Ok(pkts), Ok(bytes), Ok(epoch_id)) =
                           (src_ip_res, dst_ip_res, src_port_res, dst_port_res, pkts_res, bytes_res, epoch_id_res) {

                            // Handle epoch change and resets
                            if epoch_id > current_eids[i] {
                                // Send resets for intermediate epochs if needed
                                while epoch_id > current_eids[i] {
                                    let reset_tup = utils::tuple_of_list(vec![
                                        (epoch_id_key.to_string(), OpResult::Int(current_eids[i])),
                                        ("tuples".to_string(), OpResult::Int(tup_counts[i])),
                                    ]);
                                    ops[i].reset(reset_tup);
                                    tup_counts[i] = 0;
                                    current_eids[i] += 1;
                                }
                            }

                            // Create tuple
                            let mut p = Tuple::new();
                            p.insert("ipv4.src".to_string(), src_ip);
                            p.insert("ipv4.dst".to_string(), dst_ip);
                            p.insert("l4.sport".to_string(), OpResult::Int(src_port));
                            p.insert("l4.dport".to_string(), OpResult::Int(dst_port));
                            p.insert("packet_count".to_string(), OpResult::Int(pkts));
                            p.insert("byte_count".to_string(), OpResult::Int(bytes));
                            p.insert(epoch_id_key.to_string(), OpResult::Int(epoch_id)); // Add current epoch ID

                            tup_counts[i] += 1;
                            p.insert("tuples".to_string(), OpResult::Int(tup_counts[i])); // Add running count for this epoch

                            // Send to operator
                            ops[i].next(p);

                        } else {
                             eprintln!("Warning: Failed to parse line in {}: {}", file_names[i], line.trim());
                        }
                    } else {
                        eprintln!("Warning: Malformed line in {}: {}", file_names[i], line.trim());
                    }
                    line.clear(); // Reuse string buffer
                }
                Err(e) => { // Read error
                    eprintln!("Error reading from file {}: {}", file_names[i], e);
                    active_readers[i] = false; // Stop reading from this file
                    running -= 1;
                     // Send final reset? Or maybe just error out? OCaml raised failure. Let's stop.
                    return Err(e);
                }
            }
        }
    }
    println!("Done reading all files.");
    Ok(())
}


// --- Meta Meter Operator ---
// Tracks tuple counts per epoch.
pub struct MetaMeterOp<W: Write> {
    name: String,
    out: W,
    static_field: Option<String>,
    epoch_count: i64,
    tups_count: i64,
    next_op: Box<dyn Operator>,
}

impl<W: Write> MetaMeterOp<W> {
     pub fn new(name: String, out: W, static_field: Option<String>, next_op: Box<dyn Operator>) -> Self {
        Self { name, out, static_field, epoch_count: 0, tups_count: 0, next_op }
    }
}

impl<W: Write> Operator for MetaMeterOp<W> {
    fn next(&mut self, tup: Tuple) {
        self.tups_count += 1;
        self.next_op.next(tup);
    }

    fn reset(&mut self, tup: Tuple) {
        let static_val = self.static_field.as_deref().unwrap_or("");
         if let Err(e) = writeln!(self.out, "{},{},{},{}", self.epoch_count, self.name, self.tups_count, static_val) {
             eprintln!("Error writing meta meter log: {}", e);
         }
        self.tups_count = 0;
        self.epoch_count += 1;
        self.next_op.reset(tup);
    }
}

/// Creates a `MetaMeterOp`.
pub fn meta_meter<W: Write + 'static>(
    name: String,
    out: W,
    static_field: Option<String>,
    next_op: Box<dyn Operator>,
) -> Box<dyn Operator> {
    Box::new(MetaMeterOp::new(name, out, static_field, next_op))
}


// --- Epoch Operator ---
// Groups tuples into time-based epochs.
pub struct EpochOp {
    epoch_width: f64,
    key_out: String,
    epoch_boundary: Option<f64>, // Use Option for initial state
    eid: i64,
    next_op: Box<dyn Operator>,
}

impl EpochOp {
    pub fn new(epoch_width: f64, key_out: String, next_op: Box<dyn Operator>) -> Self {
        Self { epoch_width, key_out, epoch_boundary: None, eid: 0, next_op }
    }
}

impl Operator for EpochOp {
    fn next(&mut self, mut tup: Tuple) {
        match get_mapped_float("time", &tup) {
            Ok(time) => {
                 match self.epoch_boundary {
                     None => { // First tuple, establish boundary
                         self.epoch_boundary = Some(time + self.epoch_width);
                     }
                     Some(boundary) if time >= boundary => {
                         // Time crossed epoch boundary
                         let mut current_boundary = boundary;
                         while time >= current_boundary {
                             // Send reset for the completed epoch
                             let reset_tup = utils::tuple_of_list(vec![(self.key_out.clone(), OpResult::Int(self.eid))]);
                             self.next_op.reset(reset_tup);
                             // Advance to the next epoch
                             current_boundary += self.epoch_width;
                             self.eid += 1;
                         }
                         self.epoch_boundary = Some(current_boundary);
                     }
                     Some(_) => { /* Time within current epoch, do nothing special */ }
                 }
                 // Add current epoch ID to the tuple
                 tup.insert(self.key_out.clone(), OpResult::Int(self.eid));
                 self.next_op.next(tup);
            }
            Err(e) => {
                 eprintln!("EpochOp Error: Failed to get time - {}. Dropping tuple.", e);
                 // Optionally, could forward tuple without epoch id, but dropping seems safer.
            }
        }
    }

    fn reset(&mut self, _tup: Tuple) { // Input tuple to reset is ignored by EpochOp itself
         // Send a final reset for the last active epoch
         let reset_tup = utils::tuple_of_list(vec![(self.key_out.clone(), OpResult::Int(self.eid))]);
         self.next_op.reset(reset_tup);

         // Reset internal state
         self.epoch_boundary = None;
         self.eid = 0;
    }
}

/// Creates an `EpochOp`.
pub fn epoch(epoch_width: f64, key_out: String, next_op: Box<dyn Operator>) -> Box<dyn Operator> {
     Box::new(EpochOp::new(epoch_width, key_out, next_op))
}

// --- Filter Operator ---
// Passes tuples only if a predicate function returns true.
pub struct FilterOp<F> where F: Fn(&Tuple) -> bool {
    predicate: F,
    next_op: Box<dyn Operator>,
}

impl<F> FilterOp<F> where F: Fn(&Tuple) -> bool {
    pub fn new(predicate: F, next_op: Box<dyn Operator>) -> Self {
        Self { predicate, next_op }
    }
}

impl<F> Operator for FilterOp<F> where F: Fn(&Tuple) -> bool {
    fn next(&mut self, tup: Tuple) {
        if (self.predicate)(&tup) {
            self.next_op.next(tup);
        }
        // Else, drop the tuple
    }

    fn reset(&mut self, tup: Tuple) {
        // Pass reset downstream regardless of filter
        self.next_op.reset(tup);
    }
}

/// Creates a `FilterOp`.
pub fn filter<F>(predicate: F, next_op: Box<dyn Operator>) -> Box<dyn Operator>
where
    F: Fn(&Tuple) -> bool + 'static, // Ensure closure lives long enough
{
    Box::new(FilterOp::new(predicate, next_op))
}

// Filter utility: Checks if key's integer value >= threshold. Panics on error.
// Consider making this return Result or Option for robustness.
pub fn key_geq_int(key: String, threshold: i64) -> impl Fn(&Tuple) -> bool {
     move |tup: &Tuple| -> bool {
        match get_mapped_int(&key, tup) {
            Ok(val) => val >= threshold,
            Err(e) => {
                eprintln!("key_geq_int error for key '{}': {}. Filter fails.", key, e);
                false // Treat error as filter failure
            }
        }
    }
}

// --- Map Operator ---
// Applies a function to transform each tuple.
pub struct MapOp<F> where F: Fn(Tuple) -> Tuple {
    transform: F,
    next_op: Box<dyn Operator>,
}

impl<F> MapOp<F> where F: Fn(Tuple) -> Tuple {
    pub fn new(transform: F, next_op: Box<dyn Operator>) -> Self {
        Self { transform, next_op }
    }
}

impl<F> Operator for MapOp<F> where F: Fn(Tuple) -> Tuple {
    fn next(&mut self, tup: Tuple) {
        let transformed_tup = (self.transform)(tup);
        self.next_op.next(transformed_tup);
    }

    fn reset(&mut self, tup: Tuple) {
        // Pass reset downstream unchanged
        self.next_op.reset(tup);
    }
}

/// Creates a `MapOp`.
pub fn map<F>(transform: F, next_op: Box<dyn Operator>) -> Box<dyn Operator>
where
    F: Fn(Tuple) -> Tuple + 'static,
{
    Box::new(MapOp::new(transform, next_op))
}

// --- GroupBy Operator ---
pub type GroupingFunc = Box<dyn Fn(&Tuple) -> Tuple>;
pub type ReductionFunc = Box<dyn Fn(OpResult, &Tuple) -> OpResult>;

pub struct GroupByOp {
    groupby_fn: GroupingFunc,
    reduce_fn: ReductionFunc,
    out_key: String,
    h_tbl: HashMap<Tuple, OpResult>, // Key is the result of groupby_fn
    next_op: Box<dyn Operator>,
}

impl GroupByOp {
     pub fn new(
         groupby_fn: GroupingFunc,
         reduce_fn: ReductionFunc,
         out_key: String,
         next_op: Box<dyn Operator>
     ) -> Self {
         Self {
             groupby_fn,
             reduce_fn,
             out_key,
             h_tbl: HashMap::with_capacity(INIT_TABLE_SIZE),
             next_op,
         }
     }
}

impl Operator for GroupByOp {
    fn next(&mut self, tup: Tuple) {
        let grouping_key = (self.groupby_fn)(&tup);
        let current_val = self.h_tbl.get(&grouping_key).cloned().unwrap_or(OpResult::Empty);
        let next_val = (self.reduce_fn)(current_val, &tup);
        self.h_tbl.insert(grouping_key, next_val);
         // Original tuple is consumed here
    }

    fn reset(&mut self, tup: Tuple) {
        // Create a base tuple from the reset input for merging
        // Only include keys *not* present in the grouping key? OCaml used union...
        // Let's replicate OCaml's Tuple.union (preferring reset tuple's value on collision)
        for (grouping_key, reduced_val) in self.h_tbl.drain() {
            let mut merged_tup = tup.clone(); // Start with reset tuple
            // Add grouping key fields, potentially overwriting reset tuple fields
            for (k, v) in grouping_key {
                 merged_tup.insert(k, v);
            }
            // Add the reduction result
            merged_tup.insert(self.out_key.clone(), reduced_val);
            self.next_op.next(merged_tup);
        }
        // Clear is implicitly done by drain()

        // Pass the original reset tuple downstream
        self.next_op.reset(tup);
    }
}

/// Creates a `GroupByOp`.
pub fn groupby(
    groupby_fn: GroupingFunc,
    reduce_fn: ReductionFunc,
    out_key: String,
    next_op: Box<dyn Operator>,
) -> Box<dyn Operator> {
    Box::new(GroupByOp::new(groupby_fn, reduce_fn, out_key, next_op))
}


// --- Distinct Operator ---
// Outputs unique tuples based on a grouping function each epoch.
pub struct DistinctOp {
    groupby_fn: GroupingFunc,
    h_tbl: HashMap<Tuple, bool>, // Value doesn't matter, just presence
    next_op: Box<dyn Operator>,
}

impl DistinctOp {
     pub fn new(groupby_fn: GroupingFunc, next_op: Box<dyn Operator>) -> Self {
         Self {
             groupby_fn,
             h_tbl: HashMap::with_capacity(INIT_TABLE_SIZE),
             next_op,
         }
     }
}

impl Operator for DistinctOp {
    fn next(&mut self, tup: Tuple) {
        let grouping_key = (self.groupby_fn)(&tup);
        // Insert/replace the key. We only care about its presence.
        // OCaml Hashtbl used the grouping key, Rust HashMap needs Eq+Hash
        self.h_tbl.insert(grouping_key, true);
        // Consume the input tuple
    }

    fn reset(&mut self, tup: Tuple) {
        for (grouping_key, _) in self.h_tbl.drain() {
             // Like GroupBy, merge the reset tuple and the distinct key tuple
             let mut merged_tup = tup.clone();
             for (k, v) in grouping_key {
                 merged_tup.insert(k, v);
             }
             self.next_op.next(merged_tup);
        }
        // Pass the original reset tuple downstream
        self.next_op.reset(tup);
    }
}

/// Creates a `DistinctOp`.
pub fn distinct(groupby_fn: GroupingFunc, next_op: Box<dyn Operator>) -> Box<dyn Operator> {
     Box::new(DistinctOp::new(groupby_fn, next_op))
}

// --- Split Operator ---
// Sends `next` and `reset` calls to two downstream operators.
pub struct SplitOp {
    left: Box<dyn Operator>,
    right: Box<dyn Operator>,
}

impl SplitOp {
    pub fn new(left: Box<dyn Operator>, right: Box<dyn Operator>) -> Self {
        Self { left, right }
    }
}

impl Operator for SplitOp {
    fn next(&mut self, tup: Tuple) {
        // Need to clone the tuple to send to both sides
        self.left.next(tup.clone());
        self.right.next(tup); // Pass ownership to the second one
    }

    fn reset(&mut self, tup: Tuple) {
         // Need to clone the tuple to send to both sides
        self.left.reset(tup.clone());
        self.right.reset(tup); // Pass ownership to the second one
    }
}

/// Creates a `SplitOp`.
pub fn split(left: Box<dyn Operator>, right: Box<dyn Operator>) -> Box<dyn Operator> {
    Box::new(SplitOp::new(left, right))
}

// --- Join Operator ---
// Joins tuples from two streams based on keys and epoch IDs.
// This is complex due to shared state.

pub type KeyExtractor = Box<dyn Fn(Tuple) -> (Tuple, Tuple)>; // (key_tuple, value_tuple)

// Shared state between the two sides of the join
struct JoinState {
    h_tbl1: HashMap<Tuple, Tuple>, // Stores values pending match from stream 1
    h_tbl2: HashMap<Tuple, Tuple>, // Stores values pending match from stream 2
    epoch1: i64,
    epoch2: i64,
    eid_key: String,
}

// Operator for one side of the join
pub struct JoinSideOp {
    state: Rc<RefCell<JoinState>>, // Shared mutable state
    is_left_side: bool, // True if this is the 'left' input (handles h_tbl1, epoch1)
    extractor: KeyExtractor,
    next_op: Rc<RefCell<Box<dyn Operator>>>, // Shared next operator
}

impl Operator for JoinSideOp {
    fn next(&mut self, tup: Tuple) {
        let eid_key_local = self.state.borrow().eid_key.clone(); // Clone eid_key locally

        // Extract epoch ID first
        let current_epoch_res = get_mapped_int(&eid_key_local, &tup);

        // Extract key and value tuples
        let (key_tup, val_tup) = (self.extractor)(tup); // Consumes original tup

         match current_epoch_res {
            Ok(current_epoch) => {
                let mut state = self.state.borrow_mut();
                let (curr_epoch_ref, other_epoch_ref, curr_h_tbl, other_h_tbl) = if self.is_left_side {
                    (&mut state.epoch1, &mut state.epoch2, &mut state.h_tbl1, &mut state.h_tbl2)
                } else {
                    (&mut state.epoch2, &mut state.epoch1, &mut state.h_tbl2, &mut state.h_tbl1)
                };

                 // Process epoch advancement and resets before handling the tuple
                 while current_epoch > *curr_epoch_ref {
                     if *other_epoch_ref >= *curr_epoch_ref { // Only reset if other side is >= current epoch
                         let reset_tup = utils::tuple_of_list(vec![
                             (state.eid_key.clone(), OpResult::Int(*curr_epoch_ref))
                         ]);
                         // Use Rc<RefCell<>> for the next_op
                         self.next_op.borrow_mut().reset(reset_tup);
                     }
                      // Potential place to clean up old entries from hash tables based on epoch?
                      // OCaml didn't explicitly clean, relying on epoch advancement.

                     *curr_epoch_ref += 1;
                 }

                 // Add epoch ID to the key tuple for matching
                 let mut match_key = key_tup; // Take ownership
                 match_key.insert(state.eid_key.clone(), OpResult::Int(current_epoch));


                // Try to find a match in the *other* table
                if let Some(other_val) = other_h_tbl.remove(&match_key) {
                     // Match found! Merge and send downstream.
                     // Merge: match_key (includes key fields + epoch) U val_tup U other_val
                     let mut final_tup = match_key; // Start with key + eid
                     // Add fields from this side's value tuple
                     for (k, v) in val_tup { final_tup.insert(k, v); }
                     // Add fields from the matched value tuple from the other side
                     for (k, v) in other_val { final_tup.insert(k, v); }

                     self.next_op.borrow_mut().next(final_tup);
                 } else {
                     // No match found, store this side's value tuple in *our* table, keyed by match_key
                     curr_h_tbl.insert(match_key, val_tup);
                 }
            }
            Err(e) => {
                 eprintln!("JoinOp Error: Failed to get epoch id '{}' - {}. Dropping tuple.", eid_key_local, e);
            }
         }
    }

    fn reset(&mut self, tup: Tuple) {
        let mut state = self.state.borrow_mut();
        let eid_key_local = state.eid_key.clone();

         match get_mapped_int(&eid_key_local, &tup) {
            Ok(reset_epoch) => {
                 let (curr_epoch_ref, other_epoch_ref) = if self.is_left_side {
                     (&mut state.epoch1, &mut state.epoch2)
                 } else {
                     (&mut state.epoch2, &mut state.epoch1)
                 };

                 // Process epoch advancement based on reset signal
                 while reset_epoch > *curr_epoch_ref {
                      if *other_epoch_ref >= *curr_epoch_ref {
                          let reset_out_tup = utils::tuple_of_list(vec![
                             (state.eid_key.clone(), OpResult::Int(*curr_epoch_ref))
                          ]);
                         self.next_op.borrow_mut().reset(reset_out_tup);
                      }
                     *curr_epoch_ref += 1;
                 }

                 // Check if this reset allows the *final* downstream reset
                 // Both sides must have processed up to this epoch
                 if *curr_epoch_ref == reset_epoch && *other_epoch_ref >= reset_epoch {
                      // Don't forward the original reset tuple directly? OCaml didn't seem to.
                      // Just use the epoch ID from it.
                       let final_reset_tup = utils::tuple_of_list(vec![
                          (state.eid_key.clone(), OpResult::Int(reset_epoch))
                       ]);
                      self.next_op.borrow_mut().reset(final_reset_tup);

                      // Clear hash tables on final reset for the epoch?
                      // OCaml join didn't explicitly clear tables in reset, which seems risky.
                      // Let's add cleaning for epochs <= reset_epoch
                       let epoch_key = state.eid_key.clone();
                       state.h_tbl1.retain(|k, _| k.get(&epoch_key).map_or(true, |v| v.as_int().map_or(true, |e| e > reset_epoch)));
                       state.h_tbl2.retain(|k, _| k.get(&epoch_key).map_or(true, |v| v.as_int().map_or(true, |e| e > reset_epoch)));

                 }

            }
            Err(e) => {
                 eprintln!("JoinOp Reset Error: Failed to get epoch id '{}' - {}. Ignoring reset.", eid_key_local, e);
            }
         }
        // Consume the incoming reset tuple 'tup'
        drop(tup);
    }
}


/// Creates the two operators for a join operation.
pub fn join(
    eid_key: String,
    left_extractor: KeyExtractor,
    right_extractor: KeyExtractor,
    next_op: Box<dyn Operator>,
) -> (Box<dyn Operator>, Box<dyn Operator>) {
    let shared_state = Rc::new(RefCell::new(JoinState {
        h_tbl1: HashMap::with_capacity(INIT_TABLE_SIZE / 2), // Split capacity
        h_tbl2: HashMap::with_capacity(INIT_TABLE_SIZE / 2),
        epoch1: -1, // Start before epoch 0
        epoch2: -1,
        eid_key,
    }));

    let shared_next_op = Rc::new(RefCell::new(next_op));

    let left_op = Box::new(JoinSideOp {
        state: Rc::clone(&shared_state),
        is_left_side: true,
        extractor: left_extractor,
        next_op: Rc::clone(&shared_next_op),
    });

    let right_op = Box::new(JoinSideOp {
        state: shared_state, // Rc moves here
        is_left_side: false,
        extractor: right_extractor,
        next_op: shared_next_op, // Rc moves here
    });

    (left_op, right_op)
}

// --- Join Utility ---
/// Creates a new tuple by filtering and renaming keys from the input tuple.
pub fn rename_filtered_keys(
    renaming_pairs: &[(String, String)], // List of (old_key, new_key)
    in_tup: &Tuple,
) -> Tuple {
    let mut new_tup = Tuple::new();
    for (old_key, new_key) in renaming_pairs {
        if let Some(val) = in_tup.get(old_key) {
            new_tup.insert(new_key.clone(), val.clone());
        }
    }
    new_tup
}
```

**`src/main.rs`**

```rust
use std::{
    io::{stdout, Write},
    net::Ipv4Addr,
    str::FromStr,
    rc::Rc,
    cell::RefCell
};

// Modules defined in other files
mod utils;
mod builtins;

// Use items from modules
use utils::{
    OpResult, Tuple, Operator, chain, chain_dbl,
    single_group, counter, sum_ints, filter_groups,
    get_mapped_int, get_mapped_float, lookup_int, // Add lookup_* if needed directly
};
use builtins::{
    epoch, groupby, filter, map, distinct, split, join, dump_tuple, dump_as_csv,
    meta_meter, key_geq_int, rename_filtered_keys, dump_walts_csv, read_walts_csv, // Add read/write CSV if needed
};

// --- Query Definitions ---
// These functions construct operator pipelines.

// Identity (removes MAC addresses) -> Dump
fn ident(next_op: Box<dyn Operator>) -> Box<dyn Operator> {
     let map_fn = map(Box::new(|mut tup: Tuple| -> Tuple {
         tup.remove("eth.src");
         tup.remove("eth.dst");
         tup
     }), next_op);
     map_fn // Return the created map operator directly
}

// Count packets per epoch -> Next
fn count_pkts(next_op: Box<dyn Operator>) -> Box<dyn Operator> {
    let group_op = groupby(
        Box::new(single_group),
        Box::new(counter),
        "pkts".to_string(),
        next_op,
    );
    epoch(1.0, "eid".to_string(), group_op)
}

// Count packets per src/dst pair per epoch -> Next
fn pkts_per_src_dst(next_op: Box<dyn Operator>) -> Box<dyn Operator> {
     let group_op = groupby(
        Box::new(|tup| filter_groups(&["ipv4.src", "ipv4.dst"], tup)),
        Box::new(counter),
        "pkts".to_string(),
        next_op,
     );
     epoch(1.0, "eid".to_string(), group_op)
}

// Count distinct source IPs per epoch -> Next
fn distinct_srcs(next_op: Box<dyn Operator>) -> Box<dyn Operator> {
     let group_op = groupby(
        Box::new(single_group),
        Box::new(counter),
        "srcs".to_string(),
        next_op
     );
     let distinct_op = distinct(
        Box::new(|tup| filter_groups(&["ipv4.src"], tup)),
        group_op
     );
    epoch(1.0, "eid".to_string(), distinct_op)
}

// Sonata 1: TCP New Connections (Heavy Hitters)
fn tcp_new_cons(next_op: Box<dyn Operator>) -> Box<dyn Operator> {
    let threshold = 40;
     let filter_conns = filter(
        key_geq_int("cons".to_string(), threshold),
        next_op
     );
     let group_op = groupby(
         Box::new(|tup| filter_groups(&["ipv4.dst"], tup)),
         Box::new(counter),
         "cons".to_string(),
         filter_conns
     );
     let filter_syn = filter(
         Box::new(|tup| {
             get_mapped_int("ipv4.proto", tup).map_or(false, |p| p == 6) &&
             get_mapped_int("l4.flags", tup).map_or(false, |f| f == 2) // SYN flag = 2
         }),
         group_op
     );
     epoch(1.0, "eid".to_string(), filter_syn)
}


// Sonata 2: SSH Brute Force
fn ssh_brute_force(next_op: Box<dyn Operator>) -> Box<dyn Operator> {
     let threshold = 40;
     let filter_srcs = filter(
        key_geq_int("srcs".to_string(), threshold),
        next_op
     );
      let group_op = groupby(
         Box::new(|tup| filter_groups(&["ipv4.dst", "ipv4.len"], tup)), // Group by dst and length
         Box::new(counter),
         "srcs".to_string(),
         filter_srcs
     );
      let distinct_op = distinct(
         Box::new(|tup| filter_groups(&["ipv4.src", "ipv4.dst", "ipv4.len"], tup)), // Distinct src trying a specific length to a dst
         group_op
     );
     let filter_ssh = filter(
         Box::new(|tup| {
             get_mapped_int("ipv4.proto", tup).map_or(false, |p| p == 6) &&
             get_mapped_int("l4.dport", tup).map_or(false, |p| p == 22)
         }),
         distinct_op
     );
     epoch(1.0, "eid".to_string(), filter_ssh) // Consider longer epoch?
}

// Sonata 3: Super Spreader
fn super_spreader(next_op: Box<dyn Operator>) -> Box<dyn Operator> {
     let threshold = 40;
     let filter_dsts = filter(
        key_geq_int("dsts".to_string(), threshold),
        next_op
     );
     let group_op = groupby(
        Box::new(|tup| filter_groups(&["ipv4.src"], tup)), // Group by source
        Box::new(counter),
        "dsts".to_string(),
        filter_dsts
     );
     let distinct_op = distinct(
        Box::new(|tup| filter_groups(&["ipv4.src", "ipv4.dst"], tup)), // Distinct src/dst pairs
        group_op
     );
     epoch(1.0, "eid".to_string(), distinct_op)
}

// Sonata 4: Port Scan
fn port_scan(next_op: Box<dyn Operator>) -> Box<dyn Operator> {
    let threshold = 40;
     let filter_ports = filter(
        key_geq_int("ports".to_string(), threshold),
        next_op
     );
     let group_op = groupby(
         Box::new(|tup| filter_groups(&["ipv4.src"], tup)), // Group by source
         Box::new(counter),
         "ports".to_string(),
         filter_ports
     );
     let distinct_op = distinct(
         Box::new(|tup| filter_groups(&["ipv4.src", "l4.dport"], tup)), // Distinct ports tried by a source
         group_op
     );
     epoch(1.0, "eid".to_string(), distinct_op)
}

// Sonata 5: DDoS Target
fn ddos(next_op: Box<dyn Operator>) -> Box<dyn Operator> {
     let threshold = 45;
     let filter_srcs = filter(
         key_geq_int("srcs".to_string(), threshold),
         next_op
     );
     let group_op = groupby(
         Box::new(|tup| filter_groups(&["ipv4.dst"], tup)), // Group by destination
         Box::new(counter),
         "srcs".to_string(),
         filter_srcs
     );
     let distinct_op = distinct(
         Box::new(|tup| filter_groups(&["ipv4.src", "ipv4.dst"], tup)), // Distinct src/dst pairs
         group_op
     );
     epoch(1.0, "eid".to_string(), distinct_op)
}

// Sonata 6: SYN Flood (Sonata semantics)
// Returns a Vec of operators because it uses join
fn syn_flood_sonata(next_op: Box<dyn Operator>) -> Vec<Box<dyn Operator>> {
    let threshold: i64 = 3;
    let epoch_dur: f64 = 1.0;
    let eid_key = "eid".to_string();

    // --- Define the final stages after the joins ---
    let filter_final = filter(
        key_geq_int("syns+synacks-acks".to_string(), threshold),
        next_op
    );
    let map_final = map(Box::new(|mut tup: Tuple| {
        let syn_ack_res = get_mapped_int("syns+synacks", &tup);
        let ack_res = get_mapped_int("acks", &tup);
        if let (Ok(sa), Ok(a)) = (syn_ack_res, ack_res) {
            tup.insert("syns+synacks-acks".to_string(), OpResult::Int(sa - a));
        } else {
            eprintln!("Error calculating syns+synacks-acks");
            // Maybe insert an error marker or default value?
            tup.insert("syns+synacks-acks".to_string(), OpResult::Int(-1)); // Indicate error
        }
        tup
    }), filter_final);

    // --- Define the first join (SYN+SYNACK vs ACK) ---
    let (join1_left_in, join1_right_in) = join(
        eid_key.clone(),
        // Left Extractor (from SYN+SYNACK stream)
        Box::new(|tup: Tuple| {
            let key = filter_groups(&["host"], &tup);
            let val = filter_groups(&["syns+synacks"], &tup);
            (key, val)
        }),
        // Right Extractor (from ACK stream)
        Box::new(|tup: Tuple| {
            // Rename ipv4.dst to host for the key
            let key = rename_filtered_keys(&[("ipv4.dst".to_string(), "host".to_string())], &tup);
             let val = filter_groups(&["acks"], &tup);
             (key, val)
         }),
         map_final // Output of this join goes to the final map/filter
    );

    // --- Define the second join (SYN vs SYNACK) ---
     let map_join2 = map(Box::new(|mut tup: Tuple| {
         let syn_res = get_mapped_int("syns", &tup);
         let synack_res = get_mapped_int("synacks", &tup);
         if let (Ok(s), Ok(sa)) = (syn_res, synack_res) {
            tup.insert("syns+synacks".to_string(), OpResult::Int(s + sa));
         } else {
             eprintln!("Error calculating syns+synacks");
            tup.insert("syns+synacks".to_string(), OpResult::Int(-1)); // Error marker
         }
         tup
     }), join1_left_in); // Output of this join goes to the *left input* of join 1


    let (join2_left_in, join2_right_in) = join(
        eid_key.clone(),
         // Left Extractor (from SYN stream)
         Box::new(|tup: Tuple| {
             let key = rename_filtered_keys(&[("ipv4.dst".to_string(), "host".to_string())], &tup);
             let val = filter_groups(&["syns"], &tup);
             (key, val)
         }),
          // Right Extractor (from SYNACK stream)
          Box::new(|tup: Tuple| {
             let key = rename_filtered_keys(&[("ipv4.src".to_string(), "host".to_string())], &tup);
             let val = filter_groups(&["synacks"], &tup);
             (key, val)
         }),
         map_join2 // Output of this join goes to map_join2
    );


    // --- Define the initial streams ---
    let syns_stream = {
        let group_op = groupby(
            Box::new(|tup| filter_groups(&["ipv4.dst"], tup)),
            Box::new(counter),
            "syns".to_string(),
            join2_left_in, // Goes to left input of join 2
        );
        let filter_op = filter(
            Box::new(|tup| {
                get_mapped_int("ipv4.proto", tup).map_or(false, |p| p == 6) &&
                get_mapped_int("l4.flags", tup).map_or(false, |f| f == 2) // SYN
            }),
            group_op
        );
        epoch(epoch_dur, eid_key.clone(), filter_op)
    };

    let synacks_stream = {
         let group_op = groupby(
            Box::new(|tup| filter_groups(&["ipv4.src"], tup)),
            Box::new(counter),
            "synacks".to_string(),
            join2_right_in, // Goes to right input of join 2
        );
        let filter_op = filter(
            Box::new(|tup| {
                 get_mapped_int("ipv4.proto", tup).map_or(false, |p| p == 6) &&
                 get_mapped_int("l4.flags", tup).map_or(false, |f| f == 18) // SYN+ACK = 18
             }),
             group_op
        );
        epoch(epoch_dur, eid_key.clone(), filter_op)
    };

    let acks_stream = {
        let group_op = groupby(
            Box::new(|tup| filter_groups(&["ipv4.dst"], tup)),
            Box::new(counter),
            "acks".to_string(),
            join1_right_in, // Goes to right input of join 1
        );
        let filter_op = filter(
            Box::new(|tup| {
                 get_mapped_int("ipv4.proto", tup).map_or(false, |p| p == 6) &&
                 get_mapped_int("l4.flags", tup).map_or(false, |f| f == 16) // ACK = 16
             }),
             group_op
        );
        epoch(epoch_dur, eid_key.clone(), filter_op)
    };

    // Return the three starting points of the streams
    vec![syns_stream, synacks_stream, acks_stream]
}


// Sonata 7: Completed Flows Imbalance
// Returns a Vec of operators because it uses join
fn completed_flows(next_op: Box<dyn Operator>) -> Vec<Box<dyn Operator>> {
     let threshold: i64 = 1;
     let epoch_dur: f64 = 30.0; // Longer epoch
     let eid_key = "eid".to_string();

     let filter_final = filter(
        key_geq_int("diff".to_string(), threshold),
        next_op
     );
     let map_final = map(Box::new(|mut tup: Tuple| {
        let syn_res = get_mapped_int("syns", &tup);
        let fin_res = get_mapped_int("fins", &tup);
        if let (Ok(s), Ok(f)) = (syn_res, fin_res) {
            tup.insert("diff".to_string(), OpResult::Int(s - f));
        } else {
            eprintln!("Error calculating syns-fins diff");
            tup.insert("diff".to_string(), OpResult::Int(-1)); // Error marker
        }
        tup
     }), filter_final);

     let (join_left_in, join_right_in) = join(
        eid_key.clone(),
        // Left Extractor (SYNs)
        Box::new(|tup: Tuple| {
             let key = rename_filtered_keys(&[("ipv4.dst".to_string(), "host".to_string())], &tup);
             let val = filter_groups(&["syns"], &tup);
             (key, val)
         }),
         // Right Extractor (FINs)
         Box::new(|tup: Tuple| {
            let key = rename_filtered_keys(&[("ipv4.src".to_string(), "host".to_string())], &tup);
             let val = filter_groups(&["fins"], &tup);
             (key, val)
         }),
         map_final
     );


      let syns_stream = {
        let group_op = groupby(
            Box::new(|tup| filter_groups(&["ipv4.dst"], tup)),
            Box::new(counter),
            "syns".to_string(),
            join_left_in,
        );
        let filter_op = filter(
            Box::new(|tup| {
                 get_mapped_int("ipv4.proto", tup).map_or(false, |p| p == 6) &&
                 get_mapped_int("l4.flags", tup).map_or(false, |f| f == 2) // SYN
             }),
             group_op
        );
        epoch(epoch_dur, eid_key.clone(), filter_op)
    };

      let fins_stream = {
          let group_op = groupby(
             Box::new(|tup| filter_groups(&["ipv4.src"], tup)),
             Box::new(counter),
             "fins".to_string(),
             join_right_in,
         );
         let filter_op = filter(
             Box::new(|tup| {
                  get_mapped_int("ipv4.proto", tup).map_or(false, |p| p == 6) &&
                  get_mapped_int("l4.flags", tup).map_or(false, |f| (f & 1) == 1) // FIN flag is set
              }),
              group_op
         );
         epoch(epoch_dur, eid_key.clone(), filter_op)
     };

     vec![syns_stream, fins_stream]
}


// Sonata 8: Slowloris Attack
// Returns a Vec of operators because it uses join
fn slowloris(next_op: Box<dyn Operator>) -> Vec<Box<dyn Operator>> {
     let t1_n_conns: i64 = 5;
     let t2_n_bytes: i64 = 500;
     let t3_bytes_per_conn: i64 = 90;
     let epoch_dur: f64 = 1.0;
     let eid_key = "eid".to_string();

     let filter_final = filter(
        Box::new(move |tup: &Tuple| -> bool { // Use move closure for t3
            get_mapped_int("bytes_per_conn", tup).map_or(false, |bpc| bpc <= t3_bytes_per_conn)
        }),
        next_op
     );
     let map_final = map(Box::new(|mut tup: Tuple| {
         let bytes_res = get_mapped_int("n_bytes", &tup);
         let conns_res = get_mapped_int("n_conns", &tup);
         if let (Ok(b), Ok(c)) = (bytes_res, conns_res) {
             if c > 0 { // Avoid division by zero
                tup.insert("bytes_per_conn".to_string(), OpResult::Int(b / c));
             } else {
                 tup.insert("bytes_per_conn".to_string(), OpResult::Int(0)); // Or some other indicator
             }
         } else {
            eprintln!("Error calculating bytes_per_conn");
            tup.insert("bytes_per_conn".to_string(), OpResult::Int(-1)); // Error marker
         }
         tup
     }), filter_final);

     let (join_left_in, join_right_in) = join(
        eid_key.clone(),
        // Left Extractor (from n_conns stream)
        Box::new(|tup: Tuple| {
            let key = filter_groups(&["ipv4.dst"], &tup);
            let val = filter_groups(&["n_conns"], &tup);
            (key, val)
        }),
        // Right Extractor (from n_bytes stream)
        Box::new(|tup: Tuple| {
            let key = filter_groups(&["ipv4.dst"], &tup);
            let val = filter_groups(&["n_bytes"], &tup);
            (key, val)
        }),
        map_final
     );

     // Stream 1: Calculate n_conns >= t1
     let n_conns_stream = {
         let filter_t1 = filter(
            Box::new(move |tup: &Tuple| -> bool { // move closure for t1
                 get_mapped_int("n_conns", tup).map_or(false, |nc| nc >= t1_n_conns)
            }),
            join_left_in // Goes to left input of join
         );
         let group_op = groupby(
            Box::new(|tup| filter_groups(&["ipv4.dst"], tup)),
            Box::new(counter),
            "n_conns".to_string(),
            filter_t1
         );
         let distinct_op = distinct(
            Box::new(|tup| filter_groups(&["ipv4.src", "ipv4.dst", "l4.sport"], tup)), // Distinct connections
            group_op
         );
         let filter_tcp = filter(
            Box::new(|tup| get_mapped_int("ipv4.proto", tup).map_or(false, |p| p == 6)),
            distinct_op
         );
         epoch(epoch_dur, eid_key.clone(), filter_tcp)
     };

    // Stream 2: Calculate n_bytes >= t2
    let n_bytes_stream = {
        let filter_t2 = filter(
            Box::new(move |tup: &Tuple| -> bool { // move closure for t2
                 get_mapped_int("n_bytes", tup).map_or(false, |nb| nb >= t2_n_bytes)
            }),
            join_right_in // Goes to right input of join
        );
        let group_op = groupby(
            Box::new(|tup| filter_groups(&["ipv4.dst"], tup)),
            sum_ints("ipv4.len".to_string()), // Use sum_ints reduction
            "n_bytes".to_string(),
            filter_t2
        );
         let filter_tcp = filter(
            Box::new(|tup| get_mapped_int("ipv4.proto", tup).map_or(false, |p| p == 6)),
            group_op
         );
        epoch(epoch_dur, eid_key.clone(), filter_tcp)
    };


     vec![n_conns_stream, n_bytes_stream]
}

// Simple Join Test
fn join_test(next_op: Box<dyn Operator>) -> Vec<Box<dyn Operator>> {
     let epoch_dur: f64 = 1.0;
     let eid_key = "eid".to_string();

     let (join_left_in, join_right_in) = join(
        eid_key.clone(),
         // Left Extractor (SYN)
         Box::new(|tup: Tuple| {
             let key = rename_filtered_keys(&[("ipv4.src".to_string(), "host".to_string())], &tup);
             let val = rename_filtered_keys(&[("ipv4.dst".to_string(), "remote".to_string())], &tup);
             (key, val)
         }),
         // Right Extractor (SYNACK)
         Box::new(|tup: Tuple| {
             let key = rename_filtered_keys(&[("ipv4.dst".to_string(), "host".to_string())], &tup);
             let val = filter_groups(&["time"], &tup); // Just keep time from SYNACK
             (key, val)
         }),
         next_op // Output goes directly to next_op
     );

      let syns_stream = {
         let filter_op = filter(
            Box::new(|tup| {
                 get_mapped_int("ipv4.proto", tup).map_or(false, |p| p == 6) &&
                 get_mapped_int("l4.flags", tup).map_or(false, |f| f == 2) // SYN
             }),
            join_left_in
         );
        epoch(epoch_dur, eid_key.clone(), filter_op)
    };

     let synacks_stream = {
         let filter_op = filter(
             Box::new(|tup| {
                  get_mapped_int("ipv4.proto", tup).map_or(false, |p| p == 6) &&
                  get_mapped_int("l4.flags", tup).map_or(false, |f| f == 18) // SYNACK
              }),
             join_right_in
         );
         epoch(epoch_dur, eid_key.clone(), filter_op)
     };

     vec![syns_stream, synacks_stream]
}

// Query 3: Distinct src/dst pairs over 100s
fn q3(next_op: Box<dyn Operator>) -> Box<dyn Operator> {
    let distinct_op = distinct(
        Box::new(|tup| filter_groups(&["ipv4.src", "ipv4.dst"], tup)),
        next_op
    );
    epoch(100.0, "eid".to_string(), distinct_op)
}

// Query 4: Packet count per destination over 10000s
fn q4(next_op: Box<dyn Operator>) -> Box<dyn Operator> {
     let group_op = groupby(
        Box::new(|tup| filter_groups(&["ipv4.dst"], tup)),
        Box::new(counter),
        "pkts".to_string(),
        next_op
     );
    epoch(10000.0, "eid".to_string(), group_op)
}

// --- Main Execution ---

// Generates simple test data like the OCaml example
fn generate_test_data(count: usize) -> Vec<Tuple> {
    let mut data = Vec::with_capacity(count);
    let src_mac: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    let dst_mac: [u8; 6] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
    let ip_addr = Ipv4Addr::new(127, 0, 0, 1);

    for i in 0..count {
        let time = 0.000000 + i as f64 * 0.001; // Small time increment
        let mut tup = Tuple::new();
        tup.insert("time".to_string(), OpResult::Float(time));

        tup.insert("eth.src".to_string(), OpResult::MAC(src_mac));
        tup.insert("eth.dst".to_string(), OpResult::MAC(dst_mac));
        tup.insert("eth.ethertype".to_string(), OpResult::Int(0x0800)); // IPv4

        tup.insert("ipv4.hlen".to_string(), OpResult::Int(20));
        tup.insert("ipv4.proto".to_string(), OpResult::Int(6)); // TCP
        tup.insert("ipv4.len".to_string(), OpResult::Int(60));
        tup.insert("ipv4.src".to_string(), OpResult::IPv4(ip_addr));
        tup.insert("ipv4.dst".to_string(), OpResult::IPv4(ip_addr));

        tup.insert("l4.sport".to_string(), OpResult::Int(44000 + i as i64)); // Vary source port
        tup.insert("l4.dport".to_string(), OpResult::Int(50000));
        // Vary flags slightly for testing different queries
        let flags = match i % 4 {
            0 => 2,  // SYN
            1 => 18, // SYNACK
            2 => 16, // ACK
            _ => 17, // FIN+ACK (or just FIN=1)
        };
        tup.insert("l4.flags".to_string(), OpResult::Int(flags));

        data.push(tup);
    }
    data
}


fn run_queries() {
    println!("Setting up queries...");

    // --- Define the final sink/output operator ---
    // Let's use a simple tuple dump to stdout for demonstration
    // We wrap it in Rc<RefCell> because some queries (joins) need shared access to the sink.
    let final_sink = Rc::new(RefCell::new(dump_tuple(stdout(), false)));


    // --- Instantiate queries ---
    // Queries that return a single operator
    let mut single_op_queries: Vec<Box<dyn Operator>> = vec![
        ident(final_sink.borrow().clone()), // Requires clone because dump_tuple isn't Copy
        count_pkts(final_sink.borrow().clone()),
        pkts_per_src_dst(final_sink.borrow().clone()),
        distinct_srcs(final_sink.borrow().clone()),
        tcp_new_cons(final_sink.borrow().clone()),
        ssh_brute_force(final_sink.borrow().clone()),
        super_spreader(final_sink.borrow().clone()),
        port_scan(final_sink.borrow().clone()),
        ddos(final_sink.borrow().clone()),
        q3(final_sink.borrow().clone()),
        q4(final_sink.borrow().clone()),
    ];

    // Queries that return multiple operators (due to joins)
    let mut multi_op_queries_starts: Vec<Vec<Box<dyn Operator>>> = vec![
        syn_flood_sonata(final_sink.borrow().clone()),
        completed_flows(final_sink.borrow().clone()),
        slowloris(final_sink.borrow().clone()),
        join_test(final_sink.borrow().clone()),
    ];

    // Flatten the multi-op starts into the main list
    for mut starts in multi_op_queries_starts {
         single_op_queries.append(&mut starts);
    }


    println!("Generating test data...");
    let test_data = generate_test_data(200); // Increase data size for better testing

    println!("Running data through queries...");
    // --- Process Data ---
    for tup in test_data {
        for query in single_op_queries.iter_mut() {
            // Clone tuple for each independent query pipeline
            query.next(tup.clone());
        }
    }

    // --- Final Resets ---
    // Send a final reset signal, e.g., with the last known epoch or a special marker.
    // This is important for stateful operators like groupby, distinct, join to flush.
    // We'll use a simple empty tuple with a final epoch ID (can be arbitrary if time isn't tracked)
    println!("Sending final resets...");
    let final_reset_tup = utils::tuple_of_list(vec![("eid".to_string(), OpResult::Int(999))]); // Example EID
    for query in single_op_queries.iter_mut() {
        query.reset(final_reset_tup.clone());
    }

}


fn main() {
    run_queries();
    println!("Done");
}
```

**Explanation of Key Changes and Idioms:**

1.  **`OpResult` Enum:** Replaces the OCaml variant type. `Ipv4Addr` from `std::net` is used. MAC addresses use a fixed-size array `[u8; 6]`. `Eq` and `Hash` are manually implemented due to `f64`.
2.  **`Tuple` Type Alias:** `HashMap<String, OpResult>` replaces `Map.Make(String)`.
3.  **`Operator` Trait:** Defines the `next` and `reset` methods. Operators are structs implementing this trait. `&mut self` allows internal state mutation.
4.  **`OpCreator` / `DblOpCreator`:** Type aliases for `FnOnce` closures returning `Box<dyn Operator>`. Dynamic dispatch (`dyn`) is necessary here.
5.  **`chain` / `chain_dbl`:** Helper functions replace the custom OCaml operators (`@=>`, `@==>`).
6.  **Error Handling:** Functions like `get_mapped_int` return `Result<i64, String>`. Callers use `match`, `map_or`, `and_then`, `ok()` etc., to handle potential errors instead of raising exceptions. Panics are avoided in library-like code (`utils`, `builtins`).
7.  **State Management:** OCaml `ref`s are replaced by mutable struct fields (e.g., `epoch_count`, `tups_count` in `MetaMeterOp`). OCaml `Hashtbl` is replaced by `std::collections::HashMap`.
8.  **Closures:** Functions passed as arguments (like for `filter`, `groupby`, `map`) are closures, often captured using `move` if they need to own captured variables. Type bounds like `F: Fn(&Tuple) -> bool + 'static` ensure the closure is valid.
9.  **`Box<dyn Operator>`:** Used extensively where the specific type of the next operator isn't known at compile time (passed as arguments, returned by creators, stored in collections).
10. **`join` Operator:** This is the most complex translation.
    * It requires shared, mutable state (`h_tbl1`, `h_tbl2`, `epoch1`, `epoch2`) between the two operator instances it creates.
    * `Rc<RefCell<JoinState>>` is used to allow shared ownership (`Rc`) and interior mutability (`RefCell`) of this state in a single-threaded context.
    * The `next_op` is also wrapped in `Rc<RefCell<...>>` so both join sides can call `next`/`reset` on it.
    * Epoch handling and matching logic are carefully translated. Table clearing on reset is added for potentially better memory management than the OCaml version.
11. **I/O:** `std::io::{Write, BufReader, BufRead}`, `std::fs::File` are used. `writeln!` macro replaces `fprintf`. CSV handling is done manually similar to OCaml; the `csv` crate could be used for more robustness.
12. **`main.rs`:** Query definitions are functions returning `Box<dyn Operator>`. The OCaml chaining is replaced by nested function calls constructing the pipeline backward from the sink. Test data generation and the main loop mimic the OCaml structure. `Rc<RefCell<>>` is needed for the `final_sink` because `join` requires shared access. Tuples are cloned when sent down multiple query pipelines or to both sides of a `split`/`join`. Final `reset` calls are added to flush stateful operators.