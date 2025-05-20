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