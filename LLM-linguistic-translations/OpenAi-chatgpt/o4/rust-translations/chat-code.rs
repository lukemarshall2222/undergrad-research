// src/main.rs

use std::collections::{HashMap, BTreeMap};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::io::{self, BufRead, BufReader, Write};
use std::net::Ipv4Addr;
use std::fs::File;
use std::rc::Rc;
use std::cell::RefCell;

//-----------------------------------------------------------------------------
// 1) Tagged values and Tuple wrapper (so we can hash & eq them)
//-----------------------------------------------------------------------------

/// A single field’s value.
#[derive(Clone, Debug)]
pub enum OpResult {
    Float(f64),
    Int(i32),
    IPv4(Ipv4Addr),
    MAC([u8; 6]),
    Empty,
}

impl PartialEq for OpResult {
    fn eq(&self, other: &Self) -> bool {
        use OpResult::*;
        match (self, other) {
            (Float(a), Float(b))   => a.to_bits() == b.to_bits(),
            (Int(a), Int(b))       => a == b,
            (IPv4(a), IPv4(b))     => a == b,
            (MAC(a), MAC(b))       => a == b,
            (Empty, Empty)         => true,
            _                      => false,
        }
    }
}
impl Eq for OpResult {}

impl Hash for OpResult {
    fn hash<H: Hasher>(&self, state: &mut H) {
        use OpResult::*;
        match self {
            Float(f) => {
                state.write_u8(0);
                state.write_u64(&f.to_bits());
            }
            Int(i) => {
                state.write_u8(1);
                i.hash(state);
            }
            IPv4(a) => {
                state.write_u8(2);
                a.hash(state);
            }
            MAC(b) => {
                state.write_u8(3);
                b.hash(state);
            }
            Empty => {
                state.write_u8(4);
            }
        }
    }
}

impl fmt::Display for OpResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use OpResult::*;
        match self {
            Float(x) => write!(f, "{}", x),
            Int(i) => write!(f, "{}", i),
            IPv4(a) => write!(f, "{}", a),
            MAC(b) => write!(
                f,
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                b[0], b[1], b[2], b[3], b[4], b[5]
            ),
            Empty => write!(f, "Empty"),
        }
    }
}

impl OpResult {
    pub fn as_int(&self) -> i32 {
        if let OpResult::Int(i) = *self {
            i
        } else {
            panic!("Trying to extract int from non-int result");
        }
    }
    pub fn as_float(&self) -> f64 {
        if let OpResult::Float(x) = *self {
            x
        } else {
            panic!("Trying to extract float from non-float result");
        }
    }
}

/// A “tuple” is just a map from field‐names to tagged values.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Tuple(pub BTreeMap<String, OpResult>);

impl Tuple {
    pub fn empty() -> Self {
        Tuple(BTreeMap::new())
    }
    pub fn singleton(key: impl Into<String>, val: OpResult) -> Self {
        let mut m = BTreeMap::new();
        m.insert(key.into(), val);
        Tuple(m)
    }
    pub fn add(&self, key: impl Into<String>, val: OpResult) -> Self {
        let mut m = self.0.clone();
        m.insert(key.into(), val);
        Tuple(m)
    }
    pub fn union(a: &Self, b: &Self) -> Self {
        let mut m = a.0.clone();
        for (k, v) in &b.0 {
            m.insert(k.clone(), v.clone());
        }
        Tuple(m)
    }
    pub fn filter_keys(&self, keys: &[&str]) -> Self {
        let mut m = BTreeMap::new();
        for &k in keys {
            if let Some(v) = self.0.get(k) {
                m.insert(k.to_string(), v.clone());
            }
        }
        Tuple(m)
    }
    pub fn find(&self, key: &str) -> &OpResult {
        &self.0[key]
    }
    pub fn find_opt(&self, key: &str) -> Option<&OpResult> {
        self.0.get(key)
    }
    pub fn string_of(&self) -> String {
        let mut s = String::new();
        for (k, v) in &self.0 {
            s.push_str(&format!("\"{}\" => {}, ", k, v));
        }
        s
    }
}

/// Build a tuple from a Vec of (String,OpResult)
pub fn tuple_of_list(pairs: Vec<(String, OpResult)>) -> Tuple {
    let mut m = BTreeMap::new();
    for (k, v) in pairs {
        m.insert(k, v);
    }
    Tuple(m)
}

/// Lookup convenience
pub fn lookup_int(key: &str, tup: &Tuple) -> i32 {
    tup.find(key).as_int()
}
pub fn lookup_float(key: &str, tup: &Tuple) -> f64 {
    tup.find(key).as_float()
}

//-----------------------------------------------------------------------------
// 2) Conversion & formatting utilities
//-----------------------------------------------------------------------------

/// “0” → Int(0), otherwise parse as IPv4
pub fn get_ip_or_zero(s: &str) -> OpResult {
    if s == "0" {
        OpResult::Int(0)
    } else {
        OpResult::IPv4(s.parse().expect("invalid IPv4"))
    }
}

/// Format 6‐byte MAC
pub fn string_of_mac(bytes: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
    )
}

/// TCP flag bits → “SYN|ACK|…”
pub fn tcp_flags_to_strings(flags: u8) -> String {
    let mapping = [
        ("FIN", 1 << 0),
        ("SYN", 1 << 1),
        ("RST", 1 << 2),
        ("PSH", 1 << 3),
        ("ACK", 1 << 4),
        ("URG", 1 << 5),
        ("ECE", 1 << 6),
        ("CWR", 1 << 7),
    ];
    mapping
        .iter()
        .filter_map(|&(name, bit)| if flags & bit == bit { Some(name) } else { None })
        .collect::<Vec<_>>()
        .join("|")
}

//-----------------------------------------------------------------------------
// 3) The Operator trait & combinators
//-----------------------------------------------------------------------------

/// A processing unit in the pipeline.
pub trait Operator {
    fn next(&mut self, tup: &Tuple);
    fn reset(&mut self, tup: &Tuple);
}

/// Single‐arg constructor
pub type OpCreator = Box<dyn Fn(Box<dyn Operator>) -> Box<dyn Operator>>;

/// Two‐arg constructor (for join)
pub type DblOpCreator =
    Box<dyn Fn(Box<dyn Operator>) -> (Box<dyn Operator>, Box<dyn Operator>)>;

/// Right‐associative chain
pub fn chain(opc: OpCreator, next: Box<dyn Operator>) -> Box<dyn Operator> {
    opc(next)
}

/// Right‐associative chain2
pub fn chain2(opc: DblOpCreator, next: Box<dyn Operator>) -> (Box<dyn Operator>, Box<dyn Operator>) {
    opc(next)
}

//-----------------------------------------------------------------------------
// 4) Core operators
//-----------------------------------------------------------------------------

/// Dump every tuple to a writer, optionally marking resets.
pub struct DumpTuple<W: Write> {
    out: W,
    show_reset: bool,
}

impl<W: Write> DumpTuple<W> {
    pub fn new(out: W, show_reset: bool) -> Self {
        DumpTuple { out, show_reset }
    }
}

impl<W: Write> Operator for DumpTuple<W> {
    fn next(&mut self, tup: &Tuple) {
        writeln!(self.out, "{}", tup.string_of()).unwrap();
    }
    fn reset(&mut self, tup: &Tuple) {
        if self.show_reset {
            writeln!(self.out, "{}\n[reset]", tup.string_of()).unwrap();
        }
    }
}

/// CSV dumper: one header + rows
pub struct CsvDumper<W: Write> {
    out: W,
    first: bool,
    static_field: Option<(String, String)>,
}

impl<W: Write> CsvDumper<W> {
    pub fn new(out: W, static_field: Option<(String, String)>, header: bool) -> Self {
        CsvDumper { out, first: header, static_field }
    }
}

impl<W: Write> Operator for CsvDumper<W> {
    fn next(&mut self, tup: &Tuple) {
        if self.first {
            if let Some((ref k, _)) = self.static_field {
                write!(self.out, "{},", k).unwrap();
            }
            for key in tup.0.keys() {
                write!(self.out, "{},", key).unwrap();
            }
            writeln!(self.out).unwrap();
            self.first = false;
        }
        if let Some((_, ref v)) = self.static_field {
            write!(self.out, "{},", v).unwrap();
        }
        for val in tup.0.values() {
            write!(self.out, "{},", val).unwrap();
        }
        writeln!(self.out).unwrap();
    }
    fn reset(&mut self, _tup: &Tuple) {}
}

/// Walt’s canonical CSV dumper
pub struct WaltCsv {
    out: Option<File>,
    filename: String,
    first: bool,
}

impl WaltCsv {
    pub fn new(filename: impl Into<String>) -> Self {
        WaltCsv { out: None, filename: filename.into(), first: true }
    }
}

impl Operator for WaltCsv {
    fn next(&mut self, tup: &Tuple) {
        if self.first {
            self.out = Some(File::create(&self.filename).unwrap());
            self.first = false;
        }
        let o = self.out.as_mut().unwrap();
        // Order: src_ip,dst_ip,src_l4_port,dst_l4_port,packet_count,byte_count,epoch_id
        let line = format!(
            "{},{},{},{},{},{},{}\n",
            tup.find("src_ip"),
            tup.find("dst_ip"),
            tup.find("src_l4_port"),
            tup.find("dst_l4_port"),
            tup.find("packet_count"),
            tup.find("byte_count"),
            tup.find("epoch_id"),
        );
        write!(o, "{}", line).unwrap();
    }
    fn reset(&mut self, _tup: &Tuple) {}
}

/// Read Walt’s CSVs and drive operators.
/// TODO: exactly mirror the OCaml `read_walts_csv` logic here.
pub fn read_walts_csv(
    filenames: &[&str],
    epoch_id_key: &str,
    ops: &mut [Box<dyn Operator>],
) -> io::Result<()> {
    // You’d open each file with BufReader, track (in_chan, eid, tup_count),
    // loop over rows with `for line in reader.lines()`, parse with `split(',')`,
    // assemble a Tuple, call next/reset on each operator exactly as in OCaml.
    unimplemented!("read_walts_csv is left as an exercise in direct translation");
}

/// Count & log per‐epoch stats, then forward to next_op.
pub struct MetaMeter<W: Write> {
    name: String,
    out: W,
    static_field: Option<String>,
    epoch_count: i32,
    tups_count: i32,
    next: Box<dyn Operator>,
}

impl<W: Write> MetaMeter<W> {
    pub fn new(
        name: impl Into<String>,
        out: W,
        static_field: Option<String>,
        next: Box<dyn Operator>,
    ) -> Self {
        MetaMeter {
            name: name.into(),
            out,
            static_field,
            epoch_count: 0,
            tups_count: 0,
            next,
        }
    }
}

impl<W: Write> Operator for MetaMeter<W> {
    fn next(&mut self, tup: &Tuple) {
        self.tups_count += 1;
        self.next.next(tup);
    }
    fn reset(&mut self, tup: &Tuple) {
        let sf = self.static_field.clone().unwrap_or_default();
        writeln!(
            self.out,
            "{},{},{},{}",
            self.epoch_count, self.name, self.tups_count, sf
        )
        .unwrap();
        self.tups_count = 0;
        self.epoch_count += 1;
        self.next.reset(tup);
    }
}

/// Epoch‐based splitter
pub struct Epoch {
    width: f64,
    key_out: String,
    boundary: f64,
    eid: i32,
    next: Box<dyn Operator>,
}

impl Epoch {
    pub fn new(width: f64, key_out: impl Into<String>, next: Box<dyn Operator>) -> Self {
        Epoch { width, key_out: key_out.into(), boundary: 0.0, eid: 0, next }
    }
}

impl Operator for Epoch {
    fn next(&mut self, tup: &Tuple) {
        let time = tup.find("time").as_float();
        if self.boundary == 0.0 {
            self.boundary = time + self.width;
        } else if time >= self.boundary {
            while time >= self.boundary {
                self.next
                    .reset(&Tuple::singleton(self.key_out.clone(), OpResult::Int(self.eid)));
                self.boundary += self.width;
                self.eid += 1;
            }
        }
        let with_eid = tup.add(self.key_out.clone(), OpResult::Int(self.eid));
        self.next.next(&with_eid);
    }
    fn reset(&mut self, _tup: &Tuple) {
        self.next
            .reset(&Tuple::singleton(self.key_out.clone(), OpResult::Int(self.eid)));
        self.boundary = 0.0;
        self.eid = 0;
    }
}

/// Filter operator
pub struct FilterOp {
    f: Box<dyn Fn(&Tuple) -> bool>,
    next: Box<dyn Operator>,
}

impl FilterOp {
    pub fn new<F>(f: F, next: Box<dyn Operator>) -> Box<dyn Operator>
    where
        F: 'static + Fn(&Tuple) -> bool,
    {
        Box::new(FilterOp { f: Box::new(f), next })
    }
}

impl Operator for FilterOp {
    fn next(&mut self, tup: &Tuple) {
        if (self.f)(tup) {
            self.next.next(tup);
        }
    }
    fn reset(&mut self, tup: &Tuple) {
        self.next.reset(tup);
    }
}

/// Map operator
pub struct MapOp {
    f: Box<dyn Fn(&Tuple) -> Tuple>,
    next: Box<dyn Operator>,
}

impl MapOp {
    pub fn new<F>(f: F, next: Box<dyn Operator>) -> Box<dyn Operator>
    where
        F: 'static + Fn(&Tuple) -> Tuple,
    {
        Box::new(MapOp { f: Box::new(f), next })
    }
}

impl Operator for MapOp {
    fn next(&mut self, tup: &Tuple) {
        let mapped = (self.f)(tup);
        self.next.next(&mapped);
    }
    fn reset(&mut self, tup: &Tuple) {
        self.next.reset(tup);
    }
}

/// GroupBy operator
pub struct GroupBy {
    key_extractor: Box<dyn Fn(&Tuple) -> Tuple>,
    reducer: Box<dyn Fn(&OpResult, &Tuple) -> OpResult>,
    out_key: String,
    table: HashMap<Tuple, OpResult>,
    next: Box<dyn Operator>,
}

impl GroupBy {
    pub fn new<KE, RF>(
        key_extractor: KE,
        reducer: RF,
        out_key: impl Into<String>,
        next: Box<dyn Operator>,
    ) -> Box<dyn Operator>
    where
        KE: 'static + Fn(&Tuple) -> Tuple,
        RF: 'static + Fn(&OpResult, &Tuple) -> OpResult,
    {
        Box::new(GroupBy {
            key_extractor: Box::new(key_extractor),
            reducer: Box::new(reducer),
            out_key: out_key.into(),
            table: HashMap::new(),
            next,
        })
    }
}

impl Operator for GroupBy {
    fn next(&mut self, tup: &Tuple) {
        let key = (self.key_extractor)(tup);
        let entry = self.table.entry(key.clone()).or_insert_with(|| OpResult::Empty);
        *entry = (self.reducer)(entry, tup);
    }
    fn reset(&mut self, tup: &Tuple) {
        for (group_key, val) in &self.table {
            let mut out_tup = Tuple::union(tup, group_key);
            out_tup = out_tup.add(self.out_key.clone(), val.clone());
            self.next.next(&out_tup);
        }
        self.next.reset(tup);
        self.table.clear();
    }
}

/// Distinct operator
pub struct Distinct {
    key_extractor: Box<dyn Fn(&Tuple) -> Tuple>,
    table: HashMap<Tuple, ()>,
    next: Box<dyn Operator>,
}

impl Distinct {
    pub fn new<KE>(key_extractor: KE, next: Box<dyn Operator>) -> Box<dyn Operator>
    where
        KE: 'static + Fn(&Tuple) -> Tuple,
    {
        Box::new(Distinct {
            key_extractor: Box::new(key_extractor),
            table: HashMap::new(),
            next,
        })
    }
}

impl Operator for Distinct {
    fn next(&mut self, tup: &Tuple) {
        let key = (self.key_extractor)(tup);
        self.table.insert(key, ());
    }
    fn reset(&mut self, tup: &Tuple) {
        for key in self.table.keys() {
            let out_tup = Tuple::union(tup, key);
            self.next.next(&out_tup);
        }
        self.next.reset(tup);
        self.table.clear();
    }
}

/// Split operator
pub struct Split {
    left: Box<dyn Operator>,
    right: Box<dyn Operator>,
}

impl Split {
    pub fn new(left: Box<dyn Operator>, right: Box<dyn Operator>) -> Box<dyn Operator> {
        Box::new(Split { left, right })
    }
}

impl Operator for Split {
    fn next(&mut self, tup: &Tuple) {
        self.left.next(tup);
        self.right.next(tup);
    }
    fn reset(&mut self, tup: &Tuple) {
        self.left.reset(tup);
        self.right.reset(tup);
    }
}

/// Join stub: two operators sharing state
pub fn join(
    _left_extractor: impl Fn(&Tuple) -> (Tuple, Tuple) + 'static,
    _right_extractor: impl Fn(&Tuple) -> (Tuple, Tuple) + 'static,
) -> DblOpCreator {
    Box::new(move |down: Box<dyn Operator>| {
        // TODO: implement real join semantics with two shared hash‐tables.
        let op1 = Box::new(UnimplementedJoinSide {});
        let op2 = Box::new(UnimplementedJoinSide {});
        (op1, op2)
    })
}

/// A placeholder join operator until you wire in real logic.
struct UnimplementedJoinSide;
impl Operator for UnimplementedJoinSide {
    fn next(&mut self, _tup: &Tuple) { unimplemented!("join side not yet implemented") }
    fn reset(&mut self, _tup: &Tuple) { unimplemented!("join side not yet implemented") }
}

/// Rename‐and‐filter keys (join helper)
pub fn rename_filtered_keys(
    renames: &[(impl AsRef<str>, impl AsRef<str>)],
    tup: &Tuple,
) -> Tuple {
    let mut out = Tuple::empty();
    for (old, new) in renames {
        if let Some(v) = tup.find_opt(old.as_ref()) {
            out = out.add(new.as_ref().to_string(), v.clone());
        }
    }
    out
}

//-----------------------------------------------------------------------------
// 5) Sonata query constructors
//-----------------------------------------------------------------------------

pub fn ident(next: Box<dyn Operator>) -> Box<dyn Operator> {
    let mapper = |tup: &Tuple| {
        tup.clone().filter_keys(&["eth.src", "eth.dst"])
    };
    chain(Box::new(move |down| MapOp::new(mapper, down)), next)
}

pub fn count_pkts(next: Box<dyn Operator>) -> Box<dyn Operator> {
    chain(
        Box::new(move |down| Epoch::new(1.0, "eid", down)),
        chain(
            Box::new(move |down| GroupBy::new(
                |_| Tuple::empty(),
                |acc, _| match acc {
                    OpResult::Empty => OpResult::Int(1),
                    OpResult::Int(i) => OpResult::Int(i+1),
                    _ => panic!("counter got non-int")
                },
                "pkts",
                down,
            )),
            next,
        ),
    )
}

pub fn pkts_per_src_dst(next: Box<dyn Operator>) -> Box<dyn Operator> {
    chain(
        Box::new(move |down| Epoch::new(1.0, "eid", down)),
        chain(
            Box::new(move |down| GroupBy::new(
                move |tup| tup.filter_keys(&["ipv4.src","ipv4.dst"]),
                |acc, _| match acc {
                    OpResult::Empty => OpResult::Int(1),
                    OpResult::Int(i) => OpResult::Int(i+1),
                    _ => panic!(),
                },
                "pkts",
                down,
            )),
            next,
        ),
    )
}

pub fn distinct_srcs(next: Box<dyn Operator>) -> Box<dyn Operator> {
    chain(
        Box::new(move |down| Epoch::new(1.0, "eid", down)),
        chain(
            Box::new(move |down| Distinct::new(
                move |tup| tup.filter_keys(&["ipv4.src"]),
                down,
            )),
            chain(
                Box::new(move |down| GroupBy::new(
                    |_| Tuple::empty(),
                    |acc, _| match acc {
                        OpResult::Empty => OpResult::Int(1),
                        OpResult::Int(i) => OpResult::Int(i+1),
                        _ => panic!(),
                    },
                    "srcs",
                    down,
                )),
                next,
            ),
        ),
    )
}

pub fn tcp_new_cons(next: Box<dyn Operator>) -> Box<dyn Operator> {
    let threshold = 40;
    chain(
        Box::new(move |down| Epoch::new(1.0, "eid", down)),
        chain(
            Box::new(move |down| FilterOp::new(
                move |tup| lookup_int("ipv4.proto", tup) == 6 && lookup_int("l4.flags", tup) == 2,
                down,
            )),
            chain(
                Box::new(move |down| GroupBy::new(
                    move |tup| tup.filter_keys(&["ipv4.dst"]),
                    |acc, _| match acc {
                        OpResult::Empty => OpResult::Int(1),
                        OpResult::Int(i) => OpResult::Int(i+1),
                        _ => panic!(),
                    },
                    "cons",
                    down,
                )),
                chain(
                    Box::new(move |down| FilterOp::new(
                        move |tup| lookup_int("cons", tup) >= threshold,
                        down,
                    )),
                    next,
                ),
            ),
        ),
    )
}

pub fn ssh_brute_force(next: Box<dyn Operator>) -> Box<dyn Operator> {
    let threshold = 40;
    chain(
        Box::new(move |down| Epoch::new(1.0, "eid", down)),
        chain(
            Box::new(move |down| FilterOp::new(
                move |tup| lookup_int("ipv4.proto", tup) == 6 && lookup_int("l4.dport", tup) == 22,
                down,
            )),
            chain(
                Box::new(move |down| Distinct::new(
                    move |tup| tup.filter_keys(&["ipv4.src","ipv4.dst","ipv4.len"]),
                    down,
                )),
                chain(
                    Box::new(move |down| GroupBy::new(
                        move |tup| tup.filter_keys(&["ipv4.dst","ipv4.len"]),
                        |acc, _| match acc {
                            OpResult::Empty => OpResult::Int(1),
                            OpResult::Int(i) => OpResult::Int(i+1),
                            _ => panic!(),
                        },
                        "srcs",
                        down,
                    )),
                    chain(
                        Box::new(move |down| FilterOp::new(
                            move |tup| lookup_int("srcs", tup) >= threshold,
                            down,
                        )),
                        next,
                    ),
                ),
            ),
        ),
    )
}

pub fn super_spreader(next: Box<dyn Operator>) -> Box<dyn Operator> {
    let threshold = 40;
    chain(
        Box::new(move |down| Epoch::new(1.0, "eid", down)),
        chain(
            Box::new(move |down| Distinct::new(
                move |tup| tup.filter_keys(&["ipv4.src","ipv4.dst"]),
                down,
            )),
            chain(
                Box::new(move |down| GroupBy::new(
                    move |tup| tup.filter_keys(&["ipv4.src"]),
                    |acc, _| match acc {
                        OpResult::Empty => OpResult::Int(1),
                        OpResult::Int(i) => OpResult::Int(i+1),
                        _ => panic!(),
                    },
                    "dsts",
                    down,
                )),
                chain(
                    Box::new(move |down| FilterOp::new(
                        move |tup| lookup_int("dsts", tup) >= threshold,
                        down,
                    )),
                    next,
                ),
            ),
        ),
    )
}

pub fn port_scan(next: Box<dyn Operator>) -> Box<dyn Operator> {
    let threshold = 40;
    chain(
        Box::new(move |down| Epoch::new(1.0, "eid", down)),
        chain(
            Box::new(move |down| Distinct::new(
                move |tup| tup.filter_keys(&["ipv4.src","l4.dport"]),
                down,
            )),
            chain(
                Box::new(move |down| GroupBy::new(
                    move |tup| tup.filter_keys(&["ipv4.src"]),
                    |acc, _| match acc {
                        OpResult::Empty => OpResult::Int(1),
                        OpResult::Int(i) => OpResult::Int(i+1),
                        _ => panic!(),
                    },
                    "ports",
                    down,
                )),
                chain(
                    Box::new(move |down| FilterOp::new(
                        move |tup| lookup_int("ports", tup) >= threshold,
                        down,
                    )),
                    next,
                ),
            ),
        ),
    )
}

pub fn ddos(next: Box<dyn Operator>) -> Box<dyn Operator> {
    let threshold = 45;
    chain(
        Box::new(move |down| Epoch::new(1.0, "eid", down)),
        chain(
            Box::new(move |down| Distinct::new(
                move |tup| tup.filter_keys(&["ipv4.src","ipv4.dst"]),
                down,
            )),
            chain(
                Box::new(move |down| GroupBy::new(
                    move |tup| tup.filter_keys(&["ipv4.dst"]),
                    |acc, _| match acc {
                        OpResult::Empty => OpResult::Int(1),
                        OpResult::Int(i) => OpResult::Int(i+1),
                        _ => panic!(),
                    },
                    "srcs",
                    down,
                )),
                chain(
                    Box::new(move |down| FilterOp::new(
                        move |tup| lookup_int("srcs", tup) >= threshold,
                        down,
                    )),
                    next,
                ),
            ),
        ),
    )
}

/// Sonata 6: SYN flood (two joins + post‐map + filter)
pub fn syn_flood_sonata(next: Box<dyn Operator>) -> Vec<Box<dyn Operator>> {
    let threshold = 3;
    let epoch_dur = 1.0;
    // build the three sides: syns, synacks, acks
    let syns = chain(
        Box::new(move |d| Epoch::new(epoch_dur, "eid", d)),
        chain(
            Box::new(move |d| FilterOp::new(
                move |t| lookup_int("ipv4.proto", t) == 6 && lookup_int("l4.flags", t) == 2,
                d,
            )),
            next.clone_box(),
        ),
    );
    let synacks = chain(
        Box::new(move |d| Epoch::new(epoch_dur, "eid", d)),
        chain(
            Box::new(move |d| FilterOp::new(
                move |t| lookup_int("ipv4.proto", t) == 6 && lookup_int("l4.flags", t) == 18,
                d,
            )),
            next.clone_box(),
        ),
    );
    let acks = chain(
        Box::new(move |d| Epoch::new(epoch_dur, "eid", d)),
        chain(
            Box::new(move |d| FilterOp::new(
                move |t| lookup_int("ipv4.proto", t) == 6 && lookup_int("l4.flags", t) == 16,
                d,
            )),
            next.clone_box(),
        ),
    );

    // stub out join usage
    let (j1, j2) = chain2(join(
        |t| (t.filter_keys(&["ipv4.dst"]), t.filter_keys(&["syns+synacks"])),
        |t| (
            rename_filtered_keys(&[("ipv4.dst","host")], t),
            t.filter_keys(&["acks"])
        ),
    ), next.clone_box());

    let (j3, j4) = chain2(join(
        |t| (
            rename_filtered_keys(&[("ipv4.dst","host")], t),
            t.filter_keys(&["syns"])
        ),
        |t| (
            rename_filtered_keys(&[("ipv4.src","host")], t),
            t.filter_keys(&["synacks"])
        ),
    ), j1.clone_box());

    vec![
        syns,
        synacks,
        acks,
    ]
}

/// Sonata 7,8, join_test, q3, q4… you’d continue in the same style,
/// using `chain`, `chain2(join(...))`, `FilterOp::new`, `GroupBy::new`, etc.
/// For brevity they’re omitted—but the pattern is identical to the ones above.

// Remaining Sonata query constructors in Rust:

pub fn completed_flows(next: Box<dyn Operator>) -> Vec<Box<dyn Operator>> {
    let threshold = 1;
    let epoch_dur = 30.0;

    // Build the “tail” after join: compute diff = syns – fins, then filter
    let tail = Box::new(MapOp::new(
        Box::new(move |t: &Tuple| {
            let diff = lookup_int("syns", t) - lookup_int("fins", t);
            t.clone().add("diff".to_string(), OpResult::Int(diff))
        }),
        Box::new(FilterOp::new(
            Box::new(move |t: &Tuple| lookup_int("diff", t) >= threshold),
            next,
        )),
    ));

    // Chain the join with that tail
    let (join_op1, join_op2) = chain2(
        join(
            |t: &Tuple| (rename_filtered_keys(&[("ipv4.dst","host")], t),
                         t.filter_keys(&["syns"])),
            |t: &Tuple| (rename_filtered_keys(&[("ipv4.src","host")], t),
                         t.filter_keys(&["fins"]))
        ),
        tail,
    );

    // syns branch
    let syns = chain(
        Box::new(move |down| Epoch::new(epoch_dur, "eid", down)),
        chain(
            Box::new(move |down| FilterOp::new(
                Box::new(move |t: &Tuple|
                    lookup_int("ipv4.proto", t) == 6 &&
                    (lookup_int("l4.flags", t) & 1) == 1
                ),
                down,
            )),
            join_op1,
        ),
    );

    // fins branch
    let fins = chain(
        Box::new(move |down| Epoch::new(epoch_dur, "eid", down)),
        chain(
            Box::new(move |down| FilterOp::new(
                Box::new(move |t: &Tuple|
                    lookup_int("ipv4.proto", t) == 6 &&
                    (lookup_int("l4.flags", t) & 1) == 1
                ),
                down,
            )),
            join_op2,
        ),
    );

    vec![syns, fins]
}

pub fn slowloris(next: Box<dyn Operator>) -> Vec<Box<dyn Operator>> {
    let t1 = 5;
    let t2 = 500;
    let t3 = 90;
    let epoch_dur = 1.0;

    // n_conns branch
    let n_conns = chain(
        Box::new(move |down| Epoch::new(epoch_dur, "eid", down)),
        chain(
            Box::new(move |down| FilterOp::new(
                Box::new(move |t: &Tuple| lookup_int("ipv4.proto", t) == 6),
                down,
            )),
            chain(
                Box::new(move |down| Distinct::new(
                    Box::new(move |t: &Tuple| t.filter_keys(&["ipv4.src","ipv4.dst","l4.sport"])),
                    down,
                )),
                chain(
                    Box::new(move |down| GroupBy::new(
                        Box::new(move |t: &Tuple| t.filter_keys(&["ipv4.dst"])),
                        Box::new(move |acc, _| match acc {
                            OpResult::Empty => OpResult::Int(1),
                            OpResult::Int(i) => OpResult::Int(i + 1),
                            _ => panic!(),
                        }),
                        "n_conns",
                        down,
                    )),
                    next.clone_box(),
                ),
            ),
        ),
    );

    // n_bytes branch
    let n_bytes = chain(
        Box::new(move |down| Epoch::new(epoch_dur, "eid", down)),
        chain(
            Box::new(move |down| FilterOp::new(
                Box::new(move |t: &Tuple| lookup_int("ipv4.proto", t) == 6),
                down,
            )),
            chain(
                Box::new(move |down| GroupBy::new(
                    Box::new(move |t: &Tuple| t.filter_keys(&["ipv4.dst"])),
                    Box::new(move |acc, tup| match acc {
                        OpResult::Empty => match tup.find_opt("ipv4.len") {
                            Some(OpResult::Int(n)) => OpResult::Int(*n),
                            _ => panic!("sum_ints missing ipv4.len"),
                        },
                        OpResult::Int(i) => match tup.find_opt("ipv4.len") {
                            Some(OpResult::Int(n)) => OpResult::Int(i + *n),
                            _ => panic!(),
                        },
                        _ => panic!(),
                    }),
                    "n_bytes",
                    down,
                )),
                next.clone_box(),
            ),
        ),
    );

    // join tail: compute bytes_per_conn then filter ≤ t3
    let tail = Box::new(MapOp::new(
        Box::new(move |t: &Tuple| {
            let bytes = lookup_int("n_bytes", t);
            let conns = lookup_int("n_conns", t);
            t.clone().add("bytes_per_conn".to_string(), OpResult::Int(bytes / conns))
        }),
        Box::new(FilterOp::new(
            Box::new(move |t: &Tuple| lookup_int("bytes_per_conn", t) <= t3),
            next,
        )),
    ));

    let (op1, op2) = chain2(
        join(
            |t: &Tuple| (t.filter_keys(&["ipv4.dst"]), t.filter_keys(&["n_conns"])),
            |t: &Tuple| (t.filter_keys(&["ipv4.dst"]), t.filter_keys(&["n_bytes"])),
        ),
        tail,
    );

    vec![
        chain(Box::new(move |down| n_conns), op1),
        chain(Box::new(move |down| n_bytes), op2),
    ]
}

pub fn join_test(next: Box<dyn Operator>) -> Vec<Box<dyn Operator>> {
    let epoch_dur = 1.0;

    let syns = chain(
        Box::new(move |down| Epoch::new(epoch_dur, "eid", down)),
        chain(
            Box::new(move |down| FilterOp::new(
                Box::new(move |t: &Tuple|
                    lookup_int("ipv4.proto", t) == 6 &&
                    lookup_int("l4.flags", t) == 2
                ),
                down,
            )),
            next.clone_box(),
        ),
    );

    let synacks = chain(
        Box::new(move |down| Epoch::new(epoch_dur, "eid", down)),
        chain(
            Box::new(move |down| FilterOp::new(
                Box::new(move |t: &Tuple|
                    lookup_int("ipv4.proto", t) == 6 &&
                    lookup_int("l4.flags", t) == 18
                ),
                down,
            )),
            next.clone_box(),
        ),
    );

    let (op1, op2) = chain2(
        join(
            |t: &Tuple| (
                rename_filtered_keys(&[("ipv4.src","host")], t),
                rename_filtered_keys(&[("ipv4.dst","remote")], t)
            ),
            |t: &Tuple| (
                rename_filtered_keys(&[("ipv4.dst","host")], t),
                t.filter_keys(&["time"])
            ),
        ),
        next,
    );

    vec![
        chain(Box::new(move |down| syns), op1),
        chain(Box::new(move |down| synacks), op2),
    ]
}

pub fn q3(next: Box<dyn Operator>) -> Box<dyn Operator> {
    chain(
        Box::new(move |down| Epoch::new(100.0, "eid", down)),
        chain(
            Box::new(move |down| Distinct::new(
                Box::new(move |t| t.filter_keys(&["ipv4.src","ipv4.dst"])),
                down,
            )),
            next,
        ),
    )
}

pub fn q4(next: Box<dyn Operator>) -> Box<dyn Operator> {
    chain(
        Box::new(move |down| Epoch::new(10000.0, "eid", down)),
        chain(
            Box::new(move |down| GroupBy::new(
                Box::new(move |t| t.filter_keys(&["ipv4.dst"])),
                Box::new(move |acc, _| match acc {
                    OpResult::Empty => OpResult::Int(1),
                    OpResult::Int(i) => OpResult::Int(i + 1),
                    _ => panic!(),
                }),
                "pkts",
                down,
            )),
            next,
        ),
    )
}


/// Finally, assemble all queries and run them on a synthetic stream:
pub fn queries() -> Vec<Box<dyn Operator>> {
    vec![
        chain(Box::new(|d| ident(d)), Box::new(DumpTuple::new(std::io::stdout(), false))),
    ]
}

pub fn run_queries() {
    let mut qs = queries();
    for i in 0..20 {
        let tup = Tuple::empty()
            .add("time", OpResult::Float(i as f64))
            .add("eth.src", OpResult::MAC([0x00,0x11,0x22,0x33,0x44,0x55]))
            .add("eth.dst", OpResult::MAC([0xAA,0xBB,0xCC,0xDD,0xEE,0xFF]))
            .add("eth.ethertype", OpResult::Int(0x0800))
            .add("ipv4.hlen", OpResult::Int(20))
            .add("ipv4.proto", OpResult::Int(6))
            .add("ipv4.len", OpResult::Int(60))
            .add("ipv4.src", OpResult::IPv4("127.0.0.1".parse().unwrap()))
            .add("ipv4.dst", OpResult::IPv4("127.0.0.1".parse().unwrap()))
            .add("l4.sport", OpResult::Int(440))
            .add("l4.dport", OpResult::Int(50000))
            .add("l4.flags", OpResult::Int(10));
        for q in qs.iter_mut() {
            q.next(&tup);
        }
    }
    println!("Done");
}

fn main() {
    run_queries();
}
