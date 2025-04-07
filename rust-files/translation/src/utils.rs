use std::net::Ipv4Addr;
use std::collections::HashMap;
use std::ops::ShrAssign;
use std::io::{Error, ErrorKind};

enum OpResult {
    Float(f64),
    Int(i32),
    IPv4(Ipv4Addr),
    MAC([u8; 6]),
    Empty,
}

type Headers = HashMap<String, OpResult>;
struct Operator {
    next: Box<dyn FnMut(Headers)>,
    reset: Box<dyn FnMut(Headers)>,
}

type OpCreator = fn(Operator) -> Operator;
type DoubleOpCreator = fn(Operator) -> (Operator, Operator);

struct OpApplicator {
    func: Box<dyn FnMut(Operator) -> Operator>,
}

struct DblOpApplicator {
    func: Box<dyn FnMut(Operator) -> (Operator, Operator)>,
}

impl OpApplicator {
    fn __π(&mut self, next_op: Operator) -> Operator {
        (self.func)(next_op)
    }
}

impl DblOpApplicator {
    fn ____ππ(&mut self, next_op: Operator) -> (Operator, Operator) {
        (self.func)(next_op)
    }
}

fn string_of_mac(buf: &[u8; 6]) -> String {
    buf.iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":")
}

fn tcp_flags_to_strings(flags: i32) -> String {
    let mut hmap: HashMap<&str, i32> = HashMap::new();
    hmap
        .extend([
            ("FIN", 1 << 0),
            ("SYN", 1 << 1),
            ("RST", 1 << 2),
            ("PSH", 1 << 3),
            ("ACK", 1 << 4),
            ("URG", 1 << 5),
            ("ECE", 1 << 6),
            ("CWR", 1 << 7),
        ]);
    hmap
        .iter()
        .filter(|(_, val)| (flags & **val) == **val)
        .fold(String::new(), |mut acc, (key, _)| {
            if !acc.is_empty() {
                acc.push('|');
            }
            acc.push_str(key);
            acc 
        })
}

fn int_of_op_result(input: &OpResult) -> Result<i32, Error>  {
    match *input {
        OpResult::Int(i) => Ok(i),
        _ => Err(Error::new(ErrorKind::InvalidInput, "Trying to extract int from non-int result"))
    } 
}




