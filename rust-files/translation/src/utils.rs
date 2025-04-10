use std::net::Ipv4Addr;
use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::io::Write;
use std::fmt;

pub enum OpResult {
    Float(f64),
    Int(i32),
    IPv4(Ipv4Addr),
    MAC([u8; 6]),
    Empty,
}

impl OpResult {
    fn clone(&self) -> Self {
        match self {
            OpResult::Float(f) => OpResult::Float(f.clone()),
            OpResult::Int(i)   => OpResult::Int(i.clone()),
            OpResult::IPv4(a)  => OpResult::IPv4(a.clone()),
            OpResult::MAC(m)   => OpResult::MAC(m.clone()),
            OpResult::Empty  => OpResult::Empty
        }
    }
}

impl fmt::Display for OpResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", string_of_op_result(self))
    }
}

pub type Headers = HashMap<String, OpResult>;

pub struct Operator<'a> {
    pub next: Box<dyn FnMut(&Headers) + 'a>,
    pub reset: Box<dyn FnMut(&Headers) + 'a>,
}

impl<'a> Operator<'a> {

    pub fn new( next: Box<dyn FnMut(&Headers) + 'a>, 
                reset: Box<dyn FnMut(&Headers) + 'a>
            ) -> Operator<'a> {
            Operator { next, reset }
    }
}

pub type OpCreator = fn(Operator) -> Operator;
pub type DoubleOpCreator = fn(Operator) -> (Operator, Operator);

pub struct OpApplicator {
    func: Box<dyn FnMut(Operator) -> Operator>,
}

pub struct DblOpApplicator {
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

pub fn string_of_mac(buf: &[u8; 6]) -> String {
    buf.iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":")
}

pub fn tcp_flags_to_strings(flags: i32) -> String {
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

pub fn int_of_op_result(input: &OpResult) -> Result<i32, Error>  {
    match *input {
        OpResult::Int(i) => Ok(i),
        _                     => Err(Error::new(
                                    ErrorKind::InvalidInput, 
                                    "Trying to extract int from non-int result"
                                ))
    } 
}

pub fn float_of_op_result(input: &OpResult) -> Result<f64, Error> {
    match *input {
        OpResult::Float(f) => Ok(f),
        _                       => Err(Error::new(
                                ErrorKind::InvalidInput, 
                                "Trying to extract float from non-float result"
        ))
    }
}

pub fn string_of_op_result(input: &OpResult) -> String {
    match *input {
        OpResult::Float(f)     => f.to_string(),
        OpResult::Int(i)       => i.to_string(),
        OpResult::IPv4(a) => a.to_string(),
        OpResult::MAC(m)   => string_of_mac(&m),
        OpResult::Empty             => String::from("Empty")
    }
}

pub fn string_of_headers(input_headers: &Headers) -> String {
    input_headers
        .iter()
        .fold(String::new(), 
        |mut acc, (key, val)| {
            acc
                .push_str(format!("\"{}\" => {}, ", 
                                            key, 
                                            string_of_op_result(val))
                .as_str()); 
            acc 
        })
}

pub fn headers_of_list(header_list: &[(String, OpResult)]) -> Headers {
    let mut hmap: HashMap<String, OpResult> = HashMap::new();
    for (key, val) in header_list {
        hmap.insert(key.clone(), val.clone());
    }
    hmap
}

pub fn dump_headers<'a>(outc: &'a mut Box<dyn Write>, headers: &Headers) -> Result<&'a Box<dyn Write>, Error> {
    writeln!(outc, "{}", string_of_headers(headers));
    Ok(outc)
}

pub fn lookup_int(key: &String, headers: &Headers) -> Result<i32, Error> {
    match headers.get(key) {
        Some(i) => int_of_op_result(i),
        None => Err(Error::new(ErrorKind::InvalidData, 
                        "key given as argument is not a valid key of the given hashmap"))
    }
}

pub fn lookup_float(key: &String, headers: &Headers) -> Result<f64, Error> {
    match headers.get(key) {
        Some(f) => float_of_op_result(f),
        None => Err(Error::new(ErrorKind::InvalidData, 
                        "key given as argument is not a valid key of the given hashmap"))
    }
}
