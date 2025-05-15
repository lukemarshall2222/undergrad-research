#![allow(dead_code)]

use ordered_float::OrderedFloat;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fmt;
use std::io::Write;
use std::io::{Error, ErrorKind};
use std::net::Ipv4Addr;
use std::rc::Rc;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum OpResult {
    Float(OrderedFloat<f64>),
    Int(i32),
    IPv4(Ipv4Addr),
    MAC([u8; 6]),
    Empty,
}

impl fmt::Display for OpResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", string_of_op_result(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Headers {
    pub headers: BTreeMap<String, OpResult>,
}
pub struct Operator {
    pub next: Box<dyn FnMut(&mut Headers) -> () + 'static>,
    pub reset: Box<dyn FnMut(&mut Headers) -> () + 'static>,
}

pub type OperatorRef = Rc<RefCell<Operator>>;

impl<'a> Operator {
    pub fn new(
        next: Box<dyn FnMut(&mut Headers) + 'static>,
        reset: Box<dyn FnMut(&mut Headers) + 'static>,
    ) -> Operator {
        Operator { next, reset }
    }
}

impl Headers {
    pub fn new() -> Self {
        Headers {
            headers: BTreeMap::new(),
        }
    }

    pub fn with_map(map: BTreeMap<String, OpResult>) -> Self {
        Self { headers: map }
    }

    pub fn get(&self, key: &str) -> Option<&OpResult> {
        self.headers.get(key)
    }

    pub fn insert(&mut self, key: String, val: OpResult) -> Option<OpResult> {
        self.headers.insert(key, val)
    }

    pub fn remove(&mut self, key: String) {
        self.headers.remove(&key);
    }

    pub fn items(&self) -> impl Iterator<Item = (&String, &OpResult)> {
        self.headers.iter()
    }

    pub fn items_mut(&mut self) -> impl Iterator<Item = (&String, &mut OpResult)> {
        self.headers.iter_mut()
    }

    pub fn union(&self, other: &Headers) -> Headers {
        let mut unioned_headers: BTreeMap<String, OpResult> = other.headers.clone();
        unioned_headers.extend(self.headers.iter().map(|(k, v)| (k.clone(), v.clone())));
        Headers {
            headers: unioned_headers,
        }
    }

    pub fn get_mapped_int(&self, key: String) -> i32 {
        int_of_op_result(self.headers.get(&key).unwrap_or(&OpResult::Empty)).unwrap()
    }

    pub fn get_mapped_float(&self, key: String) -> OrderedFloat<f64> {
        float_of_op_result(self.headers.get(&key).unwrap_or(&OpResult::Empty)).unwrap()
    }

    pub fn to_string(&self) -> String {
        self.headers
            .iter()
            .fold(String::new(), |mut acc, (key, val)| {
                acc.push_str(format!("\"{}\" => {}, ", key, string_of_op_result(val)).as_str());
                acc
            })
    }

    pub fn headers_of_list(&mut self, header_list: &[(String, OpResult)]) -> &mut Self {
        let mut hmap: BTreeMap<String, OpResult> = BTreeMap::new();
        for (key, val) in header_list {
            hmap.insert(key.clone(), val.clone());
        }
        self.headers = hmap;
        self
    }

    pub fn lookup_int(&self, key: &String) -> Result<i32, Error> {
        match self.headers.get(key) {
            Some(i) => int_of_op_result(i),
            None => Err(Error::new(
                ErrorKind::InvalidData,
                "key given as argument is not a valid key of the given BTreeMap",
            )),
        }
    }

    pub fn lookup_float(&self, key: &String) -> Result<OrderedFloat<f64>, Error> {
        match self.headers.get(key) {
            Some(f) => float_of_op_result(f),
            None => Err(Error::new(
                ErrorKind::InvalidData,
                "key given as argument is not a valid key of the given BTreeMap",
            )),
        }
    }
}

impl fmt::Display for Headers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (key, value) in &self.headers {
            write!(f, r#""{}" => {}, "#, key, string_of_op_result(value))?;
        }
        Ok(())
    }
}

pub fn string_of_mac(buf: &[u8; 6]) -> String {
    buf.iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":")
}

pub fn tcp_flags_to_strings(flags: i32) -> String {
    let mut hmap: BTreeMap<&str, i32> = BTreeMap::new();
    hmap.extend([
        ("FIN", 1 << 0),
        ("SYN", 1 << 1),
        ("RST", 1 << 2),
        ("PSH", 1 << 3),
        ("ACK", 1 << 4),
        ("URG", 1 << 5),
        ("ECE", 1 << 6),
        ("CWR", 1 << 7),
    ]);
    hmap.iter()
        .filter(|(_, val)| (flags & **val) == **val)
        .fold(String::new(), |mut acc, (key, _)| {
            if !acc.is_empty() {
                acc.push('|');
            }
            acc.push_str(key);
            acc
        })
}

pub fn int_of_op_result(input: &OpResult) -> Result<i32, Error> {
    match *input {
        OpResult::Int(i) => Ok(i),
        _ => Err(Error::new(
            ErrorKind::InvalidInput,
            "Trying to extract int from non-int result",
        )),
    }
}

pub fn float_of_op_result(input: &OpResult) -> Result<OrderedFloat<f64>, Error> {
    match *input {
        OpResult::Float(f) => Ok(f),
        _ => Err(Error::new(
            ErrorKind::InvalidInput,
            "Trying to extract float from non-float result",
        )),
    }
}

pub fn string_of_op_result(input: &OpResult) -> String {
    match *input {
        OpResult::Float(f) => f.to_string(),
        OpResult::Int(i) => i.to_string(),
        OpResult::IPv4(a) => a.to_string(),
        OpResult::MAC(m) => string_of_mac(&m),
        OpResult::Empty => String::from("Empty"),
    }
}

pub fn dump_headers<'a, W: Write>(outc: &'a mut W, headers: &Headers) -> Result<&'a W, Error> {
    writeln!(outc, "{}", headers.to_string()).unwrap();
    Ok(outc)
}
