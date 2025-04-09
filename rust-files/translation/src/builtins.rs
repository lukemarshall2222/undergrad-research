
use std::cell::RefCell;
use std::net::Ipv4Addr;
use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::io::Write;
use std::str::FromStr;
use crate::utils::{dump_headers, Headers, OpResult, Operator};
use std::rc::Rc;

fn create_dump_operator<'a, W: Write + 'a>(show_reset: bool, outc: W) -> Operator<'a> {
    let outc = Rc::new(RefCell::new(outc));

    let next_outc = Rc::clone(&outc);
    let next: Box <dyn FnMut(&Headers) -> () + 'a> = Box::new( move |headers: &Headers| {
        dump_headers(&mut *next_outc.borrow_mut(), headers);
    });

    let reset_outc = Rc::clone(&outc);
    let reset: Box<dyn FnMut(&Headers) -> () + 'a> = Box::new(move |headers: &Headers| {
        if show_reset {
            let mut writer = reset_outc.borrow_mut();
            dump_headers(&mut *writer, headers);
            &mut reset_outc
                .borrow_mut()
                .write_all(String::from("[rest]\n")
                                            .as_bytes());
        } else {
            ()
        }
    });
    Operator::new(next, reset)
}

fn dump_as_csv<'a, W: Write + 'a>(static_field: Option<(String, String)>, 
            header: Option<bool>, outc: W) -> Operator<'a> {
    let outc = Rc::new(RefCell::new(outc));
    let mut first: bool = header.unwrap_or(true);

    let next: Box<dyn FnMut(&Headers) -> () + 'a> = Box::new(move |headers: &Headers| {
        if first {
            match &static_field {
                Some((key, _)) => { 
                    outc
                        .borrow_mut()
                        .write_all(String::from(format!("{}", key))
                                                        .as_bytes()); },
                None                   => { () },
            }
            first = false;
        }

        headers
            .iter()
            .map(|(key, _)| outc
                                        .borrow_mut()
                                        .write_all(String::from(format!("{}, ", key))
                                                                        .as_bytes()));
        outc
            .borrow_mut()
            .write_all(String::from(format!("\n"))
                                            .as_bytes());

        match &static_field {
            Some((_, val)) => { 
                outc
                    .borrow_mut()
                    .write_all(String::from(format!("{}", val))
                                                    .as_bytes()); },
            None                   => { () }
        }

        headers
            .iter()
            .map(|(_, val)| outc
                                        .borrow_mut()
                                        .write_all(String::from(format!("{}, ", val))
                                                                        .as_bytes()));
        outc
            .borrow_mut()
            .write_all(String::from(format!("\n"))
                                            .as_bytes());
    });

    let reset: Box<dyn FnMut(&Headers) -> () + 'a> = Box::new(move |_headers: &Headers| { () });

    Operator::new(next, reset)
}

fn get_ip_or_zero(input: String) -> OpResult {
    match input {
        z if z == "0" => OpResult::Int(0),
        catchall => OpResult::IPv4(Ipv4Addr::from_str(&catchall).unwrap())
    }
}

