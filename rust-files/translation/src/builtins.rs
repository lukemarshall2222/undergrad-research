use crate::utils::{Headers, OpResult, Operator, dump_headers, float_of_op_result};
use std::cell::RefCell;
use std::collections::HashMap;
use std::io::Write;
use std::io::{Error, ErrorKind};
use std::net::Ipv4Addr;
use std::rc::Rc;
use std::str::FromStr;

fn create_dump_operator<'a>(show_reset: bool, outc: Box<dyn Write + 'static>) -> Operator<'a> {
    let outc = Rc::new(RefCell::new(outc));

    let next_outc = Rc::clone(&outc);
    let next: Box<dyn FnMut(&Headers) + 'a> = Box::new(move |headers: &Headers| {
        let _ = dump_headers(&mut *next_outc.borrow_mut(), headers);
    });

    let reset_outc = Rc::clone(&outc);
    let reset: Box<dyn FnMut(&Headers) + 'a> = Box::new(move |headers: &Headers| {
        if show_reset {
            dump_headers(&mut *reset_outc.borrow_mut(), headers);
            writeln!(&mut reset_outc.borrow_mut(), "[rest]\n");
        } else {
            ()
        }
    });
    Operator::new(next, reset)
}

fn dump_as_csv<'a>(
    static_field: Option<(String, String)>,
    header: Option<bool>,
    mut outc: Box<dyn Write + 'a>,
) -> Operator<'a> {
    let outc = Rc::new(RefCell::new(outc));
    let mut first: bool = header.unwrap_or(true);

    let next: Box<dyn FnMut(&Headers) + 'a> = Box::new(move |headers: &Headers| {
        if first {
            match &static_field {
                Some((key, _)) => {
                    writeln!(outc.borrow_mut(), "{}", key);
                }
                None => (),
            }
            first = false;
        }

        for (key, val) in headers {
            writeln!(outc.borrow_mut(), "{}, ", key);
        }
        writeln!(outc.borrow_mut(), "\n");

        match &static_field {
            Some((_, val)) => {
                writeln!(outc.borrow_mut(), "{}", val);
            }
            None => (),
        }

        for (key, val) in headers {
            writeln!(outc.borrow_mut(), "{}, ", val).unwrap();
        }
        writeln!(outc.borrow_mut(), "\n");
    });

    let reset: Box<dyn FnMut(&Headers) + 'a> = Box::new(move |_headers: &Headers| ());

    Operator::new(next, reset)
}

fn get_ip_or_zero(input: String) -> OpResult {
    match input {
        z if z == "0" => OpResult::Int(0),
        catchall => OpResult::IPv4(Ipv4Addr::from_str(&catchall).unwrap()),
    }
}

fn create_meta_meter<'a>(
    static_field: Option<String>,
    name: String,
    outc: Box<dyn Write + 'a>,
    mut next_op: Operator<'a>,
) -> Operator<'a> {
    let outc = Rc::new(RefCell::new(outc));
    let mut epoch_count: i32 = 0;
    let mut tups_count: i32 = 0;

    let next: Box<dyn FnMut(&Headers) + 'a> = Box::new(move |headers: &Headers| {
        tups_count += 1;
        (next_op.next)(headers)
    });

    let reset: Box<dyn FnMut(&Headers) + 'a> = Box::new(move |headers: &Headers| {
        writeln!(
            outc.borrow_mut(),
            "{}, {}, {}, {}\n",
            epoch_count,
            name,
            tups_count,
            match &static_field {
                Some(v) => v.clone(),
                None => format!(""),
            }
        );
        tups_count = 0;
        epoch_count += 1;
        (next_op.reset)(headers)
    });

    Operator::new(next, reset)
}

fn create_epoch_operator<'a>(
    epoch_width: f64,
    key_out: String,
    next_op: Operator<'a>,
) -> Operator<'a> {
    let mut epoch_boundary: f64 = 0.0;
    let mut eid: i32 = 0;
    let new_reset = Rc::new(RefCell::new(next_op.next));
    let key_out2 = key_out.clone();

    let next_reset = new_reset.clone();
    let next: Box<dyn FnMut(&Headers) + 'a> = Box::new(move |headers: &Headers| {
        let time: f64 =
            float_of_op_result(headers.get("time").unwrap_or(&OpResult::Empty)).unwrap();

        if epoch_boundary == 0.0 {
            epoch_boundary = time + epoch_width;
        }

        while time >= epoch_boundary {
            let mut new_map: Headers = HashMap::new();
            new_map.insert(key_out.clone(), OpResult::Int(eid));
            (next_reset.borrow_mut())(&new_map);
            epoch_boundary += epoch_width;
            eid += 1;
        }

        let mut new_map: Headers = HashMap::new();
        new_map.insert(key_out.clone(), OpResult::Int(eid));
        (next_reset.borrow_mut())(&new_map)
    });

    let reset_reset = new_reset.clone();
    let reset: Box<dyn FnMut(&Headers) + 'a> = Box::new(move |_headers: &Headers| {
        let mut new_map: Headers = HashMap::new();
        new_map.insert(key_out2.clone(), OpResult::Int(eid));
        (reset_reset.borrow_mut())(&new_map);
        epoch_boundary = 0.0;
        eid = 0;
    });

    Operator::new(next, reset)
}


