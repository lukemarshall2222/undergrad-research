#![allow(dead_code)]

use ordered_float::OrderedFloat;

use crate::utils::{
    Headers, OpResult, Operator, dump_headers, float_of_op_result, int_of_op_result,
    string_of_op_result,
};
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io::{Error, ErrorKind, Write, stdout};
use std::net::Ipv4Addr;
use std::rc::Rc;
use std::str::FromStr;

pub fn create_dump_operator<'a>(show_reset: bool, outc: Box<dyn Write>) -> Operator<'a> {
    let outc = Rc::new(RefCell::new(outc));

    let next_outc = Rc::clone(&outc);
    let next: Box<dyn FnMut(&mut Headers) -> () + 'a> = Box::new(move |headers: &mut Headers| {
        dump_headers(&mut *next_outc.borrow_mut(), headers).unwrap();
    });

    let reset_outc = Rc::clone(&outc);
    let reset: Box<dyn FnMut(&mut Headers) -> () + 'a> = Box::new(move |headers: &mut Headers| {
        if show_reset {
            dump_headers(&mut *reset_outc.borrow_mut(), headers).unwrap();
            writeln!(&mut reset_outc.borrow_mut(), "[rest]\n").unwrap();
        } else {
            ()
        }
    });
    Operator::new(next, reset)
}

pub fn dump_as_csv<'a>(
    static_field: Option<(String, String)>,
    header: Option<bool>,
    outc: Box<dyn Write>,
) -> Operator<'a> {
    let outc = Rc::new(RefCell::new(outc));
    let mut first: bool = header.unwrap_or(true);

    let next: Box<dyn FnMut(&mut Headers) -> () + 'a> = Box::new(move |headers: &mut Headers| {
        if first {
            match &static_field {
                Some((key, _)) => {
                    writeln!(outc.borrow_mut(), "{}", key).unwrap();
                }
                None => (),
            }
            first = false;
        }

        for (key, _) in headers.iter_mut() {
            writeln!(outc.borrow_mut(), "{}, ", key).unwrap();
        }
        writeln!(outc.borrow_mut(), "\n").unwrap();

        match &static_field {
            Some((_, val)) => {
                writeln!(outc.borrow_mut(), "{}", val).unwrap();
            }
            None => (),
        }

        for (_, val) in headers.iter_mut() {
            writeln!(outc.borrow_mut(), "{}, ", val).unwrap();
        }
        writeln!(outc.borrow_mut(), "\n").unwrap();
    });

    let reset: Box<dyn FnMut(&mut Headers) -> () + 'a> = Box::new(move |_headers: &mut Headers| ());

    Operator::new(next, reset)
}

pub fn dump_walts_csv<'a>(filename: String) -> Operator<'a> {
    let mut outc: Box<dyn Write> = Box::new(stdout());
    let mut first: bool = true;

    let next: Box<dyn FnMut(&mut Headers) -> () + 'a> = Box::new(move |headers: &mut Headers| {
        if first {
            outc = Box::new(File::open(&filename).unwrap());
            first = false;
        }
        writeln!(
            outc,
            "{}, {}, {}, {}, {}, {}, {}\n",
            string_of_op_result(headers.get("src_ip").unwrap_or(&OpResult::Empty)),
            string_of_op_result(headers.get("dst_ip").unwrap_or(&OpResult::Empty)),
            string_of_op_result(headers.get("src_l4_port").unwrap_or(&OpResult::Empty)),
            string_of_op_result(headers.get("dst_l4_port").unwrap_or(&OpResult::Empty)),
            string_of_op_result(headers.get("packet_count").unwrap_or(&OpResult::Empty)),
            string_of_op_result(headers.get("byte_count").unwrap_or(&OpResult::Empty)),
            string_of_op_result(headers.get("epoch_id").unwrap_or(&OpResult::Empty)),
        )
        .unwrap();
    });

    let reset: Box<dyn FnMut(&mut Headers) -> () + 'a> = Box::new(move |_headers: &mut Headers| ());

    Operator::new(next, reset)
}

pub fn get_ip_or_zero(input: String) -> OpResult {
    match input {
        z if z == "0" => OpResult::Int(0),
        catchall => OpResult::IPv4(Ipv4Addr::from_str(&catchall).unwrap()),
    }
}

pub fn create_meta_meter<'a>(
    static_field: Option<String>,
    name: String,
    mut outc: Box<dyn Write>,
    mut next_op: Operator<'a>,
) -> Operator<'a> {
    let mut epoch_count: i32 = 0;
    let mut _headers_count: i32 = 0;

    let next: Box<dyn FnMut(&mut Headers) + 'a> = Box::new(move |headers: &mut Headers| {
        _headers_count += 1;
        (next_op.next)(headers)
    });

    let reset: Box<dyn FnMut(&mut Headers) + 'a> = Box::new(move |headers: &mut Headers| {
        writeln!(
            outc,
            "{}, {}, {}, {}\n",
            epoch_count,
            name,
            _headers_count,
            match &static_field {
                Some(v) => v,
                None => "",
            }
        )
        .unwrap();
        _headers_count = 0;
        epoch_count += 1;
        (next_op.reset)(headers)
    });

    Operator::new(next, reset)
}

pub fn create_epoch_operator<'a>(
    epoch_width: f64,
    key_out: String,
    mut next_op: Operator<'a>,
) -> Operator<'a> {
    let mut _next_op_reset_ref = Rc::new(RefCell::new(next_op.reset));
    let mut _epoch_boundary: f64 = 0.0;
    let mut eid: i32 = 0;
    let key_out_cp: String = (*key_out.clone()).to_string();

    let first_reset: Rc<RefCell<Box<dyn FnMut(&mut Headers) + 'a>>> =
        Rc::clone(&_next_op_reset_ref);
    let next: Box<dyn FnMut(&mut Headers) + 'a> = Box::new(move |headers: &mut Headers| {
        let time: f64 = float_of_op_result(&headers.get("time").unwrap_or(&OpResult::Empty))
            .unwrap()
            .0;
        if _epoch_boundary == 0.0 {
            _epoch_boundary = time + epoch_width;
        }
        while time >= _epoch_boundary {
            let mut new_headers: Headers = headers.clone();
            new_headers
                .insert(key_out.clone(), OpResult::Int(eid))
                .unwrap();
            (first_reset.borrow_mut())(&mut new_headers);
            _epoch_boundary += epoch_width;
            eid += 1;
        }
        let mut new_headers: Headers = headers.clone();
        new_headers
            .insert(key_out.clone(), OpResult::Int(eid))
            .unwrap();
        (next_op.next)(headers)
    });

    let reset: Box<dyn FnMut(&mut Headers) + 'a> = Box::new(move |_headers: &mut Headers| {
        let mut new_hmap: BTreeMap<String, OpResult> = BTreeMap::new();
        new_hmap.insert(key_out_cp.clone(), OpResult::Int(eid));
        (_next_op_reset_ref.borrow_mut())(&mut new_hmap);
        _epoch_boundary = 0.0;
        eid = 0;
    });

    Operator::new(next, reset)
}

pub type FilterFunc = Box<dyn Fn(&Headers) -> bool>;

pub fn create_filter_operator<'a>(
    f: FilterFunc,
    mut next_op: Operator<'a>,
) -> Operator<'a> {
    let next: Box<dyn FnMut(&mut Headers) + 'a> = Box::new(move |headers: &mut Headers| {
        if (f)(headers) {
            (next_op.next)(headers)
        }
    });

    let reset: Box<dyn FnMut(&mut Headers) + 'a> =
        Box::new(move |headers: &mut Headers| (next_op.reset)(headers));

    Operator::new(next, reset)
}

pub fn key_geq_int(key: String, threshold: i32, headers: &Headers) -> bool {
    int_of_op_result(headers.get(&key).unwrap_or(&OpResult::Empty)).unwrap() >= threashold
}

pub fn get_mapped_int(key: String, headers: &Headers) -> i32 {
    int_of_op_result(headers.get(&key).unwrap_or(&OpResult::Empty)).unwrap()
}

pub fn get_mapped_float(key: String, headers: &Headers) -> OrderedFloat<f64> {
    float_of_op_result(headers.get(&key).unwrap_or(&OpResult::Empty)).unwrap()
}

pub fn create_map_operator<'a>(
    f: Box<dyn Fn(&mut Headers) -> &mut Headers + 'a>,
    mut next_op: Operator<'a>,
) -> Operator<'a> {
    let f = Rc::new(RefCell::new(f));

    let mapping_func_ref1: Rc<RefCell<Box<dyn Fn(&mut Headers) -> &mut Headers + 'a>>> =
        Rc::clone(&f);
    let mapping_func_ref2: Rc<RefCell<Box<dyn Fn(&mut Headers) -> &mut Headers + 'a>>> =
        Rc::clone(&f);

    let next: Box<dyn FnMut(&mut Headers) + 'a> = Box::new(move |headers: &mut Headers| {
        (next_op.next)((mapping_func_ref1.borrow_mut())(headers))
    });

    let reset: Box<dyn FnMut(&mut Headers) + 'a> = Box::new(move |headers: &mut Headers| {
        (next_op.reset)((mapping_func_ref2.borrow_mut())(headers))
    });

    Operator::new(next, reset)
}

pub type GroupingFunc = Box<dyn Fn(Headers) -> Headers>;
pub type ReductionFunc = Box<dyn Fn(OpResult, &mut Headers) -> OpResult>;

pub fn union_headers(headers1: &mut Headers, headers2: &mut Headers) -> Headers {
    let mut new_headers: Headers = BTreeMap::new();

    for (key, val) in headers1.iter_mut() {
        new_headers.insert(key.clone(), val.clone());
    }

    for (key, val) in headers2.iter_mut() {
        new_headers.insert(key.clone(), val.clone());
    }

    new_headers
}

pub fn create_groupby_operator<'a>(
    groupby: GroupingFunc,
    reduce: ReductionFunc,
    out_key: String,
    mut next_op: Operator<'a>,
) -> Operator<'a> {
    let mut _h_tbl: Box<HashMap<Headers, OpResult>> = Box::new(HashMap::new());
    let h_tbl_ref = Rc::new(RefCell::new(_h_tbl));

    let next_htbl_ref: Rc<RefCell<Box<HashMap<Headers, OpResult>>>> = Rc::clone(&h_tbl_ref);
    let reset_htbl_ref: Rc<RefCell<Box<HashMap<Headers, OpResult>>>> = Rc::clone(&h_tbl_ref);

    let mut _reset_counter: i32 = 0;

    let next: Box<dyn FnMut(&mut Headers) + 'a> = Box::new(move |headers: &mut Headers| {
        let grouping_key: Headers = groupby(headers.clone());
        next_htbl_ref
            .borrow_mut()
            .entry(grouping_key)
            .and_modify(|val: &mut OpResult| *val = reduce(val.clone(), headers))
            .or_insert_with(|| reduce(OpResult::Empty, headers));
    });

    let reset: Box<dyn FnMut(&mut Headers) + 'a> = Box::new(move |headers: &mut Headers| {
        _reset_counter += 1;
        for (grouping_key, val) in reset_htbl_ref.borrow_mut().iter_mut() {
            let mut unioned_headers: Headers = union_headers(headers, &mut grouping_key.clone());
            unioned_headers.insert(out_key.clone(), val.clone());
            (next_op.next)(&mut unioned_headers)
        }
        (next_op.reset)(headers);
        reset_htbl_ref.borrow_mut().clear();
    });

    Operator::new(next, reset)
}

pub fn filter_groups(incl_keys: Vec<String>, headers: &mut Headers) -> Headers {
    let mut new_headers: Headers = BTreeMap::new();
    for (key, val) in headers.iter_mut() {
        if incl_keys.contains(key) {
            new_headers.insert(key.clone(), val.clone());
        }
    }
    new_headers
}

pub fn single_group(_headers: Headers) -> Headers {
    BTreeMap::new()
}

pub fn counter(val: OpResult, _headers: &mut Headers) -> OpResult {
    match val {
        OpResult::Empty => OpResult::Int(1),
        OpResult::Int(i) => OpResult::Int(i + 1),
        _ => val,
    }
}

pub fn sum_ints(
    search_key: String,
    init_val: OpResult,
    headers: &mut Headers,
) -> Result<OpResult, Error> {
    match init_val {
        OpResult::Empty => Ok(OpResult::Int(1)),
        OpResult::Int(i) => match headers.get_mut(&search_key) {
            Some(OpResult::Int(n)) => Ok(OpResult::Int(*n + i)),
            _ => Err(Error::new(
                ErrorKind::InvalidInput,
                "'sum_vals' function failed to find integer 
                        value mapped to the incorrect type",
            )),
        },
        _ => Ok(init_val),
    }
}

pub fn create_distinct_operator<'a>(groupby: GroupingFunc, mut next_op: Operator<'a>) -> Operator<'a> {
    let mut _h_tbl: Box<HashMap<Headers, bool>> = Box::new(HashMap::new());
    let h_tbl_ref = Rc::new(RefCell::new(_h_tbl));

    let next_htbl_ref: Rc<RefCell<Box<HashMap<Headers, bool>>>> = Rc::clone(&h_tbl_ref);
    let reset_htbl_ref: Rc<RefCell<Box<HashMap<Headers, bool>>>> = Rc::clone(&h_tbl_ref);

    let mut _reset_counter: i32 = 0;

    let next: Box<dyn FnMut(&mut Headers) + 'a> = Box::new(move |headers: &mut Headers| {
        let mut _grouping_key: BTreeMap<String, OpResult> = groupby(headers.clone());
        next_htbl_ref.borrow_mut().insert(_grouping_key, true);
    });

    let reset: Box<dyn FnMut(&mut Headers) + 'a> = Box::new(move |headers: &mut Headers| {
        _reset_counter += 1;
        for (key, _) in reset_htbl_ref.borrow_mut().iter_mut() {
            let mut unioned_headers: Headers = union_headers(headers, &mut key.clone());
            (next_op.next)(&mut unioned_headers);
        }
        (next_op.reset)(headers);
        reset_htbl_ref.borrow_mut().clear();
    });

    Operator::new(next, reset)
}

pub fn create_split_operator<'a>(l: Operator<'a>, r: Operator<'a>) -> Operator<'a> {
    let l: Rc<RefCell<Box<Operator>>> = Rc::new(RefCell::new(Box::new(l)));
    let next_l: Rc<RefCell<Box<Operator>>> = l.clone();
    let reset_l: Rc<RefCell<Box<Operator>>> = l.clone();

    let r: Rc<RefCell<Box<Operator>>> = Rc::new(RefCell::new(Box::new(r)));
    let next_r: Rc<RefCell<Box<Operator>>> = r.clone();
    let reset_r: Rc<RefCell<Box<Operator>>> = r.clone();

    let next: Box<dyn FnMut(&mut Headers) + 'a> = Box::new(move |headers: &mut Headers| {
        (next_l.borrow_mut().next)(headers);
        (next_r.borrow_mut().next)(headers);
    });

    let reset: Box<dyn FnMut(&mut Headers) + 'a> = Box::new(move |headers: &mut Headers| {
        (reset_l.borrow_mut().reset)(headers);
        (reset_r.borrow_mut().reset)(headers);
    });

    Operator::new(next, reset)
}

pub type KeyExtractor = Box<dyn Fn(&mut Headers) -> (&mut Headers, &mut Headers)>;

pub fn singleton(key: String, val: OpResult) -> Headers {
    BTreeMap::from([(key, val)])
}

pub fn handle_join_side<'a>(
    mut _curr_h_tbl: Rc<RefCell<HashMap<Headers, Headers>>>,
    mut _other_hash_tbl: Rc<RefCell<HashMap<Headers, Headers>>>,
    curr_epoch_ref: Rc<RefCell<i32>>,
    other_epoch_ref: Rc<RefCell<i32>>,
    f: KeyExtractor,
    mut _first_reset_func_ref: Rc<RefCell<Box<dyn FnMut(&mut Headers) + 'a>>>,
    mut _second_reset_func_ref: Rc<RefCell<Box<dyn FnMut(&mut Headers) + 'a>>>,
    mut _next_func_ref: Rc<RefCell<Box<dyn FnMut(&mut Headers) + 'a>>>,
    mut _eid_key1: Rc<RefCell<String>>,
    mut _eid_key2: Rc<RefCell<String>>,
) -> Operator<'a> {
    let eid_key1 = Rc::clone(&_eid_key1);
    let eid_key2 = Rc::clone(&_eid_key2);
    let first_reset_func_ref = Rc::clone(&_first_reset_func_ref);
    let second_reset_func_ref = Rc::clone(&_second_reset_func_ref);
    let next_func_ref = Rc::clone(&_next_func_ref);
    let curr_epoch_ref_cloned_for_reset = Rc::clone(&curr_epoch_ref);
    let other_epoch_ref_cloned_for_next = Rc::clone(&other_epoch_ref);
    let other_epoch_ref_cloned_for_reset = Rc::clone(&other_epoch_ref);


    let next: Box<dyn FnMut(&mut Headers) + 'a> = Box::new(move |headers: &mut Headers| {
        let mut _headers_cp = &mut headers.clone();
        let (key, vals) = f(_headers_cp);
        let mut _curr_epoch: i32 = get_mapped_int(eid_key1.borrow_mut().clone(), headers);

        while _curr_epoch > *curr_epoch_ref.borrow() {
            if *other_epoch_ref_cloned_for_next.borrow() > *curr_epoch_ref.borrow() {
                (first_reset_func_ref.borrow_mut())(&mut singleton(
                    eid_key1.borrow().clone(),
                    OpResult::Int(*curr_epoch_ref.borrow()),
                ));
            }
            let mut count = curr_epoch_ref.borrow_mut();
            *count += 1;
        }

        let mut new_headers: Headers = key.clone();
        new_headers.insert(eid_key1.borrow().clone(), OpResult::Int(_curr_epoch));
        match _other_hash_tbl
            .borrow_mut()
            .iter_mut()
            .find(|(key, _)| **key == new_headers)
        {
            Some((_, val)) => {
                (next_func_ref.borrow_mut())(
                    &mut (union_headers(&mut union_headers(&mut new_headers, vals), val)),
                )
            }
            None => {
                _curr_h_tbl
                    .borrow_mut()
                    .insert(new_headers, vals.clone())
                    .unwrap();
            }
        }
    });

    let reset: Box<dyn FnMut(&mut Headers) + 'a> = Box::new(move |headers: &mut Headers| {
        let mut _curr_epoch: i32 = get_mapped_int(eid_key2.borrow().clone(), headers);
        while _curr_epoch > curr_epoch_ref_cloned_for_reset.borrow().clone() {
            if *other_epoch_ref_cloned_for_reset.borrow() > *curr_epoch_ref_cloned_for_reset.borrow() {
                (second_reset_func_ref.borrow_mut())(&mut singleton(
                    eid_key2.borrow().clone(),
                    OpResult::Int(*curr_epoch_ref_cloned_for_reset.borrow()),
                ));
            }
            let mut count = curr_epoch_ref_cloned_for_reset.borrow_mut();
            *count += 1;
        }
    });
    Operator::new(next, reset)
}

pub fn create_join_operator<'a>(
    eid_key: Option<String>,
    left_extractor: KeyExtractor,
    right_extractor: KeyExtractor,
    mut _next_op: Operator<'a>,
) -> (Operator<'a>, Operator<'a>) {
    let mut _h_tbl1: Rc<RefCell<HashMap<Headers, Headers>>> = Rc::new(RefCell::new(HashMap::new()));
    let h_tbl1_ref_1 = Rc::clone(&_h_tbl1);
    let h_tbl1_ref_2 = Rc::clone(&_h_tbl1);

    let mut _h_tbl2: Rc<RefCell<HashMap<Headers, Headers>>> = Rc::new(RefCell::new(HashMap::new()));
    let h_tbl2_ref_1 = Rc::clone(&_h_tbl2);
    let h_tbl2_ref_2 = Rc::clone(&_h_tbl2);

    let mut _left_curr_epoch: Rc<RefCell<i32>> = Rc::new(RefCell::new(0));
    let mut _right_curr_epoch:  Rc<RefCell<i32>> = Rc::new(RefCell::new(0));

    let reset_ref: Rc<RefCell<Box<dyn FnMut(&mut Headers) + 'a>>> =
        Rc::new(RefCell::new(_next_op.reset));
    let next_ref: Rc<RefCell<Box<dyn FnMut(&mut Headers) + 'a>>> =
        Rc::new(RefCell::new(_next_op.next));

    let reset_ref1: Rc<RefCell<Box<dyn FnMut(&mut Headers) + 'a>>> = Rc::clone(&reset_ref);
    let reset_ref2: Rc<RefCell<Box<dyn FnMut(&mut Headers) + 'a>>> = Rc::clone(&reset_ref);
    let next_ref1: Rc<RefCell<Box<dyn FnMut(&mut Headers) + 'a>>> = Rc::clone(&next_ref);

    let mut _eid_key: Rc<RefCell<String>> = Rc::new(RefCell::new(
        eid_key.clone().unwrap_or_else(|| "eid".to_string()),
    ));
    let eid_key1: Rc<RefCell<String>> = Rc::clone(&_eid_key);
    let eid_key2: Rc<RefCell<String>> = Rc::clone(&_eid_key);
    (
        handle_join_side(
            h_tbl1_ref_1,
            h_tbl2_ref_1,
            Rc::clone(&_left_curr_epoch),
            Rc::clone(&_right_curr_epoch),
            left_extractor,
            Rc::clone(&reset_ref1),
            Rc::clone(&reset_ref2),
            Rc::clone(&next_ref1),
            Rc::clone(&eid_key1),
            Rc::clone(&eid_key2)
        ),
        handle_join_side(
            h_tbl2_ref_2,
            h_tbl1_ref_2,
            Rc::clone(&_right_curr_epoch),
            Rc::clone(&_left_curr_epoch),
            right_extractor,
            Rc::clone(&reset_ref1),
            Rc::clone(&reset_ref2),
            Rc::clone(&next_ref1),
            Rc::clone(&eid_key1),
            Rc::clone(&eid_key2)
        )
    )
}

fn rename_filtered_keys(renaming_pairs: Vec<(String, String)>, headers: &mut Headers) -> Headers {
    let mut new_headers: BTreeMap<String, OpResult> = BTreeMap::new();
    for (new_key, old_key) in renaming_pairs {
        if let Some(val) = headers.get(&old_key) {
            new_headers.insert(new_key, val.clone()).unwrap();
        }
    }
    new_headers
}
