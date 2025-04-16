#![allow(dead_code)]
use std::{cell::RefCell, rc::Rc};

use builtins::{
    FilterFunc, GroupingFunc, counter, create_distinct_operator,
    create_epoch_operator, create_filter_operator, create_groupby_operator, create_join_operator,
    create_map_operator, filter_groups, get_mapped_int, key_geq_int, rename_filtered_keys,
    single_group,
};
use utils::{Headers, Operator};

mod builtins;
mod utils;

fn ident(next_op: Operator) -> Operator {
    create_map_operator(
        Box::new(|headers: Headers| {
            let mut headers = headers.clone();
            headers.remove("eth.src");
            headers.remove("eth.dst");
            headers
        }),
        next_op,
    )
}

fn count_pkts(next_op: Operator) -> Operator {
    let incl_keys = Vec::from(["ipv4.src".to_string(), "ipv4.dst".to_string()]);
    let groupby_func: GroupingFunc =
        Box::new(move |headers: Headers| filter_groups(incl_keys.clone(), &mut headers.clone()));
    create_epoch_operator(
        1.0,
        "eid".to_string(),
        create_groupby_operator(groupby_func, Box::new(counter), "pkts".to_string(), next_op),
    )
}

fn pkts_per_source_dst(next_op: Operator) -> Operator {
    let incl_keys = Vec::from(["ipv4.src".to_string(), "ipv4.dst".to_string()]);
    let groupby_func: GroupingFunc =
        Box::new(move |headers: Headers| filter_groups(incl_keys.clone(), &mut headers.clone()));
    create_epoch_operator(
        1.0,
        "eid".to_string(),
        create_groupby_operator(groupby_func, Box::new(counter), "pkts".to_string(), next_op),
    )
}

fn distinct_srcs(next_op: Operator) -> Operator {
    let incl_keys = Vec::from(["ipv4.src".to_string()]);
    let groupby_func: GroupingFunc =
        Box::new(move |headers: Headers| filter_groups(incl_keys.clone(), &mut headers.clone()));
    create_epoch_operator(
        1.0,
        "eid".to_string(),
        create_distinct_operator(
            groupby_func,
            create_groupby_operator(
                Box::new(single_group),
                Box::new(counter),
                "srcs".to_string(),
                next_op,
            ),
        ),
    )
}

fn tcp_new_cons<'a>(next_op: Operator<'a>) -> Operator<'a> {
    let threshold: i32 = 40;
    let incl_keys: Vec<String> = Vec::from(["ipv4.dst".to_string()]);
    let filter_func: FilterFunc = Box::new(move |headers: &Headers| {
        get_mapped_int("ipv4.proto".to_string(), &headers) == 6
            && get_mapped_int("l4.flags".to_string(), &headers) == 2
    });
    let groupby_func: GroupingFunc =
        Box::new(move |headers: Headers| filter_groups(incl_keys.clone(), &mut headers.clone()));
    let filter_func2: FilterFunc =
        Box::new(move |headers: &Headers| key_geq_int("cons".to_string(), threshold, headers));
    create_epoch_operator(
        1.0,
        "eid".to_string(),
        create_filter_operator(
            filter_func,
            create_groupby_operator(
                groupby_func,
                Box::new(counter),
                "cons".to_string(),
                create_filter_operator(filter_func2, next_op),
            ),
        ),
    )
}

fn ssh_brute_force(next_op: Operator) -> Operator {
    let threshold: i32 = 40;
    let incl_keys: Vec<String> = Vec::from([
        "ipv4.src".to_string(),
        "ipv4.dst".to_string(),
        "ipv4.len".to_string(),
    ]);
    let incl_keys2: Vec<String> = Vec::from(["ipv4.dst".to_string(), "ipv4.len".to_string()]);
    let filter_func: FilterFunc = Box::new(move |headers: &Headers| {
        get_mapped_int("ipv4.proto".to_string(), &headers) == 6
            && get_mapped_int("l4.dport".to_string(), &headers) == 22
    });
    let groupby_func: GroupingFunc =
        Box::new(move |headers: Headers| filter_groups(incl_keys.clone(), &mut headers.clone()));
    let groupby_func2: GroupingFunc =
        Box::new(move |headers: Headers| filter_groups(incl_keys2.clone(), &mut headers.clone()));
    let filter_func2: FilterFunc =
        Box::new(move |headers: &Headers| key_geq_int("srcs".to_string(), threshold, headers));
    create_epoch_operator(
        1.0,
        "eid".to_string(),
        create_filter_operator(
            filter_func,
            create_distinct_operator(
                groupby_func,
                create_groupby_operator(
                    groupby_func2,
                    Box::new(counter),
                    "srcs".to_string(),
                    create_filter_operator(filter_func2, next_op),
                ),
            ),
        ),
    )
}

fn super_spreader(next_op: Operator) -> Operator {
    let threshold: i32 = 40;
    let incl_keys: Vec<String> = Vec::from(["ipv4.src".to_string(), "ipv4.dst".to_string()]);
    let incl_keys2: Vec<String> = Vec::from(["ipv4.src".to_string()]);
    let groupby_func: GroupingFunc =
        Box::new(move |headers: Headers| filter_groups(incl_keys.clone(), &mut headers.clone()));
    let groupby_func2: GroupingFunc =
        Box::new(move |headers: Headers| filter_groups(incl_keys2.clone(), &mut headers.clone()));
    let filter_func: FilterFunc =
        Box::new(move |headers: &Headers| key_geq_int("dsts".to_string(), threshold, headers));
    create_epoch_operator(
        1.0,
        "eid".to_string(),
        create_distinct_operator(
            groupby_func,
            create_groupby_operator(
                groupby_func2,
                Box::new(counter),
                "dsts".to_string(),
                create_filter_operator(filter_func, next_op),
            ),
        ),
    )
}

fn port_scan(next_op: Operator) -> Operator {
    let threshold: i32 = 40;
    let incl_keys: Vec<String> = Vec::from(["ipv4.src".to_string(), "l4.dport".to_string()]);
    let incl_keys2: Vec<String> = Vec::from(["ipv4.src".to_string()]);
    let groupby_func: GroupingFunc =
        Box::new(move |headers: Headers| filter_groups(incl_keys.clone(), &mut headers.clone()));
    let groupby_func2: GroupingFunc =
        Box::new(move |headers: Headers| filter_groups(incl_keys2.clone(), &mut headers.clone()));
    let filter_func: FilterFunc =
        Box::new(move |headers: &Headers| key_geq_int("ports".to_string(), threshold, headers));
    create_epoch_operator(
        1.0,
        "eid".to_string(),
        create_distinct_operator(
            groupby_func,
            create_groupby_operator(
                groupby_func2,
                Box::new(counter),
                "ports".to_string(),
                create_filter_operator(filter_func, next_op),
            ),
        ),
    )
}

fn ddos(next_op: Operator) -> Operator {
    let threshold: i32 = 40;
    let incl_keys: Vec<String> = Vec::from(["ipv4.src".to_string(), "ipv4.dst".to_string()]);
    let incl_keys2: Vec<String> = Vec::from(["ipv4.dst".to_string()]);
    let groupby_func: GroupingFunc =
        Box::new(move |headers: Headers| filter_groups(incl_keys.clone(), &mut headers.clone()));
    let groupby_func2: GroupingFunc =
        Box::new(move |headers: Headers| filter_groups(incl_keys2.clone(), &mut headers.clone()));
    let filter_func: FilterFunc =
        Box::new(move |headers: &Headers| key_geq_int("ports".to_string(), threshold, headers));
    create_epoch_operator(
        1.0,
        "eid".to_string(),
        create_distinct_operator(
            groupby_func,
            create_groupby_operator(
                groupby_func2,
                Box::new(counter),
                "srcs".to_string(),
                create_filter_operator(filter_func, next_op),
            ),
        ),
    )
}

fn ack_creator<'a, 'b>(next_op: Operator<'a>) -> Operator<'b> 
    where
        'a: 'b, {
    let epoch_dur: f64 = 1.0;
    let mut acks: Box<dyn FnMut(Operator<'b>) -> Operator<'b> + 'a> =
        Box::new( move |next_op: Operator<'b>| {
            let incl_keys: Vec<String> = Vec::from(["ipv4.dst".to_string()]);
            let filter_func: FilterFunc = Box::new(move |headers: &Headers| {
                get_mapped_int("ipv4.proto".to_string(), &headers) == 6
                    && get_mapped_int("l4.flags".to_string(), &headers) == 16
            });
            let groupby_func: GroupingFunc = Box::new(move |headers: Headers| {
                filter_groups(incl_keys.clone(), &mut headers.clone())
            });
            create_epoch_operator(
                epoch_dur,
                "eid".to_string(),
                create_filter_operator(
                    filter_func,
                    create_groupby_operator(
                        groupby_func,
                        Box::new(counter),
                        "acks".to_string(),
                        next_op,
                    ),
                ),
            )
        }
    );
    acks(next_op)
}

fn syn_flood_sonata<'a>(next_op: Operator<'a>, next_op1: Operator<'a>, next_op2: Operator<'a>) -> Vec<Operator<'a>> {
    let threshold: i32 = 3;
    let epoch_dur: f64 = 1.0;
    let mut syns: Box<dyn FnMut(Operator) -> Operator + 'a> =
        Box::new(move |next_op: Operator<'a>| {
            let incl_keys: Vec<String> = Vec::from(["ipv4.dst".to_string()]);
            let filter_func: FilterFunc = Box::new(move |headers: &Headers| {
                get_mapped_int("ipv4.proto".to_string(), &headers) == 6
                    && get_mapped_int("l4.flags".to_string(), &headers) == 2
            });
            let groupby_func: GroupingFunc = Box::new(move |headers: Headers| {
                filter_groups(incl_keys.clone(), &mut headers.clone())
            });
            create_epoch_operator(
                epoch_dur,
                "eid".to_string(),
                create_filter_operator(
                    filter_func,
                    create_groupby_operator(
                        groupby_func,
                        Box::new(counter),
                        "syns".to_string(),
                        next_op,
                    ),
                ),
            )
        });

    let mut synacks: Box<dyn FnMut(Operator) -> Operator + 'a> =
        Box::new(move |next_op: Operator<'a>| {
            let incl_keys: Vec<String> = Vec::from(["ipv4.src".to_string()]);
            let filter_func: FilterFunc = Box::new(move |headers: &Headers| {
                get_mapped_int("ipv4.proto".to_string(), &headers) == 6
                    && get_mapped_int("l4.flags".to_string(), &headers) == 18
            });
            let groupby_func: GroupingFunc = Box::new(move |headers: Headers| {
                filter_groups(incl_keys.clone(), &mut headers.clone())
            });
            create_epoch_operator(
                epoch_dur,
                "eid".to_string(),
                create_filter_operator(
                    filter_func,
                    create_groupby_operator(
                        groupby_func,
                        Box::new(counter),
                        "synacks".to_string(),
                        next_op,
                    ),
                ),
            )
        });

    

    let next_op_ref: Rc<RefCell<Operator>> = Rc::new(RefCell::new(next_op));
    let next_op_ref1: Rc<RefCell<Operator>> = Rc::clone(&next_op_ref);
    let next_op_ref2: Rc<RefCell<Operator>> = Rc::clone(&next_op_ref);
    let next_op_ref3: Rc<RefCell<Operator>> = Rc::clone(&next_op_ref);

    let mut first_join_ops_creator: Box<dyn FnMut(Operator) -> (Operator<'a>, Operator<'a>) + 'a> =
        Box::new(move |next_op: Operator<'a>| {
            let incl_keys: Vec<String> = Vec::from(["host".to_string()]);
            let incl_keys2: Vec<String> = Vec::from(["syns+synacks".to_string()]);
            let incl_keys3: Vec<String> = Vec::from(["acks".to_string()]);
            let left_extractor_func: Box<dyn FnMut(Headers) -> (Headers, Headers) + 'a> =
                Box::new(move |headers: Headers| {
                    (
                        filter_groups(incl_keys.clone(), &mut headers.clone()),
                        filter_groups(incl_keys2.clone(), &mut headers.clone()),
                    )
                });
            let right_extractor_func: Box<dyn FnMut(Headers) -> (Headers, Headers) + 'a> =
                Box::new(move |headers: Headers| {
                    (
                        rename_filtered_keys(
                            Vec::from([("ipv4.dst".to_string(), "host".to_string())]),
                            &mut headers.clone(),
                        ),
                        filter_groups(incl_keys3.clone(), &mut headers.clone()),
                    )
                });
            let mapping_func: Box<dyn Fn(Headers) -> Headers + 'a> =
                Box::new(move |headers: Headers| {
                    headers
                        .clone()
                        .insert(
                            "syns+synacks".to_string(),
                            utils::OpResult::Int(get_mapped_int("acks".to_string(), &headers)),
                        )
                        .unwrap();
                    headers
                });
            let filter_func: FilterFunc = Box::new(move |headers: &Headers| {
                key_geq_int("syns+synacks-acks".to_string(), threshold, headers)
            });
            create_join_operator(
                None,
                left_extractor_func,
                right_extractor_func,
                create_map_operator(mapping_func, create_filter_operator(filter_func, *next_op_ref1.borrow_mut())),
            )
        });

    let mut second_join_ops_creator: Box<dyn FnMut(Operator) -> (Operator<'a>, Operator<'a>) + 'a> =
        Box::new(move |next_op: Operator<'a>| {
            let incl_keys: Vec<String> = Vec::from(["syns".to_string()]);
            let incl_keys2: Vec<String> = Vec::from(["synacks".to_string()]);
            let left_extractor_func: Box<dyn FnMut(Headers) -> (Headers, Headers) + 'a> =
                Box::new(move |headers: Headers| {
                    (
                        rename_filtered_keys(
                            Vec::from([("ipv4.dst".to_string(), "host".to_string())]),
                            &mut headers.clone(),
                        ),
                        filter_groups(incl_keys.clone(), &mut headers.clone()),
                    )
                });
            let right_extractor_func: Box<dyn FnMut(Headers) -> (Headers, Headers) + 'a> =
                Box::new(move |headers: Headers| {
                    (
                        rename_filtered_keys(
                            Vec::from([("ipv4.src".to_string(), "host".to_string())]),
                            &mut headers.clone(),
                        ),
                        filter_groups(incl_keys2.clone(), &mut headers.clone()),
                    )
                });
            let mapping_func: Box<dyn Fn(Headers) -> Headers + 'a> =
                Box::new(move |headers: Headers| {
                    headers
                        .clone()
                        .insert(
                            "syns+synacks".to_string(),
                            utils::OpResult::Int(
                                get_mapped_int("syns".to_string(), &headers)
                                    + get_mapped_int("synacks".to_string(), &headers),
                            ),
                        )
                        .unwrap();
                    headers
                });
            create_join_operator(
                None,
                left_extractor_func,
                right_extractor_func,
                create_map_operator(mapping_func, *next_op_ref2.borrow()),
            )
        });

    let (join_op1, join_op2) = first_join_ops_creator(*next_op_ref3.borrow());
    let (join_op3, join_op4) = second_join_ops_creator(join_op1);

    Vec::from([syns(join_op3), synacks(join_op4), acks(join_op2)])
}

fn main() {
    println!("Hello, world!");
}
