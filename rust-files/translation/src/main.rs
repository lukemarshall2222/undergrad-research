#![allow(dead_code)]

use builtins::{
    FilterFunc, GroupingFunc, ReductionFunc, counter, create_distinct_operator,
    create_epoch_operator, create_filter_operator, create_groupby_operator, create_map_operator,
    filter_groups, get_mapped_int, key_geq_int, single_group,
};
use utils::{Headers, OpResult, Operator};

mod builtins;
mod utils;

fn ident(next_op: Operator) -> Operator {
    create_map_operator(
        Box::new(|headers: &mut Headers| {
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

fn main() {
    println!("Hello, world!");
}
