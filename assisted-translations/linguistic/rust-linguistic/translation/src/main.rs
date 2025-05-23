#![allow(dead_code)]

// use std::{cell::RefCell, io::stdout, rc::Rc};

use std::{cell::RefCell, error::Error, io::Error, rc::Rc};

use builtins::{
    DblOpCreator, FilterFunc, GroupingFunc, OpCreator, OpKind, OpPair, Query, QueryKind, counter,
    filter_groups, key, key_geq_int, rename_filtered_keys, single_group,
};
use utils::{Headers, Operator, OperatorRef};
// use ordered_float::OrderedFloat;
// use utils::{Headers, OpResult, OperatorRef};

mod builtins;
mod utils;

type QueryCreator = Box<dyn Fn(OperatorRef) -> Result<QueryKind, Error> + 'static>;

fn ident() -> QueryCreator {
    Box::new(move |next_op: OperatorRef| {
        let f = Box::new(move |mut headers: Headers| {
            headers.remove("eth.src".to_string());
            headers.remove("eth.dst".to_string());
            headers
        });
        Query::new(None, None)
            .map(f)
            .add_query(Query::new(None, Some(next_op)))
            .collect()
    })
}

fn count_pkts() -> QueryCreator {
    Box::new(move |next_op: OperatorRef| {
        let incl_keys = Vec::from(["ipv4.src".to_string(), "ipv4.dst".to_string()]);
        let groupby_func: GroupingFunc =
            Box::new(move |mut headers: Headers| filter_groups(incl_keys.clone(), &mut headers));

        Query::new(None, None)
            .epoch(1.0, "eid".to_string())
            .groupby(groupby_func, Box::new(counter), "pkts".to_string())
            .add_query(Query::new(None, Some(next_op)))
            .collect()
    })
}

fn pkts_per_source_dst() -> QueryCreator {
    Box::new(move |next_op: OperatorRef| {
        let incl_keys = Vec::from(["ipv4.src".to_string(), "ipv4.dst".to_string()]);
        let groupby_func: GroupingFunc =
            Box::new(move |mut headers: Headers| filter_groups(incl_keys.clone(), &mut headers));

        Query::new(None, None)
            .epoch(1.0, "eid".to_string())
            .groupby(groupby_func, Box::new(counter), "pkts".to_string())
            .add_query(Query::new(None, Some(next_op)))
            .collect()
    })
}

fn distinct_srcs() -> QueryCreator {
    Box::new(move |next_op: OperatorRef| {
        let incl_keys = Vec::from(["ipv4.src".to_string()]);
        let groupby_func: GroupingFunc =
            Box::new(move |mut headers: Headers| filter_groups(incl_keys.clone(), &mut headers));
        Query::new(None, None)
            .epoch(1.0, "eid".to_string())
            .distinct(groupby_func)
            .groupby(
                Box::new(single_group),
                Box::new(counter),
                "srcs".to_string(),
            )
            .add_query(Query::new(None, Some(next_op)))
            .collect()
    })
}

fn tcp_new_cons() -> QueryCreator {
    Box::new(move |next_op: OperatorRef| {
        let threshold: i32 = 40;
        let incl_keys: Vec<String> = Vec::from(["ipv4.dst".to_string()]);
        let filter_func: FilterFunc = Box::new(move |headers: &Headers| {
            headers.get_mapped_int("ipv4.proto".to_string()) == 6
                && headers.get_mapped_int("l4.flags".to_string()) == 2
        });
        let groupby_func: GroupingFunc =
            Box::new(move |mut headers: Headers| filter_groups(incl_keys.clone(), &mut headers));
        let filter_func2: FilterFunc =
            Box::new(move |headers: &Headers| key_geq_int("cons".to_string(), threshold, headers));

        Query::new(None, None)
            .epoch(1.0, "eid".to_string())
            .filter(filter_func)
            .groupby(groupby_func, Box::new(counter), "cons".to_string())
            .filter(filter_func2)
            .add_query(Query::new(None, Some(next_op)))
            .collect()
    })
}

fn ssh_brute_force() -> QueryCreator {
    Box::new(move |next_op: OperatorRef| {
        let threshold: i32 = 40;
        let incl_keys: Vec<String> = Vec::from([
            "ipv4.src".to_string(),
            "ipv4.dst".to_string(),
            "ipv4.len".to_string(),
        ]);
        let incl_keys2: Vec<String> = Vec::from(["ipv4.dst".to_string(), "ipv4.len".to_string()]);
        let filter_func: FilterFunc = Box::new(move |headers: &Headers| {
            headers.get_mapped_int("ipv4.proto".to_string()) == 6
                && headers.get_mapped_int("l4.dport".to_string()) == 22
        });
        let groupby_func: GroupingFunc =
            Box::new(move |mut headers: Headers| filter_groups(incl_keys.clone(), &mut headers));
        let groupby_func2: GroupingFunc =
            Box::new(move |mut headers: Headers| filter_groups(incl_keys2.clone(), &mut headers));
        let filter_func2: FilterFunc =
            Box::new(move |headers: &Headers| key_geq_int("srcs".to_string(), threshold, headers));

        Query::new(None, None)
            .epoch(1.0, "eid".to_string())
            .filter(filter_func)
            .distinct(groupby_func)
            .groupby(groupby_func2, Box::new(counter), "srcs".to_string())
            .filter(filter_func2)
            .add_query(Query::new(None, Some(next_op)))
            .collect()
    })
}

fn super_spreader() -> QueryCreator {
    Box::new(move |next_op: OperatorRef| {
        let threshold: i32 = 40;
        let incl_keys: Vec<String> = Vec::from(["ipv4.src".to_string(), "ipv4.dst".to_string()]);
        let incl_keys2: Vec<String> = Vec::from(["ipv4.src".to_string()]);
        let groupby_func: GroupingFunc =
            Box::new(move |mut headers: Headers| filter_groups(incl_keys.clone(), &mut headers));
        let groupby_func2: GroupingFunc =
            Box::new(move |mut headers: Headers| filter_groups(incl_keys2.clone(), &mut headers));
        let filter_func: FilterFunc =
            Box::new(move |headers: &Headers| key_geq_int("dsts".to_string(), threshold, headers));

        Query::new(None, None)
            .epoch(1.0, "eid".to_string())
            .distinct(groupby_func)
            .groupby(groupby_func2, Box::new(counter), "dsts".to_string())
            .filter(filter_func)
            .add_query(Query::new(None, Some(next_op)))
            .collect()
    })
}

fn port_scan() -> QueryCreator {
    Box::new(move |next_op: OperatorRef| {
        let threshold: i32 = 40;
        let incl_keys: Vec<String> = Vec::from(["ipv4.src".to_string(), "l4.dport".to_string()]);
        let incl_keys2: Vec<String> = Vec::from(["ipv4.src".to_string()]);
        let groupby_func: GroupingFunc =
            Box::new(move |mut headers: Headers| filter_groups(incl_keys.clone(), &mut headers));
        let groupby_func2: GroupingFunc =
            Box::new(move |mut headers: Headers| filter_groups(incl_keys2.clone(), &mut headers));
        let filter_func: FilterFunc =
            Box::new(move |headers: &Headers| key_geq_int("ports".to_string(), threshold, headers));

        Query::new(None, None)
            .epoch(1.0, "eid".to_string())
            .distinct(groupby_func)
            .groupby(groupby_func2, Box::new(counter), "ports".to_string())
            .filter(filter_func)
            .add_query(Query::new(None, Some(next_op)))
            .collect()
    })
}

fn ddos() -> QueryCreator {
    Box::new(move |next_op: OperatorRef| {
        let threshold: i32 = 40;
        let incl_keys: Vec<String> = Vec::from(["ipv4.src".to_string(), "ipv4.dst".to_string()]);
        let incl_keys2: Vec<String> = Vec::from(["ipv4.dst".to_string()]);
        let groupby_func: GroupingFunc =
            Box::new(move |mut headers: Headers| filter_groups(incl_keys.clone(), &mut headers));
        let groupby_func2: GroupingFunc =
            Box::new(move |mut headers: Headers| filter_groups(incl_keys2.clone(), &mut headers));
        let filter_func: FilterFunc =
            Box::new(move |headers: &Headers| key_geq_int("ports".to_string(), threshold, headers));

        Query::new(None, None)
            .epoch(1.0, "eid".to_string())
            .distinct(groupby_func)
            .groupby(groupby_func2, Box::new(counter), "srcs".to_string())
            .filter(filter_func)
            .add_query(Query::new(None, Some(next_op)))
            .collect()
    })
}

fn syn_flood_sonata(next_op: OperatorRef) -> Result<[OperatorRef; 3], Box<dyn Error>> {
    let threshold: i32 = 5;

    let mut syns: QueryCreator = Box::new(move |next_op: OperatorRef| {
        let incl_keys: Vec<String> = Vec::from(["ipv4.dst".to_string()]);
        let filter_func: FilterFunc = Box::new(move |headers: &Headers| {
            headers.get_mapped_int("ipv4.proto".to_string()) == 6
                && headers.get_mapped_int("l4.flags".to_string()) == 2
        });
        let groupby_func: GroupingFunc =
            Box::new(move |mut headers: Headers| filter_groups(incl_keys.clone(), &mut headers));

        Query::new(None, None)
            .epoch(1.0, "eid".to_string())
            .filter(filter_func)
            .groupby(groupby_func, Box::new(counter), "syns".to_string())
            .add_query(Query::new(None, Some(next_op)))
            .collect()
    });

    let mut acks: QueryCreator = Box::new(move |next_op: OperatorRef| {
        let incl_keys: Vec<String> = Vec::from(["ipv4.dst".to_string()]);
        let filter_func: FilterFunc = Box::new(move |headers: &Headers| {
            headers.get_mapped_int("ipv4.proto".to_string()) == 6
                && headers.get_mapped_int("l4.flags".to_string()) == 16
        });
        let groupby_func: GroupingFunc =
            Box::new(move |mut headers: Headers| filter_groups(incl_keys.clone(), &mut headers));

        Query::new(None, None)
            .epoch(1.0, "eid".to_string())
            .filter(filter_func)
            .groupby(groupby_func, Box::new(counter), "acks".to_string())
            .add_query(Query::new(None, Some(next_op)))
            .collect()
    });

    let mut synacks: QueryCreator = Box::new(move |next_op: OperatorRef| {
        let incl_keys: Vec<String> = Vec::from(["ipv4.src".to_string()]);
        let filter_func: FilterFunc = Box::new(move |headers: &Headers| {
            headers.get_mapped_int("ipv4.proto".to_string()) == 6
                && headers.get_mapped_int("l4.flags".to_string()) == 18
        });
        let groupby_func: GroupingFunc =
            Box::new(move |mut headers: Headers| filter_groups(incl_keys.clone(), &mut headers));

        Query::new(None, None)
            .epoch(1.0, "eid".to_string())
            .filter(filter_func)
            .groupby(groupby_func, Box::new(counter), "synacks".to_string())
            .add_query(Query::new(None, Some(next_op)))
            .collect()
    });

    let mut first_join_ops: Box<
        dyn FnOnce(Rc<RefCell<Operator>>) -> Result<QueryKind, Box<dyn Error>>,
    > = Box::new(move |next_op_inner: OperatorRef| {
        let incl_keys: Vec<String> = Vec::from(["host".to_string()]);
        let incl_keys2: Vec<String> = Vec::from(["syns+synacks".to_string()]);
        let incl_keys3: Vec<String> = Vec::from(["acks".to_string()]);
        let left_extractor_func: Box<dyn FnMut(Headers) -> (Headers, Headers) + 'static> =
            Box::new(move |mut headers: Headers| {
                (
                    filter_groups(incl_keys.clone(), &mut headers),
                    filter_groups(incl_keys2.clone(), &mut headers),
                )
            });
        let right_extractor_func: Box<dyn FnMut(Headers) -> (Headers, Headers) + 'static> =
            Box::new(move |mut headers: Headers| {
                (
                    rename_filtered_keys(
                        Vec::from([("ipv4.dst".to_string(), "host".to_string())]),
                        &mut headers.clone(),
                    ),
                    filter_groups(incl_keys3.clone(), &mut headers),
                )
            });
        let mapping_func: Box<dyn Fn(Headers) -> Headers + 'static> =
            Box::new(move |mut headers: Headers| {
                headers
                    .insert(
                        "syns+synacks".to_string(),
                        utils::OpResult::Int(headers.get_mapped_int("acks".to_string())),
                    )
                    .unwrap();
                headers
            });
        let filter_func: FilterFunc = Box::new(move |headers: &Headers| {
            key_geq_int("syns+synacks-acks".to_string(), threshold, headers)
        });

        Ok(Query::new(None, None)
            .join(None, left_extractor_func, right_extractor_func)
            .map(mapping_func)
            .filter(filter_func)
            .add_query(Query::new(None, Some(next_op_inner)))
            .collect()?)
    });

    let mut second_join_ops: Box<
        dyn FnOnce(Rc<RefCell<Operator>>) -> Result<QueryKind, Box<dyn Error>>,
    > = Box::new(move |next_op_inner: OperatorRef| {
        let incl_keys: Vec<String> = Vec::from(["syns".to_string()]);
        let incl_keys2: Vec<String> = Vec::from(["synacks".to_string()]);
        let left_extractor_func: Box<dyn FnMut(Headers) -> (Headers, Headers) + 'static> =
            Box::new(move |mut headers: Headers| {
                (
                    rename_filtered_keys(
                        Vec::from([("ipv4.dst".to_string(), "host".to_string())]),
                        &mut headers.clone(),
                    ),
                    filter_groups(incl_keys.clone(), &mut headers),
                )
            });
        let right_extractor_func: Box<dyn FnMut(Headers) -> (Headers, Headers) + 'static> =
            Box::new(move |mut headers: Headers| {
                (
                    rename_filtered_keys(
                        Vec::from([("ipv4.src".to_string(), "host".to_string())]),
                        &mut headers.clone(),
                    ),
                    filter_groups(incl_keys2.clone(), &mut headers),
                )
            });
        let mapping_func: Box<dyn Fn(Headers) -> Headers + 'static> =
            Box::new(move |mut headers: Headers| {
                headers
                    .insert(
                        "syns+synacks".to_string(),
                        utils::OpResult::Int(
                            headers.get_mapped_int("syns".to_string())
                                + headers.get_mapped_int("synacks".to_string()),
                        ),
                    )
                    .unwrap();
                headers
            });
        Ok(Query::new(None, None)
            .join(None, left_extractor_func, right_extractor_func)
            .map(mapping_func)
            .add_query(Query::new(None, Some(next_op_inner)))
            .collect()?)
    });

    let first_join_query: QueryKind = first_join_ops(next_op.clone())?;
    let (mut join_op1, mut join_op2) = (None, None);

    match first_join_query {
        QueryKind::OpPair((op1, op2)) => {
            join_op1 = Some(op1);
            join_op2 = Some(op2);
        }
        _ => {
            return Err("first_join_ops did not return QueryKind::OpPair".into());
        }
    }

    let second_join_query: QueryKind = second_join_ops(
        join_op1.expect("Expected join_op1 to be Some(OperatorRef) before calling second_join_ops"),
    )?;
    let (mut join_op3, mut join_op4) = (None, None);

    match second_join_query {
        QueryKind::OpPair((op3, op4)) => {
            join_op3 = Some(op3);
            join_op4 = Some(op4);
        }
        _ => {
            return Err("first_join_ops did not return QueryKind::OpPair".into());
        }
    }

    [syns(join_op3), synacks(join_op4), acks(join_op2)]
}


// fn completed_flows(next_op: OperatorRef) -> [OperatorRef; 2] {
//     let threshold: i32 = 1;
//     let epoch_dur: f64 = 30.0;
//     let mut syns: Box<dyn FnMut(OperatorRef) -> OperatorRef + 'static> =
//         Box::new(move |next_op: OperatorRef| {
//             let incl_keys: Vec<String> = Vec::from(["ipv4.dst".to_string()]);
//             let filter_func: FilterFunc = Box::new(move |headers: &Headers| {
//                 headers.get_mapped_int("ipv4.proto".to_string()) == 6
//                     && headers.get_mapped_int("l4.flags".to_string()) == 2
//             });
//             let groupby_func: GroupingFunc = Box::new(move |mut headers: Headers| {
//                 filter_groups(incl_keys.clone(), &mut headers)
//             });
//             create_epoch_operator(
//                 epoch_dur,
//                 "eid".to_string(),
//                 create_filter_operator(
//                     filter_func,
//                     create_groupby_operator(
//                         groupby_func,
//                         Box::new(counter),
//                         "syns".to_string(),
//                         next_op,
//                     ),
//                 ),
//             )
//         });

//     let mut fins: Box<dyn FnMut(OperatorRef) -> OperatorRef + 'static> =
//         Box::new(move |next_op: OperatorRef| {
//             let incl_keys: Vec<String> = Vec::from(["ipv4.src".to_string()]);
//             let filter_func: FilterFunc = Box::new(move |headers: &Headers| {
//                 headers.get_mapped_int("ipv4.proto".to_string()) == 6
//                     && ((headers.get_mapped_int("l4.flags".to_string()) & 1) == 1)
//             });
//             let groupby_func: GroupingFunc = Box::new(move |mut headers: Headers| {
//                 filter_groups(incl_keys.clone(), &mut headers)
//             });
//             create_epoch_operator(
//                 epoch_dur,
//                 "eid".to_string(),
//                 create_filter_operator(
//                     filter_func,
//                     create_groupby_operator(
//                         groupby_func,
//                         Box::new(counter),
//                         "fins".to_string(),
//                         next_op,
//                     ),
//                 ),
//             )
//         });

//     let mut create_join_ops: Box<dyn FnMut(OperatorRef) -> (OperatorRef, OperatorRef) + 'static> =
//         Box::new(move |next_op: OperatorRef| {
//             let incl_keys: Vec<String> = Vec::from(["syns".to_string()]);
//             let left_extractor_func: Box<dyn FnMut(Headers) -> (Headers, Headers) + 'static> =
//                 Box::new(move |mut headers: Headers| {
//                     (
//                         rename_filtered_keys(
//                             Vec::from([("ipv4.dst".to_string(), "host".to_string())]),
//                             &mut headers,
//                         ),
//                         filter_groups(incl_keys.clone(), &mut headers),
//                     )
//                 });
//             let right_extractor_func: Box<dyn FnMut(Headers) -> (Headers, Headers) + 'static> =
//                 Box::new(move |mut headers: Headers| {
//                     let incl_keys2: Vec<String> = Vec::from(["fins".to_string()]);
//                     (
//                         rename_filtered_keys(
//                             Vec::from([("ipv4.src".to_string(), "host".to_string())]),
//                             &mut headers,
//                         ),
//                         filter_groups(incl_keys2.clone(), &mut headers),
//                     )
//                 });
//             let mapping_func: Box<dyn Fn(Headers) -> Headers + 'static> =
//                 Box::new(move |mut headers: Headers| {
//                     headers
//                         .insert(
//                             "diff".to_string(),
//                             utils::OpResult::Int(headers.get_mapped_int("syns".to_string())),
//                         )
//                         .unwrap();
//                     headers
//                 });
//             let filter_func: FilterFunc = Box::new(move |headers: &Headers| {
//                 key_geq_int("diff".to_string(), threshold, headers)
//             });
//             create_join_operator(
//                 None,
//                 left_extractor_func,
//                 right_extractor_func,
//                 create_map_operator(mapping_func, create_filter_operator(filter_func, next_op)),
//             )
//         });
//     let (join_op1, join_op2) = create_join_ops(next_op);

//     [syns(join_op1), fins(join_op2)]
// }



// fn slowloris(next_op: OperatorRef) -> [OperatorRef; 2] {
//     let t1: i32 = 5;
//     let t2: i32 = 500;
//     let t3: i32 = 90;
//     let epoch_dur: f64 = 1.0;

//     let mut n_conns: Box<dyn FnMut(OperatorRef) -> OperatorRef + 'static> =
//         Box::new(move |next_op: OperatorRef| {
//             let incl_keys: Vec<String> = Vec::from([
//                 "ipv4.src".to_string(),
//                 "ipv4.dst".to_string(),
//                 "l4.sport".to_string(),
//             ]);
//             let incl_keys2: Vec<String> = Vec::from(["ipv4.dst".to_string()]);
//             let filter_func: FilterFunc = Box::new(move |headers: &Headers| {
//                 headers.get_mapped_int("ipv4.proto".to_string()) == 6
//             });
//             let filter_func2: FilterFunc = Box::new(move |headers: &Headers| {
//                 headers.get_mapped_int("n_conns".to_string()) >= t1
//             });
//             let groupby_func: GroupingFunc = Box::new(move |mut headers: Headers| {
//                 filter_groups(incl_keys.clone(), &mut headers)
//             });
//             let groupby_func2: GroupingFunc = Box::new(move |mut headers: Headers| {
//                 filter_groups(incl_keys2.clone(), &mut headers)
//             });
//             create_epoch_operator(
//                 epoch_dur,
//                 "eid".to_string(),
//                 create_filter_operator(
//                     filter_func,
//                     create_distinct_operator(
//                         groupby_func,
//                         create_groupby_operator(
//                             groupby_func2,
//                             Box::new(counter),
//                             "n_conns".to_string(),
//                             create_filter_operator(filter_func2, next_op),
//                         ),
//                     ),
//                 ),
//             )
//         });

//     let mut n_bytes: Box<dyn FnMut(OperatorRef) -> OperatorRef + 'static> =
//         Box::new(move |next_op: OperatorRef| {
//             let incl_keys: Vec<String> = Vec::from(["ipv4.dst".to_string()]);
//             let filter_func: FilterFunc = Box::new(move |headers: &Headers| {
//                 headers.get_mapped_int("ipv4.proto".to_string()) == 6
//             });
//             let filter_func2: FilterFunc = Box::new(move |headers: &Headers| {
//                 headers.get_mapped_int("n_bytes".to_string()) >= t2
//             });
//             let groupby_func: GroupingFunc = Box::new(move |mut headers: Headers| {
//                 filter_groups(incl_keys.clone(), &mut headers)
//             });
//             let reduce_func: ReductionFunc =
//                 Box::new(move |init_val: OpResult, headers: &mut Headers| {
//                     sum_ints("ipv4.len".to_string(), init_val, headers).unwrap()
//                 });
//             create_epoch_operator(
//                 epoch_dur,
//                 "eid".to_string(),
//                 create_filter_operator(
//                     filter_func,
//                     create_groupby_operator(
//                         groupby_func,
//                         reduce_func,
//                         "n_bytes".to_string(),
//                         create_filter_operator(filter_func2, next_op),
//                     ),
//                 ),
//             )
//         });

//     let mut create_join_ops: Box<dyn FnMut(OperatorRef) -> (OperatorRef, OperatorRef) + 'static> =
//         Box::new(move |next_op: OperatorRef| {
//             let left_extractor_func: Box<dyn FnMut(Headers) -> (Headers, Headers) + 'static> =
//                 Box::new(move |mut headers: Headers| {
//                     let incl_keys: Vec<String> = Vec::from(["ipv4.dst".to_string()]);
//                     let incl_keys2: Vec<String> = Vec::from(["n_conns".to_string()]);
//                     (
//                         filter_groups(incl_keys.clone(), &mut headers),
//                         filter_groups(incl_keys2.clone(), &mut headers),
//                     )
//                 });
//             let right_extractor_func: Box<dyn FnMut(Headers) -> (Headers, Headers) + 'static> =
//                 Box::new(move |mut headers: Headers| {
//                     let incl_keys: Vec<String> = Vec::from(["ipv4.dst".to_string()]);
//                     let incl_keys2: Vec<String> = Vec::from(["n_bytes".to_string()]);
//                     (
//                         filter_groups(incl_keys.clone(), &mut headers),
//                         filter_groups(incl_keys2.clone(), &mut headers),
//                     )
//                 });
//             let mapping_func: Box<dyn Fn(Headers) -> Headers + 'static> =
//                 Box::new(move |mut headers: Headers| {
//                     headers
//                         .insert(
//                             "bytes_per_conn".to_string(),
//                             utils::OpResult::Int(
//                                 headers.get_mapped_int("n_bytes".to_string())
//                                     / headers.get_mapped_int("n_conns".to_string()),
//                             ),
//                         )
//                         .unwrap();
//                     headers
//                 });
//             let filter_func: FilterFunc = Box::new(move |headers: &Headers| {
//                 headers.get_mapped_int("bytes_per_conn".to_string()) <= t3
//             });
//             create_join_operator(
//                 None,
//                 left_extractor_func,
//                 right_extractor_func,
//                 create_map_operator(mapping_func, create_filter_operator(filter_func, next_op)),
//             )
//         });
//     let (join_op1, join_op2) = create_join_ops(next_op);

//     [n_conns(join_op1), n_bytes(join_op2)]
// }

// fn create_join_operator_test(next_op: OperatorRef) -> [OperatorRef; 2] {
//     let epoch_dur: f64 = 1.0;
//     let mut syns: Box<dyn FnMut(OperatorRef) -> OperatorRef + 'static> =
//         Box::new(move |next_op: OperatorRef| {
//             let filter_func: FilterFunc = Box::new(move |headers: &Headers| {
//                 headers.get_mapped_int("ipv4.proto".to_string()) == 6
//                     && headers.get_mapped_int("l4.flags".to_string()) == 2
//             });
//             create_epoch_operator(
//                 epoch_dur,
//                 "eid".to_string(),
//                 create_filter_operator(filter_func, next_op),
//             )
//         });

//     let mut synacks: Box<dyn FnMut(OperatorRef) -> OperatorRef + 'static> =
//         Box::new(move |next_op: OperatorRef| {
//             let filter_func: FilterFunc = Box::new(move |headers: &Headers| {
//                 headers.get_mapped_int("ipv4.proto".to_string()) == 6
//                     && headers.get_mapped_int("l4.flags".to_string()) == 18
//             });
//             create_epoch_operator(
//                 epoch_dur,
//                 "eid".to_string(),
//                 create_filter_operator(filter_func, next_op),
//             )
//         });

//     let mut join_ops: Box<dyn FnMut(OperatorRef) -> (OperatorRef, OperatorRef) + 'static> =
//         Box::new(move |next_op: OperatorRef| {
//             let left_extractor_func: Box<dyn FnMut(Headers) -> (Headers, Headers) + 'static> =
//                 Box::new(move |mut headers: Headers| {
//                     (
//                         rename_filtered_keys(
//                             Vec::from([("ipv4.src".to_string(), "host".to_string())]),
//                             &mut headers,
//                         ),
//                         rename_filtered_keys(
//                             Vec::from([("ipv4.dst".to_string(), "remote".to_string())]),
//                             &mut headers,
//                         ),
//                     )
//                 });
//             let right_extractor_func: Box<dyn FnMut(Headers) -> (Headers, Headers) + 'static> =
//                 Box::new(move |mut headers: Headers| {
//                     (
//                         rename_filtered_keys(
//                             Vec::from([("ipv4.src".to_string(), "host".to_string())]),
//                             &mut headers,
//                         ),
//                         filter_groups(Vec::from(["time".to_string()]), &mut headers),
//                     )
//                 });
//             create_join_operator(None, left_extractor_func, right_extractor_func, next_op)
//         });
//     let (join_op1, join_op2) = join_ops(next_op);

//     [syns(join_op1), synacks(join_op2)]
// }

// fn q3(next_op: OperatorRef) -> OperatorRef {
//     let incl_keys: Vec<String> = Vec::from(["ipv4.src".to_string(), "ipv4.dst".to_string()]);
//     let groupby_func: GroupingFunc =
//         Box::new(move |mut headers: Headers| filter_groups(incl_keys.clone(), &mut headers));
//     create_epoch_operator(
//         100.0,
//         "eid".to_string(),
//         create_distinct_operator(groupby_func, next_op),
//     )
// }

// fn q4(next_op: OperatorRef) -> OperatorRef {
//     let incl_keys: Vec<String> = Vec::from(["ipv4.src".to_string()]);
//     let groupby_func: GroupingFunc =
//         Box::new(move |mut headers: Headers| filter_groups(incl_keys.clone(), &mut headers));
//     create_epoch_operator(
//         10000.0,
//         "eid".to_string(),
//         create_groupby_operator(groupby_func, Box::new(counter), "pkts".to_string(), next_op),
//     )
// }

// fn create_query() -> OperatorRef {
//     ident(Rc::new(RefCell::new(dump_as_csv(None, Some(false), Box::new(stdout())))))
// }

fn main() {
    // let mut _query: OperatorRef = create_query();
    // for i in 0..20 {
    //     let mut header: Headers = Headers::new();
    //     header.insert("time".to_string(), OpResult::Float(OrderedFloat(i as f64)));
    //     header.insert("eth.src".to_string(), OpResult::MAC([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]));
    //     header.insert("eth.dst".to_string(), OpResult::MAC([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]));
    //     header.insert("eth.ethertype".to_string(), OpResult::Int(0x0800));
    //     header.insert("ipv4.hlen".to_string(), OpResult::Int(20));
    //     header.insert("ipv4.proto".to_string(), OpResult::Int(6));
    //     header.insert("ipv4.len".to_string(), OpResult::Int(60));
    //     header.insert("ipv4.src".to_string(), OpResult::IPv4("127.0.0.1".parse().unwrap()));
    //     header.insert("ipv4.dst".to_string(), OpResult::IPv4("127.0.0.1".parse().unwrap()));
    //     header.insert("l4.sport".to_string(), OpResult::Int(440));
    //     header.insert("l4.dport".to_string(), OpResult::Int(50000));
    //     header.insert("l4.flags".to_string(), OpResult::Int(10));
    //     (_query.borrow_mut().next)(&mut header)
    // }
}
