from utils_translated import *
from builtins_translated import *
from functools import partial
import sys
from typing import cast

epoch_dur: float = 5.0
threshold: int = 40

ident = Query()\
    .map(remove_keys) \
    .collect()

count_pkts = Query() \
    .groupby(single_group, counter, "pkts") \
    .epoch(1.0, "eid") \
    .collect()

pkts_per_src_dst = Query() \
    .groupby(partial(filter_groups, ["ipv4.src", "ipv4.dst"]), counter, "pkts") \
    .epoch(1.0, "eid") \
    .collect()

distinct_srcs = Query() \
    .groupby(single_group, counter, "srcs") \
    .distinct(partial(filter_groups, ["ipv4.src"])) \
    .epoch(1.0, "eid") \
    .collect()

tcp_new_cons = Query() \
    .filter(partial(key_geq_int, "cons", 40)) \
    .groupby(partial(filter_groups, ["ipv4.dst"]), counter, "cons") \
    .filter(partial(filter_helper, 6, 2)) \
    .epoch(1.0, "eid") \
    .collect()

ssh_brute_force = Query() \
    .filter(partial(key_geq_int, "srcs", 40)) \
    .groupby(partial(filter_groups, ["ipv4.dst", "ipv4.len"]), counter, "srcs") \
    .filter(partial(filter_groups, ["ipv4.src", "ipv4.dst", "ipv4.len"])) \
    .filter(partial(filter_helper, 6, 22)) \
    .epoch(1.0, "eid") \
    .collect()

super_spreader = Query() \
    .filter(partial(key_geq_int, "ports", threshold)) \
    .groupby(partial(key_geq_int, "ports", threshold), counter, "ports") \
    .distinct(partial(filter_groups, ["ipv4.src", "l4.dport"])) \
    .epoch(epoch_dur, "eid") \
    .collect()

ddos = Query() \
    .filter(partial(key_geq_int, "srcs", threshold+5)) \
    .groupby(partial(filter_groups, ["ipv4.dst"]), counter, "srcs") \
    .distinct(partial(filter_groups, ["ipv4.src", "ipv4.dst"])) \
    .epoch(epoch_dur, "eid") \
    .collect()


def syn_flood_sonata(next_op: Operator) -> list[QueryMethods]:
    join_queries: tuple[Query, Query] = Query() \
        .filter(partial(key_geq_int, "syns+synacks-acks", threshold-37)) \
        .map(lambda packet:
             packet.__setitem__("syns+synacks-acks", Op_result(Op_result.INT,
                                                               packet.get_mapped_int("syns+synacks") -
                                                               packet.get_mapped_int("acks")))) \
        .join(lambda packet:
              (filter_groups(["host"], packet),
                  filter_groups(["syns+synacks"], packet)),
              lambda packet:
              (rename_filtered_keys([("ipv4.dst", "host")], packet),
               filter_groups(["acks"], packet)))
    join_query1, join_query2 = join_queries

    join_queries2: tuple[Query, Query] = Query(join_query1) \
        .map(lambda packet:
             packet.__setitem__
             ("syns+synacks",
              Op_result(Op_result.INT,
                        packet.get_mapped_int("syns") +
                        packet.get_mapped_int("synacks")))) \
        .join(lambda packet:
              (rename_filtered_keys([("ipv4.dst", "host")], packet),
               filter_groups(["syns"], packet)),
              lambda packet:
              (rename_filtered_keys([("ipv4.src", "host")], packet),
               filter_groups(["synacks"], packet)))
    join_query3, join_query4 = join_queries2

    syns: QueryMethods = Query(join_query3) \
        .groupby(partial(filter_groups, ["ipv4.dst"]), counter, "syns") \
        .filter(partial(filter_helper, 6, 2)) \
        .epoch(epoch_dur, "eid") \
        .collect

    synacks: QueryMethods = Query(join_query4) \
        .groupby(partial(filter_groups, ["ipv4.dst"]), counter, "synacks") \
        .filter(partial(filter_helper, 6, 18)) \
        .epoch(epoch_dur, "eid") \
        .collect()

    acks: QueryMethods = Query(join_query2) \
        .groupby(partial(filter_groups, ["ipv4.dst"]), counter, "acks") \
        .filter(partial(filter_groups, 6, 16)) \
        .epoch(epoch_dur, "eid") \
        .collect()

    return [syns, synacks, acks]


def completed_flows(next_query: Query = Query()) -> list[QueryMethods]:

    join_queries: tuple[Query, Query] = Query(next_query) \
        .filter(partial(key_geq_int, "diff", threshold-39)) \
        .map((lambda packet:
              packet.__setitem__
              ("diff", Op_result(Op_result.INT,
                                 packet.get_mapped_int("syns") -
                                 packet.get_mapped_int("fins"))))) \
        .join((lambda packet:
               (rename_filtered_keys([("ipv4.dst", "host")], packet),
                   filter_groups(["syns"], packet))),
              (lambda packet:
                  (rename_filtered_keys([("ipv4.src", "host")], packet),
                   filter_groups(["fins"], packet))))
    join_query1, join_query2 = join_queries

    syns: QueryMethods = Query(join_query1) \
        .groupby(partial(filter_groups, ["ipv4.src"]),
                 counter, "syns") \
        .filter(partial(filter_helper, 6, 2)) \
        .epoch(epoch_dur+29.0, "eid") \
        .collect()

    fins: QueryMethods = Query(join_query2) \
        .groupby(partial(filter_groups, ["ipv4.src"]),
                 counter, "fins") \
        .filter((lambda packet:
                 packet.get_mapped_int("ipv4.proto") == 6 and
                 (packet.get_mapped_int("l4.flags") & 1) == 1)) \
        .epoch(epoch_dur, "eid") \
        .collect()

    return [syns, fins]


t1: int = 5
t2: int = 500
t3: int = 90


def slowloris(next_op: Operator) -> list[Operator]:
    def n_conns(next_op: Operator) -> Operator:
        Op_to_op(create_epoch_operator, epoch_dur, "eid") \
            >> (Op_to_op(create_filter_operator,
                         (lambda packet:
                          packet.get_mapped_int("ipv4.proto") == 6))
                >> (Op_to_op(create_distinct_operator,
                             partial(filter_groups,
                                     ["ipv4.src", "ipv4.dst", "l4.sport"]))
                >> (Op_to_op(create_groupby_operator,
                             partial(filter_groups, ["ipv4.dst"]),
                             counter, "n_conns")
                    >> (Op_to_op(create_filter_operator,
                                 (lambda packet:
                                  packet.get_mapped_int("n_conns") >= t1))
                    >> next_op))))

    def n_bytes(next_op: Operator) -> Operator:
        Op_to_op(create_epoch_operator, epoch_dur, "eid") \
            >> (Op_to_op(create_filter_operator,
                         (lambda packet:
                          packet.get_mapped_int("ipv4.proto") == 6))
                >> (Op_to_op(create_groupby_operator,
                             partial(filter_groups, ["ipv4.dst"]),
                             partial(sum_ints, "ipv4.len"), "n_bytes")
                >> (Op_to_op(create_filter_operator,
                             (lambda packet:
                              packet.get_mapped_int("n_bytes") >= t2))
                    >> next_op)))

    operators: tuple[Operator, Operator] = \
        Op_to_op(create_join_operator,
                 (lambda packet:
                  (filter_groups(["n_conns"], packet),
                   filter_groups(["n_conns"], packet))),
                 (lambda packet:
                  (filter_groups(["ipv4.dst"], packet),
                   filter_groups(["n_bytes"], packet)))) \
        >> (Op_to_op_tup(create_map_operator,
                         (lambda packet:
                          packet.__setitem__
                          ("bytes_per_conn", Op_result(Op_result.INT,
                                                       packet.get_mapped_int("n_bytes") -
                                                       packet.get_mapped_int("n_conns")))))
            >> (Op_to_op(create_filter_operator,
                         (lambda packet:
                          packet.get_mapped_int("bytes_per_conn") <= t3))
            >> next_op))
    op1, op2 = operators

    return [
        Op_to_op(n_conns) >> op1,
        Op_to_op(n_bytes) >> op2,
    ]


def create_join_operator_test(next_op: Operator) -> list[Operator]:
    epoch_dur: float = 1.0

    def syns(next_op: Operator) -> Operator:
        return \
            Op_to_op(create_epoch_operator, epoch_dur, "eid") \
            >> (Op_to_op(create_filter_operator, partial(filter_helper, 6, 2))
                >> next_op)

    def synacks(next_op: Operator) -> Operator:
        return \
            Op_to_op(create_epoch_operator, epoch_dur, "eid") \
            >> (Op_to_op(create_filter_operator, partial(filter_helper, 6, 18))
                >> next_op)

    operators: tuple[Operator, Operator] = \
        Op_to_op_tup(create_join_operator,
                     (lambda packet: (rename_filtered_keys([("ipv4.src", "host")], packet),
                                      (rename_filtered_keys([("ipv4.dst", "remote")], packet))))
                     (lambda packet: ((rename_filtered_keys([("ipv4.dst", "host")], packet)),
                                      (filter_groups(["time"], packet))))) \
        >> next_op
    op1, op2 = operators
    return [
        syns >> op1,
        synacks >> op2
    ]


def q3(next_op: Operator) -> Operator:
    return \
        Op_to_op(create_epoch_operator, 100.0, "eid") \
        >> (Op_to_op(create_distinct_operator,
                     partial(filter_groups, ["ipv4.src", "ipv4.dst"]))
            >> next_op)


def q4(next_op: Operator) -> Operator:
    return \
        Op_to_op(create_epoch_operator, 10000.0, "eid") \
        >> (Op_to_op(create_groupby_operator,
                     partial(filter_groups, ["ipv4.dst"]),
                     counter, "pkts")
            >> next_op)


queries: list[Operator] = [(dump_as_csv(sys.stdout))]


def run_queries() -> None:
    [[query.next(packet) for query in queries] for packet in [PacketHeaders({
        "time": Op_result(Op_result.FLOAT, (0.000000 + cast(float, i))),
        "eth.src": Op_result(Op_result.MAC,
                             (bytearray(b"\x00\x11\x22\x33\x44\x55"))),
        "eth.dst": Op_result(Op_result.MAC,
                             (bytearray(b"\xAA\xBB\xCC\xDD\xEE\xFF"))),
        "eth.ethertype": Op_result(Op_result.INT, 0x0800),
        "ipv4.hlen": Op_result(Op_result.INT, 20),
        "ipv4.proto": Op_result(Op_result.INT, 6),
        "ipv4.len": Op_result(Op_result.INT, 60),
        "ipv4.src": Op_result(Op_result.IPV4, IPv4Address("127.0.0.1")),
        "ipv4.dst": Op_result(Op_result.IPV4,  IPv4Address("127.0.0.1")),
        "l4.sport": Op_result(Op_result.INT, 440),
        "l4.dport": Op_result(Op_result.INT, 50000),
        "l4.flags": Op_result(Op_result.INT, 10),
    }) for i in range(20)]]


def main():
    run_queries()
    print("Done")


if __name__ == "__main__":
    main()
