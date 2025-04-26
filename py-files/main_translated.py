from utils_translated import *
from builtins_translated import *
from functools import partial
from sys import stdout
from typing import cast, Callable

epoch_dur: float = 5.0
threshold: int = 40

ident = Query()\
    .map(remove_keys) \
    .collect()

count_pkts = Query() \
    .epoch(1.0, "eid") \
    .groupby(single_group, counter, "pkts") \
    .collect()

pkts_per_src_dst = Query() \
    .epoch(1.0, "eid") \
    .groupby(partial(filter_groups, ["ipv4.src", "ipv4.dst"]), counter, "pkts") \
    .collect()

distinct_srcs = Query() \
    .epoch(1.0, "eid") \
    .distinct(partial(filter_groups, ["ipv4.src"])) \
    .groupby(single_group, counter, "srcs") \
    .collect()

tcp_new_cons = Query() \
    .epoch(1.0, "eid") \
    .filter(partial(filter_helper, 6, 2)) \
    .groupby(partial(filter_groups, ["ipv4.dst"]), counter, "cons") \
    .filter(partial(key_geq_int, "cons", 40)) \
    .collect()

ssh_brute_force = Query() \
    .epoch(1.0, "eid") \
    .filter(partial(filter_helper, 6, 22)) \
    .groupby(partial(filter_groups, ["ipv4.src", "ipv4.dst", "ipv4.len"]), counter, "srcs") \
    .filter(partial(key_geq_int, "srcs", 40)) \
    .collect()

super_spreader = Query() \
    .epoch(epoch_dur, "eid") \
    .distinct(partial(filter_groups, ["ipv4.src", "l4.dport"])) \
    .groupby(partial(key_geq_int, "ports", threshold), counter, "ports") \
    .filter(partial(key_geq_int, "ports", threshold)) \
    .collect()

ddos = Query() \
    .epoch(epoch_dur, "eid") \
    .distinct(partial(filter_groups, ["ipv4.src", "ipv4.dst"])) \
    .groupby(partial(filter_groups, ["ipv4.dst"]), counter, "srcs") \
    .filter(partial(key_geq_int, "srcs", threshold+5)) \
    .collect()


def syn_flood_sonata(next_op: Query = Query().continue_flow()) -> list[QueryMethods]:
    join_queries: BranchedQuery = Query() \
        .join(lambda packet:
              (filter_groups(["host"], packet),
                  filter_groups(["syns+synacks"], packet)),
              lambda packet:
              (rename_filtered_keys([("ipv4.dst", "host")], packet),
               filter_groups(["acks"], packet))) \
        .map(lambda packet:
             packet.__setitem__("syns+synacks-acks", Op_result(Op_result.INT,
                                                               packet.get_mapped_int("syns+synacks") -
                                                               packet.get_mapped_int("acks")))) \
        .filter(partial(key_geq_int, "syns+synacks-acks", threshold-37)) \
        .add_query(next_op) \
        .collect()
    join_query1, join_query2 = join_queries

    join_queries2: BranchedQuery = Query(join_query1) \
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
               filter_groups(["synacks"], packet))) \
        .add_query(join_query1) \
        .collect()
    join_query3, join_query4 = join_queries2

    syns: Query = Query() \
        .epoch(epoch_dur, "eid") \
        .filter(partial(filter_helper, 6, 2)) \
        .groupby(partial(filter_groups, ["ipv4.dst"]), counter, "syns") \
        .add_query(next_op) \
        .collect()

    synacks: Query = Query(join_query4) \
        .epoch(epoch_dur, "eid") \
        .filter(partial(filter_helper, 6, 18)) \
        .groupby(partial(filter_groups, ["ipv4.dst"]), counter, "synacks") \
        .add_query(next_op) \

    acks: Query = Query(join_query2) \
        .epoch(epoch_dur, "eid") \
        .filter(partial(filter_groups, 6, 16)) \
        .groupby(partial(filter_groups, ["ipv4.dst"]), counter, "acks") \
        .add_query(next_op) \

    return [
        syns.add_query((join_query3)).collect(),
        synacks.add_query(join_query4).collect(),
        acks.add_query(join_query2).collect(),
    ]


def completed_flows(next_query: Query = Query().continue_flow()) -> list[QueryMethods]:

    join_queries: BranchedQuery = Query(next_query) \
        .join((lambda packet:
               (rename_filtered_keys([("ipv4.dst", "host")], packet),
                   filter_groups(["syns"], packet))),
              (lambda packet:
                  (rename_filtered_keys([("ipv4.src", "host")], packet),
                   filter_groups(["fins"], packet)))) \
        .map((lambda packet:
              packet.__setitem__
              ("diff", Op_result(Op_result.INT,
                                 packet.get_mapped_int("syns") -
                                 packet.get_mapped_int("fins"))))) \
        .filter(partial(key_geq_int, "diff", threshold-39)) \
        .add_query(next_query) \
        .collect()
    join_query1, join_query2 = join_queries

    syns: Query = Query(join_query1) \
        .epoch(epoch_dur+29.0, "eid") \
        .filter(partial(filter_helper, 6, 2)) \
        .groupby(partial(filter_groups, ["ipv4.src"]),
                 counter, "syns") \
        .add_query(next_query) \

    fins: Query = Query(join_query2) \
        .epoch(epoch_dur, "eid") \
        .filter((lambda packet:
                 packet.get_mapped_int("ipv4.proto") == 6 and
                 (packet.get_mapped_int("l4.flags") & 1) == 1)) \
        .groupby(partial(filter_groups, ["ipv4.src"]),
                 counter, "fins") \
        .add_query(next_query) \

    return [
        syns.add_query(join_query1).collect(),
        fins.add_query(join_query2).collect()
    ]


t1: int = 5
t2: int = 500
t3: int = 90


def slowloris(next_query: Query = Query().continue_flow()) -> list[QueryMethods]:

    n_conns: Query = Query() \
        .epoch(epoch_dur, "eid") \
        .filter(lambda packet:
                packet.get_mapped_int("ipv4.proto") == 6) \
        .distinct(partial(filter_groups,
                          ["ipv4.src", "ipv4.dst", "l4.sport"])) \
        .groupby(partial(filter_groups, ["ipv4.dst"]),
                 counter, "n_conns") \
        .filter(lambda packet:
                packet.get_mapped_int("n_conns") >= t1) \
        .add_query(next_query) \

    n_bytes: Query = Query() \
        .epoch(epoch_dur, "eid") \
        .filter(lambda packet:
                packet.get_mapped_int("ipv4.proto") == 6) \
        .groupby(partial(filter_groups, ["ipv4.dst"]),
                 partial(sum_ints, "ipv4.len"), "n_bytes") \
        .filter(lambda packet:
                packet.get_mapped_int("n_bytes") >= t2) \
        .add_query(next_query)

    join_queries: BranchedQuery[Query, Query] = Query() \
        .join((lambda packet:
               (filter_groups(["n_conns"], packet),
                   filter_groups(["n_conns"], packet))),
              (lambda packet:
                  (filter_groups(["ipv4.dst"], packet),
                   filter_groups(["n_bytes"], packet)))) \
        .map((lambda packet:
              packet.__setitem__
              ("bytes_per_conn", Op_result(Op_result.INT,
                                           packet.get_mapped_int("n_bytes") -
                                           packet.get_mapped_int("n_conns"))))) \
        .filter(lambda packet:
                packet.get_mapped_int("bytes_per_conn") <= t3) \
        .add_query(next_query) \
        .collect()
    join_query1, join_query2 = join_queries

    return [
        n_conns.add_query(join_query1),
        n_bytes.add_query(join_query2),
    ]


def create_join_operator_test(next_query: Query = Query().continue_flow()) -> list[QueryMethods]:
    epoch_dur: float = 1.0

    syns: Query = Query() \
        .epoch(epoch_dur, "eid") \
        .filter(partial(filter_helper, 6, 2)) \
        .add_query(next_query)

    synacks: Query = Query() \
        .epoch(epoch_dur, "eid") \
        .filter(partial(filter_helper, 6, 18)) \
        .add_query(next_query)

    join_queries: BranchedQuery = Query() \
        .join((lambda packet: (rename_filtered_keys([("ipv4.src", "host")], packet),
                               (rename_filtered_keys([("ipv4.dst", "remote")], packet)))),
              (lambda packet: ((rename_filtered_keys([("ipv4.dst", "host")], packet)),
                               (filter_groups(["time"], packet))))) \
        .add_query(next_query) \
        .collect()
    join_query1, join_query2 = join_queries

    return [
        syns.add_query(join_query1),
        synacks.add_query(join_query2)
    ]


q3: Callable[[Query], QueryMethods] = lambda next_query=Query.dump(): Query() \
    .epoch(100.0, "eid") \
    .distinct(partial(filter_groups, ["ipv4.src", "ipv4.dst"])) \
    .add_query(next_query) \
    .collect()

q4: Callable[[Query], QueryMethods] = lambda next_query=Query.dump(): Query() \
    .epoch(10000.0, "eid") \
    .groupby(partial(filter_groups, ["ipv4.dst"]),
             counter, "pkts") \
    .add_query(next_query) \
    .collect()


queries: list[QueryMethods] = [Query().dump_as_csv(stdout).collect()]


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
