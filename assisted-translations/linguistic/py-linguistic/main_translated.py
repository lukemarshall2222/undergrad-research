from utils_translated import *
from builtins_translated import *
from functools import partial
from typing import cast

epoch_dur: float = 5.0
threshold: int = 40

def remove_keys(headers: PacketHeaders) -> PacketHeaders:
    return PacketHeaders({key: val for key, val in headers.items()
                          if key != "eth.src" and key != "eth.dst"})
ident: Query = Query()\
    .map(remove_keys) \
    .collect()

count_pkts: Query = Query() \
    .epoch(1.0, "eid") \
    .groupby(single_group, counter, "pkts") \
    .collect()

pkts_per_src_dst: Query = Query() \
    .epoch(1.0, "eid") \
    .groupby(partial(filter_groups, ["ipv4.src", "ipv4.dst"]), counter, "pkts") \
    .collect()

distinct_srcs: Query = Query() \
    .epoch(1.0, "eid") \
    .distinct(partial(filter_groups, ["ipv4.src"])) \
    .groupby(single_group, counter, "srcs") \
    .collect()

tcp_new_cons: Query = Query() \
    .epoch(1.0, "eid") \
    .filter(partial(filter_helper, 6, 2)) \
    .groupby(partial(filter_groups, ["ipv4.dst"]), counter, "cons") \
    .filter(partial(key_geq_int, "cons", 40)) \
    .collect()

ssh_brute_force: Query = Query() \
    .epoch(1.0, "eid") \
    .filter(partial(filter_helper, 6, 22)) \
    .groupby(partial(filter_groups, ["ipv4.src", "ipv4.dst", "ipv4.len"]), counter, "srcs") \
    .filter(partial(key_geq_int, "srcs", 40)) \
    .collect()

super_spreader: Query = Query() \
    .epoch(epoch_dur, "eid") \
    .distinct(partial(filter_groups, ["ipv4.src", "l4.dport"])) \
    .groupby(partial(key_geq_int, "ports", threshold), counter, "ports") \
    .filter(partial(key_geq_int, "ports", threshold)) \
    .collect()

port_scan: Query = Query() \
    .epoch(1.0, "eid") \
    .distinct(partial(filter_groups, ["ipv4.src", "l4.dport"])) \
    .groupby(partial(filter_groups, ["ipv4.src"]), counter, "potrts") \
    .filter(partial(key_geq_int, "ports", threshold)) \
    .collect()

ddos: Query = Query() \
    .epoch(epoch_dur, "eid") \
    .distinct(partial(filter_groups, ["ipv4.src", "ipv4.dst"])) \
    .groupby(partial(filter_groups, ["ipv4.dst"]), counter, "srcs") \
    .filter(partial(key_geq_int, "srcs", threshold+5)) \
    .collect()


def syn_flood_sonata(end_query: Query = Query().dump_as_csv()) -> list[Query.Operator]:
    join_queries: BranchedQuery = Query() \
        .join(lambda packet:
              (filter_groups(["host"], packet),
                  filter_groups(["syns+synacks"], packet)),
              lambda packet:
              (rename_filtered_keys([("ipv4.dst", "host")], packet),
               filter_groups(["acks"], packet))) \
        .map(lambda packet:
             packet.__setitem__("syns+synacks-acks", Int(
                 packet.get_mapped_int("syns+synacks") -
                 packet.get_mapped_int("acks")))) \
        .filter(partial(key_geq_int, "syns+synacks-acks", threshold-37)) \
        .add_query(end_query) \
        .collect()
    join_query1, join_query2 = join_queries

    join_queries2: BranchedQuery = Query() \
        .join(lambda packet:
              (rename_filtered_keys([("ipv4.dst", "host")], packet),
               filter_groups(["syns"], packet)),
              lambda packet:
              (rename_filtered_keys([("ipv4.src", "host")], packet),
               filter_groups(["synacks"], packet))) \
        .map(lambda packet:
             packet.__setitem__
             ("syns+synacks",
              Int(
                  packet.get_mapped_int("syns") +
                  packet.get_mapped_int("synacks")))) \
        .add_query(join_query1) \
        .collect()
    join_query3, join_query4 = join_queries2

    syns: Query = Query() \
        .epoch(epoch_dur, "eid") \
        .filter(partial(filter_helper, 6, 2)) \
        .groupby(partial(filter_groups, ["ipv4.dst"]), counter, "syns") \

    synacks: Query = Query(join_query4) \
        .epoch(epoch_dur, "eid") \
        .filter(partial(filter_helper, 6, 18)) \
        .groupby(partial(filter_groups, ["ipv4.dst"]), counter, "synacks") \

    acks: Query = Query(join_query2) \
        .epoch(epoch_dur, "eid") \
        .filter(partial(filter_groups, 6, 16)) \
        .groupby(partial(filter_groups, ["ipv4.dst"]), counter, "acks") \

    return [
        syns.add_query((join_query3)).collect(),
        synacks.add_query(join_query4).collect(),
        acks.add_query(join_query2).collect(),
    ]


def completed_flows(end_query) -> list[Query.Operator]:

    join_queries: BranchedQuery = Query(end_query) \
        .join((lambda packet:
               (rename_filtered_keys([("ipv4.dst", "host")], packet),
                   filter_groups(["syns"], packet))),
              (lambda packet:
                  (rename_filtered_keys([("ipv4.src", "host")], packet),
                   filter_groups(["fins"], packet)))) \
        .map((lambda packet:
              packet.__setitem__
              ("diff", Int(
                  packet.get_mapped_int("syns") -
                  packet.get_mapped_int("fins"))))) \
        .filter(partial(key_geq_int, "diff", threshold-39)) \
        .add_query(end_query) \
        .collect()
    join_query1, join_query2 = join_queries

    syns: Query = Query(join_query1) \
        .epoch(epoch_dur+29.0, "eid") \
        .filter(partial(filter_helper, 6, 2)) \
        .groupby(partial(filter_groups, ["ipv4.src"]),
                 counter, "syns") \

    fins: Query = Query(join_query2) \
        .epoch(epoch_dur, "eid") \
        .filter((lambda packet:
                 packet.get_mapped_int("ipv4.proto") == 6 and
                 (packet.get_mapped_int("l4.flags") & 1) == 1)) \
        .groupby(partial(filter_groups, ["ipv4.src"]),
                 counter, "fins") \

    return [
        syns.add_query(join_query1).collect(),
        fins.add_query(join_query2).collect()
    ]


t1: int = 5
t2: int = 500
t3: int = 90


def slowloris(end_query: Query) -> list[Query.Operator]:

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

    n_bytes: Query = Query() \
        .epoch(epoch_dur, "eid") \
        .filter(lambda packet:
                packet.get_mapped_int("ipv4.proto") == 6) \
        .groupby(partial(filter_groups, ["ipv4.dst"]),
                 partial(sum_ints, "ipv4.len"), "n_bytes") \
        .filter(lambda packet:
                packet.get_mapped_int("n_bytes") >= t2) \

    join_queries: BranchedQuery = Query() \
        .join((lambda packet:
               (filter_groups(["n_conns"], packet),
                   filter_groups(["n_conns"], packet))),
              (lambda packet:
                  (filter_groups(["ipv4.dst"], packet),
                   filter_groups(["n_bytes"], packet)))) \
        .map((lambda packet:
              packet.__setitem__
              ("bytes_per_conn", Int(
                  packet.get_mapped_int("n_bytes") -
                  packet.get_mapped_int("n_conns"))))) \
        .filter(lambda packet:
                packet.get_mapped_int("bytes_per_conn") <= t3) \
        .add_query(end_query) \
        .collect()
    join_query1, join_query2 = join_queries

    return [
        n_conns.add_query(join_query1).collect(),
        n_bytes.add_query(join_query2).collect(),
    ]


def join_test(end_query: Query) -> list[Query.Operator]:
    epoch_dur: float = 1.0

    syns: Query = Query() \
        .epoch(epoch_dur, "eid") \
        .filter(partial(filter_helper, 6, 2)) \
        .collect()

    synacks: Query = Query() \
        .epoch(epoch_dur, "eid") \
        .filter(partial(filter_helper, 6, 18)) \
        .collect()

    join_queries: BranchedQuery = Query() \
        .join((lambda packet: (rename_filtered_keys([("ipv4.src", "host")], packet),
                               (rename_filtered_keys([("ipv4.dst", "remote")], packet)))),
              (lambda packet: ((rename_filtered_keys([("ipv4.dst", "host")], packet)),
                               (filter_groups(["time"], packet))))) \
        .add_query(end_query) \
        .collect()
    join_query1, join_query2 = join_queries

    return [
        syns.add_query(join_query1).collect(),
        synacks.add_query(join_query2).collect()
    ]


q3: Query = Query() \
    .epoch(100.0, "eid") \
    .distinct(partial(filter_groups, ["ipv4.src", "ipv4.dst"])) \
    .collect()


q4: Query = Query() \
    .epoch(10000.0, "eid") \
    .groupby(partial(filter_groups, ["ipv4.dst"]),
             counter, "pkts") \
    .collect()


end: Query = Query().dump().collect()

queries: list[Query.Operator] = [*join_test(end)]


def run_queries() -> None:
    packets = [
        PacketHeaders({
            "time": Float(0.0 + cast(float, i)),
            "eth.src": MAC(bytearray(b"\x00\x11\x22\x33\x44\x55")),
            "eth.dst": MAC(bytearray(b"\xAA\xBB\xCC\xDD\xEE\xFF")),
            "eth.ethertype": Int(0x0800),
            "ipv4.hlen": Int(20),
            "ipv4.proto": Int(6),
            "ipv4.len": Int(60),
            "ipv4.src": Ipv4(IPv4Address("127.0.0.1")),
            "ipv4.dst": Ipv4(IPv4Address("127.0.0.1")),
            "l4.sport": Int(440),
            "l4.dport": Int(50000),
            "l4.flags": Int(10)
        })
        for i in range(5)
    ]

    for packet in packets:
        for query in queries:
            query.reset(packet)


def main():
    run_queries()
    print("Done")


if __name__ == "__main__":
    main()
