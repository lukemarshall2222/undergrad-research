from utils_translated import *
from builtins_translated import *
from functools import partial
import sys
from typing import cast

def ident(next_op: Operator) -> Operator:
    def remove_keys(packet: PacketHeaders) -> PacketHeaders:
        return PacketHeaders({key: val for key, val in packet.items()
                       if key != "eth.src" and key != "eth.dst"})
    return \
    Op_to_op(create_map_operator, remove_keys) \
    >> next_op

def count_pkts(next_op: Operator) -> Operator:
    return \
    Op_to_op(create_epoch_operator, 1.0, "eid") \
    >> (Op_to_op(create_groupby_operator, single_group, counter, "pkts") \
    >> next_op)

def pkts_per_src_dst(next_op: Operator) -> Operator:
    return \
    Op_to_op(create_epoch_operator, 1.0, "eid") \
    >> (Op_to_op(create_groupby_operator,
            partial(filter_groups, ["ipv4.src", "ipv4.dst"]), 
            counter, "pkts") \
    >> next_op)

def distinct_srcs(next_op: Operator) -> Operator:
    return \
    Op_to_op(create_epoch_operator, 1.0, "eid") \
    >> (Op_to_op(create_distinct_operator, 
                partial(filter_groups, ["ipv4.src"])) \
    >> (Op_to_op(create_groupby_operator, single_group, counter, "srcs") \
    >> next_op))

def tcp_new_cons(next_op: Operator) -> Operator:
    threshold: int = 40

    return \
    Op_to_op(create_epoch_operator, 1.0, "eid") \
    >> (Op_to_op(create_filter_operator, partial(filter_helper, 6, 2)) \
    >> (Op_to_op(create_groupby_operator, 
                partial(filter_groups, ["ipv4.dst"]), 
                counter, "cons") \
    >> (Op_to_op(create_filter_operator, 
                partial(key_geq_int, "cons", threshold)) \
    >> next_op)))

def ssh_brute_force(next_op: Operator) -> Operator:
    threshold: int = 40

    return \
    Op_to_op(create_epoch_operator, 1.0, "eid") \
    >> (Op_to_op(create_filter_operator, partial(filter_helper, 6, 22)) \
    >> (Op_to_op(create_distinct_operator, 
                partial(filter_groups, 
                ["ipv4.src", "ipv4.dst", "ipv4.len"])) \
    >> (Op_to_op(create_groupby_operator, 
                partial(filter_groups, ["ipv4.src", "ipv4.dst", "ipv4.len"]),
                counter, "srcs") \
    >> (Op_to_op(create_filter_operator, 
                partial(key_geq_int, "srcs", threshold)) \
    >> next_op))))
    

def super_spreader(next_op: Operator) -> Operator:
    threshold: int = 40
    return \
    Op_to_op(create_epoch_operator, 1.0, "eid") \
    >> (Op_to_op(create_distinct_operator, 
                partial(filter_groups, ["ipv4.src", "l4.dport"])) \
    >> (Op_to_op(create_groupby_operator, 
                partial(filter_groups, ["ipv4.src"]), counter, "ports") \
    >> (Op_to_op(create_filter_operator, 
                partial(key_geq_int, "ports", threshold)) \
    >> next_op)))

def ddos(next_op: Operator) -> Operator:
    threshold: int = 45
    return \
    Op_to_op(create_epoch_operator, 1.0, "eid") \
    >> (Op_to_op(create_distinct_operator, 
                partial(filter_groups, ["ipv4.src", "ipv4.dst"])) \
    >> (Op_to_op(create_groupby_operator, 
                partial(filter_groups, ["ipv4.dst"]), counter, "srcs") \
    >> (Op_to_op(create_filter_operator, 
                partial(key_geq_int, "srcs", threshold)) \
    >> next_op)))

def syn_flood_sonata(next_op: Operator) -> list[Operator]:
    threshold: int = 3
    epoch_dur: float = 1.0

    def syns(end_op: Operator) -> Operator:
        return \
        Op_to_op(create_epoch_operator, epoch_dur, "eid") \
        >> (Op_to_op(create_filter_operator, partial(filter_helper, 6, 2)) \
        >> (Op_to_op(create_groupby_operator, 
                    partial(filter_groups, ["ipv4.dst"]), counter, "syns") \
        >> end_op))
    
    def synacks(end_op: Operator) -> Operator:
        return \
        Op_to_op(create_epoch_operator, epoch_dur, "eid") \
        >> (Op_to_op(create_filter_operator, partial(filter_helper, 6, 18)) \
        >> (Op_to_op(create_groupby_operator, 
                    partial(filter_groups, ["ipv4.dst"]), 
                    counter, "synacks") \
        >> end_op))
    
    def acks(end_op: Operator) -> Operator:
        return \
        Op_to_op(create_epoch_operator, epoch_dur, "eid") \
        >> (Op_to_op(create_filter_operator, partial(filter_helper, 6, 16)) \
        >> (Op_to_op(create_groupby_operator,
                     partial(filter_groups, ["ipv4.dst"]), counter, "acks") \
        >> end_op))
    
    join_ops: tuple[Operator, Operator] = \
        Op_to_op_tup(create_join_operator, 
            lambda packet: 
                (filter_groups(["host"], packet), 
                filter_groups(["syns+synacks"], packet)), 
            lambda packet: 
                (rename_filtered_keys([("ipv4.dst","host")], packet), 
                 filter_groups(["acks"], packet))) \
    >> (Op_to_op(create_map_operator, 
            lambda packet:
                packet.__setitem__("syns+synacks-acks", Int( 
                        packet.get_mapped_int("syns+synacks") - 
                        packet.get_mapped_int("acks")))) \
    >> (Op_to_op(create_filter_operator, 
                partial(key_geq_int, "syns+synacks-acks", threshold)) \
    >> next_op))
    join_op1, join_op2 = join_ops

    join_ops = \
        Op_to_op_tup(create_join_operator,
            lambda packet:
                (rename_filtered_keys([("ipv4.dst","host")], packet), 
                filter_groups(["syns"], packet)), \
            lambda packet:
                (rename_filtered_keys([("ipv4.src","host")], packet), 
                filter_groups(["synacks"], packet))) \
        >> (Op_to_op(create_map_operator, lambda packet:
                packet.__setitem__
                ("syns+synacks", 
                Int( packet.get_mapped_int("syns") + 
                    packet.get_mapped_int("synacks")))) \
        >> join_op1)
    join_op3, join_op4 = join_ops

    return [
            Op_to_op(syns) >> join_op3, 
            Op_to_op(synacks) >> join_op4, 
            Op_to_op(acks) >> join_op2,
           ]

def completed_flows(next_op: Operator) -> list[Operator]:
    threshold: int = 1
    epoch_dur: float = 30.0

    def syns(next_op: Operator) -> Operator:
        return \
        Op_to_op(create_epoch_operator, epoch_dur, "eid") \
        >> (Op_to_op(create_filter_operator, 
            partial(filter_helper, 6, 2)) \
        >> (Op_to_op(create_groupby_operator, 
            partial(filter_groups, ["ipv4.src"]), 
            counter, "syns") \
        >> next_op))
    
    def fins(next_op: Operator) -> Operator:
        return \
        Op_to_op(create_epoch_operator, epoch_dur, "eid") \
        >> (Op_to_op(create_filter_operator, 
                    (lambda packet:
                        packet.get_mapped_int("ipv4.proto") == 6 and \
                        (packet.get_mapped_int("l4.flags") & 1) == 1)) \
        >> (Op_to_op(create_groupby_operator, 
                    partial(filter_groups, ["ipv4.src"]), 
                    counter, "fins") \
        >> next_op))

    operators: tuple[Operator, Operator] = \
        Op_to_op(create_join_operator, 
                (lambda packet:
                    (rename_filtered_keys([("ipv4.dst","host")], packet),
                    filter_groups(["syns"], packet))),
                (lambda packet:
                    (rename_filtered_keys([("ipv4.src","host")], packet),
                    filter_groups(["fins"], packet)))) \
        >> (Op_to_op_tup(create_map_operator,
                    (lambda packet:
                        packet.__setitem__
                        ("diff", Int( 
                        packet.get_mapped_int("syns") - 
                        packet.get_mapped_int("fins"))))) \
        >> (Op_to_op(create_filter_operator, 
            partial(key_geq_int, "diff", threshold)) \
        >> next_op))
    op1, op2 = operators

    return [
            Op_to_op(syns) >> op1,
            Op_to_op(fins) >> op2,
           ]

def slowloris(next_op: Operator) -> list[Operator]:
    t1: int = 5
    t2: int = 500
    t3: int = 90
    epoch_dur: float = 1.0

    def n_conns(next_op: Operator) -> Operator:
        return \
        Op_to_op(create_epoch_operator, epoch_dur, "eid") \
        >> (Op_to_op(create_filter_operator, 
                    (lambda packet: 
                        packet.get_mapped_int("ipv4.proto") == 6)) \
        >> (Op_to_op(create_distinct_operator, 
                    partial(filter_groups, 
                    ["ipv4.src", "ipv4.dst", "l4.sport"])) \
        >> (Op_to_op(create_groupby_operator, 
                    partial(filter_groups, ["ipv4.dst"]), 
                    counter, "n_conns") \
        >> (Op_to_op(create_filter_operator, 
                    (lambda packet: 
                        packet.get_mapped_int("n_conns") >= t1))\
        >> next_op))))

    def n_bytes(next_op: Operator) -> Operator:
        return \
        Op_to_op(create_epoch_operator, epoch_dur, "eid") \
        >> (Op_to_op(create_filter_operator, 
                    (lambda packet: 
                        packet.get_mapped_int("ipv4.proto") == 6)) \
        >> (Op_to_op(create_groupby_operator, 
            partial(filter_groups, ["ipv4.dst"]), 
            partial(sum_ints, "ipv4.len"), "n_bytes") \
        >> (Op_to_op(create_filter_operator, 
                    (lambda packet: 
                        packet.get_mapped_int("n_bytes") >= t2)) \
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
                        ("bytes_per_conn", Int( 
                        packet.get_mapped_int("n_bytes") - 
                        packet.get_mapped_int("n_conns"))))) \
        >> (Op_to_op(create_filter_operator,
                    (lambda packet:
                        packet.get_mapped_int("bytes_per_conn") <= t3)) \
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
        >> (Op_to_op(create_filter_operator, partial(filter_helper, 6, 2)) \
        >> next_op)
    
    def synacks(next_op: Operator) -> Operator:
        return \
        Op_to_op(create_epoch_operator, epoch_dur, "eid") \
        >> (Op_to_op(create_filter_operator, partial(filter_helper, 6, 18)) \
        >> next_op)
    
    operators: tuple[Operator, Operator] = \
        Op_to_op_tup(create_join_operator,
            (lambda packet: (rename_filtered_keys([("ipv4.src","host")], packet), 
                        (rename_filtered_keys([("ipv4.dst","remote")], packet)))),
            (lambda packet: ((rename_filtered_keys([("ipv4.dst","host")], packet)), 
                        (filter_groups(["time"] , packet))))) \
        >> next_op
    op1, op2 = operators
    return [
            Op_to_op(syns) >> op1, 
            Op_to_op(synacks) >> op2
           ]

def q3(next_op: Operator) -> Operator:
    return \
    Op_to_op(create_epoch_operator, 100.0, "eid") \
    >> (Op_to_op(create_distinct_operator, 
                partial(filter_groups, ["ipv4.src", "ipv4.dst"])) \
    >> next_op)

def q4(next_op: Operator) -> Operator:
    return \
    Op_to_op(create_epoch_operator, 10000.0, "eid") \
    >> (Op_to_op(create_groupby_operator, 
                partial(filter_groups, ["ipv4.dst"]), 
                counter, "pkts") \
    >> next_op)

queries: list[Operator] = [q4(dump_as_csv(sys.stdout))]

def run_queries() -> None:           
    [[query.next(packet) for query in queries] for packet in [PacketHeaders({
            "time": Float(0.000000 + cast(float, i)),
            "eth.src": MAC(bytearray(b"\x00\x11\x22\x33\x44\x55")),
            "eth.dst": MAC(bytearray(b"\xAA\xBB\xCC\xDD\xEE\xFF")),
            "eth.ethertype": Int(0x0800),
            "ipv4.hlen": Int(20+i),
            "ipv4.proto": Int(6),
            "ipv4.len": Int(60),
            "ipv4.src": Ipv4(IPv4Address("127.0.0.1")),
            "ipv4.dst": Ipv4(IPv4Address("192.6.8.1")),
            "l4.sport": Int(440),
            "l4.dport": Int(50000),
            "l4.flags": Int(10),
        }) for i in range(4)]]

def main():
    run_queries()
    print("Done")

if __name__ == "__main__":
    main()
