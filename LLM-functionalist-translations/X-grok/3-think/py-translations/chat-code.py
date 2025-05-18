###given as a file named: stream_processing.py

import sys
import ipaddress
from typing import Dict, List, Tuple, Callable, Optional
from io import TextIOWrapper

# OpResult variants
class OpResult:
    pass

class Float(OpResult):
    def __init__(self, value: float):
        self.value = value

class Int(OpResult):
    def __init__(self, value: int):
        self.value = value

class IPv4(OpResult):
    def __init__(self, value: ipaddress.IPv4Address):
        self.value = value

class MAC(OpResult):
    def __init__(self, value: bytes):
        self.value = value

class Empty(OpResult):
    pass

# Tuple is a dictionary from strings to OpResult
TupleType = Dict[str, OpResult]

# Operator base class
class Operator:
    def next(self, tup: TupleType) -> None:
        raise NotImplementedError

    def reset(self, tup: TupleType) -> None:
        raise NotImplementedError

# Conversion utilities
def string_of_mac(buf: bytes) -> str:
    return ":".join(f"{byte:02x}" for byte in buf[:6])

def tcp_flags_to_strings(flags: int) -> str:
    flag_names = {
        "FIN": 1 << 0,
        "SYN": 1 << 1,
        "RST": 1 << 2,
        "PSH": 1 << 3,
        "ACK": 1 << 4,
        "URG": 1 << 5,
        "ECE": 1 << 6,
        "CWR": 1 << 7,
    }
    return "|".join(name for name, value in flag_names.items() if flags & value == value)

def int_of_op_result(input: OpResult) -> int:
    if isinstance(input, Int):
        return input.value
    raise ValueError("Trying to extract int from non-int result")

def float_of_op_result(input: OpResult) -> float:
    if isinstance(input, Float):
        return input.value
    raise ValueError("Trying to extract float from non-float result")

def string_of_op_result(input: OpResult) -> str:
    if isinstance(input, Float):
        return str(input.value)
    elif isinstance(input, Int):
        return str(input.value)
    elif isinstance(input, IPv4):
        return str(input.value)
    elif isinstance(input, MAC):
        return string_of_mac(input.value)
    elif isinstance(input, Empty):
        return "Empty"
    raise ValueError("Unknown OpResult type")

def string_of_tuple(input_tuple: TupleType) -> str:
    return ", ".join(f'"{key}" => {string_of_op_result(value)}' for key, value in input_tuple.items())

def tuple_of_list(tup_list: List[Tuple[str, OpResult]]) -> TupleType:
    return dict(tup_list)

def dump_tuple(outc: TextIOWrapper, tup: TupleType) -> None:
    print(string_of_tuple(tup), file=outc)

def lookup_int(key: str, tup: TupleType) -> int:
    return int_of_op_result(tup[key])

def lookup_float(key: str, tup: TupleType) -> float:
    return float_of_op_result(tup[key])

# Built-in operator definitions
INIT_TABLE_SIZE = 10000

class DumpTupleOperator(Operator):
    def __init__(self, outc: TextIOWrapper, show_reset: bool = False):
        self.outc = outc
        self.show_reset = show_reset

    def next(self, tup: TupleType):
        dump_tuple(self.outc, tup)

    def reset(self, tup: TupleType):
        if self.show_reset:
            dump_tuple(self.outc, tup)
            print("[reset]", file=self.outc)

class DumpAsCsvOperator(Operator):
    def __init__(self, outc: TextIOWrapper, static_field: Optional[Tuple[str, str]] = None, header: bool = True):
        self.outc = outc
        self.static_field = static_field
        self.first = header

    def next(self, tup: TupleType):
        if self.first:
            if self.static_field:
                print(f"{self.static_field[0]},", end="", file=self.outc)
            print(",".join(tup.keys()), file=self.outc)
            self.first = False
        if self.static_field:
            print(f"{self.static_field[1]},", end="", file=self.outc)
        print(",".join(string_of_op_result(value) for value in tup.values()), file=self.outc)

    def reset(self, tup: TupleType):
        pass

class DumpWaltsCsvOperator(Operator):
    def __init__(self, filename: str):
        self.filename = filename
        self.outc = sys.stdout
        self.first = True

    def next(self, tup: TupleType):
        if self.first:
            self.outc = open(self.filename, 'w')
            self.first = False
        print(f"{tup['src_ip']},{tup['dst_ip']},{tup['src_l4_port']},{tup['dst_l4_port']},"
              f"{tup['packet_count']},{tup['byte_count']},{tup['epoch_id']}", file=self.outc)

    def reset(self, tup: TupleType):
        pass

def get_ip_or_zero(input: str) -> OpResult:
    if input == "0":
        return Int(0)
    return IPv4(ipaddress.IPv4Address(input))

class EpochOperator(Operator):
    def __init__(self, epoch_width: float, key_out: str, next_op: Operator):
        self.epoch_width = epoch_width
        self.key_out = key_out
        self.next_op = next_op
        self.epoch_boundary = 0.0
        self.eid = 0

    def next(self, tup: TupleType):
        time = lookup_float("time", tup)
        if self.epoch_boundary == 0.0:
            self.epoch_boundary = time + self.epoch_width
        elif time >= self.epoch_boundary:
            while time >= self.epoch_boundary:
                self.next_op.reset({self.key_out: Int(self.eid)})
                self.epoch_boundary += self.epoch_width
                self.eid += 1
        self.next_op.next({**tup, self.key_out: Int(self.eid)})

    def reset(self, tup: TupleType):
        self.next_op.reset({self.key_out: Int(self.eid)})
        self.epoch_boundary = 0.0
        self.eid = 0

class FilterOperator(Operator):
    def __init__(self, f: Callable[[TupleType], bool], next_op: Operator):
        self.f = f
        self.next_op = next_op

    def next(self, tup: TupleType):
        if self.f(tup):
            self.next_op.next(tup)

    def reset(self, tup: TupleType):
        self.next_op.reset(tup)

def key_geq_int(key: str, threshold: int) -> Callable[[TupleType], bool]:
    def f(tup: TupleType) -> bool:
        return lookup_int(key, tup) >= threshold
    return f

def get_mapped_int(key: str, tup: TupleType) -> int:
    return lookup_int(key, tup)

def get_mapped_float(key: str, tup: TupleType) -> float:
    return lookup_float(key, tup)

class MapOperator(Operator):
    def __init__(self, f: Callable[[TupleType], TupleType], next_op: Operator):
        self.f = f
        self.next_op = next_op

    def next(self, tup: TupleType):
        self.next_op.next(self.f(tup))

    def reset(self, tup: TupleType):
        self.next_op.reset(tup)

def make_hashable(key: TupleType) -> tuple:
    return tuple(sorted((k, v.value) for k, v in key.items()))

class GroupByOperator(Operator):
    def __init__(self, groupby: Callable[[TupleType], TupleType], reduce: Callable[[OpResult, TupleType], OpResult],
                 out_key: str, next_op: Operator):
        self.groupby = groupby
        self.reduce = reduce
        self.out_key = out_key
        self.next_op = next_op
        self.h_tbl = {}  # Dict[tuple, Tuple[TupleType, OpResult]]
        self.reset_counter = 0

    def next(self, tup: TupleType):
        grouping_key = self.groupby(tup)
        hash_key = make_hashable(grouping_key)
        if hash_key in self.h_tbl:
            _, val = self.h_tbl[hash_key]
            new_val = self.reduce(val, tup)
            self.h_tbl[hash_key] = (grouping_key, new_val)
        else:
            new_val = self.reduce(Empty(), tup)
            self.h_tbl[hash_key] = (grouping_key, new_val)

    def reset(self, tup: TupleType):
        self.reset_counter += 1
        for grouping_key, val in self.h_tbl.values():
            unioned_tup = {**tup, **grouping_key}
            final_tup = {**unioned_tup, self.out_key: val}
            self.next_op.next(final_tup)
        self.next_op.reset(tup)
        self.h_tbl.clear()

def filter_groups(incl_keys: List[str]) -> Callable[[TupleType], TupleType]:
    def f(tup: TupleType) -> TupleType:
        return {k: v for k, v in tup.items() if k in incl_keys}
    return f

def single_group(_: TupleType) -> TupleType:
    return {}

def counter(val: OpResult, _: TupleType) -> OpResult:
    if isinstance(val, Empty):
        return Int(1)
    elif isinstance(val, Int):
        return Int(val.value + 1)
    return val

def sum_ints(search_key: str) -> Callable[[OpResult, TupleType], OpResult]:
    def f(init_val: OpResult, tup: TupleType) -> OpResult:
        if isinstance(init_val, Empty):
            return Int(0)
        elif isinstance(init_val, Int):
            if search_key in tup and isinstance(tup[search_key], Int):
                return Int(tup[search_key].value + init_val.value)
            raise ValueError(f"'sum_ints' failed to find integer value mapped to '{search_key}'")
        return init_val
    return f

class DistinctOperator(Operator):
    def __init__(self, groupby: Callable[[TupleType], TupleType], next_op: Operator):
        self.groupby = groupby
        self.next_op = next_op
        self.seen = {}  # Dict[tuple, TupleType]
        self.reset_counter = 0

    def next(self, tup: TupleType):
        grouping_key = self.groupby(tup)
        hash_key = make_hashable(grouping_key)
        if hash_key not in self.seen:
            self.seen[hash_key] = grouping_key

    def reset(self, tup: TupleType):
        self.reset_counter += 1
        for grouping_key in self.seen.values():
            merged_tup = {**tup, **grouping_key}
            self.next_op.next(merged_tup)
        self.next_op.reset(tup)
        self.seen.clear()

class SplitOperator(Operator):
    def __init__(self, left: Operator, right: Operator):
        self.left = left
        self.right = right

    def next(self, tup: TupleType):
        self.left.next(tup)
        self.right.next(tup)

    def reset(self, tup: TupleType):
        self.left.reset(tup)
        self.right.reset(tup)

def join(eid_key: str, left_extractor: Callable[[TupleType], Tuple[TupleType, TupleType]],
         right_extractor: Callable[[TupleType], Tuple[TupleType, TupleType]], next_op: Operator) -> Tuple[Operator, Operator]:
    eid_key = "eid" if eid_key == None else eid_key
    h_tbl1 = {}
    h_tbl2 = {}
    left_curr_epoch = 0
    right_curr_epoch = 0

    class JoinSideOperator(Operator):
        def __init__(self, curr_h_tbl, other_h_tbl, curr_epoch_ref, other_epoch_ref, f):
            self.curr_h_tbl = curr_h_tbl
            self.other_h_tbl = other_h_tbl
            self.curr_epoch_ref = [curr_epoch_ref]  # Mutable reference
            self.other_epoch_ref = [other_epoch_ref]
            self.f = f
            self.next_op = next_op

        def next(self, tup: TupleType):
            key, vals_ = self.f(tup)
            curr_epoch = get_mapped_int(eid_key, tup)
            while curr_epoch > self.curr_epoch_ref[0]:
                if self.other_epoch_ref[0] > self.curr_epoch_ref[0]:
                    self.next_op.reset({eid_key: Int(self.curr_epoch_ref[0])})
                self.curr_epoch_ref[0] += 1
            new_tup = {**key, eid_key: Int(curr_epoch)}
            hash_key = make_hashable(new_tup)
            if hash_key in self.other_h_tbl:
                val_ = self.other_h_tbl.pop(hash_key)
                self.next_op.next({**new_tup, **vals_, **val_})
            else:
                self.curr_h_tbl[hash_key] = vals_

        def reset(self, tup: TupleType):
            curr_epoch = get_mapped_int(eid_key, tup)
            while curr_epoch > self.curr_epoch_ref[0]:
                if self.other_epoch_ref[0] > self.curr_epoch_ref[0]:
                    self.next_op.reset({eid_key: Int(self.curr_epoch_ref[0])})
                self.curr_epoch_ref[0] += 1

    left_op = JoinSideOperator(h_tbl1, h_tbl2, left_curr_epoch, right_curr_epoch, left_extractor)
    right_op = JoinSideOperator(h_tbl2, h_tbl1, right_curr_epoch, left_curr_epoch, right_extractor)
    return left_op, right_op

def rename_filtered_keys(renamings_pairs: List[Tuple[str, str]]) -> Callable[[TupleType], TupleType]:
    def f(in_tup: TupleType) -> TupleType:
        new_tup = {}
        for old_key, new_key in renamings_pairs:
            if old_key in in_tup:
                new_tup[new_key] = in_tup[old_key]
        return new_tup
    return f

# Query definitions
def ident(next_op: Operator) -> Operator:
    def filter_func(tup: TupleType) -> TupleType:
        return {k: v for k, v in tup.items() if k != "eth.src" and k != "eth.dst"}
    return MapOperator(filter_func, next_op)

def count_pkts(next_op: Operator) -> Operator:
    return EpochOperator(1.0, "eid", GroupByOperator(single_group, counter, "pkts", next_op))

def pkts_per_src_dst(next_op: Operator) -> Operator:
    return EpochOperator(1.0, "eid", GroupByOperator(filter_groups(["ipv4.src", "ipv4.dst"]), counter, "pkts", next_op))

def distinct_srcs(next_op: Operator) -> Operator:
    return EpochOperator(1.0, "eid", DistinctOperator(filter_groups(["ipv4.src"]), GroupByOperator(single_group, counter, "srcs", next_op)))

def tcp_new_cons(next_op: Operator) -> Operator:
    threshold = 40
    def tcp_filter(tup: TupleType) -> bool:
        return get_mapped_int("ipv4.proto", tup) == 6 and get_mapped_int("l4.flags", tup) == 2
    return EpochOperator(1.0, "eid", FilterOperator(tcp_filter, GroupByOperator(filter_groups(["ipv4.dst"]), counter, "cons", FilterOperator(key_geq_int("cons", threshold), next_op))))

def ssh_brute_force(next_op: Operator) -> Operator:
    threshold = 40
    def ssh_filter(tup: TupleType) -> bool:
        return get_mapped_int("ipv4.proto", tup) == 6 and get_mapped_int("l4.dport", tup) == 22
    return EpochOperator(1.0, "eid", FilterOperator(ssh_filter, DistinctOperator(filter_groups(["ipv4.src", "ipv4.dst", "ipv4.len"]), GroupByOperator(filter_groups(["ipv4.dst", "ipv4.len"]), counter, "srcs", FilterOperator(key_geq_int("srcs", threshold), next_op)))))

def super_spreader(next_op: Operator) -> Operator:
    threshold = 40
    return EpochOperator(1.0, "eid", DistinctOperator(filter_groups(["ipv4.src", "ipv4.dst"]), GroupByOperator(filter_groups(["ipv4.src"]), counter, "dsts", FilterOperator(key_geq_int("dsts", threshold), next_op))))

def port_scan(next_op: Operator) -> Operator:
    threshold = 40
    return EpochOperator(1.0, "eid", DistinctOperator(filter_groups(["ipv4.src", "l4.dport"]), GroupByOperator(filter_groups(["ipv4.src"]), counter, "ports", FilterOperator(key_geq_int("ports", threshold), next_op))))

def ddos(next_op: Operator) -> Operator:
    threshold = 45
    return EpochOperator(1.0, "eid", DistinctOperator(filter_groups(["ipv4.src", "ipv4.dst"]), GroupByOperator(filter_groups(["ipv4.dst"]), counter, "srcs", FilterOperator(key_geq_int("srcs", threshold), next_op))))

def syn_flood_sonata(next_op: Operator) -> List[Operator]:
    threshold = 3
    epoch_dur = 1.0

    def syns_filter(tup: TupleType) -> bool:
        return get_mapped_int("ipv4.proto", tup) == 6 and get_mapped_int("l4.flags", tup) == 2
    def synacks_filter(tup: TupleType) -> bool:
        return get_mapped_int("ipv4.proto", tup) == 6 and get_mapped_int("l4.flags", tup) == 18
    def acks_filter(tup: TupleType) -> bool:
        return get_mapped_int("ipv4.proto", tup) == 6 and get_mapped_int("l4.flags", tup) == 16

    syns_op = EpochOperator(epoch_dur, "eid", FilterOperator(syns_filter, GroupByOperator(filter_groups(["ipv4.dst"]), counter, "syns", Operator())))
    synacks_op = EpochOperator(epoch_dur, "eid", FilterOperator(synacks_filter, GroupByOperator(filter_groups(["ipv4.src"]), counter, "synacks", Operator())))
    acks_op = EpochOperator(epoch_dur, "eid", FilterOperator(acks_filter, GroupByOperator(filter_groups(["ipv4.dst"]), counter, "acks", Operator())))

    join_op1, join_op2 = join("eid",
        left_extractor=lambda tup: (filter_groups(["host"])(tup), filter_groups(["syns+synacks"])(tup)),
        right_extractor=lambda tup: (rename_filtered_keys([("ipv4.dst", "host")])(tup), filter_groups(["acks"])(tup)),
        next_op=MapOperator(
            lambda tup: {**tup, "syns+synacks-acks": Int(get_mapped_int("syns+synacks", tup) - get_mapped_int("acks", tup))},
            FilterOperator(key_geq_int("syns+synacks-acks", threshold), next_op)
        )
    )
    join_op3, join_op4 = join("eid",
        left_extractor=lambda tup: (rename_filtered_keys([("ipv4.dst", "host")])(tup), filter_groups(["syns"])(tup)),
        right_extractor=lambda tup: (rename_filtered_keys([("ipv4.src", "host")])(tup), filter_groups(["synacks"])(tup)),
        next_op=MapOperator(
            lambda tup: {**tup, "syns+synacks": Int(get_mapped_int("syns", tup) + get_mapped_int("synacks", tup))},
            join_op1
        )
    )
    return [syns_op.next_op.next_op.next_op.next_op(join_op3), synacks_op.next_op.next_op.next_op.next_op(join_op4), acks_op.next_op.next_op.next_op.next_op(join_op2)]

def completed_flows(next_op: Operator) -> List[Operator]:
    threshold = 1
    epoch_dur = 30.0

    def syns_filter(tup: TupleType) -> bool:
        return get_mapped_int("ipv4.proto", tup) == 6 and get_mapped_int("l4.flags", tup) == 2
    def fins_filter(tup: TupleType) -> bool:
        return get_mapped_int("ipv4.proto", tup) == 6 and (get_mapped_int("l4.flags", tup) & 1) == 1

    syns_op = EpochOperator(epoch_dur, "eid", FilterOperator(syns_filter, GroupByOperator(filter_groups(["ipv4.dst"]), counter, "syns", Operator())))
    fins_op = EpochOperator(epoch_dur, "eid", FilterOperator(fins_filter, GroupByOperator(filter_groups(["ipv4.src"]), counter, "fins", Operator())))

    op1, op2 = join("eid",
        left_extractor=lambda tup: (rename_filtered_keys([("ipv4.dst", "host")])(tup), filter_groups(["syns"])(tup)),
        right_extractor=lambda tup: (rename_filtered_keys([("ipv4.src", "host")])(tup), filter_groups(["fins"])(tup)),
        next_op=MapOperator(
            lambda tup: {**tup, "diff": Int(get_mapped_int("syns", tup) - get_mapped_int("fins", tup))},
            FilterOperator(key_geq_int("diff", threshold), next_op)
        )
    )
    return [syns_op.next_op.next_op.next_op.next_op(op1), fins_op.next_op.next_op.next_op.next_op(op2)]

def slowloris(next_op: Operator) -> List[Operator]:
    t1, t2, t3 = 5, 500, 90
    epoch_dur = 1.0

    def tcp_filter(tup: TupleType) -> bool:
        return get_mapped_int("ipv4.proto", tup) == 6

    n_conns_op = EpochOperator(epoch_dur, "eid", FilterOperator(tcp_filter, DistinctOperator(filter_groups(["ipv4.src", "ipv4.dst", "l4.sport"]), GroupByOperator(filter_groups(["ipv4.dst"]), counter, "n_conns", FilterOperator(lambda tup: get_mapped_int("n_conns", tup) >= t1, Operator())))))
    n_bytes_op = EpochOperator(epoch_dur, "eid", FilterOperator(tcp_filter, GroupByOperator(filter_groups(["ipv4.dst"]), sum_ints("ipv4.len"), "n_bytes", FilterOperator(lambda tup: get_mapped_int("n_bytes", tup) >= t2, Operator()))))

    op1, op2 = join("eid",
        left_extractor=lambda tup: (filter_groups(["ipv4.dst"])(tup), filter_groups(["n_conns"])(tup)),
        right_extractor=lambda tup: (filter_groups(["ipv4.dst"])(tup), filter_groups(["n_bytes"])(tup)),
        next_op=MapOperator(
            lambda tup: {**tup, "bytes_per_conn": Int(get_mapped_int("n_bytes", tup) // get_mapped_int("n_conns", tup))},
            FilterOperator(lambda tup: get_mapped_int("bytes_per_conn", tup) <= t3, next_op)
        )
    )
    return [n_conns_op.next_op.next_op.next_op.next_op.next_op.next_op(op1), n_bytes_op.next_op.next_op.next_op.next_op.next_op(op2)]

# Main entry point
queries = [ident(DumpTupleOperator(sys.stdout))]

def run_queries():
    sample_tuples = [
        {
            "time": Float(0.0 + i),
            "eth.src": MAC(b"\x00\x11\x22\x33\x44\x55"),
            "eth.dst": MAC(b"\xAA\xBB\xCC\xDD\xEE\xFF"),
            "eth.ethertype": Int(0x0800),
            "ipv4.hlen": Int(20),
            "ipv4.proto": Int(6),
            "ipv4.len": Int(60),
            "ipv4.src": IPv4(ipaddress.IPv4Address("127.0.0.1")),
            "ipv4.dst": IPv4(ipaddress.IPv4Address("127.0.0.1")),
            "l4.sport": Int(440),
            "l4.dport": Int(50000),
            "l4.flags": Int(10)
        }
        for i in range(5)
    ]
    for tup in sample_tuples:
        for query in queries:
            query.next(tup)

if __name__ == "__main__":
    run_queries()
    print("Done")