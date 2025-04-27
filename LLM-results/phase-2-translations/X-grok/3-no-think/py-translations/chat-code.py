import ipaddress
import csv
from collections import defaultdict
from typing import Dict, Union, Callable, List, Tuple as PyTuple, Optional
import sys
from enum import Enum
import hashlib

# Enum to mimic OCaml's op_result variant type
class OpResultType(Enum):
    FLOAT = "Float"
    INT = "Int"
    IPV4 = "IPv4"
    MAC = "MAC"
    EMPTY = "Empty"

class OpResult:
    def __init__(self, type_: OpResultType, value=None):
        self.type_ = type_
        self.value = value

    @staticmethod
    def Float(value: float) -> 'OpResult':
        return OpResult(OpResultType.FLOAT, value)

    @staticmethod
    def Int(value: int) -> 'OpResult':
        return OpResult(OpResultType.INT, value)

    @staticmethod
    def IPv4(value: ipaddress.IPv4Address) -> 'OpResult':
        return OpResult(OpResultType.IPV4, value)

    @staticmethod
    def MAC(value: bytes) -> 'OpResult':
        return OpResult(OpResultType.MAC, value)

    @staticmethod
    def Empty() -> 'OpResult':
        return OpResult(OpResultType.EMPTY)

# Tuple is a dictionary mapping strings to OpResult
Tuple = Dict[str, OpResult]

# Operator class to mimic OCaml's record type
class Operator:
    def __init__(self, next: Callable[[Tuple], None], reset: Callable[[Tuple], None]):
        self.next = next
        self.reset = reset

# Function types
OpCreator = Callable[[Operator], Operator]
DblOpCreator = Callable[[Operator], PyTuple[Operator, Operator]]

# Chaining operators (mimicking @=> and @==>)
def chain(op_creator: OpCreator, next_op: Operator) -> Operator:
    return op_creator(next_op)

def chain_dbl(op_creator: DblOpCreator, op: Operator) -> PyTuple[Operator, Operator]:
    return op_creator(op)

# Conversion utilities
def string_of_mac(buf: bytes) -> str:
    return ":".join(f"{b:02x}" for b in buf[:6])

def tcp_flags_to_strings(flags: int) -> str:
    tcp_flags = {
        "FIN": 1 << 0,
        "SYN": 1 << 1,
        "RST": 1 << 2,
        "PSH": 1 << 3,
        "ACK": 1 << 4,
        "URG": 1 << 5,
        "ECE": 1 << 6,
        "CWR": 1 << 7,
    }
    result = [
        key for key, value in tcp_flags.items() if flags & value == value
    ]
    return "|".join(result) if result else ""

def int_of_op_result(input: OpResult) -> int:
    if input.type_ == OpResultType.INT:
        return input.value
    raise ValueError("Trying to extract int from non-int result")

def float_of_op_result(input: OpResult) -> float:
    if input.type_ == OpResultType.FLOAT:
        return input.value
    raise ValueError("Trying to extract float from non-float result")

def string_of_op_result(input: OpResult) -> str:
    if input.type_ == OpResultType.FLOAT:
        return f"{input.value}"
    elif input.type_ == OpResultType.INT:
        return str(input.value)
    elif input.type_ == OpResultType.IPV4:
        return str(input.value)
    elif input.type_ == OpResultType.MAC:
        return string_of_mac(input.value)
    elif input.type_ == OpResultType.EMPTY:
        return "Empty"
    return ""

def string_of_tuple(input_tuple: Tuple) -> str:
    return ", ".join(
        f'"{key}" => {string_of_op_result(value)}'
        for key, value in input_tuple.items()
    )

def tuple_of_list(tup_list: List[PyTuple[str, OpResult]]) -> Tuple:
    return dict(tup_list)

def dump_tuple(outc, tup: Tuple) -> None:
    print(string_of_tuple(tup), file=outc)

def lookup_int(key: str, tup: Tuple) -> int:
    return int_of_op_result(tup[key])

def lookup_float(key: str, tup: Tuple) -> float:
    return float_of_op_result(tup[key])

# Built-in operator definitions
init_table_size = 10000

def dump_tuple_op(show_reset: bool = False, outc=sys.stdout) -> Operator:
    def next(tup: Tuple) -> None:
        dump_tuple(outc, tup)
    
    def reset(tup: Tuple) -> None:
        if show_reset:
            dump_tuple(outc, tup)
            print("[reset]", file=outc)
    
    return Operator(next, reset)

def dump_as_csv(static_field: Optional[PyTuple[str, str]] = None, header: bool = True, outc=sys.stdout) -> Operator:
    first = [header]
    
    def next(tup: Tuple) -> None:
        nonlocal first
        if first[0]:
            if static_field:
                print(f"{static_field[0]},", end="", file=outc)
            print(",".join(tup.keys()), file=outc)
            first[0] = False
        if static_field:
            print(f"{static_field[1]},", end="", file=outc)
        print(",".join(string_of_op_result(v) for v in tup.values()), file=outc)
    
    def reset(_: Tuple) -> None:
        pass
    
    return Operator(next, reset)

def dump_walts_csv(filename: str) -> Operator:
    outc = [sys.stdout]
    first = [True]
    
    def next(tup: Tuple) -> None:
        nonlocal outc, first
        if first[0]:
            outc[0] = open(filename, 'w')
            first[0] = False
        print(
            f"{string_of_op_result(tup['src_ip'])},"
            f"{string_of_op_result(tup['dst_ip'])},"
            f"{string_of_op_result(tup['src_l4_port'])},"
            f"{string_of_op_result(tup['dst_l4_port'])},"
            f"{string_of_op_result(tup['packet_count'])},"
            f"{string_of_op_result(tup['byte_count'])},"
            f"{string_of_op_result(tup['epoch_id'])}",
            file=outc[0]
        )
    
    def reset(_: Tuple) -> None:
        pass
    
    return Operator(next, reset)

def get_ip_or_zero(input: str) -> OpResult:
    if input == "0":
        return OpResult.Int(0)
    return OpResult.IPv4(ipaddress.IPv4Address(input))

def read_walts_csv(epoch_id_key: str = "eid", file_names: List[str], ops: List[Operator]) -> None:
    inchs_eids_tupcount = [(open(fn, 'r'), [0], [0]) for fn in file_names]
    running = [len(ops)]
    
    while running[0] > 0:
        for (in_ch, eid, tup_count), op in zip(inchs_eids_tupcount, ops):
            if eid[0] >= 0:
                try:
                    reader = csv.reader(in_ch)
                    for row in reader:
                        src_ip, dst_ip, src_l4_port, dst_l4_port, packet_count, byte_count, epoch_id = row
                        src_l4_port = int(src_l4_port)
                        dst_l4_port = int(dst_l4_port)
                        packet_count = int(packet_count)
                        byte_count = int(byte_count)
                        epoch_id = int(epoch_id)
                        
                        p = {}
                        p["ipv4.src"] = get_ip_or_zero(src_ip)
                        p["ipv4.dst"] = get_ip_or_zero(dst_ip)
                        p["l4.sport"] = OpResult.Int(src_l4_port)
                        p["l4.dport"] = OpResult.Int(dst_l4_port)
                        p["packet_count"] = OpResult.Int(packet_count)
                        p["byte_count"] = OpResult.Int(byte_count)
                        p[epoch_id_key] = OpResult.Int(epoch_id)
                        
                        tup_count[0] += 1
                        if epoch_id > eid[0]:
                            while epoch_id > eid[0]:
                                reset_tup = {epoch_id_key: OpResult.Int(eid[0]), "tuples": OpResult.Int(tup_count[0])}
                                op.reset(reset_tup)
                                tup_count[0] = 0
                                eid[0] += 1
                        op.next({**p, "tuples": OpResult.Int(tup_count[0])})
                except (csv.Error, ValueError) as e:
                    print(f"Failed to scan: {e}")
                    raise ValueError("Scan failure")
                except EOFError:
                    reset_tup = {epoch_id_key: OpResult.Int(eid[0] + 1), "tuples": OpResult.Int(tup_count[0])}
                    op.reset(reset_tup)
                    running[0] -= 1
                    eid[0] = -1
    print("Done.")

def meta_meter(static_field: Optional[str] = None, name: str, outc, next_op: Operator) -> Operator:
    epoch_count = [0]
    tups_count = [0]
    
    def next(tup: Tuple) -> None:
        tups_count[0] += 1
        next_op.next(tup)
    
    def reset(tup: Tuple) -> None:
        print(f"{epoch_count[0]},{name},{tups_count[0]},{static_field or ''}", file=outc)
        tups_count[0] = 0
        epoch_count[0] += 1
        next_op.reset(tup)
    
    return Operator(next, reset)

def epoch(epoch_width: float, key_out: str, next_op: Operator) -> Operator:
    epoch_boundary = [0.0]
    eid = [0]
    
    def next(tup: Tuple) -> None:
        time = float_of_op_result(tup["time"])
        if epoch_boundary[0] == 0.0:
            epoch_boundary[0] = time + epoch_width
        elif time >= epoch_boundary[0]:
            while time >= epoch_boundary[0]:
                next_op.reset({key_out: OpResult.Int(eid[0])})
                epoch_boundary[0] += epoch_width
                eid[0] += 1
        next_op.next({**tup, key_out: OpResult.Int(eid[0])})
    
    def reset(_: Tuple) -> None:
        next_op.reset({key_out: OpResult.Int(eid[0])})
        epoch_boundary[0] = 0.0
        eid[0] = 0
    
    return Operator(next, reset)

def filter(f: Callable[[Tuple], bool], next_op: Operator) -> Operator:
    def next(tup: Tuple) -> None:
        if f(tup):
            next_op.next(tup)
    
    def reset(tup: Tuple) -> None:
        next_op.reset(tup)
    
    return Operator(next, reset)

def key_geq_int(key: str, threshold: int) -> Callable[[Tuple], bool]:
    def f(tup: Tuple) -> bool:
        return int_of_op_result(tup[key]) >= threshold
    return f

def get_mapped_int(key: str, tup: Tuple) -> int:
    return int_of_op_result(tup[key])

def get_mapped_float(key: str, tup: Tuple) -> float:
    return float_of_op_result(tup[key])

def map(f: Callable[[Tuple], Tuple], next_op: Operator) -> Operator:
    def next(tup: Tuple) -> None:
        next_op.next(f(tup))
    
    def reset(tup: Tuple) -> None:
        next_op.reset(tup)
    
    return Operator(next, reset)

GroupingFunc = Callable[[Tuple], Tuple]
ReductionFunc = Callable[[OpResult, Tuple], OpResult]

def groupby(groupby: GroupingFunc, reduce: ReductionFunc, out_key: str, next_op: Operator) -> Operator:
    h_tbl = {}
    reset_counter = [0]
    
    def next(tup: Tuple) -> None:
        grouping_key = groupby(tup)
        key_hash = hashlib.md5(str(grouping_key).encode()).hexdigest()  # Simple hash for dict key
        val_ = h_tbl.get(key_hash, OpResult.Empty())
        h_tbl[key_hash] = reduce(val_, tup)
    
    def reset(tup: Tuple) -> None:
        reset_counter[0] += 1
        for key_hash, val_ in h_tbl.items():
            grouping_key = groupby(tup)  # Recompute for simplicity
            unioned_tup = {**tup, **grouping_key}
            next_op.next({**unioned_tup, out_key: val_})
        next_op.reset(tup)
        h_tbl.clear()
    
    return Operator(next, reset)

def filter_groups(incl_keys: List[str]) -> GroupingFunc:
    def f(tup: Tuple) -> Tuple:
        return {k: v for k, v in tup.items() if k in incl_keys}
    return f

def single_group(_: Tuple) -> Tuple:
    return {}

def counter(val_: OpResult, _: Tuple) -> OpResult:
    if val_.type_ == OpResultType.EMPTY:
        return OpResult.Int(1)
    elif val_.type_ == OpResultType.INT:
        return OpResult.Int(val_.value + 1)
    return val_

def sum_ints(search_key: str) -> ReductionFunc:
    def f(init_val: OpResult, tup: Tuple) -> OpResult:
        if init_val.type_ == OpResultType.EMPTY:
            return OpResult.Int(0)
        elif init_val.type_ == OpResultType.INT:
            if search_key in tup and tup[search_key].type_ == OpResultType.INT:
                return OpResult.Int(tup[search_key].value + init_val.value)
            raise ValueError(f"'sum_vals' function failed to find integer value mapped to \"{search_key}\"")
        return init_val
    return f

def distinct(groupby: GroupingFunc, next_op: Operator) -> Operator:
    h_tbl = {}
    reset_counter = [0]
    
    def next(tup: Tuple) -> None:
        grouping_key = groupby(tup)
        key_hash = hashlib.md5(str(grouping_key).encode()).hexdigest()
        h_tbl[key_hash] = True
    
    def reset(tup: Tuple) -> None:
        reset_counter[0] += 1
        for key_hash in h_tbl:
            grouping_key = groupby(tup)  # Recompute for simplicity
            merged_tup = {**tup, **grouping_key}
            next_op.next(merged_tup)
        next_op.reset(tup)
        h_tbl.clear()
    
    return Operator(next, reset)

def split(l: Operator, r: Operator) -> Operator:
    def next(tup: Tuple) -> None:
        l.next(tup)
        r.next(tup)
    
    def reset(tup: Tuple) -> None:
        l.reset(tup)
        r.reset(tup)
    
    return Operator(next, reset)

KeyExtractor = Callable[[Tuple], PyTuple[Tuple, Tuple]]

def join(eid_key: str = "eid", left_extractor: KeyExtractor, right_extractor: KeyExtractor, next_op: Operator) -> PyTuple[Operator, Operator]:
    h_tbl1 = {}
    h_tbl2 = {}
    left_curr_epoch = [0]
    right_curr_epoch = [0]
    
    def handle_join_side(curr_h_tbl, other_h_tbl, curr_epoch_ref, other_epoch_ref, f: KeyExtractor) -> Operator:
        def next(tup: Tuple) -> None:
            key, vals_ = f(tup)
            curr_epoch = get_mapped_int(eid_key, tup)
            
            while curr_epoch > curr_epoch_ref[0]:
                if other_epoch_ref[0] > curr_epoch_ref[0]:
                    next_op.reset({eid_key: OpResult.Int(curr_epoch_ref[0])})
                curr_epoch_ref[0] += 1
            
            new_tup = {**key, eid_key: OpResult.Int(curr_epoch)}
            new_tup_key = hashlib.md5(str(new_tup).encode()).hexdigest()
            
            if new_tup_key in other_h_tbl:
                val_ = other_h_tbl.pop(new_tup_key)
                merged = {**new_tup, **vals_, **val_}
                next_op.next(merged)
            else:
                curr_h_tbl[new_tup_key] = vals_
        
        def reset(tup: Tuple) -> None:
            curr_epoch = get_mapped_int(eid_key, tup)
            while curr_epoch > curr_epoch_ref[0]:
                if other_epoch_ref[0] > curr_epoch_ref[0]:
                    next_op.reset({eid_key: OpResult.Int(curr_epoch_ref[0])})
                curr_epoch_ref[0] += 1
        
        return Operator(next, reset)
    
    return (
        handle_join_side(h_tbl1, h_tbl2, left_curr_epoch, right_curr_epoch, left_extractor),
        handle_join_side(h_tbl2, h_tbl1, right_curr_epoch, left_curr_epoch, right_extractor)
    )

def rename_filtered_keys(renamings_pairs: List[PyTuple[str, str]]) -> Callable[[Tuple], Tuple]:
    def f(in_tup: Tuple) -> Tuple:
        new_tup = {}
        for old_key, new_key in renamings_pairs:
            if old_key in in_tup:
                new_tup[new_key] = in_tup[old_key]
        return new_tup
    return f

# Main query definitions
def ident(next_op: Operator) -> Operator:
    def f(tup: Tuple) -> Tuple:
        return {k: v for k, v in tup.items() if k not in ["eth.src", "eth.dst"]}
    return chain(map(f), next_op)

def count_pkts(next_op: Operator) -> Operator:
    return chain(epoch(1.0, "eid"), chain(groupby(single_group, counter, "pkts"), next_op))

def pkts_per_src_dst(next_op: Operator) -> Operator:
    return chain(epoch(1.0, "eid"), chain(groupby(filter_groups(["ipv4.src", "ipv4.dst"]), counter, "pkts"), next_op))

def distinct_srcs(next_op: Operator) -> Operator:
    return chain(epoch(1.0, "eid"), chain(distinct(filter_groups(["ipv4.src"])), chain(groupby(single_group, counter, "srcs"), next_op)))

def tcp_new_cons(next_op: Operator) -> Operator:
    threshold = 40
    def f(tup: Tuple) -> bool:
        return get_mapped_int("ipv4.proto", tup) == 6 and get_mapped_int("l4.flags", tup) == 2
    return chain(epoch(1.0, "eid"), chain(filter(f), chain(groupby(filter_groups(["ipv4.dst"]), counter, "cons"), chain(filter(key_geq_int("cons", threshold)), next_op))))

def ssh_brute_force(next_op: Operator) -> Operator:
    threshold = 40
    def f(tup: Tuple) -> bool:
        return get_mapped_int("ipv4.proto", tup) == 6 and get_mapped_int("l4.dport", tup) == 22
    return chain(epoch(1.0, "eid"), chain(filter(f), chain(distinct(filter_groups(["ipv4.src", "ipv4.dst", "ipv4.len"])), chain(groupby(filter_groups(["ipv4.dst", "ipv4.len"]), counter, "srcs"), chain(filter(key_geq_int("srcs", threshold)), next_op)))))

def super_spreader(next_op: Operator) -> Operator:
    threshold = 40
    return chain(epoch(1.0, "eid"), chain(distinct(filter_groups(["ipv4.src", "ipv4.dst"])), chain(groupby(filter_groups(["ipv4.src"]), counter, "dsts"), chain(filter(key_geq_int("dsts", threshold)), next_op))))

def port_scan(next_op: Operator) -> Operator:
    threshold = 40
    return chain(epoch(1.0, "eid"), chain(distinct(filter_groups(["ipv4.src", "l4.dport"])), chain(groupby(filter_groups(["ipv4.src"]), counter, "ports"), chain(filter(key_geq_int("ports", threshold)), next_op))))

def ddos(next_op: Operator) -> Operator:
    threshold = 45
    return chain(epoch(1.0, "eid"), chain(distinct(filter_groups(["ipv4.src", "ipv4.dst"])), chain(groupby(filter_groups(["ipv4.dst"]), counter, "srcs"), chain(filter(key_geq_int("srcs", threshold)), next_op))))

def syn_flood_sonata(next_op: Operator) -> List[Operator]:
    threshold = 3
    epoch_dur = 1.0
    
    def syns(next_op: Operator) -> Operator:
        def f(tup: Tuple) -> bool:
            return get_mapped_int("ipv4.proto", tup) == 6 and get_mapped_int("l4.flags", tup) == 2
        return chain(epoch(epoch_dur, "eid"), chain(filter(f), chain(groupby(filter_groups(["ipv4.dst"]), counter, "syns"), next_op)))
    
    def synacks(next_op: Operator) -> Operator:
        def f(tup: Tuple) -> bool:
            return get_mapped_int("ipv4.proto", tup) == 6 and get_mapped_int("l4.flags", tup) == 18
        return chain(epoch(epoch_dur, "eid"), chain(filter(f), chain(groupby(filter_groups(["ipv4.src"]), counter, "synacks"), next_op)))
    
    def acks(next_op: Operator) -> Operator:
        def f(tup: Tuple) -> bool:
            return get_mapped_int("ipv4.proto", tup) == 6 and get_mapped_int("l4.flags", tup) == 16
        return chain(epoch(epoch_dur, "eid"), chain(filter(f), chain(groupby(filter_groups(["ipv4.dst"]), counter, "acks"), next_op)))
    
    join_op1, join_op2 = chain_dbl(join(
        lambda tup: (filter_groups(["host"])(tup), filter_groups(["syns+synacks"])(tup)),
        lambda tup: (rename_filtered_keys([("ipv4.dst", "host")])(tup), filter_groups(["acks"])(tup))
    ), chain(map(
        lambda tup: {**tup, "syns+synacks-acks": OpResult.Int(get_mapped_int("syns+synacks", tup) - get_mapped_int("acks", tup))}
    ), chain(filter(key_geq_int("syns+synacks-acks", threshold)), next_op)))
    
    join_op3, join_op4 = chain_dbl(join(
        lambda tup: (rename_filtered_keys([("ipv4.dst", "host")])(tup), filter_groups(["syns"])(tup)),
        lambda tup: (rename_filtered_keys([("ipv4.src", "host")])(tup), filter_groups(["synacks"])(tup))
    ), chain(map(
        lambda tup: {**tup, "syns+synacks": OpResult.Int(get_mapped_int("syns", tup) + get_mapped_int("synacks", tup))}
    ), join_op1))
    
    return [chain(syns, join_op3), chain(synacks, join_op4), chain(acks, join_op2)]

def completed_flows(next_op: Operator) -> List[Operator]:
    threshold = 1
    epoch_dur = 30.0
    
    def syns(next_op: Operator) -> Operator:
        def f(tup: Tuple) -> bool:
            return get_mapped_int("ipv4.proto", tup) == 6 and get_mapped_int("l4.flags", tup) == 2
        return chain(epoch(epoch_dur, "eid"), chain(filter(f), chain(groupby(filter_groups(["ipv4.dst"]), counter, "syns"), next_op)))
    
    def fins(next_op: Operator) -> Operator:
        def f(tup: Tuple) -> bool:
            return get_mapped_int("ipv4.proto", tup) == 6 and (get_mapped_int("l4.flags", tup) & 1) == 1
        return chain(epoch(epoch_dur, "eid"), chain(filter(f), chain(groupby(filter_groups(["ipv4.src"]), counter, "fins"), next_op)))
    
    op1, op2 = chain_dbl(join(
        lambda tup: (rename_filtered_keys([("ipv4.dst", "host")])(tup), filter_groups(["syns"])(tup)),
        lambda tup: (rename_filtered_keys([("ipv4.src", "host")])(tup), filter_groups(["fins"])(tup))
    ), chain(map(
        lambda tup: {**tup, "diff": OpResult.Int(get_mapped_int("syns", tup) - get_mapped_int("fins", tup))}
    ), chain(filter(key_geq_int("diff", threshold)), next_op)))
    
    return [chain(syns, op1), chain(fins, op2)]

def slowloris(next_op: Operator) -> List[Operator]:
    t1, t2, t3 = 5, 500, 90
    epoch_dur = 1.0
    
    def n_conns(next_op: Operator) -> Operator:
        def f(tup: Tuple) -> bool:
            return get_mapped_int("ipv4.proto", tup) == 6
        return chain(epoch(epoch_dur, "eid"), chain(filter(f), chain(distinct(filter_groups(["ipv4.src", "ipv4.dst", "l4.sport"])), chain(groupby(filter_groups(["ipv4.dst"]), counter, "n_conns"), chain(filter(lambda tup: get_mapped_int("n_conns", tup) >= t1), next_op)))))
    
    def n_bytes(next_op: Operator) -> Operator:
        def f(tup: Tuple) -> bool:
            return get_mapped_int("ipv4.proto", tup) == 6
        return chain(epoch(epoch_dur, "eid"), chain(filter(f), chain(groupby(filter_groups(["ipv4.dst"]), sum_ints("ipv4.len"), "n_bytes"), chain(filter(lambda tup: get_mapped_int("n_bytes", tup) >= t2), next_op))))
    
    op1, op2 = chain_dbl(join(
        lambda tup: (filter_groups(["ipv4.dst"])(tup), filter_groups(["n_conns"])(tup)),
        lambda tup: (filter_groups(["ipv4.dst"])(tup), filter_groups(["n_bytes"])(tup))
    ), chain(map(
        lambda tup: {**tup, "bytes_per_conn": OpResult.Int(get_mapped_int("n_bytes", tup) // get_mapped_int("n_conns", tup))}
    ), chain(filter(lambda tup: get_mapped_int("bytes_per_conn", tup) <= t3), next_op)))
    
    return [chain(n_conns, op1), chain(n_bytes, op2)]

def join_test(next_op: Operator) -> List[Operator]:
    epoch_dur = 1.0
    
    def syns(next_op: Operator) -> Operator:
        def f(tup: Tuple) -> bool:
            return get_mapped_int("ipv4.proto", tup) == 6 and get_mapped_int("l4.flags", tup) == 2
        return chain(epoch(epoch_dur, "eid"), chain(filter(f), next_op))
    
    def synacks(next_op: Operator) -> Operator:
        def f(tup: Tuple) -> bool:
            return get_mapped_int("ipv4.proto", tup) == 6 and get_mapped_int("l4.flags", tup) == 18
        return chain(epoch(epoch_dur, "eid"), chain(filter(f), next_op))
    
    op1, op2 = chain_dbl(join(
        lambda tup: (rename_filtered_keys([("ipv4.src", "host")])(tup), rename_filtered_keys([("ipv4.dst", "remote")])(tup)),
        lambda tup: (rename_filtered_keys([("ipv4.dst", "host")])(tup), filter_groups(["time"])(tup))
    ), next_op)
    
    return [chain(syns, op1), chain(synacks, op2)]

def q3(next_op: Operator) -> Operator:
    return chain(epoch(100.0, "eid"), chain(distinct(filter_groups(["ipv4.src", "ipv4.dst"])), next_op))

def q4(next_op: Operator) -> Operator:
    return chain(epoch(10000.0, "eid"), chain(groupby(filter_groups(["ipv4.dst"]), counter, "pkts"), next_op))

# Queries and main entry point
queries = [chain(ident, dump_tuple_op())]

def run_queries():
    tuples = [
        {
            "time": OpResult.Float(0.0 + i),
            "eth.src": OpResult.MAC(b"\x00\x11\x22\x33\x44\x55"),
            "eth.dst": OpResult.MAC(b"\xAA\xBB\xCC\xDD\xEE\xFF"),
            "eth.ethertype": OpResult.Int(0x0800),
            "ipv4.hlen": OpResult.Int(20),
            "ipv4.proto": OpResult.Int(6),
            "ipv4.len": OpResult.Int(60),
            "ipv4.src": OpResult.IPv4(ipaddress.IPv4Address("127.0.0.1")),
            "ipv4.dst": OpResult.IPv4(ipaddress.IPv4Address("127.0.0.1")),
            "l4.sport": OpResult.Int(440),
            "l4.dport": OpResult.Int(50000),
            "l4.flags": OpResult.Int(10),
        }
        for i in range(20)
    ]
    
    for tup in tuples:
        for query in queries:
            query.next(tup)

if __name__ == "__main__":
    run_queries()
    print("Done")