from dataclasses import dataclass
from typing import Callable, Dict, Union, Optional, Tuple as Tup
import ipaddress
import sys

# === Variant Type ===

@dataclass
class FloatResult:
    value: float

@dataclass
class IntResult:
    value: int

@dataclass
class IPv4Result:
    value: ipaddress.IPv4Address

@dataclass
class MACResult:
    value: bytes  # MAC as 6-byte bytes

@dataclass
class EmptyResult:
    pass

OpResult = Union[FloatResult, IntResult, IPv4Result, MACResult, EmptyResult]
TupleType = Dict[str, OpResult]

# === Operator Type ===

@dataclass
class Operator:
    next: Callable[[TupleType], None]
    reset: Callable[[TupleType], None]

OpCreator = Callable[[Operator], Operator]
DblOpCreator = Callable[[Operator], Tup[Operator, Operator]]

# === Chaining Operators ===

def at_arrow(op_creator_func: OpCreator, next_op: Operator) -> Operator:
    return op_creator_func(next_op)

def at_double_arrow(op_creator_func: DblOpCreator, op: Operator) -> Tup[Operator, Operator]:
    return op_creator_func(op)

# === Utility Functions ===

def string_of_mac(buf: bytes) -> str:
    return ":".join(f"{b:02x}" for b in buf)

def tcp_flags_to_strings(flags: int) -> str:
    tcp_flags_map = {
        "FIN": 1 << 0,
        "SYN": 1 << 1,
        "RST": 1 << 2,
        "PSH": 1 << 3,
        "ACK": 1 << 4,
        "URG": 1 << 5,
        "ECE": 1 << 6,
        "CWR": 1 << 7
    }
    return "|".join(k for k, v in tcp_flags_map.items() if flags & v)

def int_of_op_result(val: OpResult) -> int:
    if isinstance(val, IntResult):
        return val.value
    raise TypeError("Expected IntResult")

def float_of_op_result(val: OpResult) -> float:
    if isinstance(val, FloatResult):
        return val.value
    raise TypeError("Expected FloatResult")

def string_of_op_result(val: OpResult) -> str:
    if isinstance(val, FloatResult):
        return f"{val.value}"
    elif isinstance(val, IntResult):
        return str(val.value)
    elif isinstance(val, IPv4Result):
        return str(val.value)
    elif isinstance(val, MACResult):
        return string_of_mac(val.value)
    elif isinstance(val, EmptyResult):
        return "Empty"
    return "Unknown"

def string_of_tuple(t: TupleType) -> str:
    return ", ".join(f'"{k}" => {string_of_op_result(v)}' for k, v in t.items())

def tuple_of_list(pairs: list[tuple[str, OpResult]]) -> TupleType:
    return dict(pairs)

def dump_tuple(out, t: TupleType) -> None:
    print(string_of_tuple(t), file=out)

def lookup_int(key: str, tup: TupleType) -> int:
    return int_of_op_result(tup[key])

def lookup_float(key: str, tup: TupleType) -> float:
    return float_of_op_result(tup[key])

from typing import List, Optional, TextIO, Callable
import ipaddress
import sys

# If these are not already defined, you must import or define them:
# from common_utils import Operator, TupleType, OpResult, IntResult, IPv4Result,
#                         string_of_op_result, dump_tuple, lookup_int

INIT_TABLE_SIZE = 10000

def dump_tuple_operator(out: TextIO = sys.stdout, show_reset: bool = False) -> Operator:
    def next_fn(tup: TupleType):
        dump_tuple(out, tup)

    def reset_fn(tup: TupleType):
        if show_reset:
            dump_tuple(out, tup)
            print("[reset]", file=out)

    return Operator(next=next_fn, reset=reset_fn)

def dump_as_csv_operator(out: TextIO = sys.stdout,
                         static_field: Optional[tuple[str, str]] = None,
                         header: bool = True) -> Operator:
    first = [header]

    def next_fn(tup: TupleType):
        if first[0]:
            if static_field:
                print(f"{static_field[0]}", end=",", file=out)
            print(",".join(tup.keys()), file=out)
            first[0] = False

        if static_field:
            print(f"{static_field[1]}", end=",", file=out)
        print(",".join(string_of_op_result(v) for v in tup.values()), file=out)

    return Operator(next=next_fn, reset=lambda _: None)

def get_ip_or_zero(input_str: str) -> OpResult:
    if input_str == "0":
        return IntResult(0)
    return IPv4Result(ipaddress.IPv4Address(input_str))

def meta_meter(name: str, out: TextIO, next_op: Operator, static_field: Optional[str] = None) -> Operator:
    epoch_count = [0]
    tups_count = [0]

    def next_fn(tup: TupleType):
        tups_count[0] += 1
        next_op.next(tup)

    def reset_fn(tup: TupleType):
        print(f"{epoch_count[0]},{name},{tups_count[0]},{static_field or ''}", file=out)
        tups_count[0] = 0
        epoch_count[0] += 1
        next_op.reset(tup)

    return Operator(next=next_fn, reset=reset_fn)

def filter_operator(predicate: Callable[[TupleType], bool], next_op: Operator) -> Operator:
    return Operator(
        next=lambda tup: next_op.next(tup) if predicate(tup) else None,
        reset=next_op.reset
    )

def key_geq_int(key: str, threshold: int) -> Callable[[TupleType], bool]:
    return lambda tup: lookup_int(key, tup) >= threshold

def map_operator(f: Callable[[TupleType], TupleType], next_op: Operator) -> Operator:
    return Operator(
        next=lambda tup: next_op.next(f(tup)),
        reset=next_op.reset
    )

def filter_groups(keys: List[str]) -> Callable[[TupleType], TupleType]:
    return lambda tup: {k: v for k, v in tup.items() if k in keys}

def single_group(_: TupleType) -> TupleType:
    return {}

from typing import Callable, Tuple as Tup

def join(
    left_extractor: Callable[[TupleType], Tup[TupleType, TupleType]],
    right_extractor: Callable[[TupleType], Tup[TupleType, TupleType]],
    eid_key: str = "eid"
) -> Callable[[Operator], Tup[Operator, Operator]]:
    def join_builder(next_op: Operator) -> Tup[Operator, Operator]:
        h1, h2 = {}, {}
        left_epoch = [0]
        right_epoch = [0]

        def make_side(curr_h, other_h, curr_epoch, other_epoch, extractor):
            def next_fn(tup: TupleType):
                epoch = int_of_op_result(tup[eid_key])
                while epoch > curr_epoch[0]:
                    if other_epoch[0] > curr_epoch[0]:
                        next_op.reset({eid_key: IntResult(curr_epoch[0])})
                    curr_epoch[0] += 1

                key, vals = extractor(tup)
                key[eid_key] = IntResult(epoch)
                frozen = frozenset(key.items())

                if frozen in other_h:
                    combined = {**key, **vals, **other_h[frozen]}
                    next_op.next(combined)
                    del other_h[frozen]
                else:
                    curr_h[frozen] = vals

            def reset_fn(tup: TupleType):
                epoch = int_of_op_result(tup[eid_key])
                while epoch > curr_epoch[0]:
                    if other_epoch[0] > curr_epoch[0]:
                        next_op.reset({eid_key: IntResult(curr_epoch[0])})
                    curr_epoch[0] += 1

            return Operator(next=next_fn, reset=reset_fn)

        return (
            make_side(h1, h2, left_epoch, right_epoch, left_extractor),
            make_side(h2, h1, right_epoch, left_epoch, right_extractor)
        )

    return join_builder

def rename_filtered_keys(rename_pairs: list[tuple[str, str]]) -> Callable[[TupleType], TupleType]:
    def renamer(tup: TupleType) -> TupleType:
        return {
            new_key: tup[old_key]
            for old_key, new_key in rename_pairs
            if old_key in tup
        }
    return renamer

def tcp_new_cons(next_op: Operator) -> Operator:
    threshold = 40
    return at_arrow(epoch(1.0, "eid"),
        at_arrow(filter_operator(lambda tup:
            lookup_int("ipv4.proto", tup) == 6 and lookup_int("l4.flags", tup) == 2,
        at_arrow(groupby(filter_groups(["ipv4.dst"]), counter, "cons"),
        at_arrow(filter_operator(key_geq_int("cons", threshold)),
            next_op)))))

def ddos(next_op: Operator) -> Operator:
    threshold = 45
    return at_arrow(epoch(1.0, "eid"),
        at_arrow(distinct(filter_groups(["ipv4.src", "ipv4.dst"])),
        at_arrow(groupby(filter_groups(["ipv4.dst"]), counter, "srcs"),
        at_arrow(filter_operator(key_geq_int("srcs", threshold)),
            next_op))))

def port_scan(next_op: Operator) -> Operator:
    threshold = 40
    return at_arrow(epoch(1.0, "eid"),
        at_arrow(distinct(filter_groups(["ipv4.src", "l4.dport"])),
        at_arrow(groupby(filter_groups(["ipv4.src"]), counter, "ports"),
        at_arrow(filter_operator(key_geq_int("ports", threshold)),
            next_op))))

def super_spreader(next_op: Operator) -> Operator:
    threshold = 40
    return at_arrow(epoch(1.0, "eid"),
        at_arrow(distinct(filter_groups(["ipv4.src", "ipv4.dst"])),
        at_arrow(groupby(filter_groups(["ipv4.src"]), counter, "dsts"),
        at_arrow(filter_operator(key_geq_int("dsts", threshold)),
            next_op))))

def q3(next_op: Operator) -> Operator:
    return at_arrow(epoch(100.0, "eid"),
        at_arrow(distinct(filter_groups(["ipv4.src", "ipv4.dst"])),
            next_op))

def q4(next_op: Operator) -> Operator:
    return at_arrow(epoch(10000.0, "eid"),
        at_arrow(groupby(filter_groups(["ipv4.dst"]), counter, "pkts"),
            next_op))


def run_queries(queries: List[Operator]):
    for i in range(20):
        tup = {
            "time": FloatResult(float(i)),
            "eth.src": MACResult(b"\x00\x11\x22\x33\x44\x55"),
            "eth.dst": MACResult(b"\xAA\xBB\xCC\xDD\xEE\xFF"),
            "eth.ethertype": IntResult(0x0800),
            "ipv4.hlen": IntResult(20),
            "ipv4.proto": IntResult(6),
            "ipv4.len": IntResult(60),
            "ipv4.src": IPv4Result(ipaddress.IPv4Address("127.0.0.1")),
            "ipv4.dst": IPv4Result(ipaddress.IPv4Address("127.0.0.1")),
            "l4.sport": IntResult(440),
            "l4.dport": IntResult(50000),
            "l4.flags": IntResult(10)
        }
        for query in queries:
            query.next(tup)
    for query in queries:
        query.reset({})

if __name__ == "__main__":
    queries = [
        tcp_new_cons(dump_tuple_operator()),
        ddos(dump_tuple_operator()),
        q3(dump_tuple_operator()),
        q4(dump_tuple_operator())
    ]
    run_queries(queries)
    print("Done")
