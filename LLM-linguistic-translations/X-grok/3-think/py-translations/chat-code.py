import sys
import ipaddress
from typing import Dict, Callable, List, Tuple as PyTuple, Optional
from collections import defaultdict

# Define OpResult class to mimic OCaml's variant type
class OpResult:
    def __init__(self, tag: str, value: any):
        self.tag = tag
        self.value = value

    def __repr__(self):
        return f"{self.tag}({self.value})"

    def __eq__(self, other):
        if isinstance(other, OpResult):
            return self.tag == other.tag and self.value == other.value
        return False

    def __hash__(self):
        return hash((self.tag, self.value))

# Define Tuple as a dictionary from strings to OpResult
Tuple = Dict[str, OpResult]

# Define Operator base class
class Operator:
    def next(self, tup: Tuple) -> None:
        pass

    def reset(self, tup: Tuple) -> None:
        pass

# Conversion utilities
def string_of_mac(buf: bytes) -> str:
    return ':'.join(f'{byte:02x}' for byte in buf)

def tcp_flags_to_strings(flags: int) -> str:
    flag_names = ["FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"]
    return '|'.join(name for i, name in enumerate(flag_names) if flags & (1 << i))

def int_of_op_result(input: OpResult) -> int:
    if input.tag == "Int":
        return input.value
    raise ValueError("Trying to extract int from non-int result")

def float_of_op_result(input: OpResult) -> float:
    if input.tag == "Float":
        return input.value
    raise ValueError("Trying to extract float from non-float result")

def string_of_op_result(input: OpResult) -> str:
    if input.tag == "Float":
        return str(input.value)
    elif input.tag == "Int":
        return str(input.value)
    elif input.tag == "IPv4":
        return str(input.value)
    elif input.tag == "MAC":
        return string_of_mac(input.value)
    elif input.tag == "Empty":
        return "Empty"
    else:
        return "Unknown"

def string_of_tuple(input_tuple: Tuple) -> str:
    return ", ".join(f'"{k}" => {string_of_op_result(v)}' for k, v in input_tuple.items())

def dump_tuple(outc, tup: Tuple) -> None:
    outc.write(string_of_tuple(tup) + "\n")

def lookup_int(key: str, tup: Tuple) -> int:
    return int_of_op_result(tup[key])

def lookup_float(key: str, tup: Tuple) -> float:
    return float_of_op_result(tup[key])

# Operator implementations
class DumpTupleOperator(Operator):
    def __init__(self, outc, show_reset: bool = False):
        self.outc = outc
        self.show_reset = show_reset

    def next(self, tup: Tuple) -> None:
        dump_tuple(self.outc, tup)

    def reset(self, tup: Tuple) -> None:
        if self.show_reset:
            dump_tuple(self.outc, tup)
            self.outc.write("[reset]\n")

def dump_tuple_operator(outc, show_reset: bool = False) -> Operator:
    return DumpTupleOperator(outc, show_reset)

class EpochOperator(Operator):
    def __init__(self, epoch_width: float, key_out: str, next_op: Operator):
        self.epoch_width = epoch_width
        self.key_out = key_out
        self.next_op = next_op
        self.epoch_boundary = 0.0
        self.eid = 0

    def next(self, tup: Tuple) -> None:
        time = lookup_float("time", tup)
        if self.epoch_boundary == 0.0:
            self.epoch_boundary = time + self.epoch_width
        else:
            while time >= self.epoch_boundary:
                self.next_op.reset({self.key_out: OpResult("Int", self.eid)})
                self.epoch_boundary += self.epoch_width
                self.eid += 1
        tup_with_eid = tup.copy()
        tup_with_eid[self.key_out] = OpResult("Int", self.eid)
        self.next_op.next(tup_with_eid)

    def reset(self, tup: Tuple) -> None:
        self.next_op.reset({self.key_out: OpResult("Int", self.eid)})
        self.epoch_boundary = 0.0
        self.eid = 0

def epoch(epoch_width: float, key_out: str, next_op: Operator) -> Operator:
    return EpochOperator(epoch_width, key_out, next_op)

class FilterOperator(Operator):
    def __init__(self, f: Callable[[Tuple], bool], next_op: Operator):
        self.f = f
        self.next_op = next_op

    def next(self, tup: Tuple) -> None:
        if self.f(tup):
            self.next_op.next(tup)

    def reset(self, tup: Tuple) -> None:
        self.next_op.reset(tup)

def filter(f: Callable[[Tuple], bool], next_op: Operator) -> Operator:
    return FilterOperator(f, next_op)

def key_geq_int(key: str, threshold: int) -> Callable[[Tuple], bool]:
    return lambda tup: lookup_int(key, tup) >= threshold

class MapOperator(Operator):
    def __init__(self, f: Callable[[Tuple], Tuple], next_op: Operator):
        self.f = f
        self.next_op = next_op

    def next(self, tup: Tuple) -> None:
        self.next_op.next(self.f(tup))

    def reset(self, tup: Tuple) -> None:
        self.next_op.reset(tup)

def map(f: Callable[[Tuple], Tuple], next_op: Operator) -> Operator:
    return MapOperator(f, next_op)

GroupingFunc = Callable[[Tuple], Tuple]
ReductionFunc = Callable[[OpResult, Tuple], OpResult]

class GroupByOperator(Operator):
    def __init__(self, groupby: GroupingFunc, reduce: ReductionFunc, out_key: str, next_op: Operator):
        self.groupby = groupby
        self.reduce = reduce
        self.out_key = out_key
        self.next_op = next_op
        self.h_tbl = defaultdict(lambda: OpResult("Empty", None))

    def next(self, tup: Tuple) -> None:
        grouping_key = frozenset(self.groupby(tup).items())
        current_val = self.h_tbl[grouping_key]
        self.h_tbl[grouping_key] = self.reduce(current_val, tup)

    def reset(self, tup: Tuple) -> None:
        for grouping_key, val in self.h_tbl.items():
            key_dict = dict(grouping_key)
            unioned_tup = {**tup, **key_dict}
            self.next_op.next({**unioned_tup, self.out_key: val})
        self.next_op.reset(tup)
        self.h_tbl.clear()

def groupby(groupby: GroupingFunc, reduce: ReductionFunc, out_key: str, next_op: Operator) -> Operator:
    return GroupByOperator(groupby, reduce, out_key, next_op)

def filter_groups(incl_keys: List[str]) -> GroupingFunc:
    return lambda tup: {k: v for k, v in tup.items() if k in incl_keys}

def single_group(_: Tuple) -> Tuple:
    return {}

def counter(val: OpResult, _: Tuple) -> OpResult:
    if val.tag == "Empty":
        return OpResult("Int", 1)
    elif val.tag == "Int":
        return OpResult("Int", val.value + 1)
    return val

def sum_ints(search_key: str) -> ReductionFunc:
    def reduce(init_val: OpResult, tup: Tuple) -> OpResult:
        if init_val.tag == "Empty":
            init_val = OpResult("Int", 0)
        if init_val.tag == "Int":
            val = tup.get(search_key)
            if val and val.tag == "Int":
                return OpResult("Int", init_val.value + val.value)
            else:
                raise ValueError(f"'sum_vals' failed to find integer value for \"{search_key}\"")
        return init_val
    return reduce

class DistinctOperator(Operator):
    def __init__(self, groupby: GroupingFunc, next_op: Operator):
        self.groupby = groupby
        self.next_op = next_op
        self.h_tbl = set()

    def next(self, tup: Tuple) -> None:
        grouping_key = frozenset(self.groupby(tup).items())
        self.h_tbl.add(grouping_key)

    def reset(self, tup: Tuple) -> None:
        for grouping_key in self.h_tbl:
            key_dict = dict(grouping_key)
            merged_tup = {**tup, **key_dict}
            self.next_op.next(merged_tup)
        self.next_op.reset(tup)
        self.h_tbl.clear()

def distinct(groupby: GroupingFunc, next_op: Operator) -> Operator:
    return DistinctOperator(groupby, next_op)

# Query definitions
def ident(next_op: Operator) -> Operator:
    def map_func(tup: Tuple) -> Tuple:
        return {k: v for k, v in tup.items() if k not in ["eth.src", "eth.dst"]}
    return map(map_func, next_op)

def count_pkts(next_op: Operator) -> Operator:
    return epoch(1.0, "eid", groupby(single_group, counter, "pkts", next_op))

def pkts_per_src_dst(next_op: Operator) -> Operator:
    group_func = filter_groups(["ipv4.src", "ipv4.dst"])
    return epoch(1.0, "eid", groupby(group_func, counter, "pkts", next_op))

def distinct_srcs(next_op: Operator) -> Operator:
    group_func = filter_groups(["ipv4.src"])
    return epoch(1.0, "eid", distinct(group_func, groupby(single_group, counter, "srcs", next_op)))

def tcp_new_cons(next_op: Operator) -> Operator:
    threshold = 40
    def filter_func(tup: Tuple) -> bool:
        return lookup_int("ipv4.proto", tup) == 6 and lookup_int("l4.flags", tup) == 2
    group_func = filter_groups(["ipv4.dst"])
    return epoch(1.0, "eid", filter(filter_func, groupby(group_func, counter, "cons", filter(key_geq_int("cons", threshold), next_op))))

def ssh_brute_force(next_op: Operator) -> Operator:
    threshold = 40
    def filter_func(tup: Tuple) -> bool:
        return lookup_int("ipv4.proto", tup) == 6 and lookup_int("l4.dport", tup) == 22
    distinct_group = filter_groups(["ipv4.src", "ipv4.dst", "ipv4.len"])
    group_func = filter_groups(["ipv4.dst", "ipv4.len"])
    return epoch(1.0, "eid", filter(filter_func, distinct(distinct_group, groupby(group_func, counter, "srcs", filter(key_geq_int("srcs", threshold), next_op)))))

def super_spreader(next_op: Operator) -> Operator:
    threshold = 40
    distinct_group = filter_groups(["ipv4.src", "ipv4.dst"])
    group_func = filter_groups(["ipv4.src"])
    return epoch(1.0, "eid", distinct(distinct_group, groupby(group_func, counter, "dsts", filter(key_geq_int("dsts", threshold), next_op))))

def port_scan(next_op: Operator) -> Operator:
    threshold = 40
    distinct_group = filter_groups(["ipv4.src", "l4.dport"])
    group_func = filter_groups(["ipv4.src"])
    return epoch(1.0, "eid", distinct(distinct_group, groupby(group_func, counter, "ports", filter(key_geq_int("ports", threshold), next_op))))

def ddos(next_op: Operator) -> Operator:
    threshold = 45
    distinct_group = filter_groups(["ipv4.src", "ipv4.dst"])
    group_func = filter_groups(["ipv4.dst"])
    return epoch(1.0, "eid", distinct(distinct_group, groupby(group_func, counter, "srcs", filter(key_geq_int("srcs", threshold), next_op))))

import csv
from typing import List, Optional

def read_walts_csv(file_names: List[str], ops: List[Operator], epoch_id_key: str = "eid") -> None:
    class CSVReader:
        def __init__(self, filename: str):
            self.filename = filename
            self.eid = 0
            self.tup_count = 0
            self.file = open(filename, 'r')
            self.reader = csv.reader(self.file)

        def __iter__(self):
            return self

        def __next__(self):
            row = next(self.reader)
            src_ip, dst_ip, src_l4_port, dst_l4_port, packet_count, byte_count, epoch_id = row
            p = {
                "ipv4.src": get_ip_or_zero(src_ip),
                "ipv4.dst": get_ip_or_zero(dst_ip),
                "l4.sport": OpResult("Int", int(src_l4_port)),
                "l4.dport": OpResult("Int", int(dst_l4_port)),
                "packet_count": OpResult("Int", int(packet_count)),
                "byte_count": OpResult("Int", int(byte_count)),
                epoch_id_key: OpResult("Int", int(epoch_id)),
            }
            self.tup_count += 1
            if int(epoch_id) > self.eid:
                while int(epoch_id) > self.eid:
                    ops[0].reset({epoch_id_key: OpResult("Int", self.eid), "tuples": OpResult("Int", self.tup_count)})
                    self.tup_count = 0
                    self.eid += 1
            return {**p, "tuples": OpResult("Int", self.tup_count)}

        def __del__(self):
            self.file.close()

    def get_ip_or_zero(input: str) -> OpResult:
        if input == "0":
            return OpResult("Int", 0)
        else:
            return OpResult("IPv4", ipaddress.IPv4Address(input))

    readers = [CSVReader(filename) for filename in file_names]
    running = len(ops)
    while running > 0:
        for reader, op in zip(readers, ops):
            try:
                tup = next(reader)
                op.next(tup)
            except StopIteration:
                op.reset({epoch_id_key: OpResult("Int", reader.eid + 1), "tuples": OpResult("Int", reader.tup_count)})
                running -= 1
                reader.eid = -1
    print("Done.")

from collections import defaultdict

class JoinOperator:
    def __init__(self, eid_key: str, left_extractor: Callable[[Tuple], PyTuple[Tuple, Tuple]], 
                 right_extractor: Callable[[Tuple], PyTuple[Tuple, Tuple]], next_op: Operator):
        self.eid_key = eid_key
        self.left_extractor = left_extractor
        self.right_extractor = right_extractor
        self.next_op = next_op
        self.h_tbl1 = defaultdict(dict)  # Left hash table
        self.h_tbl2 = defaultdict(dict)  # Right hash table
        self.left_curr_epoch = 0
        self.right_curr_epoch = 0

    def handle_join_side(self, curr_h_tbl: defaultdict, other_h_tbl: defaultdict, 
                         curr_epoch_ref: int, other_epoch_ref: int, 
                         extractor: Callable[[Tuple], PyTuple[Tuple, Tuple]]) -> Operator:
        class SideOperator(Operator):
            def next(self, tup: Tuple) -> None:
                key, vals = extractor(tup)
                curr_epoch = lookup_int(self.eid_key, tup)
                nonlocal curr_epoch_ref, other_epoch_ref
                while curr_epoch > curr_epoch_ref:
                    if other_epoch_ref > curr_epoch_ref:
                        self.next_op.reset({self.eid_key: OpResult("Int", curr_epoch_ref)})
                    curr_epoch_ref += 1
                new_tup = {**key, self.eid_key: OpResult("Int", curr_epoch)}
                if new_tup in other_h_tbl:
                    val = other_h_tbl.pop(new_tup)
                    self.next_op.next({**new_tup, **vals, **val})
                else:
                    curr_h_tbl[new_tup] = vals

            def reset(self, tup: Tuple) -> None:
                curr_epoch = lookup_int(self.eid_key, tup)
                nonlocal curr_epoch_ref, other_epoch_ref
                while curr_epoch > curr_epoch_ref:
                    if other_epoch_ref > curr_epoch_ref:
                        self.next_op.reset({self.eid_key: OpResult("Int", curr_epoch_ref)})
                    curr_epoch_ref += 1

        return SideOperator()

def join(eid_key: str = "eid", left_extractor: Callable[[Tuple], PyTuple[Tuple, Tuple]], 
         right_extractor: Callable[[Tuple], PyTuple[Tuple, Tuple]], next_op: Operator) -> PyTuple[Operator, Operator]:
    join_op = JoinOperator(eid_key, left_extractor, right_extractor, next_op)
    op1 = join_op.handle_join_side(join_op.h_tbl1, join_op.h_tbl2, join_op.left_curr_epoch, join_op.right_curr_epoch, left_extractor)
    op2 = join_op.handle_join_side(join_op.h_tbl2, join_op.h_tbl1, join_op.right_curr_epoch, join_op.left_curr_epoch, right_extractor)
    return op1, op2

def rename_filtered_keys(renamings_pairs: List[PyTuple[str, str]]) -> Callable[[Tuple], Tuple]:
    def rename(tup: Tuple) -> Tuple:
        new_tup = {}
        for old_key, new_key in renamings_pairs:
            if old_key in tup:
                new_tup[new_key] = tup[old_key]
        return new_tup
    return rename

def filter_groups(keys: List[str]) -> Callable[[Tuple], Tuple]:
    def filter_func(tup: Tuple) -> Tuple:
        return {k: v for k, v in tup.items() if k in keys}
    return filter_func

def filter(predicate: Callable[[Tuple], bool], next_op: Operator) -> Operator:
    class FilterOperator(Operator):
        def next(self, tup: Tuple) -> None:
            if predicate(tup):
                next_op.next(tup)
        def reset(self, tup: Tuple) -> None:
            next_op.reset(tup)
    return FilterOperator()

def map(transform: Callable[[Tuple], Tuple], next_op: Operator) -> Operator:
    class MapOperator(Operator):
        def next(self, tup: Tuple) -> None:
            next_op.next(transform(tup))
        def reset(self, tup: Tuple) -> None:
            next_op.reset(tup)
    return MapOperator()

def key_geq_int(key: str, threshold: int) -> Callable[[Tuple], bool]:
    def predicate(tup: Tuple) -> bool:
        return lookup_int(key, tup) >= threshold
    return predicate

# Placeholder for groupby and counter (simplified)
def groupby(key_func: Callable[[Tuple], Tuple], agg_func: Callable[[Tuple], Operator], 
            agg_key: str, next_op: Operator) -> Operator:
    class GroupByOperator(Operator):
        def __init__(self):
            self.groups = defaultdict(int)
        def next(self, tup: Tuple) -> None:
            key = key_func(tup)
            self.groups[str(key)] += 1
            next_op.next({**tup, agg_key: OpResult("Int", self.groups[str(key)])})
        def reset(self, tup: Tuple) -> None:
            next_op.reset(tup)
    return GroupByOperator()

def syn_flood_sonata(next_op: Operator) -> List[Operator]:
    threshold = 3
    epoch_dur = 1.0

    def syns(next_op: Operator) -> Operator:
        def filter_func(tup: Tuple) -> bool:
            return lookup_int("ipv4.proto", tup) == 6 and lookup_int("l4.flags", tup) == 2
        return epoch(epoch_dur, "eid", filter(filter_func, groupby(filter_groups(["ipv4.dst"]), lambda x: x, "syns", next_op)))

    def synacks(next_op: Operator) -> Operator:
        def filter_func(tup: Tuple) -> bool:
            return lookup_int("ipv4.proto", tup) == 6 and lookup_int("l4.flags", tup) == 18
        return epoch(epoch_dur, "eid", filter(filter_func, groupby(filter_groups(["ipv4.src"]), lambda x: x, "synacks", next_op)))

    def acks(next_op: Operator) -> Operator:
        def filter_func(tup: Tuple) -> bool:
            return lookup_int("ipv4.proto", tup) == 6 and lookup_int("l4.flags", tup) == 16
        return epoch(epoch_dur, "eid", filter(filter_func, groupby(filter_groups(["ipv4.dst"]), lambda x: x, "acks", next_op)))

    def join_op1_extractor(tup: Tuple) -> PyTuple[Tuple, Tuple]:
        return filter_groups(["host"])(tup), filter_groups(["syns+synacks"])(tup)

    def join_op2_extractor(tup: Tuple) -> PyTuple[Tuple, Tuple]:
        return rename_filtered_keys([("ipv4.dst", "host")])(tup), filter_groups(["acks"])(tup)

    def map_func(tup: Tuple) -> Tuple:
        syns_synacks = lookup_int("syns+synacks", tup)
        acks = lookup_int("acks", tup)
        return {**tup, "syns+synacks-acks": OpResult("Int", syns_synacks - acks)}

    join_op1, join_op2 = join(left_extractor=join_op1_extractor, right_extractor=join_op2_extractor, 
                              next_op=map(map_func, filter(key_geq_int("syns+synacks-acks", threshold), next_op)))

    def join_op3_extractor(tup: Tuple) -> PyTuple[Tuple, Tuple]:
        return rename_filtered_keys([("ipv4.dst", "host")])(tup), filter_groups(["syns"])(tup)

    def join_op4_extractor(tup: Tuple) -> PyTuple[Tuple, Tuple]:
        return rename_filtered_keys([("ipv4.src", "host")])(tup), filter_groups(["synacks"])(tup)

    def map_func2(tup: Tuple) -> Tuple:
        syns = lookup_int("syns", tup)
        synacks = lookup_int("synacks", tup)
        return {**tup, "syns+synacks": OpResult("Int", syns + synacks)}

    join_op3, join_op4 = join(left_extractor=join_op3_extractor, right_extractor=join_op4_extractor, 
                              next_op=map(map_func2, join_op1))

    return [syns(join_op3), synacks(join_op4), acks(join_op2)]

def completed_flows(next_op: Operator) -> List[Operator]:
    threshold = 1
    epoch_dur = 30.0

    def syns(next_op: Operator) -> Operator:
        def filter_func(tup: Tuple) -> bool:
            return lookup_int("ipv4.proto", tup) == 6 and lookup_int("l4.flags", tup) == 2
        return epoch(epoch_dur, "eid", filter(filter_func, groupby(filter_groups(["ipv4.dst"]), lambda x: x, "syns", next_op)))

    def fins(next_op: Operator) -> Operator:
        def filter_func(tup: Tuple) -> bool:
            return lookup_int("ipv4.proto", tup) == 6 and (lookup_int("l4.flags", tup) & 1) == 1
        return epoch(epoch_dur, "eid", filter(filter_func, groupby(filter_groups(["ipv4.src"]), lambda x: x, "fins", next_op)))

    def join_op1_extractor(tup: Tuple) -> PyTuple[Tuple, Tuple]:
        return rename_filtered_keys([("ipv4.dst", "host")])(tup), filter_groups(["syns"])(tup)

    def join_op2_extractor(tup: Tuple) -> PyTuple[Tuple, Tuple]:
        return rename_filtered_keys([("ipv4.src", "host")])(tup), filter_groups(["fins"])(tup)

    def map_func(tup: Tuple) -> Tuple:
        syns = lookup_int("syns", tup)
        fins = lookup_int("fins", tup)
        return {**tup, "diff": OpResult("Int", syns - fins)}

    op1, op2 = join(left_extractor=join_op1_extractor, right_extractor=join_op2_extractor, 
                    next_op=map(map_func, filter(key_geq_int("diff", threshold), next_op)))

    return [syns(op1), fins(op2)]


def slowloris(next_op: Operator) -> List[Operator]:
    threshold = 5
    epoch_dur = 10.0

    def connections(next_op: Operator) -> Operator:
        def filter_func(tup: Tuple) -> bool:
            return lookup_int("ipv4.proto", tup) == 6 and lookup_int("l4.flags", tup) == 2
        return epoch(epoch_dur, "eid", filter(filter_func, groupby(filter_groups(["ipv4.dst"]), lambda x: x, "conns", next_op)))

    def map_func(tup: Tuple) -> Tuple:
        conns = lookup_int("conns", tup)
        return {**tup, "conns": OpResult("Int", conns)}

    op = connections(map(map_func, filter(key_geq_int("conns", threshold), next_op)))
    return [op]

import sys

class DumpTupleOperator(Operator):
    def __init__(self, out):
        self.out = out
    def next(self, tup: Tuple) -> None:
        print({k: v.value for k, v in tup.items()}, file=self.out)
    def reset(self, tup: Tuple) -> None:
        pass

def ident(next_op: Operator) -> Operator:
    return next_op

def run_queries(queries: List[Operator]):
    # Sample tuples for testing
    tuples = [
        {
            "time": OpResult("Float", 0.000000 + i),
            "ipv4.proto": OpResult("Int", 6),
            "ipv4.src": OpResult("IPv4", ipaddress.IPv4Address("127.0.0.1")),
            "ipv4.dst": OpResult("IPv4", ipaddress.IPv4Address("127.0.0.2")),
            "l4.sport": OpResult("Int", 440 + i),
            "l4.dport": OpResult("Int", 80),
            "l4.flags": OpResult("Int", 2 if i < 10 else 18 if i < 15 else 16),
            "eid": OpResult("Int", i // 5)
        } for i in range(20)
    ]
    for tup in tuples:
        for query in queries:
            query.next(tup)
    print("Done")

def main():
    queries = [ident(DumpTupleOperator(sys.stdout))]
    # Example usage with a query
    # queries = syn_flood_sonata(DumpTupleOperator(sys.stdout))
    run_queries(queries)

if __name__ == "__main__":
    main()