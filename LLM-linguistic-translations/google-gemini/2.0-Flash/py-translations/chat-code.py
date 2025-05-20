from typing import Dict, Callable, Tuple as PyTuple, List, Optional, IO, Any
import ipaddress
import struct
from collections import OrderedDict
import time

# Type alias for the named tuple
Tuple = Dict[str, Any]

# Variant type for operation results
class OpResult:
    def __repr__(self):
        return str(self.value)

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
    def __init__(self):
        self.value = None

# Data processing unit in a stream processing pipeline
class Operator:
    def __init__(self, next_func: Callable[[Tuple], None], reset_func: Callable[[Tuple], None]):
        self.next = next_func
        self.reset = reset_func

OpCreator = Callable[[Operator], Operator]
DblOpCreator = Callable[[Operator], PyTuple[Operator, Operator]]

# Right associative "chaining" operator
def chain(op_creator_func: OpCreator) -> Callable[[Operator], Operator]:
    def _apply(next_op: Operator) -> Operator:
        return op_creator_func(next_op)
    return _apply

# Python doesn't have a direct equivalent to the infix operator, so we'll use a function
at_equals_greater_than = chain

def double_chain(op_creator_func: DblOpCreator) -> Callable[[Operator], PyTuple[Operator, Operator]]:
    def _apply(op: Operator) -> PyTuple[Operator, Operator]:
        return op_creator_func(op)
    return _apply

at_double_equals_greater_than = double_chain

# Conversion utilities

# Formats the 6 bytes of the MAC address as a colon-separated string in hex
def string_of_mac(buf: bytes) -> str:
    return ":".join(f"{b:02x}" for b in buf)

# Converts TCP flags into a human-readable string representation
def tcp_flags_to_strings(flags: int) -> str:
    tcp_flags_map = OrderedDict([
        ("FIN", 1 << 0),
        ("SYN", 1 << 1),
        ("RST", 1 << 2),
        ("PSH", 1 << 3),
        ("ACK", 1 << 4),
        ("URG", 1 << 5),
        ("ECE", 1 << 6),
        ("CWR", 1 << 7),
    ])
    active_flags = [key for key, value in tcp_flags_map.items() if flags & value == value]
    return "|".join(active_flags)

# Checks if input is an Int OpResult, raises exception otherwise
def int_of_op_result(input_val: OpResult) -> int:
    if isinstance(input_val, Int):
        return input_val.value
    raise ValueError("Trying to extract int from non-int result")

# Checks if input is a Float OpResult, raises exception otherwise
def float_of_op_result(input_val: OpResult) -> float:
    if isinstance(input_val, Float):
        return input_val.value
    raise ValueError("Trying to extract float from non-float result")

# Returns the human-readable version of each OpResult value
def string_of_op_result(input_val: OpResult) -> str:
    if isinstance(input_val, Float):
        return f"{input_val.value}"
    elif isinstance(input_val, Int):
        return str(input_val.value)
    elif isinstance(input_val, IPv4):
        return str(input_val.value)
    elif isinstance(input_val, MAC):
        return string_of_mac(input_val.value)
    elif isinstance(input_val, Empty):
        return "Empty"
    return str(input_val)

# Outputs the tuple in a human-readable form
def string_of_tuple(input_tuple: Tuple) -> str:
    return ", ".join(f"\"{key}\" => {string_of_op_result(value)}" for key, value in input_tuple.items()) + ", "

# Creates a Tuple (Dict[str, OpResult]) out of a list of tuples
def tuple_of_list(tup_list: List[PyTuple[str, OpResult]]) -> Tuple:
    return dict(tup_list)

# Prints formatted representation of a Tuple
def dump_tuple_func(outc: IO[str], tup: Tuple) -> None:
    print(string_of_tuple(tup), file=outc)

# Retrieves the int value of the OpResult associated with a given key in the given Tuple
def lookup_int(key: str, tup: Tuple) -> int:
    return int_of_op_result(tup[key])

# Retrieves the float value of the OpResult associated with a given key in the given Tuple
def lookup_float(key: str, tup: Tuple) -> float:
    return float_of_op_result(tup[key])

# Built-in operator definitions and common utilities for readability

init_table_size: int = 10000

# Dump all fields of all tuples to the given output channel
def dump_tuple(outc: IO[str], show_reset: bool = False) -> Operator:
    def next_func(tup: Tuple) -> None:
        dump_tuple_func(outc, tup)
    def reset_func(tup: Tuple) -> None:
        if show_reset:
            dump_tuple_func(outc, tup)
            print("[reset]", file=outc)
    return Operator(next_func, reset_func)

# Tries to dump a nice csv-style output
def dump_as_csv(outc: IO[str], static_field: Optional[PyTuple[str, str]] = None, header: bool = True) -> Operator:
    first = [header]  # Using a list to make it mutable within the nested function

    def next_func(tup: Tuple) -> None:
        if first[0]:
            if static_field:
                print(f"{static_field[0]},", end="", file=outc)
            print(",".join(tup.keys()) + ",", file=outc)
            first[0] = False

        if static_field:
            print(f"{static_field[1]},", end="", file=outc)
        print(",".join(string_of_op_result(value) for value in tup.values()) + ",", file=outc)

    def reset_func(tup: Tuple) -> None:
        pass

    return Operator(next_func, reset_func)

# Dumps csv in Walt's canonical csv format
def dump_walts_csv(filename: str) -> Operator:
    outc = [None]  # Using a list to make it mutable within the nested function
    first = [True]

    def next_func(tup: Tuple) -> None:
        if first[0]:
            outc[0] = open(filename, "w")
            first[0] = False
        print(
            f"{string_of_op_result(tup['ipv4.src'])},{string_of_op_result(tup['ipv4.dst'])},"
            f"{string_of_op_result(tup['l4.sport'])},{string_of_op_result(tup['l4.dport'])},"
            f"{string_of_op_result(tup['packet_count'])},{string_of_op_result(tup['byte_count'])},"
            f"{string_of_op_result(tup['epoch_id'])}",
            file=outc[0]
        )

    def reset_func(tup: Tuple) -> None:
        pass

    return Operator(next_func, reset_func)

# input is either "0" or and IPv4 address in string format, returns corresponding OpResult
def get_ip_or_zero(input_str: str) -> OpResult:
    if input_str == "0":
        return Int(0)
    else:
        return IPv4(ipaddress.IPv4Address(input_str))

# Reads an intermediate result CSV in Walt's canonical format
def read_walts_csv(file_names: List[str], ops: List[Operator], epoch_id_key: str = "eid") -> None:
    inchs_eids_tupcount = [(open(filename, "r"), [0], [0]) for filename in file_names]
    running = len(ops)

    while running > 0:
        for (in_ch, eid, tup_count), op in zip(inchs_eids_tupcount, ops):
            if eid[0] >= 0:
                try:
                    line = in_ch.readline().strip()
                    if not line:
                        raise StopIteration
                    parts = line.split(',')
                    if len(parts) != 7:
                        raise ValueError(f"Expected 7 comma-separated values, got {len(parts)}")
                    src_ip_str, dst_ip_str, src_l4_port_str, dst_l4_port_str, packet_count_str, byte_count_str, epoch_id_str = parts
                    src_l4_port = int(src_l4_port_str)
                    dst_l4_port = int(dst_l4_port_str)
                    packet_count = int(packet_count_str)
                    byte_count = int(byte_count_str)
                    epoch_id = int(epoch_id_str)

                    p: Tuple = {}
                    p["ipv4.src"] = get_ip_or_zero(src_ip_str)
                    p["ipv4.dst"] = get_ip_or_zero(dst_ip_str)
                    p["l4.sport"] = Int(src_l4_port)
                    p["l4.dport"] = Int(dst_l4_port)
                    p["packet_count"] = Int(packet_count)
                    p["byte_count"] = Int(byte_count)
                    p[epoch_id_key] = Int(epoch_id)

                    tup_count[0] += 1
                    if epoch_id > eid[0]:
                        while epoch_id > eid[0]:
                            op.reset({"tuples": Int(tup_count[0]), epoch_id_key: Int(eid[0])})
                            tup_count[0] = 0
                            eid[0] += 1
                    op.next({"tuples": Int(tup_count[0]), **p})

                except ValueError as e:
                    print(f"Failed to parse line: {e}")
                    raise
                except StopIteration:
                    op.reset({"tuples": Int(tup_count[0]), epoch_id_key: Int(eid[0] + 1)})
                    running -= 1
                    eid[0] = -1
                except Exception as e:
                    print(f"An unexpected error occurred: {e}")
                    raise
    print("Done.")
    for in_ch, _, _ in inchs_eids_tupcount:
        in_ch.close()

# Write the number of tuples passing through this operator each epoch to the out_channel
def meta_meter(name: str, outc: IO[str], next_op: Operator, static_field: Optional[str] = None) -> Operator:
    epoch_count = [0]
    tups_count = [0]

    def next_func(tup: Tuple) -> None:
        tups_count[0] += 1
        next_op.next(tup)

    def reset_func(tup: Tuple) -> None:
        static_val = static_field if static_field is not None else ""
        print(f"{epoch_count[0]},{name},{tups_count[0]},{static_val}", file=outc)
        tups_count[0] = 0
        epoch_count[0] += 1
        next_op.reset(tup)

    return Operator(next_func, reset_func)

# Passes tuples through to op, Resets op every w seconds, Adds epoch id to tuple under key_out
def epoch(epoch_width: float, key_out: str, next_op: Operator) -> Operator:
    epoch_boundary = [0.0]
    eid = [0]

    def next_func(tup: Tuple) -> None:
        time_val = float_of_op_result(tup["time"])
        if epoch_boundary[0] == 0.0:
            epoch_boundary[0] = time_val + epoch_width
        elif time_val >= epoch_boundary[0]:
            while time_val >= epoch_boundary[0]:
                next_op.reset({key_out: Int(eid[0])})
                epoch_boundary[0] += epoch_width
                eid[0] += 1
        next_op.next({key_out: Int(eid[0]), **tup})

    def reset_func(tup: Tuple) -> None:
        next_op.reset({key_out: Int(eid[0])})
        epoch_boundary[0] = 0.0
        eid[0] = 0

    return Operator(next_func, reset_func)

# Passes only tuples where f applied to the tuple returns true
def filter_op(f: Callable[[Tuple], bool], next_op: Operator) -> Operator:
    def next_func(tup: Tuple) -> None:
        if f(tup):
            next_op.next(tup)
    def reset_func(tup: Tuple) -> None:
        next_op.reset(tup)
    return Operator(next_func, reset_func)

# (filter utility) comparison function for testing int values against a threshold
def key_geq_int(key: str, threshold: int, tup: Tuple) -> bool:
    return lookup_int(key, tup) >= threshold

# (filter utility) Looks up the given key and converts to Int OpResult
def get_mapped_int(key: str, tup: Tuple) -> int:
    return lookup_int(key, tup)

# (filter utility) Looks up the given key and converts to Float OpResult
def get_mapped_float(key: str, tup: Tuple) -> float:
    return lookup_float(key, tup)

# Operator which applied the given function on all tuples, Passes resets unchanged
def map_op(f: Callable[[Tuple], Tuple], next_op: Operator) -> Operator:
    def next_func(tup: Tuple) -> None:
        next_op.next(f(tup))
    def reset_func(tup: Tuple) -> None:
        next_op.reset(tup)
    return Operator(next_func, reset_func)

GroupingFunc = Callable[[Tuple], Tuple]
ReductionFunc = Callable[[OpResult, Tuple], OpResult]

# Groups the input Tuples according to canonic members returned by key_extractor
def groupby(groupby_func: GroupingFunc, reduce_func: ReductionFunc, out_key: str, next_op: Operator) -> Operator:
    h_tbl: Dict[Tuple, OpResult] = {}
    reset_counter = [0]

    def next_func(tup: Tuple) -> None:
        grouping_key = groupby_func(tup)
        if grouping_key in h_tbl:
            h_tbl[grouping_key] = reduce_func(h_tbl[grouping_key], tup)
        else:
            h_tbl[grouping_key] = reduce_func(Empty(), tup)

    def reset_func(tup: Tuple) -> None:
        reset_counter[0] += 1
        for grouping_key, value in h_tbl.items():
            unioned_tup = {**tup, **grouping_key}
            next_op.next({out_key: value, **unioned_tup})
        next_op.reset(tup)
        h_tbl.clear()

    return Operator(next_func, reset_func)

# (groupby utility : key_extractor) Returns a new tuple with only the keys included in the incl_keys list
def filter_groups(incl_keys: List[str], tup: Tuple) -> Tuple:
    return {key: value for key, value in tup.items() if key in incl_keys}

# (groupby utility : key_extractor) Grouping function that forms a single group
def single_group(tup: Tuple) -> Tuple:
    return {}

# (groupby utility : grouping_mech) Reduction function to count tuples
def counter(val: OpResult, tup: Tuple) -> OpResult:
    if isinstance(val, Empty):
        return Int(1)
    elif isinstance(val, Int):
        return Int(val.value + 1)
    return val

# (groupby utility) Reduction

# (groupby utility) Reduction function (f) to sum values (assumed to be Int ()) of a given field
def sum_ints(search_key: str, init_val: OpResult, tup: Tuple) -> OpResult:
    if isinstance(init_val, Empty):
        return Int(0)
    elif isinstance(init_val, Int):
        if search_key in tup and isinstance(tup[search_key], Int):
            return Int(init_val.value + tup[search_key].value)
        else:
            raise ValueError(f"'sum_vals' function failed to find integer value mapped to \"{search_key}\"")
    return init_val

# Returns a list of distinct elements (as determined by group_tup) each epoch
def distinct_op(groupby_func: GroupingFunc, next_op: Operator) -> Operator:
    h_tbl: Dict[Tuple, bool] = {}
    reset_counter = [0]

    def next_func(tup: Tuple) -> None:
        grouping_key = groupby_func(tup)
        h_tbl[grouping_key] = True

    def reset_func(tup: Tuple) -> None:
        reset_counter[0] += 1
        for key in h_tbl.keys():
            merged_tup = {**tup, **key}
            next_op.next(merged_tup)
        next_op.reset(tup)
        h_tbl.clear()

    return Operator(next_func, reset_func)

# Just sends both next and reset directly to two different downstream operators
def split_op(l: Operator, r: Operator) -> Operator:
    def next_func(tup: Tuple) -> None:
        l.next(tup)
        r.next(tup)
    def reset_func(tup: Tuple) -> None:
        l.reset(tup)
        r.reset(tup)
    return Operator(next_func, reset_func)

KeyExtractor = Callable[[Tuple], PyTuple[Tuple, Tuple]]

# Initial shot at a join semantic that doesn't require maintaining entire state
def join_op(left_extractor: KeyExtractor, right_extractor: KeyExtractor, next_op: Operator, eid_key: str = "eid") -> PyTuple[Operator, Operator]:
    h_tbl1: Dict[Tuple, Tuple] = {}
    h_tbl2: Dict[Tuple, Tuple] = {}
    left_curr_epoch = [0]
    right_curr_epoch = [0]

    def handle_join_side(curr_h_tbl: Dict[Tuple, Tuple], other_h_tbl: Dict[Tuple, Tuple],
                         curr_epoch_ref: List[int], other_epoch_ref: List[int],
                         f: KeyExtractor) -> Operator:
        def next_func(tup: Tuple) -> None:
            key, vals_ = f(tup)
            curr_epoch = get_mapped_int(eid_key, tup)

            while curr_epoch > curr_epoch_ref[0]:
                if other_epoch_ref[0] > curr_epoch_ref[0]:
                    next_op.reset({eid_key: Int(curr_epoch_ref[0])})
                curr_epoch_ref[0] += 1

            new_tup = {eid_key: Int(curr_epoch), **key}
            if new_tup in other_h_tbl:
                val_ = other_h_tbl.pop(new_tup)
                use_left = lambda _k, a, _b: a
                merged_tup = {**new_tup, **vals_, **val_}
                next_op.next(merged_tup)
            else:
                curr_h_tbl[new_tup] = vals_

        def reset_func(tup: Tuple) -> None:
            curr_epoch = get_mapped_int(eid_key, tup)
            while curr_epoch > curr_epoch_ref[0]:
                if other_epoch_ref[0] > curr_epoch_ref[0]:
                    next_op.reset({eid_key: Int(curr_epoch_ref[0])})
                curr_epoch_ref[0] += 1

        return Operator(next_func, reset_func)

    op1 = handle_join_side(h_tbl1, h_tbl2, left_curr_epoch, right_curr_epoch, left_extractor)
    op2 = handle_join_side(h_tbl2, h_tbl1, right_curr_epoch, left_curr_epoch, right_extractor)
    return op1, op2

# (join utility) Returns a new tuple with renamed and filtered keys
def rename_filtered_keys(renamings_pairs: List[PyTuple[str, str]], in_tup: Tuple) -> Tuple:
    new_tup = {}
    for old_key, new_key in renamings_pairs:
        if old_key in in_tup:
            new_tup[new_key] = in_tup[old_key]
    return new_tup

# Main entry point and implementation for simple header-dump operation

# See builtins.ml for definitions of building blocks used here
# '@=>' is just a right-associative application (simulated with function calls)

# counts total number of packets observed in an epoch
def ident(next_op: Operator) -> Operator:
    def filter_func(tup: Tuple) -> Tuple:
        return {key: value for key, value in tup.items() if key not in ["eth.src", "eth.dst"]}
    return at_equals_greater_than(map_op(filter_func))(next_op)

# assigns each tuple an epoch ID based on time by adding an eid key, counts the number of tuples in each epoch
def count_pkts(next_op: Operator) -> Operator:
    return at_equals_greater_than(epoch(1.0, "eid"))(
        at_equals_greater_than(groupby(single_group, counter, "pkts"))(next_op)
    )

# assigns each tuple an epoch ID based on time by adding an eid key, groups them by source and dest ip
def pkts_per_src_dst(next_op: Operator) -> Operator:
    return at_equals_greater_than(epoch(1.0, "eid"))(
        at_equals_greater_than(groupby(filter_groups(["ipv4.src", "ipv4.dst"]), counter, "pkts"))(next_op)
    )

def distinct_srcs(next_op: Operator) -> Operator:
    return at_equals_greater_than(epoch(1.0, "eid"))(
        at_equals_greater_than(distinct_op(filter_groups(["ipv4.src"])))(
            at_equals_greater_than(groupby(single_group, counter, "srcs"))(next_op)
        )
    )

# Sonata 1
def tcp_new_cons(next_op: Operator) -> Operator:
    threshold: int = 40
    def filter_func(tup: Tuple) -> bool:
        return get_mapped_int("ipv4.proto", tup) == 6 and get_mapped_int("l4.flags", tup) == 2
    return at_equals_greater_than(epoch(1.0, "eid"))(
        at_equals_greater_than(filter_op(filter_func))(
            at_equals_greater_than(groupby(filter_groups(["ipv4.dst"]), counter, "cons"))(
                at_equals_greater_than(filter_op(lambda tup: key_geq_int("cons", threshold, tup)))(next_op)
            )
        )
    )

# Sonata 2
def ssh_brute_force(next_op: Operator) -> Operator:
    threshold: int = 40
    def filter_func(tup: Tuple) -> bool:
        return get_mapped_int("ipv4.proto", tup) == 6 and get_mapped_int("l4.dport", tup) == 22
    return at_equals_greater_than(epoch(1.0, "eid"))(
        at_equals_greater_than(distinct_op(filter_groups(["ipv4.src", "ipv4.dst", "ipv4.len"])))(
            at_equals_greater_than(groupby(filter_groups(["ipv4.dst", "ipv4.len"]), counter, "srcs"))(
                at_equals_greater_than(filter_op(lambda tup: key_geq_int("srcs", threshold, tup)))(next_op)
            )
        )
    )

# Sonata 3
def super_spreader(next_op: Operator) -> Operator:
    threshold: int = 40
    return at_equals_greater_than(epoch(1.0, "eid"))(
        at_equals_greater_than(distinct_op(filter_groups(["ipv4.src", "ipv4.dst"])))(
            at_equals_greater_than(groupby(filter_groups(["ipv4.src"]), counter, "dsts"))(
                at_equals_greater_than(filter_op(lambda tup: key_geq_int("dsts", threshold, tup)))(next_op)
            )
        )
    )

# Sonata 4
def port_scan(next_op: Operator) -> Operator:
    threshold: int = 40
    return at_equals_greater_than(epoch(1.0, "eid"))(
        at_equals_greater_than(distinct_op(filter_groups(["ipv4.src", "l4.dport"])))(
            at_equals_greater_than(groupby(filter_groups(["ipv4.src"]), counter, "ports"))(
                at_equals_greater_than(filter_op(lambda tup: key_geq_int("ports", threshold, tup)))(next_op)
            )
        )
    )

# Sonata 5
def ddos(next_op: Operator) -> Operator:
    threshold: int = 45
    return at_equals_greater_than(epoch(1.0, "eid"))(
        at_equals_greater_than(distinct_op(filter_groups(["ipv4.src", "ipv4.dst"])))(
            at_equals_greater_than(groupby(filter_groups(["ipv4.dst"]), counter, "srcs"))(
                at_equals_greater_than(filter_op(lambda tup: key_geq_int("srcs", threshold, tup)))(next_op)
            )
        )
    )

# Sonata 6 --- Note this implements the Sonata semantic of this query *NOT* the intended semantic from NetQRE
def syn_flood_sonata(next_op: Operator) -> List[Operator]:
    threshold: int = 3
    epoch_dur: float = 1.0

    def syns(next_op: Operator) -> Operator:
        def filter_func(tup: Tuple) -> bool:
            return get_mapped_int("ipv4.proto", tup) == 6 and get_mapped_int("l4.flags", tup) == 2
        return at_equals_greater_than(epoch(epoch_dur, "eid"))(
            at_equals_greater_than(filter_op(filter_func))(
                at_equals_greater_than(groupby(filter_groups(["ipv4.dst"]), counter, "syns"))(next_op)
            )
        )

    def synacks(next_op: Operator) -> Operator:
        def filter_func(tup: Tuple) -> bool:
            return get_mapped_int("ipv4.proto", tup) == 6 and get_mapped_int("l4.flags", tup) == 18
        return at_equals_greater_than(epoch(epoch_dur, "eid"))(
            at_equals_greater_than(filter_op(filter_func))(
                at_equals_greater_than(groupby(filter_groups(["ipv4.src"]), counter, "synacks"))(next_op)
            )
        )

    def acks(next_op: Operator) -> Operator:
        def filter_func(tup: Tuple) -> bool:
            return get_mapped_int("ipv4.proto", tup) == 6 and get_mapped_int("l4.flags", tup) == 16
        return at_equals_greater_than(epoch(epoch_dur, "eid"))(
            at_equals_greater_than(filter_op(filter_func))(
                at_equals_greater_than(groupby(filter_groups(["ipv4.dst"]), counter, "acks"))(next_op)
            )
        )

    join_op1, join_op2 = at_double_equals_greater_than(
        join_op(
            lambda tup: (filter_groups(["host"], tup), filter_groups(["syns+synacks"], tup)),
            lambda tup: (rename_filtered_keys([("ipv4.dst", "host")], tup), filter_groups(["acks"], tup))
        )
    )(at_equals_greater_than(map_op(lambda tup: {**tup, "syns+synacks-acks": Int(get_mapped_int("syns+synacks", tup) - get_mapped_int("acks", tup))}))(
        at_equals_greater_than(filter_op(lambda tup: key_geq_int("syns+synacks-acks", threshold, tup)))(next_op)
    ))

    join_op3, join_op4 = at_double_equals_greater_than(
        join_op(
            lambda tup: (rename_filtered_keys([("ipv4.dst", "host")], tup), filter_groups(["syns"], tup)),
            lambda tup: (rename_filtered_keys([("ipv4.src", "host")], tup), filter_groups(["synacks"], tup))
        )
    )(at_equals_greater_than(map_op(lambda tup: {**tup, "syns+synacks": Int(get_mapped_int("syns", tup) + get_mapped_int("synacks", tup))}))(join_op1))

    return [syns(join_op3), synacks(join_op4), acks(join_op2)]

# Sonata 7
def completed_flows(next_op: Operator) -> List[Operator]:
    threshold: int = 1
    epoch_dur: float = 30.0

    def syns(next_op: Operator) -> Operator:
        def filter_func(tup: Tuple) -> bool:
            return get_mapped_int("ipv4.proto", tup) == 6 and get_mapped_int("l4.flags", tup) == 2
        return at_equals_greater_than(epoch(epoch_dur, "eid"))(
            at_equals_greater_than(filter_op(filter_func))(
                at_equals_greater_than(groupby(filter_groups(["ipv4.dst"]), counter, "syns"))(next_op)
            )
        )

    def fins(next_op: Operator) -> Operator:
        def filter_func(tup: Tuple) -> bool:
            return get_mapped_int("ipv4.proto", tup) == 6 and (get_mapped_int("l4.flags", tup) & 1) == 1
        return at_equals_greater_than(epoch(epoch_dur, "eid"))(
            at_equals_greater_than(filter_op(filter_func))(
                at_equals_greater_than(groupby(filter_groups(["ipv4.src"]), counter, "fins"))(next_op)
            )
        )

    op1, op2 = at_double_equals_greater_than(
        join_op(
            lambda tup: (rename_filtered_keys([("ipv4.dst", "host")], tup), filter_groups(["syns"], tup)),
            lambda tup: (rename_filtered_keys([("ipv4.src", "host")], tup), filter_groups(["fins"], tup))
        )
    )(at_equals_greater_than(map_op(lambda tup: {**tup, "diff": Int(get_mapped_int("syns", tup) - get_mapped_int("fins", tup))}))(
        at_equals_greater_than(filter_op(lambda tup: key_geq_int("diff", threshold, tup)))(next_op)
    ))

    return [syns(op1), fins(op2)]

# Sonata 8
def slowloris(next_op: Operator) -> List[Operator]:
    t1: int = 5
    t2: int = 500
    t3: int = 90
    epoch_dur: float = 1.0

    def n_conns(next_op: Operator) -> Operator:
        def filter_func(tup: Tuple) -> bool:
            return get_mapped_int("ipv4.proto", tup) == 6
        return at_equals_greater_than(epoch(epoch_dur, "eid"))(
            at_equals_greater_than(distinct_op(filter_groups(["ipv4.src", "ipv4.dst", "l4.sport"])))(
                at_equals_greater_than(groupby(filter_groups(["ipv4.dst"]), counter, "n_conns")
                )(
                    filter_op(lambda tup: get_mapped_int("n_conns", tup) >= t1)(next_op)
                )
            )
        )

    def n_bytes(next_op: Operator) -> Operator:
        def filter_func(tup: Tuple) -> bool:
            return get_mapped_int("ipv4.proto", tup) == 6
        return at_equals_greater_than(epoch(epoch_dur, "eid"))(
            at_equals_greater_than(
                groupby(filter_groups(["ipv4.dst"]), lambda acc, tup: sum_ints("ipv4.len", acc, tup), "n_bytes")
            )(
                filter_op(lambda tup: get_mapped_int("n_bytes", tup) >= t2)(next_op)
            )
        )

    op1, op2 = at_double_equals_greater_than(
        join_op(
            lambda tup: (filter_groups(["ipv4.dst"], tup), filter_groups(["n_conns"], tup)),
            lambda tup: (filter_groups(["ipv4.dst"], tup), filter_groups(["n_bytes"], tup))
        )
    )(
        at_equals_greater_than(
            map_op(lambda tup: {**tup, "bytes_per_conn": Int(get_mapped_int("n_bytes", tup) // get_mapped_int("n_conns", tup))})
        )(
            filter_op(lambda tup: get_mapped_int("bytes_per_conn", tup) <= t3)(next_op)
        )
    )

    return [n_conns(op1), n_bytes(op2)]

def join_test(next_op: Operator) -> List[Operator]:
    epoch_dur: float = 1.0

    def syns(next_op: Operator) -> Operator:
        def filter_func(tup: Tuple) -> bool:
            return get_mapped_int("ipv4.proto", tup) == 6 and get_mapped_int("l4.flags", tup) == 2
        return at_equals_greater_than(epoch(epoch_dur, "eid"))(filter_op(filter_func)(next_op))

    def synacks(next_op: Operator) -> Operator:
        def filter_func(tup: Tuple) -> bool:
            return get_mapped_int("ipv4.proto", tup) == 6 and get_mapped_int("l4.flags", tup) == 18
        return at_equals_greater_than(epoch(epoch_dur, "eid"))(filter_op(filter_func)(next_op))

    op1, op2 = at_double_equals_greater_than(
        join_op(
            lambda tup: (rename_filtered_keys([("ipv4.src", "host")], tup), rename_filtered_keys([("ipv4.dst", "remote")], tup)),
            lambda tup: (rename_filtered_keys([("ipv4.dst", "host")], tup), filter_groups(["time"], tup))
        )
    )(next_op)

    return [syns(op1), synacks(op2)]

def q3(next_op: Operator) -> Operator:
    return at_equals_greater_than(epoch(100.0, "eid"))(
        at_equals_greater_than(distinct_op(filter_groups(["ipv4.src", "ipv4.dst"])))(next_op)
    )

def q4(next_op: Operator) -> Operator:
    return at_equals_greater_than(epoch(10000.0, "eid"))(
        at_equals_greater_than(groupby(filter_groups(["ipv4.dst"]), counter, "pkts"))(next_op)
    )

queries: List[Operator] = [at_equals_greater_than(ident)(dump_tuple(sys.stdout))]

def run_queries() -> None:
    for i in range(20):
        tup: Tuple = {}
        tup["time"] = Float(0.000000 + float(i))
        tup["eth.src"] = MAC(bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]))
        tup["eth.dst"] = MAC(bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]))
        tup["eth.ethertype"] = Int(0x0800)
        tup["ipv4.hlen"] = Int(20)
        tup["ipv4.proto"] = Int(6)
        tup["ipv4.len"] = Int(60)
        tup["ipv4.src"] = IPv4(ipaddress.IPv4Address("127.0.0.1"))
        tup["ipv4.dst"] = IPv4(ipaddress.IPv4Address("127.0.0.1"))
        tup["l4.sport"] = Int(440)
        tup["l4.dport"] = Int(50000)
        tup["l4.flags"] = Int(10)

        for query in queries:
            query.next(tup)

# Main entrypoint
if __name__ == "__main__":
    import sys
    run_queries()
    print("Done")