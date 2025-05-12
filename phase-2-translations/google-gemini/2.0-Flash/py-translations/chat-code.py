from typing import Union, Dict, Callable, Tuple as PyTuple, List, Optional
import ipaddress
import binascii

# Define the equivalent of OCaml's Bytes type (using bytearray for mutability)
Bytes = bytearray

# Define the op_result variant type as a Python Union
OpResult = Union[float, int, ipaddress.IPv4Address, Bytes, None]

# Define the Tuple type as a dictionary mapping strings to OpResult
Tuple = Dict[str, OpResult]

# Define the operator record type as a Python dictionary or class
class Operator:
    def __init__(self, next_func: Callable[[Tuple], None], reset_func: Callable[[Tuple], None]):
        self.next = next_func
        self.reset = reset_func

OpCreator = Callable[[Operator], Operator]
DblOpCreator = Callable[[Operator], PyTuple[Operator, Operator]]

# Right associative "chaining" operator
def at_equals_greater_than(op_creator_func: OpCreator, next_op: Operator) -> Operator:
    return op_creator_func(next_op)

# Right associative "chaining" operator for double creators
def at_double_equals_greater_than(op_creator_func: DblOpCreator, op: Operator) -> PyTuple[Operator, Operator]:
    return op_creator_func(op)

# Conversion utilities

def string_of_mac(buf: Bytes) -> str:
    return ":".join(f"{byte:02x}" for byte in buf)

def tcp_flags_to_strings(flags: int) -> str:
    tcp_flags_map = {
        "FIN": 1 << 0,
        "SYN": 1 << 1,
        "RST": 1 << 2,
        "PSH": 1 << 3,
        "ACK": 1 << 4,
        "URG": 1 << 5,
        "ECE": 1 << 6,
        "CWR": 1 << 7,
    }
    active_flags = [key for key, value in tcp_flags_map.items() if flags & value == value]
    return "|".join(active_flags)

def int_of_op_result(input_val: OpResult) -> int:
    if isinstance(input_val, int):
        return input_val
    else:
        raise ValueError("Trying to extract int from non-int result")

def float_of_op_result(input_val: OpResult) -> float:
    if isinstance(input_val, float):
        return input_val
    else:
        raise ValueError("Trying to extract float from non-float result")

def string_of_op_result(input_val: OpResult) -> str:
    if isinstance(input_val, float):
        return f"{input_val}"
    elif isinstance(input_val, int):
        return str(input_val)
    elif isinstance(input_val, ipaddress.IPv4Address):
        return str(input_val)
    elif isinstance(input_val, Bytes):
        return string_of_mac(input_val)
    elif input_val is None:
        return "Empty"
    else:
        raise TypeError(f"Unsupported op_result type: {type(input_val)}")

def string_of_tuple(input_tuple: Tuple) -> str:
    return ", ".join(f"\"{key}\" => {string_of_op_result(value)}" for key, value in input_tuple.items()) + ", "

def tuple_of_list(tup_list: List[PyTuple[str, OpResult]]) -> Tuple:
    return dict(tup_list)

def dump_tuple_py(outc, tup: Tuple) -> None:
    print(string_of_tuple(tup), file=outc)

def lookup_int(key: str, tup: Tuple) -> int:
    return int_of_op_result(tup[key])

def lookup_float(key: str, tup: Tuple) -> float:
    return float_of_op_result(tup[key])

# Built-in operator definitions
# and common utilities for readability

init_table_size: int = 10000

# Dump all fields of all tuples to the given output channel
# Note that dump is terminal in that it does not take a continuation operator
# as argument
def dump_tuple_op(show_reset: bool = False, outc=None) -> Operator:
    if outc is None:
        import sys
        outc = sys.stdout
    def next_func(tup: Tuple) -> None:
        dump_tuple_py(outc, tup)
    def reset_func(tup: Tuple) -> None:
        if show_reset:
            dump_tuple_py(outc, tup)
            print("[reset]", file=outc)
    return Operator(next_func, reset_func)

# Tries to dump a nice csv-style output
# Assumes all tuples have the same fields in the same order...
def dump_as_csv(static_field: Optional[PyTuple[str, str]] = None, header: bool = True, outc=None) -> Operator:
    if outc is None:
        import sys
        outc = sys.stdout
    first = [header]  # Mutable boolean in a list

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

# Dumps csv in Walt's canonical csv format: src_ip, dst_ip, src_l4_port,
# dst_l4_port, packet_count, byte_count, epoch_id
# Unused fields are zeroed, map packet length to src_l4_port for ssh brute
# force
def dump_walts_csv(filename: str) -> Operator:
    outc = [None]
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
            file=outc[0],
        )

    def reset_func(tup: Tuple) -> None:
        if outc[0]:
            outc[0].close()

    return Operator(next_func, reset_func)

# input is either "0" or and IPv4 address in string format,
# returns corresponding op_result
def get_ip_or_zero(input_str: str) -> OpResult:
    if input_str == "0":
        return 0
    else:
        return ipaddress.IPv4Address(input_str)

# Reads an intermediate result CSV in Walt's canonical format
# Injects epoch ids and incomming tuple counts into reset call
# TODO: read files in RR order...
# otherwise the whole file gets cached in joins
# reads multiple CSV files, extracts their network flow data, processes it into
# tuples, and applies ops on the extracted data
def read_walts_csv(file_names: List[str], ops: List[Operator], epoch_id_key: str = "eid") -> None:
    inchs_eids_tupcount = [(open(filename, "r"), [0], [0]) for filename in file_names]
    running = [len(ops)]

    while running[0] > 0:
        for (in_ch, eid, tup_count), op in zip(inchs_eids_tupcount, ops):
            if eid[0] >= 0:
                try:
                    line = in_ch.readline().strip()
                    if not line:
                        raise EOFError
                    parts = line.split(',')
                    src_ip_str, dst_ip_str, src_l4_port_str, dst_l4_port_str, packet_count_str, byte_count_str, epoch_id_str = parts
                    src_ip = get_ip_or_zero(src_ip_str)
                    dst_ip = get_ip_or_zero(dst_ip_str)
                    src_l4_port = int(src_l4_port_str)
                    dst_l4_port = int(dst_l4_port_str)
                    packet_count = int(packet_count_str)
                    byte_count = int(byte_count_str)
                    epoch_id = int(epoch_id_str)

                    p: Tuple = {
                        "ipv4.src": src_ip,
                        "ipv4.dst": dst_ip,
                        "l4.sport": src_l4_port,
                        "l4.dport": dst_l4_port,
                        "packet_count": packet_count,
                        "byte_count": byte_count,
                        epoch_id_key: epoch_id,
                    }
                    tup_count[0] += 1
                    if epoch_id > eid[0]:
                        while epoch_id > eid[0]:
                            op.reset({"tuples": tup_count[0], epoch_id_key: eid[0]})
                            tup_count[0] = 0
                            eid[0] += 1
                    op.next({"tuples": tup_count[0], **p})

                except ValueError as e:
                    print(f"Failed to parse line: {e}")
                    raise
                except EOFError:
                    op.reset({"tuples": tup_count[0], epoch_id_key: eid[0] + 1})
                    running[0] -= 1
                    eid[0] = -1
                    in_ch.close()
                except Exception as e:
                    print(f"An unexpected error occurred: {e}")
                    raise
    print("Done.")

# Write the number of tuples passing through this operator each epoch
# to the out_channel
def meta_meter(name: str, outc=None, next_op: Optional[Operator] = None, static_field: Optional[str] = None) -> Operator:
    if outc is None:
        import sys
        outc = sys.stdout
    epoch_count = [0]
    tups_count = [0]

    def next_func(tup: Tuple) -> None:
        tups_count[0] += 1
        if next_op:
            next_op.next(tup)

    def reset_func(tup: Tuple) -> None:
        static_val = static_field if static_field is not None else ""
        print(f"{epoch_count[0]},{name},{tups_count[0]},{static_val}", file=outc)
        tups_count[0] = 0
        epoch_count[0] += 1
        if next_op:
            next_op.reset(tup)

    return Operator(next_func, reset_func)

# Passes tuples through to op
# Resets op every w seconds
# Adds epoch id to tuple under key_out
def epoch(epoch_width: float, key_out: str, next_op: Operator) -> Operator:
    epoch_boundary = [0.0]
    eid = [0]

    def next_func(tup: Tuple) -> None:
        time: float = float_of_op_result(tup["time"])
        if epoch_boundary[0] == 0.0:
            epoch_boundary[0] = time + epoch_width
        elif time >= epoch_boundary[0]:
            while time >= epoch_boundary[0]:
                next_op.reset({key_out: eid[0]})
                epoch_boundary[0] += epoch_width
                eid[0] += 1
        next_op.next({key_out: eid[0], **tup})

    def reset_func(tup: Tuple) -> None:
        next_op.reset({key_out: eid[0]})
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

# (filter utility)
# comparison function for testing int values against a threshold
def key_geq_int(key: str, threshold: int, tup: Tuple) -> bool:
    return int_of_op_result(tup[key]) >= threshold

# (filter utility)
# Looks up the given key and converts to Int op_result
# if the key does not hold an int, this will raise an exception
def get_mapped_int(key: str, tup: Tuple) -> int:
    return int_of_op_result(tup[key])

# (filter utility)
# Looks up the given key and converts to Float op_result
# if the key does not hold an int, this will raise an exception
def get_mapped_float(key: str, tup: Tuple) -> float:
    return float_of_op_result(tup[key])

# Operator which applied the given function on all tuples
# Passes resets, unchanged
def map_op(f: Callable[[Tuple], Tuple], next_op: Operator) -> Operator:
    def next_func(tup: Tuple) -> None:
        next_op.next(f(tup))
    def reset_func(tup: Tuple) -> None:
        next_op.reset(tup)
    return Operator(next_func, reset_func)

GroupingFunc = Callable[[Tuple], Tuple]
ReductionFunc = Callable[[OpResult, Tuple], OpResult]

# Groups the input Tuples according to canonic members returned by
#   key_extractor : Tuple -> Tuple
# Tuples in each group are folded (starting with Empty) by
#   accumulate : op_result -> Tuple -> op_result
# When reset, op is passed a Tuple for each group containing the union of
#   (i) the reset argument tuple,
#   (ii) the result of g for that group, and
#   (iii) a mapping from out_key to the result of the fold for that group
def groupby(groupby_func: GroupingFunc, reduce_func: ReductionFunc, out_key: str, next_op: Operator) -> Operator:
    h_tbl: Dict[Tuple, OpResult] = {}
    reset_counter = [0]

    def next_func(tup: Tuple) -> None:
        grouping_key: Tuple = groupby_func(tup)
        if grouping_key in h_tbl:
            h_tbl[grouping_key] = reduce_func(h_tbl[grouping_key], tup)
        else:
            h_tbl[grouping_key] = reduce_func(None, tup)

    def reset_func(tup: Tuple) -> None:
        reset_counter[0] += 1
        for grouping_key, value in h_tbl.items():
            merged_tup: Tuple = {**tup, **grouping_key, out_key: value}
            next_op.next(merged_tup)
        next_op.reset(tup)
        h_tbl.clear()

    return Operator(next_func, reset_func)

# (groupby utility : key_extractor)
# Returns a new tuple with only the keys included in the incl_keys list
def filter_groups(incl_keys: List[str], tup: Tuple) -> Tuple:
    return {key: value for key, value in tup.items() if key in incl_keys}

# (groupby utility : key_extractor)
# Grouping function (key_extractor) that forms a single group
def single_group(tup: Tuple) -> Tuple:
    return {}

# (groupby utility : grouping_mech)
# Reduction function (f) to count tuples
def counter(val_: Optional[OpResult], tup: Tuple) -> OpResult:
    if val_ is None:
        return 1
    elif isinstance(val_, int):
        return val_ + 1
    else:
        return val_

# (groupby utility)
# Reduction function (f) to sum values (assumed to be Int ()) of a given field
def sum_ints(search_key: str, init_val: Optional[OpResult], tup: Tuple) -> OpResult:
    if init_val is None:
        return 0
    elif isinstance(init_val, int):
        if search_key in tup and isinstance(tup[search_key], int):
            return tup[search_key] + init_val
        else:
            raise ValueError(f"'sum_vals' function failed to find integer value mapped to \"{search_key}\"")
    else:
        return init_val

# Returns a list of distinct elements (as determined by group_tup) each epoch
# removes duplicate Tuples based on group_tup
def distinct(groupby_func: GroupingFunc, next_op: Operator) -> Operator:
    h_tbl: Dict[Tuple, bool] = {}
    reset_counter = [0]

    def next_func(tup: Tuple) -> None:
        grouping_key: Tuple = groupby_func(tup)
        h_tbl[grouping_key] = True

    def reset_func(tup: Tuple) -> None:
        reset_counter[0] += 1
        for key_, _ in h_tbl.items():
            merged_tup: Tuple = {**tup, **key_}
            next_op.next(merged_tup)
        next_op.reset(tup)
        h_tbl.clear()

    return Operator(next_func, reset_func)

# Just sends both next and reset directly to two different downstream operators
# i.e. splits the stream processing in two
def split(l: Operator, r: Operator) -> Operator:
    def next_func(tup: Tuple) -> None:
        l.next(tup)
        r.next(tup)
    def reset_func(tup: Tuple) -> None:
        l.reset(tup)
        r.reset(tup)
    return Operator(next_func, reset_func)

KeyExtractor = Callable[[Tuple], PyTuple[Tuple, Tuple]]

# Initial shot at a join semantic that doesn't require maintining entire state
# Functions left and right transform input tuples into a key,value pair of tuples
# The key determines a canonical tuple against which the other stream will match
# The value determines extra fields which should be saved and added when a
# match is made
#
# Requires tuples to have epoch id as int value in field referenced by eid_key.
def join(left_extractor: KeyExtractor, right_extractor: KeyExtractor, next_op: Operator, eid_key: str = "eid") -> PyTuple[Operator, Operator]:
    h_tbl1: Dict[Tuple, Tuple] = {}
    h_tbl2: Dict[Tuple, Tuple] = {}
    left_curr_epoch = [0]
    right_curr_epoch = [0]

    def handle_join_side(curr_h_tble: Dict[Tuple, Tuple], other_h_tbl: Dict[Tuple, Tuple],
                         curr_epoch_ref: List[int], other_epoch_ref: List[int],
                         f: KeyExtractor) -> Operator:
        def next_func(tup: Tuple) -> None:
            key, vals_ = f(tup)
            curr_epoch: int = get_mapped_int(eid_key, tup)

            while curr_epoch > curr_epoch_ref[0]:
                if other_epoch_ref[0] > curr_epoch_ref[0]:
                    next_op.reset({eid_key: curr_epoch_ref[0]})
                curr_epoch_ref[0] += 1

            new_tup: Tuple = {eid_key: curr_epoch, **key}
            if new_tup in other_h_tbl:
                val_: Tuple = other_h_tbl.pop(new_tup)
                merged = {**new_tup, **vals_, **val_}
                next_op.next(merged)
            else:
                curr_h_tble[new_tup] = vals_

        def reset_func(tup: Tuple) -> None:
            curr_epoch: int = get_mapped_int(eid_key, tup)
            while curr_epoch > curr_epoch_ref[0]:
                if other_epoch_ref[0] > curr_epoch_ref[0]:
                    next_op.reset({eid_key: curr_epoch_ref[0]})
                curr_epoch_ref[0] += 1

        return Operator(next_func, reset_func)

    op1 = handle_join_side(h_tbl1, h_tbl2, left_curr_epoch, right_curr_epoch, left_extractor)
    op2 = handle_join_side(h_tbl2, h_tbl1, right_curr_epoch, left_curr_epoch, right_extractor)
    return op1, op2

# (join utility)
# Returns a new tuple with only the keys included in the first of each pair in
# keys
# These keys are renamed to the second of each pair in keys
# Use in conjunction with the join implementation above to get the "join left
# with right on left.x = right.y" kind of thing
def rename_filtered_keys(renamings_pairs: List[PyTuple[str, str]], in_tup: Tuple) -> Tuple:
    new_tup: Tuple = {}
    for old_key, new_key in renamings_pairs:
        if old_key in in_tup:
            new_tup[new_key] = in_tup[old_key]
    return new_tup

# Main entry point and implementation for simple header-dump operation

# See builtins.ml for definitions of building blocks used here
# '@=>' is just a right-associative application to avoid nasty nested parens
at_equals_greater_than = at_equals_greater_than
at_double_equals_greater_than = at_double_equals_greater_than
dump_tuple = dump_tuple_op
filter_op = filter_op
map_op = map_op

# counts total number of packets obeserved in an epoch
def ident(next_op: Operator) -> Operator:
    def filter_func(tup: Tuple) -> Tuple:
        return {k: v for k, v in tup.items() if k != "eth.src" and k != "eth.dst"}
    return at_equals_greater_than(lambda n: map_op(filter_func, n), next_op)

# assigns each tuple an epoch ID based on time by adding an eid key, counts
# the number of tuples in each epoch, then passes the processed tuples to the
# next_op
def count_pkts(next_op: Operator) -> Operator:
    return at_equals_greater_than(lambda n: groupby(single_group, counter, "pkts", n),
                                  epoch(1.0, "eid", next_op))

# assigns each tuple an epoch ID based on time by adding an eid key, groups
# them by source and dest ip, counts and stores the number of tuples in each
# group, and passes result to next_op
def pkts_per_src_dst(next_op: Operator) -> Operator:
    return at_equals_greater_than(
        lambda n: groupby(lambda t: filter_groups(["ipv4.src", "ipv4.dst"], t), counter, "pkts", n),
        epoch(1.0, "eid", next_op)
    )

def distinct_srcs(next_op: Operator) -> Operator:
    return at_equals_greater_than(
        lambda n: groupby(single_group, counter, "srcs", n),
        at_equals_greater_than(lambda n: distinct(lambda t: filter_groups(["ipv4.src"], t), n),
                               epoch(1.0, "eid", next_op))
    )

# Sonata 1
def tcp_new_cons(next_op: Operator) -> Operator:
    threshold: int = 40
    return at_equals_greater_than(
        lambda n: filter_op(lambda t: get_mapped_int("cons", t) >= threshold, n),
        at_equals_greater_than(
            lambda n: groupby(lambda t: filter_groups(["ipv4.dst"], t), counter, "cons", n),
            at_equals_greater_than(
                lambda n: filter_op(lambda t: get_mapped_int("ipv4.proto", t) == 6 and get_mapped_int("l4.flags", t) == 2, n),
                epoch(1.0, "eid", next_op)
            )
        )
    )

# Sonata 2
def ssh_brute_force(next_op: Operator) -> Operator:
    threshold: int = 40
    return at_equals_greater_than(
        lambda n: filter_op(lambda t: get_mapped_int("srcs", t) >= threshold, n),
        at_equals_greater_than(
            lambda n: groupby(lambda t: filter_groups(["ipv4.dst", "ipv4.len"], t), counter, "srcs", n),
            at_equals_greater_than(
                lambda n: distinct(lambda t: filter_groups(["ipv4.src", "ipv4.dst", "ipv4.len"], t), n),
                at_equals_greater_than(
                    lambda n: filter_op(lambda t: get_mapped_int("ipv4.proto", t) == 6 and get_mapped_int("l4.dport", t) == 22, n),
                    epoch(1.0, "eid", next_op) # might need to elongate epoch for this one...
                )
            )
        )
    )

# Sonata 3
def super_spreader(next_op: Operator) -> Operator:
    threshold: int = 40
    return at_equals_greater_than(
        lambda n: filter_op(lambda t: get_mapped_int("dsts", t) >= threshold, n),
        at_equals_greater_than(
            lambda n: groupby(lambda t: filter_groups(["ipv4.src"], t), counter, "dsts", n),
            at_equals_greater_than(
                lambda n: distinct(lambda t: filter_groups(["ipv4.src", "ipv4.dst"], t), n),
                epoch(1.0, "eid", next_op)
            )
        )
    )

# Sonata 4
def port_scan(next_op: Operator) -> Operator:
    threshold: int = 40
    return at_equals_greater_than(
        lambda n: filter_op(lambda t: get_mapped_int("ports", t) >= threshold, n),
        at_equals_greater_than(
            lambda n: groupby(lambda t: filter_groups(["ipv4.src"], t), counter, "ports", n),
            at_equals_greater_than(
                lambda n: distinct(lambda t: filter_groups(["ipv4.src", "l4.dport"], t), n),
                epoch(1.0, "eid", next_op)
            )
        )
    )

# Sonata 5
def ddos(next_op: Operator) -> Operator:
    threshold: int = 45
    return at_equals_greater_than(
        lambda n: filter_op(lambda t: get_mapped_int("srcs", t) >= threshold, n),
        at_equals_greater_than(
            lambda n: groupby(lambda t: filter_groups(["ipv4.dst"], t), counter, "srcs", n),
            at_equals_greater_than(
                lambda n: distinct(lambda t: filter_groups(["ipv4.src", "ipv4.dst"], t), n),
                epoch(1.0, "eid", next_op)
            )
        )
    )

# Sonata 6 --- Note this implements the Sonata semantic of this query
#*NOT* the intended semantic from NetQRE *)
def syn_flood_sonata(next_op: Operator) -> List[Operator]:
    threshold: int = 3
    epoch_dur: float = 1.0

    def syns(next_op_inner: Operator) -> Operator:
        return at_equals_greater_than(
            lambda n: groupby(lambda t: filter_groups(["ipv4.dst"], t), counter, "syns", n),
            at_equals_greater_than(
                lambda n: filter_op(lambda t: get_mapped_int("ipv4.proto", t) == 6 and get_mapped_int("l4.flags", t) == 2, n),
                epoch(epoch_dur, "eid", next_op)
            )
        )

    def synacks(next_op_inner: Operator) -> Operator:
        return at_equals_greater_than(
            lambda n: groupby(lambda t: filter_groups(["ipv4.src"], t), counter, "synacks", n),
            at_equals_greater_than(
                lambda n: filter_op(lambda t: get_mapped_int("ipv4.proto", t) == 6 and get_mapped_int("l4.flags", t) == 18, n),
                epoch(epoch_dur, "eid", next_op)
            )
        )

    def acks(next_op_inner: Operator) -> Operator:
        return at_equals_greater_than(
            lambda n: groupby(lambda t: filter_groups(["ipv4.dst"], t), counter, "acks", n),
            at_equals_greater_than(
                lambda n: filter_op(lambda t: get_mapped_int("ipv4.proto", t) == 6 and get_mapped_int("l4.flags", t) == 16, n),
                epoch(epoch_dur, "eid", next_op)
            )
        )

    join_op1, join_op2 = at_double_equals_greater_than(
        lambda n: map_op(
            lambda t: {**t, "syns+synacks-acks": get_mapped_int("syns+synacks", t) - get_mapped_int("acks", t)},
            at_equals_greater_than(
                lambda n2: filter_op(lambda t: get_mapped_int("syns+synacks-acks", t) >= threshold, n2),
                n
            )
        ),
        join(
            lambda t: (filter_groups(["host"], t), filter_groups(["syns+synacks"], t)),
            lambda t: (rename_filtered_keys([("ipv4.dst", "host")], t), filter_groups(["acks"], t)),
            next_op
        )
    )

    join_op3, join_op4 = at_double_equals_greater_than(
        lambda n: map_op(
            lambda t: {**t, "syns+synacks": get_mapped_int("syns", t) + get_mapped_int("synacks", t)},
            n
        ),
        join(
            lambda t: (rename_filtered_keys([("ipv4.dst", "host")], t), filter_groups(["syns"], t)),
            lambda t: (rename_filtered_keys([("ipv4.src", "host")], t), filter_groups(["synacks"], t)),
            join_op1
        )
    )

    return [syns(join_op3), synacks(join_op4), acks(join_op2)]

# Sonata 7
def completed_flows(next_op: Operator) -> List[Operator]:
    threshold: int = 1
    epoch_dur: float = 30.0

    def syns(next_op_inner: Operator) -> Operator:
        return at_equals_greater_than(
            lambda n: groupby(lambda t: filter_groups(["ipv4.dst"], t), counter, "syns", n),
            at_equals_greater_than(
                lambda n: filter_op(lambda t: get_mapped_int("ipv4.proto", t) == 6 and get_mapped_int("l4.flags", t) == 2, n),
                epoch(epoch_dur, "eid", next_op_inner)
            )
        )

    def fins(next_op_inner: Operator) -> Operator:
        return at_equals_greater_than(
            lambda n: groupby(lambda t: filter_groups(["ipv4.src"], t), counter, "fins", n),
            at_equals_greater_than(
                lambda n: filter_op(lambda t: get_mapped_int("ipv4.proto", t) == 6 and (get_mapped_int("l4.flags", t) & 1) == 1, n),
                epoch(epoch_dur, "eid", next_op_inner)
            )
        )

    op1, op2 = at_double_equals_greater_than(
        lambda n: map_op(
            lambda t: {**t, "diff": get_mapped_int("syns", t) - get_mapped_int("fins", t)},
            at_equals_greater_than(
lambda n2: filter_op(lambda t: get_mapped_int("diff", t) >= threshold, n2),
                n
            )
        ),
        join(
            lambda t: (rename_filtered_keys([("ipv4.dst", "host")], t), filter_groups(["syns"], t)),
            lambda t: (rename_filtered_keys([("ipv4.src", "host")], t), filter_groups(["fins"], t)),
            next_op
        )
    )

    return [syns(op1), fins(op2)]

# Sonata 8
def slowloris(next_op: Operator) -> List[Operator]:
    t1: int = 5
    t2: int = 500
    t3: int = 90
    epoch_dur: float = 1.0

    def n_conns(next_op_inner: Operator) -> Operator:
        return at_equals_greater_than(
            lambda n: filter_op(lambda t: get_mapped_int("n_conns", t) >= t1, n),
            at_equals_greater_than(
                lambda n: groupby(lambda t: filter_groups(["ipv4.dst"], t), counter, "n_conns", n),
                at_equals_greater_than(
                    lambda n: distinct(lambda t: filter_groups(["ipv4.src", "ipv4.dst", "l4.sport"], t), n),
                    at_equals_greater_than(
                        lambda n: filter_op(lambda t: get_mapped_int("ipv4.proto", t) == 6, n),
                        epoch(epoch_dur, "eid", next_op_inner)
                    )
                )
            )
        )

    def n_bytes(next_op_inner: Operator) -> Operator:
        return at_equals_greater_than(
            lambda n: filter_op(lambda t: get_mapped_int("n_bytes", t) >= t2, n),
            at_equals_greater_than(
                lambda n: groupby(lambda t: filter_groups(["ipv4.dst"], t), lambda acc, curr: sum_ints("ipv4.len", acc, curr), "n_bytes", n),
                at_equals_greater_than(
                    lambda n: filter_op(lambda t: get_mapped_int("ipv4.proto", t) == 6, n),
                    epoch(epoch_dur, "eid", next_op_inner)
                )
            )
        )

    op1, op2 = at_double_equals_greater_than(
        lambda n: filter_op(lambda t: get_mapped_int("bytes_per_conn", t) <= t3,
                             map_op(lambda t: {**t, "bytes_per_conn": get_mapped_int("n_bytes", t) // get_mapped_int("n_conns", t)}, n)),
        join(
            lambda t: (filter_groups(["ipv4.dst"], t), filter_groups(["n_conns"], t)),
            lambda t: (filter_groups(["ipv4.dst"], t), filter_groups(["n_bytes"], t)),
            next_op
        )
    )

    return [n_conns(op1), n_bytes(op2)]

def join_test(next_op: Operator) -> List[Operator]:
    epoch_dur: float = 1.0

    def syns(next_op_inner: Operator) -> Operator:
        return at_equals_greater_than(
            lambda n: filter_op(lambda t: get_mapped_int("ipv4.proto", t) == 6 and get_mapped_int("l4.flags", t) == 2, n),
            epoch(epoch_dur, "eid", next_op_inner)
        )

    def synacks(next_op_inner: Operator) -> Operator:
        return at_equals_greater_than(
            lambda n: filter_op(lambda t: get_mapped_int("ipv4.proto", t) == 6 and get_mapped_int("l4.flags", t) == 18, n),
            epoch(epoch_dur, "eid", next_op_inner)
        )

    op1, op2 = at_double_equals_greater_than(
        lambda n: n,
        join(
            lambda t: (rename_filtered_keys([("ipv4.src", "host")], t), rename_filtered_keys([("ipv4.dst", "remote")], t)),
            lambda t: (rename_filtered_keys([("ipv4.dst", "host")], t), filter_groups(["time"], t)),
            next_op
        )
    )

    return [syns(op1), synacks(op2)]

def q3(next_op: Operator) -> Operator:
    return at_equals_greater_than(
        lambda n: distinct(lambda t: filter_groups(["ipv4.src", "ipv4.dst"], t), n),
        epoch(100.0, "eid", next_op)
    )

def q4(next_op: Operator) -> Operator:
    return at_equals_greater_than(
        lambda n: groupby(lambda t: filter_groups(["ipv4.dst"], t), counter, "pkts", n),
        epoch(10000.0, "eid", next_op)
    )

queries: List[Operator] = [at_equals_greater_than(tcp_new_cons, dump_tuple_op())]

def run_queries():
    for i in range(5):
        tup: Tuple = {
            "time": float(0.000000 + i),
            "eth.src": Bytes(binascii.unhexlify("001122334455")),
            "eth.dst": Bytes(binascii.unhexlify("AABBCCDDEEFF")),
            "eth.ethertype": 0x0800,
            "ipv4.hlen": 20,
            "ipv4.proto": 6,
            "ipv4.len": 60,
            "ipv4.src": ipaddress.IPv4Address("127.0.0.1"),
            "ipv4.dst": ipaddress.IPv4Address("127.0.0.1"),
            "l4.sport": 440,
            "l4.dport": 50000,
            "l4.flags": 10,
        }
        for query in queries:
            query.next(tup)
            if hasattr(query, 'reset'):
                query.reset(tup) # Call reset for each tuple for demonstration

# Main entrypoint
if __name__ == "__main__":
    run_queries()
    print("Done")                