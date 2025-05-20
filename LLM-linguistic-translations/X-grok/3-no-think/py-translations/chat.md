prompt: base prompt

Translating the provided OCaml code to Python while adhering to Python's idiomatic practices and paradigms requires careful consideration of the differences between the two languages. OCaml is a functional programming language with strong static typing, algebraic data types, pattern matching, and a focus on immutability. Python, on the other hand, is a dynamically typed, multi-paradigm language that emphasizes readability, simplicity, and object-oriented or imperative programming. The translation will use Python's standard libraries and conventions, avoiding direct emulation of OCaml-specific features (like functors or variant types) and instead leveraging Python's natural constructs such as classes, dictionaries, and exceptions.

The OCaml code implements a stream processing pipeline for network data analysis, with utilities for parsing, transforming, and aggregating data represented as "tuples" (maps from strings to values of different types). The translation will:

- Use Python dictionaries to represent OCaml's `Map` and `tuple` types.
- Replace OCaml's variant type `op_result` with a tagged dictionary or class-based approach, as Python lacks algebraic data types.
- Implement OCaml's record types (e.g., `operator`) as Python classes or dictionaries with function references.
- Use Python's exception handling instead of OCaml's pattern matching for type checks.
- Replace OCaml's functional composition operators (`@=>`, `@==>`) with Python function calls or method chaining.
- Leverage Python's standard library (e.g., `collections`, `struct`, `ipaddress`) for equivalent functionality.
- Maintain the stream processing semantics using Python generators or iterative processing where appropriate.

Below is the Python translation, organized to reflect the structure of the OCaml code while embracing Pythonic idioms. Note that some OCaml dependencies (e.g., `Ipaddr.V4.t`) are simulated with Python's `ipaddress` module, and `Bytes.t` for MAC addresses is handled with Python's `bytes`. The translation assumes the `ipaddress` module for IP address handling and uses standard Python I/O for file operations.

```python
import sys
import csv
from collections import defaultdict
from typing import Dict, Union, Callable, List, Tuple, Optional
from ipaddress import IPv4Address, ip_address
from struct import pack
import hashlib

# Type alias for op_result to mimic OCaml's variant type
OpResult = Dict[str, Union[float, int, IPv4Address, bytes, None]]

def create_op_result_float(value: float) -> OpResult:
    return {"type": "Float", "value": value}

def create_op_result_int(value: int) -> OpResult:
    return {"type": "Int", "value": value}

def create_op_result_ipv4(value: IPv4Address) -> OpResult:
    return {"type": "IPv4", "value": value}

def create_op_result_mac(value: bytes) -> OpResult:
    return {"type": "MAC", "value": value}

def create_op_result_empty() -> OpResult:
    return {"type": "Empty", "value": None}

# Type alias for tuple (Map<string, op_result> in OCaml)
TupleType = Dict[str, OpResult]

# Operator class to mimic OCaml's record type
class Operator:
    def __init__(self, next: Callable[[TupleType], None], reset: Callable[[TupleType], None]):
        self.next = next
        self.reset = reset

# Operator creator type
OperatorCreator = Callable[[Operator], Operator]
DoubleOperatorCreator = Callable[[Operator], Tuple[Operator, Operator]]

# Conversion utilities

def string_of_mac(buf: bytes) -> str:
    """Formats a 6-byte MAC address as a colon-separated hex string."""
    return ":".join(f"{byte:02x}" for byte in buf)

def tcp_flags_to_strings(flags: int) -> str:
    """Converts TCP flags to a human-readable string."""
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
    """Extracts int from op_result, raises exception if not an int."""
    if input["type"] == "Int":
        return input["value"]
    raise ValueError("Trying to extract int from non-int result")

def float_of_op_result(input: OpResult) -> float:
    """Extracts float from op_result, raises exception if not a float."""
    if input["type"] == "Float":
        return input["value"]
    raise ValueError("Trying to extract float from non-float result")

def string_of_op_result(input: OpResult) -> str:
    """Converts op_result to a human-readable string."""
    match input["type"]:
        case "Float":
            return f"{input['value']}"
        case "Int":
            return str(input["value"])
        case "IPv4":
            return str(input["value"])
        case "MAC":
            return string_of_mac(input["value"])
        case "Empty":
            return "Empty"
        case _:
            raise ValueError("Unknown op_result type")

def string_of_tuple(input_tuple: TupleType) -> str:
    """Formats a tuple as a human-readable string."""
    return ", ".join(
        f'"{key}" => {string_of_op_result(value)}'
        for key, value in input_tuple.items()
    )

def tuple_of_list(tup_list: List[Tuple[str, OpResult]]) -> TupleType:
    """Creates a tuple from a list of (key, value) pairs."""
    return dict(tup_list)

def dump_tuple(out_file, tup: TupleType):
    """Prints a formatted tuple to the output file."""
    print(string_of_tuple(tup), file=out_file)

def lookup_int(key: str, tup: TupleType) -> int:
    """Retrieves an int value from a tuple by key."""
    return int_of_op_result(tup[key])

def lookup_float(key: str, tup: TupleType) -> float:
    """Retrieves a float value from a tuple by key."""
    return float_of_op_result(tup[key])

# Built-in operator definitions

init_table_size = 10000

def dump_tuple_op(show_reset: bool = False, out_file=sys.stdout) -> Operator:
    """Dumps all fields of tuples to the given output."""
    def reset(tup: TupleType):
        if show_reset:
            dump_tuple(out_file, tup)
            print("[reset]", file=out_file)
    
    return Operator(
        next=lambda tup: dump_tuple(out_file, tup),
        reset=reset
    )

def dump_as_csv(static_field: Optional[Tuple[str, str]] = None, header: bool = True, out_file=sys.stdout) -> Operator:
    """Dumps tuples in CSV format."""
    first = [header]  # Mutable flag for header
    
    def next(tup: TupleType):
        nonlocal first
        if first[0]:
            if static_field:
                print(f"{static_field[0]},", end="", file=out_file)
            print(",".join(tup.keys()), file=out_file)
            first[0] = False
        if static_field:
            print(f"{static_field[1]},", end="", file=out_file)
        print(",".join(string_of_op_result(value) for value in tup.values()), file=out_file)
    
    return Operator(next=next, reset=lambda _: None)

def dump_walts_csv(filename: str) -> Operator:
    """Dumps tuples in Walt's canonical CSV format."""
    out_file = [None]  # Mutable reference for output file
    first = [True]
    
    def next(tup: TupleType):
        nonlocal out_file, first
        if first[0]:
            out_file[0] = open(filename, "w")
            first[0] = False
        print(
            ",".join(
                string_of_op_result(tup[key])
                for key in ["src_ip", "dst_ip", "src_l4_port", "dst_l4_port", "packet_count", "byte_count", "epoch_id"]
            ),
            file=out_file[0]
        )
    
    return Operator(next=next, reset=lambda _: None)

def get_ip_or_zero(input: str) -> OpResult:
    """Converts a string to an IP op_result or zero."""
    if input == "0":
        return create_op_result_int(0)
    return create_op_result_ipv4(ip_address(input))

def read_walts_csv(epoch_id_key: str = "eid", file_names: List[str], ops: List[Operator]):
    """Reads CSV files in Walt's format and processes them with operators."""
    inchs_eids_tupcount = [
        (open(filename, "r"), [0], [0]) for filename in file_names
    ]
    running = [len(ops)]
    
    while running[0] > 0:
        for (in_file, eid, tup_count), op in zip(inchs_eids_tupcount, ops):
            if eid[0] >= 0:
                try:
                    reader = csv.reader(in_file)
                    for row in reader:
                        src_ip, dst_ip, src_l4_port, dst_l4_port, packet_count, byte_count, epoch_id = row
                        p = {}
                        p["ipv4.src"] = get_ip_or_zero(src_ip)
                        p["ipv4.dst"] = get_ip_or_zero(dst_ip)
                        p["l4.sport"] = create_op_result_int(int(src_l4_port))
                        p["l4.dport"] = create_op_result_int(int(dst_l4_port))
                        p["packet_count"] = create_op_result_int(int(packet_count))
                        p["byte_count"] = create_op_result_int(int(byte_count))
                        p[epoch_id_key] = create_op_result_int(int(epoch_id))
                        
                        tup_count[0] += 1
                        epoch_id_int = int(epoch_id)
                        if epoch_id_int > eid[0]:
                            while epoch_id_int > eid[0]:
                                reset_tup = {epoch_id_key: create_op_result_int(eid[0]), "tuples": create_op_result_int(tup_count[0])}
                                op.reset(reset_tup)
                                tup_count[0] = 0
                                eid[0] += 1
                        op.next({**p, "tuples": create_op_result_int(tup_count[0])})
                except (csv.Error, ValueError) as e:
                    print(f"Failed to scan: {e}", file=sys.stderr)
                    raise ValueError("Scan failure")
                except EOFError:
                    reset_tup = {epoch_id_key: create_op_result_int(eid[0] + 1), "tuples": create_op_result_int(tup_count[0])}
                    op.reset(reset_tup)
                    running[0] -= 1
                    eid[0] = -1
    print("Done.")

def meta_meter(static_field: Optional[str] = None, name: str = "", out_file=sys.stdout) -> OperatorCreator:
    """Tracks and logs the number of tuples per epoch."""
    def create(next_op: Operator) -> Operator:
        epoch_count = [0]
        tups_count = [0]
        
        def next(tup: TupleType):
            tups_count[0] += 1
            next_op.next(tup)
        
        def reset(tup: TupleType):
            print(
                f"{epoch_count[0]},{name},{tups_count[0]},{static_field or ''}",
                file=out_file
            )
            tups_count[0] = 0
            epoch_count[0] += 1
            next_op.reset(tup)
        
        return Operator(next, reset)
    
    return create

def epoch(epoch_width: float, key_out: str) -> OperatorCreator:
    """Assigns epoch IDs based on time and resets periodically."""
    def create(next_op: Operator) -> Operator:
        epoch_boundary = [0.0]
        eid = [0]
        
        def next(tup: TupleType):
            time = float_of_op_result(tup["time"])
            if epoch_boundary[0] == 0.0:
                epoch_boundary[0] = time + epoch_width
            elif time >= epoch_boundary[0]:
                while time >= epoch_boundary[0]:
                    next_op.reset({key_out: create_op_result_int(eid[0])})
                    epoch_boundary[0] += epoch_width
                    eid[0] += 1
            next_op.next({**tup, key_out: create_op_result_int(eid[0])})
        
        def reset(_):
            next_op.reset({key_out: create_op_result_int(eid[0])})
            epoch_boundary[0] = 0.0
            eid[0] = 0
        
        return Operator(next, reset)
    
    return create

def filter(f: Callable[[TupleType], bool]) -> OperatorCreator:
    """Filters tuples based on a predicate."""
    def create(next_op: Operator) -> Operator:
        def next(tup: TupleType):
            if f(tup):
                next_op.next(tup)
        
        return Operator(next, next_op.reset)
    
    return create

def key_geq_int(key: str, threshold: int) -> Callable[[TupleType], bool]:
    """Filter utility: checks if a tuple's int value for a key meets a threshold."""
    def check(tup: TupleType) -> bool:
        return int_of_op_result(tup[key]) >= threshold
    return check

def get_mapped_int(key: str, tup: TupleType) -> int:
    """Retrieves an int value from a tuple by key."""
    return int_of_op_result(tup[key])

def get_mapped_float(key: str, tup: TupleType) -> float:
    """Retrieves a float value from a tuple by key."""
    return float_of_op_result(tup[key])

def map(f: Callable[[TupleType], TupleType]) -> OperatorCreator:
    """Applies a function to all tuples."""
    def create(next_op: Operator) -> Operator:
        def next(tup: TupleType):
            next_op.next(f(tup))
        
        return Operator(next, next_op.reset)
    
    return create

GroupingFunc = Callable[[TupleType], TupleType]
ReductionFunc = Callable[[OpResult, TupleType], OpResult]

def groupby(groupby_func: GroupingFunc, reduce_func: ReductionFunc, out_key: str) -> OperatorCreator:
    """Groups tuples by a key and applies a reduction function."""
    def create(next_op: Operator) -> Operator:
        h_tbl = {}
        reset_counter = [0]
        
        def next(tup: TupleType):
            grouping_key = groupby_func(tup)
            key_hash = hashlib.md5(str(grouping_key).encode()).hexdigest()  # Simulate tuple hashing
            if key_hash in h_tbl:
                h_tbl[key_hash] = (grouping_key, reduce_func(h_tbl[key_hash][1], tup))
            else:
                h_tbl[key_hash] = (grouping_key, reduce_func(create_op_result_empty(), tup))
        
        def reset(tup: TupleType):
            reset_counter[0] += 1
            for key_hash, (grouping_key, val_) in h_tbl.items():
                unioned_tup = {**tup, **grouping_key}
                next_op.next({**unioned_tup, out_key: val_})
            next_op.reset(tup)
            h_tbl.clear()
        
        return Operator(next, reset)
    
    return create

def filter_groups(incl_keys: List[str]) -> GroupingFunc:
    """Filters tuple keys to include only those specified."""
    def filter_func(tup: TupleType) -> TupleType:
        return {k: v for k, v in tup.items() if k in incl_keys}
    return filter_func

def single_group(_: TupleType) -> TupleType:
    """Groups all tuples into a single group."""
    return {}

def counter(val_: OpResult, _: TupleType) -> OpResult:
    """Counts tuples."""
    if val_["type"] == "Empty":
        return create_op_result_int(1)
    if val_["type"] == "Int":
        return create_op_result_int(val_["value"] + 1)
    return val_

def sum_ints(search_key: str) -> ReductionFunc:
    """Sums integer values for a given key."""
    def reduce(val_: OpResult, tup: TupleType) -> OpResult:
        if val_["type"] == "Empty":
            return create_op_result_int(0)
        if val_["type"] == "Int":
            if search_key in tup and tup[search_key]["type"] == "Int":
                return create_op_result_int(val_["value"] + tup[search_key]["value"])
            raise ValueError(f"'sum_vals' failed to find integer value for '{search_key}'")
        return val_
    return reduce

def distinct(groupby_func: GroupingFunc) -> OperatorCreator:
    """Removes duplicate tuples based on a grouping function."""
    def create(next_op: Operator) -> Operator:
        h_tbl = {}
        reset_counter = [0]
        
        def next(tup: TupleType):
            grouping_key = groupby_func(tup)
            key_hash = hashlib.md5(str(grouping_key).encode()).hexdigest()
            h_tbl[key_hash] = (grouping_key, True)
        
        def reset(tup: TupleType):
            reset_counter[0] += 1
            for key_hash, (key_, _) in h_tbl.items():
                merged_tup = {**tup, **key_}
                next_op.next(merged_tup)
            next_op.reset(tup)
            h_tbl.clear()
        
        return Operator(next, reset)
    
    return create

def split(left: Operator, right: Operator) -> Operator:
    """Splits the stream to two operators."""
    def next(tup: TupleType):
        left.next(tup)
        right.next(tup)
    
    def reset(tup: TupleType):
        left.reset(tup)
        right.reset(tup)
    
    return Operator(next, reset)

KeyExtractor = Callable[[TupleType], Tuple[TupleType, TupleType]]

def join(eid_key: str = "eid", left_extractor: KeyExtractor, right_extractor: KeyExtractor) -> DoubleOperatorCreator:
    """Joins two streams based on key extractors."""
    def create(next_op: Operator) -> Tuple[Operator, Operator]:
        h_tbl1 = {}
        h_tbl2 = {}
        left_curr_epoch = [0]
        right_curr_epoch = [0]
        
        def handle_join_side(curr_h_tbl: Dict, other_h_tbl: Dict, curr_epoch_ref: List[int], other_epoch_ref: List[int], f: KeyExtractor) -> Operator:
            def next(tup: TupleType):
                key, vals_ = f(tup)
                curr_epoch = get_mapped_int(eid_key, tup)
                
                while curr_epoch > curr_epoch_ref[0]:
                    if other_epoch_ref[0] > curr_epoch_ref[0]:
                        next_op.reset({eid_key: create_op_result_int(curr_epoch_ref[0])})
                    curr_epoch_ref[0] += 1
                
                new_tup = {**key, eid_key: create_op_result_int(curr_epoch)}
                new_tup_hash = hashlib.md5(str(new_tup).encode()).hexdigest()
                
                if new_tup_hash in other_h_tbl:
                    val_ = other_h_tbl.pop(new_tup_hash)[1]
                    next_op.next({**new_tup, **vals_, **val_})
                else:
                    curr_h_tbl[new_tup_hash] = (new_tup, vals_)
            
            def reset(tup: TupleType):
                curr_epoch = get_mapped_int(eid_key, tup)
                while curr_epoch > curr_epoch_ref[0]:
                    if other_epoch_ref[0] > curr_epoch_ref[0]:
                        next_op.reset({eid_key: create_op_result_int(curr_epoch_ref[0])})
                    curr_epoch_ref[0] += 1
            
            return Operator(next, reset)
        
        return (
            handle_join_side(h_tbl1, h_tbl2, left_curr_epoch, right_curr_epoch, left_extractor),
            handle_join_side(h_tbl2, h_tbl1, right_curr_epoch, left_curr_epoch, right_extractor)
        )
    
    return create

def rename_filtered_keys(renamings_pairs: List[Tuple[str, str]]) -> Callable[[TupleType], TupleType]:
    """Renames and filters tuple keys."""
    def rename(tup: TupleType) -> TupleType:
        result = {}
        for old_key, new_key in renamings_pairs:
            if old_key in tup:
                result[new_key] = tup[old_key]
        return result
    return rename

# Query definitions

def ident() -> OperatorCreator:
    """Filters out eth.src and eth.dst from tuples."""
    def create(next_op: Operator) -> Operator:
        def map_func(tup: TupleType) -> TupleType:
            return {
                k: v for k, v in tup.items()
                if k not in ["eth.src", "eth.dst"]
            }
        return map(map_func)(next_op)
    return create

def count_pkts() -> OperatorCreator:
    """Counts packets per epoch."""
    def create(next_op: Operator) -> Operator:
        return epoch(1.0, "eid")(
            groupby(single_group, counter, "pkts")(next_op)
        )
    return create

def pkts_per_src_dst() -> OperatorCreator:
    """Counts packets per source and destination IP."""
    def create(next_op: Operator) -> Operator:
        return epoch(1.0, "eid")(
            groupby(filter_groups(["ipv4.src", "ipv4.dst"]), counter, "pkts")(next_op)
        )
    return create

def distinct_srcs() -> OperatorCreator:
    """Counts distinct source IPs per epoch."""
    def create(next_op: Operator) -> Operator:
        return epoch(1.0, "eid")(
            distinct(filter_groups(["ipv4.src"]))(
                groupby(single_group, counter, "srcs")(next_op)
            )
        )
    return create

def tcp_new_cons() -> OperatorCreator:
    """Detects new TCP connections."""
    threshold = 40
    def create(next_op: Operator) -> Operator:
        def filter_func(tup: TupleType) -> bool:
            return (
                get_mapped_int("ipv4.proto", tup) == 6 and
                get_mapped_int("l4.flags", tup) == 2
            )
        return epoch(1.0, "eid")(
            filter(filter_func)(
                groupby(filter_groups(["ipv4.dst"]), counter, "cons")(
                    filter(key_geq_int("cons", threshold))(next_op)
                )
            )
        )
    return create

def ssh_brute_force() -> OperatorCreator:
    """Detects SSH brute force attempts."""
    threshold = 40
    def create(next_op: Operator) -> Operator:
        def filter_func(tup: TupleType) -> bool:
            return (
                get_mapped_int("ipv4.proto", tup) == 6 and
                get_mapped_int("l4.dport", tup) == 22
            )
        return epoch(1.0, "eid")(
            filter(filter_func)(
                distinct(filter_groups(["ipv4.src", "ipv4.dst", "ipv4.len"]))(
                    groupby(filter_groups(["ipv4.dst", "ipv4.len"]), counter, "srcs")(
                        filter(key_geq_int("srcs", threshold))(next_op)
                    )
                )
            )
        )
    return create

def super_spreader() -> OperatorCreator:
    """Detects super spreaders."""
    threshold = 40
    def create(next_op: Operator) -> Operator:
        return epoch(1.0, "eid")(
            distinct(filter_groups(["ipv4.src", "ipv4.dst"]))(
                groupby(filter_groups(["ipv4.src"]), counter, "dsts")(
                    filter(key_geq_int("dsts", threshold))(next_op)
                )
            )
        )
    return create

def port_scan() -> OperatorCreator:
    """Detects port scans."""
    threshold = 40
    def create(next_op: Operator) -> Operator:
        return epoch(1.0, "eid")(
            distinct(filter_groups(["ipv4.src", "l4.dport"]))(
                groupby(filter_groups(["ipv4.src"]), counter, "ports")(
                    filter estrema de las Americas.

prompt: Give the rest of the translation

Continuing the translation of the provided OCaml code into Python, we pick up where the previous response left off, ensuring the translation remains idiomatic to Python while preserving the functionality of the original code. The OCaml code defines a series of network data processing queries (Sonata queries) and utilities for stream processing, including operators for filtering, grouping, joining, and outputting data in various formats. The remaining translation covers the incomplete `port_scan` query, the remaining Sonata queries (`ddos`, `syn_flood_sonata`, `completed_flows`, `slowloris`, `join_test`, `q3`, `q4`), and the main entry point with query execution.

The translation continues to:
- Use Python dictionaries for OCaml's `Map` and `tuple` types.
- Represent `op_result` as tagged dictionaries.
- Implement operators as Python classes with `next` and `reset` methods.
- Use Python's standard library (`ipaddress`, `hashlib`, etc.) for equivalent functionality.
- Maintain stream processing semantics with iterative processing.
- Avoid direct emulation of OCaml-specific features (e.g., functors) and use Pythonic constructs like closures and classes.

Below is the continuation of the Python translation, completing the queries and main entry point.

```python
import sys
import csv
from collections import defaultdict
from typing import Dict, Union, Callable, List, Tuple, Optional
from ipaddress import IPv4Address, ip_address
from struct import pack
import hashlib

# Type alias for op_result to mimic OCaml's variant type
OpResult = Dict[str, Union[float, int, IPv4Address, bytes, None]]

def create_op_result_float(value: float) -> OpResult:
    return {"type": "Float", "value": value}

def create_op_result_int(value: int) -> OpResult:
    return {"type": "Int", "value": value}

def create_op_result_ipv4(value: IPv4Address) -> OpResult:
    return {"type": "IPv4", "value": value}

def create_op_result_mac(value: bytes) -> OpResult:
    return {"type": "MAC", "value": value}

def create_op_result_empty() -> OpResult:
    return {"type": "Empty", "value": None}

# Type alias for tuple (Map<string, op_result> in OCaml)
TupleType = Dict[str, OpResult]

# Operator class to mimic OCaml's record type
class Operator:
    def __init__(self, next: Callable[[TupleType], None], reset: Callable[[TupleType], None]):
        self.next = next
        self.reset = reset

# Operator creator type
OperatorCreator = Callable[[Operator], Operator]
DoubleOperatorCreator = Callable[[Operator], Tuple[Operator, Operator]]

# Conversion utilities

def string_of_mac(buf: bytes) -> str:
    """Formats a 6-byte MAC address as a colon-separated hex string."""
    return ":".join(f"{byte:02x}" for byte in buf)

def tcp_flags_to_strings(flags: int) -> str:
    """Converts TCP flags to a human-readable string."""
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
    """Extracts int from op_result, raises exception if not an int."""
    if input["type"] == "Int":
        return input["value"]
    raise ValueError("Trying to extract int from non-int result")

def float_of_op_result(input: OpResult) -> float:
    """Extracts float from op_result, raises exception if not a float."""
    if input["type"] == "Float":
        return input["value"]
    raise ValueError("Trying to extract float from non-float result")

def string_of_op_result(input: OpResult) -> str:
    """Converts op_result to a human-readable string."""
    match input["type"]:
        case "Float":
            return f"{input['value']}"
        case "Int":
            return str(input["value"])
        case "IPv4":
            return str(input["value"])
        case "MAC":
            return string_of_mac(input["value"])
        case "Empty":
            return "Empty"
        case _:
            raise ValueError("Unknown op_result type")

def string_of_tuple(input_tuple: TupleType) -> str:
    """Formats a tuple as a human-readable string."""
    return ", ".join(
        f'"{key}" => {string_of_op_result(value)}'
        for key, value in input_tuple.items()
    )

def tuple_of_list(tup_list: List[Tuple[str, OpResult]]) -> TupleType:
    """Creates a tuple from a list of (key, value) pairs."""
    return dict(tup_list)

def dump_tuple(out_file, tup: TupleType):
    """Prints a formatted tuple to the output file."""
    print(string_of_tuple(tup), file=out_file)

def lookup_int(key: str, tup: TupleType) -> int:
    """Retrieves an int value from a tuple by key."""
    return int_of_op_result(tup[key])

def lookup_float(key: str, tup: TupleType) -> float:
    """Retrieves a float value from a tuple by key."""
    return float_of_op_result(tup[key])

# Built-in operator definitions

init_table_size = 10000

def dump_tuple_op(show_reset: bool = False, out_file=sys.stdout) -> Operator:
    """Dumps all fields of tuples to the given output."""
    def reset(tup: TupleType):
        if show_reset:
            dump_tuple(out_file, tup)
            print("[reset]", file=out_file)
    
    return Operator(
        next=lambda tup: dump_tuple(out_file, tup),
        reset=reset
    )

def dump_as_csv(static_field: Optional[Tuple[str, str]] = None, header: bool = True, out_file=sys.stdout) -> Operator:
    """Dumps tuples in CSV format."""
    first = [header]  # Mutable flag for header
    
    def next(tup: TupleType):
        nonlocal first
        if first[0]:
            if static_field:
                print(f"{static_field[0]},", end="", file=out_file)
            print(",".join(tup.keys()), file=out_file)
            first[0] = False
        if static_field:
            print(f"{static_field[1]},", end="", file=out_file)
        print(",".join(string_of_op_result(value) for value in tup.values()), file=out_file)
    
    return Operator(next=next, reset=lambda _: None)

def dump_walts_csv(filename: str) -> Operator:
    """Dumps tuples in Walt's canonical CSV format."""
    out_file = [None]  # Mutable reference for output file
    first = [True]
    
    def next(tup: TupleType):
        nonlocal out_file, first
        if first[0]:
            out_file[0] = open(filename, "w")
            first[0] = False
        print(
            ",".join(
                string_of_op_result(tup[key])
                for key in ["src_ip", "dst_ip", "src_l4_port", "dst_l4_port", "packet_count", "byte_count", "epoch_id"]
            ),
            file=out_file[0]
        )
    
    return Operator(next=next, reset=lambda _: None)

def get_ip_or_zero(input: str) -> OpResult:
    """Converts a string to an IP op_result or zero."""
    if input == "0":
        return create_op_result_int(0)
    return create_op_result_ipv4(ip_address(input))

def read_walts_csv(epoch_id_key: str = "eid", file_names: List[str], ops: List[Operator]):
    """Reads CSV files in Walt's format and processes them with operators."""
    inchs_eids_tupcount = [
        (open(filename, "r"), [0], [0]) for filename in file_names
    ]
    running = [len(ops)]
    
    while running[0] > 0:
        for (in_file, eid, tup_count), op in zip(inchs_eids_tupcount, ops):
            if eid[0] >= 0:
                try:
                    reader = csv.reader(in_file)
                    for row in reader:
                        src_ip, dst_ip, src_l4_port, dst_l4_port, packet_count, byte_count, epoch_id = row
                        p = {}
                        p["ipv4.src"] = get_ip_or_zero(src_ip)
                        p["ipv4.dst"] = get_ip_or_zero(dst_ip)
                        p["l4.sport"] = create_op_result_int(int(src_l4_port))
                        p["l4.dport"] = create_op_result_int(int(dst_l4_port))
                        p["packet_count"] = create_op_result_int(int(packet_count))
                        p["byte_count"] = create_op_result_int(int(byte_count))
                        p[epoch_id_key] = create_op_result_int(int(epoch_id))
                        
                        tup_count[0] += 1
                        epoch_id_int = int(epoch_id)
                        if epoch_id_int > eid[0]:
                            while epoch_id_int > eid[0]:
                                reset_tup = {epoch_id_key: create_op_result_int(eid[0]), "tuples": create_op_result_int(tup_count[0])}
                                op.reset(reset_tup)
                                tup_count[0] = 0
                                eid[0] += 1
                        op.next({**p, "tuples": create_op_result_int(tup_count[0])})
                except (csv.Error, ValueError) as e:
                    print(f"Failed to scan: {e}", file=sys.stderr)
                    raise ValueError("Scan failure")
                except EOFError:
                    reset_tup = {epoch_id_key: create_op_result_int(eid[0] + 1), "tuples": create_op_result_int(tup_count[0])}
                    op.reset(reset_tup)
                    running[0] -= 1
                    eid[0] = -1
    print("Done.")

def meta_meter(static_field: Optional[str] = None, name: str = "", out_file=sys.stdout) -> OperatorCreator:
    """Tracks and logs the number of tuples per epoch."""
    def create(next_op: Operator) -> Operator:
        epoch_count = [0]
        tups_count = [0]
        
        def next(tup: TupleType):
            tups_count[0] += 1
            next_op.next(tup)
        
        def reset(tup: TupleType):
            print(
                f"{epoch_count[0]},{name},{tups_count[0]},{static_field or ''}",
                file=out_file
            )
            tups_count[0] = 0
            epoch_count[0] += 1
            next_op.reset(tup)
        
        return Operator(next, reset)
    
    return create

def epoch(epoch_width: float, key_out: str) -> OperatorCreator:
    """Assigns epoch IDs based on time and resets periodically."""
    def create(next_op: Operator) -> Operator:
        epoch_boundary = [0.0]
        eid = [0]
        
        def next(tup: TupleType):
            time = float_of_op_result(tup["time"])
            if epoch_boundary[0] == 0.0:
                epoch_boundary[0] = time + epoch_width
            elif time >= epoch_boundary[0]:
                while time >= epoch_boundary[0]:
                    next_op.reset({key_out: create_op_result_int(eid[0])})
                    epoch_boundary[0] += epoch_width
                    eid[0] += 1
            next_op.next({**tup, key_out: create_op_result_int(eid[0])})
        
        def reset(_):
            next_op.reset({key_out: create_op_result_int(eid[0])})
            epoch_boundary[0] = 0.0
            eid[0] = 0
        
        return Operator(next, reset)
    
    return create

def filter(f: Callable[[TupleType], bool]) -> OperatorCreator:
    """Filters tuples based on a predicate."""
    def create(next_op: Operator) -> Operator:
        def next(tup: TupleType):
            if f(tup):
                next_op.next(tup)
        
        return Operator(next, next_op.reset)
    
    return create

def key_geq_int(key: str, threshold: int) -> Callable[[TupleType], bool]:
    """Filter utility: checks if a tuple's int value for a key meets a threshold."""
    def check(tup: TupleType) -> bool:
        return int_of_op_result(tup[key]) >= threshold
    return check

def get_mapped_int(key: str, tup: TupleType) -> int:
    """Retrieves an int value from a tuple by key."""
    return int_of_op_result(tup[key])

def get_mapped_float(key: str, tup: TupleType) -> float:
    """Retrieves a float value from a tuple by key."""
    return float_of_op_result(tup[key])

def map(f: Callable[[TupleType], TupleType]) -> OperatorCreator:
    """Applies a function to all tuples."""
    def create(next_op: Operator) -> Operator:
        def next(tup: TupleType):
            next_op.next(f(tup))
        
        return Operator(next, next_op.reset)
    
    return create

GroupingFunc = Callable[[TupleType], TupleType]
ReductionFunc = Callable[[OpResult, TupleType], OpResult]

def groupby(groupby_func: GroupingFunc, reduce_func: ReductionFunc, out_key: str) -> OperatorCreator:
    """Groups tuples by a key and applies a reduction function."""
    def create(next_op: Operator) -> Operator:
        h_tbl = {}
        reset_counter = [0]
        
        def next(tup: TupleType):
            grouping_key = groupby_func(tup)
            key_hash = hashlib.md5(str(grouping_key).encode()).hexdigest()  # Simulate tuple hashing
            if key_hash in h_tbl:
                h_tbl[key_hash] = (grouping_key, reduce_func(h_tbl[key_hash][1], tup))
            else:
                h_tbl[key_hash] = (grouping_key, reduce_func(create_op_result_empty(), tup))
        
        def reset(tup: TupleType):
            reset_counter[0] += 1
            for key_hash, (grouping_key, val_) in h_tbl.items():
                unioned_tup = {**tup, **grouping_key}
                next_op.next({**unioned_tup, out_key: val_})
            next_op.reset(tup)
            h_tbl.clear()
        
        return Operator(next, reset)
    
    return create

def filter_groups(incl_keys: List[str]) -> GroupingFunc:
    """Filters tuple keys to include only those specified."""
    def filter_func(tup: TupleType) -> TupleType:
        return {k: v for k, v in tup.items() if k in incl_keys}
    return filter_func

def single_group(_: TupleType) -> TupleType:
    """Groups all tuples into a single group."""
    return {}

def counter(val_: OpResult, _: TupleType) -> OpResult:
    """Counts tuples."""
    if val_["type"] == "Empty":
        return create_op_result_int(1)
    if val_["type"] == "Int":
        return create_op_result_int(val_["value"] + 1)
    return val_

def sum_ints(search_key: str) -> ReductionFunc:
    """Sums integer values for a given key."""
    def reduce(val_: OpResult, tup: TupleType) -> OpResult:
        if val_["type"] == "Empty":
            return create_op_result_int(0)
        if val_["type"] == "Int":
            if search_key in tup and tup[search_key]["type"] == "Int":
                return create_op_result_int(val_["value"] + tup[search_key]["value"])
            raise ValueError(f"'sum_vals' failed to find integer value for '{search_key}'")
        return val_
    return reduce

def distinct(groupby_func: GroupingFunc) -> OperatorCreator:
    """Removes duplicate tuples based on a grouping function."""
    def create(next_op: Operator) -> Operator:
        h_tbl = {}
        reset_counter = [0]
        
        def next(tup: TupleType):
            grouping_key = groupby_func(tup)
            key_hash = hashlib.md5(str(grouping_key).encode()).hexdigest()
            h_tbl[key_hash] = (grouping_key, True)
        
        def reset(tup: TupleType):
            reset_counter[0] += 1
            for key_hash, (key_, _) in h_tbl.items():
                merged_tup = {**tup, **key_}
                next_op.next(merged_tup)
            next_op.reset(tup)
            h_tbl.clear()
        
        return Operator(next, reset)
    
    return create

def split(left: Operator, right: Operator) -> Operator:
    """Splits the stream to two operators."""
    def next(tup: TupleType):
        left.next(tup)
        right.next(tup)
    
    def reset(tup: TupleType):
        left.reset(tup)
        right.reset(tup)
    
    return Operator(next, reset)

KeyExtractor = Callable[[TupleType], Tuple[TupleType, TupleType]]

def join(eid_key: str = "eid", left_extractor: KeyExtractor, right_extractor: KeyExtractor) -> DoubleOperatorCreator:
    """Joins two streams based on key extractors."""
    def create(next_op: Operator) -> Tuple[Operator, Operator]:
        h_tbl1 = {}
        h_tbl2 = {}
        left_curr_epoch = [0]
        right_curr_epoch = [0]
        
        def handle_join_side(curr_h_tbl: Dict, other_h_tbl: Dict, curr_epoch_ref: List[int], other_epoch_ref: List[int], f: KeyExtractor) -> Operator:
            def next(tup: TupleType):
                key, vals_ = f(tup)
                curr_epoch = get_mapped_int(eid_key, tup)
                
                while curr_epoch > curr_epoch_ref[0]:
                    if other_epoch_ref[0] > curr_epoch_ref[0]:
                        next_op.reset({eid_key: create_op_result_int(curr_epoch_ref[0])})
                    curr_epoch_ref[0] += 1
                
                new_tup = {**key, eid_key: create_op_result_int(curr_epoch)}
                new_tup_hash = hashlib.md5(str(new_tup).encode()).hexdigest()
                
                if new_tup_hash in other_h_tbl:
                    val_ = other_h_tbl.pop(new_tup_hash)[1]
                    next_op.next({**new_tup, **vals_, **val_})
                else:
                    curr_h_tbl[new_tup_hash] = (new_tup, vals_)
            
            def reset(tup: TupleType):
                curr_epoch = get_mapped_int(eid_key, tup)
                while curr_epoch > curr_epoch_ref[0]:
                    if other_epoch_ref[0] > curr_epoch_ref[0]:
                        next_op.reset({eid_key: create_op_result_int(curr_epoch_ref[0])})
                    curr_epoch_ref[0] += 1
            
            return Operator(next, reset)
        
        return (
            handle_join_side(h_tbl1, h_tbl2, left_curr_epoch, right_curr_epoch, left_extractor),
            handle_join_side(h_tbl2, h_tbl1, right_curr_epoch, left_curr_epoch, right_extractor)
        )
    
    return create

def rename_filtered_keys(renamings_pairs: List[Tuple[str, str]]) -> Callable[[TupleType], TupleType]:
    """Renames and filters tuple keys."""
    def rename(tup: TupleType) -> TupleType:
        result = {}
        for old_key, new_key in renamings_pairs:
            if old_key in tup:
                result[new_key] = tup[old_key]
        return result
    return rename

# Query definitions

def ident() -> OperatorCreator:
    """Filters out eth.src and eth.dst from tuples."""
    def create(next_op: Operator) -> Operator:
        def map_func(tup: TupleType) -> TupleType:
            return {
                k: v for k, v in tup.items()
                if k not in ["eth.src", "eth.dst"]
            }
        return map(map_func)(next_op)
    return create

def count_pkts() -> OperatorCreator:
    """Counts packets per epoch."""
    def create(next_op: Operator) -> Operator:
        return epoch(1.0, "eid")(
            groupby(single_group, counter, "pkts")(next_op)
        )
    return create

def pkts_per_src_dst() -> OperatorCreator:
    """Counts packets per source and destination IP."""
    def create(next_op: Operator) -> Operator:
        return epoch(1.0, "eid")(
            groupby(filter_groups(["ipv4.src", "ipv4.dst"]), counter, "pkts")(next_op)
        )
    return create

def distinct_srcs() -> OperatorCreator:
    """Counts distinct source IPs per epoch."""
    def create(next_op: Operator) -> Operator:
        return epoch(1.0, "eid")(
            distinct(filter_groups(["ipv4.src"]))(
                groupby(single_group, counter, "srcs")(next_op)
            )
        )
    return create

def tcp_new_cons() -> OperatorCreator:
    """Detects new TCP connections."""
    threshold = 40
    def create(next_op: Operator) -> Operator:
        def filter_func(tup: TupleType) -> bool:
            return (
                get_mapped_int("ipv4.proto", tup) == 6 and
                get_mapped_int("l4.flags", tup) == 2
            )
        return epoch(1.0, "eid")(
            filter(filter_func)(
                groupby(filter_groups(["ipv4.dst"]), counter, "cons")(
                    filter(key_geq_int("cons", threshold))(next_op)
                )
            )
        )
    return create

def ssh_brute_force() -> OperatorCreator:
    """Detects SSH brute force attempts."""
    threshold = 40
    def create(next_op: Operator) -> Operator:
        def filter_func(tup: TupleType) -> bool:
            return (
                get_mapped_int("ipv4.proto", tup) == 6 and
                get_mapped_int("l4.dport", tup) == 22
            )
        return epoch(1.0, "eid")(
            filter(filter_func)(
                distinct(filter_groups(["ipv4.src", "ipv4.dst", "ipv4.len"]))(
                    groupby(filter_groups(["ipv4.dst", "ipv4.len"]), counter, "srcs")(
                        filter(key_geq_int("srcs", threshold))(next_op)
                    )
                )
            )
        )
    return create

def super_spreader() -> OperatorCreator:
    """Detects super spreaders."""
    threshold = 40
    def create(next_op: Operator) -> Operator:
        return epoch(1.0, "eid")(
            distinct(filter_groups(["ipv4.src", "ipv4.dst"]))(
                groupby(filter_groups(["ipv4.src"]), counter, "dsts")(
                    filter(key_geq_int("dsts", threshold))(next_op)
                )
            )
        )
    return create

def port_scan() -> OperatorCreator:
    """Detects port scans."""
    threshold = 40
    def create(next_op: Operator) -> Operator:
        return epoch(1.0, "eid")(
            distinct(filter_groups(["ipv4.src", "l4.dport"]))(
                groupby(filter_groups(["ipv4.src"]), counter, "ports")(
                    filter(key_geq_int("ports", threshold))(next_op)
                )
            )
        )
    return create

def ddos() -> OperatorCreator:
    """Detects DDoS attacks."""
    threshold = 45
    def create(next_op: Operator) -> Operator:
        return epoch(1.0, "eid")(
            distinct(filter_groups(["ipv4.src", "ipv4.dst"]))(
                groupby(filter_groups(["ipv4.dst"]), counter, "srcs")(
                    filter(key_geq_int("srcs", threshold))(next_op)
                )
            )
        )
    return create

def syn_flood_sonata() -> Callable[[Operator], List[Operator]]:
    """Detects SYN flood attacks (Sonata semantic)."""
    threshold = 3
    epoch_dur = 1.0
    
    def create(next_op: Operator) -> List[Operator]:
        def syns(next_op: Operator) -> Operator:
            def filter_func(tup: TupleType) -> bool:
                return (
                    get_mapped_int("ipv4.proto", tup) == 6 and
                    get_mapped_int("l4.flags", tup) == 2
                )
            return epoch(epoch_dur, "eid")(
                filter(filter_func)(
                    groupby(filter_groups(["ipv4.dst"]), counter, "syns")(next_op)
                )
            )
        
        def synacks(next_op: Operator) -> Operator:
            def filter_func(tup: TupleType) -> bool:
                return (
                    get_mapped_int("ipv4.proto", tup) == 6 and
                    get_mapped_int("l4.flags", tup) == 18
                )
            return epoch(epoch_dur, "eid")(
                filter(filter_func)(
                    groupby(filter_groups(["ipv4.src"]), counter, "synacks")(next_op)
                )
            )
        
        def acks(next_op: Operator) -> Operator:
            def filter_func(tup: TupleType) -> bool:
                return (
                    get_mapped_int("ipv4.proto", tup) == 6 and
                    get_mapped_int("l4.flags", tup) == 16
                )
            return epoch(epoch_dur, "eid")(
                filter(filter_func)(
                    groupby(filter_groups(["ipv4.dst"]), counter, "acks")(next_op)
                )
            )
        
        join_op1, join_op2 = join(
            lambda tup: (filter_groups(["host"])(tup), filter_groups(["syns+synacks"])(tup)),
            lambda tup: (rename_filtered_keys([("ipv4.dst", "host")])(tup), filter_groups(["acks"])(tup))
        )(
            map(
                lambda tup: {
                    **tup,
                    "syns+synacks-acks": create_op_result_int(
                        get_mapped_int("syns+synacks", tup) - get_mapped_int("acks", tup)
                    )
                }
            )(
                filter(key_geq_int("syns+synacks-acks", threshold))(next_op)
            )
        )
        
        join_op3, join_op4 = join(
            lambda tup: (rename_filtered_keys([("ipv4.dst", "host")])(tup), filter_groups(["syns"])(tup)),
            lambda tup: (rename_filtered_keys([("ipv4.src", "host")])(tup), filter_groups(["synacks"])(tup))
        )(
            map(
                lambda tup: {
                    **tup,
                    "syns+synacks": create_op_result_int(
                        get_mapped_int("syns", tup) + get_mapped_int("synacks", tup)
                    )
                }
            )(join_op1)
        )
        
        return [
            syns(join_op3),
            synacks(join_op4),
            acks(join_op2)
        ]
    
    return create

def completed_flows() -> Callable[[Operator], List[Operator]]:
    """Detects completed TCP flows."""
    threshold = 1
    epoch_dur = 30.0
    
    def create(next_op: Operator) -> List[Operator]:
        def syns(next_op: Operator) -> Operator:
            def filter_func(tup: TupleType) -> bool:
                return (
                    get_mapped_int("ipv4.proto", tup) == 6 and
                    get_mapped_int("l4.flags", tup) == 2
                )
            return epoch(epoch_dur, "eid")(
                filter(filter_func)(
                    groupby(filter_groups(["ipv4.dst"]), counter, "syns")(next_op)
                )
            )
        
        def fins(next_op: Operator) -> Operator:
            def filter_func(tup: TupleType) -> bool:
                return (
                    get_mapped_int("ipv4.proto", tup) == 6 and
                    (get_mapped_int("l4.flags", tup) & 1) == 1
                )
            return epoch(epoch_dur, "eid")(
                filter(filter_func)(
                    groupby(filter_groups(["ipv4.src"]), counter, "fins")(next_op)
                )
            )
        
        op1, op2 = join(
            lambda tup: (rename_filtered_keys([("ipv4.dst", "host")])(tup), filter_groups(["syns"])(tup)),
            lambda tup: (rename_filtered_keys([("ipv4.src", "host")])(tup), filter_groups(["fins"])(tup))
        )(
            map(
                lambda tup: {
                    **tup,
                    "diff": create_op_result_int(
                        get_mapped_int("syns", tup) - get_mapped_int("fins", tup)
                    )
                }
            )(
                filter(key_geq_int("diff", threshold))(next_op)
            )
        )
        
        return [
            syns(op1),
            fins(op2)
        ]
    
    return create

def slowloris() -> Callable[[Operator], List[Operator]]:
    """Detects Slowloris attacks."""
    t1 = 5
    t2 = 500
    t3 = 90
    epoch_dur = 1.0
    
    def create(next_op: Operator) -> List[Operator]:
        def n_conns(next_op: Operator) -> Operator:
            def filter_func(tup: TupleType) -> bool:
                return get_mapped_int("ipv4.proto", tup) == 6
            return epoch(epoch_dur, "eid")(
                filter(filter_func)(
                    distinct(filter_groups(["ipv4.src", "ipv4.dst", "l4.sport"]))(
                        groupby(filter_groups(["ipv4.dst"]), counter, "n_conns")(
                            filter(lambda tup: get_mapped_int("n_conns", tup) >= t1)(next_op)
                        )
                    )
                )
            )
        
        def n_bytes(next_op: Operator) -> Operator:
            def filter_func(tup: TupleType) -> bool:
                return get_mapped_int("ipv4.proto", tup) == 6
            return epoch(epoch_dur, "eid")(
                filter(filter_func)(
                    groupby(filter_groups(["ipv4.dst"]), sum_ints("ipv4.len"), "n_bytes")(
                        filter(lambda tup: get_mapped_int("n_bytes", tup) >= t2)(next_op)
                    )
                )
            )
        
        op1, op2 = join(
            lambda tup: (filter_groups(["ipv4.dst"])(tup), filter_groups(["n_conns"])(tup)),
            lambda tup: (filter_groups(["ipv4.dst"])(tup), filter_groups(["n_bytes"])(tup))
        )(
            map(
                lambda tup: {
                    **tup,
                    "bytes_per_conn": create_op_result_int(
                        get_mapped_int("n_bytes", tup) // get_mapped_int("n_conns", tup)
                    )
                }
            )(
                filter(lambda tup: get_mapped_int("bytes_per_conn", tup) <= t3)(next_op)
            )
        )
        
        return [
            n_conns(op1),
            n_bytes(op2)
        ]
    
    return create

def join_test() -> Callable[[Operator], List[Operator]]:
    """Test join operation."""
    epoch_dur = 1.0
    
    def create(next_op: Operator) -> List[Operator]:
        def syns(next_op: Operator) -> Operator:
            def filter_func(tup: TupleType) -> bool:
                return (
                    get_mapped_int("ipv4.proto", tup) == 6 and
                    get_mapped_int("l4.flags", tup) == 2
                )
            return epoch(epoch_dur, "eid")(
                filter(filter_func)(next_op)
            )
        
        def synacks(next_op: Operator) -> Operator:
            def filter_func(tup: TupleType) -> bool:
                return (
                    get_mapped_int("ipv4.proto", tup) == 6 and
                    get_mapped_int("l4.flags", tup) == 18
                )
            return epoch(epoch_dur, "eid")(
                filter(filter_func)(next_op)
            )
        
        op1, op2 = join(
            lambda tup: (
                rename_filtered_keys([("ipv4.src", "host")])(tup),
                rename_filtered_keys([("ipv4.dst", "remote")])(tup)
            ),
            lambda tup: (
                rename_filtered_keys([("ipv4.dst", "host")])(tup),
                filter_groups(["time"])(tup)
            )
        )(next_op)
        
        return [
            syns(op1),
            synacks(op2)
        ]
    
    return create

def q3() -> OperatorCreator:
    """Query 3: Distinct source-destination pairs."""
    def create(next_op: Operator) -> Operator:
        return epoch(100.0, "eid")(
            distinct(filter_groups(["ipv4.src", "ipv4.dst"]))(next_op)
        )
    return create

def q4() -> OperatorCreator:
    """Query 4: Packet count per destination."""
    def create(next_op: Operator) -> Operator:
        return epoch(10000.0, "eid")(
            groupby(filter_groups(["ipv4.dst"]), counter, "pkts")(next_op)
        )
    return create

# Main entry point

def run_queries():
    """Runs predefined queries on sample data."""
    queries = [ident()(dump_tuple_op(out_file=sys.stdout))]
    
    tuples = [
        {
            "time": create_op_result_float(0.0 + i),
            "eth.src": create_op_result_mac(b"\x00\x11\x22\x33\x44\x55"),
            "eth.dst": create_op_result_mac(b"\xAA\xBB\xCC\xDD\xEE\xFF"),
            "eth.ethertype": create_op_result_int(0x0800),
            "ipv4.hlen": create_op_result_int(20),
            "ipv4.proto": create_op_result_int(6),
            "ipv4.len": create_op_result_int(60),
            "ipv4.src": create_op_result_ipv4(ip_address("127.0.0.1")),
            "ipv4.dst": create_op_result_ipv4(ip_address("127.0.0.1")),
            "l4.sport": create_op_result_int(440),
            "l4.dport": create_op_result_int(50000),
            "l4.flags": create_op_result_int(10),
        }
        for i in range(20)
    ]
    
    for tup in tuples:
        for query in queries:
            query.next(tup)
    
    return None

if __name__ == "__main__":
    run_queries()
    print("Done")
```