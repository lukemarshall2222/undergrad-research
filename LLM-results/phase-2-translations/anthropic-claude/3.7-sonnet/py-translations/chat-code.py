# Common utilities
#
# Includes minimal parsing of header fields into a map from strings to values

# Operators act on named "tuples" which are maps from strings to op_result types
import ipaddress
import struct
import collections
from typing import Dict, List, Tuple, Callable, Any, Optional, Union, Set
import time

# Equivalent to OCaml's variant type using Python classes
class OpResult:
    """Base class for operation results"""
    pass

class Float(OpResult):
    """Floating point value"""
    def __init__(self, value: float):
        self.value = value

class Int(OpResult):
    """Integer value"""
    def __init__(self, value: int):
        self.value = value

class IPv4(OpResult):
    """IPv4 address"""
    def __init__(self, value: ipaddress.IPv4Address):
        self.value = value

class MAC(OpResult):
    """MAC address"""
    def __init__(self, value: bytes):
        self.value = value

class Empty(OpResult):
    """Empty/missing value"""
    pass

# Map equivalent in Python using dict
class Tuple:
    """Map from strings to op_results"""
    def __init__(self):
        self.data = {}
    
    @classmethod
    def empty(cls):
        """Creates an empty tuple"""
        return cls()
    
    @classmethod
    def singleton(cls, key: str, value: OpResult):
        """Creates a tuple with a single key-value pair"""
        t = cls()
        t.data[key] = value
        return t
    
    def add(self, key: str, value: OpResult):
        """Adds a key-value pair to the tuple"""
        self.data[key] = value
        return self
    
    def find(self, key: str) -> OpResult:
        """Finds a value for the given key"""
        if key in self.data:
            return self.data[key]
        raise KeyError(f"Key '{key}' not found in tuple")
    
    def find_opt(self, key: str) -> Optional[OpResult]:
        """Optional find - returns None if key not found"""
        return self.data.get(key, None)
    
    def filter(self, predicate: Callable[[str, OpResult], bool]):
        """Returns a new tuple with only the key-value pairs that satisfy the predicate"""
        result = Tuple()
        for key, value in self.data.items():
            if predicate(key, value):
                result.data[key] = value
        return result
    
    def iter(self, func: Callable[[str, OpResult], None]):
        """Iterates over the tuple and applies a function to each key-value pair"""
        for key, value in self.data.items():
            func(key, value)
    
    def fold(self, func: Callable[[str, OpResult, str], str], initial_value: str) -> str:
        """Folds over the tuple"""
        result = initial_value
        for key, value in self.data.items():
            result = func(key, value, result)
        return result
    
    def union(self, resolver: Callable[[str, OpResult, OpResult], Optional[OpResult]], 
              other: 'Tuple') -> 'Tuple':
        """Merges two tuples, using resolver to handle key conflicts"""
        result = Tuple()
        # Add all keys from self
        for key, value in self.data.items():
            result.data[key] = value
        
        # Add or merge keys from other
        for key, value in other.data.items():
            if key in result.data:
                resolved = resolver(key, result.data[key], value)
                if resolved is not None:
                    result.data[key] = resolved
            else:
                result.data[key] = value
        
        return result

# Operator class - equivalent to OCaml's record type
class Operator:
    """Defines a data processing unit in a stream processing pipeline"""
    def __init__(self, next_func: Callable[[Tuple], None], reset_func: Callable[[Tuple], None]):
        self.next = next_func
        self.reset = reset_func

# Types for operator creators
OpCreator = Callable[[Operator], Operator]
DblOpCreator = Callable[[Operator], Tuple[Operator, Operator]]

# Chaining operators
def chain_op(op_creator_func: OpCreator, next_op: Operator) -> Operator:
    """Right associative 'chaining' operator for passing output to the next operator"""
    return op_creator_func(next_op)

def chain_double_op(op_creator_func: DblOpCreator, op: Operator) -> Tuple[Operator, Operator]:
    """Chaining for operators that return two operators"""
    return op_creator_func(op)

# Conversion utilities

def string_of_mac(buf: bytes) -> str:
    """Formats the 6 bytes of the MAC address as a colon-separated string in hex"""
    return ':'.join(f'{b:02x}' for b in buf)

def tcp_flags_to_strings(flags: int) -> str:
    """Converts TCP flags into a human-readable string representation"""
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
    
    result = []
    for key, value in tcp_flags_map.items():
        if flags & value == value:
            result.append(key)
    
    return "|".join(result)

def int_of_op_result(input_op: OpResult) -> int:
    """Extracts int from Int op_result"""
    if isinstance(input_op, Int):
        return input_op.value
    raise ValueError("Trying to extract int from non-int result")

def float_of_op_result(input_op: OpResult) -> float:
    """Extracts float from Float op_result"""
    if isinstance(input_op, Float):
        return input_op.value
    raise ValueError("Trying to extract float from non-float result")

def string_of_op_result(input_op: OpResult) -> str:
    """Returns the human-readable version of each op_result value"""
    if isinstance(input_op, Float):
        return f"{input_op.value}"
    elif isinstance(input_op, Int):
        return str(input_op.value)
    elif isinstance(input_op, IPv4):
        return str(input_op.value)
    elif isinstance(input_op, MAC):
        return string_of_mac(input_op.value)
    elif isinstance(input_op, Empty):
        return "Empty"
    else:
        return str(input_op)

def string_of_tuple(input_tuple: Tuple) -> str:
    """Outputs the tuple in a human-readable form"""
    result = ""
    for key, val in input_tuple.data.items():
        result += f'"{key}" => {string_of_op_result(val)}, '
    return result

def tuple_of_list(tup_list: List[Tuple[str, OpResult]]) -> Tuple:
    """Creates a Tuple from a list of key-value pairs"""
    result = Tuple()
    for key, value in tup_list:
        result.data[key] = value
    return result

def dump_tuple(outc, tup: Tuple) -> None:
    """Prints formatted representation of a Tuple"""
    print(string_of_tuple(tup), file=outc)

def lookup_int(key: str, tup: Tuple) -> int:
    """Retrieves the int value for a given key"""
    return int_of_op_result(tup.find(key))

def lookup_float(key: str, tup: Tuple) -> float:
    """Retrieves the float value for a given key"""
    return float_of_op_result(tup.find(key))

# Built-in operator definitions
init_table_size = 10000

def dump_tuple_op(outc, show_reset=False) -> Operator:
    """Dump all fields of all tuples to the given output channel"""
    def next_func(tup: Tuple) -> None:
        dump_tuple(outc, tup)
    
    def reset_func(tup: Tuple) -> None:
        if show_reset:
            dump_tuple(outc, tup)
            print("[reset]", file=outc)
    
    return Operator(next_func, reset_func)

def dump_as_csv(outc, static_field=None, header=True) -> Operator:
    """Writes tuples to an output channel in CSV format"""
    first = [header]  # Using list as a mutable container for the boolean
    
    def next_func(tup: Tuple) -> None:
        if first[0]:
            if static_field:
                key, _ = static_field
                print(f"{key},", end="", file=outc)
            
            for key in tup.data:
                print(f"{key},", end="", file=outc)
            print("", file=outc)
            first[0] = False
        
        if static_field:
            _, value = static_field
            print(f"{value},", end="", file=outc)
        
        for value in tup.data.values():
            print(f"{string_of_op_result(value)},", end="", file=outc)
        print("", file=outc)
    
    def reset_func(_: Tuple) -> None:
        pass
    
    return Operator(next_func, reset_func)

def dump_walts_csv(filename: str) -> Operator:
    """Dumps csv in Walt's canonical csv format"""
    outc = [None]  # Using list as a mutable container
    first = [True]  # Using list as a mutable container
    
    def next_func(tup: Tuple) -> None:
        if first[0]:
            outc[0] = open(filename, 'w')
            first[0] = False
        
        print(f"{string_of_op_result(tup.find('src_ip'))},"
              f"{string_of_op_result(tup.find('dst_ip'))},"
              f"{string_of_op_result(tup.find('src_l4_port'))},"
              f"{string_of_op_result(tup.find('dst_l4_port'))},"
              f"{string_of_op_result(tup.find('packet_count'))},"
              f"{string_of_op_result(tup.find('byte_count'))},"
              f"{string_of_op_result(tup.find('epoch_id'))}", 
              file=outc[0])
    
    def reset_func(_: Tuple) -> None:
        pass
    
    return Operator(next_func, reset_func)

def get_ip_or_zero(input_str: str) -> OpResult:
    """Converts string to either Int(0) or IPv4 address"""
    if input_str == "0":
        return Int(0)
    else:
        return IPv4(ipaddress.IPv4Address(input_str))

def read_walts_csv(file_names: List[str], ops: List[Operator], epoch_id_key="eid") -> None:
    """Reads multiple CSV files and processes the data"""
    # Open each CSV file for scanning
    inchs_eids_tupcount = [(open(filename, 'r'), 0, 0) for filename in file_names]
    
    running = len(ops)
    while running > 0:
        for (in_ch, eid, tup_count), op in zip(inchs_eids_tupcount, ops):
            if eid >= 0:
                try:
                    line = in_ch.readline().strip()
                    if not line:
                        raise EOFError
                    
                    fields = line.split(',')
                    src_ip, dst_ip = fields[0], fields[1]
                    src_l4_port, dst_l4_port = int(fields[2]), int(fields[3])
                    packet_count, byte_count = int(fields[4]), int(fields[5])
                    epoch_id = int(fields[6])
                    
                    p = Tuple.empty()
                    p.add("ipv4.src", get_ip_or_zero(src_ip))
                    p.add("ipv4.dst", get_ip_or_zero(dst_ip))
                    p.add("l4.sport", Int(src_l4_port))
                    p.add("l4.dport", Int(dst_l4_port))
                    p.add("packet_count", Int(packet_count))
                    p.add("byte_count", Int(byte_count))
                    p.add(epoch_id_key, Int(epoch_id))
                    
                    tup_count += 1
                    
                    if epoch_id > eid:
                        while epoch_id > eid:
                            reset_tup = Tuple.singleton(epoch_id_key, Int(eid))
                            reset_tup.add("tuples", Int(tup_count))
                            op.reset(reset_tup)
                            tup_count = 0
                            eid += 1
                    
                    p.add("tuples", Int(tup_count))
                    op.next(p)
                
                except EOFError:
                    reset_tup = Tuple.singleton(epoch_id_key, Int(eid + 1))
                    reset_tup.add("tuples", Int(tup_count))
                    op.reset(reset_tup)
                    running -= 1
                    eid = -1
    
    print("Done.")

def meta_meter(name: str, outc, next_op: Operator, static_field=None) -> Operator:
    """Tracks how many tuples processed per epoch and logs it"""
    epoch_count = [0]  # Using list as a mutable container
    tups_count = [0]   # Using list as a mutable container
    
    def next_func(tup: Tuple) -> None:
        tups_count[0] += 1
        next_op.next(tup)
    
    def reset_func(tup: Tuple) -> None:
        static_value = static_field if static_field else ""
        print(f"{epoch_count[0]},{name},{tups_count[0]},{static_value}", file=outc)
        tups_count[0] = 0
        epoch_count[0] += 1
        next_op.reset(tup)
    
    return Operator(next_func, reset_func)

def epoch(epoch_width: float, key_out: str, next_op: Operator) -> Operator:
    """Resets op every w seconds and adds epoch id to tuple under key_out"""
    epoch_boundary = [0.0]  # Using list as a mutable container
    eid = [0]              # Using list as a mutable container
    
    def next_func(tup: Tuple) -> None:
        time_value = float_of_op_result(tup.find("time"))
        
        if epoch_boundary[0] == 0.0:  # Start of epoch
            epoch_boundary[0] = time_value + epoch_width
        elif time_value >= epoch_boundary[0]:
            # Within an epoch, calculate which one
            while time_value >= epoch_boundary[0]:
                next_op.reset(Tuple.singleton(key_out, Int(eid[0])))
                epoch_boundary[0] += epoch_width
                eid[0] += 1
        
        next_op.next(tup.add(key_out, Int(eid[0])))
    
    def reset_func(_: Tuple) -> None:
        next_op.reset(Tuple.singleton(key_out, Int(eid[0])))
        epoch_boundary[0] = 0.0
        eid[0] = 0
    
    return Operator(next_func, reset_func)

def filter_op(f: Callable[[Tuple], bool], next_op: Operator) -> Operator:
    """Passes only tuples where f applied to the tuple returns true"""
    def next_func(tup: Tuple) -> None:
        if f(tup):
            next_op.next(tup)
    
    def reset_func(tup: Tuple) -> None:
        next_op.reset(tup)
    
    return Operator(next_func, reset_func)

def key_geq_int(key: str, threshold: int, tup: Tuple) -> bool:
    """Tests if a key's int value is >= threshold"""
    return int_of_op_result(tup.find(key)) >= threshold

def get_mapped_int(key: str, tup: Tuple) -> int:
    """Retrieves int value for a key"""
    return int_of_op_result(tup.find(key))

def get_mapped_float(key: str, tup: Tuple) -> float:
    """Retrieves float value for a key"""
    return float_of_op_result(tup.find(key))

def map_op(f: Callable[[Tuple], Tuple], next_op: Operator) -> Operator:
    """Applies function f to all tuples"""
    def next_func(tup: Tuple) -> None:
        next_op.next(f(tup))
    
    def reset_func(tup: Tuple) -> None:
        next_op.reset(tup)
    
    return Operator(next_func, reset_func)

# Type definitions for grouping
GroupingFunc = Callable[[Tuple], Tuple]
ReductionFunc = Callable[[OpResult, Tuple], OpResult]

def groupby(groupby_func: GroupingFunc, reduce_func: ReductionFunc, 
            out_key: str, next_op: Operator) -> Operator:
    """Groups tuples by a key and reduces them"""
    h_tbl = {}  # Python dict instead of OCaml hashtable
    reset_counter = [0]  # Using list as a mutable container
    
    def next_func(tup: Tuple) -> None:
        # Extract grouping key
        grouping_key = groupby_func(tup)
        grouping_key_str = string_of_tuple(grouping_key)
        
        # Update or create group
        if grouping_key_str in h_tbl:
            val = h_tbl[grouping_key_str]
            h_tbl[grouping_key_str] = (grouping_key, reduce_func(val[1], tup))
        else:
            h_tbl[grouping_key_str] = (grouping_key, reduce_func(Empty(), tup))
    
    def reset_func(tup: Tuple) -> None:
        reset_counter[0] += 1
        
        for key_str, (grouping_key, val) in h_tbl.items():
            # Merge tuples
            def use_left(_, a, _b):
                return a
            
            unioned_tup = tup.union(use_left, grouping_key)
            unioned_tup.add(out_key, val)
            next_op.next(unioned_tup)
        
        next_op.reset(tup)
        h_tbl.clear()
    
    return Operator(next_func, reset_func)

def filter_groups(incl_keys: List[str], tup: Tuple) -> Tuple:
    """Returns a new tuple with only the keys included in incl_keys"""
    def key_filter(key: str, _):
        return key in incl_keys
    
    return tup.filter(key_filter)

def single_group(_: Tuple) -> Tuple:
    """Grouping function that forms a single group"""
    return Tuple.empty()

def counter(val: OpResult, _: Tuple) -> OpResult:
    """Reduction function to count tuples"""
    if isinstance(val, Empty):
        return Int(1)
    elif isinstance(val, Int):
        return Int(val.value + 1)
    else:
        return val

def sum_ints(search_key: str, init_val: OpResult, tup: Tuple) -> OpResult:
    """Sum values (assumed to be Int) of a given field"""
    if isinstance(init_val, Empty):
        return Int(0)
    elif isinstance(init_val, Int):
        result = tup.find_opt(search_key)
        if result and isinstance(result, Int):
            return Int(result.value + init_val.value)
        else:
            raise ValueError(f"'sum_vals' function failed to find integer value mapped to '{search_key}'")
    else:
        return init_val

def distinct(groupby_func: GroupingFunc, next_op: Operator) -> Operator:
    """Returns a list of distinct elements each epoch"""
    h_tbl = {}  # Python dict instead of OCaml hashtable
    reset_counter = [0]  # Using list as a mutable container
    
    def next_func(tup: Tuple) -> None:
        grouping_key = groupby_func(tup)
        h_tbl[string_of_tuple(grouping_key)] = grouping_key
    
    def reset_func(tup: Tuple) -> None:
        reset_counter[0] += 1
        
        for key_str, key_ in h_tbl.items():
            def use_left(_, a, _b):
                return a
            
            merged_tup = tup.union(use_left, key_)
            next_op.next(merged_tup)
        
        next_op.reset(tup)
        h_tbl.clear()
    
    return Operator(next_func, reset_func)

def split(l: Operator, r: Operator) -> Operator:
    """Splits the stream processing in two"""
    def next_func(tup: Tuple) -> None:
        l.next(tup)
        r.next(tup)
    
    def reset_func(tup: Tuple) -> None:
        l.reset(tup)
        r.reset(tup)
    
    return Operator(next_func, reset_func)

# Define key extractor type
KeyExtractor = Callable[[Tuple], Tuple[Tuple, Tuple]]

def join(left_extractor: KeyExtractor, right_extractor: KeyExtractor, 
         next_op: Operator, eid_key="eid") -> Tuple[Operator, Operator]:
    """Joins two streams based on matching keys"""
    h_tbl1 = {}
    h_tbl2 = {}
    left_curr_epoch = [0]
    right_curr_epoch = [0]
    
    def handle_join_side(curr_h_tbl, other_h_tbl, curr_epoch_ref, other_epoch_ref, f):
        def next_func(tup: Tuple) -> None:
            key, vals_ = f(tup)
            curr_epoch = get_mapped_int(eid_key, tup)
            
            while curr_epoch > curr_epoch_ref[0]:
                if other_epoch_ref[0] > curr_epoch_ref[0]:
                    next_op.reset(Tuple.singleton(eid_key, Int(curr_epoch_ref[0])))
                curr_epoch_ref[0] += 1
            
            new_tup = key.add(eid_key, Int(curr_epoch))
            new_tup_str = string_of_tuple(new_tup)
            
            if new_tup_str in other_h_tbl:
                val_ = other_h_tbl[new_tup_str]
                del other_h_tbl[new_tup_str]
                
                def use_left(_, a, _b):
                    return a
                
                result = new_tup.union(use_left, vals_.union(use_left, val_))
                next_op.next(result)
            else:
                curr_h_tbl[new_tup_str] = vals_
        
        def reset_func(tup: Tuple) -> None:
            curr_epoch = get_mapped_int(eid_key, tup)
            while curr_epoch > curr_epoch_ref[0]:
                if other_epoch_ref[0] > curr_epoch_ref[0]:
                    next_op.reset(Tuple.singleton(eid_key, Int(curr_epoch_ref[0])))
                curr_epoch_ref[0] += 1
        
        return Operator(next_func, reset_func)
    
    return (
        handle_join_side(h_tbl1, h_tbl2, left_curr_epoch, right_curr_epoch, left_extractor),
        handle_join_side(h_tbl2, h_tbl1, right_curr_epoch, left_curr_epoch, right_extractor)
    )

def rename_filtered_keys(renamings_pairs: List[Tuple[str, str]], in_tup: Tuple) -> Tuple:
    """Renames selected keys in a tuple"""
    new_tup = Tuple.empty()
    
    for old_key, new_key in renamings_pairs:
        val = in_tup.find_opt(old_key)
        if val:
            new_tup.add(new_key, val)
    
    return new_tup

# Main entry functions
def ident(next_op: Operator) -> Operator:
    """Identity function with filtering"""
    def filter_func(tup: Tuple):
        return tup.filter(lambda key, _: key != "eth.src" and key != "eth.dst")
    
    return chain_op(lambda next_op: map_op(filter_func, next_op), next_op)

def count_pkts(next_op: Operator) -> Operator:
    """Counts packets per epoch"""
    def epoch_op(next_op):
        return epoch(1.0, "eid", next_op)
    
    def groupby_op(next_op):
        return groupby(single_group, counter, "pkts", next_op)
    
    return chain_op(epoch_op, chain_op(groupby_op, next_op))

def pkts_per_src_dst(next_op: Operator) -> Operator:
    """Counts packets per source/destination pair"""
    def epoch_op(next_op):
        return epoch(1.0, "eid", next_op)
    
    def groupby_op(next_op):
        return groupby(
            lambda tup: filter_groups(["ipv4.src", "ipv4.dst"], tup),
            counter,
            "pkts",
            next_op
        )
    
    return chain_op(epoch_op, chain_op(groupby_op, next_op))

def distinct_srcs(next_op: Operator) -> Operator:
    """Counts distinct sources"""
    def epoch_op(next_op):
        return epoch(1.0, "eid", next_op)
    
    def distinct_op(next_op):
        return distinct(lambda tup: filter_groups(["ipv4.src"], tup), next_op)
    
    def groupby_op(next_op):
        return groupby(single_group, counter, "srcs", next_op)
    
    return chain_op(epoch_op, chain_op(distinct_op, chain_op(groupby_op, next_op)))

def tcp_new_cons(next_op: Operator) -> Operator:
    """Sonata 1: TCP new connections"""
    threshold = 40
    
    def epoch_op(next_op):
        return epoch(1.0, "eid", next_op)
    
    def filter_op_func(next_op):
        return filter_op(
            lambda tup: get_mapped_int("ipv4.proto", tup) == 6 and 
                       get_mapped_int("l4.flags", tup) == 2,
            next_op
        )
    
    def groupby_op(next_op):
        return groupby(
            lambda tup: filter_groups(["ipv4.dst"], tup),
            counter,
            "cons",
            next_op
        )
    
    def filter_threshold(next_op):
        return filter_op(
            lambda tup: key_geq_int("cons", threshold, tup),
            next_op
        )
    
    return chain_op(epoch_op, 
                   chain_op(filter_op_func, 
                           chain_op(groupby_op, 
                                   chain_op(filter_threshold, next_op))))

# Main Entry Points
def run_queries():
    """Run the defined queries"""
    queries = [chain_op(ident, dump_tuple_op(print))]
    
    # Create test data
    tuples = []
    for i in range(20):
        tup = Tuple.empty()
        tup.add("time", Float(0.0 + float(i)))
        
        # Ethernet fields
        tup.add("eth.src", MAC(b'\x00\x11\x22\x33\x44\x55'))
        tup.add("eth.dst", MAC(b'\xAA\xBB\xCC\xDD\xEE\xFF'))
        tup.add("eth.ethertype", Int(0x0800))
        
        # IPv4 fields
        tup.add("ipv4.hlen", Int(20))
        tup.add("ipv4.proto", Int(6))
        tup.add("ipv4.len", Int(60))
        tup.add("ipv4.src", IPv4(ipaddress.IPv4Address('127.0.0.1')))
        tup.add("ipv4.dst", IPv4(ipaddress.IPv4Address('127.0.0.1')))
        
        # Layer 4 fields
        tup.add("l4.sport", Int(440))
        tup.add("l4.dport", Int(50000))
        tup.add("l4.flags", Int(10))
        
        tuples.append(tup)
    
    # Apply each tuple to all queries
    for tup in tuples:
        for query in queries:
            query.next(tup)

# Main entrypoint
if __name__ == "__main__":
    run_queries()
    print("Done")