import sys
import ipaddress
import csv
from typing import Union, Dict, List, Callable, Tuple, Optional, Any, TextIO, Set

# Type Definitions and Core Data Structures (Equivalent to OCaml types)

# Represents the possible types of values in a tuple (OCaml's op_result)
class OpResult:
    """Base class for operation results."""
    pass

class FloatResult(OpResult):
    def __init__(self, value: float):
        self.value = value
    def __repr__(self) -> str:
        return f"FloatResult({self.value})"
    def __str__(self) -> str:
        return f"{self.value:f}" # OCaml's %f format

class IntResult(OpResult):
    def __init__(self, value: int):
        self.value = value
    def __repr__(self) -> str:
        return f"IntResult({self.value})"
    def __str__(self) -> str:
        return str(self.value)

class IPv4Result(OpResult):
    def __init__(self, value: ipaddress.IPv4Address):
        self.value = value
    def __repr__(self) -> str:
        return f"IPv4Result('{self.value}')"
    def __str__(self) -> str:
        return str(self.value)

class MACResult(OpResult):
    def __init__(self, value: bytes):
        if len(value) != 6:
            raise ValueError("MAC address must be 6 bytes long")
        self.value = value
    def __repr__(self) -> str:
        return f"MACResult({self.value!r})"
    def __str__(self) -> str:
        # OCaml's string_of_mac equivalent
        return ":".join(f"{b:02x}" for b in self.value)

class EmptyResult(OpResult):
    """Represents an empty or missing value."""
    def __repr__(self) -> str:
        return "EmptyResult()"
    def __str__(self) -> str:
        return "Empty"

# Represents a tuple as a dictionary (OCaml's Map<string, op_result>)
TupleType = Dict[str, OpResult]

# Forward declaration for Operator type hint
class Operator:
    pass

# Type hints for operator functions and creators
NextFunc = Callable[[TupleType], None]
ResetFunc = Callable[[TupleType], None]
OpCreator = Callable[[Operator], Operator]
DblOpCreator = Callable[[Operator], Tuple[Operator, Operator]]
GroupingFunc = Callable[[TupleType], TupleType]
ReductionFunc = Callable[[OpResult, TupleType], OpResult]
KeyExtractor = Callable[[TupleType], Tuple[TupleType, TupleType]]
FilterFunc = Callable[[TupleType], bool]
MapFunc = Callable[[TupleType], TupleType]


# Represents a data processing unit (OCaml's operator record)
class Operator:
    def __init__(self, next_func: NextFunc, reset_func: ResetFunc):
        self.next = next_func
        self.reset = reset_func

# --- Utils Module Equivalents ---

# Conversion utilities

def string_of_mac(buf: bytes) -> str:
    """Formats the 6 bytes of the MAC address as a colon-separated string."""
    if len(buf) != 6:
        raise ValueError("MAC address must be 6 bytes long")
    return ":".join(f"{b:02x}" for b in buf)

def tcp_flags_to_strings(flags: int) -> str:
    """Converts TCP flags integer into a human-readable string representation."""
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
    active_flags = [name for name, mask in tcp_flags_map.items() if flags & mask]
    return "|".join(active_flags) if active_flags else ""

def int_of_op_result(input_res: OpResult) -> int:
    """Extracts int value, raises TypeError if not an IntResult."""
    if isinstance(input_res, IntResult):
        return input_res.value
    else:
        raise TypeError(f"Trying to extract int from non-int result: {type(input_res)}")

def float_of_op_result(input_res: OpResult) -> float:
    """Extracts float value, raises TypeError if not a FloatResult."""
    if isinstance(input_res, FloatResult):
        return input_res.value
    else:
        raise TypeError(f"Trying to extract float from non-float result: {type(input_res)}")

def string_of_op_result(input_res: OpResult) -> str:
    """Returns the human-readable string version of an OpResult."""
    return str(input_res) # Relies on __str__ methods defined above

def string_of_tuple(input_tuple: TupleType) -> str:
    """Outputs the tuple dictionary in a human-readable form."""
    items = [f'"{key}" => {string_of_op_result(val)}' for key, val in input_tuple.items()]
    return ", ".join(items) + (", " if items else "") # Match OCaml's trailing comma+space

def tuple_of_list(tup_list: List[Tuple[str, OpResult]]) -> TupleType:
    """Creates a dictionary (TupleType) from a list of key-value pairs."""
    return dict(tup_list)

def dump_tuple_to_stream(out_stream: TextIO, tup: TupleType) -> None:
    """Prints formatted representation of a Tuple dictionary to a stream."""
    out_stream.write(string_of_tuple(tup) + "\n")

def lookup_int(key: str, tup: TupleType) -> int:
    """Retrieves the int value associated with a key in the dictionary."""
    try:
        return int_of_op_result(tup[key])
    except KeyError:
        raise KeyError(f"Key '{key}' not found in tuple")
    except TypeError as e:
        raise TypeError(f"Error looking up int for key '{key}': {e}")

def lookup_float(key: str, tup: TupleType) -> float:
    """Retrieves the float value associated with a key in the dictionary."""
    try:
        return float_of_op_result(tup[key])
    except KeyError:
        raise KeyError(f"Key '{key}' not found in tuple")
    except TypeError as e:
        raise TypeError(f"Error looking up float for key '{key}': {e}")

# --- Builtins Module Equivalents ---

INIT_TABLE_SIZE: int = 10000 # Hint for hash table sizes, less relevant in Python dicts

def dump_tuple_op(out_stream: TextIO = sys.stdout, show_reset: bool = False) -> Operator:
    """
    Creates an operator that dumps all fields of tuples to the given output stream.
    Terminal operator (does not call a next_op).
    """
    def next_func(tup: TupleType) -> None:
        dump_tuple_to_stream(out_stream, tup)

    def reset_func(tup: TupleType) -> None:
        if show_reset:
            dump_tuple_to_stream(out_stream, tup)
            out_stream.write("[reset]\n")

    return Operator(next_func=next_func, reset_func=reset_func)

def dump_as_csv(out_stream: TextIO = sys.stdout,
                static_field: Optional[Tuple[str, str]] = None,
                header: bool = True) -> Operator:
    """
    Creates an operator that writes tuples to an output stream in CSV format.
    Assumes all tuples have the same fields in the same order after the first.
    """
    # Use a mutable list to store the 'first' flag state across calls
    first_flag = [header]

    def next_func(tup: TupleType) -> None:
        writer = csv.writer(out_stream, lineterminator='\n') # Use csv module
        if first_flag[0]:
            header_row = []
            if static_field:
                header_row.append(static_field[0])
            header_row.extend(tup.keys())
            writer.writerow(header_row)
            first_flag[0] = False

        row = []
        if static_field:
            row.append(static_field[1])
        row.extend(string_of_op_result(value) for value in tup.values())
        writer.writerow(row)

    def reset_func(tup: TupleType) -> None:
        pass # Does nothing on reset

    return Operator(next_func=next_func, reset_func=reset_func)


def dump_walts_csv(filename: str) -> Operator:
    """
    Dumps csv in Walt's canonical format: src_ip, dst_ip, src_l4_port,
    dst_l4_port, packet_count, byte_count, epoch_id.
    """
    state = {'out_file': None, 'writer': None, 'first': True}

    def next_func(tup: TupleType) -> None:
        if state['first']:
            # Open file lazily on first tuple
            state['out_file'] = open(filename, 'w', newline='')
            state['writer'] = csv.writer(state['out_file'], lineterminator='\n')
            state['first'] = False

        try:
            row = [
                string_of_op_result(tup["src_ip"]),
                string_of_op_result(tup["dst_ip"]),
                string_of_op_result(tup["src_l4_port"]),
                string_of_op_result(tup["dst_l4_port"]),
                string_of_op_result(tup["packet_count"]),
                string_of_op_result(tup["byte_count"]),
                string_of_op_result(tup["epoch_id"]),
            ]
            state['writer'].writerow(row)
        except KeyError as e:
            print(f"Warning: Key {e} not found in tuple for Walt's CSV dump. Skipping row.", file=sys.stderr)
        except Exception as e:
             print(f"Error writing Walt's CSV: {e}", file=sys.stderr)


    def reset_func(tup: TupleType) -> None:
        # Close the file when the stream resets/ends?
        # The original OCaml doesn't explicitly close, relies on GC or process end.
        # It might be better to close it elsewhere if this isn't the true end.
        # For this translation, we won't close it here.
        pass

    # Ensure file is closed if process ends unexpectedly (optional)
    # import atexit
    # def cleanup():
    #     if state['out_file']:
    #         state['out_file'].close()
    # atexit.register(cleanup)

    return Operator(next_func=next_func, reset_func=reset_func)


def get_ip_or_zero(input_str: str) -> OpResult:
    """Parses string as IPv4 or returns Int 0."""
    if input_str == "0":
        return IntResult(0)
    else:
        try:
            return IPv4Result(ipaddress.IPv4Address(input_str))
        except ipaddress.AddressValueError:
             # OCaml uses of_string_exn, which raises Failure.
             # Python raises AddressValueError. Re-raise as ValueError for consistency?
             raise ValueError(f"Invalid IPv4 address string: {input_str}")

def read_walts_csv(file_names: List[str], ops: List[Operator], epoch_id_key="eid") -> None:
    """
    Reads multiple CSV files in Walt's format, processes rows into tuples,
    and passes them to corresponding operators, handling epochs.
    NOTE: This translation processes files sequentially then round-robins rows,
          unlike the OCaml version which seems to read one row per file per loop iteration.
          Achieving the exact OCaml round-robin requires more complex file handling.
    """
    if len(file_names) != len(ops):
        raise ValueError("Number of file names must match number of operators")

    # Prepare state for each file/operator pair
    states = [{'file': open(fname, 'r'),
               'reader': csv.reader(open(fname, 'r')), # Separate reader
               'eid': 0,
               'tup_count': 0,
               'active': True,
               'operator': op}
              for fname, op in zip(file_names, ops)]

    active_count = len(states)

    while active_count > 0:
        processed_in_cycle = False
        for state in states:
            if not state['active']:
                continue

            try:
                row = next(state['reader'])
                processed_in_cycle = True
                if len(row) != 7:
                   print(f"Warning: Skipping malformed row in {state['file'].name}: {row}", file=sys.stderr)
                   continue

                src_ip_str, dst_ip_str, src_port_str, dst_port_str, pkt_cnt_str, byte_cnt_str, epoch_id_str = row

                try:
                    src_l4_port = int(src_port_str)
                    dst_l4_port = int(dst_port_str)
                    packet_count = int(pkt_cnt_str)
                    byte_count = int(byte_cnt_str)
                    epoch_id = int(epoch_id_str)
                except ValueError as e:
                    print(f"Warning: Skipping row with invalid integer in {state['file'].name}: {e} in row {row}", file=sys.stderr)
                    continue


                p: TupleType = {
                    "ipv4.src": get_ip_or_zero(src_ip_str),
                    "ipv4.dst": get_ip_or_zero(dst_ip_str),
                    "l4.sport": IntResult(src_l4_port),
                    "l4.dport": IntResult(dst_l4_port),
                    "packet_count": IntResult(packet_count),
                    "byte_count": IntResult(byte_count),
                    epoch_id_key: IntResult(epoch_id),
                }

                state['tup_count'] += 1

                # Handle epoch change
                if epoch_id > state['eid']:
                    while epoch_id > state['eid']:
                        reset_tuple = {
                            "tuples": IntResult(state['tup_count'] - 1), # OCaml increments *before* call
                            epoch_id_key: IntResult(state['eid'])
                        }
                        state['operator'].reset(reset_tuple)
                        state['tup_count'] = 1 # Reset count for the new epoch (or 0?) OCaml resets to 0 *after* call
                        state['eid'] += 1
                    state['tup_count'] = 0 # Correct reset to 0 before processing current tuple

                current_tuple = {**p, "tuples": IntResult(state['tup_count'])}
                state['operator'].next(current_tuple)

            except StopIteration: # End of this file
                # Final reset for the last epoch seen + 1
                reset_tuple = {
                    "tuples": IntResult(state['tup_count']),
                     epoch_id_key: IntResult(state['eid'] + 1) # OCaml uses eid + 1
                }
                state['operator'].reset(reset_tuple)
                state['file'].close()
                state['active'] = False
                active_count -= 1
            except Exception as e:
                print(f"Error processing file {state['file'].name}: {e}", file=sys.stderr)
                # Decide whether to stop or continue with other files
                state['file'].close()
                state['active'] = False
                active_count -= 1
                # raise # Optional: re-raise to stop everything

        # If no file yielded data in a cycle, break (all EOF or inactive)
        if not processed_in_cycle and active_count > 0:
             # This condition might be needed if files become inactive due to errors
             print("Warning: No active files processed in a cycle, but active_count > 0. Exiting loop.", file=sys.stderr)
             break


    print("Done reading CSVs.")


def meta_meter(name: str, out_stream: TextIO, next_op: Operator,
               static_field: Optional[str] = None) -> Operator:
    """
    Tracks how many tuples processed per epoch and logs it.
    """
    state = {'epoch_count': 0, 'tups_count': 0}

    def next_func(tup: TupleType) -> None:
        state['tups_count'] += 1
        next_op.next(tup)

    def reset_func(tup: TupleType) -> None:
        static_val = static_field if static_field is not None else ""
        out_stream.write(f"{state['epoch_count']},{name},{state['tups_count']},{static_val}\n")
        state['tups_count'] = 0
        state['epoch_count'] += 1
        next_op.reset(tup)

    return Operator(next_func=next_func, reset_func=reset_func)


def epoch(epoch_width: float, key_out: str, next_op: Operator) -> Operator:
    """
    Adds epoch id based on time, resets next_op every epoch_width seconds.
    Requires a 'time' field (FloatResult) in incoming tuples.
    """
    state = {'epoch_boundary': 0.0, 'eid': 0}

    def next_func(tup: TupleType) -> None:
        try:
            time = float_of_op_result(tup["time"])
        except (KeyError, TypeError) as e:
             raise ValueError(f"Epoch operator requires a valid float 'time' field: {e}")

        if state['epoch_boundary'] == 0.0: # First tuple, initialize boundary
            state['epoch_boundary'] = time + epoch_width
        elif time >= state['epoch_boundary']:
            # Time crossed one or more boundaries
            while time >= state['epoch_boundary']:
                reset_tuple = {key_out: IntResult(state['eid'])}
                next_op.reset(reset_tuple)
                state['epoch_boundary'] += epoch_width
                state['eid'] += 1

        # Add epoch ID to the current tuple and pass downstream
        out_tup = {**tup, key_out: IntResult(state['eid'])}
        next_op.next(out_tup)

    def reset_func(tup: TupleType) -> None:
        # Reset triggered externally, pass reset downstream with last known eid
        reset_tuple = {**tup, key_out: IntResult(state['eid'])}
        next_op.reset(reset_tuple)
        # Reset internal state for next stream segment
        state['epoch_boundary'] = 0.0
        state['eid'] = 0

    return Operator(next_func=next_func, reset_func=reset_func)

def filter_op(f: FilterFunc, next_op: Operator) -> Operator:
    """
    Creates an operator that passes tuples through only if f(tuple) is true.
    """
    def next_func(tup: TupleType) -> None:
        if f(tup):
            next_op.next(tup)

    def reset_func(tup: TupleType) -> None:
        next_op.reset(tup)

    return Operator(next_func=next_func, reset_func=reset_func)

# (filter utility)
def key_geq_int(key: str, threshold: int) -> FilterFunc:
    """Returns a filter function checking if tuple[key] >= threshold."""
    def func(tup: TupleType) -> bool:
        try:
            return int_of_op_result(tup[key]) >= threshold
        except (KeyError, TypeError):
             # Original OCaml raises Failure. Decide if error or False is desired.
             # Let's raise an error for clarity, matching OCaml's likely behavior.
             raise ValueError(f"Could not compare key '{key}' as int >= {threshold}")
             # Or return False:
             # return False
    return func

# (filter utility - direct Python lookup is preferred)
def get_mapped_int(key: str, tup: TupleType) -> int:
    """Looks up key and returns its int value. Raises error if not found/not int."""
    return lookup_int(key, tup) # Use the existing lookup function

def get_mapped_float(key: str, tup: TupleType) -> float:
    """Looks up key and returns its float value. Raises error if not found/not float."""
    return lookup_float(key, tup) # Use the existing lookup function


def map_op(f: MapFunc, next_op: Operator) -> Operator:
    """
    Operator which applies the given function to transform tuples.
    """
    def next_func(tup: TupleType) -> None:
        next_op.next(f(tup))

    def reset_func(tup: TupleType) -> None:
        next_op.reset(tup) # Passes reset unchanged

    return Operator(next_func=next_func, reset_func=reset_func)


# --- Groupby, Distinct, Split, Join ---

# Note: OCaml's Map/Hashtbl use structural equality for tuple keys.
# Python dicts require keys to be hashable. Dictionaries themselves are not
# directly hashable. We need to convert the TupleType (dict) grouping key
# into a hashable representation, e.g., a sorted tuple of key-value pairs.

def _make_hashable(tup_key: TupleType) -> tuple:
    """Converts a TupleType dict into a hashable sorted tuple of items."""
    # Ensure consistent ordering for hashing/equality
    return tuple(sorted(tup_key.items()))


def groupby(grouping_func: GroupingFunc,
            reduce_func: ReductionFunc,
            out_key: str,
            next_op: Operator) -> Operator:
    """
    Groups tuples based on grouping_func, accumulates using reduce_func.
    Outputs aggregated results on reset.
    """
    h_tbl: Dict[tuple, OpResult] = {} # Use hashable tuple keys

    def next_func(tup: TupleType) -> None:
        grouping_key_dict = grouping_func(tup)
        grouping_key_hashable = _make_hashable(grouping_key_dict)

        current_val = h_tbl.get(grouping_key_hashable, EmptyResult())
        new_val = reduce_func(current_val, tup)
        h_tbl[grouping_key_hashable] = new_val

    def reset_func(reset_tup: TupleType) -> None:
        for grouping_key_hashable, final_val in h_tbl.items():
            # Reconstruct the original dict key (may not be perfectly efficient)
            grouping_key_dict = dict(grouping_key_hashable)

            # Merge reset_tup, grouping_key_dict, and the result
            # Python's dict update/merge: later keys overwrite earlier ones.
            # OCaml's union function needs specific behavior: `fun _ a _ -> Some a` means keep the value from the first dict `tup` (reset_tup)
            # Let's try to replicate: reset_tup has priority, then grouping_key
            unioned_tup = {**grouping_key_dict, **reset_tup} # grouping first, then reset overwrites
            unioned_tup[out_key] = final_val
            next_op.next(unioned_tup)

        next_op.reset(reset_tup) # Pass reset downstream
        h_tbl.clear()           # Clear state for next epoch

    return Operator(next_func=next_func, reset_func=reset_func)


# (groupby utility : grouping_func)
def filter_groups(incl_keys: List[str]) -> GroupingFunc:
    """Returns a grouping function that selects only specified keys."""
    def func(tup: TupleType) -> TupleType:
        return {key: val for key, val in tup.items() if key in incl_keys}
    return func

# (groupby utility : grouping_func)
def single_group(_: TupleType) -> TupleType:
    """Grouping function that maps all tuples to a single empty group."""
    return {} # Empty dict represents the single group key

# (groupby utility : reduction_func)
def counter(val_: OpResult, _: TupleType) -> OpResult:
    """Reduction function to count tuples."""
    if isinstance(val_, EmptyResult):
        return IntResult(1)
    elif isinstance(val_, IntResult):
        return IntResult(val_.value + 1)
    else:
        # Should not happen if used correctly, but mirrors OCaml's fallback
        print(f"Warning: Counter received non-Int/Empty value: {val_}", file=sys.stderr)
        return val_ # Return unchanged

# (groupby utility : reduction_func)
def sum_ints(search_key: str) -> ReductionFunc:
    """Reduction function to sum Int values of a given field."""
    def func(init_val: OpResult, tup: TupleType) -> OpResult:
        current_sum = 0
        if isinstance(init_val, EmptyResult):
            current_sum = 0
        elif isinstance(init_val, IntResult):
            current_sum = init_val.value
        else:
             print(f"Warning: sum_ints received non-Int/Empty initial value: {init_val}", file=sys.stderr)
             return init_val # Propagate error state

        try:
            term = int_of_op_result(tup[search_key])
            return IntResult(current_sum + term)
        except KeyError:
            # OCaml raises Failure. Let's raise ValueError.
             raise ValueError(f"'sum_ints' function failed to find key '{search_key}'")
        except TypeError:
            raise TypeError(f"'sum_ints' function expected integer value for key '{search_key}', got {type(tup.get(search_key))}")
            
    # OCaml version takes init_val first, Python needs to return a function that takes it
    # Let's adjust the signature to match ReductionFunc directly
    def reduction_wrapper(val_: OpResult, tup: TupleType) -> OpResult:
         return func(val_, tup) # Call the inner logic
    return reduction_wrapper


def distinct(grouping_func: GroupingFunc, next_op: Operator) -> Operator:
    """
    Outputs distinct tuples based on the grouping_func key each epoch.
    """
    h_tbl: Set[tuple] = set() # Store hashable keys of seen groups

    def next_func(tup: TupleType) -> None:
        grouping_key_dict = grouping_func(tup)
        grouping_key_hashable = _make_hashable(grouping_key_dict)
        h_tbl.add(grouping_key_hashable) # Add the key to the set

    def reset_func(reset_tup: TupleType) -> None:
        for grouping_key_hashable in h_tbl:
            # Reconstruct the original dict key
            key_dict = dict(grouping_key_hashable)
            # Merge reset tuple and key tuple, priority to reset_tup
            merged_tup = {**key_dict, **reset_tup}
            next_op.next(merged_tup)

        next_op.reset(reset_tup)
        h_tbl.clear()

    return Operator(next_func=next_func, reset_func=reset_func)


def split(left_op: Operator, right_op: Operator) -> Operator:
    """
    Splits the stream, sending next and reset calls to two downstream operators.
    """
    def next_func(tup: TupleType) -> None:
        left_op.next(tup)
        right_op.next(tup)

    def reset_func(tup: TupleType) -> None:
        left_op.reset(tup)
        right_op.reset(tup)

    return Operator(next_func=next_func, reset_func=reset_func)


def join(left_extractor: KeyExtractor,
         right_extractor: KeyExtractor,
         next_op: Operator,
         eid_key: str = "eid") -> Tuple[Operator, Operator]:
    """
    Joins two streams based on keys extracted by functions. Requires epoch IDs.
    Returns a tuple of two operators, one for the left stream, one for the right.
    """
    h_tbl1: Dict[tuple, TupleType] = {} # Stores values from left stream, keyed by hashable key + eid
    h_tbl2: Dict[tuple, TupleType] = {} # Stores values from right stream
    # Use lists for mutable integer refs like OCaml's ref
    left_curr_epoch = [0]
    right_curr_epoch = [0]

    # Helper function to create one side of the join logic
    def handle_join_side(
        curr_h_tbl: Dict[tuple, TupleType],
        other_h_tbl: Dict[tuple, TupleType],
        curr_epoch_ref: List[int],
        other_epoch_ref: List[int],
        extractor: KeyExtractor
    ) -> Operator:

        def next_func(tup: TupleType) -> None:
            try:
                key_dict, vals_dict = extractor(tup)
                curr_epoch = get_mapped_int(eid_key, tup)
            except Exception as e:
                print(f"Error in join extractor or getting epoch: {e}", file=sys.stderr)
                return # Skip tuple on error

            # Advance current epoch marker if needed, potentially triggering resets
            while curr_epoch > curr_epoch_ref[0]:
                 # Only reset if the *other* stream has also passed this epoch boundary
                if other_epoch_ref[0] > curr_epoch_ref[0]:
                    next_op.reset({eid_key: IntResult(curr_epoch_ref[0])})
                curr_epoch_ref[0] += 1

            # Create the actual key used for matching (includes epoch)
            join_key_dict = {**key_dict, eid_key: IntResult(curr_epoch)}
            join_key_hashable = _make_hashable(join_key_dict)

            # Look for a match in the *other* table
            match = other_h_tbl.pop(join_key_hashable, None) # Pop removes if found

            if match is not None:
                # Found match: merge keys, values, and matched values, then output
                # Priority: join_key > incoming vals > matched vals
                # OCaml union `use_left = fun _ a _ -> Some a` means keep value from first dict
                # Let's try: incoming tuple's extractor results first, then matched values
                merged_tup = {**match, **vals_dict, **join_key_dict}
                next_op.next(merged_tup)
            else:
                # No match: store own values in own table, keyed by join key
                curr_h_tbl[join_key_hashable] = vals_dict

        def reset_func(tup: TupleType) -> None:
             try:
                curr_epoch = get_mapped_int(eid_key, tup)
             except (KeyError, TypeError):
                 # If reset tuple doesn't have eid, maybe use current epoch marker?
                 # OCaml seems to expect it. Let's assume it's there.
                 print(f"Warning: join reset tuple missing '{eid_key}'", file=sys.stderr)
                 curr_epoch = curr_epoch_ref[0] # Fallback?

             # Advance epoch marker based on reset signal
             while curr_epoch > curr_epoch_ref[0]:
                 if other_epoch_ref[0] > curr_epoch_ref[0]:
                     next_op.reset({eid_key: IntResult(curr_epoch_ref[0])})
                 curr_epoch_ref[0] += 1
             # Note: OCaml clears tables in groupby/distinct on reset. Join doesn't explicitly.
             # Tuples are removed on match, but unmatched tuples from past epochs might remain.
             # This might differ from OCaml if not handled by epoch advancement logic.
             # A manual cleanup based on epoch could be added if needed.


        return Operator(next_func=next_func, reset_func=reset_func)

    # Create the left and right operators
    left_op = handle_join_side(h_tbl1, h_tbl2, left_curr_epoch, right_curr_epoch, left_extractor)
    right_op = handle_join_side(h_tbl2, h_tbl1, right_curr_epoch, left_curr_epoch, right_extractor)

    return left_op, right_op


# (join utility)
def rename_filtered_keys(renamings_pairs: List[Tuple[str, str]]) -> Callable[[TupleType], TupleType]:
    """
    Returns function that filters and renames keys in a tuple based on pairs.
    """
    def func(in_tup: TupleType) -> TupleType:
        new_tup = {}
        for old_key, new_key in renamings_pairs:
            if old_key in in_tup:
                new_tup[new_key] = in_tup[old_key]
        return new_tup
    return func


# --- Main Execution Part (was headerdump.ml) ---

# Define the specific query pipelines (Sonata queries, etc.)
# Note: OCaml's @=> operator is right-associative function application.
# In Python, we write f(g(h(x))) instead of (f @=> g @=> h) x.

def ident(next_op: Operator) -> Operator:
    """Removes ethernet addresses."""
    def map_func(tup: TupleType) -> TupleType:
        return {k: v for k, v in tup.items() if k not in ["eth.src", "eth.dst"]}
    # Equivalent to: map_op(map_func) @=> next_op
    return map_op(map_func, next_op)

def count_pkts(next_op: Operator) -> Operator:
    """Counts total packets per 1-second epoch."""
    # (epoch 1.0 "eid") @=> (groupby single_group counter "pkts") @=> next_op
    op1 = groupby(single_group, counter, "pkts", next_op)
    op0 = epoch(1.0, "eid", op1)
    return op0

def pkts_per_src_dst(next_op: Operator) -> Operator:
    """Counts packets per source/destination IP pair per 1-second epoch."""
    group_func = filter_groups(["ipv4.src", "ipv4.dst"])
    # (epoch 1.0 "eid") @=> (groupby group_func counter "pkts") @=> next_op
    op1 = groupby(group_func, counter, "pkts", next_op)
    op0 = epoch(1.0, "eid", op1)
    return op0

def distinct_srcs(next_op: Operator) -> Operator:
    """Counts distinct source IPs per 1-second epoch."""
    group_distinct_func = filter_groups(["ipv4.src"])
    # (epoch 1.0 "eid")
    # @=> (distinct group_distinct_func)
    # @=> (groupby single_group counter "srcs")
    # @=> next_op
    op2 = groupby(single_group, counter, "srcs", next_op)
    op1 = distinct(group_distinct_func, op2)
    op0 = epoch(1.0, "eid", op1)
    return op0


# Sonata 1: TCP New Connections DDoS
def tcp_new_cons(next_op: Operator) -> Operator:
    threshold = 40
    filter_syn_func: FilterFunc = lambda tup: (
        get_mapped_int("ipv4.proto", tup) == 6 and
        get_mapped_int("l4.flags", tup) == 2 # SYN flag
    )
    group_dst_func = filter_groups(["ipv4.dst"])
    filter_threshold_func = key_geq_int("cons", threshold)

    # (epoch 1.0 "eid")
    # @=> (filter filter_syn_func)
    # @=> (groupby group_dst_func counter "cons")
    # @=> (filter filter_threshold_func)
    # @=> next_op
    op3 = filter_op(filter_threshold_func, next_op)
    op2 = groupby(group_dst_func, counter, "cons", op3)
    op1 = filter_op(filter_syn_func, op2)
    op0 = epoch(1.0, "eid", op1)
    return op0


# Sonata 2: SSH Brute Force
def ssh_brute_force(next_op: Operator) -> Operator:
    threshold = 40
    filter_ssh_func: FilterFunc = lambda tup: (
        get_mapped_int("ipv4.proto", tup) == 6 and
        get_mapped_int("l4.dport", tup) == 22
    )
    distinct_group_func = filter_groups(["ipv4.src", "ipv4.dst", "ipv4.len"]) # Distinct src,dst,len combo
    groupby_group_func = filter_groups(["ipv4.dst", "ipv4.len"]) # Group by dst,len
    filter_threshold_func = key_geq_int("srcs", threshold) # Check count of distinct sources per group

    # (epoch 1.0 "eid")
    # @=> (filter filter_ssh_func)
    # @=> (distinct distinct_group_func)
    # @=> (groupby groupby_group_func counter "srcs")
    # @=> (filter filter_threshold_func)
    # @=> next_op
    op4 = filter_op(filter_threshold_func, next_op)
    op3 = groupby(groupby_group_func, counter, "srcs", op4)
    op2 = distinct(distinct_group_func, op3)
    op1 = filter_op(filter_ssh_func, op2)
    op0 = epoch(1.0, "eid", op1)
    return op0

# Sonata 3: Super Spreader
def super_spreader(next_op: Operator) -> Operator:
    threshold = 40
    distinct_group_func = filter_groups(["ipv4.src", "ipv4.dst"])
    groupby_group_func = filter_groups(["ipv4.src"])
    filter_threshold_func = key_geq_int("dsts", threshold)

    # (epoch 1.0 "eid")
    # @=> (distinct distinct_group_func)
    # @=> (groupby groupby_group_func counter "dsts")
    # @=> (filter filter_threshold_func)
    # @=> next_op
    op3 = filter_op(filter_threshold_func, next_op)
    op2 = groupby(groupby_group_func, counter, "dsts", op3)
    op1 = distinct(distinct_group_func, op2)
    op0 = epoch(1.0, "eid", op1)
    return op0

# Sonata 4: Port Scan
def port_scan(next_op: Operator) -> Operator:
    threshold = 40
    distinct_group_func = filter_groups(["ipv4.src", "l4.dport"])
    groupby_group_func = filter_groups(["ipv4.src"])
    filter_threshold_func = key_geq_int("ports", threshold)

    # (epoch 1.0 "eid")
    # @=> (distinct distinct_group_func)
    # @=> (groupby groupby_group_func counter "ports")
    # @=> (filter filter_threshold_func)
    # @=> next_op
    op3 = filter_op(filter_threshold_func, next_op)
    op2 = groupby(groupby_group_func, counter, "ports", op3)
    op1 = distinct(distinct_group_func, op2)
    op0 = epoch(1.0, "eid", op1)
    return op0

# Sonata 5: DDoS (Distributed Denial of Service)
def ddos(next_op: Operator) -> Operator:
    threshold = 45
    distinct_group_func = filter_groups(["ipv4.src", "ipv4.dst"])
    groupby_group_func = filter_groups(["ipv4.dst"])
    filter_threshold_func = key_geq_int("srcs", threshold)

    # (epoch 1.0 "eid")
    # @=> (distinct distinct_group_func)
    # @=> (groupby groupby_group_func counter "srcs")
    # @=> (filter filter_threshold_func)
    # @=> next_op
    op3 = filter_op(filter_threshold_func, next_op)
    op2 = groupby(groupby_group_func, counter, "srcs", op3)
    op1 = distinct(distinct_group_func, op2)
    op0 = epoch(1.0, "eid", op1)
    return op0


# Sonata 6: SYN Flood (Sonata semantic)
def syn_flood_sonata(next_op: Operator) -> List[Operator]:
    threshold = 3
    epoch_dur = 1.0

    # --- Define the three input branches ---
    def syns_branch(op_after_syns: Operator) -> Operator:
        filter_func = lambda tup: (get_mapped_int("ipv4.proto", tup) == 6 and get_mapped_int("l4.flags", tup) == 2) # SYN
        group_func = filter_groups(["ipv4.dst"])
        op1 = groupby(group_func, counter, "syns", op_after_syns)
        op0 = filter_op(filter_func, op1)
        return epoch(epoch_dur, "eid", op0)

    def synacks_branch(op_after_synacks: Operator) -> Operator:
        filter_func = lambda tup: (get_mapped_int("ipv4.proto", tup) == 6 and get_mapped_int("l4.flags", tup) == 18) # SYN+ACK
        group_func = filter_groups(["ipv4.src"]) # Group by source for SYN+ACK
        op1 = groupby(group_func, counter, "synacks", op_after_synacks)
        op0 = filter_op(filter_func, op1)
        return epoch(epoch_dur, "eid", op0)

    def acks_branch(op_after_acks: Operator) -> Operator:
        filter_func = lambda tup: (get_mapped_int("ipv4.proto", tup) == 6 and get_mapped_int("l4.flags", tup) == 16) # ACK
        group_func = filter_groups(["ipv4.dst"]) # Group by destination for ACK
        op1 = groupby(group_func, counter, "acks", op_after_acks)
        op0 = filter_op(filter_func, op1)
        return epoch(epoch_dur, "eid", op0)

    # --- Define the join operations ---
    # Post-join 1: Calculate difference and filter
    map_diff_func: MapFunc = lambda tup: {
        **tup,
        "syns+synacks-acks": IntResult(get_mapped_int("syns+synacks", tup) - get_mapped_int("acks", tup))
    }
    filter_diff_func = key_geq_int("syns+synacks-acks", threshold)
    op_after_join1 = filter_op(filter_diff_func, next_op)
    op_map_diff = map_op(map_diff_func, op_after_join1)

    # Join 1: Join (SYN+SYNACK results) with ACK results
    left_extractor1: KeyExtractor = lambda tup: (filter_groups(["host"])(tup), filter_groups(["syns+synacks"])(tup))
    right_extractor1: KeyExtractor = lambda tup: (rename_filtered_keys([("ipv4.dst", "host")])(tup), filter_groups(["acks"])(tup))
    join_op1_left, join_op1_right = join(left_extractor1, right_extractor1, op_map_diff) # Output goes to map_diff

    # Post-join 2: Calculate SYN + SYNACK sum
    map_sum_func: MapFunc = lambda tup: {
        **tup,
        "syns+synacks": IntResult(get_mapped_int("syns", tup) + get_mapped_int("synacks", tup))
    }
    op_after_join2 = map_op(map_sum_func, join_op1_left) # Output goes to left input of join_op1

    # Join 2: Join SYN results with SYNACK results
    left_extractor2: KeyExtractor = lambda tup: (rename_filtered_keys([("ipv4.dst", "host")])(tup), filter_groups(["syns"])(tup))
    right_extractor2: KeyExtractor = lambda tup: (rename_filtered_keys([("ipv4.src", "host")])(tup), filter_groups(["synacks"])(tup))
    join_op2_left, join_op2_right = join(left_extractor2, right_extractor2, op_after_join2) # Output goes to map_sum

    # --- Connect the branches to the joins ---
    # The list returned contains the entry points for the initial streams
    return [
        syns_branch(join_op2_left),      # syns stream feeds left side of join 2
        synacks_branch(join_op2_right),  # synacks stream feeds right side of join 2
        acks_branch(join_op1_right)      # acks stream feeds right side of join 1
    ]

# Sonata 7: Completed Flows Anomaly
def completed_flows(next_op: Operator) -> List[Operator]:
    threshold = 1 # At least 1 more SYN than FIN
    epoch_dur = 30.0

    def syns_branch(op_after_syns: Operator) -> Operator:
        filter_func = lambda tup: (get_mapped_int("ipv4.proto", tup) == 6 and get_mapped_int("l4.flags", tup) == 2) # SYN
        group_func = filter_groups(["ipv4.dst"])
        op1 = groupby(group_func, counter, "syns", op_after_syns)
        op0 = filter_op(filter_func, op1)
        return epoch(epoch_dur, "eid", op0)

    def fins_branch(op_after_fins: Operator) -> Operator:
        filter_func = lambda tup: (get_mapped_int("ipv4.proto", tup) == 6 and (get_mapped_int("l4.flags", tup) & 1) == 1) # FIN flag is set
        group_func = filter_groups(["ipv4.src"]) # Group FINs by source
        op1 = groupby(group_func, counter, "fins", op_after_fins)
        op0 = filter_op(filter_func, op1)
        return epoch(epoch_dur, "eid", op0)

    map_diff_func: MapFunc = lambda tup: {
        **tup,
        "diff": IntResult(get_mapped_int("syns", tup) - get_mapped_int("fins", tup))
    }
    filter_diff_func = key_geq_int("diff", threshold)

    op_after_join = filter_op(filter_diff_func, next_op)
    op_map_diff = map_op(map_diff_func, op_after_join)

    # Join SYN results (keyed by dst renamed to host) with FIN results (keyed by src renamed to host)
    left_extractor: KeyExtractor = lambda tup: (rename_filtered_keys([("ipv4.dst", "host")])(tup), filter_groups(["syns"])(tup))
    right_extractor: KeyExtractor = lambda tup: (rename_filtered_keys([("ipv4.src", "host")])(tup), filter_groups(["fins"])(tup))
    join_op_left, join_op_right = join(left_extractor, right_extractor, op_map_diff)

    return [
        syns_branch(join_op_left),
        fins_branch(join_op_right)
    ]


# Sonata 8: Slowloris Attack
def slowloris(next_op: Operator) -> List[Operator]:
    t1 = 5    # Min connections per dest
    t2 = 500  # Min bytes per dest
    t3 = 90   # Max bytes per connection allowed
    epoch_dur = 1.0

    # Branch 1: Count distinct connections (src, dst, sport) per destination
    def n_conns_branch(op_after_conns: Operator) -> Operator:
        filter_tcp = lambda tup: get_mapped_int("ipv4.proto", tup) == 6
        distinct_conn_func = filter_groups(["ipv4.src", "ipv4.dst", "l4.sport"])
        group_dst_func = filter_groups(["ipv4.dst"])
        filter_min_conns = key_geq_int("n_conns", t1)

        op3 = filter_op(filter_min_conns, op_after_conns)
        op2 = groupby(group_dst_func, counter, "n_conns", op3)
        op1 = distinct(distinct_conn_func, op2)
        op0 = filter_op(filter_tcp, op1)
        return epoch(epoch_dur, "eid", op0)

    # Branch 2: Sum bytes per destination
    def n_bytes_branch(op_after_bytes: Operator) -> Operator:
        filter_tcp = lambda tup: get_mapped_int("ipv4.proto", tup) == 6
        group_dst_func = filter_groups(["ipv4.dst"])
        sum_bytes_func = sum_ints("ipv4.len") # Use the sum_ints reduction helper
        filter_min_bytes = key_geq_int("n_bytes", t2)

        op2 = filter_op(filter_min_bytes, op_after_bytes)
        op1 = groupby(group_dst_func, sum_bytes_func, "n_bytes", op2)
        op0 = filter_op(filter_tcp, op1)
        return epoch(epoch_dur, "eid", op0)

    # Post-join: Calculate bytes/connection and filter
    def map_avg_func(tup: TupleType) -> TupleType:
        n_bytes = get_mapped_int("n_bytes", tup)
        n_conns = get_mapped_int("n_conns", tup)
        # Avoid division by zero, though n_conns should be >= t1 (5) here
        avg = n_bytes // n_conns if n_conns > 0 else 0
        return {**tup, "bytes_per_conn": IntResult(avg)}

    # Filter: bytes_per_conn <= t3
    filter_max_avg = lambda tup: get_mapped_int("bytes_per_conn", tup) <= t3

    op_after_join = filter_op(filter_max_avg, next_op)
    op_map_avg = map_op(map_avg_func, op_after_join)

    # Join the two branches on destination IP
    left_extractor: KeyExtractor = lambda tup: (filter_groups(["ipv4.dst"])(tup), filter_groups(["n_conns"])(tup))
    right_extractor: KeyExtractor = lambda tup: (filter_groups(["ipv4.dst"])(tup), filter_groups(["n_bytes"])(tup))
    join_op_left, join_op_right = join(left_extractor, right_extractor, op_map_avg)

    return [
        n_conns_branch(join_op_left),
        n_bytes_branch(join_op_right)
    ]

# Example Test Join
def join_test(next_op: Operator) -> List[Operator]:
    epoch_dur = 1.0

    def syns_branch(op: Operator) -> Operator:
        f = lambda tup: (get_mapped_int("ipv4.proto", tup) == 6 and get_mapped_int("l4.flags", tup) == 2)
        op1 = filter_op(f, op)
        return epoch(epoch_dur, "eid", op1)

    def synacks_branch(op: Operator) -> Operator:
        f = lambda tup: (get_mapped_int("ipv4.proto", tup) == 6 and get_mapped_int("l4.flags", tup) == 18)
        op1 = filter_op(f, op)
        return epoch(epoch_dur, "eid", op1)

    # Join SYN (key=src as host, value=dst as remote) with SYNACK (key=dst as host, value=time)
    left_extractor: KeyExtractor = lambda tup: (rename_filtered_keys([("ipv4.src", "host")])(tup), rename_filtered_keys([("ipv4.dst", "remote")])(tup))
    right_extractor: KeyExtractor = lambda tup: (rename_filtered_keys([("ipv4.dst", "host")])(tup), filter_groups(["time"])(tup))

    op1, op2 = join(left_extractor, right_extractor, next_op)

    return [syns_branch(op1), synacks_branch(op2)]


# Other test queries
def q3(next_op: Operator) -> Operator:
    """Distinct source-destination pairs over 100s epochs."""
    op1 = distinct(filter_groups(["ipv4.src", "ipv4.dst"]), next_op)
    return epoch(100.0, "eid", op1)

def q4(next_op: Operator) -> Operator:
    """Total packets per destination over 10000s epochs."""
    op1 = groupby(filter_groups(["ipv4.dst"]), counter, "pkts", next_op)
    return epoch(10000.0, "eid", op1)


# --- Main Execution ---

def create_dummy_data(count: int) -> List[TupleType]:
    """Generates a list of dummy packet tuples."""
    data = []
    base_time = 0.0
    for i in range(count):
        tup: TupleType = {
            "time": FloatResult(base_time + float(i) * 0.01), # Increment time
            "eth.src": MACResult(bytes.fromhex("001122334455")),
            "eth.dst": MACResult(bytes.fromhex("AABBCCDDEEFF")),
            "eth.ethertype": IntResult(0x0800), # IPv4
            "ipv4.hlen": IntResult(20),
            "ipv4.proto": IntResult(6), # TCP
            "ipv4.len": IntResult(60 + i % 20), # Vary length slightly
            "ipv4.src": IPv4Result(ipaddress.IPv4Address(f"192.168.1.{1 + i % 5}")), # Vary src IP
            "ipv4.dst": IPv4Result(ipaddress.IPv4Address(f"10.0.0.{1 + i % 3}")), # Vary dst IP
            "l4.sport": IntResult(10000 + i),
            "l4.dport": IntResult(22 if i % 10 == 0 else 80 if i % 10 == 1 else 443), # Vary dport
            # Vary flags: SYN, SYN+ACK, ACK, PSH+ACK, FIN+ACK
            "l4.flags": IntResult([2, 18, 16, 24, 17][i % 5]),
        }
        data.append(tup)
    return data


def run_queries(queries: List[Operator], data: List[TupleType]):
    """Runs a list of queries against the provided data."""
    print(f"Running {len(queries)} queries against {len(data)} tuples...")
    for tup in data:
        for query_op in queries:
            try:
                 query_op.next(tup)
            except Exception as e:
                 print(f"Error processing tuple in query: {e}\nTuple: {string_of_tuple(tup)}", file=sys.stderr)
                 # Decide whether to continue or stop on error

    # Signal end of stream by calling reset on all operators
    # Use a dummy tuple for reset, possibly containing the final epoch ID if applicable
    # Here, we use an empty tuple as the OCaml test does.
    print("Signalling end of stream (reset)...")
    reset_tup: TupleType = {}
    for query_op in queries:
         try:
            query_op.reset(reset_tup)
         except Exception as e:
            print(f"Error resetting query: {e}", file=sys.stderr)

if __name__ == "__main__":
    # --- Define the list of queries to run ---
    # Each query is constructed by composing operators, ending with a dump operator.

    # Example: Just dump the identified packets
    query1 = ident(dump_tuple_op(sys.stdout, show_reset=True))

    # Example: Count packets per epoch and dump as CSV
    query2 = count_pkts(dump_as_csv(sys.stdout, header=True, static_field=("query","count_pkts")))

    # Example: Run Sonata 3 (Super Spreader) and dump results
    query3 = super_spreader(dump_tuple_op(sys.stdout, show_reset=True))

    # Example: Run Sonata 6 (SYN Flood) - Requires multiple entry points
    # We need a way to handle queries that return multiple operators.
    # For now, let's focus on single-entry queries or test join separately.

    # Example: Run Join Test and dump results
    # query_join_test = join_test(dump_tuple_op(sys.stdout, show_reset=True))
    # Note: join_test returns a list of operators. Need to handle this.

    queries_to_run: List[Operator] = [
         # query1,
         # query2,
         query3,
    ]

    # Handle multi-operator queries (like joins) - Example Setup:
    # This part needs adjustment based on how you want to feed data to multi-stream queries.
    # For testing, we can create separate data streams or feed the same data to all inputs.
    # query_syn_flood_list = syn_flood_sonata(dump_tuple_op(sys.stdout, show_reset=True))


    # Generate some data
    dummy_data = create_dummy_data(100) # Generate 100 sample packets

    # Run the selected single-entry queries
    if queries_to_run:
       run_queries(queries_to_run, dummy_data)

    # --- How to run multi-entry queries (e.g., Sonata 6, 7, 8, join_test) ---
    # Option 1: Feed the same data to all entry points
    # print("\nRunning SYN Flood (Sonata 6)...")
    # syn_flood_ops = syn_flood_sonata(dump_tuple_op(sys.stdout, show_reset=True))
    # run_queries(syn_flood_ops, dummy_data)

    # Option 2: Prepare separate data streams if needed (more complex setup)
    # ...

    print("\nPython script finished.")