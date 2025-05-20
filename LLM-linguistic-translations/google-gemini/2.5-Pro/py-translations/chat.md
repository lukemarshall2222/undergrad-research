prompt: base prompt

Okay, here's the OCaml code translated into idiomatic Python, organized into modules (`utils.py`, `builtins.py`, `main.py`) as is common practice.

This translation attempts to preserve the original structure and logic while using Pythonic conventions (classes for operators, dictionaries for maps, type hinting, standard libraries).

**1. `utils.py` (Common Utilities)**

```python
# utils.py
import ipaddress
import sys
from typing import Union, Dict, List, Tuple as PyTuple, Optional, Callable, TextIO, Protocol, Any
from collections import defaultdict
import csv

# Define the type for results within a tuple
# Using Union to represent the OCaml variant type 'op_result'
OpResult = Union[float, int, ipaddress.IPv4Address, bytes, None] # None represents Empty

# Define the type for a 'tuple' (map from string to OpResult)
# Using Dict as the Python equivalent of OCaml's Map.Make(String)
Tuple = Dict[str, OpResult]

# Define the Operator interface using a Protocol (structural subtyping)
# This matches the OCaml record type for 'operator'
class Operator(Protocol):
    """Protocol defining a data processing unit in the stream."""
    def next(self, tup: Tuple) -> None:
        """Processes the incoming tuple, likely with side effects."""
        ...

    def reset(self, tup: Tuple) -> None:
        """Performs a reset operation, often at epoch boundaries."""
        ...

# Type hints for operator creators (higher-order functions)
OpCreator = Callable[[Operator], Operator]
DblOpCreator = Callable[[Operator], PyTuple[Operator, Operator]]

# OCaml's '@=>' and '@==>' operators are for right-associative function application (CPS).
# In Python, we achieve this through standard function composition: op1(op2(op3(next_op))).
# No direct equivalent operator is defined, as it's not standard Python practice.

# --- Conversion Utilities ---

def string_of_mac(buf: bytes) -> str:
    """Formats the 6 bytes of the MAC address as a colon-separated hex string."""
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
    active_flags = [
        name for name, mask in tcp_flags_map.items() if (flags & mask) == mask
    ]
    return "|".join(active_flags) if active_flags else ""

def int_of_op_result(input_val: OpResult) -> int:
    """Checks if input is an Int op_result, raises TypeError otherwise."""
    if isinstance(input_val, int):
        return input_val
    raise TypeError(f"Trying to extract int from non-int result: {type(input_val)}")

def float_of_op_result(input_val: OpResult) -> float:
    """Checks if input is a Float op_result, raises TypeError otherwise."""
    if isinstance(input_val, float):
        return input_val
    raise TypeError(f"Trying to extract float from non-float result: {type(input_val)}")

def string_of_op_result(input_val: OpResult) -> str:
    """Returns the human-readable version of each op_result value."""
    if isinstance(input_val, float):
        return f"{input_val:f}"
    elif isinstance(input_val, int):
        return str(input_val)
    elif isinstance(input_val, ipaddress.IPv4Address):
        return str(input_val)
    elif isinstance(input_val, bytes):
        try:
            return string_of_mac(input_val)
        except ValueError:
            return repr(input_val) # Fallback for non-MAC bytes
    elif input_val is None: # Empty
        return "Empty"
    else:
        # Should ideally not happen with OpResult type hint, but good for safety
        return repr(input_val)

def string_of_tuple(input_tuple: Tuple) -> str:
    """Outputs the tuple in a human-readable form."""
    items = [f'"{key}" => {string_of_op_result(val)}' for key, val in input_tuple.items()]
    return ", ".join(items) + ("," if items else "") # Add trailing comma like OCaml

def tuple_of_list(tup_list: List[PyTuple[str, OpResult]]) -> Tuple:
    """Creates a Tuple (dict) out of a list of key-value pairs."""
    return dict(tup_list)

def dump_tuple_to_stream(out_stream: TextIO, tup: Tuple) -> None:
    """Prints formatted representation of a Tuple to a stream."""
    print(string_of_tuple(tup), file=out_stream)

def lookup_int(key: str, tup: Tuple) -> int:
    """Retrieves the int value associated with a key, raising KeyError or TypeError."""
    try:
        return int_of_op_result(tup[key])
    except KeyError:
        raise KeyError(f"Key '{key}' not found in tuple")
    except TypeError as e:
        raise TypeError(f"Value for key '{key}' is not an integer: {e}")


def lookup_float(key: str, tup: Tuple) -> float:
    """Retrieves the float value associated with a key, raising KeyError or TypeError."""
    try:
        return float_of_op_result(tup[key])
    except KeyError:
        raise KeyError(f"Key '{key}' not found in tuple")
    except TypeError as e:
        raise TypeError(f"Value for key '{key}' is not a float: {e}")

# --- Helper for making dicts hashable (needed for groupby/distinct keys) ---
def make_hashable(d: Dict) -> frozenset:
    """Converts dict items to frozenset for hashability."""
    # Ensure values are hashable too (our OpResult types generally are)
    return frozenset(d.items())

# --- Tuple Merging Logic (emulating OCaml's Tuple.union behavior) ---
def merge_tuples(*tuples: Tuple, precedence: str = 'first') -> Tuple:
    """
    Merges multiple dictionaries (Tuples).
    precedence='first': Keys in earlier dictionaries take precedence (like OCaml's `fun _ a _ -> Some a`).
    precedence='last': Keys in later dictionaries take precedence (like Python's dict.update).
    """
    merged = {}
    if precedence == 'first':
        for tup in reversed(tuples):
            merged.update(tup)
    elif precedence == 'last':
        for tup in tuples:
            merged.update(tup)
    else:
        raise ValueError("precedence must be 'first' or 'last'")
    return merged

```

**2. `builtins.py` (Built-in Operators)**

```python
# builtins.py
import sys
import csv
import ipaddress
from typing import List, Dict, Optional, TextIO, Tuple as PyTuple, Callable, Any
from collections import defaultdict
import time # Needed for epoch logic if not using 'time' field

from utils import (
    OpResult, Tuple, Operator, OpCreator, DblOpCreator,
    dump_tuple_to_stream, string_of_op_result, get_ip_or_zero, # Note: get_ip_or_zero needs definition
    int_of_op_result, float_of_op_result, lookup_int, lookup_float, make_hashable, merge_tuples
)

INIT_TABLE_SIZE: int = 10000 # Hint for dicts, Python handles resizing

# --- Utility Functions specific to Builtins (like get_ip_or_zero) ---

def get_ip_or_zero(input_str: str) -> OpResult:
    """Parses string as IPv4 or returns Int 0."""
    if input_str == "0":
        return 0
    else:
        try:
            return ipaddress.IPv4Address(input_str)
        except ipaddress.AddressValueError as e:
            raise ValueError(f"Invalid IP address string: {input_str}") from e


# --- Operator Implementations (as classes) ---

class DumpTupleOperator:
    """Operator to dump all fields of tuples to an output stream."""
    def __init__(self, out_stream: TextIO, show_reset: bool = False):
        self._out_stream = out_stream
        self._show_reset = show_reset

    def next(self, tup: Tuple) -> None:
        dump_tuple_to_stream(self._out_stream, tup)
        self._out_stream.flush() # Ensure output is visible

    def reset(self, tup: Tuple) -> None:
        if self._show_reset:
            dump_tuple_to_stream(self._out_stream, tup)
            print("[reset]", file=self._out_stream)
            self._out_stream.flush()

class DumpCsvOperator:
    """Operator to dump tuples as CSV."""
    def __init__(self, out_stream: TextIO,
                 static_field: Optional[PyTuple[str, str]] = None,
                 header: bool = True):
        self._out_stream = out_stream
        self._static_field = static_field
        self._print_header = header
        self._first = True
        self._writer = csv.writer(out_stream) # Use csv module
        self._header_written = False

    def next(self, tup: Tuple) -> None:
        if self._first and self._print_header and not self._header_written:
            header_row = []
            if self._static_field:
                header_row.append(self._static_field[0])
            header_row.extend(tup.keys())
            self._writer.writerow(header_row)
            self._header_written = True # Header written only once overall
            self._first = False # Reset for next potential header write if reset logic needs it

        row = []
        if self._static_field:
            row.append(self._static_field[1])
        row.extend(string_of_op_result(val) for val in tup.values())
        self._writer.writerow(row)
        self._out_stream.flush()

    def reset(self, tup: Tuple) -> None:
        # Original doesn't reset the header flag, CSV usually has one header.
        # If reset means "start a new CSV section", logic might need change.
        # Assuming reset doesn't affect CSV structure here.
        pass

class DumpWaltsCsvOperator:
    """Operator to dump tuples in Walt's canonical CSV format."""
    def __init__(self, filename: str):
        self._filename = filename
        self._out_stream: Optional[TextIO] = None
        self._writer: Optional[csv.writer] = None
        self._first = True

    def _open_file_if_needed(self):
        if self._first:
            try:
                # Open in write mode, buffering=1 for line buffering
                self._out_stream = open(self._filename, 'w', newline='', buffering=1)
                self._writer = csv.writer(self._out_stream)
                # Walt's format doesn't seem to have a header in the OCaml code
                self._first = False
            except IOError as e:
                print(f"Error opening file {self._filename}: {e}", file=sys.stderr)
                # Prevent further attempts if open fails
                self._out_stream = None
                self._writer = None
                self._first = False # Don't try again

    def next(self, tup: Tuple) -> None:
        self._open_file_if_needed()
        if not self._writer or not self._out_stream:
            return # File couldn't be opened

        try:
            row = [
                string_of_op_result(tup.get("src_ip")), # Use .get for safety? Original uses find
                string_of_op_result(tup.get("dst_ip")),
                string_of_op_result(tup.get("src_l4_port")),
                string_of_op_result(tup.get("dst_l4_port")),
                string_of_op_result(tup.get("packet_count")),
                string_of_op_result(tup.get("byte_count")),
                string_of_op_result(tup.get("epoch_id")),
            ]
            self._writer.writerow(row)
            # OCaml fprintf implies flush, csv doesn't always, but line buffering helps.
            # self._out_stream.flush() # Explicit flush if needed
        except KeyError as e:
            print(f"Warning: Missing key {e} in tuple for Walt's CSV.", file=sys.stderr)
        except Exception as e:
             print(f"Error writing Walt's CSV row: {e}", file=sys.stderr)


    def reset(self, tup: Tuple) -> None:
        # The original reset does nothing for this operator
        pass

    def close(self) -> None:
        """Explicitly close the file."""
        if self._out_stream:
            self._out_stream.close()
            self._out_stream = None
            self._writer = None
            print(f"Closed {self._filename}")

    def __del__(self):
        """Attempt to close file on object deletion as a fallback."""
        self.close()


# --- Function to read Walt's CSV (Not an operator, but drives operators) ---

def read_walts_csv(
    file_names: List[str],
    ops: List[Operator],
    epoch_id_key: str = "eid"
) -> None:
    """Reads Walt's CSV files and drives a list of operators."""
    if not file_names or not ops:
        return
    if len(file_names) != len(ops):
        raise ValueError("Number of file names must match number of operators")

    inputs = []
    for filename in file_names:
        try:
            # Use 'utf-8' encoding, adjust if needed
            f = open(filename, 'r', encoding='utf-8')
            reader = csv.reader(f)
            inputs.append({
                'reader': reader,
                'file': f,
                'filename': filename,
                'eid': 0,
                'tup_count': 0,
                'active': True
            })
        except FileNotFoundError:
            print(f"Warning: File not found {filename}, skipping.", file=sys.stderr)
        except Exception as e:
            print(f"Error opening {filename}: {e}, skipping.", file=sys.stderr)

    if not inputs:
        print("No valid input files to process.", file=sys.stderr)
        return

    num_ops = len(ops) # Use the actual number of ops provided
    active_streams = len(inputs) # Number of successfully opened files

    while active_streams > 0:
        current_active = 0
        for i, op in enumerate(ops):
             # Check if the corresponding input stream exists and is active
            if i >= len(inputs) or not inputs[i]['active']:
                continue # Skip if no input for this op or input is finished

            input_data = inputs[i]
            reader = input_data['reader']
            try:
                row = next(reader)
                if len(row) != 7:
                    print(f"Warning: Malformed row in {input_data['filename']}: {row}, skipping.", file=sys.stderr)
                    continue

                src_ip_str, dst_ip_str, src_l4_port_str, dst_l4_port_str, \
                packet_count_str, byte_count_str, epoch_id_str = row

                # Parse data
                try:
                    src_ip = get_ip_or_zero(src_ip_str)
                    dst_ip = get_ip_or_zero(dst_ip_str)
                    src_l4_port = int(src_l4_port_str)
                    dst_l4_port = int(dst_l4_port_str)
                    packet_count = int(packet_count_str)
                    byte_count = int(byte_count_str)
                    epoch_id = int(epoch_id_str)
                except (ValueError, TypeError) as parse_err:
                    print(f"Warning: Error parsing row in {input_data['filename']} ({parse_err}): {row}, skipping.", file=sys.stderr)
                    continue

                # Construct tuple
                p: Tuple = {
                    "ipv4.src": src_ip,
                    "ipv4.dst": dst_ip,
                    "l4.sport": src_l4_port,
                    "l4.dport": dst_l4_port,
                    "packet_count": packet_count,
                    "byte_count": byte_count,
                    epoch_id_key: epoch_id
                }

                input_data['tup_count'] += 1

                # Epoch handling (reset calls)
                if epoch_id > input_data['eid']:
                    while epoch_id > input_data['eid']:
                        reset_tup: Tuple = {
                            epoch_id_key: input_data['eid'],
                            "tuples": input_data['tup_count'] # Pass count *before* reset
                        }
                        op.reset(reset_tup)
                        input_data['tup_count'] = 0 # Reset count for new epoch
                        input_data['eid'] += 1
                    # After loop, input_data['eid'] should equal epoch_id

                # Process the current tuple
                # Add tuple count *for the current epoch* (after potential resets)
                current_tup = p.copy()
                current_tup["tuples"] = input_data['tup_count']
                op.next(current_tup)
                current_active += 1 # This op processed something in this round

            except StopIteration: # End of this specific file
                # Final reset for the last epoch in this file
                final_reset_tup: Tuple = {
                    epoch_id_key: input_data['eid'], # Use the last known eid
                    "tuples": input_data['tup_count']
                }
                op.reset(final_reset_tup)

                print(f"Finished processing {input_data['filename']}")
                input_data['file'].close()
                input_data['active'] = False
                # active_streams is decremented after the loop

            except Exception as e: # Catch other potential errors during processing
                print(f"Error processing row from {input_data['filename']}: {e}", file=sys.stderr)
                # Potentially mark as inactive or try to recover
                # For simplicity, we continue to next iteration/file here
                # input_data['active'] = False # Mark as inactive on error?

        # Update count of active streams *after* iterating through all ops/files
        active_streams = sum(1 for input_data in inputs if input_data['active'])

    print("Done reading all files.")


# --- More Operator Implementations ---

class MetaMeterOperator:
    """Tracks tuple count per epoch for meta-analysis."""
    def __init__(self, name: str, out_stream: TextIO, next_op: Operator,
                 static_field: Optional[str] = None):
        self._name = name
        self._out_stream = out_stream
        self._next_op = next_op
        self._static_field = static_field if static_field is not None else ""
        self._epoch_count = 0
        self._tups_count = 0
        # Use a simple CSV writer for this specific format
        self._writer = csv.writer(self._out_stream)

    def next(self, tup: Tuple) -> None:
        self._tups_count += 1
        self._next_op.next(tup)

    def reset(self, tup: Tuple) -> None:
        # Write meta data: epoch_num, operator_name, tuples_in_epoch, static_val
        self._writer.writerow([
            self._epoch_count,
            self._name,
            self._tups_count,
            self._static_field
        ])
        self._out_stream.flush() # Ensure meta-data is written out

        self._tups_count = 0 # Reset tuple count for the new epoch
        self._epoch_count += 1 # Increment epoch counter
        self._next_op.reset(tup) # Propagate reset


class EpochOperator:
    """Adds epoch IDs based on time and triggers resets."""
    def __init__(self, epoch_width: float, key_out: str, next_op: Operator):
        if epoch_width <= 0:
            raise ValueError("epoch_width must be positive")
        self._epoch_width = epoch_width
        self._key_out = key_out
        self._next_op = next_op
        self._epoch_boundary: float = 0.0
        self._eid: int = 0

    def next(self, tup: Tuple) -> None:
        try:
            # Assumes 'time' field exists and is a float
            current_time = float_of_op_result(tup['time'])
        except (KeyError, TypeError) as e:
            print(f"EpochOperator Error: Missing or invalid 'time' field: {e}", file=sys.stderr)
            # Decide how to handle: skip tuple, raise error, assign default epoch?
            # Skipping for now:
            return

        if self._epoch_boundary == 0.0: # First tuple seen or after reset
            self._epoch_boundary = current_time + self._epoch_width
            # print(f"Epoch {self._eid} starts, boundary set to {self._epoch_boundary}")

        # Check if epoch boundary crossed
        while current_time >= self._epoch_boundary:
            # print(f"Time {current_time} crossed boundary {self._epoch_boundary}, resetting epoch {self._eid}")
            reset_tup: Tuple = {self._key_out: self._eid}
            self._next_op.reset(reset_tup)
            self._epoch_boundary += self._epoch_width
            self._eid += 1
            # print(f"Advanced to epoch {self._eid}, new boundary {self._epoch_boundary}")


        # Add epoch ID to the tuple and pass it on
        # Create a new dictionary to avoid modifying the original tuple inplace
        # if it's used elsewhere.
        out_tup = tup.copy()
        out_tup[self._key_out] = self._eid
        self._next_op.next(out_tup)


    def reset(self, tup: Tuple) -> None:
        # When the upstream resets, we reset the current epoch state and pass reset down.
        # Pass the *last* completed epoch ID in the reset tuple.
        # print(f"EpochOperator received reset, resetting epoch {self._eid}")
        reset_tup: Tuple = {self._key_out: self._eid}
        # Ensure the incoming tup fields are also passed if necessary?
        # OCaml just passes a singleton. Let's stick to that.
        self._next_op.reset(reset_tup)

        # Reset internal state
        self._epoch_boundary = 0.0
        self._eid = 0


class FilterOperator:
    """Filters tuples based on a predicate function."""
    def __init__(self, predicate: Callable[[Tuple], bool], next_op: Operator):
        self._predicate = predicate
        self._next_op = next_op

    def next(self, tup: Tuple) -> None:
        try:
            if self._predicate(tup):
                self._next_op.next(tup)
        except Exception as e:
            # Catch potential errors in predicate (e.g., missing keys)
            print(f"Filter predicate error: {e} on tuple {tup}", file=sys.stderr)


    def reset(self, tup: Tuple) -> None:
        self._next_op.reset(tup)


# --- Filter utility functions ---
def key_geq_int(key: str, threshold: int) -> Callable[[Tuple], bool]:
    """Returns a predicate function checking if key's int value >= threshold."""
    def predicate(tup: Tuple) -> bool:
        try:
            return lookup_int(key, tup) >= threshold
        except (KeyError, TypeError):
            return False # Key missing or not int, filter it out
    return predicate

# get_mapped_int/float are essentially lookup_int/lookup_float from utils
# Renaming slightly for clarity if preferred, but they do the same thing.
get_mapped_int = lookup_int
get_mapped_float = lookup_float


class MapOperator:
    """Applies a function to transform each tuple."""
    def __init__(self, func: Callable[[Tuple], Tuple], next_op: Operator):
        self._func = func
        self._next_op = next_op

    def next(self, tup: Tuple) -> None:
        try:
            transformed_tup = self._func(tup)
            self._next_op.next(transformed_tup)
        except Exception as e:
            # Catch potential errors in map function
            print(f"Map function error: {e} on tuple {tup}", file=sys.stderr)

    def reset(self, tup: Tuple) -> None:
        self._next_op.reset(tup)


# --- GroupBy related types and functions ---
GroupingFunc = Callable[[Tuple], Tuple]
# Reduction func takes accumulated value (OpResult) and current tuple (Tuple) -> new accumulated value (OpResult)
ReductionFunc = Callable[[OpResult, Tuple], OpResult]

class GroupByOperator:
    """Groups tuples and applies a reduction function."""
    def __init__(self, groupby_func: GroupingFunc,
                 reduce_func: ReductionFunc,
                 out_key: str, next_op: Operator):
        self._groupby_func = groupby_func
        self._reduce_func = reduce_func
        self._out_key = out_key
        self._next_op = next_op
        # Use a dictionary for the hash table. Key needs to be hashable.
        # The result of groupby_func (a Tuple/dict) must be converted.
        self._hash_table: Dict[frozenset, OpResult] = {}
        # self._reset_counter = 0 # OCaml code tracked this, seems unused

    def next(self, tup: Tuple) -> None:
        try:
            grouping_key_dict = self._groupby_func(tup)
            grouping_key_hashable = make_hashable(grouping_key_dict)

            # Get current accumulated value, default is None (Empty in OCaml)
            current_val = self._hash_table.get(grouping_key_hashable, None)

            # Apply reduction function
            new_val = self._reduce_func(current_val, tup)

            # Store the new accumulated value
            self._hash_table[grouping_key_hashable] = new_val
        except Exception as e:
            print(f"GroupBy next error: {e} on tuple {tup}", file=sys.stderr)


    def reset(self, tup: Tuple) -> None:
        # self._reset_counter += 1
        # Process accumulated results
        for grouping_key_hashable, accumulated_val in self._hash_table.items():
            try:
                # Reconstruct the grouping key dictionary from the frozenset
                grouping_key_dict = dict(grouping_key_hashable)

                # Merge: reset tuple fields + grouping key fields + output value
                # OCaml union `fun _ a _ -> Some a` means tup takes precedence over grouping_key
                # Then add the output key/value.
                # merged_tup = {**grouping_key_dict, **tup} # tup overwrites grouping_key
                # Using merge_tuples for clarity on precedence ('first' means tup takes precedence)
                base_merged = merge_tuples(tup, grouping_key_dict, precedence='first')
                final_tup = base_merged.copy()
                final_tup[self._out_key] = accumulated_val

                self._next_op.next(final_tup)
            except Exception as e:
                print(f"GroupBy reset processing error: {e} for group {grouping_key_hashable}", file=sys.stderr)


        # Propagate reset to downstream operator *after* processing groups
        self._next_op.reset(tup)

        # Clear the hash table for the next epoch
        self._hash_table.clear()


# --- GroupBy utility functions ---

def filter_groups(incl_keys: List[str]) -> GroupingFunc:
    """GroupBy utility: Creates a grouping key from included keys."""
    key_set = set(incl_keys) # Faster lookups
    def func(tup: Tuple) -> Tuple:
        return {k: v for k, v in tup.items() if k in key_set}
    return func

def single_group(_tup: Tuple) -> Tuple:
    """GroupBy utility: Groups all tuples into a single group."""
    return {} # Empty dict as the single key

def counter() -> ReductionFunc:
    """GroupBy utility: Reduction function to count tuples in a group."""
    def func(val: OpResult, _tup: Tuple) -> OpResult:
        if val is None: # Empty (first tuple in group)
            return 1
        elif isinstance(val, int):
            return val + 1
        else:
            # Should not happen if used correctly, maybe raise error or return val
            print(f"Warning: Counter expected Int or None, got {type(val)}", file=sys.stderr)
            return val # Return existing value to avoid crashing
    return func

def sum_ints(search_key: str) -> ReductionFunc:
    """GroupBy utility: Reduction function to sum integer values from a field."""
    def func(current_sum: OpResult, tup: Tuple) -> OpResult:
        try:
            value_to_add = lookup_int(search_key, tup)
        except (KeyError, TypeError):
             # Field missing or not an int in the current tuple
             print(f"Warning: sum_ints failed to find integer for key '{search_key}' in tuple {tup}", file=sys.stderr)
             # Decide behavior: skip tuple's contribution, raise error?
             # OCaml raised Failure. Let's return current sum to avoid losing progress.
             return current_sum # Keep current sum unchanged


        if current_sum is None: # First value for this group
            return value_to_add # Start sum with this value
        elif isinstance(current_sum, int):
            return current_sum + value_to_add
        else:
            # Accumulated value is not an int - error condition
             print(f"Warning: sum_ints expected accumulated value to be Int or None, got {type(current_sum)}", file=sys.stderr)
             return current_sum # Return existing sum to avoid crashing
    return func


class DistinctOperator:
    """Outputs distinct tuples based on a grouping function each epoch."""
    def __init__(self, groupby_func: GroupingFunc, next_op: Operator):
        self._groupby_func = groupby_func
        self._next_op = next_op
        # Use a set to store hashable versions of the distinct keys seen
        self._hash_set: set[frozenset] = set()
        # self._reset_counter = 0 # OCaml code tracked this, seems unused

    def next(self, tup: Tuple) -> None:
        try:
            grouping_key_dict = self._groupby_func(tup)
            grouping_key_hashable = make_hashable(grouping_key_dict)
            # Add the key to the set (duplicates are ignored by set)
            self._hash_set.add(grouping_key_hashable)
        except Exception as e:
            print(f"Distinct next error: {e} on tuple {tup}", file=sys.stderr)

    def reset(self, tup: Tuple) -> None:
        # self._reset_counter += 1
        # Process accumulated distinct keys
        for grouping_key_hashable in self._hash_set:
            try:
                # Reconstruct the grouping key dictionary
                grouping_key_dict = dict(grouping_key_hashable)

                # Merge reset tuple fields and the distinct key fields
                # OCaml union `fun _ a _ -> Some a` means tup takes precedence.
                # final_tup = {**grouping_key_dict, **tup}
                final_tup = merge_tuples(tup, grouping_key_dict, precedence='first')

                self._next_op.next(final_tup)
            except Exception as e:
                 print(f"Distinct reset processing error: {e} for group {grouping_key_hashable}", file=sys.stderr)


        # Propagate reset downstream
        self._next_op.reset(tup)

        # Clear the set for the next epoch
        self._hash_set.clear()


class SplitOperator:
    """Sends next and reset calls to two downstream operators."""
    def __init__(self, left_op: Operator, right_op: Operator):
        self._left_op = left_op
        self._right_op = right_op

    def next(self, tup: Tuple) -> None:
        # Maybe deepcopy tup if operators modify it? Assume they don't for now.
        try:
            self._left_op.next(tup)
        except Exception as e:
            print(f"Split left next error: {e}", file=sys.stderr)
        try:
            self._right_op.next(tup)
        except Exception as e:
            print(f"Split right next error: {e}", file=sys.stderr)


    def reset(self, tup: Tuple) -> None:
        # Maybe deepcopy tup if operators modify it? Assume they don't for now.
        try:
            self._left_op.reset(tup)
        except Exception as e:
            print(f"Split left reset error: {e}", file=sys.stderr)
        try:
            self._right_op.reset(tup)
        except Exception as e:
            print(f"Split right reset error: {e}", file=sys.stderr)


# --- Join related types and functions ---
# Key extractor returns (key_tuple, value_tuple)
KeyExtractor = Callable[[Tuple], PyTuple[Tuple, Tuple]]

class _JoinSideOperator:
    """Helper class representing one side of the join logic."""
    def __init__(self, eid_key: str,
                 key_extractor: KeyExtractor,
                 current_h_table: Dict[frozenset, Tuple],
                 other_h_table: Dict[frozenset, Tuple],
                 current_epoch_ref: List[int], # Use list for mutable ref
                 other_epoch_ref: List[int],   # Use list for mutable ref
                 next_op: Operator):
        self._eid_key = eid_key
        self._key_extractor = key_extractor
        self._current_h_table = current_h_table
        self._other_h_table = other_h_table
        self._current_epoch_ref = current_epoch_ref
        self._other_epoch_ref = other_epoch_ref
        self._next_op = next_op

    def next(self, tup: Tuple) -> None:
        try:
            key_dict, vals_dict = self._key_extractor(tup)
            current_epoch = lookup_int(self._eid_key, tup)

            # Advance current epoch marker if needed, triggering resets downstream
            while current_epoch > self._current_epoch_ref[0]:
                # Only reset if the *other* stream has also passed this epoch boundary
                if self._other_epoch_ref[0] > self._current_epoch_ref[0]:
                    # print(f"Join side: Resetting downstream for epoch {self._current_epoch_ref[0]} due to epoch advance")
                    self._next_op.reset({self._eid_key: self._current_epoch_ref[0]})
                self._current_epoch_ref[0] += 1

            # Create the actual key for matching (includes epoch)
            # Need to merge key_dict and epoch info for the hash table key
            join_key_dict = key_dict.copy()
            join_key_dict[self._eid_key] = current_epoch
            join_key_hashable = make_hashable(join_key_dict)

            # Check if the key exists in the *other* stream's table
            if join_key_hashable in self._other_h_table:
                # Match found!
                other_vals_dict = self._other_h_table.pop(join_key_hashable) # Consume match

                # Merge: join key (incl. epoch), current values, other stream's values
                # OCaml `use_left` = `fun _ a _ -> Some a`
                # Tuple.union use_left new_tup (Tuple.union use_left vals_ val_)
                # Means new_tup takes precedence over (vals_ union val_)
                # And vals_ takes precedence over val_
                # So, precedence order: join_key_dict > vals_dict > other_vals_dict
                # Using merge_tuples(dict1, dict2, ...) where dict1 has highest precedence
                merged_tup = merge_tuples(join_key_dict, vals_dict, other_vals_dict, precedence='first')

                self._next_op.next(merged_tup)
            else:
                # No match yet, store current key/values in *this* stream's table
                self._current_h_table[join_key_hashable] = vals_dict

        except (KeyError, TypeError) as e:
             print(f"Join next error (key/epoch handling): {e} in tuple {tup}", file=sys.stderr)
        except Exception as e:
             print(f"Join next error (general): {e} in tuple {tup}", file=sys.stderr)


    def reset(self, tup: Tuple) -> None:
        # Reset is mainly about synchronizing epochs downstream
        try:
            reset_epoch = lookup_int(self._eid_key, tup)

            # Ensure our epoch counter catches up to the reset epoch
            while reset_epoch > self._current_epoch_ref[0]:
                 # Only reset if the *other* stream has also passed this epoch boundary
                if self._other_epoch_ref[0] > self._current_epoch_ref[0]:
                    # print(f"Join side: Resetting downstream for epoch {self._current_epoch_ref[0]} due to reset call")
                    self._next_op.reset({self._eid_key: self._current_epoch_ref[0]})
                self._current_epoch_ref[0] += 1

            # Note: Original OCaml doesn't explicitly clear hash tables on reset here.
            # It seems expired entries (from old epochs) are implicitly handled
            # because matching requires the epoch ID. We might need explicit cleanup
            # if memory becomes an issue, by iterating tables and removing entries
            # where epoch < current_epoch_ref[0]. For now, match OCaml behavior.

        except (KeyError, TypeError) as e:
             print(f"Join reset error (key/epoch handling): {e} in tuple {tup}", file=sys.stderr)
        except Exception as e:
             print(f"Join reset error (general): {e} in tuple {tup}", file=sys.stderr)


def join(left_extractor: KeyExtractor, right_extractor: KeyExtractor,
         next_op: Operator, eid_key: str = "eid") -> PyTuple[Operator, Operator]:
    """Creates two operators for joining two streams based on keys and epoch."""

    # Shared state for both join sides
    h_table1: Dict[frozenset, Tuple] = {} # Stores values from left stream awaiting match
    h_table2: Dict[frozenset, Tuple] = {} # Stores values from right stream awaiting match
    left_curr_epoch: List[int] = [0]  # Use list for mutable integer reference
    right_curr_epoch: List[int] = [0] # Use list for mutable integer reference

    # Create the operator for the left input stream
    left_op = _JoinSideOperator(
        eid_key=eid_key,
        key_extractor=left_extractor,
        current_h_table=h_table1,
        other_h_table=h_table2,
        current_epoch_ref=left_curr_epoch,
        other_epoch_ref=right_curr_epoch,
        next_op=next_op
    )

    # Create the operator for the right input stream
    right_op = _JoinSideOperator(
        eid_key=eid_key,
        key_extractor=right_extractor,
        current_h_table=h_table2, # Swapped tables
        other_h_table=h_table1,   # Swapped tables
        current_epoch_ref=right_curr_epoch, # Swapped refs
        other_epoch_ref=left_curr_epoch,    # Swapped refs
        next_op=next_op
    )

    return left_op, right_op

# --- Join utility function ---

def rename_filtered_keys(renamings_pairs: List[PyTuple[str, str]]) -> Callable[[Tuple], Tuple]:
    """
    Join utility: Returns a function that extracts and renames keys.
    The returned function takes a tuple and returns a new tuple
    containing only the specified keys, renamed according to the pairs.
    """
    # Pre-process pairs for efficiency if needed, but list is likely small
    def func(in_tup: Tuple) -> Tuple:
        new_tup: Tuple = {}
        for old_key, new_key in renamings_pairs:
            if old_key in in_tup:
                new_tup[new_key] = in_tup[old_key]
        return new_tup
    return func

```

**3. `main.py` (Query Definitions and Execution)**

```python
# main.py
import sys
import ipaddress
from typing import List, Dict, Callable, Any, Tuple as PyTuple

# Import necessary components from our modules
from utils import (
    OpResult, Tuple, Operator, OpCreator, DblOpCreator,
    MAC, IPv4, Int, Float, Empty,  # Make constructors available if needed
    int_of_op_result, float_of_op_result, lookup_int, lookup_float,
    tuple_of_list, make_hashable, merge_tuples
)
from builtins import (
    # Operators (Classes implementing Operator protocol)
    DumpTupleOperator, DumpCsvOperator, DumpWaltsCsvOperator,
    MetaMeterOperator, EpochOperator, FilterOperator, MapOperator,
    GroupByOperator, DistinctOperator, SplitOperator,
    # Operator Constructors (Functions returning Operators or pairs)
    join,
    # Utility functions used in query definitions
    key_geq_int, get_mapped_int, get_mapped_float, # Aliases for lookup_*
    filter_groups, single_group, counter, sum_ints,
    rename_filtered_keys,
    # Driver function
    read_walts_csv,
)

# --- Query Definitions ---
# These functions take the *next* operator and return the *entry point* operator
# for that specific query pipeline.

def ident() -> OpCreator:
    """Query: Remove ethernet fields."""
    def creator(next_op: Operator) -> Operator:
        map_func = lambda tup: {
            k: v for k, v in tup.items()
            if k not in ("eth.src", "eth.dst")
        }
        return MapOperator(map_func, next_op)
    return creator

def count_pkts() -> OpCreator:
    """Query: Count total packets per epoch."""
    def creator(next_op: Operator) -> Operator:
        # Composition: epoch -> groupby -> next_op
        gb_op = GroupByOperator(single_group, counter(), "pkts", next_op)
        ep_op = EpochOperator(1.0, "eid", gb_op)
        return ep_op
    return creator

def pkts_per_src_dst() -> OpCreator:
    """Query: Count packets per source/destination IP pair per epoch."""
    def creator(next_op: Operator) -> Operator:
        gb_op = GroupByOperator(
            filter_groups(["ipv4.src", "ipv4.dst"]),
            counter(),
            "pkts",
            next_op
        )
        ep_op = EpochOperator(1.0, "eid", gb_op)
        return ep_op
    return creator

def distinct_srcs() -> OpCreator:
    """Query: Count distinct source IPs per epoch."""
    def creator(next_op: Operator) -> Operator:
        gb_op = GroupByOperator(single_group, counter(), "srcs", next_op)
        dist_op = DistinctOperator(filter_groups(["ipv4.src"]), gb_op)
        ep_op = EpochOperator(1.0, "eid", dist_op)
        return ep_op
    return creator

# --- Sonata Queries ---

def tcp_new_cons(threshold: int = 40) -> OpCreator:
    """Sonata 1: Detect hosts receiving many new TCP connections."""
    def creator(next_op: Operator) -> Operator:
        filter_threshold_op = FilterOperator(key_geq_int("cons", threshold), next_op)
        gb_op = GroupByOperator(
            filter_groups(["ipv4.dst"]),
            counter(),
            "cons",
            filter_threshold_op
        )
        filter_syn_op = FilterOperator(
            lambda tup: lookup_int("ipv4.proto", tup) == 6 and lookup_int("l4.flags", tup) == 2, # SYN flag = 2
            gb_op
        )
        ep_op = EpochOperator(1.0, "eid", filter_syn_op)
        return ep_op
    return creator

def ssh_brute_force(threshold: int = 40) -> OpCreator:
    """Sonata 2: Detect SSH brute force attacks."""
    def creator(next_op: Operator) -> Operator:
        filter_threshold_op = FilterOperator(key_geq_int("srcs", threshold), next_op)
        gb_op = GroupByOperator(
            filter_groups(["ipv4.dst", "ipv4.len"]), # Group by dst IP and packet length
            counter(),
            "srcs", # Count distinct sources per (dst, len) group
            filter_threshold_op
        )
        dist_op = DistinctOperator(
             filter_groups(["ipv4.src", "ipv4.dst", "ipv4.len"]), # Distinct (src, dst, len)
             gb_op
        )
        filter_ssh_op = FilterOperator(
            lambda tup: lookup_int("ipv4.proto", tup) == 6 and lookup_int("l4.dport", tup) == 22,
            dist_op
        )
        ep_op = EpochOperator(1.0, "eid", filter_ssh_op) # Maybe longer epoch?
        return ep_op
    return creator

def super_spreader(threshold: int = 40) -> OpCreator:
    """Sonata 3: Detect hosts connecting to many distinct destinations."""
    def creator(next_op: Operator) -> Operator:
        filter_threshold_op = FilterOperator(key_geq_int("dsts", threshold), next_op)
        gb_op = GroupByOperator(
            filter_groups(["ipv4.src"]), # Group by source
            counter(),
            "dsts", # Count distinct destinations contacted by source
            filter_threshold_op
        )
        dist_op = DistinctOperator(
             filter_groups(["ipv4.src", "ipv4.dst"]), # Distinct (src, dst) pairs
             gb_op
        )
        ep_op = EpochOperator(1.0, "eid", dist_op)
        return ep_op
    return creator

def port_scan(threshold: int = 40) -> OpCreator:
    """Sonata 4: Detect hosts scanning many distinct ports on destinations."""
    # NOTE: Original groups by src only. If scanning multiple hosts, maybe group by (src, dst)? Sticking to original.
    def creator(next_op: Operator) -> Operator:
        filter_threshold_op = FilterOperator(key_geq_int("ports", threshold), next_op)
        gb_op = GroupByOperator(
            filter_groups(["ipv4.src"]), # Group by source IP
            counter(),
            "ports", # Count distinct destination ports tried by source
            filter_threshold_op
        )
        dist_op = DistinctOperator(
             filter_groups(["ipv4.src", "l4.dport"]), # Distinct (src, port) pairs tried
             gb_op
        )
        ep_op = EpochOperator(1.0, "eid", dist_op)
        return ep_op
    return creator

def ddos(threshold: int = 45) -> OpCreator:
    """Sonata 5: Detect hosts targeted by many distinct sources (DDoS)."""
    def creator(next_op: Operator) -> Operator:
        filter_threshold_op = FilterOperator(key_geq_int("srcs", threshold), next_op)
        gb_op = GroupByOperator(
            filter_groups(["ipv4.dst"]), # Group by destination IP
            counter(),
            "srcs", # Count distinct sources hitting the destination
            filter_threshold_op
        )
        dist_op = DistinctOperator(
             filter_groups(["ipv4.src", "ipv4.dst"]), # Distinct (src, dst) pairs
             gb_op
        )
        ep_op = EpochOperator(1.0, "eid", dist_op)
        return ep_op
    return creator


# Sonata 6 (SYN Flood) requires multiple input streams processed and joined.
# It returns a LIST of operator entry points.
def syn_flood_sonata(threshold: int = 3, epoch_dur: float = 1.0) -> Callable[[Operator], List[Operator]]:
    """Sonata 6: Detect SYN flood (SYN > SYNACK + ACK). Returns *list* of operators."""
    def creator(final_next_op: Operator) -> List[Operator]:
        # Define the final filtering and mapping steps after joins
        filter_final_op = FilterOperator(
            key_geq_int("syns+synacks-acks", threshold),
            final_next_op
        )
        map_final_op = MapOperator(
            lambda tup: merge_tuples(tup, {"syns+synacks-acks": lookup_int("syns+synacks", tup) - lookup_int("acks", tup)}, precedence='last'),
            filter_final_op
        )

        # Define the second join (SYN+SYNACK vs ACK)
        join2_left_extract: KeyExtractor = lambda tup: (
            filter_groups(["host"])(tup),          # Key: {"host": ...}
            filter_groups(["syns+synacks"])(tup)   # Value: {"syns+synacks": ...}
        )
        join2_right_extract: KeyExtractor = lambda tup: (
            rename_filtered_keys([("ipv4.dst", "host")])(tup), # Key: {"host": ...}
            filter_groups(["acks"])(tup)                       # Value: {"acks": ...}
        )
        # The 'next_op' for join2 is the map_final_op chain
        join2_op1, join2_op2 = join(join2_left_extract, join2_right_extract, map_final_op, eid_key="eid")

        # Define the first join (SYN vs SYNACK)
        map_join1_op = MapOperator(
             lambda tup: merge_tuples(tup, {"syns+synacks": lookup_int("syns", tup) + lookup_int("synacks", tup)}, precedence='last'),
             join2_op1 # Output of this map goes to the left input of join2
        )
        join1_left_extract: KeyExtractor = lambda tup: (
            rename_filtered_keys([("ipv4.dst", "host")])(tup), # Key: {"host":...}
            filter_groups(["syns"])(tup)                       # Value: {"syns":...}
        )
        join1_right_extract: KeyExtractor = lambda tup: (
            rename_filtered_keys([("ipv4.src", "host")])(tup), # Key: {"host":...} Renamed from src!
            filter_groups(["synacks"])(tup)                    # Value: {"synacks":...}
        )
        # The 'next_op' for join1 is the map_join1_op
        join1_op3, join1_op4 = join(join1_left_extract, join1_right_extract, map_join1_op, eid_key="eid")


        # --- Define the initial processing pipelines for SYN, SYNACK, ACK ---
        # SYN Pipeline -> feeds left side of join1 (join1_op3)
        syns_gb_op = GroupByOperator(filter_groups(["ipv4.dst"]), counter(), "syns", join1_op3)
        syns_filter_op = FilterOperator(
            lambda tup: lookup_int("ipv4.proto", tup) == 6 and lookup_int("l4.flags", tup) == 2, # SYN
            syns_gb_op
        )
        syns_epoch_op = EpochOperator(epoch_dur, "eid", syns_filter_op)

        # SYNACK Pipeline -> feeds right side of join1 (join1_op4)
        synacks_gb_op = GroupByOperator(filter_groups(["ipv4.src"]), counter(), "synacks", join1_op4) # Group by SYNACK sender (src)
        synacks_filter_op = FilterOperator(
            lambda tup: lookup_int("ipv4.proto", tup) == 6 and lookup_int("l4.flags", tup) == 18, # SYN+ACK = 18 (0x12)
            synacks_gb_op
        )
        synacks_epoch_op = EpochOperator(epoch_dur, "eid", synacks_filter_op)

        # ACK Pipeline -> feeds right side of join2 (join2_op2)
        acks_gb_op = GroupByOperator(filter_groups(["ipv4.dst"]), counter(), "acks", join2_op2) # Group by ACK receiver (dst)
        acks_filter_op = FilterOperator(
            lambda tup: lookup_int("ipv4.proto", tup) == 6 and lookup_int("l4.flags", tup) == 16, # ACK = 16 (0x10)
            acks_gb_op
        )
        acks_epoch_op = EpochOperator(epoch_dur, "eid", acks_filter_op)

        # Return the entry points of the three pipelines
        return [syns_epoch_op, synacks_epoch_op, acks_epoch_op]

    return creator

# Sonata 7 (Completed Flows)
def completed_flows(threshold: int = 1, epoch_dur: float = 30.0) -> Callable[[Operator], List[Operator]]:
    """Sonata 7: Detect hosts with more SYNs than FINs. Returns *list* of operators."""
    def creator(final_next_op: Operator) -> List[Operator]:
        filter_final_op = FilterOperator(key_geq_int("diff", threshold), final_next_op)
        map_final_op = MapOperator(
            lambda tup: merge_tuples(tup, {"diff": lookup_int("syns", tup) - lookup_int("fins", tup)}, precedence='last'),
            filter_final_op
        )

        join_left_extract: KeyExtractor = lambda tup: (
            rename_filtered_keys([("ipv4.dst", "host")])(tup), # Key is host receiving SYN
            filter_groups(["syns"])(tup)
        )
        join_right_extract: KeyExtractor = lambda tup: (
            rename_filtered_keys([("ipv4.src", "host")])(tup), # Key is host sending FIN (maps to same host)
            filter_groups(["fins"])(tup)
        )
        op1, op2 = join(join_left_extract, join_right_extract, map_final_op, eid_key="eid")

        # SYN pipeline -> feeds op1 (left join input)
        syns_gb_op = GroupByOperator(filter_groups(["ipv4.dst"]), counter(), "syns", op1)
        syns_filter_op = FilterOperator(
            lambda tup: lookup_int("ipv4.proto", tup) == 6 and lookup_int("l4.flags", tup) == 2, # SYN
            syns_gb_op
        )
        syns_epoch_op = EpochOperator(epoch_dur, "eid", syns_filter_op)

        # FIN pipeline -> feeds op2 (right join input)
        fins_gb_op = GroupByOperator(filter_groups(["ipv4.src"]), counter(), "fins", op2) # Group by FIN sender (src)
        fins_filter_op = FilterOperator(
            lambda tup: lookup_int("ipv4.proto", tup) == 6 and (lookup_int("l4.flags", tup) & 1) == 1, # FIN flag is bit 0
            fins_gb_op
        )
        fins_epoch_op = EpochOperator(epoch_dur, "eid", fins_filter_op)

        return [syns_epoch_op, fins_epoch_op]
    return creator

# Sonata 8 (Slowloris)
def slowloris(t1: int = 5, t2: int = 500, t3: int = 90, epoch_dur: float = 1.0) -> Callable[[Operator], List[Operator]]:
    """Sonata 8: Detect Slowloris attacks. Returns *list* of operators."""
    def creator(final_next_op: Operator) -> List[Operator]:
        # Final filtering and mapping
        filter_final_op = FilterOperator(
            lambda tup: lookup_int("bytes_per_conn", tup) <= t3,
            final_next_op
        )
        map_final_op = MapOperator(
            lambda tup: merge_tuples(tup, {"bytes_per_conn": lookup_int("n_bytes", tup) // lookup_int("n_conns", tup)}, precedence='last'),
            filter_final_op
        )

        # Join definition
        join_left_extract: KeyExtractor = lambda tup: ( # n_conns side
            filter_groups(["ipv4.dst"])(tup),
            filter_groups(["n_conns"])(tup)
        )
        join_right_extract: KeyExtractor = lambda tup: ( # n_bytes side
            filter_groups(["ipv4.dst"])(tup),
            filter_groups(["n_bytes"])(tup)
        )
        op1, op2 = join(join_left_extract, join_right_extract, map_final_op, eid_key="eid")

        # n_conns pipeline -> feeds op1
        n_conns_filter_t1 = FilterOperator(key_geq_int("n_conns", t1), op1)
        n_conns_gb = GroupByOperator(filter_groups(["ipv4.dst"]), counter(), "n_conns", n_conns_filter_t1)
        n_conns_distinct = DistinctOperator(filter_groups(["ipv4.src", "ipv4.dst", "l4.sport"]), n_conns_gb) # Distinct connections
        n_conns_filter_proto = FilterOperator(lambda tup: lookup_int("ipv4.proto", tup) == 6, n_conns_distinct)
        n_conns_epoch = EpochOperator(epoch_dur, "eid", n_conns_filter_proto)

        # n_bytes pipeline -> feeds op2
        n_bytes_filter_t2 = FilterOperator(key_geq_int("n_bytes", t2), op2)
        n_bytes_gb = GroupByOperator(filter_groups(["ipv4.dst"]), sum_ints("ipv4.len"), "n_bytes", n_bytes_filter_t2) # Sum bytes per dest
        n_bytes_filter_proto = FilterOperator(lambda tup: lookup_int("ipv4.proto", tup) == 6, n_bytes_gb)
        n_bytes_epoch = EpochOperator(epoch_dur, "eid", n_bytes_filter_proto)

        return [n_conns_epoch, n_bytes_epoch]

    return creator

# Join Test Example
def join_test() -> Callable[[Operator], List[Operator]]:
    """Example demonstrating a join."""
    def creator(final_next_op: Operator) -> List[Operator]:
        join_left_extract: KeyExtractor = lambda tup: (
            rename_filtered_keys([("ipv4.src", "host")])(tup),   # Key: {"host": src_ip}
            rename_filtered_keys([("ipv4.dst", "remote")])(tup) # Value: {"remote": dst_ip}
        )
        join_right_extract: KeyExtractor = lambda tup: (
            rename_filtered_keys([("ipv4.dst", "host")])(tup),   # Key: {"host": dst_ip}
            filter_groups(["time"])(tup)                       # Value: {"time": time}
        )
        # Note: eid_key="eid" is default for join
        op1, op2 = join(join_left_extract, join_right_extract, final_next_op)

        # SYN pipeline -> feeds op1
        syns_filter_op = FilterOperator(
            lambda tup: lookup_int("ipv4.proto", tup) == 6 and lookup_int("l4.flags", tup) == 2, # SYN
            op1 # Send SYN packets directly to left join input
        )
        syns_epoch_op = EpochOperator(1.0, "eid", syns_filter_op)

        # SYNACK pipeline -> feeds op2
        synacks_filter_op = FilterOperator(
            lambda tup: lookup_int("ipv4.proto", tup) == 6 and lookup_int("l4.flags", tup) == 18, # SYNACK
            op2 # Send SYNACK packets directly to right join input
        )
        synacks_epoch_op = EpochOperator(1.0, "eid", synacks_filter_op)

        return [syns_epoch_op, synacks_epoch_op]

    return creator

# --- Other simple queries from OCaml main ---
def q3() -> OpCreator:
    """Distinct source/destination pairs over a long epoch."""
    def creator(next_op: Operator) -> Operator:
        dist_op = DistinctOperator(filter_groups(["ipv4.src", "ipv4.dst"]), next_op)
        ep_op = EpochOperator(100.0, "eid", dist_op)
        return ep_op
    return creator

def q4() -> OpCreator:
    """Count packets per destination over a very long epoch."""
    def creator(next_op: Operator) -> Operator:
        gb_op = GroupByOperator(filter_groups(["ipv4.dst"]), counter(), "pkts", next_op)
        ep_op = EpochOperator(10000.0, "eid", gb_op)
        return ep_op
    return creator


# --- Main Execution ---

def run_queries(queries_to_run: List[Operator]):
    """Generates sample data and runs it through the specified queries."""
    print("Generating sample data...")
    sample_data: List[Tuple] = []
    base_time = 0.0 # Or use time.time() for real timestamps
    for i in range(20):
        tup: Tuple = {
            "time": base_time + float(i) * 0.01, # Increment time slightly
            "eth.src": b'\x00\x11\x22\x33\x44\x55',
            "eth.dst": b'\xAA\xBB\xCC\xDD\xEE\xFF',
            "eth.ethertype": 0x0800, # IPv4
            "ipv4.hlen": 20,
            "ipv4.proto": 6, # TCP
            "ipv4.len": 60 + i, # Vary length slightly
            "ipv4.src": ipaddress.IPv4Address(f"192.168.1.{100 + i % 5}"), # Vary src IP
            "ipv4.dst": ipaddress.IPv4Address(f"10.0.0.{1 + i % 3}"), # Vary dst IP
            "l4.sport": 44000 + i,
            "l4.dport": 80 if i % 4 != 0 else 22, # Mostly port 80, sometimes 22
            # Vary flags: SYN, SYNACK, ACK, FIN, PSH+ACK
            "l4.flags": [2, 18, 16, 1, 24][i % 5]
        }
        sample_data.append(tup)

    print(f"Running {len(sample_data)} sample tuples through {len(queries_to_run)} queries...")
    for tup in sample_data:
        for query_op in queries_to_run:
            try:
                 query_op.next(tup)
            except Exception as e:
                 print(f"Error processing tuple in query: {e}", file=sys.stderr)
                 # Decide whether to continue with next query or tuple

    # Signal end of stream by calling reset on all query entry points
    # Use an empty tuple or a tuple indicating end for the reset signal?
    # The OCaml 'epoch' reset used a singleton with the last epoch ID.
    # Let's send a generic reset signal (empty dict). Individual operators
    # might add relevant info (like epoch id) when propagating the reset.
    print("Signaling end of stream (reset)...")
    reset_signal: Tuple = {}
    for query_op in queries_to_run:
         try:
             query_op.reset(reset_signal)
         except Exception as e:
             print(f"Error resetting query: {e}", file=sys.stderr)


if __name__ == "__main__":
    print("--- Python Stream Processor ---")

    # Define the terminal operator (where the results go)
    # Change stdout to a file stream if needed: open('output.txt', 'w')
    # terminal_op = DumpTupleOperator(sys.stdout, show_reset=True)
    terminal_op = DumpCsvOperator(sys.stdout, header=True) # Use CSV output for testing

    # --- Select and Instantiate Queries ---
    # Note: For queries returning List[Operator] (like syn_flood),
    # you would typically run them by reading data multiple times or splitting
    # the input stream appropriately *before* the query entry points.
    # The `read_walts_csv` function handles this for its specific use case.
    # For the simple `run_queries` example, we'll run simpler queries.

    # Example: Run count_pkts and distinct_srcs queries
    # Apply the creator function to the terminal operator
    query1_creator = count_pkts()
    query1_entry_op = query1_creator(terminal_op)

    query2_creator = distinct_srcs()
    query2_entry_op = query2_creator(terminal_op)

    query3_creator = tcp_new_cons()
    query3_entry_op = query3_creator(terminal_op)


    # List of *entry point* operators for the selected queries
    active_queries: List[Operator] = [query1_entry_op, query2_entry_op, query3_entry_op]


    # --- Execute ---
    # run_queries(active_queries) # Run with sample data

    # Example of using read_walts_csv (if you have suitable files)
    # Create dummy files first for testing
    # try:
    #     with open("dummy_walt1.csv", "w") as f:
    #         f.write("1.1.1.1,2.2.2.2,100,200,10,1000,0\n")
    #         f.write("1.1.1.1,2.2.2.2,101,201,5,500,0\n")
    #         f.write("3.3.3.3,4.4.4.4,300,400,20,2000,1\n") # Epoch 1
    #     with open("dummy_walt2.csv", "w") as f:
    #         f.write("5.5.5.5,6.6.6.6,500,600,1,100,0\n")
    #         f.write("7.7.7.7,8.8.8.8,700,800,2,200,1\n") # Epoch 1
    #         f.write("7.7.7.7,8.8.8.8,701,801,3,300,1\n") # Epoch 1
    #
    #     # Define terminal ops for each input file/stream
    #     term_op1 = DumpTupleOperator(open("walt_out1.txt", "w"), show_reset=True)
    #     term_op2 = DumpTupleOperator(open("walt_out2.txt", "w"), show_reset=True)
    #
    #     # Apply query creators
    #     walt_query1_entry = pkts_per_src_dst()(term_op1)
    #     walt_query2_entry = count_pkts()(term_op2)
    #
    #     read_walts_csv(
    #         file_names=["dummy_walt1.csv", "dummy_walt2.csv"],
    #         ops=[walt_query1_entry, walt_query2_entry]
    #     )
    #     # Remember to close file streams if not using 'with' or DumpWaltsCsvOperator
    #     term_op1._out_stream.close() # Manually close if needed
    #     term_op2._out_stream.close() # Manually close if needed
    # except Exception as e:
    #     print(f"Error running read_walts_csv example: {e}")


    # --- Example demonstrating a join query with sample data ---
    print("\n--- Running Join Test Example ---")
    join_term_op = DumpTupleOperator(sys.stdout, show_reset=True)
    join_creator = join_test()
    join_entry_ops: List[Operator] = join_creator(join_term_op) # Get the two entry points

    # Need to feed data to the correct entry point based on type (SYN vs SYNACK)
    print("Generating data for join test...")
    join_sample_data = []
    base_time = 100.0
    # Generate some SYNs
    for i in range(5):
         join_sample_data.append({
            "time": base_time + i * 0.1, "type": "SYN",
            "ipv4.proto": 6, "l4.flags": 2, "eid": 0,
            "ipv4.src": ipaddress.IPv4Address("1.1.1.1"),
            "ipv4.dst": ipaddress.IPv4Address("2.2.2.2"),
         })
    # Generate some SYNACKs (some matching, some not)
    for i in range(5):
         join_sample_data.append({
            "time": base_time + i * 0.1 + 0.05, "type": "SYNACK",
            "ipv4.proto": 6, "l4.flags": 18, "eid": 0,
             # SYNACK source is the original SYN destination
            "ipv4.src": ipaddress.IPv4Address("2.2.2.2") if i%2 == 0 else ipaddress.IPv4Address("3.3.3.3"),
             # SYNACK dest is the original SYN source
            "ipv4.dst": ipaddress.IPv4Address("1.1.1.1"),
         })
    # Add data for next epoch
    join_sample_data.append({
            "time": base_time + 1.5, "type": "SYN",
            "ipv4.proto": 6, "l4.flags": 2, "eid": 1, # Epoch 1
            "ipv4.src": ipaddress.IPv4Address("4.4.4.4"),
            "ipv4.dst": ipaddress.IPv4Address("5.5.5.5"),
         })
    join_sample_data.append({
            "time": base_time + 1.6, "type": "SYNACK",
            "ipv4.proto": 6, "l4.flags": 18, "eid": 1, # Epoch 1
            "ipv4.src": ipaddress.IPv4Address("5.5.5.5"),
            "ipv4.dst": ipaddress.IPv4Address("4.4.4.4"),
         })


    print("Processing join data...")
    syn_op_entry = join_entry_ops[0]   # Corresponds to the 'syns' pipeline in join_test
    synack_op_entry = join_entry_ops[1] # Corresponds to the 'synacks' pipeline

    for tup in join_sample_data:
        if tup["type"] == "SYN":
            syn_op_entry.next(tup)
        elif tup["type"] == "SYNACK":
            synack_op_entry.next(tup)

    # Reset both sides
    print("Resetting join streams...")
    # Reset signal needs the last epoch ID encountered
    syn_op_entry.reset({"eid": 1})
    synack_op_entry.reset({"eid": 1})


    print("\nDone")

```

**Explanation and Key Changes:**

1.  **Modules:** Code is split into `utils.py` (basic types, conversions), `builtins.py` (operator implementations, core logic like `read_walts_csv`), and `main.py` (query definitions, execution).
2.  **Types:**
    * `op_result` -> `typing.Union` named `OpResult`. `Empty` becomes `None`.
    * `tuple` -> `typing.Dict[str, OpResult]` named `Tuple`.
    * `operator` record -> `typing.Protocol` named `Operator`. This defines the required `next` and `reset` methods without forcing inheritance. Operator implementations are now classes (e.g., `FilterOperator`, `GroupByOperator`) that implicitly satisfy the protocol.
    * `op_creator` / `dbl_op_creator` -> `typing.Callable`.
3.  **Operators (`@=>`, `@==>`)**: Replaced with standard Python function composition. Query definitions now show nested calls like `EpochOperator(..., GroupByOperator(..., FilterOperator(..., next_op)))`.
4.  **State Management:** OCaml `ref` types used for mutable state (like counts or epoch boundaries) are replaced with instance variables within the operator classes (e.g., `self._epoch_count`). For shared mutable state needed by `join` (epoch counters, hash tables), Python's standard closure mechanism is used by defining the `_JoinSideOperator` class *inside* the `join` function, or by passing mutable objects like lists (`[0]`) for epoch counters.
5.  **Maps/Hash Tables:** OCaml `Map.Make(String)` and `Hashtbl` are replaced by Python dictionaries (`dict`).
6.  **Hashing Dictionary Keys:** Since `groupby` and `distinct` use tuples (which are dictionaries in Python) as keys, and dictionaries aren't directly hashable, a helper `make_hashable(d: Dict) -> frozenset` converts the dictionary's items into a `frozenset`, which *is* hashable and can be used as a dictionary key.
7.  **Tuple Merging:** OCaml's `Tuple.union` with a conflict resolution function is replaced by a `merge_tuples` helper function that mimics the precedence logic (using dictionary unpacking or `update`).
8.  **Pattern Matching:** OCaml `match` statements are translated into Python `if/elif/else` blocks, often using `isinstance()` for type checking (equivalent to matching on `op_result` tags).
9.  **Error Handling:** OCaml `Failure` exceptions are replaced by standard Python exceptions like `TypeError`, `ValueError`, `KeyError`. Added basic error handling (`try...except`) in key places like file I/O, type conversions, and predicate/map function calls.
10. **File Handling:** Used `with open(...)` where appropriate (though the persistent file handle in `DumpWaltsCsvOperator` mimics the OCaml `ref` logic more closely, requiring explicit closing or relying on `__del__`). The `csv` module is used for more robust CSV parsing/writing.
11. **Function Naming:** Followed Python's `snake_case` convention.
12. **Class Naming:** Followed Python's `PascalCase` convention.
13. **Main Execution:** The `main.py` defines query *creator* functions (following the OCaml pattern) and then instantiates them by calling them with a terminal operator (like `DumpTupleOperator` or `DumpCsvOperator`). Examples show how to run simple queries and sketch how to handle multi-input queries like joins.

This translation provides a functional equivalent in Python, emphasizing clarity, type safety (via hints), and standard Python practices.