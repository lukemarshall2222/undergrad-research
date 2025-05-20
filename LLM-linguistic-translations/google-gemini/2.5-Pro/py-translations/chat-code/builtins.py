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