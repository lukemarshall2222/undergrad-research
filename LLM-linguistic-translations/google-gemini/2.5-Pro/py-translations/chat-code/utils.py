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