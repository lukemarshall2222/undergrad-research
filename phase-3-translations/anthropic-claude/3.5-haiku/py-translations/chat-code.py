from typing import Dict, Any, List, Optional, Union, Callable
from enum import Enum, auto
from dataclasses import dataclass, field
import ipaddress
import struct
import csv
import sys
import time
import hashlib

class OpResult(Enum):
    FLOAT = auto()
    INT = auto()
    IPV4 = auto()
    MAC = auto()
    EMPTY = auto()

@dataclass
class Tuple:
    data: Dict[str, Union[float, int, ipaddress.IPv4Address, bytes, None]] = field(default_factory=dict)

    def add(self, key: str, value: Any) -> 'Tuple':
        new_tuple = Tuple(self.data.copy())
        new_tuple.data[key] = value
        return new_tuple

    def get(self, key: str) -> Any:
        return self.data.get(key)

    def items(self):
        return self.data.items()

    def filter_keys(self, keys: List[str]) -> 'Tuple':
        return Tuple({k: v for k, v in self.data.items() if k in keys})

    def union(self, other: 'Tuple', priority='first') -> 'Tuple':
        merged = self.data.copy()
        for k, v in other.data.items():
            if priority == 'first' and k in merged:
                continue
            merged[k] = v
        return Tuple(merged)

@dataclass
class Operator:
    next_func: Callable[[Tuple], None]
    reset_func: Callable[[Tuple], None]

def filter_operator(predicate: Callable[[Tuple], bool], next_op: Operator) -> Operator:
    def filter_next(tup: Tuple):
        if predicate(tup):
            next_op.next_func(tup)

    return Operator(next_func=filter_next, reset_func=next_op.reset_func)

def map_operator(transform: Callable[[Tuple], Tuple], next_op: Operator) -> Operator:
    def map_next(tup: Tuple):
        next_op.next_func(transform(tup))

    return Operator(next_func=map_next, reset_func=next_op.reset_func)

def epoch_operator(epoch_width: float, key_out: str, next_op: Operator) -> Operator:
    epoch_boundary = 0.0
    eid = 0

    def epoch_next(tup: Tuple):
        nonlocal epoch_boundary, eid
        time_val = tup.get('time')

        if epoch_boundary == 0.0:
            epoch_boundary = time_val + epoch_width
        elif time_val >= epoch_boundary:
            while time_val >= epoch_boundary:
                next_op.reset_func(Tuple().add(key_out, eid))
                epoch_boundary += epoch_width
                eid += 1

        tup_with_eid = tup.add(key_out, eid)
        next_op.next_func(tup_with_eid)

    def epoch_reset(_: Tuple):
        nonlocal epoch_boundary, eid
        next_op.reset_func(Tuple().add(key_out, eid))
        epoch_boundary = 0.0
        eid = 0

    return Operator(next_func=epoch_next, reset_func=epoch_reset)

def groupby_operator(groupby_keys: List[str], reducer: Callable, out_key: str, next_op: Operator) -> Operator:
    group_table = {}

    def groupby_next(tup: Tuple):
        # Extract grouping key
        grouping_key = tup.filter_keys(groupby_keys)
        
        # Find or create group
        if grouping_key not in group_table:
            group_table[grouping_key] = OpResult.EMPTY
        
        # Reduce
        group_table[grouping_key] = reducer(group_table[grouping_key], tup)

    def groupby_reset(reset_tup: Tuple):
        for grouping_key, value in list(group_table.items()):
            # Merge reset tuple with grouping key
            merged_tup = reset_tup.union(grouping_key)
            # Add the reduced value to the tuple
            final_tup = merged_tup.add(out_key, value)
            next_op.next_func(final_tup)
        
        # Clear the group table
        group_table.clear()
        next_op.reset_func(reset_tup)

    return Operator(next_func=groupby_next, reset_func=groupby_reset)

def join_operator(
    left_extractor: Callable[[Tuple], Tuple], 
    right_extractor: Callable[[Tuple], Tuple], 
    next_op: Operator
) -> Tuple[Operator, Operator]:
    left_table = {}
    right_table = {}
    left_epoch = 0
    right_epoch = 0

    def handle_join_side(
        curr_table, other_table, 
        curr_epoch_ref, other_epoch_ref, 
        extractor
    ) -> Operator:
        def join_next(tup: Tuple):
            nonlocal curr_epoch_ref, other_epoch_ref
            key, vals = extractor(tup)
            curr_epoch = tup.get('eid')

            # Advance epochs
            while curr_epoch > curr_epoch_ref:
                if other_epoch_ref > curr_epoch_ref:
                    next_op.reset_func(Tuple().add('eid', curr_epoch_ref))
                curr_epoch_ref += 1

            new_tup = key.add('eid', curr_epoch)

            # Check for match in other table
            if new_tup in other_table:
                other_vals = other_table[new_tup]
                del other_table[new_tup]
                
                # Merge tuples
                merged_tup = new_tup.union(vals).union(other_vals)
                next_op.next_func(merged_tup)
            else:
                curr_table[new_tup] = vals

        def join_reset(tup: Tuple):
            nonlocal curr_epoch_ref
            curr_epoch = tup.get('eid')

            # Advance epochs
            while curr_epoch > curr_epoch_ref:
                if other_epoch_ref > curr_epoch_ref:
                    next_op.reset_func(Tuple().add('eid', curr_epoch_ref))
                curr_epoch_ref += 1

        return Operator(next_func=join_next, reset_func=join_reset)

    left_op = handle_join_side(
        left_table, right_table, 
        left_epoch, right_epoch, 
        left_extractor
    )
    right_op = handle_join_side(
        right_table, left_table, 
        right_epoch, left_epoch, 
        right_extractor
    )

    return left_op, right_op

def distinct_operator(groupby_keys: List[str], next_op: Operator) -> Operator:
    seen_keys = set()

    def distinct_next(tup: Tuple):
        grouping_key = tuple(tup.get(k) for k in groupby_keys)
        if grouping_key not in seen_keys:
            seen_keys.add(grouping_key)
            next_op.next_func(tup)

    def distinct_reset(reset_tup: Tuple):
        seen_keys.clear()
        next_op.reset_func(reset_tup)

    return Operator(next_func=distinct_next, reset_func=distinct_reset)

# Utility functions
def string_of_mac(mac_bytes: bytes) -> str:
    return ':'.join(f'{b:02x}' for b in mac_bytes)

def tcp_flags_to_strings(flags: int) -> str:
    tcp_flags = {
        'FIN': 1 << 0, 'SYN': 1 << 1, 'RST': 1 << 2,
        'PSH': 1 << 3, 'ACK': 1 << 4, 'URG': 1 << 5,
        'ECE': 1 << 6, 'CWR': 1 << 7
    }
    return '|'.join(flag for flag, value in tcp_flags.items() if flags & value)

# Reduction functions
def counter(current_val, _):
    if current_val == OpResult.EMPTY:
        return 1
    elif isinstance(current_val, int):
        return current_val + 1
    return current_val

def sum_ints(search_key):
    def reducer(current_val, tup):
        if current_val == OpResult.EMPTY:
            return 0
        elif isinstance(current_val, int):
            val = tup.get(search_key)
            return current_val + (val if val is not None else 0)
        return current_val
    return reducer

# Example query implementations
def ident(next_op: Operator) -> Operator:
    return map_operator(
        lambda tup: Tuple({k: v for k, v in tup.items() 
                           if k not in ['eth.src', 'eth.dst']}), 
        next_op
    )

def tcp_new_cons(next_op: Operator) -> Operator:
    threshold = 40
    return (
        epoch_operator(1.0, "eid", 
        filter_operator(
            lambda tup: (tup.get('ipv4.proto') == 6 and 
                         tup.get('l4.flags') == 2),
            groupby_operator(
                ['ipv4.dst'], 
                counter, 
                "cons", 
                filter_operator(
                    lambda tup: tup.get('cons') >= threshold, 
                    next_op
                )
            )
        ))
    )
# Continuing from the previous implementation...

def ssh_brute_force(next_op: Operator) -> Operator:
    threshold = 40
    return (
        epoch_operator(1.0, "eid",
        filter_operator(
            lambda tup: (tup.get('ipv4.proto') == 6 and 
                         tup.get('l4.dport') == 22),
            distinct_operator(
                ['ipv4.src', 'ipv4.dst', 'ipv4.len'],
                groupby_operator(
                    ['ipv4.dst', 'ipv4.len'], 
                    counter, 
                    "srcs", 
                    filter_operator(
                        lambda tup: tup.get('srcs') >= threshold, 
                        next_op
                    )
                )
            )
        ))
    )

def super_spreader(next_op: Operator) -> Operator:
    threshold = 40
    return (
        epoch_operator(1.0, "eid",
        distinct_operator(
            ['ipv4.src', 'ipv4.dst'],
            groupby_operator(
                ['ipv4.src'], 
                counter, 
                "dsts", 
                filter_operator(
                    lambda tup: tup.get('dsts') >= threshold, 
                    next_op
                )
            )
        ))
    )

def port_scan(next_op: Operator) -> Operator:
    threshold = 40
    return (
        epoch_operator(1.0, "eid",
        distinct_operator(
            ['ipv4.src', 'l4.dport'],
            groupby_operator(
                ['ipv4.src'], 
                counter, 
                "ports", 
                filter_operator(
                    lambda tup: tup.get('ports') >= threshold, 
                    next_op
                )
            )
        ))
    )

def ddos(next_op: Operator) -> Operator:
    threshold = 45
    return (
        epoch_operator(1.0, "eid",
        distinct_operator(
            ['ipv4.src', 'ipv4.dst'],
            groupby_operator(
                ['ipv4.dst'], 
                counter, 
                "srcs", 
                filter_operator(
                    lambda tup: tup.get('srcs') >= threshold, 
                    next_op
                )
            )
        ))
    )

def syn_flood_sonata(next_op: Operator) -> List[Operator]:
    threshold = 3
    epoch_dur = 1.0

    def syns(next_op: Operator) -> Operator:
        return (
            epoch_operator(epoch_dur, "eid",
            filter_operator(
                lambda tup: (tup.get('ipv4.proto') == 6 and 
                             tup.get('l4.flags') == 2),
                groupby_operator(
                    ['ipv4.dst'], 
                    counter, 
                    "syns", 
                    next_op
                )
            ))
        )

    def synacks(next_op: Operator) -> Operator:
        return (
            epoch_operator(epoch_dur, "eid",
            filter_operator(
                lambda tup: (tup.get('ipv4.proto') == 6 and 
                             tup.get('l4.flags') == 18),
                groupby_operator(
                    ['ipv4.src'], 
                    counter, 
                    "synacks", 
                    next_op
                )
            ))
        )

    def acks(next_op: Operator) -> Operator:
        return (
            epoch_operator(epoch_dur, "eid",
            filter_operator(
                lambda tup: (tup.get('ipv4.proto') == 6 and 
                             tup.get('l4.flags') == 16),
                groupby_operator(
                    ['ipv4.dst'], 
                    counter, 
                    "acks", 
                    next_op
                )
            ))
        )

    # Complex join logic
    def join_ops(next_op: Operator) -> List[Operator]:
        def left_extractor(tup: Tuple) -> Tuple:
            return (
                Tuple({'host': tup.get('ipv4.dst')}),
                Tuple({'syns+synacks': tup.get('syns')})
            )

        def right_extractor(tup: Tuple) -> Tuple:
            return (
                Tuple({'host': tup.get('ipv4.src')}),
                Tuple({'acks': tup.get('acks')})
            )

        join_op1, join_op2 = join_operator(left_extractor, right_extractor, next_op)

        # Additional map and filter operations
        def transform(tup: Tuple) -> Tuple:
            syns_synacks = tup.get('syns+synacks')
            acks = tup.get('acks')
            return tup.add('syns+synacks-acks', syns_synacks - acks)

        filtered_join = filter_operator(
            lambda tup: tup.get('syns+synacks-acks') >= threshold,
            map_operator(transform, join_op1)
        )

        return [syns(join_op1), synacks(join_op2), acks(filtered_join)]

    return join_ops(next_op)

def completed_flows(next_op: Operator) -> List[Operator]:
    threshold = 1
    epoch_dur = 30.0

    def syns(next_op: Operator) -> Operator:
        return (
            epoch_operator(epoch_dur, "eid",
            filter_operator(
                lambda tup: (tup.get('ipv4.proto') == 6 and 
                             tup.get('l4.flags') == 2),
                groupby_operator(
                    ['ipv4.dst'], 
                    counter, 
                    "syns", 
                    next_op
                )
            ))
        )

    def fins(next_op: Operator) -> Operator:
        return (
            epoch_operator(epoch_dur, "eid",
            filter_operator(
                lambda tup: (tup.get('ipv4.proto') == 6 and 
                             (tup.get('l4.flags') & 1) == 1),
                groupby_operator(
                    ['ipv4.src'], 
                    counter, 
                    "fins", 
                    next_op
                )
            ))
        )

    def join_ops(next_op: Operator) -> List[Operator]:
        def left_extractor(tup: Tuple) -> Tuple:
            return (
                Tuple({'host': tup.get('ipv4.dst')}),
                Tuple({'syns': tup.get('syns')})
            )

        def right_extractor(tup: Tuple) -> Tuple:
            return (
                Tuple({'host': tup.get('ipv4.src')}),
                Tuple({'fins': tup.get('fins')})
            )

        join_op1, join_op2 = join_operator(left_extractor, right_extractor, next_op)

        # Additional map and filter operations
        def transform(tup: Tuple) -> Tuple:
            syns = tup.get('syns')
            fins = tup.get('fins')
            return tup.add('diff', syns - fins)

        filtered_join = filter_operator(
            lambda tup: tup.get('diff') >= threshold,
            map_operator(transform, join_op1)
        )

        return [syns(join_op1), fins(join_op2)]

    return join_ops(next_op)

def dump_tuple(output_stream=sys.stdout):
    def next_func(tup: Tuple):
        print(', '.join(f'"{k}": {v}' for k, v in tup.items()), file=output_stream)

    return Operator(next_func=next_func, reset_func=lambda _: None)

def dump_as_csv(output_stream=sys.stdout, header=True, static_field=None):
    first_row = [True]
    writer = csv.writer(output_stream)

    def next_func(tup: Tuple):
        if first_row[0] and header:
            # Write header
            if static_field:
                writer.writerow([static_field[0]] + list(tup.keys()))
            else:
                writer.writerow(list(tup.keys()))
            first_row[0] = False

        # Write data row
        row = []
        if static_field:
            row.append(static_field[1])
        row.extend(str(v) for v in tup.values())
        writer.writerow(row)

    return Operator(next_func=next_func, reset_func=lambda _: None)

def main():
    # Example comprehensive query setup
    queries = [
        ident,
        tcp_new_cons,
        ssh_brute_force,
        super_spreader,
        port_scan,
        ddos
    ]

    # More comprehensive test data generation
    tuples = []
    for i in range(20):
        tup = Tuple()
        tup = tup.add('time', float(i))
        tup = tup.add('ipv4.proto', 6)
        tup = tup.add('l4.flags', 2)
        tup = tup.add('l4.dport', 22)
        tup = tup.add('ipv4.dst', ipaddress.IPv4Address('127.0.0.1'))
        tup = tup.add('ipv4.src', ipaddress.IPv4Address('192.168.1.1'))
        tup = tup.add('ipv4.len', 60)
        tuples.append(tup)

    # Run queries with multiple output options
    for tup in tuples:
        for query in queries:
            # Dump to console and CSV
            query(dump_tuple()).next_func(tup)
            query(dump_as_csv(sys.stdout)).next_func(tup)

if __name__ == "__main__":
    main()