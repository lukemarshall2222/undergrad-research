
from typing import Iterator, TextIO, ItemsView, Callable, Union
from abc import ABC
from dataclasses import dataclass
from ipaddress import IPv4Address
from collections import deque
from functools import partial

type op_result_type = Union[float, int, IPv4Address, bytearray, None]

@dataclass
class Op_result(ABC):
    val: op_result_type

    def __hash__(self): 
        return hash(self.val)

@dataclass
class Float(Op_result):
    val: float

@dataclass
class Int(Op_result):
    val: int

    def __hash__(self): 
        return hash(self.val)

@dataclass
class Ipv4(Op_result):
    val: IPv4Address

    def __hash__(self):
        return hash(self.val.exploded)

@dataclass
class MAC(Op_result):
    val: bytearray

    def __hash__(self):
        return hash(bytes(self.val))

@dataclass
class Empty(Op_result):
    val: None = None


class PacketHeaders:
    def __init__(self, data: dict[str, Op_result] | None=None):
        self.data: dict[str, 'Op_result'] | None = data if data is not None else {}

    def __iter__(self):
        return iter(self.data)
    
    def __getitem__(self, key: str):
        if not isinstance(key, str):
            raise TypeError("Packet keys may only be strings.")
        else:
            return self.data[key]
    
    def __setitem__(self, key: str, val: Op_result):
        if not isinstance(key, str):
            raise TypeError("Packet keys may only be strings.")
        elif not isinstance(val, Op_result):
            raise TypeError("Packet values may only be Op_results.")
        else: 
            self.data[key] = val
        return self
    
    def items(self) -> ItemsView[str, Op_result]:
        return self.data.items()
    
    def __hash__(self):
        return hash(frozenset(self.data.items()))
    
    def __or__(self, other: 'PacketHeaders') -> 'PacketHeaders':
        if not isinstance(other, PacketHeaders):
            raise TypeError("Packets may only be unioned with other Packets.")
        return PacketHeaders(self.data.__or__(other.data))
    
    def get(self, key: str, default=None):
        if not isinstance(key, str):
            raise TypeError("Packet keys may only be strings.")
        return self.data.get(key, default)
    
    def get_mapped_int(self, key: str) -> int:
        if not isinstance(key, str):
            raise TypeError("Packet keys may only be strings.")
        return int_of_op_result(self.data[key])
    
    def get_mapped_float(self, key: str) -> float:
        if not isinstance(key, str):
            raise TypeError("Packet keys may only be strings.")
        return float_of_op_result(self.data[key])


class Operator(ABC):
    def __init__(self, next: Callable[[PacketHeaders], None], 
                 reset: Callable[[PacketHeaders], None]):
        self.next = next
        self.reset = reset
    def next(packet: PacketHeaders) -> None:
        raise NotImplementedError("next method not implemented in base class.")
    def reset(packet: PacketHeaders) -> None:
        raise NotImplementedError("reset method not implemented in base class.")

class Op_to_op:
    def __init__(self, func: Callable[[any], Operator], *args):
        self.func = partial(func, *args)
    def __rshift__(self, op: Operator) -> Operator:
        if not isinstance(op, Operator):
            raise TypeError(f"Can only apply an operator \
                                argument to an Op_to_op.")
        return self.func(op)

class Op_to_op_tup(Op_to_op):
    def __init__(self, func: Callable[[any], Operator], *args):
        self.func = partial(func, *args)
    def __rshift__(self, op: Operator) -> tuple[Operator, Operator]:
        if not isinstance(op, Operator):
            raise TypeError(f"Can only apply an operator \
                                argument to an Op_to_op_tup.")
        return self.func(op)

def string_of_mac(buf: bytearray) -> str:
    return f"{buf[0]: .2f}:{buf[1]: .2f}:{buf[3]: .2f}:\
                {buf[4]: .2f}:{buf[5]: .2f}"

def tcp_flags_to_strings(flags: int) -> str:
    tcp_flags: list[str] = [ 
                            "FIN", "SYN", "RST", "PSH", 
                            "ACK", "URG", "ECE", "CWR", 
                           ]
    def tcp_flags_map() -> Iterator[list[tuple[str, float]]]:
        for i, flag in enumerate(tcp_flags):
            yield (flag, 1 << i)
    return "|".join(flag for flag, val in tcp_flags_map() 
                    if (flags & val) == val)

def int_of_op_result(input: Int) -> int:
    match input:
        case Int(val=val): return val
        case _:
            raise TypeError("Trying to extract int from non-int result")

def float_of_op_result(input: Float) -> float:
    match input:
        case Float(val=val): return val
        case _:
            raise TypeError("Trying to extract float from non-float result")
        
def string_of_op_result(input: Op_result) -> str:
    match input:
        case Float(val=val) | Int(val=val) | Ipv4(val=val):
            return f"{val}"
        case MAC(val=val):
            return string_of_mac(val)
        case Empty():
            "Empty"
        case _:
            raise RuntimeError("Reached unreachable code")
        
def string_of_packet(input_packet: PacketHeaders) -> str:
    return "".join(f'"{key}" => {string_of_op_result(val)}, ' 
                   for key, val in input_packet)
        
def packet_of_list(packet_list: deque[tuple[str, Op_result]]) -> PacketHeaders:
    return PacketHeaders({key: val for key, val in list(packet_list)})

def dump_packet(outc: TextIO, packet: PacketHeaders) -> None:
    print(string_of_packet(packet), outc)

def lookup_int(key: str, packet: PacketHeaders) -> int:
    return int_of_op_result(packet[key])

def lookup_float(key: str, packet: PacketHeaders) -> float:
    return float_of_op_result(packet[key])

