
from typing import Iterator, TextIO, ItemsView, Callable, Union
from abc import ABC
from dataclasses import dataclass
from ipaddress import IPv4Address
from collections import deque
from functools import partial
from builtins_translated import Operator

type op_result_type = Union[float, int, IPv4Address, bytearray, None]

@dataclass
class Op_result(ABC):
    val: op_result_type = None

    def __hash__(self): 
        return hash(self.val)

@dataclass
class Float(Op_result):
    val: float

@dataclass
class Int(Op_result):
    val: int

@dataclass
class Ipv4(Op_result):
    val: IPv4Address

@dataclass
class MAC(Op_result):
    val: bytearray

@dataclass
class Empty(Op_result):
    val: None = None


class PacketHeaders:
    def __init__(self, data: dict[str, Op_result] | None=None):
        self.headers: dict[str, 'Op_result'] | None = data if data is not None else {}

    def __iter__(self):
        return iter(self.headers)
    
    def __getitem__(self, key: str):
        if not isinstance(key, str):
            raise TypeError("Packet keys may only be strings.")
        else:
            return self.headers[key]
    
    def __setitem__(self, key: str, val: Op_result):
        if not isinstance(key, str):
            raise TypeError("Packet keys may only be strings.")
        elif not isinstance(val, Op_result):
            raise TypeError("Packet values may only be Op_results.")
        else: 
            self.headers[key] = val
        return self
    
    def items(self) -> ItemsView[str, Op_result]:
        return self.headers.items()
    
    def __hash__(self):
        return hash(frozenset(self.headers.items()))
    
    def __or__(self, other: 'PacketHeaders') -> 'PacketHeaders':
        if not isinstance(other, PacketHeaders):
            raise TypeError("Packets may only be unioned with other Packets.")
        return PacketHeaders(self.headers.__or__(other.headers))
    
    def get(self, key: str, default=None):
        if not isinstance(key, str):
            raise TypeError("Packet keys may only be strings.")
        return self.headers.get(key, default)
    
    def get_mapped_int(self, key: str) -> int:
        if not isinstance(key, str):
            raise TypeError("Packet keys may only be strings.")
        return int_of_op_result(self.headers[key])
    
    def get_mapped_float(self, key: str) -> float:
        if not isinstance(key, str):
            raise TypeError("Packet keys may only be strings.")
        return float_of_op_result(self.headers[key])
    
    def string_of_packet(self) -> str:
        return "".join(f'"{key}" => {string_of_op_result(val)}, ' 
                   for key, val in self.headers)
        
    def packet_of_list(self, packet_list: deque[tuple[str, Op_result]]) -> "PacketHeaders":
        self.headers = {key: val for key, val in list(packet_list)}

    def dump_packet(self, outc: TextIO) -> None:
        print(self.string_of_packet())

    def lookup_int(self, key: str) -> int:
        return int_of_op_result(self.headers[key])

    def lookup_float(self, key: str) -> float:
        return float_of_op_result(self.headers[key])

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

def int_of_op_result(input: Op_result) -> int:
    match input.kind:
        case Op_result.INT: return input.val
        case _:
            raise TypeError("Trying to extract int from non-int result")

def float_of_op_result(input: Op_result) -> float:
    match input.kind:
        case Op_result.FLOAT: return input.val
        case _:
            raise TypeError("Trying to extract float from non-float result")
        
def string_of_op_result(input: Op_result) -> str:
    match input.kind:
        case Op_result.FLOAT | Op_result.INT:
            return f"{input.val}"
        case Op_result.IPV4:
            return str(IPv4Address(input.val))
        case Op_result.MAC:
            return string_of_mac(input.val)
        case Op_result.Empty:
            "Empty"
        case _:
            raise RuntimeError("Reached unreachable code")
        
