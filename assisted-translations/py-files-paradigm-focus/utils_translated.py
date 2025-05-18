
from typing import TextIO, ItemsView
from abc import ABC
from dataclasses import dataclass
from ipaddress import IPv4Address
from collections import deque

type op_result_type = float | int | IPv4Address | bytearray | None

@dataclass
class Op_result(ABC):
    val: op_result_type

    def __hash__(self): 
        return hash(self.val)

@dataclass
class Float(Op_result):
    val: float

    def __hash__(self): 
        return hash(self.val)

@dataclass
class Int(Op_result):
    val: int

    def __hash__(self): 
        return hash(self.val)

@dataclass
class Ipv4(Op_result):
    val: IPv4Address

    def __hash__(self): 
        return hash(self.val)

@dataclass
class MAC(Op_result):
    val: bytearray

    def __hash__(self): 
        return hash(self.val)

@dataclass
class Empty(Op_result):
    val: None = None

    def __hash__(self): 
        return hash(self.val)


class PacketHeaders:
    def __init__(self, data: dict[str, Op_result] | None=None):
        self.headers: dict[str, 'Op_result'] = data if data is not None else {}

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
                   for key, val in self.headers.items())
        
    def packet_of_list(self, packet_list: deque[tuple[str, Op_result]]):
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
    tcp_flags = [ 
        "FIN", "SYN", "RST", "PSH", 
        "ACK", "URG", "ECE", "CWR"
    ]
    return "|".join(
        flag for i, flag in enumerate(tcp_flags)
        if flags & (1 << i)
    )


def int_of_op_result(input: Op_result) -> int:
    match input:
        case Int(): return input.val
        case _:
            raise TypeError("Trying to extract int from non-int result")

def float_of_op_result(input: Op_result) -> float:
    match input:
        case Float(): return input.val
        case _:
            raise TypeError("Trying to extract float from non-float result")
        
def string_of_op_result(input: Op_result) -> str:
    match input:
        case Float() | Int():
            return str(input.val)
        case Ipv4():
            return str(IPv4Address(input.val))
        case MAC():
            return string_of_mac(input.val)
        case Empty():
            "Empty"
        case _:
            raise RuntimeError("Reached unreachable code")
    
    return ""
        
