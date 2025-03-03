
from typing import Optional, Iterator, TextIO, ItemsView
from abc import ABC
from enum import Enum
from dataclasses import dataclass
from ipaddress import IPv4Address
from collections import deque
from construct import Struct, Bytes, Int16ub, Int8ub, Int32ub
import struct




class res_kind(Enum):
    FLOAT = "Float"
    INT = "int"
    IPV4 = "IPv4"
    MAC = "MAC"
    Empty = None

@dataclass
class Op_result(ABC):
    def __init__(self, kind: res_kind, val: float | int | IPv4Address | bytearray | None=None):
        self.kind = kind
        self.val = val


class Packet:
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
    
    def items(self) -> ItemsView[str, Op_result]:
        return self.data.items()


class Operator(ABC):
    def __init__(self, next: callable[[Packet], None], 
                 reset: callable[[Packet], None]):
        self.next = next
        self.reset = reset
    def next(tup: Packet) -> None:
        raise NotImplementedError("next method not implemented in base class.")
    def reset(tup: Packet) -> None:
        raise NotImplementedError("reset method not implemented in base class.")

class Op_to_op:
    def __init__(self, func: callable[Operator, Operator]):
        self.func = func
    def __rshift__(self, op: Operator) -> Operator:
        if not isinstance(op, Operator):
            raise TypeError(f"Can only apply an operator 
                                argument to an Op_to_op.")
        return self.func(op)

class Op_to_op_tup(Op_to_op):
    def __init__(self, func: callable[Operator, Operator]):
        super().__init__(func)
    def __rshift__(self, op: Operator) -> tuple[Operator, Operator]:
        if not isinstance(op, Operator):
            raise TypeError(f"Can only apply an operator 
                                argument to an Op_to_op.")
        return self.func(op)

def string_of_mac(buf: bytearray) -> str:
    return f"{buf[0]: .2f}:{buf[1]: .2f}:{buf[3]: .2f}:
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
        case res_kind.INT: return input.val
        case _:
            raise TypeError("Trying to extract int from non-int result")

def float_of_op_result(input: Op_result) -> float:
    match input.kind:
        case res_kind.FLOAT: return input.val
        case _:
            raise TypeError("Trying to extract float from non-float result")
        
def string_of_op_result(input: Op_result) -> str:
    match input.kind:
        case res_kind.FLOAT | res_kind.INT:
            return f"{input.val}"
        case res_kind.IPV4:
            return str(IPv4Address(input.val))
        case res_kind.MAC:
            return string_of_mac(input.val)
        case res_kind.Empty:
            "Empty"
        case _:
            raise RuntimeError("Reached unreachable code")
        
def string_of_packet(input_packet: Packet) -> str:
    return "".join(f'"{key}" => {string_of_op_result(val)}, ' 
                   for key, val in input_packet)
        
def packet_of_list(packet_list: deque[tuple[str, Op_result]]) -> Packet:
    return Packet({key: val for key, val in list(packet_list)})

def dump_packet(outc: TextIO, packet: Packet) -> None:
    print(string_of_packet(packet), outc)

def lookup_int(key: str, packet: Packet) -> int:
    return int_of_op_result(packet[key])

def lookup_float(key: str, packet: Packet) -> float:
    return float_of_op_result(packet[key])

ethernet: Struct = Struct(
    "dst" / Bytes(6),
    "src" / Bytes(6),
    "ethertype" / Int16ub,
)

ipv4: Struct = Struct(
    "hlen_version" / Int8ub,
    "tos" / Int8ub,
    "len" / Int16ub,
    "id" / Int16ub,
    "off" / Int16ub,
    "ttl" / Int8ub,
    "proto" / Int8ub,
    "csum" / Int16ub,
    "src" / Int32ub,
    "dst" / Int32ub,
)

tcp: Struct = Struct(
    "src_port" / Int16ub,
    "dst_port" / Int16ub,
    "seqnum" / Int32ub,
    "acknum" / Int32ub,
    "offset_flags" / Int16ub,
    "window" / Int16ub,
    "checksum" / Int16ub,
    "urg" / Int16ub,
)

udp: Struct = Struct(
    "src_port" / Int16ub,
    "dst_port" / Int16ub,
    "length" / Int16ub,
    "checksum" / Int16ub,
)

def parse_ethernet(eth_struct: Struct, data: bytes, packet: Packet) -> Packet:
    dst, src, ethertype = eth_struct.parse(data).values()
    packet["eth.src"] = Op_result(res_kind.MAC, src)
    packet["eth.dst"] = Op_result(res_kind.MAC, dst)
    packet["eth.ethertype"] = Op_result(res_kind.INT, ethertype)
    return packet

def parse_ipv4(ipv4_struct: Struct, data: bytes, packet: Packet) -> Packet:
    hlen, proto, len, src, dst = ipv4_struct.parse(data).values()
    packet["ipv4.hlen"] = Op_result(res_kind.INT, hlen)
    packet["ipv4.proto"] = Op_result(res_kind.INT, proto)
    packet["ipv4.len"] = Op_result(res_kind.INT, len)
    packet["ipv4.src"] = Op_result(res_kind.IPV4, src)
    packet["ipv4.dst"] = Op_result(res_kind.IPV4, dst)
    return packet

def parse_tcp(tcp_struct: Struct, data: bytes, packet: Packet) -> Packet:
    src_port, dst_port, offset_flags = tcp_struct.parse(data).values()
    packet["l4.sport"] = Op_result(res_kind.INT, src_port)
    packet["l4.dport"] = Op_result(res_kind.INT, dst_port)
    packet["l4.flags"] = Op_result(res_kind.INT, offset_flags & 0xFF)
    return packet

def parse_udp(udp_struct: Struct, data: bytes, packet: Packet) -> Packet:
    src_port, dst_port = udp_struct.parse(data).values()
    packet["l4.sport"] = Op_result(res_kind.INT, src_port)    
    packet["l4.dport"] = Op_result(res_kind.INT, dst_port)
    packet["l4.flags"] = Op_result(res_kind.INT, 0)
    return packet

def set_default_l4_fields(packet: Packet) -> Packet:
    packet["l4.sport"] = Op_result(res_kind.INT, 0)    
    packet["l4.dport"] = Op_result(res_kind.INT, 0)
    packet["l4.flags"] = Op_result(res_kind.INT, 0)
    return packet

def get_ip_version(eth_struct: bytearray, offset: int) -> int:
    return (eth_struct[offset] & 0xF0) >> 4

def parse_pkt(network: int, pcap_header, metadata: Struct, payload: Struct):
    new_packet: Packet = Packet()
    ts_sec, ts_usec = struct.unpack("=II", metadata)
    new_packet["time"] = Op_result(res_kind.FLOAT, (float(ts_sec) + float(ts_usec) / 1000000))

    def helper(packet_metadata: Packet, offset: int):
        match network:
            case 1:
                parse_ethernet(payload, time_metadata)

    return
                    
