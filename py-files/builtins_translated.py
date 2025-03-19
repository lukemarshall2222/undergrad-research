from typing import TextIO, Optional, Callable
from utils_translated import *
import utils_translated
from copy import deepcopy

INIT_TABE_SIZE: int = 100

type next_func = Callable[[PacketHeaders], None]
type reset_func = Callable[[PacketHeaders], None]
type grouping_func = Callable[[PacketHeaders], PacketHeaders]
type reduction_func = Callable[[Op_result, PacketHeaders], Op_result]
type key_extractor = Callable[[PacketHeaders], tuple[PacketHeaders, PacketHeaders]]

def create_dump_operator(outc: TextIO, show_reset: bool=False) -> Operator:
    next: Callable[[PacketHeaders], None] = lambda packet: utils_translated.dump_packet(packet, outc)

    def reset(packet: PacketHeaders) -> None: 
        if show_reset is not None:
            utils_translated.dump_packet(packet, outc)
            print("[reset]\n", file=outc)
        return None
    
    return Operator(next, reset)

def dump_as_csv(outc: TextIO, static_field: Optional[tuple[str, str]]=None, 
                header: bool=True) -> Operator:
    first: bool = header

    def next(packet: PacketHeaders) -> None:
        nonlocal first # handling implicit state with closures
        if first is None:
            if static_field is not None: 
                print(static_field[0], file=outc)

            for key, _ in packet.items(): 
                print(key, file=outc)
            print("\n", file=outc)
            first = False

        if static_field is not None: 
            print(static_field[1], outc)
        assert(isinstance(packet, PacketHeaders))
        for _, val in packet.items(): 
            print(string_of_op_result(val), file=outc)
        print("\n", file=outc)

    reset: reset_func = lambda _: None
    
    return Operator(next, reset)

def dump_walts_csv(filename: str) -> Operator:
    first: bool = True

    def next(packet: PacketHeaders) -> None:
        file_contents: str = (
            f"{string_of_op_result(packet["src_ip"])},"
            f"{string_of_op_result(packet["dst_ip"])}"
            f"{string_of_op_result(packet["src_l4_port"])}"
            f"{string_of_op_result(packet["dst_l4_port"])}"
            f"{string_of_op_result(packet["packet_count"])}"
            f"{string_of_op_result(packet["byte_count"])}"
            f"{string_of_op_result(packet["epoch_id"])}",
        )
        if first:
            print(file_contents)
        else:
            with open(filename, "a") as outc:
                print(file_contents, file=outc)
    
    reset: reset_func = lambda _: None
    
    return Operator(next, reset)

def get_ip_or_zero(input: str) -> Op_result:
    match input:
        case "0":
            return Int(0)
        case s:
            return Ipv4(IPv4Address(s))

def read_walts_csv(filenames: list[str], ops: list[Operator], 
                   epoc_id_key="eid") -> None:
    pass

def create_meta_meter(name: str, outc: TextIO, next_op: Operator, 
                      static_field: str | None=None) -> Operator: 
    epoch_count: int = 0
    packet_count: int = 0

    def next(packet: PacketHeaders) -> None:
        nonlocal packet_count
        packet_count += 1
        next_op.next(packet)
    
    def reset(packet: PacketHeaders) -> None:
        nonlocal epoch_count
        print(epoch_count, name, packet_count, 
              static_field if static_field is not None else "",
              file=outc)
        packet_count = 0
        epoch_count += 1
        next_op.reset(packet)

    return Operator(next, reset)

def create_epoch_operator(epoch_width: float, key_out: str, 
                          next_op: Operator) -> Operator:
    epoch_boundary: float = 0.0
    eid: int = 0

    def next(packet: PacketHeaders) -> None:
        nonlocal epoch_boundary, eid
        time: float = float_of_op_result(packet["time"])
        if epoch_boundary == 0.0:
            epoch_boundary = time + epoch_width
        while time >= epoch_boundary:
            next_op.reset({key_out: Int(eid)})
            epoch_boundary = epoch_boundary + epoch_width
            eid += 1
        next_op.next(packet.__setitem__
                     (key_out, Int(eid)))
        
    def reset(_ : PacketHeaders) -> None:
        nonlocal epoch_boundary, eid
        next_op.reset({key_out: Int(eid)})
        epoch_boundary = 0.0
        eid = 0

    return Operator(next, reset)

def create_filter_operator(f: Callable[[PacketHeaders], bool], 
                           next_op: Operator) -> Operator:
    
    def next(packet: PacketHeaders) -> None:
        if f(packet):
            next_op.next(packet)
    
    reset: reset_func = lambda packet: next_op.reset(packet)

    return Operator(next, reset)

def key_geq_int(key: str, threshold: int, packet: PacketHeaders) -> bool:
    return int_of_op_result(packet[key]) >= threshold

def create_map_operator(f: Callable[[PacketHeaders], PacketHeaders], next_op: Operator) -> Operator:
    next: next_func = lambda packet: next_op.next(f(packet))
    reset: reset_func = lambda packet: next_op.reset(packet)

    return Operator(next, reset)

def create_groupby_operator(group_packet: grouping_func, reduce: reduction_func,
                            out_key: str, next_op: Operator) -> Operator:
    h_tbl: dict[PacketHeaders, Op_result] = {}
    reset_counter: int = 0

    def next(packet: PacketHeaders) -> None:
        grouping_key: PacketHeaders = group_packet(packet)
        match h_tbl.get(grouping_key, None):
            case None:
                h_tbl[grouping_key] = reduce(Empty(), packet)
            case val: h_tbl[grouping_key] = reduce(val, packet)
        
    def reset(packet: PacketHeaders) -> None:
        nonlocal reset_counter
        reset_counter += 1
        for packt, op_res in h_tbl.items():
            # keeps the original val for a given key if in both Packets:
            unioned_packet = packt | packet
            next_op.next(unioned_packet.__setitem__(out_key, op_res))
        next_op.reset(packet)
        h_tbl.clear()

    return Operator(next, reset)

def filter_groups(incl_keys: list[str], packet: PacketHeaders) -> PacketHeaders:
    incl_keys_set: set[str] = set(incl_keys)
    return PacketHeaders({key: val for key, val in packet.items() 
                            if key in incl_keys_set})

def single_group(_: PacketHeaders) -> PacketHeaders:
    return PacketHeaders()

def counter(val: Op_result, _: PacketHeaders) -> Op_result:
    match val:
        case Empty():
            return Int(1)
        case Int():
            return int_of_op_result(val) + 1
        case _:
            return val
        
def sum_ints(search_key: str, init_val: Op_result, packet: PacketHeaders) -> Op_result:
    match init_val:
        case Empty():
            return Int(1)
        case Int():
            match packet.get(search_key, None):
                case None:
                    raise KeyError("'sum_vals' function failed to find integer",
                                   f"value mapped to {search_key}")
                case val:
                    return Int(int_of_op_result(val)+1)
        case _:
            return init_val
        
def create_distinct_operator(group_packet: grouping_func, next_op: Operator) -> Operator:
    h_tbl: dict[PacketHeaders, bool] = {}
    reset_counter: int = 0

    def next(packet: PacketHeaders) -> None:
        # assert(isinstance(packet.data, dict))
        grouping_key: PacketHeaders = group_packet(packet)
        h_tbl[grouping_key] = True

    def reset(packet: PacketHeaders) -> None:
        nonlocal reset_counter
        reset_counter += 1
        for key, _ in h_tbl.items():
            next_op.next(key | packet) # unioned packet
        next_op.reset(packet)
        h_tbl.clear()

    return Operator(next, reset)

def create_split_operator(l: Operator, r: Operator) -> Operator:
    def next(packet: PacketHeaders) -> None:
        l.next(packet)
        r.next(packet)

    def reset(packet: PacketHeaders) -> None:
        l.reset(packet)
        r.reset(packet)

    return Operator(next, reset)

def create_join_operator(left_extractor: key_extractor, right_extractor: key_extractor,
                          next_op: Operator, eid_key: str="eid") -> tuple[Operator, Operator]:
    h_tbl1: dict[PacketHeaders, PacketHeaders] = {}
    h_tbl2: dict[PacketHeaders, PacketHeaders] = {}
    left_curr_epoch = 0
    right_curr_epoch = 0

    def handle_join_side(curr_h_tbl: dict[PacketHeaders, PacketHeaders], other_h_tbl: dict[PacketHeaders, PacketHeaders], 
                         curr_epoch: int, other_epoch: int, extractor: key_extractor) -> Operator:
        def next(packet: PacketHeaders) -> None:
            key_n_val: tuple[PacketHeaders, PacketHeaders] = extractor(packet)
            key, val = key_n_val
            curr_e: int = packet.get_mapped_int(eid_key)

            while curr_e > curr_epoch:
                if other_epoch > curr_epoch:
                    next_op.reset({eid_key, Int(curr_epoch+1)})
            
            new_packet: PacketHeaders = PacketHeaders(deepcopy(key.data).__setitem__
                                        (eid_key, Int(curr_e)))
            match other_h_tbl.get(new_packet, None):
                case None:
                    curr_h_tbl[new_packet] = val
                case packt:
                    del other_h_tbl[new_packet]
                    next_op.next(packt | val | new_packet)

        def reset(packet: PacketHeaders) -> None:
            nonlocal curr_epoch
            curr_e: int = packet.get_mapped_int(eid_key)
            while curr_e > curr_epoch:
                if other_epoch > curr_epoch:
                    next_op.reset({eid_key, Int(curr_epoch)})
                curr_epoch += 1
        
        return Operator(next, reset)
        
    return ( 
            handle_join_side(h_tbl1, h_tbl2, left_curr_epoch, right_curr_epoch, left_extractor),
            handle_join_side(h_tbl2, h_tbl1, right_curr_epoch, left_curr_epoch, right_extractor)
           )

def rename_filtered_keys(renaming_pairs: list[tuple[str, str]], in_packet: PacketHeaders) -> PacketHeaders:
    new_packet: PacketHeaders = PacketHeaders()
    return [ new_packet.__setitem__(new, in_packet[old]) 
                for new, old in renaming_pairs if old in in_packet ]

def filter_helper(proto: int, flags: int, packet: PacketHeaders) -> bool:
    return packet.get_mapped_int("ipv4.proto") == proto and \
            packet.get_mapped_int("l4.flags") == flags
 
    
    
