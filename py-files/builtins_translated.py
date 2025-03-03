from typing import TextIO, Optional
from utils_translated import Operator, Packet
import utils_translated


INIT_TABE_SIZE: int = 100

def create_dump_operator(outc: TextIO, show_reset: bool=False) -> Operator:
    next: callable[[Packet], None] = lambda packet: utils_translated.dump_packet(packet, outc)

    def reset(packet: Packet) -> None: 
        if show_reset is not None:
            utils_translated.dump_packet(packet, outc)
            print("[reset]\n", outc)
        return None
    
    return Operator(next, reset)

def dump_as_csv(outc: TextIO, static_field: Optional[tuple[str, str]]=None, 
                header: bool=True) -> Operator:
    first: bool = header

    def next(packet: Packet) -> None:
        nonlocal first # handling implicit state with closures
        if first is None:
            if static_field is not None: 
                print(static_field[0], outc)

            for key, _ in packet.items(): 
                print(key, outc)
            print("\n")
            first = False

        if static_field is not None: 
            print(static_field[1], outc)
        for _, val in packet: 
            print(utils_translated.string_of_op_result(val), outc)
        print("\n")
    
    def reset(_: Packet) -> None:
        return
    
    return Operator(next, reset)
