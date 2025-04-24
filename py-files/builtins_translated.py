from typing import TextIO, Optional, Callable, Self
from types import MethodType
from utils_translated import *
from copy import deepcopy
from sys import stdout
from collections import namedtuple

type GroupingFunc = Callable[[PacketHeaders], PacketHeaders]
type ReductionFunc = Callable[[Op_result, PacketHeaders], Op_result]
type KeyExtractor = Callable[[PacketHeaders],
                             tuple[PacketHeaders, PacketHeaders]]
type QueryMethod = Callable[[PacketHeaders], None]
QueryMethods = namedtuple('QueryMethods', ['next', 'reset'])


class Query():
    def __init__(self, last_op: QueryMethods | None = None) -> Self:
        match last_op:
            case QueryMethods(next, reset):
                self.next = next
                self.reset = reset
            case None:
                self.dump(stdout)
            case catchall:
                print(f"Query must be instantiated with either a QueryMethods named tuple with fields \
                      next and reset, or with None, cannot use {catchall}")

    def next(self, headers: PacketHeaders) -> None:
        raise NotImplementedError("next method has not been assigned")

    def reset(self, headers: PacketHeaders) -> None:
        raise NotImplementedError("reset method has not been assigned")

    def dump(self, outc: TextIO, show_reset: bool = False) -> Self:
        next: QueryMethod = lambda packet: packet.dump_packet(outc)

        def reset(packet: PacketHeaders) -> None:
            if show_reset is not None:
                packet.dump_packet(outc)
                print("[reset]\n", file=outc)
            return None

        self.next = next
        self.reset = reset
        return self

    def dump_as_csv(self, outc: TextIO, static_field: Optional[tuple[str, str]] = None,
                    header: bool = True) -> Self:
        first: bool = header

        def next(packet: PacketHeaders) -> None:
            nonlocal first  # handling implicit state with closures
            if first is None:
                if static_field is not None:
                    print(static_field[0], file=outc)

                for key, _ in packet.items():
                    print(key, file=outc)
                print("\n", file=outc)
                first = False

            if static_field is not None:
                print(static_field[1], outc)
            assert (isinstance(packet, PacketHeaders))
            for _, val in packet.items():
                print(string_of_op_result(val), file=outc)
            print("\n", file=outc)

        reset: QueryMethod = lambda _: None

        self.next = next
        self.reset = reset
        return self

    def dump_as_waltz_csv(self, filename: str) -> Self:
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

        reset: QueryMethod = lambda _: None

        self.next = next
        self.reset = reset
        return self

    def meta_meter(self, name: str, outc: TextIO, static_field: str | None = None) -> Self:
        epoch_count: int = 0
        packet_count: int = 0
        curr_next = MethodType(self.next.__func__)
        curr_reset = MethodType(self.reset.__func__)

        def next(packet: PacketHeaders) -> None:
            nonlocal packet_count
            packet_count += 1
            curr_next(packet)

        def reset(packet: PacketHeaders) -> None:
            nonlocal epoch_count
            print(epoch_count, name, packet_count,
                  static_field if static_field is not None else "",
                  file=outc)
            packet_count = 0
            epoch_count += 1
            curr_reset(packet)

        self.next = next
        self.reset = reset
        return self

    def epoch(self, epoch_width: float, key_out: str) -> Self:
        epoch_boundary: float = 0.0
        eid: int = 0
        curr_next = MethodType(self.next.__func__)
        curr_reset = MethodType(self.reset.__func__)

        def next(packet: PacketHeaders) -> None:
            nonlocal epoch_boundary, eid
            time: float = float_of_op_result(packet["time"])
            if epoch_boundary == 0.0:
                epoch_boundary = time + epoch_width
            while time >= epoch_boundary:
                curr_reset({key_out: Int(eid)})
                epoch_boundary = epoch_boundary + epoch_width
                eid += 1
            curr_next(packet.__setitem__
                      (key_out, Int(eid)))

        def reset(_: PacketHeaders) -> None:
            nonlocal epoch_boundary, eid
            curr_reset({key_out: Int(eid)})
            epoch_boundary = 0.0
            eid = 0

        self.next = next
        self.reset = reset
        return self

    def filter(self, f: Callable[[PacketHeaders], bool]) -> Self:
        curr_next = MethodType(self.next.__func__)
        curr_reset = MethodType(self.reset.__func__)

        def next(packet: PacketHeaders) -> None:
            if f(packet):
                curr_next(packet)

        reset: QueryMethod = lambda packet: curr_reset(packet)

        self.next = next
        self.reset = reset
        return self

    def map(self, f: Callable[[PacketHeaders], PacketHeaders]) -> Self:
        curr_next = MethodType(self.next.__func__)
        curr_reset = MethodType(self.reset.__func__)

        next: QueryMethod = lambda packet: curr_next(f(packet))
        reset: QueryMethod = lambda packet: curr_reset(packet)

        self.next = next
        self.reset = reset
        return self

    def groupby(self, group_packet: GroupingFunc, reduce: ReductionFunc, out_key: str) -> Self:
        h_tbl: dict[PacketHeaders, Op_result] = {}
        reset_counter: int = 0
        curr_next = MethodType(self.next.__func__)
        curr_reset = MethodType(self.reset.__func__)

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
                curr_next(unioned_packet.__setitem__(out_key, op_res))
            curr_reset(packet)
            h_tbl.clear()

        self.next = next
        self.reset = reset
        return self

    def distinct(self, group_packet: GroupingFunc) -> Self:
        h_tbl: dict[PacketHeaders, bool] = {}
        reset_counter: int = 0
        curr_next = MethodType(self.next.__func__)
        curr_reset = MethodType(self.reset.__func__)

        def next(packet: PacketHeaders) -> None:
            grouping_key: PacketHeaders = group_packet(packet)
            h_tbl[grouping_key] = True

        def reset(packet: PacketHeaders) -> None:
            nonlocal reset_counter
            reset_counter += 1
            for key, _ in h_tbl.items():
                curr_next(key | packet)  # unioned packet
            curr_reset(packet)
            h_tbl.clear()

        self.next = next
        self.reset = reset
        return self

    def split(self, l: "Query", r: "Query") -> Self:

        def next(packet: PacketHeaders) -> None:
            l[0](packet)
            r[0](packet)

        def reset(packet: PacketHeaders) -> None:
            l[1](packet)
            r[1](packet)

        self.next = next
        self.reset = reset
        return self

    def join(self, left_extractor: KeyExtractor, right_extractor: KeyExtractor,
             eid_key: str = "eid") -> tuple["Query", "Query"]:
        h_tbl1: dict[PacketHeaders, PacketHeaders] = {}
        h_tbl2: dict[PacketHeaders, PacketHeaders] = {}
        left_curr_epoch: int = 0
        right_curr_epoch: int = 0
        curr_next = MethodType(self.next.__func__)
        curr_reset = MethodType(self.reset.__func__)

        def handle_join_side(curr_h_tbl: dict[PacketHeaders, PacketHeaders],
                             other_h_tbl: dict[PacketHeaders, PacketHeaders],
                             curr_epoch: int, other_epoch: int,
                             extractor: KeyExtractor) -> "Query":
            def next(packet: PacketHeaders) -> None:
                key_n_val: tuple[PacketHeaders,
                                 PacketHeaders] = extractor(packet)
                key, val = key_n_val
                curr_e: int = packet.get_mapped_int(eid_key)

                while curr_e > curr_epoch:
                    if other_epoch > curr_epoch:
                        curr_reset({eid_key, Int(curr_epoch+1)})

                new_packet: PacketHeaders = PacketHeaders(deepcopy(key.headers).__setitem__
                                                          (eid_key, Int(curr_e)))
                match other_h_tbl.get(new_packet, None):
                    case None:
                        curr_h_tbl[new_packet] = val
                    case packt:
                        del other_h_tbl[new_packet]
                        curr_next(packt | val | new_packet)

            def reset(packet: PacketHeaders) -> None:
                nonlocal curr_epoch
                curr_e: int = packet.get_mapped_int(eid_key)
                while curr_e > curr_epoch:
                    if other_epoch > curr_epoch:
                        curr_reset({eid_key, Int(curr_epoch)})
                    curr_epoch += 1

            Query(next, reset)

        return (
            handle_join_side(h_tbl1, h_tbl2, left_curr_epoch,
                             right_curr_epoch, left_extractor),
            handle_join_side(h_tbl2, h_tbl1, right_curr_epoch,
                             left_curr_epoch, right_extractor)
        )


def rename_filtered_keys(renaming_pairs: list[tuple[str, str]],
                         in_packet: PacketHeaders) -> PacketHeaders:
    new_packet: PacketHeaders = PacketHeaders()
    return [new_packet.__setitem__(new, in_packet[old])
            for new, old in renaming_pairs if old in in_packet]


def filter_helper(proto: int, flags: int, packet: PacketHeaders) -> bool:
    return packet.get_mapped_int("ipv4.proto") == proto and \
        packet.get_mapped_int("l4.flags") == flags


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


def key_geq_int(key: str, threshold: int, packet: PacketHeaders) -> bool:
    return int_of_op_result(packet[key]) >= threshold


def get_ip_or_zero(input: str) -> Op_result:
    match input:
        case "0":
            return Int(0)
        case s:
            return Ipv4(IPv4Address(s))


def remove_keys(packet: PacketHeaders) -> PacketHeaders:
    return PacketHeaders({key: val for key, val in packet.items()
                          if key != "eth.src" and key != "eth.dst"})
