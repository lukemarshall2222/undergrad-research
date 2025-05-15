from typing import TextIO, Optional, Callable, Self
from utils_translated import *
from copy import deepcopy
import sys

type GroupingFunc = Callable[[PacketHeaders], PacketHeaders]
type ReductionFunc = Callable[[Op_result, PacketHeaders], Op_result]
type KeyExtractor = Callable[[PacketHeaders],
                             tuple[PacketHeaders, PacketHeaders]]

type BranchedQuery = tuple[Query]
type BranchCreator = Callable[[Query.Operator], BranchedQuery]
type OpCreator = Callable[[Query.Operator], Query.Operator]
type opSplitter = Callable[..., Query.Operator]
type opMethod = Callable[[PacketHeaders], None]


class Query():

    class Operator():
        def __init__(self, next: Callable[[PacketHeaders], None],
                     reset: Callable[[PacketHeaders], None]):
            self.next = next
            self.reset = reset

    def __init__(self, middle_op: Optional[OpCreator] = None,
                 end_op: Optional[Operator] = None,
                 additional_query: Optional["Query"] = None) -> None:
        self.__ops: list[OpCreator | BranchCreator] = []
        self.__end_op: Query.Operator | None = None

        match middle_op:
            case None:
                pass
            case _ if callable(middle_op):
                self.__ops.append(middle_op)

        match end_op:
            case Query.Operator():
                self.__end_op = end_op
            case None:
                pass

        match additional_query:
            case Query():
                self.__end_op = additional_query.__end_op
                self.__ops += additional_query.__ops
            case None:
                pass

    def collect(self) -> Operator | BranchedQuery | Self:
        if self.is_empty():
            raise NotImplementedError("A query must be built from combinators in order to"
                                      "collect the query")
        if self.__end_op is None or len(self.__ops) == 0:
            return self

        curr_op = self.__end_op
        for op in reversed(self.__ops):
            if isinstance(curr_op, list):
                try:
                    curr_op = op(curr_op)
                except TypeError:
                    raise TypeError("You must call `.split()` immediately after `.join()`.")
            else: 
                curr_op = op(curr_op)

        return curr_op

    def add_query(self, other: "Query") -> Self:
        self.__ops += other.__ops
        self.__end_op = other.__end_op

        return self

    def dump(self, outc: Optional[TextIO] = sys.stdout, show_reset: bool = False) -> Self:
        def next(headers: PacketHeaders):
            headers.dump_packet(outc)

        def reset(headers: PacketHeaders):
            if show_reset is not None:
                headers.dump_packet(outc)
            print("[reset]\n", file=outc)

        self.__end_op = Query.Operator(next, reset)

        return self

    def dump_as_csv(self, outc: Optional[TextIO] = sys.stdout,
                    static_field: Optional[tuple[str, str]] = None,
                    header: bool = True) -> Self:
        first: bool = header

        def next(headers: PacketHeaders) -> None:
            nonlocal first  # handling implicit state with closures
            if first is None:
                if static_field is not None:
                    print(static_field[0], file=outc)

                for key, _ in headers.items():
                    print(key, file=outc)
                print("\n", file=outc)
                first = False

            if static_field is not None:
                print(static_field[1], outc)
            assert (isinstance(headers, PacketHeaders))
            for _, val in headers.items():
                print(string_of_op_result(val), file=outc)
            print("\n", file=outc)

        reset: opMethod = lambda _: None

        self.__end_op = Query.Operator(next, reset)

        return self

    def dump_as_walts_csv(self, filename: str) -> Self:
        first: bool = True

        def next(headers: PacketHeaders) -> None:
            file_contents: tuple[str] = (
                f"{string_of_op_result(headers["src_ip"])},"
                f"{string_of_op_result(headers["dst_ip"])}"
                f"{string_of_op_result(headers["src_l4_port"])}"
                f"{string_of_op_result(headers["dst_l4_port"])}"
                f"{string_of_op_result(headers["packet_count"])}"
                f"{string_of_op_result(headers["byte_count"])}"
                f"{string_of_op_result(headers["epoch_id"])}",
            )
            if first:
                print(file_contents)
            else:
                with open(filename, "a") as outc:
                    print(file_contents, file=outc)

        reset: opMethod = lambda _: None

        self.__end_op = Query.Operator(next, reset)

        return self

    def end_query_abrupt(self):
        next: opMethod = lambda _: None
        reset: opMethod = lambda _: None

        self.__end_op = Query.Operator(next, reset)

        return self

    def meta_meter(self, name: str, outc: TextIO, static_field: str | None = None) -> Self:
        epoch_count: int = 0
        packet_count: int = 0

        def creatorFunc(next_op: Query.Operator):
            def next(headers: PacketHeaders) -> None:
                nonlocal packet_count
                packet_count += 1
                next_op.next(headers)

            def reset(headers: PacketHeaders) -> None:
                nonlocal epoch_count, packet_count
                print(epoch_count, name, packet_count,
                      static_field if static_field is not None else "",
                      file=outc)
                packet_count = 0
                epoch_count += 1
                next_op.reset(headers)

            return Query.Operator(next, reset)

        self.__ops.append(creatorFunc)

        return self

    def epoch(self, epoch_width: float, key_out: str) -> Self:
        epoch_boundary: float = 0.0
        eid: int = 0

        def creatorFunc(next_op: Query.Operator) -> Query.Operator:
            def next(headers: PacketHeaders) -> None:
                nonlocal epoch_boundary, eid
                time: float = float_of_op_result(headers["time"])
                if epoch_boundary == 0.0:
                    epoch_boundary = time + epoch_width
                while time >= epoch_boundary:
                    next_op.reset(PacketHeaders({key_out: Int(eid)}))
                    epoch_boundary = epoch_boundary + epoch_width
                    eid += 1
                next_op.next(headers.__setitem__
                              (key_out, Int(eid)))

            def reset(_: PacketHeaders) -> None:
                nonlocal epoch_boundary, eid
                next_op.reset(PacketHeaders({key_out: Int(eid)}))
                epoch_boundary = 0.0
                eid = 0

            return Query.Operator(next, reset)

        self.__ops.append(creatorFunc)

        return self

    def filter(self, f: Callable[[PacketHeaders], bool]) -> Self:

        def creatorFunc(next_op: Query.Operator) -> Query.Operator:
            def next(headers: PacketHeaders) -> None:
                if f(headers):
                    next_op.next(headers)

            reset: opMethod = lambda headers: next_op.reset(
                headers)

            return Query.Operator(next, reset)

        self.__ops.append(creatorFunc)

        return self

    def map(self, f: Callable[[PacketHeaders], PacketHeaders]) -> Self:

        def creatorFunc(next_op: Query.Operator) -> Query.Operator:
            next: opMethod = lambda headers: next_op.next(
                f(headers))
            reset: opMethod = lambda headers: next_op.reset(
                headers)

            return Query.Operator(next, reset)

        self.__ops.append(creatorFunc)

        return self

    def groupby(self, group_packet: GroupingFunc, reduce: ReductionFunc, out_key: str) -> Self:
        h_tbl: dict[PacketHeaders, Op_result] = {}
        reset_counter: int = 0

        def creatorFunc(next_op: Query.Operator) -> Query.Operator:
            def next(headers: PacketHeaders) -> None:
                grouping_key: PacketHeaders = group_packet(headers)
                match h_tbl.get(grouping_key, None):
                    case None:
                        h_tbl[grouping_key] = reduce(Empty(), headers)
                    case val: h_tbl[grouping_key] = reduce(val, headers)

            def reset(headers: PacketHeaders) -> None:
                nonlocal reset_counter
                reset_counter += 1
                for packt, op_res in h_tbl.items():
                    # keeps the original val for a given key if in both Packets:
                    unioned_packet = packt | headers
                    next_op.next(unioned_packet.__setitem__(out_key, op_res))
                next_op.reset(headers)
                h_tbl.clear()
            return Query.Operator(next, reset)

        self.__ops.append(creatorFunc)

        return self

    def distinct(self, group_packet: GroupingFunc) -> Self:
        h_tbl: dict[PacketHeaders, bool] = {}
        reset_counter: int = 0

        def creatorFunc(next_op: Query.Operator) -> Query.Operator:
            def next(headers: PacketHeaders) -> None:
                grouping_key: PacketHeaders = group_packet(headers)
                h_tbl[grouping_key] = True

            def reset(headers: PacketHeaders) -> None:
                nonlocal reset_counter
                reset_counter += 1
                for key, _ in h_tbl.items():
                    next_op.next(key | headers)  # unioned headers
                next_op.reset(headers)
                h_tbl.clear()

            return Query.Operator(next, reset)

        self.__ops.append(creatorFunc)

        return self

    def split(self) -> Self:
        def splitterFunc(branches: list[Query]) -> Query.Operator:
            l, r = branches

            def next(headers: PacketHeaders) -> None:
                l.next(headers)
                r.next(headers)

            def reset(headers: PacketHeaders) -> None:
                l.reset(headers)
                r.reset(headers)

            return Query.Operator(next, reset)

        self.__ops.append(splitterFunc)

        return self


    def join(self, left_extractor: KeyExtractor, right_extractor: KeyExtractor,
             eid_key: str = "eid") -> Self:
        h_tbl1: dict[PacketHeaders, PacketHeaders] = {}
        h_tbl2: dict[PacketHeaders, PacketHeaders] = {}
        left_curr_epoch: int = 0
        right_curr_epoch: int = 0

        def creatorFunc(next_op: Query.Operator) -> BranchedQuery:
            def handle_join_side(curr_h_tbl: dict[PacketHeaders, PacketHeaders],
                                 other_h_tbl: dict[PacketHeaders, PacketHeaders],
                                 curr_epoch: int, other_epoch: int,
                                 extractor: KeyExtractor) -> "Query":
                def next(headers: PacketHeaders) -> None:
                    key_n_val: tuple[PacketHeaders,
                                     PacketHeaders] = extractor(headers)
                    key, val = key_n_val
                    curr_e: int = headers.get_mapped_int(eid_key)

                    while curr_e > curr_epoch:
                        if other_epoch > curr_epoch:
                            next_op.reset(PacketHeaders(
                                {eid_key: Int(curr_epoch+1)}))

                    new_packet: PacketHeaders = PacketHeaders(deepcopy(key.headers).__setitem__
                                                              (eid_key, Int(curr_e)))
                    match other_h_tbl.get(new_packet, None):
                        case None:
                            curr_h_tbl[new_packet] = val
                        case packt:
                            del other_h_tbl[new_packet]
                            next_op.next(packt | val | new_packet)

                def reset(headers: PacketHeaders) -> None:
                    nonlocal curr_epoch
                    curr_e: int = headers.get_mapped_int(eid_key)
                    while curr_e > curr_epoch:
                        if other_epoch > curr_epoch:
                            next_op.reset(PacketHeaders(
                                {eid_key: Int(curr_epoch)}))
                        curr_epoch += 1

                newQ: Query = Query()
                newQ.__end_op = Query.Operator(next, reset)
                return newQ

            return (handle_join_side(h_tbl1, h_tbl2, left_curr_epoch,
                                     right_curr_epoch, left_extractor),
                    handle_join_side(h_tbl2, h_tbl1, right_curr_epoch,
                                     left_curr_epoch, right_extractor))

        self.__ops.append(creatorFunc)

        return self

    def is_empty(self) -> bool:
        return len(self.__ops) == 0 and self.__end_op is None

    def remove_end_op(self):
        self.__end_op = None


def rename_filtered_keys(renaming_pairs: list[tuple[str, str]],
                         in_packet: PacketHeaders) -> list[PacketHeaders]:
    new_packet: PacketHeaders = PacketHeaders()
    return [new_packet.__setitem__(new, in_packet[old])
            for new, old in renaming_pairs if old in in_packet]


def filter_helper(proto: int, flags: int, headers: PacketHeaders) -> bool:
    return headers.get_mapped_int("ipv4.proto") == proto and \
        headers.get_mapped_int("l4.flags") == flags


def filter_groups(incl_keys: list[str], headers: PacketHeaders) -> PacketHeaders:
    incl_keys_set: set[str] = set(incl_keys)
    return PacketHeaders({key: val for key, val in headers.items()
                          if key in incl_keys_set})


def single_group(_: PacketHeaders) -> PacketHeaders:
    return PacketHeaders()


def counter(val: Op_result, _: PacketHeaders) -> Op_result:
    match val:
        case Empty():
            return Int(1)
        case Int():
            return Int(int_of_op_result(val) + 1)
        case _:
            return val


def sum_ints(search_key: str, init_val: Op_result, headers: PacketHeaders) -> Op_result:
    match init_val:
        case Empty():
            return Int(1)
        case Int():
            match headers.get(search_key, None):
                case None:
                    raise KeyError("'sum_vals' function failed to find integer",
                                   f"value mapped to {search_key}")
                case val:
                    return Int(int_of_op_result(val)+1)
        case _:
            return init_val


def key_geq_int(key: str, threshold: int, headers: PacketHeaders) -> bool:
    return int_of_op_result(headers.get(key, Int(1))) >= threshold


def get_ip_or_zero(input: str) -> Op_result:
    match input:
        case "0":
            return Int(0)
        case s:
            return Ipv4(IPv4Address(s))


def remove_keys(headers: PacketHeaders) -> PacketHeaders:
    return PacketHeaders({key: val for key, val in headers.items()
                          if key != "eth.src" and key != "eth.dst"})
