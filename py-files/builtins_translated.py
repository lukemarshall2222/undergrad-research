from typing import TextIO, Optional, Callable, Self
from types import Optional
from utils_translated import *
from copy import deepcopy
from collections import namedtuple
from functools import reduce

type GroupingFunc = Callable[[PacketHeaders], PacketHeaders]
type ReductionFunc = Callable[[Op_result, PacketHeaders], Op_result]
type KeyExtractor = Callable[[PacketHeaders],
                             tuple[PacketHeaders, PacketHeaders]]
type EmptyQueryMethod = Callable[[
    IncompleteQueryMethod | FullQueryMethod], IncompleteQueryMethod]
type IncompleteQueryMethod = Callable[[
    IncompleteQueryMethod | FullQueryMethod, PacketHeaders], None]
type FullQueryMethod = Callable[[PacketHeaders], None]
type QueryMethodType = IncompleteQueryMethod | FullQueryMethod
BranchedQuery = namedtuple("BranchedQuery", ['right', 'left'])
type OpCreator = Callable[[Query.Operator], Query.Operator]


class Query():

    class Operator():
        def __init__(self, next: Callable[[PacketHeaders], None],
                     reset: Callable[[PacketHeaders], None]):
            self.next = next
            self.reset = reset

        def next(packet: PacketHeaders) -> None:
            raise NotImplementedError(
                "next method has not been assigned for this operator.")

        def reset(packet: PacketHeaders) -> None:
            raise NotImplementedError(
                "reset method has not been assigned for this operator.")

    def __init__(self, middle_op: Optional[OpCreator] = None,
                 end_op: Optional[Operator] = None,
                 additional_query: Optional["Query"] = None) -> Self:
        self.__ops: list[OpCreator] = []
        self.__end_op: Query.Operator | None = None
        self.__query: OpCreator | Query.Operator | None = None

        match middle_op:
            case Callable():
                self.__ops.append(middle_op)
            case None:
                pass

        match end_op:
            case Query.Operator():
                self.__end_op = end_op
            case None:
                pass

        match additional_query:
            case Query():
                self.__end_op = additional_query.__end_op
                self.__ops.append(additional_query.__ops)

        return self

    def next(self, headers: PacketHeaders) -> None:
        if self.is_empty():
            raise NotImplementedError("Query must be built using combinators before next"
                                      "method can be called")
        self.collect()
        return self.__query.next(headers)

    def reset(self, headers: PacketHeaders) -> None:
        if self.is_empty():
            raise NotImplementedError("Query must be built using combinators before next"
                                      "method can be called")
        self.collect()
        return self.__query.next(headers)

    def collect(self) -> Operator | BranchedQuery | OpCreator:
        if self.is_empty():
            raise NotImplementedError("A query must be built from combinators in order to"
                                      "collect the query")
        i: int = 0
        curr_op: OpCreator | Query.Operator
        while not isinstance(curr_op, Query.Operator):
            curr_op = self.__ops[i]
            if not isinstance(curr_op, Callable) or curr_op.__code__.co_argcount != 1:
                raise TypeError(f"{curr_op.__code__.co_name} is not an OpCreator function."
                                "Cannot use as part of a query")

        def compose(f: OpCreator, g: OpCreator) -> OpCreator:
            return lambda next_op: f(g(next_op))

        return reduce(compose, self.__ops)(self.__end_op) \
            if self.__end_op is None \
            else reduce(compose, self.__ops)

    def add_query(self, other: "Query") -> Self:
        self.__ops.append(other.__ops)
        self.__end_op = other.__end_op

    def dump(self, outc: TextIO, show_reset: bool = False) -> Self:
        def create_op(next_op: Query.Operator):
            def next(headers: PacketHeaders): headers.dump_packet(outc),

            def reset(headers: PacketHeaders): 
                if show_reset is not None:
                    headers.dump_packet(outc)
                print("[reset]\n", file=outc)
                return None
        
        self.__end_op = Query.Operator(
            
            
        )

        return self

    def dump_as_csv(self, outc: TextIO, static_field: Optional[tuple[str, str]] = None,
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

        reset: IncompleteQueryMethod = lambda _, __: None

        self.__next.add_op(next)
        self.__reset.add_op(reset)
        return self

    def dump_as_waltz_csv(self, filename: str) -> Self:
        first: bool = True

        def next(headers: PacketHeaders) -> None:
            file_contents: str = (
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

        reset: FullQueryMethod = lambda _: None

        self.__next.add_op(next)
        self.__reset.add_op(reset)
        return self

    def end_query_abrupt(self):
        next: FullQueryMethod = lambda _: None
        reset: FullQueryMethod = lambda _: None

        self.__next.add_op(next)
        self.__reset.add_op(reset)
        return self

    def meta_meter(self, name: str, outc: TextIO, static_field: str | None = None) -> Self:
        epoch_count: int = 0
        packet_count: int = 0

        def next(next_op: QueryMethodType, headers: PacketHeaders) -> None:
            nonlocal packet_count
            packet_count += 1
            next_op(headers)

        def reset(reset_op: QueryMethodType, headers: PacketHeaders) -> None:
            nonlocal epoch_count
            print(epoch_count, name, packet_count,
                  static_field if static_field is not None else "",
                  file=outc)
            packet_count = 0
            epoch_count += 1
            reset_op(headers)

        self.__next.add_op(next)
        self.__reset.add_op(reset)
        return self

    def epoch(self, epoch_width: float, key_out: str) -> Self:
        epoch_boundary: float = 0.0
        eid: int = 0

        def next(reset_op: QueryMethodType, headers: PacketHeaders) -> None:
            nonlocal epoch_boundary, eid
            time: float = float_of_op_result(headers["time"])
            if epoch_boundary == 0.0:
                epoch_boundary = time + epoch_width
            while time >= epoch_boundary:
                reset_op({key_out: Int(eid)})
                epoch_boundary = epoch_boundary + epoch_width
                eid += 1
            reset_op(headers.__setitem__
                     (key_out, Int(eid)))

        def reset(_: QueryMethodType, __: PacketHeaders) -> None:
            nonlocal epoch_boundary, eid
            next({key_out: Int(eid)})
            epoch_boundary = 0.0
            eid = 0

        self.__next.add_op(next)
        self.__reset.add_op(reset)
        return self

    def filter(self, f: Callable[[PacketHeaders], bool]) -> Self:

        def next(next_op: QueryMethodType, headers: PacketHeaders) -> None:
            if f(headers):
                next_op(headers)

        reset: IncompleteQueryMethod = lambda reset_op, headers: reset_op(
            headers)

        self.__next.add_op(next)
        self.__reset.add_op(reset)
        return self

    def map(self, f: Callable[[PacketHeaders], PacketHeaders]) -> Self:

        next: IncompleteQueryMethod = lambda next_op, headers: next_op(
            f(headers))
        reset: IncompleteQueryMethod = lambda reset_op, headers: reset_op(
            headers)

        self.__next.add_op(next)
        self.__reset.add_op(reset)
        return self

    def groupby(self, group_packet: GroupingFunc, reduce: ReductionFunc, out_key: str) -> Self:
        h_tbl: dict[PacketHeaders, Op_result] = {}
        reset_counter: int = 0

        def next(_: QueryMethodType, headers: PacketHeaders) -> None:
            grouping_key: PacketHeaders = group_packet(headers)
            match h_tbl.get(grouping_key, None):
                case None:
                    h_tbl[grouping_key] = reduce(Empty(), headers)
                case val: h_tbl[grouping_key] = reduce(val, headers)

        def reset(reset_op: QueryMethodType, headers: PacketHeaders) -> None:
            nonlocal reset_counter
            reset_counter += 1
            for packt, op_res in h_tbl.items():
                # keeps the original val for a given key if in both Packets:
                unioned_packet = packt | headers
                reset_op(unioned_packet.__setitem__(out_key, op_res))
            reset_op(headers)
            h_tbl.clear()

        self.__next.add_op(next)
        self.__reset.add_op(reset)
        return self

    def distinct(self, group_packet: GroupingFunc) -> Self:
        h_tbl: dict[PacketHeaders, bool] = {}
        reset_counter: int = 0

        def next(_: QueryMethodType, headers: PacketHeaders) -> None:
            grouping_key: PacketHeaders = group_packet(headers)
            h_tbl[grouping_key] = True

        def reset(reset_op: QueryMethodType, headers: PacketHeaders) -> None:
            nonlocal reset_counter
            reset_counter += 1
            for key, _ in h_tbl.items():
                reset_op(key | headers)  # unioned headers
            reset_op(headers)
            h_tbl.clear()

        self.__next.add_op(next)
        self.__reset.add_op(reset)
        return self

    def split(self, l: "Query", r: "Query") -> Self:

        def next(headers: PacketHeaders) -> None:
            l.next(headers)
            r.next(headers)

        def reset(headers: PacketHeaders) -> None:
            l.reset(headers)
            r.reset(headers)

        self.__next.add_op(next)
        self.__reset.add_op(reset)
        return self

    def join(self, left_extractor: KeyExtractor, right_extractor: KeyExtractor,
             eid_key: str = "eid") -> Self:
        h_tbl1: dict[PacketHeaders, PacketHeaders] = {}
        h_tbl2: dict[PacketHeaders, PacketHeaders] = {}
        left_curr_epoch: int = 0
        right_curr_epoch: int = 0

        def handle_join_side(curr_h_tbl: dict[PacketHeaders, PacketHeaders],
                             other_h_tbl: dict[PacketHeaders, PacketHeaders],
                             curr_epoch: int, other_epoch: int,
                             extractor: KeyExtractor) -> "Query":
            def next(next_op: FullQueryMethod, headers: PacketHeaders) -> None:
                key_n_val: tuple[PacketHeaders,
                                 PacketHeaders] = extractor(headers)
                key, val = key_n_val
                curr_e: int = headers.get_mapped_int(eid_key)

                while curr_e > curr_epoch:
                    if other_epoch > curr_epoch:
                        next_op({eid_key, Int(curr_epoch+1)})

                new_packet: PacketHeaders = PacketHeaders(deepcopy(key.headers).__setitem__
                                                          (eid_key, Int(curr_e)))
                match other_h_tbl.get(new_packet, None):
                    case None:
                        curr_h_tbl[new_packet] = val
                    case packt:
                        del other_h_tbl[new_packet]
                        next_op(packt | val | new_packet)

            def reset(reset_op: FullQueryMethod, headers: PacketHeaders) -> None:
                nonlocal curr_epoch
                curr_e: int = headers.get_mapped_int(eid_key)
                while curr_e > curr_epoch:
                    if other_epoch > curr_epoch:
                        reset_op({eid_key, Int(curr_epoch)})
                    curr_epoch += 1

            return Query(next, reset)

        return BranchedQuery(
            handle_join_side(h_tbl1, h_tbl2, left_curr_epoch,
                             right_curr_epoch, left_extractor),
            handle_join_side(h_tbl2, h_tbl1, right_curr_epoch,
                             left_curr_epoch, right_extractor))

    def continue_flow(self) -> Self:
        def next(next_op: QueryMethodType, headers: PacketHeaders) -> None:
            next_op(headers)

        def reset(reset_op: QueryMethodType, headers: PacketHeaders) -> None:
            reset_op(headers)

        self.__next.add_op(next)
        self.__reset.add_op(reset)
        return self

    def is_empty(self) -> bool:
        return len(self.__ops) == 0


def rename_filtered_keys(renaming_pairs: list[tuple[str, str]],
                         in_packet: PacketHeaders) -> PacketHeaders:
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
            return int_of_op_result(val) + 1
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
    return int_of_op_result(headers[key]) >= threshold


def get_ip_or_zero(input: str) -> Op_result:
    match input:
        case "0":
            return Int(0)
        case s:
            return Ipv4(IPv4Address(s))


def remove_keys(headers: PacketHeaders) -> PacketHeaders:
    return PacketHeaders({key: val for key, val in headers.items()
                          if key != "eth.src" and key != "eth.dst"})
