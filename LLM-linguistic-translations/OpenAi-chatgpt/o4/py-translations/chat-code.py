from typing import Union, Dict, Callable, List, Tuple as TypingTuple, Optional, Any
import ipaddress
import csv
import sys
from collections import defaultdict
from dataclasses import dataclass

# --- op_result variants ---
class OpResult: pass

@dataclass(frozen=True)
class FloatResult(OpResult):
    value: float

@dataclass(frozen=True)
class IntResult(OpResult):
    value: int

@dataclass(frozen=True)
class IPv4Result(OpResult):
    value: ipaddress.IPv4Address

@dataclass(frozen=True)
class MACResult(OpResult):
    value: bytes

class EmptyResult(OpResult): pass

TupleType = Dict[str, OpResult]

# --- Operator ---
class Operator:
    def __init__(self, next_fn: Callable[[TupleType], None], reset_fn: Callable[[TupleType], None]) -> None:
        self.next = next_fn
        self.reset = reset_fn

# --- Conversions ---
def string_of_mac(buf: bytes) -> str:
    return ":".join(f"{b:02x}" for b in buf)

TCP_FLAGS = [
    ("FIN", 1<<0), ("SYN", 1<<1), ("RST", 1<<2), ("PSH", 1<<3),
    ("ACK",1<<4), ("URG",1<<5), ("ECE",1<<6), ("CWR",1<<7)
]

def tcp_flags_to_strings(flags: int) -> str:
    return "|".join(name for name, bit in TCP_FLAGS if flags & bit == bit)

def int_of_op_result(r: OpResult) -> int:
    if isinstance(r, IntResult): return r.value
    raise ValueError("Non-int op result")

def float_of_op_result(r: OpResult) -> float:
    if isinstance(r, FloatResult): return r.value
    raise ValueError("Non-float op result")

def string_of_op_result(r: OpResult) -> str:
    if isinstance(r, FloatResult): return str(r.value)
    if isinstance(r, IntResult): return str(r.value)
    if isinstance(r, IPv4Result): return str(r.value)
    if isinstance(r, MACResult): return string_of_mac(r.value)
    if isinstance(r, EmptyResult): return "Empty"
    raise ValueError("Unknown op result")

def string_of_tuple(t: TupleType) -> str:
    return ", ".join(f'"{k}" => {string_of_op_result(v)}' for k,v in t.items())

def tuple_of_list(pairs: List[TypingTuple[str, OpResult]]) -> TupleType:
    return {k:v for k,v in pairs}

# --- Lookup ---
def lookup_int(k: str, t: TupleType) -> int:
    return int_of_op_result(t[k])
def lookup_float(k: str, t: TupleType) -> float:
    return float_of_op_result(t[k])

# --- Base operators ---
init_table_size = 10000

def dump_tuple(outc=sys.stdout, show_reset: bool=False) -> Operator:
    def nxt(t: TupleType): outc.write(string_of_tuple(t)+"\n")
    def rst(t: TupleType):
        if show_reset:
            outc.write(string_of_tuple(t)+"\n"); outc.write("[reset]\n")
    return Operator(nxt, rst)

def dump_as_csv(outc=sys.stdout, header: bool=True, static_field: Optional[TypingTuple[str,str]]=None) -> Operator:
    first=True
    def nxt(t: TupleType):
        nonlocal first
        if first and header:
            if static_field: outc.write(static_field[0] + ",")
            outc.write(",".join(t.keys())+"\n"); first=False
        if static_field: outc.write(static_field[1] + ",")
        outc.write(",".join(string_of_op_result(v) for v in t.values())+"\n")
    def rst(_: TupleType): pass
    return Operator(nxt, rst)

def dump_walts_csv(filename: str) -> Operator:
    outc=None; first=True
    def nxt(t: TupleType):
        nonlocal outc, first
        if first: outc=open(filename,'w'); first=False
        row=[string_of_op_result(t[k]) for k in(
            "src_ip","dst_ip","src_l4_port","dst_l4_port",
            "packet_count","byte_count","epoch_id"
        )]
        outc.write(",".join(row)+"\n")
    def rst(_: TupleType): pass
    return Operator(nxt,rst)

def get_ip_or_zero(s: str) -> OpResult:
    return IntResult(0) if s=="0" else IPv4Result(ipaddress.IPv4Address(s))

# --- Control flow ---
def filter_op(pred: Callable[[TupleType], bool], nxt_op: Operator) -> Operator:
    def nxt(t: TupleType):
        if pred(t): nxt_op.next(t)
    def rst(t: TupleType): nxt_op.reset(t)
    return Operator(nxt, rst)

def map_op(f: Callable[[TupleType], TupleType], nxt_op: Operator) -> Operator:
    def nxt(t: TupleType): nxt_op.next(f(t))
    def rst(t: TupleType): nxt_op.reset(t)
    return Operator(nxt, rst)

def epoch(width: float, key: str, nxt_op: Operator) -> Operator:
    boundary=0.0; eid=0
    def nxt(t: TupleType):
        nonlocal boundary,eid
        tm=lookup_float("time", t)
        if boundary==0.0: boundary=tm+width
        elif tm>=boundary:
            while tm>=boundary:
                nxt_op.reset({key: IntResult(eid)}); boundary+=width; eid+=1
        t[key]=IntResult(eid); nxt_op.next(t)
    def rst(_: TupleType):
        nonlocal boundary,eid
        nxt_op.reset({key: IntResult(eid)}); boundary=0.0; eid=0
    return Operator(nxt,rst)

def meta_meter(name:str, outc=sys.stdout, static_field:Optional[str]=None, nxt_op:Operator=None) -> Operator:
    ecount=0; tcount=0
    def nxt(t: TupleType):
        nonlocal tcount; tcount+=1; nxt_op.next(t)
    def rst(t: TupleType):
        nonlocal ecount,tcount
        outc.write(f"{ecount},{name},{tcount},{static_field or ''}\n"); tcount=0; ecount+=1; nxt_op.reset(t)
    return Operator(nxt,rst)

# --- Grouping & reductions ---
def filter_groups(keys: List[str], t: TupleType) -> TupleType:
    return {k:v for k,v in t.items() if k in keys}

def single_group(_: TupleType) -> TupleType: return {}

def counter(acc: OpResult, t: TupleType) -> OpResult:
    return IntResult(1) if isinstance(acc, EmptyResult) else IntResult(acc.value+1 if isinstance(acc, IntResult) else 0)

def sum_ints(key:str, init: OpResult, t: TupleType) -> OpResult:
    total=0 if isinstance(init, EmptyResult) else init.value if isinstance(init, IntResult) else 0
    if key in t and isinstance(t[key], IntResult): total+=t[key].value; return IntResult(total)
    raise ValueError(f"sum_ints failed for {key}")

def groupby(group_fn:Callable[[TupleType],TupleType], red_fn:Callable[[OpResult,TupleType],OpResult], out_key:str, nxt_op:Operator) -> Operator:
    table:{}={}
    def nxt(t: TupleType):
        key=frozenset(group_fn(t).items()); prev=table.get(key, EmptyResult()); table[key]=red_fn(prev,t)
    def rst(base: TupleType):
        for key,val in table.items(): grp=dict(key); merged={**base,**grp, out_key: val}; nxt_op.next(merged)
        nxt_op.reset(base); table.clear()
    return Operator(nxt,rst)

def distinct(group_fn:Callable[[TupleType],TupleType], nxt_op:Operator) -> Operator:
    seen=set()
    def nxt(t: TupleType): seen.add(frozenset(group_fn(t).items()))
    def rst(base: TupleType):
        for key in seen: grp=dict(key); merged={**base,**grp}; nxt_op.next(merged)
        nxt_op.reset(base); seen.clear()
    return Operator(nxt,rst)

def split(left:Operator, right:Operator) -> Operator:
    def nxt(t: TupleType): left.next(t); right.next(t)
    def rst(t: TupleType): left.reset(t); right.reset(t)
    return Operator(nxt,rst)

# --- Join ---
def rename_filtered_keys(pairs:List[TypingTuple[str,str]], t:TupleType)->TupleType:
    return {new:t[old] for old,new in pairs if old in t}

def join(left_ex:Callable[[TupleType],TypingTuple[TupleType,TupleType]], right_ex:Callable[[TupleType],TypingTuple[TupleType,TupleType]], nxt_op:Operator, eid_key:str="eid") -> TypingTuple[Operator,Operator]:
    tbl1={}; tbl2={}; le=0; re=0
    def make_side(curr, other, ce, oe, ex):
        def nxt(t:TupleType):
            nonlocal ce, oe
            key_t, vals = ex(t); key=frozenset({**key_t, eid_key: t[eid_key]}.items())
            curr_epoch=lookup_int(eid_key,t)
            while curr_epoch>ce:
                if oe>ce: nxt_op.reset({eid_key: IntResult(ce)})
                ce+=1
            if key in other:
                ov=other.pop(key); merged={**dict(key), **vals, **ov}; nxt_op.next(merged)
            else: curr[key]=vals
        def rst(t:TupleType):
            nonlocal ce, oe
            curr_epoch=lookup_int(eid_key,t)
            while curr_epoch>ce:
                if oe>ce: nxt_op.reset({eid_key: IntResult(ce)})
                ce+=1
        return Operator(nxt,rst)
    l=make_side(tbl1,tbl2,le,re,left_ex); r=make_side(tbl2,tbl1,re,le,right_ex)
    return l,r

# --- Queries / Sonata builders ---
def ident(nxt:Operator)->Operator: return map_op(lambda t: {k:v for k,v in t.items() if k not in ("eth.src","eth.dst")}, nxt)

def count_pkts(nxt:Operator)->Operator: return epoch(1.0,"eid", groupby(single_group,counter,"pkts", nxt))

def pkts_per_src_dst(nxt:Operator)->Operator:
    return epoch(1.0,"eid", groupby(lambda t: filter_groups(["ipv4.src","ipv4.dst"],t), counter, "pkts", nxt))

def distinct_srcs(nxt:Operator)->Operator:
    return epoch(1.0,"eid", distinct(lambda t: filter_groups(["ipv4.src"],t), groupby(single_group,counter,"srcs", nxt)))

def tcp_new_cons(nxt:Operator)->Operator:
    return epoch(1.0,"eid", filter_op(lambda t: lookup_int("ipv4.proto",t)==6 and lookup_int("l4.flags",t)==2, groupby(lambda tt: filter_groups(["ipv4.dst"],tt), counter,"cons", nxt)))

def ssh_brute_force(nxt:Operator)->Operator:
    return epoch(1.0,"eid", filter_op(lambda t: lookup_int("ipv4.proto",t)==6 and lookup_int("l4.dport",t)==22, distinct(lambda tt: filter_groups(["ipv4.src","ipv4.dst","ipv4.len"],tt), groupby(lambda tt: filter_groups(["ipv4.dst","ipv4.len"],tt), counter,"srcs", nxt))))

def super_spreader(nxt:Operator)->Operator:
    return epoch(1.0,"eid", distinct(lambda t: filter_groups(["ipv4.src","ipv4.dst"],t), groupby(lambda t: filter_groups(["ipv4.src"],t), counter,"dsts", nxt)))

def port_scan(nxt:Operator)->Operator:
    return epoch(1.0,"eid", distinct(lambda t: filter_groups(["ipv4.src","l4.dport"],t), groupby(lambda t: filter_groups(["ipv4.src"],t), counter,"ports", nxt)))

def ddos(nxt:Operator)->Operator:
    return epoch(1.0,"eid", distinct(lambda t: filter_groups(["ipv4.src","ipv4.dst"],t), groupby(lambda t: filter_groups(["ipv4.dst"],t), counter,"srcs", nxt)))

def syn_flood_sonata(nxt:Operator)->List[Operator]:
    th=3; dur=1.0
    # syns, synacks, acks
    syns=lambda n: epoch(dur,"eid", filter_op(lambda t: lookup_int("ipv4.proto",t)==6 and lookup_int("l4.flags",t)==2, groupby(lambda tt: filter_groups(["ipv4.dst"],tt), counter,"syns", n)))
    synacks=lambda n: epoch(dur,"eid", filter_op(lambda t: lookup_int("ipv4.proto",t)==6 and lookup_int("l4.flags",t)==18, groupby(lambda tt: filter_groups(["ipv4.src"],tt), counter,"synacks", n)))
    acks=lambda n: epoch(dur,"eid", filter_op(lambda t: lookup_int("ipv4.proto",t)==6 and lookup_int("l4.flags",t)==16, groupby(lambda tt: filter_groups(["ipv4.dst"],tt), counter,"acks", n)))
    # first join
    j1,j2 = join(lambda t: (filter_groups(["host"],t), filter_groups(["syns+synacks"],t)),
                  lambda t: (rename_filtered_keys([("ipv4.dst","host")],t), filter_groups(["acks"],t)),
                  map_op(lambda t: {**t, "syns+synacks-acks": IntResult(lookup_int("syns+synacks",t)-lookup_int("acks",t))}, nxt))
    # second join
    j3,j4= join(lambda t: (rename_filtered_keys([("ipv4.dst","host")],t), filter_groups(["syns"],t)),
                lambda t: (rename_filtered_keys([("ipv4.src","host")],t), filter_groups(["synacks"],t)),
                j1)
    return [syns(j3), synacks(j4), acks(j2)]

def completed_flows(nxt:Operator)->List[Operator]:
    th=1; dur=30.0
    syn=lambda n: epoch(dur,"eid", filter_op(lambda t: lookup_int("ipv4.proto",t)==6 and lookup_int("l4.flags",t)==2, groupby(lambda tt: filter_groups(["ipv4.dst"],tt), counter,"syns", n)))
    fin=lambda n: epoch(dur,"eid", filter_op(lambda t: lookup_int("ipv4.proto",t)==6 and (lookup_int("l4.flags",t)&1)==1, groupby(lambda tt: filter_groups(["ipv4.src"],tt), counter,"fins", n)))
    o1,o2= join(lambda t: (rename_filtered_keys([("ipv4.dst","host")],t), filter_groups(["syns"],t)),
                 lambda t: (rename_filtered_keys([("ipv4.src","host")],t), filter_groups(["fins"],t)),
                 map_op(lambda t: {**t, "diff": IntResult(lookup_int("syns",t)-lookup_int("fins",t))}, nxt))
    return [syn(o1), fin(o2)]

def slowloris(nxt:Operator)->List[Operator]:
    t1,t2,t3=5,500,90; dur=1.0
    ncon=lambda n: epoch(dur,"eid", filter_op(lambda t: lookup_int("ipv4.proto",t)==6, distinct(lambda tt: filter_groups(["ipv4.src","ipv4.dst","l4.sport"],tt), groupby(lambda tt: filter_groups(["ipv4.dst"],tt), counter,"n_conns", n))))
    nbytes=lambda n: epoch(dur,"eid", filter_op(lambda t: lookup_int("ipv4.proto",t)==6, groupby(lambda tt: filter_groups(["ipv4.dst"],tt), sum_ints("ipv4.len", EmptyResult(), tt),"n_bytes", n)))
    o1,o2= join(lambda t:(filter_groups(["ipv4.dst"],t), filter_groups(["n_conns"],t)),
                lambda t:(filter_groups(["ipv4.dst"],t), filter_groups(["n_bytes"],t)),
                map_op(lambda t: {**t, "bytes_per_conn": IntResult(lookup_int("n_bytes",t)//lookup_int("n_conns",t))}, nxt))
    return [ncon(o1), nbytes(o2)]

def join_test(nxt:Operator)->List[Operator]:
    dur=1.0
    syn=lambda n: epoch(dur,"eid", filter_op(lambda t: lookup_int("ipv4.proto",t)==6 and lookup_int("l4.flags",t)==2, n))
    synacks=lambda n: epoch(dur,"eid", filter_op(lambda t: lookup_int("ipv4.proto",t)==6 and lookup_int("l4.flags",t)==18, n))
    o1,o2= join(lambda t:(rename_filtered_keys([("ipv4.src","host")],t), rename_filtered_keys([("ipv4.dst","remote")],t)),
                lambda t:(rename_filtered_keys([("ipv4.dst","host")],t), filter_groups(["time"],t)), nxt)
    return [syn(o1), synacks(o2)]

def q3(nxt:Operator)->Operator: return epoch(100.0,"eid", distinct(lambda t: filter_groups(["ipv4.src","ipv4.dst"],t), nxt))

def q4(nxt:Operator)->Operator: return epoch(10000.0,"eid", groupby(lambda t: filter_groups(["ipv4.dst"],t), counter,"pkts", nxt))

# --- Assemble and run queries ---
queries: List[Operator] = [ident(dump_tuple())]

def run_queries() -> None:
    for i in range(20):
        tup = {
            "time": FloatResult(float(i)),
            "eth.src": MACResult(b"\x00\x11\x22\x33\x44\x55"),
            "eth.dst": MACResult(b"\xAA\xBB\xCC\xDD\xEE\xFF"),
            "eth.ethertype": IntResult(0x0800),
            "ipv4.hlen": IntResult(20),
            "ipv4.proto": IntResult(6),
            "ipv4.len": IntResult(60),
            "ipv4.src": IPv4Result(ipaddress.IPv4Address("127.0.0.1")),
            "ipv4.dst": IPv4Result(ipaddress.IPv4Address("127.0.0.1")),
            "l4.sport": IntResult(440),
            "l4.dport": IntResult(50000),
            "l4.flags": IntResult(10)
        }
        for op in queries:
            op.next(tup)
    print("Done")

if __name__ == "__main__": run_queries()
