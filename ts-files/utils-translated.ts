import { Address4 } from 'ip-address';
import { Writable } from 'stream'

export type PacketHeaders = Map<string, opResult>

export enum opResultKind {
    Float,
    Int,
    IPv4,
    MAC,
    Empty,
}

export type opResult = 
    | {kind: opResultKind.Float, val: number}
    | {kind: opResultKind.Int, val: number}
    | {kind: opResultKind.IPv4, val: Address4}
    | {kind: opResultKind.MAC, val: Uint8Array} 
    | {kind: opResultKind.Empty, val: null}

export type Operator = {
    next:  (headers: PacketHeaders) => void;
    reset: (headers: PacketHeaders) => void;
}

export type opCreator    = (nextOp: Operator) => Operator
export type dblOpCreator = (nextOp: Operator) => [Operator, Operator]

export function $π(opCreatorFunc: opCreator, nextOp: Operator): Operator {
    return opCreatorFunc(nextOp);
}

export function $$π(opCreatorFunc: dblOpCreator, nextOp: Operator): [Operator, Operator] {
    return opCreatorFunc(nextOp);
}  

export function tcpFlagsToStrings(flags: number) : string {
    let acc: string = "";
    new Map([
        ["FIN", 1 << 0],
        ["SYN", 1 << 1],
        ["RST", 1 << 2],
        ["PSH", 1 << 3],
        ["ACK", 1 << 4],
        ["URG", 1 << 5],
        ["ECE", 1 << 6],
        ["CWR", 1 << 7],
    ]).forEach((val: number, key: string) => { if ((flags & val) === val) {
                                                    acc = acc + (acc === "") 
                                                    ? `${key}` 
                                                    : "|" + `${key}`;
                                                    }})  
    return acc;
}

export function intOfOpResult(input: opResult) : number | TypeError{
    switch (input.kind) {
        case opResultKind.Int:
            return input.val;
        default:
            throw new TypeError("Trying to extract int from non-int result");
    }
}

export function floatOfOpResult(input: opResult) : number | TypeError {
    switch (input.kind) {
        case opResultKind.Float:
            return input.val;
        default:
            throw new TypeError("Trying to extract float from non-float result");
    }
}

export function stringOfOpResult(input: opResult) : string {
    switch (input.kind) {
        case opResultKind.Float:
        case opResultKind.Int:
        case opResultKind.IPv4:
        case opResultKind.MAC:
            return input.val.toString();
        case opResultKind.Empty:
            return "Empty";
    }
}

export function stringOfPacketHeaders(input_packet: PacketHeaders) : string {
   return ([...input_packet.entries()])
            .reduce((acc, [key, val]) => acc += `${key}" \
                        => ${stringOfOpResult(val)}, `, "");
}

export function packetHeadersOfList(header_list: [string, opResult][]) : PacketHeaders {
    return new Map(header_list);
}

export function dumpPacketHeaders(outc: Writable, headers: PacketHeaders) : void {
    outc.write(`${stringOfPacketHeaders(headers)}`);
}

export function lookupInt(key: string, headers: PacketHeaders) : number | TypeError {
    return intOfOpResult(headers.get(key) ?? 
            {kind: opResultKind.Empty, val: null});
}

export function lookupFloat(key: string, headers: PacketHeaders) : number | TypeError {
    return floatOfOpResult(headers.get(key) ?? 
                {kind: opResultKind.Empty, val: null});
}