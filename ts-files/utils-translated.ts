class IPv4Adress {
    private address: Uint8Array;

    constructor(address: string) {
        const parts: number[] = address.split(".").map(Number)
        if (parts.length !== 4) {
            throw new Error("Error. Attempt made to create IPv4Address \
                                out of illegal string");
        }

        this.address = new Uint8Array(parts);
    }
}

class Bytes {
    private bytes: Uint8Array;

    constructor(bytes: string) {
        const parts: number[] = bytes.split(".").map(Number)
        if (parts.length !== 4) {
            throw new Error("Error. Attempt made to create IPv4Address \
                                out of illegal string");
        }

        this.bytes = new Uint8Array(parts);
    }

    getUint8(index: number) : number {
        return this.bytes[index];
    }
}

enum opResultKind {
    Float,
    Int,
    IPv4,
    MAC,
    Empty,
}

type opResult = 
    | {kind: opResultKind.Float, type_: number}
    | {kind: opResultKind.Int, type_: number}
    | {kind: opResultKind.IPv4, type_: IPv4Adress}
    | {kind: opResultKind.MAC, type_: Bytes} 
    | {kind: opResultKind.Empty, type_: null}

type Packet = Map<string, opResult>

type Operator = {
    next:  (packet: Packet) => null;
    reset: (packet: Packet) => null;
}

type opCreator    = (nextOp: Operator) => Operator
type dblOpCreator = (nextOp: Operator) => Operator

function $π(opCreatorFunc: opCreator, nextOp: Operator): Operator {
    return opCreatorFunc(nextOp);
}

function $$π(opCreatorFunc: opCreator, nextOp: Operator): Operator {
    return opCreatorFunc(nextOp);
}

function stringOfMac(buf: Bytes) : string {
    const byteAt = (index: number) => buf.getUint8(index);
    return `${byteAt(0).toFixed(2)}:\
            ${byteAt(1).toFixed(2)}:\
            ${byteAt(2).toFixed(2)}:\
            ${byteAt(3).toFixed(2)}:\
            ${byteAt(4).toFixed(2)}:\
            ${byteAt(5).toFixed(2)}:`
}   

function tcpFlagsToStrings(flags: number) : string {
    let acc: string;
    const tcpFlagsMap: Map<string, number> = new Map([
        ["FIN", 1 << 0],
        ["SYN", 1 << 1],
        ["RST", 1 << 2],
        ["PSH", 1 << 3],
        ["ACK", 1 << 4],
        ["URG", 1 << 5],
        ["ECE", 1 << 6],
        ["CWR", 1 << 7],
    ]).forEach((_: number, key: string) => 
                acc = acc + acc === "" 
                      ? `${key}` 
                      : "|" + `${key}`)
                                
                
    
}
