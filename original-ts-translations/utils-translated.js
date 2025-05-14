"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.opResultKind = void 0;
exports.$π = $π;
exports.$$π = $$π;
exports.tcpFlagsToStrings = tcpFlagsToStrings;
exports.intOfOpResult = intOfOpResult;
exports.floatOfOpResult = floatOfOpResult;
exports.stringOfOpResult = stringOfOpResult;
exports.stringOfPacketHeaders = stringOfPacketHeaders;
exports.packetHeadersOfList = packetHeadersOfList;
exports.dumpPacketHeaders = dumpPacketHeaders;
exports.lookupInt = lookupInt;
exports.lookupFloat = lookupFloat;
var opResultKind;
(function (opResultKind) {
    opResultKind[opResultKind["Float"] = 0] = "Float";
    opResultKind[opResultKind["Int"] = 1] = "Int";
    opResultKind[opResultKind["IPv4"] = 2] = "IPv4";
    opResultKind[opResultKind["MAC"] = 3] = "MAC";
    opResultKind[opResultKind["Empty"] = 4] = "Empty";
})(opResultKind || (exports.opResultKind = opResultKind = {}));
function $π(opCreatorFunc, nextOp) {
    return opCreatorFunc(nextOp);
}
function $$π(opCreatorFunc, nextOp) {
    return opCreatorFunc(nextOp);
}
function tcpFlagsToStrings(flags) {
    let acc = "";
    new Map([
        ["FIN", 1 << 0],
        ["SYN", 1 << 1],
        ["RST", 1 << 2],
        ["PSH", 1 << 3],
        ["ACK", 1 << 4],
        ["URG", 1 << 5],
        ["ECE", 1 << 6],
        ["CWR", 1 << 7],
    ]).forEach((val, key) => {
        if ((flags & val) === val) {
            acc = acc + (acc === "")
                ? `${key}`
                : "|" + `${key}`;
        }
    });
    return acc;
}
function intOfOpResult(input) {
    switch (input.kind) {
        case opResultKind.Int:
            return input.val;
        default:
            throw new TypeError("Trying to extract int from non-int result");
    }
}
function floatOfOpResult(input) {
    switch (input.kind) {
        case opResultKind.Float:
            return input.val;
        default:
            throw new TypeError("Trying to extract float from non-float result");
    }
}
function stringOfOpResult(input) {
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
function stringOfPacketHeaders(input_packet) {
    return ([...input_packet.entries()])
        .reduce((acc, [key, val]) => acc += `${key}" \
                        => ${stringOfOpResult(val)}, `, "");
}
function packetHeadersOfList(header_list) {
    return new Map(header_list);
}
function dumpPacketHeaders(outc, headers) {
    outc.write(`${stringOfPacketHeaders(headers)}`);
}
function lookupInt(key, headers) {
    return intOfOpResult(headers.get(key) ??
        { kind: opResultKind.Empty, val: null });
}
function lookupFloat(key, headers) {
    return floatOfOpResult(headers.get(key) ??
        { kind: opResultKind.Empty, val: null });
}
