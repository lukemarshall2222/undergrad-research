"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const process_1 = require("process");
const builtins_translated_1 = require("./builtins-translated");
const utils_translated_1 = require("./utils-translated");
const ip_address_1 = require("ip-address");
function ident(end_op) {
    const firstFun = (headers) => {
        const tmpHeaders = new Map(headers);
        tmpHeaders.delete("eth.src");
        tmpHeaders.delete("eth.dst");
        return tmpHeaders;
    };
    return (0, builtins_translated_1.map)(firstFun), end_op;
}
function countPkts(end_op) {
    return (0, utils_translated_1.$π)((0, builtins_translated_1.epoch)(1.0, "eid"), (0, utils_translated_1.$π)((0, builtins_translated_1.Grouby)(builtins_translated_1.singleGroup, builtins_translated_1.counter, "pkts"), end_op));
}
function pktsPerSrcDst(end_op) {
    return (0, utils_translated_1.$π)((0, builtins_translated_1.epoch)(1.0, "eid"), (0, utils_translated_1.$π)((0, builtins_translated_1.Grouby)((0, builtins_translated_1.filterGroups)(["ipv4.src", "ipv4.dst"]), builtins_translated_1.counter, "pkts"), end_op));
}
function distinctSrcs(end_op) {
    return (0, utils_translated_1.$π)((0, builtins_translated_1.epoch)(1.0, "eid"), (0, utils_translated_1.$π)((0, builtins_translated_1.distinct)((0, builtins_translated_1.filterGroups)(["ipv4.src"])), (0, utils_translated_1.$π)((0, builtins_translated_1.Grouby)(builtins_translated_1.singleGroup, builtins_translated_1.counter, "srcs"), end_op)));
}
function filterHelper(headers, proto, flags) {
    return ((0, builtins_translated_1.getMappedInt)("ipv4.proto", headers) === proto &&
        (0, builtins_translated_1.getMappedInt)("l4.flags", headers) === flags);
}
function tcpNewCons(end_op) {
    const threshold = 40;
    return (0, utils_translated_1.$π)((0, builtins_translated_1.epoch)(1.0, "eid"), (0, utils_translated_1.$π)((0, builtins_translated_1.filter)((headers) => filterHelper(headers, 6, 2)), (0, utils_translated_1.$π)((0, builtins_translated_1.Grouby)((0, builtins_translated_1.filterGroups)(["ipv4.dst"]), builtins_translated_1.counter, "cons"), (0, utils_translated_1.$π)((0, builtins_translated_1.filter)((0, builtins_translated_1.keyGeqInt)("cons", threshold)), end_op))));
}
function sshBruteForce(end_op) {
    const threshold = 40;
    return (0, utils_translated_1.$π)((0, builtins_translated_1.epoch)(1.0, "eid"), (0, utils_translated_1.$π)((0, builtins_translated_1.filter)((headers) => filterHelper(headers, 6, 22)), (0, utils_translated_1.$π)((0, builtins_translated_1.distinct)((0, builtins_translated_1.filterGroups)(["ipv4.src", "ipv4.dst", "ipv4.len"])), (0, utils_translated_1.$π)((0, builtins_translated_1.Grouby)((0, builtins_translated_1.filterGroups)(["ipv4.dst", "ipv4.len"]), builtins_translated_1.counter, "srcs"), (0, utils_translated_1.$π)((0, builtins_translated_1.filter)((0, builtins_translated_1.keyGeqInt)("srcs", threshold)), end_op)))));
}
function superSpreader(end_op) {
    const threshold = 40;
    return (0, utils_translated_1.$π)((0, builtins_translated_1.epoch)(1.0, "eid"), (0, utils_translated_1.$π)((0, builtins_translated_1.distinct)((0, builtins_translated_1.filterGroups)(["ipv4.src", "ipv4.dst"])), (0, utils_translated_1.$π)((0, builtins_translated_1.Grouby)((0, builtins_translated_1.filterGroups)(["ipv4.src"]), builtins_translated_1.counter, "dsts"), (0, utils_translated_1.$π)((0, builtins_translated_1.filter)((0, builtins_translated_1.keyGeqInt)("dsts", threshold)), end_op))));
}
function portScan(end_op) {
    const threshold = 40;
    return (0, utils_translated_1.$π)((0, builtins_translated_1.epoch)(1.0, "eid"), (0, utils_translated_1.$π)((0, builtins_translated_1.distinct)((0, builtins_translated_1.filterGroups)(["ipv4.src", "l4.dport"])), (0, utils_translated_1.$π)((0, builtins_translated_1.Grouby)((0, builtins_translated_1.filterGroups)(["ipv4.src"]), builtins_translated_1.counter, "dsts"), (0, utils_translated_1.$π)((0, builtins_translated_1.filter)((0, builtins_translated_1.keyGeqInt)("dsts", threshold)), end_op))));
}
function ddos(end_op) {
    const threshold = 45;
    return (0, utils_translated_1.$π)((0, builtins_translated_1.epoch)(1.0, "eid"), (0, utils_translated_1.$π)((0, builtins_translated_1.distinct)((0, builtins_translated_1.filterGroups)(["ipv4.src", "ipv4.dst"])), (0, utils_translated_1.$π)((0, builtins_translated_1.Grouby)((0, builtins_translated_1.filterGroups)(["ipv4.dst"]), builtins_translated_1.counter, "srcs"), (0, utils_translated_1.$π)((0, builtins_translated_1.filter)((0, builtins_translated_1.keyGeqInt)("srcs", threshold)), end_op))));
}
function synFloodSonata(end_op) {
    const threshold = 3;
    const epochDur = 1.0;
    const syns = (next_op) => {
        return (0, utils_translated_1.$π)((0, builtins_translated_1.epoch)(epochDur, "eid"), (0, utils_translated_1.$π)((0, builtins_translated_1.filter)((headers) => filterHelper(headers, 6, 22)), (0, utils_translated_1.$π)((0, builtins_translated_1.Grouby)((0, builtins_translated_1.filterGroups)(["ipv4.dst"]), builtins_translated_1.counter, "syns"), next_op)));
    };
    const synacks = (next_op) => {
        return (0, utils_translated_1.$π)((0, builtins_translated_1.epoch)(epochDur, "eid"), (0, utils_translated_1.$π)((0, builtins_translated_1.filter)((headers) => filterHelper(headers, 6, 18)), (0, utils_translated_1.$π)((0, builtins_translated_1.Grouby)((0, builtins_translated_1.filterGroups)(["ipv4.src"]), builtins_translated_1.counter, "synacks"), next_op)));
    };
    const acks = (next_op) => {
        return (0, utils_translated_1.$π)((0, builtins_translated_1.epoch)(epochDur, "eid"), (0, utils_translated_1.$π)((0, builtins_translated_1.filter)((headers) => filterHelper(headers, 6, 16)), (0, utils_translated_1.$π)((0, builtins_translated_1.Grouby)((0, builtins_translated_1.filterGroups)(["ipv4.dst"]), builtins_translated_1.counter, "acks"), next_op)));
    };
    const [joinOp1, joinOp2] = (0, utils_translated_1.$$π)((0, builtins_translated_1.join)((headers) => {
        return [(0, builtins_translated_1.filterGroups)(["host"])(headers),
            (0, builtins_translated_1.filterGroups)(["syns+synacks"])(headers)];
    }, (headers) => {
        return [(0, builtins_translated_1.renameFilterKeys)([["ipv4.dst", "host"]], headers),
            (0, builtins_translated_1.filterGroups)(["acks"])(headers)];
    }), (0, utils_translated_1.$π)((0, builtins_translated_1.map)((headers) => {
        return headers.set("syns+synacks", {
            kind: utils_translated_1.opResultKind.Int,
            val: (0, builtins_translated_1.getMappedInt)("syns", headers)
                + (0, builtins_translated_1.getMappedInt)("synacks", headers)
        });
    }), (0, utils_translated_1.$π)((0, builtins_translated_1.filter)((0, builtins_translated_1.keyGeqInt)("syns+synacks-acks", threshold)), end_op)));
    const [joinOp3, joinOp4] = (0, utils_translated_1.$$π)((0, builtins_translated_1.join)((headers) => {
        return [(0, builtins_translated_1.renameFilterKeys)([["ipv4.dst", "host"]], headers),
            (0, builtins_translated_1.filterGroups)(["syns"])(headers)];
    }, (headers) => {
        return [(0, builtins_translated_1.renameFilterKeys)([["ipv4.src", "host"]], headers),
            (0, builtins_translated_1.filterGroups)(["synacks"])(headers)];
    }), (0, utils_translated_1.$π)((0, builtins_translated_1.map)((headers) => {
        return headers.set("syns+synacks", {
            kind: utils_translated_1.opResultKind.Int,
            val: (0, builtins_translated_1.getMappedInt)("syns", headers)
                + (0, builtins_translated_1.getMappedInt)("synacks", headers)
        });
    }), joinOp1));
    return [
        syns(joinOp3),
        synacks(joinOp4),
        acks(joinOp2)
    ];
}
function completed_flows(endOp) {
    let threshold = 1;
    let epochDur = 30.0;
    const syns = (nextOp) => {
        return (0, utils_translated_1.$π)((0, builtins_translated_1.epoch)(epochDur, "eid"), (0, utils_translated_1.$π)((0, builtins_translated_1.filter)((headers) => filterHelper(headers, 6, 16)), (0, utils_translated_1.$π)((0, builtins_translated_1.Grouby)((0, builtins_translated_1.filterGroups)(["ipv4.dst"]), builtins_translated_1.counter, "syns"), nextOp)));
    };
    const fins = (nextOp) => {
        return (0, utils_translated_1.$π)((0, builtins_translated_1.epoch)(epochDur, "eid"), (0, utils_translated_1.$π)((0, builtins_translated_1.filter)((headers) => {
            return (0, builtins_translated_1.getMappedInt)("ipv4.proto", headers) === 6 &&
                ((0, builtins_translated_1.getMappedInt)("l4.flags", headers) & 1) === 1;
        }), (0, utils_translated_1.$π)((0, builtins_translated_1.Grouby)((0, builtins_translated_1.filterGroups)(["ipv4.src"]), builtins_translated_1.counter, "fins"), nextOp)));
    };
    const [joinOp1, joinOp2] = (0, utils_translated_1.$$π)((0, builtins_translated_1.join)((headers) => {
        return [(0, builtins_translated_1.renameFilterKeys)([["ipv4.dst", "host"]], headers),
            (0, builtins_translated_1.filterGroups)(["syns"])(headers)];
    }, (headers) => {
        return [(0, builtins_translated_1.renameFilterKeys)([["ipv4.src", "host"]], headers),
            (0, builtins_translated_1.filterGroups)(["fins"])(headers)];
    }), (0, utils_translated_1.$π)((0, builtins_translated_1.map)((headers) => {
        return headers.set("diff", {
            kind: utils_translated_1.opResultKind.Int,
            val: (0, builtins_translated_1.getMappedInt)("syn", headers)
                + (0, builtins_translated_1.getMappedInt)("fins", headers)
        });
    }), (0, utils_translated_1.$π)((0, builtins_translated_1.filter)((0, builtins_translated_1.keyGeqInt)("diff", threshold)), endOp)));
    return [
        syns(joinOp1),
        fins(joinOp2)
    ];
}
function slowloris(end_op) {
    let t1 = 5;
    let t2 = 500;
    let t3 = 90;
    let epochDur = 1.0;
    const nConns = (nextOp) => {
        return (0, utils_translated_1.$π)((0, builtins_translated_1.epoch)(epochDur, "eid"), (0, utils_translated_1.$π)((0, builtins_translated_1.filter)((headers) => (0, builtins_translated_1.getMappedInt)("ipv4.proto", headers) === 6), (0, utils_translated_1.$π)((0, builtins_translated_1.distinct)((0, builtins_translated_1.filterGroups)(["ipv4.src", "ipv4.dst", "l4.sport"])), (0, utils_translated_1.$π)((0, builtins_translated_1.Grouby)((0, builtins_translated_1.filterGroups)(["ipv4.dst"]), builtins_translated_1.counter, "n_conns"), (0, utils_translated_1.$π)((0, builtins_translated_1.filter)((headers) => (0, builtins_translated_1.getMappedInt)("n_conns", headers) >= t1), nextOp)))));
    };
    const nBytes = (nextOp) => {
        return (0, utils_translated_1.$π)((0, builtins_translated_1.epoch)(epochDur, "eid"), (0, utils_translated_1.$π)((0, builtins_translated_1.filter)((headers) => (0, builtins_translated_1.getMappedInt)("ipv4.proto", headers) === 6), (0, utils_translated_1.$π)((0, builtins_translated_1.Grouby)((0, builtins_translated_1.filterGroups)(["ipv4.dst"]), (initVal, header) => (0, builtins_translated_1.sumInts)("ipv4.len", initVal, header), "n_bytes"), (0, utils_translated_1.$π)((0, builtins_translated_1.filter)((headers) => (0, builtins_translated_1.getMappedInt)("n_bytes", headers) >= t2), nextOp))));
    };
    const [joinOp1, joinOp2] = (0, utils_translated_1.$$π)((0, builtins_translated_1.join)((headers) => {
        return [(0, builtins_translated_1.filterGroups)(["ipv4.dst"])(headers),
            (0, builtins_translated_1.filterGroups)(["n_conns"])(headers)];
    }, (headers) => {
        return [(0, builtins_translated_1.filterGroups)(["ipv4.dst"])(headers),
            (0, builtins_translated_1.filterGroups)(["n_bytes"])(headers)];
    }), (0, utils_translated_1.$π)((0, builtins_translated_1.map)((headers) => {
        return headers.set("bytes_per_conn", {
            kind: utils_translated_1.opResultKind.Int,
            val: (0, builtins_translated_1.getMappedInt)("n_bytes", headers)
                + (0, builtins_translated_1.getMappedInt)("n_conns", headers)
        });
    }), (0, utils_translated_1.$π)((0, builtins_translated_1.filter)((headers) => (0, builtins_translated_1.getMappedInt)("bytes_per_conn", headers) <= t3), end_op)));
    return [
        nConns(joinOp1),
        nBytes(joinOp2),
    ];
}
function join_test(end_op) {
    let epochDur = 1.0;
    const syns = (nextOp) => {
        return (0, utils_translated_1.$π)((0, builtins_translated_1.epoch)(epochDur, "eid"), (0, utils_translated_1.$π)((0, builtins_translated_1.filter)((headers) => filterHelper(headers, 6, 2)), nextOp));
    };
    const synacks = (nextOp) => {
        return (0, utils_translated_1.$π)((0, builtins_translated_1.epoch)(epochDur, "eid"), (0, utils_translated_1.$π)((0, builtins_translated_1.filter)((headers) => filterHelper(headers, 6, 18)), nextOp));
    };
    const [joinOp1, joinOp2] = (0, utils_translated_1.$$π)((0, builtins_translated_1.join)((headers) => {
        return [(0, builtins_translated_1.renameFilterKeys)([["ipv4.dst", "host"]], headers),
            (0, builtins_translated_1.filterGroups)(["syns"])(headers)];
    }, (headers) => {
        return [(0, builtins_translated_1.renameFilterKeys)([["ipv4.src", "host"]], headers),
            (0, builtins_translated_1.filterGroups)(["fins"])(headers)];
    }), end_op);
    return [
        syns(joinOp1),
        synacks(joinOp2)
    ];
}
function q3(end_op) {
    return (0, utils_translated_1.$π)((0, builtins_translated_1.epoch)(100.0, "eid"), (0, utils_translated_1.$π)((0, builtins_translated_1.distinct)((0, builtins_translated_1.filterGroups)(["ipv4.src", "ipv4.dst"])), end_op));
}
function q4(end_op) {
    return (0, utils_translated_1.$π)((0, builtins_translated_1.epoch)(10000.0, "eid"), (0, utils_translated_1.$π)((0, builtins_translated_1.Grouby)((0, builtins_translated_1.filterGroups)(["ipv4.dst"]), builtins_translated_1.counter, "pkts"), end_op));
}
const queries = [(0, utils_translated_1.$π)(pktsPerSrcDst, (0, builtins_translated_1.dumpAsCsv)(process_1.stdout))];
function runQueries() {
    let headers = [];
    for (let i = 1; i <= 20; i++) {
        new Map([
            ["time", { kind: utils_translated_1.opResultKind.Float, val: i }],
            ["eth.src", {
                    kind: utils_translated_1.opResultKind.MAC,
                    val: new Uint8Array([..."\x00\x11\x22\x33\x44\x55"]
                        .map(c => c.charCodeAt(0)))
                }],
            ["eth.dst", {
                    kind: utils_translated_1.opResultKind.MAC,
                    val: new Uint8Array([..."\xAA\xBB\xCC\xDD\xEE\xFF"]
                        .map(c => c.charCodeAt(0)))
                }],
            ["eth.ethertype", { kind: utils_translated_1.opResultKind.Int, val: 0x0800 }],
            ["ipv4.hlen", { kind: utils_translated_1.opResultKind.Int, val: 20 }],
            ["ipv4.proto", { kind: utils_translated_1.opResultKind.Int, val: 6 }],
            ["ipv4.len", { kind: utils_translated_1.opResultKind.Int, val: 60 }],
            ["ipv4.src", { kind: utils_translated_1.opResultKind.IPv4, val: new ip_address_1.Address4("127.0.0.1") }],
            ["ipv4.dst", { kind: utils_translated_1.opResultKind.IPv4, val: new ip_address_1.Address4("127.0.0.1") }],
            ["l4.sport", { kind: utils_translated_1.opResultKind.Int, val: 440 }],
            ["l4.dport", { kind: utils_translated_1.opResultKind.Int, val: 50000 }],
            ["l4.flags", { kind: utils_translated_1.opResultKind.Int, val: 10 }],
        ]);
    }
    headers.forEach((header) => queries.forEach((op) => op.next(header)));
}
runQueries();
