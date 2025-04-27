import { stdout } from "process";
import {
    epoch,
    Grouby as grouby,
    map,
    singleGroup,
    counter,
    filterGroups,
    distinct,
    filter,
    getMappedInt,
    keyGeqInt,
    renameFilterKeys,
    join,
    sumInts,
    dumpAsCsv
} from "./builtins-translated";
import {
    opCreator,
    Operator,
    opResult,
    PacketHeaders,
    $π,
    $$π,
    opResultKind,
} from "./utils-translated";
import { Address4 } from "ip-address";

function ident(end_op: Operator): Operator {
    const firstFun = (headers: PacketHeaders) => {
        const tmpHeaders: Map<string, opResult> = new Map(headers);
        tmpHeaders.delete("eth.src");
        tmpHeaders.delete("eth.dst");
        return tmpHeaders;
    };
    return map(firstFun), end_op;
}

function countPkts(end_op: Operator): opCreator | Operator {
    return $π(epoch(1.0, "eid"),
        $π(grouby(singleGroup, counter, "pkts"),
            end_op
        ));
}

function pktsPerSrcDst(end_op: Operator): opCreator | Operator {
    return $π(epoch(1.0, "eid"),
        $π(grouby(filterGroups(["ipv4.src", "ipv4.dst"]), counter, "pkts"),
            end_op
        ));
}

function distinctSrcs(end_op: Operator): Operator {
    return $π(epoch(1.0, "eid"),
        $π(distinct(filterGroups(["ipv4.src"])),
            $π(grouby(singleGroup, counter, "srcs"),
                end_op
            )));
}

function filterHelper(
    headers: PacketHeaders,
    proto: number,
    flags: number
): boolean {
    return (
        getMappedInt("ipv4.proto", headers) === proto &&
        getMappedInt("l4.flags", headers) === flags
    );
}

function tcpNewCons(end_op: Operator): Operator {
    const threshold: number = 40;
    return $π(epoch(1.0, "eid"),
        $π(filter((headers: PacketHeaders) => filterHelper(headers, 6, 2)),
            $π(grouby(filterGroups(["ipv4.dst"]), counter, "cons"),
                $π(filter(keyGeqInt("cons", threshold)),
                    end_op
                ))));
}

function sshBruteForce(end_op: Operator): Operator {
    const threshold: number = 40;
    return $π(epoch(1.0, "eid"),
        $π(filter((headers: PacketHeaders) => filterHelper(headers, 6, 22)),
            $π(distinct(filterGroups(["ipv4.src", "ipv4.dst", "ipv4.len"])),
                $π(grouby(filterGroups(["ipv4.dst", "ipv4.len"]), counter, "srcs"),
                    $π(filter(keyGeqInt("srcs", threshold)),
                        end_op
                    )))));
}

function superSpreader(end_op: Operator): Operator {
    const threshold: number = 40;
    return $π(epoch(1.0, "eid"),
        $π(distinct(filterGroups(["ipv4.src", "ipv4.dst"])),
            $π(grouby(filterGroups(["ipv4.src"]), counter, "dsts"),
                $π(filter(keyGeqInt("dsts", threshold)),
                    end_op
                ))));
}

function portScan(end_op: Operator): Operator {
    const threshold: number = 40;
    return $π(epoch(1.0, "eid"),
        $π(distinct(filterGroups(["ipv4.src", "l4.dport"])),
            $π(grouby(filterGroups(["ipv4.src"]), counter, "dsts"),
                $π(filter(keyGeqInt("dsts", threshold)),
                    end_op
                ))));
}

function ddos(end_op: Operator): Operator {
    const threshold: number = 45;
    return $π(epoch(1.0, "eid"),
        $π(distinct(filterGroups(["ipv4.src", "ipv4.dst"])),
            $π(grouby(filterGroups(["ipv4.dst"]), counter, "srcs"),
                $π(filter(keyGeqInt("srcs", threshold)),
                    end_op
                ))));
}

function synFloodSonata(
    end_op: Operator,
): Operator[] {
    const threshold: number = 3;
    const epochDur: number = 1.0;

    const syns: opCreator = (next_op: Operator) => {
        return $π(epoch(epochDur, "eid"),
            $π(filter((headers: PacketHeaders) => filterHelper(headers, 6, 22)),
                $π(grouby(filterGroups(["ipv4.dst"]), counter, "syns"),
                    next_op
                )));
    };

    const synacks: opCreator = (next_op: Operator) => {
        return $π(epoch(epochDur, "eid"),
            $π(filter((headers: PacketHeaders) => filterHelper(headers, 6, 18)),
                $π(grouby(filterGroups(["ipv4.src"]), counter, "synacks"),
                    next_op
                )));
    }

    const acks: opCreator = (next_op: Operator) => {
        return $π(epoch(epochDur, "eid"),
            $π(filter((headers: PacketHeaders) => filterHelper(headers, 6, 16)),
                $π(grouby(filterGroups(["ipv4.dst"]), counter, "acks"),
                    next_op
                )));
    }

    const [joinOp1, joinOp2]: [Operator, Operator] =
        $$π(join((headers: PacketHeaders) => {
            return [filterGroups(["host"])(headers),
            filterGroups(["syns+synacks"])(headers)]
        },
            (headers: PacketHeaders) => {
                return [renameFilterKeys([["ipv4.dst", "host"]], headers),
                filterGroups(["acks"])(headers)]
            }), $π(map((headers: PacketHeaders) => {
                return headers.set("syns+synacks",
                    {
                        kind: opResultKind.Int,
                        val: getMappedInt("syns", headers)
                            + getMappedInt("synacks", headers)
                    })
            }),
                $π(filter(keyGeqInt("syns+synacks-acks", threshold)),
                    end_op)));

    const [joinOp3, joinOp4]: [Operator, Operator] =
        $$π(join((headers: PacketHeaders) => {
            return [renameFilterKeys([["ipv4.dst", "host"]], headers),
            filterGroups(["syns"])(headers)]
        }, (headers: PacketHeaders) => {
            return [renameFilterKeys([["ipv4.src", "host"]], headers),
            filterGroups(["synacks"])(headers)]
        }), $π(map((headers: PacketHeaders) => {
            return headers.set("syns+synacks",
                {
                    kind: opResultKind.Int,
                    val: getMappedInt("syns", headers)
                        + getMappedInt("synacks", headers)
                })
        }), joinOp1));

    return [
        syns(joinOp3),
        synacks(joinOp4),
        acks(joinOp2)
    ];
}

function completed_flows(endOp: Operator): Operator[] {
    let threshold: number = 1;
    let epochDur: number = 30.0;

    const syns: opCreator = (nextOp: Operator) => {
        return $π(epoch(epochDur, "eid"),
            $π(filter((headers: PacketHeaders) => filterHelper(headers, 6, 16)),
                $π(grouby(filterGroups(["ipv4.dst"]), counter, "syns"),
                    nextOp
                )));
    }

    const fins: opCreator = (nextOp: Operator) => {
        return $π(epoch(epochDur, "eid"),
            $π(filter((headers: PacketHeaders) => {
                return getMappedInt("ipv4.proto", headers) === 6 &&
                    (getMappedInt("l4.flags", headers) & 1) === 1
            }),
                $π(grouby(filterGroups(["ipv4.src"]), counter, "fins"),
                    nextOp
                )));
    }

    const [joinOp1, joinOp2]: [Operator, Operator] =
        $$π(join((headers: PacketHeaders) => {
            return [renameFilterKeys([["ipv4.dst", "host"]], headers),
            filterGroups(["syns"])(headers)]
        }, (headers: PacketHeaders) => {
            return [renameFilterKeys([["ipv4.src", "host"]], headers),
            filterGroups(["fins"])(headers)]
        }),
            $π(map((headers: PacketHeaders) => {
                return headers.set("diff",
                    {
                        kind: opResultKind.Int,
                        val: getMappedInt("syn", headers)
                            + getMappedInt("fins", headers)
                    })
            }),
                $π(filter(keyGeqInt("diff", threshold)),
                    endOp
                )));

    return [
        syns(joinOp1),
        fins(joinOp2)
    ];
}

function slowloris(end_op: Operator): Operator[] {
    let t1: number = 5;
    let t2: number = 500;
    let t3: number = 90;
    let epochDur: number = 1.0;

    const nConns: opCreator = (nextOp: Operator) => {
        return $π(epoch(epochDur, "eid"),
            $π(filter((headers: PacketHeaders) => getMappedInt("ipv4.proto", headers) === 6),
                $π(distinct(filterGroups(["ipv4.src", "ipv4.dst", "l4.sport"])),
                    $π(grouby(filterGroups(["ipv4.dst"]), counter, "n_conns"),
                        $π(filter((headers: PacketHeaders) => getMappedInt("n_conns", headers) >= t1),
                            nextOp
                        )))));
    }

    const nBytes: opCreator = (nextOp: Operator) => {
        return $π(epoch(epochDur, "eid"),
            $π(filter((headers: PacketHeaders) => getMappedInt("ipv4.proto", headers) === 6),
                $π(grouby(filterGroups(["ipv4.dst"]),
                    (initVal: opResult, header: PacketHeaders) =>
                        sumInts("ipv4.len", initVal, header), "n_bytes"),
                    $π(filter((headers: PacketHeaders) => getMappedInt("n_bytes", headers) >= t2),
                        nextOp
                    ))));
    }

    const [joinOp1, joinOp2]: [Operator, Operator] =
        $$π(join((headers: PacketHeaders) => {
            return [filterGroups(["ipv4.dst"])(headers),
            filterGroups(["n_conns"])(headers)]
        },
            (headers: PacketHeaders) => {
                return [filterGroups(["ipv4.dst"])(headers),
                filterGroups(["n_bytes"])(headers)]
            }),
            $π(map((headers: PacketHeaders) => {
                return headers.set("bytes_per_conn",
                    {
                        kind: opResultKind.Int,
                        val: getMappedInt("n_bytes", headers)
                            + getMappedInt("n_conns", headers)
                    })
            }),
                $π(filter((headers: PacketHeaders) => getMappedInt("bytes_per_conn", headers) <= t3),
                    end_op
                )));

    return [
        nConns(joinOp1),
        nBytes(joinOp2),
    ]
}

function join_test(end_op: Operator): Operator[] {
    let epochDur: number = 1.0;
    const syns: opCreator = (nextOp: Operator) => {
        return $π(epoch(epochDur, "eid"),
            $π(filter((headers: PacketHeaders) => filterHelper(headers, 6, 2)),
                nextOp
            ));
    }

    const synacks: opCreator = (nextOp: Operator) => {
        return $π(epoch(epochDur, "eid"),
            $π(filter((headers: PacketHeaders) => filterHelper(headers, 6, 18)),
                nextOp
            ));
    }

    const [joinOp1, joinOp2]: [Operator, Operator] =
        $$π(join((headers: PacketHeaders) => {
            return [renameFilterKeys([["ipv4.dst", "host"]], headers),
            filterGroups(["syns"])(headers)]
        }, (headers: PacketHeaders) => {
            return [renameFilterKeys([["ipv4.src", "host"]], headers),
            filterGroups(["fins"])(headers)]
        }),
            end_op
        );

    return [
        syns(joinOp1),
        synacks(joinOp2)
    ]
}

function q3(end_op: Operator): Operator {
    return $π(epoch(100.0, "eid"),
        $π(distinct(filterGroups(["ipv4.src", "ipv4.dst"])),
            end_op
        ));
}

function q4(end_op: Operator): Operator {
    return $π(epoch(10000.0, "eid"),
        $π(grouby(filterGroups(["ipv4.dst"]), counter, "pkts"),
            end_op
        ));
}


const queries: Operator[] = [$π(ident, dumpAsCsv(stdout))]

function runQueries(): void {
    let headers: PacketHeaders[] = [];
    for (let i = 1; i <= 20; i++) {
        new Map<string, opResult>([
            ["time", { kind: opResultKind.Float, val: i }],
            ["eth.src", {
                kind: opResultKind.MAC,
                val: new Uint8Array([..."\x00\x11\x22\x33\x44\x55"]
                    .map(c => c.charCodeAt(0)))
            }],
            ["eth.dst", {
                kind: opResultKind.MAC,
                val: new Uint8Array([..."\xAA\xBB\xCC\xDD\xEE\xFF"]
                    .map(c => c.charCodeAt(0)))
            }],
            ["eth.ethertype", { kind: opResultKind.Int, val: 0x0800 }],
            ["ipv4.hlen", { kind: opResultKind.Int, val: 20 }],
            ["ipv4.proto", { kind: opResultKind.Int, val: 6 }],
            ["ipv4.len", { kind: opResultKind.Int, val: 60 }],
            ["ipv4.src", { kind: opResultKind.IPv4, val: new Address4("127.0.0.1") }],
            ["ipv4.dst", { kind: opResultKind.IPv4, val: new Address4("127.0.0.1") }],
            ["l4.sport", { kind: opResultKind.Int, val: 440 }],
            ["l4.dport", { kind: opResultKind.Int, val: 50000 }],
            ["l4.flags", { kind: opResultKind.Int, val: 10 }],
        ])
    }
    headers.forEach((header) => queries.forEach((op) => op.next(header)));
}

runQueries()