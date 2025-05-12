// Represents the variant type `op_result` from OCaml as a discriminated union
type OpResult = 
    | { type: 'Float'; value: number }
    | { type: 'Int'; value: number }
    | { type: 'IPv4'; value: string } // Simplified as string; could use a library for Ipaddr.V4.t
    | { type: 'MAC'; value: Uint8Array } // Bytes.t as Uint8Array for MAC addresses
    | { type: 'Empty' };

// Represents a tuple as a Map from strings to OpResult
type Tuple = Map<string, OpResult>;

// Operator interface with next and reset methods
interface Operator {
    next: (tup: Tuple) => void;
    reset: (tup: Tuple) => void;
}

// Function types for operator creators
type OpCreator = (nextOp: Operator) => Operator;
type DblOpCreator = (op: Operator) => [Operator, Operator];

// Utility to create a tuple from a list of key-value pairs
function tupleOfList(tupList: [string, OpResult][]): Tuple {
    return new Map(tupList);
}

// Conversion Utilities

// Formats a MAC address (Uint8Array) as a colon-separated hex string
function stringOfMac(buf: Uint8Array): string {
    return Array.from(buf)
        .map(byte => byte.toString(16).padStart(2, '0'))
        .join(':');
}

// Converts TCP flags (number) to a human-readable string
function tcpFlagsToStrings(flags: number): string {
    const tcpFlags: { [key: string]: number } = {
        "FIN": 1 << 0,
        "SYN": 1 << 1,
        "RST": 1 << 2,
        "PSH": 1 << 3,
        "ACK": 1 << 4,
        "URG": 1 << 5,
        "ECE": 1 << 6,
        "CWR": 1 << 7,
    };
    const activeFlags = Object.entries(tcpFlags)
        .filter(([_, value]) => (flags & value) === value)
        .map(([key]) => key);
    return activeFlags.join('|');
}

// Extracts an integer from an OpResult, throws if not an Int
function intOfOpResult(input: OpResult): number {
    if (input.type === 'Int') {
        return input.value;
    }
    throw new Error("Trying to extract int from non-int result");
}

// Extracts a float from an OpResult, throws if not a Float
function floatOfOpResult(input: OpResult): number {
    if (input.type === 'Float') {
        return input.value;
    }
    throw new Error("Trying to extract float from non-float result");
}

// Converts an OpResult to a string
function stringOfOpResult(input: OpResult): string {
    switch (input.type) {
        case 'Float': return input.value.toString();
        case 'Int': return input.value.toString();
        case 'IPv4': return input.value; // Assuming IPv4 is stored as string
        case 'MAC': return stringOfMac(input.value);
        case 'Empty': return "Empty";
    }
}

// Converts a Tuple to a string representation
function stringOfTuple(inputTuple: Tuple): string {
    return Array.from(inputTuple.entries())
        .map(([key, value]) => `"${key}" => ${stringOfOpResult(value)}`)
        .join(", ");
}

// Looks up an integer value in a Tuple by key
function lookupInt(key: string, tup: Tuple): number {
    const value = tup.get(key);
    if (!value) throw new Error(`Key "${key}" not found`);
    return intOfOpResult(value);
}

// Looks up a float value in a Tuple by key
function lookupFloat(key: string, tup: Tuple): number {
    const value = tup.get(key);
    if (!value) throw new Error(`Key "${key}" not found`);
    return floatOfOpResult(value);
}

const INIT_TABLE_SIZE = 10000;

// Dumps tuples to console (simulating OCaml's out_channel with console.log)
function dumpTupleOperator(showReset: boolean = false): Operator {
    return {
        next: (tup: Tuple) => console.log(stringOfTuple(tup)),
        reset: (tup: Tuple) => {
            if (showReset) {
                console.log(stringOfTuple(tup));
                console.log("[reset]");
            }
        }
    };
}

// Dumps tuples as CSV to console
function dumpAsCsv(staticField?: [string, string], header: boolean = true): Operator {
    let first = header;
    return {
        next: (tup: Tuple) => {
            if (first) {
                if (staticField) process.stdout.write(`${staticField[0]},`);
                Array.from(tup.keys()).forEach(key => process.stdout.write(`${key},`));
                process.stdout.write("\n");
                first = false;
            }
            if (staticField) process.stdout.write(`${staticField[1]},`);
            Array.from(tup.values()).forEach(value => process.stdout.write(`${stringOfOpResult(value)},`));
            process.stdout.write("\n");
        },
        reset: (_tup: Tuple) => {}
    };
}

// Simplified dumpWaltsCsv (writes to console; file output requires Node.js fs)
function dumpWaltsCsv(filename: string): Operator {
    let first = true;
    return {
        next: (tup: Tuple) => {
            if (first) {
                first = false;
                // Could use fs.writeFileSync with Node.js, but using console for simplicity
            }
            console.log(`${stringOfOpResult(tup.get("src_ip")!)},` +
                        `${stringOfOpResult(tup.get("dst_ip")!)},` +
                        `${stringOfOpResult(tup.get("src_l4_port")!)},` +
                        `${stringOfOpResult(tup.get("dst_l4_port")!)},` +
                        `${stringOfOpResult(tup.get("packet_count")!)},` +
                        `${stringOfOpResult(tup.get("byte_count")!)},` +
                        `${stringOfOpResult(tup.get("epoch_id")!)}`);
        },
        reset: (_tup: Tuple) => {}
    };
}

// Converts string input to OpResult (IPv4 or Int 0)
function getIpOrZero(input: string): OpResult {
    return input === "0" ? { type: 'Int', value: 0 } : { type: 'IPv4', value: input };
}

// Meta meter operator to track tuple counts per epoch
function metaMeter(name: string, nextOp: Operator, staticField?: string): Operator {
    let epochCount = 0;
    let tupsCount = 0;
    return {
        next: (tup: Tuple) => {
            tupsCount++;
            nextOp.next(tup);
        },
        reset: (tup: Tuple) => {
            console.log(`${epochCount},${name},${tupsCount},${staticField || ""}`);
            tupsCount = 0;
            epochCount++;
            nextOp.reset(tup);
        }
    };
}

// Epoch operator to assign epoch IDs based on time
function epochOperator(epochWidth: number, keyOut: string, nextOp: Operator): Operator {
    let epochBoundary = 0;
    let eid = 0;
    return {
        next: (tup: Tuple) => {
            const time = floatOfOpResult(tup.get("time")!);
            if (epochBoundary === 0) {
                epochBoundary = time + epochWidth;
            } else if (time >= epochBoundary) {
                while (time >= epochBoundary) {
                    nextOp.reset(new Map([[keyOut, { type: 'Int', value: eid }]]));
                    epochBoundary += epochWidth;
                    eid++;
                }
            }
            const newTup = new Map(tup).set(keyOut, { type: 'Int', value: eid });
            nextOp.next(newTup);
        },
        reset: (_tup: Tuple) => {
            nextOp.reset(new Map([[keyOut, { type: 'Int', value: eid }]]));
            epochBoundary = 0;
            eid = 0;
        }
    };
}

// Filter operator
function filterOperator(f: (tup: Tuple) => boolean, nextOp: Operator): Operator {
    return {
        next: (tup: Tuple) => { if (f(tup)) nextOp.next(tup); },
        reset: (tup: Tuple) => nextOp.reset(tup)
    };
}

// Filter utility: Compare key value against threshold
function keyGeqInt(key: string, threshold: number): (tup: Tuple) => boolean {
    return (tup: Tuple) => lookupInt(key, tup) >= threshold;
}

// Filter utility: Get mapped int
function getMappedInt(key: string, tup: Tuple): number {
    return lookupInt(key, tup);
}

// Filter utility: Get mapped float
function getMappedFloat(key: string, tup: Tuple): number {
    return lookupFloat(key, tup);
}

// Map operator
function mapOperator(f: (tup: Tuple) => Tuple, nextOp: Operator): Operator {
    return {
        next: (tup: Tuple) => nextOp.next(f(tup)),
        reset: (tup: Tuple) => nextOp.reset(tup)
    };
}

// Utility to serialize a Tuple as a key
function tupleToKey(tup: Tuple): string {
    const entries = Array.from(tup.entries()).sort(([a], [b]) => a.localeCompare(b));
    return entries.map(([key, value]) => `${key}:${stringOfOpResult(value)}`).join(',');
}

// Groupby operator
function groupbyOperator(groupby: (tup: Tuple) => Tuple, reduce: (acc: OpResult, tup: Tuple) => OpResult, outKey: string, nextOp: Operator): Operator {
    const hTbl = new Map<string, { groupingKey: Tuple; value: OpResult }>();
    return {
        next: (tup: Tuple) => {
            const groupingKey = groupby(tup);
            const keyStr = tupleToKey(groupingKey);
            const current = hTbl.get(keyStr);
            const newVal = reduce(current ? current.value : { type: 'Empty' }, tup);
            hTbl.set(keyStr, { groupingKey, value: newVal });
        },
        reset: (tup: Tuple) => {
            hTbl.forEach(({ groupingKey, value }) => {
                const unionedTup = new Map([...groupingKey, ...tup]);
                const finalTup = new Map([...unionedTup, [outKey, value]]);
                nextOp.next(finalTup);
            });
            nextOp.reset(tup);
            hTbl.clear();
        }
    };
}

// Groupby utility: Filter groups by included keys
function filterGroups(inclKeys: string[]): (tup: Tuple) => Tuple {
    return (tup: Tuple) => new Map([...tup].filter(([key]) => inclKeys.includes(key)));
}

// Groupby utility: Single group (empty tuple)
function singleGroup(_tup: Tuple): Tuple {
    return new Map();
}

// Groupby utility: Counter reduction
function counter(val: OpResult, _tup: Tuple): OpResult {
    if (val.type === 'Empty') return { type: 'Int', value: 1 };
    if (val.type === 'Int') return { type: 'Int', value: val.value + 1 };
    return val;
}

// Groupby utility: Sum integers
function sumInts(searchKey: string): (initVal: OpResult, tup: Tuple) => OpResult {
    return (initVal: OpResult, tup: Tuple) => {
        if (initVal.type === 'Empty') return { type: 'Int', value: 0 };
        if (initVal.type === 'Int') {
            const found = tup.get(searchKey);
            if (found && found.type === 'Int') return { type: 'Int', value: found.value + initVal.value };
            throw new Error(`'sumInts' failed to find integer value mapped to "${searchKey}"`);
        }
        return initVal;
    };
}

// Distinct operator
function distinctOperator(groupby: (tup: Tuple) => Tuple, nextOp: Operator): Operator {
    const hTbl = new Map<string, Tuple>();
    return {
        next: (tup: Tuple) => {
            const groupingKey = groupby(tup);
            const keyStr = tupleToKey(groupingKey);
            if (!hTbl.has(keyStr)) hTbl.set(keyStr, groupingKey);
        },
        reset: (tup: Tuple) => {
            hTbl.forEach(groupingKey => {
                const mergedTup = new Map([...tup, ...groupingKey]);
                nextOp.next(mergedTup);
            });
            nextOp.reset(tup);
            hTbl.clear();
        }
    };
}

// Split operator
function splitOperator(l: Operator, r: Operator): Operator {
    return {
        next: (tup: Tuple) => { l.next(tup); r.next(tup); },
        reset: (tup: Tuple) => { l.reset(tup); r.reset(tup); }
    };
}

// Join operator (simplified; full implementation requires file I/O context)
type KeyExtractor = (tup: Tuple) => [Tuple, Tuple];
function joinOperator(eidKey: string = "eid", leftExtractor: KeyExtractor, rightExtractor: KeyExtractor, nextOp: Operator): [Operator, Operator] {
    const hTbl1 = new Map<string, Tuple>();
    const hTbl2 = new Map<string, Tuple>();
    let leftCurrEpoch = 0;
    let rightCurrEpoch = 0;

    function handleJoinSide(currHTbl: Map<string, Tuple>, otherHTbl: Map<string, Tuple>, currEpochRef: number, otherEpochRef: number, f: KeyExtractor): Operator {
        return {
            next: (tup: Tuple) => {
                const [key, vals] = f(tup);
                const currEpoch = getMappedInt(eidKey, tup);
                while (currEpoch > currEpochRef) {
                    if (otherEpochRef > currEpochRef) {
                        nextOp.reset(new Map([[eidKey, { type: 'Int', value: currEpochRef }]]));
                    }
                    currEpochRef++;
                }
                const newTup = new Map([...key, [eidKey, { type: 'Int', value: currEpoch }]] as [string, OpResult][]);
                const keyStr = tupleToKey(newTup);
                const match = otherHTbl.get(keyStr);
                if (match) {
                    otherHTbl.delete(keyStr);
                    const merged = new Map([...newTup, ...vals, ...match]);
                    nextOp.next(merged);
                } else {
                    currHTbl.set(keyStr, vals);
                }
            },
            reset: (tup: Tuple) => {
                const currEpoch = getMappedInt(eidKey, tup);
                while (currEpoch > currEpochRef) {
                    if (otherEpochRef > currEpochRef) {
                        nextOp.reset(new Map([[eidKey, { type: 'Int', value: currEpochRef }]]));
                    }
                    currEpochRef++;
                }
            }
        };
    }

    return [
        handleJoinSide(hTbl1, hTbl2, leftCurrEpoch, rightCurrEpoch, leftExtractor),
        handleJoinSide(hTbl2, hTbl1, rightCurrEpoch, leftCurrEpoch, rightExtractor)
    ];
}

// Join utility: Rename and filter keys
function renameFilteredKeys(renamings: [string, string][]): (tup: Tuple) => Tuple {
    return (inTup: Tuple) => {
        let newTup = new Map();
        for (const [oldKey, newKey] of renamings) {
            const val = inTup.get(oldKey);
            if (val) newTup.set(newKey, val);
        }
        return newTup;
    };
}

// Identity operator (filters out eth.src and eth.dst)
function ident(nextOp: Operator): Operator {
    return mapOperator(
        tup => new Map([...tup].filter(([key]) => key !== "eth.src" && key !== "eth.dst")),
        nextOp
    );
}

// Count packets per epoch
function countPkts(nextOp: Operator): Operator {
    const groupbyOp = groupbyOperator(singleGroup, counter, "pkts", nextOp);
    return epochOperator(1.0, "eid", groupbyOp);
}

// Packets per source-destination pair
function pktsPerSrcDst(nextOp: Operator): Operator {
    const groupbyOp = groupbyOperator(filterGroups(["ipv4.src", "ipv4.dst"]), counter, "pkts", nextOp);
    return epochOperator(1.0, "eid", groupbyOp);
}

// Distinct sources
function distinctSrcs(nextOp: Operator): Operator {
    const groupbyOp = groupbyOperator(singleGroup, counter, "srcs", nextOp);
    const distinctOp = distinctOperator(filterGroups(["ipv4.src"]), groupbyOp);
    return epochOperator(1.0, "eid", distinctOp);
}

// Sonata 1: TCP new connections
function tcpNewCons(nextOp: Operator): Operator {
    const threshold = 40;
    const filterThreshold = filterOperator(keyGeqInt("cons", threshold), nextOp);
    const groupbyOp = groupbyOperator(filterGroups(["ipv4.dst"]), counter, "cons", filterThreshold);
    const filterTcpSyn = filterOperator(
        tup => getMappedInt("ipv4.proto", tup) === 6 && getMappedInt("l4.flags", tup) === 2,
        groupbyOp
    );
    return epochOperator(1.0, "eid", filterTcpSyn);
}

// Sonata 2: SSH brute force
function sshBruteForce(nextOp: Operator): Operator {
    const threshold = 40;
    const filterThreshold = filterOperator(keyGeqInt("srcs", threshold), nextOp);
    const groupbyOp = groupbyOperator(filterGroups(["ipv4.dst", "ipv4.len"]), counter, "srcs", filterThreshold);
    const distinctOp = distinctOperator(filterGroups(["ipv4.src", "ipv4.dst", "ipv4.len"]), groupbyOp);
    const filterSsh = filterOperator(
        tup => getMappedInt("ipv4.proto", tup) === 6 && getMappedInt("l4.dport", tup) === 22,
        distinctOp
    );
    return epochOperator(1.0, "eid", filterSsh);
}

// Sonata 3: Super spreader
function superSpreader(nextOp: Operator): Operator {
    const threshold = 40;
    const filterThreshold = filterOperator(keyGeqInt("dsts", threshold), nextOp);
    const groupbyOp = groupbyOperator(filterGroups(["ipv4.src"]), counter, "dsts", filterThreshold);
    const distinctOp = distinctOperator(filterGroups(["ipv4.src", "ipv4.dst"]), groupbyOp);
    return epochOperator(1.0, "eid", distinctOp);
}

// Sonata 4: Port scan
function portScan(nextOp: Operator): Operator {
    const threshold = 40;
    const filterThreshold = filterOperator(keyGeqInt("ports", threshold), nextOp);
    const groupbyOp = groupbyOperator(filterGroups(["ipv4.src"]), counter, "ports", filterThreshold);
    const distinctOp = distinctOperator(filterGroups(["ipv4.src", "l4.dport"]), groupbyOp);
    return epochOperator(1.0, "eid", distinctOp);
}

// Sonata 5: DDoS
function ddos(nextOp: Operator): Operator {
    const threshold = 45;
    const filterThreshold = filterOperator(keyGeqInt("srcs", threshold), nextOp);
    const groupbyOp = groupbyOperator(filterGroups(["ipv4.dst"]), counter, "srcs", filterThreshold);
    const distinctOp = distinctOperator(filterGroups(["ipv4.src", "ipv4.dst"]), groupbyOp);
    return epochOperator(1.0, "eid", distinctOp);
}

// Sonata 6: SYN flood (returns list of operators)
function synFloodSonata(nextOp: Operator): Operator[] {
    const threshold = 3;
    const epochDur = 1.0;

    const syns = (nextOp: Operator) => {
        const groupbyOp = groupbyOperator(filterGroups(["ipv4.dst"]), counter, "syns", nextOp);
        const filterSyn = filterOperator(
            tup => getMappedInt("ipv4.proto", tup) === 6 && getMappedInt("l4.flags", tup) === 2,
            groupbyOp
        );
        return epochOperator(epochDur, "eid", filterSyn);
    };

    const synacks = (nextOp: Operator) => {
        const groupbyOp = groupbyOperator(filterGroups(["ipv4.src"]), counter, "synacks", nextOp);
        const filterSynAck = filterOperator(
            tup => getMappedInt("ipv4.proto", tup) === 6 && getMappedInt("l4.flags", tup) === 18,
            groupbyOp
        );
        return epochOperator(epochDur, "eid", filterSynAck);
    };

    const acks = (nextOp: Operator) => {
        const groupbyOp = groupbyOperator(filterGroups(["ipv4.dst"]), counter, "acks", nextOp);
        const filterAck = filterOperator(
            tup => getMappedInt("ipv4.proto", tup) === 6 && getMappedInt("l4.flags", tup) === 16,
            groupbyOp
        );
        return epochOperator(epochDur, "eid", filterAck);
    };

    const [joinOp1, joinOp2] = joinOperator(
        "eid",
        tup => [renameFilteredKeys([["ipv4.dst", "host"]])(tup), filterGroups(["syns"])(tup)],
        tup => [renameFilteredKeys([["ipv4.src", "host"]])(tup), filterGroups(["synacks"])(tup)]
    );
    const mapOp = mapOperator(
        tup => new Map([...tup, ["syns+synacks", { type: 'Int', value: getMappedInt("syns", tup) + getMappedInt("synacks", tup) }]]),
        joinOp1
    );
    const [joinOp3, joinOp4] = joinOperator(
        "eid",
        tup => [filterGroups(["host"])(tup), filterGroups(["syns+synacks"])(tup)],
        tup => [renameFilteredKeys([["ipv4.dst", "host"]])(tup), filterGroups(["acks"])(tup)]
    );
    const mapFinal = mapOperator(
        tup => new Map([...tup, ["syns+synacks-acks", { type: 'Int', value: getMappedInt("syns+synacks", tup) - getMappedInt("acks", tup) }]]),
        filterOperator(keyGeqInt("syns+synacks-acks", threshold), nextOp)
    );

    return [syns(mapOp), synacks(joinOp4), acks(joinOp2)];
}

// Sonata 7: Completed flows
function completedFlows(nextOp: Operator): Operator[] {
    const threshold = 1;
    const epochDur = 30.0;

    const syns = (nextOp: Operator) => {
        const groupbyOp = groupbyOperator(filterGroups(["ipv4.dst"]), counter, "syns", nextOp);
        const filterSyn = filterOperator(
            tup => getMappedInt("ipv4.proto", tup) === 6 && getMappedInt("l4.flags", tup) === 2,
            groupbyOp
        );
        return epochOperator(epochDur, "eid", filterSyn);
    };

    const fins = (nextOp: Operator) => {
        const groupbyOp = groupbyOperator(filterGroups(["ipv4.src"]), counter, "fins", nextOp);
        const filterFin = filterOperator(
            tup => getMappedInt("ipv4.proto", tup) === 6 && (getMappedInt("l4.flags", tup) & 1) === 1,
            groupbyOp
        );
        return epochOperator(epochDur, "eid", filterFin);
    };

    const [op1, op2] = joinOperator(
        "eid",
        tup => [renameFilteredKeys([["ipv4.dst", "host"]])(tup), filterGroups(["syns"])(tup)],
        tup => [renameFilteredKeys([["ipv4.src", "host"]])(tup), filterGroups(["fins"])(tup)]
    );
    const mapOp = mapOperator(
        tup => new Map([...tup, ["diff", { type: 'Int', value: getMappedInt("syns", tup) - getMappedInt("fins", tup) }]]),
        filterOperator(keyGeqInt("diff", threshold), nextOp)
    );

    return [syns(op1), fins(op2)];
}

// Sonata 8: Slowloris
function slowloris(nextOp: Operator): Operator[] {
    const t1 = 5;
    const t2 = 500;
    const t3 = 90;
    const epochDur = 1.0;

    const nConns = (nextOp: Operator) => {
        const filterT1 = filterOperator(tup => getMappedInt("n_conns", tup) >= t1, nextOp);
        const groupbyOp = groupbyOperator(filterGroups(["ipv4.dst"]), counter, "n_conns", filterT1);
        const distinctOp = distinctOperator(filterGroups(["ipv4.src", "ipv4.dst", "l4.sport"]), groupbyOp);
        const filterTcp = filterOperator(tup => getMappedInt("ipv4.proto", tup) === 6, distinctOp);
        return epochOperator(epochDur, "eid", filterTcp);
    };

    const nBytes = (nextOp: Operator) => {
        const filterT2 = filterOperator(tup => getMappedInt("n_bytes", tup) >= t2, nextOp);
        const groupbyOp = groupbyOperator(filterGroups(["ipv4.dst"]), sumInts("ipv4.len"), "n_bytes", filterT2);
        const filterTcp = filterOperator(tup => getMappedInt("ipv4.proto", tup) === 6, groupbyOp);
        return epochOperator(epochDur, "eid", filterTcp);
    };

    const [op1, op2] = joinOperator(
        "eid",
        tup => [filterGroups(["ipv4.dst"])(tup), filterGroups(["n_conns"])(tup)],
        tup => [filterGroups(["ipv4.dst"])(tup), filterGroups(["n_bytes"])(tup)]
    );
    const mapOp = mapOperator(
        tup => new Map([...tup, ["bytes_per_conn", { type: 'Int', value: Math.floor(getMappedInt("n_bytes", tup) / getMappedInt("n_conns", tup)) }]]),
        filterOperator(tup => getMappedInt("bytes_per_conn", tup) <= t3, nextOp)
    );

    return [nConns(op1), nBytes(op2)];
}

// Additional test queries
function joinTest(nextOp: Operator): Operator[] {
    const epochDur = 1.0;

    const syns = (nextOp: Operator) => {
        const filterSyn = filterOperator(
            tup => getMappedInt("ipv4.proto", tup) === 6 && getMappedInt("l4.flags", tup) === 2,
            nextOp
        );
        return epochOperator(epochDur, "eid", filterSyn);
    };

    const synacks = (nextOp: Operator) => {
        const filterSynAck = filterOperator(
            tup => getMappedInt("ipv4.proto", tup) === 6 && getMappedInt("l4.flags", tup) === 18,
            nextOp
        );
        return epochOperator(epochDur, "eid", filterSynAck);
    };

    const [op1, op2] = joinOperator(
        "eid",
        tup => [renameFilteredKeys([["ipv4.src", "host"]])(tup), renameFilteredKeys([["ipv4.dst", "remote"]])(tup)],
        tup => [renameFilteredKeys([["ipv4.dst", "host"]])(tup), filterGroups(["time"])(tup)]
    );

    return [syns(op1), synacks(op2)];
}

function q3(nextOp: Operator): Operator {
    const distinctOp = distinctOperator(filterGroups(["ipv4.src", "ipv4.dst"]), nextOp);
    return epochOperator(100.0, "eid", distinctOp);
}

function q4(nextOp: Operator): Operator {
    const groupbyOp = groupbyOperator(filterGroups(["ipv4.dst"]), counter, "pkts", nextOp);
    return epochOperator(10000.0, "eid", groupbyOp);
}

// Queries to run
const queries: Operator[] = [ident(dumpTupleOperator())];

// Simulate tuple stream and run queries
function runQueries(): void {
    const tuples = Array.from({ length: 20 }, (_, i) =>
        tupleOfList([
            ["time", { type: 'Float', value: 0.000000 + i }],
            ["eth.src", { type: 'MAC', value: new Uint8Array([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]) }],
            ["eth.dst", { type: 'MAC', value: new Uint8Array([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]) }],
            ["eth.ethertype", { type: 'Int', value: 0x0800 }],
            ["ipv4.hlen", { type: 'Int', value: 20 }],
            ["ipv4.proto", { type: 'Int', value: 6 }],
            ["ipv4.len", { type: 'Int', value: 60 }],
            ["ipv4.src", { type: 'IPv4', value: "127.0.0.1" }],
            ["ipv4.dst", { type: 'IPv4', value: "127.0.0.1" }],
            ["l4.sport", { type: 'Int', value: 440 }],
            ["l4.dport", { type: 'Int', value: 50000 }],
            ["l4.flags", { type: 'Int', value: 10 }]
        ])
    );

    tuples.forEach(tup => queries.forEach(query => query.next(tup)));
    console.log("Done");
}

// Execute
runQueries();

