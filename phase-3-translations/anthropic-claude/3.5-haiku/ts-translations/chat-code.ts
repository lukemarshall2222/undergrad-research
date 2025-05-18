// Type definitions
enum OpResultType {
    Float,
    Int,
    IPv4,
    MAC,
    Empty
}

type OpResult = 
    | { type: OpResultType.Float, value: number }
    | { type: OpResultType.Int, value: number }
    | { type: OpResultType.IPv4, value: string }
    | { type: OpResultType.MAC, value: string }
    | { type: OpResultType.Empty };

// Utility functions for type checking and conversion
function isInt(result: OpResult): result is { type: OpResultType.Int, value: number } {
    return result.type === OpResultType.Int;
}

function isFloat(result: OpResult): result is { type: OpResultType.Float, value: number } {
    return result.type === OpResultType.Float;
}

function intOfOpResult(result: OpResult): number {
    if (isInt(result)) return result.value;
    throw new Error("Trying to extract int from non-int result");
}

function floatOfOpResult(result: OpResult): number {
    if (isFloat(result)) return result.value;
    throw new Error("Trying to extract float from non-float result");
}

// Tuple type as a map of string keys to OpResult values
type Tuple = Map<string, OpResult>;

// Operator interface
interface Operator {
    next: (tup: Tuple) => void;
    reset: (tup: Tuple) => void;
}

// Utility functions to create tuples and manipulate them
function tupleOfList(tupList: [string, OpResult][]): Tuple {
    return new Map(tupList);
}

function stringOfOpResult(input: OpResult): string {
    switch (input.type) {
        case OpResultType.Float: return input.value.toString();
        case OpResultType.Int: return input.value.toString();
        case OpResultType.IPv4: return input.value;
        case OpResultType.MAC: return input.value;
        case OpResultType.Empty: return "Empty";
    }
}

function stringOfTuple(inputTuple: Tuple): string {
    return Array.from(inputTuple.entries())
        .map(([key, value]) => `"${key}" => ${stringOfOpResult(value)}`)
        .join(", ");
}

// Filtering, mapping, and grouping utilities
type GroupingFunc = (tup: Tuple) => Tuple;
type ReductionFunc = (val: OpResult, tup: Tuple) => OpResult;

// Core operators like epoch, filter, groupby will be similar to OCaml version
function epoch(epochWidth: number, keyOut: string, nextOp: Operator): Operator {
    let epochBoundary = 0.0;
    let eid = 0;

    return {
        next: (tup: Tuple) => {
            const time = floatOfOpResult(tup.get('time')!);

            if (epochBoundary === 0.0) {
                epochBoundary = time + epochWidth;
            } else if (time >= epochBoundary) {
                while (time >= epochBoundary) {
                    nextOp.reset(new Map([[keyOut, { type: OpResultType.Int, value: eid }]]));
                    epochBoundary += epochWidth;
                    eid++;
                }
            }

            const newTup = new Map(tup);
            newTup.set(keyOut, { type: OpResultType.Int, value: eid });
            nextOp.next(newTup);
        },
        reset: () => {
            nextOp.reset(new Map([[keyOut, { type: OpResultType.Int, value: eid }]]));
            epochBoundary = 0.0;
            eid = 0;
        }
    };
}

function filter(predicate: (tup: Tuple) => boolean, nextOp: Operator): Operator {
    return {
        next: (tup: Tuple) => {
            if (predicate(tup)) nextOp.next(tup);
        },
        reset: (tup: Tuple) => {
            nextOp.reset(tup);
        }
    };
}

function groupby(
    groupbyFunc: GroupingFunc, 
    reduceFunc: ReductionFunc, 
    outKey: string, 
    nextOp: Operator
): Operator {
    const hashTable = new Map<string, OpResult>();

    return {
        next: (tup: Tuple) => {
            const groupingKey = groupbyFunc(tup);
            const groupingKeyStr = stringOfTuple(groupingKey);

            const existingVal = hashTable.get(groupingKeyStr);
            const newVal = reduceFunc(existingVal ?? { type: OpResultType.Empty }, tup);
            hashTable.set(groupingKeyStr, newVal);
        },
        reset: (tup: Tuple) => {
            for (const [groupingKeyStr, val] of hashTable) {
                const groupingKey = tupleOfList(
                    Array.from(new Map(groupingKeyStr.split(", ").map(entry => {
                        const [key, value] = entry.split(" => ");
                        return [key.replace(/"/g, ''), parseOpResult(value)];
                    })).entries())
                );

                const unionedTup = new Map(tup);
                for (const [key, value] of groupingKey) {
                    if (!unionedTup.has(key)) {
                        unionedTup.set(key, value);
                    }
                }
                
                unionedTup.set(outKey, val);
                nextOp.next(unionedTup);
            }

            nextOp.reset(tup);
            hashTable.clear();
        }
    };
}

// Helper function to parse string representation back to OpResult
function parseOpResult(value: string): OpResult {
    // Implementation depends on your specific string format
    // This is a simplified version
    if (value === "Empty") return { type: OpResultType.Empty };
    if (/^\d+$/.test(value)) return { type: OpResultType.Int, value: parseInt(value) };
    if (/^\d+\.\d+$/.test(value)) return { type: OpResultType.Float, value: parseFloat(value) };
    if (/^[0-9a-fA-F:]+$/.test(value)) return { type: OpResultType.MAC, value };
    return { type: OpResultType.IPv4, value };
}

// Continued from previous translation...

// Utility functions for grouping and filtering
function filterGroups(inclKeys: string[]): GroupingFunc {
    return (tup: Tuple) => {
        const filteredTup = new Map<string, OpResult>();
        for (const [key, value] of tup) {
            if (inclKeys.includes(key)) {
                filteredTup.set(key, value);
            }
        }
        return filteredTup;
    };
}

function singleGroup(_tup: Tuple): Tuple {
    return new Map();
}

// Reduction functions
function counter(val: OpResult, _tup: Tuple): OpResult {
    switch (val.type) {
        case OpResultType.Empty:
            return { type: OpResultType.Int, value: 1 };
        case OpResultType.Int:
            return { type: OpResultType.Int, value: val.value + 1 };
        default:
            return val;
    }
}

function sumInts(searchKey: string, initVal: OpResult, tup: Tuple): OpResult {
    switch (initVal.type) {
        case OpResultType.Empty:
            return { type: OpResultType.Int, value: 0 };
        case OpResultType.Int: {
            const searchVal = tup.get(searchKey);
            if (searchVal && searchVal.type === OpResultType.Int) {
                return { type: OpResultType.Int, value: initVal.value + searchVal.value };
            }
            throw new Error(`Failed to find integer value mapped to "${searchKey}"`);
        }
        default:
            return initVal;
    }
}

// More complex operators
function distinct(groupbyFunc: GroupingFunc, nextOp: Operator): Operator {
    const hashTable = new Map<string, boolean>();

    return {
        next: (tup: Tuple) => {
            const groupingKey = groupbyFunc(tup);
            const groupingKeyStr = stringOfTuple(groupingKey);
            hashTable.set(groupingKeyStr, true);
        },
        reset: (tup: Tuple) => {
            for (const [keyStr] of hashTable) {
                const key = tupleOfList(
                    Array.from(new Map(keyStr.split(", ").map(entry => {
                        const [key, value] = entry.split(" => ");
                        return [key.replace(/"/g, ''), parseOpResult(value)];
                    })).entries())
                );

                const mergedTup = new Map(tup);
                for (const [k, v] of key) {
                    if (!mergedTup.has(k)) {
                        mergedTup.set(k, v);
                    }
                }

                nextOp.next(mergedTup);
            }

            nextOp.reset(tup);
            hashTable.clear();
        }
    };
}

function split(left: Operator, right: Operator): Operator {
    return {
        next: (tup: Tuple) => {
            left.next(tup);
            right.next(tup);
        },
        reset: (tup: Tuple) => {
            left.reset(tup);
            right.reset(tup);
        }
    };
}

// Join implementation
type KeyExtractor = (tup: Tuple) => [Tuple, Tuple];

function join(
    leftExtractor: KeyExtractor, 
    rightExtractor: KeyExtractor, 
    nextOp: Operator, 
    eidKey: string = "eid"
): [Operator, Operator] {
    const hashTable1 = new Map<string, Tuple>();
    const hashTable2 = new Map<string, Tuple>();
    let leftCurrEpoch = 0;
    let rightCurrEpoch = 0;

    function handleJoinSide(
        currHashTable: Map<string, Tuple>, 
        otherHashTable: Map<string, Tuple>,
        currEpochRef: { value: number },
        otherEpochRef: { value: number },
        extractor: KeyExtractor
    ): Operator {
        return {
            next: (tup: Tuple) => {
                const [key, vals] = extractor(tup);
                const keyStr = stringOfTuple(key);
                const currEpoch = intOfOpResult(tup.get(eidKey)!);

                while (currEpoch > currEpochRef.value) {
                    if (otherEpochRef.value > currEpochRef.value) {
                        nextOp.reset(new Map([[eidKey, { type: OpResultType.Int, value: currEpochRef.value }]]));
                    }
                    currEpochRef.value++;
                }

                const newTup = new Map(key);
                newTup.set(eidKey, { type: OpResultType.Int, value: currEpoch });

                const newTupStr = stringOfTuple(newTup);
                const otherVal = otherHashTable.get(newTupStr);

                if (otherVal) {
                    otherHashTable.delete(newTupStr);
                    
                    const mergedTup = new Map(newTup);
                    for (const [k, v] of vals) {
                        if (!mergedTup.has(k)) mergedTup.set(k, v);
                    }
                    for (const [k, v] of otherVal) {
                        if (!mergedTup.has(k)) mergedTup.set(k, v);
                    }

                    nextOp.next(mergedTup);
                } else {
                    currHashTable.set(newTupStr, vals);
                }
            },
            reset: (tup: Tuple) => {
                const currEpoch = intOfOpResult(tup.get(eidKey)!);

                while (currEpoch > currEpochRef.value) {
                    if (otherEpochRef.value > currEpochRef.value) {
                        nextOp.reset(new Map([[eidKey, { type: OpResultType.Int, value: currEpochRef.value }]]));
                    }
                    currEpochRef.value++;
                }
            }
        };
    }

    return [
        handleJoinSide(
            hashTable1, 
            hashTable2, 
            { value: leftCurrEpoch }, 
            { value: rightCurrEpoch }, 
            leftExtractor
        ),
        handleJoinSide(
            hashTable2, 
            hashTable1, 
            { value: rightCurrEpoch }, 
            { value: leftCurrEpoch }, 
            rightExtractor
        )
    ];
}

// Rename and filter keys for join operations
function renameFilteredKeys(renamingPairs: [string, string][], inTup: Tuple): Tuple {
    const newTup = new Map<string, OpResult>();
    
    for (const [oldKey, newKey] of renamingPairs) {
        const val = inTup.get(oldKey);
        if (val) {
            newTup.set(newKey, val);
        }
    }
    
    return newTup;
}

// Specific query implementations
function tcpNewCons(nextOp: Operator): Operator {
    const threshold = 40;
    
    return groupby(
        filterGroups(["ipv4.dst"]), 
        counter, 
        "cons", 
        filter(
            (tup: Tuple) => 
                intOfOpResult(tup.get("ipv4.proto")!) === 6 && 
                intOfOpResult(tup.get("l4.flags")!) === 2,
            filter(
                (tup: Tuple) => intOfOpResult(tup.get("cons")!) >= threshold,
                nextOp
            )
        )
    );
}

function sshBruteForce(nextOp: Operator): Operator {
    const threshold = 40;
    
    return epoch(1.0, "eid", 
        filter(
            (tup: Tuple) => 
                intOfOpResult(tup.get("ipv4.proto")!) === 6 && 
                intOfOpResult(tup.get("l4.dport")!) === 22,
            distinct(
                filterGroups(["ipv4.src", "ipv4.dst", "ipv4.len"]),
                groupby(
                    filterGroups(["ipv4.dst", "ipv4.len"]),
                    counter,
                    "srcs",
                    filter(
                        (tup: Tuple) => intOfOpResult(tup.get("srcs")!) >= threshold,
                        nextOp
                    )
                )
            )
        )
    );
}

// Example of running queries
function runQueries() {
    const dumper: Operator = {
        next: (tup: Tuple) => {
            console.log(stringOfTuple(tup));
        },
        reset: () => {}
    };

    const queries: Operator[] = [
        tcpNewCons(dumper),
        sshBruteForce(dumper)
    ];

    // Generate sample tuples
    const tuples: Tuple[] = generateSampleTuples();

    tuples.forEach(tup => {
        queries.forEach(query => query.next(tup));
    });
}

// Continued from previous translations...

function superSpreader(nextOp: Operator): Operator {
    const threshold = 40;
    
    return epoch(1.0, "eid", 
        distinct(
            filterGroups(["ipv4.src", "ipv4.dst"]),
            groupby(
                filterGroups(["ipv4.src"]),
                counter,
                "dsts",
                filter(
                    (tup: Tuple) => intOfOpResult(tup.get("dsts")!) >= threshold,
                    nextOp
                )
            )
        )
    );
}

function portScan(nextOp: Operator): Operator {
    const threshold = 40;
    
    return epoch(1.0, "eid", 
        distinct(
            filterGroups(["ipv4.src", "l4.dport"]),
            groupby(
                filterGroups(["ipv4.src"]),
                counter,
                "ports",
                filter(
                    (tup: Tuple) => intOfOpResult(tup.get("ports")!) >= threshold,
                    nextOp
                )
            )
        )
    );
}

function ddos(nextOp: Operator): Operator {
    const threshold = 45;
    
    return epoch(1.0, "eid", 
        distinct(
            filterGroups(["ipv4.src", "ipv4.dst"]),
            groupby(
                filterGroups(["ipv4.dst"]),
                counter,
                "srcs",
                filter(
                    (tup: Tuple) => intOfOpResult(tup.get("srcs")!) >= threshold,
                    nextOp
                )
            )
        )
    );
}

function synFloodSonata(nextOp: Operator): Operator[] {
    const threshold = 3;
    const epochDur = 1.0;

    function syns(nextOp: Operator): Operator {
        return epoch(epochDur, "eid", 
            filter(
                (tup: Tuple) => 
                    intOfOpResult(tup.get("ipv4.proto")!) === 6 &&
                    intOfOpResult(tup.get("l4.flags")!) === 2,
                groupby(
                    filterGroups(["ipv4.dst"]),
                    counter,
                    "syns",
                    nextOp
                )
            )
        );
    }

    function synacks(nextOp: Operator): Operator {
        return epoch(epochDur, "eid", 
            filter(
                (tup: Tuple) => 
                    intOfOpResult(tup.get("ipv4.proto")!) === 6 &&
                    intOfOpResult(tup.get("l4.flags")!) === 18,
                groupby(
                    filterGroups(["ipv4.src"]),
                    counter,
                    "synacks",
                    nextOp
                )
            )
        );
    }

    function acks(nextOp: Operator): Operator {
        return epoch(epochDur, "eid", 
            filter(
                (tup: Tuple) => 
                    intOfOpResult(tup.get("ipv4.proto")!) === 6 &&
                    intOfOpResult(tup.get("l4.flags")!) === 16,
                groupby(
                    filterGroups(["ipv4.dst"]),
                    counter,
                    "acks",
                    nextOp
                )
            )
        );
    }

    const [joinOp1, joinOp2] = join(
        (tup: Tuple) => [
            filterGroups(["host"])(tup), 
            filterGroups(["syns+synacks"])(tup)
        ],
        (tup: Tuple) => [
            renameFilteredKeys([["ipv4.dst", "host"]], tup), 
            filterGroups(["acks"])(tup)
        ],
        map(
            (tup: Tuple) => {
                const synsAndSynacks = intOfOpResult(tup.get("syns+synacks")!);
                const acks = intOfOpResult(tup.get("acks")!);
                const newTup = new Map(tup);
                newTup.set("syns+synacks-acks", { 
                    type: OpResultType.Int, 
                    value: synsAndSynacks - acks 
                });
                return newTup;
            },
            filter(
                (tup: Tuple) => intOfOpResult(tup.get("syns+synacks-acks")!) >= threshold,
                nextOp
            )
        )
    );

    const [joinOp3, joinOp4] = join(
        (tup: Tuple) => [
            renameFilteredKeys([["ipv4.dst", "host"]], tup), 
            filterGroups(["syns"])(tup)
        ],
        (tup: Tuple) => [
            renameFilteredKeys([["ipv4.src", "host"]], tup), 
            filterGroups(["synacks"])(tup)
        ],
        map(
            (tup: Tuple) => {
                const syns = intOfOpResult(tup.get("syns")!);
                const synacks = intOfOpResult(tup.get("synacks")!);
                const newTup = new Map(tup);
                newTup.set("syns+synacks", { 
                    type: OpResultType.Int, 
                    value: syns + synacks 
                });
                return newTup;
            },
            joinOp1
        )
    );

    return [
        syns(joinOp3),
        synacks(joinOp4),
        acks(joinOp2)
    ];
}

function completedFlows(nextOp: Operator): Operator[] {
    const threshold = 1;
    const epochDur = 30.0;

    function syns(nextOp: Operator): Operator {
        return epoch(epochDur, "eid", 
            filter(
                (tup: Tuple) => 
                    intOfOpResult(tup.get("ipv4.proto")!) === 6 &&
                    intOfOpResult(tup.get("l4.flags")!) === 2,
                groupby(
                    filterGroups(["ipv4.dst"]),
                    counter,
                    "syns",
                    nextOp
                )
            )
        );
    }

    function fins(nextOp: Operator): Operator {
        return epoch(epochDur, "eid", 
            filter(
                (tup: Tuple) => 
                    intOfOpResult(tup.get("ipv4.proto")!) === 6 &&
                    (intOfOpResult(tup.get("l4.flags")!) & 1) === 1,
                groupby(
                    filterGroups(["ipv4.src"]),
                    counter,
                    "fins",
                    nextOp
                )
            )
        );
    }

    const [op1, op2] = join(
        (tup: Tuple) => [
            renameFilteredKeys([["ipv4.dst", "host"]], tup), 
            filterGroups(["syns"])(tup)
        ],
        (tup: Tuple) => [
            renameFilteredKeys([["ipv4.src", "host"]], tup), 
            filterGroups(["fins"])(tup)
        ],
        map(
            (tup: Tuple) => {
                const syns = intOfOpResult(tup.get("syns")!);
                const fins = intOfOpResult(tup.get("fins")!);
                const newTup = new Map(tup);
                newTup.set("diff", { 
                    type: OpResultType.Int, 
                    value: syns - fins 
                });
                return newTup;
            },
            filter(
                (tup: Tuple) => intOfOpResult(tup.get("diff")!) >= threshold,
                nextOp
            )
        )
    );

    return [
        syns(op1),
        fins(op2)
    ];
}

function slowloris(nextOp: Operator): Operator[] {
    const t1 = 5;    // min number of connections
    const t2 = 500;  // min total bytes
    const t3 = 90;   // max bytes per connection
    const epochDur = 1.0;

    function nConns(nextOp: Operator): Operator {
        return epoch(epochDur, "eid", 
            filter(
                (tup: Tuple) => intOfOpResult(tup.get("ipv4.proto")!) === 6,
                distinct(
                    filterGroups(["ipv4.src", "ipv4.dst", "l4.sport"]),
                    groupby(
                        filterGroups(["ipv4.dst"]),
                        counter,
                        "n_conns",
                        filter(
                            (tup: Tuple) => intOfOpResult(tup.get("n_conns")!) >= t1,
                            nextOp
                        )
                    )
                )
            )
        );
    }

    function nBytes(nextOp: Operator): Operator {
        return epoch(epochDur, "eid", 
            filter(
                (tup: Tuple) => intOfOpResult(tup.get("ipv4.proto")!) === 6,
                groupby(
                    filterGroups(["ipv4.dst"]),
                    (val: OpResult, tup: Tuple) => sumInts("ipv4.len", val, tup),
                    "n_bytes",
                    filter(
                        (tup: Tuple) => intOfOpResult(tup.get("n_bytes")!) >= t2,
                        nextOp
                    )
                )
            )
        );
    }

    const [op1, op2] = join(
        (tup: Tuple) => [
            filterGroups(["ipv4.dst"])(tup), 
            filterGroups(["n_conns"])(tup)
        ],
        (tup: Tuple) => [
            filterGroups(["ipv4.dst"])(tup), 
            filterGroups(["n_bytes"])(tup)
        ],
        map(
            (tup: Tuple) => {
                const nBytes = intOfOpResult(tup.get("n_bytes")!);
                const nConns = intOfOpResult(tup.get("n_conns")!);
                const newTup = new Map(tup);
                newTup.set("bytes_per_conn", { 
                    type: OpResultType.Int, 
                    value: Math.floor(nBytes / nConns)
                });
                return newTup;
            },
            filter(
                (tup: Tuple) => intOfOpResult(tup.get("bytes_per_conn")!) <= t3,
                nextOp
            )
        )
    );

    return [
        nConns(op1),
        nBytes(op2)
    ];
}

// Utility functions for map and chaining operators
function map(mapFunc: (tup: Tuple) => Tuple, nextOp: Operator): Operator {
    return {
        next: (tup: Tuple) => {
            nextOp.next(mapFunc(tup));
        },
        reset: (tup: Tuple) => {
            nextOp.reset(tup);
        }
    };
}

// Operator chaining utility
function chainOperators(...operators: Operator[]): Operator {
    if (operators.length === 0) {
        throw new Error("At least one operator is required");
    }

    if (operators.length === 1) {
        return operators[0];
    }

    return operators.reduce((prev, curr) => ({
        next: (tup: Tuple) => {
            prev.next(tup);
        },
        reset: (tup: Tuple) => {
            prev.reset(tup);
        }
    }));
}

// CSV dumping utilities
function dumpTuple(outChannel: (msg: string) => void): Operator {
    return {
        next: (tup: Tuple) => {
            outChannel(stringOfTuple(tup));
        },
        reset: () => {}
    };
}

function dumpAsCsv(outChannel: (msg: string) => void): Operator {
    let first = true;

    return {
        next: (tup: Tuple) => {
            if (first) {
                // Print header
                const header = Array.from(tup.keys()).join(',');
                outChannel(header);
                first = false;
            }

            // Print row
            const row = Array.from(tup.values())
                .map(val => stringOfOpResult(val))
                .join(',');
            outChannel(row);
        },
        reset: () => {
            first = true;
        }
    };
}

function generateSampleTuples(): Tuple[] {
    const tuples: Tuple[] = [];
    
    for (let i = 0; i < 20; i++) {
        const tup = new Map<string, OpResult>([
            ["time", { type: OpResultType.Float, value: 0.000000 + i }],
            ["eth.src", { type: OpResultType.MAC, value: "00:11:22:33:44:55" }],
            ["eth.dst", { type: OpResultType.MAC, value: "AA:BB:CC:DD:EE:FF" }],
            ["eth.ethertype", { type: OpResultType.Int, value: 0x0800 }],
            ["ipv4.hlen", { type: OpResultType.Int, value: 20 }],
            ["ipv4.proto", { type: OpResultType.Int, value: 6 }],
            ["ipv4.len", { type: OpResultType.Int, value: 60 }],
            ["ipv4.src", { type: OpResultType.IPv4, value: "127.0.0.1" }],
            ["ipv4.dst", { type: OpResultType.IPv4, value: "127.0.0.1" }],
            ["l4.sport", { type: OpResultType.Int, value: 440 }],
            ["l4.dport", { type: OpResultType.Int, value: 50000 }],
            ["l4.flags", { type: OpResultType.Int, value: 10 }]
        ]);
        
        tuples.push(tup);
    }
    
    return tuples;
}

// Main entry point for demonstration
function main() {
    const dumper = dumpTuple(console.log);
    const csvDumper = dumpAsCsv(console.log);

    const queries: Operator[] = [
        tcpNewCons(dumper),
        sshBruteForce(dumper),
        superSpreader(dumper),
        portScan(dumper),
        ddos(dumper)
    ];

    const tuples = generateSampleTuples();

    tuples.forEach(tup => {
        queries.forEach(query => query.next(tup));
    });
}

// Run the main function
main();
