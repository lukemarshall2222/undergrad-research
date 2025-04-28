/**
 * Common utilities
 *
 * Includes minimal parsing of header fields into a map from strings to values
 */

/**
 * Operators act on named "tuples" which are maps from strings to OpResult types
 **************************************************************************************
 */

// Variant type for operation results
type OpResult =
    | { type: 'Float', value: number }
    | { type: 'Int', value: number }
    | { type: 'IPv4', value: string }
    | { type: 'MAC', value: Uint8Array }
    | { type: 'Empty' };

// TypeScript Map instead of OCaml's Map.Make
type Tuple = Map<string, OpResult>;

// Defines a data processing unit in a stream processing pipeline
interface Operator {
    next: (tup: Tuple) => void;
    reset: (tup: Tuple) => void;
}

type OpCreator = (nextOp: Operator) => Operator;
type DblOpCreator = (op: Operator) => [Operator, Operator];

/**
 * Right associative "chaining" operator
 * for passing output of one operator to the next under cps-style operator constructors
 */
function chain(opCreatorFunc: OpCreator, nextOp: Operator): Operator {
    return opCreatorFunc(nextOp);
}

function dblChain(opCreatorFunc: DblOpCreator, op: Operator): [Operator, Operator] {
    return opCreatorFunc(op);
}

/**
 * Conversion utilities
 **************************************************************************************
 */

// Formats the 6 bytes of the MAC address as a colon-separated string in hex
function stringOfMac(buf: Uint8Array): string {
    return Array.from(buf.slice(0, 6))
        .map(byte => byte.toString(16).padStart(2, '0'))
        .join(':');
}

// Converts TCP flags into a human-readable string representation
function tcpFlagsToStrings(flags: number): string {
    const tcpFlagsMap = new Map([
        ["FIN", 1 << 0],
        ["SYN", 1 << 1],
        ["RST", 1 << 2],
        ["PSH", 1 << 3],
        ["ACK", 1 << 4],
        ["URG", 1 << 5],
        ["ECE", 1 << 6],
        ["CWR", 1 << 7]
    ]);
    
    return Array.from(tcpFlagsMap.entries())
        .filter(([_, value]) => (flags & value) === value)
        .map(([key, _]) => key)
        .join('|');
}

// Checks if input is an Int OpResult, raises exception otherwise
function intOfOpResult(input: OpResult): number {
    if (input.type === 'Int') {
        return input.value;
    }
    throw new Error("Trying to extract int from non-int result");
}

// Checks if input is a Float OpResult, raises exception otherwise
function floatOfOpResult(input: OpResult): number {
    if (input.type === 'Float') {
        return input.value;
    }
    throw new Error("Trying to extract float from non-float result");
}

// Returns the human-readable version of each OpResult value
function stringOfOpResult(input: OpResult): string {
    switch (input.type) {
        case 'Float':
            return input.value.toString();
        case 'Int':
            return input.value.toString();
        case 'IPv4':
            return input.value;
        case 'MAC':
            return stringOfMac(input.value);
        case 'Empty':
            return "Empty";
    }
}

// Outputs the tuple in a human-readable form
function stringOfTuple(inputTuple: Tuple): string {
    let result = "";
    inputTuple.forEach((val, key) => {
        result += `"${key}" => ${stringOfOpResult(val)}, `;
    });
    return result;
}

// Creates a Tuple (Map<string, OpResult>) out of a list of entries
function tupleOfList(tupList: [string, OpResult][]): Tuple {
    return new Map(tupList);
}

// Prints formatted representation of a Tuple
function dumpTuple(outc: any, tup: Tuple): void {
    console.log(stringOfTuple(tup));
}

// Retrieves the int value of the OpResult associated with a given key
function lookupInt(key: string, tup: Tuple): number {
    const value = tup.get(key);
    if (!value) throw new Error(`Key ${key} not found`);
    return intOfOpResult(value);
}

// Retrieves the float value of the OpResult associated with a given key
function lookupFloat(key: string, tup: Tuple): number {
    const value = tup.get(key);
    if (!value) throw new Error(`Key ${key} not found`);
    return floatOfOpResult(value);
}

/**
 * Built-in operator definitions
 * and common utilities for readability
 */

const INIT_TABLE_SIZE = 10000;

/**
 * Dump all fields of all tuples to the given output channel
 * Note that dump is terminal in that it does not take a continuation operator
 * as argument
 */
function dumpTupleOp(outc: any, showReset: boolean = false): Operator {
    return {
        next: (tup: Tuple) => dumpTuple(outc, tup),
        reset: (tup: Tuple) => {
            if (showReset) {
                dumpTuple(outc, tup);
                console.log("[reset]");
            }
        }
    };
}

/**
 * Tries to dump a nice csv-style output
 * Assumes all tuples have the same fields in the same order...
 */
function dumpAsCSV(outc: any, staticField: [string, string] | null = null, header: boolean = true): Operator {
    let first = header;
    return {
        next: (tup: Tuple) => {
            if (first) {
                if (staticField) {
                    process.stdout.write(`${staticField[0]},`);
                }
                tup.forEach((_, key) => {
                    process.stdout.write(`${key},`);
                });
                console.log();
                first = false;
            }
            if (staticField) {
                process.stdout.write(`${staticField[1]},`);
            }
            tup.forEach((value) => {
                process.stdout.write(`${stringOfOpResult(value)},`);
            });
            console.log();
        },
        reset: (_) => {}
    };
}

/**
 * Dumps csv in Walt's canonical csv format: src_ip, dst_ip, src_l4_port,
 * dst_l4_port, packet_count, byte_count, epoch_id
 */
function dumpWaltsCSV(filename: string): Operator {
    let outc: any = process.stdout;
    let first = true;
    return {
        next: (tup: Tuple) => {
            if (first) {
                outc = require('fs').createWriteStream(filename);
                first = false;
            }
            const srcIp = stringOfOpResult(tup.get("src_ip")!);
            const dstIp = stringOfOpResult(tup.get("dst_ip")!);
            const srcL4Port = stringOfOpResult(tup.get("src_l4_port")!);
            const dstL4Port = stringOfOpResult(tup.get("dst_l4_port")!);
            const packetCount = stringOfOpResult(tup.get("packet_count")!);
            const byteCount = stringOfOpResult(tup.get("byte_count")!);
            const epochId = stringOfOpResult(tup.get("epoch_id")!);
            
            outc.write(`${srcIp},${dstIp},${srcL4Port},${dstL4Port},${packetCount},${byteCount},${epochId}\n`);
        },
        reset: (_) => {}
    };
}

// Input is either "0" or an IPv4 address in string format
function getIpOrZero(input: string): OpResult {
    if (input === "0") {
        return { type: 'Int', value: 0 };
    }
    return { type: 'IPv4', value: input };
}

/**
 * Reads an intermediate result CSV in Walt's canonical format
 * Injects epoch ids and incoming tuple counts into reset call
 */
function readWaltsCSV(fileNames: string[], ops: Operator[], epochIdKey: string = "eid"): void {
    const fs = require('fs');
    const readline = require('readline');
    
    // Create file readers
    const fileReaders = fileNames.map(filename => {
        return {
            reader: readline.createInterface({
                input: fs.createReadStream(filename),
                crlfDelay: Infinity
            }),
            eid: 0,
            tupCount: 0
        };
    });
    
    let running = ops.length;
    
    // Process each file with its corresponding operator
    fileReaders.forEach((fileReader, index) => {
        const op = ops[index];
        
        fileReader.reader.on('line', (line: string) => {
            const [srcIp, dstIp, srcL4Port, dstL4Port, packetCount, byteCount, epochId] = line.split(',');
            
            const parsedEpochId = parseInt(epochId);
            
            // Create tuple
            const tup = new Map<string, OpResult>();
            tup.set("ipv4.src", getIpOrZero(srcIp));
            tup.set("ipv4.dst", getIpOrZero(dstIp));
            tup.set("l4.sport", { type: 'Int', value: parseInt(srcL4Port) });
            tup.set("l4.dport", { type: 'Int', value: parseInt(dstL4Port) });
            tup.set("packet_count", { type: 'Int', value: parseInt(packetCount) });
            tup.set("byte_count", { type: 'Int', value: parseInt(byteCount) });
            tup.set(epochIdKey, { type: 'Int', value: parsedEpochId });
            
            fileReader.tupCount++;
            
            // Handle epoch changes
            if (parsedEpochId > fileReader.eid) {
                while (parsedEpochId > fileReader.eid) {
                    const resetTup = new Map<string, OpResult>();
                    resetTup.set(epochIdKey, { type: 'Int', value: fileReader.eid });
                    resetTup.set("tuples", { type: 'Int', value: fileReader.tupCount });
                    op.reset(resetTup);
                    fileReader.tupCount = 0;
                    fileReader.eid++;
                }
            }
            
            // Add tuple count and process
            tup.set("tuples", { type: 'Int', value: fileReader.tupCount });
            op.next(tup);
        });
        
        fileReader.reader.on('close', () => {
            // Handle final reset
            const resetTup = new Map<string, OpResult>();
            resetTup.set(epochIdKey, { type: 'Int', value: fileReader.eid + 1 });
            resetTup.set("tuples", { type: 'Int', value: fileReader.tupCount });
            op.reset(resetTup);
            running--;
            
            if (running === 0) {
                console.log("Done.");
            }
        });
    });
}

/**
 * Write the number of tuples passing through this operator each epoch
 * to the out_channel
 */
function metaMeter(name: string, outc: any, nextOp: Operator, staticField: string | null = null): Operator {
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

/**
 * Passes tuples through to op
 * Resets op every w seconds
 * Adds epoch id to tuple under key_out
 */
function epoch(epochWidth: number, keyOut: string, nextOp: Operator): Operator {
    let epochBoundary = 0;
    let eid = 0;
    
    return {
        next: (tup: Tuple) => {
            const time = floatOfOpResult(tup.get("time")!);
            
            if (epochBoundary === 0) {
                // Start of epoch
                epochBoundary = time + epochWidth;
            } else if (time >= epochBoundary) {
                // Within an epoch, calculate which one
                while (time >= epochBoundary) {
                    const resetTup = new Map<string, OpResult>();
                    resetTup.set(keyOut, { type: 'Int', value: eid });
                    nextOp.reset(resetTup);
                    epochBoundary += epochWidth;
                    eid++;
                }
            }
            
            // Add epoch ID to tuple and pass through
            const newTup = new Map(tup);
            newTup.set(keyOut, { type: 'Int', value: eid });
            nextOp.next(newTup);
        },
        reset: (_) => {
            const resetTup = new Map<string, OpResult>();
            resetTup.set(keyOut, { type: 'Int', value: eid });
            nextOp.reset(resetTup);
            epochBoundary = 0;
            eid = 0;
        }
    };
}

/**
 * Passes only tuples where f applied to the tuple returns true
 */
function filter(f: (tup: Tuple) => boolean, nextOp: Operator): Operator {
    return {
        next: (tup: Tuple) => {
            if (f(tup)) {
                nextOp.next(tup);
            }
        },
        reset: (tup: Tuple) => {
            nextOp.reset(tup);
        }
    };
}

/**
 * (filter utility)
 * comparison function for testing int values against a threshold
 */
function keyGeqInt(key: string, threshold: number, tup: Tuple): boolean {
    return intOfOpResult(tup.get(key)!) >= threshold;
}

/**
 * (filter utility)
 * Looks up the given key and converts to Int OpResult
 */
function getMappedInt(key: string, tup: Tuple): number {
    return intOfOpResult(tup.get(key)!);
}

/**
 * (filter utility)
 * Looks up the given key and converts to Float OpResult
 */
function getMappedFloat(key: string, tup: Tuple): number {
    return floatOfOpResult(tup.get(key)!);
}

/**
 * Operator which applied the given function on all tuples
 * Passes resets, unchanged
 */
function map(f: (tup: Tuple) => Tuple, nextOp: Operator): Operator {
    return {
        next: (tup: Tuple) => {
            nextOp.next(f(tup));
        },
        reset: (tup: Tuple) => {
            nextOp.reset(tup);
        }
    };
}

type GroupingFunc = (tup: Tuple) => Tuple;
type ReductionFunc = (val_: OpResult, tup: Tuple) => OpResult;

/**
 * Groups the input Tuples according to canonic members returned by
 * keyExtractor : Tuple -> Tuple
 */
function groupby(groupby: GroupingFunc, reduce: ReductionFunc, outKey: string, nextOp: Operator): Operator {
    const hTbl = new Map<string, [Tuple, OpResult]>();
    let resetCounter = 0;
    
    return {
        next: (tup: Tuple) => {
            // Grouping key is sub-Tuple of original extracted by key_extractor
            const groupingKey = groupby(tup);
            const groupingKeyStr = stringOfTuple(groupingKey);
            
            // Check if key exists in hash table
            const existing = hTbl.get(groupingKeyStr);
            if (existing) {
                // Update existing entry
                const [existingKey, existingVal] = existing;
                hTbl.set(groupingKeyStr, [existingKey, reduce(existingVal, tup)]);
            } else {
                // Add new entry
                hTbl.set(groupingKeyStr, [groupingKey, reduce({ type: 'Empty' }, tup)]);
            }
        },
        reset: (tup: Tuple) => {
            // Track the counter reset
            resetCounter++;
            
            // Process each group
            hTbl.forEach(([groupingKey, val_], _) => {
                // Create union of reset tuple and grouping key
                const unionedTup = new Map([...tup, ...groupingKey]);
                
                // Add reduction result and pass to next operator
                unionedTup.set(outKey, val_);
                nextOp.next(unionedTup);
            });
            
            // Reset next operator and clear hash table
            nextOp.reset(tup);
            hTbl.clear();
        }
    };
}

/**
 * (groupby utility : key_extractor)
 * Returns a new tuple with only the keys included in the inclKeys list
 */
function filterGroups(inclKeys: string[], tup: Tuple): Tuple {
    const result = new Map<string, OpResult>();
    inclKeys.forEach(key => {
        const value = tup.get(key);
        if (value !== undefined) {
            result.set(key, value);
        }
    });
    return result;
}

/**
 * (groupby utility : key_extractor)
 * Grouping function (key_extractor) that forms a single group
 */
function singleGroup(_: Tuple): Tuple {
    return new Map<string, OpResult>();
}

/**
 * (groupby utility : grouping_mech)
 * Reduction function (f) to count tuples
 */
function counter(val_: OpResult, _: Tuple): OpResult {
    if (val_.type === 'Empty') {
        return { type: 'Int', value: 1 };
    } else if (val_.type === 'Int') {
        return { type: 'Int', value: val_.value + 1 };
    }
    return val_;
}

/**
 * (groupby utility)
 * Reduction function (f) to sum values (assumed to be Int ()) of a given field
 */
function sumInts(searchKey: string, initVal: OpResult, tup: Tuple): OpResult {
    if (initVal.type === 'Empty') {
        return { type: 'Int', value: 0 };
    } else if (initVal.type === 'Int') {
        const searchVal = tup.get(searchKey);
        if (searchVal && searchVal.type === 'Int') {
            return { type: 'Int', value: searchVal.value + initVal.value };
        }
        throw new Error(`'sum_vals' function failed to find integer value mapped to "${searchKey}"`);
    }
    return initVal;
}

/**
 * Returns a list of distinct elements (as determined by group_tup) each epoch
 * removes duplicate Tuples based on group_tup
 */
function distinct(groupby: GroupingFunc, nextOp: Operator): Operator {
    const hTbl = new Map<string, Tuple>();
    let resetCounter = 0;
    
    return {
        next: (tup: Tuple) => {
            const groupingKey = groupby(tup);
            hTbl.set(stringOfTuple(groupingKey), groupingKey);
        },
        reset: (tup: Tuple) => {
            resetCounter++;
            
            hTbl.forEach((key_) => {
                const mergedTup = new Map([...tup, ...key_]);
                nextOp.next(mergedTup);
            });
            
            nextOp.reset(tup);
            hTbl.clear();
        }
    };
}

/**
 * Just sends both next and reset directly to two different downstream operators
 * i.e. splits the stream processing in two
 */
function split(l: Operator, r: Operator): Operator {
    return {
        next: (tup: Tuple) => {
            l.next(tup);
            r.next(tup);
        },
        reset: (tup: Tuple) => {
            l.reset(tup);
            r.reset(tup);
        }
    };
}

type KeyExtractor = (tup: Tuple) => [Tuple, Tuple];

/**
 * Initial shot at a join semantic that doesn't require maintaining entire state
 */
function join(leftExtractor: KeyExtractor, rightExtractor: KeyExtractor, nextOp: Operator, eidKey: string = "eid"): [Operator, Operator] {
    const hTbl1 = new Map<string, [Tuple, Tuple]>();
    const hTbl2 = new Map<string, [Tuple, Tuple]>();
    let leftCurrEpoch = 0;
    let rightCurrEpoch = 0;
    
    function handleJoinSide(
        currHTbl: Map<string, [Tuple, Tuple]>,
        otherHTbl: Map<string, [Tuple, Tuple]>,
        currEpochRef: { value: number },
        otherEpochRef: { value: number },
        f: KeyExtractor
    ): Operator {
        return {
            next: (tup: Tuple) => {
                // Extract grouping key and remaining values
                const [key, vals_] = f(tup);
                const currEpoch = getMappedInt(eidKey, tup);
                
                // Handle epoch transitions
                while (currEpoch > currEpochRef.value) {
                    if (otherEpochRef.value > currEpochRef.value) {
                        const resetTup = new Map<string, OpResult>();
                        resetTup.set(eidKey, { type: 'Int', value: currEpochRef.value });
                        nextOp.reset(resetTup);
                    }
                    currEpochRef.value++;
                }
                
                // Create new tuple with epoch ID
                const newTup = new Map(key);
                newTup.set(eidKey, { type: 'Int', value: currEpoch });
                const keyStr = stringOfTuple(newTup);
                
                // Check for matching tuple in other table
                const otherEntry = otherHTbl.get(keyStr);
                if (otherEntry) {
                    const [_, otherVal] = otherEntry;
                    
                    // Remove matched entry and emit joined tuple
                    otherHTbl.delete(keyStr);
                    
                    // Union of tuples
                    const joinedTuple = new Map([...newTup, ...vals_, ...otherVal]);
                    nextOp.next(joinedTuple);
                } else {
                    // Store for future matching
                    currHTbl.set(keyStr, [newTup, vals_]);
                }
            },
            reset: (tup: Tuple) => {
                const currEpoch = getMappedInt(eidKey, tup);
                
                while (currEpoch > currEpochRef.value) {
                    if (otherEpochRef.value > currEpochRef.value) {
                        const resetTup = new Map<string, OpResult>();
                        resetTup.set(eidKey, { type: 'Int', value: currEpochRef.value });
                        nextOp.reset(resetTup);
                    }
                    currEpochRef.value++;
                }
            }
        };
    }
    
    return [
        handleJoinSide(
            hTbl1, 
            hTbl2, 
            { value: leftCurrEpoch }, 
            { value: rightCurrEpoch }, 
            leftExtractor
        ),
        handleJoinSide(
            hTbl2, 
            hTbl1, 
            { value: rightCurrEpoch }, 
            { value: leftCurrEpoch }, 
            rightExtractor
        )
    ];
}

/**
 * (join utility)
 * Returns a new tuple with only the keys included in the first of each pair in keys
 * These keys are renamed to the second of each pair in keys
 */
function renameFilteredKeys(renamingsPairs: [string, string][], inTup: Tuple): Tuple {
    const newTup = new Map<string, OpResult>();
    
    renamingsPairs.forEach(([oldKey, newKey]) => {
        const val_ = inTup.get(oldKey);
        if (val_ !== undefined) {
            newTup.set(newKey, val_);
        }
    });
    
    return newTup;
}

// Main entry point implementations
function ident(nextOp: Operator): Operator {
    return map((tup: Tuple) => {
        const filtered = new Map<string, OpResult>();
        tup.forEach((value, key) => {
            if (key !== "eth.src" && key !== "eth.dst") {
                filtered.set(key, value);
            }
        });
        return filtered;
    }, nextOp);
}

function countPkts(nextOp: Operator): Operator {
    return chain(
        (next: Operator) => epoch(1.0, "eid", next),
        chain(
            (next: Operator) => groupby(singleGroup, counter, "pkts", next),
            nextOp
        )
    );
}

function pktsPerSrcDst(nextOp: Operator): Operator {
    return chain(
        (next: Operator) => epoch(1.0, "eid", next),
        chain(
            (next: Operator) => groupby(
                (tup: Tuple) => filterGroups(["ipv4.src", "ipv4.dst"], tup),
                counter,
                "pkts",
                next
            ),
            nextOp
        )
    );
}

function distinctSrcs(nextOp: Operator): Operator {
    return chain(
        (next: Operator) => epoch(1.0, "eid", next),
        chain(
            (next: Operator) => distinct((tup: Tuple) => filterGroups(["ipv4.src"], tup), next),
            chain(
                (next: Operator) => groupby(singleGroup, counter, "srcs", next),
                nextOp
            )
        )
    );
}

// Sonata 1
function tcpNewCons(nextOp: Operator): Operator {
    const threshold = 40;
    return chain(
        (next: Operator) => epoch(1.0, "eid", next),
        chain(
            (next: Operator) => filter((tup: Tuple) => {
                return getMappedInt("ipv4.proto", tup) === 6 &&
                       getMappedInt("l4.flags", tup) === 2;
            }, next),
            chain(
                (next: Operator) => groupby(
                    (tup: Tuple) => filterGroups(["ipv4.dst"], tup),
                    counter,
                    "cons",
                    next
                ),
                chain(
                    (next: Operator) => filter((tup: Tuple) => keyGeqInt("cons", threshold, tup), next),
                    nextOp
                )
            )
        )
    );
}

// Main function
function runQueries(): void {
    const queries: Operator[] = [chain(ident, dumpTupleOp(console))];
    
    // Create test data
    const tuples: Tuple[] = [];
    for (let i = 0; i < 20; i++) {
        const macSrc = new Uint8Array([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        const macDst = new Uint8Array([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        
        const tup = new Map<string, OpResult>();
        tup.set("time", { type: 'Float', value: 0.0 + i });
        tup.set("eth.src", { type: 'MAC', value: macSrc });
        tup.set("eth.dst", { type: 'MAC', value: macDst });
        tup.set("eth.ethertype", { type: 'Int', value: 0x0800 });
        tup.set("ipv4.hlen", { type: 'Int', value: 20 });
        tup.set("ipv4.proto", { type: 'Int', value: 6 });
        tup.set("ipv4.len", { type: 'Int', value: 60 });
        tup.set("ipv4.src", { type: 'IPv4', value: "127.0.0.1" });
        tup.set("ipv4.dst", { type: 'IPv4', value: "127.0.0.1" });
        tup.set("l4.sport", { type: 'Int', value: 440 });
        tup.set("l4.dport", { type: 'Int', value: 50000 });
        tup.set("l4.flags", { type: 'Int', value: 10 });
        
        tuples.push(tup);
    }
    
    // Process each tuple through all queries
    tuples.forEach(tup => {
        queries.forEach(query => {
            query.next(tup);
        });
    });
}

// Main entrypoint
function main(): void {
    runQueries();
    console.log("Done");
}

main();