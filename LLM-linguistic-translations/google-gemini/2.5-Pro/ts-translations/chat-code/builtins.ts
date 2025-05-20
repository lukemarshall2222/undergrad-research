// builtins.ts

import * as fs from 'fs';
import * as readline from 'readline';
import { Writable } from 'stream';
import {
    OpResult,
    Tuple,
    Operator,
    OpCreator,
    DblOpCreator,
    stringOfOpResult,
    intOfOpResult,
    floatOfOpResult,
    stringOfTuple,
    createIpOrZero,
    lookupInt,
    lookupFloat
} from './common';

const INIT_TABLE_SIZE: number = 10000; // Hint for Map/Set initial capacity (less impactful in JS)

// --- Output Operators ---

/**
 * Operator factory: Dumps all fields of incoming tuples to a writable stream.
 * Does not forward tuples.
 */
export function dumpTupleOperator(
    outStream: Writable,
    showReset: boolean = false
): Operator {
    return {
        next: (tup: Tuple): void => {
            outStream.write(stringOfTuple(tup) + '\n');
        },
        reset: (tup: Tuple): void => {
            if (showReset) {
                outStream.write(stringOfTuple(tup) + '\n');
                outStream.write('[reset]\n');
            }
        },
    };
}

/**
 * Operator factory: Dumps tuples to a stream in CSV format.
 * Assumes all tuples have the same fields (after the first).
 */
export function dumpAsCsvOperator(
    outStream: Writable,
    staticField?: { key: string; value: string },
    header: boolean = true
): Operator {
    let first = header; // Use closure to track if header needs writing

    return {
        next: (tup: Tuple): void => {
            let line = "";
            if (first) {
                if (staticField) {
                    line += `${staticField.key},`;
                }
                tup.forEach((_value, key) => {
                    line += `${key},`;
                });
                 // remove trailing comma if needed and add newline
                outStream.write(line.replace(/,$/, '') + '\n');
                first = false;
                line = ""; // Reset line for data
            }

            // Data row
            if (staticField) {
                line += `${staticField.value},`;
            }
            tup.forEach((value, _key) => {
                line += `${stringOfOpResult(value)},`;
            });
             // remove trailing comma if needed and add newline
            outStream.write(line.replace(/,$/, '') + '\n');
        },
        reset: (_tup: Tuple): void => {
             // No reset action for CSV dump usually, maybe flush stream if needed
        },
    };
}

/**
 * Operator factory: Dumps tuples in Walt's canonical CSV format to a file.
 * Uses synchronous file writing for simplicity mirroring OCaml's approach.
 */
export function dumpWaltsCsvOperator(filename: string): Operator {
    let first = true;
    // Overwrite file on first write
    try {
        fs.writeFileSync(filename, '');
    } catch (err) {
        console.error(`Error initializing file ${filename}:`, err);
        throw err;
    }

    return {
        next: (tup: Tuple): void => {
            try {
                 // This is inefficient for many writes, stream would be better
                 // but matches the simple OCaml stdout redirection style
                const line = [
                    stringOfOpResult(tup.get("src_ip") ?? { kind: "Empty" }),
                    stringOfOpResult(tup.get("dst_ip") ?? { kind: "Empty" }),
                    stringOfOpResult(tup.get("src_l4_port") ?? { kind: "Empty" }),
                    stringOfOpResult(tup.get("dst_l4_port") ?? { kind: "Empty" }),
                    stringOfOpResult(tup.get("packet_count") ?? { kind: "Empty" }),
                    stringOfOpResult(tup.get("byte_count") ?? { kind: "Empty" }),
                    stringOfOpResult(tup.get("epoch_id") ?? { kind: "Empty" }),
                ].join(',') + '\n';
                fs.appendFileSync(filename, line);
            } catch (err) {
                console.error(`Error writing to Walt's CSV ${filename}:`, err);
                // Decide whether to throw or continue
            }
        },
        reset: (_tup: Tuple): void => {
            // Reset does nothing here
        },
    };
}

// --- Input Operators ---

/**
 * Reads Walt's canonical CSV format from multiple files and pushes
 * tuples to corresponding operators. Handles epoch advancement based on data.
 * Uses asynchronous reading line-by-line.
 */
export async function readWaltsCsv(
    fileNames: string[],
    ops: Operator[],
    epochIdKey: string = "eid"
): Promise<void> {
    if (fileNames.length !== ops.length) {
        throw new Error("Number of file names must match number of operators");
    }

    const processors = fileNames.map((filename, index) => ({
        filename,
        op: ops[index],
        reader: readline.createInterface({
            input: fs.createReadStream(filename),
            crlfDelay: Infinity,
        }),
        currentEpochId: 0,
        tuplesInEpoch: 0,
        finished: false,
        iterator: null as AsyncIterator<string> | null, // Store iterator
    }));

    // Initialize iterators
    for (const p of processors) {
        p.iterator = p.reader[Symbol.asyncIterator]();
    }

    let activeProcessors = processors.length;

    while (activeProcessors > 0) {
        for (const p of processors) {
            if (p.finished || !p.iterator) continue;

            try {
                const result = await p.iterator.next();
                if (result.done) {
                    // End of file reached
                    const resetTuple = new Map<string, OpResult>([
                        [epochIdKey, { kind: "Int", value: p.currentEpochId }], // Use last known epoch for final reset
                        ["tuples", { kind: "Int", value: p.tuplesInEpoch }],
                    ]);
                    p.op.reset(resetTuple);
                    p.finished = true;
                    activeProcessors--;
                    p.reader.close(); // Close the readline interface
                    continue;
                }

                const line = result.value;
                const parts = line.split(',');
                if (parts.length < 7) {
                    console.warn(`Skipping malformed line in ${p.filename}: ${line}`);
                    continue;
                }

                const [srcIpStr, dstIpStr, srcPortStr, dstPortStr, pktCountStr, byteCountStr, epochIdStr] = parts;

                const epochId = parseInt(epochIdStr, 10);
                const srcPort = parseInt(srcPortStr, 10);
                const dstPort = parseInt(dstPortStr, 10);
                const pktCount = parseInt(pktCountStr, 10);
                const byteCount = parseInt(byteCountStr, 10);

                if (isNaN(epochId) || isNaN(srcPort) || isNaN(dstPort) || isNaN(pktCount) || isNaN(byteCount)) {
                     console.warn(`Skipping line with invalid numbers in ${p.filename}: ${line}`);
                     continue;
                 }

                // Handle epoch transitions
                while (epochId > p.currentEpochId) {
                     const resetTuple = new Map<string, OpResult>([
                        [epochIdKey, { kind: "Int", value: p.currentEpochId }],
                        ["tuples", { kind: "Int", value: p.tuplesInEpoch }],
                    ]);
                    p.op.reset(resetTuple);
                    p.tuplesInEpoch = 0;
                    p.currentEpochId++;
                }

                p.tuplesInEpoch++;

                const tup: Tuple = new Map<string, OpResult>([
                    ["ipv4.src", createIpOrZero(srcIpStr)],
                    ["ipv4.dst", createIpOrZero(dstIpStr)],
                    ["l4.sport", { kind: "Int", value: srcPort }],
                    ["l4.dport", { kind: "Int", value: dstPort }],
                    ["packet_count", { kind: "Int", value: pktCount }],
                    ["byte_count", { kind: "Int", value: byteCount }],
                    [epochIdKey, { kind: "Int", value: epochId }],
                    ["tuples", { kind: "Int", value: p.tuplesInEpoch}] // Current count in this epoch
                ]);

                p.op.next(tup);

            } catch (err) {
                console.error(`Error processing file ${p.filename}:`, err);
                p.finished = true; // Stop processing this file on error
                activeProcessors--;
                 if (p.reader) p.reader.close();
            }
        }
    }
    console.log("Done reading all files.");
}


// --- Processing Operators ---

/**
 * Operator factory: Logs the number of tuples processed per epoch.
 */
export function metaMeterOperator(
    name: string,
    outStream: Writable,
    nextOp: Operator,
    staticField?: string // Just the value part, key assumed to be static 'info' maybe?
): Operator {
    let epochCount = 0;
    let tupsCount = 0;

    return {
        next: (tup: Tuple): void => {
            tupsCount++;
            nextOp.next(tup);
        },
        reset: (tup: Tuple): void => {
            const staticVal = staticField ?? "";
            outStream.write(`${epochCount},${name},${tupsCount},${staticVal}\n`);
            tupsCount = 0;
            epochCount++;
            nextOp.reset(tup);
        },
    };
}

/**
 * Operator factory: Assigns epoch IDs based on time and triggers resets.
 */
export function epochOperator(
    epochWidth: number, // in seconds
    keyOut: string,
    nextOp: Operator
): Operator {
    let epochBoundary = 0.0;
    let eid = 0;

    return {
        next: (tup: Tuple): void => {
            const time = floatOfOpResult(tup.get("time")); // Assumes 'time' field exists and is Float

            if (epochBoundary === 0.0) { // First tuple initializes boundary
                epochBoundary = time + epochWidth;
            }

            while (time >= epochBoundary) { // Process epoch boundary crosses
                const resetTuple = new Map([[keyOut, { kind: "Int", value: eid } as OpResult]]);
                nextOp.reset(resetTuple);
                epochBoundary += epochWidth;
                eid++;
            }

            // Add epoch id to tuple and forward
            const outTuple = new Map(tup); // Clone tuple
            outTuple.set(keyOut, { kind: "Int", value: eid });
            nextOp.next(outTuple);
        },
        reset: (_tup: Tuple): void => { // External reset clears state
            const resetTuple = new Map([[keyOut, { kind: "Int", value: eid } as OpResult]]);
            nextOp.reset(resetTuple); // Pass final reset downstream
            epochBoundary = 0.0;
            eid = 0;
        },
    };
}

/**
 * Operator factory: Filters tuples based on a predicate function.
 */
export function filterOperator(
    predicate: (tuple: Tuple) => boolean,
    nextOp: Operator
): Operator {
    return {
        next: (tup: Tuple): void => {
            if (predicate(tup)) {
                nextOp.next(tup);
            }
        },
        reset: (tup: Tuple): void => {
            nextOp.reset(tup); // Pass reset unchanged
        },
    };
}

// --- Filter Utilities ---

/**
 * Predicate: Checks if the integer value of a key is >= threshold.
 */
export function keyGeqInt(key: string, threshold: number): (tup: Tuple) => boolean {
    return (tup: Tuple): boolean => {
        try {
            return intOfOpResult(tup.get(key)) >= threshold;
        } catch (e) {
            // Handle cases where key is missing or not an int
            // console.warn(`keyGeqInt: Key "${key}" error in tuple: ${stringOfTuple(tup)}`, e);
            return false;
        }
    };
}

// getMappedInt and getMappedFloat are essentially lookupInt/lookupFloat from common.ts
// export { lookupInt as getMappedInt, lookupFloat as getMappedFloat };

/**
 * Operator factory: Applies a function to transform each tuple.
 */
export function mapOperator(
    transform: (tuple: Tuple) => Tuple,
    nextOp: Operator
): Operator {
    return {
        next: (tup: Tuple): void => {
            nextOp.next(transform(tup));
        },
        reset: (tup: Tuple): void => {
            nextOp.reset(tup); // Pass reset unchanged
        },
    };
}

// --- GroupBy Operator and Utilities ---

export type GroupingFunc = (tuple: Tuple) => Tuple; // Extracts the key tuple
export type ReductionFunc = (currentValue: OpResult, tuple: Tuple) => OpResult; // Accumulates

/**
 * Operator factory: Groups tuples by a key and applies a reduction.
 */
export function groupbyOperator(
    groupbyFunc: GroupingFunc,
    reduceFunc: ReductionFunc,
    outKey: string, // Key for the reduction result
    nextOp: Operator
): Operator {
    // Use Map for grouping. Key needs to be canonical string representation.
    const hTbl = new Map<string, { groupKeyTuple: Tuple; reducedValue: OpResult }>();

    return {
        next: (tup: Tuple): void => {
            const groupKeyTuple = groupbyFunc(tup);
            // Convert tuple key to a stable string representation for Map key
            const groupKeyString = stringOfTuple(groupKeyTuple); // Simple but maybe slow

            const existingEntry = hTbl.get(groupKeyString);
            const currentVal = existingEntry ? existingEntry.reducedValue : { kind: "Empty" as const };
            const newVal = reduceFunc(currentVal, tup);

            hTbl.set(groupKeyString, { groupKeyTuple, reducedValue: newVal });
        },
        reset: (resetTuple: Tuple): void => {
            hTbl.forEach(({ groupKeyTuple, reducedValue }, _groupKeyString) => {
                // Merge reset tuple, group key tuple, and reduction result
                const outTuple = new Map(resetTuple);
                // Add group key fields (groupKeyTuple overrides resetTuple if conflicts)
                groupKeyTuple.forEach((val, key) => outTuple.set(key, val));
                // Add reduction result
                outTuple.set(outKey, reducedValue);
                nextOp.next(outTuple); // Send aggregated tuple downstream
            });

            nextOp.reset(resetTuple); // Pass original reset tuple downstream
            hTbl.clear(); // Clear state for next epoch
        },
    };
}

// --- GroupBy Utilities ---

/**
 * GroupingFunc: Filters tuple to keep only specified keys for grouping.
 */
export function filterGroups(inclKeys: string[]): GroupingFunc {
    return (tup: Tuple): Tuple => {
        const groupKeyTuple = new Map<string, OpResult>();
        inclKeys.forEach(key => {
            const value = tup.get(key);
            if (value !== undefined) {
                groupKeyTuple.set(key, value);
            }
        });
        return groupKeyTuple;
    };
}

/**
 * GroupingFunc: Groups all tuples into a single group.
 */
export function singleGroup(_tup: Tuple): Tuple {
    return new Map<string, OpResult>(); // Empty map means one group
}

/**
 * ReductionFunc: Counts the number of tuples in a group.
 */
export function counterReducer(currentValue: OpResult, _tup: Tuple): OpResult {
    if (currentValue.kind === "Empty") {
        return { kind: "Int", value: 1 };
    } else if (currentValue.kind === "Int") {
        return { kind: "Int", value: currentValue.value + 1 };
    } else {
         console.warn("Counter applied to non-Int or non-Empty value", currentValue);
         return currentValue; // Or throw error
    }
}

/**
 * ReductionFunc: Sums the integer values of a specific key in tuples within a group.
 */
export function sumIntsReducer(searchKey: string): ReductionFunc {
    return (currentValue: OpResult, tup: Tuple): OpResult => {
        let currentSum: number;
        if (currentValue.kind === "Empty") {
            currentSum = 0;
        } else if (currentValue.kind === "Int") {
            currentSum = currentValue.value;
        } else {
            console.warn(`SumInts reducer expected Int or Empty, got ${currentValue.kind}`);
            return currentValue; // Or throw error
        }

        try {
            // Get value to add from the current tuple
            const valueToAdd = intOfOpResult(tup.get(searchKey));
            return { kind: "Int", value: currentSum + valueToAdd };
        } catch (e) {
            // Handle case where searchKey is missing or not an Int in the tuple
            // console.warn(`sumIntsReducer: Key "${searchKey}" error in tuple: ${stringOfTuple(tup)}`, e);
            return { kind: "Int", value: currentSum }; // Keep current sum if tuple is invalid
        }
    };
}


// --- Distinct Operator ---

/**
 * Operator factory: Emits distinct tuples based on a grouping function each epoch.
 */
export function distinctOperator(
    groupbyFunc: GroupingFunc,
    nextOp: Operator
): Operator {
    // Use Set to store stringified keys of seen tuples this epoch
     const hTbl = new Map<string, Tuple>(); // Store the actual tuple representative

    return {
        next: (tup: Tuple): void => {
            const groupingKeyTuple = groupbyFunc(tup);
            const groupingKeyString = stringOfTuple(groupingKeyTuple); // Needs stable representation
            // Store the first tuple encountered for this key
            if (!hTbl.has(groupingKeyString)) {
                 // Store the *full* tuple, keyed by its group representation
                 // OCaml version replaces, so last seen is kept. Let's match that.
                 // hTbl.set(groupingKeyString, tup);
                 // Actually, OCaml used Hashtbl.replace with value 'true'. It only stored keys.
                 // The reset logic then merges the key back. Let's do that.
                 hTbl.set(groupingKeyString, groupingKeyTuple);
            }
             // OCaml version seems to store the key tuple, not the full tuple.
             // Let's try storing the key tuple directly.
             hTbl.set(groupingKeyString, groupingKeyTuple);
        },
        reset: (resetTuple: Tuple): void => {
            hTbl.forEach((keyTuple, _keyString) => {
                 // The emitted tuple is the union of the reset tuple and the distinct key tuple
                 const mergedTuple = new Map(resetTuple);
                 keyTuple.forEach((val, key) => mergedTuple.set(key, val)); // Key tuple overrides reset tuple
                 nextOp.next(mergedTuple);
            });
            nextOp.reset(resetTuple);
            hTbl.clear();
        },
    };
}


// --- Split Operator ---

/**
 * Operator factory: Sends each tuple and reset signal to two downstream operators.
 */
export function splitOperator(leftOp: Operator, rightOp: Operator): Operator {
    return {
        next: (tup: Tuple): void => {
            leftOp.next(tup);
            rightOp.next(tup);
        },
        reset: (tup: Tuple): void => {
            leftOp.reset(tup);
            rightOp.reset(tup);
        },
    };
}


// --- Join Operator ---

export type KeyExtractor = (tuple: Tuple) => [Tuple, Tuple]; // [keyTuple, valueTuple]

/**
 * Operator factory: Performs a stream join based on keys and epoch IDs.
 * Returns two operators, one for each input stream (left and right).
 */
export function joinOperator(
    leftExtractor: KeyExtractor,
    rightExtractor: KeyExtractor,
    nextOp: Operator,
    eidKey: string = "eid"
): [Operator, Operator] { // Returns a pair of operators

    // Store value tuples, keyed by stringified key tuple + epoch id
    const hTbl1 = new Map<string, Tuple>(); // State for left input waiting for right match
    const hTbl2 = new Map<string, Tuple>(); // State for right input waiting for left match

    let leftCurrEpoch = -1; // Use -1 to indicate initial state
    let rightCurrEpoch = -1;

    // Helper to create the composite key string
    const createJoinKey = (keyTuple: Tuple, epoch: number): string => {
        // Needs a stable string representation. Sort keys?
        // Simple approach: rely on Map iteration order (usually insertion order) + epoch
        return `${stringOfTuple(keyTuple)}|epoch:${epoch}`;
    }

    // Logic for handling one side of the join
    const handleJoinSide = (
        currHTbl: Map<string, Tuple>, // Table to store this side's waiting tuples
        otherHTbl: Map<string, Tuple>, // Table to check for matches from the other side
        currEpochRef: { value: number }, // Use object wrapper for mutable ref
        otherEpochRef: { value: number },
        extractor: KeyExtractor
    ): Operator => {
        return {
            next: (tup: Tuple): void => {
                const [keyTuple, valsTuple] = extractor(tup);
                let currentEpoch: number;
                try {
                     currentEpoch = lookupInt(eidKey, tup);
                } catch (e) {
                     console.error(`Join error: Tuple missing integer key "${eidKey}"`, stringOfTuple(tup));
                     return; // Skip tuple if epoch ID is missing/invalid
                }


                // Advance current epoch state if needed, triggering resets downstream
                while (currentEpoch > currEpochRef.value) {
                    // Only trigger reset if the *other* stream has also passed this epoch boundary
                    // This prevents premature resets if one stream lags significantly
                     if (otherEpochRef.value > currEpochRef.value) {
                         const resetTuple = new Map([[eidKey, { kind: "Int", value: currEpochRef.value } as OpResult]]);
                         nextOp.reset(resetTuple);
                     }
                     currEpochRef.value++;
                }
                 // Initialize epoch on first tuple
                 if (currEpochRef.value === -1) {
                    currEpochRef.value = currentEpoch;
                }

                const joinKey = createJoinKey(keyTuple, currentEpoch);

                // Check if matching tuple exists in the other table
                const matchVals = otherHTbl.get(joinKey);

                if (matchVals !== undefined) {
                    // Match found! Remove from other table and emit joined tuple
                    otherHTbl.delete(joinKey);

                    // Merge: keyTuple + valsTuple (from current) + matchVals (from other)
                    // Order matters if keys overlap: current valsTuple override keyTuple, matchVals override those.
                    // OCaml used union `fun _ a _ -> Some a` (prefer left). Let's match that roughly.
                    // Merge order: keyTuple <- valsTuple <- matchVals
                    const joinedTuple = new Map(keyTuple);
                    valsTuple.forEach((v, k) => joinedTuple.set(k, v));
                    matchVals.forEach((v, k) => joinedTuple.set(k, v));
                    joinedTuple.set(eidKey, { kind: "Int", value: currentEpoch }); // Ensure eid is present

                    nextOp.next(joinedTuple);
                } else {
                    // No match yet, store this tuple's values in the current table
                    currHTbl.set(joinKey, valsTuple);
                }
            },
            reset: (tup: Tuple): void => {
                // Reset primarily advances the epoch counter for this side
                 let currentEpoch: number;
                 try {
                     currentEpoch = lookupInt(eidKey, tup);
                 } catch (e) {
                     console.warn(`Join reset ignored: Tuple missing integer key "${eidKey}"`, stringOfTuple(tup));
                     return; // Ignore reset if no valid epoch ID
                 }
                  // Advance epoch state based on reset signal
                 while (currentEpoch > currEpochRef.value) {
                      if (otherEpochRef.value > currEpochRef.value) {
                         const resetTuple = new Map([[eidKey, { kind: "Int", value: currEpochRef.value } as OpResult]]);
                         nextOp.reset(resetTuple);
                     }
                     currEpochRef.value++;
                 }
                 // Clean up expired entries? OCaml version doesn't explicitly, relies on epoch advance.
                 // We could add cleanup based on currEpochRef.value here if needed.
            },
        };
    };

    // Create the two operators for left and right inputs
    const leftOp = handleJoinSide(
        hTbl1, hTbl2,
        { value: leftCurrEpoch }, { value: rightCurrEpoch },
        leftExtractor
    );
    const rightOp = handleJoinSide(
        hTbl2, hTbl1,
        { value: rightCurrEpoch }, { value: leftCurrEpoch },
        rightExtractor
    );

    return [leftOp, rightOp];
}


// --- Join Utility ---

/**
 * Utility for join extractors: Creates a new tuple by filtering and renaming keys.
 */
export function renameFilteredKeys(
    renamingPairs: [string, string][], // List of [oldKey, newKey]
    inTuple: Tuple
): Tuple {
    const newTuple = new Map<string, OpResult>();
    renamingPairs.forEach(([oldKey, newKey]) => {
        const value = inTuple.get(oldKey);
        if (value !== undefined) {
            newTuple.set(newKey, value);
        }
    });
    return newTuple;
}