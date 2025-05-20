Prompt: base prompt

Okay, let's translate the OCaml code into idiomatic TypeScript. We'll break it down into modules similar to the OCaml structure, focusing on TypeScript's type system, classes/interfaces, standard library features (like `Map`), and ES Modules.

**Assumptions:**

1.    **Environment:** This code assumes a Node.js environment for file system access (`fs`) and potentially process streams (`process.stdout`).
2.    **IP Addresses:** `Ipaddr.V4.t` will be represented as strings in TypeScript. More complex IP handling would require a dedicated library.
3.    **MAC Addresses:** `Bytes.t` for MAC addresses will be represented as formatted strings (e.g., "xx:xx:xx:xx:xx:xx"). The `Bytes.t` type in OCaml is mutable byte sequence, often used for raw binary data; for MAC addresses, the formatted string is usually sufficient in higher-level processing. If raw byte access were needed, `Uint8Array` would be the TypeScript equivalent.
4.    **Output:** `out_channel` will be mapped to Node.js `WritableStream` or simplified to use `console.log` / `fs.appendFileSync`.
5.    **Parsing:** `Scanf.bscanf` will be replaced with basic string splitting for CSV parsing. A robust CSV library would be better for production.
6.  **Infix Operators:** OCaml's custom infix operators (`@=>`, `@==>`) don't exist in TypeScript. We'll replace their usage with standard function composition/application. `a @=> b @=> c` becomes `a(b(c))`.

---

**1. `common.ts` (Core Types and Utilities)**

```typescript
// common.ts

// Represents IPv4 address as a string (e.g., "192.168.1.1")
export type IPv4Address = string;
// Represents MAC address as a colon-separated hex string (e.g., "00:11:22:aa:bb:cc")
export type MacAddress = string;

// Discriminated union for operation results
export type OpResult =
  | { kind: "Float"; value: number }
  | { kind: "Int"; value: number }
  | { kind: "IPv4"; value: IPv4Address }
  | { kind: "MAC"; value: MacAddress }
  | { kind: "Empty" };

// Tuple: A map from string keys to OpResult values
export type Tuple = Map<string, OpResult>;

// Operator interface defining the processing functions
export interface Operator {
  next: (tuple: Tuple) => void;
  reset: (tuple: Tuple) => void;
}

// Type for functions that create operators (taking the next operator)
export type OpCreator = (nextOp: Operator) => Operator;

// Type for functions that create a pair of operators
export type DblOpCreator = (nextOp: Operator) => [Operator, Operator];


// --- Conversion Utilities ---

/**
 * Formats a Uint8Array MAC address buffer into a colon-separated hex string.
 * Assumes buffer has at least 6 bytes.
 */
export function macBufferToString(buf: Uint8Array): MacAddress {
    if (buf.length < 6) {
        throw new Error("MAC buffer too short");
    }
    return Array.from(buf.slice(0, 6))
        .map(byte => byte.toString(16).padStart(2, '0'))
        .join(':');
}

/**
 * Converts TCP flags integer into a human-readable string (e.g., "SYN|ACK").
 */
export function tcpFlagsToStrings(flags: number): string {
    const flagMap: Record<string, number> = {
        "FIN": 1 << 0,
        "SYN": 1 << 1,
        "RST": 1 << 2,
        "PSH": 1 << 3,
        "ACK": 1 << 4,
        "URG": 1 << 5,
        "ECE": 1 << 6,
        "CWR": 1 << 7,
    };
    const activeFlags = Object.entries(flagMap)
        .filter(([_key, value]) => (flags & value) === value)
        .map(([key, _value]) => key);

    return activeFlags.join('|');
}

/**
 * Extracts integer value from OpResult, throws error if not Int.
 */
export function intOfOpResult(input: OpResult | undefined): number {
    if (input?.kind === "Int") {
        return input.value;
    }
    throw new Error(`Trying to extract int from non-int result: ${JSON.stringify(input)}`);
}

/**
 * Extracts float value from OpResult, throws error if not Float.
 */
export function floatOfOpResult(input: OpResult | undefined): number {
    if (input?.kind === "Float") {
        return input.value;
    }
    throw new Error(`Trying to extract float from non-float result: ${JSON.stringify(input)}`);
}

/**
 * Converts an OpResult to its string representation.
 */
export function stringOfOpResult(input: OpResult): string {
    switch (input.kind) {
        case "Float": return input.value.toString(); // Consider formatting (e.g., toFixed)
        case "Int": return input.value.toString();
        case "IPv4": return input.value;
        case "MAC": return input.value;
        case "Empty": return "Empty";
        default:
             // Ensure exhaustive check at compile time
             const exhaustiveCheck: never = input;
             throw new Error(`Unhandled OpResult kind: ${exhaustiveCheck}`);
    }
}

/**
 * Converts a Tuple (Map) to a human-readable string.
 * Example: "ipv4.src" => 192.168.1.1, "packet_count" => 10,
 */
export function stringOfTuple(inputTuple: Tuple): string {
    let result = "";
    inputTuple.forEach((value, key) => {
        result += `"${key}" => ${stringOfOpResult(value)}, `;
    });
    return result.replace(/, $/, ""); // Remove trailing comma and space
}

/**
 * Creates a Tuple (Map) from an array of key-value pairs.
 */
export function tupleOfList(tupList: [string, OpResult][]): Tuple {
    return new Map(tupList);
}

/**
 * Prints a formatted representation of a Tuple to the console.
 */
export function dumpTupleToConsole(tup: Tuple): void {
    console.log(stringOfTuple(tup));
}

/**
 * Retrieves the integer value associated with a key in a Tuple.
 * Throws an error if the key is not found or the value is not an Int.
 */
export function lookupInt(key: string, tup: Tuple): number {
    const result = tup.get(key);
    if (result === undefined) {
        throw new Error(`Key "${key}" not found in tuple`);
    }
    return intOfOpResult(result);
}

/**
 * Retrieves the float value associated with a key in a Tuple.
 * Throws an error if the key is not found or the value is not a Float.
 */
export function lookupFloat(key: string, tup: Tuple): number {
    const result = tup.get(key);
    if (result === undefined) {
        throw new Error(`Key "${key}" not found in tuple`);
    }
    return floatOfOpResult(result);
}

/**
* Helper to create an IPv4 OpResult, handling "0" as Int 0.
*/
export function createIpOrZero(ipString: string): OpResult {
   if (ipString === "0") {
       return { kind: "Int", value: 0 };
   } else {
       // Basic validation could be added here
       return { kind: "IPv4", value: ipString };
   }
}
```

---

**2. `builtins.ts` (Built-in Operators)**

```typescript
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
```

---

**3. `main.ts` (Query Definitions and Execution)**

```typescript
// main.ts

import * as fs from 'fs';
import * as process from 'process';
import {
    OpResult, Tuple, Operator, OpCreator,
    IPv4Address, MacAddress,
    tupleOfList, lookupInt, createIpOrZero, macBufferToString // Assuming macBufferToString exists for example data
} from './common';
import {
    dumpTupleOperator, dumpAsCsvOperator, dumpWaltsCsvOperator, // Output
    readWaltsCsv, // Input
    metaMeterOperator, epochOperator, filterOperator, mapOperator, // Processing
    groupbyOperator, distinctOperator, splitOperator, joinOperator, // Aggregation/Stateful
    filterGroups, singleGroup, counterReducer, sumIntsReducer, // GroupBy utils
    keyGeqInt, // Filter utils
    renameFilteredKeys // Join utils
} from './builtins';

// --- Query Definitions using Operator Factories ---
// Note: OCaml's '@=>' is replaced by function application order: op1(op2(nextOp))

// Example: Simple identity mapping (filtering some eth keys)
const ident: OpCreator = (nextOp) =>
    mapOperator(
        (tup) => {
            const filteredTup = new Map(tup);
            filteredTup.delete("eth.src");
            filteredTup.delete("eth.dst");
            return filteredTup;
        },
        nextOp
    );

// Counts total packets per epoch
const countPkts: OpCreator = (nextOp) =>
    epochOperator(1.0, "eid",
        groupbyOperator(singleGroup, counterReducer, "pkts",
            nextOp
        )
    );

// Counts packets per source/destination IP pair per epoch
const pktsPerSrcDst: OpCreator = (nextOp) =>
    epochOperator(1.0, "eid",
        groupbyOperator(filterGroups(["ipv4.src", "ipv4.dst"]), counterReducer, "pkts",
            nextOp
        )
    );

// Counts distinct source IPs per epoch
const distinctSrcs: OpCreator = (nextOp) =>
    epochOperator(1.0, "eid",
        distinctOperator(filterGroups(["ipv4.src"]),
            groupbyOperator(singleGroup, counterReducer, "srcs",
                nextOp
            )
        )
    );

// Sonata 1: TCP New Connections (SYN packets per destination > threshold)
const tcpNewCons: OpCreator = (nextOp) => {
    const threshold = 40;
    return epochOperator(1.0, "eid",
        filterOperator((tup) =>
            lookupInt("ipv4.proto", tup) === 6 && // TCP
            lookupInt("l4.flags", tup) === 2,   // SYN flag only
            groupbyOperator(filterGroups(["ipv4.dst"]), counterReducer, "cons",
                filterOperator(keyGeqInt("cons", threshold),
                    nextOp
                )
            )
        )
    );
};

// Sonata 2: SSH Brute Force (Distinct src/len pairs per dst > threshold for port 22)
const sshBruteForce: OpCreator = (nextOp) => {
    const threshold = 40;
    return epochOperator(1.0, "eid", // Original notes maybe longer epoch needed
        filterOperator((tup) =>
            lookupInt("ipv4.proto", tup) === 6 && // TCP
            lookupInt("l4.dport", tup) === 22,  // SSH port
            distinctOperator(filterGroups(["ipv4.src", "ipv4.dst", "ipv4.len"]), // Distinct src/dst/len tuples
                groupbyOperator(filterGroups(["ipv4.dst", "ipv4.len"]), counterReducer, "srcs", // Group by dst/len, count distinct srcs
                    filterOperator(keyGeqInt("srcs", threshold),
                        nextOp
                    )
                )
            )
        )
    );
};

// Sonata 3: Super Spreader (Distinct destinations per source > threshold)
const superSpreader: OpCreator = (nextOp) => {
    const threshold = 40;
    return epochOperator(1.0, "eid",
        distinctOperator(filterGroups(["ipv4.src", "ipv4.dst"]), // Distinct src/dst pairs
            groupbyOperator(filterGroups(["ipv4.src"]), counterReducer, "dsts", // Group by src, count distinct dsts
                filterOperator(keyGeqInt("dsts", threshold),
                    nextOp
                )
            )
        )
    );
};

// Sonata 4: Port Scan (Distinct destination ports per source > threshold)
const portScan: OpCreator = (nextOp) => {
    const threshold = 40;
    return epochOperator(1.0, "eid",
        distinctOperator(filterGroups(["ipv4.src", "l4.dport"]), // Distinct src/dport pairs
            groupbyOperator(filterGroups(["ipv4.src"]), counterReducer, "ports", // Group by src, count distinct ports
                filterOperator(keyGeqInt("ports", threshold),
                    nextOp
                )
            )
        )
    );
};

// Sonata 5: DDoS (Distinct sources per destination > threshold)
const ddos: OpCreator = (nextOp) => {
    const threshold = 45; // Note threshold differs from Port Scan slightly
    return epochOperator(1.0, "eid",
        distinctOperator(filterGroups(["ipv4.src", "ipv4.dst"]), // Distinct src/dst pairs
            groupbyOperator(filterGroups(["ipv4.dst"]), counterReducer, "srcs", // Group by dst, count distinct srcs
                filterOperator(keyGeqInt("srcs", threshold),
                    nextOp
                )
            )
        )
    );
};


// --- Sonata 6: SYN Flood (Complex Join) ---
// Returns *list* of initial operators for the branches
function synFloodSonata(nextOp: Operator): Operator[] {
    const threshold = 3;
    const epochDur = 1.0;

    // Branch 1: Count SYNs per destination
    const synsBranch: OpCreator = (op) =>
        epochOperator(epochDur, "eid",
            filterOperator(tup => lookupInt("ipv4.proto", tup) === 6 && lookupInt("l4.flags", tup) === 2, // SYN
                groupbyOperator(filterGroups(["ipv4.dst"]), counterReducer, "syns",
                    op
                )
            )
        );

    // Branch 2: Count SYN-ACKs per source
    const synacksBranch: OpCreator = (op) =>
        epochOperator(epochDur, "eid",
            filterOperator(tup => lookupInt("ipv4.proto", tup) === 6 && lookupInt("l4.flags", tup) === 18, // SYN+ACK
                groupbyOperator(filterGroups(["ipv4.src"]), counterReducer, "synacks",
                    op
                )
            )
        );

    // Branch 3: Count ACKs per destination
    const acksBranch: OpCreator = (op) =>
        epochOperator(epochDur, "eid",
            filterOperator(tup => lookupInt("ipv4.proto", tup) === 6 && lookupInt("l4.flags", tup) === 16, // ACK
                groupbyOperator(filterGroups(["ipv4.dst"]), counterReducer, "acks",
                    op
                )
            )
        );

    // Define the final processing after the second join
    const finalProcessing: OpCreator = (op) =>
        mapOperator(tup => {
                const synsPlusSynacks = lookupInt("syns+synacks", tup);
                const acks = lookupInt("acks", tup);
                const diff = synsPlusSynacks - acks;
                const outTup = new Map(tup);
                outTup.set("syns+synacks-acks", { kind: "Int", value: diff });
                return outTup;
            },
            filterOperator(keyGeqInt("syns+synacks-acks", threshold),
                op // This is the original nextOp passed to synFloodSonata
            )
        );


    // Define the second join (SYN+SYNACK results) with (ACK results)
    const [join2LeftOp, join2RightOp] = joinOperator(
        (tup) => [ // Key extractor for left (syns+synacks)
            filterGroups(["host"])(tup),
            filterGroups(["syns+synacks"])(tup)
        ],
        (tup) => [ // Key extractor for right (acks)
             renameFilteredKeys([["ipv4.dst", "host"]], tup),
             filterGroups(["acks"])(tup)
        ],
        finalProcessing(nextOp) // Apply final processing after this join
    );

    // Define the first join (SYNs) with (SYNACKs)
     const [join1LeftOp, join1RightOp] = joinOperator(
         (tup) => [ // Key extractor for left (syns)
             renameFilteredKeys([["ipv4.dst", "host"]], tup),
             filterGroups(["syns"])(tup)
         ],
         (tup) => [ // Key extractor for right (synacks)
             renameFilteredKeys([["ipv4.src", "host"]], tup),
             filterGroups(["synacks"])(tup)
         ],
          // Output of this join goes to the *left* input of the second join
          // Also need to map the result to add "syns+synacks" field
         mapOperator(tup => {
             const syns = lookupInt("syns", tup);
             const synacks = lookupInt("synacks", tup);
             const sum = syns + synacks;
             const outTup = new Map(tup);
             outTup.set("syns+synacks", { kind: "Int", value: sum });
             return outTup;
         }, join2LeftOp) // Pass result to left input of join2
     );


    // Return the list of operators that are the entry points for the branches
    return [
        synsBranch(join1LeftOp),     // SYNs feed into left input of join1
        synacksBranch(join1RightOp), // SYNACKs feed into right input of join1
        acksBranch(join2RightOp)      // ACKs feed into right input of join2
    ];
}

// --- Sonata 7: Completed Flows ---
function completedFlows(nextOp: Operator): Operator[] {
     const threshold = 1;
     const epochDur = 30.0;

     const synsBranch: OpCreator = (op) =>
         epochOperator(epochDur, "eid",
             filterOperator(tup => lookupInt("ipv4.proto", tup) === 6 && lookupInt("l4.flags", tup) === 2, // SYN
                 groupbyOperator(filterGroups(["ipv4.dst"]), counterReducer, "syns",
                     op
                 )
             )
         );

     const finsBranch: OpCreator = (op) =>
         epochOperator(epochDur, "eid",
             filterOperator(tup => lookupInt("ipv4.proto", tup) === 6 && (lookupInt("l4.flags", tup) & 1) === 1, // FIN flag set
                 groupbyOperator(filterGroups(["ipv4.src"]), counterReducer, "fins",
                     op
                 )
             )
         );

     const finalProcessing: OpCreator = (op) =>
         mapOperator(tup => {
                 const syns = lookupInt("syns", tup);
                 const fins = lookupInt("fins", tup);
                 const diff = syns - fins;
                 const outTup = new Map(tup);
                 outTup.set("diff", { kind: "Int", value: diff });
                 return outTup;
             },
             filterOperator(keyGeqInt("diff", threshold),
                 op
             )
         );

     const [joinLeftOp, joinRightOp] = joinOperator(
         (tup) => [ // Key extractor for left (syns)
             renameFilteredKeys([["ipv4.dst", "host"]], tup),
             filterGroups(["syns"])(tup)
         ],
         (tup) => [ // Key extractor for right (fins)
             renameFilteredKeys([["ipv4.src", "host"]], tup),
             filterGroups(["fins"])(tup)
         ],
         finalProcessing(nextOp)
     );

     return [
         synsBranch(joinLeftOp),
         finsBranch(joinRightOp)
     ];
 }

 // --- Sonata 8: Slowloris ---
 function slowloris(nextOp: Operator): Operator[] {
     const t1 = 5;   // min connections
     const t2 = 500; // min bytes total
     const t3 = 90;  // max bytes per connection
     const epochDur = 1.0;

     // Branch 1: Count distinct connections per destination
     const nConnsBranch: OpCreator = (op) =>
         epochOperator(epochDur, "eid",
             filterOperator(tup => lookupInt("ipv4.proto", tup) === 6, // TCP
                 distinctOperator(filterGroups(["ipv4.src", "ipv4.dst", "l4.sport"]), // Identify connection by 3-tuple
                     groupbyOperator(filterGroups(["ipv4.dst"]), counterReducer, "n_conns", // Group by dst, count distinct connections
                         filterOperator(keyGeqInt("n_conns", t1), // Filter destinations with enough connections
                             op
                         )
                     )
                 )
             )
         );

     // Branch 2: Sum bytes per destination
     const nBytesBranch: OpCreator = (op) =>
         epochOperator(epochDur, "eid",
             filterOperator(tup => lookupInt("ipv4.proto", tup) === 6, // TCP
                 groupbyOperator(filterGroups(["ipv4.dst"]), sumIntsReducer("ipv4.len"), "n_bytes", // Group by dst, sum ipv4.len
                     filterOperator(keyGeqInt("n_bytes", t2), // Filter destinations with enough bytes
                         op
                     )
                 )
             )
         );

     // Final processing after join
     const finalProcessing: OpCreator = (op) =>
         mapOperator(tup => {
                 const nBytes = lookupInt("n_bytes", tup);
                 const nConns = lookupInt("n_conns", tup);
                 // Avoid division by zero, though n_conns should be >= t1 (which is > 0)
                 const bytesPerConn = (nConns > 0) ? Math.floor(nBytes / nConns) : 0;
                 const outTup = new Map(tup);
                 outTup.set("bytes_per_conn", { kind: "Int", value: bytesPerConn });
                 return outTup;
             },
             filterOperator(tup => lookupInt("bytes_per_conn", tup) <= t3, // Check bytes per connection threshold
                 op
             )
         );

     // Join the two branches
     const [joinLeftOp, joinRightOp] = joinOperator(
         (tup) => [ // Key extractor for left (n_conns)
             filterGroups(["ipv4.dst"])(tup),
             filterGroups(["n_conns"])(tup)
         ],
         (tup) => [ // Key extractor for right (n_bytes)
             filterGroups(["ipv4.dst"])(tup),
             filterGroups(["n_bytes"])(tup)
         ],
         finalProcessing(nextOp)
     );

     return [
         nConnsBranch(joinLeftOp),
         nBytesBranch(joinRightOp)
     ];
 }


// --- Test Data Generation and Query Execution ---

// Create a simple output operator (dump to console)
const finalOutput = dumpTupleOperator(process.stdout);

// Select the query to run (e.g., ident)
const queryToRun = ident(finalOutput);
// Example with multiple branches:
// const multiBranchOps = slowloris(finalOutput);

// Generate some sample tuples (similar to OCaml test)
const sampleTuples: Tuple[] = Array.from({ length: 20 }, (_, i) => {
    // Create MAC addresses (example needs macBufferToString or similar)
    // Let's use pre-formatted strings for simplicity here
    const macSrc: MacAddress = "00:11:22:33:44:55";
    const macDst: MacAddress = "aa:bb:cc:dd:ee:ff";
    const ipSrc: IPv4Address = "127.0.0.1";
    const ipDst: IPv4Address = "127.0.0.1"; // Example has same src/dst

    return tupleOfList([
        ["time", { kind: "Float", value: 0.0 + i * 0.05 }], // Add varying time
        ["eth.src", { kind: "MAC", value: macSrc }],
        ["eth.dst", { kind: "MAC", value: macDst }],
        ["eth.ethertype", { kind: "Int", value: 0x0800 }], // IPv4

        ["ipv4.hlen", { kind: "Int", value: 20 }],
        ["ipv4.proto", { kind: "Int", value: 6 }], // TCP
        ["ipv4.len", { kind: "Int", value: 60 + i * 10 }], // Vary length slightly
        ["ipv4.src", { kind: "IPv4", value: ipSrc }],
        ["ipv4.dst", { kind: "IPv4", value: ipDst }],

        ["l4.sport", { kind: "Int", value: 44000 + i }], // Vary source port
        ["l4.dport", { kind: "Int", value: 50000 }],
        ["l4.flags", { kind: "Int", value: (i % 3 === 0) ? 2 : (i % 3 === 1 ? 18 : 16) }] // Cycle SYN, SYN+ACK, ACK
    ]);
});

// --- Main Execution Logic ---
function runQueries() {
    console.log("Running selected query with sample data...");

    // Simulate processing stream of tuples
    sampleTuples.forEach(tup => {
        // If query returns multiple operators (like joins), feed tuple to all
        if (Array.isArray(queryToRun)) {
            queryToRun.forEach(op => op.next(tup));
        } else {
            queryToRun.next(tup);
        }
    });

    // Simulate end of stream / final epoch boundary trigger
    // Need a tuple representing the reset signal, often just epoch ID
    // Find max epoch ID from sample data or use a fixed one for example
    const finalEpochTuple = tupleOfList([["eid", { kind: "Int", value: 1 }]]); // Assuming epoch 1 finishes

    if (Array.isArray(queryToRun)) {
         queryToRun.forEach(op => op.reset(finalEpochTuple));
    } else {
        queryToRun.reset(finalEpochTuple);
    }


    console.log("Done processing sample data.");
}

// --- Script Entry Point ---
if (require.main === module) {
    runQueries();

    // Example of using readWaltsCsv (assuming files exist)
    /*
    async function runWaltCsvExample() {
        const file1 = 'input1.csv';
        const file2 = 'input2.csv';
        // Create dummy files if they don't exist for testing
        if (!fs.existsSync(file1)) fs.writeFileSync(file1, '1.1.1.1,2.2.2.2,10,20,5,100,0\n1.1.1.1,2.2.2.2,11,21,6,120,0\n');
        if (!fs.existsSync(file2)) fs.writeFileSync(file2, '3.3.3.3,4.4.4.4,30,40,7,140,0\n');

        const op1 = countPkts(dumpTupleOperator(process.stdout));
        const op2 = pktsPerSrcDst(dumpTupleOperator(process.stdout));

        try {
            await readWaltsCsv([file1, file2], [op1, op2]);
        } catch (err) {
            console.error("Error running Walt's CSV reader:", err);
        }
    }
    // runWaltCsvExample(); // Uncomment to run this example
    */
}
```

---

**Key Changes and Idiomatic TypeScript Considerations:**

1.  **Types:** Used TypeScript's strong typing with Interfaces (`Operator`), Type Aliases (`Tuple`, `OpResult`, `OpCreator`), and Discriminated Unions (`OpResult`).
2.  **Modules:** Used ES Modules (`import`/`export`) to structure the code into `common.ts`, `builtins.ts`, and `main.ts`.
3.  **Standard Library:** Replaced OCaml's `Map.Make` and `Hashtbl` with TypeScript's built-in `Map`. Replaced `List` functions with `Array` methods (`forEach`, `map`, `filter`, `reduce`) and `Map`/`Set` iteration.
4.  **Mutability:** Handled mutable state (like counters in `metaMeter` or tables in `groupby`, `distinct`, `join`) using `let` variables captured in closures, which is the standard JavaScript/TypeScript way. Object wrappers (`{ value: number }`) were used in `join` to simulate mutable references passed between closures.
5.  **Operators:** Replaced custom infix operators (`@=>`, `@==>`) with standard function application. Chain calls like `a @=> b @=> c` become `a(b(c))`.
6.  **Pattern Matching:** Replaced `match` expressions with `switch` statements (for `OpResult`) or `if/else` and optional chaining (`?.`) where appropriate.
7.  **Error Handling:** Replaced `raise (Failure ...)` with `throw new Error(...)`. Added checks for `undefined` when getting values from `Map`s.
8.  **I/O:** Replaced `Printf`/`fprintf` with `console.log`, Node.js `WritableStream.write`, or `fs.appendFileSync`. Replaced `Scanf.bscanf` and `Scanning.open_in` with Node.js `fs` and `readline` for asynchronous line-by-line processing (more idiomatic for Node.js I/O than synchronous reading, though `readWaltsCsv` implements async processing).
9.  **Data Representation:** Represented IP and MAC addresses as strings. `Bytes.t` for MAC was simplified to a formatted string; `Uint8Array` would be used if raw bytes were needed.
10. **Function Definitions:** Used standard TypeScript function syntax, including arrow functions for closures and predicates. Optional arguments were handled using default parameter values.
11. **Join Implementation:** The `join` logic required careful handling of state (`Map`s) and epoch synchronization. Using stringified tuples as Map keys is a simplification; more robust hashing might be needed for complex keys. The epoch synchronization logic mirrors the OCaml version's intent.
12. **Async:** `readWaltsCsv` was implemented using `async/await` and Node.js `readline`, which is idiomatic for file processing in TypeScript/Node.js. The rest of the operators remain synchronous as per the original design.

This translation aims to be functionally equivalent while adopting common TypeScript patterns and practices. Remember to install Node.js to run this code and potentially `npm install @types/node` for better type checking during development.