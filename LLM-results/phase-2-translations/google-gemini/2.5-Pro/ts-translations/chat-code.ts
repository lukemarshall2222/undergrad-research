import * as ipaddr from 'ipaddr.js'; // npm install ipaddr.js
import * as fs from 'fs';           // Node.js file system module
import * as readline from 'readline'; // Node.js readline for file reading
import { Buffer } from 'buffer';    // Node.js Buffer, can often use Uint8Array too

// --- Common Utilities ---

// --- Core Types ---

// Equivalent to OCaml's op_result variant type
type OpResultFloat = { type: 'Float'; value: number };
type OpResultInt = { type: 'Int'; value: number };
type OpResultIPv4 = { type: 'IPv4'; value: ipaddr.IPv4 };
type OpResultMAC = { type: 'MAC'; value: Uint8Array }; // Using Uint8Array for bytes
type OpResultEmpty = { type: 'Empty' };

type OpResult =
    | OpResultFloat
    | OpResultInt
    | OpResultIPv4
    | OpResultMAC
    | OpResultEmpty;

// Factory functions for OpResult for convenience
const OpResult = {
    Float: (value: number): OpResultFloat => ({ type: 'Float', value }),
    Int: (value: number): OpResultInt => ({ type: 'Int', value }),
    IPv4: (value: ipaddr.IPv4): OpResultIPv4 => ({ type: 'IPv4', value }),
    MAC: (value: Uint8Array): OpResultMAC => ({ type: 'MAC', value }),
    Empty: (): OpResultEmpty => ({ type: 'Empty' }),
};

// Equivalent to OCaml's tuple (Map<string, op_result>)
type Tuple = Map<string, OpResult>;

// Equivalent to OCaml's operator record type
interface Operator {
    next: (tuple: Tuple) => void;
    reset: (tuple: Tuple) => void;
}

// Function types for operator creators
type OpCreator = (nextOp: Operator) => Operator;
type DblOpCreator = (op: Operator) => [Operator, Operator];

// Helper to serialize a Tuple key for use in JS Maps (structural equality)
function serializeTupleKey(tupleKey: Tuple): string {
    const entries = Array.from(tupleKey.entries());
    // Sort by key to ensure consistent serialization order
    entries.sort((a, b) => a[0].localeCompare(b[0]));
    // Simple JSON serialization might be sufficient for many cases
    // WARNING: This is basic; complex OpResult values might need custom serialization
    return JSON.stringify(entries.map(([k, v]) => [k, stringOfOpResult(v)]));
}


// --- Chaining Operators ---

// Equivalent to OCaml's @=>
const chain = (opCreatorFunc: OpCreator, nextOp: Operator): Operator => {
    return opCreatorFunc(nextOp);
};

// Equivalent to OCaml's @==>
const chainDouble = (opCreatorFunc: DblOpCreator, op: Operator): [Operator, Operator] => {
    return opCreatorFunc(op);
};

// --- Conversion Utilities ---

// Formats the 6 bytes of the MAC address as a colon-separated string in hex
function stringOfMac(buf: Uint8Array): string {
    if (buf.length !== 6) {
        throw new Error("MAC address buffer must have length 6");
    }
    return Array.from(buf)
        .map(byte => byte.toString(16).padStart(2, '0'))
        .join(':');
}

// Converts TCP flags into a human-readable string representation
function tcpFlagsToStrings(flags: number): string {
    const tcpFlagsMap: { [key: string]: number } = {
        "FIN": 1 << 0,
        "SYN": 1 << 1,
        "RST": 1 << 2,
        "PSH": 1 << 3,
        "ACK": 1 << 4,
        "URG": 1 << 5,
        "ECE": 1 << 6,
        "CWR": 1 << 7,
    };

    const setFlags = Object.entries(tcpFlagsMap)
        .filter(([_, value]) => (flags & value) === value)
        .map(([key, _]) => key);

    return setFlags.join('|');
}

// Checks if input is an Int op_result, throws error otherwise
function intOfOpResult(input: OpResult): number {
    if (input.type === 'Int') {
        return input.value;
    }
    throw new Error("Trying to extract int from non-int result: " + JSON.stringify(input));
}

// Checks if input is a Float op_result, throws error otherwise
function floatOfOpResult(input: OpResult): number {
    if (input.type === 'Float') {
        return input.value;
    }
    throw new Error("Trying to extract float from non-float result: " + JSON.stringify(input));
}

// Returns the human-readable version of each op_result value
function stringOfOpResult(input: OpResult): string {
    switch (input.type) {
        case 'Float': return input.value.toString(); // Adjust formatting if needed (e.g., toFixed)
        case 'Int': return input.value.toString();
        case 'IPv4': return input.value.toString();
        case 'MAC': return stringOfMac(input.value);
        case 'Empty': return "Empty";
        default:
             // Handle Exhaustiveness Check (useful for ensuring all cases are handled)
             const exhaustiveCheck: never = input;
             throw new Error(`Unhandled OpResult type: ${exhaustiveCheck}`);
    }
}

// Outputs the tuple in a human-readble form
function stringOfTuple(inputTuple: Tuple): string {
    let acc = "";
    inputTuple.forEach((value, key) => {
        acc += `"${key}" => ${stringOfOpResult(value)}, `;
    });
    return acc.replace(/, $/, ''); // Remove trailing comma and space
}

// Creates a Tuple (Map<string, op_result>) out of a list of key-value pairs
function tupleOfList(tupList: [string, OpResult][]): Tuple {
    return new Map(tupList);
}

// Prints formatted representation of a Tuple to console
function dumpTupleConsole(tup: Tuple): void {
    console.log(stringOfTuple(tup));
}

// Retrieves the int value associated with a given key
function lookupInt(key: string, tup: Tuple): number {
    const result = tup.get(key);
    if (result === undefined) {
        throw new Error(`Key "${key}" not found in tuple`);
    }
    return intOfOpResult(result);
}

// Retrieves the float value associated with a given key
function lookupFloat(key: string, tup: Tuple): number {
    const result = tup.get(key);
    if (result === undefined) {
        throw new Error(`Key "${key}" not found in tuple`);
    }
    return floatOfOpResult(result);
}


// --- Built-in Operator Definitions ---

const INIT_TABLE_SIZE: number = 10000; // Hint, not directly used by JS Map constructor

// Dumps tuples to console
function dumpTupleOp(showReset: boolean = false): Operator {
    return {
        next: (tup: Tuple): void => {
            dumpTupleConsole(tup);
        },
        reset: (tup: Tuple): void => {
            if (showReset) {
                dumpTupleConsole(tup);
                console.log("[reset]");
            }
        },
    };
}

// Dumps tuples as CSV to console or a file stream
function dumpAsCsv(
    outStream: NodeJS.WritableStream = process.stdout, // Default to console
    staticField?: [string, string],
    header: boolean = true
): Operator {
    let first: boolean = header; // Closure to keep track of header state

    return {
        next: (tup: Tuple): void => {
            let line = "";
            if (first) {
                let headerLine = "";
                if (staticField) {
                    headerLine += `${staticField[0]},`;
                }
                tup.forEach((_, key) => {
                    headerLine += `${key},`;
                });
                outStream.write(headerLine.replace(/,$/, '\n')); // Remove trailing comma, add newline
                first = false;
            }

            if (staticField) {
                line += `${staticField[1]},`;
            }
            tup.forEach((value) => {
                line += `${stringOfOpResult(value)},`;
            });
            outStream.write(line.replace(/,$/, '\n')); // Remove trailing comma, add newline
        },
        reset: (_tup: Tuple): void => {
            // Reset does nothing in this operator, but could flush stream etc.
        },
    };
}


// Dumps csv in Walt's canonical csv format
function dumpWaltsCsv(filename: string): Operator {
    let outStream: fs.WriteStream | null = null; // Use fs.WriteStream for files
    let first: boolean = true;

    return {
        next: (tup: Tuple): void => {
            if (first) {
                try {
                    outStream = fs.createWriteStream(filename);
                } catch (e) {
                    console.error(`Failed to open file ${filename}:`, e);
                    // Potentially disable the operator or throw
                    outStream = null;
                }
                first = false;
            }

            if (outStream) {
                try {
                    const line = [
                        stringOfOpResult(tup.get("src_ip") ?? OpResult.Empty()),
                        stringOfOpResult(tup.get("dst_ip") ?? OpResult.Empty()),
                        stringOfOpResult(tup.get("src_l4_port") ?? OpResult.Empty()),
                        stringOfOpResult(tup.get("dst_l4_port") ?? OpResult.Empty()),
                        stringOfOpResult(tup.get("packet_count") ?? OpResult.Empty()),
                        stringOfOpResult(tup.get("byte_count") ?? OpResult.Empty()),
                        stringOfOpResult(tup.get("epoch_id") ?? OpResult.Empty()),
                    ].join(',') + '\n';
                    outStream.write(line);
                } catch (e) {
                     console.error(`Error writing to ${filename}:`, e);
                     // Handle error, maybe close stream
                }
            }
        },
        reset: (_tup: Tuple): void => {
            // Close the file stream on reset? Or maybe on a final 'end' signal?
            // OCaml doesn't explicitly close here, assumes context manages it.
            // Let's not close it on every reset for now.
        },
        // Add a cleanup method if needed
        // cleanup: (): void => { outStream?.end(); }
    };
}

// Helper for readWaltsCsv
function getIpOrZero(input: string): OpResult {
    if (input === "0") {
        return OpResult.Int(0);
    } else {
        try {
            return OpResult.IPv4(ipaddr.parse(input) as ipaddr.IPv4); // Assert IPv4
        } catch (e) {
            console.error(`Failed to parse IP: ${input}`, e);
            // Decide on error handling: throw, return Empty, etc.
            throw new Error(`Invalid IP address format: ${input}`);
        }
    }
}

// Reads Walt's CSV format - Simplified async version using readline
// NOTE: This is significantly different from Scanf.bscanf. It reads line by line.
// The OCaml version seems to imply processing files in parallel/round-robin,
// which is much more complex to implement correctly in async JS.
// This version processes files sequentially for simplicity.
async function readWaltsCsv(
    fileNames: string[],
    ops: Operator[],
    epochIdKey: string = "eid"
): Promise<void> {
    if (fileNames.length !== ops.length) {
        throw new Error("Number of file names must match number of operators");
    }

    for (let i = 0; i < fileNames.length; i++) {
        const filename = fileNames[i];
        const op = ops[i];
        let currentEid = 0;
        let tupCountInEpoch = 0;

        console.log(`Processing file: ${filename}`);

        try {
            const fileStream = fs.createReadStream(filename);
            const rl = readline.createInterface({
                input: fileStream,
                crlfDelay: Infinity
            });

            for await (const line of rl) {
                const parts = line.split(',');
                if (parts.length !== 7) {
                    console.warn(`Skipping malformed line in ${filename}: ${line}`);
                    continue;
                }

                const [srcIpStr, dstIpStr, srcL4PortStr, dstL4PortStr, pktCountStr, byteCountStr, epochIdStr] = parts;

                try {
                    const srcL4Port = parseInt(srcL4PortStr, 10);
                    const dstL4Port = parseInt(dstL4PortStr, 10);
                    const packetCount = parseInt(pktCountStr, 10);
                    const byteCount = parseInt(byteCountStr, 10);
                    const epochId = parseInt(epochIdStr, 10);

                    if (isNaN(srcL4Port) || isNaN(dstL4Port) || isNaN(packetCount) || isNaN(byteCount) || isNaN(epochId)) {
                         console.warn(`Skipping line with non-integer values in ${filename}: ${line}`);
                         continue;
                    }


                    const p: Tuple = tupleOfList([
                        ["ipv4.src", getIpOrZero(srcIpStr)],
                        ["ipv4.dst", getIpOrZero(dstIpStr)],
                        ["l4.sport", OpResult.Int(srcL4Port)],
                        ["l4.dport", OpResult.Int(dstL4Port)],
                        ["packet_count", OpResult.Int(packetCount)],
                        ["byte_count", OpResult.Int(byteCount)],
                        [epochIdKey, OpResult.Int(epochId)],
                    ]);

                    tupCountInEpoch++;

                    if (epochId > currentEid) {
                        // Process resets for skipped epochs
                        while (epochId > currentEid) {
                            const resetTuple = new Map<string, OpResult>();
                            resetTuple.set("tuples", OpResult.Int(tupCountInEpoch -1)); // Count before this tuple
                            resetTuple.set(epochIdKey, OpResult.Int(currentEid));
                            op.reset(resetTuple);
                            tupCountInEpoch = 1; // Reset count for the new epoch (starting with current tuple)
                            currentEid++;
                        }
                    }
                    // Add current tuple count before processing
                    const processedTuple = new Map(p);
                    processedTuple.set("tuples", OpResult.Int(tupCountInEpoch));
                    op.next(processedTuple);

                } catch (parseError) {
                    console.warn(`Error processing line in ${filename}: ${line}`, parseError);
                }
            } // End of file reading loop

            // Final reset for the last epoch processed
            const finalResetTuple = new Map<string, OpResult>();
            finalResetTuple.set("tuples", OpResult.Int(tupCountInEpoch));
            finalResetTuple.set(epochIdKey, OpResult.Int(currentEid)); // Use the last seen or inferred epoch id
            op.reset(finalResetTuple);
            console.log(`Finished processing file: ${filename}`);

        } catch (fileError) {
            console.error(`Failed to read file ${filename}:`, fileError);
            // Decide how to proceed: skip file, stop all processing?
            // For now, just log and continue to the next file if any.
        }
    } // End of file list loop
    console.log("Done reading all files.");
}


// Meta-meter operator
function metaMeter(
    name: string,
    outStream: NodeJS.WritableStream = process.stdout,
    staticField?: string
): OpCreator {
    return (nextOp: Operator): Operator => {
        let epochCount: number = 0;
        let tupsCount: number = 0;

        return {
            next: (tup: Tuple): void => {
                tupsCount++;
                nextOp.next(tup);
            },
            reset: (tup: Tuple): void => {
                const staticVal = staticField ?? "";
                const line = `${epochCount},${name},${tupsCount},${staticVal}\n`;
                outStream.write(line);

                tupsCount = 0;
                epochCount++;
                nextOp.reset(tup); // Pass reset down
            },
        };
    };
}

// Epoch operator
function epoch(epochWidth: number, keyOut: string): OpCreator {
    return (nextOp: Operator): Operator => {
        let epochBoundary: number = 0.0;
        let eid: number = 0;

        return {
            next: (tup: Tuple): void => {
                const time = lookupFloat("time", tup);

                if (epochBoundary === 0.0) { // First tuple
                    epochBoundary = time + epochWidth;
                } else if (time >= epochBoundary) {
                    // Process resets for completed epochs
                    while (time >= epochBoundary) {
                        const resetTuple = new Map<string, OpResult>();
                        resetTuple.set(keyOut, OpResult.Int(eid));
                        nextOp.reset(resetTuple);
                        epochBoundary += epochWidth;
                        eid++;
                    }
                }
                // Add epoch ID to the current tuple and pass downstream
                const outTuple = new Map(tup);
                outTuple.set(keyOut, OpResult.Int(eid));
                nextOp.next(outTuple);
            },
            reset: (_tup: Tuple): void => { // Handle external reset signal
                // Reset the last epoch before resetting internal state
                const finalResetTuple = new Map<string, OpResult>();
                finalResetTuple.set(keyOut, OpResult.Int(eid));
                nextOp.reset(finalResetTuple);

                // Reset internal state
                epochBoundary = 0.0;
                eid = 0;
            },
        };
    };
}

// Filter operator
function filter(f: (tuple: Tuple) => boolean): OpCreator {
    return (nextOp: Operator): Operator => {
        return {
            next: (tup: Tuple): void => {
                if (f(tup)) {
                    nextOp.next(tup);
                }
            },
            reset: (tup: Tuple): void => {
                nextOp.reset(tup); // Pass reset downstream
            },
        };
    };
}

// Filter utility: key_geq_int
function keyGeqInt(key: string, threshold: number): (tup: Tuple) => boolean {
    return (tup: Tuple): boolean => {
        try {
          // Handle case where key might not exist or is not an int gracefully
           const value = tup.get(key);
           if (value?.type === 'Int') {
                return value.value >= threshold;
           }
           return false; // Or throw error if key must exist
        } catch (e) {
            // Log error or handle as needed if lookupInt throws
            console.error(`Error in keyGeqInt for key "${key}":`, e);
            return false;
        }
    };
}


// Filter utility: get_mapped_int (already implemented as lookupInt)
const getMappedInt = lookupInt;

// Filter utility: get_mapped_float (already implemented as lookupFloat)
const getMappedFloat = lookupFloat;


// Map operator
function map(f: (tuple: Tuple) => Tuple): OpCreator {
    return (nextOp: Operator): Operator => {
        return {
            next: (tup: Tuple): void => {
                nextOp.next(f(tup));
            },
            reset: (tup: Tuple): void => {
                nextOp.reset(tup); // Pass reset downstream
            },
        };
    };
}

// Type aliases for groupby functions
type GroupingFunc = (tuple: Tuple) => Tuple; // Returns the key tuple
type ReductionFunc = (currentValue: OpResult, tuple: Tuple) => OpResult;

// Groupby operator
function groupby(
    grouper: GroupingFunc,
    reducer: ReductionFunc,
    outKey: string
): OpCreator {
    return (nextOp: Operator): Operator => {
        // Use serialized keys for Map to handle structural equality
        let hTbl = new Map<string, { keyTuple: Tuple, value: OpResult }>();
        // let resetCounter = 0; // OCaml version tracks resets, not used here but could be added

        return {
            next: (tup: Tuple): void => {
                const groupingKeyTuple = grouper(tup);
                const serializedKey = serializeTupleKey(groupingKeyTuple);
                const existingEntry = hTbl.get(serializedKey);

                if (existingEntry !== undefined) {
                    const newValue = reducer(existingEntry.value, tup);
                    hTbl.set(serializedKey, { keyTuple: groupingKeyTuple, value: newValue });
                } else {
                    const newValue = reducer(OpResult.Empty(), tup);
                    hTbl.set(serializedKey, { keyTuple: groupingKeyTuple, value: newValue });
                }
            },
            reset: (resetTuple: Tuple): void => {
                // resetCounter++;
                hTbl.forEach((entry) => {
                    // Merge reset tuple, grouping key tuple, and result value
                    const mergedTuple = new Map(resetTuple);
                    // Add grouping key fields (original tuple key)
                    entry.keyTuple.forEach((val, key) => mergedTuple.set(key, val));
                    // Add the aggregated value
                    mergedTuple.set(outKey, entry.value);
                    nextOp.next(mergedTuple); // Pass each group's result downstream
                });

                nextOp.reset(resetTuple); // Pass the original reset tuple downstream
                hTbl.clear(); // Clear the table for the next epoch
            },
        };
    };
}

// Groupby utility: filter_groups
function filterGroups(inclKeys: string[]): GroupingFunc {
    return (tup: Tuple): Tuple => {
        const newTuple = new Map<string, OpResult>();
        tup.forEach((value, key) => {
            if (inclKeys.includes(key)) {
                newTuple.set(key, value);
            }
        });
        return newTuple;
    };
}

// Groupby utility: single_group
const singleGroup: GroupingFunc = (_tup: Tuple): Tuple => {
    return new Map<string, OpResult>(); // Empty map means one group
};

// Groupby utility: counter
const counter: ReductionFunc = (val: OpResult, _tup: Tuple): OpResult => {
    if (val.type === 'Empty') {
        return OpResult.Int(1);
    } else if (val.type === 'Int') {
        return OpResult.Int(val.value + 1);
    } else {
         // Should not happen if used correctly, maybe return error or current val
        console.error("Counter received non-Int/Empty value:", val);
        return val;
    }
};

// Groupby utility: sum_ints
function sumInts(searchKey: string): ReductionFunc {
    return (currentVal: OpResult, tup: Tuple): OpResult => {
        const initialSum = (currentVal.type === 'Int') ? currentVal.value : 0;
        const valueToAdd = tup.get(searchKey);

        if (valueToAdd?.type === 'Int') {
             return OpResult.Int(initialSum + valueToAdd.value);
        } else if (currentVal.type !== 'Empty') {
            // If key not found or not Int, but we have a running sum, return the sum
             return currentVal;
        } else {
            // If key not found and it's the first element, return Int 0
             return OpResult.Int(initialSum);
             // Alternative: Throw an error if the key MUST exist and be an Int
             // throw new Error(`'sumInts' function failed to find integer value mapped to "${searchKey}"`);
        }
    };
}


// Distinct operator
function distinct(grouper: GroupingFunc): OpCreator {
    return (nextOp: Operator): Operator => {
        // Use serialized keys for Set/Map to handle structural equality
        let hTbl = new Map<string, Tuple>(); // Store the representative tuple for the key
        // let resetCounter = 0;

        return {
            next: (tup: Tuple): void => {
                const groupingKeyTuple = grouper(tup);
                const serializedKey = serializeTupleKey(groupingKeyTuple);
                // Only add if not already present (replace just updates)
                if (!hTbl.has(serializedKey)) {
                   // Store the *original* tuple that generated this unique key,
                   // or just the key if that's all needed downstream.
                   // OCaml stores the key, let's do that.
                   hTbl.set(serializedKey, groupingKeyTuple);
                }
            },
            reset: (resetTuple: Tuple): void => {
                // resetCounter++;
                hTbl.forEach((keyTuple) => {
                    // Merge the reset tuple and the distinct key tuple
                    const mergedTuple = new Map(resetTuple);
                    keyTuple.forEach((val, key) => mergedTuple.set(key, val));
                    nextOp.next(mergedTuple);
                });

                nextOp.reset(resetTuple); // Pass reset downstream
                hTbl.clear();
            },
        };
    };
}


// Split operator
function split(leftOp: Operator, rightOp: Operator): Operator {
    return {
        next: (tup: Tuple): void => {
            // Create copies if downstream operators modify the tuple?
            // OCaml passes the same reference. Let's do that for now.
            leftOp.next(tup);
            rightOp.next(tup);
        },
        reset: (tup: Tuple): void => {
            leftOp.reset(tup);
            rightOp.reset(tup);
        },
    };
}


// Type alias for join key extractor
type KeyExtractor = (tuple: Tuple) => { key: Tuple, value: Tuple }; // OCaml returns pair, use object

// Join operator
// NOTE: This join logic is complex and relies heavily on epoch synchronization.
// Translating it perfectly requires careful state management.
// This version attempts to capture the core logic but might need refinement.
function join(
    leftExtractor: KeyExtractor,
    rightExtractor: KeyExtractor,
    eidKey: string = "eid"
): DblOpCreator { // Returns a creator that makes the pair
   return (nextOp: Operator): [Operator, Operator] => {
        // Use serialized keys for Maps
        // Store the value tuple associated with the key tuple
        const hTbl1 = new Map<string, Tuple>(); // State for left input
        const hTbl2 = new Map<string, Tuple>(); // State for right input
        let leftCurrEpoch = -1; // Start at -1 to handle first epoch correctly
        let rightCurrEpoch = -1;

        const handleJoinSide = (
            currHTbl: Map<string, Tuple>,
            otherHTbl: Map<string, Tuple>,
            currEpochRef: { val: number }, // Pass refs via objects
            otherEpochRef: { val: number },
            extractor: KeyExtractor
        ): Operator => {
            return {
                next: (tup: Tuple): void => {
                    const { key: keyTuple, value: valsTuple } = extractor(tup);
                    let currentTupleEpoch: number;
                    try {
                        currentTupleEpoch = getMappedInt(eidKey, tup);
                    } catch (e) {
                        console.error(`Join failed: Tuple missing epoch key "${eidKey}"`, tup);
                        return; // Skip tuple if no epoch
                    }


                    // --- Epoch Synchronization ---
                    // Advance current side's epoch if tuple is ahead
                    while (currentTupleEpoch > currEpochRef.val) {
                         // Check if the *other* side has already processed this epoch before resetting
                        if (otherEpochRef.val > currEpochRef.val) {
                           const resetTuple = new Map<string, OpResult>([[eidKey, OpResult.Int(currEpochRef.val)]]);
                           // console.log(`Join Reset from side ${currHTbl === hTbl1 ? 1 : 2}, Epoch ${currEpochRef.val}`);
                           nextOp.reset(resetTuple);
                        }
                         currEpochRef.val++;
                         // Clean up own table from previous epoch? OCaml doesn't explicitly here, assumes resets handle it.
                         // It relies on the *other* side finding matches or the reset clearing.
                    }
                    // If tuple is from an old epoch, maybe discard or handle? OCaml logic processes it.

                    // Key for matching must include the epoch
                    const keyWithEpoch = new Map(keyTuple);
                    keyWithEpoch.set(eidKey, OpResult.Int(currentTupleEpoch));
                    const serializedKey = serializeTupleKey(keyWithEpoch);

                    // --- Matching Logic ---
                    const matchInOther = otherHTbl.get(serializedKey);

                    if (matchInOther !== undefined) {
                        // Found match in the other table
                        otherHTbl.delete(serializedKey); // Consume the match

                        // Merge: key + left_vals + right_vals (order matters if keys overlap)
                        const mergedTuple = new Map<string, OpResult>();
                        // Add key fields first
                        keyWithEpoch.forEach((v, k) => mergedTuple.set(k, v));
                         // Add values from the tuple that just arrived
                        valsTuple.forEach((v, k) => mergedTuple.set(k, v));
                        // Add values from the matched tuple (from the other table)
                        matchInOther.forEach((v, k) => mergedTuple.set(k, v)); // Overwrites if key exists

                        // console.log(`Join Match Found! Epoch ${currentTupleEpoch}, Key: ${serializedKey}`);
                        nextOp.next(mergedTuple);
                    } else {
                        // No match yet, store values in own table
                        // console.log(`Join Storing. Epoch ${currentTupleEpoch}, Key: ${serializedKey} from side ${currHTbl === hTbl1 ? 1 : 2}`);
                        currHTbl.set(serializedKey, valsTuple);
                    }
                },
                reset: (resetTuple: Tuple): void => {
                    let resetEpoch: number;
                     try {
                        resetEpoch = getMappedInt(eidKey, resetTuple);
                    } catch (e) {
                        console.error(`Join reset ignored: Reset Tuple missing epoch key "${eidKey}"`, resetTuple);
                        return; // Skip reset if no epoch
                    }

                    // --- Epoch Synchronization on Reset ---
                     while (resetEpoch > currEpochRef.val) {
                        // Check if the *other* side is ahead before issuing reset
                        if (otherEpochRef.val > currEpochRef.val) {
                            const downstreamResetTuple = new Map<string, OpResult>([[eidKey, OpResult.Int(currEpochRef.val)]]);
                             // console.log(`Join Reset (Internal Loop) from side ${currHTbl === hTbl1 ? 1 : 2}, Epoch ${currEpochRef.val}`);
                            nextOp.reset(downstreamResetTuple);
                        }
                        currEpochRef.val++;
                        // Clear expired entries from own table?
                        // OCaml relies on the global reset call eventually, maybe we should too.
                        // However, explicitly clearing expired entries might be safer.
                        const epochToClear = currEpochRef.val -1;
                         currHTbl.forEach((_v, kSer) => {
                             // Hacky: deserialize just to check epoch - inefficient
                             try {
                                 const entries: [string, any][] = JSON.parse(kSer);
                                 const epochEntry = entries.find(([k, _v]) => k === eidKey);
                                 if (epochEntry && epochEntry[1] === `Int ${epochToClear}`) {
                                     // console.log(`Join clearing expired key ${kSer} from epoch ${epochToClear}`);
                                     currHTbl.delete(kSer);
                                 }
                             } catch { /* ignore parse errors */ }
                         });
                    }
                    // If resetEpoch === currEpochRef.val, the main reset below handles it.
                    // If resetEpoch < currEpochRef.val, ignore the reset? OCaml seems to.

                     // After synchronizing, pass the *original* reset tuple if it matches the current epoch expectation
                     // Or should we always pass the reset? OCaml passes resetTuple in the outer loop.
                     // Let's align with the outer loop behavior seen in groupby/distinct.
                     // The primary purpose of this specific reset might be just epoch advancement.
                     // Let's comment out the direct pass for now, relying on the outer logic.
                     // nextOp.reset(resetTuple);

                      // Clear tables on reset? OCaml's groupby/distinct clear tables on reset.
                      // Join seems stateful across epochs based on matching.
                      // Let's *not* clear the tables here, relying on matching or explicit cleanup.
                     // currHTbl.clear(); // Maybe not?
                },
            };
        };

        // Need mutable objects to pass epoch refs
        const leftEpochRef = { val: leftCurrEpoch };
        const rightEpochRef = { val: rightCurrEpoch };

        const leftOp = handleJoinSide(hTbl1, hTbl2, leftEpochRef, rightEpochRef, leftExtractor);
        const rightOp = handleJoinSide(hTbl2, hTbl1, rightEpochRef, leftEpochRef, rightExtractor);

        // Need a mechanism to trigger the final reset based on the *overall* epoch state
        // This is tricky. The OCaml version relies on the *caller* of `read_walts_csv`
        // to send the final reset signals.

        return [leftOp, rightOp];
    };
}

// Join utility: rename_filtered_keys
function renameFilteredKeys(renamingsPairs: [string, string][]): (tup: Tuple) => Tuple {
   return (inTup: Tuple): Tuple => {
        const newTuple = new Map<string, OpResult>();
        renamingsPairs.forEach(([oldKey, newKey]) => {
            const value = inTup.get(oldKey);
            if (value !== undefined) {
                newTuple.set(newKey, value);
            }
        });
        return newTuple;
    };
}


// --- Query Definitions ---

// Identity (with eth addr removal)
function ident(): OpCreator {
    return (nextOp: Operator): Operator =>
        chain(
            map((tup: Tuple) => {
                const filtered = new Map<string, OpResult>();
                tup.forEach((val, key) => {
                    if (key !== "eth.src" && key !== "eth.dst") {
                        filtered.set(key, val);
                    }
                });
                return filtered;
            }),
            nextOp
        );
}


// Count packets per epoch
function countPkts(): OpCreator {
    return (nextOp: Operator): Operator =>
        chain(epoch(1.0, "eid"),
            chain(groupby(singleGroup, counter, "pkts"),
                nextOp
            )
        );
}

// Packets per src/dst per epoch
function pktsPerSrcDst(): OpCreator {
    return (nextOp: Operator): Operator =>
        chain(epoch(1.0, "eid"),
            chain(groupby(filterGroups(["ipv4.src", "ipv4.dst"]), counter, "pkts"),
                 nextOp
            )
        );
}

// Count distinct source IPs per epoch
function distinctSrcs(): OpCreator {
    return (nextOp: Operator): Operator =>
        chain(epoch(1.0, "eid"),
            chain(distinct(filterGroups(["ipv4.src"])),
                chain(groupby(singleGroup, counter, "srcs"),
                    nextOp
                )
            )
        );
}


// Sonata 1: TCP New Connections per Destination > Threshold
function tcpNewCons(threshold: number = 40): OpCreator {
    return (nextOp: Operator): Operator =>
        chain(epoch(1.0, "eid"),
            chain(filter((tup: Tuple) =>
                getMappedInt("ipv4.proto", tup) === 6 && // TCP
                getMappedInt("l4.flags", tup) === 2 // SYN
            ),
                chain(groupby(filterGroups(["ipv4.dst"]), counter, "cons"),
                    chain(filter(keyGeqInt("cons", threshold)),
                        nextOp
                    )
                )
            )
        );
}

// Sonata 2: SSH Brute Force (Distinct Src+Len per Dst > Threshold)
function sshBruteForce(threshold: number = 40): OpCreator {
    return (nextOp: Operator): Operator =>
        chain(epoch(1.0, "eid"), // Consider longer epoch?
            chain(filter((tup: Tuple) =>
                getMappedInt("ipv4.proto", tup) === 6 && // TCP
                getMappedInt("l4.dport", tup) === 22 // SSH Port
            ),
                chain(distinct(filterGroups(["ipv4.src", "ipv4.dst", "ipv4.len"])), // Note: OCaml used len, might be packet len?
                    chain(groupby(filterGroups(["ipv4.dst", "ipv4.len"]), counter, "srcs"),
                        chain(filter(keyGeqInt("srcs", threshold)),
                            nextOp
                        )
                    )
                )
            )
        );
}

// Sonata 3: Super Spreader (Distinct Dst per Src > Threshold)
function superSpreader(threshold: number = 40): OpCreator {
    return (nextOp: Operator): Operator =>
        chain(epoch(1.0, "eid"),
            chain(distinct(filterGroups(["ipv4.src", "ipv4.dst"])),
                chain(groupby(filterGroups(["ipv4.src"]), counter, "dsts"),
                    chain(filter(keyGeqInt("dsts", threshold)),
                        nextOp
                    )
                )
            )
        );
}

// Sonata 4: Port Scan (Distinct Dst Port per Src > Threshold)
function portScan(threshold: number = 40): OpCreator {
     return (nextOp: Operator): Operator =>
        chain(epoch(1.0, "eid"),
            chain(distinct(filterGroups(["ipv4.src", "l4.dport"])),
                chain(groupby(filterGroups(["ipv4.src"]), counter, "ports"),
                    chain(filter(keyGeqInt("ports", threshold)),
                         nextOp
                    )
                )
            )
        );
}

// Sonata 5: DDOS (Distinct Src per Dst > Threshold)
function ddos(threshold: number = 45): OpCreator {
    return (nextOp: Operator): Operator =>
        chain(epoch(1.0, "eid"),
            chain(distinct(filterGroups(["ipv4.src", "ipv4.dst"])),
                chain(groupby(filterGroups(["ipv4.dst"]), counter, "srcs"),
                    chain(filter(keyGeqInt("srcs", threshold)),
                        nextOp
                    )
                )
            )
        );
}


// Sonata 6: SYN Flood (Sonata version: (SYNs + SYNACKs) - ACKs > Threshold)
function synFloodSonata(threshold: number = 3, epochDur: number = 1.0): (nextOp: Operator) => Operator[] {
    return (nextOp: Operator): Operator[] => {
        // --- Define sub-pipelines ---
        const syns = (op: Operator): Operator =>
            chain(epoch(epochDur, "eid"),
                chain(filter((tup: Tuple) =>
                    getMappedInt("ipv4.proto", tup) === 6 && getMappedInt("l4.flags", tup) === 2 // SYN
                ),
                    chain(groupby(filterGroups(["ipv4.dst"]), counter, "syns"),
                        op
                    )
                )
            );

        const synacks = (op: Operator): Operator =>
            chain(epoch(epochDur, "eid"),
                chain(filter((tup: Tuple) =>
                    getMappedInt("ipv4.proto", tup) === 6 && getMappedInt("l4.flags", tup) === 18 // SYN+ACK
                ),
                    chain(groupby(filterGroups(["ipv4.src"]), counter, "synacks"), // Group by src
                        op
                    )
                )
            );

        const acks = (op: Operator): Operator =>
             chain(epoch(epochDur, "eid"),
                chain(filter((tup: Tuple) =>
                    getMappedInt("ipv4.proto", tup) === 6 && getMappedInt("l4.flags", tup) === 16 // ACK
                ),
                     chain(groupby(filterGroups(["ipv4.dst"]), counter, "acks"),
                        op
                    )
                )
            );

        // --- Define Joins ---
        // Join 1: Combines (SYN+SYNACKs) result with ACKs result
        const [j1Input1, j1Input2] = chainDouble(
            join(
                // Left Input (from Join 2): Key = {host}, Value = {syns+synacks}
                (tup: Tuple) => ({ key: filterGroups(["host"])(tup), value: filterGroups(["syns+synacks"])(tup) }),
                // Right Input (from ACKs): Key = {host<-ipv4.dst}, Value = {acks}
                (tup: Tuple) => ({ key: renameFilteredKeys([["ipv4.dst", "host"]])(tup), value: filterGroups(["acks"])(tup) })
            ),
            // Operator after Join 1
            chain(map((tup: Tuple) => { // Calculate difference
                    const synAckSum = getMappedInt("syns+synacks", tup);
                    const ackCount = getMappedInt("acks", tup);
                    const diff = synAckSum - ackCount;
                    const out = new Map(tup);
                    out.set("syns+synacks-acks", OpResult.Int(diff));
                    return out;
                }),
                chain(filter(keyGeqInt("syns+synacks-acks", threshold)),
                    nextOp // Final downstream operator
                )
            )
        );

        // Join 2: Combines SYNs and SYNACKs
        const [j2Input1, j2Input2] = chainDouble(
            join(
                 // Left Input (from SYNs): Key = {host<-ipv4.dst}, Value = {syns}
                (tup: Tuple) => ({ key: renameFilteredKeys([["ipv4.dst", "host"]])(tup), value: filterGroups(["syns"])(tup) }),
                // Right Input (from SYNACKs): Key = {host<-ipv4.src}, Value = {synacks}
                (tup: Tuple) => ({ key: renameFilteredKeys([["ipv4.src", "host"]])(tup), value: filterGroups(["synacks"])(tup) })
            ),
            // Operator after Join 2
             chain(map((tup: Tuple) => { // Calculate sum
                    const synCount = getMappedInt("syns", tup);
                    const synAckCount = getMappedInt("synacks", tup);
                    const sum = synCount + synAckCount;
                    const out = new Map(tup);
                    out.set("syns+synacks", OpResult.Int(sum));
                    return out;
                }),
                j1Input1 // Output of Join 2 goes to the first input of Join 1
            )
        );

        // --- Connect pipelines to join inputs ---
        return [
            syns(j2Input1),    // SYNs pipeline feeds Join 2, Input 1
            synacks(j2Input2), // SYNACKs pipeline feeds Join 2, Input 2
            acks(j1Input2)     // ACKs pipeline feeds Join 1, Input 2
        ];
    };
}


// Sonata 7: Completed Flows (SYNs - FINs > Threshold)
function completedFlows(threshold: number = 1, epochDur: number = 30.0): (nextOp: Operator) => Operator[] {
     return (nextOp: Operator): Operator[] => {
         // --- Define sub-pipelines ---
         const syns = (op: Operator): Operator =>
            chain(epoch(epochDur, "eid"),
                chain(filter((tup: Tuple) =>
                     getMappedInt("ipv4.proto", tup) === 6 && getMappedInt("l4.flags", tup) === 2 // SYN
                ),
                    chain(groupby(filterGroups(["ipv4.dst"]), counter, "syns"),
                        op
                    )
                )
            );

         const fins = (op: Operator): Operator =>
            chain(epoch(epochDur, "eid"),
                chain(filter((tup: Tuple) =>
                    getMappedInt("ipv4.proto", tup) === 6 && (getMappedInt("l4.flags", tup) & 1) === 1 // FIN flag set
                ),
                    chain(groupby(filterGroups(["ipv4.src"]), counter, "fins"), // Group by src
                        op
                    )
                )
            );

         // --- Define Join ---
         const [op1, op2] = chainDouble(
             join(
                 // Left Input (from SYNs): Key = {host<-ipv4.dst}, Value = {syns}
                (tup: Tuple) => ({ key: renameFilteredKeys([["ipv4.dst", "host"]])(tup), value: filterGroups(["syns"])(tup) }),
                // Right Input (from FINS): Key = {host<-ipv4.src}, Value = {fins}
                (tup: Tuple) => ({ key: renameFilteredKeys([["ipv4.src", "host"]])(tup), value: filterGroups(["fins"])(tup) })
             ),
             // Operator after Join
             chain(map((tup: Tuple) => { // Calculate difference
                    const synCount = getMappedInt("syns", tup);
                    const finCount = getMappedInt("fins", tup);
                    const diff = synCount - finCount;
                    const out = new Map(tup);
                    out.set("diff", OpResult.Int(diff));
                    return out;
                 }),
                 chain(filter(keyGeqInt("diff", threshold)),
                     nextOp // Final downstream operator
                 )
             )
         );

         // --- Connect pipelines ---
         return [
             syns(op1), // SYNs pipeline feeds Join Input 1
             fins(op2)  // FINs pipeline feeds Join Input 2
         ];
     };
}

// Sonata 8: Slowloris (High conns, high bytes per conn > T3 threshold)
function slowloris(t1: number = 5, t2: number = 500, t3: number = 90, epochDur: number = 1.0): (nextOp: Operator) => Operator[] {
     return (nextOp: Operator): Operator[] => {
         // --- Define sub-pipelines ---
         // Calculate number of distinct connections per destination
         const nConns = (op: Operator): Operator =>
             chain(epoch(epochDur, "eid"),
                chain(filter((tup: Tuple) => getMappedInt("ipv4.proto", tup) === 6), // TCP
                    chain(distinct(filterGroups(["ipv4.src", "ipv4.dst", "l4.sport"])), // Distinct 3-tuple
                        chain(groupby(filterGroups(["ipv4.dst"]), counter, "n_conns"), // Group by dest
                            chain(filter(keyGeqInt("n_conns", t1)), // Filter by conn threshold T1
                                op
                            )
                        )
                    )
                )
            );

         // Calculate total bytes per destination
         const nBytes = (op: Operator): Operator =>
            chain(epoch(epochDur, "eid"),
                chain(filter((tup: Tuple) => getMappedInt("ipv4.proto", tup) === 6), // TCP
                    chain(groupby(filterGroups(["ipv4.dst"]), sumInts("ipv4.len"), "n_bytes"), // Sum ipv4.len per dest
                        chain(filter(keyGeqInt("n_bytes", t2)), // Filter by bytes threshold T2
                            op
                        )
                    )
                )
            );

         // --- Define Join ---
         const [op1, op2] = chainDouble(
             join(
                // Left Input (from nConns): Key = {ipv4.dst}, Value = {n_conns}
                (tup: Tuple) => ({ key: filterGroups(["ipv4.dst"])(tup), value: filterGroups(["n_conns"])(tup) }),
                // Right Input (from nBytes): Key = {ipv4.dst}, Value = {n_bytes}
                (tup: Tuple) => ({ key: filterGroups(["ipv4.dst"])(tup), value: filterGroups(["n_bytes"])(tup) })
             ),
             // Operator after Join
            chain(map((tup: Tuple) => { // Calculate bytes per connection
                    const numBytes = getMappedInt("n_bytes", tup);
                    const numConns = getMappedInt("n_conns", tup);
                    // Avoid division by zero, though filter t1 > 0 should prevent n_conns=0
                    const bytesPerConn = numConns > 0 ? Math.floor(numBytes / numConns) : 0;
                    const out = new Map(tup);
                    out.set("bytes_per_conn", OpResult.Int(bytesPerConn));
                    return out;
                }),
                chain(filter((tup: Tuple) => getMappedInt("bytes_per_conn", tup) <= t3), // Filter by T3 (bytes per conn LE threshold)
                    nextOp // Final downstream operator
                )
            )
         );

         // --- Connect pipelines ---
         return [
             nConns(op1), // nConns pipeline feeds Join Input 1
             nBytes(op2)  // nBytes pipeline feeds Join Input 2
         ];
     };
}


// Join Test
function joinTest(epochDur: number = 1.0): (nextOp: Operator) => Operator[] {
    return (nextOp: Operator): Operator[] => {
        // --- Define sub-pipelines ---
        const syns = (op: Operator): Operator =>
            chain(epoch(epochDur, "eid"),
                chain(filter((tup: Tuple) =>
                    getMappedInt("ipv4.proto", tup) === 6 && getMappedInt("l4.flags", tup) === 2 // SYN
                ),
                    op // Pass filtered SYNs directly
                )
            );

        const synacks = (op: Operator): Operator =>
            chain(epoch(epochDur, "eid"),
                chain(filter((tup: Tuple) =>
                    getMappedInt("ipv4.proto", tup) === 6 && getMappedInt("l4.flags", tup) === 18 // SYN+ACK
                ),
                    op // Pass filtered SYN+ACKs directly
                )
            );

        // --- Define Join ---
        const [op1, op2] = chainDouble(
            join(
                 // Left Input (from SYNs): Key = {host<-ipv4.src}, Value = {remote<-ipv4.dst}
                (tup: Tuple) => ({
                    key: renameFilteredKeys([["ipv4.src", "host"]])(tup),
                    value: renameFilteredKeys([["ipv4.dst", "remote"]])(tup)
                }),
                // Right Input (from SYNACKs): Key = {host<-ipv4.dst}, Value = {time}
                (tup: Tuple) => ({
                     key: renameFilteredKeys([["ipv4.dst", "host"]])(tup),
                     value: filterGroups(["time"])(tup) // Keep only time from synack
                })
            ),
            // Operator after Join (pass directly)
            nextOp
        );

        // --- Connect pipelines ---
        return [
            syns(op1),    // SYNs pipeline feeds Join Input 1
            synacks(op2) // SYNACKs pipeline feeds Join Input 2
        ];
    };
}

// Q3: Distinct src/dst pairs per epoch
function q3(epochDur: number = 100.0): OpCreator {
     return (nextOp: Operator): Operator =>
        chain(epoch(epochDur, "eid"),
            chain(distinct(filterGroups(["ipv4.src", "ipv4.dst"])),
                nextOp // Pass distinct pairs downstream
            )
        );
}

// Q4: Count packets per destination per epoch
function q4(epochDur: number = 10000.0): OpCreator {
    return (nextOp: Operator): Operator =>
        chain(epoch(epochDur, "eid"),
            chain(groupby(filterGroups(["ipv4.dst"]), counter, "pkts"),
                nextOp // Pass grouped counts downstream
            )
        );
}

// --- Main Execution Logic ---

function createSampleTuple(i: number): Tuple {
     // Helper to create MAC Uint8Array
    const mac = (hexString: string): Uint8Array => Uint8Array.from(Buffer.from(hexString.replace(/\\x/g, ''), 'hex'));
     // Helper to create IPv4 OpResult
    const ipv4 = (ipString: string): OpResult => OpResult.IPv4(ipaddr.parse(ipString) as ipaddr.IPv4);

    return tupleOfList([
        ["time", OpResult.Float(0.000000 + i)], // Simulate time progression

        ["eth.src", OpResult.MAC(mac("001122334455"))],
        ["eth.dst", OpResult.MAC(mac("AABBCCDDEEFF"))],
        ["eth.ethertype", OpResult.Int(0x0800)], // IPv4

        ["ipv4.hlen", OpResult.Int(20)],
        ["ipv4.proto", OpResult.Int(6)], // TCP
        ["ipv4.len", OpResult.Int(60)],
        ["ipv4.src", ipv4("127.0.0.1")],
        ["ipv4.dst", ipv4("192.168.1.10")], // Changed dst for variety

        ["l4.sport", OpResult.Int(44000 + i)], // Vary sport
        ["l4.dport", OpResult.Int( (i%4 === 0) ? 22 : 80)], // Vary dport (e.g. SSH/HTTP)
        ["l4.flags", OpResult.Int( (i%5 === 0) ? 2 : (i%5 === 1 ? 18 : 16) )], // Cycle SYN, SYNACK, ACK etc.
    ]);
}

function runQueries() {
    console.log("--- Running Queries ---");

    // --- Define the pipeline(s) ---
    // Example: Count packets per src/dst pair and dump to console
     const pipeline1: Operator = pktsPerSrcDst()(dumpTupleOp(true));

     // Example: Sonata 3 (Super Spreader) and dump results
     const pipeline2: Operator = superSpreader(2)(dumpTupleOp(true)); // Low threshold for sample data


     // Example: Sonata 6 (SYN Flood) - needs multiple operators
     const finalSynFloodOp = dumpTupleOp(true); // Where the final results go
     const synFloodOperators: Operator[] = synFloodSonata(1, 10.0)(finalSynFloodOp); // Low thresh, 10s epoch

     // --- Simulate Data Stream ---
     const sampleData: Tuple[] = Array.from({ length: 25 }, (_, i) => createSampleTuple(i));

     // Process data through pipeline 1
     console.log("\n--- Pipeline 1: Pkts Per Src/Dst ---");
     sampleData.forEach(tup => pipeline1.next(tup));
     // Manually trigger final reset for the last epoch
     // Need to know the last epoch ID - tricky without running epoch() logic here again
     // Let's assume the last epoch was handled by the last tuple or needs explicit reset
     const lastEpochIdPipe1 = Math.floor(floatOfOpResult(sampleData[sampleData.length - 1].get("time") ?? OpResult.Float(0)) / 1.0);
     pipeline1.reset(tupleOfList([["eid", OpResult.Int(lastEpochIdPipe1)]]));


     console.log("\n--- Pipeline 2: Super Spreader ---");
     sampleData.forEach(tup => pipeline2.next(tup));
     const lastEpochIdPipe2 = Math.floor(floatOfOpResult(sampleData[sampleData.length - 1].get("time") ?? OpResult.Float(0)) / 1.0);
     pipeline2.reset(tupleOfList([["eid", OpResult.Int(lastEpochIdPipe2)]]));


     console.log("\n--- Pipeline 3: SYN Flood (Sonata 6) ---");
     sampleData.forEach(tup => {
         // Feed the tuple to *all* starting operators of the join
         synFloodOperators.forEach(op => op.next(tup));
     });
     // Reset all starting operators
     const lastEpochIdPipe3 = Math.floor(floatOfOpResult(sampleData[sampleData.length - 1].get("time") ?? OpResult.Float(0)) / 10.0);
     const resetTuplePipe3 = tupleOfList([["eid", OpResult.Int(lastEpochIdPipe3)]]);
     synFloodOperators.forEach(op => op.reset(resetTuplePipe3));


     console.log("\n--- Done Simulating ---");
}

// --- Main Entry Point ---
runQueries();

