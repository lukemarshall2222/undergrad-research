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