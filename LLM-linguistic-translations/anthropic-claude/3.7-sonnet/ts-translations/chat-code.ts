/**
 * Common utilities
 *
 * Includes minimal parsing of header fields into a map from strings to values
 */

// In TypeScript, we'll use discriminated union types instead of OCaml's variant types
type OpResult = 
  | { type: 'Float', value: number }
  | { type: 'Int', value: number }
  | { type: 'IPv4', value: string }
  | { type: 'MAC', value: Uint8Array }
  | { type: 'Empty' };

// Instead of OCaml's Map module, we'll use TypeScript's Map interface
type Tuple = Map<string, OpResult>;

// Define the operator interface instead of OCaml's record type
interface Operator {
  next(tup: Tuple): void;
  reset(tup: Tuple): void;
}

type OpCreator = (nextOp: Operator) => Operator;
type DblOpCreator = (op: Operator) => [Operator, Operator];

// Chain operators together (simplified with arrow functions)
function chainOp(opCreatorFunc: OpCreator, nextOp: Operator): Operator {
  return opCreatorFunc(nextOp);
}

function chainDblOp(opCreatorFunc: DblOpCreator, op: Operator): [Operator, Operator] {
  return opCreatorFunc(op);
}

/**
 * Conversion utilities
 */

// Format MAC address as colon-separated hex string
function stringOfMac(buf: Uint8Array): string {
  return Array.from(buf.slice(0, 6))
    .map(byte => byte.toString(16).padStart(2, '0'))
    .join(':');
}

// Convert TCP flags to human-readable string
function tcpFlagsToStrings(flags: number): string {
  const tcpFlagsMap = new Map<string, number>([
    ["FIN", 1 << 0],
    ["SYN", 1 << 1],
    ["RST", 1 << 2],
    ["PSH", 1 << 3],
    ["ACK", 1 << 4],
    ["URG", 1 << 5],
    ["ECE", 1 << 6],
    ["CWR", 1 << 7],
  ]);

  return Array.from(tcpFlagsMap.entries())
    .filter(([_, value]) => (flags & value) === value)
    .map(([key, _]) => key)
    .join('|');
}

// Extract integer value from OpResult
function intOfOpResult(input: OpResult): number {
  if (input.type === 'Int') {
    return input.value;
  }
  throw new Error("Trying to extract int from non-int result");
}

// Extract float value from OpResult
function floatOfOpResult(input: OpResult): number {
  if (input.type === 'Float') {
    return input.value;
  }
  throw new Error("Trying to extract float from non-float result");
}

// Convert OpResult to string representation
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

// Format tuple as a human-readable string
function stringOfTuple(inputTuple: Tuple): string {
  let result = "";
  inputTuple.forEach((val, key) => {
    result += `"${key}" => ${stringOfOpResult(val)}, `;
  });
  return result;
}

// Create a Tuple from an array of key-value pairs
function tupleOfArray(tupArray: [string, OpResult][]): Tuple {
  return new Map(tupArray);
}

// Print tuple in a formatted way
function dumpTuple(outStream: NodeJS.WriteStream, tup: Tuple): void {
  outStream.write(stringOfTuple(tup) + "\n");
}

// Lookup integer value in tuple
function lookupInt(key: string, tup: Tuple): number {
  const result = tup.get(key);
  if (!result) {
    throw new Error(`Key ${key} not found in tuple`);
  }
  return intOfOpResult(result);
}

// Lookup float value in tuple
function lookupFloat(key: string, tup: Tuple): number {
  const result = tup.get(key);
  if (!result) {
    throw new Error(`Key ${key} not found in tuple`);
  }
  return floatOfOpResult(result);
}

/**
 * Built-in operator definitions and common utilities
 */

const INIT_TABLE_SIZE = 10000;

// Dump operator
function dumpTupleOperator(outStream: NodeJS.WriteStream, showReset = false): Operator {
  return {
    next: (tup: Tuple) => dumpTuple(outStream, tup),
    reset: (tup: Tuple) => {
      if (showReset) {
        dumpTuple(outStream, tup);
        outStream.write("[reset]\n");
      }
    }
  };
}

// CSV dumper operator
function dumpAsCsv(outStream: NodeJS.WriteStream, staticField?: [string, string], header = true): Operator {
  let first = header;
  
  return {
    next: (tup: Tuple) => {
      if (first) {
        if (staticField) {
          outStream.write(`${staticField[0]},`);
        }
        
        for (const key of tup.keys()) {
          outStream.write(`${key},`);
        }
        outStream.write("\n");
        first = false;
      }
      
      if (staticField) {
        outStream.write(`${staticField[1]},`);
      }
      
      for (const value of tup.values()) {
        outStream.write(`${stringOfOpResult(value)},`);
      }
      outStream.write("\n");
    },
    reset: (_) => { /* No-op */ }
  };
}

// Walt's canonical CSV format dumper
function dumpWaltsCsv(filename: string): Operator {
  let outStream: NodeJS.WriteStream | null = null;
  let first = true;
  
  return {
    next: (tup: Tuple) => {
      if (first) {
        outStream = require('fs').createWriteStream(filename);
        first = false;
      }
      
      const line = [
        stringOfOpResult(tup.get("src_ip")!),
        stringOfOpResult(tup.get("dst_ip")!),
        stringOfOpResult(tup.get("src_l4_port")!),
        stringOfOpResult(tup.get("dst_l4_port")!),
        stringOfOpResult(tup.get("packet_count")!),
        stringOfOpResult(tup.get("byte_count")!),
        stringOfOpResult(tup.get("epoch_id")!)
      ].join(',');
      
      outStream?.write(line + "\n");
    },
    reset: (_) => { /* No-op */ }
  };
}

// Get IP or zero
function getIpOrZero(input: string): OpResult {
  if (input === "0") {
    return { type: 'Int', value: 0 };
  } else {
    return { type: 'IPv4', value: input };
  }
}

// Read Walt's canonical CSV format
function readWaltsCsv(fileNames: string[], ops: Operator[], epochIdKey = "eid"): void {
  const fs = require('fs');
  const readline = require('readline');
  
  // Create file readers
  const fileReaders = fileNames.map(filename => {
    const fileStream = fs.createReadStream(filename);
    const rl = readline.createInterface({
      input: fileStream,
      crlfDelay: Infinity
    });
    
    return {
      reader: rl,
      epochId: 0,
      tupCount: 0
    };
  });
  
  let running = ops.length;
  
  // Process each file
  const processFiles = async () => {
    while (running > 0) {
      for (let i = 0; i < fileReaders.length; i++) {
        const { reader, epochId, tupCount } = fileReaders[i];
        const op = ops[i];
        
        if (epochId >= 0) {
          try {
            for await (const line of reader) {
              const [srcIp, dstIp, srcL4Port, dstL4Port, packetCount, byteCount, epochId] = 
                line.split(',').map((val, idx) => idx >= 2 ? parseInt(val) : val);
              
              const p: Tuple = new Map();
              p.set("ipv4.src", getIpOrZero(srcIp));
              p.set("ipv4.dst", getIpOrZero(dstIp));
              p.set("l4.sport", { type: 'Int', value: srcL4Port });
              p.set("l4.dport", { type: 'Int', value: dstL4Port });
              p.set("packet_count", { type: 'Int', value: packetCount });
              p.set("byte_count", { type: 'Int', value: byteCount });
              p.set(epochIdKey, { type: 'Int', value: epochId });
              
              fileReaders[i].tupCount++;
              
              if (epochId > fileReaders[i].epochId) {
                while (epochId > fileReaders[i].epochId) {
                  const resetTup = new Map();
                  resetTup.set(epochIdKey, { type: 'Int', value: fileReaders[i].epochId });
                  resetTup.set("tuples", { type: 'Int', value: fileReaders[i].tupCount });
                  
                  op.reset(resetTup);
                  fileReaders[i].tupCount = 0;
                  fileReaders[i].epochId++;
                }
              }
              
              const finalTup = new Map(p);
              finalTup.set("tuples", { type: 'Int', value: fileReaders[i].tupCount });
              op.next(finalTup);
            }
            
            // End of file
            const resetTup = new Map();
            resetTup.set(epochIdKey, { type: 'Int', value: fileReaders[i].epochId + 1 });
            resetTup.set("tuples", { type: 'Int', value: fileReaders[i].tupCount });
            
            op.reset(resetTup);
            running--;
            fileReaders[i].epochId = -1;
            
          } catch (error) {
            console.error("Failed to scan:", error);
            throw new Error("Scan failure");
          }
        }
      }
    }
    
    console.log("Done.");
  };
  
  processFiles();
}

// Meta meter operator
function metaMeter(name: string, outStream: NodeJS.WriteStream, nextOp: Operator, staticField?: string): Operator {
  let epochCount = 0;
  let tupsCount = 0;
  
  return {
    next: (tup: Tuple) => {
      tupsCount++;
      nextOp.next(tup);
    },
    reset: (tup: Tuple) => {
      outStream.write(`${epochCount},${name},${tupsCount},${staticField || ""}\n`);
      tupsCount = 0;
      epochCount++;
      nextOp.reset(tup);
    }
  };
}

// Epoch operator
function epoch(epochWidth: number, keyOut: string, nextOp: Operator): Operator {
  let epochBoundary = 0;
  let eid = 0;
  
  return {
    next: (tup: Tuple) => {
      const time = floatOfOpResult(tup.get("time")!);
      
      if (epochBoundary === 0) {
        epochBoundary = time + epochWidth;
      } else if (time >= epochBoundary) {
        while (time >= epochBoundary) {
          const resetTup = new Map();
          resetTup.set(keyOut, { type: 'Int', value: eid });
          nextOp.reset(resetTup);
          epochBoundary += epochWidth;
          eid++;
        }
      }
      
      const newTup = new Map(tup);
      newTup.set(keyOut, { type: 'Int', value: eid });
      nextOp.next(newTup);
    },
    reset: (_) => {
      const resetTup = new Map();
      resetTup.set(keyOut, { type: 'Int', value: eid });
      nextOp.reset(resetTup);
      epochBoundary = 0;
      eid = 0;
    }
  };
}

// Filter operator
function filter(f: (tup: Tuple) => boolean, nextOp: Operator): Operator {
  return {
    next: (tup: Tuple) => {
      if (f(tup)) {
        nextOp.next(tup);
      }
    },
    reset: (tup: Tuple) => nextOp.reset(tup)
  };
}

// Key greater than or equal to int predicate
function keyGeqInt(key: string, threshold: number): (tup: Tuple) => boolean {
  return (tup: Tuple) => intOfOpResult(tup.get(key)!) >= threshold;
}

// Get mapped int
function getMappedInt(key: string, tup: Tuple): number {
  return intOfOpResult(tup.get(key)!);
}

// Get mapped float
function getMappedFloat(key: string, tup: Tuple): number {
  return floatOfOpResult(tup.get(key)!);
}

// Map operator
function map(f: (tup: Tuple) => Tuple, nextOp: Operator): Operator {
  return {
    next: (tup: Tuple) => nextOp.next(f(tup)),
    reset: (tup: Tuple) => nextOp.reset(tup)
  };
}

type GroupingFunc = (tup: Tuple) => Tuple;
type ReductionFunc = (val: OpResult, tup: Tuple) => OpResult;

// Group by operator
function groupby(groupby: GroupingFunc, reduce: ReductionFunc, outKey: string, nextOp: Operator): Operator {
  const hTbl = new Map<string, [Tuple, OpResult]>();
  let resetCounter = 0;
  
  return {
    next: (tup: Tuple) => {
      const groupingKey = groupby(tup);
      const keyStr = stringOfTuple(groupingKey);
      
      if (hTbl.has(keyStr)) {
        const [existingKey, existingVal] = hTbl.get(keyStr)!;
        hTbl.set(keyStr, [existingKey, reduce(existingVal, tup)]);
      } else {
        hTbl.set(keyStr, [groupingKey, reduce({ type: 'Empty' }, tup)]);
      }
    },
    reset: (tup: Tuple) => {
      resetCounter++;
      
      for (const [_, [groupingKey, val]] of hTbl.entries()) {
        // Merge tuples
        const unionedTup = new Map([...tup, ...groupingKey]);
        unionedTup.set(outKey, val);
        nextOp.next(unionedTup);
      }
      
      nextOp.reset(tup);
      hTbl.clear();
    }
  };
}

// Filter groups utility for groupby
function filterGroups(inclKeys: string[], tup: Tuple): Tuple {
  const result = new Map<string, OpResult>();
  
  for (const key of inclKeys) {
    const val = tup.get(key);
    if (val !== undefined) {
      result.set(key, val);
    }
  }
  
  return result;
}

// Single group utility for groupby
function singleGroup(_: Tuple): Tuple {
  return new Map<string, OpResult>();
}

// Counter reduction function for groupby
function counter(val: OpResult, _: Tuple): OpResult {
  if (val.type === 'Empty') {
    return { type: 'Int', value: 1 };
  } else if (val.type === 'Int') {
    return { type: 'Int', value: val.value + 1 };
  } else {
    return val;
  }
}

// Sum integers reduction function for groupby
function sumInts(searchKey: string, initVal: OpResult, tup: Tuple): OpResult {
  if (initVal.type === 'Empty') {
    return { type: 'Int', value: 0 };
  } else if (initVal.type === 'Int') {
    const searchVal = tup.get(searchKey);
    
    if (searchVal && searchVal.type === 'Int') {
      return { type: 'Int', value: searchVal.value + initVal.value };
    } else {
      throw new Error(`'sum_vals' function failed to find integer value mapped to "${searchKey}"`);
    }
  } else {
    return initVal;
  }
}

// Distinct operator
function distinct(groupby: GroupingFunc, nextOp: Operator): Operator {
  const hTbl = new Map<string, Tuple>();
  let resetCounter = 0;
  
  return {
    next: (tup: Tuple) => {
      const groupingKey = groupby(tup);
      const keyStr = stringOfTuple(groupingKey);
      hTbl.set(keyStr, groupingKey);
    },
    reset: (tup: Tuple) => {
      resetCounter++;
      
      for (const groupingKey of hTbl.values()) {
        // Merge tuples
        const mergedTup = new Map([...tup, ...groupingKey]);
        nextOp.next(mergedTup);
      }
      
      nextOp.reset(tup);
      hTbl.clear();
    }
  };
}

// Split operator
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

// Join operator
function join(leftExtractor: KeyExtractor, rightExtractor: KeyExtractor, nextOp: Operator, eidKey = "eid"): [Operator, Operator] {
  const hTbl1 = new Map<string, [Tuple, Tuple]>();
  const hTbl2 = new Map<string, [Tuple, Tuple]>();
  let leftCurrEpoch = 0;
  let rightCurrEpoch = 0;
  
  const handleJoinSide = (
    currHTbl: Map<string, [Tuple, Tuple]>,
    otherHTbl: Map<string, [Tuple, Tuple]>,
    currEpochRef: { value: number },
    otherEpochRef: { value: number },
    f: KeyExtractor
  ): Operator => {
    return {
      next: (tup: Tuple) => {
        const [key, vals] = f(tup);
        const currEpoch = getMappedInt(eidKey, tup);
        
        while (currEpoch > currEpochRef.value) {
          if (otherEpochRef.value > currEpochRef.value) {
            const resetTup = new Map();
            resetTup.set(eidKey, { type: 'Int', value: currEpochRef.value });
            nextOp.reset(resetTup);
          }
          currEpochRef.value++;
        }
        
        const newTup = new Map(key);
        newTup.set(eidKey, { type: 'Int', value: currEpoch });
        const keyStr = stringOfTuple(newTup);
        
        const match = otherHTbl.get(keyStr);
        if (match) {
          const [_, matchVals] = match;
          otherHTbl.delete(keyStr);
          
          // Merge tuples
          const mergedTup = new Map([...newTup, ...vals, ...matchVals]);
          nextOp.next(mergedTup);
        } else {
          currHTbl.set(keyStr, [newTup, vals]);
        }
      },
      reset: (tup: Tuple) => {
        const currEpoch = getMappedInt(eidKey, tup);
        
        while (currEpoch > currEpochRef.value) {
          if (otherEpochRef.value > currEpochRef.value) {
            const resetTup = new Map();
            resetTup.set(eidKey, { type: 'Int', value: currEpochRef.value });
            nextOp.reset(resetTup);
          }
          currEpochRef.value++;
        }
      }
    };
  };
  
  const leftEpochRef = { value: leftCurrEpoch };
  const rightEpochRef = { value: rightCurrEpoch };
  
  return [
    handleJoinSide(hTbl1, hTbl2, leftEpochRef, rightEpochRef, leftExtractor),
    handleJoinSide(hTbl2, hTbl1, rightEpochRef, leftEpochRef, rightExtractor)
  ];
}

// Rename filtered keys utility for join
function renameFilteredKeys(renamingsPairs: [string, string][], inTup: Tuple): Tuple {
  const newTup = new Map<string, OpResult>();
  
  for (const [oldKey, newKey] of renamingsPairs) {
    const val = inTup.get(oldKey);
    if (val !== undefined) {
      newTup.set(newKey, val);
    }
  }
  
  return newTup;
}

/**
 * Main operators and processing functions
 */

// Identity operator
function ident(nextOp: Operator): Operator {
  return map(tup => {
    const filtered = new Map(tup);
    if (filtered.has("eth.src")) filtered.delete("eth.src");
    if (filtered.has("eth.dst")) filtered.delete("eth.dst");
    return filtered;
  }, nextOp);
}

// Count packets operator
function countPkts(nextOp: Operator): Operator {
  return chainOp(
    op => epoch(1.0, "eid", op),
    chainOp(
      op => groupby(singleGroup, counter, "pkts", op),
      nextOp
    )
  );
}

// Packets per source/destination operator
function pktsPerSrcDst(nextOp: Operator): Operator {
  return chainOp(
    op => epoch(1.0, "eid", op),
    chainOp(
      op => groupby(
        tup => filterGroups(["ipv4.src", "ipv4.dst"], tup),
        counter,
        "pkts",
        op
      ),
      nextOp
    )
  );
}

// Distinct sources operator
function distinctSrcs(nextOp: Operator): Operator {
  return chainOp(
    op => epoch(1.0, "eid", op),
    chainOp(
      op => distinct(tup => filterGroups(["ipv4.src"], tup), op),
      chainOp(
        op => groupby(singleGroup, counter, "srcs", op),
        nextOp
      )
    )
  );
}

// TCP new connections operator (Sonata 1)
function tcpNewCons(nextOp: Operator): Operator {
  const threshold = 40;
  
  return chainOp(
    op => epoch(1.0, "eid", op),
    chainOp(
      op => filter(tup => 
        getMappedInt("ipv4.proto", tup) === 6 &&
        getMappedInt("l4.flags", tup) === 2,
        op
      ),
      chainOp(
        op => groupby(
          tup => filterGroups(["ipv4.dst"], tup),
          counter,
          "cons",
          op
        ),
        chainOp(
          op => filter(keyGeqInt("cons", threshold), op),
          nextOp
        )
      )
    )
  );
}

// SSH brute force operator (Sonata 2)
function sshBruteForce(nextOp: Operator): Operator {
  const threshold = 40;
  
  return chainOp(
    op => epoch(1.0, "eid", op),
    chainOp(
      op => filter(tup =>
        getMappedInt("ipv4.proto", tup) === 6 &&
        getMappedInt("l4.dport", tup) === 22,
        op
      ),
      chainOp(
        op => distinct(
          tup => filterGroups(["ipv4.src", "ipv4.dst", "ipv4.len"], tup),
          op
        ),
        chainOp(
          op => groupby(
            tup => filterGroups(["ipv4.dst", "ipv4.len"], tup),
            counter,
            "srcs",
            op
          ),
          chainOp(
            op => filter(keyGeqInt("srcs", threshold), op),
            nextOp
          )
        )
      )
    )
  );
}

// Super spreader operator (Sonata 3)
function superSpreader(nextOp: Operator): Operator {
  const threshold = 40;
  
  return chainOp(
    op => epoch(1.0, "eid", op),
    chainOp(
      op => distinct(
        tup => filterGroups(["ipv4.src", "ipv4.dst"], tup),
        op
      ),
      chainOp(
        op => groupby(
          tup => filterGroups(["ipv4.src"], tup),
          counter,
          "dsts",
          op
        ),
        chainOp(
          op => filter(keyGeqInt("dsts", threshold), op),
          nextOp
        )
      )
    )
  );
}

// Port scan operator (Sonata 4)
function portScan(nextOp: Operator): Operator {
  const threshold = 40;
  
  return chainOp(
    op => epoch(1.0, "eid", op),
    chainOp(
      op => distinct(
        tup => filterGroups(["ipv4.src", "l4.dport"], tup),
        op
      ),
      chainOp(
        op => groupby(
          tup => filterGroups(["ipv4.src"], tup),
          counter,
          "ports",
          op
        ),
        chainOp(
          op => filter(keyGeqInt("ports", threshold), op),
          nextOp
        )
      )
    )
  );
}

// DDoS operator (Sonata 5)
function ddos(nextOp: Operator): Operator {
  const threshold = 45;
  
  return chainOp(
    op => epoch(1.0, "eid", op),
    chainOp(
      op => distinct(
        tup => filterGroups(["ipv4.src", "ipv4.dst"], tup),
        op
      ),
      chainOp(
        op => groupby(
          tup => filterGroups(["ipv4.dst"], tup),
          counter,
          "srcs",
          op
        ),
        chainOp(
          op => filter(keyGeqInt("srcs", threshold), op),
          nextOp
        )
      )
    )
  );
}

// SYN flood detection (Sonata 6) - implements Sonata semantic
function synFloodSonata(nextOp: Operator): Operator[] {
  const threshold = 3;
  const epochDur = 1.0;
  
  // Track SYN packets
  function syns(nextOp: Operator): Operator {
    return chainOp(
      op => epoch(epochDur, "eid", op),
      chainOp(
        op => filter(tup =>
          getMappedInt("ipv4.proto", tup) === 6 &&
          getMappedInt("l4.flags", tup) === 2,
          op
        ),
        chainOp(
          op => groupby(
            tup => filterGroups(["ipv4.dst"], tup),
            counter,
            "syns",
            op
          ),
          nextOp
        )
      )
    );
  }
  
  // Track SYN-ACK packets
  function synacks(nextOp: Operator): Operator {
    return chainOp(
      op => epoch(epochDur, "eid", op),
      chainOp(
        op => filter(tup =>
          getMappedInt("ipv4.proto", tup) === 6 &&
          getMappedInt("l4.flags", tup) === 18,
          op
        ),
        chainOp(
          op => groupby(
            tup => filterGroups(["ipv4.src"], tup),
            counter,
            "synacks",
            op
          ),
          nextOp
        )
      )
    );
  }
  
  // Track ACK packets
  function acks(nextOp: Operator): Operator {
    return chainOp(
      op => epoch(epochDur, "eid", op),
      chainOp(
        op => filter(tup =>
          getMappedInt("ipv4.proto", tup) === 6 &&
          getMappedInt("l4.flags", tup) === 16,
          op
        ),
        chainOp(
          op => groupby(
            tup => filterGroups(["ipv4.dst"], tup),
            counter,
            "acks",
            op
          ),
          nextOp
        )
      )
    );
  }
  
  // Join SYN+SYNACK count with ACK count
  const [joinOp1, joinOp2] = chainDblOp(
    op => join(
      tup => [
        filterGroups(["host"], tup),
        filterGroups(["syns+synacks"], tup)
      ],
      tup => [
        renameFilteredKeys([["ipv4.dst", "host"]], tup),
        filterGroups(["acks"], tup)
      ],
      chainOp(
        op => map(tup => {
          const synsPlusSynacks = getMappedInt("syns+synacks", tup);
          const acks = getMappedInt("acks", tup);
          const newTup = new Map(tup);
          newTup.set("syns+synacks-acks", { type: 'Int', value: synsPlusSynacks - acks });
          return newTup;
        }, 
        chainOp(
          op => filter(keyGeqInt("syns+synacks-acks", threshold), op),
          nextOp
        ))
      )
    ),
    op => op
  );
  
  // Join SYN count with SYNACK count
  const [joinOp3, joinOp4] = chainDblOp(
    op => join(
      tup => [
        renameFilteredKeys([["ipv4.dst", "host"]], tup),
        filterGroups(["syns"], tup)
      ],
      tup => [
        renameFilteredKeys([["ipv4.src", "host"]], tup),
        filterGroups(["synacks"], tup)
      ],
      chainOp(
        op => map(tup => {
          const syns = getMappedInt("syns", tup);
          const synacks = getMappedInt("synacks", tup);
          const newTup = new Map(tup);
          newTup.set("syns+synacks", { type: 'Int', value: syns + synacks });
          return newTup;
        },
        joinOp1)
      )
    ),
    op => op
  );
  
  return [
    chainOp(op => syns(joinOp3), op => op),
    chainOp(op => synacks(joinOp4), op => op),
    chainOp(op => acks(joinOp2), op => op)
  ];
}

// Completed flows detection (Sonata 7)
function completedFlows(nextOp: Operator): Operator[] {
  const threshold = 1;
  const epochDur = 30.0;
  
  // Track SYN packets
  function syns(nextOp: Operator): Operator {
    return chainOp(
      op => epoch(epochDur, "eid", op),
      chainOp(
        op => filter(tup =>
          getMappedInt("ipv4.proto", tup) === 6 &&
          getMappedInt("l4.flags", tup) === 2,
          op
        ),
        chainOp(
          op => groupby(
            tup => filterGroups(["ipv4.dst"], tup),
            counter,
            "syns",
            op
          ),
          nextOp
        )
      )
    );
  }
  
  // Track FIN packets
  function fins(nextOp: Operator): Operator {
    return chainOp(
      op => epoch(epochDur, "eid", op),
      chainOp(
        op => filter(tup =>
          getMappedInt("ipv4.proto", tup) === 6 &&
          (getMappedInt("l4.flags", tup) & 1) === 1,
          op
        ),
        chainOp(
          op => groupby(
            tup => filterGroups(["ipv4.src"], tup),
            counter,
            "fins",
            op
          ),
          nextOp
        )
      )
    );
  }
  
  // Join SYN count with FIN count
  const [op1, op2] = chainDblOp(
    op => join(
      tup => [
        renameFilteredKeys([["ipv4.dst", "host"]], tup),
        filterGroups(["syns"], tup)
      ],
      tup => [
        renameFilteredKeys([["ipv4.src", "host"]], tup),
        filterGroups(["fins"], tup)
      ],
      chainOp(
        op => map(tup => {
          const syns = getMappedInt("syns", tup);
          const fins = getMappedInt("fins", tup);
          const newTup = new Map(tup);
          newTup.set("diff", { type: 'Int', value: syns - fins });
          return newTup;
        },
        chainOp(
          op => filter(keyGeqInt("diff", threshold), op),
          nextOp
        ))
      )
    ),
    op => op
  );
  
  return [
    chainOp(op => syns(op1), op => op),
    chainOp(op => fins(op2), op => op)
  ];
}

// Slowloris attack detection (Sonata 8)
function slowloris(nextOp: Operator): Operator[] {
  const t1 = 5;   // Minimum connections threshold
  const t2 = 500; // Minimum bytes threshold
  const t3 = 90;  // Maximum bytes per connection threshold
  const epochDur = 1.0;
  
  // Track number of connections
  function nConns(nextOp: Operator): Operator {
    return chainOp(
      op => epoch(epochDur, "eid", op),
      chainOp(
        op => filter(tup => getMappedInt("ipv4.proto", tup) === 6, op),
        chainOp(
          op => distinct(
            tup => filterGroups(["ipv4.src", "ipv4.dst", "l4.sport"], tup),
            op
          ),
          chainOp(
            op => groupby(
              tup => filterGroups(["ipv4.dst"], tup),
              counter,
              "n_conns",
              op
            ),
            chainOp(
              op => filter(tup => getMappedInt("n_conns", tup) >= t1, op),
              nextOp
            )
          )
        )
      )
    );
  }
  
  // Track number of bytes
  function nBytes(nextOp: Operator): Operator {
    return chainOp(
      op => epoch(epochDur, "eid", op),
      chainOp(
        op => filter(tup => getMappedInt("ipv4.proto", tup) === 6, op),
        chainOp(
          op => groupby(
            tup => filterGroups(["ipv4.dst"], tup),
            sumInts("ipv4.len"),
            "n_bytes",
            op
          ),
          chainOp(
            op => filter(tup => getMappedInt("n_bytes", tup) >= t2, op),
            nextOp
          )
        )
      )
    );
  }
  
  // Join connection count with byte count
  const [op1, op2] = chainDblOp(
    op => join(
      tup => [
        filterGroups(["ipv4.dst"], tup),
        filterGroups(["n_conns"], tup)
      ],
      tup => [
        filterGroups(["ipv4.dst"], tup),
        filterGroups(["n_bytes"], tup)
      ],
      chainOp(
        op => map(tup => {
          const nBytes = getMappedInt("n_bytes", tup);
          const nConns = getMappedInt("n_conns", tup);
          const newTup = new Map(tup);
          newTup.set("bytes_per_conn", { type: 'Int', value: Math.floor(nBytes / nConns) });
          return newTup;
        },
        chainOp(
          op => filter(tup => getMappedInt("bytes_per_conn", tup) <= t3, op),
          nextOp
        ))
      )
    ),
    op => op
  );
  
  return [
    chainOp(op => nConns(op1), op => op),
    chainOp(op => nBytes(op2), op => op)
  ];
}

// Join test operator
function joinTest(nextOp: Operator): Operator[] {
  const epochDur = 1.0;
  
  // Track SYN packets
  function syns(nextOp: Operator): Operator {
    return chainOp(
      op => epoch(epochDur, "eid", op),
      chainOp(
        op => filter(tup =>
          getMappedInt("ipv4.proto", tup) === 6 &&
          getMappedInt("l4.flags", tup) === 2,
          op
        ),
        nextOp
      )
    );
  }
  
  // Track SYN-ACK packets
  function synacks(nextOp: Operator): Operator {
    return chainOp(
      op => epoch(epochDur, "eid", op),
      chainOp(
        op => filter(tup =>
          getMappedInt("ipv4.proto", tup) === 6 &&
          getMappedInt("l4.flags", tup) === 18,
          op
        ),
        nextOp
      )
    );
  }
  
  // Join SYN with SYN-ACK
  const [op1, op2] = chainDblOp(
    op => join(
      tup => [
        renameFilteredKeys([["ipv4.src", "host"]], tup),
        renameFilteredKeys([["ipv4.dst", "remote"]], tup)
      ],
      tup => [
        renameFilteredKeys([["ipv4.dst", "host"]], tup),
        filterGroups(["time"], tup)
      ],
      nextOp
    ),
    op => op
  );
  
  return [
    chainOp(op => syns(op1), op => op),
    chainOp(op => synacks(op2), op => op)
  ];
}

// Q3 query operator
function q3(nextOp: Operator): Operator {
  return chainOp(
    op => epoch(100.0, "eid", op),
    chainOp(
      op => distinct(
        tup => filterGroups(["ipv4.src", "ipv4.dst"], tup),
        op
      ),
      nextOp
    )
  );
}

// Q4 query operator
function q4(nextOp: Operator): Operator {
  return chainOp(
    op => epoch(10000.0, "eid", op),
    chainOp(
      op => groupby(
        tup => filterGroups(["ipv4.dst"], tup),
        counter,
        "pkts",
        op
      ),
      nextOp
    )
  );
}

// Enhanced main function with all the queries
function runAllQueries(): void {
  const process = require('process');
  
  // Define standard dump operator
  const standardOutput = dumpTupleOperator(process.stdout);
  
  // Define all available queries
  const availableQueries: { [key: string]: (op: Operator) => Operator } = {
    "ident": ident,
    "count_pkts": countPkts,
    "pkts_per_src_dst": pktsPerSrcDst,
    "distinct_srcs": distinctSrcs,
    "tcp_new_cons": tcpNewCons,
    "ssh_brute_force": sshBruteForce,
    "super_spreader": superSpreader,
    "port_scan": portScan,
    "ddos": ddos,
    "q3": q3,
    "q4": q4
  };
  
  // Multi-operator queries
  const multiOperatorQueries: { [key: string]: (op: Operator) => Operator[] } = {
    "syn_flood_sonata": synFloodSonata,
    "completed_flows": completedFlows,
    "slowloris": slowloris,
    "join_test": joinTest
  };
  
  // Choose which query to run
  const activeQueries = [
    availableQueries["ident"](standardOutput)
  ];
  
  // Generate test tuples
  const testTuples: Tuple[] = [];
  for (let i = 0; i < 20; i++) {
    const tup = new Map<string, OpResult>();
    
    tup.set("time", { type: 'Float', value: 0.0 + i });
    
    const macSrc = new Uint8Array([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    const macDst = new Uint8Array([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    
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
    
    testTuples.push(tup);
  }
  
  // Process tuples through active queries
  for (const tup of testTuples) {
    for (const query of activeQueries) {
      query.next(tup);
    }
  }
  
  // Signal reset to all operators
  for (const query of activeQueries) {
    query.reset(new Map());
  }
}

// Main entry point
function main(): void {
  runAllQueries();
  console.log("Done");
}

// Run the program
main();