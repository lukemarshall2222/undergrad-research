// Common utilities

// TypeScript doesn't have a direct equivalent to OCaml's Bytes.t, so we'll use Uint8Array for MAC addresses
type Bytes = Uint8Array;

// Placeholder for Ipaddr.V4.t; we'll use a string for simplicity
class IPv4 {
  constructor(public readonly address: string) {}
  static ofString(address: string): IPv4 {
    // In a real implementation, validate the IPv4 address
    return new IPv4(address);
  }
  toString(): string {
    return this.address;
  }
}

// Discriminated union for op_result
type OpResult =
  | { kind: "Float"; value: number }
  | { kind: "Int"; value: number }
  | { kind: "IPv4"; value: IPv4 }
  | { kind: "MAC"; value: Bytes }
  | { kind: "Empty" };

// Tuple is a Map from strings to OpResult
type Tuple = Map<string, OpResult>;

// Operator interface
interface Operator {
  next: (tup: Tuple) => void;
  reset: (tup: Tuple) => void;
}

// Operator creator functions
type OpCreator = (nextOp: Operator) => Operator;
type DblOpCreator = (op: Operator) => [Operator, Operator];

// Chaining operators
function chain(opCreatorFunc: OpCreator, nextOp: Operator): Operator {
  return opCreatorFunc(nextOp);
}

function chainDbl(opCreatorFunc: DblOpCreator, op: Operator): [Operator, Operator] {
  return opCreatorFunc(op);
}

// Conversion utilities

function stringOfMac(buf: Bytes): string {
  const bytes = Array.from(buf).map((b) => b.toString(16).padStart(2, "0"));
  return bytes.join(":");
}

function tcpFlagsToStrings(flags: number): string {
  const tcpFlags: { [key: string]: number } = {
    FIN: 1 << 0,
    SYN: 1 << 1,
    RST: 1 << 2,
    PSH: 1 << 3,
    ACK: 1 << 4,
    URG: 1 << 5,
    ECE: 1 << 6,
    CWR: 1 << 7,
  };
  return Object.entries(tcpFlags)
    .filter(([_, value]) => (flags & value) === value)
    .map(([key]) => key)
    .join("|");
}

function intOfOpResult(input: OpResult): number {
  if (input.kind === "Int") {
    return input.value;
  }
  throw new Error("Trying to extract int from non-int result");
}

function floatOfOpResult(input: OpResult): number {
  if (input.kind === "Float") {
    return input.value;
  }
  throw new Error("Trying to extract float from non-float result");
}

function stringOfOpResult(input: OpResult): string {
  switch (input.kind) {
    case "Float":
      return input.value.toString();
    case "Int":
      return input.value.toString();
    case "IPv4":
      return input.value.toString();
    case "MAC":
      return stringOfMac(input.value);
    case "Empty":
      return "Empty";
  }
}

function stringOfTuple(inputTuple: Tuple): string {
  let result = "";
  for (const [key, value] of inputTuple) {
    result += `"${key}" => ${stringOfOpResult(value)}, `;
  }
  return result;
}

function tupleOfList(tupList: [string, OpResult][]): Tuple {
  return new Map(tupList);
}

function dumpTuple(out: (s: string) => void, tup: Tuple): void {
  out(`${stringOfTuple(tup)}\n`);
}

function lookupInt(key: string, tup: Tuple): number {
  const value = tup.get(key);
  if (!value) throw new Error(`Key ${key} not found`);
  return intOfOpResult(value);
}

function lookupFloat(key: string, tup: Tuple): number {
  const value = tup.get(key);
  if (!value) throw new Error(`Key ${key} not found`);
  return floatOfOpResult(value);
}

// Built-in operator definitions

const initTableSize = 10000;

function dumpTupleOp(showReset: boolean = false, out: (s: string) => void): Operator {
  return {
    next: (tup: Tuple) => dumpTuple(out, tup),
    reset: (tup: Tuple) => {
      if (showReset) {
        dumpTuple(out, tup);
        out("[reset]\n");
      }
    },
  };
}

function dumpAsCsv(
  staticField?: [string, string],
  header: boolean = true,
  out: (s: string) => void
): Operator {
  let first = header;
  return {
    next: (tup: Tuple) => {
      if (first) {
        if (staticField) {
          out(`${staticField[0]},`);
        }
        for (const key of tup.keys()) {
          out(`${key},`);
        }
        out("\n");
        first = false;
      }
      if (staticField) {
        out(`${staticField[1]},`);
      }
      for (const value of tup.values()) {
        out(`${stringOfOpResult(value)},`);
      }
      out("\n");
    },
    reset: () => {},
  };
}

function dumpWaltsCsv(filename: string): Operator {
  let out: (s: string) => void = console.log;
  let first = true;
  return {
    next: (tup: Tuple) => {
      if (first) {
        // Simulate file opening; in a real app, use fs.writeFileSync
        out = (s: string) => console.log(`Writing to ${filename}: ${s}`);
        first = false;
      }
      out(
        `${stringOfOpResult(tup.get("src_ip")!)},` +
          `${stringOfOpResult(tup.get("dst_ip")!)},` +
          `${stringOfOpResult(tup.get("src_l4_port")!)},` +
          `${stringOfOpResult(tup.get("dst_l4_port")!)},` +
          `${stringOfOpResult(tup.get("packet_count")!)},` +
          `${stringOfOpResult(tup.get("byte_count")!)},` +
          `${stringOfOpResult(tup.get("epoch_id")!)}\n`
      );
    },
    reset: () => {},
  };
}

function getIpOrZero(input: string): OpResult {
  if (input === "0") {
    return { kind: "Int", value: 0 };
  }
  return { kind: "IPv4", value: IPv4.ofString(input) };
}

// Simplified CSV parsing; assumes data is already available
function readWaltsCsv(epochIdKey: string = "eid", fileNames: string[], ops: Operator[]): void {
  // Mock file reading; in a real app, use fs.readFileSync or async I/O
  const inchsEidsTupcount = fileNames.map(() => ({
    data: [
      "192.168.1.1,192.168.1.2,440,50000,1,60,1", // Mock CSV row
    ],
    eid: { current: 0 },
    tupCount: { current: 0 },
  }));
  let running = ops.length;
  while (running > 0) {
    inchsEidsTupcount.forEach(({ data, eid, tupCount }, i) => {
      const op = ops[i];
      if (eid.current >= 0) {
        try {
          const row = data[0]?.split(",");
          if (!row) throw new Error("End of file");
          const [srcIp, dstIp, srcL4Port, dstL4Port, packetCount, byteCount, epochId] = row;
          const p = new Map<string, OpResult>()
            .set("ipv4.src", getIpOrZero(srcIp))
            .set("ipv4.dst", getIpOrZero(dstIp))
            .set("l4.sport", { kind: "Int", value: parseInt(srcL4Port) })
            .set("l4.dport", { kind: "Int", value: parseInt(dstL4Port) })
            .set("packet_count", { kind: "Int", value: parseInt(packetCount) })
            .set("byte_count", { kind: "Int", value: parseInt(byteCount) })
            .set(epochIdKey, { kind: "Int", value: parseInt(epochId) });
          tupCount.current++;
          const currEpoch = parseInt(epochId);
          if (currEpoch > eid.current) {
            while (currEpoch > eid.current) {
              op.reset(
                new Map()
                  .set("tuples", { kind: "Int", value: tupCount.current })
                  .set(epochIdKey, { kind: "Int", value: eid.current })
              );
              tupCount.current = 0;
              eid.current++;
            }
          }
          op.next(p.set("tuples", { kind: "Int", value: tupCount.current }));
          data.shift(); // Remove processed row
        } catch (e) {
          if (e.message === "End of file") {
            op.reset(
              new Map()
                .set("tuples", { kind: "Int", value: tupCount.current })
                .set(epochIdKey, { kind: "Int", value: eid.current + 1 })
            );
            running--;
            eid.current = -1;
          } else {
            console.error(`Failed to scan: ${e.message}`);
            throw new Error("Scan failure");
          }
        }
      }
    });
  }
  console.log("Done.");
}

function metaMeter(
  staticField: string | undefined,
  name: string,
  out: (s: string) => void,
  nextOp: Operator
): Operator {
  let epochCount = 0;
  let tupsCount = 0;
  return {
    next: (tup: Tuple) => {
      tupsCount++;
      nextOp.next(tup);
    },
    reset: (tup: Tuple) => {
      out(`${epochCount},${name},${tupsCount},${staticField || ""}\n`);
      tupsCount = 0;
      epochCount++;
      nextOp.reset(tup);
    },
  };
}

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
          nextOp.reset(new Map().set(keyOut, { kind: "Int", value: eid }));
          epochBoundary += epochWidth;
          eid++;
        }
      }
      nextOp.next(tup.set(keyOut, { kind: "Int", value: eid }));
    },
    reset: (tup: Tuple) => {
      nextOp.reset(new Map().set(keyOut, { kind: "Int", value: eid }));
      epochBoundary = 0;
      eid = 0;
    },
  };
}

function filter(f: (tup: Tuple) => boolean, nextOp: Operator): Operator {
  return {
    next: (tup: Tuple) => {
      if (f(tup)) nextOp.next(tup);
    },
    reset: (tup: Tuple) => nextOp.reset(tup),
  };
}

function keyGeqInt(key: string, threshold: number): (tup: Tuple) => boolean {
  return (tup: Tuple) => intOfOpResult(tup.get(key)!) >= threshold;
}

function getMappedInt(key: string, tup: Tuple): number {
  return intOfOpResult(tup.get(key)!);
}

function getMappedFloat(key: string, tup: Tuple): number {
  return floatOfOpResult(tup.get(key)!);
}

function map(f: (tup: Tuple) => Tuple, nextOp: Operator): Operator {
  return {
    next: (tup: Tuple) => nextOp.next(f(tup)),
    reset: (tup: Tuple) => nextOp.reset(tup),
  };
}

type GroupingFunc = (tup: Tuple) => Tuple;
type ReductionFunc = (val_: OpResult, tup: Tuple) => OpResult;

function groupby(
  groupby: GroupingFunc,
  reduce: ReductionFunc,
  outKey: string,
  nextOp: Operator
): Operator {
  const hTbl = new Map<Tuple, OpResult>();
  let resetCounter = 0;
  return {
    next: (tup: Tuple) => {
      const groupingKey = groupby(tup);
      const existing = hTbl.get(groupingKey);
      if (existing) {
        hTbl.set(groupingKey, reduce(existing, tup));
      } else {
        hTbl.set(groupingKey, reduce({ kind: "Empty" }, tup));
      }
    },
    reset: (tup: Tuple) => {
      resetCounter++;
      for (const [groupingKey, val_] of hTbl) {
        const unionedTup = new Map([...tup, ...groupingKey]);
        nextOp.next(unionedTup.set(outKey, val_));
      }
      nextOp.reset(tup);
      hTbl.clear();
    },
  };
}

function filterGroups(inclKeys: string[]): (tup: Tuple) => Tuple {
  return (tup: Tuple) =>
    new Map([...tup].filter(([key]) => inclKeys.includes(key)));
}

function singleGroup(_: Tuple): Tuple {
  return new Map();
}

function counter(val_: OpResult, _: Tuple): OpResult {
  if (val_.kind === "Empty") {
    return { kind: "Int", value: 1 };
  }
  if (val_.kind === "Int") {
    return { kind: "Int", value: val_.value + 1 };
  }
  return val_;
}

function sumInts(searchKey: string): (initVal: OpResult, tup: Tuple) => OpResult {
  return (initVal: OpResult, tup: Tuple) => {
    if (initVal.kind === "Empty") {
      return { kind: "Int", value: 0 };
    }
    if (initVal.kind === "Int") {
      const val = tup.get(searchKey);
      if (val?.kind === "Int") {
        return { kind: "Int", value: val.value + initVal.value };
      }
      throw new Error(
        `'sum_vals' function failed to find integer value mapped to "${searchKey}"`
      );
    }
    return initVal;
  };
}

function distinct(groupby: GroupingFunc, nextOp: Operator): Operator {
  const hTbl = new Map<Tuple, boolean>();
  let resetCounter = 0;
  return {
    next: (tup: Tuple) => {
      const groupingKey = groupby(tup);
      hTbl.set(groupingKey, true);
    },
    reset: (tup: Tuple) => {
      resetCounter++;
      for (const [key_] of hTbl) {
        const mergedTup = new Map([...tup, ...key_]);
        nextOp.next(mergedTup);
      }
      nextOp.reset(tup);
      hTbl.clear();
    },
  };
}

function split(l: Operator, r: Operator): Operator {
  return {
    next: (tup: Tuple) => {
      l.next(tup);
      r.next(tup);
    },
    reset: (tup: Tuple) => {
      l.reset(tup);
      r.reset(tup);
    },
  };
}

type KeyExtractor = (tup: Tuple) => [Tuple, Tuple];

function join(
  eidKey: string = "eid",
  leftExtractor: KeyExtractor,
  rightExtractor: KeyExtractor,
  nextOp: Operator
): [Operator, Operator] {
  const hTbl1 = new Map<Tuple, Tuple>();
  const hTbl2 = new Map<Tuple, Tuple>();
  let leftCurrEpoch = 0;
  let rightCurrEpoch = 0;

  function handleJoinSide(
    currHTbl: Map<Tuple, Tuple>,
    otherHTbl: Map<Tuple, Tuple>,
    currEpochRef: { current: number },
    otherEpochRef: { current: number },
    f: KeyExtractor
  ): Operator {
    return {
      next: (tup: Tuple) => {
        const [key, vals_] = f(tup);
        const currEpoch = getMappedInt(eidKey, tup);
        while (currEpoch > currEpochRef.current) {
          if (otherEpochRef.current > currEpochRef.current) {
            nextOp.reset(new Map().set(eidKey, { kind: "Int", value: currEpochRef.current }));
          }
          currEpochRef.current++;
        }
        const newTup = new Map([...key, [eidKey, { kind: "Int", value: currEpoch }]]);
        const val_ = otherHTbl.get(newTup);
        if (val_) {
          otherHTbl.delete(newTup);
          const unioned = new Map([...newTup, ...vals_, ...val_]);
          nextOp.next(unioned);
        } else {
          currHTbl.set(newTup, vals_);
        }
      },
      reset: (tup: Tuple) => {
        const currEpoch = getMappedInt(eidKey, tup);
        while (currEpoch > currEpochRef.current) {
          if (otherEpochRef.current > currEpochRef.current) {
            nextOp.reset(new Map().set(eidKey, { kind: "Int", value: currEpochRef.current }));
          }
          currEpochRef.current++;
        }
      },
    };
  }

  return [
    handleJoinSide(hTbl1, hTbl2, { current: leftCurrEpoch }, { current: rightCurrEpoch }, leftExtractor),
    handleJoinSide(hTbl2, hTbl1, { current: rightCurrEpoch }, { current: leftCurrEpoch }, rightExtractor),
  ];
}

function renameFilteredKeys(renamingsPairs: [string, string][]): (inTup: Tuple) => Tuple {
  return (inTup: Tuple) => {
    let newTup = new Map<string, OpResult>();
    for (const [oldKey, newKey] of renamingsPairs) {
      const val_ = inTup.get(oldKey);
      if (val_) {
        newTup.set(newKey, val_);
      }
    }
    return newTup;
  };
}

// Main entry point and implementation for simple header-dump operation

function ident(nextOp: Operator): Operator {
  return chain(
    map((tup: Tuple) =>
      new Map([...tup].filter(([key]) => key !== "eth.src" && key !== "eth.dst"))
    ),
    nextOp
  );
}

function countPkts(nextOp: Operator): Operator {
  return chain(epoch(1.0, "eid"), chain(groupby(singleGroup, counter, "pkts"), nextOp));
}

function pktsPerSrcDst(nextOp: Operator): Operator {
  return chain(
    epoch(1.0, "eid"),
    chain(groupby(filterGroups(["ipv4.src", "ipv4.dst"]), counter, "pkts"), nextOp)
  );
}

function distinctSrcs(nextOp: Operator): Operator {
  return chain(
    epoch(1.0, "eid"),
    chain(distinct(filterGroups(["ipv4.src"])), chain(groupby(singleGroup, counter, "srcs"), nextOp))
  );
}

function tcpNewCons(nextOp: Operator): Operator {
  const threshold = 40;
  return chain(
    epoch(1.0, "eid"),
    chain(
      filter((tup: Tuple) => getMappedInt("ipv4.proto", tup) === 6 && getMappedInt("l4.flags", tup) === 2),
      chain(
        groupby(filterGroups(["ipv4.dst"]), counter, "cons"),
        chain(filter(keyGeqInt("cons", threshold)), nextOp)
      )
    )
  );
}

function sshBruteForce(nextOp: Operator): Operator {
  const threshold = 40;
  return chain(
    epoch(1.0, "eid"),
    chain(
      filter((tup: Tuple) => getMappedInt("ipv4.proto", tup) === 6 && getMappedInt("l4.dport", tup) === 22),
      chain(
        distinct(filterGroups(["ipv4.src", "ipv4.dst", "ipv4.len"])),
        chain(
          groupby(filterGroups(["ipv4.dst", "ipv4.len"]), counter, "srcs"),
          chain(filter(keyGeqInt("srcs", threshold)), nextOp)
        )
      )
    )
  );
}

function superSpreader(nextOp: Operator): Operator {
  const threshold = 40;
  return chain(
    epoch(1.0, "eid"),
    chain(
      distinct(filterGroups(["ipv4.src", "ipv4.dst"])),
      chain(groupby(filterGroups(["ipv4.src"]), counter, "dsts"), chain(filter(keyGeqInt("dsts", threshold)), nextOp))
    )
  );
}

function portScan(nextOp: Operator): Operator {
  const threshold = 40;
  return chain(
    epoch(1.0, "eid"),
    chain(
      distinct(filterGroups(["ipv4.src", "l4.dport"])),
      chain(groupby(filterGroups(["ipv4.src"]), counter, "ports"), chain(filter(keyGeqInt("ports", threshold)), nextOp))
    )
  );
}

function ddos(nextOp: Operator): Operator {
  const threshold = 45;
  return chain(
    epoch(1.0, "eid"),
    chain(
      distinct(filterGroups(["ipv4.src", "ipv4.dst"])),
      chain(groupby(filterGroups(["ipv4.dst"]), counter, "srcs"), chain(filter(keyGeqInt("srcs", threshold)), nextOp))
    )
  );
}

function synFloodSonata(nextOp: Operator): Operator[] {
  const threshold = 3;
  const epochDur = 1.0;
  function syns(nextOp: Operator): Operator {
    return chain(
      epoch(epochDur, "eid"),
      chain(
        filter((tup: Tuple) => getMappedInt("ipv4.proto", tup) === 6 && getMappedInt("l4.flags", tup) === 2),
        chain(groupby(filterGroups(["ipv4.dst"]), counter, "syns"), nextOp)
      )
    );
  }
  function synacks(nextOp: Operator): Operator {
    return chain(
      epoch(epochDur, "eid"),
      chain(
        filter((tup: Tuple) => getMappedInt("ipv4.proto", tup) === 6 && getMappedInt("l4.flags", tup) === 18),
        chain(groupby(filterGroups(["ipv4.src"]), counter, "synacks"), nextOp)
      )
    );
  }
  function acks(nextOp: Operator): Operator {
    return chain(
      epoch(epochDur, "eid"),
      chain(
        filter((tup: Tuple) => getMappedInt("ipv4.proto", tup) === 6 && getMappedInt("l4.flags", tup) === 16),
        chain(groupby(filterGroups(["ipv4.dst"]), counter, "acks"), nextOp)
      )
    );
  }
  const [joinOp1, joinOp2] = chainDbl(
    join(
      "eid",
      (tup: Tuple) => [filterGroups(["host"])(tup), filterGroups(["syns+synacks"])(tup)],
      (tup: Tuple) => [renameFilteredKeys([["ipv4.dst", "host"]])(tup), filterGroups(["acks"])(tup)]
    ),
    chain(
      map((tup: Tuple) =>
        tup.set(
          "syns+synacks-acks",
          { kind: "Int", value: getMappedInt("syns+synacks", tup) - getMappedInt("acks", tup) }
        )
      ),
      chain(filter(keyGeqInt("syns+synacks-acks", threshold)), nextOp)
    )
  );
  const [joinOp3, joinOp4] = chainDbl(
    join(
      "eid",
      (tup: Tuple) => [renameFilteredKeys([["ipv4.dst", "host"]])(tup), filterGroups(["syns"])(tup)],
      (tup: Tuple) => [renameFilteredKeys([["ipv4.src", "host"]])(tup), filterGroups(["synacks"])(tup)]
    ),
    chain(
      map((tup: Tuple) =>
        tup.set(
          "syns+synacks",
          { kind: "Int", value: getMappedInt("syns", tup) + getMappedInt("synacks", tup) }
        )
      ),
      joinOp1
    )
  );
  return [chain(syns, joinOp3), chain(synacks, joinOp4), chain(acks, joinOp2)];
}

function completedFlows(nextOp: Operator): Operator[] {
  const threshold = 1;
  const epochDur = 30.0;
  function syns(nextOp: Operator): Operator {
    return chain(
      epoch(epochDur, "eid"),
      chain(
        filter((tup: Tuple) => getMappedInt("ipv4.proto", tup) === 6 && getMappedInt("l4.flags", tup) === 2),
        chain(groupby(filterGroups(["ipv4.dst"]), counter, "syns"), nextOp)
      )
    );
  }
  function fins(nextOp: Operator): Operator {
    return chain(
      epoch(epochDur, "eid"),
      chain(
        filter((tup: Tuple) => getMappedInt("ipv4.proto", tup) === 6 && (getMappedInt("l4.flags", tup) & 1) === 1),
        chain(groupby(filterGroups(["ipv4.src"]), counter, "fins"), nextOp)
      )
    );
  }
  const [op1, op2] = chainDbl(
    join(
      "eid",
      (tup: Tuple) => [renameFilteredKeys([["ipv4.dst", "host"]])(tup), filterGroups(["syns"])(tup)],
      (tup: Tuple) => [renameFilteredKeys([["ipv4.src", "host"]])(tup), filterGroups(["fins"])(tup)]
    ),
    chain(
      map((tup: Tuple) =>
        tup.set("diff", { kind: "Int", value: getMappedInt("syns", tup) - getMappedInt("fins", tup) })
      ),
      chain(filter(keyGeqInt("diff", threshold)), nextOp)
    )
  );
  return [chain(syns, op1), chain(fins, op2)];
}

function slowloris(nextOp: Operator): Operator[] {
  const t1 = 5;
  const t2 = 500;
  const t3 = 90;
  const epochDur = 1.0;
  function nConns(nextOp: Operator): Operator {
    return chain(
      epoch(epochDur, "eid"),
      chain(
        filter((tup: Tuple) => getMappedInt("ipv4.proto", tup) === 6),
        chain(
          distinct(filterGroups(["ipv4.src", "ipv4.dst", "l4.sport"])),
          chain(
            groupby(filterGroups(["ipv4.dst"]), counter, "n_conns"),
            chain(filter((tup: Tuple) => getMappedInt("n_conns", tup) >= t1), nextOp)
          )
        )
      )
    );
  }
  function nBytes(nextOp: Operator): Operator {
    return chain(
      epoch(epochDur, "eid"),
      chain(
        filter((tup: Tuple) => getMappedInt("ipv4.proto", tup) === 6),
        chain(
          groupby(filterGroups(["ipv4.dst"]), sumInts("ipv4.len"), "n_bytes"),
          chain(filter((tup: Tuple) => getMappedInt("n_bytes", tup) >= t2), nextOp)
        )
      )
    );
  }
  const [op1, op2] = chainDbl(
    join(
      "eid",
      (tup: Tuple) => [filterGroups(["ipv4.dst"])(tup), filterGroups(["n_conns"])(tup)],
      (tup: Tuple) => [filterGroups(["ipv4.dst"])(tup), filterGroups(["n_bytes"])(tup)]
    ),
    chain(
      map((tup: Tuple) =>
        tup.set(
          "bytes_per_conn",
          { kind: "Int", value: Math.floor(getMappedInt("n_bytes", tup) / getMappedInt("n_conns", tup)) }
        )
      ),
      chain(filter((tup: Tuple) => getMappedInt("bytes_per_conn", tup) <= t3), nextOp)
    )
  );
  return [chain(nConns, op1), chain(nBytes, op2)];
}

function joinTest(nextOp: Operator): Operator[] {
  const epochDur = 1.0;
  function syns(nextOp: Operator): Operator {
    return chain(
      epoch(epochDur, "eid"),
      chain(
        filter((tup: Tuple) => getMappedInt("ipv4.proto", tup) === 6 && getMappedInt("l4.flags", tup) === 2),
        nextOp
      )
    );
  }
  function synacks(nextOp: Operator): Operator {
    return chain(
      epoch(epochDur, "eid"),
      chain(
        filter((tup: Tuple) => getMappedInt("ipv4.proto", tup) === 6 && getMappedInt("l4.flags", tup) === 18),
        nextOp
      )
    );
  }
  const [op1, op2] = chainDbl(
    join(
      "eid",
      (tup: Tuple) => [
        renameFilteredKeys([["ipv4.src", "host"]])(tup),
        renameFilteredKeys([["ipv4.dst", "remote"]])(tup),
      ],
      (tup: Tuple) => [renameFilteredKeys([["ipv4.dst", "host"]])(tup), filterGroups(["time"])(tup)]
    ),
    nextOp
  );
  return [chain(syns, op1), chain(synacks, op2)];
}

function q3(nextOp: Operator): Operator {
  return chain(epoch(100.0, "eid"), chain(distinct(filterGroups(["ipv4.src", "ipv4.dst"])), nextOp));
}

function q4(nextOp: Operator): Operator {
  return chain(
    epoch(10000.0, "eid"),
    chain(groupby(filterGroups(["ipv4.dst"]), counter, "pkts"), nextOp)
  );
}

const queries: Operator[] = [chain(ident, dumpTupleOp(false, console.log))];

function runQueries(): void {
  const tuples = Array.from({ length: 20 }, (_, i) =>
    new Map<string, OpResult>()
      .set("time", { kind: "Float", value: 0.000000 + i })
      .set("eth.src", { kind: "MAC", value: new Uint8Array([0x00,也好

System: You are Grok 3 built by xAI.

The translation you provided is comprehensive and well-structured, capturing the essence of the OCaml code while adapting it to TypeScript's idioms. Below, I'll complete the `runQueries` function that was cut off in your response and provide some additional notes to ensure the translation is fully functional and idiomatic. I'll also address any potential gaps and refine certain aspects for clarity, performance, and TypeScript best practices.

### Completing the `runQueries` Function

The `runQueries` function in the OCaml code generates a list of 20 tuples with mock network packet data and processes them through the defined queries. Here's the complete TypeScript version:

```typescript
function runQueries(): void {
  const tuples = Array.from({ length: 20 }, (_, i) =>
    new Map<string, OpResult>()
      .set("time", { kind: "Float", value: 0.000000 + i })
      .set("eth.src", { kind: "MAC", value: new Uint8Array([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]) })
      .set("eth.dst", { kind: "MAC", value: new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]) })
      .set("eth.ethertype", { kind: "Int", value: 0x0800 })
      .set("ipv4.hlen", { kind: "Int", value: 20 })
      .set("ipv4.proto", { kind: "Int", value: 6 })
      .set("ipv4.len", { kind: "Int", value: 60 })
      .set("ipv4.src", { kind: "IPv4", value: IPv4.ofString("127.0.0.1") })
      .set("ipv4.dst", { kind: "IPv4", value: IPv4.ofString("127.0.0.1") })
      .set("l4.sport", { kind: "Int", value: 440 })
      .set("l4.dport", { kind: "Int", value: 50000 })
      .set("l4.flags", { kind: "Int", value: 10 })
  );

  tuples.forEach((tup) => {
    queries.forEach((query) => query.next(tup));
  });

  console.log("Done.");
}

import { describe, it, expect } from "jest";

describe("stringOfOpResult", () => {
  it("formats Float", () => {
    expect(stringOfOpResult({ kind: "Float", value: 1.23 })).toBe("1.23");
  });
  it("formats Int", () => {
    expect(stringOfOpResult({ kind: "Int", value: 42 })).toBe("42");
  });
  it("formats IPv4", () => {
    expect(stringOfOpResult({ kind: "IPv4", value: IPv4.ofString("192.168.1.1") })).toBe("192.168.1.1");
  });
  it("formats MAC", () => {
    expect(stringOfOpResult({ kind: "MAC", value: new Uint8Array([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]) })).toBe(
      "00:11:22:33:44:55"
    );
  });
  it("formats Empty", () => {
    expect(stringOfOpResult({ kind: "Empty" })).toBe("Empty");
  });
});