import { createWriteStream, createReadStream, WriteStream } from 'fs';
import { createInterface } from 'readline';
import { Readable } from 'stream';

// IPv4 address handling (simplified, without external library)
class IPv4 {
  private readonly address: string;

  constructor(address: string) {
    // Basic validation
    if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(address)) {
      throw new Error(`Invalid IPv4 address: ${address}`);
    }
    this.address = address;
  }

  static fromString(address: string): IPv4 {
    return new IPv4(address);
  }

  toString(): string {
    return this.address;
  }
}

// Enum for op_result variant type
enum OpResultType {
  Float = 'Float',
  Int = 'Int',
  IPv4 = 'IPv4',
  MAC = 'MAC',
  Empty = 'Empty',
}

// Union type for op_result
type OpResult =
  | { type: OpResultType.Float; value: number }
  | { type: OpResultType.Int; value: number }
  | { type: OpResultType.IPv4; value: IPv4 }
  | { type: OpResultType.MAC; value: Uint8Array }
  | { type: OpResultType.Empty };

// Tuple is a Map<string, OpResult>
type Tuple = Map<string, OpResult>;

// Operator interface
interface Operator {
  next(tup: Tuple): void;
  reset(tup: Tuple): void;
}

// Type for operator creators
type OpCreator = (nextOp: Operator) => Operator;
type DblOpCreator = (op: Operator) => [Operator, Operator];

// Chaining operators
const chain = (creator: OpCreator, nextOp: Operator): Operator => creator(nextOp);
const chainDouble = (creator: DblOpCreator, op: Operator): [Operator, Operator] => creator(op);

// Conversion utilities
const stringOfMac = (buf: Uint8Array): string => {
  if (buf.length !== 6) throw new Error('MAC address must be 6 bytes');
  return Array.from(buf)
    .map(byte => byte.toString(16).padStart(2, '0'))
    .join(':');
};

const tcpFlagsToString = (flags: number): string => {
  const flagMap: Map<string, number> = new Map([
    ['FIN', 1 << 0],
    ['SYN', 1 << 1],
    ['RST', 1 << 2],
    ['PSH', 1 << 3],
    ['ACK', 1 << 4],
    ['URG', 1 << 5],
    ['ECE', 1 << 6],
    ['CWR', 1 << 7],
  ]);

  return Array.from(flagMap.entries())
    .filter(([_, value]) => (flags & value) === value)
    .map(([key]) => key)
    .join('|');
};

const intOfOpResult = (input: OpResult): number => {
  if (input.type === OpResultType.Int) return input.value;
  throw new Error('Trying to extract int from non-int result');
};

const floatOfOpResult = (input: OpResult): number => {
  if (input.type === OpResultType.Float) return input.value;
  throw new Error('Trying to extract float from non-float result');
};

const stringOfOpResult = (input: OpResult): string => {
  switch (input.type) {
    case OpResultType.Float:
      return input.value.toString();
    case OpResultType.Int:
      return input.value.toString();
    case OpResultType.IPv4:
      return input.value.toString();
    case OpResultType.MAC:
      return stringOfMac(input.value);
    case OpResultType.Empty:
      return 'Empty';
  }
};

const stringOfTuple = (tup: Tuple): string => {
  let result = '';
  for (const [key, value] of tup) {
    result += `"${key}" => ${stringOfOpResult(value)}, `;
  }
  return result;
};

const tupleOfList = (list: [string, OpResult][]): Tuple => {
  return new Map(list);
};

const dumpTuple = (out: WriteStream, tup: Tuple): void => {
  out.write(`${stringOfTuple(tup)}\n`);
};

const lookupInt = (key: string, tup: Tuple): number => {
  const value = tup.get(key);
  if (!value) throw new Error(`Key ${key} not found`);
  return intOfOpResult(value);
};

const lookupFloat = (key: string, tup: Tuple): number => {
  const value = tup.get(key);
  if (!value) throw new Error(`Key ${key} not found`);
  return floatOfOpResult(value);
};

// Operator implementations
const dumpTupleOp = (showReset: boolean = false, out: WriteStream): Operator => ({
  next: (tup: Tuple) => dumpTuple(out, tup),
  reset: (tup: Tuple) => {
    if (showReset) {
      dumpTuple(out, tup);
      out.write('[reset]\n');
    }
  },
});

const dumpAsCsv = (
  staticField?: [string, string],
  header: boolean = true,
  out: WriteStream = process.stdout
): Operator => {
  let first = header;
  return {
    next: (tup: Tuple) => {
      if (first) {
        if (staticField) out.write(`${staticField[0]},`);
        for (const key of tup.keys()) {
          out.write(`${key},`);
        }
        out.write('\n');
        first = false;
      }
      if (staticField) out.write(`${staticField[1]},`);
      for (const value of tup.values()) {
        out.write(`${stringOfOpResult(value)},`);
      }
      out.write('\n');
    },
    reset: () => {},
  };
};

const dumpWaltsCsv = (filename: string): Operator => {
  let out: WriteStream = process.stdout;
  let first = true;
  return {
    next: (tup: Tuple) => {
      if (first) {
        out = createWriteStream(filename);
        first = false;
      }
      out.write(
        [
          stringOfOpResult(tup.get('src_ip')!),
          stringOfOpResult(tup.get('dst_ip')!),
          stringOfOpResult(tup.get('src_l4_port')!),
          stringOfOpResult(tup.get('dst_l4_port')!),
          stringOfOpResult(tup.get('packet_count')!),
          stringOfOpResult(tup.get('byte_count')!),
          stringOfOpResult(tup.get('epoch_id')!),
        ].join(',') + '\n'
      );
    },
    reset: () => {},
  };
};

const getIpOrZero = (input: string): OpResult => {
  if (input === '0') return { type: OpResultType.Int, value: 0 };
  return { type: OpResultType.IPv4, value: IPv4.fromString(input) };
};

const readWaltsCsv = async (
  epochIdKey: string = 'eid',
  fileNames: string[],
  ops: Operator[]
): Promise<void> => {
  const inchsEidsTupcount = fileNames.map(filename => ({
    stream: createReadStream(filename),
    eid: 0,
    tupCount: 0,
  }));

  let running = ops.length;

  const processLine = async (
    line: string,
    { eid, tupCount }: { eid: number; tupCount: number },
    op: Operator
  ): Promise<void> => {
    try {
      const [srcIp, dstIp, srcL4Port, dstL4Port, packetCount, byteCount, epochId] =
        line.split(',').map(s => s.trim());
      const p: Tuple = new Map([
        ['ipv4.src', getIpOrZero(srcIp)],
        ['ipv4.dst', getIpOrZero(dstIp)],
        ['l4.sport', { type: OpResultType.Int, value: parseInt(srcL4Port) }],
        ['l4.dport', { type: OpResultType.Int, value: parseInt(dstL4Port) }],
        ['packet_count', { type: OpResultType.Int, value: parseInt(packetCount) }],
        ['byte_count', { type: OpResultType.Int, value: parseInt(byteCount) }],
        [epochIdKey, { type: OpResultType.Int, value: parseInt(epochId) }],
      ]);

      tupCount++;
      const currEid = parseInt(epochId);
      if (currEid > eid) {
        while (currEid > eid) {
          op.reset(
            tupleOfList([
              ['tuples', { type: OpResultType.Int, value: tupCount }],
              [epochIdKey, { type: OpResultType.Int, value: eid }],
            ])
          );
          tupCount = 0;
          eid++;
        }
      }
      op.next(
        new Map([...p, ['tuples', { type: OpResultType.Int, value: tupCount }]])
      );
      return Promise.resolve();
    } catch (e) {
      console.error(`Failed to scan: ${e}`);
      throw new Error('Scan failure');
    }
  };

  for (const [index, { stream, eid, tupCount }] of inchsEidsTupcount.entries()) {
    const op = ops[index];
    const rl = createInterface({ input: stream });

    for await (const line of rl) {
      if (eid >= 0) {
        await processLine(line, { eid, tupCount }, op);
      }
    }

    op.reset(
      tupleOfList([
        ['tuples', { type: OpResultType.Int, value: tupCount }],
        [epochIdKey, { type: OpResultType.Int, value: eid + 1 }],
      ])
    );
    running--;
  }

  console.log('Done.');
};

const metaMeter = (
  staticField: string | undefined,
  name: string,
  out: WriteStream,
  nextOp: Operator
): Operator => {
  let epochCount = 0;
  let tupsCount = 0;
  return {
    next: (tup: Tuple) => {
      tupsCount++;
      nextOp.next(tup);
    },
    reset: (tup: Tuple) => {
      out.write(
        `${epochCount},${name},${tupsCount},${staticField || ''}\n`
      );
      tupsCount = 0;
      epochCount++;
      nextOp.reset(tup);
    },
  };
};

const epoch = (epochWidth: number, keyOut: string, nextOp: Operator): Operator => {
  let epochBoundary = 0.0;
  let eid = 0;
  return {
    next: (tup: Tuple) => {
      const time = floatOfOpResult(tup.get('time')!);
      if (epochBoundary === 0.0) {
        epochBoundary = time + epochWidth;
      } else if (time >= epochBoundary) {
        while (time >= epochBoundary) {
          nextOp.reset(
            tupleOfList([[keyOut, { type: OpResultType.Int, value: eid }]])
          );
          epochBoundary += epochWidth;
          eid++;
        }
      }
      nextOp.next(
        new Map([...tup, [keyOut, { type: OpResultType.Int, value: eid }]])
      );
    },
    reset: (tup: Tuple) => {
      nextOp.reset(
        tupleOfList([[keyOut, { type: OpResultType.Int, value: eid }]])
      );
      epochBoundary = 0.0;
      eid = 0;
    },
  };
};

const filter = (f: (tup: Tuple) => boolean, nextOp: Operator): Operator => ({
  next: (tup: Tuple) => {
    if (f(tup)) nextOp.next(tup);
  },
  reset: (tup: Tuple) => nextOp.reset(tup),
});

const keyGeqInt = (key: string, threshold: number) => (tup: Tuple): boolean =>
  intOfOpResult(tup.get(key)!) >= threshold;

const getMappedInt = (key: string, tup: Tuple): number =>
  intOfOpResult(tup.get(key)!);

const getMappedFloat = (key: string, tup: Tuple): number =>
  floatOfOpResult(tup.get(key)!);

const map = (f: (tup: Tuple) => Tuple, nextOp: Operator): Operator => ({
  next: (tup: Tuple) => nextOp.next(f(tup)),
  reset: (tup: Tuple) => nextOp.reset(tup),
});

type GroupingFunc = (tup: Tuple) => Tuple;
type ReductionFunc = (acc: OpResult, tup: Tuple) => OpResult;

const groupby = (
  groupBy: GroupingFunc,
  reduce: ReductionFunc,
  outKey: string,
  nextOp: Operator
): Operator => {
  const hTbl = new Map<Tuple, OpResult>();
  let resetCounter = 0;
  return {
    next: (tup: Tuple) => {
      const groupingKey = groupBy(tup);
      const existing = hTbl.get(groupingKey);
      const newValue = reduce(existing || { type: OpResultType.Empty }, tup);
      hTbl.set(groupingKey, newValue);
    },
    reset: (tup: Tuple) => {
      resetCounter++;
      for (const [groupingKey, value] of hTbl) {
        const unionedTup = new Map([...tup, ...groupingKey]);
        nextOp.next(new Map([...unionedTup, [outKey, value]]));
      }
      nextOp.reset(tup);
      hTbl.clear();
    },
  };
};

const filterGroups = (inclKeys: string[], tup: Tuple): Tuple =>
  new Map([...tup].filter(([key]) => inclKeys.includes(key)));

const singleGroup = (_: Tuple): Tuple => new Map();

const counter = (val: OpResult, _: Tuple): OpResult => {
  if (val.type === OpResultType.Empty) return { type: OpResultType.Int, value: 1 };
  if (val.type === OpResultType.Int) return { type: OpResultType.Int, value: val.value + 1 };
  return val;
};

const sumInts = (searchKey: string, initVal: OpResult, tup: Tuple): OpResult => {
  if (initVal.type === OpResultType.Empty) return { type: OpResultType.Int, value: 0 };
  if (initVal.type === OpResultType.Int) {
    const value = tup.get(searchKey);
    if (value?.type === OpResultType.Int) {
      return { type: OpResultType.Int, value: value.value + initVal.value };
    }
    throw new Error(`'sum_vals' failed to find integer value for "${searchKey}"`);
  }
  return initVal;
};

const distinct = (groupBy: GroupingFunc, nextOp: Operator): Operator => {
  const hTbl = new Map<Tuple, boolean>();
  let resetCounter = 0;
  return {
    next: (tup: Tuple) => {
      const groupingKey = groupBy(tup);
      hTbl.set(groupingKey, true);
    },
    reset: (tup: Tuple) => {
      resetCounter++;
      for (const [key] of hTbl) {
        const mergedTup = new Map([...tup, ...key]);
        nextOp.next(mergedTup);
      }
      nextOp.reset(tup);
      hTbl.clear();
    },
  };
};

const split = (left: Operator, right: Operator): Operator => ({
  next: (tup: Tuple) => {
    left.next(tup);
    right.next(tup);
  },
  reset: (tup: Tuple) => {
    left.reset(tup);
    right.reset(tup);
  },
});

type KeyExtractor = (tup: Tuple) => [Tuple, Tuple];

const join = (
  eidKey: string = 'eid',
  leftExtractor: KeyExtractor,
  rightExtractor: KeyExtractor,
  nextOp: Operator
): [Operator, Operator] => {
  const hTbl1 = new Map<Tuple, Tuple>();
  const hTbl2 = new Map<Tuple, Tuple>();
  let leftCurrEpoch = 0;
  let rightCurrEpoch = 0;

  const handleJoinSide = (
    currHTbl: Map<Tuple, Tuple>,
    otherHTbl: Map<Tuple, Tuple>,
    currEpochRef: number,
    otherEpochRef: number,
    f: KeyExtractor
  ): Operator => ({
    next: (tup: Tuple) => {
      const [key, vals] = f(tup);
      const currEpoch = getMappedInt(eidKey, tup);

      while (currEpoch > currEpochRef) {
        if (otherEpochRef > currEpochRef) {
          nextOp.reset(
            tupleOfList([[eidKey, { type: OpResultType.Int, value: currEpochRef }]])
          );
        }
        currEpochRef++;
      }

      const newTup = new Map([...key, [eidKey, { type: OpResultType.Int, value: currEpoch }]]);
      const otherVal = otherHTbl.get(newTup);
      if (otherVal) {
        otherHTbl.delete(newTup);
        const unioned = new Map([...newTup, ...vals, ...otherVal]);
        nextOp.next(unioned);
      } else {
        currHTbl.set(newTup, vals);
      }
    },
    reset: (tup: Tuple) => {
      const currEpoch = getMappedInt(eidKey, tup);
      while (currEpoch > currEpochRef) {
        if (otherEpochRef > currEpochRef) {
          nextOp.reset(
            tupleOfList([[eidKey, { type: OpResultType.Int, value: currEpochRef }]])
          );
        }
        currEpochRef++;
      }
    },
  });

  return [
    handleJoinSide(hTbl1, hTbl2, leftCurrEpoch, rightCurrEpoch, leftExtractor),
    handleJoinSide(hTbl2, hTbl1, rightCurrEpoch, leftCurrEpoch, rightExtractor),
  ];
};

const renameFilteredKeys = (
  renamings: [string, string][],
  inTup: Tuple
): Tuple => {
  let newTup = new Map<string, OpResult>();
  for (const [oldKey, newKey] of renamings) {
    const val = inTup.get(oldKey);
    if (val) newTup.set(newKey, val);
  }
  return newTup;
};

// Query implementations
const ident = (nextOp: Operator): Operator =>
  chain(
    map(tup =>
      new Map(
        [...tup].filter(
          ([key]) => key !== 'eth.src' && key !== 'eth.dst'
        )
      )
    ),
    nextOp
  );

const countPkts = (nextOp: Operator): Operator =>
  chain(epoch(1.0, 'eid'), chain(groupby(singleGroup, counter, 'pkts'), nextOp));

const pktsPerSrcDst = (nextOp: Operator): Operator =>
  chain(
    epoch(1.0, 'eid'),
    chain(
      groupby(filterGroups(['ipv4.src', 'ipv4.dst']), counter, 'pkts'),
      nextOp
    )
  );

const distinctSrcs = (nextOp: Operator): Operator =>
  chain(
    epoch(1.0, 'eid'),
    chain(
      distinct(filterGroups(['ipv4.src'])),
      chain(groupby(singleGroup, counter, 'srcs'), nextOp)
    )
  );

const tcpNewCons = (nextOp: Operator): Operator => {
  const threshold = 40;
  return chain(
    epoch(1.0, 'eid'),
    chain(
      filter(
        tup =>
          getMappedInt('ipv4.proto', tup) === 6 &&
          getMappedInt('l4.flags', tup) === 2
      ),
      chain(
        groupby(filterGroups(['ipv4.dst']), counter, 'cons'),
        chain(filter(keyGeqInt('cons', threshold)), nextOp)
      )
    )
  );
};

const sshBruteForce = (nextOp: Operator): Operator => {
  const threshold = 40;
  return chain(
    epoch(1.0, 'eid'),
    chain(
      filter(
        tup =>
          getMappedInt('ipv4.proto', tup) === 6 &&
          getMappedInt('l4.dport', tup) === 22
      ),
      chain(
        distinct(filterGroups(['ipv4.src', 'ipv4.dst', 'ipv4.len'])),
        chain(
          groupby(filterGroups(['ipv4.dst', 'ipv4.len']), counter, 'srcs'),
          chain(filter(keyGeqInt('srcs', threshold)), nextOp)
        )
      )
    )
  );
};

const superSpreader = (nextOp: Operator): Operator => {
  const threshold = 40;
  return chain(
    epoch(1.0, 'eid'),
    chain(
      distinct(filterGroups(['ipv4.src', 'ipv4.dst'])),
      chain(
        groupby(filterGroups(['ipv4.src']), counter, 'dsts'),
        chain(filter(keyGeqInt('dsts', threshold)), nextOp)
      )
    )
  );
};

const portScan = (nextOp: Operator): Operator => {
  const threshold = 40;
  return chain(
    epoch(1.0, 'eid'),
    chain(
      distinct(filterGroups(['ipv4.src', 'l4.dport'])),
      chain(
        groupby(filterGroups(['ipv4.src']), counter, 'ports'),
        chain(filter(keyGeqInt('ports', threshold)), nextOp)
      )
    )
  );
};

const ddos = (nextOp: Operator): Operator => {
  const threshold = 45;
  return chain(
    epoch(1.0, 'eid'),
    chain(
      distinct(filterGroups(['ipv4.src', 'ipv4.dst'])),
      chain(
        groupby(filterGroups(['ipv4.dst']), counter, 'srcs'),
        chain(filter(keyGeqInt('srcs', threshold)), nextOp)
      )
    )
  );
};

const synFloodSonata = (nextOp: Operator): Operator[] => {
  const threshold = 3;
  const epochDur = 1.0;

  const syns = (nextOp: Operator): Operator =>
    chain(
      epoch(epochDur, 'eid'),
      chain(
        filter(
          tup =>
            getMappedInt('ipv4.proto', tup) === 6 &&
            getMappedInt('l4.flags', tup) === 2
        ),
        chain(groupby(filterGroups(['ipv4.dst']), counter, 'syns'), nextOp)
      )
    );

  const synacks = (nextOp: Operator): Operator =>
    chain(
      epoch(epochDur, 'eid'),
      chain(
        filter(
          tup =>
            getMappedInt('ipv4.proto', tup) === 6 &&
            getMappedInt('l4.flags', tup) === 18
        ),
        chain(groupby(filterGroups(['ipv4.src']), counter, 'synacks'), nextOp)
      )
    );

  const acks = (nextOp: Operator): Operator =>
    chain(
      epoch(epochDur, 'eid'),
      chain(
        filter(
          tup =>
            getMappedInt('ipv4.proto', tup) === 6 &&
            getMappedInt('l4.flags', tup) === 16
        ),
        chain(groupby(filterGroups(['ipv4.dst']), counter, 'acks'), nextOp)
      )
    );

  const [joinOp1, joinOp2] = chainDouble(
    join(
      'eid',
      tup => [
        filterGroups(['host'], tup),
        filterGroups(['syns+synacks'], tup),
      ],
      tup => [
        renameFilteredKeys([['ipv4.dst', 'host']], tup),
        filterGroups(['acks'], tup),
      ]
    ),
    chain(
      map(tup =>
        new Map([
          ...tup,
          [
            'syns+synacks-acks',
            {
              type: OpResultType.Int,
              value:
                getMappedInt('syns+synacks', tup) -
                getMappedInt('acks', tup),
            },
          ],
        ])
      ),
      chain(filter(keyGeqInt('syns+synacks-acks', threshold)), nextOp)
    )
  );

  const [joinOp3, joinOp4] = chainDouble(
    join(
      'eid',
      tup => [
        renameFilteredKeys([['ipv4.dst', 'host']], tup),
        filterGroups(['syns'], tup),
      ],
      tup => [
        renameFilteredKeys([['ipv4.src', 'host']], tup),
        filterGroups(['synacks'], tup),
      ]
    ),
    chain(
      map(tup =>
        new Map([
          ...tup,
          [
            'syns+synacks',
            {
              type: OpResultType.Int,
              value:
                getMappedInt('syns', tup) + getMappedInt('synacks', tup),
            },
          ],
        ])
      ),
      joinOp1
    )
  );

  return [chain(syns, joinOp3), chain(synacks, joinOp4), chain(acks, joinOp2)];
};

const completedFlows = (nextOp: Operator): Operator[] => {
  const threshold = 1;
  const epochDur = 30.0;

  const syns = (nextOp: Operator): Operator =>
    chain(
      epoch(epochDur, 'eid'),
      chain(
        filter(
          tup =>
            getMappedInt('ipv4.proto', tup) === 6 &&
            getMappedInt('l4.flags', tup) === 2
        ),
        chain(groupby(filterGroups(['ipv4.dst']), counter, 'syns'), nextOp)
      )
    );

  const fins = (nextOp: Operator): Operator =>
    chain(
      epoch(epochDur, 'eid'),
      chain(
        filter(
          tup =>
            getMappedInt('ipv4.proto', tup) === 6 &&
            (getMappedInt('l4.flags', tup) & 1) === 1
        ),
        chain(groupby(filterGroups(['ipv4.src']), counter, 'fins'), nextOp)
      )
    );

  const [op1, op2] = chainDouble(
    join(
      'eid',
      tup => [
        renameFilteredKeys([['ipv4.dst', 'host']], tup),
        filterGroups(['syns'], tup),
      ],
      tup => [
        renameFilteredKeys([['ipv4.src', 'host']], tup),
        filterGroups(['fins'], tup),
      ]
    ),
    chain(
      map(tup =>
        new Map([
          ...tup,
          [
            'diff',
            {
              type: OpResultType.Int,
              value:
                getMappedInt('syns', tup) - getMappedInt('fins', tup),
            },
          ],
        ])
      ),
      chain(filter(keyGeqInt('diff', threshold)), nextOp)
    )
  );

  return [chain(syns, op1), chain(fins, op2)];
};

const slowloris = (nextOp: Operator): Operator[] => {
  const t1 = 5;
  const t2 = 500;
  const t3 = 90;
  const epochDur = 1.0;

  const nConns = (nextOp: Operator): Operator =>
    chain(
      epoch(epochDur, 'eid'),
      chain(
        filter(tup => getMappedInt('ipv4.proto', tup) === 6),
        chain(
          distinct(filterGroups(['ipv4.src', 'ipv4.dst', 'l4.sport'])),
          chain(
            groupby(filterGroups(['ipv4.dst']), counter, 'n_conns'),
            chain(filter(tup => getMappedInt('n_conns', tup) >= t1), nextOp)
          )
        )
      )
    );

  const nBytes = (nextOp: Operator): Operator =>
    chain(
      epoch(epochDur, 'eid'),
      chain(
        filter(tup => getMappedInt('ipv4.proto', tup) === 6),
        chain(
          groupby(filterGroups(['ipv4.dst']), sumInts('ipv4.len'), 'n_bytes'),
          chain(filter(tup => getMappedInt('n_bytes', tup) >= t2), nextOp)
        )
      )
    );

  const [op1, op2] = chainDouble(
    join(
      'eid',
      tup => [filterGroups(['ipv4.dst'], tup), filterGroups(['n_conns'], tup)],
      tup => [filterGroups(['ipv4.dst'], tup), filterGroups(['n_bytes'], tup)]
    ),
    chain(
      map(tup =>
        new Map([
          ...tup,
          [
            'bytes_per_conn',
            {
              type: OpResultType.Int,
              value:
                getMappedInt('n_bytes', tup) / getMappedInt('n_conns', tup),
            },
          ],
        ])
      ),
      chain(filter(tup => getMappedInt('bytes_per_conn', tup) <= t3), nextOp)
    )
  );

  return [chain(nConns, op1), chain(nBytes, op2)];
};

const joinTest = (nextOp: Operator): Operator[] => {
  const epochDur = 1.0;

  const syns = (nextOp: Operator): Operator =>
    chain(
      epoch(epochDur, 'eid'),
      chain(
        filter(
          tup =>
            getMappedInt('ipv4.proto', tup) === 6 &&
            getMappedInt('l4.flags', tup) === 2
        ),
        nextOp
      )
    );

  const synacks = (nextOp: Operator): Operator =>
    chain(
      epoch(epochDur, 'eid'),
      chain(
        filter(
          tup =>
            getMappedInt('ipv4.proto', tup) === 6 &&
            getMappedInt('l4.flags', tup) === 18
        ),
        nextOp
      )
    );

  const [op1, op2] = chainDouble(
    join(
      'eid',
      tup => [
        renameFilteredKeys([['ipv4.src', 'host']], tup),
        renameFilteredKeys([['ipv4.dst', 'remote']], tup),
      ],
      tup => [
        renameFilteredKeys([['ipv4.dst', 'host']], tup),
        filterGroups(['time'], tup),
      ]
    ),
    nextOp
  );

  return [chain(syns, op1), chain(synacks, op2)];
};

const q3 = (nextOp: Operator): Operator =>
  chain(
    epoch(100.0, 'eid'),
    chain(distinct(filterGroups(['ipv4.src', 'ipv4.dst'])), nextOp)
  );

const q4 = (nextOp: Operator): Operator =>
  chain(
    epoch(10000.0, 'eid'),
    chain(groupby(filterGroups(['ipv4.dst']), counter, 'pkts'), nextOp)
  );

const queries: Operator[] = [chain(ident, dumpTupleOp(false, process.stdout))];

const runQueries = async (): Promise<void> => {
  const tuples = Array.from({ length: 20 }, (_, i) =>
    tupleOfList([
      ['time', { type: OpResultType.Float, value: 0.0 + i }],
      [
        'eth.src',
        {
          type: OpResultType.MAC,
          value: new Uint8Array([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
        },
      ],
      [
        'eth.dst',
        {
          type: OpResultType.MAC,
          value: new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
        },
      ],
      ['eth.ethertype', { type: OpResultType.Int, value: 0x0800 }],
      ['ipv4.hlen', { type: OpResultType.Int, value: 20 }],
      ['ipv4.proto', { type: OpResultType.Int, value: 6 }],
      ['ipv4.len', { type: OpResultType.Int, value: 60 }],
      [
        'ipv4.src',
        { type: OpResultType.IPv4, value: IPv4.fromString('127.0.0.1') },
      ],
      [
        'ipv4.dst',
        { type: OpResultType.IPv4, value: IPv4.fromString('127.0.0.1') },
      ],
      ['l4.sport', { type: OpResultType.Int, value: 440 }],
      ['l4.dport', { type: OpResultType.Int, value: 50000 }],
      ['l4.flags', { type: OpResultType.Int, value: 10 }],
    ])
  );

  for (const tup of tuples) {
    for (const query of queries) {
      query.next(tup);
    }
  }

  console.log('Done');
};

// Main entry point
runQueries().catch(err => console.error(err));