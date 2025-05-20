prompt: base prompt

Below is the translation of the provided OCaml code into TypeScript, adhering to TypeScript's natural paradigms and idioms, such as using interfaces, type unions, and functional composition. The code processes network packet data in a stream-like fashion, leveraging TypeScript's type system and modern JavaScript features in a Node.js environment.

```typescript
// Type Definitions
type OpResult =
  | { kind: 'Float'; value: number }
  | { kind: 'Int'; value: number }
  | { kind: 'IPv4'; value: string }
  | { kind: 'MAC'; value: string }
  | { kind: 'Empty' };

type Tuple = Map<string, OpResult>;

interface Operator {
  next: (tup: Tuple) => void;
  reset: (tup: Tuple) => void;
}

type OpCreator = (nextOp: Operator) => Operator;
type DblOpCreator = (op: Operator) => [Operator, Operator];

// Utility Functions
function stringOfMac(buf: string): string {
  return Array.from(buf)
    .map(c => c.charCodeAt(0).toString(16).padStart(2, '0'))
    .join(':');
}

function tcpFlagsToStrings(flags: number): string {
  const tcpFlagsMap = new Map<string, number>([
    ['FIN', 1 << 0], ['SYN', 1 << 1], ['RST', 1 << 2], ['PSH', 1 << 3],
    ['ACK', 1 << 4], ['URG', 1 << 5], ['ECE', 1 << 6], ['CWR', 1 << 7],
  ]);
  return Array.from(tcpFlagsMap.entries())
    .filter(([_, value]) => (flags & value) === value)
    .map(([key]) => key)
    .join('|');
}

function intOfOpResult(input: OpResult): number {
  if (input.kind === 'Int') return input.value;
  throw new Error('Trying to extract int from non-int result');
}

function floatOfOpResult(input: OpResult): number {
  if (input.kind === 'Float') return input.value;
  throw new Error('Trying to extract float from non-float result');
}

function stringOfOpResult(input: OpResult): string {
  switch (input.kind) {
    case 'Float': return input.value.toString();
    case 'Int': return input.value.toString();
    case 'IPv4': return input.value;
    case 'MAC': return stringOfMac(input.value);
    case 'Empty': return 'Empty';
  }
}

function stringOfTuple(inputTuple: Tuple): string {
  let result = '';
  inputTuple.forEach((value, key) => {
    result += `"${key}" => ${stringOfOpResult(value)}, `;
  });
  return result;
}

function dumpTuple(tup: Tuple): void {
  console.log(stringOfTuple(tup));
}

function lookupInt(key: string, tup: Tuple): number {
  const value = tup.get(key);
  if (!value) throw new Error(`Key "${key}" not found in tuple`);
  return intOfOpResult(value);
}

function lookupFloat(key: string, tup: Tuple): number {
  const value = tup.get(key);
  if (!value) throw new Error(`Key "${key}" not found in tuple`);
  return floatOfOpResult(value);
}

// Operator Creators
function dumpTupleOperator(showReset: boolean = false): Operator {
  return {
    next: (tup: Tuple) => dumpTuple(tup),
    reset: (tup: Tuple) => {
      if (showReset) {
        dumpTuple(tup);
        console.log('[reset]');
      }
    },
  };
}

function epoch(epochWidth: number, keyOut: string, nextOp: Operator): Operator {
  let epochBoundary = 0;
  let eid = 0;
  return {
    next: (tup: Tuple) => {
      const time = lookupFloat('time', tup);
      if (epochBoundary === 0) {
        epochBoundary = time + epochWidth;
      } else {
        while (time >= epochBoundary) {
          nextOp.reset(new Map([[keyOut, { kind: 'Int', value: eid }]]));
          epochBoundary += epochWidth;
          eid++;
        }
      }
      const newTup = new Map(tup);
      newTup.set(keyOut, { kind: 'Int', value: eid });
      nextOp.next(newTup);
    },
    reset: (_tup: Tuple) => {
      nextOp.reset(new Map([[keyOut, { kind: 'Int', value: eid }]]));
      epochBoundary = 0;
      eid = 0;
    },
  };
}

function filter(f: (tup: Tuple) => boolean, nextOp: Operator): Operator {
  return {
    next: (tup: Tuple) => { if (f(tup)) nextOp.next(tup); },
    reset: (tup: Tuple) => nextOp.reset(tup),
  };
}

function map(f: (tup: Tuple) => Tuple, nextOp: Operator): Operator {
  return {
    next: (tup: Tuple) => nextOp.next(f(tup)),
    reset: (tup: Tuple) => nextOp.reset(tup),
  };
}

function serializeTuple(tup: Tuple): string {
  const entries = Array.from(tup.entries()).sort((a, b) => a[0].localeCompare(b[0]));
  return JSON.stringify(entries);
}

function groupby(
  groupbyFn: (tup: Tuple) => Tuple,
  reduce: (acc: OpResult, tup: Tuple) => OpResult,
  outKey: string,
  nextOp: Operator
): Operator {
  const hTbl = new Map<string, OpResult>();
  return {
    next: (tup: Tuple) => {
      const groupingKey = groupbyFn(tup);
      const keyStr = serializeTuple(groupingKey);
      const current = hTbl.get(keyStr) || { kind: 'Empty' };
      hTbl.set(keyStr, reduce(current, tup));
    },
    reset: (tup: Tuple) => {
      hTbl.forEach((value, keyStr) => {
        const entries = JSON.parse(keyStr) as [string, OpResult][];
        const groupingKey = new Map(entries);
        const unionedTup = new Map([...tup, ...groupingKey]);
        nextOp.next(new Map([...unionedTup, [outKey, value]]));
      });
      nextOp.reset(tup);
      hTbl.clear();
    },
  };
}

function distinct(groupbyFn: (tup: Tuple) => Tuple, nextOp: Operator): Operator {
  const hTbl = new Map<string, boolean>();
  return {
    next: (tup: Tuple) => {
      const key = serializeTuple(groupbyFn(tup));
      hTbl.set(key, true);
    },
    reset: (tup: Tuple) => {
      hTbl.forEach((_, keyStr) => {
        const entries = JSON.parse(keyStr) as [string, OpResult][];
        const keyTup = new Map(entries);
        nextOp.next(new Map([...tup, ...keyTup]));
      });
      nextOp.reset(tup);
      hTbl.clear();
    },
  };
}

// Query Definitions
const singleGroup = (_tup: Tuple): Tuple => new Map();
const counter = (val_: OpResult, _tup: Tuple): OpResult => {
  if (val_.kind === 'Empty') return { kind: 'Int', value: 1 };
  if (val_.kind === 'Int') return { kind: 'Int', value: val_.value + 1 };
  return val_;
};

function ident(nextOp: Operator): Operator {
  return map((tup: Tuple) => {
    const newTup = new Map(tup);
    newTup.delete('eth.src');
    newTup.delete('eth.dst');
    return newTup;
  }, nextOp);
}

function countPkts(nextOp: Operator): Operator {
  return epoch(1.0, 'eid', groupby(singleGroup, counter, 'pkts', nextOp));
}

// Main Execution
function runQueries(): void {
  const queries: Operator[] = [ident(dumpTupleOperator())];
  const tuples = Array.from({ length: 20 }, (_, i) => {
    const tup = new Map<string, OpResult>();
    tup.set('time', { kind: 'Float', value: 0.000000 + i });
    tup.set('eth.src', { kind: 'MAC', value: '\x00\x11\x22\x33\x44\x55' });
    tup.set('eth.dst', { kind: 'MAC', value: '\xAA\xBB\xCC\xDD\xEE\xFF' });
    tup.set('eth.ethertype', { kind: 'Int', value: 0x0800 });
    tup.set('ipv4.hlen', { kind: 'Int', value: 20 });
    tup.set('ipv4.proto', { kind: 'Int', value: 6 });
    tup.set('ipv4.len', { kind: 'Int', value: 60 });
    tup.set('ipv4.src', { kind: 'IPv4', value: '127.0.0.1' });
    tup.set('ipv4.dst', { kind: 'IPv4', value: '127.0.0.1' });
    tup.set('l4.sport', { kind: 'Int', value: 440 });
    tup.set('l4.dport', { kind: 'Int', value: 50000 });
    tup.set('l4.flags', { kind: 'Int', value: 10 });
    return tup;
  });
  tuples.forEach(tup => queries.forEach(query => query.next(tup)));
  console.log('Done');
}

// Execute
runQueries();
```

prompt: Give the rest of the translation

The request is to provide "the rest of the translation," which, based on the thinking trace, refers to completing the translation of an OCaml codebase into TypeScript. The thinking trace already provides a significant portion of this translation in a file named `streamProcessor.ts`. Since the query asks for "the rest" and the thinking trace contains a detailed implementation, I interpret this as a request to present the complete translated code as a self-contained artifact, assuming the provided code is the intended remainder of the translation. The artifact in the thinking trace appears to be a comprehensive translation, including utility functions, operator creators, and query definitions, culminating in an executable `runQueries` function. Thus, I will provide this full translation as the response, ensuring it is properly formatted and wrapped as requested.

```typescript
// Additional Utility Functions
function filterGroups(inclKeys: string[], tup: Tuple): Tuple {
  const newTup = new Map<string, OpResult>();
  inclKeys.forEach(key => {
    const value = tup.get(key);
    if (value) newTup.set(key, value);
  });
  return newTup;
}

function sumInts(searchKey: string, initVal: OpResult, tup: Tuple): OpResult {
  if (initVal.kind === 'Empty') return { kind: 'Int', value: 0 };
  if (initVal.kind === 'Int') {
    const value = tup.get(searchKey);
    if (value && value.kind === 'Int') {
      return { kind: 'Int', value: initVal.value + value.value };
    }
    throw new Error(`'sumInts' failed to find integer value for "${searchKey}"`);
  }
  return initVal;
}

// Additional Operator Creators
function split(l: Operator, r: Operator): Operator {
  return {
    next: (tup: Tuple) => { l.next(tup); r.next(tup); },
    reset: (tup: Tuple) => { l.reset(tup); r.reset(tup); },
  };
}

type KeyExtractor = (tup: Tuple) => [Tuple, Tuple];

function join(
  leftExtractor: KeyExtractor,
  rightExtractor: KeyExtractor,
  nextOp: Operator
): [Operator, Operator] {
  const hTbl1 = new Map<string, Tuple>();
  const hTbl2 = new Map<string, Tuple>();
  let leftCurrEpoch = 0;
  let rightCurrEpoch = 0;

  function handleJoinSide(
    currHTbl: Map<string, Tuple>,
    otherHTbl: Map<string, Tuple>,
    currEpochRef: { value: number },
    otherEpochRef: { value: number },
    f: KeyExtractor
  ): Operator {
    return {
      next: (tup: Tuple) => {
        const [key, vals] = f(tup);
        const currEpoch = lookupInt('eid', tup);
        while (currEpoch > currEpochRef.value) {
          if (otherEpochRef.value > currEpochRef.value) {
            nextOp.reset(new Map([['eid', { kind: 'Int', value: currEpochRef.value }]]));
          }
          currEpochRef.value++;
        }
        const newTup = new Map([...key, ['eid', { kind: 'Int', value: currEpoch }]]);
        const keyStr = serializeTuple(newTup);
        const otherVal = otherHTbl.get(keyStr);
        if (otherVal) {
          otherHTbl.delete(keyStr);
          const unionedTup = new Map([...newTup, ...vals, ...otherVal]);
          nextOp.next(unionedTup);
        } else {
          currHTbl.set(keyStr, vals);
        }
      },
      reset: (tup: Tuple) => {
        const currEpoch = lookupInt('eid', tup);
        while (currEpoch > currEpochRef.value) {
          if (otherEpochRef.value > currEpochRef.value) {
            nextOp.reset(new Map([['eid', { kind: 'Int', value: currEpochRef.value }]]));
          }
          currEpochRef.value++;
        }
      },
    };
  }

  const leftOp = handleJoinSide(hTbl1, hTbl2, { value: leftCurrEpoch }, { value: rightCurrEpoch }, leftExtractor);
  const rightOp = handleJoinSide(hTbl2, hTbl1, { value: rightCurrEpoch }, { value: leftCurrEpoch }, rightExtractor);
  return [leftOp, rightOp];
}

function renameFilteredKeys(renamings: [string, string][], inTup: Tuple): Tuple {
  const newTup = new Map<string, OpResult>();
  renamings.forEach(([oldKey, newKey]) => {
    const value = inTup.get(oldKey);
    if (value) newTup.set(newKey, value);
  });
  return newTup;
}

// Query Definitions
function pktsPerSrcDst(nextOp: Operator): Operator {
  return epoch(1.0, 'eid', groupby(
    (tup: Tuple) => filterGroups(['ipv4.src', 'ipv4.dst'], tup),
    counter,
    'pkts',
    nextOp
  ));
}

function distinctSrcs(nextOp: Operator): Operator {
  return epoch(1.0, 'eid', distinct(
    (tup: Tuple) => filterGroups(['ipv4.src'], tup),
    groupby(singleGroup, counter, 'srcs', nextOp)
  ));
}

function tcpNewCons(nextOp: Operator): Operator {
  const threshold = 40;
  return epoch(1.0, 'eid', filter(
    (tup: Tuple) => lookupInt('ipv4.proto', tup) === 6 && lookupInt('l4.flags', tup) === 2,
    groupby(
      (tup: Tuple) => filterGroups(['ipv4.dst'], tup),
      counter,
      'cons',
      filter(
        (tup: Tuple) => lookupInt('cons', tup) >= threshold,
        nextOp
      )
    )
  ));
}

function sshBruteForce(nextOp: Operator): Operator {
  const threshold = 40;
  return epoch(1.0, 'eid', filter(
    (tup: Tuple) => lookupInt('ipv4.proto', tup) === 6 && lookupInt('l4.dport', tup) === 22,
    distinct(
      (tup: Tuple) => filterGroups(['ipv4.src', 'ipv4.dst', 'ipv4.len'], tup),
      groupby(
        (tup: Tuple) => filterGroups(['ipv4.dst', 'ipv4.len'], tup),
        counter,
        'srcs',
        filter(
          (tup: Tuple) => lookupInt('srcs', tup) >= threshold,
          nextOp
        )
      )
    )
  ));
}

function superSpreader(nextOp: Operator): Operator {
  const threshold = 40;
  return epoch(1.0, 'eid', distinct(
    (tup: Tuple) => filterGroups(['ipv4.src', 'ipv4.dst'], tup),
    groupby(
      (tup: Tuple) => filterGroups(['ipv4.src'], tup),
      counter,
      'dsts',
      filter(
        (tup: Tuple) => lookupInt('dsts', tup) >= threshold,
        nextOp
      )
    )
  ));
}

function portScan(nextOp: Operator): Operator {
  const threshold = 40;
  return epoch(1.0, 'eid', distinct(
    (tup: Tuple) => filterGroups(['ipv4.src', 'l4.dport'], tup),
    groupby(
      (tup: Tuple) => filterGroups(['ipv4.src'], tup),
      counter,
      'ports',
      filter(
        (tup: Tuple) => lookupInt('ports', tup) >= threshold,
        nextOp
      )
    )
  ));
}

function ddos(nextOp: Operator): Operator {
  const threshold = 45;
  return epoch(1.0, 'eid', distinct(
    (tup: Tuple) => filterGroups(['ipv4.src', 'ipv4.dst'], tup),
    groupby(
      (tup: Tuple) => filterGroups(['ipv4.dst'], tup),
      counter,
      'srcs',
      filter(
        (tup: Tuple) => lookupInt('srcs', tup) >= threshold,
        nextOp
      )
    )
  ));
}

function synFloodSonata(nextOp: Operator): Operator[] {
  const threshold = 3;
  const epochDur = 1.0;

  const syns = (nextOp: Operator) =>
    epoch(epochDur, 'eid', filter(
      (tup: Tuple) => lookupInt('ipv4.proto', tup) === 6 && lookupInt('l4.flags', tup) === 2,
      groupby(
        (tup: Tuple) => filterGroups(['ipv4.dst'], tup),
        counter,
        'syns',
        nextOp
      )
    ));

  const synacks = (nextOp: Operator) =>
    epoch(epochDur, 'eid', filter(
      (tup: Tuple) => lookupInt('ipv4.proto', tup) === 6 && lookupInt('l4.flags', tup) === 18,
      groupby(
        (tup: Tuple) => filterGroups(['ipv4.src'], tup),
        counter,
        'synacks',
        nextOp
      )
    ));

  const acks = (nextOp: Operator) =>
    epoch(epochDur, 'eid', filter(
      (tup: Tuple) => lookupInt('ipv4.proto', tup) === 6 && lookupInt('l4.flags', tup) === 16,
      groupby(
        (tup: Tuple) => filterGroups(['ipv4.dst'], tup),
        counter,
        'acks',
        nextOp
      )
    ));

  const [joinOp1, joinOp2] = join(
    (tup: Tuple) => [
      filterGroups(['host'], tup),
      filterGroups(['syns+synacks'], tup)
    ],
    (tup: Tuple) => [
      renameFilteredKeys([['ipv4.dst', 'host']], tup),
      filterGroups(['acks'], tup)
    ],
    map(
      (tup: Tuple) => {
        const newTup = new Map(tup);
        newTup.set('syns+synacks-acks', {
          kind: 'Int',
          value: lookupInt('syns+synacks', tup) - lookupInt('acks', tup)
        });
        return newTup;
      },
      filter(
        (tup: Tuple) => lookupInt('syns+synacks-acks', tup) >= threshold,
        nextOp
      )
    )
  );

  const [joinOp3, joinOp4] = join(
    (tup: Tuple) => [
      renameFilteredKeys([['ipv4.dst', 'host']], tup),
      filterGroups(['syns'], tup)
    ],
    (tup: Tuple) => [
      renameFilteredKeys([['ipv4.src', 'host']], tup),
      filterGroups(['synacks'], tup)
    ],
    map(
      (tup: Tuple) => {
        const newTup = new Map(tup);
        newTup.set('syns+synacks', {
          kind: 'Int',
          value: lookupInt('syns', tup) + lookupInt('synacks', tup)
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

  const syns = (nextOp: Operator) =>
    epoch(epochDur, 'eid', filter(
      (tup: Tuple) => lookupInt('ipv4.proto', tup) === 6 && lookupInt('l4.flags', tup) === 2,
      groupby(
        (tup: Tuple) => filterGroups(['ipv4.dst'], tup),
        counter,
        'syns',
        nextOp
      )
    ));

  const fins = (nextOp: Operator) =>
    epoch(epochDur, 'eid', filter(
      (tup: Tuple) => lookupInt('ipv4.proto', tup) === 6 && (lookupInt('l4.flags', tup) & 1) === 1,
      groupby(
        (tup: Tuple) => filterGroups(['ipv4.src'], tup),
        counter,
        'fins',
        nextOp
      )
    ));

  const [op1, op2] = join(
    (tup: Tuple) => [
      renameFilteredKeys([['ipv4.dst', 'host']], tup),
      filterGroups(['syns'], tup)
    ],
    (tup: Tuple) => [
      renameFilteredKeys([['ipv4.src', 'host']], tup),
      filterGroups(['fins'], tup)
    ],
    map(
      (tup: Tuple) => {
        const newTup = new Map(tup);
        newTup.set('diff', {
          kind: 'Int',
          value: lookupInt('syns', tup) - lookupInt('fins', tup)
        });
        return newTup;
      },
      filter(
        (tup: Tuple) => lookupInt('diff', tup) >= threshold,
        nextOp
      )
    )
  );

  return [syns(op1), fins(op2)];
}

function slowloris(nextOp: Operator): Operator[] {
  const t1 = 5;
  const t2 = 500;
  const t3 = 90;
  const epochDur = 1.0;

  const nConns = (nextOp: Operator) =>
    epoch(epochDur, 'eid', filter(
      (tup: Tuple) => lookupInt('ipv4.proto', tup) === 6,
      distinct(
        (tup: Tuple) => filterGroups(['ipv4.src', 'ipv4.dst', 'l4.sport'], tup),
        groupby(
          (tup: Tuple) => filterGroups(['ipv4.dst'], tup),
          counter,
          'n_conns',
          filter(
            (tup: Tuple) => lookupInt('n_conns', tup) >= t1,
            nextOp
          )
        )
      )
    ));

  const nBytes = (nextOp: Operator) =>
    epoch(epochDur, 'eid', filter(
      (tup: Tuple) => lookupInt('ipv4.proto', tup) === 6,
      groupby(
        (tup: Tuple) => filterGroups(['ipv4.dst'], tup),
        (acc, tup) => sumInts('ipv4.len', acc, tup),
        'n_bytes',
        filter(
          (tup: Tuple) => lookupInt('n_bytes', tup) >= t2,
          nextOp
        )
      )
    ));

  const [op1, op2] = join(
    (tup: Tuple) => [
      filterGroups(['ipv4.dst'], tup),
      filterGroups(['n_conns'], tup)
    ],
    (tup: Tuple) => [
      filterGroups(['ipv4.dst'], tup),
      filterGroups(['n_bytes'], tup)
    ],
    map(
      (tup: Tuple) => {
        const newTup = new Map(tup);
        newTup.set('bytes_per_conn', {
          kind: 'Int',
          value: Math.floor(lookupInt('n_bytes', tup) / lookupInt('n_conns', tup))
        });
        return newTup;
      },
      filter(
        (tup: Tuple) => lookupInt('bytes_per_conn', tup) <= t3,
        nextOp
      )
    )
  );

  return [nConns(op1), nBytes(op2)];
}

function joinTest(nextOp: Operator): Operator[] {
  const epochDur = 1.0;

  const syns = (nextOp: Operator) =>
    epoch(epochDur, 'eid', filter(
      (tup: Tuple) => lookupInt('ipv4.proto', tup) === 6 && lookupInt('l4.flags', tup) === 2,
      nextOp
    ));

  const synacks = (nextOp: Operator) =>
    epoch(epochDur, 'eid', filter(
      (tup: Tuple) => lookupInt('ipv4.proto', tup) === 6 && lookupInt('l4.flags', tup) === 18,
      nextOp
    ));

  const [op1, op2] = join(
    (tup: Tuple) => [
      renameFilteredKeys([['ipv4.src', 'host']], tup),
      renameFilteredKeys([['ipv4.dst', 'remote']], tup)
    ],
    (tup: Tuple) => [
      renameFilteredKeys([['ipv4.dst', 'host']], tup),
      filterGroups(['time'], tup)
    ],
    nextOp
  );

  return [syns(op1), synacks(op2)];
}

function q3(nextOp: Operator): Operator {
  return epoch(100.0, 'eid', distinct(
    (tup: Tuple) => filterGroups(['ipv4.src', 'ipv4.dst'], tup),
    nextOp
  ));
}

function q4(nextOp: Operator): Operator {
  return epoch(10000.0, 'eid', groupby(
    (tup: Tuple) => filterGroups(['ipv4.dst'], tup),
    counter,
    'pkts',
    nextOp
  ));
}

// Execute Queries
function runQueries(): void {
  const queries: Operator[] = [ident(dumpTupleOperator())];
  const tuples = Array.from({ length: 20 }, (_, i) => {
    const tup = new Map<string, OpResult>();
    tup.set('time', { kind: 'Float', value: 0.000000 + i });
    tup.set('eth.src', { kind: 'MAC', value: '\x00\x11\x22\x33\x44\x55' });
    tup.set('eth.dst', { kind: 'MAC', value: '\xAA\xBB\xCC\xDD\xEE\xFF' });
    tup.set('eth.ethertype', { kind: 'Int', value: 0x0800 });
    tup.set('ipv4.hlen', { kind: 'Int', value: 20 });
    tup.set('ipv4.proto', { kind: 'Int', value: 6 });
    tup.set('ipv4.len', { kind: 'Int', value: 60 });
    tup.set('ipv4.src', { kind: 'IPv4', value: '127.0.0.1' });
    tup.set('ipv4.dst', { kind: 'IPv4', value: '127.0.0.1' });
    tup.set('l4.sport', { kind: 'Int', value: 440 });
    tup.set('l4.dport', { kind: 'Int', value: 50000 });
    tup.set('l4.flags', { kind: 'Int', value: 10 });
    return tup;
  });
  tuples.forEach(tup => queries.forEach(query => query.next(tup)));
  console.log('Done');
}

// Execute
runQueries();
```