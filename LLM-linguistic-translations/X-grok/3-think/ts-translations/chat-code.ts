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