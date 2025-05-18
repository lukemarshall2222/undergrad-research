// Imports (TypeScript doesn't have direct equivalents for some OCaml libraries)
import * as crypto from 'crypto';

// Utility type for representing different result types
type OpResult = 
    | { type: 'Float', value: number }
    | { type: 'Int', value: number }
    | { type: 'IPv4', value: string }
    | { type: 'MAC', value: Buffer }
    | { type: 'Empty' }

// Type for a tuple (Map equivalent)
type Tuple = Map<string, OpResult>;

// Operator type 
interface Operator {
    next: (tup: Tuple) => void;
    reset: (tup: Tuple) => void;
}

// Utility functions
function stringOfMac(buf: Buffer): string {
    return Array.from(buf).map(b => b.toString(16).padStart(2, '0')).join(':');
}

function tcpFlagsToStrings(flags: number): string {
    const flagMap: [string, number][] = [
        ['FIN', 1 << 0],
        ['SYN', 1 << 1],
        ['RST', 1 << 2],
        ['PSH', 1 << 3],
        ['ACK', 1 << 4],
        ['URG', 1 << 5],
        ['ECE', 1 << 6],
        ['CWR', 1 << 7]
    ];

    return flagMap
        .filter(([_, value]) => (flags & value) === value)
        .map(([key, _]) => key)
        .join('|');
}

function intOfOpResult(input: OpResult): number {
    if (input.type === 'Int') return input.value;
    throw new Error('Trying to extract int from non-int result');
}

function floatOfOpResult(input: OpResult): number {
    if (input.type === 'Float') return input.value;
    throw new Error('Trying to extract float from non-float result');
}

function stringOfOpResult(input: OpResult): string {
    switch (input.type) {
        case 'Float': return input.value.toString();
        case 'Int': return input.value.toString();
        case 'IPv4': return input.value;
        case 'MAC': return stringOfMac(input.value);
        case 'Empty': return 'Empty';
    }
}

function stringOfTuple(inputTuple: Tuple): string {
    let result = '';
    for (const [key, value] of inputTuple.entries()) {
        result += `"${key}" => ${stringOfOpResult(value)}, `;
    }
    return result;
}

function tupleOfList(tupList: [string, OpResult][]): Tuple {
    return new Map(tupList);
}

function lookupInt(key: string, tup: Tuple): number {
    const result = tup.get(key);
    if (!result) throw new Error(`Key ${key} not found`);
    return intOfOpResult(result);
}

function lookupFloat(key: string, tup: Tuple): number {
    const result = tup.get(key);
    if (!result) throw new Error(`Key ${key} not found`);
    return floatOfOpResult(result);
}

// Example operator implementations (for brevity, not all will be translated)
function dumpTuple(outCh: NodeJS.WriteStream, showReset = false): Operator {
    return {
        next: (tup: Tuple) => {
            outCh.write(stringOfTuple(tup) + '\n');
        },
        reset: (tup: Tuple) => {
            if (showReset) {
                outCh.write(stringOfTuple(tup) + '\n');
                outCh.write('[reset]\n');
            }
        }
    };
}

// Continuing from previous translation...

// Grouping and filtering functions
function filterGroups(inclKeys: string[], tup: Tuple): Tuple {
    const filteredTup = new Map<string, OpResult>();
    for (const [key, value] of tup.entries()) {
        if (inclKeys.includes(key)) {
            filteredTup.set(key, value);
        }
    }
    return filteredTup;
}

function singleGroup(_tup: Tuple): Tuple {
    return new Map<string, OpResult>();
}

// Reduction functions
function counter(val: OpResult, _tup: Tuple): OpResult {
    switch (val.type) {
        case 'Empty': return { type: 'Int', value: 1 };
        case 'Int': return { type: 'Int', value: val.value + 1 };
        default: return val;
    }
}

function sumInts(searchKey: string, initVal: OpResult, tup: Tuple): OpResult {
    switch (initVal.type) {
        case 'Empty': return { type: 'Int', value: 0 };
        case 'Int': {
            const foundVal = tup.get(searchKey);
            if (foundVal?.type === 'Int') {
                return { type: 'Int', value: foundVal.value + initVal.value };
            }
            throw new Error(`Failed to find integer value for key "${searchKey}"`);
        }
        default: return initVal;
    }
}

// Filtering functions
function filter(f: (tup: Tuple) => boolean, nextOp: Operator): Operator {
    return {
        next: (tup: Tuple) => {
            if (f(tup)) nextOp.next(tup);
        },
        reset: (tup: Tuple) => {
            nextOp.reset(tup);
        }
    };
}

function keyGeqInt(key: string, threshold: number, tup: Tuple): boolean {
    return lookupInt(key, tup) >= threshold;
}

// Mapping function
function mapOperator(f: (tup: Tuple) => Tuple, nextOp: Operator): Operator {
    return {
        next: (tup: Tuple) => {
            nextOp.next(f(tup));
        },
        reset: (tup: Tuple) => {
            nextOp.reset(tup);
        }
    };
}

// Distinct operator
function distinct(groupby: (tup: Tuple) => Tuple, nextOp: Operator): Operator {
    const seenKeys = new Set<string>();
    
    return {
        next: (tup: Tuple) => {
            const groupingKey = groupby(tup);
            const keyStr = JSON.stringify(Array.from(groupingKey.entries()));
            
            if (!seenKeys.has(keyStr)) {
                seenKeys.add(keyStr);
                nextOp.next(tup);
            }
        },
        reset: (tup: Tuple) => {
            seenKeys.clear();
            nextOp.reset(tup);
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

// Groupby operator (simplified)
function groupby(
    groupbyFunc: (tup: Tuple) => Tuple, 
    reduceFunc: (val: OpResult, tup: Tuple) => OpResult, 
    outKey: string, 
    nextOp: Operator
): Operator {
    const groups = new Map<string, OpResult>();

    return {
        next: (tup: Tuple) => {
            const groupingKey = groupbyFunc(tup);
            const keyStr = JSON.stringify(Array.from(groupingKey.entries()));

            const existingVal = groups.get(keyStr) || { type: 'Empty' };
            groups.set(keyStr, reduceFunc(existingVal, tup));
        },
        reset: (tup: Tuple) => {
            for (const [keyStr, val] of groups.entries()) {
                const groupingKey = JSON.parse(keyStr);
                const mergedTup = new Map(tup);
                
                for (const [key, value] of groupingKey) {
                    mergedTup.set(key, value);
                }
                
                mergedTup.set(outKey, val);
                nextOp.next(mergedTup);
            }
            
            nextOp.reset(tup);
            groups.clear();
        }
    };
}

// Join operator (simplified)
function join(
    leftExtractor: (tup: Tuple) => [Tuple, Tuple],
    rightExtractor: (tup: Tuple) => [Tuple, Tuple],
    nextOp: Operator,
    eidKey = 'eid'
): [Operator, Operator] {
    const leftTable = new Map<string, Tuple>();
    const rightTable = new Map<string, Tuple>();
    let leftEpoch = 0;
    let rightEpoch = 0;

    const handleJoinSide = (
        currTable: Map<string, Tuple>, 
        otherTable: Map<string, Tuple>, 
        currEpochRef: { value: number }, 
        otherEpochRef: { value: number }, 
        extractor: (tup: Tuple) => [Tuple, Tuple]
    ): Operator => {
        return {
            next: (tup: Tuple) => {
                const [key, vals] = extractor(tup);
                const currEpoch = lookupInt(eidKey, tup);

                while (currEpoch > currEpochRef.value) {
                    if (otherEpochRef.value > currEpochRef.value) {
                        nextOp.reset(new Map([[eidKey, { type: 'Int', value: currEpochRef.value }]]));
                    }
                    currEpochRef.value++;
                }

                const newTup = new Map(key);
                newTup.set(eidKey, { type: 'Int', value: currEpoch });

                const newTupStr = JSON.stringify(Array.from(newTup.entries()));
                const matchingTup = otherTable.get(newTupStr);

                if (matchingTup) {
                    otherTable.delete(newTupStr);
                    const mergedTup = new Map(newTup);
                    
                    for (const [k, v] of matchingTup.entries()) {
                        mergedTup.set(k, v);
                    }
                    for (const [k, v] of vals.entries()) {
                        mergedTup.set(k, v);
                    }

                    nextOp.next(mergedTup);
                } else {
                    currTable.set(newTupStr, vals);
                }
            },
            reset: (tup: Tuple) => {
                const currEpoch = lookupInt(eidKey, tup);
                
                while (currEpoch > currEpochRef.value) {
                    if (otherEpochRef.value > currEpochRef.value) {
                        nextOp.reset(new Map([[eidKey, { type: 'Int', value: currEpochRef.value }]]));
                    }
                    currEpochRef.value++;
                }
            }
        };
    };

    const leftOperator = handleJoinSide(
        leftTable, 
        rightTable, 
        { value: leftEpoch }, 
        { value: rightEpoch }, 
        leftExtractor
    );

    const rightOperator = handleJoinSide(
        rightTable, 
        leftTable, 
        { value: rightEpoch }, 
        { value: leftEpoch }, 
        rightExtractor
    );

    return [leftOperator, rightOperator];
}

// Some example query implementations
function identOperator(nextOp: Operator): Operator {
    return mapOperator(tup => {
        const filteredTup = new Map(tup);
        filteredTup.delete('eth.src');
        filteredTup.delete('eth.dst');
        return filteredTup;
    }, nextOp);
}

function countPkts(nextOp: Operator): Operator {
    return epoch(1.0, 'eid', 
        groupby(singleGroup, counter, 'pkts', nextOp)
    );
}

function pktsPerSrcDst(nextOp: Operator): Operator {
    return epoch(1.0, 'eid', 
        groupby(
            tup => filterGroups(['ipv4.src', 'ipv4.dst'], tup), 
            counter, 
            'pkts', 
            nextOp
        )
    );
}

function epoch(epochWidth: number, keyOut: string, nextOp: Operator): Operator {
    let epochBoundary = 0;
    let eid = 0;

    return {
        next: (tup: Tuple) => {
            const time = floatOfOpResult(tup.get('time')!);

            if (epochBoundary === 0) {
                epochBoundary = time + epochWidth;
            } else if (time >= epochBoundary) {
                while (time >= epochBoundary) {
                    nextOp.reset(new Map([[keyOut, { type: 'Int', value: eid }]]));
                    epochBoundary += epochWidth;
                    eid++;
                }
            }

            const newTup = new Map(tup);
            newTup.set(keyOut, { type: 'Int', value: eid });
            nextOp.next(newTup);
        },
        reset: () => {
            nextOp.reset(new Map([[keyOut, { type: 'Int', value: eid }]]));
            epochBoundary = 0;
            eid = 0;
        }
    };
}

// Continuation of previous TypeScript translation

// More advanced query implementations
function distinctSrcs(nextOp: Operator): Operator {
    return epoch(1.0, 'eid', 
        distinct(
            tup => filterGroups(['ipv4.src'], tup),
            groupby(singleGroup, counter, 'srcs', nextOp)
        )
    );
}

function tcpNewCons(nextOp: Operator): Operator {
    const threshold = 40;
    return epoch(1.0, 'eid', 
        filter(
            tup => 
                lookupInt('ipv4.proto', tup) === 6 && 
                lookupInt('l4.flags', tup) === 2,
            groupby(
                tup => filterGroups(['ipv4.dst'], tup), 
                counter, 
                'cons', 
                filter(
                    tup => lookupInt('cons', tup) >= threshold, 
                    nextOp
                )
            )
        )
    );
}

function sshBruteForce(nextOp: Operator): Operator {
    const threshold = 40;
    return epoch(1.0, 'eid', 
        filter(
            tup => 
                lookupInt('ipv4.proto', tup) === 6 && 
                lookupInt('l4.dport', tup) === 22,
            distinct(
                tup => filterGroups(['ipv4.src', 'ipv4.dst', 'ipv4.len'], tup),
                groupby(
                    tup => filterGroups(['ipv4.dst', 'ipv4.len'], tup), 
                    counter, 
                    'srcs', 
                    filter(
                        tup => lookupInt('srcs', tup) >= threshold, 
                        nextOp
                    )
                )
            )
        )
    );
}

function superSpreader(nextOp: Operator): Operator {
    const threshold = 40;
    return epoch(1.0, 'eid', 
        distinct(
            tup => filterGroups(['ipv4.src', 'ipv4.dst'], tup),
            groupby(
                tup => filterGroups(['ipv4.src'], tup), 
                counter, 
                'dsts', 
                filter(
                    tup => lookupInt('dsts', tup) >= threshold, 
                    nextOp
                )
            )
        )
    );
}

function portScan(nextOp: Operator): Operator {
    const threshold = 40;
    return epoch(1.0, 'eid', 
        distinct(
            tup => filterGroups(['ipv4.src', 'l4.dport'], tup),
            groupby(
                tup => filterGroups(['ipv4.src'], tup), 
                counter, 
                'ports', 
                filter(
                    tup => lookupInt('ports', tup) >= threshold, 
                    nextOp
                )
            )
        )
    );
}

function ddos(nextOp: Operator): Operator {
    const threshold = 45;
    return epoch(1.0, 'eid', 
        distinct(
            tup => filterGroups(['ipv4.src', 'ipv4.dst'], tup),
            groupby(
                tup => filterGroups(['ipv4.dst'], tup), 
                counter, 
                'srcs', 
                filter(
                    tup => lookupInt('srcs', tup) >= threshold, 
                    nextOp
                )
            )
        )
    );
}

function synFloodSonata(nextOp: Operator): Operator[] {
    const threshold = 3;
    const epochDur = 1.0;

    function syns(innerNextOp: Operator): Operator {
        return epoch(epochDur, 'eid', 
            filter(
                tup => 
                    lookupInt('ipv4.proto', tup) === 6 && 
                    lookupInt('l4.flags', tup) === 2,
                groupby(
                    tup => filterGroups(['ipv4.dst'], tup), 
                    counter, 
                    'syns', 
                    innerNextOp
                )
            )
        );
    }

    function synacks(innerNextOp: Operator): Operator {
        return epoch(epochDur, 'eid', 
            filter(
                tup => 
                    lookupInt('ipv4.proto', tup) === 6 && 
                    lookupInt('l4.flags', tup) === 18,
                groupby(
                    tup => filterGroups(['ipv4.src'], tup), 
                    counter, 
                    'synacks', 
                    innerNextOp
                )
            )
        );
    }

    function acks(innerNextOp: Operator): Operator {
        return epoch(epochDur, 'eid', 
            filter(
                tup => 
                    lookupInt('ipv4.proto', tup) === 6 && 
                    lookupInt('l4.flags', tup) === 16,
                groupby(
                    tup => filterGroups(['ipv4.dst'], tup), 
                    counter, 
                    'acks', 
                    innerNextOp
                )
            )
        );
    }

    // Complex join operations
    const [joinOp1, joinOp2] = join(
        tup => [
            filterGroups(['host'], tup), 
            filterGroups(['syns+synacks'], tup)
        ],
        tup => [
            new Map([['host', tup.get('ipv4.dst')!]]), 
            filterGroups(['acks'], tup)
        ],
        mapOperator(
            tup => {
                const synsTotal = lookupInt('syns+synacks', tup);
                const acksTotal = lookupInt('acks', tup);
                tup.set('syns+synacks-acks', { type: 'Int', value: synsTotal - acksTotal });
                return tup;
            },
            filter(
                tup => lookupInt('syns+synacks-acks', tup) >= threshold, 
                nextOp
            )
        )
    );

    const [joinOp3, joinOp4] = join(
        tup => [
            new Map([['host', tup.get('ipv4.dst')!]]), 
            filterGroups(['syns'], tup)
        ],
        tup => [
            new Map([['host', tup.get('ipv4.src')!]]), 
            filterGroups(['synacks'], tup)
        ],
        mapOperator(
            tup => {
                const synsTotal = lookupInt('syns', tup);
                const synacksTotal = lookupInt('synacks', tup);
                tup.set('syns+synacks', { type: 'Int', value: synsTotal + synacksTotal });
                return tup;
            },
            joinOp1
        )
    );

    return [
        syns(joinOp3),
        synacks(joinOp4),
        acks(joinOp2)
    ];
}// Continuing the previous TypeScript implementation

function completedFlows(nextOp: Operator): Operator[] {
    const threshold = 1;
    const epochDur = 30.0;

    function syns(innerNextOp: Operator): Operator {
        return epoch(epochDur, 'eid', 
            filter(
                tup => 
                    lookupInt('ipv4.proto', tup) === 6 && 
                    lookupInt('l4.flags', tup) === 2,
                groupby(
                    tup => filterGroups(['ipv4.dst'], tup), 
                    counter, 
                    'syns', 
                    innerNextOp
                )
            )
        );
    }

    function fins(innerNextOp: Operator): Operator {
        return epoch(epochDur, 'eid', 
            filter(
                tup => 
                    lookupInt('ipv4.proto', tup) === 6 && 
                    (lookupInt('l4.flags', tup) & 1) === 1,
                groupby(
                    tup => filterGroups(['ipv4.src'], tup), 
                    counter, 
                    'fins', 
                    innerNextOp
                )
            )
        );
    }

    const [op1, op2] = join(
        tup => [
            new Map([['host', tup.get('ipv4.dst')!]]), 
            filterGroups(['syns'], tup)
        ],
        tup => [
            new Map([['host', tup.get('ipv4.src')!]]), 
            filterGroups(['fins'], tup)
        ],
        mapOperator(
            tup => {
                const synsTotal = lookupInt('syns', tup);
                const finsTotal = lookupInt('fins', tup);
                tup.set('diff', { type: 'Int', value: synsTotal - finsTotal });
                return tup;
            },
            filter(
                tup => lookupInt('diff', tup) >= threshold, 
                nextOp
            )
        )
    );

    return [
        syns(op1),
        fins(op2)
    ];
}

function slowloris(nextOp: Operator): Operator[] {
    const t1 = 5;    // minimum number of connections
    const t2 = 500;  // minimum total bytes
    const t3 = 90;   // maximum bytes per connection
    const epochDur = 1.0;

    function nConns(innerNextOp: Operator): Operator {
        return epoch(epochDur, 'eid', 
            filter(
                tup => lookupInt('ipv4.proto', tup) === 6,
                distinct(
                    tup => filterGroups(['ipv4.src', 'ipv4.dst', 'l4.sport'], tup),
                    groupby(
                        tup => filterGroups(['ipv4.dst'], tup), 
                        counter, 
                        'n_conns', 
                        filter(
                            tup => lookupInt('n_conns', tup) >= t1, 
                            innerNextOp
                        )
                    )
                )
            )
        );
    }

    function nBytes(innerNextOp: Operator): Operator {
        return epoch(epochDur, 'eid', 
            filter(
                tup => lookupInt('ipv4.proto', tup) === 6,
                groupby(
                    tup => filterGroups(['ipv4.dst'], tup), 
                    (val, tup) => sumInts('ipv4.len', val, tup), 
                    'n_bytes', 
                    filter(
                        tup => lookupInt('n_bytes', tup) >= t2, 
                        innerNextOp
                    )
                )
            )
        );
    }

    const [op1, op2] = join(
        tup => [
            filterGroups(['ipv4.dst'], tup), 
            filterGroups(['n_conns'], tup)
        ],
        tup => [
            filterGroups(['ipv4.dst'], tup), 
            filterGroups(['n_bytes'], tup)
        ],
        mapOperator(
            tup => {
                const nConnsTotal = lookupInt('n_conns', tup);
                const nBytesTotal = lookupInt('n_bytes', tup);
                tup.set('bytes_per_conn', { 
                    type: 'Int', 
                    value: Math.floor(nBytesTotal / nConnsTotal) 
                });
                return tup;
            },
            filter(
                tup => lookupInt('bytes_per_conn', tup) <= t3, 
                nextOp
            )
        )
    );

    return [
        nConns(op1),
        nBytes(op2)
    ];
}

function joinTest(nextOp: Operator): Operator[] {
    const epochDur = 1.0;

    function syns(innerNextOp: Operator): Operator {
        return epoch(epochDur, 'eid', 
            filter(
                tup => 
                    lookupInt('ipv4.proto', tup) === 6 && 
                    lookupInt('l4.flags', tup) === 2,
                innerNextOp
            )
        );
    }

    function synacks(innerNextOp: Operator): Operator {
        return epoch(epochDur, 'eid', 
            filter(
                tup => 
                    lookupInt('ipv4.proto', tup) === 6 && 
                    lookupInt('l4.flags', tup) === 18,
                innerNextOp
            )
        );
    }

    const [op1, op2] = join(
        tup => [
            new Map([['host', tup.get('ipv4.src')!]]), 
            new Map([['remote', tup.get('ipv4.dst')!]])
        ],
        tup => [
            new Map([['host', tup.get('ipv4.dst')!]]), 
            filterGroups(['time'], tup)
        ],
        nextOp
    );

    return [
        syns(op1),
        synacks(op2)
    ];
}

function q3(nextOp: Operator): Operator {
    return epoch(100.0, 'eid', 
        distinct(
            tup => filterGroups(['ipv4.src', 'ipv4.dst'], tup), 
            nextOp
        )
    );
}

function q4(nextOp: Operator): Operator {
    return epoch(10000.0, 'eid', 
        groupby(
            tup => filterGroups(['ipv4.dst'], tup), 
            counter, 
            'pkts', 
            nextOp
        )
    );
}

function generateSampleTuples(count: number): Tuple[] {
    return Array.from({ length: count }, (_, i): Tuple => {
        const tup = new Map<string, OpResult>();
        
        tup.set('time', { type: 'Float', value: i });
        tup.set('eth.src', { 
            type: 'MAC', 
            value: Buffer.from([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]) 
        });
        tup.set('eth.dst', { 
            type: 'MAC', 
            value: Buffer.from([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]) 
        });
        tup.set('eth.ethertype', { type: 'Int', value: 0x0800 });
        
        tup.set('ipv4.hlen', { type: 'Int', value: 20 });
        tup.set('ipv4.proto', { type: 'Int', value: 6 });
        tup.set('ipv4.len', { type: 'Int', value: 60 });
        tup.set('ipv4.src', { type: 'IPv4', value: '127.0.0.1' });
        tup.set('ipv4.dst', { type: 'IPv4', value: '127.0.0.1' });
        
        tup.set('l4.sport', { type: 'Int', value: 440 });
        tup.set('l4.dport', { type: 'Int', value: 50000 });
        tup.set('l4.flags', { type: 'Int', value: 10 });
        
        return tup;
    });
}

// Comprehensive query runner
function runAllQueries() {
    const operators: Operator[] = [
        // Simple operators
        identOperator(dumpTuple(process.stdout)),
        countPkts(dumpTuple(process.stdout)),
        pktsPerSrcDst(dumpTuple(process.stdout)),
        
        // Detection queries
        tcpNewCons(dumpTuple(process.stdout)),
        sshBruteForce(dumpTuple(process.stdout)),
        superSpreader(dumpTuple(process.stdout)),
        portScan(dumpTuple(process.stdout)),
        ddos(dumpTuple(process.stdout)),
        
        // Advanced detection queries
        ...synFloodSonata(dumpTuple(process.stdout)),
        ...completedFlows(dumpTuple(process.stdout)),
        ...slowloris(dumpTuple(process.stdout)),
        ...joinTest(dumpTuple(process.stdout)),
        
        // Specific queries
        q3(dumpTuple(process.stdout)),
        q4(dumpTuple(process.stdout))
    ];

    const tuples = generateSampleTuples(5);  // Increased sample size

    tuples.forEach(tup => {
        operators.forEach(op => op.next(tup));
    });

    // Final reset for all operators
    tuples.forEach(tup => {
        operators.forEach(op => op.reset(tup));
    });
}

// Run the comprehensive query set
runAllQueries();