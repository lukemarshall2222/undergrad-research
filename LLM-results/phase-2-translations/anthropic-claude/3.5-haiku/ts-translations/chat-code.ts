// Imports (TypeScript doesn't have direct equivalents for some OCaml libraries)
import * as crypto from 'crypto';

// Utility type for representing different result types
type OpResult = 
    | { type: 'Float', value: number }
    | { type: 'Int', value: number }
    | { type: 'IPv4', value: string }
    | { type: 'MAC', value: Buffer }
    | { type: 'Empty' };

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

// Main runner (similar to previous implementation)
function runQueries() {
    const queries: Operator[] = [identOperator(dumpTuple(process.stdout))];
    
    const tuples: Tuple[] = Array.from({ length: 20 }, (_, i) => {
        const tup = new Map<string, OpResult>();
        
        // Populate tuple with sample data (same as previous implementation)
        tup.set('time', { type: 'Float', value: i });
        tup.set('eth.src', { type: 'MAC', value: Buffer.from([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]) });
        tup.set('eth.dst', { type: 'MAC', value: Buffer.from([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]) });
        tup.set('eth.ethertype', { type: 'Int', value: 0x0800 });
        
        return tup;
    });

    tuples.forEach(tup => {
        queries.forEach(query => query.next(tup));
    });
}

runQueries();
