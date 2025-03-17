import { Writable} from 'stream';
import {createWriteStream } from 'fs';
import { dblOpCreator, dumpPacketHeaders, floatOfOpResult, intOfOpResult, opCreator, Operator, opResult, opResultKind, PacketHeaders, stringOfOpResult } from './utils-translated';
import { Address4 } from 'ip-address';

export const emptyOpRes: opResult = { kind: opResultKind.Empty, val: null };

export function createDumpOperator(outc: Writable, show_reset: boolean=false) : Operator {
    return {
        next: (headers: PacketHeaders) => dumpPacketHeaders(outc, headers),
        reset: (headers: PacketHeaders) => {if (show_reset) {
                                                dumpPacketHeaders(outc, headers);
                                                outc.write("[reset]\n")
                                            }}}
}

export function dumpAsCsv(outc: Writable, staticField: [string, string] | null=null, 
            header: boolean=true) : Operator {
    let first: boolean = header;
    return {
        next: (headers: PacketHeaders) => {
            if (first) {
                staticField !== null 
                    ? outc.write(staticField[1]) 
                    : null;
                headers.forEach((_: opResult, key: string) => outc.write(`${key},`));
                outc.write("\n");
                first = false;
            }
            staticField !== null 
                ? outc.write(staticField[1]) 
                : null;
            headers.forEach((val: opResult, _: string) => outc.write(stringOfOpResult(val)));
            outc.write("\n");
        },
        reset: (_: PacketHeaders) => null
    }
}

export function dumpWaltsCsv(filename: string) : Operator {
    let outc: Writable = process.stdout;
    let first: boolean = true;
    return {
        next: (headers: PacketHeaders) => {
            if (first) {
                outc = createWriteStream(filename);
                first = false;
            }
            outc.write(`
                ${stringOfOpResult(headers.get("src_ip") ?? emptyOpRes)},
                ${stringOfOpResult(headers.get("dst_ip") ?? emptyOpRes)},
                ${stringOfOpResult(headers.get("src_l4_port") ?? emptyOpRes)},
                ${stringOfOpResult(headers.get("dst_l4_port") ?? emptyOpRes)} ,
                ${stringOfOpResult(headers.get("packet_count") ?? emptyOpRes)},
                ${stringOfOpResult(headers.get("byte_count") ?? emptyOpRes)},
                ${stringOfOpResult(headers.get("epoch_id") ?? emptyOpRes)}`)
        },
        reset: (_: PacketHeaders) => null
    }
}

export function getIpOrZero(input: string) : opResult {
    switch (input) {
        case "0":
            return {kind: opResultKind.Int, val: 0};
        default:
            return { kind: opResultKind.IPv4, 
                     val: new Address4(input)
                   }
    }
}

export function createMetaMeter(name: string, outc: Writable, 
            staticField: string | null=null) : opCreator {
    return (nextOp: Operator) => {
        let epochCount: number = 0;
        let headersCount: number = 0;
        return {
            next: (headers: PacketHeaders) => {
                headersCount++;
                nextOp.next(headers);
            },
            reset: (headers: PacketHeaders) => {
                outc.write(`${epochCount}, 
                            ${name}, 
                            ${headersCount} 
                            ${staticField !== null 
                                ? staticField 
                                : ""}`
                            );
                headersCount = 0;
                epochCount++;
                nextOp.reset(headers);
            }
        }
    }
}

export function createEpochOperator(epochWidth: number, keyOut: string) : opCreator {
    let epochBoundary: number = 0.0
    let eid: number = 0;
    return (nextOp: Operator) => {
        return {
            next: (headers: PacketHeaders) => {
                let time: number = floatOfOpResult((headers.get("time") ?? emptyOpRes)) as number
                if (epochBoundary === 0.0) {
                    epochBoundary = time + epochWidth;
                } else if (time >= epochBoundary) {
                    while (time >= epochBoundary) {
                        nextOp.reset(new Map([[keyOut, {kind: opResultKind.Int, val: eid}]]));
                        epochBoundary += epochWidth;
                        eid++;
                    }
                }
                nextOp.next(new Map([[keyOut, {kind: opResultKind.Int, val: eid}]]));
            },
            reset: (_: PacketHeaders) => {
                nextOp.reset(new Map([[keyOut, {kind: opResultKind.Int, val: eid}]]));
                epochBoundary = 0.0;
                eid = 0;
            }
        }
    }
}

export function createFilterOperator(f: (headers: PacketHeaders) => boolean) : opCreator {
    return (next_op: Operator) => {
        return {
            next: (headers: PacketHeaders) => f(headers) ? next_op.next(headers) : null,
            reset: (headers: PacketHeaders) => next_op.reset(headers)
        }
    }
}

export function keyGeqInt(key: string, threshold: number) : (headers: PacketHeaders) => boolean {
    return (headers: PacketHeaders) => {
        return (intOfOpResult(headers.get(key) ?? emptyOpRes) as number) >= threshold;
    }
}

export function getMappedInt(key: string, headers: PacketHeaders) : number {
    return floatOfOpResult(headers.get(key) ?? emptyOpRes) as number;
}

export function getmappedFloat(key: string, headers: PacketHeaders) : number {
    return floatOfOpResult(headers.get(key) ?? emptyOpRes) as number;
}

export function createMapOperator(f: (headers: PacketHeaders) => PacketHeaders) : opCreator {
    return (next_op: Operator) => {
        return {
            next: (headers: PacketHeaders) => next_op.next(f(headers)),
            reset: (headers: PacketHeaders) => next_op.reset(headers)
        }
    }
}

export type groupingFunc = (headers: PacketHeaders) => PacketHeaders;
export type reductionFunc = (opRes: opResult, headers: PacketHeaders) => opResult;

export function createGroubyOperator(groupby: groupingFunc, reduce: reductionFunc, 
            outKey: string ) : opCreator {
    let hTble: Map<PacketHeaders, opResult> = new Map<PacketHeaders, opResult>();
    let resetCounter: number = 0;
    return (next_op: Operator) => {
        return {
            next: (headers: PacketHeaders) => {
                let groupingKey: PacketHeaders = groupby(headers);
                const val: opResult = hTble.get(groupingKey) ?? emptyOpRes;
                hTble.set(groupingKey, reduce(emptyOpRes, headers));
            },
            reset: (headers: PacketHeaders) => {
                resetCounter++;
                hTble.forEach((val: opResult, groupingKey: PacketHeaders) => {
                    const unionedHeaders: Map<string, opResult> = new Map(groupingKey);
                    headers.forEach((val, key) => unionedHeaders.set(key, val));
                    next_op.next(unionedHeaders.set(outKey, val));
                })
                next_op.reset(headers);
                hTble.clear();
            }
        }
    }
}

export function filterGroups(inclKeys: string[]) : (headers: PacketHeaders) => PacketHeaders {
    return (headers: PacketHeaders) => {
        return new Map([...headers]
                .filter(([key, _]: [string, opResult]) => 
                    inclKeys.includes(key)));
    }
}

export const singleGroup = (_: PacketHeaders) : PacketHeaders => new Map<string, opResult>();

export function counter(val: opResult, _: PacketHeaders) : opResult {
    switch (val.kind) {
        case opResultKind.Empty:
            return { kind: opResultKind.Int, val: 1 };
        case opResultKind.Int:
            return { kind: opResultKind.Int, val: val.val+1 };
        default:
            return val;
    }
}

export function sumInts(searchKey: string, initVal: opResult, headers: PacketHeaders) : opResult {
    switch (initVal.kind) {
        case opResultKind.Empty:
            return { kind: opResultKind.Int, val: 0 };
        case opResultKind.Int:
            if (headers.has(searchKey)) {
                const opRes: opResult = headers.get(searchKey)!;
                return { kind: opResultKind.Int, val: <number>opRes.val+initVal.val }
            }
            throw new Error(`'sumVals' function failed to find integer value mapped to ${searchKey}`);
        default:
            return initVal;     
    }
}

export function createDistinctOperator(groupby: groupingFunc) : opCreator {
    const hTbl: Map<PacketHeaders, boolean> = new Map<PacketHeaders, boolean>();
    let resetCounter = 0;
    return (next_op: Operator) => {
        return {
            next: (headers: PacketHeaders) => {
                let groupingKey: PacketHeaders = groupby(headers);
                hTbl.set(groupingKey, true);
            },
            reset: (headers: PacketHeaders) => {
                resetCounter++;
                hTbl.forEach((val: boolean, key: PacketHeaders) => {
                    const unionedHeaders: PacketHeaders = new Map(key);
                    headers.forEach((val: opResult, key: string) => unionedHeaders.set(key, val));
                    next_op.next(unionedHeaders);
                })
                next_op.reset(headers);
                hTbl.clear();
            }
        }
    }
}

export function createSplitOperator(l: Operator, r: Operator) : Operator {
    return {
        next: (headers: PacketHeaders) => {
            l.next(headers);
            r.next(headers);
        },
        reset: (headers: PacketHeaders) => {
            l.reset(headers);
            r.reset(headers);
        }
    }
}

export type keyExtractor = (headers: PacketHeaders) => [PacketHeaders, PacketHeaders];

export function createJoinOperator(leftExtractor: keyExtractor, rightExtractor: keyExtractor, 
            eidKey: string="eid") : dblOpCreator {
    const hTbl1: Map<PacketHeaders, PacketHeaders> = new Map<PacketHeaders, PacketHeaders>();
    const hTbl2: Map<PacketHeaders, PacketHeaders> = new Map<PacketHeaders, PacketHeaders>();
    let leftCurrEpoch: number = 0;
    let rightCurrEpoch: number = 0;
    return (next_op: Operator) => {
        const handleJoinSide = (currHTbl: Map<PacketHeaders, PacketHeaders>, 
            otherHTbl: Map<PacketHeaders, PacketHeaders>, currEpochVal: number, 
            otherEpochVal: number, f: keyExtractor) : Operator => {
                return {
                    next: (headers: PacketHeaders) => {
                        let [key, vals]: [PacketHeaders, PacketHeaders] = f(headers);
                        let currEpoch: number = getMappedInt(eidKey, headers);
                        while (currEpoch > currEpochVal) {
                            if (otherEpochVal > currEpochVal) {
                                next_op.reset(new Map([[eidKey, 
                                                { kind: opResultKind.Int, 
                                                val: currEpochVal 
                                                }]]))
                            }
                            currEpochVal++;
                        }
                        let newHeaders: PacketHeaders = new Map(key);
                        newHeaders.set(eidKey, { kind: opResultKind.Int, 
                                                val: currEpochVal 
                                            });
                        const result: PacketHeaders | undefined = otherHTbl.get(newHeaders);
                        switch (result) {
                            case undefined:
                                currHTbl.set(newHeaders, vals);
                            default:
                                otherHTbl.delete(newHeaders);
                                const unionedHeaders: PacketHeaders = new Map(result);
                                vals.forEach((val: opResult, key: string) => 
                                        unionedHeaders.set(key, val));
                                newHeaders.forEach((val: opResult, key: string) => 
                                        unionedHeaders.set(key, val));
                                next_op.next(unionedHeaders);
                        }                                    
                    },
                    reset: (headers: PacketHeaders) => {
                        let currEpoch: number = getMappedInt(eidKey, headers);
                        while (currEpoch > currEpochVal) {
                            if (otherEpochVal > currEpochVal) {
                                next_op.reset(new Map([[eidKey, 
                                                        { kind: opResultKind.Int, 
                                                        val: currEpochVal 
                                                        }]]));
                                currEpochVal++;
                            }
                        }
                    }
                }
        }
        return [ handleJoinSide(hTbl1, hTbl2, leftCurrEpoch, rightCurrEpoch, leftExtractor),
                handleJoinSide(hTbl2, hTbl1, rightCurrEpoch, leftCurrEpoch, rightExtractor)
            ];
    }
}

export function renameFilterKeys(renamingPairs: [string, string][], inHeaders: PacketHeaders) 
            : PacketHeaders {
    const newHeaders: PacketHeaders = new Map(inHeaders);
    renamingPairs.forEach(([oldKey, newKey]: [string, string]) => {
        if (newHeaders.has(oldKey)) {
            newHeaders.set(newKey, newHeaders.get(oldKey)!);
            newHeaders.delete(oldKey);
        }
    });
    return newHeaders
}

