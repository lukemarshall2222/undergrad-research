"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.singleGroup = exports.emptyOpRes = void 0;
exports.dump = dump;
exports.dumpAsCsv = dumpAsCsv;
exports.dumpAsWaltzCsv = dumpAsWaltzCsv;
exports.getIpOrZero = getIpOrZero;
exports.metaMeter = metaMeter;
exports.epoch = epoch;
exports.filter = filter;
exports.keyGeqInt = keyGeqInt;
exports.getMappedInt = getMappedInt;
exports.getmappedFloat = getmappedFloat;
exports.map = map;
exports.Grouby = Grouby;
exports.filterGroups = filterGroups;
exports.counter = counter;
exports.sumInts = sumInts;
exports.distinct = distinct;
exports.split = split;
exports.join = join;
exports.continueFlow = continueFlow;
exports.renameFilterKeys = renameFilterKeys;
const fs_1 = require("fs");
const utils_translated_1 = require("./utils-translated");
const ip_address_1 = require("ip-address");
exports.emptyOpRes = { kind: utils_translated_1.opResultKind.Empty, val: null };
function dump(outc, show_reset = false) {
    return {
        next: (headers) => (0, utils_translated_1.dumpPacketHeaders)(outc, headers),
        reset: (headers) => {
            if (show_reset) {
                (0, utils_translated_1.dumpPacketHeaders)(outc, headers);
                outc.write("[reset]\n");
            }
        },
    };
}
function dumpAsCsv(outc, staticField = null, header = true) {
    let first = header;
    return {
        next: (headers) => {
            if (first) {
                staticField !== null ? outc.write(staticField[1]) : null;
                headers.forEach((_, key) => outc.write(`${key},`));
                outc.write("\n");
                first = false;
            }
            staticField !== null ? outc.write(staticField[1]) : null;
            headers.forEach((val, _) => outc.write((0, utils_translated_1.stringOfOpResult)(val)));
            outc.write("\n");
        },
        reset: (_) => null,
    };
}
function dumpAsWaltzCsv(filename) {
    let outc = process.stdout;
    let first = true;
    return {
        next: (headers) => {
            if (first) {
                outc = (0, fs_1.createWriteStream)(filename);
                first = false;
            }
            outc.write(`
                ${(0, utils_translated_1.stringOfOpResult)(headers.get("src_ip") ?? exports.emptyOpRes)},
                ${(0, utils_translated_1.stringOfOpResult)(headers.get("dst_ip") ?? exports.emptyOpRes)},
                ${(0, utils_translated_1.stringOfOpResult)(headers.get("src_l4_port") ?? exports.emptyOpRes)},
                ${(0, utils_translated_1.stringOfOpResult)(headers.get("dst_l4_port") ?? exports.emptyOpRes)} ,
                ${(0, utils_translated_1.stringOfOpResult)(headers.get("packet_count") ?? exports.emptyOpRes)},
                ${(0, utils_translated_1.stringOfOpResult)(headers.get("byte_count") ?? exports.emptyOpRes)},
                ${(0, utils_translated_1.stringOfOpResult)(headers.get("epoch_id") ?? exports.emptyOpRes)}`);
        },
        reset: (_) => null,
    };
}
function getIpOrZero(input) {
    switch (input) {
        case "0":
            return { kind: utils_translated_1.opResultKind.Int, val: 0 };
        default:
            return { kind: utils_translated_1.opResultKind.IPv4, val: new ip_address_1.Address4(input) };
    }
}
function metaMeter(name, outc, staticField = null) {
    return (nextOp) => {
        let epochCount = 0;
        let headersCount = 0;
        return {
            next: (headers) => {
                headersCount++;
                nextOp.next(headers);
            },
            reset: (headers) => {
                outc.write(`${epochCount}, 
                            ${name}, 
                            ${headersCount} 
                            ${staticField !== null ? staticField : ""}`);
                headersCount = 0;
                epochCount++;
                nextOp.reset(headers);
            },
        };
    };
}
function epoch(epochWidth, keyOut) {
    let epochBoundary = 0.0;
    let eid = 0;
    return (nextOp) => {
        return {
            next: (headers) => {
                let time = (0, utils_translated_1.floatOfOpResult)(headers.get("time") ?? exports.emptyOpRes);
                if (epochBoundary === 0.0) {
                    epochBoundary = time + epochWidth;
                }
                else if (time >= epochBoundary) {
                    while (time >= epochBoundary) {
                        nextOp.reset(new Map([[keyOut, { kind: utils_translated_1.opResultKind.Int, val: eid }]]));
                        epochBoundary += epochWidth;
                        eid++;
                    }
                }
                nextOp.next(new Map([[keyOut, { kind: utils_translated_1.opResultKind.Int, val: eid }]]));
            },
            reset: (_) => {
                nextOp.reset(new Map([[keyOut, { kind: utils_translated_1.opResultKind.Int, val: eid }]]));
                epochBoundary = 0.0;
                eid = 0;
            },
        };
    };
}
function filter(f) {
    return (next_op) => {
        return {
            next: (headers) => f(headers) ? next_op.next(headers) : null,
            reset: (headers) => next_op.reset(headers),
        };
    };
}
function keyGeqInt(key, threshold) {
    return (headers) => {
        return ((0, utils_translated_1.intOfOpResult)(headers.get(key) ?? exports.emptyOpRes) >= threshold);
    };
}
function getMappedInt(key, headers) {
    return (0, utils_translated_1.floatOfOpResult)(headers.get(key) ?? exports.emptyOpRes);
}
function getmappedFloat(key, headers) {
    return (0, utils_translated_1.floatOfOpResult)(headers.get(key) ?? exports.emptyOpRes);
}
function map(f) {
    return (next_op) => {
        return {
            next: (headers) => next_op.next(f(headers)),
            reset: (headers) => next_op.reset(headers),
        };
    };
}
function Grouby(groupby, reduce, outKey) {
    let hTble = new Map();
    let resetCounter = 0;
    return (next_op) => {
        return {
            next: (headers) => {
                let groupingKey = groupby(headers);
                const val = hTble.get(groupingKey) ?? exports.emptyOpRes;
                hTble.set(groupingKey, reduce(val, headers));
            },
            reset: (headers) => {
                resetCounter++;
                hTble.forEach((val, groupingKey) => {
                    const unionedHeaders = new Map(groupingKey);
                    headers.forEach((val, key) => unionedHeaders.set(key, val));
                    next_op.next(unionedHeaders.set(outKey, val));
                });
                next_op.reset(headers);
                hTble.clear();
            },
        };
    };
}
function filterGroups(inclKeys) {
    return (headers) => {
        return new Map([...headers].filter(([key, _]) => inclKeys.includes(key)));
    };
}
const singleGroup = (_) => new Map();
exports.singleGroup = singleGroup;
function counter(val, _) {
    switch (val.kind) {
        case utils_translated_1.opResultKind.Empty:
            return { kind: utils_translated_1.opResultKind.Int, val: 1 };
        case utils_translated_1.opResultKind.Int:
            return { kind: utils_translated_1.opResultKind.Int, val: val.val + 1 };
        default:
            return val;
    }
}
function sumInts(searchKey, initVal, headers) {
    switch (initVal.kind) {
        case utils_translated_1.opResultKind.Empty:
            return { kind: utils_translated_1.opResultKind.Int, val: 0 };
        case utils_translated_1.opResultKind.Int:
            if (headers.has(searchKey)) {
                const opRes = headers.get(searchKey);
                return { kind: utils_translated_1.opResultKind.Int, val: opRes.val + initVal.val };
            }
            throw new Error(`'sumVals' function failed to find integer value mapped to ${searchKey}`);
        default:
            return initVal;
    }
}
function distinct(groupby) {
    const hTbl = new Map();
    let resetCounter = 0;
    return (next_op) => {
        return {
            next: (headers) => {
                let groupingKey = groupby(headers);
                hTbl.set(groupingKey, true);
            },
            reset: (headers) => {
                resetCounter++;
                hTbl.forEach((val, key) => {
                    const unionedHeaders = new Map(key);
                    headers.forEach((val, key) => unionedHeaders.set(key, val));
                    next_op.next(unionedHeaders);
                });
                next_op.reset(headers);
                hTbl.clear();
            },
        };
    };
}
function split(l, r) {
    return {
        next: (headers) => {
            l.next(headers);
            r.next(headers);
        },
        reset: (headers) => {
            l.reset(headers);
            r.reset(headers);
        },
    };
}
function join(leftExtractor, rightExtractor, eidKey = "eid") {
    const hTbl1 = new Map();
    const hTbl2 = new Map();
    let leftCurrEpoch = 0;
    let rightCurrEpoch = 0;
    return (next_op) => {
        const handleJoinSide = (currHTbl, otherHTbl, currEpochVal, otherEpochVal, f) => {
            return {
                next: (headers) => {
                    let [key, vals] = f(headers);
                    let currEpoch = getMappedInt(eidKey, headers);
                    while (currEpoch > currEpochVal) {
                        if (otherEpochVal > currEpochVal) {
                            next_op.reset(new Map([
                                [eidKey, { kind: utils_translated_1.opResultKind.Int, val: currEpochVal }],
                            ]));
                        }
                        currEpochVal++;
                    }
                    let newHeaders = new Map(key);
                    newHeaders.set(eidKey, { kind: utils_translated_1.opResultKind.Int, val: currEpochVal });
                    const result = otherHTbl.get(newHeaders);
                    switch (result) {
                        case undefined:
                            currHTbl.set(newHeaders, vals);
                        default:
                            otherHTbl.delete(newHeaders);
                            const unionedHeaders = new Map(result);
                            vals.forEach((val, key) => unionedHeaders.set(key, val));
                            newHeaders.forEach((val, key) => unionedHeaders.set(key, val));
                            next_op.next(unionedHeaders);
                    }
                },
                reset: (headers) => {
                    let currEpoch = getMappedInt(eidKey, headers);
                    while (currEpoch > currEpochVal) {
                        if (otherEpochVal > currEpochVal) {
                            next_op.reset(new Map([
                                [eidKey, { kind: utils_translated_1.opResultKind.Int, val: currEpochVal }],
                            ]));
                            currEpochVal++;
                        }
                    }
                },
            };
        };
        return [
            handleJoinSide(hTbl1, hTbl2, leftCurrEpoch, rightCurrEpoch, leftExtractor),
            handleJoinSide(hTbl2, hTbl1, rightCurrEpoch, leftCurrEpoch, rightExtractor),
        ];
    };
}
function continueFlow() {
    return (nextOp) => ({
        next: (headers) => nextOp.next(headers),
        reset: (headers) => nextOp.reset(headers)
    });
}
function renameFilterKeys(renamingPairs, inHeaders) {
    const newHeaders = new Map(inHeaders);
    renamingPairs.forEach(([oldKey, newKey]) => {
        if (newHeaders.has(oldKey)) {
            newHeaders.set(newKey, newHeaders.get(oldKey));
            newHeaders.delete(oldKey);
        }
    });
    return newHeaders;
}
