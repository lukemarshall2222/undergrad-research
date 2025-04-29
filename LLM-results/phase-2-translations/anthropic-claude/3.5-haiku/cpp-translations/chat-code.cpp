#include <iostream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <variant>
#include <vector>
#include <functional>
#include <memory>
#include <optional>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <fstream>

// Previous OpResult and Tuple classes remain the same

// Utility functions
class Utils {
public:
    // Conversion utilities
    static std::string stringOfMac(const std::vector<uint8_t>& buf) {
        std::stringstream ss;
        for (size_t i = 0; i < buf.size(); ++i) {
            ss << std::hex << std::setw(2) << std::setfill('0') 
               << static_cast<int>(buf[i]);
            if (i < buf.size() - 1) ss << ":";
        }
        return ss.str();
    }

    // TCP flags to string conversion
    static std::string tcpFlagsToStrings(int flags) {
        std::vector<std::pair<std::string, int>> flagMap = {
            {"FIN", 1 << 0},
            {"SYN", 1 << 1},
            {"RST", 1 << 2},
            {"PSH", 1 << 3},
            {"ACK", 1 << 4},
            {"URG", 1 << 5},
            {"ECE", 1 << 6},
            {"CWR", 1 << 7}
        };

        std::vector<std::string> activatedFlags;
        for (const auto& [key, value] : flagMap) {
            if ((flags & value) == value) {
                activatedFlags.push_back(key);
            }
        }

        return activatedFlags.empty() ? "" : 
            std::accumulate(
                std::next(activatedFlags.begin()), 
                activatedFlags.end(), 
                activatedFlags.front(),
                [](const std::string& a, const std::string& b) { 
                    return a + "|" + b; 
                }
            );
    }

    // Type conversion and extraction utilities
    static int intOfOpResult(const OpResult& input) {
        if (!input.isInt()) 
            throw std::runtime_error("Trying to extract int from non-int result");
        return input.asInt();
    }

    static float floatOfOpResult(const OpResult& input) {
        if (!input.isFloat()) 
            throw std::runtime_error("Trying to extract float from non-float result");
        return input.asFloat();
    }
};

// Operator creation and manipulation utilities
class OperatorUtils {
public:
    // Right-associative chaining operator (simplified)
    static Operator chain(std::function<Operator(Operator)> opCreatorFunc, 
                          const Operator& nextOp) {
        return opCreatorFunc(nextOp);
    }

    // Filtering utility
    static Operator filter(std::function<bool(const Tuple&)> predicate, 
                           const Operator& nextOp) {
        return {
            [=](const Tuple& tup) {
                if (predicate(tup)) {
                    nextOp.next(tup);
                }
            },
            [=](const Tuple& tup) {
                nextOp.reset(tup);
            }
        };
    }

    // Mapping utility
    static Operator map(std::function<Tuple(const Tuple&)> mapFunc, 
                        const Operator& nextOp) {
        return {
            [=](const Tuple& tup) {
                nextOp.next(mapFunc(tup));
            },
            [=](const Tuple& tup) {
                nextOp.reset(tup);
            }
        };
    }

    // Epoch-based operator
    static Operator epoch(float epochWidth, const std::string& keyOut, 
                          const Operator& nextOp) {
        struct EpochState {
            float epochBoundary = 0.0;
            int eid = 0;
        };
        
        auto state = std::make_shared<EpochState>();

        return {
            [=](const Tuple& tup) {
                float time = Utils::floatOfOpResult(tup.find("time"));
                
                if (state->epochBoundary == 0.0) {
                    state->epochBoundary = time + epochWidth;
                }
                else if (time >= state->epochBoundary) {
                    while (time >= state->epochBoundary) {
                        Tuple resetTup;
                        resetTup.add(keyOut, OpResult(state->eid));
                        nextOp.reset(resetTup);
                        
                        state->epochBoundary += epochWidth;
                        state->eid++;
                    }
                }

                Tuple newTup = tup;
                newTup.add(keyOut, OpResult(state->eid));
                nextOp.next(newTup);
            },
            [=](const Tuple& tup) {
                Tuple resetTup;
                resetTup.add(keyOut, OpResult(state->eid));
                nextOp.reset(resetTup);
                
                state->epochBoundary = 0.0;
                state->eid = 0;
            }
        };
    }

    // Groupby operator (simplified)
    static Operator groupby(
        std::function<Tuple(const Tuple&)> groupingFunc,
        std::function<OpResult(const OpResult&, const Tuple&)> reduceFunc,
        const std::string& outKey,
        const Operator& nextOp) 
    {
        auto groupTable = std::make_shared<std::unordered_map<std::string, OpResult>>();
        
        return {
            [=](const Tuple& tup) {
                Tuple groupingKey = groupingFunc(tup);
                std::string keyStr = groupingKey.toString();

                auto it = groupTable->find(keyStr);
                if (it != groupTable->end()) {
                    (*groupTable)[keyStr] = reduceFunc(it->second, tup);
                } else {
                    (*groupTable)[keyStr] = reduceFunc(OpResult(), tup);
                }
            },
            [=](const Tuple& tup) {
                for (const auto& [groupKey, val] : *groupTable) {
                    Tuple mergedTup = tup;
                    // Add group key and reduced value
                    mergedTup.add(outKey, val);
                    nextOp.next(mergedTup);
                }
                nextOp.reset(tup);
                groupTable->clear();
            }
        };
    }

    // Common reduction functions
    static OpResult counter(const OpResult& val, const Tuple& tup) {
        if (val.isEmpty()) return OpResult(1);
        if (val.isInt()) return OpResult(val.asInt() + 1);
        return val;
    }

    static OpResult sumInts(const std::string& searchKey) {
        return [=](const OpResult& initVal, const Tuple& tup) {
            if (initVal.isEmpty()) return OpResult(0);
            if (initVal.isInt()) {
                auto searchResult = tup.findOpt(searchKey);
                if (searchResult && searchResult->isInt()) {
                    return OpResult(initVal.asInt() + searchResult->asInt());
                }
            }
            return initVal;
        };
    }
};

// Dump utilities
class DumpUtils {
public:
    // Dump tuple to stdout or file
    static Operator dumpTuple(std::ostream& out, bool showReset = false) {
        return {
            [&](const Tuple& tup) {
                out << tup.toString() << std::endl;
            },
            [&](const Tuple& tup) {
                if (showReset) {
                    out << tup.toString() << std::endl;
                    out << "[reset]" << std::endl;
                }
            }
        };
    }

    // Dump as CSV
    static Operator dumpAsCsv(std::ostream& out, 
                               std::optional<std::pair<std::string, std::string>> staticField = std::nullopt, 
                               bool header = true) {
        static bool first = true;
        
        return {
            [&](const Tuple& tup) {
                if (first) {
                    if (staticField) {
                        out << staticField->first << ",";
                    }
                    for (const auto& [key, _] : tup.getData()) {
                        out << key << ",";
                    }
                    out << std::endl;
                    first = false;
                }

                if (staticField) {
                    out << staticField->second << ",";
                }
                for (const auto& [_, value] : tup.getData()) {
                    out << value.toString() << ",";
                }
                out << std::endl;
            },
            [](const Tuple&) {}
        };
    }
};

// Additional Utility Classes and Functions
class NetworkQueries {
    public:
        // Utility for creating network-related queries
    
        // TCP New Connections Query
        static Operator tcpNewCons(const Operator& nextOp, int threshold = 40) {
            return OperatorUtils::chain(
                [threshold](const Operator& op) {
                    return OperatorUtils::epoch(1.0, "eid", 
                        OperatorUtils::filter(
                            [](const Tuple& tup) {
                                return (Utils::intOfOpResult(tup.find("ipv4.proto")) == 6 &&
                                        Utils::intOfOpResult(tup.find("l4.flags")) == 2);
                            },
                            OperatorUtils::groupby(
                                [](const Tuple& tup) {
                                    Tuple groupKey;
                                    groupKey.add("ipv4.dst", tup.find("ipv4.dst"));
                                    return groupKey;
                                },
                                OperatorUtils::counter,
                                "cons",
                                OperatorUtils::filter(
                                    [threshold](const Tuple& tup) {
                                        return Utils::intOfOpResult(tup.find("cons")) >= threshold;
                                    },
                                    op
                                )
                            )
                        )
                    );
                },
                nextOp
            );
        }
    
        // SSH Brute Force Query
        static Operator sshBruteForce(const Operator& nextOp, int threshold = 40) {
            return OperatorUtils::chain(
                [threshold](const Operator& op) {
                    return OperatorUtils::epoch(1.0, "eid", 
                        OperatorUtils::filter(
                            [](const Tuple& tup) {
                                return (Utils::intOfOpResult(tup.find("ipv4.proto")) == 6 &&
                                        Utils::intOfOpResult(tup.find("l4.dport")) == 22);
                            },
                            OperatorUtils::distinct(
                                [](const Tuple& tup) {
                                    Tuple groupKey;
                                    groupKey.add("ipv4.src", tup.find("ipv4.src"));
                                    groupKey.add("ipv4.dst", tup.find("ipv4.dst"));
                                    groupKey.add("ipv4.len", tup.find("ipv4.len"));
                                    return groupKey;
                                },
                                OperatorUtils::groupby(
                                    [](const Tuple& tup) {
                                        Tuple groupKey;
                                        groupKey.add("ipv4.dst", tup.find("ipv4.dst"));
                                        groupKey.add("ipv4.len", tup.find("ipv4.len"));
                                        return groupKey;
                                    },
                                    OperatorUtils::counter,
                                    "srcs",
                                    OperatorUtils::filter(
                                        [threshold](const Tuple& tup) {
                                            return Utils::intOfOpResult(tup.find("srcs")) >= threshold;
                                        },
                                        op
                                    )
                                )
                            )
                        )
                    );
                },
                nextOp
            );
        }
    
        // Join Operator (Complex implementation)
        static std::pair<Operator, Operator> join(
            std::function<std::pair<Tuple, Tuple>(const Tuple&)> leftExtractor,
            std::function<std::pair<Tuple, Tuple>(const Tuple&)> rightExtractor,
            const Operator& nextOp,
            const std::string& eidKey = "eid"
        ) {
            auto leftTable = std::make_shared<std::unordered_map<std::string, Tuple>>();
            auto rightTable = std::make_shared<std::unordered_map<std::string, Tuple>>();
            auto leftCurrEpoch = std::make_shared<int>(0);
            auto rightCurrEpoch = std::make_shared<int>(0);
    
            auto handleJoinSide = [&](
                std::shared_ptr<std::unordered_map<std::string, Tuple>> currTable,
                std::shared_ptr<std::unordered_map<std::string, Tuple>> otherTable,
                std::shared_ptr<int> currEpochRef,
                std::shared_ptr<int> otherEpochRef,
                std::function<std::pair<Tuple, Tuple>(const Tuple&)> extractor
            ) {
                return Operator{
                    [=](const Tuple& tup) {
                        auto [key, vals] = extractor(tup);
                        int currEpoch = Utils::intOfOpResult(tup.find(eidKey));
    
                        // Advance epochs
                        while (currEpoch > *currEpochRef) {
                            if (*otherEpochRef > *currEpochRef) {
                                Tuple resetTup;
                                resetTup.add(eidKey, OpResult(*currEpochRef));
                                nextOp.reset(resetTup);
                            }
                            (*currEpochRef)++;
                        }
    
                        Tuple newTup = key;
                        newTup.add(eidKey, OpResult(currEpoch));
    
                        auto otherIt = otherTable->find(newTup.toString());
                        if (otherIt != otherTable->end()) {
                            // Merge tuples
                            Tuple mergedTup = newTup;
                            for (const auto& [k, v] : otherIt->second.getData()) {
                                mergedTup.add(k, v);
                            }
                            for (const auto& [k, v] : vals.getData()) {
                                mergedTup.add(k, v);
                            }
                            
                            otherTable->erase(otherIt);
                            nextOp.next(mergedTup);
                        } else {
                            currTable->emplace(newTup.toString(), vals);
                        }
                    },
                    [=](const Tuple& tup) {
                        int currEpoch = Utils::intOfOpResult(tup.find(eidKey));
                        
                        // Advance epochs
                        while (currEpoch > *currEpochRef) {
                            if (*otherEpochRef > *currEpochRef) {
                                Tuple resetTup;
                                resetTup.add(eidKey, OpResult(*currEpochRef));
                                nextOp.reset(resetTup);
                            }
                            (*currEpochRef)++;
                        }
                    }
                };
            };
    
            return {
                handleJoinSide(leftTable, rightTable, leftCurrEpoch, rightCurrEpoch, leftExtractor),
                handleJoinSide(rightTable, leftTable, rightCurrEpoch, leftCurrEpoch, rightExtractor)
            };
        }
    
        // Distinct Operator
        static Operator distinct(
            std::function<Tuple(const Tuple&)> groupby,
            const Operator& nextOp
        ) {
            auto seenKeys = std::make_shared<std::unordered_set<std::string>>();
            
            return {
                [=](const Tuple& tup) {
                    Tuple groupKey = groupby(tup);
                    std::string keyStr = groupKey.toString();
                    
                    if (seenKeys->find(keyStr) == seenKeys->end()) {
                        seenKeys->insert(keyStr);
                    }
                },
                [=](const Tuple& tup) {
                    for (const auto& keyStr : *seenKeys) {
                        // You might want to reconstruct the original tuple here
                        nextOp.next(tup);
                    }
                    nextOp.reset(tup);
                    seenKeys->clear();
                }
            };
        }
    };
    
    // Query Runner
    class QueryRunner {
    public:
        static void runQueries(const std::vector<Tuple>& tuples, 
                                const std::vector<Operator>& queries) {
            for (const auto& tup : tuples) {
                for (const auto& query : queries) {
                    query.next(tup);
                }
            }
        }
    
        // Utility to generate sample tuples
        static std::vector<Tuple> generateSampleTuples(int count) {
            std::vector<Tuple> tuples;
            
            for (int i = 0; i < count; ++i) {
                Tuple tup;
                
                // Time
                tup.add("time", OpResult(static_cast<float>(i)));
                
                // Ethernet details
                std::vector<uint8_t> srcMac = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
                std::vector<uint8_t> dstMac = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
                tup.add("eth.src", OpResult(srcMac));
                tup.add("eth.dst", OpResult(dstMac));
                tup.add("eth.ethertype", OpResult(0x0800));
                
                // IPv4 details
                tup.add("ipv4.hlen", OpResult(20));
                tup.add("ipv4.proto", OpResult(6));
                tup.add("ipv4.len", OpResult(60));
                tup.add("ipv4.src", OpResult(std::string("127.0.0.1")));
                tup.add("ipv4.dst", OpResult(std::string("127.0.0.1")));
                
                // Layer 4 details
                tup.add("l4.sport", OpResult(440));
                tup.add("l4.dport", OpResult(50000));
                tup.add("l4.flags", OpResult(10));
                
                tuples.push_back(tup);
            }
            
            return tuples;
        }
    };

// Additional Network Queries and Specialized Operators
class AdvancedNetworkQueries {
public:
    // Super Spreader Query
    static Operator superSpreader(const Operator& nextOp, int threshold = 40) {
        return OperatorUtils::chain(
            [threshold](const Operator& op) {
                return OperatorUtils::epoch(1.0, "eid", 
                    NetworkQueries::distinct(
                        [](const Tuple& tup) {
                            Tuple groupKey;
                            groupKey.add("ipv4.src", tup.find("ipv4.src"));
                            groupKey.add("ipv4.dst", tup.find("ipv4.dst"));
                            return groupKey;
                        },
                        OperatorUtils::groupby(
                            [](const Tuple& tup) {
                                Tuple groupKey;
                                groupKey.add("ipv4.src", tup.find("ipv4.src"));
                                return groupKey;
                            },
                            OperatorUtils::counter,
                            "dsts",
                            OperatorUtils::filter(
                                [threshold](const Tuple& tup) {
                                    return Utils::intOfOpResult(tup.find("dsts")) >= threshold;
                                },
                                op
                            )
                        )
                    )
                );
            },
            nextOp
        );
    }

    // Port Scan Query
    static Operator portScan(const Operator& nextOp, int threshold = 40) {
        return OperatorUtils::chain(
            [threshold](const Operator& op) {
                return OperatorUtils::epoch(1.0, "eid", 
                    NetworkQueries::distinct(
                        [](const Tuple& tup) {
                            Tuple groupKey;
                            groupKey.add("ipv4.src", tup.find("ipv4.src"));
                            groupKey.add("l4.dport", tup.find("l4.dport"));
                            return groupKey;
                        },
                        OperatorUtils::groupby(
                            [](const Tuple& tup) {
                                Tuple groupKey;
                                groupKey.add("ipv4.src", tup.find("ipv4.src"));
                                return groupKey;
                            },
                            OperatorUtils::counter,
                            "ports",
                            OperatorUtils::filter(
                                [threshold](const Tuple& tup) {
                                    return Utils::intOfOpResult(tup.find("ports")) >= threshold;
                                },
                                op
                            )
                        )
                    )
                );
            },
            nextOp
        );
    }

    // DDoS Detection Query
    static Operator ddosDetection(const Operator& nextOp, int threshold = 45) {
        return OperatorUtils::chain(
            [threshold](const Operator& op) {
                return OperatorUtils::epoch(1.0, "eid", 
                    NetworkQueries::distinct(
                        [](const Tuple& tup) {
                            Tuple groupKey;
                            groupKey.add("ipv4.src", tup.find("ipv4.src"));
                            groupKey.add("ipv4.dst", tup.find("ipv4.dst"));
                            return groupKey;
                        },
                        OperatorUtils::groupby(
                            [](const Tuple& tup) {
                                Tuple groupKey;
                                groupKey.add("ipv4.dst", tup.find("ipv4.dst"));
                                return groupKey;
                            },
                            OperatorUtils::counter,
                            "srcs",
                            OperatorUtils::filter(
                                [threshold](const Tuple& tup) {
                                    return Utils::intOfOpResult(tup.find("srcs")) >= threshold;
                                },
                                op
                            )
                        )
                    )
                );
            },
            nextOp
        );
    }

    // Syn Flood Detection (Complex Multi-Operator Query)
    static std::vector<Operator> synFloodDetection(const Operator& nextOp, 
                                                    int threshold = 3, 
                                                    float epochDur = 1.0) {
        // Helper function to create SYN packet filter
        auto synFilter = [](const Tuple& tup) {
            return (Utils::intOfOpResult(tup.find("ipv4.proto")) == 6 &&
                    Utils::intOfOpResult(tup.find("l4.flags")) == 2);
        };

        // Helper function to create SYN-ACK packet filter
        auto synAckFilter = [](const Tuple& tup) {
            return (Utils::intOfOpResult(tup.find("ipv4.proto")) == 6 &&
                    Utils::intOfOpResult(tup.find("l4.flags")) == 18);
        };

        // Helper function to create ACK packet filter
        auto ackFilter = [](const Tuple& tup) {
            return (Utils::intOfOpResult(tup.find("ipv4.proto")) == 6 &&
                    Utils::intOfOpResult(tup.find("l4.flags")) == 16);
        };

        // SYN packets operator
        auto synsOp = OperatorUtils::chain(
            [=](const Operator& op) {
                return OperatorUtils::epoch(epochDur, "eid", 
                    OperatorUtils::filter(
                        synFilter,
                        OperatorUtils::groupby(
                            [](const Tuple& tup) {
                                Tuple groupKey;
                                groupKey.add("ipv4.dst", tup.find("ipv4.dst"));
                                return groupKey;
                            },
                            OperatorUtils::counter,
                            "syns",
                            op
                        )
                    )
                );
            },
            nextOp
        );

        // SYN-ACK packets operator
        auto synAcksOp = OperatorUtils::chain(
            [=](const Operator& op) {
                return OperatorUtils::epoch(epochDur, "eid", 
                    OperatorUtils::filter(
                        synAckFilter,
                        OperatorUtils::groupby(
                            [](const Tuple& tup) {
                                Tuple groupKey;
                                groupKey.add("ipv4.src", tup.find("ipv4.src"));
                                return groupKey;
                            },
                            OperatorUtils::counter,
                            "synacks",
                            op
                        )
                    )
                );
            },
            nextOp
        );

        // ACK packets operator
        auto acksOp = OperatorUtils::chain(
            [=](const Operator& op) {
                return OperatorUtils::epoch(epochDur, "eid", 
                    OperatorUtils::filter(
                        ackFilter,
                        OperatorUtils::groupby(
                            [](const Tuple& tup) {
                                Tuple groupKey;
                                groupKey.add("ipv4.dst", tup.find("ipv4.dst"));
                                return groupKey;
                            },
                            OperatorUtils::counter,
                            "acks",
                            op
                        )
                    )
                );
            },
            nextOp
        );

        // Complex join operators would follow here
        // This is a simplified version of the join logic

        return {synsOp, synAcksOp, acksOp};
    }

    // Completed Flows Detection
    static std::vector<Operator> completedFlowsDetection(
        const Operator& nextOp, 
        int threshold = 1, 
        float epochDur = 30.0
    ) {
        // Similar structure to synFloodDetection
        auto synsOp = OperatorUtils::chain(
            [=](const Operator& op) {
                return OperatorUtils::epoch(epochDur, "eid", 
                    OperatorUtils::filter(
                        [](const Tuple& tup) {
                            return (Utils::intOfOpResult(tup.find("ipv4.proto")) == 6 &&
                                    Utils::intOfOpResult(tup.find("l4.flags")) == 2);
                        },
                        OperatorUtils::groupby(
                            [](const Tuple& tup) {
                                Tuple groupKey;
                                groupKey.add("ipv4.dst", tup.find("ipv4.dst"));
                                return groupKey;
                            },
                            OperatorUtils::counter,
                            "syns",
                            op
                        )
                    )
                );
            },
            nextOp
        );

        auto finsOp = OperatorUtils::chain(
            [=](const Operator& op) {
                return OperatorUtils::epoch(epochDur, "eid", 
                    OperatorUtils::filter(
                        [](const Tuple& tup) {
                            return (Utils::intOfOpResult(tup.find("ipv4.proto")) == 6 &&
                                    (Utils::intOfOpResult(tup.find("l4.flags")) & 1) == 1);
                        },
                        OperatorUtils::groupby(
                            [](const Tuple& tup) {
                                Tuple groupKey;
                                groupKey.add("ipv4.src", tup.find("ipv4.src"));
                                return groupKey;
                            },
                            OperatorUtils::counter,
                            "fins",
                            op
                        )
                    )
                );
            },
            nextOp
        );

        return {synsOp, finsOp};
    }

    // Slowloris Attack Detection
    static std::vector<Operator> slowlorisDetection(
        const Operator& nextOp, 
        int t1 = 5,     // Min number of connections
        int t2 = 500,   // Min total bytes
        int t3 = 90,    // Max bytes per connection
        float epochDur = 1.0
    ) {
        auto nConnsOp = OperatorUtils::chain(
            [=](const Operator& op) {
                return OperatorUtils::epoch(epochDur, "eid", 
                    OperatorUtils::filter(
                        [](const Tuple& tup) {
                            return Utils::intOfOpResult(tup.find("ipv4.proto")) == 6;
                        },
                        NetworkQueries::distinct(
                            [](const Tuple& tup) {
                                Tuple groupKey;
                                groupKey.add("ipv4.src", tup.find("ipv4.src"));
                                groupKey.add("ipv4.dst", tup.find("ipv4.dst"));
                                groupKey.add("l4.sport", tup.find("l4.sport"));
                                return groupKey;
                            },
                            OperatorUtils::groupby(
                                [](const Tuple& tup) {
                                    Tuple groupKey;
                                    groupKey.add("ipv4.dst", tup.find("ipv4.dst"));
                                    return groupKey;
                                },
                                OperatorUtils::counter,
                                "n_conns",
                                OperatorUtils::filter(
                                    [t1](const Tuple& tup) {
                                        return Utils::intOfOpResult(tup.find("n_conns")) >= t1;
                                    },
                                    op
                                )
                            )
                        )
                    )
                );
            },
            nextOp
        );

        auto nBytesOp = OperatorUtils::chain(
            [=](const Operator& op) {
                return OperatorUtils::epoch(epochDur, "eid", 
                    OperatorUtils::filter(
                        [](const Tuple& tup) {
                            return Utils::intOfOpResult(tup.find("ipv4.proto")) == 6;
                        },
                        OperatorUtils::groupby(
                            [](const Tuple& tup) {
                                Tuple groupKey;
                                groupKey.add("ipv4.dst", tup.find("ipv4.dst"));
                                return groupKey;
                            },
                            OperatorUtils::sumInts("ipv4.len"),
                            "n_bytes",
                            OperatorUtils::filter(
                                [t2](const Tuple& tup) {
                                    return Utils::intOfOpResult(tup.find("n_bytes")) >= t2;
                                },
                                op
                            )
                        )
                    )
                );
            },
            nextOp
        );

        return {nConnsOp, nBytesOp};
    }
};

// Updated Main Function with More Comprehensive Query Examples
int main() {
    // Generate sample tuples
    auto tuples = QueryRunner::generateSampleTuples(20);
    
    // Define comprehensive query set
    std::vector<Operator> queries = {
        // Basic queries
        DumpUtils::dumpTuple(std::cout),
        
        // Network security queries
        NetworkQueries::tcpNewCons(
            DumpUtils::dumpTuple(std::cout)
        ),
        NetworkQueries::sshBruteForce(
            DumpUtils::dumpTuple(std::cout)
        ),
        
        // Advanced detection queries
        AdvancedNetworkQueries::superSpreader(
            DumpUtils::dumpTuple(std::cout)
        ),
        AdvancedNetworkQueries::portScan(
            DumpUtils::dumpTuple(std::cout)
        ),
        AdvancedNetworkQueries::ddosDetection(
            DumpUtils::dumpTuple(std::cout)
        )
    };

    // Add more complex multi-operator queries
    auto synFloodQueries = AdvancedNetworkQueries::synFloodDetection(
        DumpUtils::dumpTuple(std::cout)
    );
    queries.insert(queries.end(), synFloodQueries.begin(), synFloodQueries.end());

    auto completedFlowQueries = AdvancedNetworkQueries::completedFlowsDetection(
        DumpUtils::dumpTuple(std::cout)
    );
    queries.insert(queries.end(), completedFlowQueries.begin(), completedFlowQueries.end());

    auto slowlorisQueries = AdvancedNetworkQueries::slowlorisDetection(
        DumpUtils::dumpTuple(std::cout)
    );
    queries.insert(queries.end(), slowlorisQueries.begin(), slowlorisQueries.end());
    
    // Run all queries
    QueryRunner::runQueries(tuples, queries);
    
    return 0;
}