#include "network_queries.hpp"
#include "tcp_utils.hpp"

namespace stream_processing {

Operator NetworkQueries::identityQuery(Operator next) {
    return OperatorUtils::map([](const Tuple& tup) {
        // Remove eth.src and eth.dst from the tuple
        Tuple filteredTup = tup;
        filteredTup.erase("eth.src");
        filteredTup.erase("eth.dst");
        return filteredTup;
    }) | next;
}

Operator NetworkQueries::countPacketsQuery(Operator next) {
    return OperatorUtils::epoch(1.0, "eid") | 
           OperatorUtils::groupBy(
               [](const Tuple&) { return Tuple(); }, // single group
               counterReduction, 
               "pkts"
           ) | next;
}

Operator NetworkQueries::packetsPerSrcDstQuery(Operator next) {
    return OperatorUtils::epoch(1.0, "eid") | 
           OperatorUtils::groupBy(
               [](const Tuple& tup) {
                   Tuple key;
                   key["ipv4.src"] = tup.at("ipv4.src");
                   key["ipv4.dst"] = tup.at("ipv4.dst");
                   return key;
               }, 
               counterReduction, 
               "pkts"
           ) | next;
}

Operator NetworkQueries::distinctSourcesQuery(Operator next) {
    return OperatorUtils::epoch(1.0, "eid") | 
           AdvancedOperators::distinct([](const Tuple& tup) {
               Tuple key;
               key["ipv4.src"] = tup.at("ipv4.src");
               return key;
           }) | 
           OperatorUtils::groupBy(
               [](const Tuple&) { return Tuple(); }, // single group
               counterReduction, 
               "srcs"
           ) | next;
}

Operator NetworkQueries::tcpNewConnectionsQuery(Operator next, int threshold) {
    return OperatorUtils::epoch(1.0, "eid") | 
           OperatorUtils::filter([](const Tuple& tup) {
               return tup.at("ipv4.proto").get<int>() == 6 && 
                      tup.at("l4.flags").get<int>() == 2; // SYN flag
           }) | 
           OperatorUtils::groupBy(
               [](const Tuple& tup) {
                   Tuple key;
                   key["ipv4.dst"] = tup.at("ipv4.dst");
                   return key;
               }, 
               counterReduction, 
               "cons"
           ) | 
           OperatorUtils::filter([threshold](const Tuple& tup) {
               return tup.at("cons").get<int>() >= threshold;
           }) | next;
}

Operator NetworkQueries::sshBruteForceQuery(Operator next, int threshold) {
    return OperatorUtils::epoch(1.0, "eid") | 
           OperatorUtils::filter([](const Tuple& tup) {
               return tup.at("ipv4.proto").get<int>() == 6 && 
                      tup.at("l4.dport").get<int>() == 22; // SSH port
           }) | 
           AdvancedOperators::distinct([](const Tuple& tup) {
               Tuple key;
               key["ipv4.src"] = tup.at("ipv4.src");
               key["ipv4.dst"] = tup.at("ipv4.dst");
               key["ipv4.len"] = tup.at("ipv4.len");
               return key;
           }) | 
           OperatorUtils::groupBy(
               [](const Tuple& tup) {
                   Tuple key;
                   key["ipv4.dst"] = tup.at("ipv4.dst");
                   key["ipv4.len"] = tup.at("ipv4.len");
                   return key;
               }, 
               counterReduction, 
               "srcs"
           ) | 
           OperatorUtils::filter([threshold](const Tuple& tup) {
               return tup.at("srcs").get<int>() >= threshold;
           }) | next;
}

Operator NetworkQueries::superSpreaderQuery(Operator next, int threshold) {
    return OperatorUtils::epoch(1.0, "eid") | 
           AdvancedOperators::distinct([](const Tuple& tup) {
               Tuple key;
               key["ipv4.src"] = tup.at("ipv4.src");
               key["ipv4.dst"] = tup.at("ipv4.dst");
               return key;
           }) | 
           OperatorUtils::groupBy(
               [](const Tuple& tup) {
                   Tuple key;
                   key["ipv4.src"] = tup.at("ipv4.src");
                   return key;
               }, 
               counterReduction, 
               "dsts"
           ) | 
           OperatorUtils::filter([threshold](const Tuple& tup) {
               return tup.at("dsts").get<int>() >= threshold;
           }) | next;
}

Operator NetworkQueries::portScanQuery(Operator next, int threshold) {
    return OperatorUtils::epoch(1.0, "eid") | 
           AdvancedOperators::distinct([](const Tuple& tup) {
               Tuple key;
               key["ipv4.src"] = tup.at("ipv4.src");
               key["l4.dport"] = tup.at("l4.dport");
               return key;
           }) | 
           OperatorUtils::groupBy(
               [](const Tuple& tup) {
                   Tuple key;
                   key["ipv4.src"] = tup.at("ipv4.src");
                   return key;
               }, 
               counterReduction, 
               "ports"
           ) | 
           OperatorUtils::filter([threshold](const Tuple& tup) {
               return tup.at("ports").get<int>() >= threshold;
           }) | next;
}

Operator NetworkQueries::ddosQuery(Operator next, int threshold) {
    return OperatorUtils::epoch(1.0, "eid") | 
           AdvancedOperators::distinct([](const Tuple& tup) {
               Tuple key;
               key["ipv4.src"] = tup.at("ipv4.src");
               key["ipv4.dst"] = tup.at("ipv4.dst");
               return key;
           }) | 
           OperatorUtils::groupBy(
               [](const Tuple& tup) {
                   Tuple key;
                   key["ipv4.dst"] = tup.at("ipv4.dst");
                   return key;
               }, 
               counterReduction, 
               "srcs"
           ) | 
           OperatorUtils::filter([threshold](const Tuple& tup) {
               return tup.at("srcs").get<int>() >= threshold;
           }) | next;
}

std::vector<Operator> NetworkQueries::synFloodQuery(Operator next) {
    int threshold = 3;
    float epochDur = 1.0;

    auto synOperator = OperatorUtils::epoch(epochDur, "eid") | 
        OperatorUtils::filter([](const Tuple& tup) {
            return tup.at("ipv4.proto").get<int>() == 6 && 
                   tup.at("l4.flags").get<int>() == 2; // SYN flag
        }) | 
        OperatorUtils::groupBy(
            [](const Tuple& tup) {
                Tuple key;
                key["ipv4.dst"] = tup.at("ipv4.dst");
                return key;
            }, 
            counterReduction, 
            "syns"
        );

    auto synAckOperator = OperatorUtils::epoch(epochDur, "eid") | 
        OperatorUtils::filter([](const Tuple& tup) {
            return tup.at("ipv4.proto").get<int>() == 6 && 
                   tup.at("l4.flags").get<int>() == 18; // SYN-ACK flag
        }) | 
        OperatorUtils::groupBy(
            [](const Tuple& tup) {
                Tuple key;
                key["ipv4.src"] = tup.at("ipv4.src");
                return key;
            }, 
            counterReduction, 
            "synacks"
        );

    auto ackOperator = OperatorUtils::epoch(epochDur, "eid") | 
        OperatorUtils::filter([](const Tuple& tup) {
            return tup.at("ipv4.proto").get<int>() == 6 && 
                   tup.at("l4.flags").get<int>() == 16; // ACK flag
        }) | 
        OperatorUtils::groupBy(
            [](const Tuple& tup) {
                Tuple key;
                key["ipv4.dst"] = tup.at("ipv4.dst");
                return key;
            }, 
            counterReduction, 
            "acks"
        );

    // Complex join logic would be implemented here
    // This is a simplified version
    return {synOperator, synAckOperator, ackOperator};
}

std::vector<Operator> NetworkQueries::completedFlowsQuery(Operator next) {
    int threshold = 1;
    float epochDur = 30.0;

    auto synOperator = OperatorUtils::epoch(epochDur, "eid") | 
        OperatorUtils::filter([](const Tuple& tup) {
            return tup.at("ipv4.proto").get<int>() == 6 && 
                   tup.at("l4.flags").get<int>() == 2; // SYN flag
        }) | 
        OperatorUtils::groupBy(
            [](const Tuple& tup) {
                Tuple key;
                key["ipv4.dst"] = tup.at("ipv4.dst");
                return key;
            }, 
            counterReduction, 
            "syns"
        );

    auto finOperator = OperatorUtils::epoch(epochDur, "eid") | 
        OperatorUtils::filter([](const Tuple& tup) {
            return tup.at("ipv4.proto").get<int>() == 6 && 
                   (tup.at("l4.flags").get<int>() & 1) == 1; // FIN flag
        }) | 
        OperatorUtils::groupBy(
            [](const Tuple& tup) {
                Tuple key;
                key["ipv4.src"] = tup.at("ipv4.src");
                return key;
            }, 
            counterReduction, 
            "fins"
        );

    // Similar to synFloodQuery, complex join logic would be implemented
    return {synOperator, finOperator};
}

std::vector<Operator> NetworkQueries::slowlorisQuery(Operator next) {
    int t1 = 5;    // Minimum connections
    int t2 = 500;  // Minimum bytes
    int t3 = 90;   // Maximum bytes per connection
    float epochDur = 1.0;

    auto connectionsOperator = OperatorUtils::epoch(epochDur, "eid") | 
        OperatorUtils::filter([](const Tuple& tup) {
            return tup.at("ipv4.proto").get<int>() == 6;
        }) | 
        AdvancedOperators::distinct([](const Tuple& tup) {
            Tuple key;
            key["ipv4.src"] = tup.at("ipv4.src");
            key["ipv4.dst"] = tup.at("ipv4.dst");
            key["l4.sport"] = tup.at("l4.sport");
            return key;
        }) | 
        OperatorUtils::groupBy(
            [](const Tuple& tup) {
                Tuple key;
                key["ipv4.dst"] = tup.at("ipv4.dst");
                return key;
            }, 
            counterReduction, 
            "n_conns"
        ) | 
        OperatorUtils::filter([t1](const Tuple& tup) {
            return tup.at("n_conns").get<int>() >= t1;
        });

    auto bytesOperator = OperatorUtils::epoch(epochDur, "eid") | 
        OperatorUtils::filter([](const Tuple& tup) {
            return tup.at("ipv4.proto").get<int>() == 6;
        }) | 
        OperatorUtils::groupBy(
            [](const Tuple& tup) {
                Tuple key;
                key["ipv4.dst"] = tup.at("ipv4.dst");
                return key;
            }, 
            [](const OpResult& acc, const Tuple& tup) {
                // Sum bytes
                int currentBytes = (acc.getType() == OpResultType::Empty) ? 0 : acc.get<int>();
                return OpResult(currentBytes + tup.at("ipv4.len").get<int>());
            }, 
            "n_bytes"
        ) | 
        OperatorUtils::filter([t2](const Tuple& tup) {
            return tup.at("n_bytes").get<int>() >= t2;
        });

    // In the full implementation, these would be joined
    return {connectionsOperator, bytesOperator};
}

Operator NetworkQueries::queryQ3(Operator next) {
    return OperatorUtils::epoch(100.0, "eid") | 
           AdvancedOperators::distinct([](const Tuple& tup) {
               Tuple key;
               key["ipv4.src"] = tup.at("ipv4.src");
               key["ipv4.dst"] = tup.at("ipv4.dst");
               return key;
           }) | next;
}

Operator NetworkQueries::queryQ4(Operator next) {
    return OperatorUtils::epoch(10Operator NetworkQueries::queryQ4(Operator next) {
    return OperatorUtils::epoch(10000.0, "eid") | 
           OperatorUtils::groupBy(
               [](const Tuple& tup) {
                   Tuple key;
                   key["ipv4.dst"] = tup.at("ipv4.dst");
                   return key;
               }, 
               counterReduction, 
               "pkts"
           ) | next;
}

// Utility methods for extracting and converting values
class QueryUtils {
public:
    // Extract integer value from a tuple
    static int extractIntValue(const Tuple& tup, const std::string& key) {
        try {
            return tup.at(key).get<int>();
        } catch (const std::exception& e) {
            throw std::runtime_error("Failed to extract integer value for key: " + key);
        }
    }

    // Extract float value from a tuple
    static float extractFloatValue(const Tuple& tup, const std::string& key) {
        try {
            return tup.at(key).get<float>();
        } catch (const std::exception& e) {
            throw std::runtime_error("Failed to extract float value for key: " + key);
        }
    }

    // Check if a tuple meets a threshold condition
    static bool meetsCriteria(const Tuple& tup, const std::string& key, int threshold) {
        try {
            return extractIntValue(tup, key) >= threshold;
        } catch (const std::exception& e) {
            return false;
        }
    }

    // Specialized reduction function for summing integer values
    static OpResult sumIntsReduction(const OpResult& accumulator, const Tuple& currentTuple) {
        int currentValue = 0;
        
        // Handle initial Empty case
        if (accumulator.getType() == OpResultType::Empty) {
            currentValue = 0;
        } else {
            currentValue = accumulator.get<int>();
        }

        // Try to add the value from the current tuple
        try {
            int tupleValue = currentTuple.at("packet_count").get<int>();
            return OpResult(currentValue + tupleValue);
        } catch (const std::exception& e) {
            // If value cannot be extracted, return current accumulator
            return accumulator;
        }
    }

    // Convert TCP flags to a readable format
    static std::string interpretTCPFlags(int flags) {
        std::vector<std::string> flagNames = {
            "FIN", "SYN", "RST", "PSH", 
            "ACK", "URG", "ECE", "CWR"
        };
        
        std::string result;
        for (size_t i = 0; i < flagNames.size(); ++i) {
            if (flags & (1 << i)) {
                result += (result.empty() ? "" : "|") + flagNames[i];
            }
        }
        
        return result;
    }
};

// Enhanced network query builder
class NetworkQueryBuilder {
public:
    // Fluent interface for building complex queries
    NetworkQueryBuilder& withEpoch(float duration) {
        epochDuration = duration;
        return *this;
    }

    NetworkQueryBuilder& filterByProtocol(int protocol) {
        protocolFilter = protocol;
        return *this;
    }

    NetworkQueryBuilder& groupByKey(const std::string& key) {
        groupingKey = key;
        return *this;
    }

    NetworkQueryBuilder& withThreshold(int thresh) {
        threshold = thresh;
        return *this;
    }

    Operator build(Operator next) {
        return OperatorUtils::epoch(epochDuration, "eid") | 
               OperatorUtils::filter([this](const Tuple& tup) {
                   return tup.at("ipv4.proto").get<int>() == protocolFilter;
               }) | 
               OperatorUtils::groupBy(
                   [this](const Tuple& tup) {
                       Tuple key;
                       key[groupingKey] = tup.at(groupingKey);
                       return key;
                   }, 
                   counterReduction, 
                   "count"
               ) | 
               OperatorUtils::filter([this](const Tuple& tup) {
                   return tup.at("count").get<int>() >= threshold;
               }) | next;
    }

private:
    float epochDuration = 1.0;
    int protocolFilter = 6;  // Default to TCP
    std::string groupingKey = "ipv4.dst";
    int threshold = 10;
};

// Example of using the query builder
Operator createCustomNetworkQuery(Operator next) {
    return NetworkQueryBuilder()
        .withEpoch(5.0)
        .filterByProtocol(6)  // TCP
        .groupByKey("ipv4.src")
        .withThreshold(20)
        .build(next);
}