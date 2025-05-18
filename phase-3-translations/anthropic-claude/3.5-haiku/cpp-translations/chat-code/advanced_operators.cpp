#include "advanced_operators.hpp"
#include <unordered_set>

namespace stream_processing {

Operator AdvancedOperators::join(
    std::function<std::pair<Tuple, Tuple>(const Tuple&)> leftExtractor,
    std::function<std::pair<Tuple, Tuple>(const Tuple&)> rightExtractor,
    const std::string& eidKey
) {
    std::unordered_map<Tuple, Tuple> leftTable, rightTable;
    int leftEpoch = 0, rightEpoch = 0;

    return {
        [=](const Tuple& tup) mutable {
            auto [key, vals] = leftExtractor(tup);
            int currentEpoch = tup.at(eidKey).get<int>();

            // Epoch synchronization logic
            while (currentEpoch > leftEpoch) {
                if (rightEpoch > leftEpoch) {
                    // Reset logic for epoch
                    Tuple resetTuple;
                    resetTuple[eidKey] = OpResult(leftEpoch);
                    // Trigger downstream operator
                }
                leftEpoch++;
            }

            // Join logic
            auto matchIt = rightTable.find(key);
            if (matchIt != rightTable.end()) {
                // Merge tuples on match
                Tuple mergedTuple = vals;
                mergedTuple.insert(matchIt->second.begin(), matchIt->second.end());
                // Trigger downstream operator with merged tuple
                rightTable.erase(matchIt);
            } else {
                leftTable[key] = vals;
            }
        },
        [](const Tuple&) {} // Reset logic
    };
}

Operator AdvancedOperators::distinct(
    std::function<Tuple(const Tuple&)> groupingFunc
) {
    std::unordered_set<Tuple> seenGroups;

    return {
        [=](const Tuple& tup) mutable {
            Tuple groupKey = groupingFunc(tup);
            
            if (seenGroups.find(groupKey) == seenGroups.end()) {
                seenGroups.insert(groupKey);
                // Trigger downstream operator
            }
        },
        [](const Tuple&) {
            // Reset logic
        }
    };
}

bool AdvancedOperators::isTcpPacket(const Tuple& tup) {
    return tup.at("ipv4.proto").get<int>() == 6;
}

bool AdvancedOperators::isSynPacket(const Tuple& tup) {
    return isTcpPacket(tup) && 
           tup.at("l4.flags").get<int>() == 2;
}

bool AdvancedOperators::isSynAckPacket(const Tuple& tup) {
    return isTcpPacket(tup) && 
           tup.at("l4.flags").get<int>() == 18;
}

bool AdvancedOperators::isFinPacket(const Tuple& tup) {
    return isTcpPacket(tup) && 
           (tup.at("l4.flags").get<int>() & 1) == 1;
}

Operator AdvancedOperators::tcpNewConnections(int threshold) {
    return OperatorUtils::groupBy(
        [](const Tuple& tup) {
            Tuple key;
            key["ipv4.dst"] = tup.at("ipv4.dst");
            return key;
        },
        counterReduction,
        "cons"
    ) | OperatorUtils::filter([threshold](const Tuple& tup) {
        return tup.at("cons").get<int>() >= threshold;
    });
}

Operator AdvancedOperators::sshBruteForce(int threshold) {
    return OperatorUtils::filter([](const Tuple& tup) {
        return isTcpPacket(tup) && 
               tup.at("l4.dport").get<int>() == 22;
    }) | AdvancedOperators::distinct([](const Tuple& tup) {
        Tuple key;
        key["ipv4.src"] = tup.at("ipv4.src");
        key["ipv4.dst"] = tup.at("ipv4.dst");
        key["ipv4.len"] = tup.at("ipv4.len");
        return key;
    }) | OperatorUtils::groupBy(
        [](const Tuple& tup) {
            Tuple key;
            key["ipv4.dst"] = tup.at("ipv4.dst");
            key["ipv4.len"] = tup.at("ipv4.len");
            return key;
        },
        counterReduction,
        "srcs"
    ) | OperatorUtils::filter([threshold](const Tuple& tup) {
        return tup.at("srcs").get<int>() >= threshold;
    });
}

// Other network query methods would be implemented similarly
// ... (omitted for brevity)

} // namespace stream_processing