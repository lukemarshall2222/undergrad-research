#pragma once

#include "types.hpp"
#include <unordered_map>
#include <functional>
#include <optional>

namespace stream_processing {

class AdvancedOperators {
public:
    // Join semantic
    static Operator join(
        std::function<std::pair<Tuple, Tuple>(const Tuple&)> leftExtractor,
        std::function<std::pair<Tuple, Tuple>(const Tuple&)> rightExtractor,
        const std::string& eidKey = "eid"
    );

    // Distinct operator to remove duplicates
    static Operator distinct(
        std::function<Tuple(const Tuple&)> groupingFunc
    );

    // Network-specific query operators
    static Operator tcpNewConnections(int threshold = 40);
    static Operator sshBruteForce(int threshold = 40);
    static Operator superSpreader(int threshold = 40);
    static Operator portScan(int threshold = 40);
    static Operator ddosDetection(int threshold = 45);
    static Operator synFloodDetection();
    static Operator completedFlowsDetection();
    static Operator slowlorisDetection();

private:
    // Utility functions for network query logic
    static bool isTcpPacket(const Tuple& tup);
    static bool isSynPacket(const Tuple& tup);
    static bool isSynAckPacket(const Tuple& tup);
    static bool isFinPacket(const Tuple& tup);
};

} // namespace stream_processing