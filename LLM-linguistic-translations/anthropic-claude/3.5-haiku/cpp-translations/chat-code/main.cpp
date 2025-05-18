#include "types.hpp"
#include "advanced_operators.hpp"
#include "streaming_pipeline.hpp"
#include "tcp_utils.hpp"
#include <iostream>
#include <vector>

using namespace stream_processing;

std::vector<Tuple> generateSamplePackets(int count) {
    std::vector<Tuple> packets;
    for (int i = 0; i < count; ++i) {
        Tuple packet{
            {"time", OpResult(static_cast<float>(i))},
            {"ipv4.src", OpResult(IPv4Address::fromString("192.168.1." + std::to_string(i % 255)))},
            {"ipv4.dst", OpResult(IPv4Address::fromString("10.0.0." + std::to_string(i % 255)))},
            {"ipv4.proto", OpResult(6)},  // TCP
            {"l4.sport", OpResult(1000 + i % 1000)},
            {"l4.dport", OpResult(22)},  // SSH port
            {"l4.flags", OpResult(i % 2 == 0 ? TCPUtils::SYN : TCPUtils::ACK)},
            {"ipv4.len", OpResult(64 + i % 100)}
        };
        packets.push_back(packet);
    }
    return packets;
}

int main() {
    // Generate sample network packets
    auto packets = generateSamplePackets(1000);

    // Create a streaming pipeline with multiple operators
    StreamingPipeline pipeline;

    // Add various network analysis operators
    pipeline
        .addOperator(AdvancedOperators::tcpNewConnections())
        .addOperator(AdvancedOperators::sshBruteForce())
        .addOperator(OperatorUtils::dumpTuple(std::cout));

    // Process the packets
    pipeline.processBatch(packets);

    return 0;
}