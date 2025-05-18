#pragma once

#include "types.hpp"

namespace stream_processing {

class TCPUtils {
public:
    // Convert TCP flags to human-readable string
    static std::string tcpFlagsToString(int flags) {
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

    // Check if specific TCP flags are set
    static bool hasTCPFlag(int packetFlags, int flagToCheck) {
        return (packetFlags & flagToCheck) == flagToCheck;
    }

    // Enum for well-known TCP flags
    enum TCPFlags {
        FIN = 1 << 0,
        SYN = 1 << 1,
        RST = 1 << 2,
        PSH = 1 << 3,
        ACK = 1 << 4,
        URG = 1 << 5,
        ECE = 1 << 6,
        CWR = 1 << 7
    };
};

} // namespace stream_processing