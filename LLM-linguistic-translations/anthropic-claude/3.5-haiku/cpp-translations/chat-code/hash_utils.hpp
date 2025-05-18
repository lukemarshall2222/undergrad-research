#pragma once

#include "types.hpp"
#include <functional>

namespace std {
    // Custom hash implementations for Tuple and other complex types
    template <>
    struct hash<stream_processing::Tuple> {
        size_t operator()(const stream_processing::Tuple& tup) const {
            size_t seed = tup.size();
            for (const auto& [key, value] : tup) {
                seed ^= hash<string>{}(key) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
                
                // Hash based on op_result type
                switch (value.getType()) {
                    case stream_processing::OpResultType::Float:
                        seed ^= hash<float>{}(value.get<float>()) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
                        break;
                    case stream_processing::OpResultType::Int:
                        seed ^= hash<int>{}(value.get<int>()) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
                        break;
                    case stream_processing::OpResultType::IPv4:
                        seed ^= hash<string>{}(value.get<stream_processing::IPv4Address>().toString()) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
                        break;
                    case stream_processing::OpResultType::MAC:
                        seed ^= hash<string>{}(value.get<stream_processing::MACAddress>().toString()) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
                        break;
                    case stream_processing::OpResultType::Empty:
                        break;
                }
            }
            return seed;
        }
    };
}

namespace stream_processing {

// Comparison operators for Tuple to work with standard containers
bool operator==(const Tuple& lhs, const Tuple& rhs) {
    if (lhs.size() != rhs.size()) return false;
    
    for (const auto& [key, value] : lhs) {
        auto rhsIt = rhs.find(key);
        if (rhsIt == rhs.end()) return false;
        
        const auto& rhsValue = rhsIt->second;
        if (value.getType() != rhsValue.getType()) return false;
        
        switch (value.getType()) {
            case OpResultType::Float:
                if (value.get<float>() != rhsValue.get<float>()) return false;
                break;
            case OpResultType::Int:
                if (value.get<int>() != rhsValue.get<int>()) return false;
                break;
            case OpResultType::IPv4:
                if (value.get<IPv4Address>().toString() != rhsValue.get<IPv4Address>().toString()) return false;
                break;
            case OpResultType::MAC:
                if (value.get<MACAddress>().toString() != rhsValue.get<MACAddress>().toString()) return false;
                break;
            case OpResultType::Empty:
                break;
        }
    }
    return true;
}

} // namespace stream_processing