#pragma once

#include <string>
#include <variant>
#include <memory>
#include <unordered_map>
#include <functional>
#include <vector>
#include <optional>
#include <cstdint>

namespace stream_processing {

// Equivalent to OCaml's op_result
enum class OpResultType {
    Float,
    Int,
    IPv4,
    MAC,
    Empty
};

class IPv4Address {
public:
    IPv4Address(uint32_t addr) : address(addr) {}
    static IPv4Address fromString(const std::string& str);
    std::string toString() const;
private:
    uint32_t address;
};

class MACAddress {
public:
    MACAddress(const std::array<uint8_t, 6>& bytes);
    std::string toString() const;
private:
    std::array<uint8_t, 6> bytes;
};

class OpResult {
public:
    using Value = std::variant<float, int, IPv4Address, MACAddress>;

    OpResult() : type(OpResultType::Empty) {}
    explicit OpResult(float val) : value(val), type(OpResultType::Float) {}
    explicit OpResult(int val) : value(val), type(OpResultType::Int) {}
    explicit OpResult(IPv4Address val) : value(val), type(OpResultType::IPv4) {}
    explicit OpResult(MACAddress val) : value(val), type(OpResultType::MAC) {}

    OpResultType getType() const { return type; }
    
    template<typename T>
    T get() const {
        return std::get<T>(value);
    }

private:
    Value value;
    OpResultType type;
};

using Tuple = std::unordered_map<std::string, OpResult>;

struct Operator {
    std::function<void(const Tuple&)> next;
    std::function<void(const Tuple&)> reset;
};

using OperatorCreator = std::function<Operator(const Operator&)>;
using DoubleOperatorCreator = std::function<std::pair<Operator, Operator>(const Operator&)>;

}  // namespace stream_processing