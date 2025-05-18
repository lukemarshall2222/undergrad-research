#ifndef COMMON_HPP
#define COMMON_HPP

#include <iostream>
#include <vector>
#include <string>
#include <map>
#include <unordered_map>
#include <variant>
#include <functional>
#include <memory> // For shared_ptr if needed for complex state sharing
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <numeric>   // For accumulate in hashing
#include <array>
#include <cstddef> // For std::byte
#include <cstdint> // For uint32_t etc.
#include <cmath>   // For float comparisons
#include <optional>
#include <fstream> // For file operations

// --- Basic Network Types (Placeholders/Simple Implementations) ---

struct IpAddressV4 {
    uint32_t addr = 0; // Store as integer

    // Basic constructor (replace with proper parsing)
    IpAddressV4(uint32_t a = 0) : addr(a) {}
    IpAddressV4(const std::string& s); // TODO: Implement proper parsing

    std::string toString() const; // TODO: Implement conversion to string
    bool operator==(const IpAddressV4& other) const { return addr == other.addr; }
    bool operator<(const IpAddressV4& other) const { return addr < other.addr; } // Needed for std::map
};

// Hash specialization for IpAddressV4
namespace std {
    template <>
    struct hash<IpAddressV4> {
        std::size_t operator()(const IpAddressV4& ip) const noexcept {
            return std::hash<uint32_t>{}(ip.addr);
        }
    };
}

struct MacAddress {
    std::array<std::byte, 6> addr{};

    // Basic constructor (replace with proper parsing)
    MacAddress() = default;
    MacAddress(const std::string& s); // TODO: Implement proper parsing from "xx:xx:xx:xx:xx:xx"

    std::string toString() const; // TODO: Implement conversion to string
    bool operator==(const MacAddress& other) const { return addr == other.addr; }
    bool operator<(const MacAddress& other) const { return addr < other.addr; } // Needed for std::map
};

// Hash specialization for MacAddress
namespace std {
    template <>
    struct hash<MacAddress> {
        std::size_t operator()(const MacAddress& mac) const noexcept {
            // Simple hash combining bytes
            size_t seed = 0;
            for (std::byte b : mac.addr) {
                 seed ^= std::hash<unsigned char>{}(static_cast<unsigned char>(b)) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
            }
            return seed;
        }
    };
}


// --- Core Types ---

// Represents OCaml's op_result variant
using OpResult = std::variant<
    std::monostate, // Represents Empty
    double,         // Represents Float
    int64_t,        // Represents Int (use int64_t for safety)
    IpAddressV4,    // Represents IPv4
    MacAddress      // Represents MAC
>;

// Represents OCaml's tuple (map from string to op_result)
using Tuple = std::map<std::string, OpResult>;

// Represents OCaml's operator record
struct Operator {
    std::function<void(const Tuple&)> next;
    std::function<void(const Tuple&)> reset; // Takes reset context tuple

    // Default constructor for placeholder/uninitialized operators
    Operator() : next([](const Tuple&){}), reset([](const Tuple&){}) {}

    // Constructor to initialize functions
    Operator(std::function<void(const Tuple&)> n, std::function<void(const Tuple&)> r)
        : next(std::move(n)), reset(std::move(r)) {}
};

// Represents OCaml's function types for creating operators
using OpCreator = std::function<Operator(Operator)>; // Takes next operator, returns new one
using DblOpCreator = std::function<std::pair<Operator, Operator>(Operator)>; // Takes next, returns pair

// --- Hashing and Equality for OpResult and Tuple (CRUCIAL for unordered_map) ---

// Equality for OpResult
inline bool operator==(const OpResult& lhs, const OpResult& rhs) {
    return lhs.index() == rhs.index() && // Must be same type
           std::visit([&](const auto& l_val) {
               using T = std::decay_t<decltype(l_val)>;
               if constexpr (std::is_same_v<T, std::monostate>) {
                   return true; // Monostate always equals monostate
               } else {
                   // Compare values only if types match (guaranteed by index check)
                   const auto& r_val = std::get<T>(rhs);
                   // Handle floating point comparison carefully
                   if constexpr (std::is_same_v<T, double>) {
                       return std::fabs(l_val - r_val) < 1e-9; // Example tolerance
                   } else {
                       return l_val == r_val;
                   }
               }
           }, lhs);
}


// Hash for OpResult
namespace std {
    template <>
    struct hash<OpResult> {
        std::size_t operator()(const OpResult& res) const noexcept {
            size_t type_hash = std::hash<size_t>{}(res.index());
            size_t value_hash = std::visit([](const auto& val) -> size_t {
                using T = std::decay_t<decltype(val)>;
                if constexpr (std::is_same_v<T, std::monostate>) {
                    return 0; // Or some constant hash for monostate
                } else {
                    // Use std::hash for the underlying type
                    return std::hash<T>{}(val);
                }
            }, res);
             // Combine hashes (simple example)
            return type_hash ^ (value_hash << 1);
        }
    };
}

// Hash for Tuple (std::map<string, OpResult>)
// Required for using Tuple as a key in std::unordered_map (e.g., in groupby)
namespace std {
    template <>
    struct hash<Tuple> {
        std::size_t operator()(const Tuple& tup) const noexcept {
            size_t seed = 0;
            std::hash<std::string> str_hasher;
            std::hash<OpResult> res_hasher;
            // Combine hashes of key-value pairs. Order matters for std::map!
            for (const auto& pair : tup) {
                 // Simple combination, better methods exist
                 seed ^= str_hasher(pair.first) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
                 seed ^= res_hasher(pair.second) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
            }
            return seed;
        }
    };
    // Note: operator== for std::map is already defined and works correctly.
}


// --- Helper Functions (Simulating OCaml @=>, type conversions etc.) ---
namespace Utils {

    // Simulate OCaml's @=> operator chaining
    inline Operator chain(const OpCreator& creator, const Operator& next_op) {
        return creator(next_op);
    }

    // Simulate OCaml's @==> operator chaining for double creators
    inline std::pair<Operator, Operator> chain_double(const DblOpCreator& creator, const Operator& next_op) {
        return creator(next_op);
    }

    // Conversion utilities
    std::string string_of_mac(const MacAddress& mac);
    std::string tcp_flags_to_string(int flags); // Note: OCaml uses 'int', C++ might prefer uint16_t
    std::string string_of_op_result(const OpResult& res);
    std::string string_of_tuple(const Tuple& tup);

    // Type extraction (throwing exceptions on failure)
    int64_t int_of_op_result(const OpResult& res);
    double float_of_op_result(const OpResult& res);
    IpAddressV4 ipv4_of_op_result(const OpResult& res);
    MacAddress mac_of_op_result(const OpResult& res);

    // Tuple manipulation
    Tuple tuple_of_list(const std::vector<std::pair<std::string, OpResult>>& list);
    void dump_tuple(std::ostream& outc, const Tuple& tup);

    // Lookups (throwing exceptions on failure or missing key)
    int64_t lookup_int(const std::string& key, const Tuple& tup);
    double lookup_float(const std::string& key, const Tuple& tup);
    IpAddressV4 lookup_ipv4(const std::string& key, const Tuple& tup);
    MacAddress lookup_mac(const std::string& key, const Tuple& tup);

    // Helper for reading Walt's CSV format
    OpResult get_ip_or_zero(const std::string& input);

} // namespace Utils


#endif // COMMON_HPP