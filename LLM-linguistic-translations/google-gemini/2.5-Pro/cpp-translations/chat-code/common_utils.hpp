#ifndef COMMON_UTILS_HPP
#define COMMON_UTILS_HPP

#include <iostream>
#include <vector>
#include <map>
#include <string>
#include <variant>
#include <functional>
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <array>
#include <optional>
#include <numeric>
#include <fstream> // Required for out_channel definition

// Forward Declarations
namespace Utils {
    struct IPv4Address;
    struct MACAddress;
    struct Empty {}; // Tag struct for Empty variant state

    // Represents the possible types stored in a Tuple field
    using OpResult = std::variant<
        double,        // Float
        int,           // Int
        IPv4Address,   // IPv4
        MACAddress,    // MAC
        Empty          // Empty/missing/initial state
    >;

    // The "Tuple" is a map from field names (string) to OpResult values
    using Tuple = std::map<std::string, OpResult>;

    // Forward declaration for Operator needed by OpCreator types
    struct Operator;

    // Type alias for functions that create operators (pipeline stages)
    using OpCreator = std::function<Operator(Operator)>;
    using DblOpCreator = std::function<std::pair<Operator, Operator>(Operator)>;


    // Represents a data processing unit in the pipeline
    struct Operator {
        std::function<void(const Tuple&)> next;
        std::function<void(const Tuple&)> reset;
    };

    // Helper structs for IP and MAC addresses
    struct IPv4Address {
        std::array<unsigned char, 4> octets;

        // Basic constructor from string "a.b.c.d" - throws on error
        explicit IPv4Address(const std::string& addr_str);
        std::string toString() const;

        // Needed for std::map keys
        bool operator<(const IPv4Address& other) const;
        bool operator==(const IPv4Address& other) const;
    };

    struct MACAddress {
        std::array<unsigned char, 6> bytes;

        // Basic constructor from byte array/vector
        explicit MACAddress(const std::vector<unsigned char>& data);
        explicit MACAddress(const std::array<unsigned char, 6>& data);
        std::string toString() const;

        // Needed for std::map keys
        bool operator<(const MACAddress& other) const;
        bool operator==(const MACAddress& other) const;
    };

     // Needed for std::map keys containing OpResult
    bool operator<(const OpResult& lhs, const OpResult& rhs);
    bool operator==(const OpResult& lhs, const OpResult& rhs);
    bool operator<(const Empty& lhs, const Empty& rhs);
    bool operator==(const Empty& lhs, const Empty& rhs);

    // --- Operator Chaining ---
    // Replaces OCaml's @=>
    Operator chain(const OpCreator& creator, const Operator& next_op);
    // Replaces OCaml's @==>
    std::pair<Operator, Operator> chain_double(const DblOpCreator& creator, const Operator& op);

    // --- Conversion Utilities ---
    std::string string_of_mac(const MACAddress& mac);
    std::string tcp_flags_to_string(int flags);
    int int_of_op_result(const OpResult& input);
    double float_of_op_result(const OpResult& input);
    std::string string_of_op_result(const OpResult& input);
    std::string string_of_tuple(const Tuple& input_tuple);
    Tuple tuple_of_list(const std::vector<std::pair<std::string, OpResult>>& tup_list);
    void dump_tuple(std::ostream& outc, const Tuple& tup);

    // --- Lookup Utilities ---
    int lookup_int(const std::string& key, const Tuple& tup);
    double lookup_float(const std::string& key, const Tuple& tup);
    std::optional<OpResult> lookup_opt(const std::string& key, const Tuple& tup); // Helper

} // namespace Utils

#endif // COMMON_UTILS_HPP