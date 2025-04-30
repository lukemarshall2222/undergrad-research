Prompt: Base prompt

Okay, let's translate the OCaml code into C++. This involves mapping OCaml's functional features, modules, variants, and standard library components to their C++ counterparts.

**Key Translation Choices:**

1.  **`op_result` (Variant Type):** Use `std::variant` (C++17) to represent the tagged union. `Empty` will be represented by `std::monostate`.
2.  **`Tuple` (Map):** Use `std::map<std::string, OpResult>`. `std::map` is ordered like OCaml's `Map.Make`.
3.  **`operator` (Record with Functions):** Use a `struct` containing `std::function` objects for `next` and `reset`.
4.  **`op_creator`, `dbl_op_creator` (Function Types):** Use `std::function` types.
5.  **State (`ref`, `Hashtbl`):** Use variables captured by lambdas assigned to the `next` and `reset` functions within the `Operator` struct. OCaml's `Hashtbl` maps to `std::unordered_map`.
6.  **Hashing Tuples:** `std::unordered_map` requires its keys (`Tuple` in `groupby`, `distinct`, `join`) to be hashable and comparable. We'll need to define `operator==` and a `std::hash` specialization for `OpResult` and `Tuple`. This is a significant complexity.
7.  **Modules:** Use C++ namespaces (`Utils`, `Builtins`, `Queries`).
8.  **Chaining Operators (`@=>`, `@==>`):** Replace with regular function calls (e.g., `chain(creator, next_op)`). C++ doesn't allow defining such custom infix operators easily.
9.  **IP/MAC Addresses:** Define simple placeholder structs/types. A real implementation would likely use a dedicated networking library (like Boost.Asio or a custom class). `Ipaddr.V4.t` is often represented as `uint32_t`. `Bytes.t` for MAC can be `std::array<std::byte, 6>` or similar.
10. **Error Handling:** Replace `raise (Failure ...)` with C++ exceptions (e.g., `throw std::runtime_error(...)`).
11. **Input/Output:** Replace OCaml's `Printf`, `Scanf`, `out_channel` with C++ iostreams (`<iostream>`, `<fstream>`, `<sstream>`) and formatting (`<iomanip>`).

---

**C++ Translation (Conceptual Structure)**

This is a complex translation. Below is a structured C++ equivalent, focusing on the core types and operator logic. It will require C++17 (for `std::variant`, `std::monostate`, `std::byte`). Note that implementing `read_walts_csv`, IP/MAC handling fully, and especially the hashing for `Tuple` requires significant additional code and potentially external libraries.

**1. Header File (`common.hpp`)**

```c++
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
```

**2. Implementation File (`utils.cpp`)**

```c++
#include "common.hpp"
#include <map>
#include <vector>
#include <algorithm> // For std::find_if, std::for_each if needed
#include <cstdio>    // For snprintf

// --- Placeholder Implementations for Network Types ---
// TODO: Replace these with actual parsing and formatting logic
IpAddressV4::IpAddressV4(const std::string& s) {
    // Very basic placeholder - assumes simple integer string for demo
    try { addr = std::stoul(s); } catch (...) { addr = 0; /* Handle error */ }
    // Real implementation needs to parse "a.b.c.d" format
}

std::string IpAddressV4::toString() const {
     // Real implementation needs to format to "a.b.c.d"
    return std::to_string(addr);
}

MacAddress::MacAddress(const std::string& s) {
    // TODO: Implement parsing "xx:xx:xx:xx:xx:xx"
    // Placeholder: fill with zeros
    std::fill(addr.begin(), addr.end(), std::byte{0});
}

std::string MacAddress::toString() const {
    char buf[18]; // xx:xx:xx:xx:xx:xx\0
    snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
             static_cast<unsigned char>(addr[0]), static_cast<unsigned char>(addr[1]),
             static_cast<unsigned char>(addr[2]), static_cast<unsigned char>(addr[3]),
             static_cast<unsigned char>(addr[4]), static_cast<unsigned char>(addr[5]));
    return std::string(buf);
}

// --- Implementation of Utils namespace functions ---
namespace Utils {

std::string string_of_mac(const MacAddress& mac) {
    return mac.toString(); // Delegate to the class method
}

std::string tcp_flags_to_string(int flags) {
     // Using std::map like the OCaml version
    const std::map<std::string, int> tcp_flags_map = {
        {"FIN", 1 << 0}, {"SYN", 1 << 1}, {"RST", 1 << 2},
        {"PSH", 1 << 3}, {"ACK", 1 << 4}, {"URG", 1 << 5},
        {"ECE", 1 << 6}, {"CWR", 1 << 7}
    };

    std::string result = "";
    for (const auto& pair : tcp_flags_map) {
        if ((flags & pair.second) == pair.second) { // Check if flag is set
            if (!result.empty()) {
                result += "|";
            }
            result += pair.first;
        }
    }
    return result.empty() ? "<None>" : result; // Handle case where no flags are set
}


std::string string_of_op_result(const OpResult& res) {
    return std::visit([](const auto& val) -> std::string {
        using T = std::decay_t<decltype(val)>;
        std::stringstream ss;
        if constexpr (std::is_same_v<T, std::monostate>) {
            return "Empty";
        } else if constexpr (std::is_same_v<T, double>) {
            ss << std::fixed << std::setprecision(6) << val; // Match %f precision
             return ss.str();
        } else if constexpr (std::is_same_v<T, int64_t>) {
            return std::to_string(val);
        } else if constexpr (std::is_same_v<T, IpAddressV4>) {
            return val.toString();
        } else if constexpr (std::is_same_v<T, MacAddress>) {
            return val.toString();
        } else {
             // Should not happen with std::variant
             return "<UnknownType>";
        }
    }, res);
}

std::string string_of_tuple(const Tuple& tup) {
    std::stringstream ss;
    for (const auto& pair : tup) {
        ss << "\"" << pair.first << "\" => " << string_of_op_result(pair.second) << ", ";
    }
    std::string result = ss.str();
    // Remove trailing ", " if exists
    if (result.length() > 2) {
        result.resize(result.length() - 2);
    }
    return result;
}

// Type extraction implementations
int64_t int_of_op_result(const OpResult& res) {
    if (std::holds_alternative<int64_t>(res)) {
        return std::get<int64_t>(res);
    }
    throw std::runtime_error("Trying to extract int from non-int result: " + string_of_op_result(res));
}

double float_of_op_result(const OpResult& res) {
    if (std::holds_alternative<double>(res)) {
        return std::get<double>(res);
    }
     // Allow conversion from int if needed? OCaml doesn't.
     // if (std::holds_alternative<int64_t>(res)) {
     //    return static_cast<double>(std::get<int64_t>(res));
     // }
    throw std::runtime_error("Trying to extract float from non-float result: " + string_of_op_result(res));
}
IpAddressV4 ipv4_of_op_result(const OpResult& res) {
    if (std::holds_alternative<IpAddressV4>(res)) {
        return std::get<IpAddressV4>(res);
    }
    throw std::runtime_error("Trying to extract IPv4 from non-IPv4 result: " + string_of_op_result(res));
}

MacAddress mac_of_op_result(const OpResult& res) {
     if (std::holds_alternative<MacAddress>(res)) {
        return std::get<MacAddress>(res);
    }
    throw std::runtime_error("Trying to extract MAC from non-MAC result: " + string_of_op_result(res));
}


Tuple tuple_of_list(const std::vector<std::pair<std::string, OpResult>>& list) {
    Tuple tup;
    for (const auto& pair : list) {
        tup.insert(pair); // Or tup[pair.first] = pair.second;
    }
    return tup;
}

void dump_tuple(std::ostream& outc, const Tuple& tup) {
    outc << string_of_tuple(tup) << std::endl; // endl flushes
}

// Lookup implementations
int64_t lookup_int(const std::string& key, const Tuple& tup) {
    try {
        return int_of_op_result(tup.at(key));
    } catch (const std::out_of_range& oor) {
        throw std::runtime_error("Key not found: " + key);
    } catch (const std::runtime_error& re) {
        // Catch type conversion error and add key info
        throw std::runtime_error("Type error for key '" + key + "': " + re.what());
    }
}

double lookup_float(const std::string& key, const Tuple& tup) {
     try {
        return float_of_op_result(tup.at(key));
    } catch (const std::out_of_range& oor) {
        throw std::runtime_error("Key not found: " + key);
    } catch (const std::runtime_error& re) {
        throw std::runtime_error("Type error for key '" + key + "': " + re.what());
    }
}

IpAddressV4 lookup_ipv4(const std::string& key, const Tuple& tup) {
     try {
        return ipv4_of_op_result(tup.at(key));
    } catch (const std::out_of_range& oor) {
        throw std::runtime_error("Key not found: " + key);
    } catch (const std::runtime_error& re) {
        throw std::runtime_error("Type error for key '" + key + "': " + re.what());
    }
}
MacAddress lookup_mac(const std::string& key, const Tuple& tup) {
      try {
        return mac_of_op_result(tup.at(key));
    } catch (const std::out_of_range& oor) {
        throw std::runtime_error("Key not found: " + key);
    } catch (const std::runtime_error& re) {
        throw std::runtime_error("Type error for key '" + key + "': " + re.what());
    }
}

OpResult get_ip_or_zero(const std::string& input) {
    if (input == "0") {
        return OpResult(static_cast<int64_t>(0)); // Return Int 0
    } else {
        try {
            // TODO: Replace placeholder with actual IpAddressV4 parsing
            return OpResult(IpAddressV4(input));
        } catch (...) {
            // Handle or rethrow parsing error
             throw std::runtime_error("Failed to parse IP address string: " + input);
        }
    }
}


} // namespace Utils
```

**3. Built-in Operators (`builtins.hpp` / `builtins.cpp`)**

This section defines the stream processing building blocks. Each function returns an `Operator`. State is captured in the lambdas.

```c++
// builtins.hpp
#ifndef BUILTINS_HPP
#define BUILTINS_HPP

#include "common.hpp"
#include <vector>
#include <string>
#include <list> // For read_walts_csv file list

namespace Builtins {

    // --- Constants ---
    const size_t INIT_TABLE_SIZE = 10000; // Hint for unordered_map reserve

    // --- Operator Definitions ---

    Operator dump_tuple(std::ostream& outc, bool show_reset = false);

    Operator dump_as_csv(std::ostream& outc,
                         std::optional<std::pair<std::string, std::string>> static_field = std::nullopt,
                         bool header = true);

    Operator dump_walts_csv(const std::string& filename);

    // Note: read_walts_csv is complex. This is a simplified signature.
    // A full implementation needs careful state management for multiple files.
    void read_walts_csv(const std::vector<std::string>& file_names,
                        const std::vector<Operator>& ops, // Pass operators directly
                        const std::string& epoch_id_key = "eid");


    Operator meta_meter(const std::string& name,
                        std::ostream& outc,
                        Operator next_op, // Pass next operator by value/move
                        std::optional<std::string> static_field = std::nullopt);

    Operator epoch(double epoch_width,
                   const std::string& key_out,
                   Operator next_op);

    // Filter
    using FilterFunc = std::function<bool(const Tuple&)>;
    Operator filter(FilterFunc f, Operator next_op);

    // Filter utility functions (can be implemented as lambdas or standalone funcs)
    FilterFunc key_geq_int(const std::string& key, int64_t threshold);

    // Get mapped values (wrappers around Utils::lookup_*)
    std::function<int64_t(const Tuple&)> get_mapped_int(const std::string& key);
    std::function<double(const Tuple&)> get_mapped_float(const std::string& key);


    // Map
    using MapFunc = std::function<Tuple(const Tuple&)>;
    Operator map(MapFunc f, Operator next_op);

    // Groupby types
    using GroupingFunc = std::function<Tuple(const Tuple&)>;
    using ReductionFunc = std::function<OpResult(OpResult, const Tuple&)>; // Accumulator, Current Tuple -> New Accumulator

    Operator groupby(GroupingFunc groupby_func,
                     ReductionFunc reduce_func,
                     const std::string& out_key,
                     Operator next_op);

    // Groupby utilities
    GroupingFunc filter_groups(const std::vector<std::string>& incl_keys);
    GroupingFunc single_group(); // Returns function that returns empty tuple
    ReductionFunc counter();      // Returns function for counting
    ReductionFunc sum_ints(const std::string& search_key); // Returns function for summing

    // Distinct
    Operator distinct(GroupingFunc groupby_func, Operator next_op);

    // Split
    Operator split(Operator left, Operator right);

    // Join types
    using KeyExtractor = std::function<std::pair<Tuple, Tuple>(const Tuple&)>; // Key, Value tuple pair

    // Join (Returns two operators, one for each input stream)
    std::pair<Operator, Operator> join(KeyExtractor left_extractor,
                                       KeyExtractor right_extractor,
                                       Operator next_op,
                                       const std::string& eid_key = "eid");

    // Join utility
    MapFunc rename_filtered_keys(const std::vector<std::pair<std::string, std::string>>& renamings_pairs);

} // namespace Builtins

#endif // BUILTINS_HPP
```

```c++
// builtins.cpp
#include "builtins.hpp"
#include "common.hpp" // Include Utils namespace
#include <limits> // For numeric_limits
#include <set> // Can be used for distinct if hashing Tuple is problematic initially

namespace Builtins {

// --- Operator Implementations ---

Operator dump_tuple(std::ostream& outc, bool show_reset) {
    // Capture outc and show_reset by value/reference as needed
    auto next_func = [&outc](const Tuple& tup) {
        Utils::dump_tuple(outc, tup);
    };
    auto reset_func = [&outc, show_reset](const Tuple& tup) {
        if (show_reset) {
            Utils::dump_tuple(outc, tup);
            outc << "[reset]" << std::endl;
        }
        // Reset usually propagates, but dump is often terminal.
        // If it needed to propagate: next_op.reset(tup);
    };
    return Operator(next_func, reset_func);
}

Operator dump_as_csv(std::ostream& outc,
                     std::optional<std::pair<std::string, std::string>> static_field,
                     bool header) {
    // State captured in the lambda
    auto first = std::make_shared<bool>(header); // Use shared_ptr for mutable state capture

    auto next_func = [&outc, static_field, first](const Tuple& tup) {
        if (*first) {
             if (static_field) {
                outc << static_field->first << ",";
            }
            bool first_key = true;
            for(const auto& pair : tup) {
                if (!first_key) outc << ",";
                outc << pair.first;
                first_key = false;
            }
            outc << "\n"; // Use newline instead of comma at end
            *first = false;
        }

        if (static_field) {
             outc << static_field->second << ",";
        }
        bool first_val = true;
        for(const auto& pair : tup) {
             if (!first_val) outc << ",";
             outc << Utils::string_of_op_result(pair.second);
             first_val = false;
        }
        outc << "\n"; // Use newline instead of comma at end
        outc.flush(); // Ensure output is written
    };

    auto reset_func = [](const Tuple& /*tup*/) {
        // CSV dump usually doesn't react to resets, but could reset header flag if needed
        // Propagate if necessary: next_op.reset(tup);
    };

    return Operator(next_func, reset_func);
}

Operator dump_walts_csv(const std::string& filename) {
    // State captured: output file stream, first write flag
    // Using shared_ptr to manage the stream lifetime within the lambda captures
    auto out_stream_ptr = std::make_shared<std::ofstream>();
    auto first = std::make_shared<bool>(true);
    // Capture filename by value for use in opening the stream
    std::string captured_filename = filename;

    auto next_func = [out_stream_ptr, first, captured_filename](const Tuple& tup) {
        if (*first) {
            out_stream_ptr->open(captured_filename);
            if (!out_stream_ptr->is_open()) {
                 throw std::runtime_error("Failed to open Walt's CSV file: " + captured_filename);
            }
            // No header in Walt's format example
            *first = false;
        }

        try {
             // Ensure keys exist before accessing (use lookup functions)
             *out_stream_ptr << Utils::string_of_op_result(tup.at("src_ip")) << ","
                            << Utils::string_of_op_result(tup.at("dst_ip")) << ","
                            << Utils::string_of_op_result(tup.at("src_l4_port")) << ","
                            << Utils::string_of_op_result(tup.at("dst_l4_port")) << ","
                            << Utils::string_of_op_result(tup.at("packet_count")) << ","
                            << Utils::string_of_op_result(tup.at("byte_count")) << ","
                            << Utils::string_of_op_result(tup.at("epoch_id")) << "\n";
             out_stream_ptr->flush();
        } catch (const std::out_of_range& oor) {
             std::cerr << "Error: Missing key in dump_walts_csv: " << oor.what() << " in tuple: " << Utils::string_of_tuple(tup) << std::endl;
             // Decide whether to throw, continue, or write default values
        } catch (const std::exception& e) {
            std::cerr << "Error writing Walt's CSV: " << e.what() << std::endl;
            // Handle error appropriately
        }

    };

    auto reset_func = [out_stream_ptr](const Tuple& /*tup*/) {
        // Reset might close the file, or do nothing specific for this operator
         if (out_stream_ptr->is_open()) {
            // Maybe close and reset 'first' flag if needed for multiple runs?
            // out_stream_ptr->close();
         }
        // Propagate if necessary: next_op.reset(tup);
    };

     return Operator(next_func, reset_func);
}


// --- read_walts_csv ---
// This is complex due to multiple file handling, epoch logic, and error checking.
// A full implementation is beyond a simple translation snippet.
// It would involve:
// 1. Struct/class to hold state for each file (ifstream, current eid, tuple count).
// 2. A loop that iterates while any file is active.
// 3. Inside the loop, iterate through active files.
// 4. For each file, try to read a line using `std::getline` and parse using `std::stringstream` or `sscanf`.
// 5. Handle `eof`, parsing errors (`Scanf.Scan_failure`).
// 6. Manage epoch boundaries and call `op.reset` and `op.next` correctly.
// 7. Handle the parallel `ops` list corresponding to `file_names`.
void read_walts_csv(const std::vector<std::string>& file_names,
                        const std::vector<Operator>& ops,
                        const std::string& epoch_id_key) {
     if (file_names.size() != ops.size()) {
         throw std::invalid_argument("read_walts_csv: Number of files and operators must match.");
     }
     std::cerr << "Warning: read_walts_csv implementation is a complex placeholder." << std::endl;
     // TODO: Implement the complex logic described above.
}


Operator meta_meter(const std::string& name,
                        std::ostream& outc,
                        Operator next_op, // Pass by value/move
                        std::optional<std::string> static_field) {
     auto epoch_count = std::make_shared<int64_t>(0);
     auto tups_count = std::make_shared<int64_t>(0);
     // Capture next_op itself if needed (e.g. shared_ptr if lifetime tricky)
     // Operator captured_next_op = std::move(next_op); // Or copy if needed

     auto next_func = [tups_count, next_op](const Tuple& tup) mutable {
         (*tups_count)++;
         next_op.next(tup); // Call next operator
     };

     auto reset_func = [name, &outc, static_field, epoch_count, tups_count, next_op]
                       (const Tuple& tup) mutable {
         outc << *epoch_count << "," << name << "," << *tups_count;
         if (static_field) {
             outc << "," << *static_field;
         }
         outc << std::endl; // endl includes flush

         *tups_count = 0; // Reset count for next epoch
         (*epoch_count)++; // Increment epoch number
         next_op.reset(tup); // Propagate reset
     };

     return Operator(next_func, reset_func);
}


Operator epoch(double epoch_width,
                   const std::string& key_out,
                   Operator next_op) {
     auto epoch_boundary = std::make_shared<double>(0.0);
     auto eid = std::make_shared<int64_t>(0);
     // Capture next_op

     auto next_func = [epoch_width, key_out, epoch_boundary, eid, next_op]
                      (const Tuple& tup) mutable {
         double time = 0.0;
         try {
            time = Utils::lookup_float("time", tup);
         } catch (const std::exception& e) {
            // Handle missing or incorrect "time" field - maybe skip tuple or throw?
            std::cerr << "Epoch operator error: " << e.what() << " in tuple: " << Utils::string_of_tuple(tup) << std::endl;
            return; // Skip tuple if time is invalid/missing
         }


         if (*epoch_boundary == 0.0) { // Use comparison with tolerance for float? Unlikely needed here.
             *epoch_boundary = time + epoch_width;
         } else {
             while (time >= *epoch_boundary) {
                 // Create reset context tuple
                 Tuple reset_context;
                 reset_context[key_out] = OpResult(*eid);
                 next_op.reset(reset_context);

                 *epoch_boundary += epoch_width;
                 (*eid)++;
             }
         }
         // Add epoch ID to tuple and pass downstream
         Tuple next_tup = tup; // Copy tuple
         next_tup[key_out] = OpResult(*eid);
         next_op.next(next_tup);
     };

     auto reset_func = [key_out, epoch_boundary, eid, next_op]
                       (const Tuple& /*tup*/) mutable { // Incoming reset context often ignored here
         // Reset the last epoch ID
         Tuple reset_context;
         reset_context[key_out] = OpResult(*eid);
         next_op.reset(reset_context);

         // Reset internal state
         *epoch_boundary = 0.0;
         *eid = 0;
     };

     return Operator(next_func, reset_func);
}

// --- Filter ---
Operator filter(FilterFunc f, Operator next_op) {
     auto next_func = [f, next_op](const Tuple& tup) mutable {
         if (f(tup)) {
             next_op.next(tup);
         }
     };
     auto reset_func = [next_op](const Tuple& tup) mutable {
         next_op.reset(tup); // Resets always propagate
     };
     return Operator(next_func, reset_func);
}

FilterFunc key_geq_int(const std::string& key, int64_t threshold) {
     // Return a lambda that captures key and threshold
     return [key, threshold](const Tuple& tup) -> bool {
         try {
             int64_t val = Utils::lookup_int(key, tup);
             return val >= threshold;
         } catch (const std::exception& e) {
             // Handle missing key or wrong type - typically filter out
             std::cerr << "Filter key_geq_int warning: " << e.what() << " for key '" << key << "' in tuple: " << Utils::string_of_tuple(tup) << std::endl;
             return false;
         }
     };
}

std::function<int64_t(const Tuple&)> get_mapped_int(const std::string& key) {
    return [key](const Tuple& tup) -> int64_t {
         // Let Utils::lookup_int handle exceptions
         return Utils::lookup_int(key, tup);
    };
}

std::function<double(const Tuple&)> get_mapped_float(const std::string& key) {
    return [key](const Tuple& tup) -> double {
         return Utils::lookup_float(key, tup);
    };
}

// --- Map ---
Operator map(MapFunc f, Operator next_op) {
      auto next_func = [f, next_op](const Tuple& tup) mutable {
         Tuple mapped_tup = f(tup); // Apply mapping function
         next_op.next(mapped_tup);
     };
     auto reset_func = [next_op](const Tuple& tup) mutable {
         next_op.reset(tup); // Resets propagate
     };
     return Operator(next_func, reset_func);
}


// --- Groupby ---
Operator groupby(GroupingFunc groupby_func,
                     ReductionFunc reduce_func,
                     const std::string& out_key,
                     Operator next_op) {
    // State: Hashtable (unordered_map) storing aggregated results per group
    // Use shared_ptr for the map to manage lifetime across lambda captures
    auto h_tbl_ptr = std::make_shared<std::unordered_map<Tuple, OpResult>>();
    h_tbl_ptr->reserve(INIT_TABLE_SIZE); // Pre-allocate hint

    auto next_func = [h_tbl_ptr, groupby_func, reduce_func]
                     (const Tuple& tup) mutable {
        Tuple grouping_key = groupby_func(tup);
        auto& h_tbl = *h_tbl_ptr; // Dereference pointer

        auto it = h_tbl.find(grouping_key);
        if (it != h_tbl.end()) {
            // Key exists, apply reduction with existing value
            it->second = reduce_func(it->second, tup);
        } else {
            // Key doesn't exist, apply reduction with 'Empty' (monostate)
            OpResult initial_val = std::monostate{};
            h_tbl[grouping_key] = reduce_func(initial_val, tup);
        }
    };

    auto reset_func = [h_tbl_ptr, out_key, next_op]
                      (const Tuple& reset_context) mutable {
        auto& h_tbl = *h_tbl_ptr;

        // Iterate through the groups in the hash table
        for (const auto& pair : h_tbl) {
            const Tuple& grouping_key = pair.first;
            const OpResult& aggregated_val = pair.second;

            // Merge reset_context, grouping_key, and aggregated_val
            Tuple output_tup = reset_context; // Start with reset context
            // Add grouping key fields (they overwrite context if names clash)
            output_tup.insert(grouping_key.begin(), grouping_key.end());
            // Add the aggregated result under out_key
            output_tup[out_key] = aggregated_val;

            next_op.next(output_tup); // Pass each aggregated group downstream
        }

        next_op.reset(reset_context); // Propagate the original reset context
        h_tbl.clear(); // Clear the table for the next epoch
    };

    return Operator(next_func, reset_func);
}

// Groupby utilities
GroupingFunc filter_groups(const std::vector<std::string>& incl_keys) {
    // Capture incl_keys by value
    return [keys = incl_keys](const Tuple& tup) -> Tuple {
        Tuple result;
        for (const std::string& key : keys) {
            auto it = tup.find(key);
            if (it != tup.end()) {
                result[key] = it->second;
            }
        }
        return result;
    };
}

GroupingFunc single_group() {
    return [](const Tuple& /*tup*/) -> Tuple {
        return Tuple{}; // Return an empty map
    };
}

ReductionFunc counter() {
    return [](OpResult current_val, const Tuple& /*tup*/) -> OpResult {
        if (std::holds_alternative<std::monostate>(current_val)) {
            return OpResult(static_cast<int64_t>(1)); // Start counting at 1
        } else if (std::holds_alternative<int64_t>(current_val)) {
            return OpResult(std::get<int64_t>(current_val) + 1); // Increment
        } else {
            // Should not happen if used correctly, return current value or throw
             std::cerr << "Counter error: Unexpected accumulator type: " << Utils::string_of_op_result(current_val) << std::endl;
             return current_val; // Or throw std::runtime_error("Counter error");
        }
    };
}

ReductionFunc sum_ints(const std::string& search_key) {
    return [search_key](OpResult current_val, const Tuple& tup) -> OpResult {
        int64_t current_sum = 0;
        if (std::holds_alternative<std::monostate>(current_val)) {
            current_sum = 0; // Initial value
        } else if (std::holds_alternative<int64_t>(current_val)) {
            current_sum = std::get<int64_t>(current_val);
        } else {
             std::cerr << "Sum_ints error: Unexpected accumulator type: " << Utils::string_of_op_result(current_val) << std::endl;
            // Decide error handling: return current, throw, return special error value?
            return current_val;
        }

        try {
            int64_t value_to_add = Utils::lookup_int(search_key, tup);
            return OpResult(current_sum + value_to_add);
        } catch (const std::exception& e) {
            std::cerr << "Sum_ints error: Failed to find/convert key '" << search_key << "': " << e.what() << " in tuple " << Utils::string_of_tuple(tup) << std::endl;
             // Decide error handling: return current sum, throw, etc.
             return OpResult(current_sum); // Return current sum if lookup fails
        }
    };
}

// --- Distinct ---
Operator distinct(GroupingFunc groupby_func, Operator next_op) {
    // State: Hashtable storing unique keys encountered in the epoch
    // Value can be simple bool or the first tuple encountered for that key if needed
    auto h_tbl_ptr = std::make_shared<std::unordered_map<Tuple, Tuple>>(); // Store tuple itself
    h_tbl_ptr->reserve(INIT_TABLE_SIZE);

    auto next_func = [h_tbl_ptr, groupby_func](const Tuple& tup) mutable {
        Tuple grouping_key = groupby_func(tup);
        auto& h_tbl = *h_tbl_ptr;
        // Add/overwrite the key. If we only care about existence, value could be bool.
        // Storing the original tuple allows emitting it on reset.
        // OCaml version used bool, let's stick to that for directness
        // auto h_tbl_bool_ptr = std::make_shared<std::unordered_map<Tuple, bool>>();
         h_tbl[grouping_key] = tup; // Store the full tuple associated with the key
         // If only tracking keys: h_tbl[grouping_key] = true;
    };

    auto reset_func = [h_tbl_ptr, next_op](const Tuple& reset_context) mutable {
        auto& h_tbl = *h_tbl_ptr;

        // Iterate through the unique items found
        for (const auto& pair : h_tbl) {
            //const Tuple& grouping_key = pair.first;
             const Tuple& representative_tup = pair.second; // Use the stored tuple

            // OCaml merges reset context and key. If we store the full tuple, maybe just pass that?
            // Let's follow OCaml's merge logic:
            Tuple output_tup = reset_context;
            // Merge the representative tuple fields (overwriting context if names clash)
            output_tup.insert(representative_tup.begin(), representative_tup.end());

            next_op.next(output_tup);
        }

        next_op.reset(reset_context); // Propagate reset
        h_tbl.clear(); // Clear for next epoch
    };

    return Operator(next_func, reset_func);
}


// --- Split ---
Operator split(Operator left, Operator right) {
     // Capture left and right operators
     auto next_func = [left, right](const Tuple& tup) {
         left.next(tup);
         right.next(tup);
     };
     auto reset_func = [left, right](const Tuple& tup) {
         left.reset(tup);
         right.reset(tup);
     };
     return Operator(next_func, reset_func);
}

// --- Join ---
// This is highly complex due to state management, epoch synchronization, and merging.
// The OCaml version uses two hash tables and epoch counters.
std::pair<Operator, Operator> join(KeyExtractor left_extractor,
                                       KeyExtractor right_extractor,
                                       Operator next_op,
                                       const std::string& eid_key) {
    // State shared between the two sides of the join:
    auto h_tbl1_ptr = std::make_shared<std::unordered_map<Tuple, Tuple>>(); // Key -> Value Tuple
    auto h_tbl2_ptr = std::make_shared<std::unordered_map<Tuple, Tuple>>();
    h_tbl1_ptr->reserve(INIT_TABLE_SIZE);
    h_tbl2_ptr->reserve(INIT_TABLE_SIZE);
    auto left_curr_epoch_ptr = std::make_shared<int64_t>(0);
    auto right_curr_epoch_ptr = std::make_shared<int64_t>(0);

    // Helper lambda for join logic (avoids code duplication)
    auto handle_join_side =
        [&](std::shared_ptr<std::unordered_map<Tuple, Tuple>> curr_h_tbl_ptr,
            std::shared_ptr<std::unordered_map<Tuple, Tuple>> other_h_tbl_ptr,
            std::shared_ptr<int64_t> curr_epoch_ref_ptr,
            std::shared_ptr<int64_t> other_epoch_ref_ptr,
            KeyExtractor extractor, // Capture extractor by value/copy
            Operator captured_next_op, // Capture next_op
            std::string captured_eid_key // Capture eid_key
            ) -> Operator
    {
        auto next_func = [=](const Tuple& tup) mutable {
            auto& curr_h_tbl = *curr_h_tbl_ptr;
            auto& other_h_tbl = *other_h_tbl_ptr;
            auto& curr_epoch_ref = *curr_epoch_ref_ptr;
            auto& other_epoch_ref = *other_epoch_ref_ptr;

            int64_t current_epoch = 0;
             try {
                current_epoch = Utils::lookup_int(captured_eid_key, tup);
             } catch (const std::exception& e) {
                 std::cerr << "Join error: Missing or invalid epoch key '" << captured_eid_key << "': " << e.what() << std::endl;
                 return; // Skip tuple if epoch is missing/invalid
             }

            // Advance current epoch counter if needed, emitting resets for next_op
            while (current_epoch > curr_epoch_ref) {
                if (other_epoch_ref > curr_epoch_ref) { // Only reset if other side also advanced past this epoch
                     Tuple reset_context;
                     reset_context[captured_eid_key] = OpResult(curr_epoch_ref);
                     captured_next_op.reset(reset_context);
                }
                curr_epoch_ref++;
            }

            // Extract key and value tuples using the provided extractor
            std::pair<Tuple, Tuple> extracted = extractor(tup);
            Tuple key = std::move(extracted.first);
            Tuple vals = std::move(extracted.second);

            // Create the lookup key (Key + Epoch ID)
            Tuple lookup_key = key;
            lookup_key[captured_eid_key] = OpResult(current_epoch);


            // Check the *other* table for a match
            auto it = other_h_tbl.find(lookup_key);
            if (it != other_h_tbl.end()) {
                // Match found! Merge and emit
                Tuple matched_val = it->second;
                other_h_tbl.erase(it); // Remove from other table after matching

                // Merge: lookup_key (contains original key + eid) + vals + matched_val
                Tuple merged_tup = lookup_key; // Start with key + eid
                merged_tup.insert(vals.begin(), vals.end()); // Add this side's values
                merged_tup.insert(matched_val.begin(), matched_val.end()); // Add other side's values

                captured_next_op.next(merged_tup);
            } else {
                // No match found, store in *this* table
                 curr_h_tbl[lookup_key] = vals; // Store this side's values, keyed by key+eid
            }
        };

        auto reset_func = [=](const Tuple& reset_context) mutable {
             auto& curr_epoch_ref = *curr_epoch_ref_ptr;
             auto& other_epoch_ref = *other_epoch_ref_ptr;

             int64_t reset_epoch = -1; // Default if key is missing
              try {
                 reset_epoch = Utils::lookup_int(captured_eid_key, reset_context);
             } catch (const std::exception& e) {
                 std::cerr << "Join reset warning: Missing or invalid epoch key '" << captured_eid_key << "': " << e.what() << std::endl;
                 // Decide how to proceed: use current epoch, default, or throw?
                 // OCaml likely uses current epoch if key is missing, let's try that
                 reset_epoch = curr_epoch_ref;
                 // Or maybe just propagate the context as-is without advancing?
                 // captured_next_op.reset(reset_context); return;
             }

             // Advance epoch counter based on reset context epoch, emitting resets
             while (reset_epoch > curr_epoch_ref) {
                  if (other_epoch_ref > curr_epoch_ref) {
                     Tuple downstream_reset_context;
                     downstream_reset_context[captured_eid_key] = OpResult(curr_epoch_ref);
                     captured_next_op.reset(downstream_reset_context);
                 }
                 curr_epoch_ref++;
             }
             // TODO: Consider cleaning up expired entries from hash tables based on epoch?
             // The OCaml version doesn't explicitly show cleanup in reset, relies on matching.

             // Propagate the original reset context? Or the one potentially created above?
             // OCaml seems implicitly uses the singleton {eid_key: eid} tuple. Let's stick to that idea.
             // If reset_epoch was validly read, use it.
             if (reset_epoch >= 0) {
                 Tuple final_reset_context;
                 final_reset_context[captured_eid_key] = OpResult(reset_epoch);
                  // If we always advanced up to reset_epoch, maybe use curr_epoch_ref?
                  // final_reset_context[captured_eid_key] = OpResult(curr_epoch_ref);
                 captured_next_op.reset(final_reset_context);
             } else {
                  // Propagate original if epoch lookup failed in reset
                  captured_next_op.reset(reset_context);
             }


        };
        return Operator(next_func, reset_func);
    };

    // Create the left and right operators using the helper
    Operator left_op = handle_join_side(h_tbl1_ptr, h_tbl2_ptr, left_curr_epoch_ptr, right_curr_epoch_ptr, left_extractor, next_op, eid_key);
    Operator right_op = handle_join_side(h_tbl2_ptr, h_tbl1_ptr, right_curr_epoch_ptr, left_curr_epoch_ptr, right_extractor, next_op, eid_key);

    return {left_op, right_op};
}


// Join utility
MapFunc rename_filtered_keys(const std::vector<std::pair<std::string, std::string>>& renamings_pairs) {
    return [renamings = renamings_pairs](const Tuple& in_tup) -> Tuple {
        Tuple new_tup;
        for (const auto& pair : renamings) {
            const std::string& old_key = pair.first;
            const std::string& new_key = pair.second;
            auto it = in_tup.find(old_key);
            if (it != in_tup.end()) {
                new_tup[new_key] = it->second; // Add with the new key
            }
        }
        return new_tup;
    };
}


} // namespace Builtins
```

**4. Queries and Main (`queries.hpp`, `queries.cpp`, `main.cpp`)**

This defines the specific analysis pipelines by composing the built-in operators.

```c++
// queries.hpp
#ifndef QUERIES_HPP
#define QUERIES_HPP

#include "common.hpp"
#include "builtins.hpp" // Include built-in operators
#include <vector>

namespace Queries {

    // Define functions that return OpCreators or Operators directly
    // Use Utils::chain to compose them

    OpCreator ident(); // Example: returns a creator
    OpCreator count_pkts();
    OpCreator pkts_per_src_dst();
    OpCreator distinct_srcs();
    OpCreator tcp_new_cons(int64_t threshold = 40);
    OpCreator ssh_brute_force(int64_t threshold = 40);
    OpCreator super_spreader(int64_t threshold = 40);
    OpCreator port_scan(int64_t threshold = 40);
    OpCreator ddos(int64_t threshold = 45);

    // Queries returning multiple operators (like joins)
    // Need a different signature or return type
    using MultiOpCreator = std::function<std::vector<Operator>(Operator)>;

    MultiOpCreator syn_flood_sonata(int64_t threshold = 3, double epoch_dur = 1.0);
    MultiOpCreator completed_flows(int64_t threshold = 1, double epoch_dur = 30.0);
    MultiOpCreator slowloris(int64_t t1 = 5, int64_t t2 = 500, int64_t t3 = 90, double epoch_dur = 1.0);
    MultiOpCreator join_test(double epoch_dur = 1.0);

    OpCreator q3(double epoch_dur = 100.0);
    OpCreator q4(double epoch_dur = 10000.0);


} // namespace Queries


#endif // QUERIES_HPP
```

```c++
// queries.cpp
#include "queries.hpp"
#include "common.hpp"   // Include Utils namespace
#include "builtins.hpp" // Include Builtins namespace

#include <vector>
#include <string>

namespace Queries {

    using namespace Utils; // Make Utils::chain etc. available
    using namespace Builtins; // Make built-in operators available

    // Helper for Sonata 1 filter condition
    bool filter_tcp_new_cons(const Tuple& tup) {
        try {
             return lookup_int("ipv4.proto", tup) == 6 && // TCP
                    lookup_int("l4.flags", tup) == 2;    // SYN
        } catch (...) { return false; } // Filter out if keys missing/wrong type
    }
    // ... similar helpers for other filters ...


    OpCreator ident() {
        return [](Operator next_op) -> Operator {
             auto remove_eth = [](const Tuple& tup) -> Tuple {
                 Tuple result;
                 for(const auto& pair : tup) {
                     if (pair.first != "eth.src" && pair.first != "eth.dst") {
                         result.insert(pair);
                     }
                 }
                 return result;
             };
             return chain(map(remove_eth), next_op);
        };
    }


    OpCreator count_pkts() {
        return [](Operator next_op) -> Operator {
            return chain(epoch(1.0, "eid"), // Add eid
                   chain(groupby(single_group(), counter(), "pkts"), // Group all, count
                         next_op)); // Pass to final destination
        };
    }

     OpCreator pkts_per_src_dst() {
        return [](Operator next_op) -> Operator {
            std::vector<std::string> keys = {"ipv4.src", "ipv4.dst"};
            return chain(epoch(1.0, "eid"),
                   chain(groupby(filter_groups(keys), counter(), "pkts"),
                         next_op));
        };
    }

    OpCreator distinct_srcs() {
         return [](Operator next_op) -> Operator {
             std::vector<std::string> group_keys = {"ipv4.src"};
             return chain(epoch(1.0, "eid"),
                    chain(distinct(filter_groups(group_keys)), // Find distinct sources per epoch
                    chain(groupby(single_group(), counter(), "srcs"), // Count distinct sources
                          next_op)));
         };
    }

     OpCreator tcp_new_cons(int64_t threshold) {
         return [threshold](Operator next_op) -> Operator {
              std::vector<std::string> group_keys = {"ipv4.dst"};
              FilterFunc filter_cond = [](const Tuple& tup) { /* ... check proto==6 and flags==2 ... */
                   try { return lookup_int("ipv4.proto", tup) == 6 && lookup_int("l4.flags", tup) == 2; }
                   catch(...) { return false; }
              };
              return chain(epoch(1.0, "eid"),
                     chain(filter(filter_cond),
                     chain(groupby(filter_groups(group_keys), counter(), "cons"),
                     chain(filter(key_geq_int("cons", threshold)), // Filter by threshold
                           next_op))));
         };
     }


    // --- Queries with Joins (returning multiple operators) ---

    // Example: syn_flood_sonata (structure only, details omitted for brevity)
     MultiOpCreator syn_flood_sonata(int64_t threshold, double epoch_dur) {
         return [=](Operator final_next_op) -> std::vector<Operator> {
             // Define OpCreators for syns, synacks, acks branches first
             OpCreator syns_creator = [=](Operator next) { /* ... epoch -> filter -> groupby -> next ... */ return Operator();};
             OpCreator synacks_creator = [=](Operator next) { /* ... */ return Operator();};
             OpCreator acks_creator = [=](Operator next) { /* ... */ return Operator();};

             // Define join operators (bottom-up)
             // Inner join (syns + synacks)
             KeyExtractor join1_left_extractor = [](const Tuple& t){ return std::make_pair(rename_filtered_keys({{"ipv4.dst", "host"}})(t), filter_groups({"syns"})(t)); };
             KeyExtractor join1_right_extractor = [](const Tuple& t){ return std::make_pair(rename_filtered_keys({{"ipv4.src", "host"}})(t), filter_groups({"synacks"})(t)); };
             MapFunc join1_map_func = [](const Tuple& t){ /* ... add syns+synacks ... */ return t; };
             DblOpCreator join1_creator = [&](Operator next) {
                  auto [opL, opR] = join(join1_left_extractor, join1_right_extractor, chain(map(join1_map_func), next), "eid");
                  return std::make_pair(opL, opR);
             };

             // Outer join ((syns+synacks) + acks)
             KeyExtractor join2_left_extractor = [](const Tuple& t){ /* ... host, syns+synacks ... */ return std::make_pair(Tuple(),Tuple());};
             KeyExtractor join2_right_extractor = [](const Tuple& t){ /* ... host, acks ... */ return std::make_pair(Tuple(),Tuple());};
             MapFunc join2_map_func = [](const Tuple& t){ /* ... add syns+synacks-acks ... */ return t; };
             FilterFunc final_filter_func = key_geq_int("syns+synacks-acks", threshold);
             DblOpCreator join2_creator = [&](Operator next) {
                  auto [opL, opR] = join(join2_left_extractor, join2_right_extractor, chain(map(join2_map_func), chain(filter(final_filter_func), next)), "eid");
                  return std::make_pair(opL, opR);
             };

             // Chain the joins (this is tricky with the double creators)
             // We need the output operators from join1 to feed into join2's creator input 'next' operator.
             // This requires careful composition. Let's assume chain_double exists.
             // This part needs careful thought on how to wire the creators and operators.
             // Simplified conceptual wiring:

             // Create the final stage (map -> filter -> final_next_op)
             Operator final_stage = chain(map(join2_map_func), chain(filter(final_filter_func), final_next_op));

             // Create the second join, its output feeds the final stage
             auto [join2_opL_creator_input, join2_opR] = join(join2_left_extractor, join2_right_extractor, final_stage, "eid");

             // Create the first join, its output feeds the left input of the second join
             auto [join1_opL, join1_opR] = join(join1_left_extractor, join1_right_extractor, join2_opL_creator_input, "eid");


             // Now create the initial branches feeding the first-level join operators
             Operator syns_branch = syns_creator(join1_opL);
             Operator synacks_branch = synacks_creator(join1_opR);
             Operator acks_branch = acks_creator(join2_opR);

             return {syns_branch, synacks_branch, acks_branch};
         };
     }

    // TODO: Implement other queries (ssh_brute_force, super_spreader, etc.) following similar patterns.
    // Remember to implement helper filter functions for clarity.
    // For join queries (completed_flows, slowloris, join_test), follow the syn_flood_sonata structure.


} // namespace Queries
```

```c++
// main.cpp
#include "common.hpp"
#include "builtins.hpp"
#include "queries.hpp"

#include <iostream>
#include <vector>
#include <string>
#include <cmath> // For std:: M_PI if needed, or just use float() in C++


// --- Helper to create test data ---
std::vector<Tuple> generate_test_data(int count) {
    std::vector<Tuple> data;
    MacAddress src_mac; // TODO: Initialize properly if needed
    MacAddress dst_mac; // TODO: Initialize properly if needed
    IpAddressV4 src_ip("127.0.0.1"); // TODO: Use proper constructor/parser
    IpAddressV4 dst_ip("127.0.0.1");

    // Example initialization (replace with real MAC parsing if available)
    try {
        src_mac = MacAddress("00:11:22:33:44:55");
        dst_mac = MacAddress("AA:BB:CC:DD:EE:FF");
    } catch(const std::exception& e) {
         std::cerr << "Warning: MAC address init failed: " << e.what() << std::endl;
    }


    for (int i = 0; i < count; ++i) {
        Tuple tup;
        tup["time"] = OpResult(0.000000 + static_cast<double>(i)); // Time progression

        tup["eth.src"] = OpResult(src_mac);
        tup["eth.dst"] = OpResult(dst_mac);
        tup["eth.ethertype"] = OpResult(static_cast<int64_t>(0x0800)); // IPv4

        tup["ipv4.hlen"] = OpResult(static_cast<int64_t>(20));
        tup["ipv4.proto"] = OpResult(static_cast<int64_t>(6)); // TCP
        tup["ipv4.len"] = OpResult(static_cast<int64_t>(60));
        tup["ipv4.src"] = OpResult(src_ip);
        tup["ipv4.dst"] = OpResult(dst_ip);

        tup["l4.sport"] = OpResult(static_cast<int64_t>(440 + i % 10)); // Vary source port slightly
        tup["l4.dport"] = OpResult(static_cast<int64_t>(50000));
        // Vary flags for testing different queries (e.g., SYN=2, ACK=16, SYNACK=18, FIN=1)
        int64_t flags = 0;
        if (i % 5 == 0) flags = 2;       // SYN
        else if (i % 5 == 1) flags = 18; // SYNACK
        else if (i % 5 == 2) flags = 16; // ACK
        else if (i % 5 == 3) flags = 1;  // FIN
        else flags = 16;                 // Default ACK
        tup["l4.flags"] = OpResult(flags);

        data.push_back(tup);
    }
    return data;
}

int main() {
    try {
        // --- Define the terminal operator (where the results go) ---
        // Example: Dump results to standard output using dump_tuple
        Operator terminal_op = Builtins::dump_tuple(std::cout, true); // Show resets

        // --- Create the query pipeline ---
        // Select the query to run, e.g., count_pkts
        Queries::OpCreator selected_query_creator = Queries::count_pkts();
        // Queries::OpCreator selected_query_creator = Queries::tcp_new_cons(5); // Example threshold

        // Instantiate the pipeline by applying the creator to the terminal operator
        Operator pipeline = selected_query_creator(terminal_op);


        // --- Generate some test data ---
        std::vector<Tuple> test_data = generate_test_data(20);


        // --- Run the data through the pipeline ---
        std::cout << "--- Processing Data ---" << std::endl;
        for (const auto& tup : test_data) {
             std::cout << "Input: " << Utils::string_of_tuple(tup) << std::endl;
             pipeline.next(tup); // Process next tuple
        }

        // --- Signal end of data (e.g., trigger final reset/aggregation) ---
        // Create a meaningful reset context if needed by the query, often just epoch info
        Tuple final_reset_context;
         // If the pipeline uses epoch, find the last epoch ID + 1 or similar
         // For simplicity, let's use an empty context unless epoch is known
         final_reset_context["eid"] = OpResult(static_cast<int64_t>(1)); // Example EID context if needed

        std::cout << "\n--- Final Reset ---" << std::endl;
        pipeline.reset(final_reset_context); // Trigger final aggregations and resets

        // --- Handling Multi-Operator Queries (like Joins) ---
        /*
        Queries::MultiOpCreator multi_query_creator = Queries::syn_flood_sonata();
        std::vector<Operator> multi_pipeline = multi_query_creator(terminal_op);

        if (!multi_pipeline.empty()) {
             Operator& branch1 = multi_pipeline[0];
             Operator& branch2 = multi_pipeline[1];
             // ... potentially more branches

             std::cout << "--- Processing Data (Multi-Branch) ---" << std::endl;
             for (const auto& tup : test_data) {
                 // Need logic to decide which branch(es) the tuple goes to,
                 // or if all tuples go to all branches (like split).
                 // For Sonata joins, typically all tuples go to all input branches.
                 std::cout << "Input: " << Utils::string_of_tuple(tup) << std::endl;
                  for(Operator& branch : multi_pipeline) {
                       branch.next(tup);
                  }
             }

              std::cout << "\n--- Final Reset (Multi-Branch) ---" << std::endl;
              for(Operator& branch : multi_pipeline) {
                  branch.reset(final_reset_context);
              }
        }
        */


        std::cout << "\nDone." << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "An unknown error occurred." << std::endl;
        return 1;
    }

    return 0;
}
```

**Compilation (Example using g++)**

You would need a C++17 compatible compiler:

```bash
g++ -std=c++17 -Wall -Wextra -pedantic \
    utils.cpp builtins.cpp queries.cpp main.cpp \
    -o stream_processor -I. # -I. assumes headers are in the same dir

./stream_processor
```

This translation provides the core structure and logic. Significant effort is still needed for:

1.  **Robust IP/MAC Parsing/Formatting:** Implement the `TODO`s in `IpAddressV4` and `MacAddress`.
2.  **Full `read_walts_csv` Implementation:** This is non-trivial file and state management.
3.  **Complete Join Logic:** The `join` implementation needs thorough testing and potentially refinement, especially regarding epoch synchronization and state cleanup.
4.  **Complete Query Implementations:** Fill in the details for all queries, especially the complex filter conditions and join extractor functions.
5.  **Error Handling:** Add more robust checks and error reporting.
6.  **Performance:** C++ offers opportunities for optimization (e.g., `std::unordered_map` vs. `std::map` if order isn't needed *and* hashing is efficient, move semantics), but the current translation prioritizes functional equivalence.
7.  **Hashing:** Ensure the provided hash functions for `OpResult` and `Tuple` are correct and perform reasonably well. Hashing maps/variants correctly can be tricky.