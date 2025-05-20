Okay, here's the C++ translation of the provided OCaml code. It attempts to follow idiomatic C++ practices, using standard library components like `std::variant`, `std::map`, `std::function`, `std::optional`, streams, and exceptions.

**Key C++ Idioms Used:**

1.  **`std::variant`:** Replaces OCaml's variant type `op_result`.
2.  **`std::map`:** Replaces OCaml's `Map.Make(String)`. Note that `std::map` keeps elements sorted by key, similar to OCaml's `Map`. `std::unordered_map` could be used for potentially better performance if key order isn't required, but would require defining hash functions for `Tuple` and `OpResult`. Using `std::map` avoids this complexity for now.
3.  **`std::function`:** Replaces OCaml's function types, providing type erasure for callable objects (like lambdas, function pointers).
4.  **`struct` / `class`:** Used for `Operator` and simple data structures like `IPv4Address` and `MACAddress`.
5.  **Namespaces:** Used to group related functions and types, mirroring OCaml modules.
6.  **Lambdas:** Used extensively for filter predicates, mapping functions, grouping functions, and reduction functions.
7.  **`std::optional`:** Used where OCaml code uses `find_opt`.
8.  **Streams (`iostream`, `fstream`, `sstream`):** Used for I/O and string formatting.
9.  **Exceptions (`std::runtime_error`):** Used for error handling, replacing OCaml's `Failure`.
10. **`using`:** For type aliases, similar to OCaml's `type`.
11. **Range-based for loops:** For iterating over containers.
12. **Header/Source Separation:** Code is structured into `.hpp` (declarations) and `.cpp` (definitions).
13. **`const` Correctness:** Applied where appropriate.

**Caveats & Assumptions:**

* **IP/MAC Address Handling:** Simple `struct`s are provided for `IPv4Address` and `MACAddress`. A real-world application might use a networking library (like Boost.Asio or a platform-specific API) for more robust handling and parsing. The `Ipaddr.V4.of_string_exn` behavior (raising exception on failure) is mimicked.
* **CSV Parsing:** The `read_walts_csv` parsing is basic, splitting by comma. Robust CSV parsing can be complex (handling quotes, escaped commas, etc.) and might benefit from a dedicated library.
* **Hashing for `unordered_map`:** As mentioned, `std::map` is used for `groupby`, `distinct`, and `join` state to avoid the complexity of defining hash functions for `Tuple` (which is `std::map`) and `OpResult` (which is `std::variant`). If performance with large datasets becomes critical, switching to `std::unordered_map` and implementing the necessary hash specializations would be the next step. `OpResult` and `Tuple` need `operator<` for `std::map`.
* **External Dependencies:** The OCaml code uses `Ipaddr` and `Bytes`. These are replaced with standard C++ or simple custom types.
* **Operator Chaining:** The custom OCaml operators `@=>` and `@==>` are replaced with named functions `chain` and `chain_double` for clarity, as custom symbolic infix operators aren't standard C++ practice.

---

**1. `common_utils.hpp`**

```cpp
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
```

---

**2. `common_utils.cpp`**

```cpp
#include "common_utils.hpp"
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <algorithm> // for std::find_if, std::for_each
#include <limits>    // for numeric_limits

namespace Utils {

// --- Address Implementations ---

IPv4Address::IPv4Address(const std::string& addr_str) {
    std::stringstream ss(addr_str);
    std::string segment;
    int i = 0;
    int val;
    while (std::getline(ss, segment, '.') && i < 4) {
        try {
            val = std::stoi(segment);
            if (val < 0 || val > 255) {
                 throw std::invalid_argument("Octet out of range");
            }
            octets[i++] = static_cast<unsigned char>(val);
        } catch (const std::exception& e) {
            throw std::runtime_error("Invalid IPv4 address format: '" + addr_str + "' segment '" + segment + "' error: " + e.what());
        }
    }
    if (i != 4 || ss.peek() != EOF) { // Check if exactly 4 segments were read and no trailing chars
         throw std::runtime_error("Invalid IPv4 address format: '" + addr_str + "' - expected 4 octets");
    }
}

std::string IPv4Address::toString() const {
    std::stringstream ss;
    ss << static_cast<int>(octets[0]) << "."
       << static_cast<int>(octets[1]) << "."
       << static_cast<int>(octets[2]) << "."
       << static_cast<int>(octets[3]);
    return ss.str();
}

bool IPv4Address::operator<(const IPv4Address& other) const {
    return octets < other.octets;
}
bool IPv4Address::operator==(const IPv4Address& other) const {
    return octets == other.octets;
}


MACAddress::MACAddress(const std::vector<unsigned char>& data) {
    if (data.size() != 6) {
        throw std::runtime_error("Invalid data size for MAC Address (expected 6 bytes)");
    }
    std::copy(data.begin(), data.end(), bytes.begin());
}
MACAddress::MACAddress(const std::array<unsigned char, 6>& data) : bytes(data) {}


std::string MACAddress::toString() const {
     return string_of_mac(*this); // Reuse utility
}

bool MACAddress::operator<(const MACAddress& other) const {
    return bytes < other.bytes;
}
 bool MACAddress::operator==(const MACAddress& other) const {
     return bytes == other.bytes;
 }

// Needed for std::map keys involving OpResult
bool operator<(const Empty& lhs, const Empty& rhs) { return false; } // All Empty are equal
bool operator==(const Empty& lhs, const Empty& rhs) { return true; } // All Empty are equal

bool operator<(const OpResult& lhs, const OpResult& rhs) {
    if (lhs.index() != rhs.index()) {
        return lhs.index() < rhs.index();
    }
    // Same type, compare values
    return std::visit(
        [](const auto& l, const auto& r) -> bool {
            // Need to compare values of the *same* type
            // This relies on the index check above ensuring types match
             using T = std::decay_t<decltype(l)>;
             if constexpr (!std::is_same_v<T, std::decay_t<decltype(r)>>) {
                  // This should not happen due to index check, but defensively return false
                  return false;
             } else {
                 // Handle potential NaN comparison issues for float
                 if constexpr (std::is_same_v<T, double>) {
                     if (std::isnan(l) && std::isnan(r)) return false; // NaNs compare equal for map ordering
                     if (std::isnan(l)) return true; // NaN is "less" than non-NaN
                     if (std::isnan(r)) return false;// non-NaN is not "less" than NaN
                 }
                 if constexpr (std::is_same_v<T, Empty>) {
                    return false; // All empty are equal
                 } else {
                    // Standard comparison for other types
                    return l < r;
                 }
             }
        },
        lhs, rhs
    );
}

bool operator==(const OpResult& lhs, const OpResult& rhs) {
     if (lhs.index() != rhs.index()) {
        return false;
    }
     // Same type, compare values
    return std::visit(
        [](const auto& l, const auto& r) -> bool {
             using T = std::decay_t<decltype(l)>;
             if constexpr (!std::is_same_v<T, std::decay_t<decltype(r)>>) {
                  return false; // Should not happen
             } else {
                 // Handle potential NaN comparison issues for float
                 if constexpr (std::is_same_v<T, double>) {
                     if (std::isnan(l) && std::isnan(r)) return true; // NaNs compare equal here
                     if (std::isnan(l) || std::isnan(r)) return false; // NaN != non-NaN
                 }
                 return l == r; // Standard comparison for other types (incl. Empty)
             }
        },
        lhs, rhs
    );
}


// --- Operator Chaining ---

Operator chain(const OpCreator& creator, const Operator& next_op) {
    return creator(next_op);
}

std::pair<Operator, Operator> chain_double(const DblOpCreator& creator, const Operator& op) {
    return creator(op);
}

// --- Conversion Utilities ---

std::string string_of_mac(const MACAddress& mac) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < 6; ++i) {
        ss << std::setw(2) << static_cast<int>(mac.bytes[i]);
        if (i < 5) ss << ":";
    }
    return ss.str();
}

std::string tcp_flags_to_string(int flags) {
    const std::vector<std::pair<std::string, int>> flag_map = {
        {"FIN", 1 << 0}, {"SYN", 1 << 1}, {"RST", 1 << 2},
        {"PSH", 1 << 3}, {"ACK", 1 << 4}, {"URG", 1 << 5},
        {"ECE", 1 << 6}, {"CWR", 1 << 7}
    };
    std::string result = "";
    for (const auto& pair : flag_map) {
        if ((flags & pair.second) == pair.second) {
            if (!result.empty()) {
                result += "|";
            }
            result += pair.first;
        }
    }
    return result.empty() ? "0" : result; // Return "0" if no flags set
}

int int_of_op_result(const OpResult& input) {
    try {
        return std::get<int>(input);
    } catch (const std::bad_variant_access& e) {
        throw std::runtime_error("Trying to extract int from non-int result");
    }
}

double float_of_op_result(const OpResult& input) {
     try {
        return std::get<double>(input);
    } catch (const std::bad_variant_access& e) {
        throw std::runtime_error("Trying to extract float from non-float result");
    }
}

std::string string_of_op_result(const OpResult& input) {
    return std::visit(
        [](const auto& value) -> std::string {
            using T = std::decay_t<decltype(value)>;
            if constexpr (std::is_same_v<T, double>) {
                std::stringstream ss;
                ss << std::fixed << std::setprecision(6) << value; // Match OCaml %f precision
                return ss.str();
            } else if constexpr (std::is_same_v<T, int>) {
                return std::to_string(value);
            } else if constexpr (std::is_same_v<T, IPv4Address>) {
                return value.toString();
            } else if constexpr (std::is_same_v<T, MACAddress>) {
                 return value.toString();
            } else if constexpr (std::is_same_v<T, Empty>) {
                return "Empty";
            } else {
                 // Should not happen with std::variant
                return "[Unknown Type]";
            }
        },
        input);
}

std::string string_of_tuple(const Tuple& input_tuple) {
    std::stringstream ss;
    for (const auto& pair : input_tuple) {
        ss << "\"" << pair.first << "\" => " << string_of_op_result(pair.second) << ", ";
    }
    std::string result = ss.str();
    // Remove trailing ", " if not empty
    if (result.length() > 2) {
        result.pop_back();
        result.pop_back();
    }
    return result;
}

Tuple tuple_of_list(const std::vector<std::pair<std::string, OpResult>>& tup_list) {
    Tuple result;
    for(const auto& pair : tup_list) {
        result.insert(pair); // or result[pair.first] = pair.second;
    }
    return result;
}

void dump_tuple(std::ostream& outc, const Tuple& tup) {
    outc << string_of_tuple(tup) << std::endl; // endl flushes
}


// --- Lookup Utilities ---

std::optional<OpResult> lookup_opt(const std::string& key, const Tuple& tup) {
    auto it = tup.find(key);
    if (it != tup.end()) {
        return it->second;
    }
    return std::nullopt;
}

int lookup_int(const std::string& key, const Tuple& tup) {
    auto it = tup.find(key);
    if (it != tup.end()) {
        return int_of_op_result(it->second); // Throws if not an int
    }
    throw std::runtime_error("Key '" + key + "' not found in tuple for lookup_int");
}

double lookup_float(const std::string& key, const Tuple& tup) {
     auto it = tup.find(key);
    if (it != tup.end()) {
        return float_of_op_result(it->second); // Throws if not a float
    }
    throw std::runtime_error("Key '" + key + "' not found in tuple for lookup_float");
}

} // namespace Utils
```

---

**3. `builtins.hpp`**

```cpp
#ifndef BUILTINS_HPP
#define BUILTINS_HPP

#include "common_utils.hpp"
#include <string>
#include <vector>
#include <list> // For read_walts_csv input filenames
#include <map> // For Hashtbl equivalent state
#include <set> // Alternative for distinct keys if values don't matter


namespace Builtins {

    using namespace Utils; // Use types from Utils namespace

    constexpr int INIT_TABLE_SIZE = 10000; // Used as hint if using unordered_map

    // --- Dump Operators ---
    Operator dump_tuple_op(std::ostream& outc, bool show_reset = false);
    Operator dump_as_csv(std::ostream& outc,
                         std::optional<std::pair<std::string, std::string>> static_field = std::nullopt,
                         bool header = true);
    Operator dump_walts_csv(const std::string& filename);

    // --- Input Operators ---
    OpResult get_ip_or_zero(const std::string& input);
    void read_walts_csv(const std::vector<std::string>& file_names,
                        const std::vector<Operator>& ops, // Match OCaml: one op per file
                        const std::string& epoch_id_key = "eid");

    // --- Meta Operators ---
    Operator meta_meter(const std::string& name,
                        std::ostream& outc,
                        Operator next_op,
                        std::optional<std::string> static_field = std::nullopt);

    // --- Core Stream Operators ---
    Operator epoch(double epoch_width, const std::string& key_out, Operator next_op);
    Operator filter(std::function<bool(const Tuple&)> f, Operator next_op);
    Operator map(std::function<Tuple(const Tuple&)> f, Operator next_op);

    // --- Groupby/Distinct Related ---
    using GroupingFunc = std::function<Tuple(const Tuple&)>;
    using ReductionFunc = std::function<OpResult(OpResult, const Tuple&)>;

    Operator groupby(GroupingFunc group_by_func,
                     ReductionFunc reduce_func,
                     const std::string& out_key,
                     Operator next_op);

    Operator distinct(GroupingFunc group_by_func, Operator next_op);

    // Groupby Utilities
    Tuple filter_groups(const std::vector<std::string>& incl_keys, const Tuple& tup);
    Tuple single_group(const Tuple&); // Grouping function for a single group
    OpResult counter(OpResult current_val, const Tuple& tup); // Reduction: count tuples
    OpResult sum_ints(const std::string& search_key, OpResult init_val, const Tuple& tup); // Reduction: sum int field


    // --- Split/Join Operators ---
    Operator split(Operator left, Operator right);

    using KeyExtractor = std::function<std::pair<Tuple, Tuple>(const Tuple&)>;

    std::pair<Operator, Operator> join(KeyExtractor left_extractor,
                                       KeyExtractor right_extractor,
                                       Operator next_op,
                                       const std::string& eid_key = "eid");

    // Join Utility
    Tuple rename_filtered_keys(const std::vector<std::pair<std::string, std::string>>& renamings,
                               const Tuple& in_tup);

    // --- Filter Utilities ---
    bool key_geq_int(const std::string& key, int threshold, const Tuple& tup);
    int get_mapped_int(const std::string& key, const Tuple& tup);   // Convenience alias
    double get_mapped_float(const std::string& key, const Tuple& tup); // Convenience alias


} // namespace Builtins

#endif // BUILTINS_HPP
```

---

**4. `builtins.cpp`**

```cpp
#include "builtins.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <memory> // For shared_ptr if needed for state capture
#include <stdexcept>
#include <algorithm> // For std::find
#include <cstdio>    // For sscanf (alternative to stream parsing)


namespace Builtins {

// --- Dump Operators ---

Operator dump_tuple_op(std::ostream& outc, bool show_reset) {
    // Capture outc by reference, show_reset by value
    return Operator{
        [&outc](const Tuple& tup) { // next lambda
            dump_tuple(outc, tup);
        },
        [&outc, show_reset](const Tuple& tup) { // reset lambda
            if (show_reset) {
                dump_tuple(outc, tup);
                outc << "[reset]" << std::endl;
            }
            // Reset doesn't necessarily propagate in a dump
        }
    };
}

Operator dump_as_csv(std::ostream& outc,
                     std::optional<std::pair<std::string, std::string>> static_field,
                     bool header) {
    // State needs to be mutable and captured
    auto first = std::make_shared<bool>(header); // Use shared_ptr to manage state across lambda calls

    return Operator{
        // next lambda captures state
        [&outc, static_field, first](const Tuple& tup) {
            if (*first) {
                if (static_field) {
                    outc << static_field->first << ",";
                }
                bool first_key = true;
                for (const auto& pair : tup) {
                     if (!first_key) outc << ",";
                     outc << pair.first;
                     first_key = false;
                }
                outc << "\n"; // Use \n instead of endl for potentially better performance
                *first = false;
            }

            if (static_field) {
                outc << static_field->second << ",";
            }
            bool first_val = true;
            for (const auto& pair : tup) {
                if (!first_val) outc << ",";
                outc << string_of_op_result(pair.second);
                first_val = false;
            }
            outc << "\n";
             outc.flush(); // Flush explicitly if needed line-by-line
        },
        // reset lambda (does nothing here)
        [](const Tuple& tup) { }
    };
}


Operator dump_walts_csv(const std::string& filename) {
    // State: output stream and whether it's the first write
    auto outc_ptr = std::make_shared<std::optional<std::ofstream>>(); // Optional to handle lazy opening
    auto first = std::make_shared<bool>(true);

    return Operator{
        [filename, outc_ptr, first](const Tuple& tup) {
            if (*first) {
                *outc_ptr = std::ofstream(filename); // Open the file
                if (!outc_ptr->value().is_open()) {
                     throw std::runtime_error("Failed to open file for dump_walts_csv: " + filename);
                }
                *first = false;
                // Walt's format doesn't seem to have a header line in the OCaml impl.
            }

            std::ostream& out = outc_ptr->value(); // Get reference to the stream

            // Explicitly find keys required by Walt's format
            auto src_ip = lookup_opt("src_ip", tup);
            auto dst_ip = lookup_opt("dst_ip", tup);
            auto src_port = lookup_opt("src_l4_port", tup);
            auto dst_port = lookup_opt("dst_l4_port", tup);
            auto pkt_count = lookup_opt("packet_count", tup);
            auto byte_count = lookup_opt("byte_count", tup);
            auto epoch_id = lookup_opt("epoch_id", tup);

             // Helper to get string or "0" if missing/invalid
            auto get_str = [](const std::optional<OpResult>& opt_res) {
                return opt_res ? string_of_op_result(*opt_res) : std::string("0");
            };

             out << get_str(src_ip) << ","
                << get_str(dst_ip) << ","
                << get_str(src_port) << ","
                << get_str(dst_port) << ","
                << get_str(pkt_count) << ","
                << get_str(byte_count) << ","
                << get_str(epoch_id) << "\n";
             out.flush(); // Flush after each line
        },
        [outc_ptr](const Tuple& tup) {
            // Reset in this context might mean closing the file,
            // or doing nothing if the pipeline continues. OCaml does nothing.
             if (*outc_ptr) {
                 // Optional: Could close the file here if appropriate for pipeline end
                 // outc_ptr->value().close();
                 // *outc_ptr = std::nullopt;
             }
        }
    };
}

// --- Input Operators ---

OpResult get_ip_or_zero(const std::string& input) {
    if (input == "0") {
        return OpResult{0}; // Int 0
    } else {
        try {
            return OpResult{IPv4Address(input)}; // Construct IPv4Address
        } catch (const std::exception& e) {
            // OCaml raises exception; C++ might log or return Empty/error
             // Let's stick to throwing for now to match OCaml behavior
            throw std::runtime_error("Failed to parse IP '" + input + "': " + e.what());
        }
    }
}


// Helper to parse Walt's CSV line (basic implementation)
std::optional<Tuple> parse_walts_line(const std::string& line, const std::string& epoch_id_key) {
     std::stringstream ss(line);
     std::string segment;
     std::vector<std::string> parts;
     while (std::getline(ss, segment, ',')) {
         parts.push_back(segment);
     }

     if (parts.size() != 7) {
         // Handle error: incorrect number of fields
         std::cerr << "Warning: Skipping malformed line (expected 7 fields): " << line << std::endl;
         return std::nullopt;
     }

    try {
        std::string src_ip_str = parts[0];
        std::string dst_ip_str = parts[1];
        int src_port = std::stoi(parts[2]);
        int dst_port = std::stoi(parts[3]);
        int pkt_count = std::stoi(parts[4]);
        int byte_count = std::stoi(parts[5]);
        int epoch_id = std::stoi(parts[6]);

        Tuple p;
        p["ipv4.src"] = get_ip_or_zero(src_ip_str); // Can throw
        p["ipv4.dst"] = get_ip_or_zero(dst_ip_str); // Can throw
        p["l4.sport"] = src_port;
        p["l4.dport"] = dst_port;
        p["packet_count"] = pkt_count;
        p["byte_count"] = byte_count;
        p[epoch_id_key] = epoch_id;

        return p;
    } catch (const std::exception& e) {
         std::cerr << "Warning: Skipping line due to parsing error (" << e.what() << "): " << line << std::endl;
         return std::nullopt;
    }
}

void read_walts_csv(const std::vector<std::string>& file_names,
                    const std::vector<Operator>& ops,
                    const std::string& epoch_id_key) {

    if (file_names.size() != ops.size()) {
        throw std::runtime_error("read_walts_csv: Number of file names must match number of operators.");
    }

    struct FileState {
        std::ifstream stream;
        int current_eid = 0;
        long long tuple_count_this_epoch = 0; // Use long long for potentially large counts
        bool active = true;
        std::string filename; // For error messages
    };

    std::vector<FileState> states;
    states.reserve(file_names.size());

    for (const auto& fname : file_names) {
        states.emplace_back();
        states.back().filename = fname;
        states.back().stream.open(fname);
        if (!states.back().stream.is_open()) {
             // Close already opened files before throwing
             for(auto& state : states) {
                 if(state.stream.is_open()) state.stream.close();
             }
             throw std::runtime_error("Failed to open input file: " + fname);
        }
    }

    size_t active_count = states.size();
    std::string line;

    while (active_count > 0) {
        for (size_t i = 0; i < states.size(); ++i) {
            if (!states[i].active) continue;

            FileState& state = states[i];
            const Operator& op = ops[i];

            if (std::getline(state.stream, line)) {
                std::optional<Tuple> parsed_tuple_opt = parse_walts_line(line, epoch_id_key);

                if (parsed_tuple_opt) {
                    Tuple p = std::move(*parsed_tuple_opt); // Move the tuple out
                    int file_epoch_id = lookup_int(epoch_id_key, p); // Assumes key exists and is int

                    state.tuple_count_this_epoch++;

                    // Handle epoch boundary crossings
                    if (file_epoch_id > state.current_eid) {
                         // Send resets for missed epochs
                        while (file_epoch_id > state.current_eid) {
                            Tuple reset_info;
                            reset_info[epoch_id_key] = state.current_eid;
                            reset_info["tuples"] = static_cast<int>(state.tuple_count_this_epoch); // OCaml passes tuple count in reset
                            op.reset(reset_info);
                            state.tuple_count_this_epoch = 0; // Reset count for next epoch
                            state.current_eid++;
                        }
                        // After catching up, current_eid should match file_epoch_id
                        // Re-increment count since the current tuple belongs to this new epoch
                         state.tuple_count_this_epoch = 1;
                    }
                    // else: tuple belongs to the current or past epoch (handle as needed, OCaml seems to process it)

                    Tuple next_tuple = p; // Make a copy or modify in place if safe
                    next_tuple["tuples"] = static_cast<int>(state.tuple_count_this_epoch); // Add current count
                    op.next(next_tuple);

                } else {
                    // Line parsing failed (warning already printed in helper)
                    // Decide whether to continue or handle error more strictly
                }

            } else { // End Of File reached for this stream
                 if (state.stream.eof()) {
                    // Send final reset for the last processed epoch + 1
                    Tuple reset_info;
                    reset_info[epoch_id_key] = state.current_eid; // OCaml uses eid+1, but let's use current to cap the last full epoch
                    reset_info["tuples"] = static_cast<int>(state.tuple_count_this_epoch);
                    op.reset(reset_info);

                    // Send one more reset for eid+1 like OCaml? Seems redundant if next reads use new state.
                    // Let's match OCaml here:
                    Tuple final_reset_info;
                    final_reset_info[epoch_id_key] = state.current_eid + 1;
                    final_reset_info["tuples"] = 0; // No tuples in this final boundary epoch
                    op.reset(final_reset_info);


                    state.active = false;
                    active_count--;
                    state.stream.close();
                 } else {
                      // Handle potential read error other than EOF
                      std::cerr << "Error reading from file: " << state.filename << std::endl;
                      state.active = false;
                      active_count--;
                      state.stream.close();
                 }
            }
        }
    }
    std::cout << "Done reading files." << std::endl;
}


// --- Meta Operators ---

Operator meta_meter(const std::string& name,
                    std::ostream& outc,
                    Operator next_op,
                    std::optional<std::string> static_field) {
    // Mutable state captured by shared_ptr for lambdas
    auto epoch_count = std::make_shared<long long>(0);
    auto tups_count = std::make_shared<long long>(0);

    return Operator{
        [next_op, tups_count](const Tuple& tup) {
            (*tups_count)++;
            next_op.next(tup); // Pass tuple downstream
        },
        [name, &outc, next_op, static_field, epoch_count, tups_count](const Tuple& tup) {
            outc << *epoch_count << ","
                 << name << ","
                 << *tups_count << ","
                 << (static_field ? *static_field : "")
                 << "\n"; // Use \n
            outc.flush(); // Flush output

            *tups_count = 0; // Reset tuple count for the next epoch
            (*epoch_count)++; // Increment epoch count

            next_op.reset(tup); // Propagate reset downstream
        }
    };
}


// --- Core Stream Operators ---

Operator epoch(double epoch_width, const std::string& key_out, Operator next_op) {
    // Mutable state capture
    auto epoch_boundary = std::make_shared<double>(0.0);
    auto eid = std::make_shared<int>(0);

    return Operator{
        [epoch_width, key_out, next_op, epoch_boundary, eid](const Tuple& tup) {
            double time = lookup_float("time", tup); // Assumes "time" key exists and is float

            if (*epoch_boundary == 0.0) { // First tuple, initialize boundary
                *epoch_boundary = time + epoch_width;
            } else if (time >= *epoch_boundary) {
                // Time crossed one or more epoch boundaries
                while (time >= *epoch_boundary) {
                    Tuple reset_info;
                    reset_info[key_out] = *eid;
                    next_op.reset(reset_info); // Send reset for completed epoch

                    *epoch_boundary += epoch_width; // Advance boundary
                    (*eid)++; // Increment epoch ID
                }
            }
            // Add epoch ID to current tuple and send downstream
            Tuple out_tup = tup; // Copy tuple
            out_tup[key_out] = *eid;
            next_op.next(out_tup);
        },
        [key_out, next_op, epoch_boundary, eid](const Tuple& tup) {
             // When an external reset comes, send a final reset for the current epoch
            Tuple final_reset_info;
            final_reset_info[key_out] = *eid;
             // Merge external reset info? OCaml doesn't explicitly.
             // Let's just pass the essential eid derived locally.
            next_op.reset(final_reset_info);

             // Reset internal state for potential reuse
            *epoch_boundary = 0.0;
            *eid = 0;
        }
    };
}

Operator filter(std::function<bool(const Tuple&)> f, Operator next_op) {
    return Operator{
        [f, next_op](const Tuple& tup) {
            if (f(tup)) {
                next_op.next(tup); // Pass tuple if predicate is true
            }
        },
        [next_op](const Tuple& tup) {
            next_op.reset(tup); // Always propagate reset
        }
    };
}

Operator map(std::function<Tuple(const Tuple&)> f, Operator next_op) {
    return Operator{
        [f, next_op](const Tuple& tup) {
            next_op.next(f(tup)); // Pass transformed tuple
        },
        [next_op](const Tuple& tup) {
            next_op.reset(tup); // Always propagate reset
        }
    };
}

// --- Groupby/Distinct Related ---

Operator groupby(GroupingFunc group_by_func,
                 ReductionFunc reduce_func,
                 const std::string& out_key,
                 Operator next_op) {
    // State: map from grouping key (Tuple) to accumulated value (OpResult)
    // Using std::map requires Tuple and OpResult to have operator<
    auto h_tbl = std::make_shared<std::map<Tuple, OpResult>>();
    // auto reset_counter = std::make_shared<int>(0); // OCaml tracks this, C++ might not need unless for debugging

    return Operator{
        [group_by_func, reduce_func, h_tbl](const Tuple& tup) {
            Tuple grouping_key = group_by_func(tup);
            auto it = h_tbl->find(grouping_key);

            if (it != h_tbl->end()) {
                // Key exists, reduce current value with new tuple
                it->second = reduce_func(it->second, tup);
            } else {
                // New key, reduce Empty value with new tuple
                OpResult initial_val = Empty{};
                (*h_tbl)[grouping_key] = reduce_func(initial_val, tup);
            }
        },
        [out_key, next_op, h_tbl](const Tuple& reset_tup) {
            // (*reset_counter)++;
            for (const auto& pair : *h_tbl) {
                const Tuple& grouping_key = pair.first;
                const OpResult& accumulated_val = pair.second;

                // Create output tuple: merge reset info, grouping key, and result
                Tuple out_tup = reset_tup; // Start with reset info

                // Add grouping key fields (overwrite if conflicts with reset_tup)
                for (const auto& key_val : grouping_key) {
                    out_tup[key_val.first] = key_val.second;
                }

                // Add the accumulated result
                out_tup[out_key] = accumulated_val;

                next_op.next(out_tup); // Send aggregated tuple downstream
            }

            // Propagate reset downstream *after* processing groups
            next_op.reset(reset_tup);

            // Clear the table for the next epoch
            h_tbl->clear();
        }
    };
}


Operator distinct(GroupingFunc group_by_func, Operator next_op) {
     // State: map storing unique keys encountered this epoch
     // Value can be bool or anything, just presence matters. Using bool.
    auto h_tbl = std::make_shared<std::map<Tuple, bool>>();
    // auto reset_counter = std::make_shared<int>(0);

    return Operator{
        [group_by_func, h_tbl](const Tuple& tup) {
             Tuple grouping_key = group_by_func(tup);
             // Add/overwrite key in the map. If it exists, value is updated to true.
             // If it doesn't exist, it's inserted with value true.
             (*h_tbl)[grouping_key] = true;
        },
        [next_op, h_tbl](const Tuple& reset_tup) {
            // (*reset_counter)++;
            for (const auto& pair : *h_tbl) {
                 const Tuple& distinct_key = pair.first;

                 // Create output tuple: merge reset info and distinct key fields
                 Tuple out_tup = reset_tup;
                 for (const auto& key_val : distinct_key) {
                     out_tup[key_val.first] = key_val.second;
                 }
                 next_op.next(out_tup); // Send distinct key tuple downstream
             }

             next_op.reset(reset_tup); // Propagate reset
             h_tbl->clear(); // Clear for next epoch
        }
    };
}


// Groupby Utilities Implementations
Tuple filter_groups(const std::vector<std::string>& incl_keys, const Tuple& tup) {
    Tuple result;
    for (const auto& key : incl_keys) {
        auto it = tup.find(key);
        if (it != tup.end()) {
            result[key] = it->second;
        }
    }
    return result;
}

Tuple single_group(const Tuple&) {
    return Tuple{}; // Return an empty map, representing the single group key
}

OpResult counter(OpResult current_val, const Tuple&) {
     // Check if current_val holds an int
    if (auto* p_int = std::get_if<int>(&current_val)) {
        return OpResult{(*p_int) + 1};
    } else if (std::holds_alternative<Empty>(current_val)) {
         // First item for this group
        return OpResult{1};
    } else {
         // Error condition or unexpected type - OCaml returns original value
         // Let's return the original value to mimic, but log a warning.
         std::cerr << "Warning: Counter expected Int or Empty, got different type." << std::endl;
         return current_val;
    }
}

OpResult sum_ints(const std::string& search_key, OpResult init_val, const Tuple& tup) {
     int current_sum = 0;
     // Get the initial sum
     if (auto* p_int = std::get_if<int>(&init_val)) {
         current_sum = *p_int;
     } else if (!std::holds_alternative<Empty>(init_val)) {
         // If initial value is not Empty and not Int, return it (error state)
          std::cerr << "Warning: sum_ints expected initial value Int or Empty." << std::endl;
         return init_val;
     }
     // else: init_val is Empty, current_sum remains 0

     // Find the value to add from the current tuple
     auto it = tup.find(search_key);
     if (it != tup.end()) {
         if (auto* p_add_int = std::get_if<int>(&(it->second))) {
             return OpResult{current_sum + *p_add_int};
         } else {
             // Key found but is not an int - OCaml raises Failure
             throw std::runtime_error("'sum_ints' failed: value for key \"" + search_key + "\" is not an integer.");
         }
     } else {
         // Key not found in tuple - OCaml raises Failure
          throw std::runtime_error("'sum_ints' failed: key \"" + search_key + "\" not found in tuple.");
     }
}


// --- Split/Join Operators ---

Operator split(Operator left, Operator right) {
    return Operator{
        [left, right](const Tuple& tup) {
            left.next(tup);  // Send to left
            right.next(tup); // Send to right
        },
        [left, right](const Tuple& tup) {
            left.reset(tup);  // Reset left
            right.reset(tup); // Reset right
        }
    };
}


std::pair<Operator, Operator> join(KeyExtractor left_extractor,
                                   KeyExtractor right_extractor,
                                   Operator next_op,
                                   const std::string& eid_key) {

    // State for join: two hash tables (maps) storing pending tuples keyed by their join key + epoch
    // Using std::map as key requires operator< for Tuple
    auto h_tbl1 = std::make_shared<std::map<Tuple, Tuple>>();
    auto h_tbl2 = std::make_shared<std::map<Tuple, Tuple>>();

    // State for epoch tracking for each side
    auto left_curr_epoch = std::make_shared<int>(0);
    auto right_curr_epoch = std::make_shared<int>(0);


    // Lambda defining the logic for one side of the join
    auto handle_join_side =
        [&](std::shared_ptr<std::map<Tuple, Tuple>> current_h_tbl, // Map for this side's pending tuples
            std::shared_ptr<std::map<Tuple, Tuple>> other_h_tbl,   // Map for the other side's pending tuples
            std::shared_ptr<int> current_epoch_ref,                // This side's current epoch state
            std::shared_ptr<int> other_epoch_ref,                  // Other side's current epoch state
            KeyExtractor key_extractor) -> Operator // The key extractor for this side
        {
        return Operator{
            // next lambda
            [=](const Tuple& tup) { // Capture all needed state by value/copy
                auto [key, vals] = key_extractor(tup); // Extract key and value parts
                int tuple_epoch = get_mapped_int(eid_key, tup); // Get epoch ID

                // Advance current epoch marker if necessary, sending resets
                while (tuple_epoch > *current_epoch_ref) {
                    // Only send reset if the *other* side has also advanced past this epoch
                    if (*other_epoch_ref > *current_epoch_ref) {
                         Tuple reset_info;
                         reset_info[eid_key] = *current_epoch_ref;
                         next_op.reset(reset_info);
                    }
                    (*current_epoch_ref)++;
                }
                // At this point, *current_epoch_ref >= tuple_epoch
                // If tuple_epoch < *current_epoch_ref, it's a late tuple. OCaml processes it.

                // Create the actual key for the hash table (join key + epoch id)
                Tuple lookup_key = key; // Start with extracted join key
                lookup_key[eid_key] = tuple_epoch; // Add epoch id

                // Try to find a match in the *other* table
                auto match_it = other_h_tbl->find(lookup_key);
                if (match_it != other_h_tbl->end()) {
                    // Match found! Combine tuples and send downstream
                    Tuple matched_vals = match_it->second;
                    other_h_tbl->erase(match_it); // Consume the matched tuple

                    // Merge: lookup_key (has join key + eid) + vals (from current) + matched_vals
                    Tuple joined_tup = lookup_key; // Start with key+eid
                     // Add current side's values
                    for(const auto& p : vals) joined_tup[p.first] = p.second;
                    // Add matched side's values (overwriting if conflict, OCaml uses union favoring left?)
                    // OCaml `Tuple.union (fun _ a _ -> Some a) left right` favors left (`a`).
                    // Let's assume current side (`vals`) takes precedence over matched side (`matched_vals`)
                    for(const auto& p : matched_vals) {
                        // Add only if key doesn't exist from 'vals' or 'lookup_key' already
                        joined_tup.try_emplace(p.first, p.second);
                    }

                    next_op.next(joined_tup);

                } else {
                    // No match found, store this tuple in the *current* table
                    (*current_h_tbl)[lookup_key] = vals;
                }
            },
            // reset lambda
            [=](const Tuple& reset_tup) { // Capture necessary state
                 // When reset arrives, primarily advance epoch counter if needed
                int reset_epoch = get_mapped_int(eid_key, reset_tup);

                // Advance current epoch marker based on reset signal
                 while (reset_epoch > *current_epoch_ref) {
                    if (*other_epoch_ref > *current_epoch_ref) {
                         Tuple epoch_reset_info;
                         epoch_reset_info[eid_key] = *current_epoch_ref;
                         next_op.reset(epoch_reset_info);
                    }
                    (*current_epoch_ref)++;
                }
                 // Note: Join doesn't clear its tables on external reset, only implicitly
                 //       through epoch advancement and tuple consumption.
                 //       If a full clear is needed, it would go here.
                 // OCaml doesn't clear, it relies on epoch matching.
            }
        };
    };

    // Create the two operators for the join sides
    Operator left_op = handle_join_side(h_tbl1, h_tbl2, left_curr_epoch, right_curr_epoch, left_extractor);
    Operator right_op = handle_join_side(h_tbl2, h_tbl1, right_curr_epoch, left_curr_epoch, right_extractor);

    return {left_op, right_op};
}


// Join Utility Implementation
Tuple rename_filtered_keys(const std::vector<std::pair<std::string, std::string>>& renamings,
                           const Tuple& in_tup) {
    Tuple result;
    for (const auto& rename_pair : renamings) {
        const std::string& old_key = rename_pair.first;
        const std::string& new_key = rename_pair.second;

        auto it = in_tup.find(old_key);
        if (it != in_tup.end()) {
            result[new_key] = it->second; // Add with the new key
        }
    }
    return result;
}


// --- Filter Utilities ---
bool key_geq_int(const std::string& key, int threshold, const Tuple& tup) {
    try {
        return lookup_int(key, tup) >= threshold;
    } catch (const std::exception& e) {
        // Handle cases where key doesn't exist or isn't an int
        // OCaml would raise an exception. C++ filter could return false.
        // Let's return false for robustness in filter context.
        // std::cerr << "Warning: key_geq_int check failed for key '" << key << "': " << e.what() << std::endl;
        return false;
    }
}

// Convenience aliases using Utils::lookup_*
int get_mapped_int(const std::string& key, const Tuple& tup) {
    return lookup_int(key, tup); // Will throw if key missing or not int
}

double get_mapped_float(const std::string& key, const Tuple& tup) {
    return lookup_float(key, tup); // Will throw if key missing or not float
}


} // namespace Builtins

```

---

**5. `sonata_queries.hpp`**

```cpp
#ifndef SONATA_QUERIES_HPP
#define SONATA_QUERIES_HPP

#include "common_utils.hpp"
#include "builtins.hpp"
#include <vector>

namespace SonataQueries {

    using namespace Utils;
    using namespace Builtins;

    // Simple Queries
    Operator ident(Operator next_op);
    Operator count_pkts(Operator next_op);
    Operator pkts_per_src_dst(Operator next_op);
    Operator distinct_srcs(Operator next_op);

    // Sonata Benchmark Queries (1-8)
    Operator tcp_new_cons(Operator next_op);
    Operator ssh_brute_force(Operator next_op);
    Operator super_spreader(Operator next_op);
    Operator port_scan(Operator next_op);
    Operator ddos(Operator next_op);
    // Queries returning multiple operators for joins
    std::vector<Operator> syn_flood_sonata(Operator next_op);
    std::vector<Operator> completed_flows(Operator next_op);
    std::vector<Operator> slowloris(Operator next_op);

    // Other Test Queries
    std::vector<Operator> join_test(Operator next_op);
    Operator q3(Operator next_op); // Distinct src/dst pairs
    Operator q4(Operator next_op); // Packets per destination

} // namespace SonataQueries


#endif // SONATA_QUERIES_HPP
```

---

**6. `sonata_queries.cpp`**

```cpp
#include "sonata_queries.hpp"
#include <vector>
#include <string>
#include <cmath> // For std::round or division checks if needed

namespace SonataQueries {

    using namespace Utils;
    using namespace Builtins;

// Helper lambda for filtering groups
auto filter_groups_l = [](const std::vector<std::string>& keys) {
    return [keys](const Tuple& tup) { return filter_groups(keys, tup); };
};

// Helper lambda for checking int field >= threshold
auto key_geq_int_l = [](const std::string& key, int threshold) {
    return [key, threshold](const Tuple& tup) { return key_geq_int(key, threshold, tup); };
};

// Helper lambda for renaming keys
auto rename_filtered_keys_l = [](const std::vector<std::pair<std::string, std::string>>& renames) {
    return [renames](const Tuple& tup) { return rename_filtered_keys(renames, tup); };
};


// --- Simple Queries ---
Operator ident(Operator next_op) {
    // Filter out eth.src and eth.dst
    auto filter_func = [](const Tuple& tup) -> Tuple {
        Tuple result;
        for (const auto& pair : tup) {
            if (pair.first != "eth.src" && pair.first != "eth.dst") {
                result.insert(pair);
            }
        }
        return result;
    };
    return chain(map(filter_func), next_op);
}

Operator count_pkts(Operator next_op) {
    OpCreator step1 = [](Operator op) { return epoch(1.0, "eid", op); };
    OpCreator step2 = [](Operator op) { return groupby(single_group, counter, "pkts", op); };

    return chain(step1, chain(step2, next_op));
}


Operator pkts_per_src_dst(Operator next_op) {
    std::vector<std::string> group_keys = {"ipv4.src", "ipv4.dst"};
    OpCreator step1 = [](Operator op) { return epoch(1.0, "eid", op); };
    OpCreator step2 = [&](Operator op) { return groupby(filter_groups_l(group_keys), counter, "pkts", op); };

    return chain(step1, chain(step2, next_op));
}

Operator distinct_srcs(Operator next_op) {
     std::vector<std::string> distinct_keys = {"ipv4.src"};
     OpCreator step1 = [](Operator op) { return epoch(1.0, "eid", op); };
     OpCreator step2 = [&](Operator op) { return distinct(filter_groups_l(distinct_keys), op); };
     OpCreator step3 = [](Operator op) { return groupby(single_group, counter, "srcs", op); };

     return chain(step1, chain(step2, chain(step3, next_op)));
}

// --- Sonata Benchmark Queries (1-8) ---

// Sonata 1
Operator tcp_new_cons(Operator next_op) {
    const int threshold = 40;
    std::vector<std::string> group_keys = {"ipv4.dst"};

    auto filter_syn = [](const Tuple& tup) {
        try {
            return get_mapped_int("ipv4.proto", tup) == 6 && // TCP
                   get_mapped_int("l4.flags", tup) == 2;    // SYN
        } catch (...) { return false; }
    };

    OpCreator step1 = [](Operator op) { return epoch(1.0, "eid", op); };
    OpCreator step2 = [&](Operator op) { return filter(filter_syn, op); };
    OpCreator step3 = [&](Operator op) { return groupby(filter_groups_l(group_keys), counter, "cons", op); };
    OpCreator step4 = [&](Operator op) { return filter(key_geq_int_l("cons", threshold), op); };

    return chain(step1, chain(step2, chain(step3, chain(step4, next_op))));
}

// Sonata 2
Operator ssh_brute_force(Operator next_op) {
    const int threshold = 40;
     std::vector<std::string> distinct_keys = {"ipv4.src", "ipv4.dst", "ipv4.len"};
     std::vector<std::string> group_keys = {"ipv4.dst", "ipv4.len"};

     auto filter_ssh_syn = [](const Tuple& tup) { // Assuming brute force looks at SYN on port 22
        try {
            return get_mapped_int("ipv4.proto", tup) == 6 && // TCP
                   get_mapped_int("l4.dport", tup) == 22;   // SSH Port
                   // Original OCaml didn't filter flags here, maybe intended?
                   // && get_mapped_int("l4.flags", tup) == 2; // SYN
        } catch (...) { return false; }
    };

    OpCreator step1 = [](Operator op) { return epoch(1.0, "eid", op); };
    OpCreator step2 = [&](Operator op) { return filter(filter_ssh_syn, op); };
    OpCreator step3 = [&](Operator op) { return distinct(filter_groups_l(distinct_keys), op); };
    OpCreator step4 = [&](Operator op) { return groupby(filter_groups_l(group_keys), counter, "srcs", op); };
    OpCreator step5 = [&](Operator op) { return filter(key_geq_int_l("srcs", threshold), op); };

    return chain(step1, chain(step2, chain(step3, chain(step4, chain(step5, next_op)))));
}

// Sonata 3
Operator super_spreader(Operator next_op) {
    const int threshold = 40;
    std::vector<std::string> distinct_keys = {"ipv4.src", "ipv4.dst"};
    std::vector<std::string> group_keys = {"ipv4.src"};

    OpCreator step1 = [](Operator op) { return epoch(1.0, "eid", op); };
    OpCreator step2 = [&](Operator op) { return distinct(filter_groups_l(distinct_keys), op); };
    OpCreator step3 = [&](Operator op) { return groupby(filter_groups_l(group_keys), counter, "dsts", op); };
    OpCreator step4 = [&](Operator op) { return filter(key_geq_int_l("dsts", threshold), op); };

    return chain(step1, chain(step2, chain(step3, chain(step4, next_op))));
}

// Sonata 4
Operator port_scan(Operator next_op) {
    const int threshold = 40;
    std::vector<std::string> distinct_keys = {"ipv4.src", "l4.dport"};
    std::vector<std::string> group_keys = {"ipv4.src"};

    OpCreator step1 = [](Operator op) { return epoch(1.0, "eid", op); };
    OpCreator step2 = [&](Operator op) { return distinct(filter_groups_l(distinct_keys), op); };
    OpCreator step3 = [&](Operator op) { return groupby(filter_groups_l(group_keys), counter, "ports", op); };
    OpCreator step4 = [&](Operator op) { return filter(key_geq_int_l("ports", threshold), op); };

    return chain(step1, chain(step2, chain(step3, chain(step4, next_op))));
}

// Sonata 5
Operator ddos(Operator next_op) {
    const int threshold = 45; // Note threshold differs from Port Scan
    std::vector<std::string> distinct_keys = {"ipv4.src", "ipv4.dst"};
    std::vector<std::string> group_keys = {"ipv4.dst"};

    OpCreator step1 = [](Operator op) { return epoch(1.0, "eid", op); };
    OpCreator step2 = [&](Operator op) { return distinct(filter_groups_l(distinct_keys), op); };
    OpCreator step3 = [&](Operator op) { return groupby(filter_groups_l(group_keys), counter, "srcs", op); };
    OpCreator step4 = [&](Operator op) { return filter(key_geq_int_l("srcs", threshold), op); };

    return chain(step1, chain(step2, chain(step3, chain(step4, next_op))));
}

// Sonata 6 - SYN Flood (Sonata version)
std::vector<Operator> syn_flood_sonata(Operator next_op) {
    const int threshold = 3;
    const double epoch_dur = 1.0;

    auto filter_tcp_flag = [&](int flag_val) {
         return [=](const Tuple& tup) {
            try {
                return get_mapped_int("ipv4.proto", tup) == 6 &&
                       get_mapped_int("l4.flags", tup) == flag_val;
            } catch(...) { return false; }
         };
    };

    // Define the 3 initial streams (Syns, SynAcks, Acks)
    auto syns_stream = [&](Operator op) -> Operator {
        return chain(epoch(epoch_dur, "eid"),
               chain(filter(filter_tcp_flag(2)), // SYN flag = 2
               chain(groupby(filter_groups_l({"ipv4.dst"}), counter, "syns"),
               op)));
    };
     auto synacks_stream = [&](Operator op) -> Operator {
        return chain(epoch(epoch_dur, "eid"),
               chain(filter(filter_tcp_flag(18)), // SYN+ACK flag = 18
               chain(groupby(filter_groups_l({"ipv4.src"}), counter, "synacks"),
               op)));
    };
     auto acks_stream = [&](Operator op) -> Operator {
        return chain(epoch(epoch_dur, "eid"),
               chain(filter(filter_tcp_flag(16)), // ACK flag = 16
               chain(groupby(filter_groups_l({"ipv4.dst"}), counter, "acks"),
               op)));
    };

    // Define the second join (Syns+SynAcks) - Join(Ack)
    auto map_diff = map([](const Tuple& tup){
        Tuple res = tup;
        try {
            res["syns+synacks-acks"] = get_mapped_int("syns+synacks", tup) - get_mapped_int("acks", tup);
        } catch (...) {/* handle error maybe */}
        return res;
    });
     auto filter_diff = filter(key_geq_int_l("syns+synacks-acks", threshold));
     DblOpCreator join2_creator = [&](Operator final_op) {
        Operator downstream = chain(map_diff, chain(filter_diff, final_op));
        KeyExtractor left_extract = [](const Tuple& t){ return std::make_pair(filter_groups({"host"}, t), filter_groups({"syns+synacks"}, t)); };
        KeyExtractor right_extract = [](const Tuple& t){ return std::make_pair(rename_filtered_keys({{"ipv4.dst","host"}}, t), filter_groups({"acks"}, t)); };
        return join(left_extract, right_extract, downstream);
     };

     // Define the first join (Syns) - Join(SynAcks)
     auto map_sum = map([](const Tuple& tup){
        Tuple res = tup;
         try {
            res["syns+synacks"] = get_mapped_int("syns", tup) + get_mapped_int("synacks", tup);
        } catch (...) {/* handle error maybe */}
        return res;
     });

     DblOpCreator join1_creator = [&](Operator join2_left_op) { // join2_left_op comes from join2_creator result
         Operator downstream = chain(map_sum, join2_left_op);
         KeyExtractor left_extract = [](const Tuple& t){ return std::make_pair(rename_filtered_keys({{"ipv4.dst","host"}}, t), filter_groups({"syns"}, t)); };
         KeyExtractor right_extract = [](const Tuple& t){ return std::make_pair(rename_filtered_keys({{"ipv4.src","host"}}, t), filter_groups({"synacks"}, t)); };
         return join(left_extract, right_extract, downstream);
     };

     // Wire them up using chain_double
     auto [join2_op1, join2_op2] = chain_double(join2_creator, next_op); // join2_op1 receives output of join1
     auto [join1_op3, join1_op4] = chain_double(join1_creator, join2_op1); // join1 outputs to join2_op1

     // Return the initial operators for the three streams
     return {
         syns_stream(join1_op3),
         synacks_stream(join1_op4),
         acks_stream(join2_op2)
     };
}


// Sonata 7 - Completed Flows
std::vector<Operator> completed_flows(Operator next_op) {
     const int threshold = 1;
     const double epoch_dur = 30.0;

     auto filter_syn = [](const Tuple& tup) {
         try {
             return get_mapped_int("ipv4.proto", tup) == 6 && get_mapped_int("l4.flags", tup) == 2; // SYN
         } catch(...) { return false;}
     };
      auto filter_fin = [](const Tuple& tup) {
         try {
             // Check if FIN bit (lsb) is set
             return get_mapped_int("ipv4.proto", tup) == 6 && (get_mapped_int("l4.flags", tup) & 1) == 1; // FIN
         } catch(...) { return false;}
     };

     auto syns_stream = [&](Operator op) {
        return chain(epoch(epoch_dur, "eid"),
               chain(filter(filter_syn),
               chain(groupby(filter_groups_l({"ipv4.dst"}), counter, "syns"),
               op)));
     };
      auto fins_stream = [&](Operator op) {
        return chain(epoch(epoch_dur, "eid"),
               chain(filter(filter_fin),
               chain(groupby(filter_groups_l({"ipv4.src"}), counter, "fins"),
               op)));
     };

     auto map_diff = map([](const Tuple& tup){
         Tuple res = tup;
         try {
            res["diff"] = get_mapped_int("syns", tup) - get_mapped_int("fins", tup);
         } catch(...) {}
         return res;
     });
     auto filter_diff = filter(key_geq_int_l("diff", threshold));

     DblOpCreator join_creator = [&](Operator final_op) {
         Operator downstream = chain(map_diff, chain(filter_diff, final_op));
         KeyExtractor left_extract = [](const Tuple& t){ return std::make_pair(rename_filtered_keys({{"ipv4.dst","host"}}, t), filter_groups({"syns"}, t)); };
         KeyExtractor right_extract = [](const Tuple& t){ return std::make_pair(rename_filtered_keys({{"ipv4.src","host"}}, t), filter_groups({"fins"}, t)); };
         return join(left_extract, right_extract, downstream);
     };

     auto [op1, op2] = chain_double(join_creator, next_op);

     return { syns_stream(op1), fins_stream(op2) };
}


// Sonata 8 - Slowloris
std::vector<Operator> slowloris(Operator next_op) {
     const int t1 = 5;   // min connections
     const int t2 = 500; // min bytes
     const int t3 = 90;  // max bytes per connection
     const double epoch_dur = 1.0;

     auto filter_tcp = [](const Tuple& tup) {
        try { return get_mapped_int("ipv4.proto", tup) == 6; } catch(...) { return false; }
     };

     // Stream 1: Calculate n_conns >= t1
     auto n_conns_stream = [&](Operator op) {
        return chain(epoch(epoch_dur, "eid"),
               chain(filter(filter_tcp),
               chain(distinct(filter_groups_l({"ipv4.src", "ipv4.dst", "l4.sport"})), // Distinct connections
               chain(groupby(filter_groups_l({"ipv4.dst"}), counter, "n_conns"),
               chain(filter(key_geq_int_l("n_conns", t1)), // Filter >= t1
               op)))));
     };

     // Stream 2: Calculate n_bytes >= t2
     auto n_bytes_stream = [&](Operator op) {
         // Need a lambda adapter for sum_ints
         auto sum_len = [](OpResult current, const Tuple& t) { return sum_ints("ipv4.len", current, t); };
         return chain(epoch(epoch_dur, "eid"),
                chain(filter(filter_tcp),
                chain(groupby(filter_groups_l({"ipv4.dst"}), sum_len, "n_bytes"),
                chain(filter(key_geq_int_l("n_bytes", t2)), // Filter >= t2
                op))));
     };

     // Map and Filter after join
     auto map_calc_bpc = map([](const Tuple& tup){
        Tuple res = tup;
        try {
            int n_bytes = get_mapped_int("n_bytes", tup);
            int n_conns = get_mapped_int("n_conns", tup);
            if (n_conns > 0) {
                res["bytes_per_conn"] = n_bytes / n_conns;
            } else {
                 res["bytes_per_conn"] = 0; // Avoid division by zero
            }
        } catch(...) {}
        return res;
     });
      auto filter_bpc = filter([=](const Tuple& tup){
        try {
             return get_mapped_int("bytes_per_conn", tup) <= t3; // Filter <= t3
        } catch(...) { return false; }
      });

      // Join creator
     DblOpCreator join_creator = [&](Operator final_op) {
        Operator downstream = chain(map_calc_bpc, chain(filter_bpc, final_op));
        // Extractors for join on ipv4.dst
        KeyExtractor left_extract = [](const Tuple& t){ return std::make_pair(filter_groups({"ipv4.dst"}, t), filter_groups({"n_conns"}, t)); };
        KeyExtractor right_extract = [](const Tuple& t){ return std::make_pair(filter_groups({"ipv4.dst"}, t), filter_groups({"n_bytes"}, t)); };
        return join(left_extract, right_extract, downstream);
     };

     auto [op1, op2] = chain_double(join_creator, next_op);

     return { n_conns_stream(op1), n_bytes_stream(op2) };
}


// --- Other Test Queries ---
std::vector<Operator> join_test(Operator next_op) {
     const double epoch_dur = 1.0;

     auto filter_syn = [](const Tuple& tup) {
         try { return get_mapped_int("ipv4.proto",tup) == 6 && get_mapped_int("l4.flags",tup) == 2;} catch(...) {return false;}
     };
     auto filter_synack = [](const Tuple& tup) {
         try { return get_mapped_int("ipv4.proto",tup) == 6 && get_mapped_int("l4.flags",tup) == 18;} catch(...) {return false;}
     };

     auto syns_stream = [&](Operator op){
        return chain(epoch(epoch_dur, "eid"), chain(filter(filter_syn), op));
     };
     auto synacks_stream = [&](Operator op){
         return chain(epoch(epoch_dur, "eid"), chain(filter(filter_synack), op));
     };

     DblOpCreator join_creator = [&](Operator final_op) {
         KeyExtractor left_extract = [](const Tuple& t){ return std::make_pair(rename_filtered_keys({{"ipv4.src","host"}}, t), rename_filtered_keys({{"ipv4.dst","remote"}}, t)); };
         KeyExtractor right_extract = [](const Tuple& t){ return std::make_pair(rename_filtered_keys({{"ipv4.dst","host"}}, t), filter_groups({"time"}, t)); };
         return join(left_extract, right_extract, final_op); // Just pass final_op directly
     };

     auto [op1, op2] = chain_double(join_creator, next_op);

     return { syns_stream(op1), synacks_stream(op2) };
}


Operator q3(Operator next_op) { // Distinct src/dst pairs over 100s
     return chain(epoch(100.0, "eid"),
            chain(distinct(filter_groups_l({"ipv4.src", "ipv4.dst"})),
            next_op));
}

Operator q4(Operator next_op) { // Pkts per dst over 10000s
     return chain(epoch(10000.0, "eid"),
            chain(groupby(filter_groups_l({"ipv4.dst"}), counter, "pkts"),
            next_op));
}


} // namespace SonataQueries
```

---

**7. `main.cpp`**

```cpp
#include "common_utils.hpp"
#include "builtins.hpp"
#include "sonata_queries.hpp"

#include <iostream>
#include <vector>
#include <string>
#include <stdexcept>

using namespace Utils;
using namespace Builtins;
using namespace SonataQueries;

// Example function to generate sample data similar to OCaml's run_queries
std::vector<Tuple> generate_sample_data(int count) {
    std::vector<Tuple> data;
    MACAddress src_mac({0x00, 0x11, 0x22, 0x33, 0x44, 0x55});
    MACAddress dst_mac({0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF});
    IPv4Address ip_addr("127.0.0.1"); // Can throw

    for (int i = 0; i < count; ++i) {
        Tuple tup;
        tup["time"] = 0.000000 + static_cast<double>(i);

        tup["eth.src"] = src_mac;
        tup["eth.dst"] = dst_mac;
        tup["eth.ethertype"] = 0x0800; // IPv4

        tup["ipv4.hlen"] = 20;
        tup["ipv4.proto"] = 6; // TCP
        tup["ipv4.len"] = 60;
        tup["ipv4.src"] = ip_addr;
        tup["ipv4.dst"] = ip_addr;

        tup["l4.sport"] = 440 + i; // Vary source port slightly
        tup["l4.dport"] = 50000;
        tup["l4.flags"] = 10; // Example flags (PSH+ACK)

        data.push_back(tup);
    }
    return data;
}

// Example of running a single query pipeline
void run_single_query_example() {
    std::cout << "--- Running Single Query Example (Count Packets) ---" << std::endl;
    // Define the end of the pipeline (dump to stdout)
    Operator final_op = dump_tuple_op(std::cout, true); // Show resets

    // Build the query pipeline
    Operator query_pipeline = count_pkts(final_op);

    // Generate sample data
    std::vector<Tuple> sample_data = generate_sample_data(5); // Generate 5 tuples

    // Process data
    for (const auto& tup : sample_data) {
        query_pipeline.next(tup);
    }

    // Signal end of data stream (important for epoch-based operators)
    // Create a dummy tuple for the final reset, containing the *next* potential eid.
    // Need to know the last eid processed. Let's assume eid 0 for 5 pkts over 1s epochs.
    // The last packet time is 4.0. Epoch boundaries are 1.0, 2.0, 3.0, 4.0, 5.0...
    // Packet 0 (t=0.0) -> eid=0
    // Packet 1 (t=1.0) -> reset(eid=0), next(eid=1)
    // Packet 2 (t=2.0) -> reset(eid=1), next(eid=2)
    // Packet 3 (t=3.0) -> reset(eid=2), next(eid=3)
    // Packet 4 (t=4.0) -> reset(eid=3), next(eid=4)
    // Final reset should signal end of epoch 4.
    Tuple final_reset_signal;
    // The 'epoch' operator expects the key used ('eid') in the reset tuple.
    final_reset_signal["eid"] = 4; // The last completed epoch ID
    query_pipeline.reset(final_reset_signal); // Trigger final resets through the pipeline

     std::cout << "--- Single Query Example Finished ---" << std::endl;
}

// Example mimicking the OCaml `run_queries` structure (applying multiple queries to each tuple)
void run_multiple_queries_simultaneously() {
     std::cout << "\n--- Running Multiple Queries Simultaneously Example ---" << std::endl;

     // Define multiple query pipelines ending in stdout dumps
     std::vector<Operator> queries;
     queries.push_back(ident(dump_tuple_op(std::cout)));
     queries.push_back(count_pkts(dump_tuple_op(std::cout, true))); // Show resets for this one
     queries.push_back(pkts_per_src_dst(dump_tuple_op(std::cout, true)));

     std::vector<Tuple> sample_data = generate_sample_data(5);

     // Process each tuple through all queries
     for (const auto& tup : sample_data) {
        std::cout << "Processing Tuple with time=" << lookup_float("time", tup) << std::endl;
        for (auto& query : queries) { // Pass by reference if operators have internal state to modify
            query.next(tup);
        }
         std::cout << "-----\n";
     }

     // Send final reset signals to all queries
     // This is tricky as different queries might expect different reset signals.
     // For simplicity, send a generic reset or one tailored to epoch if known.
     std::cout << "Sending final resets..." << std::endl;
      Tuple final_reset_signal;
      final_reset_signal["eid"] = 4; // Assuming last epoch ID based on data/epoch=1.0
      for (auto& query : queries) {
          query.reset(final_reset_signal);
      }

     std::cout << "--- Multiple Queries Example Finished ---" << std::endl;
}


// Example using read_walts_csv (requires dummy CSV files)
void run_read_csv_example() {
     std::cout << "\n--- Running Read CSV Example ---" << std::endl;
     // Create dummy CSV files (replace with actual paths)
     const std::string file1_name = "dummy_input1.csv";
     const std::string file2_name = "dummy_input2.csv";

     std::ofstream ofs1(file1_name);
     if (!ofs1) { std::cerr << "Cannot create " << file1_name << std::endl; return; }
     ofs1 << "192.168.1.1,10.0.0.1,1234,80,10,1500,0\n"; // eid 0
     ofs1 << "192.168.1.2,10.0.0.2,5678,443,5,500,0\n";  // eid 0
     ofs1 << "192.168.1.1,10.0.0.1,1234,80,8,1200,1\n";   // eid 1
     ofs1.close();

     std::ofstream ofs2(file2_name);
     if (!ofs2) { std::cerr << "Cannot create " << file2_name << std::endl; return; }
     ofs2 << "172.16.0.1,192.168.1.5,99,53,1,60,0\n";    // eid 0
     ofs2 << "172.16.0.1,192.168.1.6,100,53,2,120,1\n";   // eid 1
     ofs2 << "172.16.0.1,192.168.1.7,101,53,3,180,2\n";   // eid 2
     ofs2.close();

     try {
        // Define pipelines for each file - e.g., count packets per source
        Operator pipeline1 = pkts_per_src_dst(dump_tuple_op(std::cout, true));
        Operator pipeline2 = count_pkts(dump_tuple_op(std::cout, true));

        std::vector<std::string> files = {file1_name, file2_name};
        std::vector<Operator> ops = {pipeline1, pipeline2};

        read_walts_csv(files, ops, "eid"); // Use default "eid" key

     } catch (const std::exception& e) {
         std::cerr << "Error during CSV processing: " << e.what() << std::endl;
     }

     // Clean up dummy files
     // remove(file1_name.c_str());
     // remove(file2_name.c_str());
      std::cout << "--- Read CSV Example Finished ---" << std::endl;
}


int main() {
    try {
        run_single_query_example();
        run_multiple_queries_simultaneously();
        run_read_csv_example(); // Uncomment to test CSV reading

        // Add more examples calling specific Sonata queries if needed
        // Example: Running Sonata 1
        std::cout << "\n--- Running Sonata 1 Example ---" << std::endl;
        Operator s1_pipeline = tcp_new_cons(dump_tuple_op(std::cout, true));
        std::vector<Tuple> s1_data = generate_sample_data(10);
        // Add some TCP SYN packets manually to trigger the query
         Tuple syn_tup;
         syn_tup["time"] = 10.0;
         syn_tup["ipv4.proto"] = 6;
         syn_tup["l4.flags"] = 2; // SYN
         syn_tup["ipv4.dst"] = IPv4Address("10.0.0.5");
         for(int i=0; i<50; ++i) { // Generate 50 SYNs to trigger threshold
            syn_tup["time"] = 10.0 + i*0.01;
            syn_tup["ipv4.src"] = IPv4Address("192.168.1." + std::to_string(i+1));
            s1_data.push_back(syn_tup);
         }
         syn_tup["time"] = 60.0; // Move to next epoch
         s1_data.push_back(syn_tup);


        for(const auto& tup : s1_data) {
            s1_pipeline.next(tup);
        }
         Tuple s1_reset; s1_reset["eid"] = 60; // Rough estimate of last epoch based on time/epoch=1.0
         s1_pipeline.reset(s1_reset);
         std::cout << "--- Sonata 1 Example Finished ---" << std::endl;


        std::cout << "\nDone." << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Unhandled exception in main: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "Unknown unhandled exception in main." << std::endl;
        return 1;
    }

    return 0;
}

```

---

**8. Build Instructions (using CMake - `CMakeLists.txt`)**

```cmake
cmake_minimum_required(VERSION 3.15) # Increased requirement for target_link_options if needed

project(OcamlStreamTranslate LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17) # Need C++17 for std::variant, std::optional, etc.
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF) # Prefer standard C++

# Add source files
add_executable(stream_processor
    main.cpp
    common_utils.cpp
    builtins.cpp
    sonata_queries.cpp
)

# Optional: Improve warnings (GCC/Clang)
if (CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(stream_processor PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -Wshadow          # Warn when variable shadows another
        -Wnon-virtual-dtor # Warn if base class has non-virtual destructor
        -Wold-style-cast  # Warn for C-style casts
        -Wcast-align      # Warn for potential performance issues from casts
        -Wunused          # Warn about unused variables/parameters
        -Woverloaded-virtual # Warn about missed overrides
        -Werror=return-type  # Error on missing return statement
    )
endif()


# Optional: Set build type if not specified by user (e.g., Debug for development)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug CACHE STRING "Choose build type: Debug Release RelWithDebInfo MinSizeRel" FORCE)
endif()

# Optional: Enable AddressSanitizer for Debug builds
if(CMAKE_BUILD_TYPE STREQUAL "Debug" AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    message(STATUS "Enabling AddressSanitizer for Debug build")
    target_compile_options(stream_processor INTERFACE -fsanitize=address)
    target_link_options(stream_processor INTERFACE -fsanitize=address)
endif()


# Output message
message(STATUS "C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "Build Type: ${CMAKE_BUILD_TYPE}")

```

**To Compile and Run:**

1.  Save the files above (`.hpp`, `.cpp`, `CMakeLists.txt`) in a directory.
2.  Create a build directory: `mkdir build && cd build`
3.  Configure CMake: `cmake ..`
4.  Compile: `make` (or `cmake --build .`)
5.  Run: `./stream_processor`

This provides a comprehensive translation adhering to C++17 standards and common idioms. Remember the caveats about hashing and external libraries if deploying in a performance-critical or production environment.