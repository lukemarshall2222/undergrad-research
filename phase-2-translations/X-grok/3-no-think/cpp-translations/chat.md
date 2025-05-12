Prompt: Base prompt

Translating the provided OCaml code to C++ requires careful consideration of OCaml's functional programming paradigms, variant types, and module system, which differ significantly from C++'s object-oriented and imperative style. Below is a C++ translation that aims to preserve the functionality of the original code while adapting it to C++ conventions. Due to the complexity and length of the code, I'll focus on key components, provide a complete translation for the core utilities and operators, and outline the approach for the remaining parts, ensuring the response is manageable and clear.

### Translation Approach
1. **OCaml Variant Type (`op_result`)**: OCaml's `op_result` is a tagged union (variant). In C++, we use `std::variant` to represent `Float`, `Int`, `IPv4`, `MAC`, and `Empty`. This requires the `<variant>` header and careful handling of type-safe access.
2. **OCaml Map (`Tuple`)**: The `Tuple` type is a `Map` from strings to `op_result`. In C++, we use `std::map<std::string, op_result>`.
3. **OCaml Records (`operator`)**: Records are translated to C++ structs with member functions or `std::function` objects to mimic OCaml's function fields.
4. **OCaml Modules**: OCaml's module system (e.g., `Tuple` as a `Map.Make(String)`) is replaced with C++ classes or direct use of `std::map`.
5. **OCaml Functional Operators (`@=>`, `@==>`)**: These are translated as function compositions or constructor calls in C++.
6. **External Dependencies**: Types like `Ipaddr.V4.t` and `Bytes.t` are simplified to `std::string` for `IPv4` (representing IP addresses as strings) and `std::array<uint8_t, 6>` for `MAC` addresses. For full fidelity, you might use a library like `boost::asio` for IP addresses, but I’ll keep it simple here.
7. **File I/O and Formatting**: OCaml's `Printf` and channel-based I/O are replaced with C++'s `std::cout`, `std::ofstream`, and `std::sprintf` or `std::stringstream` for string formatting.
8. **Functional Patterns**: OCaml's functional constructs like `fold`, `map`, and pattern matching are emulated using C++ loops, `std::visit` for variants, and lambda functions where appropriate.

Given the code's length, I’ll provide a complete translation for the core utilities and a representative subset of operators (e.g., `dump_tuple`, `epoch`, `groupby`), then summarize how to handle the rest, including the Sonata queries. If you need specific sections expanded, let me know.

### C++ Translation

```cpp
#include <variant>
#include <string>
#include <map>
#include <functional>
#include <array>
#include <sstream>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <vector>
#include <unordered_map>
#include <stdexcept>
#include <cstdint>
#include <list>

// Variant type for op_result
using op_result = std::variant<
    double,                     // Float
    int,                        // Int
    std::string,                // IPv4 (simplified as string)
    std::array<uint8_t, 6>,     // MAC
    std::monostate              // Empty
>;

// Tuple is a map from string to op_result
using tuple = std::map<std::string, op_result>;

// Operator struct with next and reset functions
struct operator_t {
    std::function<void(const tuple&)> next;
    std::function<void(const tuple&)> reset;
};

// Function types for operator creators
using op_creator = std::function<operator_t(const operator_t&)>;
using dbl_op_creator = std::function<std::pair<operator_t, operator_t>(const operator_t&)>;

// Conversion utilities
std::string string_of_mac(const std::array<uint8_t, 6>& mac) {
    std::stringstream ss;
    for (size_t i = 0; i < mac.size(); ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(mac[i]);
        if (i < mac.size() - 1) ss << ":";
    }
    return ss.str();
}

std::string tcp_flags_to_strings(int flags) {
    std::map<std::string, int> tcp_flags_map = {
        {"FIN", 1 << 0},
        {"SYN", 1 << 1},
        {"RST", 1 << 2},
        {"PSH", 1 << 3},
        {"ACK", 1 << 4},
        {"URG", 1 << 5},
        {"ECE", 1 << 6},
        {"CWR", 1 << 7}
    };
    std::string result;
    for (const auto& [key, value] : tcp_flags_map) {
        if (flags & value) {
            if (!result.empty()) result += "|";
            result += key;
        }
    }
    return result.empty() ? "" : result;
}

int int_of_op_result(const op_result& input) {
    if (std::holds_alternative<int>(input)) {
        return std::get<int>(input);
    }
    throw std::runtime_error("Trying to extract int from non-int result");
}

double float_of_op_result(const op_result& input) {
    if (std::holds_alternative<double>(input)) {
        return std::get<double>(input);
    }
    throw std::runtime_error("Trying to extract float from non-float result");
}

std::string string_of_op_result(const op_result& input) {
    return std::visit([](const auto& value) -> std::string {
        using T = std::decay_t<decltype(value)>;
        if constexpr (std::is_same_v<T, double>) {
            std::stringstream ss;
            ss << value;
            return ss.str();
        } else if constexpr (std::is_same_v<T, int>) {
            return std::to_string(value);
        } else if constexpr (std::is_same_v<T, std::string>) {
            return value;
        } else if constexpr (std::is_same_v<T, std::array<uint8_t, 6>>) {
            return string_of_mac(value);
        } else if constexpr (std::is_same_v<T, std::monostate>) {
            return "Empty";
        }
    }, input);
}

std::string string_of_tuple(const tuple& input_tuple) {
    std::stringstream ss;
    for (const auto& [key, value] : input_tuple) {
        ss << "\"" << key << "\" => " << string_of_op_result(value) << ", ";
    }
    return ss.str();
}

tuple tuple_of_list(const std::vector<std::pair<std::string, op_result>>& tup_list) {
    tuple result;
    for (const auto& [key, value] : tup_list) {
        result[key] = value;
    }
    return result;
}

void dump_tuple(std::ostream& outc, const tuple& tup) {
    outc << string_of_tuple(tup) << "\n";
}

int lookup_int(const std::string& key, const tuple& tup) {
    auto it = tup.find(key);
    if (it == tup.end()) throw std::runtime_error("Key not found");
    return int_of_op_result(it->second);
}

double lookup_float(const std::string& key, const tuple& tup) {
    auto it = tup.find(key);
    if (it == tup.end()) throw std::runtime_error("Key not found");
    return float_of_op_result(it->second);
}

// Operator definitions
operator_t dump_tuple_op(bool show_reset = false, std::ostream& outc = std::cout) {
    return operator_t{
        [&outc](const tuple& tup) { dump_tuple(outc, tup); },
        [&outc, show_reset](const tuple& tup) {
            if (show_reset) {
                dump_tuple(outc, tup);
                outc << "[reset]\n";
            }
        }
    };
}

operator_t dump_as_csv(const std::optional<std::pair<std::string, std::string>>& static_field = std::nullopt,
                       bool header = true, std::ostream& outc = std::cout) {
    bool first = header;
    return operator_t{
        [&outc, &first, static_field](const tuple& tup) {
            if (first) {
                if (static_field) {
                    outc << static_field->first << ",";
                }
                for (const auto& [key, _] : tup) {
                    outc << key << ",";
                }
                outc << "\n";
                first = false;
            }
            if (static_field) {
                outc << static_field->second << ",";
            }
            for (const auto& [_, value] : tup) {
                outc << string_of_op_result(value) << ",";
            }
            outc << "\n";
        },
        [](const tuple&) {}
    };
}

operator_t dump_walts_csv(const std::string& filename) {
    std::ofstream outc;
    bool first = true;
    return operator_t{
        [&outc, &first, filename](const tuple& tup) {
            if (first) {
                outc.open(filename);
                first = false;
            }
            outc << string_of_op_result(tup.at("src_ip")) << ","
                 << string_of_op_result(tup.at("dst_ip")) << ","
                 << string_of_op_result(tup.at("src_l4_port")) << ","
                 << string_of_op_result(tup.at("dst_l4_port")) << ","
                 << string_of_op_result(tup.at("packet_count")) << ","
                 << string_of_op_result(tup.at("byte_count")) << ","
                 << string_of_op_result(tup.at("epoch_id")) << "\n";
        },
        [](const tuple&) {}
    };
}

op_result get_ip_or_zero(const std::string& input) {
    if (input == "0") {
        return op_result{0};
    }
    return op_result{input}; // Assuming IPv4 is stored as string
}

operator_t epoch(double epoch_width, const std::string& key_out, const operator_t& next_op) {
    double epoch_boundary = 0.0;
    int eid = 0;
    return operator_t{
        [&epoch_boundary, &eid, epoch_width, key_out, next_op](const tuple& tup) {
            double time = lookup_float("time", tup);
            if (epoch_boundary == 0.0) {
                epoch_boundary = time + epoch_width;
            } else if (time >= epoch_boundary) {
                while (time >= epoch_boundary) {
                    tuple reset_tup{{key_out, op_result{eid}}};
                    next_op.reset(reset_tup);
                    epoch_boundary += epoch_width;
                    ++eid;
                }
            }
            tuple new_tup = tup;
            new_tup[key_out] = op_result{eid};
            next_op.next(new_tup);
        },
        [&epoch_boundary, &eid, key_out, next_op](const tuple&) {
            tuple reset_tup{{key_out, op_result{eid}}};
            next_op.reset(reset_tup);
            epoch_boundary = 0.0;
            eid = 0;
        }
    };
}

operator_t filter(const std::function<bool(const tuple&)>& f, const operator_t& next_op) {
    return operator_t{
        [f, next_op](const tuple& tup) {
            if (f(tup)) {
                next_op.next(tup);
            }
        },
        [next_op](const tuple& tup) { next_op.reset(tup); }
    };
}

bool key_geq_int(const std::string& key, int threshold, const tuple& tup) {
    return lookup_int(key, tup) >= threshold;
}

int get_mapped_int(const std::string& key, const tuple& tup) {
    return lookup_int(key, tup);
}

double get_mapped_float(const std::string& key, const tuple& tup) {
    return lookup_float(key, tup);
}

operator_t map(const std::function<tuple(const tuple&)>& f, const operator_t& next_op) {
    return operator_t{
        [f, next_op](const tuple& tup) { next_op.next(f(tup)); },
        [next_op](const tuple& tup) { next_op.reset(tup); }
    };
}

using grouping_func = std::function<tuple(const tuple&)>;
using reduction_func = std::function<op_result(const op_result&, const tuple&)>;

operator_t groupby(const grouping_func& groupby, const reduction_func& reduce,
                   const std::string& out_key, const operator_t& next_op) {
    std::unordered_map<tuple, op_result, std::hash<tuple>> h_tbl;
    int reset_counter = 0;
    return operator_t{
        [groupby, reduce, &h_tbl](const tuple& tup) {
            tuple grouping_key = groupby(tup);
            auto it = h_tbl.find(grouping_key);
            if (it != h_tbl.end()) {
                h_tbl[grouping_key] = reduce(it->second, tup);
            } else {
                h_tbl[grouping_key] = reduce(op_result{std::monostate{}}, tup);
            }
        },
        [&h_tbl, &reset_counter, out_key, next_op](const tuple& tup) {
            ++reset_counter;
            for (const auto& [grouping_key, val] : h_tbl) {
                tuple unioned_tup = tup; // Copy input tuple
                for (const auto& [k, v] : grouping_key) {
                    unioned_tup[k] = v; // Merge grouping_key into unioned_tup
                }
                unioned_tup[out_key] = val;
                next_op.next(unioned_tup);
            }
            next_op.reset(tup);
            h_tbl.clear();
        }
    };
}

tuple filter_groups(const std::vector<std::string>& incl_keys, const tuple& tup) {
    tuple result;
    for (const auto& key : incl_keys) {
        auto it = tup.find(key);
        if (it != tup.end()) {
            result[key] = it->second;
        }
    }
    return result;
}

tuple single_group(const tuple&) {
    return tuple{};
}

op_result counter(const op_result& val, const tuple&) {
    if (std::holds_alternative<std::monostate>(val)) {
        return op_result{1};
    } else if (std::holds_alternative<int>(val)) {
        return op_result{std::get<int>(val) + 1};
    }
    return val;
}

op_result sum_ints(const std::string& search_key, const op_result& init_val, const tuple& tup) {
    if (std::holds_alternative<std::monostate>(init_val)) {
        return op_result{0};
    } else if (std::holds_alternative<int>(init_val)) {
        auto it = tup.find(search_key);
        if (it != tup.end() && std::holds_alternative<int>(it->second)) {
            return op_result{std::get<int>(init_val) + std::get<int>(it->second)};
        }
        throw std::runtime_error("sum_ints: Failed to find integer value for key " + search_key);
    }
    return init_val;
}

// Main entry point and example queries
operator_t ident(const operator_t& next_op) {
    return map([](const tuple& tup) {
        tuple result;
        for (const auto& [key, value] : tup) {
            if (key != "eth.src" && key != "eth.dst") {
                result[key] = value;
            }
        }
        return result;
    }, next_op);
}

operator_t count_pkts(const operator_t& next_op) {
    return epoch(1.0, "eid", groupby(single_group, counter, "pkts", next_op));
}

operator_t pkts_per_src_dst(const operator_t& next_op) {
    return epoch(1.0, "eid", groupby(
        [](const tuple& tup) { return filter_groups({"ipv4.src", "ipv4.dst"}, tup); },
        counter, "pkts", next_op));
}

operator_t distinct_srcs(const operator_t& next_op) {
    return epoch(1.0, "eid", distinct(
        [](const tuple& tup) { return filter_groups({"ipv4.src"}, tup); },
        groupby(single_group, counter, "srcs", next_op)));
}

// Example main function to run queries
int main() {
    std::vector<operator_t> queries = {ident(dump_tuple_op())};
    std::vector<tuple> tuples;
    for (int i = 0; i < 20; ++i) {
        tuple t;
        t["time"] = op_result{0.0 + static_cast<double>(i)};
        t["eth.src"] = op_result{std::array<uint8_t, 6>{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}};
        t["eth.dst"] = op_result{std::array<uint8_t, 6>{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}};
        t["eth.ethertype"] = op_result{0x0800};
        t["ipv4.hlen"] = op_result{20};
        t["ipv4.proto"] = op_result{6};
        t["ipv4.len"] = op_result{60};
        t["ipv4.src"] = op_result{std::string{"127.0.0.1"}};
        t["ipv4.dst"] = op_result{std::string{"127.0.0.1"}};
        t["l4.sport"] = op_result{440};
        t["l4.dport"] = op_result{50000};
        t["l4.flags"] = op_result{10};
        tuples.push_back(t);
    }
    for (const auto& tup : tuples) {
        for (const auto& query : queries) {
            query.next(tup);
        }
    }
    std::cout << "Done\n";
    return 0;
}
```

### Key Translation Details
1. **op_result**: Uses `std::variant` to handle different types. `std::visit` is used in `string_of_op_result` to handle type-safe conversion to strings.
2. **tuple**: Implemented as `std::map<std::string, op_result>`. Note that `std::map` is ordered, which matches OCaml’s `Map` behavior.
3. **operator_t**: A struct with two `std::function` members to store `next` and `reset` lambdas, mimicking OCaml’s record type.
4. **string_of_mac**: Converts a 6-byte MAC address (as `std::array<uint8_t, 6>`) to a hex string with colons, using `std::stringstream` for formatting.
5. **tcp_flags_to_strings**: Uses a `std::map` to store flag names and values, iterating to build the string representation.
6. **epoch**: Maintains state (`epoch_boundary`, `eid`) in the lambda’s capture list, updating the tuple with the epoch ID and managing resets.
7. **groupby**: Uses `std::unordered_map` for the hash table, with a custom hash function for `tuple` (simplified here; you may need a proper hash for production).
8. **Chaining Operators (`@=>`)**: Translated as function calls, e.g., `epoch(1.0, "eid", next_op)`. C++ doesn’t need a special operator since function composition is straightforward.

### Handling Remaining Components
- **Sonata Queries (e.g., `tcp_new_cons`, `ssh_brute_force`)**: These follow the same pattern as `count_pkts` and `pkts_per_src_dst`. Each combines `epoch`, `filter`, `groupby`, and `distinct` operators. Translate them by:
  - Defining each as a function returning `operator_t`.
  - Using lambdas for filters (e.g., checking `ipv4.proto == 6`).
  - Composing operators with function calls.
  - For queries returning `operator list` (e.g., `syn_flood_sonata`), return `std::vector<operator_t>`.
- **join and split**: The `join` operator is complex due to its dual-operator output. It’s translated as a function returning `std::pair<operator_t, operator_t>`, with hash tables (`std::unordered_map`) for state. `split` is straightforward, calling `next` and `reset` on both operators.
- **read_walts_csv**: Requires file input parsing. Use `std::ifstream` and `std::getline` with `std::stringstream` to parse CSV lines. The logic remains the same, iterating over files and applying operators.
- **meta_meter**: Tracks counts using references (`int&`) and outputs to `std::ostream`.

### Notes and Limitations
- **IPv4 Handling**: The translation uses `std::string` for `IPv4` to avoid external dependencies. For production, consider a library like `boost::asio` or a custom `IPv4` class.
- **Memory Management**: C++ requires explicit memory management. The translation uses automatic storage duration (stack) and standard containers, which handle deallocation.
- **Hashing tuple**: The `std::unordered_map<tuple, ...>` requires a hash function for `tuple`. The provided code assumes a default hash (for simplicity). In practice, implement a custom hash combining the keys and values of the `std::map`.
- **Performance**: OCaml’s `Map` is a balanced tree, while C++’s `std::map` is similar. For `groupby` and `join`, `std::unordered_map` is used for O(1) lookups, matching the OCaml hash table.
- **Error Handling**: OCaml’s exceptions are translated to C++ `std::runtime_error`. You may want to add more robust error handling depending on use case.

### Compilation
To compile the code, use a C++20-compliant compiler (e.g., `g++`):
```bash
g++ -std=c++20 -o program main.cpp
```

### Next Steps
If you need a specific query (e.g., `syn_flood_sonata`) or section (e.g., `join`) translated in full, please specify, and I can provide the detailed C++ code. Alternatively, I can refine the hash function for `tuple` or address any compilation issues. Let me know how you’d like to proceed!

Give the rest of the translation

Given the request to provide the rest of the translation, I'll complete the C++ translation for the remaining components of the OCaml code, including the `join`, `split`, `distinct`, `meta_meter`, `read_walts_csv`, and all the Sonata queries (`tcp_new_cons`, `ssh_brute_force`, `super_spreader`, `port_scan`, `ddos`, `syn_flood_sonata`, `completed_flows`, `slowloris`, `join_test`, `q3`, `q4`). I'll build on the previous translation, ensuring consistency and addressing the remaining operators and queries. Due to the code's length, I'll focus on clarity and correctness, providing the necessary additions to the existing framework.

### Translation Strategy Recap
- **OCaml Variant (`op_result`)**: Already implemented as `std::variant` with `double`, `int`, `std::string` (for IPv4), `std::array<uint8_t, 6>` (for MAC), and `std::monostate` (for Empty).
- **Tuple**: Implemented as `std::map<std::string, op_result>`.
- **Operator**: A `struct operator_t` with `std::function` members for `next` and `reset`.
- **Hashing for `tuple`**: For `std::unordered_map<tuple, ...>`, I'll include a custom hash function to make the code complete.
- **File I/O**: Use `std::ifstream` for `read_walts_csv` and `std::ofstream` for output operators.
- **Sonata Queries**: Each query is a function returning `operator_t` or `std::vector<operator_t>`, composed using the previously defined operators.

Below is the complete C++ translation, including the remaining components. I'll append the new code to the existing framework and provide a custom hash function for `tuple`.

### Complete C++ Translation

```cpp
#include <variant>
#include <string>
#include <map>
#include <functional>
#include <array>
#include <sstream>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <vector>
#include <unordered_map>
#include <stdexcept>
#include <cstdint>
#include <list>
#include <optional>
#include <algorithm>

// Variant type for op_result
using op_result = std::variant<
    double,                     // Float
    int,                        // Int
    std::string,                // IPv4 (simplified as string)
    std::array<uint8_t, 6>,     // MAC
    std::monostate              // Empty
>;

// Tuple is a map from string to op_result
using tuple = std::map<std::string, op_result>;

// Custom hash function for tuple
namespace std {
    template <>
    struct hash<tuple> {
        std::size_t operator()(const tuple& t) const {
            std::size_t seed = 0;
            for (const auto& [key, value] : t) {
                seed ^= std::hash<std::string>{}(key) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
                std::visit([&seed](const auto& val) {
                    using T = std::decay_t<decltype(val)>;
                    if constexpr (std::is_same_v<T, double>) {
                        seed ^= std::hash<double>{}(val);
                    } else if constexpr (std::is_same_v<T, int>) {
                        seed ^= std::hash<int>{}(val);
                    } else if constexpr (std::is_same_v<T, std::string>) {
                        seed ^= std::hash<std::string>{}(val);
                    } else if constexpr (std::is_same_v<T, std::array<uint8_t, 6>>) {
                        for (const auto& byte : val) {
                            seed ^= std::hash<uint8_t>{}(byte);
                        }
                    } else if constexpr (std::is_same_v<T, std::monostate>) {
                        seed ^= 0;
                    }
                }, value);
            }
            return seed;
        }
    };
}

// Operator struct with next and reset functions
struct operator_t {
    std::function<void(const tuple&)> next;
    std::function<void(const tuple&)> reset;
};

// Function types for operator creators
using op_creator = std::function<operator_t(const operator_t&)>;
using dbl_op_creator = std::function<std::pair<operator_t, operator_t>(const operator_t&)>;

// Conversion utilities
std::string string_of_mac(const std::array<uint8_t, 6>& mac) {
    std::stringstream ss;
    for (size_t i = 0; i < mac.size(); ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(mac[i]);
        if (i < mac.size() - 1) ss << ":";
    }
    return ss.str();
}

std::string tcp_flags_to_strings(int flags) {
    std::map<std::string, int> tcp_flags_map = {
        {"FIN", 1 << 0},
        {"SYN", 1 << 1},
        {"RST", 1 << 2},
        {"PSH", 1 << 3},
        {"ACK", 1 << 4},
        {"URG", 1 << 5},
        {"ECE", 1 << 6},
        {"CWR", 1 << 7}
    };
    std::string result;
    for (const auto& [key, value] : tcp_flags_map) {
        if (flags & value) {
            if (!result.empty()) result += "|";
            result += key;
        }
    }
    return result.empty() ? "" : result;
}

int int_of_op_result(const op_result& input) {
    if (std::holds_alternative<int>(input)) {
        return std::get<int>(input);
    }
    throw std::runtime_error("Trying to extract int from non-int result");
}

double float_of_op_result(const op_result& input) {
    if (std::holds_alternative<double>(input)) {
        return std::get<double>(input);
    }
    throw std::runtime_error("Trying to extract float from non-float result");
}

std::string string_of_op_result(const op_result& input) {
    return std::visit([](const auto& value) -> std::string {
        using T = std::decay_t<decltype(value)>;
        if constexpr (std::is_same_v<T, double>) {
            std::stringstream ss;
            ss << value;
            return ss.str();
        } else if constexpr (std::is_same_v<T, int>) {
            return std::to_string(value);
        } else if constexpr (std::is_same_v<T, std::string>) {
            return value;
        } else if constexpr (std::is_same_v<T, std::array<uint8_t, 6>>) {
            return string_of_mac(value);
        } else if constexpr (std::is_same_v<T, std::monostate>) {
            return "Empty";
        }
    }, input);
}

std::string string_of_tuple(const tuple& input_tuple) {
    std::stringstream ss;
    for (const auto& [key, value] : input_tuple) {
        ss << "\"" << key << "\" => " << string_of_op_result(value) << ", ";
    }
    return ss.str();
}

tuple tuple_of_list(const std::vector<std::pair<std::string, op_result>>& tup_list) {
    tuple result;
    for (const auto& [key, value] : tup_list) {
        result[key] = value;
    }
    return result;
}

void dump_tuple(std::ostream& outc, const tuple& tup) {
    outc << string_of_tuple(tup) << "\n";
}

int lookup_int(const std::string& key, const tuple& tup) {
    auto it = tup.find(key);
    if (it == tup.end()) throw std::runtime_error("Key not found: " + key);
    return int_of_op_result(it->second);
}

double lookup_float(const std::string& key, const tuple& tup) {
    auto it = tup.find(key);
    if (it == tup.end()) throw std::runtime_error("Key not found: " + key);
    return float_of_op_result(it->second);
}

// Operator definitions
operator_t dump_tuple_op(bool show_reset = false, std::ostream& outc = std::cout) {
    return operator_t{
        [&outc](const tuple& tup) { dump_tuple(outc, tup); },
        [&outc, show_reset](const tuple& tup) {
            if (show_reset) {
                dump_tuple(outc, tup);
                outc << "[reset]\n";
            }
        }
    };
}

operator_t dump_as_csv(const std::optional<std::pair<std::string, std::string>>& static_field = std::nullopt,
                       bool header = true, std::ostream& outc = std::cout) {
    bool first = header;
    return operator_t{
        [&outc, &first, static_field](const tuple& tup) {
            if (first) {
                if (static_field) {
                    outc << static_field->first << ",";
                }
                for (const auto& [key, _] : tup) {
                    outc << key << ",";
                }
                outc << "\n";
                first = false;
            }
            if (static_field) {
                outc << static_field->second << ",";
            }
            for (const auto& [_, value] : tup) {
                outc << string_of_op_result(value) << ",";
            }
            outc << "\n";
        },
        [](const tuple&) {}
    };
}

operator_t dump_walts_csv(const std::string& filename) {
    std::ofstream outc;
    bool first = true;
    return operator_t{
        [&outc, &first, filename](const tuple& tup) {
            if (first) {
                outc.open(filename);
                first = false;
            }
            outc << string_of_op_result(tup.at("src_ip")) << ","
                 << string_of_op_result(tup.at("dst_ip")) << ","
                 << string_of_op_result(tup.at("src_l4_port")) << ","
                 << string_of_op_result(tup.at("dst_l4_port")) << ","
                 << string_of_op_result(tup.at("packet_count")) << ","
                 << string_of_op_result(tup.at("byte_count")) << ","
                 << string_of_op_result(tup.at("epoch_id")) << "\n";
        },
        [](const tuple&) {}
    };
}

op_result get_ip_or_zero(const std::string& input) {
    if (input == "0") {
        return op_result{0};
    }
    return op_result{input}; // Assuming IPv4 is stored as string
}

void read_walts_csv(const std::string& epoch_id_key, const std::vector<std::string>& file_names,
                    const std::vector<operator_t>& ops) {
    struct file_state {
        std::ifstream in;
        int epoch_id = 0;
        int tup_count = 0;
    };
    std::vector<file_state> inchs_eids_tupcount;
    for (const auto& filename : file_names) {
        inchs_eids_tupcount.emplace_back(file_state{std::ifstream(filename), 0, 0});
    }
    int running = static_cast<int>(ops.size());
    while (running > 0) {
        for (size_t i = 0; i < inchs_eids_tupcount.size() && i < ops.size(); ++i) {
            auto& [in_ch, eid, tup_count] = inchs_eids_tupcount[i];
            const auto& op = ops[i];
            if (eid >= 0) {
                std::string line;
                if (std::getline(in_ch, line)) {
                    std::stringstream ss(line);
                    std::string src_ip, dst_ip;
                    int src_l4_port, dst_l4_port, packet_count, byte_count, epoch_id;
                    char comma;
                    try {
                        std::getline(ss, src_ip, ',');
                        std::getline(ss, dst_ip, ',');
                        ss >> src_l4_port >> comma
                           >> dst_l4_port >> comma
                           >> packet_count >> comma
                           >> byte_count >> comma
                           >> epoch_id;
                        tuple p;
                        p["ipv4.src"] = get_ip_or_zero(src_ip);
                        p["ipv4.dst"] = get_ip_or_zero(dst_ip);
                        p["l4.sport"] = op_result{src_l4_port};
                        p["l4.dport"] = op_result{dst_l4_port};
                        p["packet_count"] = op_result{packet_count};
                        p["byte_count"] = op_result{byte_count};
                        p[epoch_id_key] = op_result{epoch_id};
                        ++tup_count;
                        if (epoch_id > eid) {
                            while (epoch_id > eid) {
                                tuple reset_tup{{epoch_id_key, op_result{eid}}, {"tuples", op_result{tup_count}}};
                                op.reset(reset_tup);
                                tup_count = 0;
                                ++eid;
                            }
                        }
                        p["tuples"] = op_result{tup_count};
                        op.next(p);
                    } catch (const std::exception& e) {
                        std::cerr << "Failed to scan: " << e.what() << "\n";
                        throw std::runtime_error("Scan failure");
                    }
                } else {
                    tuple reset_tup{{epoch_id_key, op_result{eid + 1}}, {"tuples", op_result{tup_count}}};
                    op.reset(reset_tup);
                    --running;
                    eid = -1;
                }
            }
        }
    }
    std::cout << "Done.\n";
}

operator_t meta_meter(const std::optional<std::string>& static_field, const std::string& name,
                     std::ostream& outc, const operator_t& next_op) {
    int epoch_count = 0;
    int tups_count = 0;
    return operator_t{
        [&tups_count, next_op](const tuple& tup) {
            ++tups_count;
            next_op.next(tup);
        },
        [&epoch_count, &tups_count, name, static_field, &outc, next_op](const tuple& tup) {
            outc << epoch_count << "," << name << "," << tups_count << ","
                 << (static_field ? *static_field : "") << "\n";
            tups_count = 0;
            ++epoch_count;
            next_op.reset(tup);
        }
    };
}

operator_t epoch(double epoch_width, const std::string& key_out, const operator_t& next_op) {
    double epoch_boundary = 0.0;
    int eid = 0;
    return operator_t{
        [&epoch_boundary, &eid, epoch_width, key_out, next_op](const tuple& tup) {
            double time = lookup_float("time", tup);
            if (epoch_boundary == 0.0) {
                epoch_boundary = time + epoch_width;
            } else if (time >= epoch_boundary) {
                while (time >= epoch_boundary) {
                    tuple reset_tup{{key_out, op_result{eid}}};
                    next_op.reset(reset_tup);
                    epoch_boundary += epoch_width;
                    ++eid;
                }
            }
            tuple new_tup = tup;
            new_tup[key_out] = op_result{eid};
            next_op.next(new_tup);
        },
        [&epoch_boundary, &eid, key_out, next_op](const tuple&) {
            tuple reset_tup{{key_out, op_result{eid}}};
            next_op.reset(reset_tup);
            epoch_boundary = 0.0;
            eid = 0;
        }
    };
}

operator_t filter(const std::function<bool(const tuple&)>& f, const operator_t& next_op) {
    return operator_t{
        [f, next_op](const tuple& tup) {
            if (f(tup)) {
                next_op.next(tup);
            }
        },
        [next_op](const tuple& tup) { next_op.reset(tup); }
    };
}

bool key_geq_int(const std::string& key, int threshold, const tuple& tup) {
    return lookup_int(key, tup) >= threshold;
}

int get_mapped_int(const std::string& key, const tuple& tup) {
    return lookup_int(key, tup);
}

double get_mapped_float(const std::string& key, const tuple& tup) {
    return lookup_float(key, tup);
}

operator_t map(const std::function<tuple(const tuple&)>& f, const operator_t& next_op) {
    return operator_t{
        [f, next_op](const tuple& tup) { next_op.next(f(tup)); },
        [next_op](const tuple& tup) { next_op.reset(tup); }
    };
}

using grouping_func = std::function<tuple(const tuple&)>;
using reduction_func = std::function<op_result(const op_result&, const tuple&)>;

operator_t groupby(const grouping_func& groupby, const reduction_func& reduce,
                   const std::string& out_key, const operator_t& next_op) {
    std::unordered_map<tuple, op_result> h_tbl;
    int reset_counter = 0;
    return operator_t{
        [groupby, reduce, &h_tbl](const tuple& tup) {
            tuple grouping_key = groupby(tup);
            auto it = h_tbl.find(grouping_key);
            if (it != h_tbl.end()) {
                h_tbl[grouping_key] = reduce(it->second, tup);
            } else {
                h_tbl[grouping_key] = reduce(op_result{std::monostate{}}, tup);
            }
        },
        [&h_tbl, &reset_counter, out_key, next_op](const tuple& tup) {
            ++reset_counter;
            for (const auto& [grouping_key, val] : h_tbl) {
                tuple unioned_tup = tup;
                for (const auto& [k, v] : grouping_key) {
                    unioned_tup[k] = v;
                }
                unioned_tup[out_key] = val;
                next_op.next(unioned_tup);
            }
            next_op.reset(tup);
            h_tbl.clear();
        }
    };
}

tuple filter_groups(const std::vector<std::string>& incl_keys, const tuple& tup) {
    tuple result;
    for (const auto& key : incl_keys) {
        auto it = tup.find(key);
        if (it != tup.end()) {
            result[key] = it->second;
        }
    }
    return result;
}

tuple single_group(const tuple&) {
    return tuple{};
}

op_result counter(const op_result& val, const tuple&) {
    if (std::holds_alternative<std::monostate>(val)) {
        return op_result{1};
    } else if (std::holds_alternative<int>(val)) {
        return op_result{std::get<int>(val) + 1};
    }
    return val;
}

op_result sum_ints(const std::string& search_key, const op_result& init_val, const tuple& tup) {
    if (std::holds_alternative<std::monostate>(init_val)) {
        return op_result{0};
    } else if (std::holds_alternative<int>(init_val)) {
        auto it = tup.find(search_key);
        if (it != tup.end() && std::holds_alternative<int>(it->second)) {
            return op_result{std::get<int>(init_val) + std::get<int>(it->second)};
        }
        throw std::runtime_error("sum_ints: Failed to find integer value for key " + search_key);
    }
    return init_val;
}

operator_t distinct(const grouping_func& groupby, const operator_t& next_op) {
    std::unordered_map<tuple, bool> h_tbl;
    int reset_counter = 0;
    return operator_t{
        [groupby, &h_tbl](const tuple& tup) {
            tuple grouping_key = groupby(tup);
            h_tbl[grouping_key] = true;
        },
        [&h_tbl, &reset_counter, next_op](const tuple& tup) {
            ++reset_counter;
            for (const auto& [key, _] : h_tbl) {
                tuple merged_tup = tup;
                for (const auto& [k, v] : key) {
                    merged_tup[k] = v;
                }
                next_op.next(merged_tup);
            }
            next_op.reset(tup);
            h_tbl.clear();
        }
    };
}

operator_t split(const operator_t& l, const operator_t& r) {
    return operator_t{
        [l, r](const tuple& tup) {
            l.next(tup);
            r.next(tup);
        },
        [l, r](const tuple& tup) {
            l.reset(tup);
            r.reset(tup);
        }
    };
}

using key_extractor = std::function<std::pair<tuple, tuple>(const tuple&)>;

std::pair<operator_t, operator_t> join(const std::string& eid_key,
                                      const key_extractor& left_extractor,
                                      const key_extractor& right_extractor,
                                      const operator_t& next_op) {
    std::unordered_map<tuple, tuple> h_tbl1;
    std::unordered_map<tuple, tuple> h_tbl2;
    int left_curr_epoch = 0;
    int right_curr_epoch = 0;

    auto handle_join_side = [&](std::unordered_map<tuple, tuple>& curr_h_tbl,
                               std::unordered_map<tuple, tuple>& other_h_tbl,
                               int& curr_epoch_ref, int& other_epoch_ref,
                               const key_extractor& f) -> operator_t {
        return operator_t{
            [&curr_h_tbl, &other_h_tbl, &curr_epoch_ref, &other_epoch_ref, f, eid_key, next_op](const tuple& tup) {
                auto [key, vals] = f(tup);
                int curr_epoch = get_mapped_int(eid_key, tup);
                while (curr_epoch > curr_epoch_ref) {
                    if (other_epoch_ref > curr_epoch_ref) {
                        tuple reset_tup{{eid_key, op_result{curr_epoch_ref}}};
                        next_op.reset(reset_tup);
                    }
                    ++curr_epoch_ref;
                }
                tuple new_tup = key;
                new_tup[eid_key] = op_result{curr_epoch};
                auto it = other_h_tbl.find(new_tup);
                if (it != other_h_tbl.end()) {
                    tuple val = it->second;
                    other_h_tbl.erase(it);
                    tuple result = new_tup;
                    for (const auto& [k, v] : vals) {
                        result[k] = v;
                    }for (const auto& [k, v] : val) {
                        result[k] = v;
                    }
                    next_op.next(result);
                } else {
                    curr_h_tbl[new_tup] = vals;
                }
            },
            [&curr_epoch_ref, &other_epoch_ref, eid_key, next_op](const tuple& tup) {
                int curr_epoch = get_mapped_int(eid_key, tup);
                while (curr_epoch > curr_epoch_ref) {
                    if (other_epoch_ref > curr_epoch_ref) {
                        tuple reset_tup{{eid_key, op_result{curr_epoch_ref}}};
                        next_op.reset(reset_tup);
                    }
                    ++curr_epoch_ref;
                }
            }
        };
    };

    return {
        handle_join_side(h_tbl1, h_tbl2, left_curr_epoch, right_curr_epoch, left_extractor),
        handle_join_side(h_tbl2,纽约 h_tbl1, right_curr_epoch, left_curr_epoch, right_extractor)
    };
}

tuple rename_filtered_keys(const std::vector<std::pair<std::string, std::string>>& renamings_pairs,
                          const tuple& in_tup) {
    tuple new_tup;
    for (const auto& [old_key, new_key] : renamings_pairs) {
        auto it = in_tup.find(old_key);
        if (it != in_tup.end()) {
            new_tup[new_key] = it->second;
        }
    }
    return new_tup;
}

// Query implementations
operator_t ident(const operator_t& next_op) {
    return map([](const tuple& tup) {
        tuple result;
        for (const auto& [key, value] : tup) {
            if (key != "eth.src" && key != "eth.dst") {
                result[key] = value;
            }
        }
        return result;
    }, next_op);
}

operator_t count_pkts(const operator_t& next_op) {
    return epoch(1.0, "eid", groupby(single_group, counter, "pkts", next_op));
}

operator_t pkts_per_src_dst(const operator_t& next_op) {
    return epoch(1.0, "eid", groupby(
        [](const tuple& tup) { return filter_groups({"ipv4.src", "ipv4.dst"}, tup); },
        counter, "pkts", next_op));
}

operator_t distinct_srcs(const operator_t& next_op) {
    return epoch(1.0, "eid", distinct(
        [](const tuple& tup) { return filter_groups({"ipv4.src"}, tup); },
        groupby(single_group, counter, "srcs", next_op)));
}

operator_t tcp_new_cons(const operator_t& next_op) {
    const int threshold = 40;
    return epoch(1.0, "eid",
        filter([](const tuple& tup) {
            return get_mapped_int("ipv4.proto", tup) == 6 &&
                   get_mapped_int("l4.flags", tup) == 2;
        },
        groupby(
            [](const tuple& tup) { return filter_groups({"ipv4.dst"}, tup); },
            counter, "cons",
            filter([threshold](const tuple& tup) { return key_geq_int("cons", threshold, tup); },
                   next_op))));
}

operator_t ssh_brute_force(const operator_t& next_op) {
    const int threshold = 40;
    return epoch(1.0, "eid",
        filter([](const tuple& tup) {
            return get_mapped_int("ipv4.proto", tup) == 6 &&
                   get_mapped_int("l4.dport", tup) == 22;
        },
        distinct(
            [](const tuple& tup) { return filter_groups({"ipv4.src", "ipv4.dst", "ipv4.len"}, tup); },
            groupby(
                [](const tuple& tup) { return filter_groups({"ipv4.dst", "ipv4.len"}, tup); },
                counter, "srcs",
                filter([threshold](const tuple& tup) { return key_geq_int("srcs", threshold, tup); },
                       next_op)))));
}

operator_t super_spreader(const operator_t& next_op) {
    const int threshold = 40;
    return epoch(1.0, "eid",
        distinct(
            [](const tuple& tup) { return filter_groups({"ipv4.src", "ipv4.dst"}, tup); },
            groupby(
                [](const tuple& tup) { return filter_groups({"ipv4.src"}, tup); },
                counter, "dsts",
                filter([threshold](const tuple& tup) { return key_geq_int("dsts", threshold, tup); },
                       next_op))));
}

operator_t port_scan(const operator_t& next_op) {
    const int threshold = 40;
    return epoch(1.0, "eid",
        distinct(
            [](const tuple& tup) { return filter_groups({"ipv4.src", "l4.dport"}, tup); },
            groupby(
                [](const tuple& tup) { return filter_groups({"ipv4.src"}, tup); },
                counter, "ports",
                filter([threshold](const tuple& tup) { return key_geq_int("ports", threshold, tup); },
                       next_op))));
}

operator_t ddos(const operator_t& next_op) {
    const int threshold = 45;
    return epoch(1.0, "eid",
        distinct(
            [](const tuple& tup) { return filter_groups({"ipv4.src", "ipv4.dst"}, tup); },
            groupby(
                [](const tuple& tup) { return filter_groups({"ipv4.dst"}, tup); },
                counter, "srcs",
                filter([threshold](const tuple& tup) { return key_geq_int("srcs", threshold, tup); },
                       next_op))));
}

std::vector<operator_t> syn_flood_sonata(const operator_t& next_op) {
    const int threshold = 3;
    const double epoch_dur = 1.0;

    auto syns = [epoch_dur](const operator_t& next_op) {
        return epoch(epoch_dur, "eid",
            filter([](const tuple& tup) {
                return get_mapped_int("ipv4.proto", tup) == 6 &&
                       get_mapped_int("l4.flags", tup) == 2;
            },
            groupby(
                [](const tuple& tup) { return filter_groups({"ipv4.dst"}, tup); },
                counter, "syns", next_op)));
    };

    auto synacks = [epoch_dur](const operator_t& next_op) {
        return epoch(epoch_dur, "eid",
            filter([](const tuple& tup) {
                return get_mapped_int("ipv4.proto", tup) == 6 &&
                       get_mapped_int("l4.flags", tup) == 18;
            },
            groupby(
                [](const tuple& tup) { return filter_groups({"ipv4.src"}, tup); },
                counter, "synacks", next_op)));
    };

    auto acks = [epoch_dur](const operator_t& next_op) {
        return epoch(epoch_dur, "eid",
            filter([](const(tuple& tup) {
                return get_mapped_int("ipv4.proto", tup) == 6 &&
                       get_mapped_int("l4.flags", tup) == 16;
            },
            groupby(
                [](const tuple& tup) { return filter_groups({"ipv4.dst"}, tup); },
                counter, "acks", next_op)));
    };

    auto [join_op1, join_op2] = join(
        "eid",
        [](const tuple& tup) {
            return std::make_pair(
                filter_groups({"host"}, tup),
                filter_groups({"syns+synacks"}, tup)
            );
        },
        [](const tuple& tup) {
            return std::make_pair(
                rename_filtered_keys({{"ipv4.dst", "host"}}, tup),
                filter_groups({"acks"}, tup)
            );
        },
        map([](const tuple& tup) {
            tuple new_tup = tup;
            new_tup["syns+synacks-acks"] = op_result{
                get_mapped_int("syns+synacks", tup) - get_mapped_int("acks", tup)
            };
            return new_tup;
        },
        filter([threshold](const tuple& tup) {
            return key_geq_int("syns+synacks-acks", threshold, tup);
        }, next_op)))
    );

    auto [join_op3, join_op4] = join(
        "eid",
        [](const tuple& tup) {
            return std::make_pair(
                rename_filtered_keys({{"ipv4.dst", "host"}}, tup),
                filter_groups({"syns"}, tup)
            );
        },
        [](const tuple& tup) {
            return std::make_pair(
                rename_filtered_keys({{"ipv4.src", "host"}}, tup),
                filter_groups({"synacks"}, tup)
            );
        },
        map([](const tuple& tup) {
            tuple new_tup = tup;
            new_tup["syns+synacks"] = op_result{
                get_mapped_int("syns", tup) + get_mapped_int("synacks", tup)
            };
            return new_tup;
        }, join_op1))
    );

    return {
        syns(join_op3),
        synacks(join_op4),
        acks(join_op2)
    };
}

std::vector<operator_t> completed_flows(const operator_t& next_op) {
    const int threshold = 1;
    const double epoch_dur = 30.0;

    auto syns = [epoch_dur](const operator_t& next_op) {
        return epoch(epoch_dur, "eid",
            filter([](const tuple& tup) {
                return get_mapped_int("ipv4.proto", tup) == 6 &&
                       get_mapped_int("l4.flags", tup) == 2;
            },
            groupby(
                [](const tuple& tup) { return filter_groups({"ipv4.dst"}, tup); },
                counter, "syns", next_op)));
    };

    auto fins = [epoch_dur](const operator_t& next_op) {
        return epoch(epoch_dur, "eid",
            filter([](const tuple& tup) {
                return get_mapped_int("ipv4.proto", tup) == 6 &&
                       (get_mapped_int("l4.flags", tup) & 1) == 1;
            },
            groupby(
                [](const tuple& tup) { return filter_groups({"ipv4.src"}, tup); },
                counter, "fins", next_op)));
    };

    auto [op1, op2] = join(
        "eid",
        [](const tuple& tup) {
            return std::make_pair(
                rename_filtered_keys({{"ipv4.dst", "host"}}, tup),
                filter_groups({"syns"}, tup)
            );
        },
        [](const tuple& tup) {
            return std::make_pair(
                rename_filtered_keys({{"ipv4.src", "host"}}, tup),
                filter_groups({"fins"}, tup)
            );
        },
        map([](const tuple& tup) {
            tuple new_tup = tup;
            new_tup["diff"] = op_result{
                get_mapped_int("syns", tup) - get_mapped_int("fins", tup)
            };
            return new_tup;
        },
        filter([threshold](const tuple& tup) {
            return key_geq_int("diff", threshold, tup);
        }, next_op)))
    );

    return {syns(op1), fins(op2)};
}

std::vector<operator_t> slowloris(const operator_t& next_op) {
    const int t1 = 5;
    const int t2 = 500;
    const int t3 = 90;
    const double epoch_dur = 1.0;

    auto n_conns = [epoch_dur](const operator_t& next_op) {
        return epoch(epoch_dur, "eid",
            filter([](const tuple& tup) {
                return get_mapped_int("ipv4.proto", tup) == 6;
            },
            distinct(
                [](const tuple& tup) { return filter_groups({"ipv4.src", "ipv4.dst", "l4.sport"}, tup); },
                groupby(
                    [](const tuple& tup) { return filter_groups({"ipv4.dst"}, tup); },
                    counter, "n_conns",
                    filter([t1](const tuple& tup) { return get_mapped_int("n_conns", tup) >= t1; },
                           next_op)))));
    };

    auto n_bytes = [epoch_dur](const operator_t& next_op) {
        return epoch(epoch_dur, "eid",
            filter([](const tuple& tup) {
                return get_mapped_int("ipv4.proto", tup) == 6;
            },
            groupby(
                [](const tuple& tup) { return filter_groups({"ipv4.dst"}, tup); },
                [sum_ints](const op_result& val, const tuple& tup) {
                    return sum_ints("ipv4.len", val, tup);
                }, "n_bytes",
                filter([t2](const tuple& tup) { return get_mapped_int("n_bytes", tup) >= t2; },
                       next_op))));
    };

    auto [op1, op2] = join(
        "eid",
        [](const tuple& tup) {
            return std::make_pair(
                filter_groups({"ipv4.dst"}, tup),
                filter_groups({"n_conns"}, tup)
            );
        },
        [](const tuple& tup) {
            return std::make_pair(
                filter_groups({"ipv4.dst"}, tup),
                filter_groups({"n_bytes"}, tup)
            );
        },
        map([](const tuple& tup) {
            tuple new_tup = tup;
            new_tup["bytes_per_conn"] = op_result{
                get_mapped_int("n_bytes", tup) / get_mapped_int("n_conns", tup)
            };
            return new_tup;
        },
        filter([t3](const tuple& tup) {
            return get_mapped_int("bytes_per_conn", tup) <= t3;
        }, next_op)))
    );

    return {n_conns(op1), n_bytes(op2)};
}

std::vector<operator_t> join_test(const operator_t& next_op) {
    const double epoch_dur = 1.0;

    auto syns = [epoch_dur](const operator_t& next_op) {
        return epoch(epoch_dur, "eid",
            filter([](const tuple& tup) {
                return get_mapped_int("ipv4.proto", tup) == 6 &&
                       get_mapped_int("l4.flags", tup) == 2;
            }, next_op));
    };

    auto synacks = [epoch_dur](const operator_t& next_op) {
        return epoch(epoch_dur, "eid",
            filter([](const tuple& tup) {
                return get_mapped_int("ipv4.proto", tup) == 6 &&
                       get_mapped_int("l4.flags", tup) == 18;
            }, next_op));
    };

    auto [op1, op2] = join(
        "eid",
        [](const tuple& tup) {
            return std::make_pair(
                rename_filtered_keys({{"ipv4.src", "host"}}, tup),
                rename_filtered_keys({{"ipv4.dst", "remote"}}, tup)
            );
        },
        [](const tuple& tup) {
            return std::make_pair(
                rename_filtered_keys({{"ipv4.dst", "host"}}, tup),
                filter_groups({"time"}, tup)
            );
        }, next_op)
    );

    return {syns(op1), synacks(op2)};
}

operator_t q3(const operator_t& next_op) {
    return epoch(100.0, "eid",
        distinct(
            [](const tuple& tup) { return filter_groups({"ipv4.src", "ipv4.dst"}, tup); },
            next_op));
}

operator_t q4(const operator_t& next_op) {
    return epoch(10000.0, "eid",
        groupby(
            [](const tuple& tup) { return filter_groups({"ipv4.dst"}, tup); },
            counter, "pkts", next_op));
}

// Main entry point
int main() {
    std::vector<operator_t> queries = {ident(dump_tuple_op())};
    std::vector<tuple> tuples;
    for (int i = 0; i < 20; ++i) {
        tuple t;
        t["time"] = op_result{0.0 + static_cast<double>(i)};
        t["eth.src"] = op_result{std::array<uint8_t, 6>{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}};
        t["eth.dst"] = op_result{std::array<uint8_t, 6>{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}};
        t["eth.ethertype"] = op_result{0x0800};
        t["ipv4.hlen"] = op_result{20};
        t["ipv4.proto"] = op_result{6};
        t["ipv4.len"] = op_result{60};
        t["ipv4.src"] = op_result{std::string{"127.0.0.1"}};
        t["ipv4.dst"] = op_result{std::string{"127.0.0.1"}};
        t["l4.sport"] = op_result{440};
        t["l4.dport"] = op_result{50000};
        t["l4.flags"] = op_result{10};
        tuples.push_back(t);
    }
    for (const auto& tup : tuples) {
        for (const auto& query : queries) {
            query.next(tup);
        }
    }
    std::cout << "Done\n";
    return 0;
}
```

### Key Additions and Explanations
1. **Custom Hash for `tuple`**:
   - Implemented `std::hash<tuple>` to enable `std::unordered_map<tuple, ...>`.
   - Combines hashes of keys and values, handling each `op_result` variant type (`double`, `int`, `std::string`, `std::array<uint8_t, 6>`, `std::monostate`).
   - Uses a standard hash-combining formula to ensure uniqueness.

2. **Remaining Operators**:
   - **`meta_meter`**: Tracks tuple counts per epoch using two `int` counters (`epoch_count`, `tups_count`). Outputs to `std::ostream` in CSV format.
   - **`distinct`**: Uses `std::unordered_map<tuple, bool>` to track unique grouping keys. On reset, outputs merged tuples to `next_op`.
   - **`split`**: Simply calls `next` and `reset` on two downstream operators, passing the same tuple.
   - **`join`**: Implements a two-sided join using two hash tables (`h_tbl1`, `h_tbl2`). Matches tuples based on keys extracted by `key_extractor` functions, merging values on matches. Handles epoch synchronization with `curr_epoch_ref` and `other_epoch_ref`.
   - **`rename_filtered_keys`**: Creates a new tuple with renamed keys based on a list of `(old_key, new_key)` pairs, preserving values.
   - **`read_walts_csv`**: Reads CSV files using `std::ifstream` and `std::stringstream` for parsing. Processes each line into a `tuple`, handles epoch transitions, and applies operators. Throws exceptions on parse errors.

3. **Sonata Queries**:
   - **`tcp_new_cons`**: Filters TCP packets with SYN flag (`l4.flags == 2`), groups by destination IP, counts connections, and filters for counts ≥ 40.
   - **`ssh_brute_force`**: Filters TCP packets to port 22, removes duplicates by source/destination/length, groups by destination/length, counts sources, and filters for counts ≥ 40.
   - **`super_spreader`**: Removes duplicates by source/destination, groups by source, counts destinations, and filters for counts ≥ 40.
   - **`port_scan`**: Removes duplicates by source/port, groups by source, counts ports, and filters for counts ≥ 40.
   - **`ddos`**: Removes duplicates by source/destination, groups by destination, counts sources, and filters for counts ≥ 45.
   - **`syn_flood_sonata`**: Processes SYN, SYN-ACK, and ACK packets separately, joins them to compute `syns+synacks-acks`, and filters for values ≥ 3. Returns three operators.
   - **`completed_flows`**: Joins SYN and FIN packets to compute the difference in counts, filtering for differences ≥ 1. Returns two operators.
   - **`slowloris`**: Computes connection counts and byte counts, joins them to calculate bytes per connection, and filters for specific thresholds. Returns two operators.
   - **`join_test`**: Joins SYN and SYN-ACK packets with renamed keys, testing the join mechanism. Returns two operators.
   - **`q3`**: Removes duplicates by source/destination over a 100-second epoch.
   - **`q4`**: Groups by destination and counts packets over a 10000-second epoch.

4. **Main Function**:
   - Matches the OCaml `run_queries` function, creating 20 test tuples with sample network data.
   - Applies the `ident` query piped to `dump_tuple_op` for demonstration.

### Notes and Considerations
- **IPv4 Representation**: Continues to use `std::string` for `IPv4`. For production, consider a proper IP address class or library like `boost::asio`.
- **Error Handling**: Uses `std::runtime_error` for exceptions, consistent with the OCaml code. You may want to add more specific exception types.
- **File I/O in `read_walts_csv`**: Assumes CSV lines are well-formed. In practice, add more robust parsing (e.g., handling malformed lines or missing fields).
- **Performance**: `std::unordered_map` is used for hash tables, matching OCaml’s `Hashtbl`. For large datasets, monitor memory usage and consider optimizing the hash function.
- **Thread Safety**: The code is single-threaded, like the OCaml original. If multithreading is needed, add synchronization for shared state (e.g., hash tables).
- **Testing**: The `main` function uses a simple test case. To test other queries, modify `queries` to include `tcp_new_cons`, `ssh_brute_force`, etc., and provide appropriate input tuples.

### Compilation
Compile with a C++20-compliant compiler:
```bash
g++ -std=c++20 -o program main.cpp
```
Ensure all standard library headers are available. If you encounter issues (e.g., missing C++20 features), you can downgrade to C++17 by replacing `std::optional` with `std::experimental::optional` or a custom wrapper, though C++20 is recommended for `std::variant` and lambda improvements.

### Verification
To verify correctness:
1. Run the program and check the output of `dump_tuple_op` for the test tuples.
2. Test individual queries by modifying `queries` in `main` to include, e.g., `tcp_new_cons(dump_tuple_op())`.
3. Provide CSV files for `read_walts_csv` to test file-based input processing.
4. Compare outputs with the OCaml implementation for identical inputs.

### Further Assistance
If you need help with:
- Specific query testing (e.g., generating input for `syn_flood_sonata`).
- Optimizing the hash function or memory usage.
- Adding more robust CSV parsing for `read_walts_csv`.
- Debugging compilation or runtime issues.
Please let me know, and I can provide targeted assistance or additional code snippets. This translation should cover the entire OCaml code, but I’m happy to refine or expand any part as needed!