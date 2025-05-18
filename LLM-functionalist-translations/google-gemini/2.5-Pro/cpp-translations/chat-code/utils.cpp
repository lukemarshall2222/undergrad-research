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