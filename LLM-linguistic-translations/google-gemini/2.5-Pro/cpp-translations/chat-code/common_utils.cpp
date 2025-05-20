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