#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <map>
#include <variant>
#include <optional>
#include <functional>
#include <cmath>
#include <algorithm>
#include <unordered_map>
#include <list>
#include <fstream>

#include <arpa/inet.h>

namespace OcamlInterop {

// Forward declarations
class operator_t;
using tuple_t = std::map<std::string, std::variant<float, int, in_addr, ether_addr, std::monostate>>;
using op_creator = std::function<operator_t(operator_t)>;
using dbl_op_creator = std::function<std::pair<operator_t, operator_t>(operator_t)>;

// Variant type equivalent
using op_result = std::variant<float, int, in_addr, ether_addr, std::monostate>;

// Helper function to convert ether_addr to string
std::string string_of_mac(const ether_addr& mac) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0')
       << std::setw(2) << static_cast<int>(mac.ether_addr_octet[0]) << ":"
       << std::setw(2) << static_cast<int>(mac.ether_addr_octet[1]) << ":"
       << std::setw(2) << static_cast<int>(mac.ether_addr_octet[2]) << ":"
       << std::setw(2) << static_cast<int>(mac.ether_addr_octet[3]) << ":"
       << std::setw(2) << static_cast<int>(mac.ether_addr_octet[4]) << ":"
       << std::setw(2) << static_cast<int>(mac.ether_addr_octet[5]);
    return ss.str();
}

// Helper function to convert in_addr to string
std::string string_of_ipv4(const in_addr& ip) {
    char buffer[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip, buffer, INET_ADDRSTRLEN);
    return buffer;
}

// Helper function to convert string to in_addr
in_addr ipv4_of_string_exn(const std::string& ip_str) {
    in_addr ip_addr;
    if (inet_pton(AF_INET, ip_str.c_str(), &ip_addr) != 1) {
        throw std::runtime_error("Invalid IPv4 address: " + ip_str);
    }
    return ip_addr;
}

// Helper function for TCP flags to strings
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
    std::string acc = "";
    for (const auto& pair : tcp_flags_map) {
        if ((flags & pair.second) == pair.second) {
            if (!acc.empty()) {
                acc += "|";
            }
            acc += pair.first;
        }
    }
    return acc;
}

int int_of_op_result(const op_result& input) {
    if (std::holds_alternative<int>(input)) {
        return std::get<int>(input);
    }
    throw std::runtime_error("Trying to extract int from non-int result");
}

float float_of_op_result(const op_result& input) {
    if (std::holds_alternative<float>(input)) {
        return std::get<float>(input);
    }
    throw std::runtime_error("Trying to extract float from non-float result");
}

std::string string_of_op_result(const op_result& input) {
    if (std::holds_alternative<float>(input)) {
        std::stringstream ss;
        ss << std::fixed << std::setprecision(6) << std::get<float>(input);
        return ss.str();
    } else if (std::holds_alternative<int>(input)) {
        return std::to_string(std::get<int>(input));
    } else if (std::holds_alternative<in_addr>(input)) {
        return string_of_ipv4(std::get<in_addr>(input));
    } else if (std::holds_alternative<ether_addr>(input)) {
        return string_of_mac(std::get<ether_addr>(input));
    } else {
        return "Empty";
    }
}

std::string string_of_tuple(const tuple_t& input_tuple) {
    std::string acc = "";
    for (const auto& pair : input_tuple) {
        acc += "\"" + pair.first + "\" => " + string_of_op_result(pair.second) + ", ";
    }
    return acc;
}

tuple_t tuple_of_list(const std::vector<std::pair<std::string, op_result>>& tup_list) {
    tuple_t result;
    for (const auto& pair : tup_list) {
        result[pair.first] = pair.second;
    }
    return result;
}

void dump_tuple(std::ostream& outc, const tuple_t& tup) {
    outc << string_of_tuple(tup) << "\n";
}

int lookup_int(const std::string& key, const tuple_t& tup) {
    auto it = tup.find(key);
    if (it != tup.end()) {
        return int_of_op_result(it->second);
    }
    throw std::runtime_error("Key not found: " + key);
}

float lookup_float(const std::string& key, const tuple_t& tup) {
    auto it = tup.find(key);
    if (it != tup.end()) {
        return float_of_op_result(it->second);
    }
    throw std::runtime_error("Key not found: " + key);
}

// Operator definition
class operator_t {
public:
    std::function<void(const tuple_t&)> next;
    std::function<void(const tuple_t&)> reset;

    operator_t(std::function<void(const tuple_t&)> next_func, std::function<void(const tuple_t&)> reset_func)
        : next(next_func), reset(reset_func) {}
};

// Right associative "chaining" operator
operator_t operator_at_equals_greater_than(op_creator op_creator_func, operator_t next_op) {
    return op_creator_func(next_op);
}

std::pair<operator_t, operator_t> operator_at_equals_equals_greater_than(dbl_op_creator op_creator_func, operator_t op) {
    return op_creator_func(op);
}

// Built-in operator definitions
namespace Builtins {
    const int init_table_size = 10000;

    operator_t dump_tuple(std::ostream& outc, bool show_reset = false) {
        return operator_t(
            [&](const tuple_t& tup) { OcamlInterop::dump_tuple(outc, tup); },
            [&](const tuple_t& tup) {
                OcamlInterop::dump_tuple(outc, tup);
                if (show_reset) {
                    outc << "[reset]\n";
                }
            }
        );
    }

    operator_t dump_as_csv(std::ostream& outc, const std::optional<std::pair<std::string, std::string>>& static_field = std::nullopt, bool header = true) {
        std::shared_ptr<bool> first = std::make_shared<bool>(header);
        return operator_t(
            [&](const tuple_t& tup) {
                if (*first) {
                    if (static_field.has_value()) {
                        outc << static_field.value().first << ",";
                    }
                    for (const auto& pair : tup) {
                        outc << pair.first << ",";
                    }
                    outc << "\n";
                    *first = false;
                }
                if (static_field.has_value()) {
                    outc << static_field.value().second << ",";
                }
                for (const auto& pair : tup) {
                    outc << string_of_op_result(pair.second) << ",";
                }
                outc << "\n";
            },
            [](const tuple_t&) {}
        );
    }

    operator_t dump_walts_csv(const std::string& filename) {
        std::shared_ptr<std::ofstream> outc = std::make_shared<std::ofstream>();
        std::shared_ptr<bool> first = std::make_shared<bool>(true);
        return operator_t(
            [&](const tuple_t& tup) {
                if (*first) {
                    outc->open(filename);
                    *first = false;
                }
                *outc << string_of_op_result(tup.at("ipv4.src")) << ","
                      << string_of_op_result(tup.at("ipv4.dst")) << ","
                      << string_of_op_result(tup.at("l4.sport")) << ","
                      << string_of_op_result(tup.at("l4.dport")) << ","
                      << string_of_op_result(tup.at("packet_count")) << ","
                      << string_of_op_result(tup.at("byte_count")) << ","
                      << string_of_op_result(tup.at("epoch_id")) << "\n";
            },
            [](const tuple_t&) {}
        );
    }

    op_result get_ip_or_zero(const std::string& input) {
        if (input == "0") {
            return 0;
        } else {
            return ipv4_of_string_exn(input);
        }
    }

    void read_walts_csv(const std::string& epoch_id_key, const std::vector<std::string>& file_names, const std::vector<operator_t>& ops) {
        std::vector<std::tuple<std::ifstream, int, int>> inchs_eids_tupcount;
        for (const auto& filename : file_names) {
            inchs_eids_tupcount.emplace_back(std::ifstream(filename), 0, 0);
        }

        int running = ops.size();
        while (running > 0) {
            for (size_t i = 0; i < inchs_eids_tupcount.size(); ++i) {
                auto& [in_ch, eid, tup_count] = inchs_eids_tupcount[i];
                const auto& op = ops[i];

                if (eid >= 0) {
                    std::string line;
                    if (std::getline(in_ch, line)) {
                        std::stringstream ss(line);
                        std::string segment;
                        std::vector<std::string> parts;
                        while (std::getline(ss, segment, ',')) {
                            parts.push_back(segment);
                        }

                        if (parts.size() == 7) {
                            try {
                                tuple_t p;
                                p["ipv4.src"] = get_ip_or_zero(parts[0]);
                                p["ipv4.dst"] = get_ip_or_zero(parts[1]);
                                p["l4.sport"] = std::stoi(parts[2]);
                                p["l4.dport"] = std::stoi(parts[3]);
                                p["packet_count"] = std::stoi(parts[4]);
                                p["byte_count"] = std::stoi(parts[5]);
                                int epoch_id = std::stoi(parts[6]);

                                tup_count++;
                                if (epoch_id > eid) {
                                    while (epoch_id > eid) {
                                        tuple_t reset_tup;
                                        reset_tup["tuples"] = tup_count;
                                        reset_tup[epoch_id_key] = eid;
                                        op.reset(reset_tup);
                                        tup_count = 0;
                                        eid++;
                                    }
                                }
                                tuple_t next_tup;
                                next_tup["tuples"] = tup_count;
                                next_tup.insert(p.begin(), p.end());
                                op.next(next_tup);

                            } catch (const std::invalid_argument& e) {
                                std::cerr << "Failed to scan: Invalid argument - " << e.what() << std::endl;
                                throw std::runtime_error("Scan failure");
                            } catch (const std::out_of_range& e) {
                                std::cerr << "Failed to scan: Out of range - " << e.what() << std::endl;
                                throw std::runtime_error("Scan failure");
                            }
                        } else {
                            std::cerr << "Failed to scan: Incorrect number of fields\n";
                            throw std::runtime_error("Scan failure");
                        }
                    } else {
                        tuple_t reset_tup;
                        reset_tup["tuples"] = tup_count;
                        reset_tup[epoch_id_key] = eid + 1;
                        op.reset(reset_tup);
                        running--;
                        eid = -1;
                    }
                }
            }
        }
        std::cout << "Done.\n";
    }

    operator_t meta_meter(const std::string& name, std::ostream& outc, operator_t next_op, const std::optional<std::string>& static_field = std::nullopt) {
        std::shared_ptr<int> epoch_count = std::make_shared<int>(0);
        std::shared_ptr<int> tups_count = std::make_shared<int>(0);
        return operator_t(
            [&](const tuple_t& tup) { (*tups_count)++; next_op.next(tup); },
            [&](const tuple_t& tup) {
                outc << *epoch_count << "," << name << "," << *tups_count << ",";
                if (static_field.has_value()) {
                    outc << static_field.value();
                }
                outc << "\n";
                *tups_count = 0;
                (*epoch_count)++;
                next_op.reset(tup);
            }
        );
    }

    operator_t epoch(float epoch_width, const std::string& key_out, operator_t next_op) {
        std::shared_ptr<double> epoch_boundary = std::make_shared<double>(0.0);
        std::shared_ptr<int> eid = std::make_shared<int>(0);
        return operator_t(
            [&](const tuple_t& tup) {
                double time = float_of_op_result(tup.at("time"));
                if (*epoch_boundary == 0.0) {
                    *epoch_boundary = time + epoch_width;
                } else if (time >= *epoch_boundary) {
                    while (time >= *epoch_boundary) {
                        next_op.reset({ {key_out, *eid} });
                        *epoch_boundary += epoch_width;
                        (*eid)++;
                    }
                }
                tuple_t next_tup = tup;
                next_tup[key_out] = *eid;
                next_op.next(next_tup);
            },
            [&](const tuple_t&) {
                next_op.reset({ {key_out, *eid} });
                *epoch_boundary = 0.0;
                *eid = 0;
            }
        );
    }

    operator_t filter(std::function<bool(const tuple_t&)> f, operator_t next_op) {
        return operator_t(
            [&](const tuple_t& tup) { if (f(tup)) next_op.next(tup); },
            [&](const tuple_t& tup) { next_op.reset(tup); }
        );
    }

    bool key_geq_int(const std::string& key, int threshold, const tuple_t& tup) {
        return lookup_int(key, tup) >= threshold;
    }

    int get_mapped_int(const std::string

        & key, const tuple_t& tup) {
            return lookup_int(key, tup);
        }
    
        float get_mapped_float(const std::string& key, const tuple_t& tup) {
            return lookup_float(key, tup);
        }
    
        operator_t map(std::function<tuple_t(const tuple_t&)> f, operator_t next_op) {
            return operator_t(
                [&](const tuple_t& tup) { next_op.next(f(tup)); },
                [&](const tuple_t& tup) { next_op.reset(tup); }
            );
        }
    
        using grouping_func = std::function<tuple_t(const tuple_t&)>;
        using reduction_func = std::function<op_result(op_result, const tuple_t&)>;
    
        operator_t groupby(grouping_func groupby_f, reduction_func reduce_f, const std::string& out_key, operator_t next_op) {
            std::unordered_map<tuple_t, op_result, std::function<size_t(const tuple_t&)>> h_tbl(
                init_table_size,
                [](const tuple_t& t) {
                    size_t hash = 0;
                    for (const auto& pair : t) {
                        hash ^= std::hash<std::string>{}(pair.first) + 0x9e3779b9 + (hash << 6) + (hash >> 2);
                        std::visit([&](const auto& val) {
                            hash ^= std::hash<decltype(val)>{}(val) + 0x9e3779b9 + (hash << 6) + (hash >> 2);
                        }, pair.second);
                    }
                    return hash;
                }
            );
            std::shared_ptr<int> reset_counter = std::make_shared<int>(0);
    
            return operator_t(
                [&](const tuple_t& tup) {
                    tuple_t grouping_key = groupby_f(tup);
                    auto it = h_tbl.find(grouping_key);
                    if (it != h_tbl.end()) {
                        it->second = reduce_f(it->second, tup);
                    } else {
                        h_tbl[grouping_key] = reduce_f(std::monostate{}, tup);
                    }
                },
                [&](const tuple_t& tup) {
                    (*reset_counter)++;
                    for (const auto& pair : h_tbl) {
                        tuple_t unioned_tup = tup;
                        unioned_tup.insert(pair.first.begin(), pair.first.end());
                        unioned_tup[out_key] = pair.second;
                        next_op.next(unioned_tup);
                    }
                    next_op.reset(tup);
                    h_tbl.clear();
                }
            );
        }
    
        tuple_t filter_groups(const std::vector<std::string>& incl_keys, const tuple_t& tup) {
            tuple_t result;
            for (const auto& key : incl_keys) {
                auto it = tup.find(key);
                if (it != tup.end()) {
                    result[it->first] = it->second;
                }
            }
            return result;
        }
    
        tuple_t single_group(const tuple_t&) {
            return {};
        }
    
        op_result counter(op_result val, const tuple_t&) {
            if (std::holds_alternative<std::monostate>(val)) {
                return 1;
            } else if (std::holds_alternative<int>(val)) {
                return std::get<int>(val) + 1;
            }
            return val;
        }
    
        op_result sum_ints(const std::string& search_key, op_result init_val, const tuple_t& tup) {
            if (std::holds_alternative<std::monostate>(init_val)) {
                return 0;
            } else if (std::holds_alternative<int>(init_val)) {
                auto it = tup.find(search_key);
                if (it != tup.end() && std::holds_alternative<int>(it->second)) {
                    return std::get<int>(init_val) + std::get<int>(it->second);
                } else {
                    throw std::runtime_error("sum_vals function failed to find integer value mapped to \"" + search_key + "\"");
                }
            }
            return init_val;
        }
    
        operator_t distinct(grouping_func groupby_f, operator_t next_op) {
            std::unordered_map<tuple_t, bool, std::function<size_t(const tuple_t&)>> h_tbl(
                init_table_size,
                [](const tuple_t& t) {
                    size_t hash = 0;
                    for (const auto& pair : t) {
                        hash ^= std::hash<std::string>{}(pair.first) + 0x9e3779b9 + (hash << 6) + (hash >> 2);
                        std::visit([&](const auto& val) {
                            hash ^= std::hash<decltype(val)>{}(val) + 0x9e3779b9 + (hash << 6) + (hash >> 2);
                        }, pair.second);
                    }
                    return hash;
                }
            );
            std::shared_ptr<int> reset_counter = std::make_shared<int>(0);
    
            return operator_t(
                [&](const tuple_t& tup) {
                    tuple_t grouping_key = groupby_f(tup);
                    h_tbl[grouping_key] = true;
                },
                [&](const tuple_t& tup) {
                    (*reset_counter)++;
                    for (const auto& pair : h_tbl) {
                        tuple_t merged_tup = tup;
                        merged_tup.insert(pair.first.begin(), pair.first.end());
                        next_op.next(merged_tup);
                    }
                    next_op.reset(tup);
                    h_tbl.clear();
                }
            );
        }
    
        operator_t split(operator_t l, operator_t r) {
            return operator_t(
                [&](const tuple_t& tup) { l.next(tup); r.next(tup); },
                [&](const tuple_t& tup) { l.reset(tup); r.reset(tup); }
            );
        }
    
        using key_extractor = std::function<std::pair<tuple_t, tuple_t>(const tuple_t&)>;
    
        std::pair<operator_t, operator_t> join(
            const key_extractor& left_extractor,
            const key_extractor& right_extractor,
            operator_t next_op,
            const std::string& eid_key = "eid"
        ) {
            std::unordered_map<tuple_t, tuple_t, std::function<size_t(const tuple_t&)>> h_tbl1(
                init_table_size,
                [](const tuple_t& t) {
                    size_t hash = 0;
                    for (const auto& pair : t) {
                        hash ^= std::hash<std::string>{}(pair.first) + 0x9e3779b9 + (hash << 6) + (hash >> 2);
                        std::visit([&](const auto& val) {
                            hash ^= std::hash<decltype(val)>{}(val) + 0x9e3779b9 + (hash << 6) + (hash >> 2);
                        }, pair.second);
                    }
                    return hash;
                }
            );
            std::unordered_map<tuple_t, tuple_t, std::function<size_t(const tuple_t&)>> h_tbl2(
                init_table_size,
                [](const tuple_t& t) {
                    size_t hash = 0;
                    for (const auto& pair : t) {
                        hash ^= std::hash<std::string>{}(pair.first) + 0x9e3779b9 + (hash << 6) + (hash >> 2);
                        std::visit([&](const auto& val) {
                            hash ^= std::hash<decltype(val)>{}(val) + 0x9e3779b9 + (hash << 6) + (hash >> 2);
                        }, pair.second);
                    }
                    return hash;
                }
            );
            std::shared_ptr<int> left_curr_epoch = std::make_shared<int>(0);
            std::shared_ptr<int> right_curr_epoch = std::make_shared<int>(0);
    
            auto handle_join_side =
                [&](std::unordered_map<tuple_t, tuple_t, std::function<size_t(const tuple_t&)>>& curr_h_tble,
                    std::unordered_map<tuple_t, tuple_t, std::function<size_t(const tuple_t&)>>& other_h_tbl,
                    std::shared_ptr<int>& curr_epoch_ref,
                    std::shared_ptr<int>& other_epoch_ref,
                    const key_extractor& f) -> operator_t {
                return operator_t(
                    [&](const tuple_t& tup) {
                        auto [key, vals_] = f(tup);
                        int curr_epoch = get_mapped_int(eid_key, tup);
    
                        while (curr_epoch > *curr_epoch_ref) {
                            if (*other_epoch_ref > *curr_epoch_ref) {
                                next_op.reset({ {eid_key, *curr_epoch_ref} });
                            }
                            (*curr_epoch_ref)++;
                        }
    
                        tuple_t new_tup = key;
                        new_tup[eid_key] = curr_epoch;
    
                        auto it = other_h_tbl.find(new_tup);
                        if (it != other_h_tbl.end()) {
                            tuple_t val_ = it->second;
                            other_h_tbl.erase(it);
                            tuple_t merged_tup = new_tup;
                            merged_tup.insert(vals_.begin(), vals_.end());
                            merged_tup.insert(val_.begin(), val_.end());
                            next_op.next(merged_tup);
                        } else {
                            curr_h_tble[new_tup] = vals_;
                        }
                    },
                    [&](const tuple_t& tup) {
                        int curr_epoch = get_mapped_int(eid_key, tup);
                        while (curr_epoch > *curr_epoch_ref) {
                            if (*other_epoch_ref > *curr_epoch_ref) {
                                next_op.reset({ {eid_key, *curr_epoch_ref} });
                            }
                            (*curr_epoch_ref)++;
                        }
                    }
                );
            };
    
            return {
                handle_join_side(h_tbl1, h_tbl2, left_curr_epoch, right_curr_epoch, left_extractor),
                handle_join_side(h_tbl2, h_tbl1, right_curr_epoch, left_curr_epoch, right_extractor)
            };
        }
    
        tuple_t rename_filtered_keys(const std::vector<std::pair<std::string, std::string>>& renamings_pairs, const tuple_t& in_tup) {
            tuple_t new_tup;
            for (const auto& pair : renamings_pairs) {
                auto it = in_tup.find(pair.first);
                if (it != in_tup.end()) {
                    new_tup[pair.second] = it->second;
                }
            }
            return new_tup;
        }
    } // namespace Builtins
    
    using namespace Builtins;
    
    // Queries
    namespace Queries {
        operator_t ident(operator_t next_op) {
            return map([](const tuple_t& tup) {
                tuple_t filtered_tup;
                for (const auto& pair : tup) {
                    if (pair.first != "eth.src" && pair.first != "eth.dst") {
                        filtered_tup[pair.first] = pair.second;
                    }
                }
                return filtered_tup;
            }, next_op);
        }
    
        operator_t count_pkts(operator_t next_op) {
            return epoch(1.0, "eid", groupby(single_group, counter, "pkts", next_op));
        }
    
        operator_t pkts_per_src_dst(operator_t next_op) {
            return epoch(1.0, "eid", groupby(filter_groups({"ipv4.src", "ipv4.dst"}), counter, "pkts", next_op));
        }
    
        operator_t distinct_srcs(operator_t next_op) {
            return epoch(1.0, "eid", distinct(filter_groups({"ipv4.src"}), groupby(single_group, counter, "srcs", next_op)));
        }
    
        operator_t tcp_new_cons(operator_t next_op) {
            int threshold = 40;
            return epoch(1.0, "eid",
                         filter([](const tuple_t& tup) {
                             return get_mapped_int("ipv4.proto", tup) == 6 && get_mapped_int("l4.flags", tup) == 2;
                         },
                         groupby(filter_groups({"ipv4.dst"}), counter, "cons",
                                 filter([threshold](const tuple_t& tup) { return key_geq_int("cons", threshold, tup); }, next_op))));
        }
    
        operator_t ssh_brute_force(operator_t next_op) {
            int threshold = 40;
            return epoch(1.0, "eid",
                         filter([](const tuple_t& tup) {
                             return get_mapped_int("ipv4.proto", tup) == 6 && get_mapped_int("l4.dport", tup) == 22;
                         },
                         distinct(filter_groups({"ipv4.src", "ipv4.dst", "ipv4.len"}),
                                  groupby(filter_groups({"ipv4.dst", "ipv4.len"}), counter, "srcs",
                                          filter([threshold](const tuple_t& tup) { return key_geq_int("srcs", threshold, tup); }, next_op)))));
        }
    
        operator_t super_spreader(operator_t next_op) {
            int threshold = 40;
            return epoch(1.0, "eid",
                         distinct(filter_groups({"ipv4.src", "ipv4.dst"}),
                                  groupby(filter_groups({"ipv4.src"}), counter, "dsts",
                                          filter([threshold](const tuple_t& tup) { return key_geq_int("dsts", threshold, tup); }, next_op))));
        }
    
        operator_t port_scan(operator_t next_op) {
            int threshold = 40;
            return epoch(1.0, "eid",
                         distinct(filter_groups({"ipv4.src", "l4.dport"}),
                                  groupby(filter_groups({"ipv4.src"}), counter, "ports",
                                          filter([threshold](const tuple_t& tup) { return key_geq_int("ports", threshold, tup); }, next_op))));
        }
    
        operator_t ddos(operator_t next_op) {
            int threshold = 45;
            return epoch(1.0, "eid",
                         distinct(filter_groups({"ipv4.src", "ipv4.dst"}),
                                  groupby(filter_groups({"ipv4.dst"}), counter, "srcs",
                                          filter([threshold](const tuple_t& tup) { return key_geq_int("srcs", threshold, tup); }, next_op))));
        }
    
        std::vector<operator_t> syn_flood_sonata(operator_t next_op) {
            int threshold = 3;
            float epoch_dur = 1.0;
    
            auto syns = [&](operator_t next) {
                return epoch(epoch_dur, "eid",
                             filter([](const tuple_t& tup) {
                                 return get_mapped_int("ipv4.proto", tup) == 6 && get_mapped_int("l4.flags", tup) == 2;
                             },
                             groupby(filter_groups({"ipv4.dst"}), counter, "syns", next)));
            };
    
            auto synacks = [&](operator_t next) {
                return epoch(epoch_dur, "eid",
                             filter([](const tuple_t& tup) {
                                 return get_mapped_int("ipv4.proto", tup) == 6 && get_mapped_int("l4.flags", tup) == 18;
                             },
                             filter_groups({"ipv4.src"}), counter, "synacks", next)));
                            };
                    
                            auto acks = [&](operator_t next) {
                                return epoch(epoch_dur, "eid",
                                             filter([](const tuple_t& tup) {
                                                 return get_mapped_int("ipv4.proto", tup) == 6 && get_mapped_int("l4.flags", tup) == 16;
                                             },
                                             groupby(filter_groups({"ipv4.dst"}), counter, "acks", next)));
                            };
                    
                            operator_t join_op1, join_op2;
                            std::tie(join_op1, join_op2) = join(
                                [](const tuple_t& tup) {
                                    return std::make_pair(filter_groups({"host"}, tup), filter_groups({"syns+synacks"}, tup));
                                },
                                [](const tuple_t& tup) {
                                    return std::make_pair(rename_filtered_keys({{"ipv4.dst", "host"}}, tup), filter_groups({"acks"}, tup));
                                },
                                map([threshold](const tuple_t& tup) {
                                    tuple_t new_tup = tup;
                                    int syns_synacks = get_mapped_int("syns+synacks", tup);
                                    int acks_val = get_mapped_int("acks", tup);
                                    new_tup["syns+synacks-acks"] = syns_synacks - acks_val;
                                    return new_tup;
                                }, filter([threshold](const tuple_t& tup) { return key_geq_int("syns+synacks-acks", threshold, tup); }, next_op))
                            );
                    
                            operator_t join_op3, join_op4;
                            std::tie(join_op3, join_op4) = join(
                                [](const tuple_t& tup) {
                                    return std::make_pair(rename_filtered_keys({{"ipv4.dst", "host"}}, tup), filter_groups({"syns"}, tup));
                                },
                                [](const tuple_t& tup) {
                                    return std::make_pair(rename_filtered_keys({{"ipv4.src", "host"}}, tup), filter_groups({"synacks"}, tup));
                                },
                                map([](const tuple_t& tup) {
                                    tuple_t new_tup = tup;
                                    int syns_val = get_mapped_int("syns", tup);
                                    int synacks_val = get_mapped_int("synacks", tup);
                                    new_tup["syns+synacks"] = syns_val + synacks_val;
                                    return new_tup;
                                }, join_op1)
                            );
                    
                            return {syns(join_op3), synacks(join_op4), acks(join_op2)};
                        }
                    
                        std::vector<operator_t> completed_flows(operator_t next_op) {
                            int threshold = 1;
                            float epoch_dur = 30.0;
                    
                            auto syns = [&](operator_t next) {
                                return epoch(epoch_dur, "eid",
                                             filter([](const tuple_t& tup) {
                                                 return get_mapped_int("ipv4.proto", tup) == 6 && get_mapped_int("l4.flags", tup) == 2;
                                             },
                                             groupby(filter_groups({"ipv4.dst"}), counter, "syns", next)));
                            };
                    
                            auto fins = [&](operator_t next) {
                                return epoch(epoch_dur, "eid",
                                             filter([](const tuple_t& tup) {
                                                 return get_mapped_int("ipv4.proto", tup) == 6 && (get_mapped_int("l4.flags", tup) & 1) == 1;
                                             },
                                             groupby(filter_groups({"ipv4.src"}), counter, "fins", next)));
                            };
                    
                            operator_t op1, op2;
                            std::tie(op1, op2) = join(
                                [](const tuple_t& tup) {
                                    return std::make_pair(rename_filtered_keys({{"ipv4.dst", "host"}}, tup), filter_groups({"syns"}, tup));
                                },
                                [](const tuple_t& tup) {
                                    return std::make_pair(rename_filtered_keys({{"ipv4.src", "host"}}, tup), filter_groups({"fins"}, tup));
                                },
                                map([threshold](const tuple_t& tup) {
                                    tuple_t new_tup = tup;
                                    int syns_val = get_mapped_int("syns", tup);
                                    int fins_val = get_mapped_int("fins", tup);
                                    new_tup["diff"] = syns_val - fins_val;
                                    return new_tup;
                                }, filter([threshold](const tuple_t& tup) { return key_geq_int("diff", threshold, tup); }, next_op))
                            );
                    
                            return {syns(op1), fins(op2)};
                        }
                    
                        std::vector<operator_t> slowloris(operator_t next_op) {
                            int t1 = 5;
                            int t2 = 500;
                            int t3 = 90;
                            float epoch_dur = 1.0;
                    
                            auto n_conns = [&](operator_t next) {
                                return epoch(epoch_dur, "eid",
                                             filter([](const tuple_t& tup) {
                                                 return get_mapped_int("ipv4.proto", tup) == 6;
                                             },
                                             distinct(filter_groups({"ipv4.src", "ipv4.dst", "l4.sport"}),
                                                      groupby(filter_groups({"ipv4.dst"}), counter, "n_conns",
                                                              filter([t1](const tuple_t& tup) { return get_mapped_int("n_conns", tup) >= t1; }, next)))));
                            };
                    
                            auto n_bytes = [&](operator_t next) {
                                return epoch(epoch_dur, "eid",
                                             filter([](const tuple_t& tup) {
                                                 return get_mapped_int("ipv4.proto", tup) == 6;
                                             },
                                             groupby(filter_groups({"ipv4.dst"}), sum_ints("ipv4.len", std::monostate{}, {}), "n_bytes",
                                                     filter([t2](const tuple_t& tup) { return get_mapped_int("n_bytes", tup) >= t2; }, next))));
                            };
                    
                            operator_t op1, op2;
                            std::tie(op1, op2) = join(
                                [](const tuple_t& tup) {
                                    return std::make_pair(filter_groups({"ipv4.dst"}, tup), filter_groups({"n_conns"}, tup));
                                },
                                [](const tuple_t& tup) {
                                    return std::make_pair(filter_groups({"ipv4.dst"}, tup), filter_groups({"n_bytes"}, tup));
                                },
                                map([t3](const tuple_t& tup) {
                                    tuple_t new_tup = tup;
                                    int n_bytes_val = get_mapped_int("n_bytes", tup);
                                    int n_conns_val = get_mapped_int("n_conns", tup);
                                    new_tup["bytes_per_conn"] = n_bytes_val / n_conns_val;
                                    return new_tup;
                                }, filter([t3](const tuple_t& tup) { return get_mapped_int("bytes_per_conn", tup) <= t3; }, next_op))
                            );
                    
                            return {n_conns(op1), n_bytes(op2)};
                        }
                    
                        std::vector<operator_t> join_test(operator_t next_op) {
                            float epoch_dur = 1.0;
                    
                            auto syns = [&](operator_t next) {
                                return epoch(epoch_dur, "eid",
                                             filter([](const tuple_t& tup) {
                                                 return get_mapped_int("ipv4.proto", tup) == 6 && get_mapped_int("l4.flags", tup) == 2;
                                             }, next));
                            };
                    
                            auto synacks = [&](operator_t next) {
                                return epoch(epoch_dur, "eid",
                                             filter([](const tuple_t& tup) {
                                                 return get_mapped_int("ipv4.proto", tup) == 6 && get_mapped_int("l4.flags", tup) == 18;
                                             }, next));
                            };
                    
                            operator_t op1, op2;
                            std::tie(op1, op2) = join(
                                [](const tuple_t& tup) {
                                    return std::make_pair(rename_filtered_keys({{"ipv4.src", "host"}}, tup), rename_filtered_keys({{"ipv4.dst", "remote"}}, tup));
                                },
                                [](const tuple_t& tup) {
                                    return std::make_pair(rename_filtered_keys({{"ipv4.dst", "host"}}, tup), filter_groups({"time"}, tup));
                                },
                                next_op
                            );
                    
                            return {syns(op1), synacks(op2)};
                        }
                    
                        operator_t q3(operator_t next_op) {
                            return epoch(100.0, "eid", distinct(filter_groups({"ipv4.src", "ipv4.dst"}), next_op));
                        }
                    
                        operator_t q4(operator_t next_op) {
                            return epoch(10000.0, "eid", groupby(filter_groups({"ipv4.dst"}), counter, "pkts", next_op));
                        }
                    } // namespace Queries
                    
                    int main() {
                        using namespace Queries;
                        using namespace Builtins;
                    
                        std::vector<operator_t> queries = {ident(dump_tuple(std::cout))};
                    
                        for (int i = 0; i < 20; ++i) {
                            tuple_t tup;
                            tup["time"] = static_cast<float>(0.000000 + i);
                            ether_addr eth_src, eth_dst;
                            ether_aton_r("00:11:22:33:44:55", &eth_src);
                            ether_aton_r("AA:BB:CC:DD:EE:FF", &eth_dst);
                            tup["eth.src"] = eth_src;
                            tup["eth.dst"] = eth_dst;
                            tup["eth.ethertype"] = 0x0800;
                            tup["ipv4.hlen"] = 20;
                            tup["ipv4.proto"] = 6;
                            tup["ipv4.len"] = 60;
                            tup["ipv4.src"] = ipv4_of_string_exn("127.0.0.1");
                            tup["ipv4.dst"] = ipv4_of_string_exn("127.0.0.1");
                            tup["l4.sport"] = 440;
                            tup["l4.dport"] = 50000;
                            tup["l4.flags"] = 10;
                    
                            for (auto& query : queries) {
                                query.next(tup);
                            }
                        }
                    
                        std::cout << "Done\n";
                    
                        return 0;
                    }
                