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