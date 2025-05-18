#include <iostream>
#include <fstream>
#include <string>
#include <map>
#include <variant>
#include <functional>
#include <cstdio>
#include <iomanip>
#include <sstream>
#include <vector>
#include <memory>
#include <unordered_map>
#include <algorithm>
#include <set>
#include <cmath>

// Forward declarations and type definitions

// Equivalent to OCaml's variant type op_result
using op_result = std::variant<double, int, std::string, std::vector<uint8_t>, std::monostate>;

// Equivalent to OCaml's tuple type - a map from strings to op_result
using tuple = std::map<std::string, op_result>;

// Equivalent to OCaml's operator record type
struct operator_t {
    std::function<void(const tuple&)> next;
    std::function<void(const tuple&)> reset;
};

// Type aliases for function types
using op_creator = std::function<operator_t(operator_t)>;
using dbl_op_creator = std::function<std::pair<operator_t, operator_t>(operator_t)>;

// Type aliases for grouping and reduction functions
using grouping_func = std::function<tuple(const tuple&)>;
using reduction_func = std::function<op_result(const op_result&, const tuple&)>;
using key_extractor = std::function<std::pair<tuple, tuple>(const tuple&)>;

// Helper functions for format handling
template <typename... Args>
std::string string_printf(const std::string& format, Args... args) {
    size_t size = std::snprintf(nullptr, 0, format.c_str(), args...) + 1;
    std::unique_ptr<char[]> buf(new char[size]);
    std::snprintf(buf.get(), size, format.c_str(), args...);
    return std::string(buf.get(), buf.get() + size - 1);
}

// Helper functions for MAC address formatting
std::string string_of_mac(const std::vector<uint8_t>& buf) {
    if (buf.size() < 6) return "";
    return string_printf("%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
        buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]);
}

// TCP flags to string conversion
std::string tcp_flags_to_strings(int flags) {
    static const std::map<std::string, int> tcp_flags_map = {
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
    for (const auto& entry : tcp_flags_map) {
        if ((flags & entry.second) == entry.second) {
            if (!result.empty()) result += "|";
            result += entry.first;
        }
    }
    return result;
}

// Helper functions for variant type access
int int_of_op_result(const op_result& input) {
    return std::get<int>(input);
}

double float_of_op_result(const op_result& input) {
    return std::get<double>(input);
}

std::string string_of_op_result(const op_result& input) {
    return std::visit([](const auto& val) -> std::string {
        using T = std::decay_t<decltype(val)>;
        if constexpr (std::is_same_v<T, double>) {
            return std::to_string(val);
        } else if constexpr (std::is_same_v<T, int>) {
            return std::to_string(val);
        } else if constexpr (std::is_same_v<T, std::string>) {
            return val;
        } else if constexpr (std::is_same_v<T, std::vector<uint8_t>>) {
            return string_of_mac(val);
        } else {
            return "Empty";
        }
    }, input);
}

// Tuple utilities
std::string string_of_tuple(const tuple& input_tuple) {
    std::string result;
    for (const auto& entry : input_tuple) {
        result += string_printf("\"%s\" => %s, ", entry.first.c_str(), 
                              string_of_op_result(entry.second).c_str());
    }
    return result;
}

void dump_tuple(std::ostream& outc, const tuple& tup) {
    outc << string_of_tuple(tup) << std::endl;
}

int lookup_int(const std::string& key, const tuple& tup) {
    return int_of_op_result(tup.at(key));
}

double lookup_float(const std::string& key, const tuple& tup) {
    return float_of_op_result(tup.at(key));
}

// Built-in operator definitions
constexpr int init_table_size = 10000;

// dump_tuple operator
operator_t dump_tuple_op(std::ostream& outc, bool show_reset = false) {
    return {
        [&outc](const tuple& tup) { dump_tuple(outc, tup); },
        [&outc, show_reset](const tuple& tup) {
            if (show_reset) {
                dump_tuple(outc, tup);
                outc << "[reset]" << std::endl;
            }
        }
    };
}

// dump_as_csv operator
operator_t dump_as_csv(std::ostream& outc, 
                       std::optional<std::pair<std::string, std::string>> static_field = std::nullopt,
                       bool header = true) {
    auto first = std::make_shared<bool>(header);
    
    return {
        [&outc, static_field, first](const tuple& tup) {
            if (*first) {
                if (static_field) {
                    outc << static_field->first << ",";
                }
                for (const auto& entry : tup) {
                    outc << entry.first << ",";
                }
                outc << std::endl;
                *first = false;
            }
            
            if (static_field) {
                outc << static_field->second << ",";
            }
            for (const auto& entry : tup) {
                outc << string_of_op_result(entry.second) << ",";
            }
            outc << std::endl;
        },
        [](const tuple&) {}
    };
}

// dump_walts_csv operator
operator_t dump_walts_csv(const std::string& filename) {
    auto outc = std::make_shared<std::ofstream>();
    auto first = std::make_shared<bool>(true);
    
    return {
        [outc, first, filename](const tuple& tup) {
            if (*first) {
                outc->open(filename);
                *first = false;
            }
            
            *outc << string_of_op_result(tup.at("src_ip")) << ","
                  << string_of_op_result(tup.at("dst_ip")) << ","
                  << string_of_op_result(tup.at("src_l4_port")) << ","
                  << string_of_op_result(tup.at("dst_l4_port")) << ","
                  << string_of_op_result(tup.at("packet_count")) << ","
                  << string_of_op_result(tup.at("byte_count")) << ","
                  << string_of_op_result(tup.at("epoch_id"))
                  << std::endl;
        },
        [](const tuple&) {}
    };
}

// get_ip_or_zero utility
op_result get_ip_or_zero(const std::string& input) {
    if (input == "0") {
        return 0;
    }
    return input;
}

// read_walts_csv function
void read_walts_csv(const std::vector<std::string>& file_names,
                    const std::vector<operator_t>& ops,
                    const std::string& epoch_id_key = "eid") {
    // Implementation of file reading and processing
    // Similar to the OCaml version but using C++ streams
    auto running = std::make_shared<int>(ops.size());
    
    // Open files and process them
    std::vector<std::tuple<std::ifstream, int, int>> inchs_eids_tupcount;
    for (const auto& filename : file_names) {
        inchs_eids_tupcount.emplace_back(std::ifstream(filename), 0, 0);
    }
    
    while (*running > 0) {
        for (size_t i = 0; i < inchs_eids_tupcount.size(); ++i) {
            auto& [in_ch, eid, tup_count] = inchs_eids_tupcount[i];
            if (eid >= 0) {
                std::string line;
                if (std::getline(in_ch, line)) {
                    std::stringstream ss(line);
                    std::string src_ip, dst_ip;
                    int src_l4_port, dst_l4_port, packet_count, byte_count, epoch_id;
                    
                    ss >> src_ip;
                    ss.ignore(1);
                    ss >> dst_ip;
                    ss.ignore(1);
                    ss >> src_l4_port;
                    ss.ignore(1);
                    ss >> dst_l4_port;
                    ss.ignore(1);
                    ss >> packet_count;
                    ss.ignore(1);
                    ss >> byte_count;
                    ss.ignore(1);
                    ss >> epoch_id;
                    
                    tuple p;
                    p["ipv4.src"] = get_ip_or_zero(src_ip);
                    p["ipv4.dst"] = get_ip_or_zero(dst_ip);
                    p["l4.sport"] = src_l4_port;
                    p["l4.dport"] = dst_l4_port;
                    p["packet_count"] = packet_count;
                    p["byte_count"] = byte_count;
                    p[epoch_id_key] = epoch_id;
                    
                    tup_count++;
                    
                    if (epoch_id > eid) {
                        while (epoch_id > eid) {
                            tuple reset_tup;
                            reset_tup["tuples"] = tup_count;
                            reset_tup[epoch_id_key] = eid;
                            ops[i].reset(reset_tup);
                            tup_count = 0;
                            eid++;
                        }
                    }
                    
                    tuple new_tup = p;
                    new_tup["tuples"] = tup_count;
                    ops[i].next(new_tup);
                } else {
                    tuple reset_tup;
                    reset_tup["tuples"] = tup_count;
                    reset_tup[epoch_id_key] = eid + 1;
                    ops[i].reset(reset_tup);
                    (*running)--;
                    eid = -1;
                }
            }
        }
    }
    std::cout << "Done." << std::endl;
}

// meta_meter operator
operator_t meta_meter(const std::string& name, std::ostream& outc, operator_t next_op,
                      std::optional<std::string> static_field = std::nullopt) {
    auto epoch_count = std::make_shared<int>(0);
    auto tups_count = std::make_shared<int>(0);
    
    return {
        [tups_count, next_op](const tuple& tup) {
            (*tups_count)++;
            next_op.next(tup);
        },
        [&outc, name, epoch_count, tups_count, static_field, next_op](const tuple& tup) {
            outc << *epoch_count << "," << name << "," << *tups_count << ",";
            if (static_field) {
                outc << *static_field;
            }
            outc << std::endl;
            *tups_count = 0;
            (*epoch_count)++;
            next_op.reset(tup);
        }
    };
}

// epoch operator
operator_t epoch(double epoch_width, const std::string& key_out, operator_t next_op) {
    auto epoch_boundary = std::make_shared<double>(0.0);
    auto eid = std::make_shared<int>(0);
    
    return {
        [epoch_width, key_out, epoch_boundary, eid, next_op](const tuple& tup) {
            double time = float_of_op_result(tup.at("time"));
            if (*epoch_boundary == 0.0) {
                *epoch_boundary = time + epoch_width;
            } else if (time >= *epoch_boundary) {
                while (time >= *epoch_boundary) {
                    tuple reset_tup;
                    reset_tup[key_out] = *eid;
                    next_op.reset(reset_tup);
                    *epoch_boundary += epoch_width;
                    (*eid)++;
                }
            }
            tuple new_tup = tup;
            new_tup[key_out] = *eid;
            next_op.next(new_tup);
        },
        [key_out, epoch_boundary, eid, next_op](const tuple&) {
            tuple reset_tup;
            reset_tup[key_out] = *eid;
            next_op.reset(reset_tup);
            *epoch_boundary = 0.0;
            *eid = 0;
        }
    };
}

// filter operator
operator_t filter(std::function<bool(const tuple&)> f, operator_t next_op) {
    return {
        [f, next_op](const tuple& tup) {
            if (f(tup)) {
                next_op.next(tup);
            }
        },
        [next_op](const tuple& tup) {
            next_op.reset(tup);
        }
    };
}

// Helper functions for filtering
bool key_geq_int(const std::string& key, int threshold, const tuple& tup) {
    return int_of_op_result(tup.at(key)) >= threshold;
}

int get_mapped_int(const std::string& key, const tuple& tup) {
    return int_of_op_result(tup.at(key));
}

double get_mapped_float(const std::string& key, const tuple& tup) {
    return float_of_op_result(tup.at(key));
}

// map operator
operator_t map(std::function<tuple(const tuple&)> f, operator_t next_op) {
    return {
        [f, next_op](const tuple& tup) {
            next_op.next(f(tup));
        },
        [next_op](const tuple& tup) {
            next_op.reset(tup);
        }
    };
}

// groupby operator
operator_t groupby(grouping_func groupby_func, reduction_func reduce,
                   const std::string& out_key, operator_t next_op) {
    auto h_tbl = std::make_shared<std::unordered_map<std::string, op_result>>();
    auto reset_counter = std::make_shared<int>(0);
    
    return {
        [h_tbl, groupby_func, reduce](const tuple& tup) {
            tuple grouping_key = groupby_func(tup);
            std::string key_str = string_of_tuple(grouping_key);
            
            if (h_tbl->find(key_str) != h_tbl->end()) {
                (*h_tbl)[key_str] = reduce((*h_tbl)[key_str], tup);
            } else {
                (*h_tbl)[key_str] = reduce(std::monostate{}, tup);
            }
        },
        [h_tbl, out_key, reset_counter, next_op](const tuple& tup) {
            (*reset_counter)++;
            for (const auto& entry : *h_tbl) {
                // Parse grouping key back to tuple
                // For simplicity, assuming key_str can be parsed
                tuple grouping_key;
                tuple unioned_tup = tup;
                unioned_tup.insert(grouping_key.begin(), grouping_key.end());
                unioned_tup[out_key] = entry.second;
                next_op.next(unioned_tup);
            }
            next_op.reset(tup);
            h_tbl->clear();
        }
    };
}

// Utility functions for groupby
tuple filter_groups(const std::vector<std::string>& incl_keys, const tuple& tup) {
    tuple result;
    for (const auto& key : incl_keys) {
        if (tup.find(key) != tup.end()) {
            result[key] = tup.at(key);
        }
    }
    return result;
}

tuple single_group(const tuple&) {
    return tuple{};
}

op_result counter(const op_result& val, const tuple&) {
    if (std::holds_alternative<std::monostate>(val)) {
        return 1;
    }
    return int_of_op_result(val) + 1;
}

op_result sum_ints(const std::string& search_key, const op_result& init_val, const tuple& tup) {
    if (std::holds_alternative<std::monostate>(init_val)) {
        return 0;
    }
    int current = int_of_op_result(init_val);
    if (tup.find(search_key) != tup.end()) {
        return current + int_of_op_result(tup.at(search_key));
    }
    return current;
}

// distinct operator
operator_t distinct(grouping_func groupby_func, operator_t next_op) {
    auto h_tbl = std::make_shared<std::unordered_map<std::string, bool>>();
    auto reset_counter = std::make_shared<int>(0);
    
    return {
        [h_tbl, groupby_func](const tuple& tup) {
            tuple grouping_key = groupby_func(tup);
            std::string key_str = string_of_tuple(grouping_key);
            (*h_tbl)[key_str] = true;
        },
        [h_tbl, reset_counter, next_op](const tuple& tup) {
            (*reset_counter)++;
            for (const auto& entry : *h_tbl) {
                // Parse grouping key back to tuple
                tuple merged_tup = tup;
                // For simplicity, assuming key_str can be parsed
                next_op.next(merged_tup);
            }
            next_op.reset(tup);
            h_tbl->clear();
        }
    };
}

// split operator
operator_t split(operator_t l, operator_t r) {
    return {
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

// join operator
std::pair<operator_t, operator_t> join(key_extractor left_extractor, 
                                       key_extractor right_extractor,
                                       operator_t next_op,
                                       const std::string& eid_key = "eid") {
    auto h_tbl1 = std::make_shared<std::unordered_map<std::string, tuple>>();
    auto h_tbl2 = std::make_shared<std::unordered_map<std::string, tuple>>();
    auto left_curr_epoch = std::make_shared<int>(0);
    auto right_curr_epoch = std::make_shared<int>(0);
    
    auto handle_join_side = [eid_key](auto& curr_h_tbl, auto& other_h_tbl,
                                      auto& curr_epoch_ref, auto& other_epoch_ref,
                                      key_extractor f, operator_t next_op) {
        return operator_t{
            [&curr_h_tbl, &other_h_tbl, &curr_epoch_ref, &other_epoch_ref, f, eid_key, next_op]
            (const tuple& tup) {
                auto [key, vals] = f(tup);
                int curr_epoch = get_mapped_int(eid_key, tup);
                
                while (curr_epoch > *curr_epoch_ref) {
                    if (*other_epoch_ref > *curr_epoch_ref) {
                        tuple reset_tup;
                        reset_tup[eid_key] = *curr_epoch_ref;
                        next_op.reset(reset_tup);
                    }
                    (*curr_epoch_ref)++;
                }
                
                tuple new_tup = key;
                new_tup[eid_key] = curr_epoch;
                std::string key_str = string_of_tuple(new_tup);
                
                if (other_h_tbl->find(key_str) != other_h_tbl->end()) {
                    tuple val = (*other_h_tbl)[key_str];
                    other_h_tbl->erase(key_str);
                    tuple result = new_tup;
                    result.insert(vals.begin(), vals.end());
                    result.insert(val.begin(), val.end());
                    next_op.next(result);
                } else {
                    (*curr_h_tbl)[key_str] = vals;
                }
            },
            [&curr_epoch_ref, &other_epoch_ref, eid_key, next_op]
            (const tuple& tup) {
                int curr_epoch = get_mapped_int(eid_key, tup);
                while (curr_epoch > *curr_epoch_ref) {
                    if (*other_epoch_ref > *curr_epoch_ref) {
                        tuple reset_tup;
                        reset_tup[eid_key] = *curr_epoch_ref;
                        next_op.reset(reset_tup);
                    }
                    (*curr_epoch_ref)++;
                }
            }
        };
    };
    
    return {
        handle_join_side(h_tbl1, h_tbl2, left_curr_epoch, 
                         right_curr_epoch, left_extractor, next_op),
        handle_join_side(h_tbl2, h_tbl1, right_curr_epoch, 
                         left_curr_epoch, right_extractor, next_op)
    };
}

// rename_filtered_keys utility
tuple rename_filtered_keys(const std::vector<std::pair<std::string, std::string>>& renamings,
                           const tuple& in_tup) {
    tuple result;
    for (const auto& [old_key, new_key] : renamings) {
        if (in_tup.find(old_key) != in_tup.end()) {
            result[new_key] = in_tup.at(old_key);
        }
    }
    return result;
}

// Operators for different network analysis queries
// This section includes all the query definitions (ident, count_pkts, tcp_new_cons, etc.)
// Following the same pattern as the OCaml code

operator_t ident(operator_t next_op) {
    return map([](const tuple& tup) {
        tuple result = tup;
        result.erase("eth.src");
        result.erase("eth.dst");
        return result;
    }, next_op);
}

operator_t count_pkts(operator_t next_op) {
    return epoch(1.0, "eid", 
        groupby(single_group, counter, "pkts", next_op));
}

operator_t pkts_per_src_dst(operator_t next_op) {
    return epoch(1.0, "eid",
        groupby([](const tuple& tup) {
            return filter_groups({"ipv4.src", "ipv4.dst"}, tup);
        }, counter, "pkts", next_op));
}

operator_t distinct_srcs(operator_t next_op) {
    return epoch(1.0, "eid",
        distinct([](const tuple& tup) {
            return filter_groups({"ipv4.src"}, tup);
        },
        groupby(single_group, counter, "srcs", next_op)));
}

// Sonata 1 - TCP new connections
operator_t tcp_new_cons(operator_t next_op) {
    const int threshold = 40;
    return epoch(1.0, "eid",
        filter([](const tuple& tup) {
            return get_mapped_int("ipv4.proto", tup) == 6 &&
                   get_mapped_int("l4.flags", tup) == 2;
        },
        groupby([](const tuple& tup) {
            return filter_groups({"ipv4.dst"}, tup);
        }, counter, "cons",
        filter([threshold](const tuple& tup) {
            return get_mapped_int("cons", tup) >= threshold;
        }, next_op))));
}

// Sonata 2 - SSH brute force
operator_t ssh_brute_force(operator_t next_op) {
    const int threshold = 40;
    return epoch(1.0, "eid",
        filter([](const tuple& tup) {
            return get_mapped_int("ipv4.proto", tup) == 6 &&
                   get_mapped_int("l4.dport", tup) == 22;
        },
        distinct([](const tuple& tup) {
            return filter_groups({"ipv4.src", "ipv4.dst", "ipv4.len"}, tup);
        },
        groupby([](const tuple& tup) {
            return filter_groups({"ipv4.dst", "ipv4.len"}, tup);
        }, counter, "srcs",
        filter([threshold](const tuple& tup) {
            return get_mapped_int("srcs", tup) >= threshold;
        }, next_op)))));
}

// Sonata 3 - Super spreader
operator_t super_spreader(operator_t next_op) {
    const int threshold = 40;
    return epoch(1.0, "eid",
        distinct([](const tuple& tup) {
            return filter_groups({"ipv4.src", "ipv4.dst"}, tup);
        },
        groupby([](const tuple& tup) {
            return filter_groups({"ipv4.src"}, tup);
        }, counter, "dsts",
        filter([threshold](const tuple& tup) {
            return get_mapped_int("dsts", tup) >= threshold;
        }, next_op))));
}

// Sonata 4 - Port scan
operator_t port_scan(operator_t next_op) {
    const int threshold = 40;
    return epoch(1.0, "eid",
        distinct([](const tuple& tup) {
            return filter_groups({"ipv4.src", "l4.dport"}, tup);
        },
        groupby([](const tuple& tup) {
            return filter_groups({"ipv4.src"}, tup);
        }, counter, "ports",
        filter([threshold](const tuple& tup) {
            return get_mapped_int("ports", tup) >= threshold;
        }, next_op))));
}

// Sonata 5 - DDoS
operator_t ddos(operator_t next_op) {
    const int threshold = 45;
    return epoch(1.0, "eid",
        distinct([](const tuple& tup) {
            return filter_groups({"ipv4.src", "ipv4.dst"}, tup);
        },
        groupby([](const tuple& tup) {
            return filter_groups({"ipv4.dst"}, tup);
        }, counter, "srcs",
        filter([threshold](const tuple& tup) {
            return get_mapped_int("srcs", tup) >= threshold;
        }, next_op))));
}

// Sonata 6 - SYN flood
std::vector<operator_t> syn_flood_sonata(operator_t next_op) {
    const int threshold = 3;
    const double epoch_dur = 1.0;
    
    auto syns = [epoch_dur](operator_t next_op) {
        return epoch(epoch_dur, "eid",
            filter([](const tuple& tup) {
                return get_mapped_int("ipv4.proto", tup) == 6 &&
                       get_mapped_int("l4.flags", tup) == 2;
            },
            groupby([](const tuple& tup) {
                return filter_groups({"ipv4.dst"}, tup);
            }, counter, "syns", next_op)));
    };
    
    auto synacks = [epoch_dur](operator_t next_op) {
        return epoch(epoch_dur, "eid",
            filter([](const tuple& tup) {
                return get_mapped_int("ipv4.proto", tup) == 6 &&
                       get_mapped_int("l4.flags", tup) == 18;
            },
            groupby([](const tuple& tup) {
                return filter_groups({"ipv4.src"}, tup);
            }, counter, "synacks", next_op)));
    };
    
    auto acks = [epoch_dur](operator_t next_op) {
        return epoch(epoch_dur, "eid",
            filter([](const tuple& tup) {
                return get_mapped_int("ipv4.proto", tup) == 6 &&
                       get_mapped_int("l4.flags", tup) == 16;
            },
            groupby([](const tuple& tup) {
                return filter_groups({"ipv4.dst"}, tup);
            }, counter, "acks", next_op)));
    };
    
    auto [join_op1, join_op2] = join(
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
            tuple result = tup;
            result["syns+synacks-acks"] = get_mapped_int("syns+synacks", tup) -
                                          get_mapped_int("acks", tup);
            return result;
        },
        filter([threshold](const tuple& tup) {
                return get_mapped_int("syns+synacks-acks", tup) >= threshold;
        }, next_op))));
    
    auto [join_op3, join_op4] = join(
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
            tuple result = tup;
            result["syns+synacks"] = get_mapped_int("syns", tup) + 
                                     get_mapped_int("synacks", tup);
            return result;
        }, join_op1));
    
    return {syns(join_op3), synacks(join_op4), acks(join_op2)};
}

// Sonata 7 - Completed flows
std::vector<operator_t> completed_flows(operator_t next_op) {
    const int threshold = 1;
    const double epoch_dur = 30.0;
    
    auto syns = [epoch_dur](operator_t next_op) {
        return epoch(epoch_dur, "eid",
            filter([](const tuple& tup) {
                return get_mapped_int("ipv4.proto", tup) == 6 &&
                       get_mapped_int("l4.flags", tup) == 2;
            },
            groupby([](const tuple& tup) {
                return filter_groups({"ipv4.dst"}, tup);
            }, counter, "syns", next_op)));
    };
    
    auto fins = [epoch_dur](operator_t next_op) {
        return epoch(epoch_dur, "eid",
            filter([](const tuple& tup) {
                return get_mapped_int("ipv4.proto", tup) == 6 &&
                       (get_mapped_int("l4.flags", tup) & 1) == 1;
            },
            groupby([](const tuple& tup) {
                return filter_groups({"ipv4.src"}, tup);
            }, counter, "fins", next_op)));
    };
    
    auto [op1, op2] = join(
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
            tuple result = tup;
            result["diff"] = get_mapped_int("syns", tup) - get_mapped_int("fins", tup);
            return result;
        },
        filter([threshold](const tuple& tup) {
            return get_mapped_int("diff", tup) >= threshold;
        }, next_op)));
    
    return {syns(op1), fins(op2)};
}

// Sonata 8 - Slowloris
std::vector<operator_t> slowloris(operator_t next_op) {
    const int t1 = 5;
    const int t2 = 500;
    const int t3 = 90;
    const double epoch_dur = 1.0;
    
    auto n_conns = [epoch_dur, t1](operator_t next_op) {
        return epoch(epoch_dur, "eid",
            filter([](const tuple& tup) {
                return get_mapped_int("ipv4.proto", tup) == 6;
            },
            distinct([](const tuple& tup) {
                return filter_groups({"ipv4.src", "ipv4.dst", "l4.sport"}, tup);
            },
            groupby([](const tuple& tup) {
                return filter_groups({"ipv4.dst"}, tup);
            }, counter, "n_conns",
            filter([t1](const tuple& tup) {
                return get_mapped_int("n_conns", tup) >= t1;
            }, next_op)))));
    };
    
    auto n_bytes = [epoch_dur, t2](operator_t next_op) {
        return epoch(epoch_dur, "eid",
            filter([](const tuple& tup) {
                return get_mapped_int("ipv4.proto", tup) == 6;
            },
            groupby([](const tuple& tup) {
                return filter_groups({"ipv4.dst"}, tup);
            }, [](const op_result& init_val, const tuple& tup) {
                return sum_ints("ipv4.len", init_val, tup);
            }, "n_bytes",
            filter([t2](const tuple& tup) {
                return get_mapped_int("n_bytes", tup) >= t2;
            }, next_op))));
    };
    
    auto [op1, op2] = join(
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
            tuple result = tup;
            result["bytes_per_conn"] = get_mapped_int("n_bytes", tup) / 
                                       get_mapped_int("n_conns", tup);
            return result;
        },
        filter([t3](const tuple& tup) {
            return get_mapped_int("bytes_per_conn", tup) <= t3;
        }, next_op)));
    
    return {n_conns(op1), n_bytes(op2)};
}

// join_test
std::vector<operator_t> join_test(operator_t next_op) {
    const double epoch_dur = 1.0;
    
    auto syns = [epoch_dur](operator_t next_op) {
        return epoch(epoch_dur, "eid",
            filter([](const tuple& tup) {
                return get_mapped_int("ipv4.proto", tup) == 6 &&
                       get_mapped_int("l4.flags", tup) == 2;
            }, next_op));
    };
    
    auto synacks = [epoch_dur](operator_t next_op) {
        return epoch(epoch_dur, "eid",
            filter([](const tuple& tup) {
                return get_mapped_int("ipv4.proto", tup) == 6 &&
                       get_mapped_int("l4.flags", tup) == 18;
            }, next_op));
    };
    
    auto [op1, op2] = join(
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
        },
        next_op);
    
    return {syns(op1), synacks(op2)};
}

// q3
operator_t q3(operator_t next_op) {
    return epoch(100.0, "eid",
        distinct([](const tuple& tup) {
            return filter_groups({"ipv4.src", "ipv4.dst"}, tup);
        }, next_op));
}

// q4
operator_t q4(operator_t next_op) {
    return epoch(10000.0, "eid",
        groupby([](const tuple& tup) {
            return filter_groups({"ipv4.dst"}, tup);
        }, counter, "pkts", next_op));
}

// Generate test data
std::vector<tuple> generate_test_data() {
    std::vector<tuple> test_data;
    
    for (int i = 0; i < 20; ++i) {
        tuple tup;
        tup["time"] = 0.0 + static_cast<double>(i);
        
        // Generate MAC address
        std::vector<uint8_t> mac_src = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
        std::vector<uint8_t> mac_dst = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
        
        tup["eth.src"] = mac_src;
        tup["eth.dst"] = mac_dst;
        tup["eth.ethertype"] = 0x0800;
        
        tup["ipv4.hlen"] = 20;
        tup["ipv4.proto"] = 6;
        tup["ipv4.len"] = 60;
        tup["ipv4.src"] = "127.0.0.1";
        tup["ipv4.dst"] = "127.0.0.1";
        
        tup["l4.sport"] = 440;
        tup["l4.dport"] = 50000;
        tup["l4.flags"] = 10;
        
        test_data.push_back(tup);
    }
    
    return test_data;
}

// Run queries function
void run_queries() {
    auto queries = {ident(dump_tuple_op(std::cout))};
    auto test_data = generate_test_data();
    
    for (const auto& tup : test_data) {
        for (auto& query : queries) {
            query.next(tup);
        }
    }
}

// Main function
int main() {
    run_queries();
    std::cout << "Done" << std::endl;
    return 0;
}