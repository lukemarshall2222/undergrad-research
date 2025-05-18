#include <iostream>
#include <map>
#include <vector>
#include <string>
#include <sstream>
#include <fstream>
#include <cstdint>
#include <functional>
#include <unordered_map>

// Type definitions
enum class OpResultType {
    Float,
    Int,
    IPv4,
    MAC,
    Empty
};

struct OpResult {
    OpResultType type;
    float float_val;
    int int_val;
    uint32_t ipv4_val;
    std::string mac_val;

    OpResult(float val) : type(OpResultType::Float), float_val(val) {}
    OpResult(int val) : type(OpResultType::Int), int_val(val) {}
    OpResult(uint32_t val) : type(OpResultType::IPv4), ipv4_val(val) {}
    OpResult(const std::string& val) : type(OpResultType::MAC), mac_val(val) {}
    OpResult() : type(OpResultType::Empty) {}
};

using Tuple = std::map<std::string, OpResult>;

struct Operator {
    std::function<void(const Tuple&)> next;
    std::function<void(const Tuple&)> reset;
};

// Conversion utilities
std::string string_of_mac(const std::string& mac) {
    std::stringstream ss;
    for (size_t i = 0; i < mac.size(); ++i) {
        if (i > 0) ss << ":";
        ss << std::hex << (int)((unsigned char)mac[i]);
    }
    return ss.str();
}

std::string tcp_flags_to_strings(int flags) {
    std::vector<std::string> flag_names = {"FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"};
    std::vector<int> flag_values = {1 << 0, 1 << 1, 1 << 2, 1 << 3, 1 << 4, 1 << 5, 1 << 6, 1 << 7};
    std::string result;
    for (size_t i = 0; i < flag_names.size(); ++i) {
        if (flags & flag_values[i]) {
            if (!result.empty()) result += "|";
            result += flag_names[i];
        }
    }
    return result;
}

std::string string_of_op_result(const OpResult& result) {
    switch (result.type) {
        case OpResultType::Float:
            return std::to_string(result.float_val);
        case OpResultType::Int:
            return std::to_string(result.int_val);
        case OpResultType::IPv4:
            // Assuming IPv4 address is stored as uint32_t in network byte order
            return std::to_string((result.ipv4_val >> 24) & 0xFF) + "." +
                   std::to_string((result.ipv4_val >> 16) & 0xFF) + "." +
                   std::to_string((result.ipv4_val >> 8) & 0xFF) + "." +
                   std::to_string(result.ipv4_val & 0xFF);
        case OpResultType::MAC:
            return string_of_mac(result.mac_val);
        case OpResultType::Empty:
            return "Empty";
    }
}

std::string string_of_tuple(const Tuple& tuple) {
    std::string result;
    for (const auto& pair : tuple) {
        result += "\"" + pair.first + "\" => " + string_of_op_result(pair.second) + ", ";
    }
    return result;
}

// Built-in operator definitions
Operator dump_tuple(std::ostream& out) {
    return {
        [&out](const Tuple& tuple) { out << string_of_tuple(tuple) << std::endl; },
        [](const Tuple&) {}
    };
}

Operator dump_as_csv(std::ostream& out) {
    bool first = true;
    return {
        [&out, &first](const Tuple& tuple) {
            if (first) {
                for (const auto& pair : tuple) {
                    out << pair.first << ",";
                }
                out << std::endl;
                first = false;
            }
            for (const auto& pair : tuple) {
                out << string_of_op_result(pair.second) << ",";
            }
            out << std::endl;
        },
        [](const Tuple&) {}
    };
}

Operator meta_meter(const std::string& name, std::ostream& out, Operator next_op) {
    int epoch_count = 0;
    int tups_count = 0;
    return {
        [next_op, &tups_count](const Tuple& tuple) { ++tups_count; next_op.next(tuple); },
        [name, &out, next_op, &epoch_count, &tups_count](const Tuple& tuple) {
            out << epoch_count << "," << name << "," << tups_count << std::endl;
            tups_count = 0;
            ++epoch_count;
            next_op.reset(tuple);
        }
    };
}

Operator epoch(float epoch_width, const std::string& key_out, Operator next_op) {
    float epoch_boundary = 0.0f;
    int eid = 0;
    return {
        [next_op, &epoch_boundary, &eid, epoch_width, key_out](const Tuple& tuple) {
            auto it = tuple.find("time");
            if (it != tuple.end() && it->second.type == OpResultType::Float) {
                float time = it->second.float_val;
                if (epoch_boundary == 0.0f) {
                    epoch_boundary = time + epoch_width;
                } else if (time >= epoch_boundary) {
                    while (time >= epoch_boundary) {
                        Tuple reset_tuple;
                        reset_tuple[key_out] = OpResult(eid);
                        next_op.reset(reset_tuple);
                        epoch_boundary += epoch_width;
                        ++eid;
                    }
                }
                Tuple new_tuple = tuple;
                new_tuple[key_out] = OpResult(eid);
                next_op.next(new_tuple);
            }
        },
        [next_op, &epoch_boundary, &eid, key_out](const Tuple& tuple) {
            Tuple reset_tuple;
            reset_tuple[key_out] = OpResult(eid);
            next_op.reset(reset_tuple);
            epoch_boundary = 0.0f;
            eid = 0;
        }
    };
}

Operator filter(std::function<bool(const Tuple&)> f, Operator next_op) {
    return {
        [f, next_op](const Tuple& tuple) { if (f(tuple)) next_op.next(tuple); },
        [next_op](const Tuple& tuple) { next_op.reset(tuple); }
    };
}

Operator map(std::function<Tuple(const Tuple&)> f, Operator next_op) {
    return {
        [f, next_op](const Tuple& tuple) { next_op.next(f(tuple)); },
        [next_op](const Tuple& tuple) { next_op.reset(tuple); }
    };
}

Operator groupby(std::function<Tuple(const Tuple&)> groupby_func, std::function<OpResult(OpResult, const Tuple&)> reduce_func, const std::string& out_key, Operator next_op) {
    std::unordered_map<std::string, OpResult> h_tbl;
    return {
        [groupby_func, reduce_func, &h_tbl, out_key](const Tuple& tuple) {
            Tuple grouping_key = groupby_func(tuple);
            std::string key_str;
            for (const auto& pair : grouping_key) {
                key_str += pair.first + ":" + string_of_op_result(pair.second) + ",";
            }
            auto it = h_tbl.find(key_str);
            if (it != h_tbl.end()) {
                it->second = reduce_func(it->second, tuple);
            } else {
                h_tbl[key_str] = reduce_func(OpResult(), tuple);
            }
        },
        [next_op, &h_tbl, out_key](const Tuple& tuple) {
            for (const auto& pair : h_tbl) {
                Tuple new_tuple = tuple;
                new_tuple[out_key] = pair.second;
                next_op.next(new_tuple);
            }
            next_op.reset(tuple);
            h_tbl.clear();
        }
    };
}

// Join operator
using KeyExtractor = std::function<std::pair<Tuple, Tuple>(const Tuple&)>;

std::pair<Operator, Operator> join(const std::string& eid_key, KeyExtractor left_extractor, KeyExtractor right_extractor, Operator next_op) {
    std::unordered_map<std::string, Tuple> h_tbl1;
    std::unordered_map<std::string, Tuple> h_tbl2;
    int left_curr_epoch = 0;
    int right_curr_epoch = 0;

    auto handle_join_side = [&](std::unordered_map<std::string, Tuple>& curr_h_tbl, std::unordered_map<std::string, Tuple>& other_h_tbl, int& curr_epoch_ref, int& other_epoch_ref, KeyExtractor f) {
        return Operator{
            [f, &curr_h_tbl, &other_h_tbl, &curr_epoch_ref, &other_epoch_ref, eid_key, next_op](const Tuple& tuple) {
                auto [key, vals] = f(tuple);
                int curr_epoch = std::stoi(string_of_op_result(tuple.at(eid_key)));
                while (curr_epoch > curr_epoch_ref) {
                    if (other_epoch_ref > curr_epoch_ref) {
                        Tuple reset_tuple;
                        reset_tuple[eid_key] = OpResult(curr_epoch_ref);
                        next_op.reset(reset_tuple);
                    }
                    ++curr_epoch_ref;
                }
                std::string key_str;
                for (const auto& pair : key) {
                    key_str += pair.first + ":" + string_of_op_result(pair.second) + ",";
                }
                auto it = other_h_tbl.find(key_str);
                if (it != other_h_tbl.end()) {
                    Tuple new_tuple;
                    for (const auto& pair : key) {
                        new_tuple[pair.first] = pair.second;
                    }
                    for (const auto& pair : vals) {
                        new_tuple[pair.first] = pair.second;
                    }
                    for (const auto& pair : it->second) {
                        new_tuple[pair.first] = pair.second;
                    }
                    other_h_tbl.erase(key_str);
                    next_op.next(new_tuple);
                } else {
                    curr_h_tbl[key_str] = vals;
                }
            },
            [eid_key, &curr_epoch_ref, &other_epoch_ref, next_op](const Tuple& tuple) {
                int curr_epoch = std::stoi(string_of_op_result(tuple.at(eid_key)));
                while (curr_epoch > curr_epoch_ref) {
                    if (other_epoch_ref > curr_epoch_ref) {
                        Tuple reset_tuple;
                        reset_tuple[eid_key] = OpResult(curr_epoch_ref);
                        next_op.reset(reset_tuple);
                    }
                    ++curr_epoch_ref;
                }
            }
        };
    };

    return std::make_pair(handle_join_side(h_tbl1, h_tbl2, left_curr_epoch, right_curr_epoch, left_extractor),
                           handle_join_side(h_tbl2, h_tbl1, right_curr_epoch, left_curr_epoch, right_extractor));
}

// Distinct operator
Operator distinct(std::function<Tuple(const Tuple&)> groupby_func, Operator next_op) {
    std::unordered_map<std::string, bool> h_tbl;
    return Operator{
        [groupby_func, &h_tbl](const Tuple& tuple) {
            Tuple grouping_key = groupby_func(tuple);
            std::string key_str;
            for (const auto& pair : grouping_key) {
                key_str += pair.first + ":" + string_of_op_result(pair.second) + ",";
            }
            h_tbl[key_str] = true;
        },
        [next_op, &h_tbl](const Tuple& tuple) {
            for (const auto& pair : h_tbl) {
                Tuple new_tuple;
                // Assuming the key_str is in the format "key1:value1,key2:value2,..."
                size_t start = 0;
                while (start < pair.first.size()) {
                    size_t end = pair.first.find(',', start);
                    if (end == std::string::npos) {
                        end = pair.first.size();
                    }
                    size_t colon_pos = pair.first.find(':', start);
                    std::string key = pair.first.substr(start, colon_pos - start);
                    std::string value = pair.first.substr(colon_pos + 1, end - colon_pos - 1);
                    new_tuple[key] = OpResult(std::stoi(value));
                    start = end + 1;
                }
                next_op.next(new_tuple);
            }
            next_op.reset(tuple);
            h_tbl.clear();
        }
    };
}

// Split operator
Operator split(Operator l, Operator r) {
    return Operator{
        [l, r](const Tuple& tuple) {
            l.next(tuple);
            r.next(tuple);
        },
        [l, r](const Tuple& tuple) {
            l.reset(tuple);
            r.reset(tuple);
        }
    };
}

// Counter reduction function
OpResult counter(OpResult val, const Tuple&) {
    if (val.type == OpResultType::Empty) {
        return OpResult(1);
    } else if (val.type == OpResultType::Int) {
        return OpResult(val.int_val + 1);
    } else {
        // Handle error
        return OpResult();
    }
}

// Sum reduction function
OpResult sum_ints(const std::string& search_key, OpResult init_val, const Tuple& tuple) {
    if (init_val.type == OpResultType::Empty) {
        return OpResult(0);
    } else if (init_val.type == OpResultType::Int) {
        auto it = tuple.find(search_key);
        if (it != tuple.end() && it->second.type == OpResultType::Int) {
            return OpResult(init_val.int_val + it->second.int_val);
        } else {
            // Handle error
            return OpResult();
        }
    } else {
        // Handle error
        return OpResult();
    }
}

// TCP new connections operator
Operator tcp_new_cons(Operator next_op) {
    int threshold = 40;
    return epoch(1.0f, "eid",
                 filter([&](const Tuple& tuple) {
                     auto proto_it = tuple.find("ipv4.proto");
                     auto flags_it = tuple.find("l4.flags");
                     return proto_it != tuple.end() && flags_it != tuple.end() &&
                            proto_it->second.type == OpResultType::Int && flags_it->second.type == OpResultType::Int &&
                            proto_it->second.int_val == 6 && flags_it->second.int_val == 2;
                 },
                         groupby([](const Tuple& tuple) {
                                     Tuple key;
                                     auto dst_it = tuple.find("ipv4.dst");
                                     if (dst_it != tuple.end()) {
                                         key["ipv4.dst"] = dst_it->second;
                                     }
                                     return key;
                                 },
                                 counter,
                                 "cons",
                                 filter([&](const Tuple& tuple) {
                                             auto cons_it = tuple.find("cons");
                                             return cons_it != tuple.end() &&
                                                    cons_it->second.type == OpResultType::Int &&
                                                    cons_it->second.int_val >= threshold;
                                         },
                                         next_op))));
}

// SSH brute force operator
Operator ssh_brute_force(Operator next_op) {
    int threshold = 40;
    return epoch(1.0f, "eid",
                 filter([&](const Tuple& tuple) {
                     auto proto_it = tuple.find("ipv4.proto");
                     auto dport_it = tuple.find("l4.dport");
                     return proto_it != tuple.end() && dport_it != tuple.end() &&
                            proto_it->second.type == OpResultType::Int && dport_it->second.type == OpResultType::Int &&
                            proto_it->second.int_val == 6 && dport_it->second.int_val == 22;
                 },
                         distinct([](const Tuple& tuple) {
                                      Tuple key;
                                      auto src_it = tuple.find("ipv4.src");
                                      auto dst_it = tuple.find("ipv4.dst");
                                      auto len_it = tuple.find("ipv4.len");
                                      if (src_it != tuple.end()) {
                                          key["ipv4.src"] = src_it->second;
                                      }
                                      if (dst_it != tuple.end()) {
                                          key["ipv4.dst"] = dst_it->second;
                                      }
                                      if (len_it != tuple.end()) {
                                          key["ipv4.len"] = len_it->second;
                                      }
                                      return key;
                                  },
                                  groupby([](const Tuple& tuple) {
                                              Tuple key;
                                              auto dst_it = tuple.find("ipv4.dst");
                                              auto len_it = tuple.find("ipv4.len");
                                              if (dst_it != tuple.end()) {
                                                  key["ipv4.dst"] = dst_it->second;
                                              }
                                              if (len_it != tuple.end()) {
                                                  key["ipv4.len"] = len_it->second;
                                              }
                                              return key;
                                          },
                                          counter,
                                          "srcs",
                                          filter([&](const Tuple& tuple) {
                                                      auto srcs_it = tuple.find("srcs");
                                                      return srcs_it != tuple.end() &&
                                                             srcs_it->second.type == OpResultType::Int &&
                                                             srcs_it->second.int_val >= threshold;
                                                  },
                                                  next_op)))));
}

// Super spreader operator
Operator super_spreader(Operator next_op) {
    int threshold = 40;
    return epoch(1.0f, "eid",
                 distinct([](const Tuple& tuple) {
                              Tuple key;
                              auto src_it = tuple.find("ipv4.src");
                              auto dst_it = tuple.find("ipv4.dst");
                              if (src_it != tuple.end()) {
                                  key["ipv4.src"] = src_it->second;
                              }
                              if (dst_it != tuple.end()) {
                                  key["ipv4.dst"] = dst_it->second;
                              }
                              return key;
                          },
                          groupby([](const Tuple& tuple) {
                                      Tuple key;
                                      auto src_it = tuple.find("ipv4.src");
                                      if (src_it != tuple.end()) {
                                          key["ipv4.src"] = src_it->second;
                                      }
                                      return key;
                                  },
                                  counter,
                                  "dsts",
                                  filter([&](const Tuple& tuple) {
                                              auto dsts_it = tuple.find("dsts");
                                              return dsts_it != tuple.end() &&
                                                     dsts_it->second.type == OpResultType::Int &&
                                                     dsts_it->second.int_val >= threshold;
                                          },
                                          next_op))));
}

// Port scan operator
Operator port_scan(Operator next_op) {
    int threshold = 40;
    return epoch(1.0f, "eid",
                 distinct([](const Tuple& tuple) {
                             Tuple key;
                             auto src_it = tuple.find("ipv4.src");
                             auto dport_it = tuple.find("l4.dport");
                             if (src_it != tuple.end()) {
                                 key["ipv4.src"] = src_it->second;
                             }
                             if (dport_it != tuple.end()) {
                                 key["l4.dport"] = dport_it->second;
                             }
                             return key;
                         },
                         groupby([](const Tuple& tuple) {
                                     Tuple key;
                                     auto src_it = tuple.find("ipv4.src");
                                     if (src_it != tuple.end()) {
                                         key["ipv4.src"] = src_it->second;
                                     }
                                     return key;
                                 },
                                 counter,
                                 "ports",
                                 filter([&](const Tuple& tuple) {
                                             auto ports_it = tuple.find("ports");
                                             return ports_it != tuple.end() &&
                                                    ports_it->second.type == OpResultType::Int &&
                                                    ports_it->second.int_val >= threshold;
                                         },
                                         next_op))));
}

// DDoS operator
Operator ddos(Operator next_op) {
    int threshold = 45;
    return epoch(1.0f, "eid",
                 distinct([](const Tuple& tuple) {
                             Tuple key;
                             auto src_it = tuple.find("ipv4.src");
                             auto dst_it = tuple.find("ipv4.dst");
                             if (src_it != tuple.end()) {
                                 key["ipv4.src"] = src_it->second;
                             }
                             if (dst_it != tuple.end()) {
                                 key["ipv4.dst"] = dst_it->second;
                             }
                             return key;
                         },
                         groupby([](const Tuple& tuple) {
                                     Tuple key;
                                     auto dst_it = tuple.find("ipv4.dst");
                                     if (dst_it != tuple.end()) {
                                         key["ipv4.dst"] = dst_it->second;
                                     }
                                     return key;
                                 },
                                 counter,
                                 "srcs",
                                 filter([&](const Tuple& tuple) {
                                             auto srcs_it = tuple.find("srcs");
                                             return srcs_it != tuple.end() &&
                                                    srcs_it->second.type == OpResultType::Int &&
                                                    srcs_it->second.int_val >= threshold;
                                         },
                                         next_op))));
}

// Syn flood operator
std::tuple<Operator, Operator, Operator> syn_flood(Operator next_op) {
    int threshold = 3;
    float epoch_dur = 1.0f;

    auto syns = epoch(epoch_dur, "eid",
                      filter([&](const Tuple& tuple) {
                                 auto proto_it = tuple.find("ipv4.proto");
                                 auto flags_it = tuple.find("l4.flags");
                                 return proto_it != tuple.end() && flags_it != tuple.end() &&
                                        proto_it->second.type == OpResultType::Int && flags_it->second.type == OpResultType::Int &&
                                        proto_it->second.int_val == 6 && flags_it->second.int_val == 2;
                             },
                             groupby([](const Tuple& tuple) {
                                         Tuple key;
                                         auto dst_it = tuple.find("ipv4.dst");
                                         if (dst_it != tuple.end()) {
                                             key["ipv4.dst"] = dst_it->second;
                                         }
                                         return key;
                                     },
                                     counter,
                                     "syns",
                                     next_op)));

    auto synacks = epoch(epoch_dur, "eid",
                         filter([&](const Tuple& tuple) {
                                    auto proto_it = tuple.find("ipv4.proto");
                                    auto flags_it = tuple.find("l4.flags");
                                    return proto_it != tuple.end() && flags_it != tuple.end() &&
                                           proto_it->second.type == OpResultType::Int && flags_it->second.type == OpResultType::Int &&
                                           proto_it->second.int_val == 6 && flags_it->second.int_val == 18;
                                },
                                groupby([](const Tuple& tuple) {
                                            Tuple key;
                                            auto src_it = tuple.find("ipv4.src");
                                            if (src_it != tuple.end()) {
                                                key["ipv4.src"] = src_it->second;
                                            }
                                            return key;
                                        },
                                        counter,
                                        "synacks",
                                        next_op)));

    auto acks = epoch(epoch_dur, "eid",
                      filter([&](const Tuple& tuple) {
                                 auto proto_it = tuple.find("ipv4.proto");
                                 auto flags_it = tuple.find("l4.flags");
                                 return proto_it != tuple.end() && flags_it != tuple.end() &&
                                        proto_it->second.type == OpResultType::Int && flags_it->second.type == OpResultType::Int &&
                                        proto_it->second.int_val == 6 && flags_it->second.int_val == 16;
                             },
                             groupby([](const Tuple& tuple) {
                                         Tuple key;
                                         auto dst_it = tuple.find("ipv4.dst");
                                         if (dst_it != tuple.end()) {
                                             key["ipv4.dst"] = dst_it->second;
                                         }
                                         return key;
                                     },
                                     counter,
                                     "acks",
                                     next_op)));

    // Join syns and acks
    auto [join_op1, join_op2] = join("eid",
                                     [](const Tuple& tuple) {
                                         Tuple key;
                                         auto dst_it = tuple.find("ipv4.dst");
                                         if (dst_it != tuple.end()) {
                                             key["host"] = dst_it->second;
                                         }
                                         Tuple vals;
                                         auto syns_it = tuple.find("syns");
                                         if (syns_it != tuple.end()) {
                                             vals["syns"] = syns_it->second;
                                         }
                                         auto synacks_it = tuple.find("synacks");
                                         if (synacks_it != tuple.end()) {
                                             vals["synacks"] = synacks_it->second;
                                         }
                                         return std::make_pair(key, vals);
                                     },
                                     [](const Tuple& tuple) {
                                         Tuple key;
                                         auto dst_it = tuple.find("ipv4.dst");
                                         if (dst_it != tuple.end()) {
                                             key["host"] = dst_it->second;
                                         }
                                         Tuple vals;
                                         auto acks_it = tuple.find("acks");
                                         if (acks_it != tuple.end()) {
                                             vals["acks"] = acks_it->second;
                                         }
                                         return std::make_pair(key, vals);
                                     },
                                     map([&](const Tuple& tuple) {
                                             auto syns_it = tuple.find("syns");
                                             auto synacks_it = tuple.find("synacks");
                                             auto acks_it = tuple.find("acks");
                                             if (syns_it != tuple.end() && synacks_it != tuple.end() && acks_it != tuple.end()) {
                                                 Tuple new_tuple;
                                                 new_tuple["syns+synacks-acks"] = OpResult(syns_it->second.int_val + synacks_it->second.int_val - acks_it->second.int_val);
                                                 return new_tuple;
                                             } else {
                                                 return Tuple();
                                             }
                                         },
                                         filter([&](const Tuple& tuple) {
                                                     auto diff_it = tuple.find("syns+synacks-acks");
                                                     return diff_it != tuple.end() &&
                                                            diff_it->second.type == OpResultType::Int &&
                                                            diff_it->second.int_val >= threshold;
                                                 },
                                                 next_op))));

    // Join syns and synacks
    auto [join_op3, join_op4] = join("eid",
                                     [](const Tuple& tuple) {
                                         Tuple key;
                                         auto dst_it = tuple.find("ipv4.dst");
                                         if (dst_it != tuple.end()) {
                                             key["host"] = dst_it->second;
                                         }
                                         Tuple vals;
                                         auto syns_it = tuple.find("syns");
                                         if (syns_it != tuple.end()) {
                                             vals["syns"] = syns_it->second;
                                         }
                                         return std::make_pair(key, vals);
                                     },
                                     [](const Tuple& tuple) {
                                         Tuple key;
                                         auto src_it = tuple.find("ipv4.src");
                                         if (src_it != tuple.end()) {
                                             key["host"] = src_it->second;
                                         }
                                         Tuple vals;
                                         auto synacks_it = tuple.find("synacks");
                                         if (synacks_it != tuple.end()) {
                                             vals["synacks"] = synacks_it->second;
                                         }
                                         return std::make_pair(key, vals);
                                     },
                                     map([&](const Tuple& tuple) {
                                             auto syns_it = tuple.find("syns");
                                             auto synacks_it = tuple.find("synacks");
                                             if (syns_it != tuple.end() && synacks_it != tuple.end()) {
                                                 Tuple new_tuple;
                                                 new_tuple["syns+synacks"] = OpResult(syns_it->second.int_val + synacks_it->second.int_val);
                                                 return new_tuple;
                                             } else {
                                                 return Tuple();
                                             }
                                         },
                                         join_op1)));

    return std::make_tuple(syns, synacks, acks);
}

// Completed flows operator
std::tuple<Operator, Operator> completed_flows(Operator next_op) {
    int threshold = 1;
    float epoch_dur = 30.0f;

    auto syns = epoch(epoch_dur, "eid",
                      filter([&](const Tuple& tuple) {
                                 auto proto_it = tuple.find("ipv4.proto");
                                 auto flags_it = tuple.find("l4.flags");
                                 return proto_it != tuple.end() && flags_it != tuple.end() &&
                                        proto_it->second.type == OpResultType::Int && flags_it->second.type == OpResultType::Int &&
                                        proto_it->second.int_val == 6 && flags_it->second.int_val == 2;
                             },
                             groupby([](const Tuple& tuple) {
                                         Tuple key;
                                         auto dst_it = tuple.find("ipv4.dst");
                                         if (dst_it != tuple.end()) {
                                             key["ipv4.dst"] = dst_it->second;
                                         }
                                         return key;
                                     },
                                     counter,
                                     "syns",
                                     next_op)));

    auto fins = epoch(epoch_dur, "eid",
                      filter([&](const Tuple& tuple) {
                                 auto proto_it = tuple.find("ipv4.proto");
                                 auto flags_it = tuple.find("l4.flags");
                                 return proto_it != tuple.end() && flags_it != tuple.end() &&
                                        proto_it->second.type == OpResultType::Int && flags_it->second.type == OpResultType::Int &&
                                        proto_it->second.int_val == 6 && (flags_it->second.int_val & 1) == 1;
                             },
                             groupby([](const Tuple& tuple) {
                                         Tuple key;
                                         auto src_it = tuple.find("ipv4.src");
                                         if (src_it != tuple.end()) {
                                             key["ipv4.src"] = src_it->second;
                                         }
                                         return key;
                                     },
                                     counter,
                                     "fins",
                                     next_op)));

    // Join syns and fins
    auto [join_op1, join_op2] = join("eid",
                                     [](const Tuple& tuple) {
                                         Tuple key;
                                         auto dst_it = tuple.find("ipv4.dst");
                                         if (dst_it != tuple.end()) {
                                             key["host"] = dst_it->second;
                                         }
                                         Tuple vals;
                                         auto syns_it = tuple.find("syns");
                                         if (syns_it != tuple.end()) {
                                             vals["syns"] = syns_it->second;
                                         }
                                         return std::make_pair(key, vals);
                                     },
                                     [](const Tuple& tuple) {
                                         Tuple key;
                                         auto src_it = tuple.find("ipv4.src");
                                         if (src_it != tuple.end()) {
                                             key["host"] = src_it->second;
                                         }
                                         Tuple vals;
                                         auto fins_it = tuple.find("fins");
                                         if (fins_it != tuple.end()) {
                                             vals["fins"] = fins_it->second;
                                         }
                                         return std::make_pair(key, vals);
                                     },
                                     map([&](const Tuple& tuple) {
                                             auto syns_it = tuple.find("syns");
                                             auto fins_it = tuple.find("fins");
                                             if (syns_it != tuple.end() && fins_it != tuple.end()) {
                                                 Tuple new_tuple;
                                                 new_tuple["diff"] = OpResult(syns_it->second.int_val - fins_it->second.int_val);
                                                 return new_tuple;
                                             } else {
                                                 return Tuple();
                                             }
                                         },
                                         filter([&](const Tuple& tuple) {
                                                     auto diff_it = tuple.find("diff");
                                                     return diff_it != tuple.end() &&
                                                            diff_it->second.type == OpResultType::Int &&
                                                            diff_it->second.int_val >= threshold;
                                                 },
                                                 next_op)));

    return std::make_tuple(syns, fins);
}

// Example usage
int main() {
    // Create operators
    Operator dump_op = dump_tuple(std::cout);
    Operator tcp_new_cons_op = tcp_new_cons(dump_op);
    Operator ssh_brute_force_op = ssh_brute_force(dump_op);
    Operator super_spreader_op = super_spreader(dump_op);

    // Create tuple
    Tuple tuple = {
        {"ipv4.proto", OpResult(6)},
        {"l4.flags", OpResult(2)},
        {"ipv4.dst", OpResult(uint32_t(0x01020304))}
    };

    // Run operators
    tcp_new_cons_op.next(tuple);
    tcp_new_cons_op.reset(tuple);

    ssh_brute_force_op.next(tuple);
    ssh_brute_force_op.reset(tuple);

    super_spreader_op.next(tuple);
    super_spreader_op.reset(tuple);

    return 0;
}

