#include <variant>
#include <map>
#include <string>
#include <array>
#include <stdexcept>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <functional>
#include <vector>
#include <memory>
#include <algorithm>
#include <unordered_map>

// ### Type Definitions
using IPv4 = std::string; // Simplified representation of Ipaddr.V4.t
using MAC = std::array<char, 6>;

using op_result = std::variant<float, int, IPv4, MAC, std::monostate>;
using Tuple = std::map<std::string, op_result>;

// ### Operator Abstract Base Class
class Operator {
public:
    virtual ~Operator() = default;
    virtual void next(const Tuple& tup) = 0;
    virtual void reset(const Tuple& tup) = 0;
};

// ### Utility Functions
std::string string_of_mac(const MAC& mac) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < mac.size(); ++i) {
        if (i > 0) ss << ":";
        ss << std::setw(2) << static_cast<int>(static_cast<unsigned char>(mac[i]));
    }
    return ss.str();
}

std::string tcp_flags_to_strings(int flags) {
    std::vector<std::pair<std::string, int>> flag_map = {
        {"FIN", 1 << 0}, {"SYN", 1 << 1}, {"RST", 1 << 2}, {"PSH", 1 << 3},
        {"ACK", 1 << 4}, {"URG", 1 << 5}, {"ECE", 1 << 6}, {"CWR", 1 << 7}
    };
    std::string result;
    for (const auto& [name, value] : flag_map) {
        if (flags & value) {
            if (!result.empty()) result += "|";
            result += name;
        }
    }
    return result.empty() ? "" : result;
}

int int_of_op_result(const op_result& res) {
    if (auto* i = std::get_if<int>(&res)) return *i;
    throw std::runtime_error("Trying to extract int from non-int result");
}

float float_of_op_result(const op_result& res) {
    if (auto* f = std::get_if<float>(&res)) return *f;
    throw std::runtime_error("Trying to extract float from non-float result");
}

std::string string_of_op_result(const op_result& res) {
    struct Visitor {
        std::string operator()(float f) { return std::to_string(f); }
        std::string operator()(int i) { return std::to_string(i); }
        std::string operator()(const IPv4& ip) { return ip; }
        std::string operator()(const MAC& mac) { return string_of_mac(mac); }
        std::string operator()(std::monostate) { return "Empty"; }
    };
    return std::visit(Visitor{}, res);
}

std::string string_of_tuple(const Tuple& tup) {
    std::stringstream ss;
    for (const auto& [key, val] : tup) {
        ss << "\"" << key << "\" => " << string_of_op_result(val) << ", ";
    }
    std::string result = ss.str();
    if (!result.empty()) result = result.substr(0, result.size() - 2); // Remove trailing ", "
    return result;
}

void dump_tuple(std::ostream& out, const Tuple& tup) {
    out << string_of_tuple(tup) << std::endl;
}

int lookup_int(const std::string& key, const Tuple& tup) {
    auto it = tup.find(key);
    if (it == tup.end()) throw std::runtime_error("Key not found: " + key);
    return int_of_op_result(it->second);
}

float lookup_float(const std::string& key, const Tuple& tup) {
    auto it = tup.find(key);
    if (it == tup.end()) throw std::runtime_error("Key not found: " + key);
    return float_of_op_result(it->second);
}

std::string lookup_string(const std::string& key, const Tuple& tup) {
    auto it = tup.find(key);
    if (it == tup.end()) throw std::runtime_error("Key not found: " + key);
    return string_of_op_result(it->second);
}

// ### Operator Implementations
class DumpTupleOperator : public Operator {
    std::ostream& out;
    bool show_reset;
public:
    DumpTupleOperator(std::ostream& out, bool show_reset = false)
        : out(out), show_reset(show_reset) {}

    void next(const Tuple& tup) override {
        dump_tuple(out, tup);
    }

    void reset(const Tuple& tup) override {
        if (show_reset) {
            dump_tuple(out, tup);
            out << "[reset]\n";
        }
    }
};

class DumpAsCsvOperator : public Operator {
    std::ostream& out;
    std::pair<std::string, std::string> static_field;
    bool has_static_field;
    bool header;
    bool first = true;
public:
    DumpAsCsvOperator(std::ostream& out, bool header = true,
                      std::pair<std::string, std::string> static_field = {"", ""},
                      bool has_static_field = false)
        : out(out), static_field(static_field), has_static_field(has_static_field), header(header), first(header) {}

    void next(const Tuple& tup) override {
        if (first) {
            if (has_static_field) out << static_field.first << ",";
            for (const auto& [key, _] : tup) out << key << ",";
            out << "\n";
            first = false;
        }
        if (has_static_field) out << static_field.second << ",";
        for (const auto& [_, val] : tup) out << string_of_op_result(val) << ",";
        out << "\n";
    }

    void reset(const Tuple&) override {}
};

class EpochOperator : public Operator {
    double epoch_width;
    std::string key_out;
    Operator* next_op;
    double epoch_boundary = 0.0;
    int eid = 0;
public:
    EpochOperator(double epoch_width, std::string key_out, Operator* next_op)
        : epoch_width(epoch_width), key_out(std::move(key_out)), next_op(next_op) {}

    void next(const Tuple& tup) override {
        double time = lookup_float("time", tup);
        if (epoch_boundary == 0.0) {
            epoch_boundary = time + epoch_width;
        } else {
            while (time >= epoch_boundary) {
                next_op->reset({{key_out, eid}});
                epoch_boundary += epoch_width;
                ++eid;
            }
        }
        Tuple new_tup = tup;
        new_tup[key_out] = eid;
        next_op->next(new_tup);
    }

    void reset(const Tuple& tup) override {
        next_op->reset({{key_out, eid}});
        epoch_boundary = 0.0;
        eid = 0;
    }
};

using FilterFunc = std::function<bool(const Tuple&)>;
class FilterOperator : public Operator {
    FilterFunc filter_func;
    Operator* next_op;
public:
    FilterOperator(FilterFunc filter_func, Operator* next_op)
        : filter_func(std::move(filter_func)), next_op(next_op) {}

    void next(const Tuple& tup) override {
        if (filter_func(tup)) next_op->next(tup);
    }

    void reset(const Tuple& tup) override {
        next_op->reset(tup);
    }
};

using MapFunc = std::function<Tuple(const Tuple&)>;
class MapOperator : public Operator {
    MapFunc map_func;
    Operator* next_op;
public:
    MapOperator(MapFunc map_func, Operator* next_op)
        : map_func(std::move(map_func)), next_op(next_op) {}

    void next(const Tuple& tup) override {
        next_op->next(map_func(tup));
    }

    void reset(const Tuple& tup) override {
        next_op->reset(tup);
    }
};

using GroupingFunc = std::function<Tuple(const Tuple&)>;
using ReductionFunc = std::function<op_result(const op_result&, const Tuple&)>;
class GroupByOperator : public Operator {
    GroupingFunc groupby;
    ReductionFunc reduce;
    std::string out_key;
    Operator* next_op;
    std::unordered_map<Tuple, op_result, std::hash<Tuple>> h_tbl;
public:
    GroupByOperator(GroupingFunc groupby, ReductionFunc reduce, std::string out_key, Operator* next_op)
        : groupby(std::move(groupby)), reduce(std::move(reduce)), out_key(std::move(out_key)), next_op(next_op) {}

    void next(const Tuple& tup) override {
        Tuple grouping_key = groupby(tup);
        auto it = h_tbl.find(grouping_key);
        if (it != h_tbl.end()) {
            it->second = reduce(it->second, tup);
        } else {
            h_tbl[grouping_key] = reduce(std::monostate{}, tup);
        }
    }

    void reset(const Tuple& tup) override {
        for (const auto& [grouping_key, val] : h_tbl) {
            Tuple union_tup = grouping_key;
            for (const auto& [k, v] : tup) union_tup[k] = v; // Union with tup overriding
            union_tup[out_key] = val;
            next_op->next(union_tup);
        }
        next_op->reset(tup);
        h_tbl.clear();
    }
};

class DistinctOperator : public Operator {
    GroupingFunc groupby;
    Operator* next_op;
    std::unordered_map<Tuple, bool, std::hash<Tuple>> h_tbl;
public:
    DistinctOperator(GroupingFunc groupby, Operator* next_op)
        : groupby(std::move(groupby)), next_op(next_op) {}

    void next(const Tuple& tup) override {
        h_tbl[groupby(tup)] = true;
    }

    void reset(const Tuple& tup) override {
        for (const auto& [key, _] : h_tbl) {
            Tuple merged_tup = key;
            for (const auto& [k, v] : tup) merged_tup[k] = v;
            next_op->next(merged_tup);
        }
        next_op->reset(tup);
        h_tbl.clear();
    }
};

class SplitOperator : public Operator {
    std::vector<Operator*> next_ops;
public:
    SplitOperator(const std::vector<Operator*>& next_ops) : next_ops(next_ops) {}

    void next(const Tuple& tup) override {
        for (auto* op : next_ops) op->next(tup);
    }

    void reset(const Tuple& tup) override {
        for (auto* op : next_ops) op->reset(tup);
    }
};

using JoinFunc = std::function<std::pair<Tuple, Tuple>(const Tuple&)>;
class JoinOperator : public Operator {
    JoinFunc join_func;
    std::string key_lhs;
    std::string key_rhs;
    Operator* next_op;
    std::unordered_map<std::string, std::vector<Tuple>> h_tbl;
    bool lhs;
public:
    JoinOperator(JoinFunc join_func, std::string key_lhs, std::string key_rhs, Operator* next_op, bool lhs)
        : join_func(std::move(join_func)), key_lhs(std::move(key_lhs)), key_rhs(std::move(key_rhs)),
          next_op(next_op), lhs(lhs) {}

    void next(const Tuple& tup) override {
        auto [tup_lhs, tup_rhs] = join_func(tup);
        std::string key = lookup_string(lhs ? key_lhs : key_rhs, lhs ? tup_lhs : tup_rhs);
        auto& buf = h_tbl[key];
        if (lhs) {
            buf.push_back(tup_lhs);
            for (const auto& rhs : h_tbl[key]) {
                Tuple merged = tup_lhs;
                for (const auto& [k, v] : rhs) merged[k] = v;
                next_op->next(merged);
            }
        } else {
            buf.push_back(tup_rhs);
            for (const auto& lhs_tup : h_tbl[key]) {
                Tuple merged = lhs_tup;
                for (const auto& [k, v] : tup_rhs) merged[k] = v;
                next_op->next(merged);
            }
        }
    }

    void reset(const Tuple& tup) override {
        next_op->reset(tup);
        h_tbl.clear();
    }
};

// ### Utility Functions for Operators
Tuple filter_groups(const std::vector<std::string>& incl_keys, const Tuple& tup) {
    Tuple result;
    for (const auto& key : incl_keys) {
        auto it = tup.find(key);
        if (it != tup.end()) result[key] = it->second;
    }
    return result;
}

Tuple single_group(const Tuple&) { return Tuple(); }

op_result counter(const op_result& val, const Tuple&) {
    if (std::holds_alternative<std::monostate>(val)) return 1;
    if (std::holds_alternative<int>(val)) return std::get<int>(val) + 1;
    return val;
}

bool key_geq_int(const std::string& key, int threshold, const Tuple& tup) {
    return lookup_int(key, tup) >= threshold;
}

bool is_tcp_syn(const Tuple& tup) {
    return (lookup_int("ipv4.proto", tup) == 6) && (lookup_int("l4.flags", tup) & 2); // SYN flag
}

bool is_ssh(const Tuple& tup) {
    int sport = lookup_int("l4.sport", tup);
    int dport = lookup_int("l4.dport", tup);
    return (sport == 22 || dport == 22) && lookup_int("ipv4.proto", tup) == 6;
}

// ### Query Definitions
Operator* ident(Operator* next_op) {
    auto f = [](const Tuple& tup) {
        Tuple result;
        for (const auto& [k, v] : tup) {
            if (k != "eth.src" && k != "eth.dst") result[k] = v;
        }
        return result;
    };
    return new MapOperator(f, next_op);
}

Operator* count_pkts(Operator* next_op) {
    return new EpochOperator(1.0, "eid",
        new GroupByOperator(single_group, counter, "pkts", next_op));
}

Operator* pkts_per_src_dst(Operator* next_op) {
    auto groupby = [](const Tuple& tup) { return filter_groups({"ipv4.src", "ipv4.dst"}, tup); };
    return new EpochOperator(1.0, "eid",
        new GroupByOperator(groupby, counter, "pkts", next_op));
}

Operator* distinct_srcs(Operator* next_op) {
    auto groupby = [](const Tuple& tup) { return filter_groups({"ipv4.src"}, tup); };
    return new EpochOperator(1.0, "eid",
        new DistinctOperator(groupby,
        new GroupByOperator(single_group, counter, "srcs", next_op)));
}

Operator* tcp_new_cons(Operator* next_op) {
    auto groupby = [](const Tuple& tup) { return filter_groups({"ipv4.src", "ipv4.dst", "l4.sport", "l4.dport"}, tup); };
    return new FilterOperator(is_tcp_syn,
        new EpochOperator(1.0, "eid",
        new DistinctOperator(groupby,
        new GroupByOperator(single_group, counter, "new_cons", next_op))));
}

Operator* ssh_brute_force(Operator* next_op) {
    auto groupby = [](const Tuple& tup) { return filter_groups({"ipv4.src"}, tup); };
    return new FilterOperator(is_ssh,
        new EpochOperator(1.0, "eid",
        new GroupByOperator(groupby, counter, "attempts",
        new FilterOperator([](const Tuple& t) { return key_geq_int("attempts", 10, t); }, next_op))));
}

Operator* super_spreader(Operator* next_op) {
    int threshold = 40; // Minimum number of distinct destinations
    auto groupby = [](const Tuple& tup) { return filter_groups({"ipv4.src"}, tup); };
    return new EpochOperator(1.0, "eid",
        new DistinctOperator([](const Tuple& tup) { return filter_groups({"ipv4.src", "ipv4.dst"}, tup); },
        new GroupByOperator(groupby, counter, "dsts",
        new FilterOperator([threshold](const Tuple& tup) { return key_geq_int("dsts", threshold, tup); }, next_op))));
}

Operator* port_scan(Operator* next_op) {
    int threshold = 40; // Minimum number of distinct ports
    auto groupby = [](const Tuple& tup) { return filter_groups({"ipv4.src"}, tup); };
    return new EpochOperator(1.0, "eid",
        new DistinctOperator([](const Tuple& tup) { return filter_groups({"ipv4.src", "l4.dport"}, tup); },
        new GroupByOperator(groupby, counter, "ports",
        new FilterOperator([threshold](const Tuple& tup) { return key_geq_int("ports", threshold, tup); }, next_op))));
}

Operator* ddos(Operator* next_op) {
    int threshold = 45; // Minimum number of distinct sources
    auto groupby = [](const Tuple& tup) { return filter_groups({"ipv4.dst"}, tup); };
    return new EpochOperator(1.0, "eid",
        new DistinctOperator([](const Tuple& tup) { return filter_groups({"ipv4.src", "ipv4.dst"}, tup); },
        new GroupByOperator(groupby, counter, "srcs",
        new FilterOperator([threshold](const Tuple& tup) { return key_geq_int("srcs", threshold, tup); }, next_op))));
}

std::vector<Operator*> syn_flood_sonata(Operator* next_op) {
    int threshold = 3; // Threshold for SYN flood detection
    double epoch_dur = 1.0;
    auto syns = new EpochOperator(epoch_dur, "eid",
        new FilterOperator([](const Tuple& tup) {
            return (lookup_int("ipv4.proto", tup) == 6) && (lookup_int("l4.flags", tup) == 2); // TCP SYN
        },
        new GroupByOperator([](const Tuple& tup) { return filter_groups({"ipv4.dst"}, tup); }, counter, "syns", nullptr)));
    auto synacks = new EpochOperator(epoch_dur, "eid",
        new FilterOperator([](const Tuple& tup) {
            return (lookup_int("ipv4.proto", tup) == 6) && (lookup_int("l4.flags", tup) == 18); // TCP SYN-ACK
        },
        new GroupByOperator([](const Tuple& tup) { return filter_groups({"ipv4.src"}, tup); }, counter, "synacks", nullptr)));
    auto acks = new EpochOperator(epoch_dur, "eid",
        new FilterOperator([](const Tuple& tup) {
            return (lookup_int("ipv4.proto", tup) == 6) && (lookup_int("l4.flags", tup) == 16); // TCP ACK
        },
        new GroupByOperator([](const Tuple& tup) { return filter_groups({"ipv4.dst"}, tup); }, counter, "acks", nullptr)));
    return {syns, synacks, acks};
}

std::vector<Operator*> completed_flows(Operator* next_op) {
    int threshold = 1; // Minimum number of flows
    double epoch_dur = 30.0; // 30-second epochs
    auto syns = new EpochOperator(epoch_dur, "eid",
        new FilterOperator([](const Tuple& tup) {
            return (lookup_int("ipv4.proto", tup) == 6) && (lookup_int("l4.flags", tup) == 2); // TCP SYN
        },
        new GroupByOperator([](const Tuple& tup) { return filter_groups({"ipv4.dst"}, tup); }, counter, "syns", nullptr)));
    auto fins = new EpochOperator(epoch_dur, "eid",
        new FilterOperator([](const Tuple& tup) {
            return (lookup_int("ipv4.proto", tup) == 6) && (lookup_int("l4.flags", tup) & 1); // TCP FIN
        },
        new GroupByOperator([](const Tuple& tup) { return filter_groups({"ipv4.src"}, tup); }, counter, "fins", nullptr)));
    return {syns, fins};
}

std::vector<Operator*> slowloris(Operator* next_op) {
    int t1 = 5, t2 = 500, t3 = 90; // Thresholds for connections and bytes
    double epoch_dur = 1.0;
    auto n_conns = new EpochOperator(epoch_dur, "eid",
        new FilterOperator([](const Tuple& tup) {
            return lookup_int("ipv4.proto", tup) == 6; // TCP packets
        },
        new DistinctOperator([](const Tuple& tup) { return filter_groups({"ipv4.src", "ipv4.dst", "l4.sport"}, tup); },
        new GroupByOperator([](const Tuple& tup) { return filter_groups({"ipv4.dst"}, tup); }, counter, "n_conns",
        new FilterOperator([t1](const Tuple& tup) { return key_geq_int("n_conns", t1, tup); }, nullptr)))));
    auto n_bytes = new EpochOperator(epoch_dur, "eid",
        new FilterOperator([](const Tuple& tup) {
            return lookup_int("ipv4.proto", tup) == 6; // TCP packets
        },
        new GroupByOperator([](const Tuple& tup) { return filter_groups({"ipv4.dst"}, tup); },
            [](const op_result& acc, const Tuple& tup) {
                int len = lookup_int("ipv4.len", tup);
                if (std::holds_alternative<std::monostate>(acc)) return len;
                if (std::holds_alternative<int>(acc)) return std::get<int>(acc) + len;
                return acc;
            }, "n_bytes",
        new FilterOperator([t2](const Tuple& tup) { return key_geq_int("n_bytes", t2, tup); }, nullptr))));
    return {n_conns, n_bytes};
}

std::vector<Operator*> join_test(Operator* next_op) {
    double epoch_dur = 1.0;
    auto syns = new EpochOperator(epoch_dur, "eid",
        new FilterOperator([](const Tuple& tup) {
            return (lookup_int("ipv4.proto", tup) == 6) && (lookup_int("l4.flags", tup) == 2); // TCP SYN
        }, nullptr));
    auto synacks = new EpochOperator(epoch_dur, "eid",
        new FilterOperator([](const Tuple& tup) {
            return (lookup_int("ipv4.proto", tup) == 6) && (lookup_int("l4.flags", tup) == 18); // TCP SYN-ACK
        }, nullptr));
    return {syns, synacks};
}


// ### Main Entry Point
std::vector<Tuple> generate_tuples() {
    std::vector<Tuple> tuples;
    for (int i = 0; i < 20; ++i) {
        Tuple tup;
        tup["time"] = static_cast<float>(i * 0.5);
        tup["eth.src"] = MAC{0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
        tup["eth.dst"] = MAC{0xAA, static_cast<char>(0xBB), static_cast<char>(0xCC), static_cast<char>(0xDD), static_cast<char>(0xEE), static_cast<char>(0xFF)};
        tup["eth.ethertype"] = 0x0800;
        tup["ipv4.hlen"] = 20;
        tup["ipv4.proto"] = 6;
        tup["ipv4.len"] = 60;
        tup["ipv4.src"] = IPv4("127.0.0." + std::to_string(i % 4));
        tup["ipv4.dst"] = IPv4("127.0.0.1");
        tup["l4.sport"] = 22;
        tup["l4.dport"] = 50000 + i;
        tup["l4.flags"] = (i % 2 == 0) ? 2 : 10; // Alternate SYN and other flags
        tuples.push_back(tup);
    }
    return tuples;
}

void run_queries() {
    std::vector<std::unique_ptr<Operator>> queries;
    queries.emplace_back(ident(new DumpTupleOperator(std::cout)));
    queries.emplace_back(count_pkts(new DumpTupleOperator(std::cout)));
    queries.emplace_back(pkts_per_src_dst(new DumpTupleOperator(std::cout)));
    queries.emplace_back(distinct_srcs(new DumpTupleOperator(std::cout)));
    queries.emplace_back(tcp_new_cons(new DumpTupleOperator(std::cout)));
    queries.emplace_back(ssh_brute_force(new DumpTupleOperator(std::cout)));

    auto tuples = generate_tuples();
    for (const auto& tup : tuples) {
        for (auto& query : queries) {
            query->next(tup);
        }
    }
}

int main() {
    run_queries();
    std::cout << "Done\n";
    return 0;
}