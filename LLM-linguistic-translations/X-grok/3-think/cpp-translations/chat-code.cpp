#include <variant>
#include <cstdint>
#include <array>
#include <string>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <functional>
#include <memory>
#include <iostream>
#include <sstream>
#include <vector>
#include <stdexcept>

// Type definitions
using IPv4 = std::uint32_t;
using MAC = std::array<std::uint8_t, 6>;
using op_result = std::variant<float, int, IPv4, MAC, std::monostate>;
using tuple = std::map<std::string, op_result>;

// Convert op_result to string for hashing
std::string string_of_op_result(const op_result& val) {
    return std::visit([](const auto& v) -> std::string {
        using T = std::decay_t<decltype(v)>;
        if constexpr (std::is_same_v<T, std::monostate>) return "none";
        else if constexpr (std::is_same_v<T, IPv4>) return std::to_string(v);
        else if constexpr (std::is_same_v<T, MAC>) {
            std::ostringstream oss;
            for (auto byte : v) oss << std::hex << (int)byte;
            return oss.str();
        } else return std::to_string(v);
    }, val);
}

// Hash function for tuples
struct TupleHash {
    size_t operator()(const tuple& t) const {
        std::ostringstream oss;
        for (const auto& [k, v] : t) {
            oss << k << ":" << string_of_op_result(v) << ";";
        }
        return std::hash<std::string>{}(oss.str());
    }
};

// Merge two tuples
tuple merge_tuples(const tuple& t1, const tuple& t2) {
    tuple result = t1;
    result.insert(t2.begin(), t2.end());
    return result;
}

// Filter tuple by keys
tuple filter_groups(const std::vector<std::string>& keys, const tuple& tup) {
    tuple result;
    for (const auto& key : keys) {
        auto it = tup.find(key);
        if (it != tup.end()) result[key] = it->second;
    }
    return result;
}

// Rename and filter keys
tuple rename_filtered_keys(const std::vector<std::pair<std::string, std::string>>& renamings, const tuple& in_tup) {
    tuple result;
    for (const auto& [old_key, new_key] : renamings) {
        auto it = in_tup.find(old_key);
        if (it != in_tup.end()) result[new_key] = it->second;
    }
    return result;
}

class Operator {
public:
    virtual ~Operator() = default;
    virtual void next(const tuple& tup) = 0;
    virtual void reset(const tuple& tup) = 0;
};

class Distinct : public Operator {
public:
    Distinct(std::function<tuple(const tuple&)> groupby, std::unique_ptr<Operator> next_op)
        : groupby_(std::move(groupby)), next_op_(std::move(next_op)) {}

    void next(const tuple& tup) override {
        tuple grouping_key = groupby_(tup);
        groups_.insert(grouping_key);
    }

    void reset(const tuple& tup) override {
        for (const auto& key : groups_) {
            tuple merged_tup = merge_tuples(tup, key);
            if (next_op_) next_op_->next(merged_tup);
        }
        if (next_op_) next_op_->reset(tup);
        groups_.clear();
    }

private:
    std::function<tuple(const tuple&)> groupby_;
    std::unique_ptr<Operator> next_op_;
    std::unordered_set<tuple, TupleHash> groups_;
};

class Split : public Operator {
public:
    Split(std::unique_ptr<Operator> left, std::unique_ptr<Operator> right)
        : left_(std::move(left)), right_(std::move(right)) {}

    void next(const tuple& tup) override {
        if (left_) left_->next(tup);
        if (right_) right_->next(tup);
    }

    void reset(const tuple& tup) override {
        if (left_) left_->reset(tup);
        if (right_) right_->reset(tup);
    }

private:
    std::unique_ptr<Operator> left_;
    std::unique_ptr<Operator> right_;
};

class Join : public Operator {
public:
    Join(std::string eid_key,
         std::function<std::pair<tuple, tuple>(const tuple&)> left_extractor,
         std::function<std::pair<tuple, tuple>(const tuple&)> right_extractor,
         std::unique_ptr<Operator> next_op)
        : eid_key_(std::move(eid_key)), left_extractor_(std::move(left_extractor)),
          right_extractor_(std::move(right_extractor)), next_op_(std::move(next_op)) {}

    void next(const tuple& tup) override {
        auto it = tup.find(eid_key_);
        if (it == tup.end()) return;

        bool is_left = tup.find("left") != tup.end();
        auto [key, val] = is_left ? left_extractor_(tup) : right_extractor_(tup);

        if (is_left) {
            left_table_[key].push_back(val);
            for (const auto& right_val : right_table_[key]) {
                if (next_op_) next_op_->next(merge_tuples(val, right_val));
            }
        } else {
            right_table_[key].push_back(val);
            for (const auto& left_val : left_table_[key]) {
                if (next_op_) next_op_->next(merge_tuples(val, left_val));
            }
        }
    }

    void reset(const tuple& tup) override {
        left_table_.clear();
        right_table_.clear();
        if (next_op_) next_op_->reset(tup);
    }

private:
    std::string eid_key_;
    std::function<std::pair<tuple, tuple>(const tuple&)> left_extractor_;
    std::function<std::pair<tuple, tuple>(const tuple&)> right_extractor_;
    std::unique_ptr<Operator> next_op_;
    std::unordered_map<tuple, std::vector<tuple>, TupleHash> left_table_;
    std::unordered_map<tuple, std::vector<tuple>, TupleHash> right_table_;
};

class GroupBy : public Operator {
public:
    GroupBy(std::function<tuple(const tuple&)> groupby,
            std::function<op_result(const std::vector<tuple>&)> agg,
            std::string agg_name,
            std::unique_ptr<Operator> next_op)
        : groupby_(std::move(groupby)), agg_(std::move(agg)),
          agg_name_(std::move(agg_name)), next_op_(std::move(next_op)) {}

    void next(const tuple& tup) override {
        tuple key = groupby_(tup);
        groups_[key].push_back(tup);
    }

    void reset(const tuple& tup) override {
        for (const auto& [key, group] : groups_) {
            tuple result = key;
            result[agg_name_] = agg_(group);
            if (next_op_) next_op_->next(merge_tuples(tup, result));
        }
        if (next_op_) next_op_->reset(tup);
        groups_.clear();
    }

private:
    std::function<tuple(const tuple&)> groupby_;
    std::function<op_result(const std::vector<tuple>&)> agg_;
    std::string agg_name_;
    std::unique_ptr<Operator> next_op_;
    std::unordered_map<tuple, std::vector<tuple>, TupleHash> groups_;
};

class Epoch : public Operator {
public:
    Epoch(float duration, std::string eid_key, std::unique_ptr<Operator> next_op)
        : duration_(duration), eid_key_(std::move(eid_key)), next_op_(std::move(next_op)) {}

    void next(const tuple& tup) override {
        if (next_op_) next_op_->next(tup);
    }

    void reset(const tuple& tup) override {
        if (next_op_) next_op_->reset(tup);
    }

private:
    float duration_;
    std::string eid_key_;
    std::unique_ptr<Operator> next_op_;
};

// Aggregation functions
auto single_group = [](const tuple& tup) { return tuple{}; };
auto counter = [](const std::vector<tuple>& group) { return static_cast<int>(group.size()); };

// Distinct source IPs query
std::unique_ptr<Operator> distinct_srcs(std::unique_ptr<Operator> next_op) {
    auto distinct_op = std::make_unique<Distinct>(
        [](const tuple& tup) { return filter_groups({"ipv4.src"}, tup); },
        std::move(next_op)
    );
    auto groupby_op = std::make_unique<GroupBy>(
        single_group, counter, "srcs", std::move(distinct_op)
    );
    return std::make_unique<Epoch>(1.0, "eid", std::move(groupby_op));
}

std::unique_ptr<Operator> tcp_new_cons(std::unique_ptr<Operator> next_op) {
    int threshold = 40;
    auto filter_syn = [](const tuple& tup) {
        return int_of_op_result(tup.at("ipv4.proto")) == 6 &&  // TCP protocol
               int_of_op_result(tup.at("l4.flags")) == 2;      // SYN flag
    };
    auto groupby_dst = [](const tuple& tup) { return filter_groups({"ipv4.dst"}, tup); };
    auto filter_threshold = [threshold](const tuple& tup) {
        return key_geq_int("cons", threshold, tup);
    };
    return std::make_unique<Epoch>(1.0, "eid",
        std::make_unique<Filter>(filter_syn,
            std::make_unique<GroupBy>(groupby_dst, counter, "cons",
                std::make_unique<Filter>(filter_threshold, std::move(next_op))
            )
        )
    );
}

std::unique_ptr<Operator> ssh_brute_force(std::unique_ptr<Operator> next_op) {
    int threshold = 40;
    auto filter_ssh = [](const tuple& tup) {
        return int_of_op_result(tup.at("ipv4.proto")) == 6 &&  // TCP protocol
               int_of_op_result(tup.at("l4.dport")) == 22;     // SSH port
    };
    auto distinct_src_dst_len = [](const tuple& tup) {
        return filter_groups({"ipv4.src", "ipv4.dst", "ipv4.len"}, tup);
    };
    auto groupby_dst_len = [](const tuple& tup) { return filter_groups({"ipv4.dst", "ipv4.len"}, tup); };
    auto filter_threshold = [threshold](const tuple& tup) {
        return key_geq_int("srcs", threshold, tup);
    };
    return std::make_unique<Epoch>(1.0, "eid",
        std::make_unique<Filter>(filter_ssh,
            std::make_unique<Distinct>(distinct_src_dst_len,
                std::make_unique<GroupBy>(groupby_dst_len, counter, "srcs",
                    std::make_unique<Filter>(filter_threshold, std::move(next_op))
                )
            )
        )
    );
}

std::unique_ptr<Operator> super_spreader(std::unique_ptr<Operator> next_op) {
    int threshold = 40;
    auto distinct_src_dst = [](const tuple& tup) { return filter_groups({"ipv4.src", "ipv4.dst"}, tup); };
    auto groupby_src = [](const tuple& tup) { return filter_groups({"ipv4.src"}, tup); };
    auto filter_threshold = [threshold](const tuple& tup) {
        return key_geq_int("dsts", threshold, tup);
    };
    return std::make_unique<Epoch>(1.0, "eid",
        std::make_unique<Distinct>(distinct_src_dst,
            std::make_unique<GroupBy>(groupby_src, counter, "dsts",
                std::make_unique<Filter>(filter_threshold, std::move(next_op))
            )
        )
    );
}

std::unique_ptr<Operator> port_scan(std::unique_ptr<Operator> next_op) {
    int threshold = 40;
    auto distinct_src_dport = [](const tuple& tup) { return filter_groups({"ipv4.src", "l4.dport"}, tup); };
    auto groupby_src = [](const tuple& tup) { return filter_groups({"ipv4.src"}, tup); };
    auto filter_threshold = [threshold](const tuple& tup) {
        return key_geq_int("ports", threshold, tup);
    };
    return std::make_unique<Epoch>(1.0, "eid",
        std::make_unique<Distinct>(distinct_src_dport,
            std::make_unique<GroupBy>(groupby_src, counter, "ports",
                std::make_unique<Filter>(filter_threshold, std::move(next_op))
            )
        )
    );
}

std::unique_ptr<Operator> ddos(std::unique_ptr<Operator> next_op) {
    int threshold = 45;
    auto distinct_src_dst = [](const tuple& tup) { return filter_groups({"ipv4.src", "ipv4.dst"}, tup); };
    auto groupby_dst = [](const tuple& tup) { return filter_groups({"ipv4.dst"}, tup); };
    auto filter_threshold = [threshold](const tuple& tup) {
        return key_geq_int("srcs", threshold, tup);
    };
    return std::make_unique<Epoch>(1.0, "eid",
        std::make_unique<Distinct>(distinct_src_dst,
            std::make_unique<GroupBy>(groupby_dst, counter, "srcs",
                std::make_unique<Filter>(filter_threshold, std::move(next_op))
            )
        )
    );
}

std::vector<std::unique_ptr<Operator>> syn_flood_sonata(std::unique_ptr<Operator> next_op) {
    int threshold = 3;
    float epoch_dur = 1.0;

    auto filter_syn = [](const tuple& tup) {
        return int_of_op_result(tup.at("ipv4.proto")) == 6 &&  // TCP protocol
               int_of_op_result(tup.at("l4.flags")) == 2;      // SYN flag
    };
    auto filter_synack = [](const tuple& tup) {
        return int_of_op_result(tup.at("ipv4.proto")) == 6 &&  // TCP protocol
               int_of_op_result(tup.at("l4.flags")) == 18;     // SYN-ACK flags
    };
    auto filter_ack = [](const tuple& tup) {
        return int_of_op_result(tup.at("ipv4.proto")) == 6 &&  // TCP protocol
               int_of_op_result(tup.at("l4.flags")) == 16;     // ACK flag
    };

    auto groupby_dst = [](const tuple& tup) { return filter_groups({"ipv4.dst"}, tup); };
    auto groupby_src = [](const tuple& tup) { return filter_groups({"ipv4.src"}, tup); };

    // SYN stream
    auto syns = std::make_unique<Epoch>(epoch_dur, "eid",
        std::make_unique<Filter>(filter_syn,
            std::make_unique<GroupBy>(groupby_dst, counter, "syns", nullptr)
        )
    );

    // SYN-ACK stream
    auto synacks = std::make_unique<Epoch>(epoch_dur, "eid",
        std::make_unique<Filter>(filter_synack,
            std::make_unique<GroupBy>(groupby_src, counter, "synacks", nullptr)
        )
    );

    // ACK stream
    auto acks = std::make_unique<Epoch>(epoch_dur, "eid",
        std::make_unique<Filter>(filter_ack,
            std::make_unique<GroupBy>(groupby_dst, counter, "acks", nullptr)
        )
    );

    // Placeholder for join operator (requires additional implementation)
    auto join_op = std::make_unique<Join>("eid",
        [](const tuple& tup) { return std::make_pair(filter_groups({"host"}), filter_groups({"syns+synacks"})); },
        [](const tuple& tup) { return std::make_pair(rename_filtered_keys({{"ipv4.dst", "host"}}), filter_groups({"acks"})); },
        std::move(next_op)
    );

    return {std::move(syns), std::move(synacks), std::move(acks)};
}

std::vector<std::unique_ptr<Operator>> completed_flows(std::unique_ptr<Operator> next_op) {
    int threshold = 1;
    float epoch_dur = 30.0;

    auto filter_syn = [](const tuple& tup) {
        return int_of_op_result(tup.at("ipv4.proto")) == 6 &&  // TCP protocol
               int_of_op_result(tup.at("l4.flags")) == 2;      // SYN flag
    };
    auto filter_fin = [](const tuple& tup) {
        return int_of_op_result(tup.at("ipv4.proto")) == 6 &&  // TCP protocol
               (int_of_op_result(tup.at("l4.flags")) & 1) == 1; // FIN flag
    };

    auto groupby_dst = [](const tuple& tup) { return filter_groups({"ipv4.dst"}, tup); };
    auto groupby_src = [](const tuple& tup) { return filter_groups({"ipv4.src"}, tup); };

    // SYN stream
    auto syns = std::make_unique<Epoch>(epoch_dur, "eid",
        std::make_unique<Filter>(filter_syn,
            std::make_unique<GroupBy>(groupby_dst, counter, "syns", nullptr)
        )
    );

    // FIN stream
    auto fins = std::make_unique<Epoch>(epoch_dur, "eid",
        std::make_unique<Filter>(filter_fin,
            std::make_unique<GroupBy>(groupby_src, counter, "fins", nullptr)
        )
    );

    // Placeholder for join operator
    auto join_op = std::make_unique<Join>("eid",
        [](const tuple& tup) { return std::make_pair(rename_filtered_keys({{"ipv4.dst", "host"}}), filter_groups({"syns"})); },
        [](const tuple& tup) { return std::make_pair(rename_filtered_keys({{"ipv4.src", "host"}}), filter_groups({"fins"})); },
        std::move(next_op)
    );

    return {std::move(syns), std::move(fins)};
}

std::vector<std::unique_ptr<Operator>> slowloris(std::unique_ptr<Operator> next_op) {
    int t1 = 5, t2 = 500, t3 = 90;
    float epoch_dur = 1.0;

    auto filter_tcp = [](const tuple& tup) {
        return int_of_op_result(tup.at("ipv4.proto")) == 6;  // TCP protocol
    };

    auto distinct_conns = [](const tuple& tup) {
        return filter_groups({"ipv4.src", "ipv4.dst", "l4.sport"}, tup);
    };

    auto groupby_dst = [](const tuple& tup) { return filter_groups({"ipv4.dst"}, tup); };

    // Number of connections
    auto n_conns = std::make_unique<Epoch>(epoch_dur, "eid",
        std::make_unique<Filter>(filter_tcp,
            std::make_unique<Distinct>(distinct_conns,
                std::make_unique<GroupBy>(groupby_dst, counter, "n_conns",
                    std::make_unique<Filter>([t1](const tuple& tup) { return key_geq_int("n_conns", t1, tup); }, nullptr)
                )
            )
        )
    );

    // Number of bytes
    auto n_bytes = std::make_unique<Epoch>(epoch_dur, "eid",
        std::make_unique<Filter>(filter_tcp,
            std::make_unique<GroupBy>(groupby_dst, [](const std::vector<tuple>& group) {
                int sum = 0;
                for (const auto& tup : group) sum += int_of_op_result(tup.at("ipv4.len"));
                return sum;
            }, "n_bytes",
                std::make_unique<Filter>([t2](const tuple& tup) { return key_geq_int("n_bytes", t2, tup); }, nullptr)
            )
        )
    );

    // Placeholder for join operator
    auto join_op = std::make_unique<Join>("eid",
        [](const tuple& tup) { return std::make_pair(filter_groups({"ipv4.dst"}), filter_groups({"n_conns"})); },
        [](const tuple& tup) { return std::make_pair(filter_groups({"ipv4.dst"}), filter_groups({"n_bytes"})); },
        std::move(next_op)
    );

    return {std::move(n_conns), std::move(n_bytes)};
}

int main() {
    // Sink operator to print results
    class Sink : public Operator {
    public:
        void next(const tuple& tup) override {
            for (const auto& [k, v] : tup) {
                std::cout << k << ": " << string_of_op_result(v) << " ";
            }
            std::cout << "\n";
        }
        void reset(const tuple& tup) override {}
    };

    auto pipeline = distinct_srcs(std::make_unique<Sink>());

    // Sample tuples
    std::vector<tuple> tuples = {
        {{"ipv4.src", IPv4{192168001}}, {"eid", 1}},
        {{"ipv4.src", IPv4{192168002}}, {"eid", 1}},
        {{"ipv4.src", IPv4{192168001}}, {"eid", 1}}
    };

    // Process tuples
    for (const auto& tup : tuples) {
        pipeline->next(tup);
    }
    pipeline->reset({{"eid", 1}});

    return 0;
}