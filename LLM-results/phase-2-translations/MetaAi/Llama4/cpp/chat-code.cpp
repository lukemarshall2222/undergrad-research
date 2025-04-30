#include <iostream>
#include <string>
#include <vector>
#include <unordered_map>
#include <boost/asio.hpp>
#include <fstream>
#include <sstream>

// Enum for op_result
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
    boost::asio::ip::address_v4 ipv4_val;
    std::string mac_val;

    OpResult(float val) : type(OpResultType::Float), float_val(val) {}
    OpResult(int val) : type(OpResultType::Int), int_val(val) {}
    OpResult(boost::asio::ip::address_v4 val) : type(OpResultType::IPv4), ipv4_val(val) {}
    OpResult(std::string val) : type(OpResultType::MAC), mac_val(val) {}
    OpResult() : type(OpResultType::Empty) {}
};

// Tuple is a map from string to OpResult
using Tuple = std::unordered_map<std::string, OpResult>;

// Operator is a struct with two functions: next and reset
struct Operator {
    virtual void next(Tuple tup) = 0;
    virtual void reset(Tuple tup) = 0;
};

// Conversion utilities
std::string string_of_mac(std::string buf) {
    std::stringstream ss;
    for (int i = 0; i < 6; ++i) {
        if (i > 0) ss << ":";
        ss << std::hex << (int)buf[i];
    }
    return ss.str();
}

std::string tcp_flags_to_strings(int flags) {
    std::string result;
    if (flags & 1) result += "FIN|";
    if (flags & 2) result += "SYN|";
    if (flags & 4) result += "RST|";
    if (flags & 8) result += "PSH|";
    if (flags & 16) result += "ACK|";
    if (flags & 32) result += "URG|";
    if (flags & 64) result += "ECE|";
    if (flags & 128) result += "CWR|";
    if (!result.empty()) result.pop_back(); // remove last '|'
    return result;
}

int int_of_op_result(OpResult input) {
    if (input.type == OpResultType::Int) return input.int_val;
    else throw std::runtime_error("Trying to extract int from non-int result");
}

float float_of_op_result(OpResult input) {
    if (input.type == OpResultType::Float) return input.float_val;
    else throw std::runtime_error("Trying to extract float from non-float result");
}

std::string string_of_op_result(OpResult input) {
    switch (input.type) {
        case OpResultType::Float: return std::to_string(input.float_val);
        case OpResultType::Int: return std::to_string(input.int_val);
        case OpResultType::IPv4: return input.ipv4_val.to_string();
        case OpResultType::MAC: return string_of_mac(input.mac_val);
        case OpResultType::Empty: return "Empty";
        default: throw std::runtime_error("Unknown OpResult type");
    }
}

std::string string_of_tuple(Tuple input_tuple) {
    std::stringstream ss;
    for (auto& pair : input_tuple) {
        ss << "\"" << pair.first << "\" => " << string_of_op_result(pair.second) << ", ";
    }
    return ss.str();
}

// Built-in operator definitions
class DumpTuple : public Operator {
public:
    DumpTuple(std::ostream& outc) : outc_(outc) {}

    void next(Tuple tup) override {
        outc_ << string_of_tuple(tup) << std::endl;
    }

    void reset(Tuple tup) override {
        outc_ << "[reset]" << std::endl;
    }

private:
    std::ostream& outc_;
};

class DumpAsCSV : public Operator {
public:
    DumpAsCSV(std::ostream& outc) : outc_(outc), first_(true) {}

    void next(Tuple tup) override {
        if (first_) {
            for (auto& pair : tup) {
                outc_ << pair.first << ",";
            }
            outc_ << std::endl;
            first_ = false;
        }
        for (auto& pair : tup) {
            outc_ << string_of_op_result(pair.second) << ",";
        }
        outc_ << std::endl;
    }

    void reset(Tuple tup) override {}

private:
    std::ostream& outc_;
    bool first_;
};

// Other operators...
class Epoch : public Operator {
public:
    Epoch(float epoch_width, std::string key_out, Operator* next_op)
        : epoch_width_(epoch_width), key_out_(key_out), next_op_(next_op), epoch_boundary_(0.0), eid_(0) {}

    void next(Tuple tup) override {
        float time = float_of_op_result(tup["time"]);
        if (epoch_boundary_ == 0.0) {
            epoch_boundary_ = time + epoch_width_;
        } else if (time >= epoch_boundary_) {
            while (time >= epoch_boundary_) {
                next_op_->reset(Tuple{{key_out_, OpResult(eid_)}});
                epoch_boundary_ += epoch_width_;
                eid_++;
            }
        }
        tup[key_out_] = OpResult(eid_);
        next_op_->next(tup);
    }

    void reset(Tuple tup) override {
        next_op_->reset(Tuple{{key_out_, OpResult(eid_)}});
        epoch_boundary_ = 0.0;
        eid_ = 0;
    }

private:
    float epoch_width_;
    std::string key_out_;
    Operator* next_op_;
    float epoch_boundary_;
    int eid_;
};

// Filter operator
class Filter : public Operator {
    public:
        Filter(std::function<bool(Tuple)> f, Operator* next_op)
            : f_(f), next_op_(next_op) {}
    
        void next(Tuple tup) override {
            if (f_(tup)) {
                next_op_->next(tup);
            }
        }
    
        void reset(Tuple tup) override {
            next_op_->reset(tup);
        }
    
    private:
        std::function<bool(Tuple)> f_;
        Operator* next_op_;
    };
    
    // Map operator
    class Map : public Operator {
    public:
        Map(std::function<Tuple(Tuple)> f, Operator* next_op)
            : f_(f), next_op_(next_op) {}
    
        void next(Tuple tup) override {
            next_op_->next(f_(tup));
        }
    
        void reset(Tuple tup) override {
            next_op_->reset(tup);
        }
    
    private:
        std::function<Tuple(Tuple)> f_;
        Operator* next_op_;
    };
    
    // Groupby operator
    class Groupby : public Operator {
    public:
        Groupby(std::function<Tuple(Tuple)> groupby, std::function<OpResult(OpResult, Tuple)> reduce, std::string out_key, Operator* next_op)
            : groupby_(groupby), reduce_(reduce), out_key_(out_key), next_op_(next_op) {}
    
        void next(Tuple tup) override {
            Tuple grouping_key = groupby_(tup);
            auto it = h_tbl_.find(grouping_key);
            if (it != h_tbl_.end()) {
                it->second = reduce_(it->second, tup);
            } else {
                h_tbl_[grouping_key] = reduce_(OpResult(), tup);
            }
        }
    
        void reset(Tuple tup) override {
            for (auto& pair : h_tbl_) {
                Tuple unioned_tup = pair.first;
                unioned_tup[out_key_] = pair.second;
                next_op_->next(unioned_tup);
            }
            next_op_->reset(tup);
            h_tbl_.clear();
        }
    
    private:
        std::function<Tuple(Tuple)> groupby_;
        std::function<OpResult(OpResult, Tuple)> reduce_;
        std::string out_key_;
        Operator* next_op_;
        std::unordered_map<Tuple, OpResult> h_tbl_;
    };
    
    // Distinct operator
    class Distinct : public Operator {
    public:
        Distinct(std::function<Tuple(Tuple)> groupby, Operator* next_op)
            : groupby_(groupby), next_op_(next_op) {}
    
        void next(Tuple tup) override {
            Tuple grouping_key = groupby_(tup);
            h_tbl_[grouping_key] = true;
        }
    
        void reset(Tuple tup) override {
            for (auto& pair : h_tbl_) {
                Tuple merged_tup = pair.first;
                next_op_->next(merged_tup);
            }
            next_op_->reset(tup);
            h_tbl_.clear();
        }
    
    private:
        std::function<Tuple(Tuple)> groupby_;
        Operator* next_op_;
        std::unordered_map<Tuple, bool> h_tbl_;
    };
    
    // Join operator
    class Join : public Operator {
    public:
        Join(std::function<std::pair<Tuple, Tuple>(Tuple)> left_extractor, std::function<std::pair<Tuple, Tuple>(Tuple)> right_extractor, Operator* next_op)
            : left_extractor_(left_extractor), right_extractor_(right_extractor), next_op_(next_op) {}
    
        void next(Tuple tup) override {
            auto extracted = left_extractor_(tup);
            Tuple key = extracted.first;
            Tuple vals = extracted.second;
            auto it = right_h_tbl_.find(key);
            if (it != right_h_tbl_.end()) {
                Tuple joined_tup = vals;
                joined_tup.insert(it->second.begin(), it->second.end());
                next_op_->next(joined_tup);
                right_h_tbl_.erase(it);
            } else {
                left_h_tbl_[key] = vals;
            }
        }
    
        void reset(Tuple tup) override {
            next_op_->reset(tup);
            left_h_tbl_.clear();
            right_h_tbl_.clear();
        }
    
        void setRightHtbl(std::unordered_map<Tuple, Tuple> h_tbl) {
            right_h_tbl_ = h_tbl;
        }
    
        std::unordered_map<Tuple, Tuple> getLeftHtbl() {
            return left_h_tbl_;
        }
    
    private:
        std::function<std::pair<Tuple, Tuple>(Tuple)> left_extractor_;
        std::function<std::pair<Tuple, Tuple>(Tuple)> right_extractor_;
        Operator* next_op_;
        std::unordered_map<Tuple, Tuple> left_h_tbl_;
        std::unordered_map<Tuple, Tuple> right_h_tbl_;
    };
    
    // Meta meter operator
    class MetaMeter : public Operator {
    public:
        MetaMeter(std::string name, std::ostream& outc, Operator* next_op)
            : name_(name), outc_(outc), next_op_(next_op), epoch_count_(0), tups_count_(0) {}
    
        void next(Tuple tup) override {
            tups_count_++;
            next_op_->next(tup);
        }
    
        void reset(Tuple tup) override {
            outc_ << epoch_count_ << "," << name_ << "," << tups_count_ << std::endl;
            tups_count_ = 0;
            epoch_count_++;
            next_op_->reset(tup);
        }
    
    private:
        std::string name_;
        std::ostream& outc_;
        Operator* next_op_;
        int epoch_count_;
        int tups_count_;
    };
    
    // Read Walts CSV
    void readWaltsCSV(std::vector<std::string> file_names, Operator* ops) {
        // implement reading CSV files and applying operators
    }
    
    // Other functions...
    Tuple filterGroups(std::vector<std::string> incl_keys, Tuple tup) {
        Tuple result;
        for (auto& pair : tup) {
            if (std::find(incl_keys.begin(), incl_keys.end(), pair.first) != incl_keys.end()) {
                result[pair.first] = pair.second;
            }
        }
        return result;
    }
    
    Tuple singleGroup(Tuple tup) {
        return Tuple();
    }
    
    OpResult counter(OpResult val, Tuple tup) {
        if (val.type == OpResultType::Empty) {
            return OpResult(1);
        } else {
            return OpResult(int_of_op_result(val) + 1);
        }
    }
    
    OpResult sumInts(std::string search_key, OpResult init_val, Tuple tup) {
        if (init_val.type == OpResultType::Empty) {
            return OpResult(0);
        } else {
            auto it = tup.find(search_key);
            if (it != tup.end()) {
                return OpResult(int_of_op_result(init_val) + int_of_op_result(it->second));
            } else {
                throw std::runtime_error("sum_ints function failed to find integer value");
            }
        }
    }
    
    // Queries
    void ident(Operator* next_op) {
        // implement ident query
    }
    
    void countPkts(Operator* next_op) {
        Epoch* epoch = new Epoch(1.0, "eid", next_op);
        Groupby* groupby = new Groupby(singleGroup, counter, "pkts", epoch);
    }
    
    void pktsPerSrcDst(Operator* next_op) {
        Epoch* epoch = new Epoch(1.0, "eid", next_op);
        Groupby* groupby = new Groupby([](Tuple tup) { return filterGroups({"ipv4.src", "ipv4.dst"}, tup); }, counter, "pkts", epoch);
    }
    
    void distinctSrcs(Operator* next_op) {
        Epoch* epoch = new Epoch(1.0, "eid", next_op);
        Distinct* distinct = new Distinct([](Tuple tup) { return filterGroups({"ipv4.src"}, tup); }, epoch);
        Groupby* groupby = new Groupby(singleGroup, counter, "srcs", distinct);
    }
    
    // Sonata 1
void tcpNewCons(Operator* next_op) {
    Epoch* epoch = new Epoch(1.0, "eid", next_op);
    Filter* filter = new Filter([](Tuple tup) {
        return int_of_op_result(tup["ipv4.proto"]) == 6 && int_of_op_result(tup["l4.flags"]) == 2;
    }, epoch);
    Groupby* groupby = new Groupby([](Tuple tup) { return filterGroups({"ipv4.dst"}, tup); }, counter, "cons", filter);
    Filter* filter_threshold = new Filter([](Tuple tup) { return int_of_op_result(tup["cons"]) >= 40; }, groupby);
}

// Sonata 2
void sshBruteForce(Operator* next_op) {
    Epoch* epoch = new Epoch(1.0, "eid", next_op);
    Filter* filter = new Filter([](Tuple tup) {
        return int_of_op_result(tup["ipv4.proto"]) == 6 && int_of_op_result(tup["l4.dport"]) == 22;
    }, epoch);
    Distinct* distinct = new Distinct([](Tuple tup) { return filterGroups({"ipv4.src", "ipv4.dst", "ipv4.len"}, tup); }, filter);
    Groupby* groupby = new Groupby([](Tuple tup) { return filterGroups({"ipv4.dst", "ipv4.len"}, tup); }, counter, "srcs", distinct);
    Filter* filter_threshold = new Filter([](Tuple tup) { return int_of_op_result(tup["srcs"]) >= 40; }, groupby);
}

// Sonata 3
void superSpreader(Operator* next_op) {
    Epoch* epoch = new Epoch(1.0, "eid", next_op);
    Distinct* distinct = new Distinct([](Tuple tup) { return filterGroups({"ipv4.src", "ipv4.dst"}, tup); }, epoch);
    Groupby* groupby = new Groupby([](Tuple tup) { return filterGroups({"ipv4.src"}, tup); }, counter, "dsts", distinct);
    Filter* filter_threshold = new Filter([](Tuple tup) { return int_of_op_result(tup["dsts"]) >= 40; }, groupby);
}

// Sonata 4
void portScan(Operator* next_op) {
    Epoch* epoch = new Epoch(1.0, "eid", next_op);
    Distinct* distinct = new Distinct([](Tuple tup) { return filterGroups({"ipv4.src", "l4.dport"}, tup); }, epoch);
    Groupby* groupby = new Groupby([](Tuple tup) { return filterGroups({"ipv4.src"}, tup); }, counter, "ports", distinct);
    Filter* filter_threshold = new Filter([](Tuple tup) { return int_of_op_result(tup["ports"]) >= 40; }, groupby);
}

// Sonata 5
void ddos(Operator* next_op) {
    Epoch* epoch = new Epoch(1.0, "eid", next_op);
    Distinct* distinct = new Distinct([](Tuple tup) { return filterGroups({"ipv4.src", "ipv4.dst"}, tup); }, epoch);
    Groupby* groupby = new Groupby([](Tuple tup) { return filterGroups({"ipv4.dst"}, tup); }, counter, "srcs", distinct);
    Filter* filter_threshold = new Filter([](Tuple tup) { return int_of_op_result(tup["srcs"]) >= 45; }, groupby);
}

// Sonata 6
void synFloodSonata(Operator* next_op) {
    Epoch* epoch_syns = new Epoch(1.0, "eid", next_op);
    Filter* filter_syns = new Filter([](Tuple tup) {
        return int_of_op_result(tup["ipv4.proto"]) == 6 && int_of_op_result(tup["l4.flags"]) == 2;
    }, epoch_syns);
    Groupby* groupby_syns = new Groupby([](Tuple tup) { return filterGroups({"ipv4.dst"}, tup); }, counter, "syns", filter_syns);

    Epoch* epoch_synacks = new Epoch(1.0, "eid", next_op);
    Filter* filter_synacks = new Filter([](Tuple tup) {
        return int_of_op_result(tup["ipv4.proto"]) == 6 && int_of_op_result(tup["l4.flags"]) == 18;
    }, epoch_synacks);
    Groupby* groupby_synacks = new Groupby([](Tuple tup) { return filterGroups({"ipv4.src"}, tup); }, counter, "synacks", filter_synacks);

    Epoch* epoch_acks = new Epoch(1.0, "eid", next_op);
    Filter* filter_acks = new Filter([](Tuple tup) {
        return int_of_op_result(tup["ipv4.proto"]) == 6 && int_of_op_result(tup["l4.flags"]) == 16;
    }, epoch_acks);
    Groupby* groupby_acks = new Groupby([](Tuple tup) { return filterGroups({"ipv4.dst"}, tup); }, counter, "acks", filter_acks);

    Join* join1 = new Join([](Tuple tup) {
        Tuple key = filterGroups({"ipv4.dst"}, tup);
        key["host"] = key["ipv4.dst"];
        key.erase("ipv4.dst");
        Tuple vals = filterGroups({"syns", "synacks"}, tup);
        return std::make_pair(key, vals);
    }, [](Tuple tup) {
        Tuple key = filterGroups({"ipv4.src"}, tup);
        key["host"] = key["ipv4.src"];
        key.erase("ipv4.src");
        Tuple vals = filterGroups({"acks"}, tup);
        return std::make_pair(key, vals);
    }, next_op);

    Map* map = new Map([](Tuple tup) {
        tup["syns+synacks-acks"] = OpResult(int_of_op_result(tup["syns"]) + int_of_op_result(tup["synacks"]) - int_of_op_result(tup["acks"]));
        return tup;
    }, join1);

    Filter* filter_threshold = new Filter([](Tuple tup) { return int_of_op_result(tup["syns+synacks-acks"]) >= 3; }, map);

    Join* join2 = new Join([](Tuple tup) {
        Tuple key = filterGroups({"ipv4.dst"}, tup);
        key["host"] = key["ipv4.dst"];
        key.erase("ipv4.dst");
        Tuple vals = filterGroups({"syns"}, tup);
        return std::make_pair(key, vals);
    }, [](Tuple tup) {
        Tuple key = filterGroups({"ipv4.src"}, tup);
        key["host"] = key["ipv4.src"];
        key.erase("ipv4.src");
        Tuple vals = filterGroups({"synacks"}, tup);
        return std::make_pair(key, vals);
    }, filter_threshold);

    Map* map2 = new Map([](Tuple tup) {
        tup["syns+synacks"] = OpResult(int_of_op_result(tup["syns"]) + int_of_op_result(tup["synacks"]));
        return tup;
    }, join2);

    groupby_syns->next(*join2);
    groupby_synacks->next(*join2);
    groupby_acks->next(*join1);
}

// Sonata 7
void completedFlows(Operator* next_op) {
    Epoch* epoch_syns = new Epoch(30.0, "eid", next_op);
    Filter* filter_syns = new Filter([](Tuple tup) {
        return int_of_op_result(tup["ipv4.proto"]) == 6 && int_of_op_result(tup["l4.flags"]) == 2;
    }, epoch_syns);
    Groupby* groupby_syns = new Groupby([](Tuple tup) { return filterGroups({"ipv4.dst"}, tup); }, counter, "syns", filter_syns);

    Epoch* epoch_fins = new Epoch(30.0, "eid", next_op);
    Filter* filter_fins = new Filter([](Tuple tup) {
        return int_of_op_result(tup["ipv4.proto"]) == 6 && (int_of_op_result(tup["l4.flags"]) & 1) == 1;
    }, epoch_fins);
    Groupby* groupby_fins = new Groupby([](Tuple tup) { return filterGroups({"ipv4.src"}, tup); }, counter, "fins", filter_fins);

    Join* join = new Join([](Tuple tup) {
        Tuple key = filterGroups({"ipv4.dst"}, tup);
        key["host"] = key["ipv4.dst"];
        key.erase("ipv4.dst");
        Tuple vals = filterGroups({"syns"}, tup);
        return std::make_pair(key, vals);
    }, [](Tuple tup) {
        Tuple key = filterGroups({"ipv4.src"}, tup);
        key["host"] = key["ipv4.src"];
        key.erase("ipv4.src");
        Tuple vals = filterGroups({"fins"}, tup);
        return std::make_pair(key, vals);
    }, next_op);

    Map* map = new Map([](Tuple tup) {
        tup["diff"] = OpResult(int_of_op_result(tup["syns"]) - int_of_op_result(tup["fins"]));
        return tup;
    }, join);

    Filter* filter_threshold = new Filter([](Tuple tup) { return int_of_op_result(tup["diff"]) >= 1; }, map);

    groupby_syns->next(*join);
    groupby_fins->next(*join);
}

// Sonata 8
void slowloris(Operator* next_op) {
    Epoch* epoch_n_conns = new Epoch(1.0, "eid", next_op);
    Filter* filter_n_conns = new Filter([](Tuple tup) {
        return int_of_op_result(tup["ipv4.proto"]) == 6;
    }, epoch_n_conns);
    Distinct* distinct_n_conns = new Distinct([](Tuple tup) { return filterGroups({"ipv4.src", "ipv4.dst", "l4.sport"}, tup); }, filter_n_conns);
    Groupby* groupby_n_conns = new Groupby([](Tuple tup) { return filterGroups({"ipv4.dst"}, tup); }, counter, "n_conns", distinct_n_conns);
    Filter* filter_n_conns_threshold = new Filter([](Tuple tup) { return int_of_op_result(tup["n_conns"]) >= 5; }, groupby_n_conns);

    Epoch* epoch_n_bytes = new Epoch(1.0, "eid", next_op);
    Filter* filter_n_bytes = new Filter([](Tuple tup) {
        return int_of_op_result(tup["ipv4.proto"]) == 6;
    }, epoch_n_bytes);
    Groupby* groupby_n_bytes = new Groupby([](Tuple tup) { return filterGroups({"ipv4.dst"}, tup); }, [](OpResult val, Tuple tup) {
        return OpResult(int_of_op_result(val) + int_of_op_result(tup["ipv4.len"]));
    }, "n_bytes", filter_n_bytes);
    Filter* filter_n_bytes_threshold = new Filter([](Tuple tup) { return int_of_op_result(tup["n_bytes"]) >= 500; }, groupby_n_bytes);

    Join* join = new Join([](Tuple tup) {
        return std::make_pair(filterGroups({"ipv4.dst"}, tup), filterGroups({"n_conns"}, tup));
    }, [](Tuple tup) {
        return std::make_pair(filterGroups({"ipv4.dst"}, tup), filterGroups({"n_bytes"}, tup));
    }, next_op);

    Map* map = new Map([](Tuple tup) {
        tup["bytes_per_conn"] = OpResult(int_of_op_result(tup["n_bytes"]) / int _of_result(tup["n_conns"]));
        return tup;
    }, join);

    Filter* filter_threshold = new Filter([](Tuple tup) { return int_of_op_result(tup["bytes_per_conn"]) <= 90; }, map);

    groupby_n_conns->next(*join);
    groupby_n_bytes->next(*join);
}

int main() {
    // Create operators and run queries
    DumpTuple dump_tuple(std::cout);
    tcpNewCons(&dump_tuple);
    sshBruteForce(&dump_tuple);
    superSpreader(&dump_tuple);
    portScan(&dump_tuple);
    ddos(&dump_tuple);
    synFloodSonata(&dump_tuple);
    completedFlows(&dump_tuple);
    slowloris(&dump_tuple);
    return 0;
}