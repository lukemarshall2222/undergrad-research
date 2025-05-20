#include <cstdint>
#include <string>
#include <map>
#include <unordered_map>
#include <vector>
#include <memory>
#include <functional>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <stdexcept>
#include <optional>
#include <variant>
#include <algorithm>
#include <iostream>
#include <array>

// Forward declarations
class Tuple;

// Represents the op_result variant type
class OpResult {
public:
    enum class Type { Float, Int, IPv4, MAC, Empty };
    virtual ~OpResult() = default;
    virtual Type getType() const = 0;
    virtual std::string toString() const = 0;
    virtual std::unique_ptr<OpResult> clone() const = 0;
};

class FloatResult : public OpResult {
    double value;
public:
    FloatResult(double v) : value(v) {}
    Type getType() const override { return Type::Float; }
    std::string toString() const override { return std::to_string(value); }
    std::unique_ptr<OpResult> clone() const override { return std::make_unique<FloatResult>(value); }
    double getValue() const { return value; }
};

class IntResult : public OpResult {
    int value;
public:
    IntResult(int v) : value(v) {}
    Type getType() const override { return Type::Int; }
    std::string toString() const override { return std::to_string(value); }
    std::unique_ptr<OpResult> clone() const override { return std::make_unique<IntResult>(value); }
    int getValue() const { return value; }
};

class IPv4Result : public OpResult {
    std::string address; // Simplified; real impl might use uint32_t or Ipaddr.V4
public:
    IPv4Result(const std::string& addr) : address(addr) {}
    Type getType() const override { return Type::IPv4; }
    std::string toString() const override { return address; }
    std::unique_ptr<OpResult> clone() const override { return std::make_unique<IPv4Result>(address); }
};

class MACResult : public OpResult {
    std::array<uint8_t, 6> bytes;
public:
    MACResult(const std::string& mac) {
        if (mac.size() != 6) throw std::invalid_argument("Invalid MAC length");
        std::copy(mac.begin(), mac.end(), bytes.begin());
    }
    Type getType() const override { return Type::MAC; }
    std::string toString() const override {
        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        for (size_t i = 0; i < bytes.size(); ++i) {
            oss << std::setw(2) << static_cast<int>(bytes[i]);
            if (i < bytes.size() - 1) oss << ":";
        }
        return oss.str();
    }
    std::unique_ptr<OpResult> clone() const override {
        return std::make_unique<MACResult>(std::string(bytes.begin(), bytes.end()));
    }
};

class EmptyResult : public OpResult {
public:
    Type getType() const override { return Type::Empty; }
    std::string toString() const override { return "Empty"; }
    std::unique_ptr<OpResult> clone() const override { return std::make_unique<EmptyResult>(); }
};

// Tuple is a map from strings to OpResult
class Tuple {
    std::map<std::string, std::unique_ptr<OpResult>> data;
public:
    Tuple() = default;

    void add(const std::string& key, std::unique_ptr<OpResult> value) {
        data[key] = std::move(value);
    }

    std::optional<std::reference_wrapper<const OpResult>> find(const std::string& key) const {
        auto it = data.find(key);
        if (it != data.end()) return it->second.get();
        return std::nullopt;
    }

    std::string toString() const {
        std::ostringstream oss;
        for (const auto& [key, value] : data) {
            oss << "\"" << key << "\" => " << value->toString() << ", ";
        }
        return oss.str();
    }

    // Union operation: prefers left value in case of key collision
    static Tuple unionTuple(const Tuple& left, const Tuple& right) {
        Tuple result = left;
        for (const auto& [key, value] : right.data) {
            if (!result.data.contains(key)) {
                result.data[key] = value->clone();
            }
        }
        return result;
    }

    // Filter keys based on a predicate
    Tuple filterKeys(const std::function<bool(const std::string&)>& pred) const {
        Tuple result;
        for (const auto& [key, value] : data) {
            if (pred(key)) {
                result.add(key, value->clone());
            }
        }
        return result;
    }

    // Iterator for CSV output
    void forEach(const std::function<void(const std::string&, const OpResult&)>& func) const {
        for (const auto& [key, value] : data) {
            func(key, *value);
        }
    }
};

// Operator class
class Operator {
public:
    virtual ~Operator() = default;
    virtual void next(const Tuple& tup) = 0;
    virtual void reset(const Tuple& tup) = 0;
};

// Conversion utilities
int intOfOpResult(const OpResult& result) {
    if (result.getType() != OpResult::Type::Int) {
        throw std::runtime_error("Trying to extract int from non-int result");
    }
    return dynamic_cast<const IntResult&>(result).getValue();
}

double floatOfOpResult(const OpResult& result) {
    if (result.getType() != OpResult::Type::Float) {
        throw std::runtime_error("Trying to extract float from non-float result");
    }
    return dynamic_cast<const FloatResult&>(result).getValue();
}

std::string stringOfMac(const MACResult& mac) {
    return mac.toString();
}

// TCP flags to string
std::string tcpFlagsToStrings(int flags) {
    static const std::map<std::string, int> tcpFlags = {
        {"FIN", 1 << 0}, {"SYN", 1 << 1}, {"RST", 1 << 2}, {"PSH", 1 << 3},
        {"ACK", 1 << 4}, {"URG", 1 << 5}, {"ECE", 1 << 6}, {"CWR", 1 << 7}
    };
    std::string result;
    for (const auto& [name, value] : tcpFlags) {
        if (flags & value) {
            if (!result.empty()) result += "|";
            result += name;
        }
    }
    return result.empty() ? "" : result;
}

// Dump tuple to output
void dumpTuple(std::ostream& out, const Tuple& tup) {
    out << tup.toString() << "\n";
}

// Operator implementations
class DumpTupleOperator : public Operator {
    std::ostream& out;
    bool showReset;
public:
    DumpTupleOperator(std::ostream& out, bool showReset = false)
        : out(out), showReset(showReset) {}

    void next(const Tuple& tup) override {
        dumpTuple(out, tup);
    }

    void reset(const Tuple& tup) override {
        if (showReset) {
            dumpTuple(out, tup);
            out << "[reset]\n";
        }
    }
};

class DumpAsCsvOperator : public Operator {
    std::ostream& out;
    std::optional<std::pair<std::string, std::string>> staticField;
    bool header;
    bool first = true;
public:
    DumpAsCsvOperator(std::ostream& out, std::optional<std::pair<std::string, std::string>> staticField = std::nullopt, bool header = true)
        : out(out), staticField(staticField), header(header), first(header) {}

    void next(const Tuple& tup) override {
        if (first) {
            if (staticField) {
                out << staticField->first << ",";
            }
            tup.forEach([&](const std::string& key, const OpResult&) {
                out << key << ",";
            });
            out << "\n";
            first = false;
        }
        if (staticField) {
            out << staticField->second << ",";
        }
        tup.forEach([&](const std::string&, const OpResult& value) {
            out << value.toString() << ",";
        });
        out << "\n";
    }

    void reset(const Tuple&) override {}
};

class EpochOperator : public Operator {
    double epochWidth;
    std::string keyOut;
    std::unique_ptr<Operator> nextOp;
    double epochBoundary = 0.0;
    int eid = 0;
public:
    EpochOperator(double epochWidth, const std::string& keyOut, std::unique_ptr<Operator> nextOp)
        : epochWidth(epochWidth), keyOut(keyOut), nextOp(std::move(nextOp)) {}

    void next(const Tuple& tup) override {
        double time = floatOfOpResult(*tup.find("time").value());
        if (epochBoundary == 0.0) {
            epochBoundary = time + epochWidth;
        } else if (time >= epochBoundary) {
            while (time >= epochBoundary) {
                Tuple resetTup;
                resetTup.add(keyOut, std::make_unique<IntResult>(eid));
                nextOp->reset(resetTup);
                epochBoundary += epochWidth;
                ++eid;
            }
        }
        Tuple newTup = tup;
        newTup.add(keyOut, std::make_unique<IntResult>(eid));
        nextOp->next(newTup);
    }

    void reset(const Tuple& tup) override {
        Tuple resetTup;
        resetTup.add(keyOut, std::make_unique<IntResult>(eid));
        nextOp->reset(resetTup);
        epochBoundary = 0.0;
        eid = 0;
    }
};

class FilterOperator : public Operator {
    std::function<bool(const Tuple&)> predicate;
    std::unique_ptr<Operator> nextOp;
public:
    FilterOperator(std::function<bool(const Tuple&)> pred, std::unique_ptr<Operator> nextOp)
        : predicate(std::move(pred)), nextOp(std::move(nextOp)) {}

    void next(const Tuple& tup) override {
        if (predicate(tup)) {
            nextOp->next(tup);
        }
    }

    void reset(const Tuple& tup) override {
        nextOp->reset(tup);
    }
};

class MapOperator : public Operator {
    std::function<Tuple(const Tuple&)> mapper;
    std::unique_ptr<Operator> nextOp;
public:
    MapOperator(std::function<Tuple(const Tuple&)> mapper, std::unique_ptr<Operator> nextOp)
        : mapper(std::move(mapper)), nextOp(std::move(nextOp)) {}

    void next(const Tuple& tup) override {
        nextOp->next(mapper(tup));
    }

    void reset(const Tuple& tup) override {
        nextOp->reset(tup);
    }
};

class GroupByOperator : public Operator {
    static constexpr int INIT_TABLE_SIZE = 10000;
    std::function<Tuple(const Tuple&)> groupBy;
    std::function<std::unique_ptr<OpResult>(const OpResult&, const Tuple&)> reduce;
    std::string outKey;
    std::unique_ptr<Operator> nextOp;
    std::unordered_map<Tuple, std::unique_ptr<OpResult>, TupleHash> table;
    int resetCounter = 0;

    struct TupleHash {
        size_t operator()(const Tuple& tup) const {
            size_t hash = 0;
            tup.forEach([&](const std::string& key, const OpResult& value) {
                hash ^= std::hash<std::string>{}(key) ^ std::hash<std::string>{}(value.toString());
            });
            return hash;
        }
    };

    struct TupleEqual {
        bool operator()(const Tuple& lhs, const Tuple& rhs) const {
            // Simplified equality; real impl needs deep comparison
            return lhs.toString() == rhs.toString();
        }
    };

public:
    GroupByOperator(std::function<Tuple(const Tuple&)> groupBy,
                    std::function<std::unique_ptr<OpResult>(const OpResult&, const Tuple&)> reduce,
                    const std::string& outKey, std::unique_ptr<Operator> nextOp)
        : groupBy(std::move(groupBy)), reduce(std::move(reduce)), outKey(outKey), nextOp(std::move(nextOp)),
          table(INIT_TABLE_SIZE, TupleHash{}, TupleEqual{}) {}

    void next(const Tuple& tup) override {
        Tuple groupingKey = groupBy(tup);
        auto it = table.find(groupingKey);
        if (it != table.end()) {
            table[groupingKey] = reduce(*it->second, tup);
        } else {
            table[groupingKey] = reduce(EmptyResult{}, tup);
        }
    }

    void reset(const Tuple& tup) override {
        ++resetCounter;
        for (const auto& [key, value] : table) {
            Tuple unioned = Tuple::unionTuple(tup, key);
            unioned.add(outKey, value->clone());
            nextOp->next(unioned);
        }
        nextOp->reset(tup);
        table.clear();
    }
};

// Utility functions for groupby
Tuple filterGroups(const std::vector<std::string>& inclKeys, const Tuple& tup) {
    return tup.filterKeys([&](const std::string& key) {
        return std::find(inclKeys.begin(), inclKeys.end(), key) != inclKeys.end();
    });
}

Tuple singleGroup(const Tuple&) {
    return Tuple{};
}

std::unique_ptr<OpResult> counter(const OpResult& val, const Tuple&) {
    if (val.getType() == OpResult::Type::Empty) {
        return std::make_unique<IntResult>(1);
    }
    if (val.getType() == OpResult::Type::Int) {
        return std::make_unique<IntResult>(dynamic_cast<const IntResult&>(val).getValue() + 1);
    }
    return val.clone();
}

std::unique_ptr<OpResult> sumInts(const std::string& searchKey, const OpResult& initVal, const Tuple& tup) {
    if (initVal.getType() == OpResult::Type::Empty) {
        return std::make_unique<IntResult>(0);
    }
    if (initVal.getType() == OpResult::Type::Int) {
        auto optVal = tup.find(searchKey);
        if (optVal && optVal->get().getType() == OpResult::Type::Int) {
            int n = intOfOpResult(optVal->get());
            int i = dynamic_cast<const IntResult&>(initVal).getValue();
            return std::make_unique<IntResult>(n + i);
        }
        throw std::runtime_error("sumInts: failed to find integer value for key " + searchKey);
    }
    return initVal.clone();
}

// Main queries
std::unique_ptr<Operator> ident(std::unique_ptr<Operator> nextOp) {
    return std::make_unique<MapOperator>(
        [](const Tuple& tup) {
            return tup.filterKeys([](const std::string& key) {
                return key != "eth.src" && key != "eth.dst";
            });
        }, std::move(nextOp));
}

std::unique_ptr<Operator> countPkts(std::unique_ptr<Operator> nextOp) {
    return std::make_unique<EpochOperator>(1.0, "eid",
        std::make_unique<GroupByOperator>(singleGroup, counter, "pkts", std::move(nextOp)));
}

std::unique_ptr<Operator> pktsPerSrcDst(std::unique_ptr<Operator> nextOp) {
    return std::make_unique<EpochOperator>(1.0, "eid",
        std::make_unique<GroupByOperator>(
            [](const Tuple& tup) { return filterGroups({"ipv4.src", "ipv4.dst"}, tup); },
            counter, "pkts", std::move(nextOp)));
}

// Main entry point
void runQueries() {
    std::vector<std::unique_ptr<Operator>> queries;
    queries.push_back(ident(std::make_unique<DumpTupleOperator>(std::cout)));

    std::vector<Tuple> tuples;
    for (int i = 0; i < 20; ++i) {
        Tuple tup;
        tup.add("time", std::make_unique<FloatResult>(0.0 + i));
        tup.add("eth.src", std::make_unique<MACResult>("\x00\x11\x22\x33\x44\x55"));
        tup.add("eth.dst", std::make_unique<MACResult>("\xAA\xBB\xCC\xDD\xEE\xFF"));
        tup.add("eth.ethertype", std::make_unique<IntResult>(0x0800));
        tup.add("ipv4.hlen", std::make_unique<IntResult>(20));
        tup.add("ipv4.proto", std::make_unique<IntResult>(6));
        tup.add("ipv4.len", std::make_unique<IntResult>(60));
        tup.add("ipv4.src", std::make_unique<IPv4Result>("127.0.0.1"));
        tup.add("ipv4.dst", std::make_unique<IPv4Result>("127.0.0.1"));
        tup.add("l4.sport", std::make_unique<IntResult>(440));
        tup.add("l4.dport", std::make_unique<IntResult>(50000));
        tup.add("l4.flags", std::make_unique<IntResult>(10));
        tuples.push_back(std::move(tup));
    }

    for (const auto& tup : tuples) {
        for (const auto& query : queries) {
            query->next(tup);
        }
    }
}

int main() {
    runQueries();
    std::cout << "Done\n";
    return 0;
}