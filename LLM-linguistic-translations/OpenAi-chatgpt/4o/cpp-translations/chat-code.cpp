#include <iostream>
#include <iomanip>
#include <string>
#include <map>
#include <unordered_map>
#include <variant>
#include <vector>
#include <array>
#include <sstream>
#include <functional>
#include <set>
#include <memory>
#include <stdexcept>

class IPv4Addr {
public:
    explicit IPv4Addr(const std::string& addr) : address(addr) {}
    std::string to_string() const { return address; }
    bool operator==(const IPv4Addr& o) const { return address == o.address; }
    bool operator<(const IPv4Addr& o) const { return address < o.address; }
private:
    std::string address;
};

using MACAddr = std::array<uint8_t, 6>;

using OpResult = std::variant<std::monostate, int, float, IPv4Addr, MACAddr>;
using Tuple = std::map<std::string, OpResult>;

std::string to_string(const OpResult& val) {
    struct {
        std::string operator()(std::monostate) const { return "Empty"; }
        std::string operator()(int i) const { return std::to_string(i); }
        std::string operator()(float f) const {
            std::ostringstream oss; oss << std::fixed << std::setprecision(6) << f; return oss.str();
        }
        std::string operator()(const IPv4Addr& ip) const { return ip.to_string(); }
        std::string operator()(const MACAddr& mac) const {
            std::ostringstream oss;
            for (size_t i = 0; i < 6; ++i) {
                if (i > 0) oss << ":";
                oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(mac[i]);
            }
            return oss.str();
        }
    } visitor;
    return std::visit(visitor, val);
}

int get_int(const OpResult& v) {
    if (auto p = std::get_if<int>(&v)) return *p;
    throw std::runtime_error("Expected int");
}

float get_float(const OpResult& v) {
    if (auto p = std::get_if<float>(&v)) return *p;
    throw std::runtime_error("Expected float");
}

std::string tuple_to_string(const Tuple& tup) {
    std::ostringstream oss;
    for (const auto& [k, v] : tup)
        oss << "\"" << k << "\" => " << to_string(v) << ", ";
    return oss.str();
}

void print_tuple(const Tuple& tup) {
    std::cout << tuple_to_string(tup) << "\n";
}

Tuple merge_tuples(const Tuple& a, const Tuple& b) {
    Tuple result = a;
    result.insert(b.begin(), b.end());
    return result;
}


struct Operator {
    virtual void next(const Tuple&) = 0;
    virtual void reset(const Tuple&) = 0;
    virtual ~Operator() = default;
};

using OperatorPtr = std::shared_ptr<Operator>;
using OpCreator = std::function<OperatorPtr(OperatorPtr)>;
using DblOpCreator = std::function<std::pair<OperatorPtr, OperatorPtr>(OperatorPtr)>;

OperatorPtr operator>>(OpCreator a, OperatorPtr b) { return a(b); }
std::pair<OperatorPtr, OperatorPtr> operator>>(DblOpCreator a, OperatorPtr b) { return a(b); }


class DumpTuple : public Operator {
public:
    explicit DumpTuple(bool show = false) : showReset(show) {}
    void next(const Tuple& t) override { print_tuple(t); }
    void reset(const Tuple& t) override {
        if (showReset) {
            print_tuple(t);
            std::cout << "[reset]\n";
        }
    }
private:
    bool showReset;
};

class FilterMap : public Operator {
public:
    explicit FilterMap(OperatorPtr next) : nextOp(std::move(next)) {}
    void next(const Tuple& t) override {
        Tuple filtered;
        for (const auto& [k, v] : t)
            if (k != "eth.src" && k != "eth.dst")
                filtered[k] = v;
        nextOp->next(filtered);
    }
    void reset(const Tuple& t) override { nextOp->reset(t); }
private:
    OperatorPtr nextOp;
};

OpCreator ident = [](OperatorPtr next) {
    return std::make_shared<FilterMap>(next);
};

class Epoch : public Operator {
public:
    Epoch(float width, std::string key, OperatorPtr next)
        : epochWidth(width), keyOut(std::move(key)), nextOp(std::move(next)) {}

    void next(const Tuple& tup) override {
        float time = get_float(tup.at("time"));
        if (epochBoundary == 0.0f) epochBoundary = time + epochWidth;
        else if (time >= epochBoundary) {
            while (time >= epochBoundary) {
                Tuple resetTup = {{keyOut, epochId}};
                nextOp->reset(resetTup);
                epochBoundary += epochWidth;
                ++epochId;
            }
        }
        Tuple out = tup;
        out[keyOut] = epochId;
        nextOp->next(out);
    }

    void reset(const Tuple&) override {
        nextOp->reset({{keyOut, epochId}});
        epochBoundary = 0.0f;
        epochId = 0;
    }

private:
    float epochWidth, epochBoundary = 0.0f;
    int epochId = 0;
    std::string keyOut;
    OperatorPtr nextOp;
};

OpCreator epoch(float width, std::string key) {
    return [=](OperatorPtr next) {
        return std::make_shared<Epoch>(width, key, next);
    };
}

class Filter : public Operator {
public:
    using Predicate = std::function<bool(const Tuple&)>;
    Filter(Predicate pred, OperatorPtr next) : pred(std::move(pred)), nextOp(std::move(next)) {}
    void next(const Tuple& tup) override { if (pred(tup)) nextOp->next(tup); }
    void reset(const Tuple& tup) override { nextOp->reset(tup); }
private:
    Predicate pred;
    OperatorPtr nextOp;
};

OpCreator filter(Filter::Predicate pred) {
    return [=](OperatorPtr next) {
        return std::make_shared<Filter>(pred, next);
    };
}

class MapOp : public Operator {
public:
    using Mapper = std::function<Tuple(const Tuple&)>;
    MapOp(Mapper m, OperatorPtr next) : mapFn(std::move(m)), nextOp(std::move(next)) {}
    void next(const Tuple& tup) override { nextOp->next(mapFn(tup)); }
    void reset(const Tuple& tup) override { nextOp->reset(tup); }
private:
    Mapper mapFn;
    OperatorPtr nextOp;
};

OpCreator map(MapOp::Mapper fn) {
    return [=](OperatorPtr next) {
        return std::make_shared<MapOp>(fn, next);
    };
}

int get_mapped_int(const std::string& key, const Tuple& tup) {
    return get_int(tup.at(key));
}

bool key_geq_int(const std::string& key, int threshold, const Tuple& tup) {
    return get_mapped_int(key, tup) >= threshold;
}

std::function<Tuple(const Tuple&)> filter_keys(const std::vector<std::string>& keys) {
    return [=](const Tuple& tup) {
        Tuple out;
        for (const auto& key : keys) {
            auto it = tup.find(key);
            if (it != tup.end()) out[key] = it->second;
        }
        return out;
    };
}

int main() {
    OperatorPtr printer = std::make_shared<DumpTuple>(true);
    OperatorPtr pipeline = epoch(1.0, "eid") >> ident >> printer;

    for (int i = 0; i < 20; ++i) {
        Tuple tup;
        tup["time"] = static_cast<float>(i);
        tup["eth.src"] = MACAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
        tup["eth.dst"] = MACAddr{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
        tup["eth.ethertype"] = 0x0800;
        tup["ipv4.hlen"] = 20;
        tup["ipv4.proto"] = 6;
        tup["ipv4.len"] = 60;
        tup["ipv4.src"] = IPv4Addr("127.0.0.1");
        tup["ipv4.dst"] = IPv4Addr("127.0.0.1");
        tup["l4.sport"] = 440;
        tup["l4.dport"] = 50000;
        tup["l4.flags"] = 10;

        pipeline->next(tup);
    }

    pipeline->reset({});
    std::cout << "Done\n";
    return 0;
}
