#include "operators.hpp"
#include <iomanip>
#include <sstream>

namespace stream_processing {

Operator OperatorUtils::dumpTuple(std::ostream& out) {
    return {
        [&out](const Tuple& tup) {
            for (const auto& [key, value] : tup) {
                out << "\"" << key << "\" => ";
                switch (value.getType()) {
                    case OpResultType::Float:
                        out << value.get<float>();
                        break;
                    case OpResultType::Int:
                        out << value.get<int>();
                        break;
                    case OpResultType::IPv4:
                        out << value.get<IPv4Address>().toString();
                        break;
                    case OpResultType::MAC:
                        out << value.get<MACAddress>().toString();
                        break;
                    case OpResultType::Empty:
                        out << "Empty";
                        break;
                }
                out << ", ";
            }
            out << std::endl;
        },
        [](const Tuple&) {} // empty reset
    };
}

Operator OperatorUtils::dumpAsCsv(std::ostream& out) {
    static bool firstRow = true;
    return {
        [&out, firstRow](const Tuple& tup) mutable {
            if (firstRow) {
                // Print header
                for (const auto& [key, _] : tup) {
                    out << key << ",";
                }
                out << std::endl;
                firstRow = false;
            }

            // Print values
            for (const auto& [_, value] : tup) {
                switch (value.getType()) {
                    case OpResultType::Float:
                        out << value.get<float>() << ",";
                        break;
                    case OpResultType::Int:
                        out << value.get<int>() << ",";
                        break;
                    case OpResultType::IPv4:
                        out << value.get<IPv4Address>().toString() << ",";
                        break;
                    case OpResultType::MAC:
                        out << value.get<MACAddress>().toString() << ",";
                        break;
                    case OpResultType::Empty:
                        out << ",";
                        break;
                }
            }
            out << std::endl;
        },
        [](const Tuple&) {} // empty reset
    };
}

Operator OperatorUtils::epoch(float width, const std::string& keyOut) {
    float epochBoundary = 0.0;
    int epochId = 0;

    return {
        [=](const Tuple& tup) mutable {
            float time = tup.at("time").get<float>();

            if (epochBoundary == 0.0) {
                epochBoundary = time + width;
            }

            while (time >= epochBoundary) {
                // Reset operation for each passed epoch
                Tuple resetTuple;
                resetTuple[keyOut] = OpResult(epochId);

                epochBoundary += width;
                epochId++;
            }

            // Add epoch ID to the tuple
            Tuple newTup = tup;
            newTup[keyOut] = OpResult(epochId);
        },
        [](const Tuple&) {} // empty reset
    };
}

Operator OperatorUtils::filter(std::function<bool(const Tuple&)> predicate) {
    return {
        [predicate](const Tuple& tup) {
            if (predicate(tup)) {
                // Pass to next operator (not implemented in this example)
            }
        },
        [](const Tuple&) {} // empty reset
    };
}

Operator OperatorUtils::map(std::function<Tuple(const Tuple&)> mapper) {
    return {
        [mapper](const Tuple& tup) {
            Tuple mappedTup = mapper(tup);
            // Pass to next operator (not implemented in this example)
        },
        [](const Tuple&) {} // empty reset
    };
}

Operator OperatorUtils::groupBy(
    std::function<Tuple(const Tuple&)> grouping,
    std::function<OpResult(const OpResult&, const Tuple&)> reduction,
    const std::string& outKey
) {
    std::unordered_map<Tuple, OpResult> groups;

    return {
        [=](const Tuple& tup) mutable {
            Tuple groupKey = grouping(tup);

            auto it = groups.find(groupKey);
            if (it != groups.end()) {
                // Reduce existing group
                it->second = reduction(it->second, tup);
            } else {
                // Create new group
                groups[groupKey] = reduction(OpResult(), tup);
            }
        },
        [outKey](const Tuple& resetTup) {
            // Implement reset logic for groups
        }
    };
}

// Utility functions for group reduction
OpResult counterReduction(const OpResult& current, const Tuple&) {
    if (current.getType() == OpResultType::Empty) {
        return OpResult(1);
    }
    return OpResult(current.get<int>() + 1);
}

} // namespace stream_processing