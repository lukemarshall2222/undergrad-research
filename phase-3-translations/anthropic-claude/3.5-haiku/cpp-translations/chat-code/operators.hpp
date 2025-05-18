#pragma once

#include "types.hpp"
#include <iostream>
#include <unordered_set>

namespace stream_processing {

class OperatorUtils {
public:
    static Operator dumpTuple(std::ostream& out);
    static Operator dumpAsCsv(std::ostream& out);
    static Operator epoch(float width, const std::string& keyOut);
    static Operator filter(std::function<bool(const Tuple&)> predicate);
    static Operator map(std::function<Tuple(const Tuple&)> mapper);
    static Operator groupBy(
        std::function<Tuple(const Tuple&)> grouping,
        std::function<OpResult(const OpResult&, const Tuple&)> reduction,
        const std::string& outKey
    );

    // More utility methods...
};

}  // namespace stream_processing