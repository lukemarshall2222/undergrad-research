#pragma once

#include "types.hpp"
#include "advanced_operators.hpp"
#include <vector>
#include <memory>

namespace stream_processing {

class StreamingPipeline {
public:
    // Create a pipeline with multiple operators
    StreamingPipeline& addOperator(Operator op) {
        operators.push_back(std::move(op));
        return *this;
    }

    // Process a batch of tuples
    void processBatch(const std::vector<Tuple>& tuples) {
        for (const auto& tup : tuples) {
            for (auto& op : operators) {
                op.next(tup);
            }
        }
    }

    // Reset all operators
    void reset(const Tuple& resetTuple) {
        for (auto& op : operators) {
            op.reset(resetTuple);
        }
    }

private:
    std::vector<Operator> operators;
};

// Operator composition utility
Operator operator|(Operator lhs, Operator rhs) {
    return {
        [lhs, rhs](const Tuple& tup) {
            // Pass through the pipeline
            lhs.next(tup);
            rhs.next(tup);
        },
        [lhs, rhs](const Tuple& tup) {
            // Reset both operators
            lhs.reset(tup);
            rhs.reset(tup);
        }
    };
}

} // namespace stream_processing