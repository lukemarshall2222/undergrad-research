// builtins.hpp
#ifndef BUILTINS_HPP
#define BUILTINS_HPP

#include "common.hpp"
#include <vector>
#include <string>
#include <list> // For read_walts_csv file list

namespace Builtins {

    // --- Constants ---
    const size_t INIT_TABLE_SIZE = 10000; // Hint for unordered_map reserve

    // --- Operator Definitions ---

    Operator dump_tuple(std::ostream& outc, bool show_reset = false);

    Operator dump_as_csv(std::ostream& outc,
                         std::optional<std::pair<std::string, std::string>> static_field = std::nullopt,
                         bool header = true);

    Operator dump_walts_csv(const std::string& filename);

    // Note: read_walts_csv is complex. This is a simplified signature.
    // A full implementation needs careful state management for multiple files.
    void read_walts_csv(const std::vector<std::string>& file_names,
                        const std::vector<Operator>& ops, // Pass operators directly
                        const std::string& epoch_id_key = "eid");


    Operator meta_meter(const std::string& name,
                        std::ostream& outc,
                        Operator next_op, // Pass next operator by value/move
                        std::optional<std::string> static_field = std::nullopt);

    Operator epoch(double epoch_width,
                   const std::string& key_out,
                   Operator next_op);

    // Filter
    using FilterFunc = std::function<bool(const Tuple&)>;
    Operator filter(FilterFunc f, Operator next_op);

    // Filter utility functions (can be implemented as lambdas or standalone funcs)
    FilterFunc key_geq_int(const std::string& key, int64_t threshold);

    // Get mapped values (wrappers around Utils::lookup_*)
    std::function<int64_t(const Tuple&)> get_mapped_int(const std::string& key);
    std::function<double(const Tuple&)> get_mapped_float(const std::string& key);


    // Map
    using MapFunc = std::function<Tuple(const Tuple&)>;
    Operator map(MapFunc f, Operator next_op);

    // Groupby types
    using GroupingFunc = std::function<Tuple(const Tuple&)>;
    using ReductionFunc = std::function<OpResult(OpResult, const Tuple&)>; // Accumulator, Current Tuple -> New Accumulator

    Operator groupby(GroupingFunc groupby_func,
                     ReductionFunc reduce_func,
                     const std::string& out_key,
                     Operator next_op);

    // Groupby utilities
    GroupingFunc filter_groups(const std::vector<std::string>& incl_keys);
    GroupingFunc single_group(); // Returns function that returns empty tuple
    ReductionFunc counter();      // Returns function for counting
    ReductionFunc sum_ints(const std::string& search_key); // Returns function for summing

    // Distinct
    Operator distinct(GroupingFunc groupby_func, Operator next_op);

    // Split
    Operator split(Operator left, Operator right);

    // Join types
    using KeyExtractor = std::function<std::pair<Tuple, Tuple>(const Tuple&)>; // Key, Value tuple pair

    // Join (Returns two operators, one for each input stream)
    std::pair<Operator, Operator> join(KeyExtractor left_extractor,
                                       KeyExtractor right_extractor,
                                       Operator next_op,
                                       const std::string& eid_key = "eid");

    // Join utility
    MapFunc rename_filtered_keys(const std::vector<std::pair<std::string, std::string>>& renamings_pairs);

} // namespace Builtins

#endif // BUILTINS_HPP