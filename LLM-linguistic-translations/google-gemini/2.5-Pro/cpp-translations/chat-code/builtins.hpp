#ifndef BUILTINS_HPP
#define BUILTINS_HPP

#include "common_utils.hpp"
#include <string>
#include <vector>
#include <list> // For read_walts_csv input filenames
#include <map> // For Hashtbl equivalent state
#include <set> // Alternative for distinct keys if values don't matter


namespace Builtins {

    using namespace Utils; // Use types from Utils namespace

    constexpr int INIT_TABLE_SIZE = 10000; // Used as hint if using unordered_map

    // --- Dump Operators ---
    Operator dump_tuple_op(std::ostream& outc, bool show_reset = false);
    Operator dump_as_csv(std::ostream& outc,
                         std::optional<std::pair<std::string, std::string>> static_field = std::nullopt,
                         bool header = true);
    Operator dump_walts_csv(const std::string& filename);

    // --- Input Operators ---
    OpResult get_ip_or_zero(const std::string& input);
    void read_walts_csv(const std::vector<std::string>& file_names,
                        const std::vector<Operator>& ops, // Match OCaml: one op per file
                        const std::string& epoch_id_key = "eid");

    // --- Meta Operators ---
    Operator meta_meter(const std::string& name,
                        std::ostream& outc,
                        Operator next_op,
                        std::optional<std::string> static_field = std::nullopt);

    // --- Core Stream Operators ---
    Operator epoch(double epoch_width, const std::string& key_out, Operator next_op);
    Operator filter(std::function<bool(const Tuple&)> f, Operator next_op);
    Operator map(std::function<Tuple(const Tuple&)> f, Operator next_op);

    // --- Groupby/Distinct Related ---
    using GroupingFunc = std::function<Tuple(const Tuple&)>;
    using ReductionFunc = std::function<OpResult(OpResult, const Tuple&)>;

    Operator groupby(GroupingFunc group_by_func,
                     ReductionFunc reduce_func,
                     const std::string& out_key,
                     Operator next_op);

    Operator distinct(GroupingFunc group_by_func, Operator next_op);

    // Groupby Utilities
    Tuple filter_groups(const std::vector<std::string>& incl_keys, const Tuple& tup);
    Tuple single_group(const Tuple&); // Grouping function for a single group
    OpResult counter(OpResult current_val, const Tuple& tup); // Reduction: count tuples
    OpResult sum_ints(const std::string& search_key, OpResult init_val, const Tuple& tup); // Reduction: sum int field


    // --- Split/Join Operators ---
    Operator split(Operator left, Operator right);

    using KeyExtractor = std::function<std::pair<Tuple, Tuple>(const Tuple&)>;

    std::pair<Operator, Operator> join(KeyExtractor left_extractor,
                                       KeyExtractor right_extractor,
                                       Operator next_op,
                                       const std::string& eid_key = "eid");

    // Join Utility
    Tuple rename_filtered_keys(const std::vector<std::pair<std::string, std::string>>& renamings,
                               const Tuple& in_tup);

    // --- Filter Utilities ---
    bool key_geq_int(const std::string& key, int threshold, const Tuple& tup);
    int get_mapped_int(const std::string& key, const Tuple& tup);   // Convenience alias
    double get_mapped_float(const std::string& key, const Tuple& tup); // Convenience alias


} // namespace Builtins

#endif // BUILTINS_HPP