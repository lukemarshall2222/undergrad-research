// queries.cpp
#include "queries.hpp"
#include "common.hpp"   // Include Utils namespace
#include "builtins.hpp" // Include Builtins namespace

#include <vector>
#include <string>

namespace Queries {

    using namespace Utils; // Make Utils::chain etc. available
    using namespace Builtins; // Make built-in operators available

    // Helper for Sonata 1 filter condition
    bool filter_tcp_new_cons(const Tuple& tup) {
        try {
             return lookup_int("ipv4.proto", tup) == 6 && // TCP
                    lookup_int("l4.flags", tup) == 2;    // SYN
        } catch (...) { return false; } // Filter out if keys missing/wrong type
    }
    // ... similar helpers for other filters ...


    OpCreator ident() {
        return [](Operator next_op) -> Operator {
             auto remove_eth = [](const Tuple& tup) -> Tuple {
                 Tuple result;
                 for(const auto& pair : tup) {
                     if (pair.first != "eth.src" && pair.first != "eth.dst") {
                         result.insert(pair);
                     }
                 }
                 return result;
             };
             return chain(map(remove_eth), next_op);
        };
    }


    OpCreator count_pkts() {
        return [](Operator next_op) -> Operator {
            return chain(epoch(1.0, "eid"), // Add eid
                   chain(groupby(single_group(), counter(), "pkts"), // Group all, count
                         next_op)); // Pass to final destination
        };
    }

     OpCreator pkts_per_src_dst() {
        return [](Operator next_op) -> Operator {
            std::vector<std::string> keys = {"ipv4.src", "ipv4.dst"};
            return chain(epoch(1.0, "eid"),
                   chain(groupby(filter_groups(keys), counter(), "pkts"),
                         next_op));
        };
    }

    OpCreator distinct_srcs() {
         return [](Operator next_op) -> Operator {
             std::vector<std::string> group_keys = {"ipv4.src"};
             return chain(epoch(1.0, "eid"),
                    chain(distinct(filter_groups(group_keys)), // Find distinct sources per epoch
                    chain(groupby(single_group(), counter(), "srcs"), // Count distinct sources
                          next_op)));
         };
    }

     OpCreator tcp_new_cons(int64_t threshold) {
         return [threshold](Operator next_op) -> Operator {
              std::vector<std::string> group_keys = {"ipv4.dst"};
              FilterFunc filter_cond = [](const Tuple& tup) { /* ... check proto==6 and flags==2 ... */
                   try { return lookup_int("ipv4.proto", tup) == 6 && lookup_int("l4.flags", tup) == 2; }
                   catch(...) { return false; }
              };
              return chain(epoch(1.0, "eid"),
                     chain(filter(filter_cond),
                     chain(groupby(filter_groups(group_keys), counter(), "cons"),
                     chain(filter(key_geq_int("cons", threshold)), // Filter by threshold
                           next_op))));
         };
     }


    // --- Queries with Joins (returning multiple operators) ---

    // Example: syn_flood_sonata (structure only, details omitted for brevity)
     MultiOpCreator syn_flood_sonata(int64_t threshold, double epoch_dur) {
         return [=](Operator final_next_op) -> std::vector<Operator> {
             // Define OpCreators for syns, synacks, acks branches first
             OpCreator syns_creator = [=](Operator next) { /* ... epoch -> filter -> groupby -> next ... */ return Operator();};
             OpCreator synacks_creator = [=](Operator next) { /* ... */ return Operator();};
             OpCreator acks_creator = [=](Operator next) { /* ... */ return Operator();};

             // Define join operators (bottom-up)
             // Inner join (syns + synacks)
             KeyExtractor join1_left_extractor = [](const Tuple& t){ return std::make_pair(rename_filtered_keys({{"ipv4.dst", "host"}})(t), filter_groups({"syns"})(t)); };
             KeyExtractor join1_right_extractor = [](const Tuple& t){ return std::make_pair(rename_filtered_keys({{"ipv4.src", "host"}})(t), filter_groups({"synacks"})(t)); };
             MapFunc join1_map_func = [](const Tuple& t){ /* ... add syns+synacks ... */ return t; };
             DblOpCreator join1_creator = [&](Operator next) {
                  auto [opL, opR] = join(join1_left_extractor, join1_right_extractor, chain(map(join1_map_func), next), "eid");
                  return std::make_pair(opL, opR);
             };

             // Outer join ((syns+synacks) + acks)
             KeyExtractor join2_left_extractor = [](const Tuple& t){ /* ... host, syns+synacks ... */ return std::make_pair(Tuple(),Tuple());};
             KeyExtractor join2_right_extractor = [](const Tuple& t){ /* ... host, acks ... */ return std::make_pair(Tuple(),Tuple());};
             MapFunc join2_map_func = [](const Tuple& t){ /* ... add syns+synacks-acks ... */ return t; };
             FilterFunc final_filter_func = key_geq_int("syns+synacks-acks", threshold);
             DblOpCreator join2_creator = [&](Operator next) {
                  auto [opL, opR] = join(join2_left_extractor, join2_right_extractor, chain(map(join2_map_func), chain(filter(final_filter_func), next)), "eid");
                  return std::make_pair(opL, opR);
             };

             // Chain the joins (this is tricky with the double creators)
             // We need the output operators from join1 to feed into join2's creator input 'next' operator.
             // This requires careful composition. Let's assume chain_double exists.
             // This part needs careful thought on how to wire the creators and operators.
             // Simplified conceptual wiring:

             // Create the final stage (map -> filter -> final_next_op)
             Operator final_stage = chain(map(join2_map_func), chain(filter(final_filter_func), final_next_op));

             // Create the second join, its output feeds the final stage
             auto [join2_opL_creator_input, join2_opR] = join(join2_left_extractor, join2_right_extractor, final_stage, "eid");

             // Create the first join, its output feeds the left input of the second join
             auto [join1_opL, join1_opR] = join(join1_left_extractor, join1_right_extractor, join2_opL_creator_input, "eid");


             // Now create the initial branches feeding the first-level join operators
             Operator syns_branch = syns_creator(join1_opL);
             Operator synacks_branch = synacks_creator(join1_opR);
             Operator acks_branch = acks_creator(join2_opR);

             return {syns_branch, synacks_branch, acks_branch};
         };
     }

    // TODO: Implement other queries (ssh_brute_force, super_spreader, etc.) following similar patterns.
    // Remember to implement helper filter functions for clarity.
    // For join queries (completed_flows, slowloris, join_test), follow the syn_flood_sonata structure.


} // namespace Queries