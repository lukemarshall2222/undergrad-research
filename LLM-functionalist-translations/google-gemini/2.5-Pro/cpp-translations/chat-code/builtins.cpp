// builtins.cpp
#include "builtins.hpp"
#include "common.hpp" // Include Utils namespace
#include <limits> // For numeric_limits
#include <set> // Can be used for distinct if hashing Tuple is problematic initially

namespace Builtins {

// --- Operator Implementations ---

Operator dump_tuple(std::ostream& outc, bool show_reset) {
    // Capture outc and show_reset by value/reference as needed
    auto next_func = [&outc](const Tuple& tup) {
        Utils::dump_tuple(outc, tup);
    };
    auto reset_func = [&outc, show_reset](const Tuple& tup) {
        if (show_reset) {
            Utils::dump_tuple(outc, tup);
            outc << "[reset]" << std::endl;
        }
        // Reset usually propagates, but dump is often terminal.
        // If it needed to propagate: next_op.reset(tup);
    };
    return Operator(next_func, reset_func);
}

Operator dump_as_csv(std::ostream& outc,
                     std::optional<std::pair<std::string, std::string>> static_field,
                     bool header) {
    // State captured in the lambda
    auto first = std::make_shared<bool>(header); // Use shared_ptr for mutable state capture

    auto next_func = [&outc, static_field, first](const Tuple& tup) {
        if (*first) {
             if (static_field) {
                outc << static_field->first << ",";
            }
            bool first_key = true;
            for(const auto& pair : tup) {
                if (!first_key) outc << ",";
                outc << pair.first;
                first_key = false;
            }
            outc << "\n"; // Use newline instead of comma at end
            *first = false;
        }

        if (static_field) {
             outc << static_field->second << ",";
        }
        bool first_val = true;
        for(const auto& pair : tup) {
             if (!first_val) outc << ",";
             outc << Utils::string_of_op_result(pair.second);
             first_val = false;
        }
        outc << "\n"; // Use newline instead of comma at end
        outc.flush(); // Ensure output is written
    };

    auto reset_func = [](const Tuple& /*tup*/) {
        // CSV dump usually doesn't react to resets, but could reset header flag if needed
        // Propagate if necessary: next_op.reset(tup);
    };

    return Operator(next_func, reset_func);
}

Operator dump_walts_csv(const std::string& filename) {
    // State captured: output file stream, first write flag
    // Using shared_ptr to manage the stream lifetime within the lambda captures
    auto out_stream_ptr = std::make_shared<std::ofstream>();
    auto first = std::make_shared<bool>(true);
    // Capture filename by value for use in opening the stream
    std::string captured_filename = filename;

    auto next_func = [out_stream_ptr, first, captured_filename](const Tuple& tup) {
        if (*first) {
            out_stream_ptr->open(captured_filename);
            if (!out_stream_ptr->is_open()) {
                 throw std::runtime_error("Failed to open Walt's CSV file: " + captured_filename);
            }
            // No header in Walt's format example
            *first = false;
        }

        try {
             // Ensure keys exist before accessing (use lookup functions)
             *out_stream_ptr << Utils::string_of_op_result(tup.at("src_ip")) << ","
                            << Utils::string_of_op_result(tup.at("dst_ip")) << ","
                            << Utils::string_of_op_result(tup.at("src_l4_port")) << ","
                            << Utils::string_of_op_result(tup.at("dst_l4_port")) << ","
                            << Utils::string_of_op_result(tup.at("packet_count")) << ","
                            << Utils::string_of_op_result(tup.at("byte_count")) << ","
                            << Utils::string_of_op_result(tup.at("epoch_id")) << "\n";
             out_stream_ptr->flush();
        } catch (const std::out_of_range& oor) {
             std::cerr << "Error: Missing key in dump_walts_csv: " << oor.what() << " in tuple: " << Utils::string_of_tuple(tup) << std::endl;
             // Decide whether to throw, continue, or write default values
        } catch (const std::exception& e) {
            std::cerr << "Error writing Walt's CSV: " << e.what() << std::endl;
            // Handle error appropriately
        }

    };

    auto reset_func = [out_stream_ptr](const Tuple& /*tup*/) {
        // Reset might close the file, or do nothing specific for this operator
         if (out_stream_ptr->is_open()) {
            // Maybe close and reset 'first' flag if needed for multiple runs?
            // out_stream_ptr->close();
         }
        // Propagate if necessary: next_op.reset(tup);
    };

     return Operator(next_func, reset_func);
}


// --- read_walts_csv ---
// This is complex due to multiple file handling, epoch logic, and error checking.
// A full implementation is beyond a simple translation snippet.
// It would involve:
// 1. Struct/class to hold state for each file (ifstream, current eid, tuple count).
// 2. A loop that iterates while any file is active.
// 3. Inside the loop, iterate through active files.
// 4. For each file, try to read a line using `std::getline` and parse using `std::stringstream` or `sscanf`.
// 5. Handle `eof`, parsing errors (`Scanf.Scan_failure`).
// 6. Manage epoch boundaries and call `op.reset` and `op.next` correctly.
// 7. Handle the parallel `ops` list corresponding to `file_names`.
void read_walts_csv(const std::vector<std::string>& file_names,
                        const std::vector<Operator>& ops,
                        const std::string& epoch_id_key) {
     if (file_names.size() != ops.size()) {
         throw std::invalid_argument("read_walts_csv: Number of files and operators must match.");
     }
     std::cerr << "Warning: read_walts_csv implementation is a complex placeholder." << std::endl;
     // TODO: Implement the complex logic described above.
}


Operator meta_meter(const std::string& name,
                        std::ostream& outc,
                        Operator next_op, // Pass by value/move
                        std::optional<std::string> static_field) {
     auto epoch_count = std::make_shared<int64_t>(0);
     auto tups_count = std::make_shared<int64_t>(0);
     // Capture next_op itself if needed (e.g. shared_ptr if lifetime tricky)
     // Operator captured_next_op = std::move(next_op); // Or copy if needed

     auto next_func = [tups_count, next_op](const Tuple& tup) mutable {
         (*tups_count)++;
         next_op.next(tup); // Call next operator
     };

     auto reset_func = [name, &outc, static_field, epoch_count, tups_count, next_op]
                       (const Tuple& tup) mutable {
         outc << *epoch_count << "," << name << "," << *tups_count;
         if (static_field) {
             outc << "," << *static_field;
         }
         outc << std::endl; // endl includes flush

         *tups_count = 0; // Reset count for next epoch
         (*epoch_count)++; // Increment epoch number
         next_op.reset(tup); // Propagate reset
     };

     return Operator(next_func, reset_func);
}


Operator epoch(double epoch_width,
                   const std::string& key_out,
                   Operator next_op) {
     auto epoch_boundary = std::make_shared<double>(0.0);
     auto eid = std::make_shared<int64_t>(0);
     // Capture next_op

     auto next_func = [epoch_width, key_out, epoch_boundary, eid, next_op]
                      (const Tuple& tup) mutable {
         double time = 0.0;
         try {
            time = Utils::lookup_float("time", tup);
         } catch (const std::exception& e) {
            // Handle missing or incorrect "time" field - maybe skip tuple or throw?
            std::cerr << "Epoch operator error: " << e.what() << " in tuple: " << Utils::string_of_tuple(tup) << std::endl;
            return; // Skip tuple if time is invalid/missing
         }


         if (*epoch_boundary == 0.0) { // Use comparison with tolerance for float? Unlikely needed here.
             *epoch_boundary = time + epoch_width;
         } else {
             while (time >= *epoch_boundary) {
                 // Create reset context tuple
                 Tuple reset_context;
                 reset_context[key_out] = OpResult(*eid);
                 next_op.reset(reset_context);

                 *epoch_boundary += epoch_width;
                 (*eid)++;
             }
         }
         // Add epoch ID to tuple and pass downstream
         Tuple next_tup = tup; // Copy tuple
         next_tup[key_out] = OpResult(*eid);
         next_op.next(next_tup);
     };

     auto reset_func = [key_out, epoch_boundary, eid, next_op]
                       (const Tuple& /*tup*/) mutable { // Incoming reset context often ignored here
         // Reset the last epoch ID
         Tuple reset_context;
         reset_context[key_out] = OpResult(*eid);
         next_op.reset(reset_context);

         // Reset internal state
         *epoch_boundary = 0.0;
         *eid = 0;
     };

     return Operator(next_func, reset_func);
}

// --- Filter ---
Operator filter(FilterFunc f, Operator next_op) {
     auto next_func = [f, next_op](const Tuple& tup) mutable {
         if (f(tup)) {
             next_op.next(tup);
         }
     };
     auto reset_func = [next_op](const Tuple& tup) mutable {
         next_op.reset(tup); // Resets always propagate
     };
     return Operator(next_func, reset_func);
}

FilterFunc key_geq_int(const std::string& key, int64_t threshold) {
     // Return a lambda that captures key and threshold
     return [key, threshold](const Tuple& tup) -> bool {
         try {
             int64_t val = Utils::lookup_int(key, tup);
             return val >= threshold;
         } catch (const std::exception& e) {
             // Handle missing key or wrong type - typically filter out
             std::cerr << "Filter key_geq_int warning: " << e.what() << " for key '" << key << "' in tuple: " << Utils::string_of_tuple(tup) << std::endl;
             return false;
         }
     };
}

std::function<int64_t(const Tuple&)> get_mapped_int(const std::string& key) {
    return [key](const Tuple& tup) -> int64_t {
         // Let Utils::lookup_int handle exceptions
         return Utils::lookup_int(key, tup);
    };
}

std::function<double(const Tuple&)> get_mapped_float(const std::string& key) {
    return [key](const Tuple& tup) -> double {
         return Utils::lookup_float(key, tup);
    };
}

// --- Map ---
Operator map(MapFunc f, Operator next_op) {
      auto next_func = [f, next_op](const Tuple& tup) mutable {
         Tuple mapped_tup = f(tup); // Apply mapping function
         next_op.next(mapped_tup);
     };
     auto reset_func = [next_op](const Tuple& tup) mutable {
         next_op.reset(tup); // Resets propagate
     };
     return Operator(next_func, reset_func);
}


// --- Groupby ---
Operator groupby(GroupingFunc groupby_func,
                     ReductionFunc reduce_func,
                     const std::string& out_key,
                     Operator next_op) {
    // State: Hashtable (unordered_map) storing aggregated results per group
    // Use shared_ptr for the map to manage lifetime across lambda captures
    auto h_tbl_ptr = std::make_shared<std::unordered_map<Tuple, OpResult>>();
    h_tbl_ptr->reserve(INIT_TABLE_SIZE); // Pre-allocate hint

    auto next_func = [h_tbl_ptr, groupby_func, reduce_func]
                     (const Tuple& tup) mutable {
        Tuple grouping_key = groupby_func(tup);
        auto& h_tbl = *h_tbl_ptr; // Dereference pointer

        auto it = h_tbl.find(grouping_key);
        if (it != h_tbl.end()) {
            // Key exists, apply reduction with existing value
            it->second = reduce_func(it->second, tup);
        } else {
            // Key doesn't exist, apply reduction with 'Empty' (monostate)
            OpResult initial_val = std::monostate{};
            h_tbl[grouping_key] = reduce_func(initial_val, tup);
        }
    };

    auto reset_func = [h_tbl_ptr, out_key, next_op]
                      (const Tuple& reset_context) mutable {
        auto& h_tbl = *h_tbl_ptr;

        // Iterate through the groups in the hash table
        for (const auto& pair : h_tbl) {
            const Tuple& grouping_key = pair.first;
            const OpResult& aggregated_val = pair.second;

            // Merge reset_context, grouping_key, and aggregated_val
            Tuple output_tup = reset_context; // Start with reset context
            // Add grouping key fields (they overwrite context if names clash)
            output_tup.insert(grouping_key.begin(), grouping_key.end());
            // Add the aggregated result under out_key
            output_tup[out_key] = aggregated_val;

            next_op.next(output_tup); // Pass each aggregated group downstream
        }

        next_op.reset(reset_context); // Propagate the original reset context
        h_tbl.clear(); // Clear the table for the next epoch
    };

    return Operator(next_func, reset_func);
}

// Groupby utilities
GroupingFunc filter_groups(const std::vector<std::string>& incl_keys) {
    // Capture incl_keys by value
    return [keys = incl_keys](const Tuple& tup) -> Tuple {
        Tuple result;
        for (const std::string& key : keys) {
            auto it = tup.find(key);
            if (it != tup.end()) {
                result[key] = it->second;
            }
        }
        return result;
    };
}

GroupingFunc single_group() {
    return [](const Tuple& /*tup*/) -> Tuple {
        return Tuple{}; // Return an empty map
    };
}

ReductionFunc counter() {
    return [](OpResult current_val, const Tuple& /*tup*/) -> OpResult {
        if (std::holds_alternative<std::monostate>(current_val)) {
            return OpResult(static_cast<int64_t>(1)); // Start counting at 1
        } else if (std::holds_alternative<int64_t>(current_val)) {
            return OpResult(std::get<int64_t>(current_val) + 1); // Increment
        } else {
            // Should not happen if used correctly, return current value or throw
             std::cerr << "Counter error: Unexpected accumulator type: " << Utils::string_of_op_result(current_val) << std::endl;
             return current_val; // Or throw std::runtime_error("Counter error");
        }
    };
}

ReductionFunc sum_ints(const std::string& search_key) {
    return [search_key](OpResult current_val, const Tuple& tup) -> OpResult {
        int64_t current_sum = 0;
        if (std::holds_alternative<std::monostate>(current_val)) {
            current_sum = 0; // Initial value
        } else if (std::holds_alternative<int64_t>(current_val)) {
            current_sum = std::get<int64_t>(current_val);
        } else {
             std::cerr << "Sum_ints error: Unexpected accumulator type: " << Utils::string_of_op_result(current_val) << std::endl;
            // Decide error handling: return current, throw, return special error value?
            return current_val;
        }

        try {
            int64_t value_to_add = Utils::lookup_int(search_key, tup);
            return OpResult(current_sum + value_to_add);
        } catch (const std::exception& e) {
            std::cerr << "Sum_ints error: Failed to find/convert key '" << search_key << "': " << e.what() << " in tuple " << Utils::string_of_tuple(tup) << std::endl;
             // Decide error handling: return current sum, throw, etc.
             return OpResult(current_sum); // Return current sum if lookup fails
        }
    };
}

// --- Distinct ---
Operator distinct(GroupingFunc groupby_func, Operator next_op) {
    // State: Hashtable storing unique keys encountered in the epoch
    // Value can be simple bool or the first tuple encountered for that key if needed
    auto h_tbl_ptr = std::make_shared<std::unordered_map<Tuple, Tuple>>(); // Store tuple itself
    h_tbl_ptr->reserve(INIT_TABLE_SIZE);

    auto next_func = [h_tbl_ptr, groupby_func](const Tuple& tup) mutable {
        Tuple grouping_key = groupby_func(tup);
        auto& h_tbl = *h_tbl_ptr;
        // Add/overwrite the key. If we only care about existence, value could be bool.
        // Storing the original tuple allows emitting it on reset.
        // OCaml version used bool, let's stick to that for directness
        // auto h_tbl_bool_ptr = std::make_shared<std::unordered_map<Tuple, bool>>();
         h_tbl[grouping_key] = tup; // Store the full tuple associated with the key
         // If only tracking keys: h_tbl[grouping_key] = true;
    };

    auto reset_func = [h_tbl_ptr, next_op](const Tuple& reset_context) mutable {
        auto& h_tbl = *h_tbl_ptr;

        // Iterate through the unique items found
        for (const auto& pair : h_tbl) {
            //const Tuple& grouping_key = pair.first;
             const Tuple& representative_tup = pair.second; // Use the stored tuple

            // OCaml merges reset context and key. If we store the full tuple, maybe just pass that?
            // Let's follow OCaml's merge logic:
            Tuple output_tup = reset_context;
            // Merge the representative tuple fields (overwriting context if names clash)
            output_tup.insert(representative_tup.begin(), representative_tup.end());

            next_op.next(output_tup);
        }

        next_op.reset(reset_context); // Propagate reset
        h_tbl.clear(); // Clear for next epoch
    };

    return Operator(next_func, reset_func);
}


// --- Split ---
Operator split(Operator left, Operator right) {
     // Capture left and right operators
     auto next_func = [left, right](const Tuple& tup) {
         left.next(tup);
         right.next(tup);
     };
     auto reset_func = [left, right](const Tuple& tup) {
         left.reset(tup);
         right.reset(tup);
     };
     return Operator(next_func, reset_func);
}

// --- Join ---
// This is highly complex due to state management, epoch synchronization, and merging.
// The OCaml version uses two hash tables and epoch counters.
std::pair<Operator, Operator> join(KeyExtractor left_extractor,
                                       KeyExtractor right_extractor,
                                       Operator next_op,
                                       const std::string& eid_key) {
    // State shared between the two sides of the join:
    auto h_tbl1_ptr = std::make_shared<std::unordered_map<Tuple, Tuple>>(); // Key -> Value Tuple
    auto h_tbl2_ptr = std::make_shared<std::unordered_map<Tuple, Tuple>>();
    h_tbl1_ptr->reserve(INIT_TABLE_SIZE);
    h_tbl2_ptr->reserve(INIT_TABLE_SIZE);
    auto left_curr_epoch_ptr = std::make_shared<int64_t>(0);
    auto right_curr_epoch_ptr = std::make_shared<int64_t>(0);

    // Helper lambda for join logic (avoids code duplication)
    auto handle_join_side =
        [&](std::shared_ptr<std::unordered_map<Tuple, Tuple>> curr_h_tbl_ptr,
            std::shared_ptr<std::unordered_map<Tuple, Tuple>> other_h_tbl_ptr,
            std::shared_ptr<int64_t> curr_epoch_ref_ptr,
            std::shared_ptr<int64_t> other_epoch_ref_ptr,
            KeyExtractor extractor, // Capture extractor by value/copy
            Operator captured_next_op, // Capture next_op
            std::string captured_eid_key // Capture eid_key
            ) -> Operator
    {
        auto next_func = [=](const Tuple& tup) mutable {
            auto& curr_h_tbl = *curr_h_tbl_ptr;
            auto& other_h_tbl = *other_h_tbl_ptr;
            auto& curr_epoch_ref = *curr_epoch_ref_ptr;
            auto& other_epoch_ref = *other_epoch_ref_ptr;

            int64_t current_epoch = 0;
             try {
                current_epoch = Utils::lookup_int(captured_eid_key, tup);
             } catch (const std::exception& e) {
                 std::cerr << "Join error: Missing or invalid epoch key '" << captured_eid_key << "': " << e.what() << std::endl;
                 return; // Skip tuple if epoch is missing/invalid
             }

            // Advance current epoch counter if needed, emitting resets for next_op
            while (current_epoch > curr_epoch_ref) {
                if (other_epoch_ref > curr_epoch_ref) { // Only reset if other side also advanced past this epoch
                     Tuple reset_context;
                     reset_context[captured_eid_key] = OpResult(curr_epoch_ref);
                     captured_next_op.reset(reset_context);
                }
                curr_epoch_ref++;
            }

            // Extract key and value tuples using the provided extractor
            std::pair<Tuple, Tuple> extracted = extractor(tup);
            Tuple key = std::move(extracted.first);
            Tuple vals = std::move(extracted.second);

            // Create the lookup key (Key + Epoch ID)
            Tuple lookup_key = key;
            lookup_key[captured_eid_key] = OpResult(current_epoch);


            // Check the *other* table for a match
            auto it = other_h_tbl.find(lookup_key);
            if (it != other_h_tbl.end()) {
                // Match found! Merge and emit
                Tuple matched_val = it->second;
                other_h_tbl.erase(it); // Remove from other table after matching

                // Merge: lookup_key (contains original key + eid) + vals + matched_val
                Tuple merged_tup = lookup_key; // Start with key + eid
                merged_tup.insert(vals.begin(), vals.end()); // Add this side's values
                merged_tup.insert(matched_val.begin(), matched_val.end()); // Add other side's values

                captured_next_op.next(merged_tup);
            } else {
                // No match found, store in *this* table
                 curr_h_tbl[lookup_key] = vals; // Store this side's values, keyed by key+eid
            }
        };

        auto reset_func = [=](const Tuple& reset_context) mutable {
             auto& curr_epoch_ref = *curr_epoch_ref_ptr;
             auto& other_epoch_ref = *other_epoch_ref_ptr;

             int64_t reset_epoch = -1; // Default if key is missing
              try {
                 reset_epoch = Utils::lookup_int(captured_eid_key, reset_context);
             } catch (const std::exception& e) {
                 std::cerr << "Join reset warning: Missing or invalid epoch key '" << captured_eid_key << "': " << e.what() << std::endl;
                 // Decide how to proceed: use current epoch, default, or throw?
                 // OCaml likely uses current epoch if key is missing, let's try that
                 reset_epoch = curr_epoch_ref;
                 // Or maybe just propagate the context as-is without advancing?
                 // captured_next_op.reset(reset_context); return;
             }

             // Advance epoch counter based on reset context epoch, emitting resets
             while (reset_epoch > curr_epoch_ref) {
                  if (other_epoch_ref > curr_epoch_ref) {
                     Tuple downstream_reset_context;
                     downstream_reset_context[captured_eid_key] = OpResult(curr_epoch_ref);
                     captured_next_op.reset(downstream_reset_context);
                 }
                 curr_epoch_ref++;
             }
             // TODO: Consider cleaning up expired entries from hash tables based on epoch?
             // The OCaml version doesn't explicitly show cleanup in reset, relies on matching.

             // Propagate the original reset context? Or the one potentially created above?
             // OCaml seems implicitly uses the singleton {eid_key: eid} tuple. Let's stick to that idea.
             // If reset_epoch was validly read, use it.
             if (reset_epoch >= 0) {
                 Tuple final_reset_context;
                 final_reset_context[captured_eid_key] = OpResult(reset_epoch);
                  // If we always advanced up to reset_epoch, maybe use curr_epoch_ref?
                  // final_reset_context[captured_eid_key] = OpResult(curr_epoch_ref);
                 captured_next_op.reset(final_reset_context);
             } else {
                  // Propagate original if epoch lookup failed in reset
                  captured_next_op.reset(reset_context);
             }


        };
        return Operator(next_func, reset_func);
    };

    // Create the left and right operators using the helper
    Operator left_op = handle_join_side(h_tbl1_ptr, h_tbl2_ptr, left_curr_epoch_ptr, right_curr_epoch_ptr, left_extractor, next_op, eid_key);
    Operator right_op = handle_join_side(h_tbl2_ptr, h_tbl1_ptr, right_curr_epoch_ptr, left_curr_epoch_ptr, right_extractor, next_op, eid_key);

    return {left_op, right_op};
}


// Join utility
MapFunc rename_filtered_keys(const std::vector<std::pair<std::string, std::string>>& renamings_pairs) {
    return [renamings = renamings_pairs](const Tuple& in_tup) -> Tuple {
        Tuple new_tup;
        for (const auto& pair : renamings) {
            const std::string& old_key = pair.first;
            const std::string& new_key = pair.second;
            auto it = in_tup.find(old_key);
            if (it != in_tup.end()) {
                new_tup[new_key] = it->second; // Add with the new key
            }
        }
        return new_tup;
    };
}


} // namespace Builtins