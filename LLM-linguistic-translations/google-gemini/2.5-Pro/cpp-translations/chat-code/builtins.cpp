#include "builtins.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <memory> // For shared_ptr if needed for state capture
#include <stdexcept>
#include <algorithm> // For std::find
#include <cstdio>    // For sscanf (alternative to stream parsing)


namespace Builtins {

// --- Dump Operators ---

Operator dump_tuple_op(std::ostream& outc, bool show_reset) {
    // Capture outc by reference, show_reset by value
    return Operator{
        [&outc](const Tuple& tup) { // next lambda
            dump_tuple(outc, tup);
        },
        [&outc, show_reset](const Tuple& tup) { // reset lambda
            if (show_reset) {
                dump_tuple(outc, tup);
                outc << "[reset]" << std::endl;
            }
            // Reset doesn't necessarily propagate in a dump
        }
    };
}

Operator dump_as_csv(std::ostream& outc,
                     std::optional<std::pair<std::string, std::string>> static_field,
                     bool header) {
    // State needs to be mutable and captured
    auto first = std::make_shared<bool>(header); // Use shared_ptr to manage state across lambda calls

    return Operator{
        // next lambda captures state
        [&outc, static_field, first](const Tuple& tup) {
            if (*first) {
                if (static_field) {
                    outc << static_field->first << ",";
                }
                bool first_key = true;
                for (const auto& pair : tup) {
                     if (!first_key) outc << ",";
                     outc << pair.first;
                     first_key = false;
                }
                outc << "\n"; // Use \n instead of endl for potentially better performance
                *first = false;
            }

            if (static_field) {
                outc << static_field->second << ",";
            }
            bool first_val = true;
            for (const auto& pair : tup) {
                if (!first_val) outc << ",";
                outc << string_of_op_result(pair.second);
                first_val = false;
            }
            outc << "\n";
             outc.flush(); // Flush explicitly if needed line-by-line
        },
        // reset lambda (does nothing here)
        [](const Tuple& tup) { }
    };
}


Operator dump_walts_csv(const std::string& filename) {
    // State: output stream and whether it's the first write
    auto outc_ptr = std::make_shared<std::optional<std::ofstream>>(); // Optional to handle lazy opening
    auto first = std::make_shared<bool>(true);

    return Operator{
        [filename, outc_ptr, first](const Tuple& tup) {
            if (*first) {
                *outc_ptr = std::ofstream(filename); // Open the file
                if (!outc_ptr->value().is_open()) {
                     throw std::runtime_error("Failed to open file for dump_walts_csv: " + filename);
                }
                *first = false;
                // Walt's format doesn't seem to have a header line in the OCaml impl.
            }

            std::ostream& out = outc_ptr->value(); // Get reference to the stream

            // Explicitly find keys required by Walt's format
            auto src_ip = lookup_opt("src_ip", tup);
            auto dst_ip = lookup_opt("dst_ip", tup);
            auto src_port = lookup_opt("src_l4_port", tup);
            auto dst_port = lookup_opt("dst_l4_port", tup);
            auto pkt_count = lookup_opt("packet_count", tup);
            auto byte_count = lookup_opt("byte_count", tup);
            auto epoch_id = lookup_opt("epoch_id", tup);

             // Helper to get string or "0" if missing/invalid
            auto get_str = [](const std::optional<OpResult>& opt_res) {
                return opt_res ? string_of_op_result(*opt_res) : std::string("0");
            };

             out << get_str(src_ip) << ","
                << get_str(dst_ip) << ","
                << get_str(src_port) << ","
                << get_str(dst_port) << ","
                << get_str(pkt_count) << ","
                << get_str(byte_count) << ","
                << get_str(epoch_id) << "\n";
             out.flush(); // Flush after each line
        },
        [outc_ptr](const Tuple& tup) {
            // Reset in this context might mean closing the file,
            // or doing nothing if the pipeline continues. OCaml does nothing.
             if (*outc_ptr) {
                 // Optional: Could close the file here if appropriate for pipeline end
                 // outc_ptr->value().close();
                 // *outc_ptr = std::nullopt;
             }
        }
    };
}

// --- Input Operators ---

OpResult get_ip_or_zero(const std::string& input) {
    if (input == "0") {
        return OpResult{0}; // Int 0
    } else {
        try {
            return OpResult{IPv4Address(input)}; // Construct IPv4Address
        } catch (const std::exception& e) {
            // OCaml raises exception; C++ might log or return Empty/error
             // Let's stick to throwing for now to match OCaml behavior
            throw std::runtime_error("Failed to parse IP '" + input + "': " + e.what());
        }
    }
}


// Helper to parse Walt's CSV line (basic implementation)
std::optional<Tuple> parse_walts_line(const std::string& line, const std::string& epoch_id_key) {
     std::stringstream ss(line);
     std::string segment;
     std::vector<std::string> parts;
     while (std::getline(ss, segment, ',')) {
         parts.push_back(segment);
     }

     if (parts.size() != 7) {
         // Handle error: incorrect number of fields
         std::cerr << "Warning: Skipping malformed line (expected 7 fields): " << line << std::endl;
         return std::nullopt;
     }

    try {
        std::string src_ip_str = parts[0];
        std::string dst_ip_str = parts[1];
        int src_port = std::stoi(parts[2]);
        int dst_port = std::stoi(parts[3]);
        int pkt_count = std::stoi(parts[4]);
        int byte_count = std::stoi(parts[5]);
        int epoch_id = std::stoi(parts[6]);

        Tuple p;
        p["ipv4.src"] = get_ip_or_zero(src_ip_str); // Can throw
        p["ipv4.dst"] = get_ip_or_zero(dst_ip_str); // Can throw
        p["l4.sport"] = src_port;
        p["l4.dport"] = dst_port;
        p["packet_count"] = pkt_count;
        p["byte_count"] = byte_count;
        p[epoch_id_key] = epoch_id;

        return p;
    } catch (const std::exception& e) {
         std::cerr << "Warning: Skipping line due to parsing error (" << e.what() << "): " << line << std::endl;
         return std::nullopt;
    }
}

void read_walts_csv(const std::vector<std::string>& file_names,
                    const std::vector<Operator>& ops,
                    const std::string& epoch_id_key) {

    if (file_names.size() != ops.size()) {
        throw std::runtime_error("read_walts_csv: Number of file names must match number of operators.");
    }

    struct FileState {
        std::ifstream stream;
        int current_eid = 0;
        long long tuple_count_this_epoch = 0; // Use long long for potentially large counts
        bool active = true;
        std::string filename; // For error messages
    };

    std::vector<FileState> states;
    states.reserve(file_names.size());

    for (const auto& fname : file_names) {
        states.emplace_back();
        states.back().filename = fname;
        states.back().stream.open(fname);
        if (!states.back().stream.is_open()) {
             // Close already opened files before throwing
             for(auto& state : states) {
                 if(state.stream.is_open()) state.stream.close();
             }
             throw std::runtime_error("Failed to open input file: " + fname);
        }
    }

    size_t active_count = states.size();
    std::string line;

    while (active_count > 0) {
        for (size_t i = 0; i < states.size(); ++i) {
            if (!states[i].active) continue;

            FileState& state = states[i];
            const Operator& op = ops[i];

            if (std::getline(state.stream, line)) {
                std::optional<Tuple> parsed_tuple_opt = parse_walts_line(line, epoch_id_key);

                if (parsed_tuple_opt) {
                    Tuple p = std::move(*parsed_tuple_opt); // Move the tuple out
                    int file_epoch_id = lookup_int(epoch_id_key, p); // Assumes key exists and is int

                    state.tuple_count_this_epoch++;

                    // Handle epoch boundary crossings
                    if (file_epoch_id > state.current_eid) {
                         // Send resets for missed epochs
                        while (file_epoch_id > state.current_eid) {
                            Tuple reset_info;
                            reset_info[epoch_id_key] = state.current_eid;
                            reset_info["tuples"] = static_cast<int>(state.tuple_count_this_epoch); // OCaml passes tuple count in reset
                            op.reset(reset_info);
                            state.tuple_count_this_epoch = 0; // Reset count for next epoch
                            state.current_eid++;
                        }
                        // After catching up, current_eid should match file_epoch_id
                        // Re-increment count since the current tuple belongs to this new epoch
                         state.tuple_count_this_epoch = 1;
                    }
                    // else: tuple belongs to the current or past epoch (handle as needed, OCaml seems to process it)

                    Tuple next_tuple = p; // Make a copy or modify in place if safe
                    next_tuple["tuples"] = static_cast<int>(state.tuple_count_this_epoch); // Add current count
                    op.next(next_tuple);

                } else {
                    // Line parsing failed (warning already printed in helper)
                    // Decide whether to continue or handle error more strictly
                }

            } else { // End Of File reached for this stream
                 if (state.stream.eof()) {
                    // Send final reset for the last processed epoch + 1
                    Tuple reset_info;
                    reset_info[epoch_id_key] = state.current_eid; // OCaml uses eid+1, but let's use current to cap the last full epoch
                    reset_info["tuples"] = static_cast<int>(state.tuple_count_this_epoch);
                    op.reset(reset_info);

                    // Send one more reset for eid+1 like OCaml? Seems redundant if next reads use new state.
                    // Let's match OCaml here:
                    Tuple final_reset_info;
                    final_reset_info[epoch_id_key] = state.current_eid + 1;
                    final_reset_info["tuples"] = 0; // No tuples in this final boundary epoch
                    op.reset(final_reset_info);


                    state.active = false;
                    active_count--;
                    state.stream.close();
                 } else {
                      // Handle potential read error other than EOF
                      std::cerr << "Error reading from file: " << state.filename << std::endl;
                      state.active = false;
                      active_count--;
                      state.stream.close();
                 }
            }
        }
    }
    std::cout << "Done reading files." << std::endl;
}


// --- Meta Operators ---

Operator meta_meter(const std::string& name,
                    std::ostream& outc,
                    Operator next_op,
                    std::optional<std::string> static_field) {
    // Mutable state captured by shared_ptr for lambdas
    auto epoch_count = std::make_shared<long long>(0);
    auto tups_count = std::make_shared<long long>(0);

    return Operator{
        [next_op, tups_count](const Tuple& tup) {
            (*tups_count)++;
            next_op.next(tup); // Pass tuple downstream
        },
        [name, &outc, next_op, static_field, epoch_count, tups_count](const Tuple& tup) {
            outc << *epoch_count << ","
                 << name << ","
                 << *tups_count << ","
                 << (static_field ? *static_field : "")
                 << "\n"; // Use \n
            outc.flush(); // Flush output

            *tups_count = 0; // Reset tuple count for the next epoch
            (*epoch_count)++; // Increment epoch count

            next_op.reset(tup); // Propagate reset downstream
        }
    };
}


// --- Core Stream Operators ---

Operator epoch(double epoch_width, const std::string& key_out, Operator next_op) {
    // Mutable state capture
    auto epoch_boundary = std::make_shared<double>(0.0);
    auto eid = std::make_shared<int>(0);

    return Operator{
        [epoch_width, key_out, next_op, epoch_boundary, eid](const Tuple& tup) {
            double time = lookup_float("time", tup); // Assumes "time" key exists and is float

            if (*epoch_boundary == 0.0) { // First tuple, initialize boundary
                *epoch_boundary = time + epoch_width;
            } else if (time >= *epoch_boundary) {
                // Time crossed one or more epoch boundaries
                while (time >= *epoch_boundary) {
                    Tuple reset_info;
                    reset_info[key_out] = *eid;
                    next_op.reset(reset_info); // Send reset for completed epoch

                    *epoch_boundary += epoch_width; // Advance boundary
                    (*eid)++; // Increment epoch ID
                }
            }
            // Add epoch ID to current tuple and send downstream
            Tuple out_tup = tup; // Copy tuple
            out_tup[key_out] = *eid;
            next_op.next(out_tup);
        },
        [key_out, next_op, epoch_boundary, eid](const Tuple& tup) {
             // When an external reset comes, send a final reset for the current epoch
            Tuple final_reset_info;
            final_reset_info[key_out] = *eid;
             // Merge external reset info? OCaml doesn't explicitly.
             // Let's just pass the essential eid derived locally.
            next_op.reset(final_reset_info);

             // Reset internal state for potential reuse
            *epoch_boundary = 0.0;
            *eid = 0;
        }
    };
}

Operator filter(std::function<bool(const Tuple&)> f, Operator next_op) {
    return Operator{
        [f, next_op](const Tuple& tup) {
            if (f(tup)) {
                next_op.next(tup); // Pass tuple if predicate is true
            }
        },
        [next_op](const Tuple& tup) {
            next_op.reset(tup); // Always propagate reset
        }
    };
}

Operator map(std::function<Tuple(const Tuple&)> f, Operator next_op) {
    return Operator{
        [f, next_op](const Tuple& tup) {
            next_op.next(f(tup)); // Pass transformed tuple
        },
        [next_op](const Tuple& tup) {
            next_op.reset(tup); // Always propagate reset
        }
    };
}

// --- Groupby/Distinct Related ---

Operator groupby(GroupingFunc group_by_func,
                 ReductionFunc reduce_func,
                 const std::string& out_key,
                 Operator next_op) {
    // State: map from grouping key (Tuple) to accumulated value (OpResult)
    // Using std::map requires Tuple and OpResult to have operator<
    auto h_tbl = std::make_shared<std::map<Tuple, OpResult>>();
    // auto reset_counter = std::make_shared<int>(0); // OCaml tracks this, C++ might not need unless for debugging

    return Operator{
        [group_by_func, reduce_func, h_tbl](const Tuple& tup) {
            Tuple grouping_key = group_by_func(tup);
            auto it = h_tbl->find(grouping_key);

            if (it != h_tbl->end()) {
                // Key exists, reduce current value with new tuple
                it->second = reduce_func(it->second, tup);
            } else {
                // New key, reduce Empty value with new tuple
                OpResult initial_val = Empty{};
                (*h_tbl)[grouping_key] = reduce_func(initial_val, tup);
            }
        },
        [out_key, next_op, h_tbl](const Tuple& reset_tup) {
            // (*reset_counter)++;
            for (const auto& pair : *h_tbl) {
                const Tuple& grouping_key = pair.first;
                const OpResult& accumulated_val = pair.second;

                // Create output tuple: merge reset info, grouping key, and result
                Tuple out_tup = reset_tup; // Start with reset info

                // Add grouping key fields (overwrite if conflicts with reset_tup)
                for (const auto& key_val : grouping_key) {
                    out_tup[key_val.first] = key_val.second;
                }

                // Add the accumulated result
                out_tup[out_key] = accumulated_val;

                next_op.next(out_tup); // Send aggregated tuple downstream
            }

            // Propagate reset downstream *after* processing groups
            next_op.reset(reset_tup);

            // Clear the table for the next epoch
            h_tbl->clear();
        }
    };
}


Operator distinct(GroupingFunc group_by_func, Operator next_op) {
     // State: map storing unique keys encountered this epoch
     // Value can be bool or anything, just presence matters. Using bool.
    auto h_tbl = std::make_shared<std::map<Tuple, bool>>();
    // auto reset_counter = std::make_shared<int>(0);

    return Operator{
        [group_by_func, h_tbl](const Tuple& tup) {
             Tuple grouping_key = group_by_func(tup);
             // Add/overwrite key in the map. If it exists, value is updated to true.
             // If it doesn't exist, it's inserted with value true.
             (*h_tbl)[grouping_key] = true;
        },
        [next_op, h_tbl](const Tuple& reset_tup) {
            // (*reset_counter)++;
            for (const auto& pair : *h_tbl) {
                 const Tuple& distinct_key = pair.first;

                 // Create output tuple: merge reset info and distinct key fields
                 Tuple out_tup = reset_tup;
                 for (const auto& key_val : distinct_key) {
                     out_tup[key_val.first] = key_val.second;
                 }
                 next_op.next(out_tup); // Send distinct key tuple downstream
             }

             next_op.reset(reset_tup); // Propagate reset
             h_tbl->clear(); // Clear for next epoch
        }
    };
}


// Groupby Utilities Implementations
Tuple filter_groups(const std::vector<std::string>& incl_keys, const Tuple& tup) {
    Tuple result;
    for (const auto& key : incl_keys) {
        auto it = tup.find(key);
        if (it != tup.end()) {
            result[key] = it->second;
        }
    }
    return result;
}

Tuple single_group(const Tuple&) {
    return Tuple{}; // Return an empty map, representing the single group key
}

OpResult counter(OpResult current_val, const Tuple&) {
     // Check if current_val holds an int
    if (auto* p_int = std::get_if<int>(&current_val)) {
        return OpResult{(*p_int) + 1};
    } else if (std::holds_alternative<Empty>(current_val)) {
         // First item for this group
        return OpResult{1};
    } else {
         // Error condition or unexpected type - OCaml returns original value
         // Let's return the original value to mimic, but log a warning.
         std::cerr << "Warning: Counter expected Int or Empty, got different type." << std::endl;
         return current_val;
    }
}

OpResult sum_ints(const std::string& search_key, OpResult init_val, const Tuple& tup) {
     int current_sum = 0;
     // Get the initial sum
     if (auto* p_int = std::get_if<int>(&init_val)) {
         current_sum = *p_int;
     } else if (!std::holds_alternative<Empty>(init_val)) {
         // If initial value is not Empty and not Int, return it (error state)
          std::cerr << "Warning: sum_ints expected initial value Int or Empty." << std::endl;
         return init_val;
     }
     // else: init_val is Empty, current_sum remains 0

     // Find the value to add from the current tuple
     auto it = tup.find(search_key);
     if (it != tup.end()) {
         if (auto* p_add_int = std::get_if<int>(&(it->second))) {
             return OpResult{current_sum + *p_add_int};
         } else {
             // Key found but is not an int - OCaml raises Failure
             throw std::runtime_error("'sum_ints' failed: value for key \"" + search_key + "\" is not an integer.");
         }
     } else {
         // Key not found in tuple - OCaml raises Failure
          throw std::runtime_error("'sum_ints' failed: key \"" + search_key + "\" not found in tuple.");
     }
}


// --- Split/Join Operators ---

Operator split(Operator left, Operator right) {
    return Operator{
        [left, right](const Tuple& tup) {
            left.next(tup);  // Send to left
            right.next(tup); // Send to right
        },
        [left, right](const Tuple& tup) {
            left.reset(tup);  // Reset left
            right.reset(tup); // Reset right
        }
    };
}


std::pair<Operator, Operator> join(KeyExtractor left_extractor,
                                   KeyExtractor right_extractor,
                                   Operator next_op,
                                   const std::string& eid_key) {

    // State for join: two hash tables (maps) storing pending tuples keyed by their join key + epoch
    // Using std::map as key requires operator< for Tuple
    auto h_tbl1 = std::make_shared<std::map<Tuple, Tuple>>();
    auto h_tbl2 = std::make_shared<std::map<Tuple, Tuple>>();

    // State for epoch tracking for each side
    auto left_curr_epoch = std::make_shared<int>(0);
    auto right_curr_epoch = std::make_shared<int>(0);


    // Lambda defining the logic for one side of the join
    auto handle_join_side =
        [&](std::shared_ptr<std::map<Tuple, Tuple>> current_h_tbl, // Map for this side's pending tuples
            std::shared_ptr<std::map<Tuple, Tuple>> other_h_tbl,   // Map for the other side's pending tuples
            std::shared_ptr<int> current_epoch_ref,                // This side's current epoch state
            std::shared_ptr<int> other_epoch_ref,                  // Other side's current epoch state
            KeyExtractor key_extractor) -> Operator // The key extractor for this side
        {
        return Operator{
            // next lambda
            [=](const Tuple& tup) { // Capture all needed state by value/copy
                auto [key, vals] = key_extractor(tup); // Extract key and value parts
                int tuple_epoch = get_mapped_int(eid_key, tup); // Get epoch ID

                // Advance current epoch marker if necessary, sending resets
                while (tuple_epoch > *current_epoch_ref) {
                    // Only send reset if the *other* side has also advanced past this epoch
                    if (*other_epoch_ref > *current_epoch_ref) {
                         Tuple reset_info;
                         reset_info[eid_key] = *current_epoch_ref;
                         next_op.reset(reset_info);
                    }
                    (*current_epoch_ref)++;
                }
                // At this point, *current_epoch_ref >= tuple_epoch
                // If tuple_epoch < *current_epoch_ref, it's a late tuple. OCaml processes it.

                // Create the actual key for the hash table (join key + epoch id)
                Tuple lookup_key = key; // Start with extracted join key
                lookup_key[eid_key] = tuple_epoch; // Add epoch id

                // Try to find a match in the *other* table
                auto match_it = other_h_tbl->find(lookup_key);
                if (match_it != other_h_tbl->end()) {
                    // Match found! Combine tuples and send downstream
                    Tuple matched_vals = match_it->second;
                    other_h_tbl->erase(match_it); // Consume the matched tuple

                    // Merge: lookup_key (has join key + eid) + vals (from current) + matched_vals
                    Tuple joined_tup = lookup_key; // Start with key+eid
                     // Add current side's values
                    for(const auto& p : vals) joined_tup[p.first] = p.second;
                    // Add matched side's values (overwriting if conflict, OCaml uses union favoring left?)
                    // OCaml `Tuple.union (fun _ a _ -> Some a) left right` favors left (`a`).
                    // Let's assume current side (`vals`) takes precedence over matched side (`matched_vals`)
                    for(const auto& p : matched_vals) {
                        // Add only if key doesn't exist from 'vals' or 'lookup_key' already
                        joined_tup.try_emplace(p.first, p.second);
                    }

                    next_op.next(joined_tup);

                } else {
                    // No match found, store this tuple in the *current* table
                    (*current_h_tbl)[lookup_key] = vals;
                }
            },
            // reset lambda
            [=](const Tuple& reset_tup) { // Capture necessary state
                 // When reset arrives, primarily advance epoch counter if needed
                int reset_epoch = get_mapped_int(eid_key, reset_tup);

                // Advance current epoch marker based on reset signal
                 while (reset_epoch > *current_epoch_ref) {
                    if (*other_epoch_ref > *current_epoch_ref) {
                         Tuple epoch_reset_info;
                         epoch_reset_info[eid_key] = *current_epoch_ref;
                         next_op.reset(epoch_reset_info);
                    }
                    (*current_epoch_ref)++;
                }
                 // Note: Join doesn't clear its tables on external reset, only implicitly
                 //       through epoch advancement and tuple consumption.
                 //       If a full clear is needed, it would go here.
                 // OCaml doesn't clear, it relies on epoch matching.
            }
        };
    };

    // Create the two operators for the join sides
    Operator left_op = handle_join_side(h_tbl1, h_tbl2, left_curr_epoch, right_curr_epoch, left_extractor);
    Operator right_op = handle_join_side(h_tbl2, h_tbl1, right_curr_epoch, left_curr_epoch, right_extractor);

    return {left_op, right_op};
}


// Join Utility Implementation
Tuple rename_filtered_keys(const std::vector<std::pair<std::string, std::string>>& renamings,
                           const Tuple& in_tup) {
    Tuple result;
    for (const auto& rename_pair : renamings) {
        const std::string& old_key = rename_pair.first;
        const std::string& new_key = rename_pair.second;

        auto it = in_tup.find(old_key);
        if (it != in_tup.end()) {
            result[new_key] = it->second; // Add with the new key
        }
    }
    return result;
}


// --- Filter Utilities ---
bool key_geq_int(const std::string& key, int threshold, const Tuple& tup) {
    try {
        return lookup_int(key, tup) >= threshold;
    } catch (const std::exception& e) {
        // Handle cases where key doesn't exist or isn't an int
        // OCaml would raise an exception. C++ filter could return false.
        // Let's return false for robustness in filter context.
        // std::cerr << "Warning: key_geq_int check failed for key '" << key << "': " << e.what() << std::endl;
        return false;
    }
}

// Convenience aliases using Utils::lookup_*
int get_mapped_int(const std::string& key, const Tuple& tup) {
    return lookup_int(key, tup); // Will throw if key missing or not int
}

double get_mapped_float(const std::string& key, const Tuple& tup) {
    return lookup_float(key, tup); // Will throw if key missing or not float
}


} // namespace Builtins