Prompt:

I'll translate the OCaml code to C++. Let me analyze the code structure first and then provide a comprehensive translation.

```cpp
/**
 * Common utilities 
 *
 * Includes minimal parsing of header fields into a map from strings to values
 */

#include <iostream>
#include <map>
#include <unordered_map>
#include <string>
#include <vector>
#include <functional>
#include <cstdint>
#include <memory>
#include <fstream>
#include <sstream>
#include <ctime>
#include <algorithm>
#include <optional>

// Forward declarations for IP address handling
class IPv4Address {
public:
    IPv4Address() = default;
    explicit IPv4Address(const std::string& address);
    std::string toString() const;
    bool operator<(const IPv4Address& other) const;
    bool operator==(const IPv4Address& other) const;
private:
    uint32_t address_ = 0;
};

/**
 * Operators act on named "tuples" which are maps from strings to op_result types
 **************************************************************************************/

// Variant type for operation results
class OpResult {
public:
    enum class Type {
        FLOAT,
        INT,
        IPV4,
        MAC,
        EMPTY
    };

    OpResult() : type_(Type::EMPTY) {}
    explicit OpResult(float val) : type_(Type::FLOAT), float_val_(val) {}
    explicit OpResult(int val) : type_(Type::INT), int_val_(val) {}
    explicit OpResult(const IPv4Address& val) : type_(Type::IPV4), ipv4_val_(val) {}
    explicit OpResult(const std::vector<uint8_t>& val) : type_(Type::MAC), mac_val_(val) {}

    Type getType() const { return type_; }
    float getFloat() const { return float_val_; }
    int getInt() const { return int_val_; }
    IPv4Address getIPv4() const { return ipv4_val_; }
    const std::vector<uint8_t>& getMAC() const { return mac_val_; }

    bool isEmpty() const { return type_ == Type::EMPTY; }

private:
    Type type_;
    float float_val_ = 0.0f;
    int int_val_ = 0;
    IPv4Address ipv4_val_;
    std::vector<uint8_t> mac_val_;
};

// Map from strings to OpResult values
using Tuple = std::map<std::string, OpResult>;

// Define operator type for processing tuples
class Operator {
public:
    std::function<void(const Tuple&)> next;
    std::function<void(const Tuple&)> reset;

    Operator() = default;
    Operator(std::function<void(const Tuple&)> next_fn, 
             std::function<void(const Tuple&)> reset_fn)
        : next(std::move(next_fn)), reset(std::move(reset_fn)) {}
};

using OpCreator = std::function<Operator(const Operator&)>;
using DblOpCreator = std::function<std::pair<Operator, Operator>(const Operator&)>;

/**
 * Right associative "chaining" operator
 * for passing output of one operator to the next under cps-style operator constructors
 */
Operator chainOp(const OpCreator& op_creator_func, const Operator& next_op) {
    return op_creator_func(next_op);
}

std::pair<Operator, Operator> chainDblOp(const DblOpCreator& op_creator_func, 
                                         const Operator& op) {
    return op_creator_func(op);
}

/**
 * Conversion utilities
 **************************************************************************************/

// Formats the 6 bytes of the MAC address as a colon-separated string in hex
std::string stringOfMac(const std::vector<uint8_t>& buf) {
    char macStr[18];
    snprintf(macStr, sizeof(macStr), "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
             buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]);
    return std::string(macStr);
}

// Converts TCP flags into a human-readable string representation
std::string tcpFlagsToStrings(int flags) {
    std::map<std::string, int> tcp_flags_map = {
        {"FIN", 1 << 0},
        {"SYN", 1 << 1},
        {"RST", 1 << 2},
        {"PSH", 1 << 3},
        {"ACK", 1 << 4},
        {"URG", 1 << 5},
        {"ECE", 1 << 6},
        {"CWR", 1 << 7}
    };

    std::string result;
    for (const auto& [key, value] : tcp_flags_map) {
        if ((flags & value) == value) {
            if (!result.empty()) {
                result += "|";
            }
            result += key;
        }
    }
    return result;
}

// Extract int from OpResult, throws exception if not an int
int intOfOpResult(const OpResult& input) {
    if (input.getType() != OpResult::Type::INT) {
        throw std::runtime_error("Trying to extract int from non-int result");
    }
    return input.getInt();
}

// Extract float from OpResult, throws exception if not a float
float floatOfOpResult(const OpResult& input) {
    if (input.getType() != OpResult::Type::FLOAT) {
        throw std::runtime_error("Trying to extract float from non-float result");
    }
    return input.getFloat();
}

// Convert OpResult to string representation
std::string stringOfOpResult(const OpResult& input) {
    switch (input.getType()) {
        case OpResult::Type::FLOAT:
            return std::to_string(input.getFloat());
        case OpResult::Type::INT:
            return std::to_string(input.getInt());
        case OpResult::Type::IPV4:
            return input.getIPv4().toString();
        case OpResult::Type::MAC:
            return stringOfMac(input.getMAC());
        case OpResult::Type::EMPTY:
            return "Empty";
        default:
            return "Unknown";
    }
}

// Convert tuple to string representation
std::string stringOfTuple(const Tuple& input_tuple) {
    std::string result;
    for (const auto& [key, val] : input_tuple) {
        result += "\"" + key + "\" => " + stringOfOpResult(val) + ", ";
    }
    return result;
}

// Create a Tuple from a list of pairs
Tuple tupleOfList(const std::vector<std::pair<std::string, OpResult>>& tup_list) {
    Tuple result;
    for (const auto& [key, value] : tup_list) {
        result[key] = value;
    }
    return result;
}

// Print formatted representation of a Tuple
void dumpTuple(FILE* outc, const Tuple& tup) {
    fprintf(outc, "%s\n", stringOfTuple(tup).c_str());
}

// Lookup int value by key in tuple
int lookupInt(const std::string& key, const Tuple& tup) {
    auto it = tup.find(key);
    if (it == tup.end()) {
        throw std::runtime_error("Key not found in tuple: " + key);
    }
    return intOfOpResult(it->second);
}

// Lookup float value by key in tuple
float lookupFloat(const std::string& key, const Tuple& tup) {
    auto it = tup.find(key);
    if (it == tup.end()) {
        throw std::runtime_error("Key not found in tuple: " + key);
    }
    return floatOfOpResult(it->second);
}

/**
 * Built-in operator definitions
 * and common utilities for readability
 */

const int INIT_TABLE_SIZE = 10000;

/**
 * Dump all fields of all tuples to the given output channel
 * Note that dump is terminal in that it does not take a continuation operator
 * as argument
 */
Operator dumpTupleOp(FILE* outc, bool show_reset = false) {
    return {
        .next = [outc](const Tuple& tup) {
            dumpTuple(outc, tup);
        },
        .reset = [outc, show_reset](const Tuple& tup) {
            if (show_reset) {
                dumpTuple(outc, tup);
                fprintf(outc, "[reset]\n");
            }
        }
    };
}

/**
 * Tries to dump a nice csv-style output
 * Assumes all tuples have the same fields in the same order...
 */
Operator dumpAsCsv(FILE* outc, 
                  std::optional<std::pair<std::string, std::string>> static_field = std::nullopt,
                  bool header = true) {
    auto first = std::make_shared<bool>(header);
    return {
        .next = [outc, first, static_field](const Tuple& tup) {
            if (*first) {
                if (static_field) {
                    fprintf(outc, "%s,", static_field->first.c_str());
                }
                for (const auto& [key, _] : tup) {
                    fprintf(outc, "%s,", key.c_str());
                }
                fprintf(outc, "\n");
                *first = false;
            }
            
            if (static_field) {
                fprintf(outc, "%s,", static_field->second.c_str());
            }
            
            for (const auto& [_, value] : tup) {
                fprintf(outc, "%s,", stringOfOpResult(value).c_str());
            }
            fprintf(outc, "\n");
        },
        .reset = [](const Tuple&) { /* Do nothing */ }
    };
}

/**
 * Dumps csv in Walt's canonical csv format: src_ip, dst_ip, src_l4_port,
 * dst_l4_port, packet_count, byte_count, epoch_id
 * Unused fields are zeroed, map packet length to src_l4_port for ssh brute
 * force
 */
Operator dumpWaltsCsv(const std::string& filename) {
    auto outc = std::make_shared<FILE*>(nullptr);
    auto first = std::make_shared<bool>(true);
    
    return {
        .next = [outc, first, filename](const Tuple& tup) {
            if (*first) {
                *outc = fopen(filename.c_str(), "w");
                *first = false;
            }
            
            auto findAndConvert = [&tup](const std::string& key) -> std::string {
                auto it = tup.find(key);
                if (it != tup.end()) {
                    return stringOfOpResult(it->second);
                }
                return "";
            };
            
            fprintf(*outc, "%s,%s,%s,%s,%s,%s,%s\n",
                findAndConvert("src_ip").c_str(),
                findAndConvert("dst_ip").c_str(),
                findAndConvert("src_l4_port").c_str(),
                findAndConvert("dst_l4_port").c_str(),
                findAndConvert("packet_count").c_str(),
                findAndConvert("byte_count").c_str(),
                findAndConvert("epoch_id").c_str());
        },
        .reset = [](const Tuple&) { /* Do nothing */ }
    };
}

// Input is either "0" or an IPv4 address in string format
OpResult getIpOrZero(const std::string& input) {
    if (input == "0") {
        return OpResult(0);
    } else {
        return OpResult(IPv4Address(input));
    }
}

/**
 * Reads an intermediate result CSV in Walt's canonical format
 * Injects epoch ids and incomming tuple counts into reset call
 */
void readWaltsCsv(const std::vector<std::string>& file_names, 
                 const std::vector<Operator>& ops,
                 const std::string& epoch_id_key = "eid") {
    // Open each CSV file, for scanning, create list of triples:
    // (input_file, epoch_id, tuples_count)
    struct FileInfo {
        FILE* file;
        int epoch_id;
        int tup_count;
    };
    
    std::vector<FileInfo> file_infos;
    for (const auto& filename : file_names) {
        file_infos.push_back({fopen(filename.c_str(), "r"), 0, 0});
    }
    
    int running = ops.size();
    while (running > 0) {
        for (size_t i = 0; i < file_infos.size() && i < ops.size(); ++i) {
            auto& info = file_infos[i];
            const auto& op = ops[i];
            
            if (info.epoch_id >= 0) {
                char src_ip[64], dst_ip[64];
                int src_l4_port, dst_l4_port, packet_count, byte_count, epoch_id;
                
                if (fscanf(info.file, "%63[0-9.],%63[0-9.],%d,%d,%d,%d,%d\n",
                        src_ip, dst_ip, &src_l4_port, &dst_l4_port, 
                        &packet_count, &byte_count, &epoch_id) == 7) {
                    
                    Tuple p;
                    p["ipv4.src"] = getIpOrZero(src_ip);
                    p["ipv4.dst"] = getIpOrZero(dst_ip);
                    p["l4.sport"] = OpResult(src_l4_port);
                    p["l4.dport"] = OpResult(dst_l4_port);
                    p["packet_count"] = OpResult(packet_count);
                    p["byte_count"] = OpResult(byte_count);
                    p[epoch_id_key] = OpResult(epoch_id);
                    
                    info.tup_count++;
                    
                    if (epoch_id > info.epoch_id) {
                        while (epoch_id > info.epoch_id) {
                            Tuple reset_tup;
                            reset_tup[epoch_id_key] = OpResult(info.epoch_id);
                            reset_tup["tuples"] = OpResult(info.tup_count);
                            op.reset(reset_tup);
                            info.tup_count = 0;
                            info.epoch_id++;
                        }
                    }
                    
                    p["tuples"] = OpResult(info.tup_count);
                    op.next(p);
                } else {
                    // EOF or scan failure
                    Tuple reset_tup;
                    reset_tup[epoch_id_key] = OpResult(info.epoch_id + 1);
                    reset_tup["tuples"] = OpResult(info.tup_count);
                    op.reset(reset_tup);
                    running--;
                    info.epoch_id = -1;
                    fclose(info.file);
                }
            }
        }
    }
    
    std::cout << "Done." << std::endl;
}

/**
 * Write the number of tuples passing through this operator each epoch
 * to the out_channel
 */
OpCreator metaMeter(const std::string& name, FILE* outc, 
                   std::optional<std::string> static_field = std::nullopt) {
    return [name, outc, static_field](const Operator& next_op) {
        auto epoch_count = std::make_shared<int>(0);
        auto tups_count = std::make_shared<int>(0);
        
        return Operator{
            .next = [next_op, tups_count](const Tuple& tup) {
                (*tups_count)++;
                next_op.next(tup);
            },
            .reset = [next_op, epoch_count, tups_count, name, outc, static_field](const Tuple& tup) {
                fprintf(outc, "%d,%s,%d,%s\n", *epoch_count, name.c_str(), *tups_count,
                       static_field ? static_field->c_str() : "");
                *tups_count = 0;
                (*epoch_count)++;
                next_op.reset(tup);
            }
        };
    };
}

/**
 * Passes tuples through to op
 * Resets op every w seconds
 * Adds epoch id to tuple under key_out
 */
OpCreator epoch(float epoch_width, const std::string& key_out) {
    return [epoch_width, key_out](const Operator& next_op) {
        auto epoch_boundary = std::make_shared<float>(0.0f);
        auto eid = std::make_shared<int>(0);
        
        return Operator{
            .next = [next_op, epoch_boundary, eid, epoch_width, key_out](const Tuple& tup) {
                auto it = tup.find("time");
                if (it == tup.end()) {
                    throw std::runtime_error("Tuple missing 'time' field");
                }
                
                float time = floatOfOpResult(it->second);
                
                if (*epoch_boundary == 0.0f) {
                    // Start of epoch
                    *epoch_boundary = time + epoch_width;
                } else if (time >= *epoch_boundary) {
                    // Within an epoch, have to calculate which one
                    while (time >= *epoch_boundary) {
                        Tuple reset_tup;
                        reset_tup[key_out] = OpResult(*eid);
                        next_op.reset(reset_tup);
                        *epoch_boundary += epoch_width;
                        (*eid)++;
                    }
                }
                
                // Add epoch ID to tuple and pass it on
                Tuple new_tup = tup;
                new_tup[key_out] = OpResult(*eid);
                next_op.next(new_tup);
            },
            .reset = [next_op, epoch_boundary, eid, key_out](const Tuple&) {
                // Resets the last epoch ID
                Tuple reset_tup;
                reset_tup[key_out] = OpResult(*eid);
                next_op.reset(reset_tup);
                *epoch_boundary = 0.0f;
                *eid = 0;
            }
        };
    };
}

/**
 * Passes only tuples where f applied to the tuple returns true
 */
OpCreator filter(std::function<bool(const Tuple&)> f) {
    return [f](const Operator& next_op) {
        return Operator{
            .next = [f, next_op](const Tuple& tup) {
                if (f(tup)) {
                    next_op.next(tup);
                }
            },
            .reset = [next_op](const Tuple& tup) {
                next_op.reset(tup);
            }
        };
    };
}

/**
 * (filter utility)
 * comparison function for testing int values against a threshold
 */
std::function<bool(const Tuple&)> keyGeqInt(const std::string& key, int threshold) {
    return [key, threshold](const Tuple& tup) {
        return lookupInt(key, tup) >= threshold;
    };
}

/**
 * (filter utility)
 * Looks up the given key and converts to Int op_result
 * if the key does not hold an int, this will raise an exception
 */
int getMappedInt(const std::string& key, const Tuple& tup) {
    return lookupInt(key, tup);
}

/**
 * (filter utility)
 * Looks up the given key and converts to Float op_result
 * if the key does not hold a float, this will raise an exception
 */
float getMappedFloat(const std::string& key, const Tuple& tup) {
    return lookupFloat(key, tup);
}

/**
 * Operator which applied the given function on all tuples
 * Passes resets, unchanged
 */
OpCreator map(std::function<Tuple(const Tuple&)> f) {
    return [f](const Operator& next_op) {
        return Operator{
            .next = [f, next_op](const Tuple& tup) {
                next_op.next(f(tup));
            },
            .reset = [next_op](const Tuple& tup) {
                next_op.reset(tup);
            }
        };
    };
}

using GroupingFunc = std::function<Tuple(const Tuple&)>;
using ReductionFunc = std::function<OpResult(const OpResult&, const Tuple&)>;

/**
 * Groups the input Tuples according to canonic members returned by
 *   key_extractor : Tuple -> Tuple
 * Tuples in each group are folded (starting with Empty) by
 *   accumulate : op_result -> Tuple -> op_result
 * When reset, op is passed a Tuple for each group containing the union of
 *   (i) the reset argument tuple,
 *   (ii) the result of g for that group, and
 *   (iii) a mapping from out_key to the result of the fold for that group
 */
OpCreator groupby(GroupingFunc groupby_func, ReductionFunc reduce, const std::string& out_key) {
    return [groupby_func, reduce, out_key](const Operator& next_op) {
        auto h_tbl = std::make_shared<std::unordered_map<std::string, std::pair<Tuple, OpResult>>>();
        auto reset_counter = std::make_shared<int>(0);
        
        return Operator{
            .next = [h_tbl, groupby_func, reduce](const Tuple& tup) {
                // Grouping key is sub-Tuple of original extracted by key_extractor
                Tuple grouping_key = groupby_func(tup);
                
                // Create a string representation of the grouping key for hashing
                std::string key_str = stringOfTuple(grouping_key);
                
                auto it = h_tbl->find(key_str);
                if (it != h_tbl->end()) {
                    // If the Tuple key is already in the hash table, update the accumulator
                    it->second.second = reduce(it->second.second, tup);
                } else {
                    // Otherwise, add a new entry with the grouping key and initial accumulator
                    OpResult empty; // Empty accumulator
                    (*h_tbl)[key_str] = {grouping_key, reduce(empty, tup)};
                }
            },
            .reset = [h_tbl, next_op, reset_counter, out_key](const Tuple& tup) {
                // Track the counter reset
                (*reset_counter)++;
                
                // Iterate over the hash table
                for (const auto& [_, value] : *h_tbl) {
                    const Tuple& grouping_key = value.first;
                    const OpResult& val = value.second;
                    
                    // Create a new tuple with the combination of reset tuple and grouping key
                    Tuple unioned_tup = tup;
                    for (const auto& [k, v] : grouping_key) {
                        unioned_tup[k] = v;
                    }
                    
                    // Add the accumulated value under the output key
                    unioned_tup[out_key] = val;
                    
                    // Pass to the next operator
                    next_op.next(unioned_tup);
                }
                
                // Reset the next operator and clear the hash table
                next_op.reset(tup);
                h_tbl->clear();
            }
        };
    };
}

/**
 * (groupby utility : key_extractor)
 * Returns a new tuple with only the keys included in the incl_keys list
 */
Tuple filterGroups(const std::vector<std::string>& incl_keys, const Tuple& tup) {
    Tuple result;
    for (const auto& key : incl_keys) {
        auto it = tup.find(key);
        if (it != tup.end()) {
            result[key] = it->second;
        }
    }
    return result;
}

/**
 * (groupby utility : key_extractor)
 * Grouping function (key_extractor) that forms a single group
 */
Tuple singleGroup(const Tuple&) {
    return {};
}

/**
 * (groupby utility : grouping_mech)
 * Reduction function (f) to count tuples
 */
OpResult counter(const OpResult& val, const Tuple&) {
    if (val.isEmpty()) {
        return OpResult(1);
    } else if (val.getType() == OpResult::Type::INT) {
        return OpResult(val.getInt() + 1);
    } else {
        return val;
    }
}

/**
 * (groupby utility)
 * Reduction function (f) to sum values (assumed to be Int ()) of a given field
 */
OpResult sumInts(const std::string& search_key, const OpResult& init_val, const Tuple& tup) {
    if (init_val.isEmpty()) {
        // Empty init val, need to init the val to 0
        return OpResult(0);
    } else if (init_val.getType() == OpResult::Type::INT) {
        // Actual int val, find the given search key
        auto it = tup.find(search_key);
        if (it != tup.end() && it->second.getType() == OpResult::Type::INT) {
            // Set its val to the sum of the given and current value if found
            return OpResult(it->second.getInt() + init_val.getInt());
        } else {
            throw std::runtime_error("'sum_vals' function failed to find integer value mapped to \"" + 
                                     search_key + "\"");
        }
    } else {
        return init_val;
    }
}

/**
 * Returns a list of distinct elements (as determined by group_tup) each epoch
 * removes duplicate Tuples based on group_tup
 */
OpCreator distinct(GroupingFunc groupby_func) {
    return [groupby_func](const Operator& next_op) {
        auto h_tbl = std::make_shared<std::unordered_map<std::string, Tuple>>();
        auto reset_counter = std::make_shared<int>(0);
        
        return Operator{
            .next = [h_tbl, groupby_func](const Tuple& tup) {
                Tuple grouping_key = groupby_func(tup);
                std::string key_str = stringOfTuple(grouping_key);
                (*h_tbl)[key_str] = grouping_key;
            },
            .reset = [h_tbl, next_op, reset_counter](const Tuple& tup) {
                (*reset_counter)++;
                
                for (const auto& [_, key_tuple] : *h_tbl) {
                    Tuple merged_tup = tup;
                    for (const auto& [k, v] : key_tuple) {
                        merged_tup[k] = v;
                    }
                    next_op.next(merged_tup);
                }
                
                next_op.reset(tup);
                h_tbl->clear();
            }
        };
    };
}

/**
 * Just sends both next and reset directly to two different downstream operators
 * i.e. splits the stream processing in two
 */
Operator split(const Operator& l, const Operator& r) {
    return {
        .next = [l, r](const Tuple& tup) {
            l.next(tup);
            r.next(tup);
        },
        .reset = [l, r](const Tuple& tup) {
            l.reset(tup);
            r.reset(tup);
        }
    };
}

using KeyExtractor = std::function<std::pair<Tuple, Tuple>(const Tuple&)>;

/**
 * Initial shot at a join semantic that doesn't require maintining entire state
 * Functions left and right transform input tuples into a key,value pair of tuples
 * The key determines a canonical tuple against which the other stream will match
 * The value determines extra fields which should be saved and added when a
 * match is made
 *
 * Requires tuples to have epoch id as int value in field referenced by eid_key.
 */
DblOpCreator join(KeyExtractor left_extractor, KeyExtractor right_extractor, 
                 const std::string& eid_key = "eid") {
    return [left_extractor, right_extractor, eid_key](const Operator& next_op) {
        auto h_tbl1 = std::make_shared<std::unordered_map<std::string, Tuple>>();
        auto h_tbl2 = std::make_shared<std::unordered_map<std::string, Tuple>>();
        auto left_curr_epoch = std::make_shared<int>(0);
        auto right_curr_epoch = std::make_shared<int>(0);
        
        auto handleJoinSide = [next_op, eid_key](
            std::shared_ptr<std::unordered_map<std::string, Tuple>> curr_h_tbl,
            std::shared_ptr<std::unordered_map<std::string, Tuple>> other_h_tbl,
            std::shared_ptr<int> curr_epoch_ref,
            std::shared_ptr<int> other_epoch_ref,
            KeyExtractor f) {
                
            return Operator{
                .next = [curr_h_tbl, other_h_tbl, curr_epoch_ref, other_epoch_ref, f, next_op, eid_key](const Tuple& tup) {
                    // Extract the grouping key and remaining values
                    auto [key, vals] = f(tup);
                    
                    // Extract event ID from input tup
                    int curr_epoch = lookupInt(eid_key, tup);
                    
                    while (curr_epoch > *curr_epoch_ref) {
                        if (*other_epoch_ref > *curr_epoch_ref) {
                            Tuple reset_tup;
                            reset_tup[eid_key] = OpResult(*curr_epoch_ref);
                            next_op.reset(reset_tup);
                        }
                        (*curr_epoch_ref)++;
                    }
                    
                    Tuple new_tup = key;
                    new_tup[eid_key] = OpResult(curr_epoch);
                    
                    std::string key_str = stringOfTuple(new_tup);
                    auto it = other_h_tbl->find(key_str);
                    
                    if (it != other_h_tbl->end()) {
                        // Found a match, combine and send downstream
                        Tuple result_tup = new_tup;
                        
                        // Add values from both sides
                        for (const auto& [k, v] : vals) {
                            result_tup[k] = v;
                        }
                        
                        for (const auto& [k, v] : it->second) {
                            result_tup

Prompt: Continue

Ill continue the C++ translation of the OCaml code:

```cpp
                        for (const auto& [k, v] : it->second) {
                            result_tup[k] = v;
                        }
                        
                        // Remove from other table and send downstream
                        other_h_tbl->erase(key_str);
                        next_op.next(result_tup);
                    } else {
                        // No match yet, store for later
                        (*curr_h_tbl)[key_str] = vals;
                    }
                },
                .reset = [curr_epoch_ref, other_epoch_ref, next_op, eid_key](const Tuple& tup) {
                    int curr_epoch = lookupInt(eid_key, tup);
                    
                    while (curr_epoch > *curr_epoch_ref) {
                        if (*other_epoch_ref > *curr_epoch_ref) {
                            Tuple reset_tup;
                            reset_tup[eid_key] = OpResult(*curr_epoch_ref);
                            next_op.reset(reset_tup);
                        }
                        (*curr_epoch_ref)++;
                    }
                }
            };
        };
        
        return std::make_pair(
            handleJoinSide(h_tbl1, h_tbl2, left_curr_epoch, right_curr_epoch, left_extractor),
            handleJoinSide(h_tbl2, h_tbl1, right_curr_epoch, left_curr_epoch, right_extractor)
        );
    };
}

/**
 * (join utility)
 * Returns a new tuple with only the keys included in the first of each pair in keys
 * These keys are renamed to the second of each pair in keys
 * Use in conjunction with the join implementation above to get the "join left
 * with right on left.x = right.y" kind of thing
 */
Tuple renameFilteredKeys(const std::vector<std::pair<std::string, std::string>>& renamings_pairs,
                        const Tuple& in_tup) {
    Tuple new_tup;
    for (const auto& [old_key, new_key] : renamings_pairs) {
        auto it = in_tup.find(old_key);
        if (it != in_tup.end()) {
            new_tup[new_key] = it->second;
        }
    }
    return new_tup;
}

/**
 * Main entry point and implementation for simple header-dump operation
 */

// Implementation of IPv4Address class
IPv4Address::IPv4Address(const std::string& address) {
    if (address.empty()) {
        address_ = 0;
        return;
    }
    
    // Simple parser for IPv4 addresses in format "a.b.c.d"
    int a, b, c, d;
    if (sscanf(address.c_str(), "%d.%d.%d.%d", &a, &b, &c, &d) != 4) {
        throw std::runtime_error("Invalid IPv4 address format: " + address);
    }
    
    address_ = (a << 24) | (b << 16) | (c << 8) | d;
}

std::string IPv4Address::toString() const {
    return std::to_string((address_ >> 24) & 0xFF) + "." +
           std::to_string((address_ >> 16) & 0xFF) + "." +
           std::to_string((address_ >> 8) & 0xFF) + "." +
           std::to_string(address_ & 0xFF);
}

bool IPv4Address::operator<(const IPv4Address& other) const {
    return address_ < other.address_;
}

bool IPv4Address::operator==(const IPv4Address& other) const {
    return address_ == other.address_;
}

// Utility function implementations
OpCreator ident() {
    return [](const Operator& next_op) {
        return map([](const Tuple& tup) {
            Tuple result;
            for (const auto& [key, value] : tup) {
                if (key != "eth.src" && key != "eth.dst") {
                    result[key] = value;
                }
            }
            return result;
        })(next_op);
    };
}

OpCreator countPkts() {
    return [](const Operator& next_op) {
        return chainOp(epoch(1.0, "eid"), 
               chainOp(groupby(singleGroup, counter, "pkts"), 
                       next_op));
    };
}

OpCreator pktsPerSrcDst() {
    return [](const Operator& next_op) {
        return chainOp(epoch(1.0, "eid"), 
               chainOp(groupby([](const Tuple& tup) { 
                   return filterGroups({"ipv4.src", "ipv4.dst"}, tup); 
               }, counter, "pkts"), 
                       next_op));
    };
}

OpCreator distinctSrcs() {
    return [](const Operator& next_op) {
        return chainOp(epoch(1.0, "eid"), 
               chainOp(distinct([](const Tuple& tup) { 
                   return filterGroups({"ipv4.src"}, tup); 
               }), 
               chainOp(groupby(singleGroup, counter, "srcs"), 
                       next_op)));
    };
}

// Sonata 1
OpCreator tcpNewCons() {
    return [](const Operator& next_op) {
        const int threshold = 40;
        return chainOp(epoch(1.0, "eid"), 
               chainOp(filter([](const Tuple& tup) {
                   return getMappedInt("ipv4.proto", tup) == 6 &&
                          getMappedInt("l4.flags", tup) == 2;
               }), 
               chainOp(groupby([](const Tuple& tup) { 
                   return filterGroups({"ipv4.dst"}, tup); 
               }, counter, "cons"), 
               chainOp(filter(keyGeqInt("cons", threshold)), 
                       next_op))));
    };
}

// Sonata 2
OpCreator sshBruteForce() {
    return [](const Operator& next_op) {
        const int threshold = 40;
        return chainOp(epoch(1.0, "eid"), 
               chainOp(filter([](const Tuple& tup) {
                   return getMappedInt("ipv4.proto", tup) == 6 &&
                          getMappedInt("l4.dport", tup) == 22;
               }), 
               chainOp(distinct([](const Tuple& tup) { 
                   return filterGroups({"ipv4.src", "ipv4.dst", "ipv4.len"}, tup); 
               }), 
               chainOp(groupby([](const Tuple& tup) { 
                   return filterGroups({"ipv4.dst", "ipv4.len"}, tup); 
               }, counter, "srcs"), 
               chainOp(filter(keyGeqInt("srcs", threshold)), 
                       next_op)))));
    };
}

// Sonata 3
OpCreator superSpreader() {
    return [](const Operator& next_op) {
        const int threshold = 40;
        return chainOp(epoch(1.0, "eid"), 
               chainOp(distinct([](const Tuple& tup) { 
                   return filterGroups({"ipv4.src", "ipv4.dst"}, tup); 
               }), 
               chainOp(groupby([](const Tuple& tup) { 
                   return filterGroups({"ipv4.src"}, tup); 
               }, counter, "dsts"), 
               chainOp(filter(keyGeqInt("dsts", threshold)), 
                       next_op))));
    };
}

// Sonata 4
OpCreator portScan() {
    return [](const Operator& next_op) {
        const int threshold = 40;
        return chainOp(epoch(1.0, "eid"), 
               chainOp(distinct([](const Tuple& tup) { 
                   return filterGroups({"ipv4.src", "l4.dport"}, tup); 
               }), 
               chainOp(groupby([](const Tuple& tup) { 
                   return filterGroups({"ipv4.src"}, tup); 
               }, counter, "ports"), 
               chainOp(filter(keyGeqInt("ports", threshold)), 
                       next_op))));
    };
}

// Sonata 5
OpCreator ddos() {
    return [](const Operator& next_op) {
        const int threshold = 45;
        return chainOp(epoch(1.0, "eid"), 
               chainOp(distinct([](const Tuple& tup) { 
                   return filterGroups({"ipv4.src", "ipv4.dst"}, tup); 
               }), 
               chainOp(groupby([](const Tuple& tup) { 
                   return filterGroups({"ipv4.dst"}, tup); 
               }, counter, "srcs"), 
               chainOp(filter(keyGeqInt("srcs", threshold)), 
                       next_op))));
    };
}

// Sonata 6 --- Note this implements the Sonata semantic of this query
// *NOT* the intended semantic from NetQRE
std::vector<Operator> synFloodSonata(const Operator& next_op) {
    const int threshold = 3;
    const float epoch_dur = 1.0;
    
    // Helper functions for synFloodSonata
    auto syns = [epoch_dur](const Operator& next_op) {
        return chainOp(epoch(epoch_dur, "eid"), 
               chainOp(filter([](const Tuple& tup) {
                   return getMappedInt("ipv4.proto", tup) == 6 &&
                          getMappedInt("l4.flags", tup) == 2;
               }), 
               chainOp(groupby([](const Tuple& tup) { 
                   return filterGroups({"ipv4.dst"}, tup); 
               }, counter, "syns"), 
                       next_op)));
    };
    
    auto synacks = [epoch_dur](const Operator& next_op) {
        return chainOp(epoch(epoch_dur, "eid"), 
               chainOp(filter([](const Tuple& tup) {
                   return getMappedInt("ipv4.proto", tup) == 6 &&
                          getMappedInt("l4.flags", tup) == 18;
               }), 
               chainOp(groupby([](const Tuple& tup) { 
                   return filterGroups({"ipv4.src"}, tup); 
               }, counter, "synacks"), 
                       next_op)));
    };
    
    auto acks = [epoch_dur](const Operator& next_op) {
        return chainOp(epoch(epoch_dur, "eid"), 
               chainOp(filter([](const Tuple& tup) {
                   return getMappedInt("ipv4.proto", tup) == 6 &&
                          getMappedInt("l4.flags", tup) == 16;
               }), 
               chainOp(groupby([](const Tuple& tup) { 
                   return filterGroups({"ipv4.dst"}, tup); 
               }, counter, "acks"), 
                       next_op)));
    };
    
    // Define join operations
    auto join_stage1 = [threshold](const Operator& next_op) {
        auto [join_op1, join_op2] = chainDblOp(
            join(
                [](const Tuple& tup) {
                    return std::make_pair(
                        filterGroups({"host"}, tup),
                        filterGroups({"syns+synacks"}, tup)
                    );
                },
                [](const Tuple& tup) {
                    return std::make_pair(
                        renameFilteredKeys({{"ipv4.dst", "host"}}, tup),
                        filterGroups({"acks"}, tup)
                    );
                }
            ),
            chainOp(map([](const Tuple& tup) {
                Tuple result = tup;
                result["syns+synacks-acks"] = OpResult(
                    getMappedInt("syns+synacks", tup) - 
                    getMappedInt("acks", tup)
                );
                return result;
            }),
            chainOp(filter(keyGeqInt("syns+synacks-acks", threshold)),
                    next_op)));
        
        return std::make_pair(join_op1, join_op2);
    };
    
    auto join_stage2 = [](const Operator& join_op1) {
        auto [join_op3, join_op4] = chainDblOp(
            join(
                [](const Tuple& tup) {
                    return std::make_pair(
                        renameFilteredKeys({{"ipv4.dst", "host"}}, tup),
                        filterGroups({"syns"}, tup)
                    );
                },
                [](const Tuple& tup) {
                    return std::make_pair(
                        renameFilteredKeys({{"ipv4.src", "host"}}, tup),
                        filterGroups({"synacks"}, tup)
                    );
                }
            ),
            chainOp(map([](const Tuple& tup) {
                Tuple result = tup;
                result["syns+synacks"] = OpResult(
                    getMappedInt("syns", tup) + 
                    getMappedInt("synacks", tup)
                );
                return result;
            }),
            join_op1));
        
        return std::make_pair(join_op3, join_op4);
    };
    
    // Connect the pipeline
    auto [join_op1, join_op2] = join_stage1(next_op);
    auto [join_op3, join_op4] = join_stage2(join_op1);
    
    return {
        syns(join_op3),
        synacks(join_op4),
        acks(join_op2)
    };
}

// Sonata 7
std::vector<Operator> completedFlows(const Operator& next_op) {
    const int threshold = 1;
    const float epoch_dur = 30.0;
    
    auto syns = [epoch_dur](const Operator& next_op) {
        return chainOp(epoch(epoch_dur, "eid"), 
               chainOp(filter([](const Tuple& tup) {
                   return getMappedInt("ipv4.proto", tup) == 6 &&
                          getMappedInt("l4.flags", tup) == 2;
               }), 
               chainOp(groupby([](const Tuple& tup) { 
                   return filterGroups({"ipv4.dst"}, tup); 
               }, counter, "syns"), 
                       next_op)));
    };
    
    auto fins = [epoch_dur](const Operator& next_op) {
        return chainOp(epoch(epoch_dur, "eid"), 
               chainOp(filter([](const Tuple& tup) {
                   return getMappedInt("ipv4.proto", tup) == 6 &&
                          (getMappedInt("l4.flags", tup) & 1) == 1;
               }), 
               chainOp(groupby([](const Tuple& tup) { 
                   return filterGroups({"ipv4.src"}, tup); 
               }, counter, "fins"), 
                       next_op)));
    };
    
    auto [op1, op2] = chainDblOp(
        join(
            [](const Tuple& tup) {
                return std::make_pair(
                    renameFilteredKeys({{"ipv4.dst", "host"}}, tup),
                    filterGroups({"syns"}, tup)
                );
            },
            [](const Tuple& tup) {
                return std::make_pair(
                    renameFilteredKeys({{"ipv4.src", "host"}}, tup),
                    filterGroups({"fins"}, tup)
                );
            }
        ),
        chainOp(map([](const Tuple& tup) {
            Tuple result = tup;
            result["diff"] = OpResult(
                getMappedInt("syns", tup) - 
                getMappedInt("fins", tup)
            );
            return result;
        }),
        chainOp(filter(keyGeqInt("diff", threshold)),
                next_op)));
    
    return {syns(op1), fins(op2)};
}

// Sonata 8
std::vector<Operator> slowloris(const Operator& next_op) {
    const int t1 = 5;    // Threshold for connections
    const int t2 = 500;  // Threshold for bytes
    const int t3 = 90;   // Threshold for bytes per connection
    const float epoch_dur = 1.0;
    
    auto n_conns = [epoch_dur, t1](const Operator& next_op) {
        return chainOp(epoch(epoch_dur, "eid"), 
               chainOp(filter([](const Tuple& tup) {
                   return getMappedInt("ipv4.proto", tup) == 6;
               }), 
               chainOp(distinct([](const Tuple& tup) { 
                   return filterGroups({"ipv4.src", "ipv4.dst", "l4.sport"}, tup); 
               }), 
               chainOp(groupby([](const Tuple& tup) { 
                   return filterGroups({"ipv4.dst"}, tup); 
               }, counter, "n_conns"), 
               chainOp(filter([t1](const Tuple& tup) {
                   return getMappedInt("n_conns", tup) >= t1;
               }),
                       next_op)))));
    };
    
    auto n_bytes = [epoch_dur, t2](const Operator& next_op) {
        return chainOp(epoch(epoch_dur, "eid"), 
               chainOp(filter([](const Tuple& tup) {
                   return getMappedInt("ipv4.proto", tup) == 6;
               }), 
               chainOp(groupby([](const Tuple& tup) { 
                   return filterGroups({"ipv4.dst"}, tup); 
               }, [](const OpResult& val, const Tuple& tup) {
                   return sumInts("ipv4.len", val, tup);
               }, "n_bytes"), 
               chainOp(filter([t2](const Tuple& tup) {
                   return getMappedInt("n_bytes", tup) >= t2;
               }),
                       next_op))));
    };
    
    auto [op1, op2] = chainDblOp(
        join(
            [](const Tuple& tup) {
                return std::make_pair(
                    filterGroups({"ipv4.dst"}, tup),
                    filterGroups({"n_conns"}, tup)
                );
            },
            [](const Tuple& tup) {
                return std::make_pair(
                    filterGroups({"ipv4.dst"}, tup),
                    filterGroups({"n_bytes"}, tup)
                );
            }
        ),
        chainOp(map([](const Tuple& tup) {
            Tuple result = tup;
            result["bytes_per_conn"] = OpResult(
                getMappedInt("n_bytes", tup) / 
                getMappedInt("n_conns", tup)
            );
            return result;
        }),
        chainOp(filter([t3](const Tuple& tup) {
            return getMappedInt("bytes_per_conn", tup) <= t3;
        }),
        next_op)));
    
    return {n_conns(op1), n_bytes(op2)};
}

std::vector<Operator> joinTest(const Operator& next_op) {
    const float epoch_dur = 1.0;
    
    auto syns = [epoch_dur](const Operator& next_op) {
        return chainOp(epoch(epoch_dur, "eid"), 
               chainOp(filter([](const Tuple& tup) {
                   return getMappedInt("ipv4.proto", tup) == 6 &&
                          getMappedInt("l4.flags", tup) == 2;
               }), 
                       next_op));
    };
    
    auto synacks = [epoch_dur](const Operator& next_op) {
        return chainOp(epoch(epoch_dur, "eid"), 
               chainOp(filter([](const Tuple& tup) {
                   return getMappedInt("ipv4.proto", tup) == 6 &&
                          getMappedInt("l4.flags", tup) == 18;
               }), 
                       next_op));
    };
    
    auto [op1, op2] = chainDblOp(
        join(
            [](const Tuple& tup) {
                return std::make_pair(
                    renameFilteredKeys({{"ipv4.src", "host"}}, tup),
                    renameFilteredKeys({{"ipv4.dst", "remote"}}, tup)
                );
            },
            [](const Tuple& tup) {
                return std::make_pair(
                    renameFilteredKeys({{"ipv4.dst", "host"}}, tup),
                    filterGroups({"time"}, tup)
                );
            }
        ),
        next_op);
    
    return {syns(op1), synacks(op2)};
}

OpCreator q3() {
    return [](const Operator& next_op) {
        return chainOp(epoch(100.0, "eid"), 
               chainOp(distinct([](const Tuple& tup) { 
                   return filterGroups({"ipv4.src", "ipv4.dst"}, tup); 
               }), 
                       next_op));
    };
}

OpCreator q4() {
    return [](const Operator& next_op) {
        return chainOp(epoch(10000.0, "eid"), 
               chainOp(groupby([](const Tuple& tup) { 
                   return filterGroups({"ipv4.dst"}, tup); 
               }, counter, "pkts"), 
                       next_op));
    };
}

// Main function
int main() {
    std::vector<Operator> queries = {
        chainOp(ident(), dumpTupleOp(stdout))
    };
    
    // Create test tuples
    for (int i = 0; i < 20; i++) {
        Tuple tup;
        tup["time"] = OpResult(0.0f + static_cast<float>(i));
        
        // Create MAC addresses
        std::vector<uint8_t> src_mac = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
        std::vector<uint8_t> dst_mac = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
        
        tup["eth.src"] = OpResult(src_mac);
        tup["eth.dst"] = OpResult(dst_mac);
        tup["eth.ethertype"] = OpResult(0x0800);
        
        tup["ipv4.hlen"] = OpResult(20);
        tup["ipv4.proto"] = OpResult(6);
        tup["ipv4.len"] = OpResult(60);
        tup["ipv4.src"] = OpResult(IPv4Address("127.0.0.1"));
        tup["ipv4.dst"] = OpResult(IPv4Address("127.0.0.1"));
        
        tup["l4.sport"] = OpResult(440);
        tup["l4.dport"] = OpResult(50000);
        tup["l4.flags"] = OpResult(10);
        
        // Run each query on the tuple
        for (const auto& query : queries) {
            query.next(tup);
        }
    }
    
    std::cout << "Done" << std::endl;
    return 0;
}
```

Would you like me to explain any specific part of the translation in more detail?