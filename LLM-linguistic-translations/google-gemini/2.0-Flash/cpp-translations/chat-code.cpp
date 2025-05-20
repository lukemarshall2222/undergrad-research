#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <variant>
#include <iomanip>
#include <sstream>
#include <optional>
#include <functional>
#include <algorithm>
#include <cmath>
#include <fstream>
#include <sstream>
#include <unordered_map>

namespace Ipaddr {
namespace V4 {
struct t {
  uint32_t addr;

  bool operator<(const t& other) const { return addr < other.addr; }
};

std::string to_string(const t& ip) {
  unsigned char bytes[4];
  bytes[0] = (ip.addr >> 24) & 0xFF;
  bytes[1] = (ip.addr >> 16) & 0xFF;
  bytes[2] = (ip.addr >> 8) & 0xFF;
  bytes[3] = ip.addr & 0xFF;
  std::stringstream ss;
  ss << static_cast<int>(bytes[0]) << "." << static_cast<int>(bytes[1]) << "."
     << static_cast<int>(bytes[2]) << "." << static_cast<int>(bytes[3]);
  return ss.str();
}

t of_string_exn(const std::string& s) {
  t ip;
  unsigned int b1, b2, b3, b4;
  if (sscanf(s.c_str(), "%u.%u.%u.%u", &b1, &b2, &b3, &b4) == 4) {
    ip.addr = (b1 << 24) | (b2 << 16) | (b3 << 8) | b4;
    return ip;
  }
  throw std::invalid_argument("Invalid IPv4 address string: " + s);
}
} // namespace V4
} // namespace Ipaddr

namespace Bytes {
struct t {
  std::vector<unsigned char> data;

  bool operator<(const t& other) const { return data < other.data; }
};

unsigned char get_uint8(const t& bytes, size_t index) {
  if (index < bytes.data.size()) {
    return bytes.data[index];
  }
  throw std::out_of_range("Index out of bounds");
}

t of_string(const std::string& s) {
  return {std::vector<unsigned char>(s.begin(), s.end())};
}
} // namespace Bytes

// Forward declaration
template <typename T> std::string string_of_op_result(const T& input);

// Operators act on named "tuples" which are maps from strings to op_result types
//**************************************************************************************

using op_result = std::variant<float, int, Ipaddr::V4::t, Bytes::t, std::monostate>;

template <typename T>
struct Tuple {
  using map_type = std::map<std::string, T>;
  map_type data;

  template <typename... Args>
  void add(const std::string& key, Args&&... value) {
    data[key] = T(std::forward<Args>(value)...);
  }

  template <typename K>
  const T& find(const K& key) const {
    auto it = data.find(key);
    if (it != data.end()) {
      return it->second;
    }
    throw std::out_of_range("Key not found: " + std::string(key));
  }

  template <typename K>
  std::optional<std::reference_wrapper<const T>> find_opt(const K& key) const {
    auto it = data.find(key);
    if (it != data.end()) {
      return std::ref(it->second);
    }
    return std::nullopt;
  }

  template <typename K, typename V>
  void iter(std::function<void(const K&, const V&)> func) const {
    for (const auto& pair : data) {
      func(pair.first, pair.second);
    }
  }

  template <typename K, typename V>
  auto fold(std::function<std::string(const K&, const V&, std::string)> func,
            std::string acc) const {
    for (const auto& pair : data) {
      acc = func(pair.first, pair.second, acc);
    }
    return acc;
  }

  template <typename K, typename V>
  Tuple filter(std::function<bool(const K&, const V&)> predicate) const {
    Tuple result;
    for (const auto& pair : data) {
      if (predicate(pair.first, pair.second)) {
        result.data[pair.first] = pair.second;
      }
    }
    return result;
  }

  Tuple union_(std::function<std::optional<op_result>(const std::string&, const T&, const T&)> remapping_function, const Tuple& other) const {
        Tuple result = *this;
        for (const auto& pair : other.data) {
            auto it = result.data.find(pair.first);
            if (it != result.data.end()) {
                if (auto remapped = remapping_function(pair.first, it->second, pair.second)) {
                    result.data[pair.first] = *remapped;
                }
            } else {
                result.data[pair.first] = pair.second;
            }
        }
        return result;
    }

  static Tuple of_seq(const std::vector<std::pair<std::string, T>>& list) {
    Tuple result;
    for (const auto& pair : list) {
      result.data[pair.first] = pair.second;
    }
    return result;
  }

  static Tuple singleton(const std::string& key, const T& value) {
    Tuple result;
    result.data[key] = value;
    return result;
  }

  bool operator<(const Tuple& other) const { return data < other.data; }
  bool operator==(const Tuple& other) const { return data == other.data; }
};

using tuple = Tuple<op_result>;

struct operator_t {
  std::function<void(const tuple&)> next;
  std::function<void(const tuple&)> reset;
};

using op_creator = std::function<operator_t(operator_t)>;
using dbl_op_creator = std::function<std::pair<operator_t, operator_t>(operator_t)>;

// Right associative "chaining" operator
// for passing output of one operator to the next under cps-style operator constructors
operator_t operator|(op_creator op_creator_func, operator_t next_op) {
  return op_creator_func(next_op);
}

std::pair<operator_t, operator_t> operator|(dbl_op_creator op_creator_func,
                                            operator_t op) {
  return op_creator_func(op);
}

// Conversion utilities
//*************************************************************************************

// formats the 6 bytes of the MAC address as a colon-separated string in hex
std::string string_of_mac(const Bytes::t& buf) {
  auto byte_at = [&](size_t index) { return Bytes::get_uint8(buf, index); };
  std::stringstream ss;
  ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte_at(0))
     << ":" << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte_at(1))
     << ":" << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte_at(2))
     << ":" << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte_at(3))
     << ":" << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte_at(4))
     << ":" << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte_at(5));
  return ss.str();
}

// converts TCP flags into a human-readable string representation by matching
// flags to formatted output
std::string tcp_flags_to_strings(int flags) {
  std::map<std::string, int> tcp_flags_map = {
      {"FIN", 1 << 0}, {"SYN", 1 << 1}, {"RST", 1 << 2}, {"PSH", 1 << 3},
      {"ACK", 1 << 4}, {"URG", 1 << 5}, {"ECE", 1 << 6}, {"CWR", 1 << 7}};

  std::string acc = "";
  for (const auto& pair : tcp_flags_map) {
    if ((flags & pair.second) == pair.second) {
      if (!acc.empty()) {
        acc += "|";
      }
      acc += pair.first;
    }
  }
  return acc;
}

// checks if input is an int op_result, raises exception otherwise
int int_of_op_result(const op_result& input) {
  if (std::holds_alternative<int>(input)) {
    return std::get<int>(input);
  }
  throw std::runtime_error("Trying to extract int from non-int result");
}

// checks if input is a float op_result, raises exception otherwise
float float_of_op_result(const op_result& input) {
  if (std::holds_alternative<float>(input)) {
    return std::get<float>(input);
  }
  throw std::runtime_error("Trying to extract float from non-float result");
}

// returns the human-readable version of each op_result value
template <typename T>
std::string string_of_op_result(const T& input) {
  if (std::holds_alternative<float>(input)) {
    std::stringstream ss;
    ss << std::fixed << std::setprecision(6) << std::get<float>(input);
    return ss.str();
  } else if (std::holds_alternative<int>(input)) {
    return std::to_string(std::get<int>(input));
  } else if (std::holds_alternative<Ipaddr::V4::t>(input)) {
    return Ipaddr::V4::to_string(std::get<Ipaddr::V4::t>(input));
  } else if (std::holds_alternative<Bytes::t>(input)) {
    return string_of_mac(std::get<Bytes::t>(input));
  } else if (std::holds_alternative<std::monostate>(input)) {
    return "Empty";
  }
  return "Unknown op_result type";
}

// outputs the tuple in a human-readable form e.g.
// "ipv4.src" => 192.168.1.1, "packet_count" => 10,
std::string string_of_tuple(const tuple& input_tuple) {
  return input_tuple.fold(
      [](const std::string& key, const op_result& val, std::string acc) {
        return acc + "\"" + key + "\" => " + string_of_op_result(val) + ", ";
      },
      "");
}

// prints formatted representation of a Tuple
void dump_tuple(std::ostream& outc, const tuple& tup) {
  outc << string_of_tuple(tup) << std::endl;
}

// retrieves the int value of the op_result associated with a given key
// in the given Tuple (Map<string, op_result>)
int lookup_int(const std::string& key, const tuple& tup) {
  return int_of_op_result(tup.find(key));
}

// retrieves the float value of the op_result associated with a given key
// in the given Tuple (Map<string, op_result>)
float lookup_float(const std::string& key, const tuple& tup) {
  return float_of_op_result(tup.find(key));
}

namespace Utils {} // namespace Utils

const int init_table_size = 10000;

namespace Builtins {

// Dump all fields of all tuples to the given output channel
// Note that dump is terminal in that it does not take a continuation operator
// as argument
// returns an operator record with two functions:
//     next: dumps a given Tuple to the given output
//     reset: prints a reset message if the given show_reset is true
operator_t dump_tuple(std::ostream& outc, bool show_reset = false) {
  return {
      [&](const tuple& tup) { Builtins::dump_tuple(outc, tup); },
      [&](const tuple& tup) {
        if (show_reset) {
          Builtins::dump_tuple(outc, tup);
          outc << "[reset]" << std::endl;
        }
      }};
}

// Tries to dump a nice csv-style output
// Assumes all tuples have the same fields in the same order...
// writes tuples to an output channel in CSV format
// constructs operator record with two fields:
//     next: process tuples
//     reset: does nothing
operator_t dump_as_csv(std::ostream& outc,
                       std::optional<std::pair<std::string, std::string>> static_field = std::nullopt,
                       bool header = true) {
  std::shared_ptr<bool> first = std::make_shared<bool>(header);
  return {
      [&](const tuple& tup) {
        if (*first) {
          if (static_field.has_value()) {
            outc << static_field.value().first << ",";
          }
          tup.iter([&](const std::string& key, const op_result&) { outc << key << ","; });
          outc << std::endl;
          *first = false;
        }
        if (static_field.has_value()) {
          outc << static_field.value().second << ",";
        }
        tup.iter([&](const std::string&, const op_result& value) {
          outc << string_of_op_result(value) << ",";
        });
        outc << std::endl;
      },
      [](const tuple&) {}};
}

// Dumps csv in Walt's canonical csv format: src_ip, dst_ip, src_l4_port,
// dst_l4_port, packet_count, byte_count, epoch_id
// Unused fields are zeroed, map packet length to src_l4_port for ssh brute
// force
operator_t dump_walts_csv(const std::string& filename) {
  std::shared_ptr<std::ofstream> outc =
      std::make_shared<std::ofstream>();
  std::shared_ptr<bool> first = std::make_shared<bool>(true);
  return {
      [&](const tuple& tup) {
        if (*first) {
          outc->open(filename);
          *first = false;
        }
        *outc << string_of_op_result(tup.find("ipv4.src")) << ","
              << string_of_op_result(tup.find("ipv4.dst")) << ","
              << string_of_op_result(tup.find("l4.sport")) << ","
              << string_of_op_result(tup.find("l4.dport")) << ","
              << string_of_op_result(tup.find("packet_count")) << ","
              << string_of_op_result(tup.find("byte_count")) << ","
              << string_of_op_result(tup.find("epoch_id")) << std::endl;
      },
      [](const tuple&) {}};
}

// input is either "0" or and IPv4 address in string format,
// returns corresponding op_result
op_result get_ip_or_zero(const std::string& input) {
  if (input == "0") {
    return 0;
  } else {
    return Ipaddr::V4::of_string_exn(input);
  }
}

// Reads an intermediate result CSV in Walt's canonical format
// Injects epoch ids and incomming tuple counts into reset call
// TODO: read files in RR order...
//     otherwise the whole file gets cached in joins
// reads multiple CSV files, extracts their network flow data, processes it into
// tuples, and applies ops on the extracted data
void read_walts_csv(
    const std::vector<std::string>& file_names,
    const std::vector<operator_t>& ops,
    const std::string& epoch_id_key = "eid") {
  std::vector<std::tuple<std::ifstream, std::shared_ptr<int>, std::shared_ptr<int>>>
      inchs_eids_tupcount;
  for (const auto& filename : file_names) {
    inchs_eids_tupcount.emplace_back(
        std::ifstream(filename), std::make_shared<int>(0),
        std::make_shared<int>(0));
  }

  std::shared_ptr<int> running =
      std::make_shared<int>(ops.size());

  while (*running > 0) {
    for (size_t i = 0; i < inchs_eids_tupcount.size(); ++i) {
      auto& [in_ch, eid, tup_count] = inchs_eids_tupcount[i];
      if (*eid >= 0 && i < ops.size()) {
        operator_t& op = ops[i];
        std::string line;
        if (std::getline(in_ch, line)) {
          unsigned int src_l4_port, dst_l4_port, packet_count, byte_count,
              epoch_id;
          char src_ip_str[64], dst_ip_str[64];
          if (sscanf(line.c_str(), "%[^,],%[^,],%u,%u,%u,%u,%u", src_ip_str,
                     dst_ip_str, &src_l4_port, &dst_l4_port, &packet_count,
                     &byte_count, &epoch_id) == 7) {
            tuple p;
            p.add("ipv4.src", get_ip_or_zero(src_ip_str));
            p.add("ipv4.dst", get_ip_or_zero(dst_ip_str));
            p.add("l4.sport", static_cast<int>(src_l4_port));
            p.add("l4.dport", static_cast<int>(dst_l4_port));
            p.add("packet_count", static_cast<int>(packet_count));
            p.add("byte_count", static_cast<int>(byte_count));
            p.add(epoch_id_key, static_cast<int>(epoch_id));
            (*tup_count)++;

            if (epoch_id > *eid) {
              while (epoch_id > *eid) {
                tuple reset_tup;
                reset_tup.add("tuples", *tup_count);
                reset_tup.add(epoch_id_key, *eid);
                op.reset(reset_tup);
                *tup_count = 0;
                (*eid)++;
              }
            }
            tuple next_tup;
            next_tup.add("tuples", *tup_count);
            next_tup.union_([](const std::string&, const op_result& a, const op_result&) -> std::optional<op_result> { return a; }, p);
            op.next(next_tup);
          } else {
            std::cerr << "Failed to scan line: " << line << std::endl;
            throw std::runtime_error("Scan failure");
          }
        } else if (in_ch.eof()) {
          tuple reset_tup;
          reset_tup.add("tuples", *tup_count);
          reset_tup.add(epoch_id_key, *eid + 1);
          op.reset(reset_tup);
          (*running)--;
          *eid = -1;
        } else if (in_ch.fail()) {
          std::cerr << "Error reading file." << std::endl;
          throw std::runtime_error("File read error");
        }
      }
    }
  }
  std::cout << "Done." << std::endl;
}

// Write the number of tuples passing through this operator each epoch
// to the out_channel
// tracks how many tuples processed per epoch and logs it to outc
op_creator meta_meter(std::optional<std::string> static_field,
                      const std::string& name, std::ostream& outc) {
  return [&](operator_t next_op) {
    std::shared_ptr<int> epoch_count = std::make_shared<int>(0);
    std::shared_ptr<int> tups_count = std::make_shared<int>(0);
    return operator_t{
        [&](const tuple& tup) {
          (*tups_count)++;
          next_op.next(tup);
        },
        [&](const tuple& tup) {
          outc << *epoch_count << "," << name << "," << *tups_count << ",";
          if (static_field.has_value()) {
            outc << static_field.value();
          }
          outc << std::endl;
          *tups_count = 0;
          (*epoch_count)++;
          next_op.reset(tup);
        }};
  };
}

// Passes tuples through to op
// Resets op every w seconds
// Adds epoch id to tuple under key_out
op_creator epoch(float epoch_width, const std::string& key_out) {
  return [&](operator_t next_op) {
    std::shared_ptr<double> epoch_boundary = std::make_shared<double>(0.0);
    std::shared_ptr<int> eid = std::make_shared<int>(0);
    return operator_t{
        [&](const tuple& tup) {
          double time = float_of_op_result(tup.find("time"));
          if (*epoch_boundary == 0.0) {
            *epoch_boundary = time + epoch_width;
          } else if (time >= *epoch_boundary) {
            while (time >= *epoch_boundary) {
              next_op.reset(Tuple<op_result>::singleton(key_out, *eid));
              *epoch_boundary += epoch_width;
              (*eid)++;
            }
          }
          tuple next_tup = tup;
          next_tup.add(key_out, *eid);
          next_op.next(next_tup);
        },
        [&](const tuple&) {
          next_op.reset(Tuple<op_result>::singleton(key_out, *eid));
          *epoch_boundary = 0.0;
          *eid = 0;
        }};
  };
}

// Passes only tuples where f applied to the tuple returns true
// creates a filtering operator, applying the given operator if this one
// returns true otherwise returning false
op_creator filter(std::function<bool(const tuple&)> f) {
  return [&](operator_t next_op) {
    return operator_t{
        [&](const tuple& tup) {
          if (f(tup)) {
            next_op.next(tup);
          }
        },
        [&](const tuple& tup) { next_op.reset(tup); }};
  };
}

// (filter utility)
// comparison function for testing int values against a threshold
std::function<bool(const tuple&)> key_geq_int(const std::string& key,
                                               int threshold) {
  return [=](const tuple& tup) {
    return lookup_int(key, tup) >= threshold;
  };
}

// (filter utility)
// Looks up the given key and converts to Int op_result
// if the key does not hold an int, this will raise an exception
int get_mapped_int(const std::string& key, const tuple& tup) {
  return int_of_op_result(tup.find(key));
}

// (filter utility)
// Looks up the given key and converts to Float op_result
// if the key does not hold an int, this will raise an exception
float get_mapped_float(const std::string& key, const tuple& tup) {
  return float_of_op_result(tup.find(key));
}

// Operator which applied the given function on all tuples
// Passes resets, unchanged
// applies the given operator to the result of this operator applied to the
// Tuple
op_creator map(std::function<tuple(const tuple&)> f) {
  return [&](operator_t next_op) {
    return operator_t{
        [&](const tuple& tup) { next_op.next(f(tup)); },
        [&](const tuple& tup) { next_op.reset(tup); }};
  };
}

using grouping_func = std::function<tuple(const tuple&)>;
using reduction_func =
    std::function<op_result(const op_result&, const tuple&)>;

// Groups the input Tuples according to canonic members returned by
//   key_extractor : Tuple -> Tuple
// Tuples in each group are folded (starting with Empty) by
//   accumulate : op_result -> Tuple -> op_result
// When reset, op is passed a Tuple for each group containing the union of
//   (i) the reset argument tuple,
//   (ii) the result of g for that group, and
//   (iii) a mapping from out_key to the result of the fold for that group
op_creator groupby(grouping_func groupby_func, reduction_func reduce_func,
                    const std::string& out_key) {
  return [&](operator_t next_op) {
    std::unordered_map<tuple, op_result> h_tbl;
    std::shared_ptr<int> reset_counter = std::make_shared<int>(0);
    return operator_t{
        [&](const tuple& tup) {
          tuple grouping_key = groupby_func(tup);
          auto it = h_tbl.find(grouping_key);
          if (it != h_tbl.end()) {
            h_tbl[grouping_key] = reduce_func(it->second, tup);
          } else {
            h_tbl[grouping_key] = reduce_func(std::monostate{}, tup);
          }
        },
        [&](const tuple& tup) {
          (*reset_counter)++;
          for (const auto& pair : h_tbl) {
            tuple unioned_tup = pair.first.union_(
                [](const std::string&, const op_result& a, const op_result&) -> std::optional<op_result> { return a; }, tup);
            tuple result_tup = unioned_tup;
            result_tup.add(out_key, pair.second);
            next_op.next(result_tup);
          }
          next_op.reset(tup);
          h_tbl.clear();
        }};
  };
}

// (groupby utility : key_extractor)
// Returns a new tuple with only the keys included in the incl_keys list
std::function<tuple(const tuple&)> filter_groups(
    const std::vector<std::string>& incl_keys) {
  return [=](const tuple& tup) {
    return tup.filter([&](const std::string& key, const op_result&) {
      return std::find(incl_keys.begin(), incl_keys.end(), key) !=
             incl_keys.end();
    });
  };
}

// (groupby utility : key_extractor)
// Grouping function (key_extractor) that forms a single group
std::function<tuple(const tuple&)> single_group() {
  return [](const tuple&) { return tuple{}; };
}

// (groupby utility : grouping_mech)
// Reduction function (f) to count tuples
reduction_func counter() {
  return [](const op_result& val, const tuple&) {
    if (std::holds_alternative<std::monostate>(val)) {
      return 1;
    } else if (std::holds_alternative<int>(val)) {
      return std::get<int>(val) + 1;
    }
    return val;
  };
}

// (groupby utility)
// Reduction function (f) to sum values (assumed to be Int ()) of a given field
reduction_func sum_ints(const std::string& search_key) {
  return [=](const op_result& init_val, const tuple& tup) {
    if (std::holds_alternative<std::monostate>(init_val)) {
      return 0;
    } else if (std::holds_alternative<int>(init_val)) {
      auto val_opt = tup.find_opt(search_key);
      if (val_opt.has_value() &&
          std::holds_alternative<int>(val_opt.value().get())) {
        return std::get<int>(val_opt.value().get()) + std::get<int>(init_val);
      } else {
        std::stringstream ss;
        ss << "'sum_vals' function failed to find integer value mapped to \""
           << search_key << "\"";
        throw std::runtime_error(ss.str());
      }
    }
    return init_val;
  };
}

// Returns a list of distinct elements (as determined by group_tup) each epoch
// removes duplicate Tuples based on group_tup
op_creator distinct(grouping_func groupby_func) {
  return [&](operator_t next_op) {
    std::unordered_map<tuple, bool> h_tbl;
    std::shared_ptr<int> reset_counter = std::make_shared<int>(0);
    return operator_t{
        [&](const tuple& tup) {
          tuple grouping_key = groupby_func(tup);
          h_tbl[grouping_key] = true;
        },
        [&](const tuple& tup) {
          (*reset_counter)++;
          for (const auto& pair : h_tbl) {
            tuple merged_tup = pair.first.union_(
                [](const std::string&, const op_result& a, const op_result&) -> std::optional<op_result> { return a; }, tup);
            next_op.next(merged_tup);
          }
          next_op.reset(tup);
          h_tbl.clear();
        }};
  };
}

// Just sends both next and reset directly to two different downstream operators
// i.e. splits the stream processing in two
op_creator split(operator_t l, operator_t r) {
  return [&](operator_t) {
    return operator_t{
        [&](const tuple& tup) {
          l.next(tup);
          r.next(tup);
        },
        [&](const tuple& tup) {
          l.reset(tup);
          r.reset(tup);
        }};
  };
}

using key_extractor = std::function<std::pair<tuple, tuple>(const tuple&)>;

// Initial shot at a join semantic that doesn't require maintining entire state
// Functions left and right transform input tuples into a key,value pair of
// tuples The key determines a canonical tuple against which the other stream
// will match The value determines extra fields which should be saved and added
// when a match is made
//
// Requires tuples to have epoch id as int value in field referenced by eid_key.
dbl_op_creator join(const key_extractor& left_extractor,
                     const key_extractor& right_extractor,
                     const std::string& eid_key = "eid") {
  return [&](operator_t next_op) {
    std::unordered_map<tuple, tuple> h_tbl1;
    std::unordered_map<tuple, tuple> h_tbl2;
    std::shared_ptr<int> left_curr_epoch = std::make_shared<int>(0);
    std::shared_ptr<int> right_curr_epoch = std::make_shared<int>(0);

    auto handle_join_side =
        [&](std::unordered_map<tuple, tuple>& curr_h_tble,
            std::unordered_map<tuple, tuple>& other_h_tbl,
            std::shared_ptr<int>& curr_epoch_ref,
            std::shared_ptr<int>& other_epoch_ref,
            const key_extractor& f) -> operator_t {
      return {
          [&](const tuple& tup) {
            auto [key, vals_] = f(tup);
            int curr_epoch = get_mapped_int(eid_key, tup);

            while (curr_epoch > *curr_epoch_ref) {
              if (*other_epoch_ref > *curr_epoch_ref) {
                next_op.reset(Tuple<op_result>::singleton(eid_key, *curr_epoch_ref));
              }
              (*curr_epoch_ref)++;
            }

            tuple new_tup;
            new_tup.add(eid_key, curr_epoch);
            new_tup.union_([](const std::string&, const op_result& a, const op_result&) -> std::optional<op_result> { return a; }, key);

            auto it = other_h_tbl.find(new_tup);
            if (it != other_h_tbl.end()) {
              auto use_left = [](const std::string&, const op_result& a, const op_result&) -> std::optional<op_result> { return a; };
              other_h_tbl.erase(it);
              tuple joined_tup = new_tup.union_(use_left, vals_).union_(use_left, it->second);
              next_op.next(joined_tup);
            } else {
              curr_h_tble[new_tup] = vals_;
            }
          },
          [&](const tuple& tup) {
            int curr_epoch = get_mapped_int(eid_key, tup);
            while (curr_epoch > *curr_epoch_ref) {
              if (*other_epoch_ref > *curr_epoch_ref) {
                next_op.reset(Tuple<op_result>::singleton(eid_key, *curr_epoch_ref));
              }
              (*curr_epoch_ref)++;
            }
          }};
    };

    return {handle_join_side(h_tbl1, h_tbl2, left_curr_epoch, right_curr_epoch,
                             left_extractor),
            handle_join_side(h_tbl2, h_tbl1, right_curr_epoch, left_curr_epoch,
                             right_extractor)};
  };
}

// (join utility)
// Returns a new tuple with only the keys included in the first of each pair in
// keys These keys are renamed to the second of each pair in keys Use in
// conjunction with the join implementation above to get the "join left with
// right on left.x = right.y" kind of thing
std::function<tuple(const tuple&)> rename_filtered_keys(
    const std::vector<std::pair<std::string, std::string>>& renamings_pairs) {
  return [=](const tuple& in_tup) {
    tuple new_tup;
    for (const auto& [old_key, new_key] : renamings_pairs) {
      auto val_opt = in_tup.find_opt(old_key);
      if (val_opt.has_value()) {
        new_tup.add(new_key, val_opt.value().get());
      }
    }
    return new_tup;
  };
}

namespace Main {

// counts total number of packets obeserved in an epoch
op_creator ident() {
  return map([](const tuple& tup) {
           return tup.filter([](const std::string& key, const op_result&) {
             return !(key == "eth.src" || key == "eth.dst");
           });
         });
}

// assigns each tuple an epoch ID based on time by adding an eid key, counts
// the number of tuples in each epoch, then passes the processed tuples to the
//  next_op
op_creator count_pkts() {
  return epoch(1.0, "eid") | groupby(single_group(), counter(), "pkts");
}

// assigns each tuple an epoch ID based on time by adding an eid key, groups
// them by source and dest ip, counts and stores the number of tuples in each
// group, and passes result to next_op
op_creator pkts_per_src_dst() {
  return epoch(1.0, "eid") |
         groupby(filter_groups({"ipv4.src", "ipv4.dst"}), counter(), "pkts");
}

op_creator distinct_srcs() {
  return epoch(1.0, "eid") | distinct(filter_groups({"ipv4.src"})) |
         groupby(single_group(), counter(), "srcs");
}

// Sonata 1
op_creator tcp_new_cons(int threshold) {
  return epoch(1.0, "eid") |
         filter([](const tuple& tup) {
           return get_mapped_int("ipv4.proto", tup) == 6 &&
                  get_mapped_int("l4.flags", tup) == 2;
         }) |
         groupby(filter_groups({"ipv4.dst"}), counter(), "cons") |
         filter(key_geq_int("cons", threshold));
}

// Sonata 2
op_creator ssh_brute_force(int threshold) {
  return epoch(1.0, "eid") // might need to elongate epoch for this one...
         | filter([](const tuple& tup) {
             return get_mapped_int("ipv4.proto", tup) == 6 &&
                    get_mapped_int("l4.dport", tup) == 22;
           })
         | distinct(filter_groups({"ipv4.src", "ipv4.dst", "ipv4.len"}))
         | groupby(filter_groups({"ipv4.dst", "ipv4.len"}), counter(), "srcs")
         | filter(key_geq_int("srcs", threshold));
}

// Sonata 3
op_creator super_spreader(int threshold) {
  return epoch(1.0, "eid") | distinct(filter_groups({"ipv4.src", "ipv4.dst"})) |
         groupby(filter_groups({"ipv4.src"}), counter(), "dsts") |
         filter(key_geq_int("dsts", threshold));
}

// Sonata 4
op_creator port_scan(int threshold) {
  return epoch(1.0, "eid") | distinct(filter_groups({"ipv4.src", "l4.dport"})) |
         groupby(filter_groups({"ipv4.src"}), counter(), "ports") |
         filter(key_geq_int("ports", threshold));
}

// Sonata 5
op_creator ddos(int threshold) {
  return epoch(1.0, "eid") | distinct(filter_groups({"ipv4.src", "ipv4.dst"})) |
         groupby(filter_groups({"ipv4.dst"}), counter(), "srcs") |
         filter(key_geq_int("srcs", threshold));
}

// Sonata 6 --- Note this implements the Sonata semantic of this query
// *NOT* the intended semantic from NetQRE *
std::vector<operator_t> syn_flood_sonata(int threshold, float epoch_dur) {
  auto syns = [&](operator_t next_op) {
    return epoch(epoch_dur, "eid") |
           filter([](const tuple& tup) {
             return get_mapped_int("ipv4.proto", tup) == 6 &&
                    get_mapped_int("l4.flags", tup) == 2;
           }) |
           groupby(filter_groups({"ipv4.dst"}), counter(), "syns") | next_op;
  };
  auto synacks = [&](operator_t next_op) {
    return epoch(epoch_dur, "eid") |
           filter([](const tuple& tup) {
             return get_mapped_int("ipv4.proto", tup) == 6 &&
                    get_mapped_int("l4.flags", tup) == 18;
           }) |
           groupby(filter_groups({"ipv4.src"}), counter(), "synacks") | next_op;
  };
  auto acks = [&](operator_t next_op) {
    return epoch(epoch_dur, "eid") |
           filter([](const tuple& tup) {
             return get_mapped_int("ipv4.proto", tup) == 6 &&
                    get_mapped_int("l4.flags", tup) == 16;
           }) |
           groupby(filter_groups({"ipv4.dst"}), counter(), "acks") | next_op;
  };

  operator_t join_op1, join_op2;
  std::tie(join_op1, join_op2) =
      join([](const tuple& tup) {
             return std::make_pair(filter_groups({"host"})(tup),
                                   filter_groups({"syns+synacks"})(tup));
           },
           [](const tuple& tup) {
             return std::make_pair(rename_filtered_keys({{"ipv4.dst", "host"}})(tup),
                                   filter_groups({"acks"})(tup));
           }) |
      map([](const tuple& tup) {
        tuple result = tup;
        result.add("syns+synacks-acks",
                   get_mapped_int("syns+synacks", tup) - get_mapped_int("acks", tup));
        return result;
      }) |
      filter(key_geq_int("syns+synacks-acks", threshold));

  operator_t join_op3, join_op4;
  std::tie(join_op3, join_op4) =
      join([](const tuple& tup) {
             return std::make_pair(rename_filtered_keys({{"ipv4.dst", "host"}})(tup),
                                   filter_groups({"syns"})(tup));
           },
           [](const tuple& tup) {
             return std::make_pair(rename_filtered_keys({{"ipv4.src", "host"}})(tup),
                                   filter_groups({"synacks"})(tup));
           }) |
      map([](const tuple& tup) {
        tuple result = tup;
        result.add("syns+synacks",
                   get_mapped_int("syns", tup) + get_mapped_int("synacks", tup));
        return result;
      }) |
      join_op1;

  return {syns(join_op3), synacks(join_op4), acks(join_op2)};
}

// Sonata 7
std::vector<operator_t> completed_flows(int threshold, float epoch_dur) {
  auto syns = [&](operator_t next_op) {
    return epoch(epoch_dur, "eid") |
           filter([](const tuple& tup) {
             return get_mapped_int("ipv4.proto", tup) == 6 &&
                    get_mapped_int("l4.flags", tup) == 2;
           }) |
           groupby(filter_groups({"ipv4.dst"}), counter(), "syns") | next_op;
  };
  auto fins = [&](operator_t next_op) {
    return epoch(epoch_dur, "eid") |
           filter([](const tuple& tup) {
             return get_mapped_int("ipv4.proto", tup) == 6 &&
                    (get_mapped_int("l4.flags", tup) & 1) == 1;
           }) |
           groupby(filter_groups({"ipv4.src"}), counter(), "fins") | next_op;
  };

  operator_t op1, op2;
  std::tie(op1, op2) =
      join([](const tuple& tup) {
             return std::make_pair(rename_filtered_keys({{"ipv4.dst", "host"}})(tup),
                                   filter_groups({"syns"})(tup));
           },
           [](const tuple& tup) {
             return std::make_pair(rename_filtered_keys({{"ipv4.src", "host"}})(tup),
                                   filter_groups({"fins"})(tup));
           }) |
      map([](const tuple& tup) {
        tuple result = tup;
        result.add("diff", get_mapped_int("syns", tup) - get_mapped_int("fins", tup));
        return result;
      }) |
      filter(key_geq_int("diff", threshold));

  return {syns(op1), fins(op2)};
}

// Sonata 8
std::vector<operator_t> slowloris(int t1, int t2, int t3, float epoch_dur) {
  auto n_conns = [&](operator_t next_op) {
    return epoch(epoch_dur, "eid") |
           filter([](const tuple& tup) {
             return get_mapped_int("ipv4.proto", tup) == 6;
           }) |
           distinct(filter_groups({"ipv4.src", "ipv4.dst", "l4.sport"})) |
           groupby(filter_groups({"ipv4.dst"}), counter(), "n_conns") |
           filter(key_geq_int("n_conns", t1)) | next_op;
  };
  auto n_bytes = [&](operator_t next_op) {
    return epoch(epoch_dur, "eid") |
           filter([](const tuple& tup) {
             return get_mapped_int("ipv4.proto", tup) == 6;
           }) |
           groupby(filter_groups({"ipv4.dst"}), sum_ints("ipv4.len"), "n_bytes") |
           filter(key_geq_int("n_bytes", t2)) | next_op;
  };

  operator_t op1, op2;
  std::tie(op1, op2) =
      join([](const tuple& tup) {
             return std::make_pair(filter_groups({"ipv4.dst"})(tup),
                                   filter_groups({"n_conns"})(tup));
           },
           [](const tuple& tup) {
             return std::make_pair(filter_groups({"ipv4.dst"})(tup),
                                   filter_groups({"n_bytes"})(tup));
           }) |
      map([](const tuple& tup) {
        tuple result = tup;
        result.add("bytes_per_conn",
                   get_mapped_int("n_bytes", tup) / get_mapped_int("n_conns", tup));
        return result;
      }) |
      filter(key_geq_int("bytes_per_conn", t3));

  return {n_conns(op1), n_bytes(op2)};
}

std::vector<operator_t> join_test(float epoch_dur) {
  auto syns = [&](operator_t next_op) {
    return epoch(epoch_dur, "eid") |
           filter([](const tuple& tup) {
             return get_mapped_int("ipv4.proto", tup) == 6 &&
                    get_mapped_int("l4.flags", tup) == 2;
           }) |
           next_op;
  };
  auto synacks = [&](operator_t next_op) {
    return epoch(epoch_dur, "eid") |
           filter([](const tuple& tup) {
             return get_mapped_int("ipv4.proto", tup) == 6 &&
                    get_mapped_int("l4.flags", tup) == 18;
           }) |
           next_op;
  };

  operator_t op1, op2;
  std::tie(op1, op2) =
      join([](const tuple& tup) {
             return std::make_pair(rename_filtered_keys({{"ipv4.src", "host"}})(tup),
                                   rename_filtered_keys({{"ipv4.dst", "remote"}})(tup));
           },
           [](const tuple& tup) {
             return std::make_pair(rename_filtered_keys({{"ipv4.dst", "host"}})(tup),
                                   filter_groups({"time"})(tup));
           }) |
      map([](const tuple& tup){ return tup; }); // Identity map for testing

  return {syns(op1), synacks(op2)};
}

op_creator q3() {
  return epoch(100.0, "eid") | distinct(filter_groups({"ipv4.src", "ipv4.dst"}));
}

op_creator q4() {
  return epoch(10000.0, "eid") | groupby(filter_groups({"ipv4.dst"}), counter(), "pkts");
}

std::vector<operator_t> queries = {ident() | dump_tuple(std::cout)};

void run_queries() {
  for (int i = 0; i < 20; ++i) {
    tuple t;
    t.add("time", static_cast<float>(0.000000 + i));
    t.add("eth.src", Bytes::of_string("\x00\x11\x22\x33\x44\x55"));
    t.add("eth.dst", Bytes::of_string("\xAA\xBB\xCC\xDD\xEE\xFF"));
    t.add("eth.ethertype", 0x0800);
    t.add("ipv4.hlen", 20);
    t.add("ipv4.proto", 6);
    t.add("ipv4.len", 60);
    t.add("ipv4.src", Ipaddr::V4::of_string_exn("127.0.0.1"));
    t.add("ipv4.dst", Ipaddr::V4::of_string_exn("127.0.0.1"));
    t.add("l4.sport", 440);
    t.add("l4.dport", 50000);
    t.add("l4.flags", 10);

    for (auto& query : queries) {
      query.next(t);
    }
  }
}

} // namespace Main

int