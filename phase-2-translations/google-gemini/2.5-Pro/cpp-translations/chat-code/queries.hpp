// queries.hpp
#ifndef QUERIES_HPP
#define QUERIES_HPP

#include "common.hpp"
#include "builtins.hpp" // Include built-in operators
#include <vector>

namespace Queries {

    // Define functions that return OpCreators or Operators directly
    // Use Utils::chain to compose them

    OpCreator ident(); // Example: returns a creator
    OpCreator count_pkts();
    OpCreator pkts_per_src_dst();
    OpCreator distinct_srcs();
    OpCreator tcp_new_cons(int64_t threshold = 40);
    OpCreator ssh_brute_force(int64_t threshold = 40);
    OpCreator super_spreader(int64_t threshold = 40);
    OpCreator port_scan(int64_t threshold = 40);
    OpCreator ddos(int64_t threshold = 45);

    // Queries returning multiple operators (like joins)
    // Need a different signature or return type
    using MultiOpCreator = std::function<std::vector<Operator>(Operator)>;

    MultiOpCreator syn_flood_sonata(int64_t threshold = 3, double epoch_dur = 1.0);
    MultiOpCreator completed_flows(int64_t threshold = 1, double epoch_dur = 30.0);
    MultiOpCreator slowloris(int64_t t1 = 5, int64_t t2 = 500, int64_t t3 = 90, double epoch_dur = 1.0);
    MultiOpCreator join_test(double epoch_dur = 1.0);

    OpCreator q3(double epoch_dur = 100.0);
    OpCreator q4(double epoch_dur = 10000.0);


} // namespace Queries


#endif // QUERIES_HPP