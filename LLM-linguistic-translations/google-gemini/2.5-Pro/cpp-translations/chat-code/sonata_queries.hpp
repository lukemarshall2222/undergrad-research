#ifndef SONATA_QUERIES_HPP
#define SONATA_QUERIES_HPP

#include "common_utils.hpp"
#include "builtins.hpp"
#include <vector>

namespace SonataQueries {

    using namespace Utils;
    using namespace Builtins;

    // Simple Queries
    Operator ident(Operator next_op);
    Operator count_pkts(Operator next_op);
    Operator pkts_per_src_dst(Operator next_op);
    Operator distinct_srcs(Operator next_op);

    // Sonata Benchmark Queries (1-8)
    Operator tcp_new_cons(Operator next_op);
    Operator ssh_brute_force(Operator next_op);
    Operator super_spreader(Operator next_op);
    Operator port_scan(Operator next_op);
    Operator ddos(Operator next_op);
    // Queries returning multiple operators for joins
    std::vector<Operator> syn_flood_sonata(Operator next_op);
    std::vector<Operator> completed_flows(Operator next_op);
    std::vector<Operator> slowloris(Operator next_op);

    // Other Test Queries
    std::vector<Operator> join_test(Operator next_op);
    Operator q3(Operator next_op); // Distinct src/dst pairs
    Operator q4(Operator next_op); // Packets per destination

} // namespace SonataQueries


#endif // SONATA_QUERIES_HPP