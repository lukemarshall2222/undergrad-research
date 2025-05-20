#include "sonata_queries.hpp"
#include <vector>
#include <string>
#include <cmath> // For std::round or division checks if needed

namespace SonataQueries {

    using namespace Utils;
    using namespace Builtins;

// Helper lambda for filtering groups
auto filter_groups_l = [](const std::vector<std::string>& keys) {
    return [keys](const Tuple& tup) { return filter_groups(keys, tup); };
};

// Helper lambda for checking int field >= threshold
auto key_geq_int_l = [](const std::string& key, int threshold) {
    return [key, threshold](const Tuple& tup) { return key_geq_int(key, threshold, tup); };
};

// Helper lambda for renaming keys
auto rename_filtered_keys_l = [](const std::vector<std::pair<std::string, std::string>>& renames) {
    return [renames](const Tuple& tup) { return rename_filtered_keys(renames, tup); };
};


// --- Simple Queries ---
Operator ident(Operator next_op) {
    // Filter out eth.src and eth.dst
    auto filter_func = [](const Tuple& tup) -> Tuple {
        Tuple result;
        for (const auto& pair : tup) {
            if (pair.first != "eth.src" && pair.first != "eth.dst") {
                result.insert(pair);
            }
        }
        return result;
    };
    return chain(map(filter_func), next_op);
}

Operator count_pkts(Operator next_op) {
    OpCreator step1 = [](Operator op) { return epoch(1.0, "eid", op); };
    OpCreator step2 = [](Operator op) { return groupby(single_group, counter, "pkts", op); };

    return chain(step1, chain(step2, next_op));
}


Operator pkts_per_src_dst(Operator next_op) {
    std::vector<std::string> group_keys = {"ipv4.src", "ipv4.dst"};
    OpCreator step1 = [](Operator op) { return epoch(1.0, "eid", op); };
    OpCreator step2 = [&](Operator op) { return groupby(filter_groups_l(group_keys), counter, "pkts", op); };

    return chain(step1, chain(step2, next_op));
}

Operator distinct_srcs(Operator next_op) {
     std::vector<std::string> distinct_keys = {"ipv4.src"};
     OpCreator step1 = [](Operator op) { return epoch(1.0, "eid", op); };
     OpCreator step2 = [&](Operator op) { return distinct(filter_groups_l(distinct_keys), op); };
     OpCreator step3 = [](Operator op) { return groupby(single_group, counter, "srcs", op); };

     return chain(step1, chain(step2, chain(step3, next_op)));
}

// --- Sonata Benchmark Queries (1-8) ---

// Sonata 1
Operator tcp_new_cons(Operator next_op) {
    const int threshold = 40;
    std::vector<std::string> group_keys = {"ipv4.dst"};

    auto filter_syn = [](const Tuple& tup) {
        try {
            return get_mapped_int("ipv4.proto", tup) == 6 && // TCP
                   get_mapped_int("l4.flags", tup) == 2;    // SYN
        } catch (...) { return false; }
    };

    OpCreator step1 = [](Operator op) { return epoch(1.0, "eid", op); };
    OpCreator step2 = [&](Operator op) { return filter(filter_syn, op); };
    OpCreator step3 = [&](Operator op) { return groupby(filter_groups_l(group_keys), counter, "cons", op); };
    OpCreator step4 = [&](Operator op) { return filter(key_geq_int_l("cons", threshold), op); };

    return chain(step1, chain(step2, chain(step3, chain(step4, next_op))));
}

// Sonata 2
Operator ssh_brute_force(Operator next_op) {
    const int threshold = 40;
     std::vector<std::string> distinct_keys = {"ipv4.src", "ipv4.dst", "ipv4.len"};
     std::vector<std::string> group_keys = {"ipv4.dst", "ipv4.len"};

     auto filter_ssh_syn = [](const Tuple& tup) { // Assuming brute force looks at SYN on port 22
        try {
            return get_mapped_int("ipv4.proto", tup) == 6 && // TCP
                   get_mapped_int("l4.dport", tup) == 22;   // SSH Port
                   // Original OCaml didn't filter flags here, maybe intended?
                   // && get_mapped_int("l4.flags", tup) == 2; // SYN
        } catch (...) { return false; }
    };

    OpCreator step1 = [](Operator op) { return epoch(1.0, "eid", op); };
    OpCreator step2 = [&](Operator op) { return filter(filter_ssh_syn, op); };
    OpCreator step3 = [&](Operator op) { return distinct(filter_groups_l(distinct_keys), op); };
    OpCreator step4 = [&](Operator op) { return groupby(filter_groups_l(group_keys), counter, "srcs", op); };
    OpCreator step5 = [&](Operator op) { return filter(key_geq_int_l("srcs", threshold), op); };

    return chain(step1, chain(step2, chain(step3, chain(step4, chain(step5, next_op)))));
}

// Sonata 3
Operator super_spreader(Operator next_op) {
    const int threshold = 40;
    std::vector<std::string> distinct_keys = {"ipv4.src", "ipv4.dst"};
    std::vector<std::string> group_keys = {"ipv4.src"};

    OpCreator step1 = [](Operator op) { return epoch(1.0, "eid", op); };
    OpCreator step2 = [&](Operator op) { return distinct(filter_groups_l(distinct_keys), op); };
    OpCreator step3 = [&](Operator op) { return groupby(filter_groups_l(group_keys), counter, "dsts", op); };
    OpCreator step4 = [&](Operator op) { return filter(key_geq_int_l("dsts", threshold), op); };

    return chain(step1, chain(step2, chain(step3, chain(step4, next_op))));
}

// Sonata 4
Operator port_scan(Operator next_op) {
    const int threshold = 40;
    std::vector<std::string> distinct_keys = {"ipv4.src", "l4.dport"};
    std::vector<std::string> group_keys = {"ipv4.src"};

    OpCreator step1 = [](Operator op) { return epoch(1.0, "eid", op); };
    OpCreator step2 = [&](Operator op) { return distinct(filter_groups_l(distinct_keys), op); };
    OpCreator step3 = [&](Operator op) { return groupby(filter_groups_l(group_keys), counter, "ports", op); };
    OpCreator step4 = [&](Operator op) { return filter(key_geq_int_l("ports", threshold), op); };

    return chain(step1, chain(step2, chain(step3, chain(step4, next_op))));
}

// Sonata 5
Operator ddos(Operator next_op) {
    const int threshold = 45; // Note threshold differs from Port Scan
    std::vector<std::string> distinct_keys = {"ipv4.src", "ipv4.dst"};
    std::vector<std::string> group_keys = {"ipv4.dst"};

    OpCreator step1 = [](Operator op) { return epoch(1.0, "eid", op); };
    OpCreator step2 = [&](Operator op) { return distinct(filter_groups_l(distinct_keys), op); };
    OpCreator step3 = [&](Operator op) { return groupby(filter_groups_l(group_keys), counter, "srcs", op); };
    OpCreator step4 = [&](Operator op) { return filter(key_geq_int_l("srcs", threshold), op); };

    return chain(step1, chain(step2, chain(step3, chain(step4, next_op))));
}

// Sonata 6 - SYN Flood (Sonata version)
std::vector<Operator> syn_flood_sonata(Operator next_op) {
    const int threshold = 3;
    const double epoch_dur = 1.0;

    auto filter_tcp_flag = [&](int flag_val) {
         return [=](const Tuple& tup) {
            try {
                return get_mapped_int("ipv4.proto", tup) == 6 &&
                       get_mapped_int("l4.flags", tup) == flag_val;
            } catch(...) { return false; }
         };
    };

    // Define the 3 initial streams (Syns, SynAcks, Acks)
    auto syns_stream = [&](Operator op) -> Operator {
        return chain(epoch(epoch_dur, "eid"),
               chain(filter(filter_tcp_flag(2)), // SYN flag = 2
               chain(groupby(filter_groups_l({"ipv4.dst"}), counter, "syns"),
               op)));
    };
     auto synacks_stream = [&](Operator op) -> Operator {
        return chain(epoch(epoch_dur, "eid"),
               chain(filter(filter_tcp_flag(18)), // SYN+ACK flag = 18
               chain(groupby(filter_groups_l({"ipv4.src"}), counter, "synacks"),
               op)));
    };
     auto acks_stream = [&](Operator op) -> Operator {
        return chain(epoch(epoch_dur, "eid"),
               chain(filter(filter_tcp_flag(16)), // ACK flag = 16
               chain(groupby(filter_groups_l({"ipv4.dst"}), counter, "acks"),
               op)));
    };

    // Define the second join (Syns+SynAcks) - Join(Ack)
    auto map_diff = map([](const Tuple& tup){
        Tuple res = tup;
        try {
            res["syns+synacks-acks"] = get_mapped_int("syns+synacks", tup) - get_mapped_int("acks", tup);
        } catch (...) {/* handle error maybe */}
        return res;
    });
     auto filter_diff = filter(key_geq_int_l("syns+synacks-acks", threshold));
     DblOpCreator join2_creator = [&](Operator final_op) {
        Operator downstream = chain(map_diff, chain(filter_diff, final_op));
        KeyExtractor left_extract = [](const Tuple& t){ return std::make_pair(filter_groups({"host"}, t), filter_groups({"syns+synacks"}, t)); };
        KeyExtractor right_extract = [](const Tuple& t){ return std::make_pair(rename_filtered_keys({{"ipv4.dst","host"}}, t), filter_groups({"acks"}, t)); };
        return join(left_extract, right_extract, downstream);
     };

     // Define the first join (Syns) - Join(SynAcks)
     auto map_sum = map([](const Tuple& tup){
        Tuple res = tup;
         try {
            res["syns+synacks"] = get_mapped_int("syns", tup) + get_mapped_int("synacks", tup);
        } catch (...) {/* handle error maybe */}
        return res;
     });

     DblOpCreator join1_creator = [&](Operator join2_left_op) { // join2_left_op comes from join2_creator result
         Operator downstream = chain(map_sum, join2_left_op);
         KeyExtractor left_extract = [](const Tuple& t){ return std::make_pair(rename_filtered_keys({{"ipv4.dst","host"}}, t), filter_groups({"syns"}, t)); };
         KeyExtractor right_extract = [](const Tuple& t){ return std::make_pair(rename_filtered_keys({{"ipv4.src","host"}}, t), filter_groups({"synacks"}, t)); };
         return join(left_extract, right_extract, downstream);
     };

     // Wire them up using chain_double
     auto [join2_op1, join2_op2] = chain_double(join2_creator, next_op); // join2_op1 receives output of join1
     auto [join1_op3, join1_op4] = chain_double(join1_creator, join2_op1); // join1 outputs to join2_op1

     // Return the initial operators for the three streams
     return {
         syns_stream(join1_op3),
         synacks_stream(join1_op4),
         acks_stream(join2_op2)
     };
}


// Sonata 7 - Completed Flows
std::vector<Operator> completed_flows(Operator next_op) {
     const int threshold = 1;
     const double epoch_dur = 30.0;

     auto filter_syn = [](const Tuple& tup) {
         try {
             return get_mapped_int("ipv4.proto", tup) == 6 && get_mapped_int("l4.flags", tup) == 2; // SYN
         } catch(...) { return false;}
     };
      auto filter_fin = [](const Tuple& tup) {
         try {
             // Check if FIN bit (lsb) is set
             return get_mapped_int("ipv4.proto", tup) == 6 && (get_mapped_int("l4.flags", tup) & 1) == 1; // FIN
         } catch(...) { return false;}
     };

     auto syns_stream = [&](Operator op) {
        return chain(epoch(epoch_dur, "eid"),
               chain(filter(filter_syn),
               chain(groupby(filter_groups_l({"ipv4.dst"}), counter, "syns"),
               op)));
     };
      auto fins_stream = [&](Operator op) {
        return chain(epoch(epoch_dur, "eid"),
               chain(filter(filter_fin),
               chain(groupby(filter_groups_l({"ipv4.src"}), counter, "fins"),
               op)));
     };

     auto map_diff = map([](const Tuple& tup){
         Tuple res = tup;
         try {
            res["diff"] = get_mapped_int("syns", tup) - get_mapped_int("fins", tup);
         } catch(...) {}
         return res;
     });
     auto filter_diff = filter(key_geq_int_l("diff", threshold));

     DblOpCreator join_creator = [&](Operator final_op) {
         Operator downstream = chain(map_diff, chain(filter_diff, final_op));
         KeyExtractor left_extract = [](const Tuple& t){ return std::make_pair(rename_filtered_keys({{"ipv4.dst","host"}}, t), filter_groups({"syns"}, t)); };
         KeyExtractor right_extract = [](const Tuple& t){ return std::make_pair(rename_filtered_keys({{"ipv4.src","host"}}, t), filter_groups({"fins"}, t)); };
         return join(left_extract, right_extract, downstream);
     };

     auto [op1, op2] = chain_double(join_creator, next_op);

     return { syns_stream(op1), fins_stream(op2) };
}


// Sonata 8 - Slowloris
std::vector<Operator> slowloris(Operator next_op) {
     const int t1 = 5;   // min connections
     const int t2 = 500; // min bytes
     const int t3 = 90;  // max bytes per connection
     const double epoch_dur = 1.0;

     auto filter_tcp = [](const Tuple& tup) {
        try { return get_mapped_int("ipv4.proto", tup) == 6; } catch(...) { return false; }
     };

     // Stream 1: Calculate n_conns >= t1
     auto n_conns_stream = [&](Operator op) {
        return chain(epoch(epoch_dur, "eid"),
               chain(filter(filter_tcp),
               chain(distinct(filter_groups_l({"ipv4.src", "ipv4.dst", "l4.sport"})), // Distinct connections
               chain(groupby(filter_groups_l({"ipv4.dst"}), counter, "n_conns"),
               chain(filter(key_geq_int_l("n_conns", t1)), // Filter >= t1
               op)))));
     };

     // Stream 2: Calculate n_bytes >= t2
     auto n_bytes_stream = [&](Operator op) {
         // Need a lambda adapter for sum_ints
         auto sum_len = [](OpResult current, const Tuple& t) { return sum_ints("ipv4.len", current, t); };
         return chain(epoch(epoch_dur, "eid"),
                chain(filter(filter_tcp),
                chain(groupby(filter_groups_l({"ipv4.dst"}), sum_len, "n_bytes"),
                chain(filter(key_geq_int_l("n_bytes", t2)), // Filter >= t2
                op))));
     };

     // Map and Filter after join
     auto map_calc_bpc = map([](const Tuple& tup){
        Tuple res = tup;
        try {
            int n_bytes = get_mapped_int("n_bytes", tup);
            int n_conns = get_mapped_int("n_conns", tup);
            if (n_conns > 0) {
                res["bytes_per_conn"] = n_bytes / n_conns;
            } else {
                 res["bytes_per_conn"] = 0; // Avoid division by zero
            }
        } catch(...) {}
        return res;
     });
      auto filter_bpc = filter([=](const Tuple& tup){
        try {
             return get_mapped_int("bytes_per_conn", tup) <= t3; // Filter <= t3
        } catch(...) { return false; }
      });

      // Join creator
     DblOpCreator join_creator = [&](Operator final_op) {
        Operator downstream = chain(map_calc_bpc, chain(filter_bpc, final_op));
        // Extractors for join on ipv4.dst
        KeyExtractor left_extract = [](const Tuple& t){ return std::make_pair(filter_groups({"ipv4.dst"}, t), filter_groups({"n_conns"}, t)); };
        KeyExtractor right_extract = [](const Tuple& t){ return std::make_pair(filter_groups({"ipv4.dst"}, t), filter_groups({"n_bytes"}, t)); };
        return join(left_extract, right_extract, downstream);
     };

     auto [op1, op2] = chain_double(join_creator, next_op);

     return { n_conns_stream(op1), n_bytes_stream(op2) };
}


// --- Other Test Queries ---
std::vector<Operator> join_test(Operator next_op) {
     const double epoch_dur = 1.0;

     auto filter_syn = [](const Tuple& tup) {
         try { return get_mapped_int("ipv4.proto",tup) == 6 && get_mapped_int("l4.flags",tup) == 2;} catch(...) {return false;}
     };
     auto filter_synack = [](const Tuple& tup) {
         try { return get_mapped_int("ipv4.proto",tup) == 6 && get_mapped_int("l4.flags",tup) == 18;} catch(...) {return false;}
     };

     auto syns_stream = [&](Operator op){
        return chain(epoch(epoch_dur, "eid"), chain(filter(filter_syn), op));
     };
     auto synacks_stream = [&](Operator op){
         return chain(epoch(epoch_dur, "eid"), chain(filter(filter_synack), op));
     };

     DblOpCreator join_creator = [&](Operator final_op) {
         KeyExtractor left_extract = [](const Tuple& t){ return std::make_pair(rename_filtered_keys({{"ipv4.src","host"}}, t), rename_filtered_keys({{"ipv4.dst","remote"}}, t)); };
         KeyExtractor right_extract = [](const Tuple& t){ return std::make_pair(rename_filtered_keys({{"ipv4.dst","host"}}, t), filter_groups({"time"}, t)); };
         return join(left_extract, right_extract, final_op); // Just pass final_op directly
     };

     auto [op1, op2] = chain_double(join_creator, next_op);

     return { syns_stream(op1), synacks_stream(op2) };
}


Operator q3(Operator next_op) { // Distinct src/dst pairs over 100s
     return chain(epoch(100.0, "eid"),
            chain(distinct(filter_groups_l({"ipv4.src", "ipv4.dst"})),
            next_op));
}

Operator q4(Operator next_op) { // Pkts per dst over 10000s
     return chain(epoch(10000.0, "eid"),
            chain(groupby(filter_groups_l({"ipv4.dst"}), counter, "pkts"),
            next_op));
}


} // namespace SonataQueries