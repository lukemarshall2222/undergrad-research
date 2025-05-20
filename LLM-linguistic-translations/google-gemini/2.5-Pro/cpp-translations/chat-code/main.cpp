#include "common_utils.hpp"
#include "builtins.hpp"
#include "sonata_queries.hpp"

#include <iostream>
#include <vector>
#include <string>
#include <stdexcept>

using namespace Utils;
using namespace Builtins;
using namespace SonataQueries;

// Example function to generate sample data similar to OCaml's run_queries
std::vector<Tuple> generate_sample_data(int count) {
    std::vector<Tuple> data;
    MACAddress src_mac({0x00, 0x11, 0x22, 0x33, 0x44, 0x55});
    MACAddress dst_mac({0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF});
    IPv4Address ip_addr("127.0.0.1"); // Can throw

    for (int i = 0; i < count; ++i) {
        Tuple tup;
        tup["time"] = 0.000000 + static_cast<double>(i);

        tup["eth.src"] = src_mac;
        tup["eth.dst"] = dst_mac;
        tup["eth.ethertype"] = 0x0800; // IPv4

        tup["ipv4.hlen"] = 20;
        tup["ipv4.proto"] = 6; // TCP
        tup["ipv4.len"] = 60;
        tup["ipv4.src"] = ip_addr;
        tup["ipv4.dst"] = ip_addr;

        tup["l4.sport"] = 440 + i; // Vary source port slightly
        tup["l4.dport"] = 50000;
        tup["l4.flags"] = 10; // Example flags (PSH+ACK)

        data.push_back(tup);
    }
    return data;
}

// Example of running a single query pipeline
void run_single_query_example() {
    std::cout << "--- Running Single Query Example (Count Packets) ---" << std::endl;
    // Define the end of the pipeline (dump to stdout)
    Operator final_op = dump_tuple_op(std::cout, true); // Show resets

    // Build the query pipeline
    Operator query_pipeline = count_pkts(final_op);

    // Generate sample data
    std::vector<Tuple> sample_data = generate_sample_data(5); // Generate 5 tuples

    // Process data
    for (const auto& tup : sample_data) {
        query_pipeline.next(tup);
    }

    // Signal end of data stream (important for epoch-based operators)
    // Create a dummy tuple for the final reset, containing the *next* potential eid.
    // Need to know the last eid processed. Let's assume eid 0 for 5 pkts over 1s epochs.
    // The last packet time is 4.0. Epoch boundaries are 1.0, 2.0, 3.0, 4.0, 5.0...
    // Packet 0 (t=0.0) -> eid=0
    // Packet 1 (t=1.0) -> reset(eid=0), next(eid=1)
    // Packet 2 (t=2.0) -> reset(eid=1), next(eid=2)
    // Packet 3 (t=3.0) -> reset(eid=2), next(eid=3)
    // Packet 4 (t=4.0) -> reset(eid=3), next(eid=4)
    // Final reset should signal end of epoch 4.
    Tuple final_reset_signal;
    // The 'epoch' operator expects the key used ('eid') in the reset tuple.
    final_reset_signal["eid"] = 4; // The last completed epoch ID
    query_pipeline.reset(final_reset_signal); // Trigger final resets through the pipeline

     std::cout << "--- Single Query Example Finished ---" << std::endl;
}

// Example mimicking the OCaml `run_queries` structure (applying multiple queries to each tuple)
void run_multiple_queries_simultaneously() {
     std::cout << "\n--- Running Multiple Queries Simultaneously Example ---" << std::endl;

     // Define multiple query pipelines ending in stdout dumps
     std::vector<Operator> queries;
     queries.push_back(ident(dump_tuple_op(std::cout)));
     queries.push_back(count_pkts(dump_tuple_op(std::cout, true))); // Show resets for this one
     queries.push_back(pkts_per_src_dst(dump_tuple_op(std::cout, true)));

     std::vector<Tuple> sample_data = generate_sample_data(5);

     // Process each tuple through all queries
     for (const auto& tup : sample_data) {
        std::cout << "Processing Tuple with time=" << lookup_float("time", tup) << std::endl;
        for (auto& query : queries) { // Pass by reference if operators have internal state to modify
            query.next(tup);
        }
         std::cout << "-----\n";
     }

     // Send final reset signals to all queries
     // This is tricky as different queries might expect different reset signals.
     // For simplicity, send a generic reset or one tailored to epoch if known.
     std::cout << "Sending final resets..." << std::endl;
      Tuple final_reset_signal;
      final_reset_signal["eid"] = 4; // Assuming last epoch ID based on data/epoch=1.0
      for (auto& query : queries) {
          query.reset(final_reset_signal);
      }

     std::cout << "--- Multiple Queries Example Finished ---" << std::endl;
}


// Example using read_walts_csv (requires dummy CSV files)
void run_read_csv_example() {
     std::cout << "\n--- Running Read CSV Example ---" << std::endl;
     // Create dummy CSV files (replace with actual paths)
     const std::string file1_name = "dummy_input1.csv";
     const std::string file2_name = "dummy_input2.csv";

     std::ofstream ofs1(file1_name);
     if (!ofs1) { std::cerr << "Cannot create " << file1_name << std::endl; return; }
     ofs1 << "192.168.1.1,10.0.0.1,1234,80,10,1500,0\n"; // eid 0
     ofs1 << "192.168.1.2,10.0.0.2,5678,443,5,500,0\n";  // eid 0
     ofs1 << "192.168.1.1,10.0.0.1,1234,80,8,1200,1\n";   // eid 1
     ofs1.close();

     std::ofstream ofs2(file2_name);
     if (!ofs2) { std::cerr << "Cannot create " << file2_name << std::endl; return; }
     ofs2 << "172.16.0.1,192.168.1.5,99,53,1,60,0\n";    // eid 0
     ofs2 << "172.16.0.1,192.168.1.6,100,53,2,120,1\n";   // eid 1
     ofs2 << "172.16.0.1,192.168.1.7,101,53,3,180,2\n";   // eid 2
     ofs2.close();

     try {
        // Define pipelines for each file - e.g., count packets per source
        Operator pipeline1 = pkts_per_src_dst(dump_tuple_op(std::cout, true));
        Operator pipeline2 = count_pkts(dump_tuple_op(std::cout, true));

        std::vector<std::string> files = {file1_name, file2_name};
        std::vector<Operator> ops = {pipeline1, pipeline2};

        read_walts_csv(files, ops, "eid"); // Use default "eid" key

     } catch (const std::exception& e) {
         std::cerr << "Error during CSV processing: " << e.what() << std::endl;
     }

     // Clean up dummy files
     // remove(file1_name.c_str());
     // remove(file2_name.c_str());
      std::cout << "--- Read CSV Example Finished ---" << std::endl;
}


int main() {
    try {
        run_single_query_example();
        run_multiple_queries_simultaneously();
        run_read_csv_example(); // Uncomment to test CSV reading

        // Add more examples calling specific Sonata queries if needed
        // Example: Running Sonata 1
        std::cout << "\n--- Running Sonata 1 Example ---" << std::endl;
        Operator s1_pipeline = tcp_new_cons(dump_tuple_op(std::cout, true));
        std::vector<Tuple> s1_data = generate_sample_data(10);
        // Add some TCP SYN packets manually to trigger the query
         Tuple syn_tup;
         syn_tup["time"] = 10.0;
         syn_tup["ipv4.proto"] = 6;
         syn_tup["l4.flags"] = 2; // SYN
         syn_tup["ipv4.dst"] = IPv4Address("10.0.0.5");
         for(int i=0; i<50; ++i) { // Generate 50 SYNs to trigger threshold
            syn_tup["time"] = 10.0 + i*0.01;
            syn_tup["ipv4.src"] = IPv4Address("192.168.1." + std::to_string(i+1));
            s1_data.push_back(syn_tup);
         }
         syn_tup["time"] = 60.0; // Move to next epoch
         s1_data.push_back(syn_tup);


        for(const auto& tup : s1_data) {
            s1_pipeline.next(tup);
        }
         Tuple s1_reset; s1_reset["eid"] = 60; // Rough estimate of last epoch based on time/epoch=1.0
         s1_pipeline.reset(s1_reset);
         std::cout << "--- Sonata 1 Example Finished ---" << std::endl;


        std::cout << "\nDone." << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Unhandled exception in main: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "Unknown unhandled exception in main." << std::endl;
        return 1;
    }

    return 0;
}