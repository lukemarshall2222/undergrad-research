// main.cpp
#include "common.hpp"
#include "builtins.hpp"
#include "queries.hpp"

#include <iostream>
#include <vector>
#include <string>
#include <cmath> // For std:: M_PI if needed, or just use float() in C++


// --- Helper to create test data ---
std::vector<Tuple> generate_test_data(int count) {
    std::vector<Tuple> data;
    MacAddress src_mac; // TODO: Initialize properly if needed
    MacAddress dst_mac; // TODO: Initialize properly if needed
    IpAddressV4 src_ip("127.0.0.1"); // TODO: Use proper constructor/parser
    IpAddressV4 dst_ip("127.0.0.1");

    // Example initialization (replace with real MAC parsing if available)
    try {
        src_mac = MacAddress("00:11:22:33:44:55");
        dst_mac = MacAddress("AA:BB:CC:DD:EE:FF");
    } catch(const std::exception& e) {
         std::cerr << "Warning: MAC address init failed: " << e.what() << std::endl;
    }


    for (int i = 0; i < count; ++i) {
        Tuple tup;
        tup["time"] = OpResult(0.000000 + static_cast<double>(i)); // Time progression

        tup["eth.src"] = OpResult(src_mac);
        tup["eth.dst"] = OpResult(dst_mac);
        tup["eth.ethertype"] = OpResult(static_cast<int64_t>(0x0800)); // IPv4

        tup["ipv4.hlen"] = OpResult(static_cast<int64_t>(20));
        tup["ipv4.proto"] = OpResult(static_cast<int64_t>(6)); // TCP
        tup["ipv4.len"] = OpResult(static_cast<int64_t>(60));
        tup["ipv4.src"] = OpResult(src_ip);
        tup["ipv4.dst"] = OpResult(dst_ip);

        tup["l4.sport"] = OpResult(static_cast<int64_t>(440 + i % 10)); // Vary source port slightly
        tup["l4.dport"] = OpResult(static_cast<int64_t>(50000));
        // Vary flags for testing different queries (e.g., SYN=2, ACK=16, SYNACK=18, FIN=1)
        int64_t flags = 0;
        if (i % 5 == 0) flags = 2;       // SYN
        else if (i % 5 == 1) flags = 18; // SYNACK
        else if (i % 5 == 2) flags = 16; // ACK
        else if (i % 5 == 3) flags = 1;  // FIN
        else flags = 16;                 // Default ACK
        tup["l4.flags"] = OpResult(flags);

        data.push_back(tup);
    }
    return data;
}

int main() {
    try {
        // --- Define the terminal operator (where the results go) ---
        // Example: Dump results to standard output using dump_tuple
        Operator terminal_op = Builtins::dump_tuple(std::cout, true); // Show resets

        // --- Create the query pipeline ---
        // Select the query to run, e.g., count_pkts
        Queries::OpCreator selected_query_creator = Queries::count_pkts();
        // Queries::OpCreator selected_query_creator = Queries::tcp_new_cons(5); // Example threshold

        // Instantiate the pipeline by applying the creator to the terminal operator
        Operator pipeline = selected_query_creator(terminal_op);


        // --- Generate some test data ---
        std::vector<Tuple> test_data = generate_test_data(20);


        // --- Run the data through the pipeline ---
        std::cout << "--- Processing Data ---" << std::endl;
        for (const auto& tup : test_data) {
             std::cout << "Input: " << Utils::string_of_tuple(tup) << std::endl;
             pipeline.next(tup); // Process next tuple
        }

        // --- Signal end of data (e.g., trigger final reset/aggregation) ---
        // Create a meaningful reset context if needed by the query, often just epoch info
        Tuple final_reset_context;
         // If the pipeline uses epoch, find the last epoch ID + 1 or similar
         // For simplicity, let's use an empty context unless epoch is known
         final_reset_context["eid"] = OpResult(static_cast<int64_t>(1)); // Example EID context if needed

        std::cout << "\n--- Final Reset ---" << std::endl;
        pipeline.reset(final_reset_context); // Trigger final aggregations and resets

        // --- Handling Multi-Operator Queries (like Joins) ---
        /*
        Queries::MultiOpCreator multi_query_creator = Queries::syn_flood_sonata();
        std::vector<Operator> multi_pipeline = multi_query_creator(terminal_op);

        if (!multi_pipeline.empty()) {
             Operator& branch1 = multi_pipeline[0];
             Operator& branch2 = multi_pipeline[1];
             // ... potentially more branches

             std::cout << "--- Processing Data (Multi-Branch) ---" << std::endl;
             for (const auto& tup : test_data) {
                 // Need logic to decide which branch(es) the tuple goes to,
                 // or if all tuples go to all branches (like split).
                 // For Sonata joins, typically all tuples go to all input branches.
                 std::cout << "Input: " << Utils::string_of_tuple(tup) << std::endl;
                  for(Operator& branch : multi_pipeline) {
                       branch.next(tup);
                  }
             }

              std::cout << "\n--- Final Reset (Multi-Branch) ---" << std::endl;
              for(Operator& branch : multi_pipeline) {
                  branch.reset(final_reset_context);
              }
        }
        */


        std::cout << "\nDone." << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "An unknown error occurred." << std::endl;
        return 1;
    }

    return 0;
}