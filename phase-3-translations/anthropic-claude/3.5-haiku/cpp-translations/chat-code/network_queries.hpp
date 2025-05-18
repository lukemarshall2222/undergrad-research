#pragma once

#include "types.hpp"
#include "advanced_operators.hpp"

namespace stream_processing {

class NetworkQueries {
public:
    // Direct translations of OCaml queries
    static Operator identityQuery(Operator next);
    static Operator countPacketsQuery(Operator next);
    static Operator packetsPerSrcDstQuery(Operator next);
    static Operator distinctSourcesQuery(Operator next);
    
    // Sonata queries
    static Operator tcpNewConnectionsQuery(Operator next, int threshold = 40);
    static Operator sshBruteForceQuery(Operator next, int threshold = 40);
    static Operator superSpreaderQuery(Operator next, int threshold = 40);
    static Operator portScanQuery(Operator next, int threshold = 40);
    static Operator ddosQuery(Operator next, int threshold = 45);
    
    // More complex queries
    static std::vector<Operator> synFloodQuery(Operator next);
    static std::vector<Operator> completedFlowsQuery(Operator next);
    static std::vector<Operator> slowlorisQuery(Operator next);
    
    // Utility queries
    static Operator queryQ3(Operator next);
    static Operator queryQ4(Operator next);
};

} // namespace stream_processing