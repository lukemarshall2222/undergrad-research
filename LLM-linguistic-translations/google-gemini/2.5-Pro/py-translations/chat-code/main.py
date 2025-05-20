# main.py
import sys
import ipaddress
from typing import List, Dict, Callable, Any, Tuple as PyTuple

# Import necessary components from our modules
from utils import (
    OpResult, Tuple, Operator, OpCreator, DblOpCreator,
    MAC, IPv4, Int, Float, Empty,  # Make constructors available if needed
    int_of_op_result, float_of_op_result, lookup_int, lookup_float,
    tuple_of_list, make_hashable, merge_tuples
)
from builtins import (
    # Operators (Classes implementing Operator protocol)
    DumpTupleOperator, DumpCsvOperator, DumpWaltsCsvOperator,
    MetaMeterOperator, EpochOperator, FilterOperator, MapOperator,
    GroupByOperator, DistinctOperator, SplitOperator,
    # Operator Constructors (Functions returning Operators or pairs)
    join,
    # Utility functions used in query definitions
    key_geq_int, get_mapped_int, get_mapped_float, # Aliases for lookup_*
    filter_groups, single_group, counter, sum_ints,
    rename_filtered_keys,
    # Driver function
    read_walts_csv,
)

# --- Query Definitions ---
# These functions take the *next* operator and return the *entry point* operator
# for that specific query pipeline.

def ident() -> OpCreator:
    """Query: Remove ethernet fields."""
    def creator(next_op: Operator) -> Operator:
        map_func = lambda tup: {
            k: v for k, v in tup.items()
            if k not in ("eth.src", "eth.dst")
        }
        return MapOperator(map_func, next_op)
    return creator

def count_pkts() -> OpCreator:
    """Query: Count total packets per epoch."""
    def creator(next_op: Operator) -> Operator:
        # Composition: epoch -> groupby -> next_op
        gb_op = GroupByOperator(single_group, counter(), "pkts", next_op)
        ep_op = EpochOperator(1.0, "eid", gb_op)
        return ep_op
    return creator

def pkts_per_src_dst() -> OpCreator:
    """Query: Count packets per source/destination IP pair per epoch."""
    def creator(next_op: Operator) -> Operator:
        gb_op = GroupByOperator(
            filter_groups(["ipv4.src", "ipv4.dst"]),
            counter(),
            "pkts",
            next_op
        )
        ep_op = EpochOperator(1.0, "eid", gb_op)
        return ep_op
    return creator

def distinct_srcs() -> OpCreator:
    """Query: Count distinct source IPs per epoch."""
    def creator(next_op: Operator) -> Operator:
        gb_op = GroupByOperator(single_group, counter(), "srcs", next_op)
        dist_op = DistinctOperator(filter_groups(["ipv4.src"]), gb_op)
        ep_op = EpochOperator(1.0, "eid", dist_op)
        return ep_op
    return creator

# --- Sonata Queries ---

def tcp_new_cons(threshold: int = 40) -> OpCreator:
    """Sonata 1: Detect hosts receiving many new TCP connections."""
    def creator(next_op: Operator) -> Operator:
        filter_threshold_op = FilterOperator(key_geq_int("cons", threshold), next_op)
        gb_op = GroupByOperator(
            filter_groups(["ipv4.dst"]),
            counter(),
            "cons",
            filter_threshold_op
        )
        filter_syn_op = FilterOperator(
            lambda tup: lookup_int("ipv4.proto", tup) == 6 and lookup_int("l4.flags", tup) == 2, # SYN flag = 2
            gb_op
        )
        ep_op = EpochOperator(1.0, "eid", filter_syn_op)
        return ep_op
    return creator

def ssh_brute_force(threshold: int = 40) -> OpCreator:
    """Sonata 2: Detect SSH brute force attacks."""
    def creator(next_op: Operator) -> Operator:
        filter_threshold_op = FilterOperator(key_geq_int("srcs", threshold), next_op)
        gb_op = GroupByOperator(
            filter_groups(["ipv4.dst", "ipv4.len"]), # Group by dst IP and packet length
            counter(),
            "srcs", # Count distinct sources per (dst, len) group
            filter_threshold_op
        )
        dist_op = DistinctOperator(
             filter_groups(["ipv4.src", "ipv4.dst", "ipv4.len"]), # Distinct (src, dst, len)
             gb_op
        )
        filter_ssh_op = FilterOperator(
            lambda tup: lookup_int("ipv4.proto", tup) == 6 and lookup_int("l4.dport", tup) == 22,
            dist_op
        )
        ep_op = EpochOperator(1.0, "eid", filter_ssh_op) # Maybe longer epoch?
        return ep_op
    return creator

def super_spreader(threshold: int = 40) -> OpCreator:
    """Sonata 3: Detect hosts connecting to many distinct destinations."""
    def creator(next_op: Operator) -> Operator:
        filter_threshold_op = FilterOperator(key_geq_int("dsts", threshold), next_op)
        gb_op = GroupByOperator(
            filter_groups(["ipv4.src"]), # Group by source
            counter(),
            "dsts", # Count distinct destinations contacted by source
            filter_threshold_op
        )
        dist_op = DistinctOperator(
             filter_groups(["ipv4.src", "ipv4.dst"]), # Distinct (src, dst) pairs
             gb_op
        )
        ep_op = EpochOperator(1.0, "eid", dist_op)
        return ep_op
    return creator

def port_scan(threshold: int = 40) -> OpCreator:
    """Sonata 4: Detect hosts scanning many distinct ports on destinations."""
    # NOTE: Original groups by src only. If scanning multiple hosts, maybe group by (src, dst)? Sticking to original.
    def creator(next_op: Operator) -> Operator:
        filter_threshold_op = FilterOperator(key_geq_int("ports", threshold), next_op)
        gb_op = GroupByOperator(
            filter_groups(["ipv4.src"]), # Group by source IP
            counter(),
            "ports", # Count distinct destination ports tried by source
            filter_threshold_op
        )
        dist_op = DistinctOperator(
             filter_groups(["ipv4.src", "l4.dport"]), # Distinct (src, port) pairs tried
             gb_op
        )
        ep_op = EpochOperator(1.0, "eid", dist_op)
        return ep_op
    return creator

def ddos(threshold: int = 45) -> OpCreator:
    """Sonata 5: Detect hosts targeted by many distinct sources (DDoS)."""
    def creator(next_op: Operator) -> Operator:
        filter_threshold_op = FilterOperator(key_geq_int("srcs", threshold), next_op)
        gb_op = GroupByOperator(
            filter_groups(["ipv4.dst"]), # Group by destination IP
            counter(),
            "srcs", # Count distinct sources hitting the destination
            filter_threshold_op
        )
        dist_op = DistinctOperator(
             filter_groups(["ipv4.src", "ipv4.dst"]), # Distinct (src, dst) pairs
             gb_op
        )
        ep_op = EpochOperator(1.0, "eid", dist_op)
        return ep_op
    return creator


# Sonata 6 (SYN Flood) requires multiple input streams processed and joined.
# It returns a LIST of operator entry points.
def syn_flood_sonata(threshold: int = 3, epoch_dur: float = 1.0) -> Callable[[Operator], List[Operator]]:
    """Sonata 6: Detect SYN flood (SYN > SYNACK + ACK). Returns *list* of operators."""
    def creator(final_next_op: Operator) -> List[Operator]:
        # Define the final filtering and mapping steps after joins
        filter_final_op = FilterOperator(
            key_geq_int("syns+synacks-acks", threshold),
            final_next_op
        )
        map_final_op = MapOperator(
            lambda tup: merge_tuples(tup, {"syns+synacks-acks": lookup_int("syns+synacks", tup) - lookup_int("acks", tup)}, precedence='last'),
            filter_final_op
        )

        # Define the second join (SYN+SYNACK vs ACK)
        join2_left_extract: KeyExtractor = lambda tup: (
            filter_groups(["host"])(tup),          # Key: {"host": ...}
            filter_groups(["syns+synacks"])(tup)   # Value: {"syns+synacks": ...}
        )
        join2_right_extract: KeyExtractor = lambda tup: (
            rename_filtered_keys([("ipv4.dst", "host")])(tup), # Key: {"host": ...}
            filter_groups(["acks"])(tup)                       # Value: {"acks": ...}
        )
        # The 'next_op' for join2 is the map_final_op chain
        join2_op1, join2_op2 = join(join2_left_extract, join2_right_extract, map_final_op, eid_key="eid")

        # Define the first join (SYN vs SYNACK)
        map_join1_op = MapOperator(
             lambda tup: merge_tuples(tup, {"syns+synacks": lookup_int("syns", tup) + lookup_int("synacks", tup)}, precedence='last'),
             join2_op1 # Output of this map goes to the left input of join2
        )
        join1_left_extract: KeyExtractor = lambda tup: (
            rename_filtered_keys([("ipv4.dst", "host")])(tup), # Key: {"host":...}
            filter_groups(["syns"])(tup)                       # Value: {"syns":...}
        )
        join1_right_extract: KeyExtractor = lambda tup: (
            rename_filtered_keys([("ipv4.src", "host")])(tup), # Key: {"host":...} Renamed from src!
            filter_groups(["synacks"])(tup)                    # Value: {"synacks":...}
        )
        # The 'next_op' for join1 is the map_join1_op
        join1_op3, join1_op4 = join(join1_left_extract, join1_right_extract, map_join1_op, eid_key="eid")


        # --- Define the initial processing pipelines for SYN, SYNACK, ACK ---
        # SYN Pipeline -> feeds left side of join1 (join1_op3)
        syns_gb_op = GroupByOperator(filter_groups(["ipv4.dst"]), counter(), "syns", join1_op3)
        syns_filter_op = FilterOperator(
            lambda tup: lookup_int("ipv4.proto", tup) == 6 and lookup_int("l4.flags", tup) == 2, # SYN
            syns_gb_op
        )
        syns_epoch_op = EpochOperator(epoch_dur, "eid", syns_filter_op)

        # SYNACK Pipeline -> feeds right side of join1 (join1_op4)
        synacks_gb_op = GroupByOperator(filter_groups(["ipv4.src"]), counter(), "synacks", join1_op4) # Group by SYNACK sender (src)
        synacks_filter_op = FilterOperator(
            lambda tup: lookup_int("ipv4.proto", tup) == 6 and lookup_int("l4.flags", tup) == 18, # SYN+ACK = 18 (0x12)
            synacks_gb_op
        )
        synacks_epoch_op = EpochOperator(epoch_dur, "eid", synacks_filter_op)

        # ACK Pipeline -> feeds right side of join2 (join2_op2)
        acks_gb_op = GroupByOperator(filter_groups(["ipv4.dst"]), counter(), "acks", join2_op2) # Group by ACK receiver (dst)
        acks_filter_op = FilterOperator(
            lambda tup: lookup_int("ipv4.proto", tup) == 6 and lookup_int("l4.flags", tup) == 16, # ACK = 16 (0x10)
            acks_gb_op
        )
        acks_epoch_op = EpochOperator(epoch_dur, "eid", acks_filter_op)

        # Return the entry points of the three pipelines
        return [syns_epoch_op, synacks_epoch_op, acks_epoch_op]

    return creator

# Sonata 7 (Completed Flows)
def completed_flows(threshold: int = 1, epoch_dur: float = 30.0) -> Callable[[Operator], List[Operator]]:
    """Sonata 7: Detect hosts with more SYNs than FINs. Returns *list* of operators."""
    def creator(final_next_op: Operator) -> List[Operator]:
        filter_final_op = FilterOperator(key_geq_int("diff", threshold), final_next_op)
        map_final_op = MapOperator(
            lambda tup: merge_tuples(tup, {"diff": lookup_int("syns", tup) - lookup_int("fins", tup)}, precedence='last'),
            filter_final_op
        )

        join_left_extract: KeyExtractor = lambda tup: (
            rename_filtered_keys([("ipv4.dst", "host")])(tup), # Key is host receiving SYN
            filter_groups(["syns"])(tup)
        )
        join_right_extract: KeyExtractor = lambda tup: (
            rename_filtered_keys([("ipv4.src", "host")])(tup), # Key is host sending FIN (maps to same host)
            filter_groups(["fins"])(tup)
        )
        op1, op2 = join(join_left_extract, join_right_extract, map_final_op, eid_key="eid")

        # SYN pipeline -> feeds op1 (left join input)
        syns_gb_op = GroupByOperator(filter_groups(["ipv4.dst"]), counter(), "syns", op1)
        syns_filter_op = FilterOperator(
            lambda tup: lookup_int("ipv4.proto", tup) == 6 and lookup_int("l4.flags", tup) == 2, # SYN
            syns_gb_op
        )
        syns_epoch_op = EpochOperator(epoch_dur, "eid", syns_filter_op)

        # FIN pipeline -> feeds op2 (right join input)
        fins_gb_op = GroupByOperator(filter_groups(["ipv4.src"]), counter(), "fins", op2) # Group by FIN sender (src)
        fins_filter_op = FilterOperator(
            lambda tup: lookup_int("ipv4.proto", tup) == 6 and (lookup_int("l4.flags", tup) & 1) == 1, # FIN flag is bit 0
            fins_gb_op
        )
        fins_epoch_op = EpochOperator(epoch_dur, "eid", fins_filter_op)

        return [syns_epoch_op, fins_epoch_op]
    return creator

# Sonata 8 (Slowloris)
def slowloris(t1: int = 5, t2: int = 500, t3: int = 90, epoch_dur: float = 1.0) -> Callable[[Operator], List[Operator]]:
    """Sonata 8: Detect Slowloris attacks. Returns *list* of operators."""
    def creator(final_next_op: Operator) -> List[Operator]:
        # Final filtering and mapping
        filter_final_op = FilterOperator(
            lambda tup: lookup_int("bytes_per_conn", tup) <= t3,
            final_next_op
        )
        map_final_op = MapOperator(
            lambda tup: merge_tuples(tup, {"bytes_per_conn": lookup_int("n_bytes", tup) // lookup_int("n_conns", tup)}, precedence='last'),
            filter_final_op
        )

        # Join definition
        join_left_extract: KeyExtractor = lambda tup: ( # n_conns side
            filter_groups(["ipv4.dst"])(tup),
            filter_groups(["n_conns"])(tup)
        )
        join_right_extract: KeyExtractor = lambda tup: ( # n_bytes side
            filter_groups(["ipv4.dst"])(tup),
            filter_groups(["n_bytes"])(tup)
        )
        op1, op2 = join(join_left_extract, join_right_extract, map_final_op, eid_key="eid")

        # n_conns pipeline -> feeds op1
        n_conns_filter_t1 = FilterOperator(key_geq_int("n_conns", t1), op1)
        n_conns_gb = GroupByOperator(filter_groups(["ipv4.dst"]), counter(), "n_conns", n_conns_filter_t1)
        n_conns_distinct = DistinctOperator(filter_groups(["ipv4.src", "ipv4.dst", "l4.sport"]), n_conns_gb) # Distinct connections
        n_conns_filter_proto = FilterOperator(lambda tup: lookup_int("ipv4.proto", tup) == 6, n_conns_distinct)
        n_conns_epoch = EpochOperator(epoch_dur, "eid", n_conns_filter_proto)

        # n_bytes pipeline -> feeds op2
        n_bytes_filter_t2 = FilterOperator(key_geq_int("n_bytes", t2), op2)
        n_bytes_gb = GroupByOperator(filter_groups(["ipv4.dst"]), sum_ints("ipv4.len"), "n_bytes", n_bytes_filter_t2) # Sum bytes per dest
        n_bytes_filter_proto = FilterOperator(lambda tup: lookup_int("ipv4.proto", tup) == 6, n_bytes_gb)
        n_bytes_epoch = EpochOperator(epoch_dur, "eid", n_bytes_filter_proto)

        return [n_conns_epoch, n_bytes_epoch]

    return creator

# Join Test Example
def join_test() -> Callable[[Operator], List[Operator]]:
    """Example demonstrating a join."""
    def creator(final_next_op: Operator) -> List[Operator]:
        join_left_extract: KeyExtractor = lambda tup: (
            rename_filtered_keys([("ipv4.src", "host")])(tup),   # Key: {"host": src_ip}
            rename_filtered_keys([("ipv4.dst", "remote")])(tup) # Value: {"remote": dst_ip}
        )
        join_right_extract: KeyExtractor = lambda tup: (
            rename_filtered_keys([("ipv4.dst", "host")])(tup),   # Key: {"host": dst_ip}
            filter_groups(["time"])(tup)                       # Value: {"time": time}
        )
        # Note: eid_key="eid" is default for join
        op1, op2 = join(join_left_extract, join_right_extract, final_next_op)

        # SYN pipeline -> feeds op1
        syns_filter_op = FilterOperator(
            lambda tup: lookup_int("ipv4.proto", tup) == 6 and lookup_int("l4.flags", tup) == 2, # SYN
            op1 # Send SYN packets directly to left join input
        )
        syns_epoch_op = EpochOperator(1.0, "eid", syns_filter_op)

        # SYNACK pipeline -> feeds op2
        synacks_filter_op = FilterOperator(
            lambda tup: lookup_int("ipv4.proto", tup) == 6 and lookup_int("l4.flags", tup) == 18, # SYNACK
            op2 # Send SYNACK packets directly to right join input
        )
        synacks_epoch_op = EpochOperator(1.0, "eid", synacks_filter_op)

        return [syns_epoch_op, synacks_epoch_op]

    return creator

# --- Other simple queries from OCaml main ---
def q3() -> OpCreator:
    """Distinct source/destination pairs over a long epoch."""
    def creator(next_op: Operator) -> Operator:
        dist_op = DistinctOperator(filter_groups(["ipv4.src", "ipv4.dst"]), next_op)
        ep_op = EpochOperator(100.0, "eid", dist_op)
        return ep_op
    return creator

def q4() -> OpCreator:
    """Count packets per destination over a very long epoch."""
    def creator(next_op: Operator) -> Operator:
        gb_op = GroupByOperator(filter_groups(["ipv4.dst"]), counter(), "pkts", next_op)
        ep_op = EpochOperator(10000.0, "eid", gb_op)
        return ep_op
    return creator


# --- Main Execution ---

def run_queries(queries_to_run: List[Operator]):
    """Generates sample data and runs it through the specified queries."""
    print("Generating sample data...")
    sample_data: List[Tuple] = []
    base_time = 0.0 # Or use time.time() for real timestamps
    for i in range(20):
        tup: Tuple = {
            "time": base_time + float(i) * 0.01, # Increment time slightly
            "eth.src": b'\x00\x11\x22\x33\x44\x55',
            "eth.dst": b'\xAA\xBB\xCC\xDD\xEE\xFF',
            "eth.ethertype": 0x0800, # IPv4
            "ipv4.hlen": 20,
            "ipv4.proto": 6, # TCP
            "ipv4.len": 60 + i, # Vary length slightly
            "ipv4.src": ipaddress.IPv4Address(f"192.168.1.{100 + i % 5}"), # Vary src IP
            "ipv4.dst": ipaddress.IPv4Address(f"10.0.0.{1 + i % 3}"), # Vary dst IP
            "l4.sport": 44000 + i,
            "l4.dport": 80 if i % 4 != 0 else 22, # Mostly port 80, sometimes 22
            # Vary flags: SYN, SYNACK, ACK, FIN, PSH+ACK
            "l4.flags": [2, 18, 16, 1, 24][i % 5]
        }
        sample_data.append(tup)

    print(f"Running {len(sample_data)} sample tuples through {len(queries_to_run)} queries...")
    for tup in sample_data:
        for query_op in queries_to_run:
            try:
                 query_op.next(tup)
            except Exception as e:
                 print(f"Error processing tuple in query: {e}", file=sys.stderr)
                 # Decide whether to continue with next query or tuple

    # Signal end of stream by calling reset on all query entry points
    # Use an empty tuple or a tuple indicating end for the reset signal?
    # The OCaml 'epoch' reset used a singleton with the last epoch ID.
    # Let's send a generic reset signal (empty dict). Individual operators
    # might add relevant info (like epoch id) when propagating the reset.
    print("Signaling end of stream (reset)...")
    reset_signal: Tuple = {}
    for query_op in queries_to_run:
         try:
             query_op.reset(reset_signal)
         except Exception as e:
             print(f"Error resetting query: {e}", file=sys.stderr)


if __name__ == "__main__":
    print("--- Python Stream Processor ---")

    # Define the terminal operator (where the results go)
    # Change stdout to a file stream if needed: open('output.txt', 'w')
    # terminal_op = DumpTupleOperator(sys.stdout, show_reset=True)
    terminal_op = DumpCsvOperator(sys.stdout, header=True) # Use CSV output for testing

    # --- Select and Instantiate Queries ---
    # Note: For queries returning List[Operator] (like syn_flood),
    # you would typically run them by reading data multiple times or splitting
    # the input stream appropriately *before* the query entry points.
    # The `read_walts_csv` function handles this for its specific use case.
    # For the simple `run_queries` example, we'll run simpler queries.

    # Example: Run count_pkts and distinct_srcs queries
    # Apply the creator function to the terminal operator
    query1_creator = count_pkts()
    query1_entry_op = query1_creator(terminal_op)

    query2_creator = distinct_srcs()
    query2_entry_op = query2_creator(terminal_op)

    query3_creator = tcp_new_cons()
    query3_entry_op = query3_creator(terminal_op)


    # List of *entry point* operators for the selected queries
    active_queries: List[Operator] = [query1_entry_op, query2_entry_op, query3_entry_op]


    # --- Execute ---
    # run_queries(active_queries) # Run with sample data

    # Example of using read_walts_csv (if you have suitable files)
    # Create dummy files first for testing
    # try:
    #     with open("dummy_walt1.csv", "w") as f:
    #         f.write("1.1.1.1,2.2.2.2,100,200,10,1000,0\n")
    #         f.write("1.1.1.1,2.2.2.2,101,201,5,500,0\n")
    #         f.write("3.3.3.3,4.4.4.4,300,400,20,2000,1\n") # Epoch 1
    #     with open("dummy_walt2.csv", "w") as f:
    #         f.write("5.5.5.5,6.6.6.6,500,600,1,100,0\n")
    #         f.write("7.7.7.7,8.8.8.8,700,800,2,200,1\n") # Epoch 1
    #         f.write("7.7.7.7,8.8.8.8,701,801,3,300,1\n") # Epoch 1
    #
    #     # Define terminal ops for each input file/stream
    #     term_op1 = DumpTupleOperator(open("walt_out1.txt", "w"), show_reset=True)
    #     term_op2 = DumpTupleOperator(open("walt_out2.txt", "w"), show_reset=True)
    #
    #     # Apply query creators
    #     walt_query1_entry = pkts_per_src_dst()(term_op1)
    #     walt_query2_entry = count_pkts()(term_op2)
    #
    #     read_walts_csv(
    #         file_names=["dummy_walt1.csv", "dummy_walt2.csv"],
    #         ops=[walt_query1_entry, walt_query2_entry]
    #     )
    #     # Remember to close file streams if not using 'with' or DumpWaltsCsvOperator
    #     term_op1._out_stream.close() # Manually close if needed
    #     term_op2._out_stream.close() # Manually close if needed
    # except Exception as e:
    #     print(f"Error running read_walts_csv example: {e}")


    # --- Example demonstrating a join query with sample data ---
    print("\n--- Running Join Test Example ---")
    join_term_op = DumpTupleOperator(sys.stdout, show_reset=True)
    join_creator = join_test()
    join_entry_ops: List[Operator] = join_creator(join_term_op) # Get the two entry points

    # Need to feed data to the correct entry point based on type (SYN vs SYNACK)
    print("Generating data for join test...")
    join_sample_data = []
    base_time = 100.0
    # Generate some SYNs
    for i in range(5):
         join_sample_data.append({
            "time": base_time + i * 0.1, "type": "SYN",
            "ipv4.proto": 6, "l4.flags": 2, "eid": 0,
            "ipv4.src": ipaddress.IPv4Address("1.1.1.1"),
            "ipv4.dst": ipaddress.IPv4Address("2.2.2.2"),
         })
    # Generate some SYNACKs (some matching, some not)
    for i in range(5):
         join_sample_data.append({
            "time": base_time + i * 0.1 + 0.05, "type": "SYNACK",
            "ipv4.proto": 6, "l4.flags": 18, "eid": 0,
             # SYNACK source is the original SYN destination
            "ipv4.src": ipaddress.IPv4Address("2.2.2.2") if i%2 == 0 else ipaddress.IPv4Address("3.3.3.3"),
             # SYNACK dest is the original SYN source
            "ipv4.dst": ipaddress.IPv4Address("1.1.1.1"),
         })
    # Add data for next epoch
    join_sample_data.append({
            "time": base_time + 1.5, "type": "SYN",
            "ipv4.proto": 6, "l4.flags": 2, "eid": 1, # Epoch 1
            "ipv4.src": ipaddress.IPv4Address("4.4.4.4"),
            "ipv4.dst": ipaddress.IPv4Address("5.5.5.5"),
         })
    join_sample_data.append({
            "time": base_time + 1.6, "type": "SYNACK",
            "ipv4.proto": 6, "l4.flags": 18, "eid": 1, # Epoch 1
            "ipv4.src": ipaddress.IPv4Address("5.5.5.5"),
            "ipv4.dst": ipaddress.IPv4Address("4.4.4.4"),
         })


    print("Processing join data...")
    syn_op_entry = join_entry_ops[0]   # Corresponds to the 'syns' pipeline in join_test
    synack_op_entry = join_entry_ops[1] # Corresponds to the 'synacks' pipeline

    for tup in join_sample_data:
        if tup["type"] == "SYN":
            syn_op_entry.next(tup)
        elif tup["type"] == "SYNACK":
            synack_op_entry.next(tup)

    # Reset both sides
    print("Resetting join streams...")
    # Reset signal needs the last epoch ID encountered
    syn_op_entry.reset({"eid": 1})
    synack_op_entry.reset({"eid": 1})


    print("\nDone")