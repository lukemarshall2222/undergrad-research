(*
 * Main entry point and implementation for simple header-dump operation
 *)
open Printf

open Utils
open Builtins

(* See builtins.ml for definitions of building blocks used here *)
(* '@=>' is just a right-associative application to avoid nasty nested parens *)

(* counts total number of packets obeserved in an epoch *)
let ident (next_op: operator) : operator = 
    (create_map_operator (fun (tup: tuple) -> Tuple.filter 
        (fun (key_: string) _ -> not 
            (String.equal key_ "eth.src" || String.equal key_ "eth.dst")) tup))
    @=> next_op

(* assigns each tuple an epoch ID based on time by adding an eid key, counts 
the number of tuples in each epoch, then passes the processed tuples to the
 next_op *)
let count_pkts (next_op: operator) : operator =
    (create_epoch_operator 1.0 "eid")
    @=> (create_groupby_operator single_group counter "pkts")
    @=> next_op

(* assigns each tuple an epoch ID based on time by adding an eid key, groups
them by source and dest ip, counts and stores the number of tuples in each 
group, and passes result to next_op *)
let pkts_per_src_dst (next_op: operator) : operator =
    (create_epoch_operator 1.0 "eid")
    @=> (create_groupby_operator 
            (filter_groups ["ipv4.src" ; "ipv4.dst"]) counter "pkts")
    @=> next_op

let distinct_srcs (next_op: operator) : operator =
    (create_epoch_operator 1.0 "eid")
    @=> (create_distinct_operator (filter_groups ["ipv4.src"]))
    @=> (create_groupby_operator single_group counter "srcs")
    @=> next_op

(* Sonata 1 *)
let tcp_new_cons (next_op: operator) : operator =
    let threshold: int = 40 in
    (create_epoch_operator 1.0 "eid")
    @=> (create_filter_operator (fun (tup: tuple)->
                    (get_mapped_int "ipv4.proto" tup) = 6 &&
                    (get_mapped_int "l4.flags" tup) = 2))
    @=> (create_groupby_operator (filter_groups ["ipv4.dst"]) counter "cons")
    @=> (create_filter_operator (key_geq_int "cons" threshold))
    @=> next_op

(* Sonata 2 *)
let ssh_brute_force (next_op: operator) : operator =
    let threshold: int = 40 in
    (create_epoch_operator 1.0 "eid") (* might need to elongate epoch for this one... *)
    @=> (create_filter_operator (fun (tup: tuple)->
                    (get_mapped_int "ipv4.proto" tup) = 6 &&
                    (get_mapped_int "l4.dport" tup) = 22))
    @=> (create_distinct_operator (filter_groups 
                ["ipv4.src" ; "ipv4.dst" ; "ipv4.len"]))
    @=> (create_groupby_operator (filter_groups 
                ["ipv4.dst" ; "ipv4.len"]) counter "srcs")
    @=> (create_filter_operator (key_geq_int "srcs" threshold))
    @=> next_op

(* Sonata 3 *)
let super_spreader (next_op: operator) : operator =
    let threshold: int = 40 in
    (create_epoch_operator 1.0 "eid")
    @=> (create_distinct_operator (filter_groups ["ipv4.src" ; "ipv4.dst"]))
    @=> (create_groupby_operator (filter_groups ["ipv4.src"]) counter "dsts")
    @=> (create_filter_operator (key_geq_int "dsts" threshold))
    @=> next_op

(* Sonata 4 *)
let port_scan (next_op: operator) : operator =
    let threshold: int = 40 in
    (create_epoch_operator 1.0 "eid")
    @=> (create_distinct_operator (filter_groups ["ipv4.src" ; "l4.dport"]))
    @=> (create_groupby_operator (filter_groups ["ipv4.src"]) counter "ports")
    @=> (create_filter_operator (key_geq_int "ports" threshold))
    @=> next_op

(* Sonata 5 *)
let ddos (next_op: operator) : operator =
    let threshold: int = 45 in
    (create_epoch_operator 1.0 "eid")
    @=> (create_distinct_operator (filter_groups ["ipv4.src" ; "ipv4.dst"]))
    @=> (create_groupby_operator (filter_groups ["ipv4.dst"]) counter "srcs")
    @=> (create_filter_operator (key_geq_int "srcs" threshold))
    @=> next_op

(* Sonata 6 --- Note this implements the Sonata semantic of this query 
*NOT* the intended semantic from NetQRE *)
let syn_flood_sonata (next_op: operator) : operator list =
    let threshold: int = 3 in
    let epoch_dur: float = 1.0 in
    let syns (next_op: operator) : operator =
        (create_epoch_operator epoch_dur "eid")
        @=> (create_filter_operator (fun (tup: tuple) ->
                        (get_mapped_int "ipv4.proto" tup) = 6 &&
                        (get_mapped_int "l4.flags" tup) = 2))
        @=> (create_groupby_operator (filter_groups ["ipv4.dst"]) 
                                        counter "syns")
        @=> next_op
    in let synacks (next_op: operator) : operator =
        (create_epoch_operator epoch_dur "eid")
        @=> (create_filter_operator (fun (tup: tuple) ->
                        (get_mapped_int "ipv4.proto" tup) = 6 &&
                        (get_mapped_int "l4.flags" tup) = 18))  
        @=> (create_groupby_operator (filter_groups ["ipv4.src"]) 
                                        counter "synacks")
        @=> next_op
    in let acks (next_op: operator) : operator =
        (create_epoch_operator epoch_dur "eid")
        @=> (create_filter_operator (fun (tup: tuple)->
                        (get_mapped_int "ipv4.proto" tup) = 6 &&
                        (get_mapped_int "l4.flags" tup) = 16))
        @=> (create_groupby_operator (filter_groups ["ipv4.dst"]) 
                                        counter "acks")
        @=> next_op
    in let (join_op1: operator), (join_op2: operator) =
        (create_join_operator
            (fun (tup: tuple)-> ((filter_groups ["host"] tup), 
                        (filter_groups ["syns+synacks"] tup)))
            (fun (tup: tuple)-> ((rename_filtered_keys [("ipv4.dst","host")] tup), 
                        (filter_groups ["acks"] tup))))
        @==> (create_map_operator (fun (tup: tuple)-> Tuple.add "syns+synacks-acks" 
                    (Int ((get_mapped_int "syns+synacks" tup) - 
                    (get_mapped_int "acks" tup))) tup))
        @=> (create_filter_operator (key_geq_int "syns+synacks-acks" threshold))
        @=> next_op
    in let (join_op3: operator), (join_op4: operator) = 
        (create_join_operator
            (fun (tup: tuple)-> ((rename_filtered_keys [("ipv4.dst","host")] tup), 
                        (filter_groups ["syns"] tup)))
            (fun (tup: tuple)-> ((rename_filtered_keys [("ipv4.src","host")] tup), 
                        (filter_groups ["synacks"] tup))))
        @==> (create_map_operator (fun (tup: tuple)-> Tuple.add "syns+synacks" 
                    (Int ((get_mapped_int "syns" tup) + 
                    (get_mapped_int "synacks" tup))) tup))
        @=> join_op1
    in [syns @=> join_op3 ; synacks @=> join_op4 ; acks @=> join_op2]
    













(* Sonata 7 *)
let completed_flows (next_op: operator) : operator list =
    let threshold: int = 1 in
    let epoch_dur: float = 30.0 in
    let syns (next_op: operator) : operator=
        (create_epoch_operator epoch_dur "eid")
        @=> (create_filter_operator (fun (tup: tuple)->
                        (get_mapped_int "ipv4.proto" tup) = 6 &&
                        (get_mapped_int "l4.flags" tup) = 2))
        @=> (create_groupby_operator (filter_groups ["ipv4.dst"]) 
                                        counter "syns")
        @=> next_op
    in let fins (next_op: operator) : operator=
        (create_epoch_operator epoch_dur "eid")
        @=> (create_filter_operator (fun (tup: tuple) ->
                        (get_mapped_int "ipv4.proto" tup) = 6 &&
                        ((get_mapped_int "l4.flags" tup) land 1) = 1))
        @=> (create_groupby_operator (filter_groups ["ipv4.src"]) 
                                        counter "fins")
        @=> next_op
    in let (op1: operator), (op2: operator) =
        (create_join_operator
            (fun (tup: tuple) -> ((rename_filtered_keys [("ipv4.dst","host")] tup), 
                        (filter_groups ["syns"] tup)))
            (fun (tup: tuple) -> ((rename_filtered_keys [("ipv4.src","host")] tup), 
                        (filter_groups ["fins"] tup))))
        @==> (create_map_operator (fun (tup: tuple) -> Tuple.add "diff" 
                    (Int ((get_mapped_int "syns" tup) - 
                    (get_mapped_int "fins" tup))) tup))
        @=> (create_filter_operator (key_geq_int "diff" threshold))
        @=> next_op
    in [syns @=> op1 ; fins @=> op2]

(* Sonata 8 *)
let slowloris (next_op: operator) : operator list =
    let t1: int = 5 in
    let t2: int = 500 in
    let t3: int = 90 in
    let epoch_dur: float = 1.0 in
    let n_conns (next_op: operator) : operator=
        (create_epoch_operator epoch_dur "eid")
        @=> (create_filter_operator (fun (tup: tuple) -> 
                        (get_mapped_int "ipv4.proto" tup) = 6))
        @=> (create_distinct_operator (filter_groups 
                                        ["ipv4.src" ; "ipv4.dst" ; "l4.sport"]))
        @=> (create_groupby_operator (filter_groups ["ipv4.dst"]) counter "n_conns")
        @=> (create_filter_operator (fun (tup: tuple) -> 
                        (get_mapped_int "n_conns" tup) >= t1))
        @=> next_op
    in let n_bytes (next_op: operator) : operator=
        (create_epoch_operator epoch_dur "eid")
        @=> (create_filter_operator (fun (tup: tuple) -> 
                        (get_mapped_int "ipv4.proto" tup) = 6))
        @=> (create_groupby_operator (filter_groups ["ipv4.dst"]) 
                                        (sum_ints "ipv4.len") "n_bytes")
        @=> (create_filter_operator (fun (tup: tuple) -> 
                        (get_mapped_int "n_bytes" tup) >= t2))
        @=> next_op
    in let op1, op2 =
        (create_join_operator
            (fun (tup: tuple) -> (filter_groups ["ipv4.dst"] tup, 
                        filter_groups ["n_conns"] tup))
            (fun (tup: tuple) -> (filter_groups ["ipv4.dst"] tup, 
                        filter_groups ["n_bytes"] tup)))
        @==> (create_map_operator (fun (tup: tuple) -> Tuple.add "bytes_per_conn" 
                    (Int ((get_mapped_int "n_bytes" tup) / 
                    (get_mapped_int "n_conns" tup))) tup))
        @=> (create_filter_operator (fun (tup: tuple) -> 
                        (get_mapped_int "bytes_per_conn" tup) <= t3))
        @=> next_op
    in [n_conns @=> op1 ; n_bytes @=> op2]

let create_join_operator_test (next_op: operator) : operator list =
    let epoch_dur: float = 1.0 in
    let syns (next_op: operator) : operator=
        (create_epoch_operator epoch_dur "eid")
        @=> (create_filter_operator (fun (tup: tuple) ->
                        (get_mapped_int "ipv4.proto" tup) = 6 &&
                        (get_mapped_int "l4.flags" tup) = 2))
        @=> next_op
    in let synacks (next_op: operator) : operator=
        (create_epoch_operator epoch_dur "eid")
        @=> (create_filter_operator (fun (tup: tuple) ->
                        (get_mapped_int "ipv4.proto" tup) = 6 &&
                        (get_mapped_int "l4.flags" tup) = 18))
        @=> next_op
    in let op1, op2 =
        (create_join_operator
            (fun (tup: tuple) -> ((rename_filtered_keys [("ipv4.src","host")] tup), 
                        (rename_filtered_keys [("ipv4.dst","remote")] tup)))
            (fun (tup: tuple) -> ((rename_filtered_keys [("ipv4.dst","host")] tup), 
                        (filter_groups ["time"] tup))))
        @==> next_op
    in [syns @=> op1 ; synacks @=> op2]

let q3 (next_op: operator) : operator =
    (create_epoch_operator 100.0 "eid")
    @=> create_distinct_operator (filter_groups ["ipv4.src" ; "ipv4.dst"])
    @=> next_op

let q4 (next_op: operator) : operator =
    (create_epoch_operator 10000.0 "eid")
    @=> create_groupby_operator (filter_groups ["ipv4.dst"]) counter "pkts"
    @=> next_op
        
let queries: operator list = [ident (dump_as_csv stdout)]

let run_queries () = 
    List.map (fun (tup: tuple) -> 
        List.iter (fun (query: operator) -> query.next tup) queries)
        (List.init 20 (fun (i: int) ->
            Tuple.empty
            |> Tuple.add "time" (Float (0.000000 +. (float)i))

            |> Tuple.add "eth.src" (MAC (Bytes.of_string 
                                                    "\x00\x11\x22\x33\x44\x55"))
            |> Tuple.add "eth.dst" (MAC (Bytes.of_string 
                                                    "\xAA\xBB\xCC\xDD\xEE\xFF"))
            |> Tuple.add "eth.ethertype" (Int 0x0800)

            |> Tuple.add "ipv4.hlen" (Int 20)
            |> Tuple.add "ipv4.proto" (Int 6)
            |> Tuple.add "ipv4.len" (Int 60)
            |> Tuple.add "ipv4.src" (IPv4 (Ipaddr.V4.of_string_exn "127.0.0.1"))
            |> Tuple.add "ipv4.dst" (IPv4 (Ipaddr.V4.of_string_exn "127.0.0.1"))

            |> Tuple.add "l4.sport" (Int 440)
            |> Tuple.add "l4.dport" (Int 50000)
            |> Tuple.add "l4.flags" (Int 10))
        )

(*
 * Main entrypoint
 *)
let () = ignore (run_queries ()) ; printf "Done\n"
    