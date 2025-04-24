(*
 * Built-in operator definitions
 * and common utilities for readability
 *)

open Utils
open Printf

let init_table_size: int = 10000

(*
 * Dump all fields of all tuples to the given output channel
 * Note that dump is terminal in that it does not take a continuation operator 
 * as argument
 *)
(* returns an operator record with two functions:
    next: dumps a given Tuple to the given output
    reset: prints a reset message if the given show_reset is true  *)
let create_dump_operator ?(show_reset: bool=false) (outc: out_channel) 
            :  operator =
    {
        next = (fun (tup: tuple) -> dump_tuple outc tup);
        reset = (fun (tup: tuple) -> if show_reset
                            then ( dump_tuple outc tup; 
                                   fprintf outc "[reset]\n"
                                 ));
    }

(*
 * Tries to dump a nice csv-style output
 * Assumes all tuples have the same fields in the same order...
 *)
(* writes tuples to an output channel in CSV format 
constructs operator record with two fields:
    next: process tuples
    reset: does nothing *)
let dump_as_csv ?(static_field:(string*string)option = None) ?(header=true) 
        (outc: out_channel) : operator =
    let first: bool ref = ref header in
    {
        next = (fun (tup: tuple) ->
            if !first
            then (
                (match static_field with
                    | Some (key,_) -> fprintf outc "%s," key
                    | None -> () );
                Tuple.iter (fun key _ -> fprintf outc "%s," key) tup;
                fprintf outc "\n";
                first := false
            ) ;
            (match static_field with
                | Some (_,value) -> fprintf outc "%s," value
                | None -> () );
            Tuple.iter (fun _ value -> fprintf outc "%s," (string_of_op_result 
                                                            value)) tup;
            fprintf outc "\n"
        );
        reset = fun _ -> ();
    }

(*
 * Dumps csv in Walt's canonical csv format: src_ip, dst_ip, src_l4_port, 
 * dst_l4_port, packet_count, byte_count, epoch_id
 * Unused fields are zeroed, map packet length to src_l4_port for ssh brute 
 * force
 *)
let dump_walts_csv (filename: string) : operator =
    let outc: out_channel ref = ref stdout in
    let first: bool ref = ref true in
    {
        next = (fun (tup: tuple) ->
            if !first then (
                outc := open_out filename ;
                first := false
            ) ;
            fprintf !outc "%s,%s,%s,%s,%s,%s,%s\n"
                (Tuple.find "src_ip" tup |> string_of_op_result)
                (Tuple.find "dst_ip" tup |> string_of_op_result)
                (Tuple.find "src_l4_port" tup |> string_of_op_result)
                (Tuple.find "dst_l4_port" tup |> string_of_op_result)
                (Tuple.find "packet_count" tup |> string_of_op_result)
                (Tuple.find "byte_count" tup |> string_of_op_result)
                (Tuple.find "epoch_id" tup |> string_of_op_result)
        );
        reset = fun _ -> ();
    }
    
(* input is either "0" or and IPv4 address in string format,
returns corresponding op_result *)
let get_ip_or_zero (input: string) : op_result =
    match input with 
        | "0" -> Int 0
        | catchall -> IPv4 (Ipaddr.V4.of_string_exn catchall)

(*
 * Reads an intermediate result CSV in Walt's canonical format
 * Injects epoch ids and incomming tuple counts into reset call
 *)
(* TODO: read files in RR order... 
    otherwise the whole file gets cached in joins *)
(* reads multiple CSV files, extracts their network flow data, processes it into
tuples, and applies ops on the extracted data *)
let read_walts_csv ?(epoch_id_key="eid") (file_names: string list) 
        (ops: operator list) : unit =
    (* open each CSV file, for scanning, create list of triples: 
        (input_channel (open file), epoch_id, tuples_count)*)
    let inchs_eids_tupcount = List.map (fun (filename: string) -> 
            (Scanf.Scanning.open_in filename, ref 0, ref 0)) file_names in
    let running = ref (List.length ops) in
    while !running > 0 do (* loop while ops still active *)
        List.iter2 (fun ((in_ch: Scanf.Scanning.in_channel), (eid: int ref), 
                            (tup_count: int ref)) (op: operator) ->
            (* iterates over file inputs and operations together *)
            if !eid >= 0 then (* read one row at a time, parse it, and record
                                    the vals as pairs within the Tuple *)
            try Scanf.bscanf in_ch "%[0-9.],%[0-9.],%d,%d,%d,%d,%d\n"
                    (fun (src_ip: string) (dst_ip: string) (src_l4_port: int) 
                                (dst_l4_port: int) (packet_count: int) 
                                (byte_count: int) (epoch_id: int) ->
                        let p: tuple = Tuple.empty
                            |> Tuple.add "ipv4.src" (get_ip_or_zero src_ip)
                            |> Tuple.add "ipv4.dst" (get_ip_or_zero dst_ip)
                            |> Tuple.add "l4.sport" (Int src_l4_port)
                            |> Tuple.add "l4.dport" (Int dst_l4_port)
                            |> Tuple.add "packet_count" (Int packet_count)
                            |> Tuple.add "byte_count" (Int byte_count)
                            |> Tuple.add epoch_id_key (Int epoch_id)
                        in
                            incr tup_count ;
                            if epoch_id > !eid
                            then (
                                while epoch_id > !eid do
                                    op.reset (Tuple.add "tuples" (Int !tup_count) 
                                    (Tuple.singleton epoch_id_key (Int !eid))) ;
                                    tup_count := 0 ;
                                    incr eid
                                done
                            ) ;
                            op.next (Tuple.add "tuples" (Int !tup_count) p)
                    )
            with
                | Scanf.Scan_failure s -> (printf "Failed to scan: %s\n" s ; 
                                            raise (Failure "Scan failure"))
                | End_of_file -> (
                    op.reset (Tuple.add "tuples" (Int !tup_count) 
                    (Tuple.singleton epoch_id_key (Int (!eid + 1)))) ;
                    running := !running - 1 ;
                    eid := -1
                )
        ) inchs_eids_tupcount ops
    done ;
    printf "Done.\n"

(*
 * Write the number of tuples passing through this operator each epoch
 * to the out_channel
 *)
(* tracks how many tuples processed per epoch and logs it to outc *)
let create_meta_meter ?(static_field: string option = None) (name: string) 
            (outc: out_channel) (next_op: operator): operator =
    let epoch_count: int ref = ref 0 in (* # of times reset has been called *)
    let tups_count: int ref = ref 0 in (* # of tuples processed before reset *)
    {
        next = (fun (tup: tuple) -> incr tups_count ; next_op.next tup);
        reset = (fun (tup: tuple) ->
            fprintf outc "%d,%s,%d,%s\n" !epoch_count name !tups_count
                (match static_field with
                    | Some v -> v
                    | None -> "" );
            tups_count := 0;
            incr epoch_count;
            next_op.reset tup
        );
    }

(*
 * Passes tuples through to op
 * Resets op every w seconds
 * Adds epoch id to tuple under key_out
 *)
let create_epoch_operator (epoch_width: float) (key_out: string) 
            (next_op: operator) : operator =
    let epoch_boundary: float ref = ref 0.0 in
    let eid: int ref = ref 0 in
    {
        next = (fun (tup: tuple) ->
            let time: float = float_of_op_result (Tuple.find "time" tup) in
            if !epoch_boundary = 0.0 (* start of epoch *)
            then epoch_boundary := time +. epoch_width
            else if time >= !epoch_boundary
            then ( (* within an epoch, have to calculate which one *)
                while time >= !epoch_boundary do
                    next_op.reset (Tuple.singleton key_out (Int !eid)) ;
                    epoch_boundary := !epoch_boundary +. epoch_width ;
                    incr eid
                done
            ) ;
            next_op.next (Tuple.add key_out (Int !eid) tup)
        ) ;
        reset = fun _ -> ( (* resets the last epoch ID *)
            next_op.reset (Tuple.singleton key_out (Int !eid)) ;
            epoch_boundary := 0.0 ;
            eid := 0
        ) ;
    }

(*
 * Passes only tuples where f applied to the tuple returns true
 *)
(* creates a filtering opterator, applying the given operator if this one 
    returns true otherwise returning false *)
let create_filter_operator (f: (tuple -> bool)) 
        (next_op: operator) : operator =
    {
        next = (fun (tup: tuple) -> if f tup then next_op.next tup ) ;
        reset = (fun (tup: tuple) -> next_op.reset tup) ;
    }

(*
 * (filter utility)
 * comparison function for testing int values against a threshold
 *)
let key_geq_int (key: string) (threshold: int) (tup: tuple) : bool =
    (* tests an op_result val against a given threshold *)
    (int_of_op_result (Tuple.find key tup)) >= threshold

(*
 * (filter utility)
 * Looks up the given key and converts to Int op_result
 * if the key does not hold an int, this will raise an exception
 *)
let get_mapped_int (key: string) (tup: tuple) : int =
    int_of_op_result (Tuple.find key tup)

(*
 * (filter utility)
 * Looks up the given key and converts to Float op_result 
 * if the key does not hold an int, this will raise an exception
 *)
let get_mapped_float (key: string) (tup: tuple) : float =
    float_of_op_result (Tuple.find key tup)

(*
 * Operator which applied the given function on all tuples
 * Passes resets, unchanged
 *)
 (* applies the given operator to the result of this operator applied to the 
 Tuple *)
let create_map_operator (f: (tuple) -> (tuple)) (next_op: operator) : operator =
    {
        next = (fun (tup: tuple) -> next_op.next (f tup)) ;
        reset = (fun (tup: tuple) -> next_op.reset tup) ;
    }

type grouping_func = (tuple) -> (tuple)
type reduction_func = op_result -> (tuple) -> op_result

(*
 * Groups the input Tuples according to canonic members returned by
 *   key_extractor : Tuple -> Tuple
 * Tuples in each group are folded (starting with Empty) by
 *   accumulate : op_result -> Tuple -> op_result
 * When reset, op is passed a Tuple for each group containing the union of
 *   (i) the reset argument tuple,
 *   (ii) the result of g for that group, and
 *   (iii) a mapping from out_key to the result of the fold for that group
 *)
let create_groupby_operator (groupby: grouping_func) (reduce: reduction_func) 
                (out_key: string) (next_op: operator) : operator =
    let h_tbl: ((tuple, op_result) Hashtbl.t) = 
                Hashtbl.create init_table_size in
    let reset_counter: int ref = ref 0 in
    {
        next = (fun (tup: tuple) ->
            (*grouping_key is sub-Tuple of original extracted by key_extractor*)
            let grouping_key: tuple = groupby tup in
            (* if the Tuple key is already in the hash table, its existing value
            and the new values are grouped via the grouping mech else the new 
            values are grouped with Empty via the grouping mech *)
            match Hashtbl.find_opt h_tbl grouping_key with
                | Some val_ -> Hashtbl.replace h_tbl grouping_key 
                                    (reduce val_ tup)
                | None -> Hashtbl.add h_tbl grouping_key 
                            (reduce Empty tup)
        ) ;
        reset = (fun (tup: tuple) ->
            (* track the counter reset *)
            reset_counter := !reset_counter + 1 ;
            Hashtbl.iter (fun (grouping_key: tuple) 
                                    (val_: op_result) -> 
                (* iterate over hashtable, !!! MORE info needed to figure this out *)
                let unioned_tup: tuple = 
                        Tuple.union (fun _ a _ -> Some a) tup grouping_key in
                next_op.next (Tuple.add out_key val_ unioned_tup)
            ) h_tbl ;
            next_op.reset tup ; (* reset the next operator in line and clear the 
                                hash table *)
            Hashtbl.clear h_tbl
        ) ;
    }


(*
 * (groupby utility : key_extractor)
 * Returns a new tuple with only the keys included in the incl_keys list
 *)
let filter_groups (incl_keys: string list) (tup: tuple) 
                : tuple =
    Tuple.filter (fun key_ _ -> List.mem key_ incl_keys) tup

(*
 * (groupby utility : key_extractor)
 * Grouping function (key_extractor) that forms a single group
 *)
let single_group (_: tuple) : tuple = Tuple.empty

(*
 * (groupby utility : grouping_mech)
 * Reduction function (f) to count tuples
 *)
let counter (val_: op_result) (_: tuple) : op_result =
    match val_ with
        | Empty -> Int 1
        | Int i -> Int (i+1)
        | _ -> val_

(*
 * (groupby utility)
 * Reduction function (f) to sum values (assumed to be Int ()) of a given field
 *)
let sum_ints (search_key: string) (init_val: op_result) 
                (tup: tuple) : op_result =
    match init_val with
        | Empty -> Int 0 (* empty init val, need to init the val to 0 *)
        | Int i -> ( (* actual int val, find the given search key *)
            match Tuple.find_opt search_key tup with
                | Some (Int n) -> Int (n + i) (* set its val to the sum of the 
                the given and current value if found else report failure *)
                | _ -> raise ( Failure (sprintf 
                               "'sum_vals' function failed to find integer 
                               value mapped to \"%s\"" 
                               search_key)
                             )
        )
        | _ -> init_val

(*
 * Returns a list of distinct elements (as determined by group_tup) each epoch
 * removes duplicate Tuples based on group_tup
 *)
let create_distinct_operator (groupby: grouping_func) 
        (next_op: operator) : operator =
    let h_tbl: (tuple, bool) Hashtbl.t = Hashtbl.create 
                                                    init_table_size in
    let reset_counter: int ref = ref 0 in
    {
        next = (fun (tup: tuple) ->
            let grouping_key: tuple = groupby tup in
            Hashtbl.replace h_tbl grouping_key true
        ) ;
        reset = (fun (tup: tuple) ->
            reset_counter := !reset_counter + 1 ;
            Hashtbl.iter (fun (key_: tuple) _ ->
                let merged_tup: tuple = Tuple.union (fun _ a _ -> Some a) tup key_ in
                next_op.next merged_tup
            ) h_tbl ;
            next_op.reset tup ;
            Hashtbl.clear h_tbl
        ) ;
    }

(*
 * Just sends both next and reset directly to two different downstream operators
 * i.e. splits the stream processing in two
 *)
let create_split_operator (l: operator) (r: operator) : operator =
    {
        next = (fun (tup: tuple) -> 
            (l.next tup ; r.next tup)) ;
        reset = (fun (tup: tuple) -> 
            (l.reset tup ; r.reset tup)) ;
    }

type key_extractor = tuple -> (tuple * tuple)

(*
 * Initial shot at a join semantic that doesn't require maintining entire state
 * Functions left and right transform input tuples into a key,value pair of tuples
 * The key determines a canonical tuple against which the other stream will match
 * The value determines extra fields which should be saved and added when a match is made
 *
 * Requires tuples to have epoch id as int value in field referenced by eid_key.
 *)
let create_join_operator ?(eid_key: string="eid") 
            (left_extractor : key_extractor) 
            (right_extractor : key_extractor) (next_op: operator) 
            : (operator*operator) =
    let (h_tbl1: (tuple, tuple) Hashtbl.t) = Hashtbl.create init_table_size in
    let (h_tbl2: (tuple, tuple) Hashtbl.t) = Hashtbl.create init_table_size in
    let left_curr_epoch: int ref = ref 0 in
    let right_curr_epoch: int ref = ref 0 in
    let handle_join_side (curr_h_tble: (tuple, tuple) Hashtbl.t) 
            (other_h_tbl: (tuple, tuple) Hashtbl.t) 
            (curr_epoch_ref: int ref) (other_epoch_ref: int ref) 
            (f: key_extractor) : operator =
        {
            next = (fun (tup: tuple) ->
                (* extract the grouping key and remaining values, extract event 
                ID from input tup *)
                let (key: tuple), (vals_: tuple) = f tup in
                let curr_epoch: int = get_mapped_int eid_key tup in

                while curr_epoch > !curr_epoch_ref do
                    if !other_epoch_ref > !curr_epoch_ref 
                    then next_op.reset (Tuple.singleton eid_key 
                            (Int !curr_epoch_ref)) ;
                    curr_epoch_ref := !curr_epoch_ref + 1
                done ;
                let new_tup: tuple = Tuple.add eid_key (Int curr_epoch) key in
                match Hashtbl.find_opt other_h_tbl new_tup with
                    | Some (val_: tuple) -> (
                        let use_left = fun _ a _ -> Some a in
                        Hashtbl.remove other_h_tbl new_tup ;
                        next_op.next (Tuple.union use_left new_tup 
                                    (Tuple.union use_left vals_ val_)) ;
                    )
                    | None -> (
                        Hashtbl.add curr_h_tble new_tup vals_ ;
                    )
            ) ;
            reset = (fun (tup: tuple) -> 
                let curr_epoch: int = get_mapped_int eid_key tup in
                while curr_epoch > !curr_epoch_ref do
                    if !other_epoch_ref > !curr_epoch_ref 
                    then next_op.reset 
                            (Tuple.singleton eid_key (Int !curr_epoch_ref)) ;
                    curr_epoch_ref := !curr_epoch_ref + 1
                done
            ) ;
        }
    in ( handle_join_side 
            h_tbl1 h_tbl2 left_curr_epoch right_curr_epoch left_extractor, 
         handle_join_side 
            h_tbl2 h_tbl1 right_curr_epoch left_curr_epoch right_extractor )


(*
 * (join utility)
 * Returns a new tuple with only the keys included in the first of each pair in 
 * keys
 * These keys are renamed to the second of each pair in keys
 * Use in conjunction with the join implementation above to get the "join left 
 * with right on left.x = right.y" kind of thing
 *)
let rename_filtered_keys (renamings_pairs: (string * string) list) 
            (in_tup: tuple) : tuple =
    List.fold_left (fun (new_tup: tuple) 
                        ((old_key: string), (new_key: string)) ->
        match Tuple.find_opt old_key in_tup with
            | Some (val_: op_result) -> Tuple.add new_key val_ new_tup
            | None -> new_tup
    ) Tuple.empty renamings_pairs