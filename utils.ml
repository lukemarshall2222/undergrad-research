(*
 * Common utilities 
 *
 * Includes minimal parsing of header fields into a map from strings to values
 *)

open Printf

(*
 * Operators act on named "tuples" which are maps from strings to op_result types
 **************************************************************************************)

type op_result =  (* variant type *)
    | Float of float (* tag for floating point vals *)
    | Int of int    (* tag for int vals *)
    | IPv4 of Ipaddr.V4.t (* tag for IPv4 address *)
    | MAC of Bytes.t  (* tag for a MAC address *)
    | Empty (* tag for empty/missing val, possibly end of something *)

module Tuple = Map.Make(String) (* makes new module, Tuple, which is a map 
                                    keyed with strings *)
type tuple = op_result Tuple.t (* defines tuple as a map from strings to 
                                    op_results *)

(* defines a data processing unit in a stream processing pipeline; 
    cntains two functions *)
type operator = { (* record type *)
    next : tuple -> unit ; (* takes in Map<string, op_result>, 
                processes it in some way, most likely a side effect  *)
    reset: tuple -> unit ; (* takes same thing, performs a reset op on it after
                                processing *)
}

type op_creator = operator -> operator
type dbl_op_creator = operator -> (operator * operator)

(*
 * Right associative "chaining" operator
 * for passing output of one operator to the next under cps-style operator constructors
 *)
let ( @=> ) (op_creator_func: op_creator) (next_op: operator) 
        : operator 
    = op_creator_func next_op
(* e.g. 
    (epoch 1.0 "eid") @=> (groupby single_group count "pkts") @=> k 
instead of: 
    k (groupby single_group count "pkts" (epoch 1.0 "eid")) *)

let ( @==> ) (op_creator_func: dbl_op_creator) (op: operator) : 
            (operator * operator) = op_creator_func op



(*
 * Conversion utilities
 **************************************************************************************)

(* formats the 6 bytes of the MAC address as a colon-separated string in hex *)
let string_of_mac (buf: Bytes.t) : string =
    let byte_at index: int = Bytes.get_uint8 buf index in
    sprintf "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x"
            (byte_at 0) 
            (byte_at 1) 
            (byte_at 2) 
            (byte_at 3) 
            (byte_at 4) 
            (byte_at 5)

(* converts TCP flags into a human-readable string representation by matching
flags to formatted output *)
let tcp_flags_to_strings (flags: int) : string =
    (* local module TCPFlagsMap allows storing and retrieving TCP flag names 
    and their bit operations easy *)
    let module TCPFlagsMap = Map.Make(String) in
    let tcp_flags_map =
        TCPFlagsMap.of_seq (List.to_seq [
            ("FIN", 1 lsl 0);
            ("SYN", 1 lsl 1);
            ("RST", 1 lsl 2);
            ("PSH", 1 lsl 3);
            ("ACK", 1 lsl 4);
            ("URG", 1 lsl 5);
            ("ECE", 1 lsl 6);
            ("CWR", 1 lsl 7);
    ]) in TCPFlagsMap.(
        fold (fun (key: string) (_val: int) (acc: string) -> 
            if acc = "" 
            then key 
            else acc ^ "|" ^ key) 
        (filter (fun (_key: string) (value: int) -> 
            flags land value = value) tcp_flags_map) "")

(* checks if input is an Int op_result, raises exception otherwise *)
let int_of_op_result (input: op_result) : int = 
    match input with
    | Int i -> i
    | _ -> raise (Failure "Trying to extract int from non-int result")

(* checks if input is an Float op_result, raises exception otherwise *)
let float_of_op_result (input: op_result) : float = 
    match input with
    | Float f -> f
    | _ -> raise (Failure "Trying to exctract float from non-float result")

(* returns the human-readable version of each op_result value *)
let string_of_op_result (input: op_result) : string = 
    match input with
    | Float f -> sprintf "%f" f
    | Int i -> string_of_int i
    | IPv4 a -> Ipaddr.V4.to_string a
    | MAC m -> string_of_mac m
    | Empty -> "Empty"

(* outputs the tuple in a human-readble form e.g. 
    "ipv4.src" => 192.168.1.1, "packet_count" => 10, *)
let string_of_tuple (input_tuple : tuple) : string =
    Tuple.fold (fun (key: string) (_val: op_result) (acc: string) ->
        acc ^ (sprintf "\"%s\" => %s, " key (string_of_op_result _val))
    ) input_tuple ""

(* creates a Tuple (Map<string, op_result>) out of a list of tuples *)
let tuple_of_list (tup_list : (string * op_result) list) : tuple =
    Tuple.of_seq (List.to_seq tup_list)

(* prints formatted representation of a Tuple *)
let dump_tuple (outc: out_channel) (tup: tuple) : unit =
    fprintf outc "%s\n" (string_of_tuple tup)


(* retrieves the int value of the op_result associated with a given key 
    in the given Tuple (Map<string, op_result>) *)
let lookup_int (key: string) (tup: tuple) : int =
    int_of_op_result (Tuple.find key tup)

(* retrieves the float value of the op_result associated with a given key 
    in the given Tuple (Map<string, op_result>) *)
let lookup_float (key: string) (tup: tuple) : float =
    float_of_op_result (Tuple.find key tup)
