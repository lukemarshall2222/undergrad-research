(*
 * Common utilities 
 *
 * Includes minimal parsing of header fields into a map from strings to values
 *)

open Printf
open Option

(*
 * Operators act on named "tuples" which are maps from strings to op_result types
 **************************************************************************************)

type op_result =  (* variant type *)
    | Float of float (* tag for floating point vals *)
    | Int of int    (* tag for int vals *)
    | IPv4 of Ipaddr.V4.t (* tag for IPv4 address *)
    | MAC of Cstruct.t  (* tag for a MAC address *)
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

(*
 * Right associative "chaining" operator
 * for passing output of one operator to the next under cps-style operator constructors
 *)
let ( @=> ) (o:operator->operator) (o':operator): operator = o o'
(* e.g. 
    (epoch 1.0 "eid") @=> (groupby single_group count "pkts") @=> k 
instead of: 
    k (groupby single_group count "pkts" (epoch 1.0 "eid")) *)
let ( @==> ) (o:operator->(operator*operator)) (o':operator) : 
            (operator * operator)= o o'



(*
 * Conversion utilities
 **************************************************************************************)

(* formats the 6 bytes of the MAC address as a colon-separated string in hex *)
let string_of_mac (buf: Cstruct.t) : string =
    let byte_at index: int = Cstruct.get_uint8 buf index in
    sprintf "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x"
        (byte_at 0) (byte_at 1) (byte_at 2) (byte_at 3) (byte_at 4) (byte_at 5)

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
    (* maps *)
    ]) in TCPFlagsMap.(
        fold (fun (key: string) (_val: int) (acc: string) -> 
            if acc = "" 
            then key 
            else acc ^ "|" ^ key) 
        (filter (fun (_key: string) (value: int) -> 
            flags land value = value) tcp_flags_map) "")

(* checks if input is an Int op_result, raises exception otherwise *)
let int_of_op_result (input: op_result) : int = match input with
    | Int i -> i
    | _ -> raise (Failure "Trying to extract int from non-int result")

(* checks if input is an Float op_result, raises exception otherwise *)
let float_of_op_result (input: op_result) : float = match input with
    | Float f -> f
    | _ -> raise (Failure "Trying to exctract float from non-float result")

(* returns the human-readable version of each op_result value *)
let string_of_op_result (input: op_result) : string = match input with
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

(*
 * Packet parsing utilities
 **************************************************************************************)
(* [%%cstruct] in ocaml is a PPX (preprocessor extension) for cstruct, a library 
in ocaml used for parsing and generating binary network packet structures 
efficiently *)
[%%cstruct (* defines C-like binary structure using cstruct PPX 
and automatically generates functions to read/write a given structure efficiently *)
type ethernet = { (* defines ethernet frame header, 14 bytes long and contain: *)
  dst: uint8_t [@len 6]; (* 6 bytes for destination MAC address *)
  src: uint8_t [@len 6]; (* 6 bytes for sourse MAC address *)
  ethertype: uint16_t; (* 2 bytes for protocol tyep e.g. IPv4, ARP *)
} [@@big_endian]]

(* [@len 6] specifies a fixed-length array (in this case 6 bytes)
   [@@big_endian] specifies the multi-byte values (uint16_t) use big-endien 
   order, as in network protocols *)

(* auto-generated functions for ethernet:
    val sizeof_ethernet : int
    val get_ethernet_dst : Cstruct.t -> Cstruct.t
    val get_ethernet_src : Cstruct.t -> Cstruct.t
    val get_ethernet_ethertype : Cstruct.t -> int
    val set_ethernet_dst : Cstruct.t -> Cstruct.t -> unit
    val set_ethernet_src : Cstruct.t -> Cstruct.t -> unit
    val set_ethernet_ethertype : Cstruct.t -> int -> unit
*)

[%%cstruct
type ipv4 = { (* defines an ipv4 header *)
  hlen_version: uint8_t; (* represents IP version and 
                            header length for variable header*)
  tos: uint8_t; (* type of service, settings *)
  len: uint16_t; (* total packet length header + payload *)
  id: uint16_t; (* packet identifier used for fragmentation *)
  off: uint16_t; (* fragmentation offset and flags *)
  ttl: uint8_t; (* time-to-live max hops befor epacket discarded *)
  proto: uint8_t; (* potocol type e.g. TCP-6, UDP-17*)
  csum: uint16_t; (* header checksum verifies header integrity *)
  src: uint32_t; (* source IP address *)
  dst: uint32_t; (* destination IP address *)
} [@@big_endian]]
(* models the IPv4 packet header, main control information for IP packets in 
   network transmission, and includes:
    who is sending and receiving the packet
    how large the packet is
    how to handle fragmantation
    which protocol is encapsulated 
    how long a packet can live *)

[%%cstruct
type tcp = { (* defines TCP (transmission control protocol) header and allows 
                for parsing and constructing raw TCP packet headers in ocaml *)
  src_port: uint16_t; (* source port, port # of sender *)
  dst_port: uint16_t; (* destination port, port # of receiver *)
  seqnum: uint32_t; (* sequence number, used to track order of data packets *)
  acknum: uint32_t; (* acknowledgement number, confirms received packets *)
  offset_flags: uint16_t; (* data offset + reserved + blags bits *)
  window: uint16_t; (* window size, flow control mech for data transmission *)
  checksum: uint16_t; (* herder checksum, verifies integrity of TCP header 
                        and payload *)
  urg: uint16_t;    (* urgent pointer, used with the URG flag to indicate 
                            urgent data *)
} [@@big_endian]]
(* struct models and TCP segment header, which includes:
        port addressing to id apps
        reliable data delivery using ackowledgements 
        flwo control to prevent congestion
        error checking *)

[%%cstruct
type udp = { (* defines a UDP (user datagram protocol) header *)
    src_port: uint16_t; (* sourse port, port # of sender *)
    dst_port: uint16_t; (* dest port, port # of receiver *)
    length: uint16_t; (* total length of the UDP segment (header+payload) *)
    checksum: uint16_t; (* cehcksum for error detection *)
} [@@big_endian]]
(* struct models a UDP datagram header, which includes:
    port addressing to id apps
    packet size info
    basic integrity checking *)

(* adds the given parsed ethernet struct to the given Tuple *)
let parse_ethernet (eth_struct: Cstruct.t) (tup: tuple) : tuple =
    tup |> (* each of the fields is added to the Tuple with the struct and field 
    names as the keys and the values in the header as op_result tagged variant 
    type values *)
    (Tuple.add "eth.src" (MAC (get_ethernet_src eth_struct))) |>
    (Tuple.add "eth.dst" (MAC (get_ethernet_dst eth_struct))) |>
    (Tuple.add "eth.ethertype" (Int (get_ethernet_ethertype eth_struct)))


(* adds the given parsed ipv4 struct to the given Tuple *)
let parse_ipv4 (ipv4_struct: Cstruct.t) (tup: tuple) : 
        tuple = 
    tup |>
    (Tuple.add "ipv4.hlen" (Int ((get_ipv4_hlen_version ipv4_struct) land 0xF))) |>
    (Tuple.add "ipv4.proto" (Int (get_ipv4_proto ipv4_struct))) |>
    (Tuple.add "ipv4.len" (Int (get_ipv4_len ipv4_struct))) |>
    (Tuple.add "ipv4.src" (IPv4 (Ipaddr.V4.of_int32 (get_ipv4_src ipv4_struct)))) |>
    (Tuple.add "ipv4.dst" (IPv4 (Ipaddr.V4.of_int32 (get_ipv4_dst ipv4_struct))))


(* adds the given parsed tcp struct to the given Tuple *)
let parse_tcp (tcp_struct: Cstruct.t) (tup: tuple) = 
    tup |>
    (Tuple.add "l4.sport" (Int (get_tcp_src_port tcp_struct))) |>
    (Tuple.add "l4.dport" (Int (get_tcp_dst_port tcp_struct))) |>
    (Tuple.add "l4.flags" (Int ((get_tcp_offset_flags tcp_struct) land 0xFF)))


(* adds the given parsed udp struct to the given Tuple *)
let parse_udp (udp_struct) (tup: tuple) : tuple =
    tup |>
    (Tuple.add "l4.sport" (Int (get_udp_src_port udp_struct))) |>
    (Tuple.add "l4.dport" (Int (get_udp_dst_port udp_struct))) |>
    (Tuple.add "l4.flags" (Int 0))

let set_default_l4_fields (tup: tuple) : tuple =
    tup |>
    (Tuple.add "l4.sport" (Int 0)) |>
    (Tuple.add "l4.dport" (Int 0)) |>
    (Tuple.add "l4.flags" (Int 0))

(* reads one bye at position offset from the buffer eth *)
let get_ip_version (eth: Cstruct.t) (offset: int) : int = 
    ((Cstruct.get_uint8 eth offset) land 0xF0) lsr 4


(* parses a network packet from a PCAP file, and extracts:
    Timestamp
    Ethernet header if available
    IP header
    Transport-layer protocol
and returns a Tuple containg the parsed fields or None if parsing fails 
Args:
    network: identifies PCAP link-layer type
    *)
(* NOTE: i dont think I got the params right *)
let parse_pkt (network: int) (pcap_header) (metadata: Cstruct.t) 
    (payload: Cstruct.t) : 'a t = 
    let empty_tup: tuple = Tuple.empty in

    (* extract packet timestamp from pcap metadata and add to Tuple:  *)
    let module H = (val pcap_header: Pcap.HDR) in
    let time: float = (Int32.to_float (H.get_pcap_packet_ts_sec metadata))
            +. (Int32.to_float (H.get_pcap_packet_ts_usec metadata)) 
            /. 1000000. in
    let time_metadata: tuple = Tuple.add "time" (Float time) empty_tup in

    (* parse ethernet header if available: *)
    let (packet_metadata: tuple), (offset: int) = (
        match network with
            | 1   -> (* ethernet header: *)
                     ((parse_ethernet payload time_metadata), sizeof_ethernet)
            | 101 -> (* raw IP packets *)
                     (time_metadata, 0)
            | x   -> failwith (sprintf "Unknown pcap network value: %d" x)
    ) in

    (* parse IP header: *)
    try
        let (network_metadata: tuple), (offset: int) = (
            match get_ip_version payload offset with
            | 4 -> (* check that version is 4 *)
                    let res: tuple = parse_ipv4 
                        (Cstruct.shift payload offset) packet_metadata in
                    (res, offset + ((int_of_op_result 
                                        (Tuple.find "ipv4.hlen" res)) * 4))
            | _ -> raise (Invalid_argument "")
        ) in
        let transport_metadata: tuple = (
            match int_of_op_result (Tuple.find "ipv4.proto" network_metadata) 
            with
            | 6  -> (* tcp protocol code *)
                    parse_tcp (Cstruct.shift payload offset) network_metadata
            | 17 -> (* udp protocol code *)
                    parse_udp (Cstruct.shift payload offset) network_metadata
            | _  -> set_default_l4_fields network_metadata
            (* | _ -> raise (Invalid_argument "") *)
        ) in
            Some transport_metadata
    with
        Invalid_argument _ -> None
            (* ...some packets in CAIDA traces are not as big as we expect 
                which causes Cstruct to throw this: just ignore for now *)


(*
 * File handling utilities
 **************************************************************************************)

(* opens the given file and memory maps its contents into a struct buffer *)
let open_file (filename: string) : Cstruct.t =
    let fd = Unix.(openfile filename [O_RDONLY] 0) in
    let ba = Bigarray.(array1_of_genarray 
                        (Mmap.V1.map_file 
                                    fd Bigarray.char c_layout false [|-1|])) in
    Cstruct.of_bigarray ba

let read_header (filename: string) =
    let buf: Cstruct.t = open_file filename in
    match Pcap.detect buf with
    | Some h -> h, buf
    | None -> failwith (sprintf "Failed to parse pcap header from %s" filename)


