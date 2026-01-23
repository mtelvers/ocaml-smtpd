(** DNS Client for EIO *)

type t = {
  do_query : Cstruct.t -> Cstruct.t -> int;
  timeout : float;
  mutable next_id : int;
}

let parse_resolv_conf () =
  try
    let ic = open_in "/etc/resolv.conf" in
    let rec find_nameserver () =
      match input_line ic with
      | line ->
        let line = String.trim line in
        if String.length line > 0 && line.[0] <> '#' then
          let parts = String.split_on_char ' ' line in
          let parts = List.filter (fun s -> String.length s > 0) parts in
          match parts with
          | "nameserver" :: ip :: _ ->
            close_in ic;
            Some ip
          | _ -> find_nameserver ()
        else
          find_nameserver ()
      | exception End_of_file ->
        close_in ic;
        None
    in
    find_nameserver ()
  with _ -> None

let ip_string_to_eio_addr ip_str =
  match String.split_on_char '.' ip_str with
  | [a; b; c; d] ->
    (try
       let a = int_of_string a and b = int_of_string b
       and c = int_of_string c and d = int_of_string d in
       let bytes = Bytes.create 4 in
       Bytes.set bytes 0 (Char.chr a);
       Bytes.set bytes 1 (Char.chr b);
       Bytes.set bytes 2 (Char.chr c);
       Bytes.set bytes 3 (Char.chr d);
       Some (Eio.Net.Ipaddr.of_raw (Bytes.to_string bytes))
     with _ -> None)
  | _ -> None

let google_dns () =
  let bytes = Bytes.create 4 in
  Bytes.set bytes 0 (Char.chr 8);
  Bytes.set bytes 1 (Char.chr 8);
  Bytes.set bytes 2 (Char.chr 8);
  Bytes.set bytes 3 (Char.chr 8);
  `Udp (Eio.Net.Ipaddr.of_raw (Bytes.to_string bytes), 53)

let create ~net ?nameserver ?(timeout = 5.0) () =
  let nameserver = match nameserver with
    | Some ns -> ns
    | None -> google_dns ()
  in
  let do_query query_buf response_buf =
    (* Create socket, send query, receive response, all in one switch scope *)
    Eio.Switch.run @@ fun sw ->
    let socket = Eio.Net.datagram_socket ~sw net nameserver in
    Eio.Net.send socket ~dst:nameserver [query_buf];
    let _addr, len = Eio.Net.recv socket response_buf in
    len
  in
  { do_query; timeout; next_id = 1 }

let create_from_resolv_conf ~net ?timeout () =
  let nameserver =
    match parse_resolv_conf () with
    | Some ip_str ->
      (match ip_string_to_eio_addr ip_str with
       | Some addr -> `Udp (addr, 53)
       | None -> google_dns ())
    | None -> google_dns ()
  in
  create ~net ~nameserver ?timeout ()

let get_next_id t =
  let id = t.next_id in
  t.next_id <- (t.next_id + 1) land 0xFFFF;
  id

let query : type a. t -> [ `host ] Domain_name.t -> a Dns.Rr_map.key -> (a, [> `Msg of string]) result =
  fun t name rr_type ->
  let id = get_next_id t in
  let flags = Dns.Packet.Flags.singleton `Recursion_desired in
  let question = Dns.Packet.Question.create name rr_type in
  let header = (id, flags) in
  let packet = Dns.Packet.create header question `Query in
  let query_str, _ = Dns.Packet.encode `Udp packet in
  let query_buf = Cstruct.of_string query_str in
  let response_buf = Cstruct.create 4096 in
  let len = t.do_query query_buf response_buf in
  let response_str = Cstruct.to_string (Cstruct.sub response_buf 0 len) in
  match Dns.Packet.decode response_str with
  | Error e ->
    Error (`Msg (Fmt.str "Failed to decode DNS response: %a" Dns.Packet.pp_err e))
  | Ok response ->
    let (resp_id, _) = response.Dns.Packet.header in
    if resp_id <> id then
      Error (`Msg "DNS response ID mismatch")
    else
      let data = response.Dns.Packet.data in
      match data with
      | `Answer (answer, _authority) ->
        (match Domain_name.Map.find_opt (Domain_name.raw name) answer with
         | None -> Error (`Msg "No answer in DNS response")
         | Some rr_map ->
           match Dns.Rr_map.find rr_type rr_map with
           | None -> Error (`Msg "Record type not found in answer")
           | Some rdata -> Ok rdata)
      | `Rcode_error (rcode, _, _) ->
        Error (`Msg (Fmt.str "DNS error: %a" Dns.Rcode.pp rcode))
      | _ ->
        Error (`Msg "Unexpected DNS response type")

let lookup_a t hostname =
  match Domain_name.of_string hostname with
  | Error (`Msg msg) -> Error (`Msg ("Invalid hostname: " ^ msg))
  | Ok name ->
    match Domain_name.host name with
    | Error (`Msg msg) -> Error (`Msg ("Invalid hostname: " ^ msg))
    | Ok host_name ->
      match query t host_name Dns.Rr_map.A with
      | Error _ as e -> e
      | Ok (_, addrs) -> Ok (Ipaddr.V4.Set.elements addrs)

let lookup_aaaa t hostname =
  match Domain_name.of_string hostname with
  | Error (`Msg msg) -> Error (`Msg ("Invalid hostname: " ^ msg))
  | Ok name ->
    match Domain_name.host name with
    | Error (`Msg msg) -> Error (`Msg ("Invalid hostname: " ^ msg))
    | Ok host_name ->
      match query t host_name Dns.Rr_map.Aaaa with
      | Error _ as e -> e
      | Ok (_, addrs) -> Ok (Ipaddr.V6.Set.elements addrs)

let lookup_mx t hostname =
  match Domain_name.of_string hostname with
  | Error (`Msg msg) -> Error (`Msg ("Invalid hostname: " ^ msg))
  | Ok name ->
    match Domain_name.host name with
    | Error (`Msg msg) -> Error (`Msg ("Invalid hostname: " ^ msg))
    | Ok host_name ->
      match query t host_name Dns.Rr_map.Mx with
      | Error _ as e -> e
      | Ok (_, mx_set) ->
        let mx_list = Dns.Rr_map.Mx_set.elements mx_set in
        let sorted = List.sort (fun (a : Dns.Mx.t) (b : Dns.Mx.t) ->
          compare a.preference b.preference
        ) mx_list in
        Ok (List.map (fun (mx : Dns.Mx.t) ->
          (mx.preference, Domain_name.to_string mx.mail_exchange)
        ) sorted)

let lookup_txt t hostname =
  match Domain_name.of_string hostname with
  | Error (`Msg msg) -> Error (`Msg ("Invalid hostname: " ^ msg))
  | Ok name ->
    match Domain_name.host name with
    | Error (`Msg msg) -> Error (`Msg ("Invalid hostname: " ^ msg))
    | Ok host_name ->
      match query t host_name Dns.Rr_map.Txt with
      | Error _ as e -> e
      | Ok (_, txt_set) ->
        let txt_list = Dns.Rr_map.Txt_set.elements txt_set in
        Ok txt_list

let lookup_ptr t ip =
  let ptr_name = match ip with
    | Ipaddr.V4 v4 ->
      let octets = Ipaddr.V4.to_octets v4 in
      let a = Char.code octets.[0] in
      let b = Char.code octets.[1] in
      let c = Char.code octets.[2] in
      let d = Char.code octets.[3] in
      Printf.sprintf "%d.%d.%d.%d.in-addr.arpa" d c b a
    | Ipaddr.V6 v6 ->
      let hex = Ipaddr.V6.to_octets v6 in
      let nibbles = Buffer.create 64 in
      for i = 15 downto 0 do
        let byte = Char.code hex.[i] in
        Buffer.add_string nibbles (Printf.sprintf "%x.%x." (byte land 0xf) (byte lsr 4))
      done;
      Buffer.add_string nibbles "ip6.arpa";
      Buffer.contents nibbles
  in
  match Domain_name.of_string ptr_name with
  | Error (`Msg msg) -> Error (`Msg ("Invalid PTR name: " ^ msg))
  | Ok name ->
    match Domain_name.host name with
    | Error (`Msg msg) -> Error (`Msg ("Invalid PTR name: " ^ msg))
    | Ok host_name ->
      match query t host_name Dns.Rr_map.Ptr with
      | Error _ as e -> e
      | Ok (_, ptr_name) -> Ok (Domain_name.to_string ptr_name)
