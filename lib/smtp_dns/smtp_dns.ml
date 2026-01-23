(** SMTP DNS Resolver

    DNS lookups for SPF, DKIM, and DMARC verification.
    Uses the dns library with EIO for proper async DNS resolution.

    Note: dns_client_eio is not fiber-safe for concurrent queries,
    so we use a mutex to serialize access. *)

(** DNS lookup errors *)
type error =
  | Not_found
  | Timeout
  | Server_failure
  | Format_error of string

(** IP address type *)
type ip_addr =
  | IPv4 of int * int * int * int
  | IPv6 of string

(** DNS resolver type - wraps dns_client_eio with a mutex for fiber safety *)
type t = {
  resolver : Dns_client_eio.t;
  mutex : Eio.Mutex.t;
}

(** Create a new DNS resolver.
    @param net EIO network capability *)
let create ~net =
  {
    resolver = Dns_client_eio.create_from_resolv_conf ~net ();
    mutex = Eio.Mutex.create ();
  }

(** Convert IP address to string *)
let ip_to_string = function
  | IPv4 (a, b, c, d) -> Printf.sprintf "%d.%d.%d.%d" a b c d
  | IPv6 s -> s

(** Parse IPv4 address from string *)
let parse_ipv4 s =
  try
    match String.split_on_char '.' s with
    | [a; b; c; d] ->
      let a = int_of_string a and b = int_of_string b
      and c = int_of_string c and d = int_of_string d in
      if a >= 0 && a <= 255 && b >= 0 && b <= 255 &&
         c >= 0 && c <= 255 && d >= 0 && d <= 255 then
        Some (a, b, c, d)
      else None
    | _ -> None
  with _ -> None

(** Parse IPv6 address from string - simplified *)
let parse_ipv6 s =
  (* Very basic IPv6 validation - just check format *)
  let parts = String.split_on_char ':' s in
  if List.length parts >= 2 && List.length parts <= 8 then
    Some s
  else
    None

(** Parse IP address from string *)
let parse_ip s =
  match parse_ipv4 s with
  | Some (a, b, c, d) -> Some (IPv4 (a, b, c, d))
  | None ->
    match parse_ipv6 s with
    | Some s -> Some (IPv6 s)
    | None -> None

(** Convert Ipaddr.V4.t to our ip_addr *)
let ipv4_of_ipaddr v4 =
  let octets = Ipaddr.V4.to_octets v4 in
  IPv4 (Char.code octets.[0], Char.code octets.[1],
        Char.code octets.[2], Char.code octets.[3])

(** Convert Ipaddr.V6.t to our ip_addr *)
let ipv6_of_ipaddr v6 =
  IPv6 (Ipaddr.V6.to_string v6)

(** Convert our ip_addr to Ipaddr.t *)
let to_ipaddr = function
  | IPv4 (a, b, c, d) ->
    let bytes = Bytes.create 4 in
    Bytes.set bytes 0 (Char.chr a);
    Bytes.set bytes 1 (Char.chr b);
    Bytes.set bytes 2 (Char.chr c);
    Bytes.set bytes 3 (Char.chr d);
    Ipaddr.V4 (Ipaddr.V4.of_octets_exn (Bytes.to_string bytes))
  | IPv6 s ->
    match Ipaddr.V6.of_string s with
    | Ok v6 -> Ipaddr.V6 v6
    | Error _ -> Ipaddr.V4 Ipaddr.V4.localhost  (* Fallback *)

(** Look up TXT records for a domain.
    Returns list of TXT record strings. *)
let lookup_txt t domain =
  Eio.Mutex.use_rw ~protect:true t.mutex (fun () ->
    match Dns_client_eio.lookup_txt t.resolver domain with
    | Ok txt_list -> Ok txt_list
    | Error (`Msg msg) ->
      if String.length msg >= 8 && String.sub msg 0 8 = "DNS error" then
        Error Not_found
      else
        Error (Format_error msg))

(** Look up A records for a domain.
    Returns list of IPv4 addresses. *)
let lookup_a t domain =
  Eio.Mutex.use_rw ~protect:true t.mutex (fun () ->
    match Dns_client_eio.lookup_a t.resolver domain with
    | Ok addrs ->
      Ok (List.map ipv4_of_ipaddr addrs)
    | Error (`Msg msg) ->
      if String.length msg >= 8 && String.sub msg 0 8 = "DNS error" then
        Error Not_found
      else
        Error (Format_error msg))

(** Look up AAAA records for a domain.
    Returns list of IPv6 addresses. *)
let lookup_aaaa t domain =
  Eio.Mutex.use_rw ~protect:true t.mutex (fun () ->
    match Dns_client_eio.lookup_aaaa t.resolver domain with
    | Ok addrs ->
      Ok (List.map ipv6_of_ipaddr addrs)
    | Error (`Msg msg) ->
      if String.length msg >= 8 && String.sub msg 0 8 = "DNS error" then
        Error Not_found
      else
        Error (Format_error msg))

(** Look up MX records for a domain.
    Returns list of (preference, hostname) pairs sorted by preference. *)
let lookup_mx t domain =
  Eio.Mutex.use_rw ~protect:true t.mutex (fun () ->
    match Dns_client_eio.lookup_mx t.resolver domain with
    | Ok mx_list -> Ok mx_list
    | Error (`Msg msg) ->
      if String.length msg >= 8 && String.sub msg 0 8 = "DNS error" then
        Error Not_found
      else
        Error (Format_error msg))

(** Look up PTR record for an IP address (reverse DNS). *)
let lookup_ptr t ip =
  let ipaddr = to_ipaddr ip in
  Eio.Mutex.use_rw ~protect:true t.mutex (fun () ->
    match Dns_client_eio.lookup_ptr t.resolver ipaddr with
    | Ok ptr -> Ok ptr
    | Error (`Msg msg) ->
      if String.length msg >= 8 && String.sub msg 0 8 = "DNS error" then
        Error Not_found
      else
        Error (Format_error msg))

(** Check if an IPv4 address matches a CIDR network *)
let ipv4_in_network (a1, b1, c1, d1) (a2, b2, c2, d2) prefix_len =
  let ip1 = (a1 lsl 24) lor (b1 lsl 16) lor (c1 lsl 8) lor d1 in
  let ip2 = (a2 lsl 24) lor (b2 lsl 16) lor (c2 lsl 8) lor d2 in
  let mask = if prefix_len = 0 then 0 else (-1) lsl (32 - prefix_len) in
  (ip1 land mask) = (ip2 land mask)

(** Check if an IP address matches a CIDR network *)
let ip_in_network ip network prefix_len =
  match ip, network with
  | IPv4 (a1, b1, c1, d1), IPv4 (a2, b2, c2, d2) ->
    ipv4_in_network (a1, b1, c1, d1) (a2, b2, c2, d2) prefix_len
  | IPv6 ip1, IPv6 ip2 ->
    (* IPv6 CIDR matching using ipaddr library *)
    (match Ipaddr.V6.of_string ip1, Ipaddr.V6.of_string ip2 with
     | Ok v6_1, Ok v6_2 ->
       let prefix = Ipaddr.V6.Prefix.make prefix_len v6_2 in
       Ipaddr.V6.Prefix.mem v6_1 prefix
     | _ -> false)
  | _ -> false  (* IPv4/IPv6 mismatch *)

(** Check if IP matches a domain's A/AAAA records *)
let ip_matches_domain t ip domain =
  match ip with
  | IPv4 _ ->
    (match lookup_a t domain with
     | Ok addrs -> List.exists (fun a -> a = ip) addrs
     | Error _ -> false)
  | IPv6 _ ->
    (match lookup_aaaa t domain with
     | Ok addrs -> List.exists (fun a -> a = ip) addrs
     | Error _ -> false)
