(** DNS Client for EIO

    DNS resolver using EIO for asynchronous networking.
    Sends UDP queries to a configured nameserver and supports
    A, AAAA, MX, TXT, and PTR record lookups. *)

(** DNS client state *)
type t

(** Create a DNS client.

    @param nameserver IP address and port of DNS server (default: 8.8.8.8:53)
    @param timeout Query timeout in seconds (default: 5.0) *)
val create :
  net:_ Eio.Net.t ->
  ?nameserver:Eio.Net.Sockaddr.datagram ->
  ?timeout:float ->
  unit ->
  t

(** Create a DNS client using system resolv.conf.

    Reads /etc/resolv.conf to find nameservers. *)
val create_from_resolv_conf :
  net:_ Eio.Net.t ->
  ?timeout:float ->
  unit ->
  t

(** {2 Query Functions} *)

(** Look up A records (IPv4 addresses) *)
val lookup_a : t -> string -> (Ipaddr.V4.t list, [> `Msg of string ]) result

(** Look up AAAA records (IPv6 addresses) *)
val lookup_aaaa : t -> string -> (Ipaddr.V6.t list, [> `Msg of string ]) result

(** Look up MX records (mail exchangers).
    Returns list of (preference, hostname) sorted by preference. *)
val lookup_mx : t -> string -> ((int * string) list, [> `Msg of string ]) result

(** Look up TXT records *)
val lookup_txt : t -> string -> (string list, [> `Msg of string ]) result

(** Look up PTR record for an IP address *)
val lookup_ptr : t -> Ipaddr.t -> (string, [> `Msg of string ]) result

(** {2 Generic Query} *)

(** Perform a DNS query for any record type *)
val query :
  t ->
  [ `host ] Domain_name.t ->
  'a Dns.Rr_map.key ->
  ('a, [> `Msg of string ]) result
