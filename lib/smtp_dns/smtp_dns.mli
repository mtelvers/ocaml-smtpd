(** SMTP DNS Resolver

    DNS lookups for SPF, DKIM, and DMARC verification.
    Uses the dns library with EIO for proper async DNS resolution. *)

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

(** DNS resolver type *)
type t

(** Create a new DNS resolver.
    @param net EIO network capability for DNS queries *)
val create : net:_ Eio.Net.t -> t

(** Convert IP address to string *)
val ip_to_string : ip_addr -> string

(** Parse IP address from string *)
val parse_ip : string -> ip_addr option

(** Look up TXT records for a domain.
    Returns list of TXT record strings. *)
val lookup_txt : t -> string -> (string list, error) result

(** Look up A records for a domain.
    Returns list of IPv4 addresses. *)
val lookup_a : t -> string -> (ip_addr list, error) result

(** Look up AAAA records for a domain.
    Returns list of IPv6 addresses. *)
val lookup_aaaa : t -> string -> (ip_addr list, error) result

(** Look up MX records for a domain.
    Returns list of (preference, hostname) pairs sorted by preference. *)
val lookup_mx : t -> string -> ((int * string) list, error) result

(** Look up PTR record for an IP address (reverse DNS). *)
val lookup_ptr : t -> ip_addr -> (string, error) result

(** Check if an IP address matches a CIDR network *)
val ip_in_network : ip_addr -> ip_addr -> int -> bool

(** Check if IP matches a domain's A/AAAA records *)
val ip_matches_domain : t -> ip_addr -> string -> bool
