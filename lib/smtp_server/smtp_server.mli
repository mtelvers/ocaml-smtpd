(** SMTP Server - RFC 5321 Implementation

    Implements {{:https://datatracker.ietf.org/doc/html/rfc5321}RFC 5321} SMTP server with:
    - Closed relay enforcement (critical security)
    - SASL authentication (RFC 4954)
    - STARTTLS support (RFC 3207)
    - SPF/DKIM/DMARC verification (RFC 7208, RFC 6376, RFC 7489) *)

(** Server configuration *)
type config = {
  hostname : string;
  local_domains : string list;          (** Domains we accept mail for *)
  max_message_size : int64;             (** SIZE limit per RFC 1870 *)
  max_recipients : int;                 (** Maximum recipients per message *)
  require_auth_for_relay : bool;        (** Require auth to relay externally *)
  require_tls_for_auth : bool;          (** Require TLS before AUTH *)
  tls_config : Tls.Config.server option;
  greeting_delay : float option;        (** Anti-spam delay before greeting *)
  enable_spf : bool;                    (** Enable SPF checking *)
  enable_dkim : bool;                   (** Enable DKIM verification *)
  enable_dmarc : bool;                  (** Enable DMARC policy checking *)
  reject_on_dmarc_fail : bool;          (** Reject messages that fail DMARC *)
}

(** Default configuration *)
val default_config : config

(** Functor to create server with specific queue and auth backends *)
module Make
    (Queue : Smtp_queue.QUEUE)
    (Auth : Smtp_auth.AUTH) : sig

  type t

  (** Create a new server instance *)
  val create : config:config -> queue:Queue.t -> auth:Auth.t -> dns:Smtp_dns.t -> t

  (** Run server on cleartext port (single process mode) *)
  val run :
    t -> sw:Eio.Switch.t -> net:'a Eio.Net.t ->
    addr:Eio.Net.Sockaddr.stream -> ?after_bind:(unit -> unit) -> unit -> unit

  (** Run server on TLS port (single process mode) *)
  val run_tls :
    t -> sw:Eio.Switch.t -> net:'a Eio.Net.t ->
    addr:Eio.Net.Sockaddr.stream -> tls_config:Tls.Config.server ->
    ?after_bind:(unit -> unit) -> unit -> unit

  (** Run server with fork-per-connection privilege separation.
      Requires running as root. *)
  val run_forked :
    t -> sw:Eio.Switch.t -> net:'a Eio.Net.t ->
    addr:Eio.Net.Sockaddr.stream -> tls_config:Tls.Config.server option -> unit
end
