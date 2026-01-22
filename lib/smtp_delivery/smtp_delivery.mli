(** SMTP Delivery - Local and Remote Delivery

    Handles delivery of queued messages to:
    - Local mailboxes (Maildir format in user home directories)
    - Remote servers (via SMTP client with optional DKIM signing) *)

(** Delivery result *)
type delivery_result =
  | Delivered
  | Deferred of string   (** Temporary failure, retry later *)
  | Failed of string     (** Permanent failure, bounce *)

(** Delivery statistics *)
type delivery_stats = {
  mutable delivered : int;
  mutable deferred : int;
  mutable failed : int;
}

val create_stats : unit -> delivery_stats

(** {1 Maildir Local Delivery} *)

module Maildir : sig
  (** Ensure Maildir structure exists.
      Creates {new,cur,tmp} subdirectories with correct ownership. *)
  val ensure_maildir : uid:int -> gid:int -> string -> (unit, string) result

  (** Get Maildir path and user info for a local user.
      @return (~/Maildir, uid, gid) for the user *)
  val maildir_for_user : string -> (string * int * int, string) result

  (** Get Maildir path and user info for an email address.
      Looks up user by local part. *)
  val maildir_for_address : Smtp_types.email_address -> (string * int * int, string) result

  (** Deliver a message to a Maildir.

      @param maildir_path Path to Maildir (e.g., /home/user/Maildir)
      @param uid User ID for file ownership
      @param gid Group ID for file ownership
      @param message The message content (with headers)
      @return Ok filename on success *)
  val deliver : maildir_path:string -> uid:int -> gid:int -> message:string -> (string, string) result

  (** Deliver a queued message to a local recipient. *)
  val deliver_message :
    recipient:Smtp_types.email_address ->
    msg:Smtp_types.queued_message ->
    delivery_result
end

(** {1 SMTP Client for Remote Delivery} *)

module Remote : sig
  (** Look up MX records for a domain.
      @param dns DNS resolver
      @return List of (priority, hostname) pairs sorted by priority *)
  val lookup_mx : dns:Smtp_dns.t -> string -> ((int * string) list, string) result

  (** Connect to an SMTP server and send a message.

      @param host Remote server hostname
      @param port Remote server port (default 25)
      @param sender Envelope sender
      @param recipient Envelope recipient
      @param message Message content
      @return Delivery result *)
  val deliver :
    host:string ->
    port:int ->
    sender:Smtp_types.email_address option ->
    recipient:Smtp_types.email_address ->
    message:string ->
    delivery_result

  (** Deliver a queued message to a remote recipient.
      Looks up MX records and tries each host.

      @param dns DNS resolver for MX lookups
      @param dkim_config Optional DKIM signing configuration for outbound signing *)
  val deliver_message :
    dns:Smtp_dns.t ->
    ?dkim_config:Smtp_dkim.signing_config ->
    recipient:Smtp_types.email_address ->
    msg:Smtp_types.queued_message ->
    unit ->
    delivery_result
end

(** {1 Delivery Router} *)

(** Determine if a recipient is local or remote *)
val is_local_recipient :
  local_domains:string list ->
  Smtp_types.email_address ->
  bool

(** Deliver a message to a single recipient.
    Routes to local Maildir or remote SMTP based on domain.

    @param dns DNS resolver for remote delivery
    @param dkim_config Optional DKIM signing configuration for outbound messages *)
val deliver_to_recipient :
  dns:Smtp_dns.t ->
  ?dkim_config:Smtp_dkim.signing_config ->
  local_domains:string list ->
  recipient:Smtp_types.email_address ->
  msg:Smtp_types.queued_message ->
  unit ->
  delivery_result

(** Deliver a queued message to all recipients.

    @param dns DNS resolver for remote delivery
    @param dkim_config Optional DKIM signing configuration for outbound messages
    @return List of (recipient, result) pairs *)
val deliver_message :
  dns:Smtp_dns.t ->
  ?dkim_config:Smtp_dkim.signing_config ->
  local_domains:string list ->
  msg:Smtp_types.queued_message ->
  unit ->
  (Smtp_types.email_address * delivery_result) list
