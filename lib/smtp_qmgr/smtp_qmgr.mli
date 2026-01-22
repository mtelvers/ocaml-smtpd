(** SMTP Queue Manager

    Processes the message queue and handles delivery scheduling.
    Similar to Postfix qmgr. *)

(** Queue manager state *)
type t

(** Create a new queue manager.

    @param local_domains List of domains considered local
    @param dns DNS resolver for remote delivery
    @param dkim_config Optional DKIM signing configuration for outbound messages *)
val create :
  local_domains:string list ->
  dns:Smtp_dns.t ->
  ?dkim_config:Smtp_dkim.signing_config ->
  unit ->
  t

(** Stop the queue manager *)
val stop : t -> unit

(** Get delivery statistics *)
val get_stats : t -> Smtp_delivery.delivery_stats

(** Get count of currently deferred messages *)
val deferred_count : t -> int

(** Functor to create queue manager for specific queue type *)
module Make (Q : Smtp_queue.QUEUE) : sig
  (** Main queue processing loop (blocking).

      Continuously processes messages from the queue and handles
      delivery with retry logic for temporary failures. *)
  val run : t -> Q.t -> unit

  (** Run queue manager as an EIO fiber.

      Non-blocking version that runs in the background. *)
  val run_eio : t -> Q.t -> sw:Eio.Switch.t -> unit
end
