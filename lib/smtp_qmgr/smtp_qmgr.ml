(** SMTP Queue Manager

    Processes the message queue and handles delivery scheduling.
    Similar to Postfix qmgr. *)

open Smtp_types
open Smtp_delivery

(** Deferred message with retry information *)
type deferred_message = {
  msg : queued_message;
  recipient : email_address;
  reason : string;
  retry_count : int;
  next_retry : float;  (** Unix timestamp *)
}

(** Queue manager state *)
type t = {
  local_domains : string list;
  dkim_config : Smtp_dkim.signing_config option;
  dns : Smtp_dns.t;
  deferred : (string, deferred_message list) Hashtbl.t;  (** msg_id -> deferred recipients *)
  stats : delivery_stats;
  mutable running : bool;
  max_retries : int;
  retry_intervals : float array;  (** Backoff intervals in seconds *)
}

(** Default retry intervals (exponential backoff):
    1min, 5min, 15min, 30min, 1h, 2h, 4h, 8h, 16h, 24h *)
let default_retry_intervals = [|
  60.0;           (* 1 minute *)
  300.0;          (* 5 minutes *)
  900.0;          (* 15 minutes *)
  1800.0;         (* 30 minutes *)
  3600.0;         (* 1 hour *)
  7200.0;         (* 2 hours *)
  14400.0;        (* 4 hours *)
  28800.0;        (* 8 hours *)
  57600.0;        (* 16 hours *)
  86400.0;        (* 24 hours *)
|]

(** Create a new queue manager *)
let create ~local_domains ~dns ?dkim_config () =
  {
    local_domains;
    dkim_config;
    dns;
    deferred = Hashtbl.create 64;
    stats = create_stats ();
    running = false;
    max_retries = 10;
    retry_intervals = default_retry_intervals;
  }

(** Calculate next retry time based on attempt count *)
let next_retry_time t retry_count =
  let now = Unix.gettimeofday () in
  let idx = min retry_count (Array.length t.retry_intervals - 1) in
  now +. t.retry_intervals.(idx)

(** Generate an RFC 3464 compliant bounce message (DSN).

    Bounce messages are sent from the null sender to prevent
    bounce loops. They inform the original sender that their
    message could not be delivered. *)
let generate_bounce ~recipient ~reason ~original_msg =
  let now = Unix.gettimeofday () in
  let tm = Unix.gmtime now in
  let date = Printf.sprintf "%s, %d %s %d %02d:%02d:%02d +0000"
      (match tm.Unix.tm_wday with
       | 0 -> "Sun" | 1 -> "Mon" | 2 -> "Tue" | 3 -> "Wed"
       | 4 -> "Thu" | 5 -> "Fri" | _ -> "Sat")
      tm.Unix.tm_mday
      (match tm.Unix.tm_mon with
       | 0 -> "Jan" | 1 -> "Feb" | 2 -> "Mar" | 3 -> "Apr"
       | 4 -> "May" | 5 -> "Jun" | 6 -> "Jul" | 7 -> "Aug"
       | 8 -> "Sep" | 9 -> "Oct" | 10 -> "Nov" | _ -> "Dec")
      (1900 + tm.Unix.tm_year)
      tm.Unix.tm_hour tm.Unix.tm_min tm.Unix.tm_sec
  in
  let hostname = Unix.gethostname () in
  let boundary = Printf.sprintf "=_bounce_%s_%d" hostname (int_of_float (now *. 1000.0)) in

  (* Extract first part of original message for inclusion (headers only, max 10KB) *)
  let original_headers =
    let max_len = 10240 in
    (* Find end of headers (empty line) *)
    let header_end =
      try
        let pos = Str.search_forward (Str.regexp "\r?\n\r?\n") original_msg.data 0 in
        min pos max_len
      with Not_found -> min (String.length original_msg.data) max_len
    in
    String.sub original_msg.data 0 header_end
  in

  (* Build the bounce message per RFC 3464 *)
  Printf.sprintf
{|Date: %s
From: Mail Delivery System <MAILER-DAEMON@%s>
To: <%s>
Subject: Undelivered Mail Returned to Sender
Auto-Submitted: auto-replied
MIME-Version: 1.0
Content-Type: multipart/report; report-type=delivery-status;
	boundary="%s"

This is a MIME-encapsulated message.

--%s
Content-Type: text/plain; charset=utf-8

This message was created automatically by the mail system.

A message that you sent could not be delivered to one or more of its
recipients. The following address(es) failed:

    %s
        %s

--%s
Content-Type: message/delivery-status

Reporting-MTA: dns; %s
Original-Envelope-Id: %s
Arrival-Date: %s

Final-Recipient: rfc822; %s
Action: failed
Status: 5.0.0
Diagnostic-Code: smtp; %s

--%s
Content-Type: text/rfc822-headers

%s

--%s--
|}
    date hostname
    (match original_msg.sender with Some s -> email_to_string s | None -> "")
    boundary
    boundary
    (email_to_string recipient)
    reason
    boundary
    hostname
    original_msg.id
    date
    (email_to_string recipient)
    reason
    boundary
    original_headers
    boundary

(** Queue a bounce message for delivery to the original sender *)
let queue_bounce _t ~recipient ~reason ~original_msg =
  match original_msg.sender with
  | None ->
    (* Original message was from null sender - don't bounce to avoid loops *)
    Eio.traceln "Not generating bounce for null sender message"
  | Some sender ->
    let bounce_data = generate_bounce ~recipient ~reason ~original_msg in
    let bounce_msg = {
      id = Printf.sprintf "bounce-%s-%d" original_msg.id (int_of_float (Unix.gettimeofday () *. 1000.0));
      sender = None;  (* Bounces MUST be from null sender *)
      recipients = [sender];
      data = bounce_data;
      received_at = Unix.gettimeofday ();
      auth_user = None;
      client_ip = "127.0.0.1";
      client_domain = Unix.gethostname ();
    } in
    (* Deliver bounce to local recipient *)
    Eio.traceln "Generating bounce message for %s -> %s"
      (email_to_string recipient) (email_to_string sender);
    let result = Maildir.deliver_message ~recipient:sender ~msg:bounce_msg in
    match result with
    | Delivered -> Eio.traceln "Bounce delivered to %s" (email_to_string sender)
    | Failed err -> Eio.traceln "Failed to deliver bounce to %s: %s" (email_to_string sender) err
    | Deferred err -> Eio.traceln "Bounce deferred for %s: %s" (email_to_string sender) err

(** Process delivery results for a message *)
let process_results t msg results =
  let all_done = ref true in

  List.iter (fun (recipient, result) ->
    match result with
    | Delivered ->
      t.stats.delivered <- t.stats.delivered + 1;
      Eio.traceln "Delivered to %s" (email_to_string recipient)

    | Failed reason ->
      t.stats.failed <- t.stats.failed + 1;
      Eio.traceln "Failed delivery to %s: %s" (email_to_string recipient) reason;
      queue_bounce t ~recipient ~reason ~original_msg:msg

    | Deferred reason ->
      t.stats.deferred <- t.stats.deferred + 1;
      all_done := false;
      Eio.traceln "Deferred delivery to %s: %s" (email_to_string recipient) reason;

      (* Add to deferred list *)
      let deferred_msg = {
        msg;
        recipient;
        reason;
        retry_count = 0;
        next_retry = next_retry_time t 0;
      } in
      let existing = try Hashtbl.find t.deferred msg.id with Not_found -> [] in
      Hashtbl.replace t.deferred msg.id (deferred_msg :: existing)
  ) results;

  !all_done

(** Attempt to deliver deferred messages that are due for retry *)
let process_deferred t =
  let now = Unix.gettimeofday () in
  let to_retry = ref [] in

  (* Find messages due for retry *)
  Hashtbl.iter (fun msg_id deferred_list ->
    let (due, not_due) = List.partition (fun d -> d.next_retry <= now) deferred_list in
    if due <> [] then begin
      to_retry := (msg_id, due) :: !to_retry;
      if not_due = [] then
        Hashtbl.remove t.deferred msg_id
      else
        Hashtbl.replace t.deferred msg_id not_due
    end
  ) t.deferred;

  (* Retry delivery *)
  List.iter (fun (_msg_id, deferred_list) ->
    List.iter (fun deferred ->
      if deferred.retry_count >= t.max_retries then begin
        (* Max retries exceeded - fail permanently *)
        t.stats.failed <- t.stats.failed + 1;
        Eio.traceln "Giving up on %s after %d retries: %s"
          (email_to_string deferred.recipient)
          deferred.retry_count
          deferred.reason;
        queue_bounce t ~recipient:deferred.recipient ~reason:deferred.reason ~original_msg:deferred.msg
      end else begin
        Eio.traceln "Retrying delivery to %s (attempt %d)"
          (email_to_string deferred.recipient)
          (deferred.retry_count + 1);

        let result = deliver_to_recipient
            ~dns:t.dns
            ?dkim_config:t.dkim_config
            ~local_domains:t.local_domains
            ~recipient:deferred.recipient
            ~msg:deferred.msg
            ()
        in

        match result with
        | Delivered ->
          t.stats.delivered <- t.stats.delivered + 1;
          Eio.traceln "Delivered to %s on retry" (email_to_string deferred.recipient)

        | Failed fail_reason ->
          t.stats.failed <- t.stats.failed + 1;
          Eio.traceln "Failed delivery to %s: %s" (email_to_string deferred.recipient) fail_reason

        | Deferred defer_reason ->
          (* Re-defer with increased retry count *)
          let new_deferred = {
            deferred with
            retry_count = deferred.retry_count + 1;
            next_retry = next_retry_time t (deferred.retry_count + 1);
            reason = defer_reason;
          } in
          let msg_id = deferred.msg.id in
          let existing = try Hashtbl.find t.deferred msg_id with Not_found -> [] in
          Hashtbl.replace t.deferred msg_id (new_deferred :: existing);
          Eio.traceln "Re-deferred %s, next retry at %s"
            (email_to_string deferred.recipient)
            (let tm = Unix.localtime new_deferred.next_retry in
             Printf.sprintf "%02d:%02d:%02d" tm.Unix.tm_hour tm.Unix.tm_min tm.Unix.tm_sec)
      end
    ) deferred_list
  ) !to_retry

(** Process a single message from the queue *)
let process_message t msg =
  Eio.traceln "Processing message %s from %s"
    msg.id
    (reverse_path_to_string msg.sender);

  (* Attempt delivery to all recipients *)
  let results = deliver_message ~dns:t.dns ?dkim_config:t.dkim_config ~local_domains:t.local_domains ~msg () in
  let _all_done = process_results t msg results in
  ()

(** Stop the queue manager *)
let stop t =
  t.running <- false

(** Get queue manager statistics *)
let get_stats t =
  {
    delivered = t.stats.delivered;
    deferred = t.stats.deferred;
    failed = t.stats.failed;
  }

(** Get count of deferred messages *)
let deferred_count t =
  Hashtbl.fold (fun _ lst acc -> acc + List.length lst) t.deferred 0

(** Functor to create queue manager for specific queue type *)
module Make (Q : Smtp_queue.QUEUE) = struct

  (** Main queue processing loop.

      This should be run as a fiber/thread. It continuously:
      1. Checks for new messages in the queue
      2. Attempts delivery
      3. Processes deferred messages for retry *)
  let run t queue =
    t.running <- true;
    Eio.traceln "Queue manager started";

    while t.running do
      (* Process new messages from queue *)
      (match Q.dequeue queue with
       | Some msg ->
         process_message t msg;
         (* Mark as delivered in queue if all recipients succeeded *)
         (* For now, always remove from queue - delivery tracking is separate *)
         ignore (Q.mark_delivered queue ~id:msg.id)
       | None ->
         (* No new messages - process deferred and sleep *)
         process_deferred t;
         Unix.sleepf 1.0  (* Poll interval *)
      )
    done;

    Eio.traceln "Queue manager stopped"

  (** Run queue manager with EIO *)
  let run_eio t queue ~sw =
    Eio.Fiber.fork ~sw (fun () ->
      t.running <- true;
      Eio.traceln "Queue manager started (EIO)";

      while t.running do
        (* Process new messages from queue *)
        (match Q.dequeue queue with
         | Some msg ->
           process_message t msg;
           ignore (Q.mark_delivered queue ~id:msg.id)
         | None ->
           (* No new messages - process deferred and sleep *)
           process_deferred t;
           Eio_unix.sleep 1.0  (* Poll interval *)
        )
      done;

      Eio.traceln "Queue manager stopped"
    )
end
