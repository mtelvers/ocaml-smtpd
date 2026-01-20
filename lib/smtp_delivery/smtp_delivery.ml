(** SMTP Delivery - Local and Remote Delivery

    Handles delivery of queued messages to:
    - Local mailboxes (Maildir format in user home directories)
    - Remote servers (via SMTP client) *)

open Smtp_types

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

let create_stats () = { delivered = 0; deferred = 0; failed = 0 }

(** {1 Maildir Local Delivery} *)

module Maildir = struct
  (** Maildir subdirectories *)
  let subdirs = ["new"; "cur"; "tmp"]

  (** Generate unique Maildir filename.
      Format: timestamp.Pprocess_id.hostname *)
  let generate_filename () =
    let timestamp = Unix.gettimeofday () in
    let pid = Unix.getpid () in
    let hostname = Unix.gethostname () in
    (* Add microseconds and counter for uniqueness *)
    let usec = int_of_float ((timestamp -. floor timestamp) *. 1000000.0) in
    Printf.sprintf "%.0f.M%06dP%d.%s" timestamp usec pid hostname

  (** Ensure Maildir structure exists.
      Creates ~/Maildir/{new,cur,tmp} if needed with correct ownership. *)
  let ensure_maildir ~uid ~gid maildir_path =
    try
      (* Create base Maildir if needed *)
      if not (Sys.file_exists maildir_path) then begin
        Unix.mkdir maildir_path 0o700;
        Unix.chown maildir_path uid gid
      end;
      (* Create subdirectories *)
      List.iter (fun subdir ->
        let path = Filename.concat maildir_path subdir in
        if not (Sys.file_exists path) then begin
          Unix.mkdir path 0o700;
          Unix.chown path uid gid
        end
      ) subdirs;
      Ok ()
    with
    | Unix.Unix_error (code, func, arg) ->
      Error (Printf.sprintf "%s(%s): %s" func arg (Unix.error_message code))
    | exn ->
      Error (Printexc.to_string exn)

  (** Get Maildir path and user info for a local user.
      Returns (~/Maildir, uid, gid) for the user. *)
  let maildir_for_user username =
    try
      let pw = Unix.getpwnam username in
      Ok (Filename.concat pw.Unix.pw_dir "Maildir", pw.Unix.pw_uid, pw.Unix.pw_gid)
    with Not_found ->
      Error (Printf.sprintf "User not found: %s" username)

  (** Get Maildir path and user info for an email address.
      Extracts local part and looks up system user. *)
  let maildir_for_address addr =
    maildir_for_user addr.local_part

  (** Deliver a message to a local Maildir.

      @param maildir_path Path to Maildir (e.g., /home/user/Maildir)
      @param uid User ID for file ownership
      @param gid Group ID for file ownership
      @param message The message content (with headers)
      @return Ok filename on success, Error message on failure *)
  let deliver ~maildir_path ~uid ~gid ~message =
    match ensure_maildir ~uid ~gid maildir_path with
    | Error e -> Error e
    | Ok () ->
      try
        let filename = generate_filename () in
        let tmp_path = Filename.concat (Filename.concat maildir_path "tmp") filename in
        let new_path = Filename.concat (Filename.concat maildir_path "new") filename in

        (* Write to tmp first *)
        let oc = open_out_bin tmp_path in
        output_string oc message;
        close_out oc;

        (* Set ownership to destination user *)
        Unix.chown tmp_path uid gid;

        (* Atomic move to new *)
        Unix.rename tmp_path new_path;

        Ok filename
      with
      | Unix.Unix_error (code, func, arg) ->
        Error (Printf.sprintf "%s(%s): %s" func arg (Unix.error_message code))
      | exn ->
        Error (Printexc.to_string exn)

  (** Deliver a queued message to a local recipient.

      @param recipient The recipient email address
      @param msg The queued message
      @return Delivery result *)
  let deliver_message ~recipient ~msg =
    match maildir_for_address recipient with
    | Error e -> Failed e
    | Ok (maildir_path, uid, gid) ->
      (* Build the message with delivery headers *)
      let delivered_to = Printf.sprintf "Delivered-To: %s\r\n" (email_to_string recipient) in
      let return_path = Printf.sprintf "Return-Path: <%s>\r\n"
          (match msg.sender with Some s -> email_to_string s | None -> "") in
      let message = return_path ^ delivered_to ^ msg.data in

      match deliver ~maildir_path ~uid ~gid ~message with
      | Ok _filename -> Delivered
      | Error e ->
        (* Check if it's a temporary or permanent failure *)
        if String.length e >= 5 && (String.sub e 0 5 = "ENOSP" || String.sub e 0 5 = "EDQUO") then
          Deferred e  (* Disk full, quota - retry later *)
        else
          Failed e
end

(** {1 SMTP Client for Remote Delivery} *)

module Remote = struct

  (** Read a line from socket *)
  let read_line ic =
    try Some (input_line ic)
    with End_of_file -> None

  (** Read SMTP response (may be multi-line) *)
  let read_response ic =
    let rec loop lines =
      match read_line ic with
      | None -> Error "Connection closed"
      | Some line ->
        let line = String.trim line in
        if String.length line < 4 then
          Error ("Invalid response: " ^ line)
        else
          let code = try Some (int_of_string (String.sub line 0 3)) with _ -> None in
          let continues = String.length line > 3 && line.[3] = '-' in
          let text = if String.length line > 4 then String.sub line 4 (String.length line - 4) else "" in
          match code with
          | None -> Error ("Invalid response code: " ^ line)
          | Some c ->
            if continues then
              loop ((c, text) :: lines)
            else
              Ok (List.rev ((c, text) :: lines))
    in
    loop []

  (** Check if response indicates success *)
  let is_success_response code =
    code >= 200 && code < 400

  (** Send a command and get response *)
  let send_command oc ic cmd =
    output_string oc cmd;
    output_string oc "\r\n";
    flush oc;
    read_response ic

  (** Connect to an SMTP server and send a message.

      @param host Remote server hostname
      @param port Remote server port (default 25)
      @param sender Envelope sender
      @param recipient Envelope recipient
      @param message Message content
      @return Delivery result *)
  let deliver ~host ~port ~sender ~recipient ~message =
    try
      (* Resolve hostname *)
      let addrs = Unix.getaddrinfo host (string_of_int port)
          [Unix.AI_SOCKTYPE Unix.SOCK_STREAM] in
      match addrs with
      | [] -> Deferred ("Could not resolve: " ^ host)
      | addr :: _ ->
        (* Connect *)
        let sock = Unix.socket addr.Unix.ai_family Unix.SOCK_STREAM 0 in
        Unix.setsockopt_float sock Unix.SO_RCVTIMEO 30.0;
        Unix.setsockopt_float sock Unix.SO_SNDTIMEO 30.0;

        (try Unix.connect sock addr.Unix.ai_addr
         with Unix.Unix_error (code, _, _) ->
           Unix.close sock;
           raise (Failure (Printf.sprintf "Connect failed: %s" (Unix.error_message code))));

        let ic = Unix.in_channel_of_descr sock in
        let oc = Unix.out_channel_of_descr sock in

        let cleanup result =
          (try send_command oc ic "QUIT" |> ignore with _ -> ());
          (try close_in ic with _ -> ());
          (try close_out oc with _ -> ());
          result
        in

        (* Read greeting *)
        (match read_response ic with
         | Error e -> cleanup (Deferred e)
         | Ok ((code, _) :: _) when not (is_success_response code) ->
           cleanup (Deferred "Server rejected connection")
         | _ ->

           (* Send EHLO, fall back to HELO if needed *)
           let my_hostname = Unix.gethostname () in
           let ehlo_ok = match send_command oc ic ("EHLO " ^ my_hostname) with
             | Ok ((code, _) :: _) when is_success_response code -> true
             | _ ->
               (* Try HELO as fallback *)
               match send_command oc ic ("HELO " ^ my_hostname) with
               | Ok ((code, _) :: _) when is_success_response code -> true
               | _ -> false
           in
           if not ehlo_ok then
             cleanup (Deferred "EHLO/HELO rejected")
           else

             (* Send MAIL FROM *)
             let sender_str = match sender with
               | Some s -> email_to_string s
               | None -> ""
             in
             match send_command oc ic (Printf.sprintf "MAIL FROM:<%s>" sender_str) with
             | Error e -> cleanup (Deferred e)
             | Ok ((code, text) :: _) when not (is_success_response code) ->
               if code >= 500 then cleanup (Failed text)
               else cleanup (Deferred text)
             | _ ->

               (* Send RCPT TO *)
               match send_command oc ic (Printf.sprintf "RCPT TO:<%s>" (email_to_string recipient)) with
               | Error e -> cleanup (Deferred e)
               | Ok ((code, text) :: _) when not (is_success_response code) ->
                 if code >= 500 then cleanup (Failed text)
                 else cleanup (Deferred text)
               | _ ->

                 (* Send DATA *)
                 match send_command oc ic "DATA" with
                 | Error e -> cleanup (Deferred e)
                 | Ok ((code, _) :: _) when code <> 354 ->
                   cleanup (Deferred "DATA not accepted")
                 | _ ->

                   (* Send message body *)
                   (* Dot-stuff lines starting with . *)
                   Printf.eprintf "[DELIVERY] Sending message, total length: %d bytes\n%!" (String.length message);
                   (* Log escaped first 500 chars of message *)
                   let preview_len = min 500 (String.length message) in
                   Printf.eprintf "[DELIVERY] Message preview: %s\n%!" (String.escaped (String.sub message 0 preview_len));
                   let lines = String.split_on_char '\n' message in
                   (* Remove trailing empty string that results from splitting a message ending with \n *)
                   let lines = match List.rev lines with
                     | "" :: rest -> List.rev rest
                     | _ -> lines
                   in
                   Printf.eprintf "[DELIVERY] Split into %d lines\n%!" (List.length lines);
                   let sent_body = Buffer.create 1024 in
                   let in_body = ref false in
                   List.iter (fun line ->
                     (* Strip trailing CR if present (from CRLF line endings) *)
                     let line = if String.length line > 0 && line.[String.length line - 1] = '\r'
                       then String.sub line 0 (String.length line - 1) else line in
                     (* Track when we enter the body (after blank line) *)
                     if !in_body then begin
                       Buffer.add_string sent_body line;
                       Buffer.add_string sent_body "\r\n"
                     end else if line = "" then
                       in_body := true;
                     let line = if String.length line > 0 && line.[0] = '.' then "." ^ line else line in
                     output_string oc line;
                     output_string oc "\r\n"
                   ) lines;
                   output_string oc ".\r\n";
                   flush oc;
                   (* Log the body that was actually sent *)
                   let body_sent = Buffer.contents sent_body in
                   Printf.eprintf "[DELIVERY] Body sent length: %d bytes\n%!" (String.length body_sent);
                   (* Log hex dump of body sent *)
                   let hex_dump s =
                     String.concat " " (List.init (String.length s) (fun i ->
                       Printf.sprintf "%02x" (Char.code s.[i])
                     ))
                   in
                   Printf.eprintf "[DELIVERY] Body sent hex: %s\n%!" (hex_dump body_sent);

                   (* Read final response *)
                   match read_response ic with
                   | Error e -> cleanup (Deferred e)
                   | Ok ((code, text) :: _) ->
                     if is_success_response code then
                       cleanup Delivered
                     else if code >= 500 then
                       cleanup (Failed text)
                     else
                       cleanup (Deferred text)
                   | Ok [] -> cleanup (Deferred "Empty response"))
    with
    | Failure msg -> Deferred msg
    | Unix.Unix_error (code, func, _) ->
      Deferred (Printf.sprintf "%s: %s" func (Unix.error_message code))
    | exn ->
      Deferred (Printexc.to_string exn)

  (** Look up MX records for a domain and return hosts sorted by priority *)
  let lookup_mx domain =
    match Smtp_dns.lookup_mx (Smtp_dns.create ()) domain with
    | Ok mx_records -> Ok mx_records
    | Error Smtp_dns.Not_found ->
      (* No MX record - fall back to A record per RFC 5321 *)
      Ok [(0, domain)]
    | Error _ -> Error "DNS lookup failed"

  (** Deliver a message to a remote recipient via SMTP.

      Looks up MX records and tries each in order of priority.

      @param dkim_config Optional DKIM signing configuration
      @param recipient The recipient email address
      @param msg The queued message
      @return Delivery result *)
  let deliver_message ?(dkim_config : Smtp_dkim.signing_config option) ~recipient ~msg () =
    match lookup_mx recipient.domain with
    | Error e -> Deferred e
    | Ok mx_hosts ->
      (* Sign message with DKIM if configured *)
      let message_to_send = match dkim_config with
        | None -> msg.data
        | Some config ->
          match Smtp_dkim.sign_message ~config ~message:msg.data with
          | Ok signed -> signed
          | Error _e ->
            (* If signing fails, send unsigned - log this in production *)
            msg.data
      in
      (* Try each MX host in priority order *)
      let rec try_hosts = function
        | [] -> Deferred "All MX hosts failed"
        | (_, host) :: rest ->
          (* Remove trailing dot from hostname if present *)
          let host = if String.length host > 0 && host.[String.length host - 1] = '.'
            then String.sub host 0 (String.length host - 1)
            else host
          in
          match deliver ~host ~port:25 ~sender:msg.sender ~recipient ~message:message_to_send with
          | Delivered -> Delivered
          | Failed reason -> Failed reason  (* Permanent failure, don't try other hosts *)
          | Deferred _ -> try_hosts rest    (* Try next host *)
      in
      try_hosts mx_hosts
end

(** {1 Delivery Router} *)

(** Determine if a recipient is local or remote *)
let is_local_recipient ~local_domains recipient =
  List.exists (fun d ->
    String.lowercase_ascii d = String.lowercase_ascii recipient.domain
  ) local_domains

(** Deliver a message to a single recipient.

    Routes to local Maildir or remote SMTP based on domain.

    @param dkim_config Optional DKIM signing configuration for outbound messages *)
let deliver_to_recipient ?dkim_config ~local_domains ~recipient ~msg () =
  if is_local_recipient ~local_domains recipient then
    Maildir.deliver_message ~recipient ~msg
  else
    Remote.deliver_message ?dkim_config ~recipient ~msg ()

(** Deliver a queued message to all recipients.

    @param dkim_config Optional DKIM signing configuration for outbound messages
    @return List of (recipient, result) pairs *)
let deliver_message ?dkim_config ~local_domains ~msg () =
  List.map (fun recipient ->
    let result = deliver_to_recipient ?dkim_config ~local_domains ~recipient ~msg () in
    (recipient, result)
  ) msg.recipients
