(** SMTP Server - RFC 5321 Implementation

    Implements {{:https://datatracker.ietf.org/doc/html/rfc5321}RFC 5321} SMTP server with:
    - Closed relay enforcement (critical security)
    - SASL authentication (RFC 4954)
    - STARTTLS support (RFC 3207)
    - SPF/DKIM/DMARC verification (RFC 7208, RFC 6376, RFC 7489) *)

open Smtp_types
open Smtp_parser

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

let default_config = {
  hostname = "localhost";
  local_domains = [];
  max_message_size = 10_485_760L;  (* 10MB default *)
  max_recipients = 100;
  require_auth_for_relay = true;
  require_tls_for_auth = false;
  tls_config = None;
  greeting_delay = None;
  enable_spf = true;
  enable_dkim = true;
  enable_dmarc = true;
  reject_on_dmarc_fail = false;  (* Accept but mark by default *)
}

(** ESMTP extensions we advertise *)
let extensions config ~tls_active ~authenticated =
  let exts = [
    Printf.sprintf "SIZE %Ld" config.max_message_size;
    "8BITMIME";
    "ENHANCEDSTATUSCODES";
    "PIPELINING";
  ] in
  (* Only advertise AUTH if not already authenticated *)
  let exts = if not authenticated then
    "AUTH PLAIN LOGIN" :: exts
  else exts in
  (* Advertise STARTTLS if TLS available and not active *)
  let exts = match config.tls_config with
    | Some _ when not tls_active -> "STARTTLS" :: exts
    | _ -> exts
  in
  exts

module Make
    (Queue : Smtp_queue.QUEUE)
    (Auth : Smtp_auth.AUTH) = struct

  (** Action returned by command handlers *)
  type command_action =
    | Continue
    | Upgrade_tls
    | Close

  type t = {
    config : config;
    queue : Queue.t;
    auth : Auth.t;
    dns : Smtp_dns.t;
  }

  let create ~config ~queue ~auth ~dns =
    { config; queue; auth; dns }

  (** Send a response to the client *)
  let send_response flow response =
    let data = response_to_string response in
    Eio.Flow.copy_string data flow

  (** Send the initial greeting *)
  let send_greeting t flow =
    (* Optional anti-spam delay *)
    (match t.config.greeting_delay with
     | Some delay -> Unix.sleepf delay
     | None -> ());
    send_response flow (greeting ~hostname:t.config.hostname)

  (** Handle EHLO command *)
  let handle_ehlo t flow domain ~tls_active state =
    let authenticated = match state with
      | Authenticated _ -> true
      | _ -> false
    in
    let exts = extensions t.config ~tls_active ~authenticated in
    send_response flow (ehlo_response ~hostname:t.config.hostname ~extensions:exts);
    Greeted { client_domain = domain; tls_active }

  (** Handle HELO command (legacy) *)
  let handle_helo t flow domain ~tls_active _state =
    send_response flow (ok ~text:(t.config.hostname ^ " Hello " ^ domain) ());
    Greeted { client_domain = domain; tls_active }

  (** Handle MAIL FROM command *)
  let handle_mail_from t flow reverse_path params state =
    (* Check SIZE parameter if present *)
    let size_ok = List.for_all (function
      | Size n -> Int64.compare n t.config.max_message_size <= 0
      | _ -> true
    ) params in
    if not size_ok then begin
      send_response flow message_too_large;
      state
    end else
      match state with
      | Greeted { client_domain; tls_active } ->
        send_response flow (ok ~text:"Sender OK" ());
        Mail_from_accepted {
          username = None;
          client_domain;
          sender = reverse_path;
          params;
          tls_active;
        }
      | Authenticated { username; client_domain; tls_active } ->
        send_response flow (ok ~text:"Sender OK" ());
        Mail_from_accepted {
          username = Some username;
          client_domain;
          sender = reverse_path;
          params;
          tls_active;
        }
      | _ ->
        send_response flow bad_sequence;
        state

  (** Handle RCPT TO command - CRITICAL CLOSED RELAY ENFORCEMENT *)
  let handle_rcpt_to t flow recipient _params state =
    match state with
    | Mail_from_accepted { username; client_domain; sender; params; tls_active } ->
      (* CRITICAL: Check if relay is allowed *)
      if not (is_relay_allowed ~state ~recipient ~local_domains:t.config.local_domains) then begin
        (* Log attempted relay for security monitoring *)
        Eio.traceln "RELAY DENIED: %s -> %s (auth=%s)"
          (reverse_path_to_string sender)
          (email_to_string recipient)
          (match username with Some u -> u | None -> "none");
        send_response flow relay_denied;
        state
      end else begin
        send_response flow (ok ~text:"Recipient OK" ());
        Rcpt_to_accepted {
          username;
          client_domain;
          sender;
          recipients = [recipient];
          params;
          tls_active;
        }
      end
    | Rcpt_to_accepted { username; client_domain; sender; recipients; params; tls_active } ->
      (* Check max recipients *)
      if List.length recipients >= t.config.max_recipients then begin
        send_response flow too_many_recipients;
        state
      end
      (* CRITICAL: Check if relay is allowed *)
      else if not (is_relay_allowed ~state ~recipient ~local_domains:t.config.local_domains) then begin
        Eio.traceln "RELAY DENIED: %s -> %s (auth=%s)"
          (reverse_path_to_string sender)
          (email_to_string recipient)
          (match username with Some u -> u | None -> "none");
        send_response flow relay_denied;
        state
      end else begin
        send_response flow (ok ~text:"Recipient OK" ());
        Rcpt_to_accepted {
          username;
          client_domain;
          sender;
          recipients = recipients @ [recipient];
          params;
          tls_active;
        }
      end
    | _ ->
      send_response flow bad_sequence;
      state

  (** Extract From domain from email headers *)
  let extract_from_domain data =
    (* Simple extraction - look for From: header *)
    let lines = String.split_on_char '\n' data in
    let rec find_from = function
      | [] -> None
      | line :: rest ->
        let line = String.trim line in
        if String.length line >= 5 &&
           String.lowercase_ascii (String.sub line 0 5) = "from:" then
          (* Extract domain from email address *)
          let value = String.sub line 5 (String.length line - 5) in
          (* Find @ symbol and extract domain *)
          (match String.index_opt value '@' with
           | None -> find_from rest
           | Some i ->
             let after_at = String.sub value (i + 1) (String.length value - i - 1) in
             (* Find end of domain (space or >) *)
             let domain = String.trim after_at in
             let domain = match String.index_opt domain '>' with
               | Some j -> String.sub domain 0 j
               | None -> domain
             in
             let domain = match String.index_opt domain ' ' with
               | Some j -> String.sub domain 0 j
               | None -> domain
             in
             if String.length domain > 0 then Some domain else find_from rest)
        else
          find_from rest
    in
    find_from lines

  (** Split message into headers and body *)
  let split_headers_body data =
    match Str.bounded_split (Str.regexp "\r\n\r\n") data 2 with
    | [headers; body] -> (headers, body)
    | [headers] -> (headers, "")
    | _ -> ("", data)

  (** Perform SPF/DKIM/DMARC checks and build Authentication-Results header *)
  let check_authentication t ~client_ip ~sender ~data =
    let results = Buffer.create 256 in
    Buffer.add_string results (Printf.sprintf "Authentication-Results: %s" t.config.hostname);

    (* Determine sender domain for SPF *)
    let spf_domain = match sender with
      | Some addr -> addr.domain
      | None -> ""  (* Null sender - would use HELO domain *)
    in

    (* SPF check *)
    let spf_result =
      if t.config.enable_spf && spf_domain <> "" then begin
        let ip = match Smtp_dns.parse_ip client_ip with
          | Some ip -> ip
          | None -> Smtp_dns.IPv4 (127, 0, 0, 1)  (* Fallback *)
        in
        let result = Smtp_spf.check ~dns:t.dns ~client_ip:ip ~sender_domain:spf_domain in
        Buffer.add_string results
          (Printf.sprintf ";\r\n\tspf=%s" (Smtp_spf.result_to_string result.result));
        if result.explanation <> None then
          Buffer.add_string results
            (Printf.sprintf " (%s)" (Option.get result.explanation));
        Buffer.add_string results (Printf.sprintf " smtp.mailfrom=%s" spf_domain);
        Some result
      end else
        None
    in

    (* Extract From domain and split headers/body for DKIM *)
    let from_domain = extract_from_domain data in
    let (raw_headers, body) = split_headers_body data in

    (* DKIM check *)
    let dkim_result =
      if t.config.enable_dkim then begin
        let result = Smtp_dkim.verify ~dns:t.dns ~raw_headers ~body in
        Buffer.add_string results
          (Printf.sprintf ";\r\n\t%s" (Smtp_dkim.format_auth_results result));
        Some result
      end else
        None
    in

    (* DMARC check *)
    let dmarc_result =
      if t.config.enable_dmarc then
        match from_domain, spf_result with
        | Some fd, Some spf ->
          let dkim = match dkim_result with
            | Some d -> d
            | None -> Smtp_dkim.Dkim_none
          in
          let result = Smtp_dmarc.check
              ~dns:t.dns
              ~from_domain:fd
              ~spf_result:spf
              ~spf_domain
              ~dkim_result:dkim
          in
          Buffer.add_string results
            (Printf.sprintf ";\r\n\t%s" (Smtp_dmarc.format_auth_results result fd));
          Some result
        | _ -> None
      else
        None
    in

    let auth_header = Buffer.contents results ^ "\r\n" in
    (auth_header, dmarc_result)

  (** Handle DATA command *)
  let handle_data t flow ~read_line ~client_ip state =
    match state with
    | Rcpt_to_accepted { username; client_domain; sender; recipients; tls_active; params = _ } ->
      (* Helper to preserve auth state after DATA completes *)
      let next_state () = match username with
        | Some u -> Authenticated { username = u; client_domain; tls_active }
        | None -> Greeted { client_domain; tls_active }
      in
      send_response flow ready_for_data;
      (* Read message body *)
      (match parse_data ~read_line with
       | Error msg ->
         send_response flow (temp_failure ~text:msg ());
         next_state ()
       | Ok data ->
         (* Perform SPF/DKIM/DMARC checks *)
         let (auth_header, dmarc_result) =
           check_authentication t ~client_ip ~sender ~data
         in

         (* Check if we should reject based on DMARC *)
         let should_reject =
           t.config.reject_on_dmarc_fail &&
           (match dmarc_result with
            | Some r -> r.Smtp_dmarc.disposition = `Reject
            | None -> false)
         in

         if should_reject then begin
           send_response flow (perm_failure ~text:"Message rejected by DMARC policy" ());
           next_state ()
         end else begin
           (* Prepend Authentication-Results header *)
           let data = auth_header ^ data in

           (* Queue the message *)
           let msg = {
             id = "";  (* Will be assigned by queue *)
             sender;
             recipients;
             data;
             received_at = Unix.gettimeofday ();
             auth_user = username;
             client_ip;
             client_domain;
           } in
           match Queue.enqueue t.queue msg with
           | Error Smtp_queue.Queue_full ->
             send_response flow (temp_failure ~text:"Queue full, try again later" ());
             next_state ()
           | Error Smtp_queue.Message_too_large ->
             send_response flow message_too_large;
             next_state ()
           | Error (Smtp_queue.Storage_error s) ->
             send_response flow (temp_failure ~text:("Storage error: " ^ s) ());
             next_state ()
           | Ok queue_id ->
             Eio.traceln "SMTP: accepted message %s from %s to %s (auth=%s)"
               queue_id
               (reverse_path_to_string sender)
               (String.concat "," (List.map email_to_string recipients))
               (match username with Some u -> u | None -> "none");
             send_response flow (ok ~text:("Message accepted, queue ID: " ^ queue_id) ());
             next_state ()
         end)
    | _ ->
      send_response flow bad_sequence;
      state

  (** Handle RSET command *)
  let handle_rset flow state =
    send_response flow (ok ~text:"Reset OK" ());
    match state with
    | Greeted r -> Greeted r
    | Authenticated r -> Authenticated r
    | Mail_from_accepted { client_domain; tls_active; username = Some u; _ } ->
      Authenticated { username = u; client_domain; tls_active }
    | Mail_from_accepted { client_domain; tls_active; _ } ->
      Greeted { client_domain; tls_active }
    | Rcpt_to_accepted { client_domain; tls_active; username = Some u; _ } ->
      Authenticated { username = u; client_domain; tls_active }
    | Rcpt_to_accepted { client_domain; tls_active; _ } ->
      Greeted { client_domain; tls_active }
    | Data_mode { client_domain; tls_active; username = Some u; _ } ->
      Authenticated { username = u; client_domain; tls_active }
    | Data_mode { client_domain; tls_active; _ } ->
      Greeted { client_domain; tls_active }
    | Initial | Quit -> state

  (** Handle NOOP command *)
  let handle_noop flow state =
    send_response flow (ok ~text:"OK" ());
    state

  (** Handle VRFY command (disabled for privacy) *)
  let handle_vrfy flow _arg state =
    send_response flow (perm_failure ~text:"VRFY command disabled" ());
    state

  (** Handle QUIT command *)
  let handle_quit t flow =
    send_response flow (service_closing ~hostname:t.config.hostname);
    Quit

  (** Handle AUTH command *)
  let handle_auth t flow mechanism initial_response ~read_line state =
    match state with
    | Greeted { client_domain; tls_active } ->
      (* Check if TLS required for AUTH *)
      if t.config.require_tls_for_auth && not tls_active then begin
        send_response flow starttls_required;
        state
      end else
        (match String.uppercase_ascii mechanism with
         | "PLAIN" ->
           (* SASL PLAIN - can have initial response *)
           let auth_data = match initial_response with
             | Some data -> Some data
             | None ->
               (* Request credentials with empty challenge *)
               send_response flow (auth_challenge "");
               read_line ()
           in
           (match auth_data with
            | None ->
              send_response flow auth_failed;
              state
            | Some data ->
              match decode_auth_plain data with
              | None ->
                send_response flow auth_failed;
                state
              | Some (_authzid, authcid, password) ->
                if Auth.authenticate t.auth ~username:authcid ~password then begin
                  send_response flow auth_success;
                  Authenticated { username = authcid; client_domain; tls_active }
                end else begin
                  send_response flow auth_failed;
                  state
                end)
         | "LOGIN" ->
           (* SASL LOGIN - two-step *)
           send_response flow (auth_challenge (encode_base64 "Username:"));
           (match read_line () with
            | None ->
              send_response flow auth_failed;
              state
            | Some username_b64 ->
              let username = match decode_base64 (String.trim username_b64) with
                | Some u -> u
                | None -> ""
              in
              send_response flow (auth_challenge (encode_base64 "Password:"));
              match read_line () with
              | None ->
                send_response flow auth_failed;
                state
              | Some password_b64 ->
                let password = match decode_base64 (String.trim password_b64) with
                  | Some p -> p
                  | None -> ""
                in
                if Auth.authenticate t.auth ~username ~password then begin
                  send_response flow auth_success;
                  Authenticated { username; client_domain; tls_active }
                end else begin
                  send_response flow auth_failed;
                  state
                end)
         | _ ->
           send_response flow (perm_failure ~text:"Unsupported authentication mechanism" ());
           state)
    | Authenticated _ ->
      send_response flow (perm_failure ~text:"Already authenticated" ());
      state
    | _ ->
      send_response flow bad_sequence;
      state

  (** Handle STARTTLS command *)
  let handle_starttls t flow state =
    match state with
    | Greeted { tls_active; _ } when not tls_active ->
      (match t.config.tls_config with
       | Some _ ->
         send_response flow starttls_ready;
         (state, Upgrade_tls)
       | None ->
         send_response flow (perm_failure ~text:"TLS not available" ());
         (state, Continue))
    | Greeted { tls_active = true; _ } ->
      send_response flow (perm_failure ~text:"TLS already active" ());
      (state, Continue)
    | _ ->
      send_response flow bad_sequence;
      (state, Continue)

  (** Main command dispatcher *)
  let handle_command t flow ~read_line ~client_ip cmd state =
    match cmd with
    | Ehlo domain ->
      let tls_active = match state with
        | Initial -> false
        | Greeted { tls_active; _ } -> tls_active
        | Authenticated { tls_active; _ } -> tls_active
        | Mail_from_accepted { tls_active; _ } -> tls_active
        | Rcpt_to_accepted { tls_active; _ } -> tls_active
        | Data_mode { tls_active; _ } -> tls_active
        | Quit -> false
      in
      (handle_ehlo t flow domain ~tls_active state, Continue)
    | Helo domain ->
      let tls_active = match state with
        | Initial -> false
        | Greeted { tls_active; _ } -> tls_active
        | Authenticated { tls_active; _ } -> tls_active
        | Mail_from_accepted { tls_active; _ } -> tls_active
        | Rcpt_to_accepted { tls_active; _ } -> tls_active
        | Data_mode { tls_active; _ } -> tls_active
        | Quit -> false
      in
      (handle_helo t flow domain ~tls_active state, Continue)
    | Mail_from { reverse_path; params } ->
      (handle_mail_from t flow reverse_path params state, Continue)
    | Rcpt_to { forward_path; params } ->
      (handle_rcpt_to t flow forward_path params state, Continue)
    | Data ->
      (handle_data t flow ~read_line ~client_ip state, Continue)
    | Rset ->
      (handle_rset flow state, Continue)
    | Noop _ ->
      (handle_noop flow state, Continue)
    | Vrfy arg ->
      (handle_vrfy flow arg state, Continue)
    | Expn _ ->
      send_response flow (perm_failure ~text:"EXPN command disabled" ());
      (state, Continue)
    | Help _ ->
      send_response flow (ok ~text:"See RFC 5321 for protocol details" ());
      (state, Continue)
    | Quit ->
      (handle_quit t flow, Close)
    | Auth { mechanism; initial_response } ->
      (handle_auth t flow mechanism initial_response ~read_line state, Continue)
    | Starttls ->
      handle_starttls t flow state

  (** Maximum line length to prevent DoS *)
  let max_line_length = 65536

  (** Read a line from the client *)
  let read_line flow =
    let buf = Buffer.create 256 in
    let cs = Cstruct.create 1 in
    let rec loop () =
      try
        if Buffer.length buf > max_line_length then
          None
        else
          let n = Eio.Flow.single_read flow cs in
          if n = 0 then
            None
          else begin
            let c = Cstruct.get_char cs 0 in
            Buffer.add_char buf c;
            if c = '\n' && Buffer.length buf >= 2 &&
               Buffer.nth buf (Buffer.length buf - 2) = '\r' then
              Some (Buffer.contents buf)
            else
              loop ()
          end
      with End_of_file ->
        if Buffer.length buf > 0 then Some (Buffer.contents buf) else None
    in
    loop ()

  (** Extract IP address from socket address *)
  let addr_to_ip = function
    | `Tcp (ip, _port) -> Format.asprintf "%a" Eio.Net.Ipaddr.pp ip
    | `Unix _ -> "127.0.0.1"
    | _ -> "unknown"

  (** Main command loop *)
  let rec command_loop t flow ~client_ip state =
    let read_line_fn () = read_line flow in
    match state with
    | Quit -> `Done
    | _ ->
      match read_line flow with
      | None -> `Done
      | Some line ->
        match parse_command line with
        | Error msg ->
          send_response flow (syntax_error ~text:msg ());
          command_loop t flow ~client_ip state
        | Ok cmd ->
          let (new_state, action) = handle_command t flow ~read_line:read_line_fn ~client_ip cmd state in
          match action with
          | Continue -> command_loop t flow ~client_ip new_state
          | Close -> `Done
          | Upgrade_tls -> `Upgrade_tls new_state

  (** Internal connection handler *)
  let handle_connection_internal t flow ~client_ip ~tls_active:_ ~send_greeting:should_greet =
    if should_greet then send_greeting t flow;
    let initial_state = Initial in
    command_loop t flow ~client_ip initial_state

  (** Connection handler for cleartext connections *)
  let handle_connection t flow addr =
    let client_ip = addr_to_ip addr in
    Eio.traceln "SMTP: connection from %s" client_ip;
    match handle_connection_internal t flow ~client_ip ~tls_active:false ~send_greeting:true with
    | `Done -> ()
    | `Upgrade_tls _state ->
      match t.config.tls_config with
      | None -> ()
      | Some tls_config ->
        let tls_flow = Tls_eio.server_of_flow tls_config flow in
        (* After STARTTLS, client must re-issue EHLO *)
        ignore (command_loop t (tls_flow :> _ Eio.Flow.two_way) ~client_ip
                  (Greeted { client_domain = "unknown"; tls_active = true }))

  (** Connection handler for implicit TLS *)
  let handle_connection_tls t tls_flow addr =
    let client_ip = addr_to_ip addr in
    Eio.traceln "SMTP: TLS connection from %s" client_ip;
    ignore (handle_connection_internal t (tls_flow :> _ Eio.Flow.two_way)
              ~client_ip ~tls_active:true ~send_greeting:true)

  (** Run server on cleartext port *)
  let run t ~sw ~net ~addr ?(after_bind = fun () -> ()) () =
    let socket = Eio.Net.listen net ~sw ~reuse_addr:true ~backlog:128 addr in
    after_bind ();
    let rec accept_loop () =
      Eio.Net.accept_fork socket ~sw
        ~on_error:(fun exn -> Eio.traceln "Connection error: %a" Fmt.exn exn)
        (fun flow addr -> handle_connection t flow addr);
      accept_loop ()
    in
    accept_loop ()

  (** Run server on TLS port *)
  let run_tls t ~sw ~net ~addr ~tls_config ?(after_bind = fun () -> ()) () =
    let socket = Eio.Net.listen net ~sw ~reuse_addr:true ~backlog:128 addr in
    after_bind ();
    let rec accept_loop () =
      Eio.Net.accept_fork socket ~sw
        ~on_error:(fun exn -> Eio.traceln "Connection error: %a" Fmt.exn exn)
        (fun flow addr ->
           let tls_flow = Tls_eio.server_of_flow tls_config flow in
           handle_connection_tls t tls_flow addr);
      accept_loop ()
    in
    accept_loop ()

  (** Drop privileges to authenticated user *)
  let drop_to_user username =
    try
      let pw = Unix.getpwnam username in
      Unix.initgroups username pw.Unix.pw_gid;
      Unix.setgid pw.Unix.pw_gid;
      Unix.setuid pw.Unix.pw_uid;
      true
    with
    | Not_found -> false
    | Unix.Unix_error _ -> false

  (** Convert Unix sockaddr to IP string *)
  let unix_addr_to_ip = function
    | Unix.ADDR_INET (inet_addr, _) -> Unix.string_of_inet_addr inet_addr
    | Unix.ADDR_UNIX _ -> "127.0.0.1"

  (** Fork-based connection handler for privilege separation *)
  let handle_connection_forked t flow ~client_ip ~tls_active =
    Eio.traceln "SMTP: %sconnection from %s (forked)" (if tls_active then "TLS " else "") client_ip;
    send_greeting t flow;
    (* Run initial authentication loop as root *)
    let rec session_loop state =
      let read_line_fn () = read_line flow in
      match state with
      | Quit -> ()
      | Authenticated { username; client_domain; tls_active } ->
        (* Drop privileges after authentication *)
        if drop_to_user username then begin
          (* Continue as authenticated user *)
          ignore (command_loop t flow ~client_ip (Authenticated { username; client_domain; tls_active }))
        end else begin
          send_response flow (temp_failure ~text:"Internal error" ());
          ()
        end
      | _ ->
        match read_line flow with
        | None -> ()
        | Some line ->
          match parse_command line with
          | Error msg ->
            send_response flow (syntax_error ~text:msg ());
            session_loop state
          | Ok cmd ->
            let (new_state, action) = handle_command t flow ~read_line:read_line_fn ~client_ip cmd state in
            match action with
            | Close -> ()
            | Upgrade_tls ->
              send_response flow (perm_failure ~text:"STARTTLS not supported in this mode" ());
              session_loop state
            | Continue -> session_loop new_state
    in
    session_loop Initial

  (** Run server with fork-per-connection *)
  let run_forked t ~sw:_ ~net:_ ~addr ~tls_config =
    let port, bind_addr = match addr with
      | `Tcp (ip, port) ->
        let addr_str =
          if ip = Eio.Net.Ipaddr.V4.loopback then "127.0.0.1"
          else if ip = Eio.Net.Ipaddr.V4.any then "0.0.0.0"
          else Format.asprintf "%a" Eio.Net.Ipaddr.pp ip
        in
        (port, Unix.inet_addr_of_string addr_str)
      | _ -> failwith "Only TCP addresses supported"
    in

    let sock = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
    Unix.setsockopt sock Unix.SO_REUSEADDR true;
    Unix.bind sock (Unix.ADDR_INET (bind_addr, port));
    Unix.listen sock 128;

    (* Reap zombie children *)
    Sys.set_signal Sys.sigchld (Sys.Signal_handle (fun _ ->
      try while fst (Unix.waitpid [Unix.WNOHANG] (-1)) > 0 do () done
      with Unix.Unix_error (Unix.ECHILD, _, _) -> ()
    ));

    let rec accept_with_retry () =
      try Unix.accept sock
      with Unix.Unix_error (Unix.EINTR, _, _) -> accept_with_retry ()
    in

    while true do
      let client_sock, client_addr = accept_with_retry () in
      let client_ip = unix_addr_to_ip client_addr in
      match Unix.fork () with
      | 0 ->
        Unix.close sock;
        Eio_main.run @@ fun env ->
        Eio.Switch.run @@ fun sw ->
        (* Create fresh DNS resolver in child process to avoid EADDRINUSE *)
        let net = Eio.Stdenv.net env in
        let fresh_t = { t with dns = Smtp_dns.create ~net } in
        let flow = Eio_unix.Net.import_socket_stream ~sw ~close_unix:true client_sock in
        (match tls_config with
         | None ->
           handle_connection_forked fresh_t flow ~client_ip ~tls_active:false
         | Some tls_cfg ->
           let tls_flow = Tls_eio.server_of_flow tls_cfg flow in
           handle_connection_forked fresh_t (tls_flow :> _ Eio.Flow.two_way) ~client_ip ~tls_active:true);
        exit 0
      | _pid ->
        Unix.close client_sock
    done
end
