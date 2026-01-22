(** SMTP Server Entry Point

    Implements {{:https://datatracker.ietf.org/doc/html/rfc5321}RFC 5321} SMTP server.

    Default ports:
    - 25: MTA-to-MTA (cleartext with STARTTLS)
    - 587: Submission (cleartext with STARTTLS, AUTH required)
    - 465: Implicit TLS per {{:https://datatracker.ietf.org/doc/html/rfc8314}RFC 8314} *)

open Cmdliner

(* Load TLS configuration from certificate and key files *)
let load_tls_config ~cert_file ~key_file =
  let cert_pem = In_channel.with_open_bin cert_file In_channel.input_all in
  let key_pem = In_channel.with_open_bin key_file In_channel.input_all in
  let certs = X509.Certificate.decode_pem_multiple cert_pem in
  let key = X509.Private_key.decode_pem key_pem in
  match certs, key with
  | Ok certs, Ok key ->
    let cert = `Single (certs, key) in
    (* Require TLS 1.2+ per RFC 8996 (TLS 1.0/1.1 are deprecated) *)
    (match Tls.Config.server ~version:(`TLS_1_2, `TLS_1_3) ~certificates:cert () with
     | Ok config -> Some config
     | Error _ -> None)
  | _ -> None

(* Parse IP address *)
let parse_ipaddr host =
  match host with
  | "127.0.0.1" | "localhost" -> Eio.Net.Ipaddr.V4.loopback
  | "0.0.0.0" -> Eio.Net.Ipaddr.V4.any
  | _ ->
    match String.split_on_char '.' host with
    | [a; b; c; d] ->
      let bytes = Bytes.create 4 in
      Bytes.set bytes 0 (Char.chr (int_of_string a));
      Bytes.set bytes 1 (Char.chr (int_of_string b));
      Bytes.set bytes 2 (Char.chr (int_of_string c));
      Bytes.set bytes 3 (Char.chr (int_of_string d));
      Eio.Net.Ipaddr.of_raw (Bytes.to_string bytes)
    | _ -> Eio.Net.Ipaddr.V4.loopback

(* Run the server with memory queue - single process mode *)
let run_single_memory ~port ~host ~tls_config ~implicit_tls ~local_domains ~require_auth ~dkim_config =
  let module Server = Smtp_server.Make(Smtp_queue.Memory_queue)(Smtp_auth.Pam_auth) in
  let module Qmgr = Smtp_qmgr.Make(Smtp_queue.Memory_queue) in
  Eio_main.run @@ fun env ->
  let net = Eio.Stdenv.net env in
  let dns = Smtp_dns.create ~net in
  let queue = Smtp_queue.Memory_queue.create () in
  let auth = Smtp_auth.Pam_auth.create ~service_name:"smtpd" in
  let qmgr = Smtp_qmgr.create ~local_domains ~dns ?dkim_config () in

  let config = {
    Smtp_server.default_config with
    hostname = host;
    local_domains;
    require_auth_for_relay = require_auth;
    tls_config;
  } in
  let server = Server.create ~config ~queue ~auth ~net in

  let tls_mode = if implicit_tls then " (implicit TLS)"
    else if tls_config <> None then " (STARTTLS available)" else "" in
  Eio.traceln "SMTP server starting on %s:%d (memory queue, single-process)%s" host port tls_mode;
  Eio.traceln "Local domains: %s" (String.concat ", " local_domains);
  Eio.traceln "Relay policy: %s" (if require_auth then "authentication required" else "open relay (DANGEROUS)");

  Eio.Switch.run @@ fun sw ->
  (* Start queue manager in background *)
  Qmgr.run_eio qmgr queue ~sw;

  let ipaddr = parse_ipaddr host in
  let addr = `Tcp (ipaddr, port) in
  if implicit_tls then
    match tls_config with
    | Some tls -> Server.run_tls server ~sw ~net ~addr ~tls_config:tls ()
    | None -> failwith "TLS config required for implicit TLS"
  else
    Server.run server ~sw ~net ~addr ()

(* Run the server with file queue - single process mode *)
let run_single_file ~port ~host ~tls_config ~implicit_tls ~local_domains ~require_auth ~queue_path ~dkim_config =
  let module Server = Smtp_server.Make(Smtp_queue.File_queue)(Smtp_auth.Pam_auth) in
  let module Qmgr = Smtp_qmgr.Make(Smtp_queue.File_queue) in
  Eio_main.run @@ fun env ->
  let net = Eio.Stdenv.net env in
  let dns = Smtp_dns.create ~net in
  let queue = Smtp_queue.File_queue.create_with_path ~base_path:queue_path in
  let auth = Smtp_auth.Pam_auth.create ~service_name:"smtpd" in
  let qmgr = Smtp_qmgr.create ~local_domains ~dns ?dkim_config () in

  let config = {
    Smtp_server.default_config with
    hostname = host;
    local_domains;
    require_auth_for_relay = require_auth;
    tls_config;
  } in
  let server = Server.create ~config ~queue ~auth ~net in

  let tls_mode = if implicit_tls then " (implicit TLS)"
    else if tls_config <> None then " (STARTTLS available)" else "" in
  Eio.traceln "SMTP server starting on %s:%d (%s, single-process)%s" host port queue_path tls_mode;
  Eio.traceln "Local domains: %s" (String.concat ", " local_domains);
  Eio.traceln "Relay policy: %s" (if require_auth then "authentication required" else "open relay (DANGEROUS)");

  Eio.Switch.run @@ fun sw ->
  (* Start queue manager in background *)
  Qmgr.run_eio qmgr queue ~sw;

  let ipaddr = parse_ipaddr host in
  let addr = `Tcp (ipaddr, port) in
  if implicit_tls then
    match tls_config with
    | Some tls -> Server.run_tls server ~sw ~net ~addr ~tls_config:tls ()
    | None -> failwith "TLS config required for implicit TLS"
  else
    Server.run server ~sw ~net ~addr ()

(* Run the server with file queue - forked mode with per-user privileges *)
let run_forked ~port ~host ~tls_config ~local_domains ~require_auth ~queue_path ~dkim_config =
  let module Server = Smtp_server.Make(Smtp_queue.File_queue)(Smtp_auth.Pam_auth) in
  let module Qmgr = Smtp_qmgr.Make(Smtp_queue.File_queue) in

  let tls_mode = if tls_config <> None then " (implicit TLS)" else "" in
  Printf.eprintf "+SMTP server starting on %s:%d (%s, fork-per-connection)%s\n%!" host port queue_path tls_mode;
  Printf.eprintf "+Local domains: %s\n%!" (String.concat ", " local_domains);
  Printf.eprintf "+Relay policy: %s\n%!" (if require_auth then "authentication required" else "open relay (DANGEROUS)");

  (* Fork a separate process for queue manager *)
  (match Unix.fork () with
   | 0 ->
     (* Child: run queue manager *)
     Eio_main.run @@ fun env ->
     let net = Eio.Stdenv.net env in
     let dns = Smtp_dns.create ~net in
     let queue = Smtp_queue.File_queue.create_with_path ~base_path:queue_path in
     let qmgr = Smtp_qmgr.create ~local_domains ~dns ?dkim_config () in
     Eio.Switch.run @@ fun sw ->
     Qmgr.run_eio qmgr queue ~sw;
     (* Keep running until stopped *)
     while true do Unix.sleep 3600 done
   | _pid ->
     (* Parent: run SMTP server *)
     Eio_main.run @@ fun env ->
     let net = Eio.Stdenv.net env in
     let queue = Smtp_queue.File_queue.create_with_path ~base_path:queue_path in
     let auth = Smtp_auth.Pam_auth.create ~service_name:"smtpd" in
     let config = {
       Smtp_server.default_config with
       hostname = host;
       local_domains;
       require_auth_for_relay = require_auth;
       tls_config;
     } in
     let server = Server.create ~config ~queue ~auth ~net in
     Eio.Switch.run @@ fun sw ->
     let ipaddr = parse_ipaddr host in
     let addr = `Tcp (ipaddr, port) in
     Server.run_forked server ~sw ~net ~addr ~tls_config)

(* Main entry point *)
let run port host cert_file key_file implicit_tls forked local_domains require_auth queue_path
    dkim_key_file dkim_domain dkim_selector =
  (* Initialize cryptographic RNG for TLS *)
  Mirage_crypto_rng_unix.use_default ();

  (* Forked mode requires implicit TLS (STARTTLS not supported) *)
  if forked && not implicit_tls && (cert_file <> None || key_file <> None) then begin
    Printf.eprintf "Warning: STARTTLS not supported in forked mode. Use --tls for implicit TLS.\n%!";
  end;

  (* Check that cert and key are provided if implicit TLS is enabled *)
  if implicit_tls && (cert_file = None || key_file = None) then begin
    Printf.eprintf "Error: --cert and --key are required when using --tls\n";
    exit 1
  end;

  (* Load TLS config if cert and key provided *)
  let tls_config =
    match cert_file, key_file with
    | Some cert, Some key -> load_tls_config ~cert_file:cert ~key_file:key
    | _ -> None
  in

  (* Verify TLS config loaded successfully if implicit TLS is enabled *)
  if implicit_tls && tls_config = None then begin
    Printf.eprintf "Error: Failed to load TLS certificate or key\n";
    exit 1
  end;

  (* Load DKIM signing config if provided *)
  let dkim_config =
    match dkim_key_file, dkim_domain, dkim_selector with
    | Some key_file, Some domain, Some selector ->
      (match Smtp_dkim.load_signing_config ~key_file ~domain ~selector () with
       | Ok config ->
         Printf.eprintf "DKIM signing enabled for domain %s (selector: %s)\n%!" domain selector;
         Some config
       | Error msg ->
         Printf.eprintf "Error loading DKIM key: %s\n" msg;
         exit 1)
    | Some _, _, _ ->
      Printf.eprintf "Error: --dkim-key requires --dkim-domain and --dkim-selector\n";
      exit 1
    | None, Some _, _ | None, _, Some _ ->
      Printf.eprintf "Error: --dkim-domain and --dkim-selector require --dkim-key\n";
      exit 1
    | None, None, None -> None
  in

  (* Warn about open relay if no auth required *)
  if not require_auth then begin
    Printf.eprintf "WARNING: Running as open relay! This is dangerous.\n%!";
    Printf.eprintf "WARNING: Use --require-auth to enforce authentication for relay.\n%!";
  end;

  (* Warn if no local domains configured *)
  if local_domains = [] then begin
    Printf.eprintf "Warning: No local domains configured. Use --local-domains.\n%!";
  end;

  match forked, queue_path with
  | true, _ -> run_forked ~port ~host ~tls_config ~local_domains ~require_auth ~queue_path ~dkim_config
  | false, "" -> run_single_memory ~port ~host ~tls_config ~implicit_tls ~local_domains ~require_auth ~dkim_config
  | false, _ -> run_single_file ~port ~host ~tls_config ~implicit_tls ~local_domains ~require_auth ~queue_path ~dkim_config

(* Command-line arguments *)
let port =
  let doc = "Port to listen on (default: 25 for cleartext, 465 for TLS)." in
  Arg.(value & opt int 25 & info ["p"; "port"] ~docv:"PORT" ~doc)

let host =
  let doc = "Host address to bind to." in
  Arg.(value & opt string "127.0.0.1" & info ["h"; "host"] ~docv:"HOST" ~doc)

let cert_file =
  let doc = "TLS certificate file (PEM format). Required for --tls." in
  Arg.(value & opt (some string) None & info ["cert"] ~docv:"FILE" ~doc)

let key_file =
  let doc = "TLS private key file (PEM format). Required for --tls." in
  Arg.(value & opt (some string) None & info ["key"] ~docv:"FILE" ~doc)

let implicit_tls =
  let doc = "Enable implicit TLS (RFC 8314). TLS starts immediately on connection. Requires --cert and --key." in
  Arg.(value & flag & info ["tls"] ~doc)

let forked =
  let doc = "Fork a new process for each connection and drop privileges to the \
             authenticated user after login. Provides strong per-user isolation. \
             Requires running as root." in
  Arg.(value & flag & info ["fork"] ~doc)

let local_domains =
  let doc = "Comma-separated list of local domains to accept mail for." in
  Arg.(value & opt (list string) [] & info ["local-domains"] ~docv:"DOMAINS" ~doc)

let require_auth =
  let doc = "Require authentication to relay to external domains (closed relay). \
             STRONGLY RECOMMENDED for production." in
  Arg.(value & flag & info ["require-auth"] ~doc)

let queue_path =
  let doc = "Base path for message queue storage. When specified, enables persistent file-based queue instead of in-memory queue." in
  Arg.(value & opt string "" & info ["queue-path"] ~docv:"PATH" ~doc)

let dkim_key =
  let doc = "DKIM private key file (PEM format) for signing outbound messages." in
  Arg.(value & opt (some string) None & info ["dkim-key"] ~docv:"FILE" ~doc)

let dkim_domain =
  let doc = "Domain for DKIM signing (d= tag). Required with --dkim-key." in
  Arg.(value & opt (some string) None & info ["dkim-domain"] ~docv:"DOMAIN" ~doc)

let dkim_selector =
  let doc = "Selector for DKIM signing (s= tag). Required with --dkim-key." in
  Arg.(value & opt (some string) None & info ["dkim-selector"] ~docv:"SELECTOR" ~doc)

let cmd =
  let doc = "SMTP server (RFC 5321)" in
  let man = [
    `S Manpage.s_description;
    `P "An SMTP server (RFC 5321) implemented in OCaml with closed relay enforcement.";
    `S Manpage.s_options;
    `S "SECURITY";
    `P "$(b,Closed Relay): By default with --require-auth, only authenticated users \
        can send mail to external domains. Unauthenticated users can only deliver \
        to local domains. This prevents your server from being used as a spam relay.";
    `P "$(b,IMPORTANT): Without --require-auth, the server runs as an open relay. \
        This is dangerous and will result in your server being used for spam.";
    `S "OPERATING MODES";
    `P "$(b,Single-process) (default) - All connections handled in one process. \
        Efficient but all sessions share the same privileges.";
    `P "$(b,Fork-per-connection) (--fork) - Each connection forks a child process. \
        After authentication, the child drops privileges to the authenticated user. \
        Requires running as root.";
    `S "TLS MODES";
    `P "$(b,STARTTLS) (default) - Start cleartext, upgrade to TLS via STARTTLS command. \
        Provide --cert and --key to enable. Not supported with --fork.";
    `P "$(b,Implicit TLS) (--tls) - TLS starts immediately on connection per RFC 8314. \
        Typically used on port 465. Recommended for --fork mode.";
    `S "DKIM SIGNING";
    `P "DKIM (DomainKeys Identified Mail) signing adds a cryptographic signature to \
        outbound messages, allowing receiving servers to verify the message was \
        authorized by your domain.";
    `P "To enable DKIM signing, provide --dkim-key, --dkim-domain, and --dkim-selector. \
        You must also publish the corresponding public key in DNS as a TXT record at \
        $(i,selector)._domainkey.$(i,domain).";
    `S Manpage.s_examples;
    `P "Development server (memory queue, no TLS):";
    `Pre "  $(tname) -p 2525 --local-domains example.com";
    `P "Production submission server (port 587, auth required):";
    `Pre "  $(tname) -p 587 --local-domains example.com --require-auth \\
      --cert server.crt --key server.key";
    `P "Production server with fork-per-connection and DKIM signing:";
    `Pre "  sudo $(tname) --fork --tls -p 465 \\
      --local-domains example.com,example.org \\
      --require-auth \\
      --cert server.crt --key server.key \\
      --queue-path /var/spool/smtpd \\
      --dkim-key /etc/smtpd/dkim.key \\
      --dkim-domain example.com \\
      --dkim-selector mail";
    `S Manpage.s_bugs;
    `P "Report bugs at https://github.com/mtelvers/ocaml-smtpd/issues";
  ] in
  let info = Cmd.info "smtpd" ~version:"0.1.0" ~doc ~man in
  Cmd.v info Term.(const run $ port $ host $ cert_file $ key_file $ implicit_tls
                   $ forked $ local_domains $ require_auth $ queue_path
                   $ dkim_key $ dkim_domain $ dkim_selector)

let () = exit (Cmd.eval cmd)
