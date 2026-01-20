(** DKIM Verification - RFC 6376

    DomainKeys Identified Mail signature verification to confirm
    that an email was authorized by the domain owner. *)

open Smtp_dns

(** DKIM verification result *)
type dkim_result =
  | Dkim_pass of string       (** Verified, includes domain *)
  | Dkim_fail of string       (** Signature invalid *)
  | Dkim_temperror of string  (** Temporary error (DNS) *)
  | Dkim_permerror of string  (** Permanent error (syntax/key) *)
  | Dkim_none                 (** No signature present *)

(** DKIM signature algorithm *)
type algorithm =
  | Rsa_sha256
  | Rsa_sha1

(** Canonicalization method *)
type canonicalization = Simple | Relaxed

(** Parsed DKIM-Signature header *)
type dkim_signature = {
  version : int;                    (** v= (must be 1) *)
  algorithm : algorithm;            (** a= *)
  signature : string;               (** b= (base64 decoded) *)
  body_hash : string;               (** bh= (base64 decoded) *)
  header_canon : canonicalization;  (** c= header part *)
  body_canon : canonicalization;    (** c= body part *)
  domain : string;                  (** d= *)
  signed_headers : string list;     (** h= *)
  selector : string;                (** s= *)
  timestamp : int64 option;         (** t= *)
  expiration : int64 option;        (** x= *)
  body_length : int option;         (** l= *)
}

(** Parse algorithm from string *)
let parse_algorithm s =
  match String.lowercase_ascii s with
  | "rsa-sha256" -> Some Rsa_sha256
  | "rsa-sha1" -> Some Rsa_sha1
  | _ -> None

(** Parse canonicalization from string *)
let parse_canonicalization s =
  match String.split_on_char '/' (String.lowercase_ascii s) with
  | [h] -> Some (
      (if h = "relaxed" then Relaxed else Simple),
      Simple)  (* Default body canon is simple *)
  | [h; b] -> Some (
      (if h = "relaxed" then Relaxed else Simple),
      (if b = "relaxed" then Relaxed else Simple))
  | _ -> None

(** Remove whitespace from base64 string *)
let clean_base64 s =
  let buf = Buffer.create (String.length s) in
  String.iter (fun c ->
    if c <> ' ' && c <> '\t' && c <> '\r' && c <> '\n' then
      Buffer.add_char buf c
  ) s;
  Buffer.contents buf

(** Parse a tag=value pair *)
let parse_tag_value s =
  match String.index_opt s '=' with
  | None -> None
  | Some i ->
    let tag = String.trim (String.sub s 0 i) in
    let value = String.trim (String.sub s (i + 1) (String.length s - i - 1)) in
    Some (tag, value)

(** Parse DKIM-Signature header value into tag-value pairs *)
let parse_signature_tags value =
  let parts = String.split_on_char ';' value in
  List.filter_map parse_tag_value parts

(** Parse DKIM-Signature header *)
let parse_dkim_signature header_value =
  let tags = parse_signature_tags header_value in
  let get tag = List.assoc_opt tag tags in

  (* Required tags *)
  match get "v", get "a", get "b", get "bh", get "d", get "h", get "s" with
  | Some v, Some a, Some b, Some bh, Some d, Some h, Some s ->
    let version = try int_of_string v with _ -> 0 in
    if version <> 1 then
      Error "Invalid DKIM version (must be 1)"
    else
      (match parse_algorithm a with
       | None -> Error ("Unknown algorithm: " ^ a)
       | Some algorithm ->
         let (header_canon, body_canon) =
           match get "c" with
           | Some c ->
             (match parse_canonicalization c with
              | Some (h, b) -> (h, b)
              | None -> (Simple, Simple))
           | None -> (Simple, Simple)
         in
         let signed_headers =
           String.split_on_char ':' h
           |> List.map String.trim
           |> List.map String.lowercase_ascii
         in
         try
           let signature = Base64.decode_exn (clean_base64 b) in
           let body_hash = Base64.decode_exn (clean_base64 bh) in
           Ok {
             version;
             algorithm;
             signature;
             body_hash;
             header_canon;
             body_canon;
             domain = String.lowercase_ascii d;
             signed_headers;
             selector = s;
             timestamp = (match get "t" with
                 | Some t -> (try Some (Int64.of_string t) with _ -> None)
                 | None -> None);
             expiration = (match get "x" with
                 | Some x -> (try Some (Int64.of_string x) with _ -> None)
                 | None -> None);
             body_length = (match get "l" with
                 | Some l -> (try Some (int_of_string l) with _ -> None)
                 | None -> None);
           }
         with _ -> Error "Invalid base64 in signature")
  | _ -> Error "Missing required DKIM tags"

(** Simple canonicalization for headers *)
let canon_header_simple name value =
  name ^ ":" ^ value

(** Relaxed canonicalization for headers - RFC 6376 Section 3.4.2 *)
let canon_header_relaxed name value =
  (* Convert header name to lowercase *)
  let name = String.lowercase_ascii name in
  (* Unfold header value and compress whitespace *)
  let value = Str.global_replace (Str.regexp "[\r\n\t ]+") " " value in
  let value = String.trim value in
  name ^ ":" ^ value

(** Canonicalize a header *)
let canonicalize_header canon name value =
  match canon with
  | Simple -> canon_header_simple name value
  | Relaxed -> canon_header_relaxed name value

(** Normalize line endings to CRLF *)
let normalize_line_endings s =
  (* First normalize CRLF to LF, then convert all LF to CRLF *)
  let s = Str.global_replace (Str.regexp "\r\n") "\n" s in
  Str.global_replace (Str.regexp "\n") "\r\n" s

(** Simple canonicalization for body - RFC 6376 Section 3.4.3 *)
let canon_body_simple body =
  (* Normalize line endings first *)
  let body = normalize_line_endings body in
  (* Remove trailing empty lines, ensure single CRLF at end *)
  let lines = Str.split (Str.regexp "\r\n") body in
  let rec remove_trailing = function
    | [] -> []
    | [""] -> []
    | "" :: rest ->
      let rest' = remove_trailing rest in
      if rest' = [] then [] else "" :: rest'
    | line :: rest -> line :: remove_trailing rest
  in
  let lines = remove_trailing lines in
  if lines = [] then "\r\n"
  else String.concat "\r\n" lines ^ "\r\n"

(** Relaxed canonicalization for body - RFC 6376 Section 3.4.4 *)
let canon_body_relaxed body =
  (* Normalize line endings first *)
  let body = normalize_line_endings body in
  let lines = Str.split (Str.regexp "\r\n") body in
  let lines = List.map (fun line ->
    (* Replace sequences of WSP with single space *)
    let line = Str.global_replace (Str.regexp "[ \t]+") " " line in
    (* Remove trailing whitespace *)
    String.trim line
  ) lines in
  (* Remove trailing empty lines *)
  let rec remove_trailing = function
    | [] -> []
    | [""] -> []
    | "" :: rest ->
      let rest' = remove_trailing rest in
      if rest' = [] then [] else "" :: rest'
    | line :: rest -> line :: remove_trailing rest
  in
  let lines = remove_trailing lines in
  if lines = [] then "\r\n"
  else String.concat "\r\n" lines ^ "\r\n"

(** Canonicalize body *)
let canonicalize_body canon body =
  match canon with
  | Simple -> canon_body_simple body
  | Relaxed -> canon_body_relaxed body

(** Compute body hash *)
let compute_body_hash algorithm body =
  match algorithm with
  | Rsa_sha256 ->
    Digestif.SHA256.digest_string body |> Digestif.SHA256.to_raw_string
  | Rsa_sha1 ->
    Digestif.SHA1.digest_string body |> Digestif.SHA1.to_raw_string

(** Parse a header line into name and value *)
let parse_header_line line =
  match String.index_opt line ':' with
  | None -> None
  | Some i ->
    let name = String.sub line 0 i in
    let value = String.sub line (i + 1) (String.length line - i - 1) in
    Some (String.trim name, value)

(** Find headers by name (case-insensitive), in reverse order for DKIM *)
let find_headers name headers =
  let name_lower = String.lowercase_ascii name in
  List.filter_map (fun (n, v) ->
    if String.lowercase_ascii n = name_lower then Some (n, v)
    else None
  ) headers
  |> List.rev  (* DKIM uses bottom-up for duplicate headers *)

(** Parse raw headers string into list of (name, value) pairs *)
let parse_headers raw_headers =
  (* Split on CRLF, handling folded headers *)
  let lines = Str.split (Str.regexp "\r\n") raw_headers in
  let rec parse acc current = function
    | [] ->
      (match current with
       | Some line -> List.rev (line :: acc)
       | None -> List.rev acc)
    | line :: rest when String.length line > 0 && (line.[0] = ' ' || line.[0] = '\t') ->
      (* Folded header continuation *)
      (match current with
       | Some curr -> parse acc (Some (curr ^ "\r\n" ^ line)) rest
       | None -> parse acc (Some line) rest)
    | line :: rest ->
      (match current with
       | Some curr -> parse (curr :: acc) (Some line) rest
       | None -> parse acc (Some line) rest)
  in
  let header_lines = parse [] None lines in
  List.filter_map parse_header_line header_lines

(** Look up DKIM public key from DNS *)
let lookup_dkim_key dns selector domain =
  let query_domain = selector ^ "._domainkey." ^ domain in
  match lookup_txt dns query_domain with
  | Error Not_found -> Error "No DKIM key record"
  | Error _ -> Error "DNS lookup failed"
  | Ok records ->
    (* Find the DKIM key record *)
    let dkim_records = List.filter (fun r ->
      String.lowercase_ascii r |> fun s ->
      try String.sub s 0 2 = "v=" || String.sub s 0 2 = "p=" || String.sub s 0 2 = "k="
      with _ -> true  (* Accept any TXT if short *)
    ) records in
    match dkim_records with
    | [] -> Error "No DKIM key record"
    | record :: _ ->
      (* Parse the key record *)
      let tags = parse_signature_tags record in
      let get tag = List.assoc_opt tag tags in
      (* Check version if present *)
      match get "v" with
      | Some v when v <> "DKIM1" -> Error "Invalid DKIM key version"
      | _ ->
        (* Check key type if present *)
        match get "k" with
        | Some k when k <> "rsa" -> Error ("Unsupported key type: " ^ k)
        | _ ->
          (* Get the public key *)
          match get "p" with
          | None -> Error "No public key in DKIM record"
          | Some "" -> Error "DKIM key revoked"
          | Some p ->
            try
              let key_data = Base64.decode_exn (clean_base64 p) in
              Ok key_data
            with _ -> Error "Invalid base64 in DKIM key"

(** Parse RSA public key from DER-encoded data *)
let parse_rsa_public_key der_data =
  try
    match X509.Public_key.decode_der der_data with
    | Ok (`RSA key) -> Ok key
    | Ok _ -> Error "Not an RSA key"
    | Error (`Msg msg) -> Error ("Key parse error: " ^ msg)
  with _ -> Error "Failed to parse public key"

(** Verify RSA signature *)
let verify_rsa_signature key algorithm data signature =
  let hash_type = match algorithm with
    | Rsa_sha256 -> `SHA256
    | Rsa_sha1 -> `SHA1
  in
  try
    let result = Mirage_crypto_pk.Rsa.PKCS1.verify ~hashp:(fun h -> h = hash_type)
        ~key ~signature (`Message data) in
    Ok result
  with e -> Error ("Signature verification error: " ^ Printexc.to_string e)

(** Remove b= value from DKIM-Signature for signature computation *)
let remove_signature_value dkim_header =
  (* Replace b=... with b= (empty value) *)
  Str.global_replace (Str.regexp "b=[^;]*") "b=" dkim_header

(** Verify a DKIM signature.

    @param dns DNS resolver
    @param raw_headers Raw email headers (including DKIM-Signature)
    @param body Email body
    @return DKIM verification result *)
let verify ~dns ~raw_headers ~body =
  (* Parse headers *)
  let headers = parse_headers raw_headers in

  (* Find DKIM-Signature header *)
  match find_headers "dkim-signature" headers with
  | [] -> Dkim_none
  | (dkim_name, dkim_value) :: _ ->
    (* Parse the signature *)
    match parse_dkim_signature dkim_value with
    | Error msg -> Dkim_permerror msg
    | Ok sig_info ->
      (* Check expiration *)
      (match sig_info.expiration with
       | Some exp when Int64.of_float (Unix.time ()) > exp ->
         Dkim_fail "Signature expired"
       | _ ->
         (* Canonicalize and hash body *)
         let canon_body = canonicalize_body sig_info.body_canon body in
         let canon_body = match sig_info.body_length with
           | Some l when l < String.length canon_body ->
             String.sub canon_body 0 l
           | _ -> canon_body
         in
         let computed_body_hash = compute_body_hash sig_info.algorithm canon_body in

         (* Verify body hash *)
         if computed_body_hash <> sig_info.body_hash then
           Dkim_fail "Body hash mismatch"
         else
           (* Look up public key *)
           match lookup_dkim_key dns sig_info.selector sig_info.domain with
           | Error msg -> Dkim_temperror msg
           | Ok key_data ->
             match parse_rsa_public_key key_data with
             | Error msg -> Dkim_permerror msg
             | Ok public_key ->
               (* Build header hash input *)
               let header_data = Buffer.create 1024 in

               (* Track which headers we've used (for duplicates) *)
               let used_headers = Hashtbl.create 16 in

               List.iter (fun h ->
                 let h_lower = String.lowercase_ascii h in
                 let count = try Hashtbl.find used_headers h_lower with Not_found -> 0 in
                 let matching = find_headers h headers in
                 if count < List.length matching then begin
                   let (name, value) = List.nth matching count in
                   Hashtbl.replace used_headers h_lower (count + 1);
                   let canon = canonicalize_header sig_info.header_canon name value in
                   Buffer.add_string header_data canon;
                   Buffer.add_string header_data "\r\n"
                 end
               ) sig_info.signed_headers;

               (* Add DKIM-Signature header (without trailing CRLF, with b= emptied) *)
               let dkim_header_clean = remove_signature_value (dkim_name ^ ":" ^ dkim_value) in
               let dkim_canon = canonicalize_header sig_info.header_canon "dkim-signature"
                   (String.sub dkim_header_clean 15 (String.length dkim_header_clean - 15)) in
               Buffer.add_string header_data dkim_canon;

               let data_to_verify = Buffer.contents header_data in

               (* Verify signature *)
               match verify_rsa_signature public_key sig_info.algorithm
                       data_to_verify sig_info.signature with
               | Error msg -> Dkim_temperror msg
               | Ok true -> Dkim_pass sig_info.domain
               | Ok false -> Dkim_fail "Signature verification failed")

(** Convert DKIM result to string *)
let result_to_string = function
  | Dkim_pass domain -> "pass (domain=" ^ domain ^ ")"
  | Dkim_fail reason -> "fail (" ^ reason ^ ")"
  | Dkim_temperror reason -> "temperror (" ^ reason ^ ")"
  | Dkim_permerror reason -> "permerror (" ^ reason ^ ")"
  | Dkim_none -> "none"

(** Format DKIM result for Authentication-Results header *)
let format_auth_results result =
  match result with
  | Dkim_pass domain ->
    Printf.sprintf "dkim=pass header.d=%s" domain
  | Dkim_fail reason ->
    Printf.sprintf "dkim=fail (%s)" reason
  | Dkim_temperror reason ->
    Printf.sprintf "dkim=temperror (%s)" reason
  | Dkim_permerror reason ->
    Printf.sprintf "dkim=permerror (%s)" reason
  | Dkim_none ->
    "dkim=none"

(** {1 DKIM Signing} *)

(** Default headers to sign per RFC 6376 recommendations *)
let default_sign_headers = [
  "from";           (* Required *)
  "to";
  "subject";
  "date";
  "message-id";
  "mime-version";
  "content-type";
  "content-transfer-encoding";
  "reply-to";
  "cc";
]

(** DKIM signing configuration *)
type signing_config = {
  private_key : Mirage_crypto_pk.Rsa.priv;
  domain : string;
  selector : string;
  sign_headers : string list;
  sign_algorithm : algorithm;
  header_canon : canonicalization;
  body_canon : canonicalization;
}

(** Parse RSA private key from PEM *)
let parse_private_key_pem pem =
  match X509.Private_key.decode_pem pem with
  | Ok (`RSA key) -> Ok key
  | Ok _ -> Error "Not an RSA private key"
  | Error (`Msg msg) -> Error ("Failed to parse private key: " ^ msg)

(** Create signing configuration from PEM string *)
let create_signing_config ~private_key_pem ~domain ~selector ?(headers = default_sign_headers) () =
  match parse_private_key_pem private_key_pem with
  | Error msg -> Error msg
  | Ok private_key ->
    Ok {
      private_key;
      domain = String.lowercase_ascii domain;
      selector;
      sign_headers = List.map String.lowercase_ascii headers;
      sign_algorithm = Rsa_sha256;
      header_canon = Relaxed;
      body_canon = Relaxed;
    }

(** Load signing configuration from key file *)
let load_signing_config ~key_file ~domain ~selector ?headers () =
  try
    let pem = In_channel.with_open_bin key_file In_channel.input_all in
    create_signing_config ~private_key_pem:pem ~domain ~selector ?headers ()
  with
  | Sys_error msg -> Error ("Failed to read key file: " ^ msg)
  | e -> Error ("Failed to load key: " ^ Printexc.to_string e)

(** Get algorithm string for DKIM-Signature *)
let algorithm_to_string = function
  | Rsa_sha256 -> "rsa-sha256"
  | Rsa_sha1 -> "rsa-sha1"

(** Get canonicalization string for DKIM-Signature *)
let canonicalization_to_string header body =
  let h = match header with Simple -> "simple" | Relaxed -> "relaxed" in
  let b = match body with Simple -> "simple" | Relaxed -> "relaxed" in
  h ^ "/" ^ b

(** Sign data with RSA private key *)
let rsa_sign key algorithm data =
  let hash_type = match algorithm with
    | Rsa_sha256 -> `SHA256
    | Rsa_sha1 -> `SHA1
  in
  try
    let signature = Mirage_crypto_pk.Rsa.PKCS1.sign ~hash:hash_type
        ~key (`Message data) in
    Ok signature
  with e -> Error ("Signing failed: " ^ Printexc.to_string e)

(** Fold a long header line for DKIM signatures.
    Only breaks after semicolons to avoid corrupting tag values like header names.
    This may result in lines longer than 76 chars, but RFC 6376 says folding
    is a SHOULD not a MUST, and corrupted headers are worse than long lines. *)
let fold_header_line line =
  (* Write to debug file to confirm this function is called *)
  (try
    let oc = open_out_gen [Open_creat; Open_append; Open_text] 0o644 "/tmp/fold_debug.log" in
    Printf.fprintf oc "fold_header_line called at %f\n" (Unix.gettimeofday ());
    Printf.fprintf oc "Input length: %d\n" (String.length line);
    close_out oc
  with _ -> ());
  let buf = Buffer.create (String.length line + 50) in
  let current_line_len = ref 0 in
  let i = ref 0 in
  while !i < String.length line do
    let c = line.[!i] in
    Buffer.add_char buf c;
    incr current_line_len;
    (* After a semicolon, check if we should fold *)
    if c = ';' && !i + 1 < String.length line then begin
      (* Look ahead to see how long until next semicolon or end *)
      let next_semi = ref (String.length line) in
      for j = !i + 1 to String.length line - 1 do
        if line.[j] = ';' && !next_semi = String.length line then
          next_semi := j
      done;
      let next_segment_len = !next_semi - !i in
      (* If adding next segment would make line too long, fold here *)
      if !current_line_len + next_segment_len > 76 then begin
        Buffer.add_string buf "\r\n\t";
        current_line_len := 1  (* Tab counts as 1 *)
      end
    end;
    incr i
  done;
  Buffer.contents buf

(** Sign a message and return the DKIM-Signature header.

    @param config Signing configuration
    @param headers Raw message headers
    @param body Message body
    @return DKIM-Signature header line *)
let sign ~config ~headers ~body =
  (* Parse headers *)
  let parsed_headers = parse_headers headers in

  (* Find which headers we can sign (must exist in message) *)
  let headers_to_sign =
    List.filter (fun h ->
      List.exists (fun (name, _) ->
        String.lowercase_ascii name = h
      ) parsed_headers
    ) config.sign_headers
  in

  (* Must sign From header *)
  if not (List.mem "from" headers_to_sign) then
    Error "Message missing required From header"
  else begin
    (* Canonicalize and hash body *)
    let canon_body = canonicalize_body config.body_canon body in
    let body_hash = compute_body_hash config.sign_algorithm canon_body in
    let body_hash_b64 = Base64.encode_string body_hash in

    (* Get current timestamp *)
    let timestamp = Int64.of_float (Unix.time ()) in

    (* Build DKIM-Signature header (without b= value) *)
    let dkim_header_template = Printf.sprintf
        "v=1; a=%s; c=%s; d=%s; s=%s; t=%Ld; h=%s; bh=%s; b="
        (algorithm_to_string config.sign_algorithm)
        (canonicalization_to_string config.header_canon config.body_canon)
        config.domain
        config.selector
        timestamp
        (String.concat ":" headers_to_sign)
        body_hash_b64
    in

    (* Build data to sign: canonicalized headers + DKIM-Signature header *)
    let sign_data = Buffer.create 2048 in

    (* Track which headers we've used (for duplicates) *)
    let used_headers = Hashtbl.create 16 in

    List.iter (fun h ->
      let h_lower = String.lowercase_ascii h in
      let count = try Hashtbl.find used_headers h_lower with Not_found -> 0 in
      let matching = find_headers h parsed_headers in
      if count < List.length matching then begin
        let (name, value) = List.nth matching count in
        Hashtbl.replace used_headers h_lower (count + 1);
        let canon = canonicalize_header config.header_canon name value in
        Buffer.add_string sign_data canon;
        Buffer.add_string sign_data "\r\n"
      end
    ) headers_to_sign;

    (* Add DKIM-Signature header for signing (without trailing CRLF) *)
    let dkim_canon = canonicalize_header config.header_canon
        "dkim-signature" dkim_header_template in
    Buffer.add_string sign_data dkim_canon;

    let data_to_sign = Buffer.contents sign_data in

    (* Sign *)
    match rsa_sign config.private_key config.sign_algorithm data_to_sign with
    | Error msg -> Error msg
    | Ok signature ->
      let signature_b64 = Base64.encode_string signature in
      let full_header = "DKIM-Signature: " ^ dkim_header_template ^ signature_b64 in
      Ok (fold_header_line full_header)
  end

(** Sign a complete message and return message with DKIM-Signature prepended *)
let sign_message ~config ~message =
  (* Split message into headers and body at blank line *)
  let header_end =
    match Str.search_forward (Str.regexp "\r\n\r\n") message 0 with
    | pos -> pos
    | exception Not_found ->
      match Str.search_forward (Str.regexp "\n\n") message 0 with
      | pos -> pos
      | exception Not_found -> String.length message
  in
  let headers = String.sub message 0 header_end in
  let body_start =
    if header_end + 4 <= String.length message &&
       String.sub message header_end 4 = "\r\n\r\n" then header_end + 4
    else if header_end + 2 <= String.length message then header_end + 2
    else String.length message
  in
  let body =
    if body_start < String.length message then
      String.sub message body_start (String.length message - body_start)
    else ""
  in

  match sign ~config ~headers ~body with
  | Error msg -> Error msg
  | Ok dkim_header ->
    (* Prepend DKIM-Signature to message *)
    Ok (dkim_header ^ "\r\n" ^ message)
