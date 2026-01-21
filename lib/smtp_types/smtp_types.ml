(** SMTP Types - RFC 5321 Core Types

    Implements types for {{:https://datatracker.ietf.org/doc/html/rfc5321}RFC 5321} SMTP protocol.

    Key security invariant: Closed relay enforcement - unauthenticated senders
    can only deliver to local domains. *)

(** {1 Email Address Types} *)

(** Local part of an email address (max 64 octets per RFC 5321 Section 4.5.3.1.1) *)
type local_part = string

(** Domain name (max 255 octets per RFC 5321 Section 4.5.3.1.2) *)
type domain = string

(** Complete email address *)
type email_address = {
  local_part : local_part;
  domain : domain;
}

(** Reverse-path (MAIL FROM sender). None represents null sender <> *)
type reverse_path = email_address option

(** Forward-path (RCPT TO recipient) *)
type forward_path = email_address

(** {1 SMTP Command Parameters} *)

(** MAIL FROM parameters - RFC 5321 Section 4.1.1.2 *)
type mail_param =
  | Size of int64                                    (** RFC 1870 SIZE extension *)
  | Body of [ `SevenBit | `EightBitMime | `BinaryMime ]  (** RFC 6152 8BITMIME *)
  | Auth_param of email_address option               (** RFC 4954 AUTH parameter *)
  | Unknown_param of string * string option          (** Unknown parameters - ignored *)

(** RCPT TO parameters - RFC 5321 Section 4.1.1.3 *)
type rcpt_param =
  | Notify of [ `Never | `Success | `Failure | `Delay ] list  (** DSN notifications *)
  | Orcpt of string                                          (** Original recipient *)

(** {1 SMTP Commands} *)

(** SMTP commands per RFC 5321 Section 4.1 *)
type smtp_command =
  | Ehlo of domain                    (** Extended HELO - RFC 5321 Section 4.1.1.1 *)
  | Helo of domain                    (** HELO - RFC 5321 Section 4.1.1.1 *)
  | Mail_from of {
      reverse_path : reverse_path;
      params : mail_param list;
    }                                 (** MAIL FROM - RFC 5321 Section 4.1.1.2 *)
  | Rcpt_to of {
      forward_path : forward_path;
      params : rcpt_param list;
    }                                 (** RCPT TO - RFC 5321 Section 4.1.1.3 *)
  | Data                              (** DATA - RFC 5321 Section 4.1.1.4 *)
  | Rset                              (** RSET - RFC 5321 Section 4.1.1.5 *)
  | Vrfy of string                    (** VRFY - RFC 5321 Section 4.1.1.6 *)
  | Expn of string                    (** EXPN - RFC 5321 Section 4.1.1.7 *)
  | Help of string option             (** HELP - RFC 5321 Section 4.1.1.8 *)
  | Noop of string option             (** NOOP - RFC 5321 Section 4.1.1.9 *)
  | Quit                              (** QUIT - RFC 5321 Section 4.1.1.10 *)
  | Starttls                          (** STARTTLS - RFC 3207 *)
  | Auth of {
      mechanism : string;
      initial_response : string option;
    }                                 (** AUTH - RFC 4954 *)

(** {1 Connection State Machine} *)

(** Connection state per RFC 5321 Section 3 state machine.

    State transitions:
    - Initial → Greeted (via EHLO/HELO)
    - Greeted → Authenticated (via AUTH) or Mail_from_accepted (via MAIL FROM)
    - Authenticated → Mail_from_accepted (via MAIL FROM)
    - Mail_from_accepted → Rcpt_to_accepted (via RCPT TO)
    - Rcpt_to_accepted → Data_mode (via DATA) or more recipients (via RCPT TO)
    - Data_mode → Greeted (after message received)
    - Any state → Greeted (via RSET)
    - Any state → Quit (via QUIT) *)
type connection_state =
  | Initial
      (** Before EHLO/HELO - only greeting sent *)
  | Greeted of { client_domain : domain; tls_active : bool }
      (** After EHLO/HELO - ready for STARTTLS, AUTH, or MAIL FROM *)
  | Authenticated of { username : string; client_domain : domain; tls_active : bool }
      (** After successful AUTH - can relay to external domains *)
  | Mail_from_accepted of {
      username : string option;
      client_domain : domain;
      sender : reverse_path;
      params : mail_param list;
      tls_active : bool;
    }
      (** After MAIL FROM accepted - waiting for RCPT TO *)
  | Rcpt_to_accepted of {
      username : string option;
      client_domain : domain;
      sender : reverse_path;
      recipients : forward_path list;
      params : mail_param list;
      tls_active : bool;
    }
      (** After at least one RCPT TO accepted - can add more or DATA *)
  | Data_mode of {
      username : string option;
      client_domain : domain;
      sender : reverse_path;
      recipients : forward_path list;
      tls_active : bool;
    }
      (** Receiving message body until <CRLF>.<CRLF> *)
  | Quit
      (** Connection closing *)

(** {1 SMTP Responses} *)

(** Reply code per RFC 5321 Section 4.2 (range 200-599) *)
type reply_code = int

(** Enhanced status code per RFC 3463 (class.subject.detail) *)
type enhanced_code = int * int * int

(** SMTP response *)
type smtp_response = {
  code : reply_code;
  enhanced_code : enhanced_code option;
  lines : string list;  (** Multi-line support - RFC 5321 Section 4.2.1 *)
}

(** {1 Message Queue Types} *)

(** Message queued for delivery *)
type queued_message = {
  id : string;                    (** Unique queue identifier *)
  sender : reverse_path;          (** Envelope sender *)
  recipients : forward_path list; (** Envelope recipients *)
  data : string;                  (** Message content (headers + body) *)
  received_at : float;            (** Unix timestamp *)
  auth_user : string option;      (** Authenticated username if any *)
  client_ip : string;             (** Client IP address *)
  client_domain : domain;         (** Client EHLO/HELO domain *)
}

(** {1 Security Validation Results} *)

(** SPF check result - RFC 7208 *)
type spf_result =
  | Spf_pass
  | Spf_fail
  | Spf_softfail
  | Spf_neutral
  | Spf_none
  | Spf_temperror
  | Spf_permerror

(** DKIM verification result - RFC 6376 *)
type dkim_result =
  | Dkim_pass of string      (** Verified, domain that signed *)
  | Dkim_fail of string      (** Failed, reason *)
  | Dkim_temperror of string (** Temporary error *)
  | Dkim_permerror of string (** Permanent error *)
  | Dkim_none               (** No signature *)

(** DMARC policy - RFC 7489 *)
type dmarc_policy =
  | Dmarc_none
  | Dmarc_quarantine
  | Dmarc_reject

(** DMARC check result *)
type dmarc_result = {
  policy : dmarc_policy;
  spf_aligned : bool;
  dkim_aligned : bool;
  action : [ `Accept | `Quarantine | `Reject ];
}

(** {1 Validation Functions} *)

(** Maximum local part length per RFC 5321 Section 4.5.3.1.1 *)
let max_local_part_length = 64

(** Maximum domain length per RFC 5321 Section 4.5.3.1.2 *)
let max_domain_length = 255

(** Maximum command line length per RFC 5321 Section 4.5.3.1.4 *)
let max_command_line_length = 512

(** Maximum text line length per RFC 5321 Section 4.5.3.1.6 *)
let max_text_line_length = 1000

(** Check if a character is valid in a local part (simplified) *)
let is_valid_local_char c =
  match c with
  | 'a'..'z' | 'A'..'Z' | '0'..'9' -> true
  | '!' | '#' | '$' | '%' | '&' | '\'' | '*' | '+' | '-' | '/' -> true
  | '=' | '?' | '^' | '_' | '`' | '{' | '|' | '}' | '~' | '.' -> true
  | _ -> false

(** Check if a local part is valid per RFC 5321 *)
let is_valid_local_part local =
  let len = String.length local in
  len > 0 && len <= max_local_part_length &&
  String.for_all is_valid_local_char local &&
  (* Cannot start or end with dot, no consecutive dots *)
  not (String.length local > 0 && local.[0] = '.') &&
  not (String.length local > 0 && local.[len - 1] = '.') &&
  not (String.contains local '.' &&
       let rec has_consecutive_dots i =
         i < len - 1 &&
         (local.[i] = '.' && local.[i+1] = '.' || has_consecutive_dots (i+1))
       in has_consecutive_dots 0)

(** Check if a character is valid in a domain label *)
let is_valid_domain_char c =
  match c with
  | 'a'..'z' | 'A'..'Z' | '0'..'9' | '-' -> true
  | _ -> false

(** Check if a domain label is valid *)
let is_valid_domain_label label =
  let len = String.length label in
  len > 0 && len <= 63 &&
  String.for_all is_valid_domain_char label &&
  label.[0] <> '-' && label.[len - 1] <> '-'

(** Check if a domain is valid per RFC 5321 *)
let is_valid_domain domain =
  let len = String.length domain in
  len > 0 && len <= max_domain_length &&
  let labels = String.split_on_char '.' domain in
  List.length labels >= 1 &&
  List.for_all is_valid_domain_label labels

(** Check if an email address is valid *)
let is_valid_email_address addr =
  is_valid_local_part addr.local_part &&
  is_valid_domain addr.domain

(** Check if a domain is local (we accept mail for it) *)
let is_local_domain domain ~local_domains =
  let domain_lower = String.lowercase_ascii domain in
  List.exists (fun d -> String.lowercase_ascii d = domain_lower) local_domains

(** {1 Closed Relay Enforcement}

    This is the critical security function. Unauthenticated senders can only
    deliver to local domains. Authenticated users can relay anywhere. *)

(** Check if relay is allowed for the given recipient.

    @param state Current connection state
    @param recipient The RCPT TO address
    @param local_domains List of domains we accept mail for
    @return true if the message can be accepted for this recipient *)
let is_relay_allowed ~state ~recipient ~local_domains =
  let is_local = is_local_domain recipient.domain ~local_domains in
  match state with
  | Authenticated { username = _; client_domain = _; tls_active = _ } ->
    true  (* Authenticated users can relay anywhere *)
  | Mail_from_accepted { username = Some _; client_domain = _; sender = _; params = _; tls_active = _ }
  | Rcpt_to_accepted { username = Some _; client_domain = _; sender = _; recipients = _; params = _; tls_active = _ } ->
    true  (* Previously authenticated users can relay anywhere *)
  | Greeted { client_domain = _; tls_active = _ }
  | Mail_from_accepted { username = None; client_domain = _; sender = _; params = _; tls_active = _ }
  | Rcpt_to_accepted { username = None; client_domain = _; sender = _; recipients = _; params = _; tls_active = _ } ->
    is_local  (* Unauthenticated can only deliver to local domains *)
  | Initial
  | Data_mode { username = _; client_domain = _; sender = _; recipients = _; tls_active = _ }
  | Quit ->
    false

(** {1 Email Address String Conversion} *)

(** Convert email address to string representation *)
let email_to_string addr =
  addr.local_part ^ "@" ^ addr.domain

(** Convert reverse path to string (for MAIL FROM) *)
let reverse_path_to_string = function
  | None -> "<>"
  | Some addr -> "<" ^ email_to_string addr ^ ">"

(** Convert forward path to string (for RCPT TO) *)
let forward_path_to_string addr =
  "<" ^ email_to_string addr ^ ">"

(** Parse email address from string.
    Handles formats: user@example.com, <user@example.com> *)
let parse_email_address s =
  (* Remove surrounding angle brackets if present *)
  let s = String.trim s in
  let s =
    if String.length s >= 2 && s.[0] = '<' && s.[String.length s - 1] = '>'
    then String.sub s 1 (String.length s - 2)
    else s
  in
  match String.split_on_char '@' s with
  | [local; domain] when is_valid_local_part local && is_valid_domain domain ->
    Some { local_part = local; domain }
  | _ -> None

(** {1 SMTP Response Helpers} *)

(** Service ready greeting - RFC 5321 Section 4.2 code 220 *)
let greeting ~hostname =
  { code = 220; enhanced_code = None;
    lines = [hostname ^ " ESMTP Service Ready"] }

(** EHLO response with extensions - RFC 5321 Section 4.1.1.1 *)
let ehlo_response ~hostname ~extensions =
  { code = 250; enhanced_code = None;
    lines = hostname :: extensions }

(** Generic OK response *)
let ok ?(text = "OK") () =
  { code = 250; enhanced_code = Some (2, 0, 0); lines = [text] }

(** Ready for mail data - RFC 5321 Section 3.3 *)
let ready_for_data =
  { code = 354; enhanced_code = None;
    lines = ["Start mail input; end with <CRLF>.<CRLF>"] }

(** STARTTLS ready response - RFC 3207 *)
let starttls_ready =
  { code = 220; enhanced_code = Some (2, 0, 0);
    lines = ["Ready to start TLS"] }

(** AUTH challenge (for multi-step auth) - RFC 4954 *)
let auth_challenge challenge =
  { code = 334; enhanced_code = None; lines = [challenge] }

(** AUTH success - RFC 4954 *)
let auth_success =
  { code = 235; enhanced_code = Some (2, 7, 0);
    lines = ["Authentication successful"] }

(** AUTH failed - RFC 4954 *)
let auth_failed =
  { code = 535; enhanced_code = Some (5, 7, 8);
    lines = ["Authentication credentials invalid"] }

(** AUTH required for relay - RFC 4954 *)
let auth_required =
  { code = 530; enhanced_code = Some (5, 7, 0);
    lines = ["Authentication required"] }

(** Temporary failure - RFC 5321 Section 4.2 code 4xx *)
let temp_failure ?(text = "Temporary service failure") () =
  { code = 451; enhanced_code = Some (4, 0, 0); lines = [text] }

(** Permanent failure - RFC 5321 Section 4.2 code 5xx *)
let perm_failure ?(text = "Permanent failure") () =
  { code = 550; enhanced_code = Some (5, 0, 0); lines = [text] }

(** Relay denied - critical for closed relay enforcement *)
let relay_denied =
  { code = 550; enhanced_code = Some (5, 7, 1);
    lines = ["Relay access denied"] }

(** Bad command sequence *)
let bad_sequence =
  { code = 503; enhanced_code = Some (5, 5, 1);
    lines = ["Bad sequence of commands"] }

(** Syntax error in command *)
let syntax_error ?(text = "Syntax error") () =
  { code = 500; enhanced_code = Some (5, 5, 2); lines = [text] }

(** Command not recognized *)
let command_not_recognized =
  { code = 500; enhanced_code = Some (5, 5, 1);
    lines = ["Command not recognized"] }

(** Parameter syntax error *)
let parameter_error ?(text = "Syntax error in parameters") () =
  { code = 501; enhanced_code = Some (5, 5, 4); lines = [text] }

(** Service closing - RFC 5321 Section 4.2 code 221 *)
let service_closing ~hostname =
  { code = 221; enhanced_code = Some (2, 0, 0);
    lines = [hostname ^ " Service closing transmission channel"] }

(** Message size exceeded - RFC 1870 *)
let message_too_large =
  { code = 552; enhanced_code = Some (5, 3, 4);
    lines = ["Message size exceeds maximum permitted"] }

(** Too many recipients *)
let too_many_recipients =
  { code = 452; enhanced_code = Some (4, 5, 3);
    lines = ["Too many recipients"] }

(** Mailbox unavailable *)
let mailbox_unavailable ?(text = "Mailbox unavailable") () =
  { code = 550; enhanced_code = Some (5, 1, 1); lines = [text] }

(** STARTTLS required - RFC 3207 *)
let starttls_required =
  { code = 530; enhanced_code = Some (5, 7, 0);
    lines = ["Must issue STARTTLS first"] }
