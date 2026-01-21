# smtpd

An SMTP server implemented in OCaml.

Implements [RFC 5321](https://datatracker.ietf.org/doc/html/rfc5321) (SMTP) with support for [RFC 3207](https://datatracker.ietf.org/doc/html/rfc3207) (STARTTLS) and [RFC 8314](https://datatracker.ietf.org/doc/html/rfc8314) (Implicit TLS).

## Features

- **SMTP** (RFC 5321) compliant server
- **Closed relay enforcement** - Only authenticated users can relay to external domains
- **Fork-per-connection** privilege separation (like UW-IMAP)
- **Implicit TLS** on port 465 (RFC 8314)
- **STARTTLS** upgrade for cleartext connections
- **SASL authentication** (RFC 4954) - PLAIN and LOGIN mechanisms
- **PAM authentication** using system accounts
- **SPF verification** (RFC 7208) - Sender Policy Framework
- **DKIM verification** (RFC 6376) - DomainKeys Identified Mail signature verification
- **DKIM signing** (RFC 6376) - Sign outbound messages with DKIM
- **DMARC policy checking** (RFC 7489) - Domain-based Message Authentication
- **Local delivery** to Maildir format (compatible with IMAP servers)
- **Remote delivery** via SMTP client with MX lookup and opportunistic STARTTLS
- **Queue manager** with exponential backoff retry

### Supported Extensions

| Extension | RFC | Description |
|-----------|-----|-------------|
| SIZE | [RFC 1870](https://datatracker.ietf.org/doc/html/rfc1870) | Message size declaration |
| 8BITMIME | [RFC 6152](https://datatracker.ietf.org/doc/html/rfc6152) | 8-bit MIME transport |
| STARTTLS | [RFC 3207](https://datatracker.ietf.org/doc/html/rfc3207) | TLS upgrade |
| AUTH | [RFC 4954](https://datatracker.ietf.org/doc/html/rfc4954) | SASL authentication |
| ENHANCEDSTATUSCODES | [RFC 2034](https://datatracker.ietf.org/doc/html/rfc2034) | Enhanced status codes |
| PIPELINING | [RFC 2920](https://datatracker.ietf.org/doc/html/rfc2920) | Command pipelining |

## Installation

### Prerequisites

- OCaml 5.0+
- opam
- PAM development headers (`libpam0g-dev` on Debian/Ubuntu)

### Building

```bash
opam install . --deps-only
dune build
```

### Running Tests

```bash
dune test
```

## Usage

### Development Server

```bash
# In-memory queue on port 2525
smtpd -p 2525 --local-domains example.com
```

### Production Server (Recommended)

```bash
# Fork-per-connection with implicit TLS and closed relay
sudo smtpd --fork --tls \
  --cert /etc/ssl/certs/mail.crt \
  --key /etc/ssl/private/mail.key \
  --local-domains example.com,example.org \
  --require-auth \
  --queue-path /var/spool/smtpd \
  -p 465
```

### Submission Server (Port 587)

```bash
# STARTTLS with required authentication
smtpd -p 587 \
  --cert server.crt --key server.key \
  --local-domains example.com \
  --require-auth
```

## Security

### Closed Relay

**This is the critical security feature.**

By default with `--require-auth`, the server enforces closed relay:
- **Authenticated users** can send mail to any domain (relay)
- **Unauthenticated users** can only deliver to local domains

Without this protection, your server would be an open relay and quickly end up on spam blacklists.

```
# Unauthenticated attempt to relay - DENIED
EHLO spammer.com
MAIL FROM:<spammer@evil.com>
RCPT TO:<victim@external.com>
550 5.7.1 Relay access denied

# Authenticated relay - ALLOWED
EHLO client.com
AUTH PLAIN dXNlcm5hbWUAcGFzc3dvcmQ=
235 2.7.0 Authentication successful
MAIL FROM:<user@example.com>
RCPT TO:<recipient@external.com>
250 2.0.0 Recipient OK
```

### Anti-Spam Verification

Incoming messages are checked against:

- **SPF** (RFC 7208) - Verifies the sending server is authorized for the sender's domain
- **DKIM** (RFC 6376) - Verifies cryptographic signatures on message headers
- **DMARC** (RFC 7489) - Enforces domain policy based on SPF and DKIM alignment

Results are added to the `Authentication-Results` header for downstream processing.

### Operating Modes

#### Single-Process (default)

All connections handled in one process. Efficient but all sessions share the same privileges. Suitable for development or trusted environments.

#### Fork-per-Connection (`--fork`)

Each connection forks a child process. After successful authentication, the child drops privileges to the authenticated user via `setuid`. This provides strong isolation between users.

- Requires running as root
- STARTTLS not supported (use implicit TLS)

### TLS Configuration

- **Implicit TLS** (`--tls`): TLS starts immediately on connection. Recommended for production.
- **STARTTLS**: Client upgrades to TLS after connecting. Not supported in fork mode.

## Message Delivery

### Local Delivery (Maildir)

Messages to local domains are delivered to the recipient's Maildir:

```
/home/<username>/Maildir/
├── new/      # Newly delivered messages
├── cur/      # Messages that have been seen
└── tmp/      # Temporary files during delivery
```

This format is compatible with Dovecot, Courier, and other IMAP servers, allowing seamless integration with an IMAP implementation.

### Remote Delivery (SMTP Client)

Messages to external domains are delivered via SMTP:

1. MX records are looked up for the recipient domain
2. Connection is attempted to each MX host in priority order
3. **STARTTLS** is attempted if the server advertises it (opportunistic TLS)
4. Message is sent using standard SMTP protocol
5. Falls back to A record if no MX records exist

The SMTP client uses opportunistic TLS - if the receiving server advertises STARTTLS in its EHLO response, we upgrade the connection to TLS before sending the message. This provides transport encryption for outbound mail delivery.

### Queue Manager

The queue manager processes messages in the background:

- **Immediate delivery** attempted for new messages
- **Exponential backoff** for temporary failures (1m, 5m, 15m, 30m, 1h, 2h, 4h, 8h, 24h)
- **Permanent failures** generate bounce messages
- **Maximum retry period** of 24 hours before giving up

## Command-Line Options

| Option | Description |
|--------|-------------|
| `-p`, `--port` | Port to listen on (default: 25) |
| `-h`, `--host` | Host address to bind to (default: 127.0.0.1) |
| `--tls` | Enable implicit TLS (requires `--cert` and `--key`) |
| `--cert` | TLS certificate file (PEM format) |
| `--key` | TLS private key file (PEM format) |
| `--fork` | Fork per connection with privilege separation |
| `--local-domains` | Comma-separated list of local domains |
| `--require-auth` | Require authentication for relay |
| `--queue-path` | Base path for message queue (default: /var/spool/smtpd) |
| `--dkim-key` | DKIM private key file (PEM format) for signing outbound messages |
| `--dkim-domain` | Domain for DKIM signing (d= tag) |
| `--dkim-selector` | Selector for DKIM signing (s= tag) |

## DKIM Signing

To sign outbound messages with DKIM:

### 1. Generate a Key Pair

```bash
# Generate 2048-bit RSA private key
openssl genrsa -out dkim.key 2048

# Extract public key for DNS
openssl rsa -in dkim.key -pubout -outform PEM | \
  grep -v "PUBLIC KEY" | tr -d '\n'
```

### 2. Publish DNS Record

Create a TXT record at `selector._domainkey.example.com`:

```
v=DKIM1; k=rsa; p=MIIBIjANBgkq...your_public_key...
```

### 3. Configure the Server

```bash
smtpd --local-domains example.com \
  --dkim-key /etc/smtpd/dkim.key \
  --dkim-domain example.com \
  --dkim-selector mail
```

Messages sent to remote domains will now include a DKIM-Signature header.

## MTA-STS (RFC 8461)

MTA-STS (Mail Transfer Agent Strict Transport Security) allows you to declare that your domain supports TLS and that sending servers should require TLS when delivering mail to you.

### DNS Records

Add a TXT record at `_mta-sts.example.com`:

```
v=STSv1; id=20260121
```

The `id` should be updated whenever you change your policy.

### Policy File

Serve the policy file at `https://mta-sts.example.com/.well-known/mta-sts.txt`:

```
version: STSv1
mode: enforce
mx: mail.example.com
max_age: 604800
```

Policy modes:
- `testing` - Report failures but don't reject mail
- `enforce` - Require TLS, reject on failure

### Web Server Setup (Caddy)

The easiest way to serve MTA-STS is with Caddy, which handles TLS certificates automatically:

```
# /etc/caddy/Caddyfile
mta-sts.example.com {
    root * /var/www/mta-sts
    file_server
}
```

### Complete DNS Zone Example

Here's a complete DNS zone file showing all required records for a mail server:

```
@ 86400 IN SOA ns1.example.net. hostmaster.example.net. 1769004210 10800 3600 604800 10800
@ 10800 IN A 217.70.184.38
@ 10800 IN MX 10 mail.example.com.
@ 10800 IN TXT "v=spf1 mx -all"
_dmarc 10800 IN TXT "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"
_mta-sts 10800 IN TXT "v=STSv1; id=20260121"
_smtp._tls 10800 IN TXT "v=TLSRPTv1; rua=mailto:tlsrpt@example.com"
mail 10800 IN A 51.15.95.113
mail._domainkey 10800 IN TXT "v=DKIM1; k=rsa; p=MIIBIjANBgkq...your_public_key..."
mta-sts 10800 IN A 51.15.95.113
```

| Record | Purpose |
|--------|---------|
| `MX` | Points to your mail server |
| `SPF` | Authorizes MX servers to send mail |
| `DKIM` | Public key for signature verification |
| `DMARC` | Policy for failed SPF/DKIM checks |
| `_mta-sts` | Declares MTA-STS policy version |
| `_smtp._tls` | TLS-RPT reporting address (RFC 8460) |
| `mta-sts` | A record for the policy web server |
| `mail` | A record for the mail server |

## Architecture

```
smtp/
├── lib/
│   ├── smtp_types/     # Core SMTP types (RFC 5321)
│   ├── smtp_parser/    # Menhir parser + Faraday serializer
│   ├── smtp_auth/      # PAM authentication
│   ├── smtp_queue/     # Memory and File queue backends
│   ├── smtp_server/    # Connection handler and state machine
│   ├── smtp_dns/       # DNS resolver for MX/TXT lookups
│   ├── smtp_spf/       # SPF verification (RFC 7208)
│   ├── smtp_dkim/      # DKIM signature verification (RFC 6376)
│   ├── smtp_dmarc/     # DMARC policy checking (RFC 7489)
│   ├── smtp_delivery/  # Local Maildir and remote SMTP delivery
│   └── smtp_qmgr/      # Queue manager with retry logic
├── bin/
│   └── main.ml         # CLI entry point
└── test/               # Alcotest test suite
```

### Connection State Machine

```
┌─────────────────────┐
│ Initial             │ ← Connection established, send 220 greeting
├─────────────────────┤
│ Commands: EHLO/HELO │
│           QUIT      │
└─────────┬───────────┘
          │ EHLO/HELO
          ▼
┌─────────────────────┐
│ Greeted             │ ← Can STARTTLS, AUTH, or MAIL FROM
├─────────────────────┤
│ Commands: STARTTLS  │
│           AUTH      │
│           MAIL FROM │ (local only if not authenticated)
│           RSET,NOOP │
│           QUIT      │
└─────────┬───────────┘
          │ AUTH (optional)
          ▼
┌─────────────────────┐
│ Authenticated       │ ← Can relay to external domains
├─────────────────────┤
│ Commands: MAIL FROM │
│           RSET,NOOP │
│           QUIT      │
└─────────┬───────────┘
          │ MAIL FROM
          ▼
┌─────────────────────┐
│ Mail From Accepted  │
├─────────────────────┤
│ Commands: RCPT TO   │ (closed relay check!)
│           RSET,NOOP │
│           QUIT      │
└─────────┬───────────┘
          │ RCPT TO (at least one)
          ▼
┌─────────────────────┐
│ Rcpt To Accepted    │
├─────────────────────┤
│ Commands: RCPT TO   │
│           DATA      │
│           RSET,NOOP │
│           QUIT      │
└─────────┬───────────┘
          │ DATA
          ▼
┌─────────────────────┐
│ Data Mode           │ ← Read until .<CRLF>
├─────────────────────┤
│ SPF/DKIM/DMARC      │
│ checks applied      │
│ Message queued      │
│ Returns to Greeted  │
└─────────────────────┘
```

### Delivery Flow

```
┌─────────────────┐
│ Message Queued  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Queue Manager   │
│ picks up message│
└────────┬────────┘
         │
         ▼
┌─────────────────┐     ┌─────────────────┐
│ Local Domain?   │────►│ Maildir Delivery│
│                 │ Yes │ ~/Maildir/new/  │
└────────┬────────┘     └─────────────────┘
         │ No
         ▼
┌─────────────────┐     ┌─────────────────┐
│ MX Lookup       │────►│ SMTP Client     │
│                 │     │ Connect & Send  │
└─────────────────┘     └────────┬────────┘
                                 │
                    ┌────────────┼────────────┐
                    ▼            ▼            ▼
              ┌──────────┐ ┌──────────┐ ┌──────────┐
              │ Delivered│ │ Deferred │ │ Failed   │
              │          │ │ (retry)  │ │ (bounce) │
              └──────────┘ └──────────┘ └──────────┘
```

## Testing with a Client

```bash
# Start development server
smtpd -p 2525 --local-domains example.com &

# Connect with telnet (cleartext)
telnet localhost 2525

# Or with TLS
openssl s_client -connect localhost:465
```

Example session:
```
220 localhost ESMTP Service Ready
EHLO client.example.com
250-localhost
250-SIZE 10485760
250-8BITMIME
250-ENHANCEDSTATUSCODES
250-PIPELINING
250-AUTH PLAIN LOGIN
250 STARTTLS
AUTH PLAIN dXNlcm5hbWUAcGFzc3dvcmQ=
235 2.7.0 Authentication successful
MAIL FROM:<sender@example.com>
250 2.0.0 Sender OK
RCPT TO:<recipient@external.com>
250 2.0.0 Recipient OK
DATA
354 Start mail input; end with <CRLF>.<CRLF>
Subject: Test

Hello, World!
.
250 2.0.0 Message accepted, queue ID: 1234567890.ABCDEF
QUIT
221 2.0.0 localhost Service closing transmission channel
```

## Future Work

- Rate limiting
- Greylisting
- Milter support

## License

ISC License

Copyright (c) 2026 Mark Elvers

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.

## Contributing

Report bugs at https://github.com/mtelvers/ocaml-smtpd/issues
