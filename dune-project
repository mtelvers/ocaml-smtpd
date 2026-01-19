(lang dune 3.0)

(name smtpd)

(generate_opam_files true)

(source
 (github mtelvers/ocaml-smtpd))

(authors "Mark Elvers <mark.elvers@tunbury.org>")

(maintainers "Mark Elvers <mark.elvers@tunbury.org>")

(license ISC)

(documentation https://github.com/mtelvers/ocaml-smtpd)

(package
 (name smtpd)
 (synopsis "An SMTP server implemented in OCaml")
 (description
  "A secure SMTP server (RFC 5321) with STARTTLS, SASL authentication, SPF, DKIM, and DMARC support. Features closed relay enforcement and fork-per-connection privilege separation.")
 (depends
  (ocaml (>= 5.0))
  (dune (>= 3.0))
  (eio (>= 1.0))
  (eio_main (>= 1.0))
  (tls-eio (>= 1.0))
  (tls (>= 1.0))
  (x509 (>= 1.0))
  (mirage-crypto (>= 1.0))
  (mirage-crypto-pk (>= 1.0))
  (mirage-crypto-rng (>= 1.0))
  menhir
  faraday
  (dns (>= 8.0))
  (ipaddr (>= 5.0))
  base64
  cmdliner
  (alcotest :with-test)
  (alcotest-eio :with-test))
 (tags
  (smtp email server "RFC 5321" spf dkim dmarc)))

(using menhir 2.1)
