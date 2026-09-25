- **`pkg/trust/bootstrap.NewTOFUTLSConfig`'s `MinVersion: tls.VersionTLS12`
  stays, and the code now says why (go-xkms#897).** go-xkms servers default
  to TLS 1.3 (`pkg/server/server.go`), so raising every internal client's
  floor to match looked like a straightforward hardening pass. TOFU is not
  one of those clients: it is documented (`docs/trust-bootstrap/
  architecture.md`, `docs/trust-bootstrap/user.md` "About TOFU") to verify
  arbitrary third-party endpoints that present a self-signed certificate and
  serve no CA bundle at all -- BMCs and similar out-of-band management
  interfaces are named explicitly as the reason the mode exists -- and
  those devices are not go-xkms servers and commonly cannot negotiate TLS
  1.3. Raising the floor would have refused exactly the endpoints this mode
  exists to pin. No behavior change; `tofu_tls.go` gained a comment citing
  the doc evidence so the next TLS-hardening pass doesn't have to
  re-derive it.
