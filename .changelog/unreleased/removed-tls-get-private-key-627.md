- **`xkmsctl tls get` no longer returns the private key — BREAKING.** The
  command now goes through the canonical `ClientFactory` → SDK `Client` seam
  (`cl.GetTLSCertificate(ctx, backend, keyID)`) instead of constructing a
  local backend directly, and prints the certificate and its chain only;
  `getTLSCertLocal`'s direct `be.GetKey` path is deleted, along with the
  now-unused `--key-type`/`--key-algorithm`/`--key-size`/`--curve` flags it
  needed to look up the key locally (`cmd/xkmsctl/tls.go`,
  `cmd/xkmsctl/output.go`'s `Printer.PrintTLSCertificate`, which drops its
  `key interface{}` parameter). The wire-level cause:
  `pkg/api/transport.GetTLSCertificateResponse`'s `PrivateKeyPEM` field is
  deleted outright — it was never populated on the embedded/REST/Unix/QUIC/
  MCP paths, and the one path that did populate it, the raw gRPC
  `Service.GetTLSCertificate` (`pkg/api/grpc/service.go`), is changed to
  stop encoding and returning the private key at all. The corresponding
  proto field (`GetTLSCertificateResponse.private_key_pem`, field 3) is
  removed from `pkg/api/grpc/proto/xkmsv1/xkms.proto` and regenerated with
  `make proto`; it was unreleased, so the field number is not reserved.
  Every transport mapping that copied the field
  (`pkg/api/transport/grpc/transport.go`,
  `pkg/api/transport/unix/transport.go`) is updated to match. The private
  key for a TLS key stays in the backend that holds it: a server process
  signs and decrypts through that backend, it never receives key material
  over this call. `docs/certificate-authority/cli.md` and `user.md` are
  updated to describe the new, key-free response.
