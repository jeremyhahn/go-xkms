- **`GetTLSCertificate` returns one canonical response shape on every
  transport — BREAKING.** REST and QUIC previously failed to decode any
  certificate with a chain: the wire-level `pkg/api/rest.GetTLSCertificateResponse.ChainPEM`
  was `[]string` while `pkg/api/transport.GetTLSCertificateResponse.ChainPEM`,
  which the REST and QUIC client transports decode into, was a `string` under
  the same `chain_pem` JSON tag. MCP's server returned a locally-defined
  `GetTLSCertificateResult{CertPEM, ChainPEMs, PrivateKeyType}` whose field
  names never matched the MCP client transport's decode target
  (`transport.GetTLSCertificateResponse{CertificatePEM, ChainPEM}`), so every
  MCP call decoded to a zero-value response. Both REST- and MCP-local result
  types are deleted; every server handler (REST, gRPC, unix, QUIC, MCP,
  embedded) and every client transport now use the one canonical
  `pkg/api/transport.GetTLSCertificateResponse`, re-exported unchanged by the
  SDK. `ChainPEM` is now `[]string` everywhere — one PEM-encoded certificate
  per chain entry, leaf excluded — matching the shape the gRPC proto
  (`GetTLSCertificateResponse.cert_chain_pem`) already used. The gRPC and
  unix client transports (`pkg/api/transport/grpc/transport.go`,
  `pkg/api/transport/unix/transport.go`) had an additional latent bug fixed
  by this change: both silently discarded every chain entry past the first.
  `xkmsctl tls get` decodes each chain entry individually via
  `client.DecodeCertificatePEM` instead of concatenating a single string.
  The private key stays deleted from this response (go-xkms#627) and does
  not come back. Files: `pkg/api/transport/types.go`,
  `pkg/api/rest/types.go`, `pkg/api/rest/handlers.go`,
  `pkg/api/mcp/types.go`, `pkg/api/mcp/handlers.go`,
  `pkg/xkms/servicer_cert.go`, `pkg/api/transport/grpc/transport.go`,
  `pkg/api/transport/unix/transport.go`, `cmd/xkmsctl/tls.go`.
