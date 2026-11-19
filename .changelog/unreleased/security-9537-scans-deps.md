### Security

- Bumped golang.org/x/net to v0.63.0 in the root, sdk/go, xkey and
  web/desktop modules (CVE-2026-78661, HIGH, fixed in v0.62.0).
- Bumped the direct dependencies of the root, sdk/go and xkey modules that
  were behind a release 7 days old or older (cloud KMS, Azure, AWS SDK, cbor,
  kin-openapi, go-jose, quic-go, grpc, x/crypto and others). go-truststrap
  and go-luks2 stay held: their newest releases need go-enclave v0.9 or later,
  which the go-qrdb v0.51.0-alpha pin rules out.
