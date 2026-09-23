- **`frost.FrostBackend.Signer` refuses a threshold greater than 1 at
  construction instead of failing on the first `Sign` call — BREAKING.** A
  `crypto.Signer` performs one synchronous `Sign` call and cannot coordinate
  a multi-party FROST round, but `Signer` previously returned a working
  `*FrostSigner` for any threshold and only discovered the problem inside
  `Sign`, where it returned an untyped `"orchestrated multi-participant
  signing not implemented"` message. `Signer` now loads the key package
  first and returns the new typed `*frost.ThresholdSigningNotSupportedError`
  (wrapping the new `frost.ErrThresholdSigningNotSupported` sentinel) when
  the key's threshold requires coordinating more than one participant,
  naming the key ID and threshold and pointing callers at `GenerateNonces`,
  `SignRound`, and `Aggregate` for distributed signing. Since every FROST key
  in this codebase — and in the underlying `go-frost` trusted-dealer
  implementation itself — requires a threshold of at least 2,
  `FrostBackend.Signer` now always returns this error for real keys;
  `FrostSigner.Sign`'s single-participant round is kept for a threshold-1 key
  built directly (not reachable through any generator here today) rather
  than removed as dead code. Files: `pkg/keyprovider/frost/backend.go`,
  `pkg/keyprovider/frost/signer.go`, `pkg/keyprovider/frost/errors.go`,
  `pkg/keyprovider/frost/signer_test.go`,
  `pkg/keyprovider/frost/backend_test.go`,
  `test/integration/frost/backend_integration_test.go`,
  `docs/frost/api.md`, `docs/frost/architecture.md`. Fixes go-xkms#663.
