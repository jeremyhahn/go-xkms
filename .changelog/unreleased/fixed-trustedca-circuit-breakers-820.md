- **The standalone `TrustedCA` ACME router now wires circuit breakers and
  reports them on `GET /health`, matching xkmsd's embedded ACME listener.**
  `pkg/acme/client/trustedca.go`'s `TrustedCA` previously never set
  `handlers.Params.Breakers`, `StorageBreaker`, or `KMSBreaker`, and never
  wrapped its challenge verifiers with a breaker, so `/health` always
  reported healthy with no breakers listed regardless of the state of its
  dependencies. `TrustedCA.Serve` now builds a `circuitbreaker.Manager`
  unconditionally (matching `cmd/xkmsd/acme.go`'s always-on wiring) and
  wraps its `http-01`/`dns-01` challenge verifiers, its own CA-bundle
  storage access, and (when configured) the tenant KMS signer, through the
  same breaker `Manager`. The wrapping itself is now a single shared helper,
  `pkg/acme/server/resilience.go`'s `WrapChallengeVerifiers`, called by both
  `cmd/xkmsd/acme.go`'s `buildChallengeMap` and `TrustedCA.Serve`, so a
  breaker named `http01` or `dns01` means the same thing in either
  composition's `/health` output. `TCAACMEConfig` gained a `Resilience`
  field (`acme.resilience`) that reuses `pkg/config`'s
  `ACMEResilienceConfig` directly rather than a parallel type, so the same
  `storage`/`kms`/`http01`/`dns01` breaker sections, defaults, and
  `ErrACMEResilienceNegativeValue` validation apply to both ACME server
  compositions' configuration. An open `storage` breaker now degrades
  `GET /acme/directory` and `GET /acme/ca-bundle` on the standalone router
  exactly as it already did on xkmsd. (go-xkms#820)
