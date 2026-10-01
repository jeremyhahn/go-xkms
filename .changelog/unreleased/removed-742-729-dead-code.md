- **Dead ACME rate-limiter helper constructors removed, including the
  spoofable `TenantRateLimiterFromHeader` (#742).** The RFC 8555 §6.6
  regression they were left over from is already fixed: xkmsd
  (`cmd/xkmsd/acme.go`) and the standalone TrustedCA
  (`pkg/acme/client/trustedca.go`) both wire their per-client, per-tenant and
  per-category limiters through `pkg/acme/server.NewClientRateLimiterMiddleware`,
  `NewAccountRateLimiter`, and the tenant-aware `NewTenant{Order,Certificate,
  FailedValidation}RateLimiter` + `TenantRateLimiterFromRequestContext`, which
  resolves the tenant only from a verified JWS "kid". Deleted for having zero
  production callers: `pkg/acme/server.NewOrderRateLimiter`,
  `CertificateRateLimiter`, `OverallRateLimiter`, `FailedValidationRateLimiter`,
  `NewTenantAccountRateLimiter`, `NewTenantOverallRateLimiter`,
  `TenantRateLimiterFromHeader` (took the tenant from a client-supplied HTTP
  header) and `TenantRateLimiterFromContext` (a generic, unused
  context-value extractor), plus their tests.
- **`xkey/pkg/ca`, an unwired local-CA bridge, is deleted (#729).** It
  duplicated the canonical `pkg/xkms/servicer_ca*` CA implementation behind
  an `xkms.TCGCA`-backed `Service`, but had zero importers anywhere in the
  xkey module: `xkey`'s CLI (`cmd/xkey/cmd/ca.go`) and its `getSDKClient`
  are remote-mode only by design — "xkey never runs an in-process CA" — and
  reach the canonical servicer over the SDK transport against a running
  xkmsd. A local-CA mode for xkey is not built as part of this cleanup and
  awaits a separate owner ruling.
