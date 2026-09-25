- **ACME tenant and RFC 8555 §6.6 per-category rate limits are now
  enforced, keyed exclusively from an authenticated JWS `kid`; they were
  previously dead code with no caller.** `pkg/acme/server/tenant_rate_limiter.go`'s
  `TenantRateLimiter` and `rate_limiter.go`'s `NewAccountRateLimiter`/
  `NewOrderRateLimiter`/`CertificateRateLimiter`/`FailedValidationRateLimiter`
  existed and were unit-tested but had no caller outside their own tests
  (go-xkms#882/#885); the one HTTP-level tenant extractor,
  `handlers.TenantMiddleware`, was unwired and trusted a client-supplied
  `X-Tenant-ID` header (or host/path) with no authentication, so wiring it
  for admission control would have let a client opt out of its own quota,
  or consume another tenant's, by omitting or spoofing the header.
  New `handlers.RestService.TenantAuthMiddleware`
  (`pkg/acme/server/handlers/tenant_auth.go`) resolves the tenant exclusively
  from a fully verified JWS `kid`: for a POST request naming an account, it
  performs the exact verification `parseKID` performs — nonce check, JWS
  `"url"` match, signature verification against the account's stored public
  key — via `parseKID` itself, exactly once, caching the result (success or
  failure) on the request context so the handler's own later `parseKID` call
  returns it unchanged instead of re-verifying against an already-consumed,
  single-use replay-nonce. A request with no `kid` (new-account, new-nonce,
  directory, ca-bundle, or any GET) or a `kid` that fails verification never
  publishes a tenant, and is bounded only by the per-client limiter (#885),
  never by a client-asserted tenant.
  `cmd/xkmsd/acme.go`'s `buildACMERouter` (and `pkg/acme/client/trustedca.go`'s
  standalone `TrustedCA`, which also supports multi-tenancy) now mount
  `TenantAuthMiddleware` before dispatch, followed by a per-tenant overall
  `TenantRateLimiter` keyed with a constant client-key function
  (`tenantSharedClientKey`) so the quota is one bucket shared across every
  account of a tenant, not one bucket per account. The four RFC 8555 §6.6
  categories are wired at their endpoints: new-account (client-IP keyed,
  the tenant is never known before an account exists) on `POST /new-account`;
  new-order and certificate (account-within-tenant keyed) on `POST /new-order`
  and `POST /order/{id}/finalize`; failed-validation cannot be blanket route
  middleware — it must count only actual failures — so it is injected as
  `handlers.Params.FailedValidationRateLimiter` and `ChallengeHandler` calls
  its `Allow` method directly once a challenge has failed, using the new
  `TenantRateLimiter.RetryAfterSeconds` accessor to build the RFC 8555
  `rateLimited` response (HTTP 429, `Retry-After`) once the account's budget
  is exhausted.
  Configuration extends `ACMERateLimitConfig` (`pkg/config/acme.go`,
  `acme.rate_limit`) with five `ACMECategoryRateLimitConfig` sub-sections —
  `tenant`, `new_account`, `new_order`, `certificate`, `failed_validation` —
  each following the same secure-by-default tri-state as the per-client cap:
  an omitted or `enabled: true` section throttles at its own documented
  default (tenant 20/1s, new_account 10/1h, new_order 300/3h, certificate
  50/3h, failed_validation 5/1h); an explicit `enabled: false` on any of
  them is reported by `Config.ComplianceGaps` (a tenant gap, and a combined
  gap naming every disabled category) and `cmd/xkmsd` refuses to start on
  it. A negative `max_requests` or `interval` on any sub-section is refused
  by `Validate` rather than coerced to the default.
  Tests: `pkg/acme/server/handlers/tenant_auth_test.go` (verified-tenant
  resolution, `X-Tenant-ID` spoofing refused whether or not a `kid` is
  present, invalid-signature requests resolve no tenant and the cached error
  matches what a single verification would produce, GET and JWK-embedded
  requests skip resolution entirely); `pkg/acme/server/handlers/challenge_rate_limit_test.go`
  (the failed-validation category triggers after its budget and the
  disabled path never blocks); `pkg/acme/server/tenant_rate_limiter_test.go`
  (`RetryAfterSeconds`, and the shared-bucket-across-accounts /
  isolated-across-tenants properties); `pkg/config/acme_rate_limit_test.go`
  (tri-state defaults, negative-value validation, the tenant and
  per-category compliance gaps); `cmd/xkmsd/acme_rate_limit_test.go`
  (`buildACMERouterLimiters` enabled/disabled paths, nil-safety, the
  shared-quota router integration test). go-xkms#886.
