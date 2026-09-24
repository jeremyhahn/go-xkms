- **The xkmsd ACME listener now enforces a per-client request-rate cap; it
  previously accepted unlimited traffic.** `cmd/xkmsd/acme.go`'s
  `buildACMERouter` mounted no rate-limit middleware, so an xkmsd ACME
  endpoint admitted unbounded new-account, new-order and challenge requests
  even though the standalone `TrustedCA` (`pkg/acme/client/trustedca.go`)
  already wired one. `pkg/acme/server/rate_limiter.go` gains
  `NewClientRateLimiterMiddleware`, the single construction path both
  compositions now call: a `RateLimiter` keyed by JWS KID once an ACME
  account exists, falling back to the client IP before one does
  (`server.ClientID`), wired to the ACME audit logger so a throttled request
  is recorded via `EventRateLimitExceeded`. An exceeded cap is refused per
  RFC 8555 Section 6.6 — HTTP 429, a `Retry-After` header in integer
  seconds, and an `application/problem+json` body with type
  `urn:ietf:params:acme:error:rateLimited` — unchanged from the existing
  limiter, which was already RFC-compliant.
  Configuration is the new `ACMERateLimitConfig` (`pkg/config/acme.go`,
  `acme.rate_limit`), following the same secure-by-default tri-state as
  `acme.audit`: an omitted or `enabled: true` section throttles at
  `max_requests: 20` per `interval: 1s` by default (matching the
  standalone `TrustedCA`'s long-standing built-in default); an explicit
  `enabled: false` is reported by `Config.ComplianceGaps` ("ACME rate
  limiting disabled") and `cmd/xkmsd` refuses to start on it, the same
  refusal pattern the audit trail uses — there is no silent way to run the
  ACME listener unthrottled. A negative `max_requests` or `interval` is
  refused by `ACMEConfig.Validate` rather than coerced to the default.
  Per-tenant rate limiting (`pkg/acme/server/tenant_rate_limiter.go`) and
  the RFC 8555 §6.6 per-category limits (new-account/new-order/
  certificate/failed-validation, `rate_limiter.go`'s
  `DefaultRateLimitConfig` and its constructors) remain unwired: xkmsd only
  learns an ACME request's tenant as a side effect of handler-internal
  business logic (the verified External Account Binding inside
  `NewAccountHandler`, or the persisted account read back in
  `order_finalize.go`), never from a cheap, authenticated, pre-dispatch
  request attribute a router middleware could key on — the existing
  `handlers.TenantMiddleware` extractor trusts a client-supplied header/
  host/path with no authentication, so wiring it for admission control
  would let a client opt out of its own quota by omitting or spoofing it.
  This is tracked as follow-up work rather than forced into this change;
  see `docs/acme-issuance/engineering.md` §Rate limiting.
  Tests: `pkg/acme/server/client_rate_limiter_middleware_test.go` (within-
  limit passes, an exceeded limit is refused with the RFC 8555 problem
  document and audited, a zero-request cap fails closed) and
  `cmd/xkmsd/acme_test.go`'s `TestBuildACMERouter_RateLimit`/
  `TestBuildACMERouter_RateLimit_Disabled` (router-level enforcement and
  the explicit opt-out path), plus `pkg/config/acme_rate_limit_test.go`
  (tri-state defaults, negative-value validation, the compliance gap).
  go-xkms#882.
