- **ACME server: unauthenticated clients can no longer stall or memory-exhaust it (go-xkms#1171, HIGH).**
  The per-client rate limiter held one global mutex across the whole request —
  including an unbounded `io.ReadAll` of the body and the handler itself — so a
  single client trickling a POST body queued every ACME request, `directory`
  and `new-nonce` included, until the read timeout. `RateLimiter` now holds
  its lock only for the token-bucket arithmetic (`RateLimiter.Allow`) and
  serves the request after releasing it. A new `server.RequestBodyMiddleware`,
  mounted first after metrics on both xkmsd's ACME listener and the standalone
  `TrustedCA`, reads every body once through `http.MaxBytesReader` at
  `server.MaxRequestBodySize` (256 KiB — sized for a TCG-CSR-IDEVID finalize
  carrying a real UEFI boot event log) and answers an oversized body with 413
  and an RFC 7807 `malformed` problem; `TenantAuthMiddleware`, `parseKID` and
  `parseJWS` share that one copy through `server.RequestBody` instead of each
  re-reading the body. The blanket limiter is keyed on the client IP, and
  `server.ClientID` keys per-account buckets only on an account whose JWS
  `TenantAuthMiddleware` verified (`server.WithVerifiedAccountID`) — an
  unverified `kid` never creates a bucket, closing the random-`kid` bypass.
  `RateLimiter` state is bounded: buckets idle for `MaxRequests` intervals are
  evicted and at most `server.DefaultMaxEntries` (10,000) keys are tracked,
  new keys being refused when full, as `TenantRateLimiter` already did. A
  new-order carrying more than 100 identifiers is refused with `malformed`.
  `RateLimiter`'s exported `Tokens`/`LastRequest` maps and the unused
  `BodySizeLimitMiddleware`/`DefaultMaxRequestBodySize` are removed. ACME
  rate-limit configuration keys are unchanged.
