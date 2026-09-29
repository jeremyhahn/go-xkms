# ACME Issuance — Engineering Contract

> **Status: NORMATIVE** · Feature: `acme-issuance` · Repo: `go-xkms` · Last verified: 2026-09-29

## Exported surface

### Server

`pkg/acme` is the server. Entry points that matter to an implementer:

- `pkg/acme/server/handlers` — one file per protocol object: `directory.go`,
  `account.go`, `authorization.go`, `challenge.go`, `certificate.go`,
  `ca_bundle.go`, `endorse_eab.go`, `audit.go`, `compliance_attestation.go`,
  `service.go`, `tenant_auth.go` (authenticated tenant resolution for
  admission control, go-xkms#886).
- `pkg/acme/entities` — the protocol objects themselves.
- `pkg/acme/nonce` — encrypted-counter nonce issue and redemption
  (`Service`), plus prefix-routed multi-node dispatch (`MultiService`).
  `RestService` wires it as described under Configuration and Persistence
  below.
- `pkg/acme/issuance` — **not on any production path.** It exists as a
  standalone bridge type to `pkg/ca`, but nothing outside its own tests
  imports it; `OrderFinalizeHandler` calls `s.ca.SignCSR` /
  `s.ca.IssueEKCertificate` / `s.ca.SignTCGCSRIDevID`
  (`pkg/acme/server/handlers/order_finalize.go:677,752,1343`) directly.
- `pkg/acme/storage`, `pkg/acme/qrdb` — persistence, through `go-qrdb/sdk/go`.
- `pkg/acme/policy`, `pkg/acme/server/caa.go` — issuance policy (blocklist,
  public suffix, reserved-IP, per-identifier-type challenge selection) and
  CAA. `pkg/acme/policy` is wired into `NewOrderHandler` and
  `createChallenges`; see Identifier policy below.
- `pkg/acme/server/rate_limiter.go`, `tenant_rate_limiter.go` — request-rate
  enforcement. `rate_limiter.go`'s `NewClientRateLimiterMiddleware` is
  wired into both xkmsd (`cmd/xkmsd/acme.go`) and the standalone `TrustedCA`
  (`pkg/acme/client/trustedca.go`); the tenant limiters are wired by both
  compositions too. See Invariants below and go-xkms#882, #886, #1171.
- `pkg/acme/server/request_body.go` — the capped, read-once request body
  (`RequestBodyMiddleware`, `RequestBody`); see Invariants below.
- `pkg/acme/server/circuitbreaker` — the one circuit breaker implementation
  (`CircuitBreaker`, `Manager`, the bounded per-target groups in
  `target.go` (go-xkms#1189, #1190), the `Middleware` HTTP wrapper, and the
  `WrapChallengeVerifier`/`WrapChallengeVerifierPerTarget`/`WrapLogSubmitter`/`WrapKMSService`
  decorators; go-xkms#975 deleted the unreferenced duplicate
  `pkg/acme/server/circuit_breaker.go` that #735 had left behind) and
  `pkg/acme/server/degradation` (the cache-backed graceful-degradation
  primitives) — the protective layer, wired into both xkmsd and the
  standalone `TrustedCA` (go-xkms#820). Both compositions build their
  breaker `Manager` and wrap their challenge verifiers through
  `pkg/acme/server/resilience.go`'s `WrapChallengeVerifiers`, the one shared
  construction path — see "Circuit breakers and degradation" below.
- `pkg/acme/admin` — the administrative plane (`auth.go`, `authz.go`,
  `barrier_handlers.go`, `barrier_service.go`, `ca_adapter.go`).
- `pkg/acme/api/adapter.go` plus `api/{rest,grpc,quic,mcp}` — the transport
  adapters, and `api/swagger` for the OpenAPI surface.
- `pkg/acme/ct` — Certificate Transparency types.

### Client

- `pkg/acme/client` — the Go client. Its `dns-01` pre-checks take
  `DNSCheckOption`s: `WithNameserverLookup`, `WithPropagationQuery`, and
  `WithNameserverPort`, the port the zone's authoritative nameservers are
  queried on (`DefaultDNSPort`, `"53"`, when unset; a supplied lookup returns
  complete addresses and is not re-ported).
- `sdk/go/acme` — the SDK surface, including `sdk/go/acme/trustedca.go` and
  `sdk/go/acme/transport/quic`.
- `pkg/acme/client/service` — the multi-account service layer:
  `AccountManager`, `CertificateManager` and `DeviceManager`, each keyed by a
  named spec in `service.Config` (`Accounts`, `Certificates`, `Devices`) and
  each resolving its account through `AccountManager.Client`.
  `DeviceManager.Enroll`/`.Attest` open the `DeviceSpec.TPM` device (a real
  TPM, or go-xkms's own simulator-backed defaults when left unset — see
  [cli.md](cli.md#trusted-acme-client-device)) and drive
  `pkg/acme/client.Client.EnrollDevice`/`.DeviceAttest` over the enroll-01 /
  device-attest-01 challenges. `pkg/acme/gui/client/api` exposes the same
  three managers as `/api/v1/accounts`, `/api/v1/certificates` and
  `/api/v1/device/{enroll,attest}` for the desktop GUI and
  `trusted-acme-client serve`. None of these managers register the ACME
  account themselves: `Client.authorizeOrder` (`pkg/acme/client/client.go`)
  is the one place every order-creating call —
  `RequestCertificate`/`RenewCertificate` (through `RequestCertificate`),
  `EnrollDevice`, `DeviceAttest`, and `RequestEndorsementKeyCertificate` —
  registers the account on first use before authorizing an order, so a
  `CertificateManager`/`DeviceManager` call never needs, and never performs,
  a separate registration step.
- `cmd/acme-client` — the `trusted-acme-client` binary
  (`account`, `cert`, `device`, `service`, `serve`, `version` groups).

### Directory document

`pkg/acme/server/handlers/directory.go` builds the directory from
`s.baseRESTURI`:

```go
NewNonce:   baseRESTURI + "/acme/new-nonce"
NewAccount: baseRESTURI + "/acme/new-account"
NewOrder:   baseRESTURI + "/acme/new-order"
RevokeCert: baseRESTURI + "/acme/revoke-cert"
KeyChange:  baseRESTURI + "/acme/key-change"
```

`baseRESTURI` is configured, not derived from the request, and
`service.go:581` documents the trap it prevents: a mis-set base produces
doubled prefixes such as `https://host/api/v1/api/v1/acme/new-account`. Set it
once, to the externally visible base.

## Invariants

- **Attestation PCR data is decoded under bounds.** The compliance hooks
  decode the PCR banks inside a request's `ProdCaData`
  (`pkg/acme/server/handlers/compliance_attestation.go:187`, `:764`) through
  `DecodePCRs`, which refuses input over 64 KiB and banks no TPM reports
  before either hook reads a value (see
  [`../tpm2/engineering.md`](../tpm2/engineering.md)). The event-log hook
  turns a refused decode into an `EventLogError`. The PCR hook treats it as
  "PCR not present", which fails only under `PCRPolicy.StrictMode`; a
  non-strict policy skips PCRs it cannot find, refused or absent alike
  (`compliance_attestation.go:151-161`).

- **The admin plane resolves every mTLS caller to its qrdb user before the
  permission gate runs.** xkmsd builds the admin plane's authenticator with
  the qrdb SPKI-thumbprint user store (`cmd/xkmsd/admin.go:206-209`), so the
  identity `PermissionGate.Authorize` (`pkg/acme/admin/authz.go:83`) hands to
  qrdb's RBAC carries the user's tenant and **qrdb role IDs** — every role,
  verbatim (`pkg/auth/qrdb_userstore.go:50-59`, `pkg/auth/mtls.go:220`).
  go-qrdb resolves permissions by role ID only; a role name, or a missing
  store, leaves the identity with no resolvable role and every admin route
  answers 403, which is what go-xkms#1069 was. A certificate bound to no user
  still authenticates from its fields but holds no role, so it is refused on
  every route. The admin plane declares no permission of its own: each
  `gate.Wrap` resource:action (`pkg/acme/admin/handlers.go:108-143`,
  `tenant_handlers.go:61-127`) is a qrdb-registered permission that qrdb
  places on its built-in roles — Owner holds all of them; Admin holds all but
  `roles:create`/`roles:update`/`roles:delete`; Operator and Auditor each hold
  a subset of the read/list permissions (qrdb's placement, not restated by
  xkms). `cmd/xkmsd/admin_authz_test.go` walks the published router
  and pins all three properties against a first-boot-seeded node.
- **The admin plane degrades typed, never panics, and never falls back to an
  allow-all authorizer (go-xkms#1075).** `finalizeAdminModule` always
  constructs the admin service, even with ACME disabled: `acme.CA()` and
  `acme.StorageFactory()` are nil for a nil `*acmeServer`
  (`cmd/xkmsd/admin.go:170-176`). Every `AdminService` method that reads
  the CA or storage factory — certificate, account, and order
  listing/lookup, revoke, and `GetStatus`/`GetStats`
  (`pkg/acme/admin/service.go`) — guards its dependency and returns the
  typed `ErrCANotConfigured` / `ErrStorageNotConfigured`
  (`pkg/acme/admin/types.go:40-54`) instead of dereferencing a nil
  interface. `Handlers`' `writeUnavailableIfNotConfigured`
  (`pkg/acme/admin/handlers.go:576`) answers both with RFC 7807's 501 Not
  Implemented, the same shape `ListAuditLogs` already used for a missing
  audit trail. Separately, a nil qrdb client (`srv.QRDBClient() == nil`,
  reachable only if the admin surface is composed without the embedded
  qrdb node it always ships with) is not a degrade-and-continue case:
  `finalizeAdminModule` refuses construction with the typed
  `ErrAdminQRDBClientRequired` (`cmd/xkmsd/admin.go:79,161-167`) rather
  than building `auth.NewAuthorizer(nil)`, which is legitimate
  "RBAC disabled: allow all" elsewhere in the stack but has no such
  meaning on a plane whose `PermissionGate` has no optional-authorization
  mode. `cmd/xkmsd/admin_nildeps_test.go` walks the published router with
  ACME disabled and proves every route answers without panicking, that
  the CA/storage-backed routes answer 501, and that a nil qrdb client is
  refused at construction.
- **The admin plane binds every tenant, role, user, account and certificate a
  request names to the caller's tenant (go-xkms#1225).** The gate binds the
  caller's *own* tenant as the target, so a tenant Admin's self-scoped grants
  pass it for a request naming any tenant; the confinement is the admin
  service's, applied for every transport (REST handlers, the gRPC admin
  server, MCP), in `pkg/acme/admin/tenant_binding.go`:
  - `bindTenantTarget` (`tenant_binding.go:103`) admits a cross-tenant
    caller (`auth.IsCrossTenant`: no identity, empty or system tenant) to
    any tenant and a tenant-scoped caller to its own only. Its refusal,
    `*TenantBindingError` (`:36`), unwraps to `ErrTenantNotFound` and renders
    its message (`:47`, `:53`), so a foreign tenant reads exactly like a
    missing one — the go-xkms#1112 convention `pkg/xkms` follows. Every
    `{id}`-scoped `TenantAwareAdminService` method calls it after the
    empty-ID check (lifecycle, CA hierarchy, EAB, roles, users;
    `tenant_service.go`), and every `{id}` handler repeats it through
    `checkTenantAccess` (`tenant_handlers.go:139`) before the body is read,
    answering `writeTenantNotFound` (`:159`).
  - `requirePlatformScope` (`tenant_binding.go:113`) reserves tenant
    creation (`tenant_service.go:192`, `tenant_handlers.go:185`) and the
    audit trail (`handlers.go:447`) — whose events carry no tenant to
    filter by — to a cross-tenant caller. Its refusal, `*PlatformScopeError`
    (`tenant_binding.go:63`), unwraps to `ErrForbidden` and is answered with
    the gate's own denial body (`writePermissionDenied`, `authz.go:161`).
  - Every `/admin/barrier/*` route operates the **system** barrier, which
    protects every tenant, so all eleven are platform operations
    (go-xkms#1244). The admin plane holds no barrier handle: its
    `BarrierService` (`NewBarrierService`, `barrier_service.go:227`) runs
    every operation through `SystemBarrier` (`barrier_service.go:199`), the
    XKMSService's system-barrier methods, each of which calls
    `pkg/xkms`'s `requirePlatformScope` (`pkg/xkms/tenant_binding.go:88`,
    e.g. `pkg/xkms/servicer_barrier.go:128`) before touching the barrier.
    The gate cannot do it: qrdb grants a tenant's own Admin, SO and
    Custodian roles every `seal:*` / `barrier:*` permission the routes
    declare. `translateBarrierError` (`barrier_service.go:245`) turns the
    service's `*xkms.TenantBindingError` into this plane's
    `*PlatformScopeError`, which `writeBarrierError`
    (`barrier_handlers.go:279`) answers with the gate's denial body, like
    tenant creation and the audit trail. It also maps
    `xkms.ErrNotConfigured` to `*BarrierNotEnabledError` (409, and
    `enabled: false` on status) and `seal.ErrNotInitialized` to
    `*BarrierNotInitializedError` (409). xkmsd hands the routes the
    server's XKMSService (`cmd/xkmsd/admin.go:186-194`,
    `pkg/server/server.go:2820`) and mounts them on the admin router
    (`cmd/xkmsd/admin.go:214`); a server with no composed XKMSService is
    refused at construction with `ErrAdminXKMSServiceRequired`
    (`cmd/xkmsd/admin.go:87`). `MultiProtocolServer` mounts the same
    handlers whenever its admin service carries a `BarrierService`
    (`pkg/acme/api/server/server.go:642`).
  - `ListTenants` returns only the caller's tenant, and counts only it
    (`tenant_service.go:547`).
  - A role or user is looked up before it is returned, updated or deleted,
    and must belong to the tenant the path names — for the platform as for a
    tenant caller (`tenantRole`, `tenant_service.go:1598`; `tenantUser`,
    `:1705`). A foreign one and a missing one are the same
    `ErrRoleNotFound` / `ErrUserNotFound` (`types.go:550`, `:555`). qrdb's
    two role-miss shapes (the embedded role service's and the wire
    transports') are both recognized (`isRoleNotFound`,
    `tenant_binding.go:130`).
  - `/admin/*` certificates, accounts, orders and stats are scoped by the
    caller's tenant. An account belongs to the tenant its `TenantID` names
    (set from the EAB at registration); a tenant-less account is
    platform-owned (`visibleAccounts`, `service.go:551`; `visibleAccount`,
    `:576`). A certificate row records no owner, so a tenant caller sees the
    certificates its accounts' orders were issued (`order.Certificate`,
    `ownedCertificateURLs`, `service.go:669`; `visibleCertificates`, `:635`).
    Get, revoke and disable of anything outside that set are
    `ErrCertificateNotFound` / `ErrAccountNotFound` / `ErrOrderNotFound`,
    as for a missing one (`visibleCertificate`, `service.go:694`).
  - The authentication boundary binds the caller's tenant as the context's
    qrdb tenant (`withUser`, `auth.go:98-101`), because the admin routes are
    public qrdb module routes and qrdb's middleware binds none
    (`cmd/xkmsd/admin.go:109`). qrdb's `EffectiveTenant` enforcement then
    confines every role and user call the service makes through the
    embedded client as well.
- **`PermissionGate.Authorize` (`pkg/acme/admin/authz.go:93`) is the one place
  that logs an admin authorization denial, for every transport.** REST
  (`Wrap`, `authz.go:142-156`), gRPC (`UnaryAuthorizationInterceptor`,
  `pkg/acme/api/server/interceptor_authz.go:133-140`) and MCP
  (`authorizeMCPMethod`, `pkg/acme/api/server/mcp_authz.go:95`) all resolve
  their decision through this one gate, so a `slog.Warn` there — subject,
  tenant, resource, action, the transport's method/route (an `extra
  ...slog.Attr` each caller passes: HTTP method+path, gRPC full method, or the
  MCP JSON-RPC method name), and the authorizer's cause — covers every
  transport without a duplicate log call in each one (go-xkms#1110). The
  cause never reaches the client: REST answers the fixed
  `"Access denied: insufficient permissions"` detail, gRPC the fixed
  `"permission denied: %s requires %s:%s"` message, and MCP's JSON-RPC
  `Forbidden`/`Unauthorized` codes are unchanged by this — only the
  server-side log gained the cause.
- **Every POST carries a fresh nonce, and a nonce is consumed exactly once.**
  Replaying a nonce is rejected, not tolerated.
- **Every POST is JWS-signed by the account key** (or, for `new-account`, by the
  key being registered). The signature, not a session, is the authorization.
- **An order's state machine is one-way**: `pending → ready → processing →
  valid`, or `invalid`. There is no path back from `invalid`. Orders failing
  during finalize transition to `invalid` with an error; they never remain
  stranded in `processing`.
- **Challenge validation is server-initiated.** The client says "ready"; the
  server does the fetching, resolving or credential activation. Nothing the
  client sends about its own state is trusted.
- **`enroll-01` succeeds only if the TPM can activate the credential.** The
  server never accepts a secret it did not itself protect with
  `TPM2_MakeCredential` against the verified EK.
- **A `device-attest-01` attestation authorizes nothing until the CSR's key is
  bound to the attested key.** See device-attest-01 key binding below.
- **Every identifier is checked against the issuance policy engine before
  its authorization is created.** `NewOrderHandler`
  (`pkg/acme/server/handlers/new_order.go`) runs each identifier through
  `pkg/acme/policy` in two phases, and never creates an authorization for an
  identifier that fails either: format validation (RFC 1035 for DNS, RFC
  8738 for IP), which fails `malformed`; then the blocklist, public-suffix,
  and reserved-IP policy, which fails `rejectedIdentifier`. See Identifier
  policy below.
- **CAA (RFC 8659, plus RFC 8657 `accounturi`/`validationmethods`) is checked
  before issuance**, not after. Order finalize (`order_finalize.go`) resolves,
  for every DNS identifier on the order, the account's URI and the RFC 8657
  method-label (`http-01`, `dns-01`, `tls-alpn-01`, `device-attest-01`, ...)
  of the challenge that actually validated that identifier's authorization —
  read from the order's own `ACMEAuthorization`/`ACMEChallenge` records, not
  trusted from the request — and passes both to
  `Params.CAAValidator.Validate` alongside the domain; a rejection moves the
  order to `invalid` with the `caa` problem type. The validator itself
  (`pkg/acme/server/caa.go`) climbs the label tree to the closest non-empty
  CAA RRset, checks `issuewild` for wildcard identifiers and falls back to
  `issue` when no `issuewild` record exists, rejects an unrecognized
  property tag carrying the critical flag regardless of any authorizing
  record, and compares the `issue`/`issuewild` value's issuer-domain-name to
  `acme.caa_identities` as a full domain name — never a prefix. Once the
  issuer domain matches, an RFC 8657 `accounturi` parameter on that record
  further restricts authorization to the ACME account whose URI matches
  exactly (byte-for-byte), and a `validationmethods` parameter restricts it
  to its listed method-labels; either parameter, present and not matched,
  refuses that record without affecting any other record in the RRset. Both
  parameters are parsed per the strict RFC 8659 Section 4.2 `tag=value`
  grammar (unescaped whitespace or a `;` inside a value is not possible
  syntactically); a value that fails that grammar, or a `validationmethods`
  list containing something other than well-formed method-labels, makes that
  specific record non-authorizing per RFC 8657, rather than silently
  ignoring the restriction it was meant to express. A parameter tag this
  validator does not implement is ignored, consistent with the extensible
  parameter model. A DNS failure that prevents determining the RRset
  (SERVFAIL, timeout, any non-NXDOMAIN error) fails closed per RFC 8659
  Section 5.1: it denies issuance rather than "proceeding with caution".
- **Every request body is read once, capped, before anything parses it
  (go-xkms#1171).** `server.RequestBodyMiddleware`
  (`pkg/acme/server/request_body.go:142`) is the first middleware after
  metrics instrumentation on both compositions
  (`cmd/xkmsd/acme.go:609`, `pkg/acme/client/trustedca.go:443`). It reads
  the body through `http.MaxBytesReader` at `server.MaxRequestBodySize`
  (256 KiB, `request_body.go:38`) and replaces `r.Body` with a buffered
  copy; every later consumer — `TenantAuthMiddleware`
  (`handlers/tenant_auth.go:114`), and `parseKID`/`parseJWS` through
  `parseSignedRequest` (`handlers/service.go:1078`) — calls
  `server.RequestBody` (`request_body.go:102`) and gets those bytes without
  touching the connection. A failed read is remembered, so a second caller
  gets the same `*server.RequestBodyError` rather than reading the rest of an
  oversized body. An oversized body is `malformed` with HTTP 413; any other
  read failure is `malformed` with 400 (`RequestBodyError.Problem`,
  `request_body.go:70`). The cap is 256 KiB, not 64 KiB, because a finalize
  carrying a TCG-CSR-IDEVID embeds the UEFI boot event log, and the JWS
  double base64url encoding grows it by 16/9: the real 41,196-byte log in
  `test/integration/tpm2/testdata` alone is ~72 KiB on the wire.
- **Rate limiting is a per-client cap, enforced before RFC 8555 processing
  begins.** `acmeserver.NewClientRateLimiterMiddleware`
  (`pkg/acme/server/rate_limiter.go:266`) is mounted on the whole ACME
  surface — by the standalone `TrustedCA` (`pkg/acme/client/trustedca.go`)
  and by xkmsd's embedded listener (`cmd/xkmsd/acme.go`'s `buildACMERouter`)
  — and keys each client by IP (`server.ClientIP`, which honours
  `X-Forwarded-For`/`X-Real-IP` only from a `server.TrustedProxies` peer).
  It runs before the JWS is verified, so it never keys on the `kid`: an
  unverified `kid` is attacker-chosen, and keying on it let one client mint
  a fresh bucket per request (go-xkms#1171). Exceeding the cap refuses the
  request with `rateLimited`; it does not queue it.
- **A per-account bucket is keyed on a verified account only.**
  `server.ClientID` (`rate_limiter.go:576`) returns the decimal account ID
  that `TenantAuthMiddleware` published with `server.WithVerifiedAccountID`
  (`handlers/tenant_auth.go:131`) after `parseKID` verified the JWS, and the
  client IP otherwise. It never reads the body and never parses a `kid`
  itself.
- **The limiter's lock covers only the bucket arithmetic.**
  `RateLimiter.MiddlewareFunc` (`rate_limiter.go:311`) derives the key,
  calls `RateLimiter.Allow` (`rate_limiter.go:198`) — the only code that
  holds the mutex — and serves the request after the lock is released. A
  slow body, a slow handler, or a synchronous challenge validation against a
  slow target never delays another request.
- **Limiter state is bounded.** A `RateLimiter` evicts a bucket once it has
  been idle for its TTL — `MaxRequests` intervals, the time a drained bucket
  takes to refill, so eviction never grants or withholds a token
  (`RateLimiter.ttl`, `rate_limiter.go:171`) — in a sweep that runs at most
  once per TTL or per minute, whichever is shorter
  (`sweepExpiredLocked`, `rate_limiter.go:235`). It tracks at most
  `server.DefaultMaxEntries` (10,000, `rate_limiter.go:101`) keys; when full
  it refuses a new key with `rateLimited` until one expires, the same
  fail-closed policy `TenantRateLimiter` applies per tenant with
  `MaxEntriesPerTenant` (which now defaults to the same constant,
  `tenant_rate_limiter.go:145`). Of xkmsd's five category limiters
  (`buildACMERouterLimiters`, `cmd/xkmsd/acme.go:722`), new-account is a
  `RateLimiter` and gets these bounds directly; tenant, new-order,
  certificate and failed-validation are `TenantRateLimiter`s, already capped
  per tenant and swept by their cleanup goroutine, and their tenants and
  client keys now come only from verified accounts or the client IP.
- **An order carries at most 100 identifiers.** `NewOrderHandler` refuses a
  larger list with `malformed` (400) before creating any authorization
  (`pkg/acme/server/handlers/new_order.go:36,68`). `malformed`, not
  `rejectedIdentifier`: the request as a whole is refused, not any one
  identifier in it.
- **Tenant admission control is keyed exclusively from an authenticated JWS
  "kid", never from a client-asserted header, host, or path (go-xkms#886).**
  `handlers.RestService.TenantAuthMiddleware`
  (`pkg/acme/server/handlers/tenant_auth.go`) is mounted before dispatch, on
  every route, ahead of every tenant-keyed limiter. For a POST request whose
  JWS protected header names an account (`kid`), it performs the exact
  verification `parseKID` performs — nonce check, JWS `"url"` match,
  signature verification against the account's stored public key — via
  `parseKID` itself, exactly once, and caches the result (success or
  failure) on the request context: `parseKID`'s own later call from inside
  the handler returns the cached result instead of re-verifying, because the
  replay-nonce is single-use (`common.NonceStore.Exists` deletes it on first
  check) and a second live verification would spuriously fail with
  `badNonce`. On success the verified account's `TenantID` is published via
  `server.WithTenantID` for `server.TenantRateLimiterFromRequestContext` to
  read. A request with no `kid` (new-account's JWK-embedded JWS, new-nonce,
  directory, ca-bundle, or any GET) or one whose `kid` fails verification
  never publishes a tenant: those requests are bounded only by the
  per-client limiter above, never by a client-asserted tenant. The older
  `handlers.TenantMiddleware` header/subdomain/path extractor
  (`pkg/acme/server/handlers/middleware.go`) remains unwired anywhere in the
  ACME router for exactly this reason — it trusts a client-supplied
  `X-Tenant-ID` header (or host/path) with no authentication, so using it to
  key admission control would let a client opt out of its own tenant quota,
  or consume another tenant's, by omitting or spoofing the header.
- **The per-tenant overall quota is one bucket shared across every account
  of a tenant, keyed only on the resolved tenant.** `buildACMERouterLimiters`
  (`cmd/xkmsd/acme.go`) mounts a `server.TenantRateLimiter` (operation type
  `"overall"`) via `r.Use`, after `TenantAuthMiddleware`, with
  `tenantSharedClientKey` — a client-key function that always returns `""`
  — as its per-tenant sub-bucket key. `pkg/acme/client/trustedca.go`'s
  standalone `TrustedCA` mirrors this when `WithMultiTenant()` and
  `WithTenantRateLimit(maxRequests, interval)` are both configured. A
  request whose account has no tenant is bucketed under the empty tenant ID,
  which behaves as one shared bucket for every non-tenant account.
- **The RFC 8555 Section 6.6 per-category limits are wired at their
  endpoints (go-xkms#886).** new-account is keyed by client IP via the plain
  `acmeserver.NewAccountRateLimiter` (the tenant is never known before an
  account exists) mounted directly on `POST /new-account`. new-order and
  certificate (enforced at `finalize`) are keyed by account within its
  tenant via `server.NewTenantOrderRateLimiter`/
  `NewTenantCertificateRateLimiter`, mounted on their routes after
  `TenantAuthMiddleware`. failed-validation cannot be blanket route
  middleware — it must count only actual validation failures, not every
  request — so `handlers.Params.FailedValidationRateLimiter`
  (`*server.TenantRateLimiter`) is injected into `RestService` and
  `ChallengeHandler` (`pkg/acme/server/handlers/challenge.go`) calls its
  `Allow` method directly once a challenge has failed: the persisted
  challenge/order state always reflects the attempt, and only the response
  to that specific request changes (RFC 8555 `rateLimited`, 429,
  `Retry-After` via the new `TenantRateLimiter.RetryAfterSeconds` accessor)
  once the account's budget for that tenant is exhausted.
- **A breaker guards the one dependency it wraps, not order creation, and
  degradation never means "issue without validating".** `pkg/acme/server/circuitbreaker`
  is wired into both xkmsd (`cmd/xkmsd/acme.go`) and the standalone
  `TrustedCA` (`pkg/acme/client/trustedca.go`, go-xkms#820). See "Circuit
  breakers and degradation" below for exactly what is and is not covered.
- **An advertised URL is configured or derived, never glued to a bind
  address.** `TrustedCA.Serve` advertises `acme.external_url` (or
  `WithExternalURL`) as given; with neither set it derives the URL from the
  listen address through `acmeclient.AdvertisedURL`, which splits host and
  port, so `0.0.0.0:9443` advertises `https://localhost:9443` and
  `ca.example.com:8443` advertises itself. The standalone client's
  `serve.api_base_url` follows the same rule. Deriving from an address with no
  port is an `AdvertisedURLError` (#140).
- **A CSR's complete identity set must correspond exactly to the order's
  authorized identifiers.** For a `dns`/`ip` order, the CSR's Common Name (if
  present) and every DNS and IP Subject Alternative Name must cover the
  authorized set completely: a name the order authorized but the CSR omits is
  rejected, as is a name the CSR carries that the order did not authorize.
  Email and URI SANs in the CSR are rejected outright (the CA has no
  order-identifier type to authorize them against). Prior to this, only the
  Common Name was compared, which allowed unauthorized SANs through.
- **A `permanent-identifier` order (`enroll-01`'s non-TCG-CSR path,
  `device-attest-01`) never reads the identifier from the Common Name.** The
  CSR's RFC 4043 `permanentIdentifier` otherName (OID `1.3.6.1.5.5.7.8.3`)
  inside its `subjectAltName` is the only source: `ca.ParseOtherNames`
  (`pkg/ca/san.go`) decodes the extension by hand, since `crypto/x509` drops
  otherNames when it parses a CSR. A CSR missing the otherName, carrying more
  than one, or carrying any other otherName is `badCSR` — the shape of the
  request is wrong regardless of the order. A CSR whose otherName decodes but
  names a value the order did not authorize, or whose DNS/IP SANs are not
  exactly the order's authorized `dns`/`ip` identifiers (if any accompany the
  permanent identifier), is `rejectedIdentifier` — well-formed but asserting
  an identity the order does not grant (`matchesPermanentIdentifierOrder`,
  `pkg/acme/server/handlers/order_finalize.go`). Before this, the permanent
  identifier fell back to the Common Name whenever the otherName was absent or
  malformed, and the branch returned as soon as it found the first
  `permanent-identifier` order entry without ever checking the CSR's DNS/IP
  SANs or the order's remaining identifiers (go-xkms#684) — a CSR whose Common
  Name matched could carry an arbitrary, unauthorized DNS or IP SAN straight
  into the issued certificate.
  The `endorse-01` flow is unaffected: its permanent identifier is the EK
  public key being certified rather than a name the CSR carries, so
  `matchesEndorse01Identifier` never compares it against the CSR at all,
  only the CSR's DNS/IP SANs and the blanket email/URI rejection.
- **An endorse-01 EK certificate records the TPM's manufacturer code, or it is
  not issued.** A TPM endorsed through endorse-01 has no manufacturer EK
  certificate, so the EK certificate issued here is the only place a later
  enroll-01 can read the code that heads its §8.1 hardwareModuleName. The
  finalize handler takes the code from the CSR's subjectAltName directoryName,
  validates its form, holds it to any code the account's EAB `deviceInfo`
  names, and passes it to `IssueEKCertificate` (`endorse01TPMManufacturer`,
  `EndorseEABValidator.BoundTPMManufacturer`). Before this the handler passed
  none, and every enroll-01 of an endorsed TPM failed with a bare
  `Failed to sign TCG-CSR-IDEVID`; that failure now logs the CA's error.
- **A certificate's identity is its full serial number, hex-encoded, never
  truncated.** `entities.ACMECertificate.Serial` holds the complete X.509
  serial number (up to 20 octets per RFC 5280 Section 4.1.2.2) as a lowercase
  hex string; it is what the "id" segment of the `/acme/cert/{id}` URL
  carries and what certificate fetch, revocation, and admin lookups key on.
  The DAO's own numeric row key (`NumericID`) is an FNV-1a hash of Serial,
  kept only to satisfy the generic DAO's `uint64` entity-ID contract - it is
  never a certificate's public identity. Before go-xkms#744, the ID was the
  serial's low 64 bits, so two certificates whose 128-bit serials happened to
  share those bits collided in storage.
- **A 64-bit hash still leaves a residual collision risk, and it is
  handled, not assumed away.** `CertificateHandler` and `RevokeCertHandler`
  compare the fetched row's `Serial` against the requested serial and treat
  a mismatch as not-found - a hash collision can only ever produce a 404,
  never the wrong certificate. `storage.SaveCertificateNoCollision` (used
  by both `OrderFinalizeHandler` and the ACME client's local certificate
  cache) refuses to let a save silently overwrite a different certificate
  at the same row, returning `*storage.CertificateSerialCollisionError`;
  it uses `GenericDAO.SaveIfAbsent` atomically when the backing KVStore
  supports it (see pkg/storage/kvadapter), and falls back to a
  Get-then-Save sequence otherwise - a fallback that is NOT atomic against
  a second, concurrent writer racing to the same row, because sdk/go does
  not re-export a sentinel this package could use to positively confirm
  "no atomic support" versus some other `SaveIfAbsent` failure without
  reaching past the SDK boundary into `go-qrdb/pkg/dao` directly.
- **Revocation requires byte-equality with the stored certificate.** The
  submitted certificate's serial number is looked up, but because the returned
  record's identities must authorize the revocation and the submitted bytes are
  entirely attacker-controlled, every authorization decision uses the stored
  certificate's identities, not the submitted one's. A self-signed certificate
  forged with a victim's serial number cannot bypass this check.
- **Revocation calls canonical CA revocation,** ensuring OCSP and CRL agree on
  the revoked set.
- **Tenant-bound issuance fails closed.** If issuance is configured to bind to a
  specific tenant's CA and that CA is not available, the issuance fails; there
  is no fallback to the global CA. The signer certificate and issuer certificate
  must match.
- **Sessions are claimed atomically before validation.** A WebAuthn ceremony
  session is single-use. The ceremony finish path claims the session with `Take`
  (an atomic claim-and-remove operation) BEFORE validating the authenticator
  response, not after. A non-atomic path where validation completes first leaves
  a window in which two concurrent finish requests can both validate the same
  challenge and both succeed.

## device-attest-01 key binding

The challenge verifies the evidence; finalization binds it to the CSR. Both
formats (`tpm`, `dice`) bind through the CSR, so `Verify` returns
`ErrKeyBindingRequired` for both (`deviceattest01.go:233`) and a server holds
the `VerifiedAttestation` between the two requests
(`pkg/acme/challenges/device-attest-01/binding.go`).

**`tpm` at the challenge** — `verifyTPMEvidence` (`tpm.go:65`) applies WebAuthn
Level 2 §8.3, after `VerifyAttestation` has anchored every `x5c` entry through
`AttestationVerifier.VerifyAKCertificateChain` (`deviceattest01.go:318`; an
entry that is not a byte string refuses the chain rather than being dropped):

| Check | Where |
|---|---|
| `ver` is `"2.0"`; `x5c` present; `x5c[0]` parses | `tpm.go:65` |
| `x5c[0]` meets §8.3.1: version 3, empty subject, TCG SAN naming manufacturer/model/version (EK Credential Profile §3.2.9), not a CA | `checkAIKCertificate`, `tpm.go:155` |
| `x5c[0]` carries EKU `tcg-kp-AIKCertificate` (2.23.133.8.3) — the certificate-side stand-in for "restricted signing key" | `certifiesAttestationKey`, `pkg/tpm2/certify_verify.go:238` |
| `sig` verifies over `certInfo` under `x5c[0]` with `alg` (WebAuthn L2 §6.5.6 encoding: DER for ECDSA) | `VerifyCertifyByCertificate`, `pkg/tpm2/certify_verify.go:199` |
| `certInfo` magic is `TPM_GENERATED_VALUE`, type `TPM_ST_ATTEST_CERTIFY`, attested Name = Name(`pubArea`) under `pubArea`'s nameAlg | `verifyCertifiedObject`, `pkg/tpm2/certify_verify.go:250` |
| `extraData` equals `TPMExtraData(alg, keyAuthorization)` — the `alg` hash of the key authorization; a mismatch is `ErrStaleEvidence` | `tpm.go:205`; `pkg/attestation/invariants.go:304` |

`TPMExtraData` is the key authorization hashed with `alg`'s hash: §8.3's
`extraData = H_alg(attToBeSigned)`, with `attToBeSigned` the key authorization
because draft-ietf-acme-device-attest's attestation carries no authenticator
data. For the SHA-256 algorithms it equals `DICENonce`. An unknown `alg` is
refused, never defaulted.

**`tpm` at finalization** — `BindCSRKey` (`binding.go:142`) checks the CSR
self-signature, then `tpmCSREvidence` (`binding.go:188`) re-submits the
recorded `certInfo`/`sig`/`pubArea`/`x5c[0]` to the gate with the CSR's
SubjectPublicKeyInfo. `verifyTPMCertifyBinding` (`invariants.go:304`) repeats
every certification check and then requires `pubArea`'s key to equal the CSR's
key, compared as keys rather than encodings (`verifyCertifiedKeyIsSubjectKey`,
`invariants.go:373`). The record carries only bytes (`LeafDER`, `CertInfo`,
`Signature`, `PubArea`, `Algorithm`), so it survives storage between the two
requests.

**One gate.** The TPM2 profile identifies its attester by public area
(TCG-CSR-IDEVID) or by certificate (`Evidence.AttesterCertificate`, this
format) — never both — and reads its challenge from the certification's
`extraData` (`challengeInCertify`, `invariants.go:167`). A TCG-CSR caller that
supplies no `SubjectSPKI` and no challenge is checked exactly as before.

**What an anchoring implementation must know.** An AIK certificate's SAN is
critical and holds only a `directoryName`, which `crypto/x509` reports in
`UnhandledCriticalExtensions`; `checkAIKCertificate` reads it, so the
`AttestationVerifier` must treat it as handled when it verifies the chain.

**The client side.** `deviceattest01.Setup` (`setup.go:115`) has the IAK
certify the certificate key with `pkg/tpm2`'s `CertifyKey` over
`TPMExtraData(alg, keyAuthorization)`. `alg` is the IAK's own signature
algorithm (`coseAlgorithms`, `setup.go:84`), and `x5c` is `IAKCertificate()`.
In `pkg/acme/client`, `TPMModule.CreateAttestedKey` (`tpm.go:192`) is the one
entry point. The adapter (`tpm.go:477`) keeps the certificate key under the
Platform SRK, named by the common name, and reuses it on later attestations.
`DeviceAttest` signs the finalize CSR with that key and names the order's
permanent identifier in the RFC 4043 otherName (`deviceAttestCSR`,
`enrollment.go:887`). The account key never signs this CSR. PCR state is not
part of the statement, so the device spec's `pcr-selection` does not reach the
evidence.

**`IAKCertificate()` must resolve for `Setup` to build a statement at all.**
`EnrollDevice` installs the IAK certificate it receives at finalization via
`TPMModule.ProvisionIAKCert` (`enrollment.go`, `tpm.go`) immediately after
parsing it from the finalized chain, so a later `device-attest-01` --
including one run against the same TPM in a separate process, the normal
case on real hardware -- finds it. Before go-xkms#1100 this call did not
exist: enrollment parsed and returned the certificate but never installed
it, so `IAKCertificate()` only ever resolved on the in-process TPM simulator
(`pkg/acme/client/service.openDeviceTPM`'s development-only
`provisionSimulatorIAKCertificate`, which re-mints a throwaway certificate on
every open regardless of what enrollment issued) or when an operator
installed one some other way. A hardware device with no `IAK.CertHandle`
configured also needs somewhere for `ProvisionIAKCert` to persist to:
`openDeviceTPM`'s hardware branch is given `store.FileCertStore`
(`pkg/tpm2/store`), backed by the same `storage.Backend` the device's key
blobs already persist to, so the certificate survives a process restart.

## Challenge validation client

Every verifier that contacts a target the ACME client named -- `http-01`,
`enroll-01` (both its GET of the TCG-CSR-IDEVID and its POST of the
credential challenge), and `device-attest-01` -- does so through one
`*validation.Client` (`pkg/acme/challenges/validation/client.go:94`). The
target is attacker-chosen: a `permanent-identifier` is an opaque string, and
before go-xkms#1172 `enroll-01` spliced it into
`fmt.Sprintf("http://%s:%s%s%s", ...)`, so a value like
`169.254.169.254/latest/meta-data/#` chose the host, path and port of a
server-side GET and POST, and the challenge's `error.detail` echoed back the
status or dial error. `endorse-01` makes no request and does not use the
client.

What the client guarantees:

- **The URL is built, not formatted.** `Target.URL`
  (`client.go:155`) requires `policy.ValidateNetworkTarget`
  (`pkg/acme/policy/validator.go:346`) -- a bare RFC 1123 hostname or a
  canonical, zone-free IP literal -- and a TCP port, then assembles
  `url.URL{Scheme: "http", Host: net.JoinHostPort(host, port), Path: path}`.
  A host carrying `/ ? # @ :` or whitespace is `KindInvalidTarget` before any
  request.
- **Reserved addresses are refused at dial time.** Unless
  `acme.challenges.allow_private_targets` is set, `NewClient` wires the
  `net.Dialer.Control` hook to `netguard.DialControl(netguard.DenyReserved)`
  (`client.go:98-104`, `pkg/netguard/dial.go`), which rejects any connection
  whose resolved address satisfies `netguard.ReservedAddr`
  (`pkg/netguard/reserved.go`): loopback, RFC 1918 / RFC 4193 private,
  link-local (169.254/16 including the cloud metadata address, fe80::/10),
  multicast, unspecified, CGNAT 100.64/10, the TEST-NETs, 240/4, NAT64, 6to4
  and the other special-purpose ranges, with IPv4-mapped IPv6 unmapped
  first. The hook sees the address actually being connected to, after
  resolution, so a public-looking name that resolves (or re-resolves, DNS
  rebinding) to an internal address is refused. `netguard.ReservedAddr` is
  the one reserved-address classification in go-xkms: the CA's AIA/CRL
  fetch client (`pkg/ca/pki_fetch.go`, see
  [`../certificate-authority/engineering.md`](../certificate-authority/engineering.md))
  and the `rejectReservedIPs` identifier policy
  (`policy.IsReservedIP`, `validator.go:336`, which delegates to it) both
  use it, so an address one refuses is reserved for all three.
- **No proxy.** The transport's `Proxy` is nil (`client.go:122`), so the
  address checked is the address dialed.
- **Redirects.** `http-01` follows up to `MaxRedirects` (10) `http`/`https`
  redirects, RFC 8555 section 8.3; each hop dials through the same transport,
  so the dial-time check re-runs per hop (`redirectPolicy`, `client.go:244`).
  `enroll-01` and `device-attest-01` refuse redirects.
- **Bounded responses.** `readLimited` (`client.go:226`), built on
  `netguard.ReadLimited` (`pkg/netguard/body.go`), reads through
  `io.LimitReader(limit+1)` and refuses -- does not truncate -- a body over
  the limit (`KindResponseTooLarge`). The default is `DefaultMaxResponseBytes`
  (64 KiB, `client.go:64`); `enroll-01` raises it for the CSR fetch to the
  base64url length of `tpm2.MaxIDevIDCSRSize`
  (`pkg/acme/challenges/enroll-01/enroll01.go:136`), because the TCG-CSR
  carries the boot event log.
- **Generic client errors.** Failures are `*validation.Error`
  (`pkg/acme/challenges/validation/errors.go`) whose `Kind` is a fixed,
  client-safe category. `ChallengeHandler` logs and audits the full error but
  returns only `challengeProblem(err)`
  (`pkg/acme/server/handlers/challenge.go:47`): `connection` with
  `"Challenge validation failed: <category>"` for a transport failure, and
  `incorrectResponse` with `"Challenge validation failed"` for everything
  else. A refused target reads exactly like any other connection failure, so
  the challenge is not an oracle for which names resolve internally.

One client is built per ACME server: `buildChallengeMap`
(`cmd/xkmsd/acme.go:486`) for xkmsd, and a `TrustedCA` embedder builds its
own with `NewACMEChallengeClient` (`sdk/go/acme`) and passes it to
`http01.Verify` / `ACMEAttestationVerifiers(client, enroll, endorse)`.

## Circuit breakers and degradation

`pkg/acme/server/circuitbreaker` is the one circuit breaker implementation
(go-xkms#735 folded the previously-duplicated HTTP middleware into it).
`circuitbreaker.Manager` holds two kinds of breaker:

| Kind | Registered as | Guards | Wired by |
|---|---|---|---|
| Named (one breaker) | `ct` | CT log submission (`ct.LogSubmitter`) | `circuitbreaker.WrapLogSubmitter` — no production call site yet; see architecture.md |
| Named (one breaker) | `kms` | `Params.KMSService` (the tenant KMS signer) | `handlers.NewRestService`, automatically, when both `Params.Breakers` and `Params.KMSService` are set |
| Named (one breaker) | `storage` | CA/keystore-backed certificate storage (`CA.CABundleFiltered`, `GET /acme/ca-bundle`'s dependency) | `handlers.NewRestService`, from `Params.StorageBreaker` |
| Per-target group | `http01` | the `http-01` challenge verifier, **one breaker per validation target (domain)** | `cmd/xkmsd/acme.go:buildChallengeMap` and `TrustedCA.Serve` (`pkg/acme/client/trustedca.go`, go-xkms#820), both via `pkg/acme/server/resilience.go`'s `WrapChallengeVerifiers` -> `circuitbreaker.WrapChallengeVerifierPerTarget` |
| Per-target group | `dns01` | the `dns-01` challenge verifier, **one breaker per validation target (zone)** | same, `WrapChallengeVerifiers` -> `circuitbreaker.WrapChallengeVerifierPerTarget` |

A named breaker (`Manager.Get`/`GetOrCreate`) is a single instance for a
single, operator-configured dependency: safe to list in full on
`GET /acme/health` (`Manager.List`/`Status`) because there are only ever a
handful. A per-target group (`Manager.TargetBreaker`,
`pkg/acme/server/circuitbreaker/target.go`) is different: its keys are
whatever validation target a caller names, which is attacker-influenced
input, so it cannot be a single breaker (go-xkms#1189/#1190, see below) or
an unbounded one (it would be attacker-controlled memory growth). It is a
bounded, LRU-plus-idle-TTL table of per-target `CircuitBreaker` instances
scoped under a group name ("http01", "dns01"), reported only through
`Manager.TargetGroupStatuses` — a fixed-size summary, never a per-target
listing (see `GET /acme/health` below).

`WrapChallengeVerifiers` (`pkg/acme/server/resilience.go`) is the one place
that decides which challenge-map entries get wrapped and under which group
names: it copies the map, wraps the `http-01` and `dns-01` entries (when
present) with a per-target breaker group from the `Manager` it is given, and
returns every other entry — the TPM attestation verifiers
`sdk/go/acme.ACMEAttestationVerifiers` builds, for instance — unchanged. It
also calls `Manager.RegisterTargetGroup` for each group it wraps, so
`http01`/`dns01` are visible in `GET /acme/health` immediately, before any
target has been validated. `cmd/xkmsd/acme.go`'s `buildChallengeMap` calls
`WrapChallengeVerifiers` after selecting verifiers from `acme.challenges`;
`TrustedCA.Serve` calls it on whatever map a caller supplied through
`WithChallengeMap`. A nil `Manager` (resilience not wired) or nil map
returns the input unchanged.

**Per-target breakers, and refused targets excluded from them**
(go-xkms#1189, #1190, #1181). Before go-xkms#1189/#1190, `http01` and
`dns01` were each a single breaker for the whole server: one account whose
validation target always failed a) tripped the breaker for every other
account's `http-01` (or `dns-01`) validation, and b) for `dns-01`, a slow
authoritative name server for one account's zone could stall admission for
every zone, because the breaker's timeout is what bounds a call, and every
call shared the one breaker's admission state. `WrapChallengeVerifierPerTarget`
(`pkg/acme/server/circuitbreaker/decorators.go`) closes this: it resolves
(creating on first use) the breaker for `authzValue` — the domain http-01
dials, or the zone dns-01 queries, the only attribution the verifier's
signature actually gives the wrapper (there is no visibility into which
authoritative name server `net.Resolver.LookupTXT` contacted for dns-01) —
within the group's bounded table, via `Manager.TargetBreaker`. A failing or
slow target now only ever affects its own breaker; every other target's
admission is decided independently.

The bounded table (`circuitbreaker.TargetConfig`, `target.go`) is an
LRU-ordered `container/list` under one `sync.Mutex` per group: every
touch (creation or lookup) moves the target to the front, so the entry at
the back is simultaneously the least recently used and the longest idle,
and both `Capacity` eviction (trim the back on overflow) and `IdleTTL`
eviction (prune expired entries from the back) work off the same list.
`ACMECircuitBreakerConfig.TargetCapacity` /`TargetIdleTimeoutSeconds`
(`target_capacity` / `target_idle_timeout_seconds` in the `http01`/`dns01`
YAML sections; see "Configuration" below) bound it — defaults 1000 targets
/ 10 minutes idle (`circuitbreaker.DefaultTargetCapacity`,
`DefaultTargetIdleTTL`) — so a flood of distinct hosts cannot grow the
table without bound.

As before go-xkms#1181, a challenge the validation client refuses without
contacting the target does not count toward that target's breaker.
`WrapChallengeVerifierPerTarget` runs the verifier through the resolved
breaker's unexported `execute` (`circuitbreaker.go:214`) with
`validation.IsTargetRejected` (`pkg/acme/challenges/validation/errors.go:99`)
as its exclusion predicate. A `*validation.Error` of `KindInvalidTarget` or
`KindTargetRefused` -- a failure the validation client decided without
contacting the target -- is returned to the verifier's caller unchanged but
is not recorded (`circuitbreaker.go:242`): it is neither a failure nor a
success, so it cannot open the target's breaker and cannot reset its
failure count either. `releaseAdmission` (`circuitbreaker.go:258`) gives
back a half-open slot such a call held, under the same generation rule as
`afterRequest`. This still matters per-target: without it, an account could
still open its own target's breaker for free by naming a reserved address,
which is merely pointless self-sabotage rather than the cross-account denial
of service #1181 originally fixed, but excluding it keeps a refused target's
breaker meaningful as a signal of real reachability problems.

`storage` here is **not** the go-qrdb-backed ACME protocol state
(`pkg/acme/storage` → `go-qrdb/sdk/go`, accounts/orders/authorizations/
challenges/nonces). That storage is not wrapped in a circuit breaker: its
consistency and retry semantics are go-qrdb's, "lower layers win", and a
breaker's `Execute`/`ExecuteContext` abandon their goroutine on a
breaker-imposed timeout without waiting for it — safe for an idempotent read
or a third-party network call, wrong for a durable write whose caller must
not believe it failed while it is still committing. The candidate wrapping
point on the ACME side — `storage.Factory`'s `AccountDAO`/`OrderDAO`/etc.
constructors — does no I/O and never fails for a reason a breaker should
react to, only on malformed input (e.g. a zero account ID), so wrapping it
would trip the breaker on bad requests rather than backend health. Both are
deliberate omissions, not gaps.

An open breaker fails only the one call it guards:

- A `http-01`/`dns-01` breaker open makes `ChallengeHandler`'s validation
  attempt fail immediately with `incorrectResponse` instead of hanging on a
  dead verifier target for its own timeout.
- A `kms` breaker open makes `OrderFinalizeHandler`'s tenant-CA signing path
  fail (`getTenantCASigner`/`tenantIssuerCertificate` in
  `order_finalize.go`).
- A `storage` breaker open falls back to `pkg/acme/server/degradation`'s
  cache for `GET /acme/directory` and `GET /acme/ca-bundle` (see below)
  rather than failing those two GET endpoints outright.

None of these intercepts `POST /acme/new-order`: creating an order writes
only to the (unwrapped) ACME protocol state and calls none of the five
guarded dependencies. An operator reading "the circuit breaker" as a gate in
front of order creation is reading a claim this feature does not make; a
previous revision of this document did make that claim and was wrong (see
git history on this section, go-xkms#735).

**Degradation.** `RestService.serveOrDegrade` (CABundleHandler) runs its
compute through the `storage` breaker and, on any failure — the breaker
open, too many half-open probes, or a genuine `CA.CABundleFiltered` error —
falls back to `pkg/acme/server/degradation.Cache`'s last entry: still-fresh
(within `Resilience.Degradation.CacheTTLSeconds`) is served as a normal
response, stale-but-within-`StaleTTLSeconds` is served with a
`Warning: 110 - "Response is stale"` header, and no usable entry propagates
the failure. `RestService.serveCachedWhenOpen` (DirectoryHandler) only peeks
at the `storage` breaker's state — it never calls `Execute` — because
building the directory has no fallible call of its own; running it through
the same breaker as CABundleHandler would let cheap, always-succeeding
directory requests consume the breaker's half-open probe budget instead of
CABundleHandler's real recovery test. Both endpoints share one cache entry
each (`Resilience.Degradation.MaxCacheSize`, default 8, is generous for a
one-entry-per-endpoint cache).

`GET /acme/health` (`RestService.HealthHandler`, `HealthStatus`) reports two
things:

- `Breakers` — every *named* breaker registered on `Params.Breakers`
  (`storage`, `kms`, `ct` when wired) by name: state, failure count,
  success count. `Healthy` (and the 503/200 status) is driven only by this
  set.
- `TargetGroups` — `Manager.TargetGroupStatuses()`, one bounded
  `circuitbreaker.TargetGroupStatus` per per-target group (`http01`,
  `dns01`): `Capacity`, `Tracked`, `Closed`, `HalfOpen`, `Open`, and
  `TopOpen` (at most `circuitbreaker.TargetGroupTopOpenLimit` = 10 currently
  open target names). This does **not** affect `Healthy`: one account's
  failing validation target opening its own breaker is expected, isolated
  behavior (that isolation is the entire point of go-xkms#1189/#1190), not
  evidence that the server itself is degraded the way an open `storage` or
  `kms` breaker is. It is also why `TargetGroups` cannot be folded into
  `Breakers`: a per-target listing would grow with attacker-chosen input,
  where `Breakers` is a small, fixed, operator-configured set.

A `RestService` built without `Params.Breakers` reports healthy with both
maps empty rather than omitting the endpoint. `cmd/xkmsd/acme.go` opts in
(`Params.Breakers`, `StorageBreaker`, `KMSBreaker`, all sourced from
`acme.resilience` — see "Configuration"); the standalone `TrustedCA` path
(`pkg/acme/client/trustedca.go`) now opts in the same way (go-xkms#820),
sourcing the same four fields from `TCAACMEConfig.Resilience` — reusing
`config.ACMEResilienceConfig` directly rather than a parallel type, so a
`storage`/`kms`/`http01`/`dns01` breaker section means the same thing in
either composition's configuration file. `TrustedCA.Serve` builds its
breaker `Manager` unconditionally, same as `cmd/xkmsd/acme.go` — there is no
"resilience disabled" switch, matching `ACMEResilienceConfig`'s own
always-on defaults — so `GET /health` always lists at least the `storage`
breaker, plus an `http01`/`dns01` entry in `TargetGroups` (registered by
`WrapChallengeVerifiers`, empty until a target is validated) when the
caller-supplied challenge map (`WithChallengeMap`) has those entries.

## Error semantics

ACME errors are RFC 8555 problem documents with URN types (`urn:ietf:params:acme:error:*`).
Internal typed errors are `pkg/acme/errors` and
`pkg/acme/server/handlers/errors.go`; the CA-layer errors are
`pkg/ca/errors.go`.

The mapping an implementer needs:

| Internal condition | ACME problem type | HTTP |
|---|---|---|
| bad or replayed nonce | `badNonce` | 400 |
| JWS signature invalid | `malformed` / `unauthorized` | 400 / 401 |
| account does not exist | `accountDoesNotExist` | 400 |
| identifier not allowed by policy | `rejectedIdentifier` | 403 |
| CAA forbids issuance | `caa` | 403 |
| challenge validation failed (fixed detail, never the verifier's error; see "Challenge validation client") | `incorrectResponse` / `connection` / `dns` | 403 |
| rate limit exceeded | `rateLimited` | 429 |
| request body over `MaxRequestBodySize` (256 KiB) | `malformed` | 413 |
| more than 100 identifiers in one new-order | `malformed` | 400 |
| order not ready to finalize | `orderNotReady` | 403 |
| CSR does not match the order (`dns`/`ip` orders) | `badCSR` | 400 |
| permanent-identifier CSR missing/malformed/extra otherName | `badCSR` | 400 |
| permanent-identifier or DNS/IP SAN not authorized by the order | `rejectedIdentifier` | 401 |

**Fail closed:** unvalidated authorization, failed CAA, an undetermined CAA
RRset (DNS failure), failed attestation, an exceeded rate limit (standalone
`TrustedCA` only — see Invariants above), and, on xkmsd, an open circuit
breaker on a dependency the order's path needs (a challenge verifier during
validation, the KMS signer during finalize). Every one of them refuses to
issue for that order. None of them refuses `POST /acme/new-order` itself —
creating an order calls no breaker-guarded dependency; see "Circuit breakers
and degradation".

## Configuration

ACME configuration lives in the server config (`pkg/config`). The
cluster-enrollment block is the one with non-obvious semantics —
`RaftACMEEnrollmentConfig` (`pkg/config/config.go:703`):

```yaml
cluster:
  raft_enrollment:
    key_backend: tpm2
    acme:
      enabled: true
      directory_url: "https://node1.example.com:8443/api/v1/acme/directory"
      challenge_port: "8080"
```

- `enabled` switches Raft node certificate provisioning to attested mode.
- `directory_url` is **required on joining nodes and ignored on the first
  node**, which issues in-process from the local `TrustedCA`.
- `challenge_port` is the local HTTP port the joining node serves the
  `enroll-01` credential-activation exchange on; the ACME server dials back to
  it. Defaults to `"8080"`. The listener binds `server.host`, like every other
  daemon listener: the composition root passes it as
  `clusterca.ACMEOptions.ChallengeHost`, which becomes
  `acmeclient.EnrollmentConfig.ListenHost` and is joined with the port through
  `net.JoinHostPort` (#140).
  **It must be `"8080"`** (or, for `endorse-01`/`device-attest-01`, that
  challenge's own fixed default): the server always validates an enroll-01
  family challenge against the challenge type's fixed default port
  (`isEnrollXChallenge` in `pkg/acme/server/handlers/challenge.go`), never a
  port the client advertises. A challenge type carries no port information —
  `createChallenges` (`new_order.go`) only ever offers the bare registered
  type string. A now-removed helper, `parseChallengeAsDynamicPortAssignment`,
  could parse a port suffix out of a challenge type (`"enroll-01-8880"`), but
  nothing ever produced one, so it never routed a challenge anywhere; it was
  deleted rather than wired up; offering a client-chosen port is a protocol
  change that needs its own design decision (#1183).
- `Validate(keyBackend)` currently accepts any backend. The doc comment states
  why: in-process issuance on the first node stamps a key-provenance OID for any
  backend, and a joining node's challenge is selected by backend at runtime
  (`tpm2` → `enroll-01`; other backends → CSR enrollment). A software-only
  cluster is therefore valid configuration, and an unimplemented joiner path
  surfaces a precise runtime error rather than a config-time one.

`RaftACMEConfigError` (`Field`, `Reason`) renders as
`cluster: raft_enrollment.acme.<field>: <reason>`.

`acme.nonce` (`ACMENonceConfig`, `pkg/config/acme.go`) configures the
Replay-Nonce service, `pkg/acme/nonce`:

```yaml
acme:
  nonce:
    lifetime: 10m   # ACMENonceConfig.ResolveLifetime; 0 selects DefaultACMENonceLifetime
    max_used: 65536 # ACMENonceConfig.ResolveMaxUsed; 0 selects nonce.DefaultMaxUsed
```

Both are optional with the documented defaults, and both are also
`handlers.Params` fields (`NonceLifetime`, `NonceMaxUsed`) for an embedder
that does not go through `pkg/config`. See Persistence below for how they
bound the service's memory, and #733 for the multi-node gap
(`handlers.Params.NonceKey`) neither field closes.

`acme.enrollment.allow_loopback_identifier` (`ACMEEnrollmentConfig`,
`pkg/config/acme.go`) gates a development-only substitution in
`ChallengeHandler` (`pkg/acme/server/handlers/challenge.go`): when an
enrollment challenge's (`enroll-01`/`endorse-01`/`device-attest-01`)
permanent-identifier is the literal `127.0.0.1`, the handler can validate
against the request's client IP (or the first `X-Forwarded-For` entry)
instead of the identifier, so a device that registered with a loopback
identifier is still reachable at its real address. Off by default
(`XKMS_ACME_ENROLLMENT_ALLOW_LOOPBACK_IDENTIFIER`): with the key false, a
loopback identifier is refused with `ErrLoopbackIdentifierNotAllowed` before
the challenge verifier runs, rather than being silently substituted (#140).

`acme.challenges.allow_private_targets` (`ACMEChallengesConfig`,
`pkg/config/acme.go:756`; `XKMS_ACME_CHALLENGES_ALLOW_PRIVATE_TARGETS`)
lets the challenge validation client connect to reserved addresses --
loopback, private, link-local, metadata. Off by default, which is the
production setting. It exists for the test lanes, whose challenge targets
are loopback or container-network addresses, and for lab deployments whose
devices sit on a private network. With `allow_loopback_identifier` on, the
substituted client IP is itself a private address in most labs, so both keys
are normally set together there (go-xkms#1172).

The xkmsd ACME listener (`acme.tls`, `ACMEConfig` / `ACMETLSConfig`,
`pkg/config/acme.go`) always uses its own dedicated TLS certificate/key pair;
`acme.tls.cert_file` and `acme.tls.key_file` are required whenever
`acme.enabled` is true (`ErrACMEMissingTLS`), enforced by
`buildACMETLSConfig` in `cmd/xkmsd/acme.go`. There is no option to reuse the
primary xkmsd TLS material — the xkmsd TLS stack is authenticated against the
xkmsd REST/gRPC server CN and would generally not match an ACME client's
expected hostname. The `acme.reuse_tls` key that once gated this (and was
refused at start-up rather than actually working) is deleted from the schema;
`pkg/config.Load` rejects a file or environment variable that still sets it
with a typed `*config.RemovedFieldError{Field, Replacement}` before the
decoder gets a chance to silently drop it. This reuses the general removed-
field mechanism go-xkms#653 introduced for `barrier.passphrase`:
`removedConfigFields` (`pkg/config/load.go`) maps a dotted key to its
replacement guidance, and `rejectRemovedFields` — run on the merged viper
instance after the file is read and before `Unmarshal` — binds each key to
its canonical `XKMS_`-prefixed environment name, so a stale
`XKMS_ACME_REUSE_TLS` is rejected exactly like a stale file key, and fails
with `*RemovedFieldError` if either source still sets it. Adding a future
field deletion is one entry in that table (go-xkms#694).

The standalone `TrustedCA` (`pkg/acme/client/trustedca_config.go`) is a
separate configuration surface — not built from `pkg/config` and not read
through viper — so it carries its own copy of the same switch:
`TCAACMEConfig.AllowLoopbackIdentifier` (`allow_loopback_identifier`), also
off by default, threaded into `handlers.Params.AllowLoopbackIdentifier` in
`TrustedCA.Serve`. An embedder configuring `TrustedCAConfig` directly (rather
than through xkmsd) sets this field itself; there is no `XKMS_`-prefixed
environment name for it (#140).

**Multi-tenancy is a construction-time `Option`, not a `TrustedCAConfig`
field (`options.go` `WithMultiTenant`, `trustedca.go` `tca.multiTenant`,
go-xkms#946).** `WithMultiTenant()` is the only switch: it sets the
unexported `TrustedCA.multiTenant` bool that `validate` and `initialize`
read to require a QRDB service (`ErrMissingQRDB` otherwise) and to construct
`admin.NewTenantAwareAdminService` instead of `admin.NewAdminService`. A
`TrustedCAConfig.MultiTenant` section (`Enabled`, `DefaultTenantID`,
`TenantIsolation.{EnforceIsolation,AllowCrossTenantSuperAdmin}`) existed
alongside it — defaulted by `DefaultTrustedCAConfig` and checked by
`Validate` — but nothing in `pkg/acme/client` or `pkg/acme/admin` ever read
those fields: an operator setting `multi_tenant.enabled: true` in a config
file got a single-tenant server with no error, because `WithMultiTenant()`
was the only thing `New` actually consulted. It traces to the go-trusted-ca
heritage of this package and was never wired to xkms's own
`admin.TenantAwareAdminService`, which takes no tenant-default or
isolation-level parameter. The fix picks the option as the one interface
(go-xkms#946) rather than wiring the config section, to match how xkmsd's
embedded ACME server decides multi-tenancy: `cmd/xkmsd/admin.go`
`finalizeAdminModule` always calls `admin.NewTenantAwareAdminService`
directly, and `pkg/config.ACMEConfig` (`pkg/config/acme.go`) has no
multi-tenant key at all — the switch there is structural (which constructor
runs), not a boolean read from config. `DefaultTenantID` and
`TenantIsolation` had no runtime meaning anywhere in the tree (confirmed by
searching every package for the field names before deleting them), so
neither was wired; the whole `MultiTenantConfig`/`TenantIsolationConfig`
section, its `Validate` method, and the `multi_tenant:` YAML key were
deleted rather than kept as a second, inert switch.

**`TrustedCAConfig.Validate` runs once, at construction, and fails closed
(`trustedca.go` `New`, `trustedca_config.go` `TrustedCAConfig.Validate`,
go-xkms#938).** `client.New` calls `tca.config.Validate()` after applying
every `Option` and before `initialize()`; an invalid standalone `TrustedCA`
config no longer constructs (previously `Validate` existed but neither `New`
nor `Serve` called it, so a config missing `acme.ca_identifiers` or a
malformed `acme.external_url` would construct and run — go-xkms#938). A nil
config (`WithConfig(nil)`) fails the same way rather than panicking on a nil
receiver. `Serve` never calls `Validate` again: it reads the fields `New`
already validated and resolved. Every rule returns a typed
`*errors.TrustedCAError` (`errors.MalformedError`, `caerrors.Malformed`),
checkable with `errors.Is`/`errors.As`.

The standalone `TrustedCA` also carries its own advertised URL,
`acme.external_url`. Unlike `acme.https_addr` and `acme.ca_identifiers`,
`Validate` does **not** require it: `TrustedCA.Serve` derives an origin from
the listen address (`AdvertisedURL`, see Invariants) when neither
`WithExternalURL` nor `acme.external_url` is set, and `Validate` has no
visibility into whether a caller will supply the option — requiring the
config field unconditionally would refuse that supported,
`New`-constructible derivation path (proven by
`TestTrustedCA_Serve_DerivesExternalURLFromListenAddress`,
go-xkms#140/go-xkms#938). When `acme.external_url` **is** set, `Validate`
still requires it to parse as an absolute URL with an `https` scheme and a
host.

**Audit log path (`TrustedCAConfig.DataDir`, `trustedca_config.go`,
go-xkms#929, go-xkms#938).** `DefaultTrustedCAConfig` enables the audit trail
but leaves `Audit.LogPath` empty; `TrustedCAConfig.Validate` — now called
once by `client.New`, not by `Serve` — derives it from `DataDir` as
`DataDir/trusted-ca-audit.log` (`DefaultAuditLogFileName`) when the operator
did not set `Audit.LogPath` explicitly — the same `DataDir`-relative pattern
`ACMEAuditConfig.AuditConfig` uses for xkmsd's embedded ACME audit trail
above, so neither surface ever falls back to a path relative to the
process's working directory. An enabled trail with neither `Audit.LogPath`
nor `DataDir` set fails `Validate` (and therefore `New`) with a typed
`*errors.TrustedCAError` (`errors.MalformedError`) rather than silently
writing beside wherever the process happens to run; a disabled trail
(`Audit.Enabled = false`) needs neither field. `Serve` opens the audit
logger from the already-resolved `Audit.LogPath` — it does not call
`resolveAuditLogPath` itself, so the path `New` validated is the path the
trail is written to, never a second, divergent resolution
(`TestNew_ResolvesAuditLogPathOnce`).

**CAA configuration (`ACMEConfig`, `pkg/config/acme.go`).**
`acme.caa_identities` is the list of issuer domain names this CA is known by
in `issue`/`issuewild` CAA records, and is **required whenever `acme.enabled`
is true** — `Validate` returns `ErrACMEMissingCAAIdentities` otherwise, so a
deployment can never silently run with CAA advertised in the directory but
unenforceable at finalize. `acme.caa_dns_server` optionally pins the
recursive resolver (`host:port`) the validator queries; empty uses the same
default the `dns-01` challenge tooling does
(`pkg/acme/challenges/dns-01/providers.DefaultNameservers[0]`). xkmsd's ACME
composition (`cmd/xkmsd/acme.go`) builds the validator with
`server.NewCAAValidator` and sets it on `handlers.Params.CAAValidator` before
constructing the REST service — this is the one construction path for a CAA
validator. The standalone `TrustedCA` (`pkg/acme/client/trustedca.go`) builds
one from the same constructor and its own `TCAACMEConfig.CAIdentifiers` /
`CAADNSServer`; `TCAACMEConfig.Validate` requires at least one CA identifier
(RFC 8555 §8.1: CAA must be checked before issuance, and an empty
`ca_identifiers` gives the check nothing to compare a domain's
`issue`/`issuewild` record against), enforced once by `client.New`
(go-xkms#938) — there is no warn-and-continue path here, matching xkmsd's
own `ErrACMEMissingCAAIdentities` requirement. SDK consumers composing their
own `ACMERestServiceParams` construct the same validator through
`acmesdk.NewACMECAAValidator` (`sdk/go/acme`) rather than implementing
`ACMECAAValidatorInterface` themselves.
The standalone client's browser UI is told the origin the API is reachable at
by `serve.api_base_url` (`--api-base-url`, `ACME_CLIENT_SERVE_API_BASE_URL`),
derived from `serve.addr` when empty. The UI appends `/api/v1` and the
endpoint path itself, so the origin never carries `/api/v1` (a configured
value ending in it is refused), and the same contract holds for the Wails
desktop binding `GetApiBaseUrl`. `pkg/webui` renders the value into
`index.html` as a JSON-encoded JavaScript string literal, so it cannot
terminate the injected script.

**Rate-limit configuration (`ACMERateLimitConfig`, `pkg/config/acme.go`).**
`acme.rate_limit` configures the per-client admission-control cap described
under Invariants above. It follows the same secure-by-default, tri-state
pattern as `acme.audit`: `enabled` is a `*bool`, so an omitted key leaves the
limiter on — only an explicit `enabled: false` turns it off, and doing so is
reported by `Config.ComplianceGaps` ("ACME rate limiting disabled"), which
`cmd/xkmsd` refuses to start on; there is no override. `max_requests` and
`interval` default to `DefaultACMERateLimitMaxRequests` (20) and
`DefaultACMERateLimitInterval` (`1s`) when zero/unset, matching the
standalone `TrustedCA`'s long-standing built-in default
(`pkg/acme/client/trustedca.go`'s zero-value `rateLimitRequests`/
`rateLimitInterval`, settable via `client.WithRateLimit`), so xkmsd and the
standalone CA throttle identically out of the box:

```yaml
acme:
  rate_limit:
    enabled: true      # default; omit the key entirely for the same effect
    max_requests: 20    # per client, per interval
    interval: 1s
```

A negative `max_requests` or `interval` is refused by `Validate`
(`ErrACMERateLimitNegativeMaxRequests`/`ErrACMERateLimitNegativeInterval`)
rather than silently coerced to the default.

**Tenant and per-category rate-limit configuration (go-xkms#886).**
`acme.rate_limit` extends with five `ACMECategoryRateLimitConfig`
sub-sections — `tenant`, `new_account`, `new_order`, `certificate`,
`failed_validation` — each following the identical tri-state,
secure-by-default pattern as the per-client cap above: `enabled` is a
`*bool` (omitted means on), and an explicit `enabled: false` on any of them
is reported by `Config.ComplianceGaps` (a tenant gap and, separately, one
gap naming every disabled category), which `cmd/xkmsd` refuses to start on.
Each sub-section's `max_requests`/`interval` default independently when
zero/unset:

| Section | `MaxRequests` default | `Interval` default |
|---|---|---|
| `tenant` | `DefaultACMETenantRateLimitMaxRequests` (20) | `DefaultACMETenantRateLimitInterval` (1s) |
| `new_account` | `DefaultACMENewAccountRateLimitMaxRequests` (10) | `DefaultACMENewAccountRateLimitInterval` (1h) |
| `new_order` | `DefaultACMENewOrderRateLimitMaxRequests` (300) | `DefaultACMENewOrderRateLimitInterval` (3h) |
| `certificate` | `DefaultACMECertificateRateLimitMaxRequests` (50) | `DefaultACMECertificateRateLimitInterval` (3h) |
| `failed_validation` | `DefaultACMEFailedValidationRateLimitMaxRequests` (5) | `DefaultACMEFailedValidationRateLimitInterval` (1h) |

```yaml
acme:
  rate_limit:
    enabled: true       # per-client cap (above)
    max_requests: 20
    interval: 1s
    tenant:
      enabled: true      # per-tenant overall quota, shared across the tenant's accounts
      max_requests: 20
      interval: 1s
    new_account:
      enabled: true
      max_requests: 10
      interval: 1h
    new_order:
      enabled: true
      max_requests: 300
      interval: 3h
    certificate:
      enabled: true
      max_requests: 50
      interval: 3h
    failed_validation:
      enabled: true
      max_requests: 5
      interval: 1h
```

Every sub-section's negative `max_requests`/`interval` is refused by
`Validate` with the same sentinels as the top-level cap.

Port note: `pkg/acme/api/server/server.go:49` sets `DefaultQUICPort = 9444`,
which collides with the SDK's `DefaultMCPAddress` of `localhost:9444`. See
[`../key-management/api.md`](../key-management/api.md) §Port conflicts.

**Resilience configuration (`ACMEResilienceConfig`, `acme.resilience`,
`pkg/config/acme_resilience.go`).** Five typed sections —
`http01`/`dns01`/`ct_submitter`/`kms`/`storage`, each an
`ACMECircuitBreakerConfig` — configure the breaker(s) of the matching name
(see "Circuit breakers and degradation"): `max_failures`,
`reset_timeout_seconds`, `half_open_max_requests`, `success_threshold`,
`timeout_seconds`. Every field's zero value selects
`circuitbreaker.DefaultConfig`'s default (`DefaultACMEBreaker*` constants:
5 failures, 30s reset, 1 half-open probe, 2 successes to close, 10s call
timeout) through `ACMECircuitBreakerConfig.CircuitBreakerConfig(name)`, the
one mapping between this YAML and `circuitbreaker.Config` — mirroring
`ACMEAuditConfig.AuditConfig`. A negative `reset_timeout_seconds` or
`timeout_seconds` is `ErrACMEResilienceNegativeValue`; the unsigned counter
fields cannot go negative in YAML without a parse error first.

`http01` and `dns01` additionally carry `target_capacity` and
`target_idle_timeout_seconds`: they bound the per-target breaker table each
backs (see "Circuit breakers and degradation"), substituting
`DefaultACMEBreakerTargetCapacity` (1000) /
`DefaultACMEBreakerTargetIdleTimeoutSeconds` (600) at zero, via
`ResolveTargetCapacity`/`ResolveTargetIdleTimeout`. A negative value here is
`ErrACMEResilienceNegativeValue` too. These two fields are meaningless on
`ct_submitter`/`kms`/`storage` (each a single breaker, not a per-target
group) and are ignored there.

A `degradation`
subsection (`ACMEDegradationConfig`) configures the directory/CA-bundle
cache: `cache_ttl_seconds` (default 60), `stale_ttl_seconds` (default 300),
`max_cache_size` (default 32, generous headroom over the one entry each
endpoint actually uses). `cmd/xkmsd/acme.go` is the one place these are
mapped into `handlers.Params` (`Breakers`, `StorageBreaker`, `KMSBreaker`,
`DegradationCacheTTL`, `DegradationStaleTTL`, `DegradationMaxCacheSize`); the
`http01`/`dns01` sections are consumed directly by `buildChallengeMap`, and
`ct_submitter` has no consumer yet (see "What this feature deliberately does
not do" in architecture.md).

The standalone `TrustedCA` (`pkg/acme/client/trustedca_config.go`,
go-xkms#820) reuses `config.ACMEResilienceConfig` directly as
`TCAACMEConfig.Resilience` (`acme.resilience` in `TrustedCAConfig`'s own
YAML) rather than defining a parallel type: `TrustedCAConfig` already sits
downstream of `pkg/config` in the build graph (it imports `pkg/config` for
`audit.Config` and other shared sections), so there is no layering reason to
diverge, and every `max_failures`/`reset_timeout_seconds`/etc. field, its
zero-value defaults, and `ErrACMEResilienceNegativeValue` validation behave
identically in both compositions' configuration files.
`TCAACMEConfig.Validate` delegates to `Resilience.Validate` the same way
`ACMEConfig.Validate` does. `TrustedCA.Serve` is the `TrustedCA` equivalent
of `cmd/xkmsd/acme.go`'s mapping into `handlers.Params`: it builds a
`circuitbreaker.Manager` unconditionally, wraps its challenge map (see
"Circuit breakers and degradation") through the shared
`server.WrapChallengeVerifiers`, and sets `Breakers`, `StorageBreaker`,
`KMSBreaker`, `DegradationCacheTTL`, `DegradationStaleTTL`, and
`DegradationMaxCacheSize` from the same `Resilience` fields.

## Persistence

Accounts, orders, authorizations, challenges and issued certificates persist
through `pkg/acme/storage` over `go-qrdb/sdk/go` (`pkg/acme/qrdb`).
Certificate blobs land in the certificate store like any other certificate.

Nonces do not persist anywhere, by design. `pkg/acme/nonce.Service` validates
a nonce by decrypting it (AES-GCM, RFC 8555 Section 6.5), not by looking it up,
so there is no durable table to write or expire out of — the whole point of
the encrypted-counter scheme is that "was this ever issued, and is it still
in the valid window" is answered from the ciphertext itself plus a small,
`NonceMaxUsed`-bounded in-memory redeemed-set. `RestService` rotates to a
fresh counter window every `NonceLifetime` (`nonceEpochPrefix`,
`pkg/acme/server/handlers/service.go`), retiring every nonce still
outstanding from the previous window; that is the wall-clock lifetime
substitute for a scheme with no per-nonce timestamp to expire.

The current epoch and the time it began (`RestService.nonceEpoch`, a
`nonceEpochRecord{epoch, at}` pair) are swapped as one unit through a single
`atomic.Pointer[nonceEpochRecord]`, never as two independent fields: pairing
them separately let a reader observe a just-rotated epoch alongside the
retired epoch's start time, compute a stale age for the current epoch, and
trigger a second rotation under load (`nonceRotateMu` serializes the actual
construction, but its double-checked re-check needs the epoch and its
timestamp to change together to stay sound). Only `rotateNonceEpoch` ever
writes `nonceEpoch`, under `nonceRotateMu`; reads never block.

Multi-node caveat: nonces from different xkmsd processes only validate on
each other when every node is configured with the same
`handlers.Params.NonceKey` (there is no `pkg/config` field for it yet — see
#733). Absent a shared key, each process mints from its own random key, which
is correct for a single-node deployment but means a load-balanced deployment
without sticky routing sees `badNonce` on any request that lands on a
different node than the one that issued the nonce. RFC 8555 clients already
handle `badNonce` by retrying with a fresh nonce, so this degrades
availability, not correctness.

Migration: the ACME object model is RFC-defined on the wire and internal in
storage. Changing the storage layout requires a data migration step.

## Test strategy

- **Admin-plane tenant binding (go-xkms#1225)** —
  `pkg/acme/admin/tenant_binding_test.go` drives the service with an
  identity on the context and a qrdb double that enforces nothing, so no
  transport or qrdb check can mask a missing service check: every
  `{id}`-scoped operation refused as not-found, foreign/missing equivalence,
  role/user ownership under the caller's own path, tenant-scoped
  certificate/account/order lists, revoke and disable, the audit trail and
  tenant creation reserved to the platform, and the platform's cross-tenant
  reach. `cmd/xkmsd/admin_tenant_binding_test.go` repeats the exploit set
  over HTTP against a real embedded qrdb node with the node barrier engaged,
  asserting tenant-b's tenant, role and user are left untouched.
- **Admin-plane system barrier (go-xkms#1244)** —
  `pkg/acme/admin/barrier_service_test.go` runs the barrier routes over a
  real XKMSService holding a real passphrase barrier: a tenant Admin/SO/
  Custodian is refused `403` on all eleven routes, both behind qrdb's
  grants (which admit it to every route,
  `TestBarrierRoutes_TenantGateAdmitsEveryRoute`) and with RBAC disabled,
  and the barrier's seal state is unchanged; the platform identity seals,
  unseals with the passphrase and reads status. `cmd/xkmsd/admin_barrier_scope_test.go`
  repeats both against xkmsd's composed admin router on a real embedded
  qrdb node, including a platform seal/unseal round trip of the node
  barrier.
- **Unit** — `pkg/acme/**` is heavily covered; the handler package carries an
  explicit 90%+ coverage push (`coverage_90_*_test.go`) plus per-object suites
  (`account_test.go`, `authorization_test.go`, `challenge_test.go`,
  `certificate_test.go`, `directory_test.go`, `caa_test.go`,
  `rate_limiter_test.go`).
  `pkg/acme/server/circuitbreaker` covers closed/open/half-open transitions
  for the breaker itself (`circuitbreaker_test.go`, `admission_test.go`),
  the folded HTTP middleware (`middleware_test.go`), and each of the three
  dependency decorators (`decorators_test.go`:
  `WrapChallengeVerifier`/`WrapLogSubmitter`/`WrapKMSService`, each exercised
  closed, open-fails-fast-without-calling-the-inner-dependency, and
  half-open-probe-closes). `exclusion_test.go` covers the exclusion
  predicate (an excluded failure is returned but not recorded, does not
  reset the failure count, releases a half-open slot; a failure the
  predicate does not exclude, and the breaker's own timeout, are recorded),
  and `decorators_test.go:132`/`:159`/`:179` drive `WrapChallengeVerifier`
  with a real `validation.Client`: fifty refused or invalid targets leave a
  `MaxFailures: 1` breaker closed, connections to a closed `127.0.0.1:0`
  port (`AllowPrivateTargets`) open it, and refusals interleaved with those
  failures do not hold it closed (go-xkms#1181).
  `pkg/acme/server/handlers/resilience_test.go`
  covers the degradation-cache path end to end against the real
  `CABundleHandler`/`DirectoryHandler` code (fresh-serves-live,
  breaker-trips-on-failure, open-serves-stale-cache-degraded,
  open-with-still-fresh-cache-serves-non-degraded,
  open-with-nothing-cached-fails) and `HealthHandler` (no breakers
  configured, and a tripped breaker reported open with 503 and
  `Degradation.Active`). `pkg/config/acme_resilience_test.go` covers
  `ACMEResilienceConfig`/`ACMECircuitBreakerConfig`/`ACMEDegradationConfig`
  validation and default-substitution.
  `pkg/acme/server/caa_test.go` covers the validator against a mock DNS
  server: tree climbing, CNAME following, wildcard `issuewild`, exact
  (non-prefix) issuer matching, a critical unrecognized property tag, and
  fail-closed behavior on SERVFAIL/other DNS errors.
  `pkg/acme/server/handlers/caa_finalize_test.go` drives the same real
  validator through `OrderFinalizeHandler`, asserting the order lands
  `invalid` with the `caa` problem type on a forbidden or undetermined CAA
  outcome, and `valid` when permitted or when no CAA record exists.
- **Hermetic** — no unit test in `pkg/acme/client` may reach the public
  internet. `golang.org/x/crypto/acme` substitutes Let's Encrypt production
  for an empty `DirectoryURL`, so every `acme.Client` literal in the tests
  sets it: to the test's `httptest.Server`, or to
  `unreachableDirectoryURL` (loopback port 1, refused immediately) when the
  test expects to fail before any ACME request. `TestACMEClientLiteralsAreHermetic`
  scans the test sources and fails the suite on a literal that omits it (#152).
- **RFC conformance** — `test/integration/rfc8555`.
- **Integration** — `test/integration/acme-server`, `acme-client`,
  `acme-admin`, `acme-multiprotocol`, `acme-tpm`, `acmeclient`, `acmeserver`,
  `challenges`. The ACME admin plane's CLI coverage is
  `test/integration/acmeadmin` (`xkmsctl acme`/`xkmsctl tenant` against a
  real `xkmsd`), with its own compose file:
  `test/integration/acmeadmin/docker-compose.yml`.
- **TCG / attestation** — `test/integration/acme-tpm` plus
  `pkg/acme/server/handlers/audit_tcg_test.go`,
  `compliance_attestation_test.go` (including `findPCRValue` refusing PCR
  data no TPM produces and oversized PCR data, and preferring the SHA-256
  bank). `swtpm_helper_test.go`'s
  `SwtpmConnection.Provision` enrolls the Platform SRK and installs a
  throwaway IAK certificate via the same
  `xkmssdk.EnrollSimulatorPlatformSRK`/`xkmssdk.ProvisionSimulatorIAKCertificate`
  helpers `pkg/acme/client/service.openDeviceTPM` uses for the in-process
  simulator, so `TestDeviceAttest_CompleteWorkflow` and the other
  device-attest-01 swtpm tests certify a certificate key under the Platform
  SRK exactly as production device-attest-01 does.
- **device-attest-01 `tpm` binding** —
  `pkg/acme/challenges/device-attest-01/tpm_simulator_test.go` (build tag
  `tpm_simulator`) produces real TPM2_Certify and TPM2_Quote output with the
  in-process TPM simulator and signs the CSR with the TPM-resident key. It
  accepts the device's own key and refuses a software key, a sibling TPM key,
  a quote, another key's `pubArea`, the key authorization or its digest
  anywhere but as `extraData`, another challenge's `extraData`, a signature by
  a second AIK, an AIK certificate without `tcg-kp-AIKCertificate`, and an
  `x5c` not anchored to the roots. `tpm_test.go` covers §8.3.1 and malformed
  statements; `pkg/attestation/invariants_tpm_test.go` and
  `pkg/tpm2/certify_verify_certificate_test.go` cover the gate and the
  certificate-attester verifier.
- **device-attest-01 client** — `pkg/acme/challenges/device-attest-01/setup_simulator_test.go`
  and `pkg/acme/client/tpm_simulator_test.go` (build tag `tpm_simulator`)
  provision the simulator as a device (IAK, Platform SRK, IAK certificate) and
  hand the client's response to `VerifyAttestation` unchanged. The response is
  accepted for RSA-PSS and ECDSA IAKs, and `BindCSRKey` accepts the CSR signed
  by the certified key. The verifier refuses a software key, another
  Platform-SRK key, the account key, and the certification presented under
  another AIK's certificate. `setup_test.go`, `enrollment_test.go` and
  `tpm_test.go` cover `Setup`'s, `deviceAttestCSR`'s and `CreateAttestedKey`'s
  refusals.
- **Cross-repo** — `pkg/acme/server/handlers/cluster_issuer_test.go` covers the
  Raft enrollment path.

## Observability

The circuit breakers (`pkg/acme/server/circuitbreaker`) and the degradation
cache (`pkg/acme/server/degradation`) record failure/success/trip and
hit/miss/size counters. `GET /acme/health` (`RestService.HealthHandler`) is the
synchronous view of that state: every breaker's name, state and counters, and
whether an open `storage` breaker is degrading the directory/CA-bundle
responses (see "Circuit breakers and degradation"). `pkg/acme/audit` and
`pkg/acme/server/handlers/audit.go` write audit records for account, order and
issuance events.

`pkg/acme/server/metrics` is the Prometheus registry for the ACME protocol
handlers (`pkg/acme/server/metrics/metrics.go`), production/tenant metrics
(`production.go`) and the request-instrumentation middleware
(`middleware.go`). It is wired into the handlers that actually produce the
events it counts, not left to accumulate unread (#734):

- **Order creation and status transitions** — `NewOrderHandler` increments
  `acme_active_orders` and, per created challenge,
  `acme_pending_challenges` on a successful save
  (`pkg/acme/server/handlers/new_order.go:183`). The order's three terminal
  transitions each decrement `acme_active_orders`: an authorization failing
  during challenge validation (`pkg/acme/server/handlers/challenge.go:442`),
  a successful finalize (`pkg/acme/server/handlers/order_finalize.go:925`),
  and a finalize failure (`order_finalize.go:1236`). Per-tenant active-order
  and active-account counts (`acme_tenant_active_orders`,
  `acme_tenant_active_accounts`) mirror the same Inc/Dec pattern for a
  tenant-bound account.
- **Challenge validation** — `ChallengeHandler` decrements
  `acme_pending_challenges` and records `acme_challenges_completed_total`
  labelled by challenge type and result (`valid`/`invalid`) once validation
  resolves (`pkg/acme/server/handlers/challenge.go`, via
  `metrics.NewMetricsCollector(...).RecordChallenge`).
- **Finalize and issuance** — `OrderFinalizeHandler`'s single success sink
  (`sendFinalizeResponse`) records `acme_certificates_issued_total` and
  `acme_certificate_issuance_duration_seconds`
  (`order_finalize.go:929`); its single failure sink (`failOrder`) records
  `acme_errors_total{type="issuance_failed"}` and the same duration
  histogram, so latency is observed on both outcomes
  (`order_finalize.go:1240`).
- **Revocation** — `RevokeCertHandler` records
  `acme_certificates_revoked_total` (and the tenant-scoped counter) once the
  CA has revoked the certificate and the record is persisted
  (`pkg/acme/server/handlers/revoke_cert.go:259`).
- **Account creation** — `NewAccountHandler` records
  `acme_accounts_created_total` and increments
  `acme_tenant_active_accounts` for a tenant-bound account
  (`pkg/acme/server/handlers/new_account.go:240`); `AccountHandler`
  decrements the tenant gauge on deactivation
  (`pkg/acme/server/handlers/account.go`).
- **Requests** — `metrics.Middleware` (`middleware.go`) records
  `acme_requests_total`, `acme_request_duration_seconds` and
  `acme_errors_total{type="client_error"|"server_error"}` for every request,
  classified by the response status code.

`metrics.Mount` (`middleware.go:31`) is the single call both ACME server
compositions use to initialize the registry and attach `Middleware`:
`cmd/xkmsd/acme.go:576` (embedded xkmsd) and
`pkg/acme/client/trustedca.go` (standalone TrustedCA). xkmsd additionally
calls `srv.RegisterMetricsGatherer(acmemetrics.Registry)`
(`cmd/xkmsd/acme.go:330`), so the ACME registry - which is deliberately
private, not `prometheus.DefaultRegisterer` - becomes part of the same
`/metrics` response `pkg/server/server.go`'s `startMetrics` already serves,
gathered fresh on every scrape via `serverGatherer`
(`pkg/server/server.go:3131`) rather than a second endpoint. The standalone
TrustedCA serves `metrics.Registry` directly as its only metrics source and
additionally calls `metrics.RegisterRuntimeCollectors()`
(`metrics.go:158`) for the Go/process collectors that xkmsd's default
registry already provides for the embedded case - registering them in both
places would make `prometheus.Gatherers.Gather` reject the scrape as a
duplicate metric.

Grafana dashboards and Prometheus alerting/recording rules for these metrics
are in `deploy/grafana/` and `deploy/prometheus/rules/`; see
`deploy/README.md`'s Monitoring section for what each panel and rule
references.

`pkg/acme/audit` and `pkg/acme/server/handlers/audit.go` write audit records
for account, order and issuance events, independent of the metrics above.
Correlation IDs propagate from the transport middleware.

**Audit source-IP resolution shares the rate limiter's trusted-proxy set
(go-xkms#1179).** `audit.extractClientIP` (`pkg/acme/audit/hooks.go:128`)
resolves the recorded source IP through the same `ratelimit.TrustedProxies`
type the REST and ACME rate limiters use (`pkg/ratelimit/clientip.go:102`):
the transport peer address, or, only when that peer is a configured trusted
proxy, the right-most untrusted `X-Forwarded-For` hop. A package-level
`trustedProxies` var (`hooks.go:107`) holds the value; `SetTrustedProxies`
(`hooks.go:117`) sets it once at start-up. `startACMEServer`
(`cmd/xkmsd/acme.go:164`) is the one place that parses
`server.trusted_proxies` for the embedded ACME listener — the same config key
`pkg/server/server.go:2892` parses for REST — and hands the result to both
`acmeserver.TrustedProxies` (the ACME rate limiter's resolver) and
`audit.SetTrustedProxies` (`cmd/xkmsd/acme.go:168-169`), so a forwarding
header is trusted, or not, identically for rate limiting and for the audit
trail. Neither introduces a second `trusted_proxies`-shaped key. An untrusted
peer's forged `X-Forwarded-For` is never recorded as the source IP; audit
records always keep full address precision (no /64 folding — that is a
rate-limit-only concern, below).

**IPv6 rate-limit keys fold to their /64, audit does not
(go-xkms#1179).** `ratelimit.RateLimitKey` (`pkg/ratelimit/clientip.go:171`)
takes the address `TrustedProxies.ClientIP` resolved and returns it unchanged
for IPv4, or masked to its `/64` (`ipv6RateLimitPrefixBits`,
`clientip.go:156`) for IPv6, so a client cannot evade a limiter by rotating
through addresses an ISP delegates it within one `/64`. A value that is not a
valid IP (a JWS key ID) passes through unchanged. `ratelimit.Middleware`
(`pkg/ratelimit/ratelimit.go:247`) applies it for the REST limiters; the ACME
limiters apply it through `rateLimitClientIPKey`/`rateLimitClientIDKey`
(`pkg/acme/server/rate_limiter.go:456,467`), which every
`*RateLimiter`/`*TenantRateLimiter` constructor in `rate_limiter.go` and
`tenant_rate_limiter.go` now takes as its client-key function in place of the
raw `ClientIP`/`ClientID`. `ClientIP`/`ClientID` themselves are unchanged and
still return the full-precision address — `RateLimitKey` is applied only at
the point a limiter builds its bucket key, never to the value the audit trail
records.

**Known gap:** the ACME server's per-tenant rate limiter
(`pkg/acme/server/tenant_rate_limiter.go`) is wired through
`cmd/xkmsd/acme.go` `buildACMERouterLimiters` (go-xkms#886), but its
hit/remaining counters live in
an internal struct, not through `pkg/acme/server/metrics`, so they will not
automatically join the Prometheus registry or the dashboards above. OCSP
stapling, CRL distribution-point automation, CT log submission automation
and cross-signing automation remain roadmap items, not implemented. They are
tracked in `docs/acme/ROADMAP.md` and deliberately not documented here as if
they existed.
