# ACME Issuance — Engineering Contract

> **Status: NORMATIVE** · Feature: `acme-issuance` · Repo: `go-xkms` · Last verified: 2026-09-24

## Exported surface

### Server

`pkg/acme` is the server. Entry points that matter to an implementer:

- `pkg/acme/server/handlers` — one file per protocol object: `directory.go`,
  `account.go`, `authorization.go`, `challenge.go`, `certificate.go`,
  `ca_bundle.go`, `endorse_eab.go`, `audit.go`, `compliance_attestation.go`,
  `service.go`.
- `pkg/acme/entities` — the protocol objects themselves.
- `pkg/acme/nonce` — nonce issue and consume.
- `pkg/acme/issuance` — the bridge to `pkg/ca`.
- `pkg/acme/storage`, `pkg/acme/qrdb` — persistence, through `go-qrdb/sdk/go`.
- `pkg/acme/policy`, `pkg/acme/server/caa.go` — issuance policy and CAA.
- `pkg/acme/server/rate_limiter.go`, `tenant_rate_limiter.go` — request-rate
  enforcement.
- `pkg/acme/server/circuitbreaker` — the one circuit breaker implementation
  (`CircuitBreaker`, `Manager`, the `Middleware` HTTP wrapper, and the
  `WrapChallengeVerifier`/`WrapLogSubmitter`/`WrapKMSService` decorators) and
  `pkg/acme/server/degradation` (the cache-backed graceful-degradation
  primitives) — the protective layer. See "Circuit breakers and degradation"
  below.
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
  `trusted-acme-client serve`.
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
- **CAA (RFC 8659) is checked before issuance**, not after. Order finalize
  (`order_finalize.go`) calls `Params.CAAValidator.Validate` for every DNS
  identifier on the order before the CA signs; a rejection moves the order to
  `invalid` with the `caa` problem type. The validator itself
  (`pkg/acme/server/caa.go`) climbs the label tree to the closest non-empty
  CAA RRset, checks `issuewild` for wildcard identifiers and falls back to
  `issue` when no `issuewild` record exists, rejects an unrecognized
  property tag carrying the critical flag regardless of any authorizing
  record, and compares the `issue`/`issuewild` value's issuer-domain-name to
  `acme.caa_identities` as a full domain name — never a prefix. A DNS
  failure that prevents determining the RRset (SERVFAIL, timeout, any
  non-NXDOMAIN error) fails closed per RFC 8659 Section 5.1: it denies
  issuance rather than "proceeding with caution".
- **Rate limits are per account and per tenant.** Exceeding either refuses the
  order; it does not queue it.
- **A breaker guards the one dependency it wraps, not order creation, and
  degradation never means "issue without validating".** See "Circuit
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

## Circuit breakers and degradation

`pkg/acme/server/circuitbreaker` is the one circuit breaker implementation
(go-xkms#735 folded the previously-duplicated HTTP middleware into it). Five
dependencies each get their own breaker from a shared `circuitbreaker.Manager`:

| Breaker name | Guards | Wired by |
|---|---|---|
| `http01` | the `http-01` challenge verifier | `cmd/xkmsd/acme.go:buildChallengeMap`, via `circuitbreaker.WrapChallengeVerifier` |
| `dns01` | the `dns-01` challenge verifier | same, `circuitbreaker.WrapChallengeVerifier` |
| `ct` | CT log submission (`ct.LogSubmitter`) | `circuitbreaker.WrapLogSubmitter` — no production call site yet; see architecture.md |
| `kms` | `Params.KMSService` (the tenant KMS signer) | `handlers.NewRestService`, automatically, when both `Params.Breakers` and `Params.KMSService` are set |
| `storage` | CA/keystore-backed certificate storage (`CA.CABundleFiltered`, `GET /acme/ca-bundle`'s dependency) | `handlers.NewRestService`, from `Params.StorageBreaker` |

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

`GET /acme/health` (`RestService.HealthHandler`, `HealthStatus`) reports
every breaker registered on `Params.Breakers` by name — state, failure
count, success count — and whether `storage` is open (`Degradation.Active`).
It returns 503 when any breaker is not closed, 200 otherwise. A
`RestService` built without `Params.Breakers` reports healthy with no
breakers listed rather than omitting the endpoint. `cmd/xkmsd/acme.go` opts
in (`Params.Breakers`, `StorageBreaker`, `KMSBreaker`, all sourced from
`acme.resilience` — see "Configuration"); the standalone `TrustedCA` path
(`pkg/acme/client/trustedca.go`) mounts `HealthHandler` at `/health` too but
does not yet set `Params.Breakers`, so it always reports healthy with no
breakers — a known gap, not a design choice.

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
| challenge validation failed | `incorrectResponse` / `connection` / `dns` | 403 |
| rate limit exceeded | `rateLimited` | 429 |
| order not ready to finalize | `orderNotReady` | 403 |
| CSR does not match the order (`dns`/`ip` orders) | `badCSR` | 400 |
| permanent-identifier CSR missing/malformed/extra otherName | `badCSR` | 400 |
| permanent-identifier or DNS/IP SAN not authorized by the order | `rejectedIdentifier` | 401 |

**Fail closed:** unvalidated authorization, failed CAA, an undetermined CAA
RRset (DNS failure), failed attestation, exceeded rate limit, an open circuit
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
- `Validate(keyBackend)` currently accepts any backend. The doc comment states
  why: in-process issuance on the first node stamps a key-provenance OID for any
  backend, and a joining node's challenge is selected by backend at runtime
  (`tpm2` → `enroll-01`; other backends → CSR enrollment). A software-only
  cluster is therefore valid configuration, and an unimplemented joiner path
  surfaces a precise runtime error rather than a config-time one.

`RaftACMEConfigError` (`Field`, `Reason`) renders as
`cluster: raft_enrollment.acme.<field>: <reason>`.

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

The standalone `TrustedCA` (`pkg/acme/client/trustedca_config.go`) is a
separate configuration surface — not built from `pkg/config` and not read
through viper — so it carries its own copy of the same switch:
`TCAACMEConfig.AllowLoopbackIdentifier` (`allow_loopback_identifier`), also
off by default, threaded into `handlers.Params.AllowLoopbackIdentifier` in
`TrustedCA.Serve`. An embedder configuring `TrustedCAConfig` directly (rather
than through xkmsd) sets this field itself; there is no `XKMS_`-prefixed
environment name for it (#140).

The standalone `TrustedCA` also carries its own advertised URL,
`acme.external_url`; `Validate` requires it, and a caller that skips
validation gets the derived default described under Invariants.

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
`CAADNSServer`; unlike xkmsd it only warns (does not refuse to start) when
`ca_identifiers` is empty, because `CAAValidator.Validate` itself already
fails closed for any domain that actually publishes a CAA record — an
embedder that never expects one to is not blocked from starting. SDK
consumers composing their own `ACMERestServiceParams` construct the same
validator through `acmesdk.NewACMECAAValidator` (`sdk/go/acme`) rather than
implementing `ACMECAAValidatorInterface` themselves.
The standalone client's browser UI is told the origin the API is reachable at
by `serve.api_base_url` (`--api-base-url`, `ACME_CLIENT_SERVE_API_BASE_URL`),
derived from `serve.addr` when empty. The UI appends `/api/v1` and the
endpoint path itself, so the origin never carries `/api/v1` (a configured
value ending in it is refused), and the same contract holds for the Wails
desktop binding `GetApiBaseUrl`. `pkg/webui` renders the value into
`index.html` as a JSON-encoded JavaScript string literal, so it cannot
terminate the injected script.

Port note: `pkg/acme/api/server/server.go:49` sets `DefaultQUICPort = 9444`,
which collides with the SDK's `DefaultMCPAddress` of `localhost:9444`. See
[`../key-management/api.md`](../key-management/api.md) §Port conflicts.

**Resilience configuration (`ACMEResilienceConfig`, `acme.resilience`,
`pkg/config/acme_resilience.go`).** Five typed sections —
`http01`/`dns01`/`ct_submitter`/`kms`/`storage`, each an
`ACMECircuitBreakerConfig` — configure the breaker of the matching name (see
"Circuit breakers and degradation"): `max_failures`,
`reset_timeout_seconds`, `half_open_max_requests`, `success_threshold`,
`timeout_seconds`. Every field's zero value selects
`circuitbreaker.DefaultConfig`'s default (`DefaultACMEBreaker*` constants:
5 failures, 30s reset, 1 half-open probe, 2 successes to close, 10s call
timeout) through `ACMECircuitBreakerConfig.CircuitBreakerConfig(name)`, the
one mapping between this YAML and `circuitbreaker.Config` — mirroring
`ACMEAuditConfig.AuditConfig`. A negative `reset_timeout_seconds` or
`timeout_seconds` is `ErrACMEResilienceNegativeValue`; the unsigned counter
fields cannot go negative in YAML without a parse error first. A `degradation`
subsection (`ACMEDegradationConfig`) configures the directory/CA-bundle
cache: `cache_ttl_seconds` (default 60), `stale_ttl_seconds` (default 300),
`max_cache_size` (default 32, generous headroom over the one entry each
endpoint actually uses). `cmd/xkmsd/acme.go` is the one place these are
mapped into `handlers.Params` (`Breakers`, `StorageBreaker`, `KMSBreaker`,
`DegradationCacheTTL`, `DegradationStaleTTL`, `DegradationMaxCacheSize`); the
`http01`/`dns01` sections are consumed directly by `buildChallengeMap`, and
`ct_submitter` has no consumer yet (see "What this feature deliberately does
not do" in architecture.md).

## Persistence

Accounts, orders, authorizations, challenges, nonces and issued certificates
persist through `pkg/acme/storage` over `go-qrdb/sdk/go` (`pkg/acme/qrdb`).
Certificate blobs land in the certificate store like any other certificate.

Nonces are short-lived and single-use; their store is deliberately separate so
expiry is cheap.

Migration: the ACME object model is RFC-defined on the wire and internal in
storage. Changing the storage layout requires a data migration step.

## Test strategy

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
  half-open-probe-closes). `pkg/acme/server/handlers/resilience_test.go`
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
  `challenges`. Compose file: `test/integration/acme-docker-compose.integration.yml`.
- **TCG / attestation** — `test/integration/acme-tpm` plus
  `pkg/acme/server/handlers/audit_tcg_test.go`,
  `compliance_attestation_test.go`.
- **Cross-repo** — `pkg/acme/server/handlers/cluster_issuer_test.go` covers the
  Raft enrollment path.

## Observability

`pkg/acme/server/metrics` exposes issuance, challenge and rate-limit metrics,
plus the circuit breaker and degradation-cache counters `pkg/acme/server/
circuitbreaker` and `pkg/acme/server/degradation` record against (failure/
success/trip per breaker; hit/miss/size per cache) — not yet wired to a
Prometheus exporter, see "Known gap" below. `GET /acme/health`
(`RestService.HealthHandler`) is the synchronous, poll-driven view of the
same state: every breaker's name, state and counters, and whether
`storage` being open is currently degrading the directory/CA-bundle
responses (see "Circuit breakers and degradation"). `pkg/acme/audit` and
`pkg/acme/server/handlers/audit.go` write audit records for account, order
and issuance events. Correlation IDs propagate from the transport
middleware.

**Known gap:** Prometheus exporters, per-tenant rate-limit dashboards, OCSP
stapling, CRL distribution-point automation, CT log submission automation and
cross-signing automation are roadmap items, not implemented. They are tracked in
`docs/acme/ROADMAP.md` and deliberately not documented here as if they existed.
