# ACME Issuance — Engineering Contract

> **Status: NORMATIVE** · Feature: `acme-issuance` · Repo: `go-xkms` · Last verified: 2026-09-27

## Exported surface

### Server

`pkg/acme` is the server. Entry points that matter to an implementer:

- `pkg/acme/server/handlers` — one file per protocol object: `directory.go`,
  `account.go`, `authorization.go`, `challenge.go`, `certificate.go`,
  `ca_bundle.go`, `endorse_eab.go`, `audit.go`, `compliance_attestation.go`,
  `service.go`.
- `pkg/acme/entities` — the protocol objects themselves.
- `pkg/acme/nonce` — nonce issue and consume.
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
- `pkg/acme/server/rate_limiter.go`, `tenant_rate_limiter.go`,
  `circuit_breaker.go`, `server/circuitbreaker`, `server/degradation` — the
  protective layer as *designed*. Of these, only `rate_limiter.go` is
  actually wired anywhere, and only into the standalone `TrustedCA`
  (`pkg/acme/client/trustedca.go:381-383`), not into xkmsd. The tenant rate
  limiter and both circuit-breaker/degradation implementations are
  constructed nowhere outside their own packages; see Invariants below and
  go-xkms#820.
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
- **Rate limits are designed to be per account and per tenant, but that is not
  what runs today.** The standalone `TrustedCA` applies a single per-client-ID
  request limiter (`server.NewRateLimiter`,
  `pkg/acme/client/trustedca.go:381-383`) to its ACME router; exceeding it
  refuses the request, it does not queue it. xkmsd's production ACME router
  (`buildACMERouter`, `cmd/xkmsd/acme.go:466-483`) wires no rate limiter at
  all, and the tenant-scoped limiter
  (`pkg/acme/server/tenant_rate_limiter.go`) is constructed nowhere in the
  tree outside its own file. Wiring xkmsd's rate limiting is tracked in go-xkms#882.
- **The circuit breaker does not run anywhere today.** Two unwired
  implementations exist (`pkg/acme/server/circuit_breaker.go`,
  `pkg/acme/server/circuitbreaker`) plus `pkg/acme/server/degradation`;
  neither xkmsd nor the standalone `TrustedCA` constructs or mounts any of
  them. "Under pressure the circuit breaker refuses new orders" is the
  intended invariant once go-xkms#820 lands (open, not on `main`); a related
  change, go-xkms#819, is in an open merge train and also not on `main`.
  Until one of them lands, no degradation or circuit-breaking behavior
  exists — the server keeps accepting and validating orders regardless of
  backend health.
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

**Fail closed today:** unvalidated authorization, failed CAA, an undetermined
CAA RRset (DNS failure), failed attestation, and (in the standalone
`TrustedCA` only) an exceeded rate limit. **Not live anywhere yet:** an open
circuit breaker — see Invariants above and go-xkms#820.

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
  `rate_limiter_test.go`, `circuit_breaker_test.go`).
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

`pkg/acme/server/metrics` defines a Prometheus registry with issuance,
challenge and rate-limit counters (`RecordRequest`, `RecordCertificateIssued`,
...). The standalone `TrustedCA` calls `metrics.Init()` and mounts
`promhttp.HandlerFor(metrics.Registry, ...)` at `/metrics`
(`pkg/acme/client/trustedca.go:378,415`), but no handler in
`pkg/acme/server/handlers` ever calls a `Record*` function, so that endpoint
always reports zero — the registry is wired to a listener, not to the request
path. xkmsd never calls `metrics.Init()` or mounts `/metrics` for ACME at all
(`cmd/xkmsd/acme.go`). `pkg/acme/audit` and
`pkg/acme/server/handlers/audit.go` write audit records for account, order and
issuance events, and those are live on both paths — audit, not metrics, is
where issuance activity is actually observable today. Correlation IDs
propagate from the transport middleware. Instrumenting the metrics package
into the request path is tracked in go-xkms#734.

**Known gap:** Prometheus exporters (beyond the unwired registry above),
per-tenant rate-limit dashboards, OCSP stapling, CRL distribution-point
automation, CT log submission automation and cross-signing automation are
roadmap items, not implemented. They are tracked in `docs/acme/ROADMAP.md`
and deliberately not documented here as if they existed.
