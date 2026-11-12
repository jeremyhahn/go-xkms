# ACME Issuance — Engineering Contract

> **Status: NORMATIVE** · Feature: `acme-issuance` · Repo: `go-xkms` · Last verified: 2026-10-15

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
- `pkg/acme/issuance` — the issuance pipeline (goodkey, reserved serial,
  precertificate, CT, final certificate) behind `pkg/ca`. `OrderFinalizeHandler`
  issues CSR orders through it (`pkg/acme/server/handlers/order_finalize.go:900`);
  EK and TCG-CSR-IDEVID issuance still call `s.ca.IssueEKCertificate` /
  `s.ca.SignTCGCSRIDevID` (`order_finalize.go:805,1606`) directly.
- `pkg/acme/storage` — persistence, through the injected go-qrdb DAO factory
  (see Persistence below).
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
- `pkg/acme/api/adapter.go` plus `api/{rest,grpc,quic,mcp}` — admin-plane
  client adapters (`AdminAdapter`; `ACMEAdapter` has no implementation),
  `api/server` — the library `MultiProtocolServer`, which xkmsd does not run —
  and `api/swagger` for the OpenAPI surface. See
  [api.md](api.md#transport-adapters).
- `pkg/acme/auth` — a token-validation `Client` interface (`interface.go`)
  with an in-memory implementation (`memory.go:32`), consumed by the admin
  `AuthMiddleware` (`pkg/acme/admin/auth.go:105-111`) and by
  `pkg/acme/client`'s `WithAuthClient` (`options.go:44`).
- `pkg/acme/ct` — Certificate Transparency: per-log config, RFC 6962
  submission and SCT verification (see [Certificate Transparency](#certificate-transparency)).

### Client

- `pkg/acme/client` — the Go client. Its `dns-01` pre-checks take
  `DNSCheckOption`s: `WithNameserverLookup`, `WithPropagationQuery`, and
  `WithNameserverPort`, the port the zone's authoritative nameservers are
  queried on (`DefaultDNSPort`, `"53"`, when unset; a supplied lookup returns
  complete addresses and is not re-ported).
- `sdk/go/acme` — the SDK surface, including `sdk/go/acme/trustedca.go` and
  `sdk/go/acme/transport/quic`; the admin client is
  `sdk/go/acme/client/admin`. `NewClient(address, opts...)`
  (`sdk/go/acme/trustedca.go:730-756`) picks a transport from its options:
  `WithREST` (`:367`), `WithQUIC` (`:375`), `WithUnix` (`:383`),
  `WithEmbedded` (`:395`), `WithMCP` (`:407`), with TLS from `WithTLS`
  (`:276`). The default is gRPC (`:207`), which `createTransport` refuses
  because RFC 8555 has no gRPC binding (`:758-781`). An `http://` or
  `https://` address switches that default to REST. Defaults: 30 s timeout,
  3 retries with 100 ms → 5 s backoff (`:206-221`).
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

#### `pkg/acme/client.Client`

`NewClient(*Params)` (`pkg/acme/client/client.go:98`) takes `Params`
(`:87-95`) and a `Config` (`config.go:28-56`); `DefaultConfig` (`config.go:59-70`)
sets a 60 s timeout and 3 retries with 1 s → 30 s backoff. The client wraps
`golang.org/x/crypto/acme`.

| Group | Methods (`client.go`) |
|---|---|
| Account | `RegisterAccount` (`:433`), `Account` (`:341`), `AccountSigner` (`:336`), `UpdateAccount` (`:519`), `DeactivateAccount` (`:598`), `AccountKeyRollover` (`:1009`) |
| Orders | `RequestCertificate` (`:831`), `RenewCertificate` (`:964`), `ListOrders` (`:647`), `GetOrder` (`:740`) |
| Authorizations | `GetAuthorization` (`:807`), `DeactivateAuthorization` (`:780`) |
| Certificates | `FetchCertificate` (`:990`), `RevokeCertificate` (`:977`) |
| Lifecycle | `Close` (`:1028`) |

Device and cross-sign flows: `EnrollDevice` (`enrollment.go:178`),
`RequestEndorsementKeyCertificate` (`:550`), `DeviceAttest` (`:862`);
`CrossSignerFromClient`, `CrossSign`, `CrossSignWithChallenge`
(`cross_sign.go:135,197,424`).

**Renewal information (ARI, RFC 9773) — client only.** `ari.go`:
`SupportsARI` (`:350`, true when the directory lists `renewalInfo`), `GetRenewalInfo` (`:97`), `GetCertificateID` /
`GetCertificateIDFromHash` / `ParseCertificateID` / `ValidateCertificateID` /
`BuildRenewalInfoURL` (`:300,330,472,497,504`), and on `RenewalInfo`
`ShouldRenewNow`, `ShouldRenewSoon`, `RandomRenewalTime`, `HasExplanation`
(`:412,423,440,465`). The go-xkms server publishes no `renewalInfo` endpoint,
so against it `SupportsARI` is false. `CreateOrderWithReplaces` (`:194`)
does **not** send the `replaces` field: it logs a warning and opens an
ordinary order (`:259-286`).

Without ARI, the local helpers decide renewal: `ShouldRenewAt(cert, threshold)`
(`:543`) returns `NotAfter − validity × threshold`, where `threshold` is the
fraction of validity left and falls back to 0.3 outside (0, 1);
`ComputeRenewalTime` (`:584`), `NeedsRenewal` (`:606`), `DaysUntilExpiry`
(`:616`), `IsExpired` (`:628`), `IsNotYetValid` (`:636`).

**Pre-authorization** (`preauth.go`): `SupportsPreAuthorization` (`:44`)
reports whether the directory advertises `newAuthz`; `PreAuthorize` (`:68`),
`PreAuthorizeMany` (`:129`), `PreAuthorizeDomains` (`:204`) and
`PreAuthorizeIPs` (`:217`) drive it.

**OCSP** (`ocsp.go`): `Client.GetOCSP` (`:142`) and the package-level
`GetOCSP` (`:173`) / `CheckOCSP` (`:276`) fetch a response;
`HasMustStaple` (`:301`) reports the OCSP Must-Staple extension. The result
answers `IsGood`, `IsRevoked`, `IsUnknown`, `IsStale` and `ShouldRefresh`
(`:93-117`).

**Alternate chains** (`chain.go`): `FetchCertificateWithChain` (`:93`) takes
a `ChainOption` (`:43`; `PreferredChain` names a root, `AllowFallback`
accepts the default chain when none matches; `DefaultChainOption`, `:55`).
`GetAvailableChains` (`:153`) returns every `ChainInfo` (`:62`: `Chain`,
`RootName`, `RootIssuer`, `ChainLength`, `URL`), and
`SelectChainByRootName`, `SelectShortestChain`, `SelectLongestChain`
(`:370,386,403`) choose among them.

#### Challenge resolver and DNS solver

`ChallengeResolver` (`pkg/acme/client/resolver.go`) maps challenge types to
`ChallengeSolver`s (`:69-83`: `Type`, `Solve(ctx, domain, challenge,
keyAuth)`, `Cleanup(ctx, domain, challenge)`). `NewChallengeResolver`
(`:99-108`) starts with no solvers and the preference order `dns-01`,
`http-01`, `tls-alpn-01`.

- `RegisterSolver` (`:112`) replaces an existing solver for the type;
  `RegisterSolverStrict` (`:130`) refuses it. `UnregisterSolver`,
  `GetSolver`, `HasSolver`, `ListSolvers`, `SolverCount`,
  `SetPreferences` / `GetPreferences` manage the set.
- `SelectChallenge` (`:234`) picks the most preferred challenge in the
  authorization that has a solver. `Solve(ctx, authz, keyAuth)` (`:276`)
  selects, solves and returns the challenge for the caller to accept.
  `SolveWithCleanup(ctx, authz, keyAuth, afterSolve)` (`:312`) runs
  `afterSolve` (typically accept-and-wait) and then cleans up.
  `Cleanup` (`:356`), `Close` (`:375`), `IsClosed` (`:391`).
- Errors are the sentinels at `:28-37` and `*ChallengeCleanupError` (`:51`).

`DNSSolver` (`dns_solver.go`) is the `dns-01` `ChallengeSolver` over a DNS
provider: `NewDNSSolver(provider, opts...)` (`:128`), with
`WithPropagationWait` (fixed wait after `Present`; none by default, `:72`),
`WithPropagationCheck` (poll until the record resolves, `:81`) and
`WithNameservers` (`:90`). `WithRecordTTL` (`:97`) is stored but has no
effect: `Provider.Present` takes no TTL, so each provider applies its own.
`ComputeDNS01ChallengeValue` (`:283`) is the RFC 8555 §8.4 TXT value.
`WrapPreCheck` (`:348`) runs a check after the record is placed and before
`Solve` returns; `CheckDNSFromAuthoritative`, `CheckDNSFromPublic` and
`CheckDNSFromNameservers` (`:544,568,593`) build one. Errors: `:36-40`,
`*DNSCleanupError` (`:52`).

`NewChallengeResolver` and `DNSSolver` have no caller outside tests.

**Client service DNS-01 configuration.** `pkg/acme/client/service` reads a
`challenge.dns01` block (`config.go:259,274-278`): `provider`, `credentials`
(a string map) and `ttl` (default 300, `config.go:404-406`).
`SetupDNS01Challenge(ctx, config, logger, domain, token, keyAuth)`
(`challenge.go:275`) prints the TXT record to create by hand and returns a nil
challenge when `provider` is empty (`:279-293`); otherwise it builds the named
provider through `dns01.GetProvider` and presents the record
(`dns01_provider.go:59,80`), and `DNS01Challenge.Cleanup` (`:43`) removes it.
Credential keys per provider (`dns01_provider.go:96-153`; `ambient` is parsed
as a boolean):

| `provider` | `credentials` keys |
|---|---|
| `route53` | `accessKeyId`, `secretAccessKey`, `region`, `hostedZoneId`, `role`, `webIdentityToken`, `ambient` |
| `cloudflare` | `email`, `apiKey`, `apiToken`, `zoneApiToken`, `zoneId`, `baseUrl` |
| `azure` | `clientId`, `clientSecret`, `tenantId`, `subscriptionId`, `resourceGroupName`, `zoneName`, `environment`, `ambient`, `managedIdentityClientId`, `managedIdentityResourceId` |
| `clouddns` | `project`, `serviceAccountJson`, `hostedZoneName`, `ambient` |

Any other name fails with `ErrUnsupportedDNSProvider`, a non-boolean `ambient`
with `ErrInvalidDNSProviderCredential` (`errors.go:67-88`). Setup and cleanup
failures wrap as `ErrChallengeSetupFailed` / `ErrChallengeCleanupFailed`.
`SetupDNS01Challenge`, like `SetupHTTP01Challenge` (`challenge.go:188`), has no
caller outside tests: the `trusted-acme-client` commands do not invoke either,
so the `challenge.dns01` keys are parsed but drive no shipped command today.

#### DNS-01 providers

`pkg/acme/challenges/dns-01/providers` defines `Provider`
(`provider.go:47-71`: `Present` and `CleanUp`, each
`(ctx, domain, fqdn, value)`; `CleanUp` of a missing record is not an error),
plus the optional `ProviderTimeout` (`:77`, propagation timeout and polling
interval) and `ProviderSequential` (`:89`). Each provider package registers
itself in `init()` through `Register` / `RegisterEnvFactory`
(`:112,128`), so the caller imports it (a blank import is enough) before
using the factory: `NewProvider(ctx, name, config)` and
`NewProviderFromEnv(ctx, name)` (`factory.go:41,63`) answer
`ErrProviderNotFound` for an unregistered name. Names are `route53`,
`cloudflare`, `azure`, `clouddns` (`provider.go:163-166`).

`GetEnvOrFile` (`env.go:48`) reads `VAR`, or the file named by `VAR_FILE`;
providers use it only for the variables marked † below. Every other
variable is read directly. Every provider defaults to a 120 s propagation
timeout, 4 s polling interval and 30 s HTTP timeout.

| Provider | Config | Environment (`NewFromEnv`) | TTL | Behaviour |
|---|---|---|---|---|
| `cloudflare` (`cloudflare.go:110-159`) | `APIToken`, or `Email` + `APIKey` (mutually exclusive); optional `ZoneAPIToken` for zone listing, `ZoneID`, `BaseURL`, `HTTPClient`, `Nameservers` | `CLOUDFLARE_DNS_API_TOKEN`, `CLOUDFLARE_ZONE_API_TOKEN`, `CLOUDFLARE_EMAIL`, `CLOUDFLARE_API_KEY`, `CLOUDFLARE_ZONE_ID`, `CLOUDFLARE_{PROPAGATION_TIMEOUT,POLLING_INTERVAL,TTL,HTTP_TIMEOUT}`, each also as `CF_*` (`:74-93`); no `_FILE` | 120 | |
| `route53` (`route53.go:99-152`) | `AccessKeyID` + `SecretAccessKey`, or `Ambient`; `Region`, `HostedZoneID`, `Role` (STS assume-role), `WebIdentityToken` (requires `Role`), `ZoneFinder`, `Nameservers` | `AWS_ACCESS_KEY_ID`†, `AWS_SECRET_ACCESS_KEY`†, `AWS_REGION`, `AWS_HOSTED_ZONE_ID`, `AWS_{PROPAGATION_TIMEOUT,POLLING_INTERVAL,TTL}`, overridden by `ROUTE53_*` (`:73-82`); no key pair → `Ambient` | 10 | waits for the change to reach `INSYNC`; zone discovery skips private zones |
| `azure` (`azure.go:105-164`) | `ClientID` + `ClientSecret` + `TenantID`, or `Ambient` (optionally `ManagedIdentityClientID` / `ManagedIdentityResourceID`); `SubscriptionID`, `ResourceGroupName` (required), `ZoneName`, `Environment`, `Nameservers` | `AZURE_CLIENT_ID`†, `AZURE_CLIENT_SECRET`†, `AZURE_TENANT_ID`†, `AZURE_SUBSCRIPTION_ID`†, `AZURE_RESOURCE_GROUP`†, `AZURE_ZONE_NAME`†, `AZURE_ENVIRONMENT`, `AZURE_{PROPAGATION_TIMEOUT,POLLING_INTERVAL,TTL}` (`:79-88`); missing client credentials → `Ambient` | 60 | record-set updates are ETag-conditioned (`IfMatch`) |
| `clouddns` (`clouddns.go:94-134`) | `Project` (required), `ServiceAccountJSON` or `Ambient`, `HostedZoneName`, `ZoneFinder`, `Nameservers` | `GCE_PROJECT`†, `GCE_SERVICE_ACCOUNT_FILE`† (falls back to `GOOGLE_APPLICATION_CREDENTIALS`; neither → `Ambient`), `GCE_ZONE_NAME`, `GCE_{PROPAGATION_TIMEOUT,POLLING_INTERVAL,TTL}` (`:71-77`) | 120 | zone discovery prefers public zones |

`AZURE_ENVIRONMENT` is case-insensitive: `AzureCloud`, `AzurePublicCloud` or
empty select the public cloud, `AzureUSGovernment` /
`AzureUSGovernmentCloud` the US Government cloud, `AzureChinaCloud` the China
cloud; anything else is a `ConfigError` (`getCloudConfig`, `azure.go:528`).
Provider errors are `ProviderError`, `ConfigError` and `APIError`
(`errors.go`).

A new provider is a package under `providers/<name>/` implementing `Provider`
(and `ProviderTimeout`), with `New(ctx, Config)` and `NewFromEnv(ctx)`,
registered in `init()`; its row goes in the table above.

#### `pkg/acme/challenges/dns-01` helpers

`dns01.SetupWithProvider(ctx, provider, domain, challengeToken)` /
`CleanupWithProvider` (`dns01.go:255`) place the
`_acme-challenge.<domain>` record through a `Provider`; `ComputeChallengeValue`,
`GetProvider` and `ListProviders` wrap the registry. `SetDNSService`
(`:103`) and `Setup(challengeToken, authzValue)` (`:200`) instead write the
TXT record (TTL 300) into an in-process `DNSServiceInterface` zone (`:69`).
Errors: `ErrChallengeFailed`, `ErrDNSServiceNotInitialized`,
`ErrProviderNotConfigured`. Outside tests only `GetProvider` is called, by the
client service's DNS-01 setup below (`pkg/acme/client/service/dns01_provider.go:86`).

#### http-01 responder

`pkg/acme/challenges/http-01/responder.go` serves one key authorization at
`/.well-known/acme-challenge/<token>` for a client that has no web server of
its own; the SDK re-exports it as `acme.NewHTTP01Responder`,
`HTTP01Responder`, `HTTP01ResponderConfig`, `ConfigError`, `BindError` and
`ShutdownError` (`sdk/go/acme/http01_responder.go:72-97`).

- `ResponderConfig` (`:100`): `Addr`, `KeyAuth`, `ReadTimeout` (5 s),
  `WriteTimeout` (10 s), `IdleTimeout` (120 s), `ShutdownTimeout` (15 s)
  (`:44-53`).
- `NewResponder` (`:165`) refuses an empty `Addr` or `KeyAuth`
  (`ResponderConfigError`), turns a bare port into `:port`, and binds before
  returning, so a bind failure is a `ResponderBindError` at construction.
  `Addr()` (`:223`) reports the bound address.
- `Shutdown(ctx)` (`:252`) applies `ShutdownTimeout` when the context has no
  deadline; after a successful stop it is a no-op returning nil. A failed
  shutdown returns `ResponderShutdownError` and does not mark the responder
  stopped, so `Shutdown` can be retried.
  `Close()` (`:277`).

#### enroll-01 client endpoints

`enroll01.Setup(listenAddr, keyAuth, tpm)` (`pkg/acme/challenges/enroll-01/enroll01.go:340`)
is the device side of enroll-01: it serves `/.well-known/acme-activation/`
(`:83`), answering the server's `GET` with the challenge material and its
`POST` with the credential activation. `endorse01.Setup(challengeToken,
certAuthority, tpm, serializer)` (`endorse01.go:167`) is the endorse-01
counterpart.

The TCG-CSR-IDEVID `enroll-01` finalizes carries `TCG_IDEVID_CONTENT`
(`pkg/tpm2/types.go:853`); finalize reads `ProdModel`, `ProdSerial`,
`EkCert`, `AttestPub`, `SigningPub`, `BootEvntLog` and `ProdCaData`
(`order_finalize.go:1638-1647`). See [`api.md`](api.md#enroll-01-finalize)
for what it returns.

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

`meta.profiles` lists the order profiles a newOrder may name, with their
descriptions (draft-aaron-acme-profiles; `directory.go:50`, from
`orderProfiles`, `order_svid.go:35`). Today that is `x509-svid` only.

## Invariants

- **An ACME certificate carries the account's tenant as its first subject OU
  (go-xkms#1557).** `OrderFinalizeHandler` takes the tenant from the
  authenticated account, never the CSR: `issuanceTenant`
  (`pkg/acme/server/handlers/order_finalize.go:320`) returns the account's
  `TenantID`, or `qrdbsdk.SystemTenantID` for a tenant-less account, and is
  set on the endorse-01 EK request (`:767`), the CA `SignOptions` (`:847`) and
  the enroll-01 TCG request (`:1493`). The pipeline issuer's `buildTemplate`
  (`pkg/acme/issuance/issuance.go:461`, `:473`) stamps `Request.TenantID`
  through `ca.StampTenant`, replacing any OU the CSR carries; a request with
  no tenant fails with `ca.ErrTenantRequired` wrapped in an `IssuanceError`
  (`PhasePrecertSigning`). The rule itself is in
  [certificate-authority](../certificate-authority/engineering.md#invariants).
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

- **The admin plane resolves every mTLS caller's tenant from its certificate,
  then its qrdb user within that tenant (go-xkms#1240).** The admin routes
  are identity-gated module routes (`pkg/apimodule/admin_module.go:146`), so
  qrdb's authentication chain refuses an anonymous caller before the admin
  package runs (go-xkms#1380). The admin package still resolves the caller
  itself rather than trusting the module boundary.
  `MTLSAuthHandler` (`pkg/acme/admin/auth_mtls.go:85-108`) applies qrdb's
  own rule, `qrdbsdk.TenantFromClientCert`, pinned to the deployment's trust
  domain (`Server.TrustDomain`, `pkg/server/firstboot.go:377`, passed at
  `cmd/xkmsd/admin.go:158`): a tenant SPIFFE SAN wins, else the first
  Subject OU, else the system tenant. It binds that tenant and looks the
  SPKI thumbprint up in it alone — a certificate is never searched for in
  another tenant. The refusals are typed and all answer `401`:
  `ErrAuthenticatorNotConfigured` (no authenticator),
  `auth.ErrNoPeerCertificate` (no certificate),
  `*qrdbsdk.ClientCertificateTenantError` (a SPIFFE SAN from another trust
  domain, malformed, or naming two tenants — never a fallback to the OU or
  the system tenant), and `auth.ErrCertNotBound` (no user bound in that
  tenant). `withUser` then binds the user's tenant, so go-xkms#1225's
  `admitTenant` (`pkg/acme/admin/tenant_binding.go:105`) confines a
  tenant user to its own tenant's routes.
- **The admin plane resolves every mTLS caller to its qrdb user before the
  permission gate runs.** xkmsd builds the admin plane's authenticator with
  the qrdb SPKI-thumbprint user store (`cmd/xkmsd/admin.go:153`,
  `Server.QRDBUserStore`, `pkg/server/server.go:1586`), so the
  identity `PermissionGate.Authorize` (`pkg/acme/admin/authz.go:83`) hands to
  qrdb's RBAC carries the user's tenant and **qrdb role IDs** — every role,
  verbatim (`pkg/auth/qrdb_userstore.go:50-59`, `pkg/auth/mtls.go:220`).
  go-qrdb resolves permissions by role ID only; a role name, or a missing
  store, leaves the identity with no resolvable role and every admin route
  answers 403, which is what go-xkms#1069 was. A certificate bound to no user
  is refused with `401` and never authenticates from its fields
  (go-xkms#1096). The admin plane declares no permission of its own: each
  route permission in `admin.Routes()` (`pkg/acme/admin/routes.go:97-174`) is
  a qrdb-registered permission that qrdb
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
  - `admitTenant` (`tenant_binding.go:105`), over `auth.AdmitTenant`, admits a cross-tenant
    caller (`auth.IsCrossTenant`: no identity, empty or system tenant) to
    any tenant and a tenant-scoped caller to its own only. Its refusal,
    `*TenantBindingError` (`:36`), unwraps to `ErrTenantNotFound` and renders
    its message (`:47`, `:53`), so a foreign tenant reads exactly like a
    missing one — the go-xkms#1112 convention `pkg/xkms` follows. Every
    `{id}`-scoped `TenantAwareAdminService` method calls it after the
    empty-ID check (lifecycle, CA hierarchy, EAB, roles, users;
    `tenant_service.go`), and every `{id}` handler repeats it through
    `checkTenantAccess` (`tenant_handlers.go:72`) before the body is read,
    answering `writeTenantNotFound` (`:92`).
  - A `qrdbsdk.IdentityIsSystemTenant` check reserves tenant creation
    (`tenant_service.go:195`) and the audit trail (`handlers.go:416`) — whose
    events carry no tenant to filter by — to a cross-tenant caller. Tenant
    creation refuses with `*PlatformScopeError` (`tenant_binding.go:63`),
    which unwraps to `ErrForbidden` and is answered `403`
    (`tenant_handlers.go:143-144`); the audit trail answers with the gate's own
    denial body (`writePermissionDenied`, `authz.go:170`).
  - The admin plane carries no `/admin/barrier/*` routes: the barrier is
    go-qrdb's and the ACME admin API does not re-expose it.
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
  `pkg/acme/api/server/interceptor_authz.go:118-126`) and MCP
  (`authorizeMCPMethod`, `pkg/acme/api/server/mcp_authz.go:65`) all resolve
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
- **An attestation challenge (`enroll-01`, `endorse-01`, `device-attest-01`)
  is run only by a verifier that reports the identity it attested, and
  authorizes nothing unless that identity equals the order's identifier.** It
  never authorizes an `ip` identifier. A verifier that cannot report an
  identity is refused, not run.
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
- **A newOrder names only an offered profile.** An unknown `profile` is
  `invalidProfile` (400, `common.InvalidProfile`, `pkg/acme/common/errors.go:136`;
  `new_order.go:81`). The order echoes its profile. An order with no profile
  is issued as before.
- **`x509-svid` orders are authorized by the account's tenant binding, not a
  challenge.** The one `spiffe` identifier (`pkg/acme/common/types.go:41`)
  must be `spiffe://<tenant>/svc/<name>` in the account's own tenant, and that
  tenant must have its own signing CA. Its authorization is created valid and
  the order `ready` (`authorizeSVIDOrder`, `order_svid.go:111`). Finalize
  re-checks that and signs the SVID under the tenant CA
  (`order_finalize.go:580`, `:783`), through its own issuer, whose linter
  admits the URI SAN of a tenant trust domain (`order_finalize.go:956`;
  `linter.Identifiers.SVID`, `pkg/acme/linter/linter.go:105`). A `spiffe` identifier without the profile
  is `unsupportedIdentifier`. The refusal table is in
  [`workload-identity/engineering.md`](../workload-identity/engineering.md#acme-issuance).
- **A tenant-signed certificate is verified against the tenant CA.**
  `verifyIssued` (`order_finalize.go:325`) anchors the check at the tenant
  issuer. The global CA's pools never chain a tenant CA's certificates.
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
  permanent identifier), is `badCSR` with `ErrCSRIdentifierMismatch`'s detail
  — RFC 8555 §7.4 answers "the CSR and order identifiers differ" with
  `badCSR` (`matchesPermanentIdentifierOrder`,
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
`ErrKeyBindingRequired` for both and a server holds the `VerifiedAttestation`
between the two requests
(`pkg/acme/challenges/device-attest-01/binding.go`).

**The evidence is the client's payload (draft-ietf-acme-device-attest).** The
client POSTs the challenge URL with `{"attObj": base64url(CBOR)}`.
`ChallengeHandler` reads it from the verified JWS (`parseKID`) and passes it to
the verifier as `common.AttestationChallenge.Payload`. The server never dials
the device: `DialTarget` and `Port` are empty for this challenge, the
loopback-identifier substitution does not apply to it (`dialsDevice`), and a
device with no network address enrolls through any gateway that can POST. A
client that accepts the challenge with `{}`, as for every other type, gets an
`invalid` challenge, not a pending one.

**`tpm` at the challenge** — `verifyTPMEvidence` (`tpm.go:65`) applies WebAuthn
Level 2 §8.3, after `VerifyAttestation` has asked the `AttestationVerifier` to check the object
(`VerifyAttestationObject`) and to anchor every `x5c` entry
(`VerifyAKCertificateChain`; an entry that is not a byte string refuses the
chain rather than being dropped):

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

**`tpm` at finalization** — `BindCSRKey` (`binding.go:161`) checks the CSR
self-signature, then `tpmCSREvidence` (`binding.go:228`) re-submits the
recorded `certInfo`/`sig`/`pubArea`/`x5c[0]` to the gate with the CSR's
SubjectPublicKeyInfo. `verifyTPMCertifyBinding` (`invariants.go:304`) repeats
every certification check and then requires `pubArea`'s key to equal the CSR's
key, compared as keys rather than encodings (`verifyCertifiedKeyIsSubjectKey`,
`invariants.go:373`). The record carries only bytes (`LeafDER`, `CertInfo`,
`Signature`, `PubArea`, `Algorithm`), so it survives storage between the two
requests.

**`dice` at finalization — the possession request.** A template-minting DICE
device's alias key is its static DeviceID key, so its challenge leaf says
nothing about which finalize it belongs to. Its CSR is therefore a possession
request: a PKCS#10 CertificationRequestInfo built from a fixed template whose
inputs are the attested key, the alias certificate's claims set and one
host-supplied value, `b = DICENonce(keyAuthorization)`, signed by the device
and wrapped by the host
(`pkg/acme/challenges/device-attest-01/possession.go:38-77`). The template is an
empty subject, a P-256 key and one `extensionRequest` holding a critical
`subjectAltName` with the `permanentIdentifier` otherName `hex(ueid)` and a
critical `tcg-dice-UCCS-evidence` carrying the alias claims
`{10: b, 256: ueid, 273: measurements}`; the ADR's 365-byte vector pins it
(`possession_test.go:126`). The ACME identifier type is `permanent-identifier`
(`possession.go:85`).
`bindDeviceAttestationKey` runs `VerifyPossessionCSR` for every `dice` record
before `BindCSRKey` (`pkg/acme/server/handlers/device_attest.go:228-235`).
`ParsePossessionCSR` (`possession.go:318`) refuses anything the template would
not have written, then four checks run, each its own `badCSR` cause:

| Check | Error | Where |
|---|---|---|
| the signature verifies under the request's key | `ErrPossessionSignatureInvalid` | `possession.go:386` |
| the SubjectPublicKeyInfo is byte-equal to the attested leaf's | `ErrPossessionKeyMismatch` | `possession.go:389` |
| the UCCS nonce is SHA-256 of this order's key authorization | `ErrPossessionNonceMismatch` | `possession.go:392` |
| the request's identifiers are exactly the order's | `ErrPossessionIdentifierMismatch` | `possession.go:395` |

`BindCSRKey` (`binding.go:153`) then refuses, as `ErrKeyBindingUnavailable`
("no attested SPKI"), a record without `AttestedSPKI`, the key the device
registry vouched for at the challenge, and as `attestation.ErrKeyNotBound` a
request whose SubjectPublicKeyInfo is not byte-equal to it (`diceCSREvidence`,
`binding.go:184`).

A request that passes is then **re-confirmed against the device registry**
(`ConfirmRegistration`, `registry.go:298`, called from
`bindDeviceAttestationKey`, `handlers/device_attest.go:238`). The server looks
the device's UEID up again and refuses, as `unauthorized`, a device whose
provisioning record was deleted or whose provisioned key is no longer
`AttestedSPKI`. The CSR is judged first, so a request for the wrong key is
`badCSR` whatever the registry says. The registry's error can name internal
state, so the client gets a fixed detail and the cause is logged.


So a `dice` order names one device and nothing else. No requested extension
reaches the certificate: the handler issues with the attested
`permanentIdentifier` alone (`order_finalize.go:851`), and the CA hands a CSR's
extensions only to a certificate profile (`pkg/ca/ca.go:1956`). The profile and
the rejected alternatives are in
[dice-device-identity/architecture.md](../dice-device-identity/architecture.md#possession-at-finalize-the-device-signs-a-fixed-template).

**One gate.** The TPM2 profile identifies its attester by public area
(TCG-CSR-IDEVID) or by certificate (`Evidence.AttesterCertificate`, this
format) — never both — and reads its challenge from the certification's
`extraData` (`challengeInCertify`, `invariants.go:167`). A TCG-CSR caller that
supplies no `SubjectSPKI` and no challenge is checked exactly as before.

**What an anchoring implementation must know.** An AIK certificate's SAN is
critical and holds only a `directoryName`, which `crypto/x509` reports in
`UnhandledCriticalExtensions`; `checkAIKCertificate` reads it, so the
`AttestationVerifier` must treat it as handled when it verifies the chain.
`TrustAnchorVerifier` (`anchors.go`), the production implementation, reads the
SAN with `checkAIKCertificate` first and marks it handled on a copy.

**The production verifier.** `deviceattest01.TrustAnchorVerifier` anchors a
`tpm` chain to configured `tpm_roots` with `evidence.VerifyAKCertificate`. A
`dice` attestation is anchored in the **device registry**, never in a root
pool alone, as described in the next section. `xkmsd` builds the verifier from
`acme.challenges.device_attest` and refuses to start with `device_attest01`
enabled and no anchor (`config.ErrACMEDeviceAttestNoAnchors`,
`ErrACMEDeviceAttestAnchors`). The keys are under
[Configuration](#configuration).

## DICE device registry

A DICE alias certificate is signed by the key it carries, so on its own it
vouches only for itself: any host can mint one for a key it generated and name
any device's UEID. What says which key belongs to a device is the device's
**provisioning record**, written when the device is provisioned, outside any
field host (`pkg/acme/challenges/device-attest-01/registry.go`).

**The resolver contract.** go-xkms declares the lookup, and the platform that
owns enrollment implements it and injects it through `TrustAnchors.Devices`
(`anchors.go:75`), so the dependency points from the enrollment layer to go-xkms:

```go
type DeviceResolver interface {
    ResolveDevice(ctx context.Context, ueid string) (*ProvisionedDevice, error)
}

type ProvisionedDevice struct {
    DeviceIDKey         []byte // DER SubjectPublicKeyInfo: the raw-key path
    DeviceIDCertificate []byte // DER DeviceID certificate: the endorsement path
}
```

- `ueid` is the lowercase hex of the complete RFC 9711 UEID: `01` followed by
  the 16-byte DeviceID, 34 digits.
- A UEID with no record is reported as an error wrapping
  `ErrDeviceNotProvisioned`. Any other failure is any other error. Both refuse
  the device; the sentinel only lets a caller tell an unprovisioned device from
  a registry that is down.
- Exactly one field of the record is set. Neither or both is
  `ErrProvisioningRecordInvalid`, as is a key that is not an ECDSA P-256
  SubjectPublicKeyInfo or a certificate that does not parse.

**The two paths.** `VerifyRegisteredDevice` (`registry.go:116`) reads the UEID
from the alias leaf only as the lookup key, then anchors the leaf along the path
its record selects. Nothing else the leaf says is believed until then.

| Path | Record | The leaf is anchored when | Attested SPKI |
|---|---|---|---|
| raw key | `DeviceIDKey` | its SubjectPublicKeyInfo is byte-equal to the provisioned key (`ErrAttestedKeyMismatch`) **and** its ECDSA-SHA256 signature verifies under that key (`ErrAliasSignatureInvalid`) | the provisioned key |
| endorsement | `DeviceIDCertificate` | the DeviceID certificate names the same UEID, and `dice.Verify([alias, DeviceID certificate])` anchors in `dice_roots` (`ErrDeviceEndorsementInvalid`) | the DeviceID certificate's key |

On the raw-key path neither check is enough alone: a leaf can copy the
registered key and forge its measurements, and `dice.Verify` does not check a
leaf's signature when it is given no roots. On the endorsement path an empty
`dice_roots` refuses the device (`ErrNoTrustAnchors`); it never falls back to
the raw-key path. Because the attested SPKI there is the DeviceID certificate's
key, finalization accepts only a CSR for that key, and the alias must carry it
too.

Only after anchoring does `dice.Verify` check the claims: the `eat_nonce`
(`DICENonce(keyAuthorization)`), a required `Ueid`, and the configured
`dice_require_*` policy. A claim that fails is `ErrCertificateChainInvalid`,
answered as `incorrectResponse`.

**Fail closed.** Every refusal by the registry is joined under
`ErrDeviceNotAuthorized`, which the challenge handler answers as `unauthorized`
(`handlers/challenge.go:65`):

| Condition | Joined reason |
|---|---|
| `TrustAnchors.Devices` is nil, or the `AttestationVerifier` does not implement `RegisteredDeviceVerifier` | `ErrNoDeviceResolver` |
| the leaf carries no readable UEID | the identity error |
| the resolver returns an error, including no record | the resolver's error (`ErrDeviceNotProvisioned` for no record) |
| the record is malformed | `ErrProvisioningRecordInvalid` |
| raw key: another key, or a signature that does not verify | `ErrAttestedKeyMismatch`, `ErrAliasSignatureInvalid` |
| endorsement: no `dice_roots`, another UEID, or no chain to the roots | `ErrNoTrustAnchors`, `ErrDeviceEndorsementInvalid` |
| at finalization: the record is gone, or its key is no longer `AttestedSPKI` | the resolver's error, `ErrAttestedKeyMismatch` |

**`AttestedSPKI` is persisted.** `VerifiedAttestation.AttestedSPKI`
(`binding.go:107`) is stored with the challenge as
`entities.DeviceAttestation.AttestedSPKI` (`persist.go`) and read back at
finalization. A `dice` record without one was never anchored in a registry and
is refused as `badCSR`.

**`xkmsd` fails closed.** `xkmsd` has no resolver to inject, so it builds its
verifier with `TrustAnchors.Devices` nil and refuses every `dice` attestation as
`unauthorized`, whatever `dice_roots` and `dice_require_*` say. A DICE fleet is
enrolled by an embedder that supplies its registry; `tpm` is unaffected.

**Device identity, at the challenge.** Binding the CSR's key to
the attested key says the certificate is for a key some genuine device holds.
It says nothing about *which* device, and the evidence is not secret, so a
challenge verifier that stopped there would let a genuine attestation from
device X satisfy an order for a different identifier Y.
`VerifiedAttestation.DeviceIdentity` (`identity.go:78`) closes that: it reads
the RFC 4043 `permanentIdentifier` otherName from the evidence's leaf
certificate — `x5c[0]` for `tpm`, the alias certificate for `dice` (read as
the hex-encoded UEID instead, since a DICE leaf carries no otherName; read by
`dice.DeviceUeid` from the `tcg-dice-Ueid` extension or, as the
trusted-firmware AVR profile states it, from CWT claim 256 of the
`tcg-dice-UCCS-evidence` extension, type byte included, and refused as
`ErrUeidConflict` if a leaf states both and they differ) — the same convention
`pkg/acme/server/handlers.matchesPermanentIdentifierOrder` already reads from
a CSR. go-xkms's own `enroll-01` issuance (`pkg/ca/tcg.go`) puts the same
`permanentIdentifier` otherName on the IAK certificate it issues alongside the
IDevID (TCG DevID v1 r12 §8.1: "on both credentials"), so an AIK this stack
certified carries it; a `tpm` AIK meeting only WebAuthn L2 §8.3.1's minimum
(manufacturer/model/version) does not, and `DeviceIdentity` refuses it with
`ErrDeviceIdentityUnavailable` rather than treating the absence as "no
identity to check."

**The server side: an attesting verifier for every
attestation challenge.** `common.ChallengeVerifierFunc` returns only an error,
so it cannot say which device answered. Beside it, unchanged,
`common.AttestingVerifier` (`pkg/acme/common/attesting.go`) has one method,
`VerifyAttested(resolver, ca, AttestationChallenge)`, returning a
`*common.AttestedIdentity{Identifier, Attestation}`: the identity the evidence
carries, and the `*entities.DeviceAttestation` to persist for finalization
(nil where a challenge type has none). `http-01`, `dns-01` and `tls-alpn-01`
stay on `ChallengeVerifierFunc` in `Params.ChallengeMap`; the attestation types
register in the additive `Params.AttestingVerifiers`
(`sdk/go/acme.ACMEAttestingVerifiers` builds the map; `cmd/xkmsd/acme.go`'s
`buildChallengeMap` registers it). `ChallengeHandler` fails closed on three
counts, all before the verifier is trusted with anything:

- An attestation type with no entry in `AttestingVerifiers` is refused
  (`unauthorized`, logged as `handlers.ErrAttestingVerifierRequired`), even
  when a plain verifier function is registered for it in `ChallengeMap`: that
  function cannot report an identity, so it is never run. Such a type is also
  not offered by `createChallenges`.
- An `ip` authorization is refused (`unsupportedIdentifier`,
  `handlers.ErrAttestationIdentifierType`) without running the verifier. An
  attested device identity is not an IP address; inventing a mapping is the
  hole this design closes. `"ip"` therefore has no default challenge
  candidates (`xkmsDefaultIdentifierChallengeTypes`), and new-order refuses an
  `ip` identifier up front as `rejectedIdentifier` (400,
  `handlers.ErrIPIdentifierNotValidatable`) when the policy offers it no
  non-attestation challenge.
- After the verifier returns, the attested `Identifier` is compared with
  `authz.Identifier.Value` in constant time (both sides are
  attacker-influenced); a difference is refused as `unauthorized`
  (`handlers.ErrIdentityMismatch`, which the client never sees). A verifier
  that reports success with no identity is a server error
  (`handlers.ErrAttestationNoIdentity`).

Only on a match is the verifier's `Attestation` stored as
`entities.ACMEChallenge.DeviceAttestation`, through the ordinary
authorization/challenge DAOs.

What each verifier attests:

| Challenge | Attested identity | Evidence persisted |
|-----------|-------------------|--------------------|
| `device-attest-01` | `tpm`: the AIK certificate's RFC 4043 `permanentIdentifier`; `dice`: the TCG `Ueid`. Evidence without one is refused. | yes |
| `enroll-01` | the order's identifier, which the dial established (a genuine TPM activated a credential at that address); the TPM itself is named by the activated EK in the record | yes: the activation record |
| `endorse-01` | the EK the account's EAB authorized (`AttestationChallenge.AuthorizedIdentity`), never the order's own identifier | no |

`enroll-01` attests possession of a TPM-resident key at an address. Its order's
`permanent-identifier` value is also the address the server dials, so reporting
the identifier is the dial's real binding and the comparison is kept. What the
dial does not say is *which* TPM, and the TCG-CSR-IDEVID arrives one request
later, so the challenge records the activated endorsement key certificate (its
TCG permanent identifier, `ca.EKCertificatePermanentIdentifier`) and the IAK's
public area, and `bindEnrollActivation` refuses a TCG-CSR built around any other
(`ErrEnrollActivationMismatch`).

`endorse-01` attests nothing about the device: an EK is decrypt-only and no
exchange takes place. Its only control is the External Account Binding, so the
identity it reports is the EK that binding names, derived by
`EndorseEABValidator` and handed to `handlers.NewEndorseVerifier`; EAB is
required unless waived, and a binding that names no EK is refused. There is
no MakeCredential proof of possession because the exchange has no carrier:
the order's identifier is the EK, not an address, so there is nothing for the
server to dial, and a second request on the challenge would change the ACME
protocol.
Separating the `enroll-01` order identifier from the dial address remains an
open design question.

**The validated challenge decides which finalize request is honored**
(`order_attestation.go`, `validatedAttestations.requireOnly`). A TCG-CSR-IDEVID
needs enroll-01 to be the only attestation challenge that validated the order;
the EK-certificate request needs endorse-01 alone; a standard permanent-identifier
certificate request needs device-attest-01 alone. Anything else is `badCSR`
(`ErrFinalizeRequestNotPermitted`): an endorse-01 authorization cannot be turned
into an IDevID or a cluster node certificate, and an order no attestation
challenge validated (an `ip` identifier `http-01` validated) cannot be
finalized with a TCG-CSR.

`handlers.NewDeviceAttestVerifier` (`device_attest.go`) is the
`device-attest-01` entry. It takes the server's trust policy
(`deviceattest01.AttestationVerifier`) as an argument. The CA handle is not
asked to be the verifier, because the shipped `*ca.CA` cannot implement an
interface defined in a package that imports `pkg/ca`, and the roots that vouch
for a device are not the CA's issuing configuration. It refuses any identifier
type other than `permanent-identifier` (`handlers.ErrAttestationIdentifierType`),
verifies the payload, and returns the evidence's `DeviceIdentity()` with
`VerifiedAttestation.Record` (`persist.go`) as the record. With no policy it
refuses every attestation (`ErrNoAttestationVerifier`).
`OrderFinalizeHandler` finds the recorded evidence at finalization
(`findDeviceAttestation`, scanning the order's authorizations for a `valid`
`device-attest-01` challenge carrying one) and calls
`bindDeviceAttestationKey`, which reconstructs the `VerifiedAttestation`
(`deviceattest01.FromRecord`), checks a `dice` record's possession request with
`VerifyPossessionCSR`, and re-runs `BindCSRKey` against the submitted CSR
(`device_attest.go:179-200`, called from `order_finalize.go:605`). A permanent-identifier order reaching this point with no record is
refused (`badCSR`) rather than signed as an ordinary certificate request — the
order is never anything other than `device-attest-01` once `enroll-01`'s
TCG-CSR-IDEVID path and `endorse-01`'s EK-public-key identifier have been
ruled out (`matchesPermanentIdentifierOrder` callers), so there is no
legitimate case for the record to be absent.

**A missing authorization refuses finalize.** What an order is -- a
`device-attest-01` order whose key must be bound, an `endorse-01` order, a
TCG-CSR order -- is decided from the authorizations it references
(`orderAuthorizations`, `device_attest.go`). A reference storage does not hold
(a partial restore, a replication fault) is `ErrOrderAuthorizationMissing`, a
`serverInternal` (500) problem, and the request is refused. It is never read as
"no authorization attested this", which would route a TCG-CSR or an `endorse-01`
EK request past the key binding exactly when state is incomplete.

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
`openDeviceTPM`'s hardware branch is given `store.BlobCertStore`
(`pkg/tpm2/store`), which keeps the certificate as a `TPMBlob` in the same
`BlobStore` as the device's key blobs, so it survives a process restart.

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
  `enroll-01` refuses redirects. (`device-attest-01` makes no request.)
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
`http01.Verify` / `ACMEAttestingVerifiers(client, enroll, endorse, deviceAttest)`.

## Certificate Transparency

`pkg/acme/ct` submits precertificates to RFC 6962 logs
([rfc-6962.txt](../references/rfc-6962.txt)) and verifies every SCT a log
returns. Finalize submits every precertificate through it and embeds the
verified SCTs in the final certificate (see [At finalize](#ct-at-finalize)).

**CT is off by default and enabled per log.** A log is a `LogGroup`
(`pkg/acme/ct/types.go:128`) with a base URL, the log's public key and an
`Enabled` flag (`types.go:150`). `PolicyConfig.Enabled`
(`types.go:261`) is true only when at least one log is enabled;
`validatePolicyConfig` (`pkg/acme/ct/policy.go:45`) returns
`ErrNoLogsConfigured` otherwise (`policy.go:68`), and `filterEligibleLogs`
never submits to a disabled log (`policy.go:130`).

**Log configuration is validated before use.** `LogGroup.validate`
(`types.go:191`) runs for every configured log and for `AddLog`
(`policy.go:293`). It refuses:

| Problem | Error |
|---|---|
| URL not an absolute `http`/`https` URL | `ErrLogURLInvalid` |
| No public key | `ErrLogPublicKeyMissing` |
| Key other than ECDSA P-256 or RSA ≥ 2048 (RFC 6962 §2.1.4), `checkLogPublicKey` (`types.go:216`) | `ErrLogPublicKeyUnsupported` |
| Configured `LogID` not the SHA-256 of the key's SPKI (§3.2) | `ErrLogIDMismatch` |
| Same URL or log ID as another log, `checkDuplicateLog` (`policy.go:84`) | `ErrDuplicateLog` |

Each is wrapped in `*LogConfigError` (`pkg/acme/ct/errors.go:137`), which
matches `ErrInvalidLogConfig` under `errors.Is` and names the log. A log ID
left zero is derived from the key with `KeyToLogID` (`types.go:313`).

**Every SCT is verified.** `HTTPLogSubmitter.SubmitPrecert`
(`pkg/acme/ct/submitter.go:61`) refuses a log without a usable key before
sending anything (`submitter.go:63`). It posts to `add-pre-chain` (§4.2) and
returns an SCT only after `VerifySCT` accepts it (`submitter.go:133`).
`VerifySCT` (`pkg/acme/ct/verify.go:74`) rebuilds the §3.2 `digitally-signed`
struct for a `precert_entry`, encoded per RFC 5246 §4
([rfc-5246.txt](../references/rfc-5246.txt)), in `sctSignedData`
(`verify.go:114`):

- `issuer_key_hash` is the SHA-256 of the issuing CA's SPKI, `precertEntry`
  (`verify.go:167`). When the precertificate was signed by a Precertificate
  Signing Certificate (§3.1, EKU 1.3.6.1.4.1.11129.2.4.4), the issuer is the
  next certificate in the chain, `newTBSRewrite` (`verify.go:228`).
- `tbs_certificate` is the precertificate's TBSCertificate without the poison
  extension, `precertTBS` (`verify.go:246`) and `precertExtensions`
  (`verify.go:291`). With a Precertificate Signing Certificate, the issuer
  and Authority Key Identifier are replaced with the final issuer's, as §3.2
  requires.

`verifyDigitallySigned` (`verify.go:138`) accepts only SHA-256 with the
algorithm matching the log's key (RFC 5246 §4.7). The refusals:

| Problem | Error |
|---|---|
| Nil SCT or empty precertificate | `ErrNilInput` |
| SCT version other than v1 | `ErrInvalidSCT` |
| SCT log ID not the configured log's | `ErrSCTLogIDMismatch` |
| Hash other than SHA-256, or signature algorithm not the key's | `ErrUnsupportedSCTAlgorithm` |
| Signature does not verify (including another issuer, TBS, timestamp or extensions) | `ErrInvalidSignature` |
| Precertificate not DER | `ErrPrecertMalformed` |
| Poison extension missing or not critical NULL | `ErrPrecertPoisonMissing` / `ErrPrecertPoisonInvalid` |
| Issuer (or the final issuer after a Precertificate Signing Certificate) missing or not DER | `ErrPrecertIssuerMissing` |

Transport and decoding failures stay `*caerrors.TrustedCAError`
(connection, serialization, malformed).

**Tests.** `pkg/acme/ct/ctlog_test.go` runs an httptest RFC 6962 log that
signs real SCTs with P-256 or RSA-2048 keys over a `precert_entry` it builds
from the final certificate, not from the code under test.
`submitter_test.go` and `verify_test.go` verify them end to end, including the
Precertificate Signing Certificate chain, and cover every refusal above.
`MockLogSubmitter` is test-only (`mock_submitter_test.go`).

<a id="ct-at-finalize"></a>
### At finalize

With CT enabled, `Issuer.Issue` (`pkg/acme/issuance/issuance.go:105`) logs
the precertificate before it signs the final certificate:

1. **Submit.** `submitPrecertificate` (`issuance.go:169`) sends the
   precertificate and its issuing chain to every enabled log whose temporal
   window holds the precertificate's `notAfter`, through `CTPolicy.Submit`
   (`pkg/acme/ct/policy.go:101`), the RFC 6962 §4.2 `add-pre-chain` call.
   The chain is built by `issuingChain` (`issuance.go:211`): the order's
   tenant issuer first when the order is signed by one, then the CA bundle
   (`Config.Chain`, `issuance.go:59`; `pkg/ca` `CABundle`), with duplicates
   dropped. On the wire the precertificate leads and each certificate
   chains to the one before it (§4.1, §4.2).
2. **Wait for every log.** `submitToLogs` (`policy.go:147`) submits in
   parallel (at most `MaxParallelSubmissions`), each submission bounded by
   `SubmissionTimeout`, and waits for every log to answer or time out, so each
   failure is reported. Each SCT is verified against its log's key (§3.2,
   above) before it counts.
3. **Apply the policy.** `collectSCTs` (`policy.go:226`) requires at least
   `MinSCTs` verified SCTs from at least `MinOperators` distinct operators,
   and one from an RFC 6962 (not tiled) log when `RequireRFC6962Log` is set.
   A shortfall is a `*PolicyViolationError` or `ErrNoRFC6962Log`, joined with
   each failed log's `*CTSubmissionError`. Logs that failed while the policy
   was still met are returned in `Submission.Failures` (`types.go:297`):
   each is logged at warn level and named in the audit event, and issuance
   continues.
4. **Embed.** `ct.MakeSCTListExtension` (`pkg/acme/ct/sct.go:37`) encodes the
   verified SCTs as a `SignedCertificateTimestampList` in an OCTET STRING
   under OID 1.3.6.1.4.1.11129.2.4.2 (§3.3), and `Issue` appends it to a copy
   of `SignOptions.ExtraExtensions` (`issuance.go:146`) for the final
   certificate. The final certificate keeps the precertificate's serial and
   `notBefore` (§3.1), and `matchPrecertificate` (`issuance.go:292`) still
   requires the two tbsCertificates to be equal once the poison and SCT list
   extensions are removed.

Every submission is audited as `CERTIFICATE_TRANSPARENCY`
(`pkg/acme/audit/types.go:82`): `success` with the SCT count and the failed
logs, or `failure` with the cause. A refused submission, a chain that cannot
be built, or an SCT list that cannot be encoded fails issuance with
`issuance.ErrCertificateTransparency` (`pkg/acme/issuance/errors.go:34`); no
final certificate is signed, and finalize moves the order to `invalid`. Audit
fails closed here as for the other stages.

**The CT problem document.** `issuanceProblem`
(`pkg/acme/server/handlers/order_finalize.go:1774`) maps
`ErrCertificateTransparency` to `certificateTransparencyProblem`
(`order_finalize.go:1794`). RFC 8555 §6.7 has no CT type: the CSR is sound
and the CA could not obtain the SCTs it embeds, so the type is
`serverInternal`. The detail names the unmet requirement and adds whether a
log refused or timed out. It never includes a log's URL or error:

| Cause | Detail |
|---|---|
| `*PolicyViolationError` | `Certificate transparency policy not met: <n> <SCTs\|operators> obtained, <m> required` |
| `ErrNoRFC6962Log` | `Certificate transparency policy not met: no SCT from an RFC 6962 log` |
| `ErrNoEligibleLogs` | `Certificate transparency policy not met: no log accepts the certificate's expiry` |
| any other CT failure | `Certificate transparency submission failed` |
| plus a log timed out (`ErrCTSubmissionTimeout`) | `; a log did not respond in time` |
| plus another `*CTSubmissionError` | `; a log returned no valid SCT` |

**What is not logged.** Only certificates issued through `Issuer.Issue` are
CT-logged:

- EK certificates (endorse-01) are not logged. `s.ca.IssueEKCertificate`
  (`order_finalize.go:814`) bypasses the issuer because the EK is the TPM's
  own key, not the CSR's subject key.
- IAK and IDevID certificates from a TCG-CSR-IDEVID enrollment are not
  logged either; `finalizeTCGCSR` (`order_finalize.go:1454`) issues them.

Both identify a device: the EK certificate identifies the TPM (TCG DevID v1.1
§3.11), and TCG DevID v1.1 §11 keeps device identity private. CT exists to
audit Web PKI certificates (RFC 6962 §1), and a public log would make these
identifiers permanent and correlatable. device-attest-01 certificates go
through the device-identity issuer and are logged when CT is enabled.

**Wiring.** `issuance.New` (`issuance.go:71`) refuses `Config.CT` without
`Config.Chain` (`ErrInvalidConfig`). `newIssuer`
(`pkg/acme/server/handlers/service.go:678`) sets both, for the default and
the device-identity issuer, only when `Params.CT.Enabled()` (`service.go:361`);
`newCTPolicy` (`service.go:714`) submits over HTTP through
`ct.NewHTTPLogSubmitter`, wrapped by `circuitbreaker.WrapLogSubmitter`
(`pkg/acme/server/circuitbreaker/decorators.go:92`) when `Params.Breakers`
is set, with `Params.CTBreaker` (`service.go:367`) or the `ct_submitter`
defaults. An invalid policy fails `NewRestService`. xkmsd
(`cmd/xkmsd/acme.go:352`) and the standalone `TrustedCA`
(`pkg/acme/client/trustedca.go:395`) both build `Params.CT` from
`config.ACMECTConfig.PolicyConfig` (`pkg/config/acme_ct.go:115`) and the
breaker from `acme.resilience.ct_submitter`.

**Configuration.** `acme.ct` (`pkg/config/acme.go:216`; `ct` under the
`TrustedCA` ACME config) is off unless a log is enabled:

```yaml
acme:
  ct:
    min_scts: 2                 # zero selects 1
    min_operators: 2            # zero selects 1
    require_rfc6962_log: false
    submission_timeout: 10s     # zero selects 10s
    max_parallel_submissions: 10
    logs:
      - name: example-log-2026
        operator: example
        url: https://ct.example.com/2026
        public_key: MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...   # PEM or base64 DER SPKI
        enabled: true
        start_time: "2026-01-01T00:00:00Z"   # temporal shard, RFC 3339; empty is open
        end_time: "2027-01-01T00:00:00Z"
```

`ACMECTConfig.Validate` (`acme_ct.go:108`) runs from `ACMEConfig.Validate`
and refuses a key that is not a PEM or base64 DER SubjectPublicKeyInfo
(`ErrACMECTLogPublicKey`), a bound that is not RFC 3339
(`ErrACMECTLogTime`), and every `LogGroup` refusal above.

**Tests.** `cttest.NewLog` (`pkg/acme/ct/cttest/log.go:56`) is an
in-process RFC 6962 §4.2 log. It either signs real SCTs or refuses, returns a
bad signature, or hangs. `pkg/acme/issuance/ct_test.go` issues through a real
CA against it:

- the SCTs are embedded and verify against the final certificate's issuer;
- a failed log is named and issuance proceeds;
- an unmet policy and an unbuildable chain fail;
- a tenant issuer is submitted first.

`pkg/acme/server/handlers/order_finalize_ct_test.go` covers finalize:

- the problem detail for every cause (`TestIssuanceProblemNamesTheUnmetCTPolicy`);
- policy met, not met and log unreachable, end to end
  (`TestFinalizeEnforcesTheCTPolicy`);
- an EK certificate and a TCG-CSR-IDEVID enrollment issued under a policy no
  log can meet, with nothing submitted (`TestFinalizeEKCertificateIsNotCTLogged`,
  `TestFinalizeTCGCSRIsNotCTLogged`).

`pkg/config/acme_ct_test.go` covers the configuration, and
`pkg/acme/server/handlers/ct_issuer_test.go` the wiring.

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
returns every other entry unchanged. The attestation verifiers
(`sdk/go/acme.ACMEAttestingVerifiers`) are not in this map: they make no
outbound call a breaker protects. It
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

`GET /acme/health` (`RestService.HealthHandler`, `HealthStatus`) reports three
things:

- `Checks` — `Params.Health.Ready`: every readiness check registered on the
  go-qrdb SDK `HealthChecker` (`qrdbsdk.NewHealthChecker`), as
  `qrdbsdk.HealthCheckResult`s. `cmd/xkmsd/acme.go` registers
  `datastore.HealthCheckName` (`"datastore"`) backed by
  `(*datastore.Datastore).HealthCheck`, which reports the go-qrdb client's
  `Healthy`. An aggregate `unhealthy` sets `Healthy` false (503). A nil
  `Params.Health` leaves `Checks` empty.
- `Breakers` — every *named* breaker registered on `Params.Breakers`
  (`storage`, `kms`, `ct` when wired) by name: state, failure count,
  success count. `Healthy` (and the 503/200 status) is driven only by this
  set and by `Checks`.
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

## ACME tenant CA hierarchy

An ACME tenant (`entities.Tenant`, `pkg/acme/entities/tenant.go:20-63`) is the
admin plane's issuance tenant, separate from the key-management tenant model in
[`../multi-tenancy/`](../multi-tenancy/architecture.md). Its routes are listed in
[`api.md`](api.md#admin-api-tenant-routes).

| Type | Fields that matter |
|---|---|
| `Tenant` | `ID`, `Name`, `Status` (internal deleted marker only: `UpdateTenantStatus` and a `ListTenants` status filter return `*admin.UnsupportedFieldError{Field: "status"}` / `admin.ErrTenantStatusUnsupported`, HTTP 400 `urn:trusted-ca:error:tenant-status-unsupported`, because go-qrdb v0.51.0-alpha has no tenant status; `pkg/acme/admin/tenant_service.go`), `RootCA` (nil = issue under the global CA), `IntermediateCAs`, `DefaultIntermediateCAID`, `Settings` |
| `TenantRootCA` (`:67-95`) | `CommonName`, `SerialNumber`, `KeyID`, `KeyAlgorithm`, validity, `Status` (`active` / `pending-rotation` / `revoked`), `CertificatePEM` |
| `TenantIntermediateCA` (`:100-145`) | the same, plus `ID`, `ParentType` (`global` / `tenant`), `Purpose`, `ChainPEM` |
| `TenantSettings` (`:148-183`) | `MaxCertificates`, `MaxAccounts`, `AllowedKeyAlgorithms`, `AllowedChallengeTypes`, `CertificateValidityDays`, `RequireEAB`, `AllowEndorse01`, `AllowEnroll01`, `ComplianceConfig`, `CustomMetadata` |

CA purposes are `general`, `server-auth`, `client-auth`, `code-signing` and
`tpm-endorsement` (`CAPurpose*`, ending at `:283`).

- **Parent.** An intermediate with `parent_type: tenant` is signed by the
  tenant's root CA and fails with `ErrTenantRootCANotFound` when the tenant
  has none. Any other value is signed by the global `TrustedCA` root, and
  fails with `ErrCANotConfigured` when ACME is disabled
  (`pkg/acme/admin/tenant_service.go:801-830`).
- **Default.** A new intermediate becomes the default when `set_as_default`
  is true or no default is set yet (`tenant_service.go:926-927`). Setting an
  intermediate's status to anything but `active` clears it as the default
  (`:1100-1101`). `GetDefaultIntermediateCA` (`tenant.go:317`) returns the
  default if it is still active, otherwise the first active intermediate.
- **Selection at finalize.** For an account bound to a tenant,
  `resolveTenantSigningCA` (`pkg/acme/server/handlers/order_finalize.go:120`)
  refuses issuance when the tenant cannot be loaded (`ErrTenantDAOUnavailable`,
  `ErrTenantNotFound`) or is not active (`ErrTenantInactive`, `:158-164`).
  It then calls `GetSigningCA(purpose)` (`tenant.go:426`), which picks:
  1. the first active intermediate of the requested purpose;
  2. the default intermediate;
  3. the tenant root CA;
  4. the global CA.

  The purpose is `tpm-endorsement` when the order's first identifier is a
  `permanent-identifier` and `general` otherwise (`order_finalize.go:691-695`).
  The other purposes are labels that finalize never requests.
- **Settings are recorded, not enforced.** `TenantSettings` is stored and
  round-tripped by the admin service and the gRPC adapters
  (`tenant_service.go:2068-2091`, `pkg/acme/api/server/grpc_service.go:669-676`).
  No issuance path reads it: EAB, endorse-01 and challenge policy come from the
  server configuration (see Configuration).

## Certificate issuance pipeline

Every non-TCG finalize (RFC 8555 §7.4) issues through
`pkg/acme/issuance.Issuer`; the handler calls `Issue` at
`pkg/acme/server/handlers/order_finalize.go:900` and `NewRestService` builds
the issuer in `newIssuer` (`pkg/acme/server/handlers/service.go:678`).
`Issue` (`pkg/acme/issuance/issuance.go:105`) runs, in order:

1. **goodkey.** The CSR's public key passes
   `goodkey.New(goodkey.DefaultPolicy())` (`pkg/acme/goodkey/goodkey.go:91`,
   `:122`) or the order fails with `badPublicKey`: RSA 2048/3072/4096,
   P-256/384/521 and Ed25519 only.
2. **Reserved serial.** `ReserveSerial` (`pkg/ca/ca.go:1985`) reserves one
   serial (RFC 5280 §4.1.2.2) that the precertificate and the certificate
   share (RFC 6962 §3.1); `Issue` also fixes one `notBefore` for both
   (`pkg/acme/issuance/issuance.go:122`).
3. **Precertificate.** `ca.SignCSR` with `SignOptions.Precertificate`
   (`pkg/ca/types.go:610`) adds the critical poison extension
   (`pkg/ca/ca.go:2058`) and neither stores nor records the result.
4. **Certificate.** `ca.SignCSR` signs and stores the final certificate on
   the same profile and SAN path as the precertificate.
5. **TBS match.** `matchPrecertificate`
   (`pkg/acme/issuance/issuance.go:292`) requires the two tbsCertificates to
   be equal once the poison and SCT list extensions are removed, else
   `ErrTBSMismatch`.

With CT enabled, the precertificate is submitted to the CT logs between steps
3 and 4 and the final certificate embeds the verified SCTs (RFC 6962 §3.3;
see [At finalize](#ct-at-finalize)).

**Lint before signing** (CA/Browser Forum Baseline Requirements §4.3.1.2).
For steps 3 and 4 the CA signs a copy of the final tbsCertificate with a
throwaway key of the issuing key's algorithm and passes it to
`SignOptions.Linter`; it signs with the issuing key only if the linter
returns nil (`pkg/ca/presign_lint.go:58`). The issuer's linter
(`lintStage`, `pkg/acme/issuance/issuance.go:237`) runs zlint
(`pkg/acme/linter/linter.go:179`):

- an error or fatal finding refuses the certificate (`ca.ErrLintFailed`,
  `linter.ErrRefused`); it is logged at error level, audited as
  `CERTIFICATE_LINTED` with result `failure`, and the order fails with
  `badCSR`;
- a warning is logged at warn level and audited as `CERTIFICATE_LINTED`
  with result `success`, and issuance continues.

Each signed precertificate is audited as `PRECERTIFICATE_SIGNED`
(`pkg/acme/audit/types.go:72`, `:77`). Audit fails closed: an event that
cannot be recorded stops issuance (`ErrAudit`, `serverInternal`;
`pkg/acme/issuance/issuance.go:266`).

**Lint configuration.** `handlers.Params.Lint`
(`pkg/acme/server/handlers/service.go:353`) selects the lints; its zero
value runs every lint zlint registers. The go-xkms CA is a private PKI, so
both xkmsd (`cmd/xkmsd/acme.go:364`) and the client's `TrustedCA`
(`pkg/acme/client/trustedca.go:405`) run `linter.PrivatePKIConfig`
(`pkg/acme/linter/linter.go:61`). It excludes the Baseline Requirements
lints that policy decides differently: the tenant is the subject OU with no
O; there is no certificate-policy OID; AIA and CRL distribution points
appear only when the CA identity configures them; the validity period is
the operator's; and the signature algorithm is the CA key's, which may be
Ed25519 (`pkg/ca/ca.go:1615`), not only RSA or ECDSA. xkmsd adds the operator's exclusions from `acme.lint`
(`pkg/config/acme.go:221`, merged by `acmeLintConfig`,
`cmd/xkmsd/acme.go:982`):

```yaml
acme:
  lint:
    exclude_lints: ["w_subject_common_name_included"]
    exclude_sources: ["Mozilla"]
```

Finalize issues every identifier authorization accepted: when the
identifier policy does not require a public suffix or does not reject
reserved IP addresses, `newIssuer`
(`pkg/acme/server/handlers/service.go:678`) also excludes the lints that
refuse internal names or reserved IPs (`linter.Config.Admit`,
`pkg/acme/linter/linter.go:104`).

A device-attest-01 certificate asserts the verified device identity as an
RFC 4043 permanentIdentifier otherName, which `e_ext_san_other_name_present`
refuses. `NewRestService` builds a second issuer whose linter also excludes
that lint (`linter.Identifiers.DeviceIdentity`), and finalize uses it only
when the order's attestation verified a device identity
(`pkg/acme/server/handlers/order_finalize.go:897`); every other order keeps
the lint.

An unknown lint name or source fails `linter.New`
(`pkg/acme/linter/linter.go:158`, `ErrConfig`), so xkmsd does not start.

**Key usage.** Without a profile or `SignOptions.KeyUsage`, the CA asserts
`digitalSignature`, plus `keyEncipherment` only for an RSA subject key
(RFC 5480 §3, RFC 8410 §5; `pkg/ca/ca.go:1755`).

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
| permanent-identifier or DNS/IP SAN not authorized by the order (`ErrCSRIdentifierMismatch`) | `badCSR` | 400 |
| `dice` finalize CSR not signed by the attested key, missing its UCCS evidence, or carrying another order's nonce | `badCSR` | 400 |
| finalize CSR key refused by goodkey (`issuance.ErrBadPublicKey`) | `badPublicKey` | 400 |
| certificate fails lint with an error or fatal (`linter.ErrRefused`) | `badCSR` | 400 |
| issuance audit event not recorded (`issuance.ErrAudit`) | `serverInternal` | 500 |

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
`RaftACMEEnrollmentConfig` (`pkg/config/config.go:704`):

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
  **It must be `"8080"`** (or, for `endorse-01`, that challenge's own fixed
  default; `device-attest-01` opens no listener): the server always validates an enroll-01
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
enrollment challenge's (`enroll-01`/`endorse-01`)
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

`acme.challenges.device_attest01` enables `device-attest-01`, and
`acme.challenges.device_attest` (`ACMEDeviceAttestConfig`,
`pkg/config/acme.go:776,780,803-829`) holds its trust anchors:

```yaml
acme:
  challenges:
    device_attest01: true
    device_attest:
      tpm_roots:  [<install-dir>/acme/tpm-aik-root.pem]
      dice_roots: [<install-dir>/acme/dice-device-id.pem]
      dice_require_device_signed_leaf: true   # secure-element profiles
      dice_require_measurement: true          # DiceTcbInfo must carry an FWID
      dice_require_tcb_info: true             # DiceTcbInfo must be present
```

`tpm_roots` are the CAs that vouch for AIK certificates (a manufacturer
attestation CA, a privacy CA, or this deployment's own CA); `dice_roots` are the
anchors of DICE alias chains. A certificate listed in `tpm_roots` anchors a
chain whether or not it is self-signed, so when an AIK is issued by an
intermediate, list that intermediate.

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
through `pkg/acme/storage`. xkmsd builds the storage factory with
`objstore.NewFactory(ds.DAOFactory())` over the server's datastore
(`cmd/xkmsd/acme.go`, `startACMEServer`), so ACME entities live in the same
configured engine as the rest of the daemon. A caller holding only a bare
go-qrdb `KVStore` (the ACME client's local state) uses
`objstore.NewFactoryFromKVStore`. The admin plane and the multi-tenant
`TrustedCA` take the go-qrdb SDK client itself (`admin.QRDBClient`: `KV`,
`Users`, `Roles`) for tenant roles and users; there is no ACME-specific
database client.
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

**The client's `cert deploy` is a filesystem write by design, not a storage
gap.** `pkg/acme/client/service.Deployer.Deploy` writes the issued
certificate and private key PEM to the operator-configured `CertPath`/
`KeyPath` (`trusted-acme-client cert deploy <spec>`), because the consumer is
a third-party web server (nginx, Apache, ...) that loads TLS material from a
filesystem path, not from xkms's datastore. go-xkms#1323's 2026-09-30 ruling
confirms this stays a plain file, moving onto go-qrdb's exported atomic-write
helper once it ships rather than a shared ad hoc temp-then-rename copy; see
`docs/datastore/engineering.md`'s "Secrets that intentionally leave the
server" section.

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
  `SwtpmConnection.Provision` enrolls the Platform SRK
  (`xkmstest.EnrollPlatformSRK`, the test-only `sdk/go/xkmstest`) and
  installs a throwaway IAK certificate with
  `service.ProvisionSimulatorIAKCertificate`, the function
  `pkg/acme/client/service.openDeviceTPM` uses for the in-process
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
deliberately not documented here as if they existed.
