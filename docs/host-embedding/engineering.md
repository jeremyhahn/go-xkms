# Host Embedding — Engineering

> **Status: NORMATIVE** · Feature: `host-embedding` · Repo: `go-xkms` · Last verified: 2026-10-04

## Exported surface

### `pkg/compose`

| Symbol | Purpose |
|---|---|
| `Deps` | What a host supplies to `Build`. Only `Service` is required. |
| `Build(ctx, Deps) (*Stores, error)` | Composes every feature `Deps` has the dependencies for. Fails only on a nil `Service` (`*NilServiceError`). |
| `Stores` / `(*Stores).Wire(svc)` | The composed stores; `Wire` publishes the non-nil ones into an `*xkms.XKMSService`. |
| `BuildPasswordStore`, `BuildTenantPasswordManager`, `BuildPlatformStore`, `BuildCredentialService`, `BuildSSHClient`, `BuildCA`, `BuildTPMPolicyService` | One builder per store; xkmsd calls them directly. |
| `StorageFactory`, `BackendLookup`, `PlatformSealer`, `CAParams` | Builder inputs. |
| `Feature` + `Feature*` constants | Feature names used in errors and logs. |
| `Storage*` constants | Persisted store names (`passwords`, `platform-store`, `ssh`, `ca`, `ca-serials`, `ca-revocations`, `tpm-policies`, `tpm-keys`). Renaming one orphans data. |

### `pkg/apimodule` options and their SDK re-exports (`sdk/go/apimodule.go`)

| Option | SDK name | Enables |
|---|---|---|
| `WithQRDBClient(func() *qrdbsdk.Client)` | `WithServiceModuleQRDBClient` | Storage for every store (host KV under `xkms/`); the WebAuthn and mTLS/PIV login plane |
| `WithBarrierRegistry(func() *qrdbsdk.BarrierRegistry)` | `WithServiceModuleBarrierRegistry` | Per-tenant Password Manager stores; the `barrier` credential strategy |
| `WithPINBackend(qrdbsdk.PINBackend)` | `WithServiceModulePINBackend` | Unlocking a tenant Password Manager session (user PIN); the `/api/v1/pin/*` routes |
| `WithPlatformSealer(strategy string, types.Sealer)` | `WithServiceModulePlatformSealer` | The platform sealed-secret store (`/api/v1/platform/*`) |
| `WithCredentialStrategy(string)` | `WithServiceModuleCredentialStrategy` | The credential service's seal strategy (default `manual`) |
| `WithCA(*ca.MultiIdentityCAConfig)` | `WithServiceModuleCA` (takes `TrustedCAMultiIdentityConfig`) | The CA (`/api/v1/ca/*` and the CA RPCs) |
| `WithVTPM(*vtpm.Config)` | `WithServiceModuleVTPM` (`TPMVTPMConfig`) | vtpm mode for the TPM policy service, which a self-built module composes whenever its XKMSService has a `tpm2` backend (`/api/v1/tpm/*`) |

`(*Module).HostStores() *compose.Stores` (SDK: `ServiceModuleHostStores`)
returns the composition after first use; `Disabled` holds the typed reasons
(`ServiceModuleFeatureDisabledError`, `ServiceModuleFeatureBuildError`).

### Host request chain (`sdk/go`)

A host that embeds a go-qrdb node and mounts xkms surfaces on it inherits
qrdb's authentication and tenant chain, and adds these xkms pieces around it
instead of writing its own:

| SDK name | Canonical symbol | Role |
|---|---|---|
| `NewQRDBBearerAuthenticator(AuthenticatorSource)`, `QRDBBearerAuthenticator`, `AuthenticatorSource`, `ErrBearerNotAccepted` | `pkg/auth` (`qrdb_bearer.go`) | Register with the node's `WithAuthenticators` so the node's transports accept the host's session tokens. Declines a request with no bearer token (`qrdbsdk.ErrUnauthenticated`, the next authenticator decides); refuses one when its source holds no authenticator or the no-op one; reports its login method as unobservable, because the token's issuer enforced the account's permitted-method policy at login. xkmsd registers it over its `LiveAuthenticator` (`pkg/server/qrdb_node.go`). |
| `Authenticator`, `LiveAuthenticator`, `NewLiveAuthenticator` | `pkg/auth` | The source a bearer bridge reads, once per request; a reload applies to the next request. A host with a fixed authenticator wraps it in `NewLiveAuthenticator`. |
| `NewIPRateLimiter`, `IPRateLimiter`, `IPRateLimitConfig`, `IPRateLimitCapacityError`, `IPRateLimitDefaultMaxClients`, `IPRateLimitMiddleware`, `IPRateLimitUnaryServerInterceptor`, `IPRateLimitStreamServerInterceptor`, `IPRateLimitKey` | `pkg/ratelimit` | The pre-authentication per-client limiter: HTTP 429 / gRPC `ResourceExhausted`, a bounded client table that fails closed when full, IPv6 clients bucketed on their /64 on every transport. |
| `ParseTrustedProxies`, `TrustedProxies`, `InvalidTrustedProxyError` | `pkg/ratelimit` (`clientip.go`) | The client IP: `X-Forwarded-For` is believed only from a configured proxy network. |
| `CorrelationMiddleware`, `CorrelationUnaryServerInterceptor`, `CorrelationStreamServerInterceptor`, `WithCorrelationID`, `CorrelationIDFromContext`, `NewCorrelationID`, `CorrelationIDOrNew`, `Correlation*Header`/`Key` constants | `pkg/correlation` | One correlation ID per request, read from `X-Correlation-ID`/`X-Request-ID` (or the gRPC metadata keys), generated when absent, echoed to the client. The same middleware xkmsd's REST router and gRPC server install. |
| `ScopePrincipal`, `ScopeTarget`, `ScopePrincipalOf`, … | `pkg/scope` | The object ownership rule; see [multi-tenancy/engineering.md](../multi-tenancy/engineering.md#ownership-scopes--pkgscope). An absent identity fails closed. |

The per-identity tenant-barrier gate (`pkg/api/tenantgate`) is not exported:
tenant barriers are go-qrdb's, and that gate belongs in qrdb's middleware.

### Feature → dependency

| Feature | Needs | Off reason recorded |
|---|---|---|
| `passwords` | storage | `no storage was supplied` |
| `tenant-passwords` | storage + barrier registry | `no barrier registry was supplied` |
| `pin` | PIN backend | `no PIN backend was supplied` |
| `platform-store` | storage + sealer | `no platform sealer was supplied` |
| `credentials` | strategy's store (`barrier` → registry, platform strategies → platform store) | `no barrier registry` / `no platform store` |
| `ssh` | storage | `no storage was supplied` |
| `ca` | CA configuration + storage | `no CA configuration was supplied` |
| `policies` | PCR reader + storage | `no PCR reader was supplied` |

## Invariants

- Composition runs **once** per module (`composeMu` + `atomic.Pointer`), for
  every transport. Only an absent XKMSService defers it.
- A nil qrdb client or registry from its resolver means "not supplied", not
  "still composing": the feature is off, with its reason.
- `BuildCA` loads a persisted hierarchy and initializes one only on
  `ca.ErrCertificateNotFound`; any other load failure fails closed
  (go-xkms#793).
- The platform sealer must seal with nil `SealOptions` (it carries its own
  key, as the TPM and cloud sealers xkmsd builds do).
- PCR policy definitions persist through `policy.BackendPolicyStore`, a
  durable `PolicyStore` over a `storage.Backend`.
- xkmsd behavior is unchanged: its stores are built at the same start-up
  points, from the same configuration, now through the `Build*` functions.

## Errors

| Type | When |
|---|---|
| `compose.FeatureDisabledError{Feature, Missing}` | A dependency was not supplied. Informational. |
| `compose.FeatureBuildError{Feature, Err}` | Construction failed with dependencies present. Unwraps. |
| `compose.NilDependencyError{Feature, Dependency}` | A `Build*` caller passed a nil required argument. |
| `compose.NilServiceError` | `Build` without an XKMSService. |
| `compose.CAOperationError{Operation, Err}` | A named CA construction step failed. Unwraps. |
| `compose.CANoIdentitiesError` | CA configuration with no identity. |
| `policy.StoreError{Op, Name, Err}` | `BackendPolicyStore` storage or decoding failure. Unwraps. |

## Tests

| Test | Proves |
|---|---|
| `pkg/apimodule/module_host_stores_test.go` `TestModule_HostMount_EveryStoreAnswers` | Mounted as a host mounts it, the Password Manager, SSH, CA, platform store, policy and credential routes serve real requests, and gRPC sees the same CA |
| `…MissingDependenciesAreTypedAndOff`, `…NoQRDBClientLeavesStoresOff` | Missing dependencies are typed, logged and answer 501/503, never a silent 404 |
| `pkg/compose/compose_test.go` | Every builder, its nil-input and storage-failure errors, CA reload, SSH backend resolution |
| `pkg/compose/compose_tpm_sim_test.go` | The TPM policy service composes over a simulator TPM2 backend and answers through the service |
| `pkg/api/rest/host_stores_test.go` | `NewHostServer` mounts store surfaces exactly from `HostConfig` |
| `sdk/go/apimodule_host_test.go` | The SDK re-exports configure the same composition |
| `pkg/auth/qrdb_bearer_test.go` | The bearer bridge admits a token its source verifies, follows a reload, declines a request with no bearer token, and admits nothing through the no-op authenticator, no authenticator or no source |
| `pkg/correlation/middleware_test.go`, `pkg/ratelimit/*_test.go` (`TestInterceptors_IPv6PeersShareTheirSlash64`) | The correlation middleware and interceptors; the limiter's /64 bucketing on gRPC and raw connections |
| `sdk/go/{qrdb_bearer,ratelimit,correlation,scope}_test.go` | The SDK names are the canonical symbols and keep their behavior |

Run them with the per-package targets: `make test-compose`,
`make test-apimodule`, `make coverage-compose`.
