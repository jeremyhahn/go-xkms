# Host Embedding — Engineering

> **Status: NORMATIVE** · Feature: `host-embedding` · Repo: `go-xkms` · Last verified: 2026-09-29

## Exported surface

### `pkg/compose`

| Symbol | Purpose |
|---|---|
| `Deps` | What a host supplies to `Build`. Only `Service` is required. |
| `Build(ctx, Deps) (*Stores, error)` | Composes every feature `Deps` has the dependencies for. Fails only on a nil `Service` (`*NilServiceError`). |
| `Stores` / `(*Stores).Wire(svc)` | The composed stores; `Wire` publishes the non-nil ones into an `*xkms.XKMSService`. |
| `BuildPasswordStore`, `BuildTenantPasswordManager`, `BuildPlatformStore`, `BuildCredentialService`, `BuildSSHClient`, `BuildCA`, `BuildPolicyManager` | One builder per store; xkmsd calls them directly. |
| `StorageFactory`, `BackendLookup`, `PlatformSealer`, `CAParams` | Builder inputs. |
| `Feature` + `Feature*` constants | Feature names used in errors and logs. |
| `Storage*` constants | Persisted store names (`passwords`, `platform-store`, `ssh`, `ca`, `ca-serials`, `ca-revocations`, `policies`). Renaming one orphans data. |

### `pkg/apimodule` options and their SDK re-exports (`sdk/go/apimodule.go`)

| Option | SDK name | Enables |
|---|---|---|
| `WithQRDBClient(func() *qrdbsdk.Client)` | `WithServiceModuleQRDBClient` | Storage for every store (host KV under `xkms/`); the WebAuthn and mTLS/PIV login plane |
| `WithBarrierRegistry(func() *qrdbsdk.BarrierRegistry)` | `WithServiceModuleBarrierRegistry` | Per-tenant Password Manager stores; the `barrier` credential strategy; the barrier served by `WithBarrierRoutes` |
| `WithPINBackend(qrdbsdk.PINBackend)` | `WithServiceModulePINBackend` | Unlocking a tenant Password Manager session (user PIN); the `/api/v1/pin/*` routes |
| `WithPlatformSealer(strategy string, types.Sealer)` | `WithServiceModulePlatformSealer` | The platform sealed-secret store (`/api/v1/platform/*`) |
| `WithCredentialStrategy(string)` | `WithServiceModuleCredentialStrategy` | The credential service's seal strategy (default `manual`) |
| `WithCA(*ca.MultiIdentityCAConfig)` | `WithServiceModuleCA` (takes `TrustedCAMultiIdentityConfig`) | The CA (`/api/v1/ca/*` and the CA RPCs) |
| `WithPCRReader(policy.PCRReader)` | `WithServiceModulePCRReader` (`ServiceModulePCRReader`) | PCR policies (`/api/v1/policies/*`) |
| `WithBarrierRoutes()` | `WithServiceModuleBarrierRoutes` | Registers and serves the barrier, custodian, shares and init route families over the host's barrier and node |

`(*Module).HostStores() *compose.Stores` (SDK: `ServiceModuleHostStores`)
returns the composition after first use; `Disabled` holds the typed reasons
(`ServiceModuleFeatureDisabledError`, `ServiceModuleFeatureBuildError`).

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
| `barrier` | `WithBarrierRoutes` + barrier registry | `no barrier registry was supplied` |
| `custody` | `WithBarrierRoutes` + qrdb client | `no custody clients was supplied` |

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
| `…BarrierRoutes_OffByDefault`, `…ServeTheHostBarrier`, `…WithoutRegistryIsTypedOff` | Barrier families unregistered by default; opt-in serves the host's own unsealed barrier |
| `pkg/compose/compose_test.go` | Every builder, its nil-input and storage-failure errors, CA reload, SSH backend resolution |
| `pkg/seal/policy/backend_store_test.go` | Durable policy store round-trip across reopen, typed faults |
| `pkg/api/rest/host_stores_test.go` | `NewHostServer` mounts store surfaces exactly from `HostConfig` |
| `sdk/go/apimodule_host_test.go` | The SDK re-exports configure the same composition |

Run them with the per-package targets: `make test-compose`,
`make test-apimodule`, `make coverage-compose`.
