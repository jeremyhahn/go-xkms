# Backend Credentials — Engineering

> **Status: NORMATIVE** · Feature: `backend-credentials` · Repo: `go-xkms` · Last verified: 2026-10-12

## Exported surface — `pkg/server/credentials`

| Symbol | Contract | Source |
|---|---|---|
| `StrategyManual`, `StrategyBarrier` | go-qrdb's strategy IDs, re-used | `service.go:36-42` |
| `Config{Strategy string}` | `""` selects `manual` | `service.go:75-82` |
| `New(cfg, platformStore, barrier, logger)` | Validates the strategy, then picks the store: platform strategies → `platformCredentials`; `manual`/`barrier` → `qrdbsdk.NewVersionedCredentialService` | `service.go:104-137` |
| `(*Service).StoreCredential` | Seals a value; name and value must be non-empty | `service.go:140-145` |
| `(*Service).RetrieveCredentialBuffer` | Unseals a value into a `*secure.Buffer` the caller destroys. Under `manual` it blocks until the value is submitted or `ctx` is cancelled | `service.go:147-155` |
| `(*Service).SubmitCredential` | Operator entry point. Under `manual` a name can be submitted once, and a repeat returns `ErrCredentialAlreadySubmitted`. The other strategies overwrite | `service.go:157-174` |
| `(*Service).DeleteCredential` | Removes a value | `service.go:176-182` |
| `(*Service).ListCredentials` | Sorted names only | `service.go:184-198` |
| `(*Service).AutoUnsealAvailable` | `true` for every strategy except `manual` | `service.go:200-204` |
| `(*Service).Strategy` | The configured name | `service.go:206-209` |

## Errors

| Sentinel | When | Source |
|---|---|---|
| `ErrInvalidStrategy` | Name not in `validStrategies` | `errors.go:29`, `service.go:110-112` |
| `ErrNilPlatformStore` | Platform strategy without a store | `errors.go:23`, `service.go:120-122` |
| `ErrNilBarrier` | `barrier` without a barrier | `errors.go:26`, `service.go:129-131` |
| `ErrCredentialAlreadySubmitted` | Second `manual` submit of a name | `errors.go:33`, `service.go:169-171` |
| `ErrCredentialNotFound` | go-qrdb's sentinel; also mapped from `seal.ErrSecretNotFound` for platform strategies | `errors.go:37`, `service.go:232-234`, `:244-246` |
| `ErrEmptyCredentialName`, `ErrEmptyCredentialValue` | go-qrdb's sentinels, from `validateInput` | `errors.go:40-43`, `service.go:284-292` |

The service layer adds `xkms.ErrNotConfigured` (no credential service is
wired) and `xkms.ErrInvalidEncoding` (the submitted value is not standard
base64). It also adds the platform-scope `*TenantBindingError`
(`pkg/xkms/servicer_credentials.go:31-55`).

## Service layer — `pkg/xkms`

The transports never call `pkg/server/credentials` directly. They go through
`XKMSService` (`pkg/xkms/servicer_credentials.go`):

| Method | Behaviour | Source |
|---|---|---|
| `SubmitCredential(ctx, *transport.CredentialSubmitRequest)` | Platform-scope check, base64-decode `Value`, submit, return `{status: "accepted"}` | `:31-55` |
| `GetCredentialStrategy(ctx)` | `{strategy, auto_unseal}`; no scope check | `:59-69` |
| `ListCredentials(ctx)` | Platform-scope check, then names | `:74-83` |

The service is installed with `XKMSService.SetCredentialService`
(`pkg/xkms/service.go:351-353`), and `pkg/compose` calls it
(`compose.go:294-296`).

## Invariants

- One strategy per `Service`. It never changes after `New`.
- Platform-strategy entries are namespaced `credentials/` in the platform
  store. `ListCredentials` skips keys outside that prefix
  (`service.go:260-275`).
- Values never leave the service through `ListCredentials`, and no transport
  exposes `RetrieveCredentialBuffer`. Platform secrets refuse and hide the
  `credentials/` namespace, so the credentials service is its only reader
  ([`architecture.md`](architecture.md) §"Read boundary").

## Configuration

| Key | Values | Default | Source |
|---|---|---|---|
| `credentials.seal_strategy` | `manual`, `barrier`, `tpm2`, `pkcs11`, `awskms`, `gcpkms`, `azurekv`, `vault`, `passphrase` | `manual` | `pkg/config/config.go:58`, `:271-282` |

There is no other key under `credentials:`. For what `xkmsd` does with each
value, see [`architecture.md`](architecture.md) §"What `xkmsd` actually
builds".

## Tests

| What | Where |
|---|---|
| Service, every strategy path, sentinels | `pkg/server/credentials/service_test.go` |
| REST handlers and status mapping | `pkg/api/rest/handlers_credentials_test.go` |
| Route permission pairs | `pkg/api/rest/server_route_authz_test.go` (`credentials` rows) |
| CLI request paths and output | `cmd/xkmsctl/credential_test.go`, `cmd/xkmsctl/credential_run_test.go` |
| `credential list` against the real REST router, not a stub | `cmd/xkmsctl/credential_router_test.go` |
| Platform secrets refuse and hide the `credentials/` namespace | `pkg/xkms/servicer_seal_store_test.go`, `pkg/api/rest/seal_store_handlers_test.go`, `pkg/api/grpc/service_seal_store_i705_test.go`, `pkg/api/mcp/handlers_seal_store_test.go` |

`make test-server` runs these together with the rest of `./pkg/server/...`
(`Makefile:1199-1201`). There is no target for this package alone.
