# Backend Credentials — Engineering

> **Status: NORMATIVE** · Feature: `backend-credentials` · Repo: `go-xkms` · Last verified: 2026-10-11

## Exported surface — `pkg/server/credentials`

| Symbol | Contract | Source |
|---|---|---|
| `StrategyManual`, `StrategyBarrier` | go-qrdb's strategy IDs, re-used | `service.go:34-40` |
| `Config{Strategy string}` | `""` selects `manual` | `service.go:64-71` |
| `New(cfg, platformStore, barrier, logger)` | Validates the strategy, then picks the store: platform strategies → `platformCredentials`; `manual`/`barrier` → `qrdbsdk.NewVersionedCredentialService` | `service.go:93-126` |
| `(*Service).StoreCredential` | Seals a value; name and value must be non-empty | `service.go:129-134` |
| `(*Service).RetrieveCredential` | Unseals a value. Under `manual` it blocks until the value is submitted or `ctx` is cancelled | `service.go:136-143` |
| `(*Service).SubmitCredential` | Operator entry point. Under `manual` a name can be submitted once, and a repeat returns `ErrCredentialAlreadySubmitted`. The other strategies overwrite | `service.go:145-162` |
| `(*Service).DeleteCredential` | Removes a value | `service.go:164-170` |
| `(*Service).ListCredentials` | Sorted names only | `service.go:172-186` |
| `(*Service).AutoUnsealAvailable` | `true` for every strategy except `manual` | `service.go:188-192` |
| `(*Service).Strategy` | The configured name | `service.go:194-197` |

## Errors

| Sentinel | When | Source |
|---|---|---|
| `ErrInvalidStrategy` | Name not in `validStrategies` | `errors.go:29`, `service.go:99-101` |
| `ErrNilPlatformStore` | Platform strategy without a store | `errors.go:23`, `service.go:109-111` |
| `ErrNilBarrier` | `barrier` without a barrier | `errors.go:26`, `service.go:118-120` |
| `ErrCredentialAlreadySubmitted` | Second `manual` submit of a name | `errors.go:33`, `service.go:157-159` |
| `ErrCredentialNotFound` | go-qrdb's sentinel; also mapped from `seal.ErrSecretNotFound` for platform strategies | `errors.go:37`, `service.go:219-221`, `:234-236` |
| `ErrEmptyCredentialName`, `ErrEmptyCredentialValue` | go-qrdb's sentinels, from `validateInput` | `errors.go:40-43`, `service.go:268-276` |

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
  (`service.go:244-259`).
- Values never leave the service through `ListCredentials`, and no transport
  exposes `RetrieveCredential`. The platform-secrets exception is described
  in [`architecture.md`](architecture.md) §"Read boundary".

## Configuration

| Key | Values | Default | Source |
|---|---|---|---|
| `credentials.seal_strategy` | `manual`, `barrier`, `tpm2`, `pkcs11`, `awskms`, `gcpkms`, `azurekv`, `vault`, `passphrase` | `manual` | `pkg/config/config.go:57`, `:271-282` |

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

`make test-server` runs these together with the rest of `./pkg/server/...`
(`Makefile:1199-1201`). There is no target for this package alone.

### Known gap

`xkmsctl credential list` requests `GET /api/v1/credentials`
(`cmd/xkmsctl/credential.go:239`). The route is registered as
`GET /api/v1/credentials/` with a trailing slash
(`pkg/api/rest/routes.go:416`). The REST router is chi
(`pkg/api/rest/server.go:484`), with no slash redirect, so it answers 404 for
the path without the slash. The CLI unit test uses a stub server and does
not catch this.
