# Backend Credentials — Architecture

> **Status: NORMATIVE** · Feature: `backend-credentials` · Repo: `go-xkms` · Last verified: 2026-10-12

## The problem

A crypto backend needs a secret before it can serve anything: the PKCS#11
User PIN, an AWS secret key, an Azure client secret, a Vault token. The
secret must not sit in the config file as plaintext. Depending on the
deployment, it has to be either sealed at rest so the server can restart
unattended, or supplied by an operator and never written to disk.

## Shape chosen: one service, one strategy per process

`pkg/server/credentials.Service` keeps named byte values under a single
strategy, picked once at construction (`New`,
`pkg/server/credentials/service.go:103-136`). Every strategy implements the
same five operations: store, retrieve, submit, delete and list
(`credentialStore`, `service.go:86-92`).

| Strategy | Where the value lives | Owner |
|---|---|---|
| `manual` (default) | go-qrdb's versioned credential service, held in memory, with retrieval that blocks until the value is submitted | go-qrdb (`qrdbsdk.CredentialStrategyManual`, `service.go:37`) |
| `barrier` | go-qrdb's versioned credential service, encrypted by the embedded qrdb node's barrier | go-qrdb (`service.go:40`, `service.go:128-135`) |
| `tpm2`, `pkcs11`, `awskms`, `gcpkms`, `azurekv`, `vault`, `passphrase` | xkms's sealed `seal.PlatformStore`, under the key `credentials/<name>` | go-xkms (`platformCredentials`, `service.go:211-269`, prefix `service.go:45`) |

The split follows the layer ownership. Manual and barrier storage are
go-qrdb's, and xkms uses them as they are. The hardware and cloud sealing
strategies belong to xkms, and go-qrdb has no equivalent (package doc,
`service.go:14-21`). The in-memory behaviour of `manual` is go-qrdb's: its
`pkg/credentials/config.go` defines `StrategyManual` as "stores credentials
in-memory with blocking retrieval until a credential is submitted".

`New` accepts the name set in `validStrategies` (`service.go:59-72`). An
unknown name returns `ErrInvalidStrategy`. A platform strategy without a
platform store returns `ErrNilPlatformStore`, and `barrier` without a barrier
returns `ErrNilBarrier` (`service.go:109-130`).

## What `xkmsd` actually builds per strategy

The name list is broader than what the daemon can serve today. `xkmsd` builds
the platform store from `credentials.seal_strategy` before it builds the
credential service (`initializePlatformStore`,
`pkg/server/platform_store.go:58-82`; call site `pkg/server/server.go:687`):

| `seal_strategy` | `xkmsd` behaviour | Source |
|---|---|---|
| `manual`, `barrier` | No platform store is built. | `platform_store.go:63-66` |
| `barrier` | Refused at config validation unless `datastore.mode` is `standalone` (or unset) and `barrier.enabled` is true. | `pkg/config/config.go:1588-1592`, `CredentialsBarrierStrategySupported` `config.go:291` |
| `tpm2` | The value is sealed under the TPM's Platform SRK and bound to the built-in `platform` PCR policy. Startup fails if the Platform SRK is not enrolled. | `buildTPM2PlatformSealer`, `platform_store.go:146-157` |
| `awskms`, `gcpkms`, `azurekv` | Needs a `backends.<name>` section and the matching build tag. Without the tag, startup fails with `ErrNotCompiledIn`. | `platform_store_awskms.go:39-45`, `platform_store_gcpkms.go:33-39`, `platform_store_azurekv.go:31-37`, `*_stub.go:21-22` |
| `pkcs11`, `vault` | **Startup fails** with `ErrPlatformStoreStrategyUnavailable`. Sealing the credential would need the credential it seals (a cycle). | `platform_store.go:107-121` |
| `passphrase` | **Startup fails** with `ErrPlatformStoreStrategyUnavailable`. No config field carries the passphrase. | `platform_store.go:90-106` |

A host that embeds the `xkms` ServiceModule instead of running `xkmsd` picks
the strategy with `WithServiceModuleCredentialStrategy`
(`sdk/go/apimodule.go:188`). `pkg/compose` builds the service there
(`BuildCredentialService`, `pkg/compose/builders.go:158-166`). A strategy
whose storage the host did not compose turns the feature **off**; it does
not fail startup (`pkg/compose/compose.go:346-359`). See
[`../host-embedding/`](../host-embedding/).

## Data flow at startup

```
initializePlatformStore     credentials.seal_strategy -> sealed PlatformStore (or none)
initializeCredentialService compose.BuildCredentialService(strategy, platformStore, barrier)
resolveConfigSecrets        every credential://<name> reference -> Service.RetrieveCredential
initializeBackends          backends read the resolved secrets
```

`pkg/server/server.go:687-712`. The `credential://` resolver is go-qrdb's
`secret.NewCredentialResolver`, backed by `Service.RetrieveCredential`
(`pkg/server/secret_wiring.go:29-35`). Five backend fields resolve this way:
`backends.pkcs11.pin`, `rng.pkcs11.pin`, `backends.awskms.secret_key`,
`backends.azurekv.client_secret` and `backends.vault.token`
(`secret_wiring.go:62-69`). Once built, the service is passed to the
`XKMSService` (`pkg/server/server.go:979`, `pkg/compose/compose.go:295`).
Every transport reaches it through that service.

## Read boundary

The credential API can submit, list names and report the strategy. It has
no verb that returns a value (`Service.ListCredentials`,
`service.go:182-196`). Rotating a credential means submitting a new value
under an existing name (`cmd/xkmsctl/credential.go:64-66`).

Under a platform strategy the value is a platform-store entry named
`credentials/<name>`, and the platform-secrets API cannot reach it. Its Put,
Get, Delete and Reseal refuse any name inside that namespace with
`xkms.ErrReservedSecretName`, and its List and Status leave those names out
(`requirePlatformSecretName` and `platformSecretNames`,
`pkg/xkms/servicer_seal_store.go:167-183`; error `pkg/xkms/errors.go:359`).
The namespace test is `credentials.InNamespace`
(`pkg/server/credentials/service.go:52-54`). It cleans the name first, so
`/credentials/x` and `a/../credentials/x` are refused too. The credentials
service is the namespace's only reader.

Each transport reports the refusal as a permission error, not as not-found:

| Transport | Answer | Source |
|---|---|---|
| REST, QUIC | 403 | `pkg/api/rest/seal_store_handlers.go:262` |
| gRPC, Unix | `PermissionDenied` | `pkg/api/apierrors/tables.go:46`, `pkg/api/grpc/errors_keyops.go:42` |
| MCP | Forbidden | `tables.go:46`, `pkg/api/mcp/errors_shared.go:49` |

The Unix socket serves the gRPC service (`pkg/api/unix/grpc_server.go:334`).
See [`../platform-secrets/`](../platform-secrets/).

## Scope

Submitting and listing credentials is **platform-scoped**. A tenant-scoped
caller is refused with `*xkms.TenantBindingError`, which reads as not-found
(`requirePlatformScope`, `pkg/xkms/servicer_credentials.go:26-34`, `:76`).
Reading the strategy has no scope check (`servicer_credentials.go:59-69`).

## Rejected alternatives

- **A separate `rotate` verb.** `submit` already replaces a value in place,
  and with no read path no old value can be lost
  (`cmd/xkmsctl/credential.go:64-66`).
- **Strategy-specific config sub-sections** (`credentials.tpm2.*`,
  `credentials.awskms.*`). `CredentialsConfig` has only `seal_strategy`
  (`pkg/config/config.go:271-282`). The sealers reuse the backend's own
  config (`backends.tpm2`, `backends.awskms`, ...).
- **A random passphrase stored next to the data** for `passphrase`. It was
  removed because it does not seal anything (`platform_store.go:91-100`).

## Corrections to the legacy document

The deleted `docs/init/credentials.md` described several things the code does
not do:

- per-strategy config blocks under `credentials:`
- a `CredentialSealer` interface with nine sealer types
- an interactive `Enter User PIN:` prompt
- `storage.backend: qrdb` as the barrier precondition (the check is on
  `datastore.mode`)
- `pkcs11`, `vault` and `passphrase` as working strategies
