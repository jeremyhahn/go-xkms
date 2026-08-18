# Platform Secrets — Architecture

> **Status: NORMATIVE** · Feature: `platform-secrets` · Repo: `go-xkms` · Last verified: 2026-08-19

## The problem

A platform has a handful of secrets that are not keys and not user data:
credentials for an upstream service, a bootstrap token, a webhook secret. They
need to be at rest under the same protection everything else has, and they need
to survive the machine changing state — or deliberately not survive it.

## Shape chosen: a named byte-blob store over a sealed backend

```go
type PlatformStore interface {
	Put(ctx, name string, secret []byte) error
	Get(ctx, name string) ([]byte, error)
	Delete(ctx, name string) error
	Exists(ctx, name string) (bool, error)
	List(ctx) ([]string, error)
	Reseal(ctx, name string) error
}

var _ PlatformStore = (*SealedPlatformStore)(nil)
func NewPlatformStore(backend storage.Backend, logger *slog.Logger) (*SealedPlatformStore, error)
```

Six operations, names to bytes. The design decision is that **sealing is the
backend's job, not the store's**. `SealedPlatformStore` sits on a
`storage.Backend`; when that backend is a `sealed.Backend`, `Get` transparently
unseals — including, on TPM, only when the PCR state still matches. When it is a
plain file or memory backend, values are stored as-is.

So the same store code is a hardware-sealed secret store in production and an
ordinary map in a test, with no branching.

`Reseal(name)` exists because sealing to platform state has a lifecycle: after a
firmware or boot change the old sealed copy no longer opens. `Reseal` reads the
current plaintext, deletes the old copy, and writes it back sealed against the
*current* state.

Rejected alternatives:

- **Sealing inside the store.** Rejected: that is a second sealer, and the rule
  is that go-qrdb's barrier is the sealer.
- **A general-purpose secret manager.** Rejected — this is deliberately narrow.
  User-facing secrets are the password vault; keys are the keystore.
- **Making `Reseal` implicit on `Get`.** Rejected: resealing silently on read
  would rebind a secret to whatever state the machine happens to be in,
  including a compromised one.

## Component boundaries

| Piece | Where | Owner |
|---|---|---|
| `PlatformStore`, `SealedPlatformStore` | `pkg/seal/platform_store.go` | go-xkms |
| Per-tenant platform store | `pkg/seal/platform_store_tenant.go` | go-xkms |
| Platform sealer | `pkg/seal/platform_sealer.go` | go-xkms |
| Storage backends, including `sealed.Backend` | `pkg/storage` | go-xkms |
| The barrier doing the sealing | go-qrdb | **go-qrdb** |
| Wire surface | `pkg/api/rest/seal_store_handlers.go`, `transport.SealStoreService` | go-xkms |
| CLI | `cmd/xkmsctl/platform.go` | go-xkms |

## Data flow

```
put:    xkmsctl platform put NAME --value -
          → PlatformStore.Put(name, secret)
            → storage.Backend write
              → sealed.Backend: seal under the current strategy (TPM PCRs, HSM, cloud KMS…)

get:    PlatformStore.Get(name)
          → backend read → sealed.Backend unseals if it can
            → TPM: only when the PCR state still matches

reseal: PlatformStore.Reseal(name)
          → read current plaintext → delete old sealed copy → write back under current state
```

## Trust boundaries

- **Protection is entirely the backend's.** On a plain file or memory backend
  the secrets are **not sealed**. That is correct for tests and a serious
  misconfiguration in production. Know which backend a deployment has.
- **`Get` on a TPM-sealed backend fails after a state change.** That is the
  mechanism working, and `Reseal` is the deliberate remedy — which is why it is
  an explicit operation.
- **`Reseal` re-binds to whatever state the machine is in now.** Running it on a
  machine you have not verified rebinds the secret to that machine's state.
- **`Put` overwrites with a fresh seal.** There is no versioning and no
  previous-value recovery.
- **Secret names are not secret.** `List` returns them.
- **`SealedPlatformStore` is concurrency-safe** — all operations take a
  read-write mutex — but concurrency safety is not access control; that is the
  route's session gate.

## What this feature deliberately does not do

- **It does not seal anything itself.** The backend does; the barrier is
  go-qrdb's.
- **It is not the password vault.** User-facing credentials are
  `pkg/staticpw` and xkey.
- **It is not a key store.** Keys are [`../key-management/`](../key-management/architecture.md).
- **It does not version secrets or keep history.**
- **It does not reseal automatically.**
