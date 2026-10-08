# Platform Secrets — Architecture

> **Status: NORMATIVE** · Feature: `platform-secrets` · Repo: `go-xkms` · Last verified: 2026-10-07

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
| The barrier doing the sealing (per-tenant stores; the `barrier` credential strategy bypasses the platform store entirely) | go-qrdb | **go-qrdb** |
| The daemon's own (system) platform store: composition root, per-strategy sealer resolution, tpm2 platform-policy binding | `pkg/server/platform_store.go` | go-xkms |
| Wire surface | `pkg/api/rest/seal_store_handlers.go`, `transport.SealStoreService` | go-xkms |
| CLI | `cmd/xkmsctl/platform.go` | go-xkms |

xkmsd's own platform store is sealed by whichever strategy
`credentials.seal_strategy` names (`tpm2`, `pkcs11`, `awskms`, `gcpkms`,
`azurekv`, `vault`, `passphrase`) — a `seal.PlatformSealer` built around a
single-strategy `types.Sealer`, independent of and parallel to the barrier.
`credentials.seal_strategy: barrier` is the one value that does NOT go
through the platform store at all: for `barrier` and `manual`,
`credentials.Service` delegates to go-qrdb's versioned credential service
(`qrdbsdk.NewVersionedCredentialService`), which stores a `barrier`
credential directly in the barrier and holds a `manual` one in memory only.
The platform strategies are the part xkms adds; go-qrdb has no hardware
credential strategy. See
[`platform_store.go`'s `initializePlatformStore`](../../pkg/server/platform_store.go)
for the per-strategy sealer resolution:

- **`tpm2`** seals under the Platform SRK only — go-xkms never seals under
  the TCG Shared SRK (owner ruling; PR #681 removes every Shared-SRK
  fallback in `pkg/tpm2`/`pkg/backend/tpm2`). It reuses a single TPM open
  with the node-seal flip and the general tpm2 backend rather than opening
  the simulator/device a second time, and fails closed with a typed error
  naming `PlatformKeyStore.EnrollPlatformSRK` when the Platform SRK is not
  yet enrolled — enrollment is a deliberate, separate operator/ceremony
  step this call never performs implicitly.
- **`awskms`/`gcpkms`/`azurekv`** authenticate with each cloud SDK's ambient
  credential chain (IAM role, Application Default Credentials,
  `DefaultAzureCredential`) and resolve their symmetric wrapping key through
  `seal_strategies.go` (`sealKeyAttributesFor`, `ensureSealKey`), over the
  same `seal.EnsureSealKey` the node seal's cloud-KMS strategy provisions
  through — the same fixed key name, not a second scheme.
- **`pkcs11`/`vault`** fail closed today (go-xkms#677): the PIN/token is
  only resolvable through the credential service this call itself builds
  storage for.
- **`passphrase`** fails closed pending an owner ruling on where the
  operator passphrase comes from — see Trust boundaries.

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
- **`Reseal` refreshes a seal that still opens; it does not restore one that no
  longer does.** `Reseal`'s own implementation reads the current plaintext
  first (`Get`), then deletes and re-writes. If the platform state has already
  drifted far enough that `Get` fails — the exact TPM-PCR-mismatch case this
  feature exists to detect — `Reseal` fails identically: there is no plaintext
  left to re-seal, for any strategy, because the secret's only copy was sealed
  under the state that no longer holds. Call `Reseal` proactively, while the
  old state (and therefore `Get`) is still valid — e.g. ahead of a planned
  firmware/PCR change — not as a post-hoc recovery from one that already
  broke access. Verified empirically against the tpm2 strategy
  (`pkg/server/platform_store_test.go`,
  `TestInitializePlatformStore_TPM2PlatformPolicy_PCRExtendBreaksGet`).
- **`Put` overwrites with a fresh seal.** There is no versioning and no
  previous-value recovery.
- **The `passphrase` strategy has no working seal today; it fails closed.**
  `CredentialsConfig` has no field for an operator passphrase, and a
  literal/inline secret in a protected `*types.SecretValue` field is refused
  by the qrdb secret-value contract, so this strategy cannot derive a real
  seal key without either new config surface or a design the owner has not
  yet chosen. An earlier version generated a random secret and persisted it
  **unsealed** next to the data as a stand-in; that is not sealing, and it
  was removed — `credentials.seal_strategy: passphrase` now fails
  `Server.New` with a typed error rather than silently protecting nothing.
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
