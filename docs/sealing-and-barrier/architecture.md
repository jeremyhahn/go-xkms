# Sealing and Barrier — Architecture

> **Status: NORMATIVE** · Feature: `sealing-and-barrier` · Repo: `go-xkms` · Last verified: 2026-08-19

## The problem

Every persistent secret in the stack is encrypted under a root key, and that
root key has to be protected by something outside the software. What that
"something" is differs completely per deployment: a TPM on a node, an HSM in a
rack, a cloud KMS, a passphrase a human types, or M-of-N Shamir shares held by
several custodians.

go-qrdb owns the barrier and the `StrategyRegistry`, and has **zero hardware
coupling**. go-xkms supplies every hardware and cloud `SealingStrategy` and
registers them in. That is the whole feature: qrdb decides *when* to seal;
go-xkms decides *how*, for the hardware cases.

## Shape chosen: strategies as flat files, registered into qrdb's registry

`pkg/seal` holds one file per family:

| File | Strategies |
|---|---|
| `strategy_tpm2.go` | `tpm2` |
| `strategy_pkcs11.go` | `pkcs11` |
| `strategy_cloud.go` | `awskms`, `gcpkms`, `azurekv`, `vault` |
| `strategy_software.go` | the software path |

`strategy.go` is deliberately thin — it aliases the core types rather than
redefining them:

```go
type StrategyID        = qrdbsdk.StrategyID
type SealingStrategy   = qrdbsdk.SealingStrategy
type SymmetricEncrypter = qrdbsdk.SymmetricEncrypter
type Credentials       = qrdbsdk.Credentials
type SealedRootKey     = qrdbsdk.SealedRootKey
type ShamirConfig      = qrdbsdk.ShamirConfig
type BarrierStatus     = qrdbsdk.BarrierStatus
// … and the rest
```

The ownership split is written into the constants:

```go
// go-xkms owns these six
StrategyTPM2    StrategyID = "tpm2"
StrategyPKCS11  StrategyID = "pkcs11"
StrategyAWSKMS  StrategyID = "awskms"
StrategyGCPKMS  StrategyID = "gcpkms"
StrategyAzureKV StrategyID = "azurekv"
StrategyVault   StrategyID = "vault"

// re-exported, owned elsewhere
StrategyShamir     = qrdbsdk.StrategyShamir      // go-qrdb
StrategyPassphrase = qrdbsdk.StrategyPassphrase  // go-quicraft (L1)
StrategyNone       = qrdbsdk.StrategyNone        // go-quicraft (L1)
```

**"There is no implicit preference-order default — strategy selection is always
explicit."** That sentence is in the source, and it is the design decision that
matters most here. A barrier that silently picked the best available strategy
would mean a node that lost its TPM came back up protected by a passphrase, with
nothing in the logs to say the deployment's security posture had changed.

`autodetect.go` exists and is opt-in: `ProbeStrategies` reports what is
available and `BuildBestStrategy` builds from it. A caller that wants
autodetection asks for it.

Rejected alternatives:

- **Implementing the barrier in go-xkms.** Rejected by ownership: qrdb owns the
  barrier, the registry and Shamir custody; go-xkms implements seams.
- **Defaulting to the strongest available strategy.** Rejected — see above.
- **One strategy interface per hardware type.** Rejected: `SealingStrategy` is
  qrdb's single seam, and every implementation satisfies it.

## Component boundaries

| Piece | Where | Owner |
|---|---|---|
| `SealingStrategy`, `StrategyRegistry`, barrier, `SealedRootKey`, Shamir | `go-qrdb/sdk/go` | **go-qrdb** |
| `none`, `passphrase`, `EpochBarrier`, the Shamir GF(256) primitive | go-quicraft | **go-quicraft** |
| Hardware and cloud strategies | `pkg/seal/strategy_{tpm2,pkcs11,cloud,software}.go` | go-xkms |
| Cloud KMS strategy composition (shared by `xkmsd` and `xkey`, go-xkms#757) | `pkg/seal/cloud_provision.go` | go-xkms |
| Barrier adapter and CAS put | `pkg/seal/barrier_adapter.go`, `barrier_putifabsent.go` | go-xkms |
| Hardware encryptor | `pkg/seal/hardware_encryptor.go` | go-xkms |
| Platform secret store | `pkg/seal/platform_store.go`, `platform_sealer.go`, `platform_store_tenant.go` | go-xkms |
| Secret sealer | `pkg/seal/secret_sealer.go` | go-xkms |
| Seal policy | `pkg/seal/policy` | go-xkms |
| Autodetection | `pkg/seal/autodetect.go` | go-xkms |
| Seal audit | `pkg/seal/audit.go` | go-xkms |
| Sealed blob store | `pkg/sealblobstore` | go-xkms |

Capability row: **"Hardware / cloud `SealingStrategy` impls (TPM2, PKCS#11,
AWS-KMS, GCP-KMS, Azure-KV, Vault)" (tier 2)** — composer-only, registered into
qrdb's `StrategyRegistry`.

**The registry is go-qrdb's.** Any text describing "the xkms `StrategyRegistry`"
describes something that does not exist.

## Data flow

```
initialize:
  xkmsctl barrier init --barrier-strategy tpm2
    → qrdb's barrier generates a root key
      → SealingStrategy.Seal(rootKey, credentials)   ← go-xkms's implementation
        → TPM: PCR-bound seal · PKCS#11: HSM-resident KEK · cloud: envelope
      → SealedRootKey persisted by qrdb

unseal:
  xkmsctl barrier unseal
    → SealingStrategy.Unseal(sealedRootKey, credentials)
      → hardware or provider releases the root key
    → barrier open; every other subsystem becomes usable

per-tenant:
  tenants get their own barriers — pkg/seal/platform_store_tenant.go
```

`barrier_putifabsent.go` is the compare-and-swap path: initializing a barrier
twice concurrently must not produce two root keys.

## Trust boundaries

- **The strategy is the security posture.** `tpm2` and `pkcs11` bind the root
  key to hardware; `passphrase` binds it to something a human remembers; `none`
  disables barrier encryption entirely. These are not interchangeable.
- **`none` exists and means what it says.** It is legitimate for development and
  a disaster in production.
- **Explicit selection, always.** Nothing here falls back. A deployment that
  cannot open its configured strategy fails to unseal — which is the correct
  behaviour, because the alternative is coming up in a weaker posture nobody
  noticed.
- **Shamir custody is qrdb's.** go-xkms neither holds nor distributes shares;
  see [`../share-custody/`](../share-custody/architecture.md) for the client
  surface.
- **Recovery keys are a second door.** `barrier recovery generate` produces
  keys that open the barrier without the primary credential; generating them
  and leaving them where the barrier is is equivalent to not having a barrier.
- **Per-tenant barriers isolate tenants from each other**, not from the
  operator.

## What this feature deliberately does not do

- **It does not own the barrier, the registry, Shamir custody, the ceremony,
  firstboot or bootstrap.** All go-qrdb's; go-xkms implements seams.
- **It does not choose a strategy for you.**
- **It does not implement `none` or `passphrase`** — those are go-quicraft's.
- **It is not a general secret store.** The platform store
  ([`../platform-secrets/`](../platform-secrets/architecture.md), unconverted at
  time of writing) is a narrow surface for platform-owned secrets.
