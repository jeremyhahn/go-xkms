# Sealing and Barrier — Architecture

> **Status: NORMATIVE** · Feature: `sealing-and-barrier` · Repo: `go-xkms` · Last verified: 2026-10-13

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
- **A second, xkms-built barrier beside the node's.** Removed: xkmsd once
  built its own `StorageBarrier` and registry over the store for the
  strategies the node could not take (pkcs11 and the cloud KMS strategies),
  and wrapped the node's registry in an xkms type. Every strategy is now a
  node seal, so there is one barrier and it is go-qrdb's, unwrapped.
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
| PKCS#11 strategy composition from a sealed PIN (shared by `xkmsd` and `xkey`, go-xkms#677) | `pkg/pkcs11strategy` | go-xkms |
| Pre-barrier secret store (the PKCS#11 PIN) | `pkg/preseal` | go-xkms |
| Node seal resolution and injection | `pkg/embeddednode` (`ResolveNodeSeal`, `NodeSealOptions`, `node_seal_*.go`) | go-xkms |
| Barrier type aliases, xkms-storage guard, CAS put | `pkg/seal/barrier_adapter.go`, `barrier_putifabsent.go` | go-xkms |
| Hardware encryptor | `pkg/seal/hardware_encryptor.go` | go-xkms |
| Platform secret store | `pkg/seal/platform_store.go`, `platform_sealer.go`, `platform_store_tenant.go` | go-xkms |
| Secret sealer | `pkg/seal/secret_sealer.go` | go-xkms |
| TPM policies (named, TPM-authorized) | `pkg/tpm2/policy` — see [`../tpm-policies/`](../tpm-policies/) | go-xkms |
| Autodetection | `pkg/seal/autodetect.go` | go-xkms |
| Seal audit | `pkg/seal/audit.go` | go-xkms |
| Sealed blob store | `pkg/sealblobstore` | go-xkms |
| go-enclave `KeyProtector` / `RootUnsealer` over `types.Sealer` | `pkg/enclaveprovider` | go-xkms (the seam is go-enclave's) |

Capability row: **"Hardware / cloud `SealingStrategy` impls (TPM2, PKCS#11,
AWS-KMS, GCP-KMS, Azure-KV, Vault)" (tier 2)** — composer-only, registered into
qrdb's `StrategyRegistry`.

**The registry is go-qrdb's.** Any text describing "the xkms `StrategyRegistry`"
describes something that does not exist.

## Data flow

```
initialize:
  xkmsd init --barrier-strategy tpm2
    → qrdb's barrier generates a root key
      → SealingStrategy.Seal(rootKey, credentials)   ← go-xkms's implementation
        → TPM: PCR-bound seal · PKCS#11: HSM-resident KEK · cloud: envelope
      → SealedRootKey persisted by qrdb

unseal:
  node unseal (go-qrdb's barrier surface)
    → SealingStrategy.Unseal(sealedRootKey, credentials)
      → hardware or provider releases the root key
    → barrier open; every other subsystem becomes usable

per-tenant:
  TenantService.CreateTenant (go-qrdb, through the node's Services().Tenant)
    → a per-tenant barrier in the node's BarrierRegistry
    → sealed by any strategy in the injected StrategyRegistry
```

### One barrier: the node's

An embedded xkmsd (`datastore.mode: standalone`, `barrier.enabled: true`)
has exactly one barrier: the embedded go-qrdb node's own, which encrypts the
node's whole data plane at rest. go-xkms never builds or wraps a barrier; it
only chooses the strategy and hands it to the node.

```
embeddednode.ResolveNodeSeal(cfg)          builds the configured strategy:
                                           tpm2 · pkcs11 · awskms · gcpkms · azurekv · vault
embeddednode.NodeSealOptions(resolved)
  → node.WithSealStrategy(strategy)        the node barrier seals its root key with it
  → node.WithTenantIsolation()
  → node.WithDefaultTenantEntitlements(…)  every isolation mode, system-managed auto-unseal
  → sdk.WithStrategyRegistry(registry)     per-tenant barriers resolve the same strategy by ID
node.NewStandaloneNode(…)                  a hardware or cloud strategy auto-unseals here
xkmsd adopts:
  node.BarrierRegistry()                   s.barrierRegistry (go-qrdb's type, unwrapped)
  node.BarrierRegistry().SystemBarrier()   s.barrier
  node.Services().Tenant                   the tenant service
```

`passphrase` and `shamir` leave the node sealed, and xkmsd waits behind the
sealed-window listener for an operator unseal. With `datastore.mode: remote`
the barrier belongs to the remote go-qrdb, and this process has none.

The cloud node seals keep their KMS key metadata in
`<datastore.path>/node-seal/<strategy>`, outside the barrier, because the
metadata names the key that opens it. Each is compiled in only under its
provider's build tag; a binary without the tag refuses the strategy at boot.

`barrier_putifabsent.go` is the compare-and-swap path: initializing a barrier
twice concurrently must not produce two root keys.

### Pre-barrier secrets (go-xkms#677)

A `pkcs11` barrier needs the token user PIN, and a `vault` barrier its
Transit token, before the barrier, or anything stored behind it, is open.
These secrets live in the pre-barrier secret store
(`pkg/preseal`). The store is a platform store (`seal.PlatformStore`) over
a go-qrdb file engine in `<datastore>/preseal`, beside the barriered
datastore and never inside it. Every record is sealed by
`seal.PlatformPolicySealer` under the Platform SRK and the built-in platform
PCR policy. The TPM releases a secret only on the machine that sealed it, and
only while the platform PCRs match. No operator is involved, so a `pkcs11` or
`vault` node boots unattended exactly as a `tpm2` node does.

```
seal (once):   xkmsd seal-pkcs11-pin --config xkmsd.yaml < pin
                 → preseal.Store.Put("platform/pkcs11-pin") → TPM seal under PSRK + platform policy
boot:          embeddednode.ResolveNodeSeal (barrier.strategy: pkcs11)
                 → preseal.Store.Get → pkcs11strategy.BuildWithSealedPIN
                   → C_Login with the released PIN; the released copy is wiped
                 → the PKCS#11 SealingStrategy seals the qrdb node

seal (once):   xkmsd seal-vault-token --config xkmsd.yaml < token
boot:          embeddednode.ResolveNodeSeal (barrier.strategy: vault)
                 → preseal.Store.Get("platform/vault-token") → the Vault backend's token
                 → the Transit SealingStrategy seals the qrdb node
```

xkey's `barrier init --strategy pkcs11` seals into its own store
(`<data-dir>/preseal`), and its unseal takes the same
`BuildWithSealedPIN` path through `sdk/go`.

Rejected alternatives:

- **The secret in configuration or a flag.** Rejected: a config file is
  readable by whoever reads the config, and argv is readable by everyone on
  the host.
- **The secret behind a `credential://` reference.** Rejected: that reference
  resolves through the credential service, which needs the open barrier.
  Using it would be a cycle.
- **A second sealed store.** Rejected: `pkg/preseal` composes the existing
  platform store and platform-policy sealer instead of adding a new format.

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
  holders and the quorum are go-qrdb's holder/quorum model.
- **Per-tenant barriers isolate tenants from each other**, not from the
  operator.

## Telling an attack from an outage

A failed unseal has two very different causes. Either the sealed data is
wrong — forged, tampered with, cut short, produced under another key or
backend, or sealed under other AAD — and retrying is pointless, or the
environment is — the device or KMS is unreachable, throttling, refusing the
credential, or (TPM) the platform's PCRs moved — and the same data may unseal
later. Each backend reports its native signal differently (an AES-GCM open
failure, `InvalidCiphertextException`, `TPM_RC_INTEGRITY`,
`CKR_ENCRYPTED_DATA_INVALID`, Transit's message text), so the distinction is
made where that signal is understood: inside each `types.Sealer`, which joins
`types.ErrSealedDataAuthentication` onto exactly the native errors that blame
the data. Wrappers (the platform sealer, the composite key store, the TPM
backend) pass the classification through and add only the mismatches they
detect themselves. The per-backend mapping is the table in
[`engineering.md`](engineering.md) §"Sealed-data authentication".

Rules that shape it:

- **Allow-list, not deny-list.** Only native errors that name the input are
  authentication. Anything unrecognised stays unclassified -- it may be the
  environment or, where the native signal is ambiguous, bad data -- so a new
  outage mode can never page as an attack.
- **Scope matters on a TPM.** `TPM2_Load`'s only parameters are the sealed
  object's two areas, so a parameter-scoped response code from it blames the
  data; the same code from `TPM2_PolicyPCR` is a policy failure. Only the
  load is classified.
- **An ambiguous code is never promoted.** PKCS#11 reserves
  `CKR_GENERAL_ERROR` for an unrecoverable token error; SoftHSM before 2.7.0
  also returns it for an AES-GCM tag mismatch, and nothing in the failed
  operation tells the two apart. The PKCS#11 backend therefore classifies
  only the codes that name the ciphertext (`CKR_ENCRYPTED_DATA_INVALID`,
  `_LEN_RANGE`, `CKR_AEAD_DECRYPT_FAILED`): on those SoftHSM versions a
  tampered ciphertext fails with the token's own code and without the
  sentinel, and SoftHSM 2.7.0, which answers `CKR_ENCRYPTED_DATA_INVALID`, is
  classified. The sentinel's presence is conclusive; its absence is not. Repeating the decrypt or
  probing the token afterwards was considered and rejected -- a later
  success does not prove why the original operation failed. Likewise a Cloud
  KMS `InvalidArgument` that reports a request CRC32C mismatch is corruption
  in transit, not a bad ciphertext.
- **AAD must actually be bound before a mismatch can be reported.** Vault
  Transit ignored the parameter AAD was sent in, and the TPM sealed object has
  no AAD input; both now bind it (see the engineering contract).

Rejected: classifying in the transports (they see flattened errors, and the
SDK/embedded callers need it in-process); matching error strings generically
(only Vault, which has no codes, is matched on text, and only its
documented decrypt messages); treating every unseal failure as one error
(the distinction is the point).

## The go-enclave provider bridge (go-xkms#1415)

go-enclave keeps secrets in locked memory and seals values at rest under a
`Sealer` whose keys sit behind a provider seam: a `KeyProtector`, called on
every seal and open (`ModePerOperation`), or a `RootUnsealer`, asked once for
a root key that an in-memory KEK hierarchy then runs under (`ModeRootKey`).
go-enclave ships only a software provider and leaves the hardware bridge to
the library that owns the hardware. That is go-xkms, and it already has one
abstraction over every backend that can seal: `types.Sealer`.

`pkg/enclaveprovider` implements both seams once, over any `types.Sealer`,
rather than once per backend:

```
ModePerOperation:  enclave.Sealer → KeyProtector.Protect(DEK)
                     → types.Sealer.Seal(DEK, AAD = protected-key)  ← TPM / HSM / KMS
                     → envelope(sealed data) ‖ HMAC tag keyed from the DEK
ModeRootKey:       ProvisionRoot → root drawn into locked pages → types.Sealer.Seal(root, AAD = sealed-root)
                   at start: RootUnsealer.UnsealRoot(dst) → types.Sealer.Unseal → dst (locked)
```

The envelope makes every blob self-describing and versioned, and its tag,
keyed from the protected key, makes every byte authentic even where a backend
ignores a field on unseal. A blob the provider did not write fails as
`enclave.ErrSealedAuthentication`; an outage keeps the backend's own error,
so go-enclave's open reports `ErrOpenFailed` for it, never tampering.

The modes are not equals, and the choice is the caller's: per-operation keeps
the sealing key in the device and calls it for every value; root-key calls it
once, after which the root is in this process's locked memory. A TPM that
cannot sustain a session per value suits root-key; an HSM or KMS that can,
per-operation.

Rejected alternatives:

- **One provider per backend.** Rejected: `types.Sealer` already absorbs the
  backend differences, including the authentication-versus-outage
  classification, so a per-backend provider would repeat it six times.
- **Serialising `types.SealedData` as JSON.** Rejected: JSON matches field
  names case-insensitively and ignores unknown ones, so a flipped bit can leave
  a blob that still opens. The binary envelope is strict and fully tagged.
- **Relying on the backend to authenticate the whole blob.** Rejected: the
  backends authenticate their ciphertext, not the metadata beside it.
- **A provider in go-enclave or in a consumer.** Rejected by ownership:
  hardware crypto is go-xkms's, and go-enclave's owner placed the bridge here.

## What this feature deliberately does not do

- **It does not own the barrier, the registry, Shamir custody, the ceremony,
  firstboot or bootstrap.** All go-qrdb's; go-xkms implements seams.
- **It does not choose a strategy for you.**
- **It does not implement `none` or `passphrase`** — those are go-quicraft's.
- **It is not a general secret store.** The platform store
  ([`../platform-secrets/`](../platform-secrets/architecture.md), unconverted at
  time of writing) is a narrow surface for platform-owned secrets.
