# Cluster CA Key Custody Architecture

> **Status: REFERENCE** · Last verified: 2026-10-12
> Design companion to the clustering feature folder; [architecture.md](architecture.md) is normative.

How the cluster's certificate-authority signing key is protected and made
available so that **any node can issue** node certificates, across software,
HSM, and TPM-rooted deployments — through one pluggable strategy consumed
identically by every product in the stack.

This is the internal design companion to the operator-facing
[Clustering user guide](user.md); see that document for configuration.

## Problem

ACME-attested cluster enrollment (see [Clustering user guide → ACME-attested
cluster enrollment](user.md#acme-attested-cluster-enrollment)) and local-CA
mode (any key backend, software included) make the runtime TrustedCA the single cluster trust anchor and issue each
Raft node's transport certificate from a dedicated cluster intermediate. The
same TrustedCA is go-qrdb's Key A through `clusterca.KeyProvider`, so every
signature goes through the keystore's `crypto.Signer` and no CA key bytes leave
the keystore (go-xkms#1381). That raises a custody
question: **where does the cluster intermediate's signing key live, and which
nodes can use it to issue?**

Two hard constraints shape the answer:

1. **Bootstrap ordering.** The first node needs a CA signing key *before* the
   replicated datastore exists (a simultaneous multi-node bootstrap requires
   Raft mTLS at node construction). So the key is first created node-local.
2. **High availability.** For the cluster to keep enrolling nodes when any
   single node is down, more than one node must be able to issue — the key
   cannot stay pinned to the first node.

Grounding fact: the qrdb barrier is per-node local-storage encryption, **not**
a cluster-shared secret. The replicated key storage a strategy receives is
qrdb-routed and barrier-encrypted on each node
(`pkg/trust/clusterca/keystrategy.go:79-81`).

## The seam: `ClusterCAKeyStrategy`

Every custody model reduces to one question — *"resolve the cluster CA keystore
backend for this node"* — which fits xkms's existing multi-backend abstraction
(the CA consumes a `KeyStore` backend). The strategy is a factory for that
backend, plus a provisioning step and an issuance-locality signal.

```go
type ClusterCAKeyStrategy interface {
    Name() KeyStrategyName
    // Pre-datastore: the resolver the provisioner uses to pre-stage the CA and
    // issue this node's transport leaf.
    BootstrapBackends(ctx, *StrategyDeps) (func(name string) (xkms.Backend, error), error)
    // Post-datastore: this node's durable CA keystore. On the first node it
    // promotes the bootstrap key into the durable store as needed.
    RuntimeBackend(ctx, *StrategyDeps) (xkms.Backend, error)
}
```

`ClusterCAKeyStrategy` is declared at `pkg/trust/clusterca/keystrategy.go:119`.
`StrategyDeps` (`keystrategy.go:63`) is the product-agnostic dependency bundle a
composition root supplies: the node-local data dir, the CA hierarchy config, the
`KeyProtection` mode, the replicated (qrdb-routed) key and cert storage, the
shared HSM backend, the TPM sealer and credential activator, and a
`Bootstrapping` flag. Selection is a one-line config choice,
`cluster.raft_enrollment.ca_key_strategy` (`pkg/config/config.go:934`); empty
selects `barrier`, and an unknown name fails with `ErrUnknownKeyStrategy`
(`keystrategy.go:142-153`).

## The three strategies

### `barrier` (default — software HA)

```
first node:  generate key node-local (KeyProtection: shared passphrase)
             │  pre-stage CA, issue own leaf
             ▼
   datastore up ──► RuntimeBackend PROMOTES: Scan node-local keys → Put into
                    the qrdb-routed replicated store (barrier-encrypted per node)
             ▼
every node:  loads the key from the replicated store (its own barrier decrypts)
             ──► any node issues
```

The promoted key blob is passphrase-wrapped (a shared cluster CA passphrase lets
every node decrypt it) and the qrdb barrier additionally encrypts each node's
local copy at rest — defense in depth. This is the natural realization of "a
node-local key encrypts a cluster-wide replicated key," using qrdb's own barrier
rather than a parallel scheme.

### `hsm` (shared PKCS#11 — FIPS)

The CA key is generated inside a shared HSM under a fixed label; every node
references the same HSM and signs by calling it. **Key material never leaves the
HSM**, and there is no promotion (the HSM is the durable, shared store both
before and after the datastore). This is the primary path for a FIPS-validated
deployment. `BootstrapBackends` and `RuntimeBackend` both resolve to the shared
HSM backend supplied in `StrategyDeps.HSMBackend`.

### `tpm-kek` (TPM-sealed cluster seed — hardware-rooted, no shared HSM)

The replicated CA key is wrapped under a KEK derived from a **cluster seed**:

```
KEK = HKDF-SHA256(seed, salt="go-xkms/cluster-ca", info="kek/v1", 32 bytes)
CA key blobs in the replicated store are wrapped under KEK
```

(`pkg/trust/clusterca/keystrategy_tpmkek.go:100`)

- The **bootstrap node** generates the seed, seals it to its **local TPM**, and
  wraps the CA key under `KEK(seed)`.
- Each **joining node** receives the seed via **TPM credential activation**
  during attested enrollment — `MakeCredentialWithExternalEK` wraps it to the
  joiner's EK + attestation-key name, and only the genuine target TPM can
  `ActivateCredential` it. The joiner then seals the seed to its own TPM.

Every node derives the same KEK from the seed and can therefore load the
KEK-wrapped CA key from the replicated store. Hardware-rooted, without requiring
a shared HSM. Because the seed never sits in the datastore in the clear, the CA
key gains a protection layer independent of the general barrier.

> A cluster-shared KEK cannot be derived from the qrdb barrier (it is per-node),
> which is why `tpm-kek` distributes a dedicated seed.

## Decoupled enrollment-secret delivery

`tpm-kek` needs to get the seed to joiners, but the enrollment protocol must not
learn what a "seed" is. The design applies dependency inversion:

```
       enroll-01 (generic)                     custody strategy
  ┌───────────────────────────┐        ┌──────────────────────────────┐
  │ OrderPreSignHooks (SANs)   │        │ tpm-kek: NodeSecretProvider   │
  │ SecretDeliveryService      │◄──────►│  ProvisionFor(EK,AK) → wrap   │
  │  (provider orchestration)  │  bridge│ EnrollmentSecretStrategy      │
  └───────────────────────────┘  (opt.  │  ConsumeEnrollmentSecret(...) │
                                  iface) └──────────────────────────────┘
```

- **`NodeSecretProvider`** — a neutral producer: given an enrolling node's EK
  certificate + attestation-key public area, return wrapped material
  (`ProvisionedSecret{OID, Data}`), or nil.
- **`EnrollmentSecretStrategy`** — an *optional* interface a key strategy
  implements when it must deliver material (`SecretProvider()` +
  `ConsumeEnrollmentSecret()`). Discovered by type assertion
  (`EnrollmentSecretStrategyOf`), so `barrier`/`hsm` are entirely unaffected —
  the enrollment/delivery layer never references them (open/closed).
- **`SecretDeliveryService`** — orchestrates the registered providers and serves
  a **post-enrollment authenticated fetch** (`POST /api/v1/cluster/secret`),
  mirroring the platform's device-config-fetch pattern. The requesting node is
  authorized by its cluster-CA-signed certificate (verified at the application
  layer against the CA pool); the delivered material is *additionally* wrapped to
  the node's TPM, so confidentiality holds independent of transport.

### Delivery flow (tpm-kek joiner)

```
joiner enrolls (enroll-01) ──► receives cluster-CA-signed node cert
   │
   ├─ reads EK cert + AK public from its TPM
   ├─ POST /api/v1/cluster/secret  { node cert, EK cert, IAK pub }
   │        └─ existing node: verify node cert → run providers → MakeCredential(seed → EK) → return
   ├─ ActivateCredential(blob) → recover seed → seal to local TPM
   └─ RuntimeBackend derives KEK(seed) → loads the KEK-wrapped CA key → can issue
```

## Composition-root wiring (per product)

Each product supplies the same three things and gets identical behavior:

1. **`StrategyDeps`** — including the single shared TPM (from the seal strategy)
   as both `TPMSealer` and `Credentials`, and `Bootstrapping = (no joiner
   directory URL)`.
2. **Delivery mount** — build `SecretDeliveryService` from
   `EnrollmentSecretStrategyOf(strategy).SecretProvider()` + the CA pool, and
   mount its handler on the node's server (xkmsd mounts it on the ACME mux at
   `SecretDeliveryPath`, `cmd/xkmsd/acme.go:394-397`).
3. **Joiner fetch** — after enrollment, read the TPM EK/AK material, fetch, and
   `ConsumeEnrollmentSecret` before the runtime CA is built.

All of this is re-exported through `sdk/go/clusterca`, so downstream products
consume one mechanism rather than reimplementing it.

## Fail-closed & compliance posture

- Selecting a strategy whose prerequisites are absent (e.g. `hsm` with no HSM
  backend, `tpm-kek` with no TPM) **fails closed** with a typed error rather than
  silently downgrading.
- `barrier` (software HA) and `hsm` (FIPS-validated module) are the paths to lead
  with for FedRAMP/PCI/HIPAA certification. `tpm-kek` is hardware-rooted and
  fully implemented, but its credential-activation delivery protocol is a novel
  construction that warrants a security review and a documented threat model
  before it is certified as a production control.

## Source map

| Concern | Location |
| --- | --- |
| Strategy seam + factory | `pkg/trust/clusterca/keystrategy.go` |
| `barrier` / `hsm` / `tpm-kek` | `keystrategy_barrier.go` / `keystrategy_hsm.go` / `keystrategy_tpmkek.go` |
| Enrollment-secret seam | `enrollment_secret.go` |
| Delivery service + client | `secret_delivery.go` |
| Pre-node node-local backends | `backends.go` |
| SDK re-exports | `sdk/go/clusterca/clusterca.go` |
| xkms wiring | `pkg/server/cluster_ca_strategy.go`, `qrdb_node_cluster_acme.go`, `cmd/xkmsd/acme.go` |
