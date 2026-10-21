# Trust Roots — Architecture

> **Status: NORMATIVE** · Feature: `trust-roots` · Repo: `go-xkms` · Last verified: 2026-10-15

## The problem

Every verifier in the stack needs anchors: the CA bundle, TCG EK manufacturer
roots, the Google hardware attestation root, IDevID issuers and image signers.
Before this feature each consumer found its own, and the only classified store
was xkey's, local to one desktop. A server had no persisted, operator-managed
place to keep them.

## Shape chosen: one purpose-classified store on a qrdb DAO

The store is xkey's truststore, moved with its history to
`pkg/attestation/truststore`, and persisted through go-qrdb's DAO layer
(`go-qrdb/sdk/go` only).

- **Purpose taxonomy** (`types.go:22-58`): `general`, `tpm-manufacturer`,
  `android-hardware`, `user-ca`, `bootstrap-ca`, `idevid-issuer`,
  `image-signer`, and `synced`, the quarantine.
- **Classification** (`ClassifyCertificate`, `classify.go:61`) files a
  certificate the caller did not classify. `android-hardware` is granted only to
  a certificate byte-identical to the embedded Google root (`config.go:30`),
  never on issuer names or extensions a minter controls.
- **Quarantine** is the `synced` purpose. A quarantined root stays listed but
  anchors nothing: `IsAnchorPurpose` is false for it, and `Anchors(synced)`
  returns `ErrNotAnchorPurpose` (`dao_store.go:192`).
- **Persistence** is `DAOStore` (`dao_store.go:40`) over the `trust_roots`
  database, entity type `trust_certs` (`dao_store.go:30`, `:33`). The entity ID
  is a hash of the fingerprint (`NewDAOStore`, `dao_store.go:47`).
- **Verbs**: list, get, import, quarantine and remove, served by
  `XKMSService` (`pkg/xkms/servicer_trust_roots.go`) on every transport. See
  [api.md](api.md).

Rejected alternatives:

- **Keep the store in xkey.** Rejected: servers, peergate and go-quicbaas need
  the same anchors, and root may not import xkey.
- **A file or KV store of xkms's own.** Rejected: go-qrdb is the one datastore;
  a second store is what the SPEC forbids.
- **An unclassified pool.** Rejected: an image signer must not anchor a TLS
  chain, and an EK root must not anchor an image. The purpose is the trust
  decision.

## Component boundaries

| Piece | Package | Owner |
|---|---|---|
| `TrustStore`, `CertPurpose`, `ClassifyCertificate`, import, `DAOStore` | `pkg/attestation/truststore` | go-xkms |
| Verbs | `pkg/xkms/servicer_trust_roots.go`, `pkg/api/*` | go-xkms |
| `trust_roots:*` permissions, scope and grants | `pkg/auth`, `pkg/apimodule` | go-xkms (declared into go-qrdb's registry) |
| DAO, database, pagination | `go-qrdb/sdk/go` (`DAOFactory`, `GenericDAO`) | **go-qrdb** |
| Composition | `pkg/compose` (`BuildTrustRootStore`, `builders.go:106`) | go-xkms |

## Data flow

```
transport (REST / gRPC / QUIC / Unix / MCP / embedded)
  → permission gate: trust_roots:<action>, ScopeCross
  → XKMSService.TrustRoot*  → qrdbsdk.IdentityIsSystemTenant
  → DAOStore → qrdbsdk GenericDAO → database "trust_roots"
```

`compose.Build` builds the store whenever a DAO factory exists
(`pkg/compose/compose.go:260-261`), lists its database in `Databases`
(`:167`) and wires it into the service (`:312-313`).

## Trust boundaries

- **The store is platform state.** Every verb refuses a tenant-scoped caller
  before it touches the store (`trustRootStore`,
  `pkg/xkms/servicer_trust_roots.go:38`), and the permissions are declared
  `ScopeCross` (`pkg/apimodule/module_scopes.go:142-149`). A tenant cannot see
  or change the platform's anchors.
- **Quarantine fails closed.** A root received from a peer (pairing, sync) is
  recorded as `synced` and anchors nothing until an operator classifies it.
- **An import never reclassifies.** A certificate already held is skipped and
  keeps its purpose, so re-importing a bundle cannot promote a quarantined
  root.

## Readers

SPEC names peergate, image verification, VM attestation and go-xkms
appraisal as readers of this store. They read it through `DAOStore.Anchors`
or `GetByPurpose`; each is wired by its own row's work and is not part of this
feature.

## What this feature deliberately does not do

- It does not verify chains. Verifiers take anchors from it.
- It does not install roots into the OS store. That stays in xkey.
- It does not hold tenant CA bundles. Those are the tenant CA's.
