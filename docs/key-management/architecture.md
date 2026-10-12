# Key Management — Architecture

> **Status: NORMATIVE** · Feature: `key-management` · Repo: `go-xkms` · Last verified: 2026-10-12

## The problem

An application that needs a signing key should not care whether the private
material lives in a file, a TPM, a PKCS#11 token, or AWS KMS. Every one of
those stores has a different API, a different key-handle format, a different
notion of "export", and a different set of operations it can perform in
hardware. Written naively, each store leaks into the calling code and the
choice becomes permanent.

go-xkms's key-management feature is the single operation surface over all of
them: one `KeyService` + `CryptoService` contract, one key identifier scheme,
one algorithm vocabulary, and a backend registry that resolves a request to
the store that holds the key.

## Shape chosen: a composite over a backend registry

`pkg/xkms` holds the composite (`composite.go`, `composite_keys.go`,
`composite_crypto.go`, `composite_certs.go`, `composite_seal.go`,
`composite_keyid.go`). Each backend registers itself into the keystore
through a `register_*.go` file — `register_tpm2.go`, `register_pkcs11.go`,
`register_awskms.go`, `register_gcpkms.go`, `register_azurekv.go`,
`register_vault.go`, `register_software.go`, `register_pkcs8.go`,
`register_symmetric.go`, `register_quantum.go`, `register_frost.go`. A caller
names a backend (or takes the default) and the composite dispatches.

Rejected alternatives:

- **One Go interface per store, chosen at compile time.** Rejected because the
  backend set is a deployment decision, not a build decision: the same binary
  ships to a laptop with no TPM and to a node with a hardware token. Backends
  are instead selected by config and compiled in behind build tags
  (see [`../crypto-backends/engineering.md`](../crypto-backends/engineering.md#build-toggles)).
- **Passing raw `crypto.Signer` around.** Rejected because it cannot express
  the operations that only exist in hardware — attestation, wrap/unwrap under
  a KEK that never leaves the device, sealed export — and because it gives no
  place to hang key metadata, policy, or the tenant scope.
- **A thin proxy to a single external KMS.** Rejected: the product's premise is
  that the *same* surface covers hardware you own and cloud you rent.

## Component boundaries

| Piece | Package | Owner |
|---|---|---|
| Composite keystore, dispatch, key-ID scheme | `pkg/xkms` | go-xkms |
| Backend implementations | `pkg/backend/{awskms,gcpkms,azurekv,vault}`, `pkg/pkcs11`, `pkg/tpm2`, `pkg/quantum`, `pkg/keyprovider/*` | go-xkms |
| Wire surface | `pkg/api/{rest,grpc,mcp,unix}`, `pkg/api/transport/*` | go-xkms |
| Client contract | `sdk/go` (`transport.KeyService`, `transport.CryptoService`) | go-xkms |
| Persistence of key blobs and metadata | go-qrdb, reached through `go-qrdb/sdk/go` | **go-qrdb** |
| Object storage for large blobs | go-objstore | **go-objstore** |

This feature is the capability row **"Hardware / cloud KMS", tier 1**, in the
portfolio ownership register. Tier 1 means the surface must exist on all six
portfolio transports; see `api.md` for the per-transport matrix and the gaps
recorded there.

**Consumed SDK edge:** all durable storage goes through `go-qrdb/sdk/go`.
go-xkms never opens a database, never defines a KV layout of its own, and
never re-exports a qrdb data-plane type. If a store operation is missing from
qrdb's SDK, it is added there first.

## Data flow

A `sign` request over REST:

```
xkmsctl / SDK client
  → POST /api/v1/keys/{id}/sign            (pkg/api/rest, RBAC keys:sign)
    → tenant middleware resolves the tenant DAO scope
      → xkms.XKMSService composite
        → backend registry resolves {backend, keyID}
          → backend Signer  (TPM2 / PKCS#11 / cloud SDK / software)
            ← signature bytes
```

Nothing about the private key crosses the process boundary. For hardware and
cloud backends the private material never leaves the device or the provider;
for the software backend it is held under the barrier
(see [`../sealing-and-barrier/architecture.md`](../sealing-and-barrier/architecture.md)).

## Trust boundaries

- **Key material.** Export is refused unless the key was created `exportable`;
  `sensitive` keys are refused export unconditionally. `ExportKeyMaterial`
  returns raw bytes and is gated on `keys:export`.
- **Wrapping.** `WrapKey`/`UnwrapKey` take caller-supplied material;
  `WrapKeyByID`/`UnwrapKeyByID` never expose plaintext — the KEK and the
  target both stay server-side. Prefer the by-ID pair.
- **Tenancy.** Every `/api/v1` key route runs behind tenant middleware; a key
  ID is only resolvable inside the tenant that owns it. See
  [`../multi-tenancy/architecture.md`](../multi-tenancy/architecture.md).
- **Attestation.** `AttestKey` returns evidence that a key was generated inside
  a specific device. Its meaning is backend-specific and is documented per
  backend in [`../crypto-backends/engineering.md`](../crypto-backends/engineering.md).

## What this feature deliberately does not do

- **It is not a database.** No KV, MVCC, SQL, vector, time-series, index,
  collection, lock, lease, transaction, batch, watch or volume-pool surface is
  exposed here. Consumers needing those use `go-qrdb/sdk/go` directly.
- **It does not compose deployments.** Deciding which backend each crypto site
  in a product uses is go-quicbaas's job.
- **It does not own the barrier, the seal registry, Shamir custody, the
  ceremony, or the identity/RBAC model.** Those are go-qrdb's; go-xkms
  implements their seams.
- **Key versioning is not implemented.** The RPCs are declared and unserved —
  see `api.md`.
