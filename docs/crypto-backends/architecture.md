# Crypto Backends — Architecture

> **Status: NORMATIVE** · Feature: `crypto-backends` · Repo: `go-xkms` · Last verified: 2026-09-24

## The problem

"Hardware and cloud crypto" is one capability row in the portfolio's ownership
register, but it is eleven very different stores underneath. A TPM cannot
export a key; AWS KMS cannot hold a key you generated locally unless you wrap it
first; Azure Key Vault supports import but deliberately not export; a PKCS#11
token has slots and PINs; a software backend has none of that and can do
everything. The feature exists so callers can express *what* they want and the
backend layer decides whether it is possible.

## Shape chosen: a common `Backend` interface plus a declared capability set

`pkg/xkms/keystore.go` defines `Backend` — the contract every store satisfies:

```go
type Backend interface {
	GenerateRSA(ctx, attrs) (crypto.PrivateKey, error)
	GenerateECDSA(ctx, attrs) (crypto.PrivateKey, error)
	GenerateEd25519(ctx, attrs) (crypto.PrivateKey, error)
	GetKey / DeleteKey / ListKeys / RotateKey
	Signer(ctx, attrs) (crypto.Signer, error)
	Decrypter(ctx, attrs) (crypto.Decrypter, error)
	SaveCert / GetCert / DeleteCert / SaveCertChain / GetCertChain / ListCerts / CertExists
	GetTLSCertificate(ctx, keyID, attrs) (tls.Certificate, error)
	GetKeyByID / GetSignerByID / GetDecrypterByID
	Seal(ctx, data, opts) (*types.SealedData, error)
	Unseal(ctx, sealed, opts) ([]byte, error)
	CanSeal() bool
	Type() types.StoreType
	KeyProvider() types.KeyProvider
	CertStorage() certstore.CertificateStorageAdapter
	SignerStore() store.SignerStorer
	Close() error
}
```

`SignerStore()` (go-xkms#724) returns the same kind of thing `CertStorage()`
does: a persistence seam every backend gets for free from `compositeBackend`,
not something each backend implementation writes. It backs
`SignOptions.BlobCN` (`pkg/xkms/service.go` `Sign`) and
`VerifyOpts.IntegrityCheck` (`Verify`) — see
[`signing/architecture.md`](../signing/architecture.md) for why a signature
record is persisted the same way a certificate is.

The interface is uniform; the *differences* are declared as data, not discovered
by trial. `types.Capabilities` (`pkg/types/types.go:1366`) is the declaration:

`Keys`, `HardwareBacked`, `Signing`, `Decryption`, `KeyRotation`,
`SymmetricEncryption`, `Sealing`, `Import`, `Export`, `KeyAgreement`, `ECIES`,
`Attestation`, `QuantumSigning`, `KeyEncapsulation`, `SecurityLevel`.

Callers ask before they act — `caps.SupportsImportExport()`,
`caps.SupportsKeyAgreement()`, `caps.IsHardwareBacked()` — and
`GET /api/v1/backends/{id}` serves the same struct so a UI can grey out what a
backend cannot do instead of offering it and failing.

Rejected alternatives:

- **A lowest-common-denominator interface** carrying only what every store can
  do. Rejected because it deletes the reason to buy hardware: attestation,
  PCR-bound sealing, non-exportable keys.
- **Backend-specific interfaces with type assertions at each call site.**
  Rejected because the assertion set becomes the real API and drifts silently.
- **Runtime probing** ("try it and see"). Rejected: probing a hardware token
  costs a session and can trip a lockout counter.

## Component boundaries

| Backend | Package | Build tag | Registered by |
|---|---|---|---|
| software (default) | `pkg/backend/software` | none — always built | `pkg/xkms/register_software.go` |
| symmetric | `pkg/keyprovider/symmetric` | none | `register_symmetric.go` |
| PKCS#8 | `pkg/keyprovider/pkcs8` | none (`pkcs8` tag selects the CLI/server profile) | `register_pkcs8.go` |
| quantum (ML-DSA / ML-KEM) | `pkg/keyprovider/quantum` | none | `register_quantum.go` |
| TPM 2.0 | `pkg/backend/tpm2`, `pkg/tpm2` | none | `register_tpm2.go` |
| PKCS#11 | `pkg/backend/pkcs11`, `pkg/pkcs11` | `pkcs11` | `register_pkcs11.go` |
| AWS KMS | `pkg/backend/awskms` | `awskms` | `register_awskms.go` |
| GCP KMS | `pkg/backend/gcpkms` | `gcpkms` | `register_gcpkms.go` |
| Azure Key Vault | `pkg/backend/azurekv` | `azurekv` | `register_azurekv.go` |
| HashiCorp Vault | `pkg/backend/vault` | `vault` | `register_vault.go` |
| FROST threshold | `pkg/keyprovider/frost` | `frost` | `register_frost.go` |
| phone (xkey-android as HSM) | `pkg/backend/phone` | — | `pkg/server/backend_phone.go` |
| AVR device (DICE identity) | `pkg/backend/avr` | — | not yet wired into `initializeBackends`; constructed by the caller around an open link |

Backend construction at server start is `server.go`'s `initializeBackends`,
which calls one `initXBackend` per backend in `pkg/server/backend_<backend>.go`
and registers the result under a fixed name; each tagged backend has a
`_stub.go` sibling so a build without the tag still compiles and reports the
backend as unavailable rather than failing to link. There is no other
registration path: a name-driven factory (`Initialize` over a list of
`BackendConfig`) once sat beside this one, uncalled, modelling backends with
operator-supplied names and a randomized default; it was removed because
readers reasoned from it.

This feature is the implementation half of capability row **"Hardware / cloud
KMS" (tier 1)**; the operation surface over it is
[`../key-management/`](../key-management/architecture.md). The
`SealingStrategy` and `PINBackend` implementations these backends provide are
tier-2 rows documented in
[`../sealing-and-barrier/`](../sealing-and-barrier/architecture.md) and
[`../pin-management/`](../pin-management/architecture.md).

## Model: backend name vs. store type

A key's attributes (`types.KeyAttributes`) carry two separate facts about
where it lives, and the two used to be conflated into one field
(go-xkms#312):

- **`Backend`** is the exact string a backend was registered under —
  `service.backends[name]`'s key — e.g. `token-a` for a second PKCS#11 token
  beside one named `token-b`. It is an operator-chosen identifier with no
  required relationship to what the backend *is*.
- **`StoreType`** is what KIND of backend that is — `StoreSoftware`,
  `StorePKCS11`, `StoreTPM2`, … — reported by the resolved backend's own
  `Type()` method, never guessed from its name. Two PKCS#11 tokens registered
  as `token-a` and `token-b` both report `StorePKCS11` here and are told
  apart only by `Backend`.

Before `Backend` existed, `BackendFor` and `getBackendForKID` resolved
`GetBackend(string(attrs.StoreType))` — using the store type AS the registry
key. That happened to work because every backend that existed had been
registered under a name that was also a store-type keyword; a backend
registered under any other name resolved to `backend not found: unknown`
everywhere its attributes were read back rather than passed by name
directly. `StoreType` is also a segment of `types.KeyAttributes.ID()`
(`storetype:keytype:cn:algorithm`), so the same conflation put the wrong
word in the storage identifier for such a backend's keys.

`BackendFor` and `getBackendForKID` resolve `attrs.Backend` only — there is
no `StoreType` fallback (removed 2026-09-22, pre-release alpha, no migration
kept). Every producer of `KeyAttributes` that has a name to give it sets
`Backend` directly: `ParseKeyIDToAttributes` sets it from a Key ID string's
backend segment, and the Simplified API's `ListKeys` stamps it from the
registry name it listed under (`stampBackendName`), since a backend's own
`ListKeys` has no way to learn that name itself. Attributes that carry no
`Backend` resolve to `DefaultBackend`, exactly like attributes with neither
field set. `ID()` is unaffected for every key that already exists, because a
backend registered under a store-type keyword reports that same keyword from
`Type()`; a backend registered under a non-keyword name stores keys under its
real kind instead of the `unknown` segment `ParseStoreType(backendName)` used
to produce.

## Data flow

Backends are resolved, not constructed, per request:

```
request names {backend, keyID}
  → composite keystore (pkg/xkms) looks the backend up in its registry
    → Backend.Signer(ctx, attrs)   — a crypto.Signer bound to device state
      → device / provider performs the operation
```

For hardware and cloud backends nothing but the operation crosses the boundary:
the private key never enters go-xkms's address space. For the software backend
the material is held under the barrier and decrypted only for the operation.

## Trust boundaries

- **The device is the trust root for `HardwareBacked` backends.** A key marked
  `FixedTPM` cannot be exported at all, regardless of what the request asks for.
- **Credentials never live in this repo.** Cloud backends read provider
  credentials from the server's environment; PKCS#11 and TPM2 take PINs through
  the PIN backends. Infrastructure deployment configs are never copied here.
- **`SecurityLevel` is advisory ordering, not enforcement** — 0 software,
  1 cloud, 2 PKCS#11, 3 TPM2. Use it to sort a picker, never to authorize.
- **Import ≠ export.** Azure Key Vault supports `Import` and deliberately not
  `Export`. Treat the pair as independent.

## What this feature deliberately does not do

- It does not choose a backend for you. Composition — which backend each crypto
  site in a product uses — is go-quicbaas's decision, one layer up.
- It does not store anything itself. Metadata and blobs go through
  `go-qrdb/sdk/go` and go-objstore.
- It does not add a database surface. go-xkms is not a database server product.
