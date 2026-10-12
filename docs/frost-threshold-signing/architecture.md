# FROST Threshold Signing — Architecture

> **Status: NORMATIVE** · Feature: `frost-threshold-signing` · Repo: `go-xkms` · Last verified: 2026-10-12 (#1433)

## The problem

Shamir-style share custody (`docs/share-custody/`) reconstructs the private
key at signing time, even if only in an enclave: every signature has one
moment where the whole key exists. FROST (RFC 9591, "Flexible Round-Optimized
Schnorr Threshold Signatures") removes that moment. M-of-N participants each
hold a scalar share and run a two-round protocol that produces a valid
Schnorr signature the group public key verifies — the full private key is
never assembled anywhere, at generation or at signing time.

## Build tag: everything here requires `-tags frost`

Every source file under `pkg/keyprovider/frost`, `cmd/xkmsctl/frost.go`, and
the FROST-specific REST/gRPC/MCP handler files carries `//go:build frost`
(`pkg/keyprovider/frost/doc.go:14`, `cmd/xkmsctl/frost.go:14`). A default
build (`go build ./...` or `make build` without the tag) compiles a stub
instead:

- `cmd/xkmsctl/frost_stub.go` (`//go:build !frost`) registers an `xkmsctl
  frost` command whose `Run` prints "FROST support not compiled in" and
  exits 1.
- `pkg/api/rest/handlers_frost_stub.go`, the gRPC `service_frost_stub.go`,
  and the MCP `handlers_frost_stub.go` (all `//go:build !frost`) keep every
  route/RPC/method registered, but every handler returns a fixed "FROST
  support not compiled" error — REST answers `501 Not Implemented`.

`go build -tags frost ./...` compiles the real implementation everywhere.

## Two independent surfaces, not one

The CLI and the network API are **not the same code path**.

```
xkmsctl frost <verb>                      REST /frost/*, gRPC Frost*, MCP frost.*
        |                                          |
        v                                          v
client.NewFrostBackend(...)               XKMSService.Frost* (pkg/xkms/servicer_frost.go)
(sdk/go/frost.go type aliases over        resolves the caller's tenant from the
 pkg/keyprovider/frost, embedded          identity on ctx, then the registered
 in the xkmsctl process)                  *frost.FrostBackend
        |                                          |
        v                                          v
<key-dir>/frost/{public,secrets}          xkmsd's "frost" backend, registered by
(local files, untenanted)                 pkg/server/backend_frost.go when
                                          backends.frost.enabled is set
```

### The CLI path is local-only, every subcommand

`xkmsctl frost keygen|import|list|info|delete|round1|round2|aggregate|verify`
all open a fresh `frost.FrostBackend` in the `xkmsctl` process itself, over
two owner-only (`0700`) directories under `--key-dir`:

- `<key-dir>/frost/public` — group public key, verification shares,
  metadata, and each key's secret share **sealed** (AES-256-GCM under a key
  HKDF-derived from the wrapping key).
- `<key-dir>/frost/secrets` — the Ed25519 wrapping key and the ECDSA P-256
  recipient key that dealer packages are encrypted to, both stored as
  encrypted PKCS#8 under the operator's FROST passphrase by a PKCS#8 backend
  that refuses plaintext keys (`newFrostWrapKeyProvider`,
  `cmd/xkmsctl/frost.go:1413`).

The share verbs (`keygen` in participant mode, `import`, `round1`, `round2`)
go through `openFrostLocalStore` (`frost.go:1364`), which resolves the
passphrase and decrypts the wrapping key with it. The public verbs go through
`openFrostPublicBackend` (`frost.go:1334`), which never provisions or
decrypts the wrapping key, so any unseal through it fails closed. The
passphrase is what protects the shares at rest: the sealed envelopes and the
wrapping key sit on the same disk, and before go-xkms#1324 the wrapping key
was plaintext PKCS#8 beside them.

xkmsctl builds no local TPM 2.0 or PKCS#11 key backend (`--backend` only
names a backend for the service API and `--pkcs11-module` configures mTLS
client authentication), so the passphrase-encrypted software key is the
only wrapping key the CLI can hold; any other `--backend` is refused. A
hardware-held wrapping key is available through `xkmsd`'s
`backends.frost.secret_backend` (see
[`engineering.md`](engineering.md) §"Provisioning").

None of these subcommands call the SDK's network transports;
`--server`/`--transport` has no effect on `xkmsctl frost`. The CLI names keys
by bare key ID, so every key it writes is an untenanted (platform) key — see
"Tenancy" below.

### The network API path goes through the service layer

REST (`pkg/api/rest/routes.go:174-182`), gRPC
(`pkg/api/grpc/service_frost.go`, nine RPCs) and MCP (nine `frost.*` methods,
`pkg/api/mcp/handlers_frost.go:575`) are thin adapters: each decodes its wire
format, authorizes, and calls the matching `XKMSService` method
(`FrostGenerateKey`, `FrostImportKey`, `FrostListKeys`, `FrostGetKey`,
`FrostDeleteKey`, `FrostGenerateNonces`, `FrostSignRound`, `FrostAggregate`,
`FrostVerify` — `pkg/xkms/servicer_frost.go:253-620`). The service resolves
the registered `*frost.FrostBackend` (`frostBackend`,
`pkg/xkms/servicer_frost.go:173`) and fails with `ErrFrostNotConfigured`
(`servicer_frost.go:47`) when none is registered. `xkmsd` registers one only
when `backends.frost.enabled` is set (`pkg/server/backend_frost.go:41-45`,
called from `pkg/server/server.go:1122`).

## Tenancy (go-xkms#1231)

A FROST key belongs to the tenant of the identity that generated or imported
it. The service takes that tenant from the authenticated identity on the
context (`frostTenant`, `pkg/xkms/servicer_frost.go:193`, over
`scopedTenantIDFromContext`, `pkg/xkms/servicer_password.go:93`, and
`tenantScopes`, `pkg/xkms/servicer_helpers.go:65`) — never from the request —
exactly as the key lifecycle RPCs do (go-xkms#1218).

- **Namespaced storage.** A key is stored under its *storage key ID*: the key
  ID alone for a platform key, `{tenantID}:{keyID}` for a tenant's key
  (`frost.StorageKeyID`, `pkg/keyprovider/frost/tenant.go:46`). Neither half
  may contain `:`, `/` or `..` (`validation.ValidateKeyID`,
  `storage.ValidateTenantID`), so two tenants' keys can never collide, and a
  key ID is unique only within its tenant. The tenant is also stamped in the
  key's metadata (`KeyMetadata.TenantID`,
  `pkg/keyprovider/frost/storage.go:65`) and reported by `ListKeys`
  (`pkg/keyprovider/frost/backend.go:300`), so the generic tenant-scoped
  backend view (`TenantScopedBackend.ListKeys`) sees a tenant's FROST keys
  too.
- **Every key-naming operation resolves inside the caller's tenant.** Get,
  delete, Round 1, Round 2, aggregate and verify all address the caller's own
  namespace (`frostKeyAttrs`, `pkg/xkms/servicer_frost.go:207`). Another
  tenant's key is not there: the answer is the bare `ErrKeyNotFound`
  (`frostKeyError`, `servicer_frost.go:231`) — byte for byte the answer a key
  no tenant holds gets, on every transport.
- **Import writes only into the caller's tenant.** `FrostImportKey` stamps the
  caller's tenant (`FrostBackend.ImportKeyPackage`,
  `pkg/keyprovider/frost/backend.go:464`), so importing a package under
  another tenant's key ID creates the caller's own key rather than replacing
  the other tenant's share.
- **Listing is the caller's tenant only.** A platform-scoped caller — no
  identity, or the system tenant — lists every tenant's FROST keys, as
  `ListKeys` lets it list every key, and addresses by ID only platform
  (untenanted) keys: a bare key ID names the platform namespace.
- **No migration.** A key written before this change has no tenant in its
  metadata and sits at its bare key ID, so it is a platform key: invisible to
  every tenant and reachable only by a platform-scoped caller.

Rejected alternative: stamping the tenant in metadata while keeping the bare
key ID as the storage path. A second tenant creating a key ID the first
already uses would then be refused with "already exists", an existence
oracle across tenants, and every lookup would need a metadata read to decide
ownership. Namespacing the path makes the lookup O(1) and the refusal
indistinguishable from a miss.

## Package layout

| Package | Role |
|---|---|
| `pkg/keyprovider/frost` | The `FrostBackend` (`types.KeyProvider`), trusted-dealer key generation, the explicit round API, nonce-reuse tracking, ciphersuite math |
| `pkg/xkms/register_frost.go` | Registers `types.BackendType("frost")` with the generic backend-factory registry (`xkms.AutoInitialize`/library embedding only — not `xkmsd`) |
| `sdk/go/frost.go` | Type aliases (`FrostBackend`, `FrostConfig`, …) and constructors re-exported for `xkmsctl` and other SDK consumers — no network client |
| `cmd/xkmsctl/frost.go` | The `xkmsctl frost` command tree, entirely local |
| `pkg/xkms/servicer_frost.go` | The FROST service layer: tenant resolution, validation, error translation |
| `pkg/api/rest/handlers_frost.go`, `pkg/api/grpc/service_frost.go`, `pkg/api/mcp/handlers_frost.go` | Thin transport adapters over the `XKMSService` FROST methods |

## Key storage split: public vs. secret

`frost.Config` (`pkg/keyprovider/frost/config.go:24`) takes two storage
handles, matching the pattern used by `pkg/share-custody` and the sealing
strategies:

- `PublicStorage storage.Backend` — group public key, verification shares,
  per-key metadata, and (go-xkms#841) the *sealed* secret-share envelope
  (`types.SealedData`, JSON). Sealing is what makes storing the last one
  here safe; the payload is opaque ciphertext, not the share in the clear.
- `SecretBackend types.SealingKeyProvider` — seals and unseals this
  participant's secret share with its own native mechanism: TPM 2.0
  PCR-bound sealing under the Platform SRK, PKCS#11/cloud KMS AES-256-GCM
  envelope encryption under a provisioned wrapping key, or software/PKCS#8
  HKDF-derived AES-GCM from a provisioned Ed25519 key. `xkmsctl` seals
  through a local `software` backend; the daemon factory
  (`pkg/xkms/register_frost.go`) seals through a local `pkcs8` backend. See
  [`engineering.md`](engineering.md)'s "Secret share sealing" section for
  the full per-backend wrapping-key contract.

## Key generation: trusted dealer only

`Config.DKG KeyGenerator` (`config.go:56`) is an extension point for a real
distributed-key-generation protocol where no single party ever sees the
whole key; if left nil, `Config.GetKeyGenerator()` falls back to
`NewTrustedDealer()` (`config.go:175-180`). **Only the trusted-dealer
generator ships today.** A custom `KeyGenerator` is something an embedder
must write and wire in themselves; its contract is in
[`engineering.md`](engineering.md) §"Key generation contract".

The dealer's packages leave `xkmsctl` encrypted, never as a plaintext share
(go-xkms#1337). Each participant first creates a recipient key with
`frost recipient` and gives the dealer its public half; dealer-mode `keygen`
encrypts each package to its participant's key as a JWE (`ECDH-ES+A256KW`,
`A256GCM`), and `import` decrypts it with the key held in the participant's
passphrase-protected store. The encryption reuses the SDK's JWE helper
rather than a new envelope format.

Recipient keys were chosen over per-participant passphrases:

- **Only the participant can decrypt.** The private key never leaves the
  participant's `--key-dir`. With a passphrase, the dealer chooses the
  secret and has to deliver it to the participant alongside the package.
- **No second secret.** `import` already needs the FROST passphrase to open
  the store, and that passphrase also unlocks the recipient key. A per-package
  passphrase would be a second secret competing for the same stdin, file and
  environment sources.
- **An existing, FIPS-approved helper.** `pkg/encoding/jwe` was already
  re-exported by the SDK. A passphrase envelope would have needed a new
  KDF-plus-AEAD format. An X25519 box, age-style, uses a curve FIPS 140-3
  does not approve.

What it costs: one extra step (`frost recipient`) before the dealer runs,
and the operator must confirm each public key's `recipient_id` out of band.

## Two signing modes

1. **Orchestrated** (`FrostBackend.Signer`) — returns a `crypto.Signer`.
   Works only for a key with one required signer; a key whose `MinSigners`
   is above 1 is refused with `*frost.ThresholdSigningNotSupportedError`
   (`pkg/keyprovider/frost/backend.go:358-359`), because a synchronous
   `Sign` call cannot coordinate a multi-party protocol.
2. **Explicit round API** — `GenerateNonces` → (exchange commitments
   out-of-band) → `SignRound` → (collect ≥ threshold shares) → `Aggregate` →
   `Verify`. This is what both `xkmsctl frost round1/round2/aggregate/verify`
   and the REST/gRPC/MCP handlers drive.

## Nonce-reuse prevention

FROST nonce reuse recovers the private key outright. `Config.NonceStorage`
(falls back to `PublicStorage`) and `EnableNonceTracking` (`true` in
`DefaultConfig`, `config.go:189`) make `SignRound` check every commitment
before it is used a second time (`rounds.go:198`); a repeat returns
`ErrNonceAlreadyUsed` (`pkg/keyprovider/frost/errors.go`). The package
documentation calls nonce reuse catastrophic and tells callers to keep
tracking on (`pkg/keyprovider/frost/doc.go:80-82`). Neither the CLI nor the
network handlers expose a flag to turn it off, and `xkmsd` always sets it
(`pkg/server/backend_frost.go`) — it is only reachable by constructing `frost.Config` directly.

## Sessions

`FrostBackend` keeps no server-side signing session between rounds
(go-xkms#1261). `GenerateNonces` returns a `NoncePackage` -- the participant's
secret Round-1 nonces plus its public commitments -- directly to the caller,
who holds it and passes it back to `SignRound` for Round 2; the caller is
responsible for completing the round promptly and zeroizing the nonces once
used (`SigningNonces.Zeroize`, `pkg/keyprovider/frost/nonce.go:162`). `EnableNonceTracking` (default `true`) still
rejects reuse of any commitment across signing attempts regardless of who
holds the nonces, which is what actually prevents the catastrophic case this
section used to describe as session expiry.

## Rejected alternative: reusing the Shamir share-custody plane

`docs/share-custody/` already has an M-of-N custodian/share model. FROST does
not build on it, because the two protocols solve different problems: Shamir
custody protects a key that is periodically *reconstructed*; FROST exists
specifically so the key is *never* reconstructed. Sharing the storage layer
would have coupled a "the key is whole, briefly" data model to a "the key is
never whole" one for no code reuse that mattered — `frost.Config` deliberately
takes its own `PublicStorage`/`SecretBackend` pair instead of a
`custodian.Group`.
