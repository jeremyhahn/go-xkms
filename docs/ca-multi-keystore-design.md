# CA Per-Key Multi-Keystore Implementation Design

**Status**: Implemented — Phases 1-2 shipped (swtpm-proven). Phases 3-5 (consumer wiring) tracked separately.  
**Target repo**: go-xkms (`pkg/ca`, `sdk/go`). Consumer repos: go-quicbaas, go-trusted-platform.

> Phase 1 (core `pkg/ca` per-key routing) and Phase 2 (`sdk/go` re-exports) are
> implemented and verified end-to-end against swtpm. The `Identity.Keystores`
> model, `Params.BackendForStore` / `BackendForStoreFunc`, the per-instance
> `keystoreMap`, `resolveKeyBackend`, and `initSecondaryKeys` all ship as
> described below. See [`ca/multi-keystore.md`](./ca/multi-keystore.md) for the
> user-facing reference. The consumer-wiring phases (go-trusted-platform /
> go-quicbaas `BackendForStore` factories) remain follow-on work.

---

## Executive Summary

The CA config schema in go-trusted-platform (`configs/platform/templates/single-node/default.yaml`) already declares per-identity `keystores` (software, tpm2) and per-key `store:` routing. The go-xkms CA implementation ignores all of it: every identity uses one injected `xkms.Backend` and every key operation goes to `Keys[0]` only. This design makes the CA honor both fields — additive, backward-compatible — so TPM2-bound CA signing keys actually land in the TPM and software keys remain in PKCS8 storage.

---

## Investigation Findings

### Multi-Key Semantics

The go-trusted-platform YAML declares five keys per CA identity
(`configs/platform/templates/single-node/default.yaml:657–712`):

```
Keys[0]: RSA-2048,  store: software  ← PRIMARY (CA certificate is signed by this key)
Keys[1]: RSA-2048,  store: tpm2      ← TPM-backed RSA backup
Keys[2]: ECDSA-P256,store: software
Keys[3]: ECDSA-P256,store: tpm2
Keys[4]: Ed25519,   store: software
```

**Semantics confirmed**: The CA holds N signing keys, one per algorithm×backend
combination, all under the same CN. `Keys[0]` is the primary; its public key appears in
the CA certificate. The remaining keys are pre-generated in their respective backends so
they are immediately available for key rotation, TPM-backed failover, or algorithm-agile
signing (future work). Issuance today always signs with `Keys[0]`; algorithm-selection
(`opts.PreferredAlgorithm`) is a follow-on concern and is out of scope here.

### What the CA Currently Does

| Site | File:line | Behavior |
|---|---|---|
| `Params.KeyStore` | `pkg/ca/ca.go:112` | Single `xkms.Backend` — one backend for all keys |
| `Params.KeyStoreFactory` | `pkg/ca/ca.go:155–157` | Resolves one backend per CA CN, not per StoreType |
| `Identity.KeystoreType` | `pkg/ca/config.go:65` | Scalar — one store type per identity |
| `Identity.Keys` | `pkg/ca/config.go:61` | Slice present, but only `Keys[0]` is read |
| `ToKeyAttributes()` | `pkg/ca/config.go:442–446` | Returns attrs from `Keys[0]` only |
| `getCAKeyAttributes` | `pkg/ca/ca.go:890–903` | Calls `ToKeyAttributes()` → `Keys[0]` |
| `getOrGenerateCAKey` | `pkg/ca/ca.go:908–932` | Uses `ca.keyStore` unconditionally |
| `getSigner` | `pkg/ca/ca.go:873–884` | Uses `identity.ToKeyAttributes()` + `ca.keyStore` |
| `Load()` key verify | `pkg/ca/ca.go:615,637` | Calls `ca.keyStore.Signer(ctx, attrs)` for one key |
| `compositeBackend` | `pkg/xkms/keystore.go:238` | One `types.KeyProvider` — correct per-instance |
| `GenerateRSA/ECDSA/Ed25519` | `pkg/xkms/composite_keys.go:43,76,108` | Delegates to `c.backend.GenerateKey` — no StoreType routing needed here |
| `BackendFor` (global) | `pkg/xkms/service.go:514` | Routes `attrs.StoreType → GetBackend()` — CA never calls this |

The `compositeBackend` itself does NOT need changes: it correctly wraps a single
`types.KeyProvider`. The routing problem is entirely in `pkg/ca`, which needs to hold
multiple `compositeBackend` instances (one per StoreType) and dispatch per key.

---

## A. Data Model

### A1. New types in `pkg/ca/config.go`

Add after the existing `Identity` struct (after line 103). These types are
**additive and optional**; nil means the legacy single-keystore path applies.

```go
// CAKeystoreSoftwareConfig carries per-identity configuration for the
// software (PKCS#8) backend.
type CAKeystoreSoftwareConfig struct {
    // PlatformPolicy enables TPM platform policy binding for software keys
    // that are encrypted-at-rest under a TPM SRK.
    PlatformPolicy bool `yaml:"platform-policy" json:"platform_policy" mapstructure:"platform-policy"`
}

// CAKeystoreTPM2Config carries per-identity configuration for the tpm2 backend.
// Mirrors tpm2.PlatformSRKConfig (pkg/tpm2/config.go:157–162) but lives in
// pkg/ca so the CA package has zero dependency on pkg/tpm2.
type CAKeystoreTPM2Config struct {
    // SRKHandle is the persistent TPM handle for the SRK used to wrap CA keys.
    // E.g. 0x81000001.
    SRKHandle uint32 `yaml:"srk-handle" json:"srk_handle" mapstructure:"srk-handle"`
    // SRKAuth is a KMS URI resolving to the SRK password (e.g.
    // "kms://ca/root/tpm2/srk-auth?ensure=true&len=32&enc=base64").
    SRKAuth string `yaml:"srk-auth,omitempty" json:"srk_auth,omitempty" mapstructure:"srk-auth"`
    // PlatformPolicy enables PCR-bound platform policy on TPM CA keys.
    PlatformPolicy bool `yaml:"platform-policy" json:"platform_policy" mapstructure:"platform-policy"`
}

// CAKeystorePKCS11Config carries per-identity configuration for PKCS#11 backends.
type CAKeystorePKCS11Config struct {
    Pin    string `yaml:"pin,omitempty" json:"pin,omitempty" mapstructure:"pin"`
    Slot   int    `yaml:"slot,omitempty" json:"slot,omitempty" mapstructure:"slot"`
    Module string `yaml:"module,omitempty" json:"module,omitempty" mapstructure:"module"`
}

// CAKeystoresConfig holds per-backend keystore configuration for one CA identity.
// Each field corresponds to a well-known store type. nil fields are ignored.
// This maps to the "keystores:" block in the platform YAML config.
type CAKeystoresConfig struct {
    Software *CAKeystoreSoftwareConfig `yaml:"software,omitempty" json:"software,omitempty" mapstructure:"software"`
    TPM2     *CAKeystoreTPM2Config     `yaml:"tpm2,omitempty" json:"tpm2,omitempty" mapstructure:"tpm2"`
    PKCS11   *CAKeystorePKCS11Config   `yaml:"pkcs11,omitempty" json:"pkcs11,omitempty" mapstructure:"pkcs11"`
}
```

### A2. Identity struct diff (`pkg/ca/config.go:48–103`)

Add one new field to `Identity`. All existing fields remain unchanged.

```go
// Keystores holds per-backend configuration for this identity's keys.
// When nil, the legacy single-keystore path (KeystoreType) is used.
// When set, the CA builds a per-StoreType backend map and routes each
// key in Keys[*] to the backend matching its StoreType.
// NEW — optional, additive.
Keystores *CAKeystoresConfig `yaml:"keystores,omitempty" json:"keystores,omitempty" mapstructure:"keystores"`
```

**YAML round-trip**: The platform YAML already writes:
```yaml
keystores:
  software:
    platform-policy: true
  tpm2:
    srk-handle: 0x81000001
    srk-auth: "kms://ca/root/tpm2/srk-auth?ensure=true&len=32&enc=base64"
    platform-policy: true
```
`mapstructure` and standard YAML unmarshal will populate `CAKeystoresConfig.Software`
and `CAKeystoresConfig.TPM2` automatically since the struct field tags match.

**`types.KeyConfig.StoreType` is already correct** (`pkg/types/types.go:3019`). No
change needed; `Keys[i].StoreType` is the routing key.

### A3. Backward compatibility of the data model

Callers that omit `keystores:` in YAML (go-quicbaas single-keystore path,
`lifecycle.go:382`) will have `Identity.Keystores == nil`. The CA falls back to the
current single-backend path exactly as before. Zero behavior change.

---

## B. Backend Resolution

### B1. New factory function type in `pkg/ca/constructors.go`

Add alongside the existing `KeyStoreFactoryFunc` (line 63):

```go
// BackendForStoreFunc resolves an xkms.Backend for a given CA CN and
// StoreType. It is called once per unique StoreType found in an
// identity's Keys slice. nil return + nil error is not permitted; the
// function must return a usable Backend or an error.
//
// The CA caches the returned backends in a per-instance keystoreMap so
// BackendForStoreFunc is called at most once per (cn, storeType) pair.
type BackendForStoreFunc func(cn string, storeType types.StoreType) (xkms.Backend, error)
```

### B2. New field on `Params` (`pkg/ca/ca.go:97–165`)

Add one optional field:

```go
// BackendForStore resolves an xkms.Backend per (CA CN, StoreType). When
// set, New/NewParentCA/NewIntermediateCA call it for every unique
// StoreType in identity.Keys and build an internal keystoreMap. Keys are
// then routed to the matching backend at generation and signing time.
//
// Callers that do not set this field get zero behavior change: all keys
// continue to use the single Params.KeyStore backend.
// Optional.
BackendForStore BackendForStoreFunc
```

### B3. New field on `CA` struct (`pkg/ca/ca.go:195–248`)

```go
// keystoreMap holds one xkms.Backend per StoreType for this CA instance.
// Populated by New() when Params.BackendForStore is set; nil otherwise.
// Read-only after construction.
keystoreMap map[types.StoreType]xkms.Backend
```

### B4. `resolveKeyBackend` helper on `*CA`

New private method added to `pkg/ca/ca.go`:

```go
// resolveKeyBackend returns the appropriate xkms.Backend for a key with
// the given StoreType. If keystoreMap has an entry for storeType it is
// returned; otherwise the single fallback ca.keyStore is returned.
// Thread-safe: keystoreMap is read-only after construction.
func (ca *CA) resolveKeyBackend(storeType types.StoreType) xkms.Backend {
    if len(ca.keystoreMap) > 0 {
        if b, ok := ca.keystoreMap[storeType]; ok {
            return b
        }
    }
    return ca.keyStore
}
```

### B5. `buildKeystoreMap` helper (called from `New()`)

```go
// buildKeystoreMap iterates identity.Keys, collects unique StoreTypes,
// and calls params.BackendForStore once per unique type to populate the
// map. Returns an error if the factory fails for any StoreType.
func buildKeystoreMap(
    identity *Identity,
    cn string,
    factory BackendForStoreFunc,
) (map[types.StoreType]xkms.Backend, error) {
    if factory == nil || identity == nil {
        return nil, nil
    }
    seen := make(map[types.StoreType]bool)
    m := make(map[types.StoreType]xkms.Backend)
    for _, kc := range identity.Keys {
        st := kc.StoreType
        if st == "" {
            st = types.StoreSoftware
        }
        if seen[st] {
            continue
        }
        seen[st] = true
        b, err := factory(cn, st)
        if err != nil {
            return nil, fmt.Errorf("ca: backend factory for %q storeType %q: %w", cn, st, err)
        }
        if b == nil {
            return nil, fmt.Errorf("%w: BackendForStore returned nil for cn=%q storeType=%q",
                ErrKeyStoreRequired, cn, st)
        }
        m[st] = b
    }
    return m, nil
}
```

### B6. Wire `buildKeystoreMap` in `New()` (`pkg/ca/ca.go:392–430`)

After the current Validate call, before constructing the `CA` struct:

```go
// Derive CN for factory calls.
cn := params.Config.Identity
if params.Config.Subject != nil && params.Config.Subject.CommonName != "" {
    cn = params.Config.Subject.CommonName
}

// Build per-StoreType backend map when the caller provides the factory.
// Only the issuing identity's Keys are used here; this is the single-identity
// New() constructor path.
issuingID := multiConfig.IssuingIdentity()
ksMap, err := buildKeystoreMap(issuingID, cn, params.BackendForStore)
if err != nil {
    return nil, err
}

ca := &CA{
    // ... existing fields ...
    keystoreMap: ksMap, // NEW
}
```

### B7. Wire in `NewParentCA` and `NewIntermediateCA` (`pkg/ca/constructors.go`)

`NewParentCA` (line 183) currently builds a flat `Params` and passes it to `New()`. It
must also forward `params.BackendForStore` (and optionally derive the keystoreMap from the
root Identity). The simplest approach: pass `BackendForStore` through to the inner `New()`
call via the inner `Params`:

```go
// In NewParentCA, after resolving ks/cs/os and building cfg:
instance, err := New(&Params{
    Config:         cfg,
    KeyAttributes:  keyAttrs,
    KeyStore:       ks,
    CertStore:      cs,
    ObjectStore:    os,
    SerialGen:      params.SerialGen,
    Profiles:       params.Profiles,
    BackendForStore: params.BackendForStore, // NEW — forward factory
    // The inner New() derives the identity from cfg; we must supply
    // the raw Identity so buildKeystoreMap can iterate all Keys.
    // Reuse Params.Identity[0] since NewParentCA already validated it.
    Identity: []Identity{root}, // pass for keystoreMap construction
})
```

Wait: the inner `New()` path takes a flat `CAConfig`, not the rich `Identity`. The
`buildKeystoreMap` needs the `Identity.Keys` slice. **Resolution**: pass `Identity` on the
inner `Params` too; `New()` should check `params.Identity` and use `params.Identity[0]`
(if present) when calling `buildKeystoreMap`, falling back to reconstructing a synthetic
identity from `params.Config` + `params.KeyAttributes` as it does today.

Concretely, in `New()` at the buildKeystoreMap call:

```go
// Select the Identity for keystoreMap: prefer the pre-validated
// caller-supplied one (from NewParentCA / NewIntermediateCA) since it
// contains the full Keys slice. Fall back to the identity synthesized
// from the flat CAConfig (contains only Keys[0]).
idForMap := issuingID // from multiConfig (may be Keys[0]-only)
if len(params.Identity) > 0 {
    idForMap = &params.Identity[0]
}
ksMap, err := buildKeystoreMap(idForMap, cn, params.BackendForStore)
```

`NewIntermediateCA` follows the same pattern using `params.Identity[1]`.

---

## C. Issuance Path

### C1. `getOrGenerateCAKey` routing (`pkg/ca/ca.go:908–932`)

Replace the single `ca.keyStore` call with `resolveKeyBackend`:

```go
func (ca *CA) getOrGenerateCAKey(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
    backend := ca.resolveKeyBackend(attrs.StoreType) // NEW routing

    privateKey, err := backend.GetKey(ctx, attrs)
    if err == nil {
        return privateKey, nil
    }

    switch attrs.KeyAlgorithm {
    case x509.RSA:
        privateKey, err = backend.GenerateRSA(ctx, attrs)  // was ca.keyStore
    case x509.ECDSA:
        privateKey, err = backend.GenerateECDSA(ctx, attrs)
    case x509.Ed25519:
        privateKey, err = backend.GenerateEd25519(ctx, attrs)
    default:
        return nil, fmt.Errorf("%w: %v", ErrInvalidKeyAlgorithm, attrs.KeyAlgorithm)
    }
    // ...
}
```

### C2. `getSigner` routing (`pkg/ca/ca.go:873–884`)

```go
func (ca *CA) getSigner(ctx context.Context) (crypto.Signer, error) {
    issuingIdentity := ca.config.IssuingIdentity()
    if issuingIdentity == nil {
        return nil, ErrInvalidConfig
    }
    attrs, err := ca.getCAKeyAttributes(issuingIdentity)
    if err != nil {
        return nil, fmt.Errorf("failed to get signer: %w", err)
    }
    backend := ca.resolveKeyBackend(attrs.StoreType) // NEW routing
    return backend.Signer(ctx, attrs)                // was ca.keyStore
}
```

`getCAKeyAttributes` still calls `identity.ToKeyAttributes()` (→ `Keys[0]`). This is
correct: the primary signing key is always `Keys[0]`, and its `StoreType` drives backend
selection.

### C3. `createRootCertificate` / `createIntermediateCertificate`

Both call `getOrGenerateCAKey`, which now routes correctly via `resolveKeyBackend`. No
additional changes needed.

### C4. Init() — generate ALL keys (`pkg/ca/ca.go:553–575`)

Currently `createRootCertificate` generates exactly one key (from `Keys[0]`). To make
all configured keys land in their backends, `Init()` must generate each key after the
primary. Add a loop after `createRootCertificate` succeeds:

```go
// Generate all non-primary keys into their respective backends.
// Errors here are non-fatal warnings: if the primary (Keys[0]) succeeded,
// the CA is functional. Subsequent keys are for backup/rotation only.
if err := ca.initSecondaryKeys(ctx, rootIdentity); err != nil {
    // Log warning but do not fail Init — secondary key generation is
    // best-effort at initialization time.
    // TODO: expose via structured logging once the CA has a logger field.
}
```

```go
// initSecondaryKeys generates Keys[1..n] in their respective backends.
// Called during Init() after the primary CA certificate is created.
// Must be called with mu held (write lock).
func (ca *CA) initSecondaryKeys(ctx context.Context, identity *Identity) error {
    // Prefer inputIdentity because it carries the full Keys slice; the
    // flat caConfig only preserves Keys[0].
    id := identity
    if ca.inputIdentity != nil {
        id = ca.inputIdentity
    }
    if id == nil || len(id.Keys) <= 1 {
        return nil
    }
    for i, kc := range id.Keys[1:] {
        attrs, err := types.KeyAttributesFromConfig(kc)
        if err != nil {
            return fmt.Errorf("ca: secondary key %d attrs: %w", i+1, err)
        }
        attrs.CN = id.Subject.CommonName
        attrs.KeyType = types.KeyTypeCA
        if _, err := ca.getOrGenerateCAKey(ctx, attrs); err != nil {
            return fmt.Errorf("ca: generate secondary key %d (store=%s): %w",
                i+1, attrs.StoreType, err)
        }
    }
    return nil
}
```

### C5. `Load()` — verify ALL keys (`pkg/ca/ca.go:590–650`)

Currently `Load()` calls `ca.keyStore.Signer(ctx, rootAttrs)` only once per identity
(line 615, 637). These become:

```go
// Verify primary key exists in its backend.
rootAttrs, err := rootIdentity.ToKeyAttributes()
// ...
primaryBackend := ca.resolveKeyBackend(rootAttrs.StoreType) // NEW
if _, err := primaryBackend.Signer(ctx, rootAttrs); err != nil {
    return fmt.Errorf("%w: root key not found: %v", ErrKeyStoreRequired, err)
}
```

Secondary key verification in `Load()` is SKIPPED intentionally: the CA certificate
only contains the primary public key; secondary keys are optional at load time.

### C6. No change to `SignCSR` / `IssueCertificate`

`SignCSR` and `IssueCertificate` call `getSigner()`, which now routes correctly.
No further changes needed at the issuance level.

### C7. Algorithm-agile signing — deferred

Algorithm selection (`opts.PreferredAlgorithm`) is explicitly out of scope. The default
behavior (sign with Keys[0]) is unchanged. Algorithm-agile signing is a follow-on feature
that adds `CAKeyAlgorithm types.KeyAlgorithmString` to `SignOptions` and a
`selectCASigningKey(identity *Identity, algo types.KeyAlgorithmString) (*types.KeyConfig, error)`
helper. It does not require any data model or backend resolution changes beyond what is
designed here.

---

## D. Backward Compatibility

| Caller | Path | Impact |
|---|---|---|
| `quicbaas/pkg/server/lifecycle.go:382–387` | `TrustedCAParams{KeyStore: xkmsBackend, ...}` — no `BackendForStore`, no `Keystores` | Zero change: `keystoreMap` nil, all ops via `ca.keyStore` |
| `go-trusted-platform/pkg/app/app.go:2693` | `NewCA(ctx, &Params{Identity: app.CAConfig.Identity, KeyStoreFactory: ...})` — no `BackendForStore` yet | Zero change: `keystoreMap` nil. `Identity.Keystores` parsed from YAML into the new field but ignored at runtime until caller wires `BackendForStore` |
| Any caller using `New()` directly with a single `Params.KeyStore` | No `BackendForStore` | `keystoreMap` nil → `resolveKeyBackend` returns `ca.keyStore` unconditionally |
| `NewFromMultiIdentityConfig` (`pkg/ca/ca.go:475–527`) | No `BackendForStore` on `MultiIdentityParams` | `MultiIdentityParams` needs `BackendForStore` added (same pattern as `Params`) for completeness; optional field, nil safe |

`MultiIdentityParams` (`ca.go:436–465`) must also gain `BackendForStore BackendForStoreFunc` so
`NewFromMultiIdentityConfig` can forward it to the inner `New()` call at line 517.

---

## E. SDK Surface

### E1. go-xkms `sdk/go/ca.go`

Add type and function aliases for all new types. Pattern matches existing aliases in
this file.

```go
// TrustedCAKeystoresConfig holds per-backend keystore configuration for one
// CA identity (root or intermediate). Aliased to pkg/ca.CAKeystoresConfig.
type TrustedCAKeystoresConfig = pkgca.CAKeystoresConfig

// TrustedCAKeystoreSoftwareConfig is the software-backend keystore config.
type TrustedCAKeystoreSoftwareConfig = pkgca.CAKeystoreSoftwareConfig

// TrustedCAKeystoreTPM2Config is the tpm2-backend keystore config.
type TrustedCAKeystoreTPM2Config = pkgca.CAKeystoreTPM2Config

// TrustedCAKeystorePKCS11Config is the pkcs11-backend keystore config.
type TrustedCAKeystorePKCS11Config = pkgca.CAKeystorePKCS11Config

// TrustedCABackendForStoreFunc resolves an xkms.Backend for a given CA CN
// and StoreType. Aliased to pkg/ca.BackendForStoreFunc.
type TrustedCABackendForStoreFunc = pkgca.BackendForStoreFunc
```

`sdk/go/tpm.go` already exports `PlatformKeyStore` and `NewPlatformKeyStore` from
`pkg/tpm2`. Verify these exports are present (they are used by go-trusted-platform
`pkg/platform/keychain.go`). No new TPM exports are needed: the CA config types live in
`pkg/ca` (no TPM import), and callers build the TPM backend externally then pass it via
`BackendForStoreFunc`.

### E2. go-quicbaas `sdk/go/xkms/ca/ca.go`

Add re-exports alongside the existing aliases:

```go
type (
    // ...existing...
    CAKeystoresConfig        = xkmssdk.TrustedCAKeystoresConfig
    CAKeystoreSoftwareConfig = xkmssdk.TrustedCAKeystoreSoftwareConfig
    CAKeystoreTPM2Config     = xkmssdk.TrustedCAKeystoreTPM2Config
    CAKeystorePKCS11Config   = xkmssdk.TrustedCAKeystorePKCS11Config
    BackendForStoreFunc      = xkmssdk.TrustedCABackendForStoreFunc
)
```

This is a pure type-alias expansion: no behavior change for existing quicbaas consumers.

---

## F. Consumer Wiring

### F1. go-trusted-platform — what changes

**NOTHING needs to change for the existing bootstrap or load paths.**

`pkg/app/app.go:2693` already passes `Identity: app.CAConfig.Identity` to `NewCA`. Once
`pkg/ca.Identity` has the `Keystores *CAKeystoresConfig` field, the YAML parser
(`mapstructure`) will populate `Identity.Keystores.TPM2.SRKHandle`, `SRKAuth`, etc.
automatically. This data is then available in the CA instance's `inputIdentity`.

However the CA does NOT yet use that data unless a `BackendForStore` factory is wired.
Wiring `BackendForStore` in `InitCA()`/`LoadCA()` is the required follow-on work:

```go
// pkg/app/app.go — future addition to InitCA (after TPM is initialized)
var bfs pkgca.BackendForStoreFunc
if app.TPM != nil {
    bfs = func(cn string, storeType types.StoreType) (xkms.Backend, error) {
        return buildCABackendForStore(app, cn, storeType, app.CAConfig)
    }
}
root, intermediate, err := quicbaasca.NewCA(ctx, &quicbaasca.Params{
    Identity:           app.CAConfig.Identity,
    KeyStoreFactory:    keyStoreFactoryAdapter(storeFactory),
    CertStoreFactory:   certStoreFactoryAdapter(storeFactory),
    ObjectStoreFactory: objectStoreFactoryAdapter(storeFactory),
    BackendForStore:    bfs, // NEW
})
```

`buildCABackendForStore(app, cn, storeType, caConfig)` would:
- For `storeType == "software"`: return the existing PKCS8 service backend (same as
  `BootstrapCAStoreFactory.CreateKeyStore(cn)` already does)
- For `storeType == "tpm2"`: read `caConfig.Identity[i].Keystores.TPM2` (find identity
  by CN), construct a `tpm2.PlatformKeyStore` using `app.TPM`, `SRKHandle`, and `SRKAuth`,
  then wrap it in an `xkms.New(&xkms.BackendConfig{...})` call using the pintpm2 backend
- For other store types: return `ErrBackendNotCompiledError` or `ErrKeyStoreRequired`

This function lives in `pkg/app/` (go-trusted-platform) and only touches go-xkms SDK
types. The go-xkms CA library has no dependency on `pkg/tpm2` of go-trusted-platform.

### F2. go-quicbaas — the P1 band-aids

`pkg/server/lifecycle.go:initializeCA` (`lifecycle.go:311–314`) contains the
`resolveCAStoreType()` + single-keystore band-aid documented in comments as a known
limitation ("crypto-backend-selection design §5.2"). The design here provides the missing
§5.2 mechanism (`BackendForStore`). The quicbaas wiring is a follow-on task:

1. Build the appropriate `BackendForStoreFunc` from the resolved xkms subsystem
2. Pass it to the `TrustedCAParams` construction at line 382
3. Delete the `resolveCAStoreType()` band-aid comment

This is an independent lifecycle change that does not block the core go-xkms implementation.

---

## G. Test Plan

### G1. Unit tests (in `pkg/ca/`)

**TestIdentityKeystoresParsing**  
Unmarshal a YAML snippet containing `keystores.software.platform-policy` and
`keystores.tpm2.srk-handle/srk-auth/platform-policy`. Assert `Identity.Keystores` is
non-nil and fields round-trip correctly. **Does not require a TPM.**

**TestBuildKeystoreMap_NilFactory**  
Pass nil `BackendForStore`. Assert `buildKeystoreMap` returns `(nil, nil)`.

**TestBuildKeystoreMap_FactoryCalled**  
Provide an identity with Keys: software ECDSA + tpm2 ECDSA. Provide a factory that
returns distinct mock backends per StoreType. Assert the returned map has exactly two
entries and the factory was called exactly twice (once per unique StoreType, not once
per key).

**TestBuildKeystoreMap_FactoryError**  
Factory returns error for tpm2. Assert `buildKeystoreMap` returns wrapped error.

**TestResolveKeyBackend_WithMap**  
Construct a `CA` with a pre-populated `keystoreMap`. Assert `resolveKeyBackend(software)`
returns the software entry and `resolveKeyBackend(tpm2)` returns the TPM2 entry.

**TestResolveKeyBackend_Fallback**  
Construct a `CA` with nil `keystoreMap`. Assert `resolveKeyBackend(tpm2)` returns
`ca.keyStore` (the fallback). Proves the backward-compat path.

**TestNewCA_BackwardCompat**  
Use the existing `DefaultMultiIdentityCAConfig()` (no `BackendForStore`, no `Keystores`).
Assert CA initializes and issues certificates identically to today. This is a non-
regression gate for all existing callers.

**TestInitSecondaryKeys_AllGenerated**  
Construct an identity with 3 keys (software RSA, tpm2 RSA via a mock backend, software
ECDSA). Provide `BackendForStore`. Call `Init()`. Assert the mock tpm2 backend's
`GenerateKey` was called once (for the tpm2 RSA key). Assert `getSigner` returns a signer
from the software backend (Keys[0]).

**TestGetOrGenerateCAKey_RoutesCorrectly**  
Mock two backends. One answers `GetKey` with ErrNotFound; the other answers successfully.
Confirm routing by StoreType reaches the correct backend.

### G2. swtpm integration test (in `pkg/ca/` with `//go:build swtpm` tag)

**TestCA_TPM2Key_InitAndSign**  
1. Start swtpm (same setup as `pkg/tpm2/platform_keystore_swtpm_test.go`)
2. Build a `tpm2.PlatformKeyStore` for the CA with a dedicated `SRKHandle`
3. Create an `xkms.Backend` wrapping that PlatformKeyStore
4. Construct a CA identity with Keys[0]=ECDSA-software and Keys[1]=ECDSA-TPM2
5. Provide `BackendForStore` that returns the TPM2 backend for `storeType=="tpm2"`
6. Call `NewCA` → `Init()`
7. Assert the software ECDSA key exists in the software backend
8. Assert the TPM2 ECDSA key exists in the swtpm (via `tpm.KeyAttributes`)
9. Issue a test certificate and verify signature using the software CA key

**TestCA_TPM2PrimaryKey_InitAndSign**  
Same as above but with Keys[0]=ECDSA-TPM2 (primary key is hardware-backed):
1. CA certificate is self-signed by the TPM2 ECDSA key
2. Verify certificate signature using TPM2 signer

### G3. softhsm integration test (in `pkg/ca/` with `//go:build pkcs11` tag)

**TestCA_PKCS11Key_InitAndSign**  
1. Initialize softhsm slot
2. Build a pkcs11 backend for the CA
3. Construct identity with Keys[0]=ECDSA-software, Keys[1]=ECDSA-PKCS11
4. Provide `BackendForStore` returning the pkcs11 backend for `storeType=="pkcs11"`
5. Call `Init()`, assert the PKCS11 key exists in the hsm
6. Issue and verify a certificate

### G4. Coverage targets

All new functions in `pkg/ca/`:
- `buildKeystoreMap` — 100% branch coverage via unit tests
- `resolveKeyBackend` — 100% branch coverage (map hit + nil map + miss fallback)
- `initSecondaryKeys` — covered by TestInitSecondaryKeys_AllGenerated
- Data model types — covered by parse + validate tests

---

## H. Phased Plan and Risk Assessment

### Phase 1 — Core go-xkms (go-xkms repo, pkg/ca only)

**Files changed:**
- `pkg/ca/config.go` — add `CAKeystoresConfig` family + `Keystores` field on `Identity`
- `pkg/ca/constructors.go` — add `BackendForStoreFunc` type
- `pkg/ca/ca.go` — add `keystoreMap` on CA, `BackendForStore` on Params + MultiIdentityParams, `buildKeystoreMap`, `resolveKeyBackend`, `initSecondaryKeys`; update `getOrGenerateCAKey`, `getSigner`, `Load()` to route via `resolveKeyBackend`
- Unit tests (no build tags): all backward-compat + new routing tests

**Risk**: `getOrGenerateCAKey` and `getSigner` are hot paths used in ALL CA operations.
Regression risk is contained by the `resolveKeyBackend` fallback: when `keystoreMap` is
nil (all existing callers), it returns `ca.keyStore` — identical behavior to today.

**Verification**: Run `make test` in go-xkms; all existing CA tests must pass unchanged.
Add TestNewCA_BackwardCompat specifically to catch regressions.

### Phase 2 — SDK exports (go-xkms repo, sdk/go)

**Files changed:**
- `sdk/go/ca.go` — add type aliases for new CA keystore config types and
  `TrustedCABackendForStoreFunc`

Zero risk: pure type aliases.

### Phase 3 — go-quicbaas re-exports

**Files changed:**
- `sdk/go/xkms/ca/ca.go` — add `CAKeystoresConfig`, `CAKeystoreTPM2Config`, etc.

Zero risk.

### Phase 4 — go-trusted-platform consumer wiring

**Files changed:**
- `pkg/app/app.go` — wire `BackendForStore` in `InitCA()` and `LoadCA()`
- New helper `buildCABackendForStore` in `pkg/app/`

**Risk**: This is where the TPM2 SRK provisioning and `kms://` auth URI resolution occurs.
The SRK auth URI uses the KMS resolver chain (same path as existing TPM2 keys in the
platform). Regression risk is isolated to the new `buildCABackendForStore` function;
existing callers remain on the nil-factory path until `buildCABackendForStore` is wired.

Test with: `make integration-test-ca` with swtpm — exercise the full init+sign path with
a real swtpm backing the CA TPM2 keys.

### Phase 5 — go-quicbaas lifecycle wiring

**Files changed:**
- `pkg/server/lifecycle.go` — wire `BackendForStore` when a TPM2 or PKCS11 backend is
  available; remove the `resolveCAStoreType()` band-aid comment block

**Risk**: Low. The quicbaas lifecycle currently only uses a software PKCS8 CA backend.
The `resolveCAStoreType` band-aid is replaced by `BackendForStore`, which falls back to
software when the TPM is unavailable — same as today.

### Highest-Regression Areas

| Area | Risk | Mitigation |
|---|---|---|
| `getOrGenerateCAKey` routing change | Medium — used in Init, Load, createRoot, createIntermediate | `resolveKeyBackend` nil-map path = identical to today. Gate with TestNewCA_BackwardCompat. |
| `initSecondaryKeys` best-effort errors | Low — secondary key failure does not fail Init | Log warning only; do not return error from Init. |
| `Identity.Keystores` YAML unmarshal | Low — additive field, nil when absent | Standard mapstructure behavior; empty struct = nil pointer. |
| `buildKeystoreMap` called twice per CA (once for root, once for intermediate) in `NewCA` | Low — factory called at most once per (cn, storeType) pair by design | Verified by TestBuildKeystoreMap_FactoryCalled assertion on call count. |
| Phase 4 SRK auth URI resolution in go-trusted-platform | Medium — new code path for TPM2 CA key provisioning | Covered by swtpm integration test; separate from Phase 1. |

---

## File Path Summary

| File | Change Type | Description |
|---|---|---|
| `pkg/ca/config.go` | Modify | Add `CAKeystoresConfig`, `CAKeystoreSoftwareConfig`, `CAKeystoreTPM2Config`, `CAKeystorePKCS11Config`; add `Keystores *CAKeystoresConfig` to `Identity` after line 103 |
| `pkg/ca/constructors.go` | Modify | Add `BackendForStoreFunc` type after line 63 |
| `pkg/ca/ca.go` | Modify | Add `keystoreMap` to `CA` struct (after line 248); add `BackendForStore` to `Params` (after line 165) and `MultiIdentityParams` (after line 465); add `buildKeystoreMap`, `resolveKeyBackend`, `initSecondaryKeys` helpers; update `getOrGenerateCAKey` (line 908), `getSigner` (line 873), `Load()` (lines 615, 637), `New()` (line 392), `Init()` (line 562) |
| `sdk/go/ca.go` | Modify | Add type aliases for new CA keystore config types and `TrustedCABackendForStoreFunc` |
| `../go-quicbaas/sdk/go/xkms/ca/ca.go` | Modify (Phase 3) | Add re-exports for new CA keystore config types and `BackendForStoreFunc` |
| `../go-trusted-platform/pkg/app/app.go` | Modify (Phase 4) | Wire `BackendForStore` in `InitCA()` and `LoadCA()` |
| `../go-trusted-platform/pkg/app/ca_factory.go` | Modify (Phase 4) | Add `buildCABackendForStore` helper |
