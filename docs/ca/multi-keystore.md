# Multi-Keystore Routing

## Overview

go-xkms CA supports routing each key in a CA identity's `Keys` slice to a
different backend — software PKCS#8, TPM 2.0, or PKCS#11 — within the same
CA instance. This is called per-key keystore routing.

**BREAKING**: `BackendForStoreFunc` is required on every CA constructor
(`New`, `NewParentCA`, `NewIntermediateCA`, `NewCA`,
`NewFromMultiIdentityConfig`, `NewHierarchicalCA`). There is no fallback to
a single shared `KeyStore` for every `StoreType`; a caller that omits
`BackendForStore` gets `ErrBackendForStoreRequired` at construction. A
caller with one uniform backend for every key supplies a factory that
returns it for every `StoreType` — an explicit, visible choice in the
caller's own code rather than an implicit default.

## Key Routing Model

### Keys[0] — Primary Signing Key

`Keys[0]` is always the **primary signing key**. Its public key is bound in
the CA certificate and all certificate issuance signs with this key. Its
`StoreType` determines which backend is used for both generation and signing.

### Keys[1..n] — Secondary Keys

`Keys[1]` and beyond are **secondary keys**. They are generated in their
respective backends at `Init` time and can be used for:

- Offline backup copies in a different store (e.g. a software copy of a
  TPM-primary key).
- Future key rotation (promote a secondary to primary by updating
  `Keys[0]`).
- Multi-algorithm coverage for algorithm-agile signing (deferred; not yet
  active in the current release).

Secondary keys are intentionally skipped during `Load` because the CA
certificate binds only the primary public key. A secondary-key failure at
`Init` is logged but does **not** fail the overall `Init` call.

### StoreType Routing

The routing key is `types.KeyConfig.StoreType` (the `store` field in YAML).
An empty `StoreType` defaults to `types.StoreSoftware`.

```
identity.Keys:
  Keys[0]  store: software  ──►  software Backend  (primary, cert-bound)
  Keys[1]  store: tpm2      ──►  TPM 2.0 Backend   (secondary)
  Keys[2]  store: software  ──►  software Backend   (secondary)
  Keys[3]  store: tpm2      ──►  TPM 2.0 Backend   (secondary)
```

## CAKeystoresConfig

The `keystores:` block in the CA identity YAML configures backend-specific
parameters. Each sub-field corresponds to one store type; nil sub-fields
are ignored.

```go
type CAKeystoresConfig struct {
    Software *CAKeystoreSoftwareConfig `yaml:"software"`
    TPM2     *CAKeystoreTPM2Config     `yaml:"tpm2"`
    PKCS11   *CAKeystorePKCS11Config   `yaml:"pkcs11"`
}
```

### CAKeystoreSoftwareConfig

```go
type CAKeystoreSoftwareConfig struct {
    PlatformPolicy bool   `yaml:"platform-policy"`
    Password       string `yaml:"password,omitempty"`
}
```

| Field | YAML key | Description |
|-------|----------|-------------|
| `PlatformPolicy` | `platform-policy` | Enables TPM platform-policy binding for software keys encrypted at rest under a TPM SRK. |
| `Password` | `password` | Identity-wide fallback passphrase for software keys (see Password Precedence below). |

### CAKeystoreTPM2Config

```go
type CAKeystoreTPM2Config struct {
    SRKHandle      uint32 `yaml:"srk-handle"`
    SRKAuth        string `yaml:"srk-auth,omitempty"`
    PlatformPolicy bool   `yaml:"platform-policy"`
}
```

| Field | YAML key | Description |
|-------|----------|-------------|
| `SRKHandle` | `srk-handle` | Persistent TPM handle for the Storage Root Key wrapping CA keys, e.g. `0x81000001`. |
| `SRKAuth` | `srk-auth` | KMS URI resolving to the SRK password at startup, e.g. `kms://ca/root/tpm2/srk-auth?ensure=true&len=32&enc=base64`. |
| `PlatformPolicy` | `platform-policy` | Enables PCR-bound platform policy on TPM CA keys. |

### CAKeystorePKCS11Config

```go
type CAKeystorePKCS11Config struct {
    Pin    string `yaml:"pin,omitempty"`
    Slot   int    `yaml:"slot,omitempty"`
    Module string `yaml:"module,omitempty"`
}
```

| Field | YAML key | Description |
|-------|----------|-------------|
| `Pin` | `pin` | User PIN for HSM access. |
| `Slot` | `slot` | HSM slot number. |
| `Module` | `module` | Path to PKCS#11 shared library (.so/.dll). |

### Password Precedence (Software Keys)

When determining the passphrase for a software-backed key, the CA applies
the following precedence:

1. `KeyConfig.Password` — per-key passphrase (highest priority).
2. `Keystores.Software.Password` — identity-wide fallback for any key
   whose per-key password is empty.

When a password is present the key file is written as encrypted PKCS#8 at
rest. Source passwords from a secrets manager or the node's PIN backend —
do not embed secrets in YAML.

## BackendForStoreFunc

```go
type BackendForStoreFunc func(cn string, storeType types.StoreType) (xkms.Backend, error)
```

Supply a `BackendForStoreFunc` via `Params.BackendForStore` (or
`MultiIdentityParams.BackendForStore`); it is required, not optional.

The CA calls the function **once per unique `StoreType`** found in the
identity's `Keys` slice and caches the result in an internal
`keystoreMap`. The function is therefore invoked at most once per
`(cn, storeType)` pair. Returning `(nil, nil)` is not permitted.

```go
backendForStore := func(cn string, storeType types.StoreType) (xkms.Backend, error) {
    switch storeType {
    case types.StoreSoftware:
        return newSoftwareBackend(cn)
    case types.StoreTPM2:
        return newTPM2Backend(cn, tpmDevice)
    default:
        return nil, fmt.Errorf("unsupported store type: %v", storeType)
    }
}

authority, err := ca.NewWithParams(ca.Params{
    Config:          config,
    BackendForStore: backendForStore,
})
```

## A Single Uniform Backend

There is no implicit fallback to `Params.KeyStore` for every `StoreType`. A
caller whose CA identity only ever uses one backend supplies a trivial
factory that ignores `storeType` and returns that one backend:

```go
backendForStore := func(cn string, storeType types.StoreType) (xkms.Backend, error) {
    return softwareBackend, nil
}
```

This keeps the choice explicit and visible in the caller's own
composition root rather than an implicit default `pkg/ca` supplies. Passing
`nil` for `Params.BackendForStore` (or `MultiIdentityParams.BackendForStore`)
returns `ErrBackendForStoreRequired`.

## Worked YAML Example

The following identity configures a single CA with four keys across two
backends. `Keys[0]` (software RSA) is the primary signing key; the
remaining three are secondary.

```yaml
certificate-authority:
  home: /var/lib/xkms
  platform-ca: 1
  default-validity: 398

  identity:
    # Root CA — software only, single key
    - subject:
        cn: "Example Root CA"
        organization: "Example Corp"
        country: "US"
      valid: 20
      key-algorithm: RSA
      key-size: 4096
      is-root: true
      keystores:
        software:
          password: "${ROOT_CA_PASSWORD}"

    # Intermediate CA — four keys across software and TPM 2.0
    - subject:
        cn: "Example Intermediate CA"
        organization: "Example Corp"
        country: "US"
      valid: 10
      keystores:
        software:
          password: "${INT_CA_SW_PASSWORD}"  # fallback for software keys
        tpm2:
          srk-handle: 0x81000001
          srk-auth: "kms://ca/intermediate/tpm2/srk-auth?ensure=true&len=32&enc=base64"
          platform-policy: true
      keys:
        # Keys[0] — primary signing key (software RSA, cert-bound)
        - algorithm: RSA
          rsa:
            size: 4096
          signature-algorithm: SHA256-RSA
          hash: SHA-256
          store: software

        # Keys[1] — secondary (TPM 2.0 RSA, backup / future rotation)
        - algorithm: RSA
          rsa:
            size: 2048
          signature-algorithm: SHA256-RSA
          hash: SHA-256
          store: tpm2

        # Keys[2] — secondary (software ECDSA, algorithm-agile reserve)
        - algorithm: ECDSA
          ecc:
            curve: P-256
          signature-algorithm: ECDSA-SHA256
          hash: SHA-256
          store: software

        # Keys[3] — secondary (TPM 2.0 ECDSA, hardware-backed reserve)
        - algorithm: ECDSA
          ecc:
            curve: P-256
          signature-algorithm: ECDSA-SHA256
          hash: SHA-256
          store: tpm2
```

## SDK Re-Exports

The following type aliases are available from `github.com/jeremyhahn/go-xkms/sdk/go`:

| SDK alias | Underlying type |
|-----------|----------------|
| `TrustedCAKeystoresConfig` | `pkgca.CAKeystoresConfig` |
| `TrustedCAKeystoreSoftwareConfig` | `pkgca.CAKeystoreSoftwareConfig` |
| `TrustedCAKeystoreTPM2Config` | `pkgca.CAKeystoreTPM2Config` |
| `TrustedCAKeystorePKCS11Config` | `pkgca.CAKeystorePKCS11Config` |
| `TrustedCABackendForStoreFunc` | `pkgca.BackendForStoreFunc` |

These are pure type aliases — they carry no transport state and are provided
so downstream consumers can reference CA config types without a direct
`go-xkms/pkg/ca` import.

## See Also

- [Architecture](architecture.md)
- [Configuration Reference](configuration.md)
- [API Reference](api-reference.md)
