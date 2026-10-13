# Certificate Management

> **Status: REFERENCE** · Last verified: 2026-10-13
> Scope: the certificate functions of the `pkg/xkms` service and the hardware certificate storage in `pkg/storage/hardware`; for the CLI see [`xkmsctl cert`](cli/cert.md).

go-xkms stores each key's certificate and certificate chain next to the key.
By default, certificates go in the backend's certificate storage, which is a
`storage.Backend` on the configured datastore. PKCS#11 tokens and TPM NV RAM
can hold certificates themselves.

## Service API

Each function takes a `context.Context` first. It addresses the key either by
`*types.KeyAttributes` or, in the `ByID` form, by a key ID string
(`backend:type:algo:keyname`, see [API parity](api-parity.md#xkmsservice)).

| Function | `ByID` form | Description |
|----------|-------------|-------------|
| `Certificate` | `CertificateByID` | Get the certificate |
| `SaveCertificate` | `SaveCertificateByID` | Save a certificate |
| `DeleteCertificate` | `DeleteCertificateByID` | Delete the certificate |
| `CertificateExists` | `CertificateExistsByID` | Report whether a certificate is stored |
| `CertificateChain` | `CertificateChainByID` | Get the chain |
| `SaveCertificateChain` | `SaveCertificateChainByID` | Save a chain (leaf first) |
| `TLSCertificate` | `TLSCertificateByID` | Get a `tls.Certificate`: the private key, leaf and chain |
| `ListCertificates(ctx, backend...)` | — | List certificate IDs across all backends, or only those named |

These functions are defined in `pkg/xkms/service.go:984-1074` and
`pkg/xkms/service.go:1226-1272`, and the `ByID` chain, exists and TLS forms at
`pkg/xkms/service.go:1779-1831`.

### Example

```go
import (
    "context"
    "crypto/tls"
    "crypto/x509"
    "net/http"

    "github.com/jeremyhahn/go-xkms/pkg/types"
    "github.com/jeremyhahn/go-xkms/pkg/xkms"
)

ctx := context.Background()

// A nil Datastore keeps everything in memory; pass the datastore's
// storage.Backend for persistent storage (pkg/xkms/auto.go:23).
if err := xkms.AutoInitialize(&xkms.AutoConfig{}); err != nil {
    return err
}
defer xkms.Close()

attrs := &types.KeyAttributes{
    CN:        "api.example.com",
    StoreType: types.BackendType("software"),
}

if err := xkms.SaveCertificate(ctx, attrs, cert); err != nil {
    return err
}
if err := xkms.SaveCertificateChain(ctx, attrs, []*x509.Certificate{cert, intermediate}); err != nil {
    return err
}

tlsCert, err := xkms.TLSCertificate(ctx, attrs)
if err != nil {
    return err
}
server := &http.Server{TLSConfig: &tls.Config{Certificates: []tls.Certificate{tlsCert}}}

// The same certificate by key ID.
same, err := xkms.CertificateByID(ctx, "software:::api.example.com")
```

## Hardware certificate storage

`pkg/storage/hardware` stores certificates on the device. Hardware storage
implements `HardwareCertStorage` (`pkg/storage/hardware/interface.go`):

- the certificate and chain operations
- `GetCapacity`, which returns the total and available slots, or
  `ErrNotSupported`
- `SupportsChains`, `IsHardwareBacked` and `Compact`

| Mode | Constant | Behaviour |
|------|----------|-----------|
| External | `hardware.CertStorageModeExternal` | Every certificate is in the external `storage.Backend` (the default). |
| Hardware | `hardware.CertStorageModeHardware` | Every certificate is on the device. |
| Hybrid | `hardware.CertStorageModeHybrid` | Writes try the device first and fall back to external storage. Reads check the device, then external storage. Deletes remove from both. |

In hybrid mode a save falls back to external storage only when the device
fails with a capacity error or a hardware-unavailable error. Any other device
error is returned (`pkg/storage/hardware/hybrid_cert_storage.go:369`).

### PKCS#11

A PKCS#11 token stores certificates as `CKO_CERTIFICATE` objects.
`(*pkcs11.Backend).CreateCertificateStorage` (`pkg/backend/pkcs11/cert_config.go:78`)
builds certificate storage from a `CertStorageConfig`. It returns a
`storage.Backend`:

```go
certStorage, err := p11Backend.CreateCertificateStorage(&pkcs11.CertStorageConfig{
    Mode:                  hardware.CertStorageModeHybrid,
    ExternalStorage:       externalBackend, // a storage.Backend
    EnableHardwareStorage: true,
})
```

The validation rules (`cert_config.go:45`):

- `external` and `hybrid` require `ExternalStorage`.
- `hardware` and `hybrid` require `EnableHardwareStorage`.
- `MaxCertificates` must not be negative. It is not enforced as a cap: the
  token's own capacity limits the count.
- The backend must be initialized first.
- A nil config means external mode (`DefaultCertStorageConfig`).

On a YubiKey PIV token, deletes use the SO PIN, because libykcs11 refuses
`C_DestroyObject` for the user role (`cert_config.go:122`).

### TPM 2.0

TPM NV RAM holds certificates through `hardware.NewTPM2CertStorage(tpm, cfg)`
(`pkg/storage/hardware/tpm2_cert_storage.go:132`). It takes an open TPM
transport and a `TPM2CertStorageConfig`:

| Field | Default | Rule |
|-------|---------|------|
| `BaseIndex` | `0x01800000` | Must lie in `0x01000000`–`0x01BFFFFF` |
| `MaxCertSize` | `2048` | 512 to 4096 bytes per certificate |
| `OwnerAuth` | nil | Owner hierarchy authorization, used to define and undefine NV indices |

NV RAM is small, so keep only the few certificates that must be bound to the
TPM there. To combine it with external storage, wrap it in
`hardware.NewHybridCertStorageFromBackend(tpmStorage, externalBackend)`
(`hybrid_cert_storage.go:344`).

### Capacity

The storage returned by `CreateCertificateStorage` in hardware or hybrid mode
is a `*hardware.HardwareBackendAdapter`. `GetHardwareStorage()`
(`pkg/storage/hardware/backend_adapter.go:263`) returns the underlying
`HardwareCertStorage`:

```go
if adapter, ok := certStorage.(*hardware.HardwareBackendAdapter); ok {
    total, available, err := adapter.GetHardwareStorage().GetCapacity()
    // ...
}
```

## Errors

These sentinels are in `pkg/storage/hardware/errors.go`:

| Error | Meaning |
|-------|---------|
| `ErrCapacityExceeded` | The device's certificate storage is full |
| `ErrTokenFull` | The PKCS#11 token has no room for another object |
| `ErrCertificateTooLarge` | The certificate exceeds the device's maximum size |
| `ErrHardwareUnavailable` | The device cannot be reached |

`hardware.IsCapacityError(err)` matches the first three
(`errors.go:99`). `hardware.IsHardwareError(err)` matches
`ErrHardwareUnavailable`, `ErrNVIndexUnavailable` and `ErrNotSupported`
(`errors.go:107`).

## Troubleshooting

- **The device is full.** Delete unused certificates, or use hybrid mode so
  new certificates overflow to external storage.
- **Certificate too large for the TPM.** Raise `MaxCertSize` (4096 at most),
  or keep the certificate in external storage.
- **`backend must be initialized before creating certificate storage`.**
  Initialize and log in to the PKCS#11 backend before calling
  `CreateCertificateStorage`.

## See Also

- [`xkmsctl cert`](cli/cert.md)
- [PKCS#11 backend](../../../docs/pkcs11-backend/user.md)
- [TPM 2.0](../../../docs/tpm2/user.md)
- [Key import and export](key-import-export.md)
