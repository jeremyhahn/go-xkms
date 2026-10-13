# Key Import and Export

> **Status: REFERENCE** · Last verified: 2026-10-13
> Scope: the import, export and copy functions of the `pkg/xkms` service and the wrapping algorithms each backend accepts; for the CLI see [`xkmsctl key`](cli/key.md).

go-xkms moves keys between systems as wrapped key material. The key is
encrypted under a wrapping public key that the destination backend provides,
and only the destination can unwrap it.

## Service API

Each function takes a `context.Context` first (`pkg/xkms/service.go:1849-2088`):

| Function | Description |
|----------|-------------|
| `GetImportParameters(ctx, backendName, attrs, algorithm)` | Get the destination's wrapping public key, import token and expiry |
| `WrapKey(ctx, backendName, keyMaterial, params)` | Wrap plaintext key material under the import parameters |
| `UnwrapKey(ctx, backendName, wrapped, params)` | Unwrap wrapped material |
| `ImportKey(ctx, backendName, attrs, wrapped)` | Import wrapped material as a new key |
| `ExportKey(ctx, kid, algorithm)` | Export a key in wrapped form |
| `CopyKey(ctx, sourceKID, destBackend, destAttrs)` | Copy a key from one backend to another |
| `WrapKeyByID`, `UnwrapKeyByID` | Wrap and unwrap under a key the server holds, addressed by ID |

The types are in `pkg/backend/backend_importexport.go`:

- `ImportParameters` (`:74`): `WrappingPublicKey`, `ImportToken`, `Algorithm`,
  `ExpiresAt` (a `*time.Time`, nil when the parameters do not expire) and
  `KeySpec`.
- `WrappedKeyMaterial` (`:101`): `WrappedKey`, `Algorithm`, `ImportToken` and
  `Metadata`.

A backend supports import if it implements `backend.ImportBackend` (`:132`), and
export if it implements `ExportBackend`. `ImportExportBackend` (`:281`) embeds
both. `types.Capabilities` reports the halves as `Import` and `Export`, and
`SupportsImportExport()` is true only when both are set
(`pkg/types/types.go:1670-1705`).

## Wrapping algorithms

| Constant (`backend.`) | Value | Construction |
|-----------------------|-------|--------------|
| `WrappingAlgorithmRSAES_OAEP_SHA_1` | `RSAES_OAEP_SHA_1` | RSA-OAEP, SHA-1 |
| `WrappingAlgorithmRSAES_OAEP_SHA_256` | `RSAES_OAEP_SHA_256` | RSA-OAEP, SHA-256 |
| `WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_1` | `RSA_AES_KEY_WRAP_SHA_1` | RSA-OAEP wraps an ephemeral AES key, which wraps the material with AES-KWP; SHA-1 |
| `WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256` | `RSA_AES_KEY_WRAP_SHA_256` | The same, SHA-256 |
| `WrappingAlgorithmRSA_OAEP_3072_SHA256_AES_256` | `RSA_OAEP_3072_SHA256_AES_256` | GCP hybrid, RSA-3072 |
| `WrappingAlgorithmRSA_OAEP_4096_SHA256_AES_256` | `RSA_OAEP_4096_SHA256_AES_256` | GCP hybrid, RSA-4096 |
| `WrappingAlgorithmRSA_OAEP_4096_SHA256` | `RSA_OAEP_4096_SHA256` | GCP plain RSA-OAEP, RSA-4096 |
| `WrappingAlgorithmVaultTransitBYOK` | `VAULT_TRANSIT_BYOK_RSA_OAEP_SHA256_AES256_GCM96` | Vault Transit BYOK format |

The constants are defined at `backend_importexport.go:37-68`. Plain RSA-OAEP can
wrap only material smaller than the RSA modulus less the padding, which is
enough for a symmetric key. Use a hybrid algorithm for private keys. In a
hybrid algorithm, `WrappedKey` is the wrapped AES key followed by the wrapped
material (`:103`). Prefer the SHA-256 variants.

## Backend support

| Backend | Import | Export | Algorithms accepted | Parameters expire |
|---------|--------|--------|---------------------|-------------------|
| Software | Yes | Yes, if `Exportable` | The four `RSAES_OAEP_*` and `RSA_AES_KEY_WRAP_*` | Yes, set by the import-token store |
| Symmetric | Yes | Yes, if `Exportable` | The four `RSAES_OAEP_*` and `RSA_AES_KEY_WRAP_*` | Yes |
| PKCS#11 | Yes, through `C_UnwrapKey` | Yes, if the key is `CKA_EXTRACTABLE` | The four `RSAES_OAEP_*` and `RSA_AES_KEY_WRAP_*` | — |
| AWS KMS | Yes | No (`ErrExportNotSupported`) | The four `RSAES_OAEP_*` and `RSA_AES_KEY_WRAP_*` | When AWS says (`ParametersValidTo`) |
| GCP KMS | Yes | No (`ErrExportNotSupported`) | The three GCP constants; `RSAES_OAEP_SHA_256` maps to `RSA_OAEP_4096_SHA256` | After 3 days |
| Azure Key Vault | Yes | No (`ErrNotSupported`) | `RSA_AES_KEY_WRAP_SHA_1` and `_SHA_256` only | — |
| Vault Transit | Symmetric keys only | No | `WrappingAlgorithmVaultTransitBYOK` only | — |
| TPM 2.0 | Yes, as a TPM duplicate | No: TPM keys are hardware-bound | `TPM2_DUPLICATE` only | — |
| Phone | No | No | — | — |

Citations:

- Software: `pkg/backend/software/software.go:494`, `:727`, `:1075`.
- Symmetric: `pkg/keyprovider/symmetric/backend.go:1381`, `:1627`.
- PKCS#11: `pkg/backend/pkcs11/pkcs11_importexport.go:99`, `:755`.
- AWS: `pkg/backend/awskms/awskms.go:1071`, `:1221`, `:1278`.
- GCP: `pkg/backend/gcpkms/gcpkms_importexport.go:94`, `:264`, `:302`.
- Azure: `pkg/backend/azurekv/azurekv_importexport.go:116`, `:467`.
- Vault: `pkg/backend/vault/vault_importexport.go:80`, `:312`.
- TPM 2.0: `pkg/backend/tpm2/importexport.go:62`, `:225`, `:265`. A tenant-scoped
  TPM backend refuses imports outside the system tenant (`:238`).
- Phone: `pkg/backend/phone/import_export.go:58`.

The wrapping private key stays in the destination backend. Wrapping happens
outside it, so the plaintext material exists in the caller's memory until it
is wrapped.

## Copying a key between backends

`CopyKey` copies in one call (`service.go:2016`). It:

1. Loads the source key's stored attributes, so a key generated with
   `Exportable: true` can be copied.
2. Gets the destination's import parameters with `RSAES_OAEP_SHA_256`
   (`service.go:2068`).
3. Wraps the key for those parameters with the source's `ExportKeyTo`.
4. Imports it into the destination.

With `destAttrs` nil, the destination uses the source's attributes. Because
the algorithm is fixed, a destination that refuses `RSAES_OAEP_SHA_256`
(Azure, Vault, TPM 2.0) cannot be a `CopyKey` target.

```go
import (
    "context"

    "github.com/jeremyhahn/go-xkms/pkg/xkms"
)

ctx := context.Background()

// A nil Datastore keeps everything in memory (pkg/xkms/auto.go:23).
if err := xkms.AutoInitialize(&xkms.AutoConfig{}); err != nil {
    return err
}
defer xkms.Close()

if err := xkms.CopyKey(ctx, "software:::my-key", "pkcs11", nil); err != nil {
    return err
}
sig, err := xkms.Sign(ctx, "pkcs11:::my-key", digest, nil)
```

## Importing external key material

To import material generated elsewhere, get the parameters, wrap, then import:

```go
import (
    "context"
    "crypto/rand"

    "github.com/jeremyhahn/go-xkms/pkg/backend"
    "github.com/jeremyhahn/go-xkms/pkg/types"
    "github.com/jeremyhahn/go-xkms/pkg/xkms"
)

attrs := &types.KeyAttributes{
    CN:                 "imported-aes-key",
    KeyType:            types.KeyTypeEncryption,
    SymmetricAlgorithm: types.SymmetricAES256GCM,
    StoreType:          types.StoreAWSKMS,
}

params, err := xkms.GetImportParameters(ctx, "awskms", attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
if err != nil {
    return err
}

keyMaterial := make([]byte, 32)
if _, err := rand.Read(keyMaterial); err != nil {
    return err
}
defer clear(keyMaterial)

wrapped, err := xkms.WrapKey(ctx, "awskms", keyMaterial, params)
if err != nil {
    return err
}
if err := xkms.ImportKey(ctx, "awskms", attrs, wrapped); err != nil {
    return err
}
```

For an RSA private key, marshal it with `x509.MarshalPKCS8PrivateKey` and use
`WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256`, or a GCP hybrid algorithm for GCP.

Import parameters can expire. Check `params.ExpiresAt` before a slow step, and
get new parameters once it has passed:

```go
if params.ExpiresAt != nil && time.Now().After(*params.ExpiresAt) {
    // Call GetImportParameters again.
}
```

## Exporting a key

`ExportKey` loads the key's stored attributes, so the backend sees the
`Exportable` flag the key was generated with (`service.go:2002`). It returns
material wrapped under a key the source backend creates:

```go
wrapped, err := xkms.ExportKey(ctx, "software:::my-key", backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
```

To move a key to another backend, use `CopyKey`, which wraps for the
destination's own parameters instead.

## Errors

| Error | Returned when |
|-------|---------------|
| `xkms.ErrImportExportNotSupported` | The backend implements neither half, or not the half requested (`pkg/xkms/errors.go:282`) |
| `xkms.ErrBackendNotFound` | No backend has that name (`errors.go:222`) |
| `backend.ErrExportNotSupported` | The backend never releases key material |
| `backend.ErrImportNotSupported` | The backend cannot import |
| `backend.ErrKeyNotExportable` | The key is not marked `Exportable` or `CKA_EXTRACTABLE` |
| `backend.ErrInvalidAlgorithm` | The backend does not accept that wrapping algorithm |
| `backend.ErrNotSupported`, `backend.ErrOperationNotSupported` | Azure and Vault's form of "not supported" |
| `backend.ErrKeyAlreadyExists` | A key with that name already exists |

The `backend.` sentinels are in `pkg/backend/errors.go`. Match them with
`errors.Is`.

## Troubleshooting

- **`invalid algorithm`.** The destination accepts a different set. See
  [Backend support](#backend-support).
- **The material is too large to wrap.** Use a hybrid algorithm.
- **Import fails after a delay.** The parameters have expired. Get new ones and
  wrap again.
- **`key is not exportable`.** Generate the key with `Exportable: true`.
  Existing non-exportable keys cannot be exported.

## See Also

- [`xkmsctl key`](cli/key.md): `get-import-params`, `wrap`, `unwrap`, `import`, `export`, `export-material`, `copy`
- [API parity](api-parity.md): the import and export operations on each transport
- [Crypto backends](../../../docs/crypto-backends/user.md)
