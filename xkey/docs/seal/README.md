# xKey Seal/Unseal Architecture

The `xkey/pkg/gui/services` seal subsystem provides backend-agnostic data sealing for the xKey desktop application. It manages sealed blobs (JSON files on disk), policy enforcement, and integrates with the auto-unseal and platform policy subsystems. The default backend is TPM 2.0, but any go-xkms backend implementing `types.Sealer` can be registered and used.

## Architecture Overview

```
  Frontend (Svelte)
       |
  Wails Runtime (context + bindings)
       |
  +----+----------+----------+
  |               |          |
SealService  AutoUnseal  PlatformPolicy
  |               |          |
  +---  Sealer Registry  ---+
       |         |         |
  types.Sealer  types.Sealer  types.Sealer
       |         |         |
     TPM2     Software    PKCS#11 / Cloud KMS
```

All three GUI services share a common sealer registry and TPMAccessor. The SealService is the primary entry point for seal/unseal operations; AutoUnsealService and PlatformPolicyService consume it for their specialized workflows.

## Sealer Registry

The SealService maintains a `map[string]types.Sealer` registry that maps backend names to sealer implementations. This provides O(1) backend lookup and complete backend agnosticism.

```go
type Sealer interface {
    Seal(ctx context.Context, data []byte, opts *SealOptions) (*SealedData, error)
    Unseal(ctx context.Context, sealed *SealedData, opts *UnsealOptions) ([]byte, error)
    CanSeal() bool
}
```

### Registration

Backends are registered at startup:

```go
sealSvc := services.NewSealService(storageDir)
sealSvc.SetTPMAccessor(accessor)                       // auto-registers "tpm2"
sealSvc.RegisterSealer("software", softwareSealer)     // register additional
sealSvc.SetDefaultBackend("tpm2")                      // optional, "tpm2" is default
```

Setting the TPMAccessor automatically registers a `tpmSealerAdapter` under the `"tpm2"` key. Additional sealers can be registered for any backend name.

### Backend Tracking

Every `SealedData` returned by `types.Sealer.Seal()` carries a `Backend` field that records which backend performed the seal. On unseal, this field is used to route the request to the correct sealer. Empty backend fields (pre-Phase 3 blobs) fall back to the configured default backend for backward compatibility.

## Policy Types

| Policy Type | Value | TPM Required | Description |
|---|---|---|---|
| None | `none` | No | No additional policy. Data sealed with backend defaults. |
| Password | `password` | No | Argon2id password verification at the xKey application level. |
| Platform Policy | `platform_policy` | Yes | PCR binding via PlatformPolicyService stored digests. |
| Custom PCR | `custom_pcr` | Yes | Direct PCR index selection from the request. |

Policy handlers are dispatched via map-based lookup:

```go
var policyHandlers = map[PolicyType]policyHandler{
    PolicyTypeNone:           handlePolicyNone,
    PolicyTypePassword:       handlePolicyPassword,
    PolicyTypePlatformPolicy: handlePolicyPlatformPolicy,
    PolicyTypeCustomPCR:      handlePolicyCustomPCR,
}
```

Policies `platform_policy` and `custom_pcr` are validated against the backend type. If the resolved backend is not `tpm2`, the operation returns `ErrSealPolicyRequiresTPM`.

## Sealed Blob Storage

Sealed blobs are persisted as individual JSON files in a configurable storage directory. The default location is `~/.xkey/data/sealed/`.

### File Format

Filename: `{id}.sealed.json`

```json
{
  "id": "a1b2c3d4e5f6...",
  "label": "auto-unseal-passphrase",
  "size_bytes": 32,
  "pcr_bound": true,
  "pcrs": [0, 7, 9],
  "pcr_bank": "sha256",
  "policy_type": "platform_policy",
  "password": "",
  "category": "system",
  "sealed_data": {
    "backend": "tpm2",
    "ciphertext": "<base64>",
    "tpm_public": "<base64>",
    "tpm_private": "<base64>"
  },
  "created_at": "2025-07-01T10:30:00Z"
}
```

| Field | Type | Description |
|---|---|---|
| `id` | string | 128-bit random hex identifier |
| `label` | string | Human-readable label |
| `size_bytes` | int | Size of original plaintext |
| `pcr_bound` | bool | True if sealed with PCR policy |
| `pcrs` | []int | PCR indices (if PCR-bound) |
| `pcr_bank` | string | Hash algorithm (`sha256`, `sha384`, `sha512`) |
| `policy_type` | string | One of: `none`, `password`, `platform_policy`, `custom_pcr` |
| `password` | string | Argon2id hash (only for `password` policy) |
| `category` | string | `system` or `user` |
| `sealed_data` | SealedData | Backend-specific sealed payload |
| `created_at` | time.Time | Creation timestamp |

### System vs User Blobs

Blobs are classified by their label:

| Category | Labels |
|---|---|
| `system` | `password_master_key`, `user_pin`, `auto-unseal-passphrase` |
| `user` | All other labels |

Classification uses a map-based lookup:

```go
var systemSealLabels = map[string]struct{}{
    "password_master_key":    {},
    "user_pin":               {},
    "auto-unseal-passphrase": {},
}
```

System blobs are managed by internal services and are typically not displayed to or directly manipulable by the user in the UI.

## SealData Flow

```
  SealRequest
       |
  1. Validate label + data (base64)
       |
  2. Resolve backend (req.Backend -> default)
       |
  3. Look up sealer from registry
       |
  4. Validate policy type vs backend
       |
  5. Dispatch policy handler (build SealOptions)
       |
  6. sealer.Seal(ctx, plaintext, opts)
       |
  7. Generate 128-bit random blob ID
       |
  8. Persist sealed blob JSON (0600)
       |
  SealedBlobEntry (returned to frontend)
```

1. **Validate inputs** -- `label` must be non-empty. `data` must be non-empty base64.
2. **Resolve backend** -- If `SealRequest.Backend` is empty, use `SealService.defaultBackend` (default: `"tpm2"`).
3. **Look up sealer** -- Map lookup in the sealer registry. Returns `ErrSealBackendNotFound` if the backend is not registered.
4. **Validate policy** -- Parse `policy_type` string via `policyTypeMap`. If the policy is TPM-only (`platform_policy` or `custom_pcr`) but the backend is not `tpm2`, return `ErrSealPolicyRequiresTPM`.
5. **Apply policy handler** -- The handler populates `SealOptions` (e.g., `TPMPolicy.PCRSelection` for PCR-based policies). Password policy validates the password is non-empty.
6. **Seal** -- Call the sealer's `Seal` method with the populated options.
7. **Generate ID** -- 16 random bytes, hex-encoded to 32 characters.
8. **Persist** -- Write JSON to `{storageDir}/{id}.sealed.json` with file mode `0600`. If password policy, store the Argon2id hash on the blob.

### SealRequest

```go
type SealRequest struct {
    Label      string `json:"label"`       // required
    Data       string `json:"data"`        // base64-encoded plaintext
    PCRs       []int  `json:"pcrs"`        // optional PCR binding
    PCRBank    string `json:"pcr_bank"`    // default "sha256"
    PolicyType string `json:"policy_type"` // "none"|"password"|"platform_policy"|"custom_pcr"
    Password   string `json:"password"`    // for password policy
    Backend    string `json:"backend"`     // "tpm2", "software", etc. Empty = default
}
```

## UnsealData Flow

```
  UnsealData(id, password)
       |
  1. Load blob by ID
       |
  2. Verify password (if password policy)
       |
  3. Determine backend from SealedData.Backend
       |
  4. Look up sealer from registry
       |
  5. sealer.Unseal(ctx, sealed, opts)
       |
  6. base64-encode plaintext
       |
  Return base64 string
```

1. **Load blob** -- Read `{storageDir}/{id}.sealed.json`. Returns `ErrSealBlobNotFound` if the file does not exist.
2. **Verify password** -- If `policy_type` is `"password"`, require a non-empty password and verify it against the stored Argon2id hash using constant-time comparison.
3. **Determine backend** -- Read `SealedData.Backend` from the blob. Empty values (pre-registry blobs) fall back to `SealService.defaultBackend`.
4. **Look up sealer** -- Same registry lookup as seal.
5. **Unseal** -- Call the sealer's `Unseal` method with default `UnsealOptions`.
6. **Encode** -- Return base64-encoded plaintext to the frontend.

## TPMSealerAdapter

The `tpmSealerAdapter` wraps a shared `TPMAccessor` as a `types.Sealer` to serialize TPM access across all GUI services:

```go
type tpmSealerAdapter struct {
    accessor *TPMAccessor
}

func (a *tpmSealerAdapter) Seal(ctx context.Context, data []byte, opts *types.SealOptions) (*types.SealedData, error) {
    tpm, err := a.accessor.Acquire()
    if err != nil {
        return nil, ErrSealTPMNotAvailable
    }
    defer a.accessor.Release()
    return tpm.Seal(ctx, data, opts)
}
```

The adapter acquires the TPMAccessor's mutex before every operation and releases it after. This prevents concurrent TPM access from multiple Wails-bound service methods.

## Password Hashing

When `PolicyTypePassword` is used, the password is hashed with Argon2id and stored on the blob metadata (not passed to the TPM):

| Parameter | Value |
|---|---|
| Time cost | 1 iteration |
| Memory cost | 64 MiB |
| Parallelism | 4 threads |
| Key length | 32 bytes |
| Salt length | 16 bytes (random) |

Storage format: `hex(salt):hex(hash)`.

Verification uses `crypto/subtle.ConstantTimeCompare` to prevent timing side-channels.

## Configuration

### SealService Fields

| Field | Type | Default | Description |
|---|---|---|---|
| `storageDir` | string | `~/.xkey/data/sealed/` | Absolute path to sealed blob directory |
| `defaultBackend` | string | `"tpm2"` | Backend used when SealRequest.Backend is empty |

### GUIConfigData Fields (auto-unseal related)

| Field | Type | Description |
|---|---|---|
| `AutoUnsealEnabled` | bool | Master enable flag |
| `AutoUnsealBlobID` | string | ID of the sealed passphrase blob |
| `AutoUnsealPCRs` | []int | PCR indices for binding |
| `AutoUnsealPCRBank` | string | Hash algorithm (`sha256`) |
| `AutoUnsealPolicyType` | string | Policy type used for sealing |
| `AutoUnsealPolicyName` | string | Named policy reference |
| `AutoUnsealBackend` | string | Seal backend (`tpm2`, `software`) |

## Error Reference

| Error | Condition |
|---|---|
| `ErrSealTPMNotAvailable` | TPMAccessor is nil or Acquire failed |
| `ErrSealNotSupported` | Sealer's `CanSeal()` returns false |
| `ErrSealInvalidLabel` | SealRequest has empty label |
| `ErrSealInvalidData` | SealRequest has empty data |
| `ErrSealBlobNotFound` | Blob file does not exist or ID is empty |
| `ErrSealStorageFailed` | Filesystem write/read/mkdir failed |
| `ErrSealDecodeFailed` | SealRequest.Data is not valid base64 |
| `ErrSealMarshalFailed` | JSON marshal of blob failed |
| `ErrSealUnmarshalFailed` | JSON unmarshal of blob file failed |
| `ErrSealInvalidPolicyType` | PolicyType string not in `policyTypeMap` |
| `ErrSealPasswordRequired` | Password policy but password is empty |
| `ErrSealPolicyMismatch` | Password verification failed |
| `ErrSealPolicyNotAvailable` | PlatformPolicyService is nil or has no policy |
| `ErrSealStorageDirNotSet` | Storage directory is empty string |
| `ErrSealStorageDirRelative` | Storage directory is not an absolute path |
| `ErrSealBackendNotFound` | Requested backend not in sealer registry |
| `ErrSealPolicyRequiresTPM` | PCR-based policy used with non-TPM backend |

## Security Properties

- **Backend isolation** -- Each sealed blob records its backend. Unsealing always routes to the same backend that sealed the data.
- **Constant-time password verification** -- Argon2id hash comparison uses `crypto/subtle.ConstantTimeCompare`.
- **Restrictive file permissions** -- Blob files are written with `0600`; storage directory created with `0700`.
- **Serialized TPM access** -- The TPMAccessor mutex prevents concurrent TPM operations from multiple UI threads.
- **Panic recovery** -- All Wails-bound methods use `defer/recover` to prevent panics from crashing the GUI application.

## See Also

- [Auto-Unseal Architecture](auto-unseal.md) -- Automatic LUKS volume unlock via sealed passphrases
- [Platform Policy Service](platform-policy.md) -- PCR-based platform policy for seal operations
- [Setup Wizard - Seal Integration](setup-wizard.md) -- First-run wizard orchestration
- [Barrier Encryption Architecture](../../seal/README.md) -- go-xkms core barrier seal subsystem
- [PIN Management](../../seal/pin.md) -- PIN-based authentication for barrier unseal
