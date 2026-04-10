# Platform Policy Service

The `PlatformPolicyService` manages PCR-based platform policies for TPM data sealing. A platform policy captures the current TPM PCR values at a point in time and stores them outside the LUKS volume so they are accessible before the encrypted volume is mounted. This policy is used by the SealService for `platform_policy`-type seal operations and by the AutoUnsealService for PCR-bound passphrase sealing.

## Architecture

```
  PlatformPolicyService
       |
  +----+----+
  |         |
TPMAccessor  Policy File (~/.config/xkey/platform.policy)
  |
  TPM PCR Read
  |
  +----+----+----+
  |    |    |    |
 PCR0 PCR7 PCR9  ...   (captured digests)
```

The service reads live PCR values from the TPM via the shared `TPMAccessor` and persists them as a JSON policy file. On verification, it re-reads the same PCRs and compares using constant-time comparison.

## Policy Definition

```go
type PlatformPolicyDefinition struct {
    PCRs      []int          `json:"pcrs"`       // selected PCR indices
    Bank      string         `json:"bank"`        // hash algorithm
    Digests   map[int]string `json:"digests"`     // PCR index -> hex digest
    CreatedAt time.Time      `json:"created_at"`
    UpdatedAt time.Time      `json:"updated_at"`
}
```

Example on-disk representation:

```json
{
  "pcrs": [0, 7, 9],
  "bank": "sha256",
  "digests": {
    "0": "a3f1b2c4d5e6f7...",
    "7": "b1c2d3e4f5a6b7...",
    "9": "c2d3e4f5a6b7c8..."
  },
  "created_at": "2025-07-01T10:30:00Z",
  "updated_at": "2025-07-01T10:30:00Z"
}
```

## Storage Location

The policy file is stored at `~/.config/xkey/platform.policy`, which is outside the LUKS volume. This is intentional: the policy must be readable before the encrypted volume is mounted so that the auto-unseal subsystem can use it during startup.

| Path | Purpose |
|---|---|
| `~/.config/xkey/platform.policy` | Policy definition (outside LUKS) |
| `~/.xkey/data/sealed/*.sealed.json` | Sealed blobs (inside LUKS) |

## Default PCR Selection

| PCR Index | Measures | Description |
|---|---|---|
| 0 | SRTM, BIOS, firmware | Core platform firmware integrity |
| 7 | Secure Boot state | Secure Boot policy and certificates |
| 9 | Boot loader config | GRUB configuration, initramfs |

Default bank: `sha256`. Both the PCR selection and bank are configurable through the API.

## Supported PCR Banks

| Bank | Algorithm |
|---|---|
| `sha1` | SHA-1 (legacy) |
| `sha256` | SHA-256 (default) |
| `sha384` | SHA-384 |
| `sha512` | SHA-512 |

PCR indices are validated to the range 0-23. The bank name is validated against the `validPCRBanks` map.

## Policy Lifecycle

```
  Create
    |
    v
  Read PCR digests from TPM
    |
    v
  Store policy file (atomic write)
    |
    v
  Load into atomic.Pointer
    |
    v
  +------+------+
  |      |      |
Verify  Update  Export
  |      |      |
  v      v      v
Compare  Re-read  tpm2-tools
current  PCRs     JSON format
values
```

### Create

`CreatePolicy(pcrs []int, bank string)` captures live PCR values from the TPM and writes the policy file:

1. Validate PCR selection (non-empty, indices 0-23).
2. Validate PCR bank (must be in `validPCRBanks`).
3. Acquire TPM, read PCR digests, release TPM.
4. Build `PlatformPolicyDefinition` with current timestamps.
5. Atomic file write: write to `.tmp`, then `os.Rename`.
6. Store in `atomic.Pointer[PlatformPolicyDefinition]`.

### Initialize

`Initialize()` loads an existing policy file from disk at service startup. If no file exists, the service starts with no policy (nil pointer). This is not an error.

### Verify

`VerifyPolicy()` compares stored digests against live TPM PCR values:

1. Load policy from `atomic.Pointer`.
2. Read current PCR values from TPM.
3. For each stored digest, hex-decode both stored and live values.
4. Compare using `crypto/subtle.ConstantTimeCompare`.
5. Return `true` if all digests match, `false` if any mismatch.

Drift detection: if the platform firmware, Secure Boot state, or boot configuration has changed since the policy was captured, verification returns `false`. This indicates the auto-unseal passphrase (if PCR-bound) will fail to unseal.

### Update

`UpdatePolicy(pcrs []int, bank string)` re-captures PCR values:

1. Verify an existing policy is configured.
2. Read fresh PCR digests from TPM.
3. Preserve the original `CreatedAt`, update `UpdatedAt`.
4. Atomic save and pointer store.

### Export

`ExportPolicy()` produces tpm2-tools compatible JSON:

```json
{
  "name": "Platform Policy",
  "created_at": "2025-07-01T10:30:00Z",
  "updated_at": "2025-07-01T10:30:00Z",
  "pcr_bank": "sha256",
  "pcr_selections": [0, 7, 9],
  "pcr_digests": {
    "sha256:0": "a3f1b2c4d5e6f7...",
    "sha256:7": "b1c2d3e4f5a6b7...",
    "sha256:9": "c2d3e4f5a6b7c8..."
  }
}
```

Digest keys are formatted as `{bank}:{pcr_index}` for compatibility with tpm2-tools policy tooling.

### Delete

`DeletePolicy()` clears the in-memory pointer and removes the policy file from disk.

## Integration with SealService

When the SealService processes a `PolicyTypePlatformPolicy` request, it calls `PlatformPolicyService.GetPolicyPCRs()` to retrieve the PCR selection and bank, then builds the TPM seal options:

```
  SealService.SealData(req{PolicyType: "platform_policy"})
       |
  handlePolicyPlatformPolicy(s, req, opts)
       |
  s.policyService.GetPolicyPCRs() --> pcrs, bank
       |
  Build TPMSealPolicy{
      PCRSelection: tpm2.TPMLPCRSelection{...},
      HashAlg:      tpm2.TPMAlgSHA256,
  }
       |
  Set opts.TPMPolicy
       |
  Store pcrs + bank on request (for blob metadata)
```

This delegates the PCR selection to the platform policy rather than requiring the caller to specify PCRs directly.

## Integration with AutoUnsealService

The auto-unseal enable flow passes `policyType: "platform_policy"` when a platform policy has been created during setup. This causes the sealed passphrase to be PCR-bound via the platform policy, ensuring the passphrase can only be recovered when the platform boot state matches.

## Status Reporting

```go
type PlatformPolicyStatus struct {
    Configured bool   `json:"configured"`   // policy file exists
    PCRs       []int  `json:"pcrs"`         // selected PCR indices
    Bank       string `json:"bank"`          // hash algorithm
    Valid      bool   `json:"valid"`         // live PCRs match stored digests
    CreatedAt  string `json:"created_at"`
    UpdatedAt  string `json:"updated_at"`
}
```

`GetStatus()` both reports the configuration state and performs a live verification against the TPM. The `Valid` field tells the frontend whether the platform has drifted since the policy was captured.

## Concurrency

The policy definition is stored in an `atomic.Pointer[PlatformPolicyDefinition]`, allowing lock-free reads from any goroutine. Writes (create, update, delete) replace the pointer atomically. File writes use the temp-file-then-rename pattern for crash safety.

## Error Reference

| Error | Condition |
|---|---|
| `ErrPolicyNotConfigured` | No policy loaded (pointer is nil) |
| `ErrPolicyTPMNotAvailable` | TPMAccessor is nil or Acquire failed |
| `ErrPolicyInvalidPCRs` | Empty PCR list or index outside 0-23 |
| `ErrPolicyInvalidBank` | Bank name not in `validPCRBanks` |
| `ErrPolicySaveFailed` | Directory creation, JSON marshal, or file rename failed |
| `ErrPolicyLoadFailed` | File read or JSON unmarshal failed |
| `ErrPolicyVerifyFailed` | PCR read failed or hex decode error during verification |
| `ErrPolicyExportFailed` | JSON marshal of export format failed |

## Security Properties

- **Constant-time comparison** -- Digest verification uses `crypto/subtle.ConstantTimeCompare` to prevent timing side-channels.
- **Atomic file writes** -- Policy files are written to a temp file then renamed to prevent partial writes on crash.
- **Restrictive permissions** -- Policy directory created with `0700`, policy file written with `0600`.
- **Panic recovery** -- All Wails-bound methods use `defer/recover` to prevent panics from crashing the application.
- **Outside LUKS** -- The policy file lives at `~/.config/xkey/` so it is accessible before the encrypted volume is mounted. This is a deliberate trade-off: the policy file contains PCR digests (public measurements) not secrets.

## See Also

- [xKey Seal/Unseal Architecture](README.md) -- SealService and sealer registry
- [Auto-Unseal Architecture](auto-unseal.md) -- Uses platform policy for PCR-bound passphrase sealing
- [Setup Wizard - Seal Integration](setup-wizard.md) -- Platform policy creation during first-run
- [Barrier Encryption Architecture](../../seal/README.md) -- go-xkms core barrier seal subsystem
