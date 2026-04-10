# xkey Auto-Unseal

Auto-unseal enables xkey to start unattended by retrieving sealed credentials from the PlatformStore during boot. This eliminates the need for manual password entry when the sealing backend supports non-interactive authentication (TPM2 PCR state, HSM presence, cloud IAM, etc.).

## How Auto-Unseal Works

Auto-unseal combines two layers:

1. **Barrier** -- Protects the xkey data directory with AES-256-GCM encryption. A root key is sealed using the best available strategy.
2. **PlatformStore** -- Stores named secrets (PINs, passphrases) sealed by the PlatformSealer. When the sealing backend supports automatic authentication, these secrets can be retrieved without user interaction.

### PlatformStore-Based Auto-Unseal Flow

```
                     Boot
                       |
                       v
            +--------------------+
            |  xkmsd starts      |
            +--------------------+
                       |
                       v
            +--------------------+
            |  Barrier unseal    |
            |  (auto or manual)  |
            +--------------------+
                       |
                       v
            +--------------------+
            |  PlatformStore     |
            |  available         |
            +--------------------+
                       |
         +-------------+-------------+
         |             |             |
         v             v             v
   +----------+  +----------+  +----------+
   | Get LUKS |  | Get User |  | Get HSM  |
   |passphrase|  |   PIN    |  |   PIN    |
   +----------+  +----------+  +----------+
         |             |             |
         v             v             v
   +----------+  +----------+  +----------+
   | Unseal   |  | Unlock   |  | Unlock   |
   |  LUKS    |  | password |  | PKCS#11  |
   |container |  |  store   |  |  token   |
   +----------+  +----------+  +----------+
                       |
                       v
            +--------------------+
            |  xkey daemon ready |
            +--------------------+
```

## Backend-Specific Auto-Unseal Capabilities

Each sealing strategy has different auto-unseal characteristics:

### TPM2 (PCR-Bound Sealing)

The TPM2 strategy seals secrets bound to specific PCR values. On boot, if the system state matches the recorded PCR policy, the TPM automatically releases the sealed data without user interaction.

- **Auto-unseal**: Yes, when PCR state matches.
- **Requires password**: No (unless PCR policy fails, then falls through to software).
- **Reseal required**: After kernel/firmware updates that change PCR values.
- **Hardware-backed**: Yes.

### PKCS#11 / HSM

The PKCS#11 strategy seals secrets using an HSM token's wrapping key. The token must be physically present and the PIN provided. The PlatformStore can hold the HSM PIN under `platform/pkcs11-pin` for automated access.

- **Auto-unseal**: Partial. Token must be present; PIN retrieved from PlatformStore if stored.
- **Requires password**: PIN required for first HSM access; PlatformStore can cache it.
- **Hardware-backed**: Yes.

### Software (Argon2id / PBKDF2)

The software strategy derives a key from a password using Argon2id (or PBKDF2 in FIPS mode) and encrypts the root key with AES-256-GCM.

- **Auto-unseal**: No. Requires the password interactively or piped from stdin.
- **Requires password**: Yes, always.
- **Hardware-backed**: No.

### Cloud KMS (AWS, GCP, Azure, Vault)

Cloud KMS strategies delegate sealing to the cloud provider's key management service. Authentication uses IAM roles, service accounts, or managed identity.

- **Auto-unseal**: Yes, when IAM/identity is configured (instance profiles, workload identity, managed identity).
- **Requires password**: No (authentication is external).
- **Hardware-backed**: Yes (cloud HSM-backed keys).

## Auto-Unseal Comparison

| Strategy | Auto-Unseal | Password Required | Hardware | Reseal Trigger |
|----------|:-----------:|:-----------------:|:--------:|---------------|
| TPM2 | Yes (PCR match) | No | Yes | Firmware/kernel update |
| PKCS#11 | Partial | PIN from PlatformStore | Yes | Token replacement |
| AWS KMS | Yes (IAM) | No | Yes | Key rotation |
| GCP KMS | Yes (IAM) | No | Yes | Key rotation |
| Azure KV | Yes (Identity) | No | Yes | Key rotation |
| Vault | Yes (Token/AppRole) | No | Yes | Token renewal |
| Software | No | Yes (always) | No | Password change |

## Barrier + PlatformStore Integration

The Barrier and PlatformStore serve complementary roles:

- **Barrier** encrypts the entire xkey data directory. It implements `storage.Backend`, so anything stored through it is transparently encrypted with AES-256-GCM. The barrier ALWAYS wraps the base backend, whether that base is a plain filesystem or a LUKS volume.
- **PlatformStore** sits on top of a `storage.Backend` (which can be a Barrier) and provides a named-secret API with automatic seal/unseal routing.

When both are active, the data protection chain is:

```
Without LUKS:
Secret --> PlatformSealer.Seal() --> Barrier.Put() --> AES-256-GCM --> file backend

With LUKS:
Secret --> PlatformSealer.Seal() --> Barrier.Put() --> AES-256-GCM --> luks.Backend --> LUKS volume
```

When LUKS is active, this provides triple protection: the PlatformSealer encrypts the secret with the backend-specific mechanism (TPM, HSM, cloud KMS), the Barrier encrypts the sealed blob with AES-256-GCM, and LUKS encrypts the entire volume with AES-256-XTS.

### Barrier Auto-Unseal via TPM

When the barrier uses the software sealing strategy, it requires a password. The `BarrierAutoUnsealBlobID` configuration field enables automatic barrier unlock by storing the barrier password as a TPM-sealed blob.

```
Boot
  |
  v
BarrierAutoUnsealBlobID set?
  |
  +-- Yes: SealService.UnsealData(blobID) --> barrier password
  |         |
  |         +-- Success: Barrier.Unseal(password) --> barrier ready
  |         |
  |         +-- Failure (PCR mismatch): fall through to manual prompt
  |
  +-- No: Prompt user for barrier password
```

On shutdown, the auto-unseal blob is re-sealed with current PCR values. This handles kernel or firmware updates that change the measured boot state, so the blob remains valid on next boot.

## Boot Sequence: Mode A vs Mode B Auto-Unseal

### Mode A: Per-Operation Auto-Unseal

In `pin_per_operation` mode, each password decryption requires a PIN. Auto-unseal retrieves the PIN from PlatformStore and supplies it for every `GetDecrypted` call.

```
Boot --> PlatformStore.Get("platform/user-pin") --> PIN
Each request --> PINAccessStore.GetDecrypted(name, PIN) --> decrypted password
```

The PIN is held in memory for the lifetime of the process. This provides the strongest access control: if the process is compromised, the attacker must also compromise the in-memory PIN.

### Mode B: Session Auto-Unseal

In `session_based` mode, auto-unseal retrieves the PIN from PlatformStore and calls `SessionStore.Unlock(pin)` once. All subsequent `GetDecrypted` calls succeed without additional PIN verification until `Lock()` is called.

```
Boot --> PlatformStore.Get("platform/user-pin") --> PIN
        SessionStore.Unlock(PIN) --> unlocked
Each request --> SessionStore.GetDecrypted(name) --> decrypted password
Shutdown --> SessionStore.Lock()
```

This is more efficient for high-throughput scenarios. The session lock provides a clear boundary.

## CLI: Barrier Commands

The `xkey barrier` command manages the Barrier lifecycle:

```bash
# First-time setup: generate root key, seal with best strategy
xkey barrier init
xkey barrier init --strategy software
xkey barrier init --strategy tpm2
xkey barrier init --data-dir /secure/xkey

# Unseal the barrier (interactive or piped password)
xkey barrier unseal
echo "mypassword" | xkey barrier unseal

# Seal the barrier (lock all operations)
xkey barrier seal

# Show barrier status
xkey barrier status
xkey barrier status --json
```

### Barrier Data Directory Resolution

Priority (highest to lowest):

1. `--data-dir` flag
2. `XKEY_DATA_DIR` environment variable
3. Viper config `data_dir`
4. `~/.xkey` (default)

### Barrier Status Fields

| Field | Description |
|-------|-------------|
| `initialized` | Whether the barrier has been initialized with a root key |
| `sealed` | Whether the barrier is currently sealed (locked) |
| `strategy` | Which sealing strategy protects the root key |
| `hardware_backed` | Whether the strategy uses dedicated cryptographic hardware |
| `data_dir` | Path to the data directory |
| `root_key_path` | Full path to the sealed root key blob |

## Security Considerations

- **TPM PCR binding** provides strong local attestation but requires reseal after system updates that change measured boot state.
- **Software strategy** should only be used when no hardware backend is available. The password is the sole protection for the root key.
- **Cloud KMS** requires network connectivity at boot time. Plan for graceful degradation if the cloud endpoint is unreachable.
- **Shamir secret sharing** is available for barrier initialization, splitting the root key into M-of-N shares for quorum-based unsealing.
- **Root key zeroing** -- After deriving the DEK, the root key is immediately zeroed from memory using `mem.Zero()`.
- **DEK zeroing** -- When the barrier is sealed, the DEK is zeroed and all subsequent operations return `ErrSealed`.

## Related Packages

- `pkg/seal/barrier.go` -- Barrier implementation (AES-256-GCM transparent encryption)
- `pkg/seal/platform_store.go` -- SealedPlatformStore (named-secret API)
- `pkg/seal/platform_sealer.go` -- PlatformSealer (multi-strategy seal routing)
- `pkg/seal/strategy.go` -- SealingStrategy interface
- `pkg/seal/strategy_tpm2.go` -- TPM2 sealing strategy
- `pkg/seal/strategy_pkcs11.go` -- PKCS#11 sealing strategy
- `pkg/seal/strategy_cloud.go` -- Cloud KMS sealing strategy
- `pkg/seal/strategy_software.go` -- Software (Argon2id/PBKDF2) sealing strategy

## See Also

- [Platform Store](platform-store.md) -- PlatformStore CLI and API reference
- [Password Guide](password.md) -- Static password management and access modes
- [LUKS Guide](luks.md) -- Encrypted container management
- [Configuration](configuration.md) -- All xkey configuration options
- [Setup and Unlock Flow](../architecture/setup-and-unlock-flow.md) -- Backend execution flow with TPM provisioning and auto-unseal
