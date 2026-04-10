# CLI Reference: Barrier Commands

Barrier commands manage the encrypted storage layer that protects all key material at rest. The barrier must be initialized once and unsealed on each application start before key operations can proceed.

Two sealing strategies are available:

- **password** -- Seal/unseal with a password or secret (default).
- **shamir** -- Split the root key into N shares with a threshold of M required to unseal.

## Commands

### barrier init

Initialize a new barrier with a sealed root key.

```bash
xkmsctl barrier init [flags]
```

**Flags:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--secret` | string | | Password or authorization value for sealing |
| `--shamir` | bool | `false` | Use Shamir secret sharing strategy |
| `--threshold` | int | `3` | Minimum shares required to unseal (Shamir mode) |
| `--shares` | int | `5` | Total number of shares to generate (Shamir mode) |

**Examples:**

```bash
# Initialize with password strategy
xkmsctl barrier init --secret my-secret

# Initialize with Shamir secret sharing (3-of-5)
xkmsctl barrier init --shamir --threshold 3 --shares 5 --secret my-secret

# Initialize with Shamir (2-of-3)
xkmsctl barrier init --shamir --threshold 2 --shares 3 --secret my-secret
```

When using Shamir mode, the command outputs the generated shares. Store each share in a separate secure location -- they will not be displayed again.

---

### barrier unseal

Unseal the barrier to enable cryptographic operations.

```bash
xkmsctl barrier unseal [flags]
```

Exactly one of `--secret`, `--share`, or `--shares` must be provided.

**Flags:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--secret` | string | | Password or authorization value (password mode) |
| `--share` | string | | Single Shamir share for incremental quorum unsealing |
| `--shares` | string | | Comma-separated Shamir shares for batch unsealing |

**Examples:**

```bash
# Unseal with password
xkmsctl barrier unseal --secret my-secret

# Submit a single Shamir share (incremental quorum)
xkmsctl barrier unseal --share "base64-encoded-share-1"
# Output: Share accepted: 1/3 shares submitted (need 2 more)

xkmsctl barrier unseal --share "base64-encoded-share-2"
# Output: Share accepted: 2/3 shares submitted (need 1 more)

xkmsctl barrier unseal --share "base64-encoded-share-3"
# Output: Barrier unsealed successfully (3/3 shares submitted)

# Submit all shares at once (batch mode)
xkmsctl barrier unseal --shares "share1,share2,share3"
```

Incremental unsealing allows separate operators to each submit their share independently without exposing the other shares.

---

### barrier seal

Seal the barrier, zeroing the encryption key in memory.

```bash
xkmsctl barrier seal
```

All cryptographic operations will be blocked until the barrier is unsealed again. This operation is idempotent.

**Examples:**

```bash
# Seal the barrier
xkmsctl barrier seal

# Verify sealed state
xkmsctl barrier status
```

---

### barrier status

Display the current barrier state.

```bash
xkmsctl barrier status [flags]
```

**Flags:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--output` | string | `text` | Output format: `text`, `json` |

**Examples:**

```bash
# Text output
xkmsctl barrier status

# Output:
# Barrier Status:
#   State:           unsealed
#   Strategy:        shamir
#   Hardware Backed: false
#   Initialized At:  2025-01-15T10:30:00Z

# JSON output
xkmsctl barrier status --output json

# Output:
# {
#   "sealed": false,
#   "strategy": "shamir",
#   "hardware_backed": false,
#   "initialized_at": "2025-01-15T10:30:00Z"
# }
```

---

### barrier rekey

Re-split the root key with new Shamir shares.

```bash
xkmsctl barrier rekey [flags]
```

The barrier must be unsealed to perform a rekey. Old shares are invalidated and new shares are generated with the specified parameters.

**Flags:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--threshold` | int | *required* | New minimum shares required to unseal |
| `--shares` | int | *required* | New total number of shares to generate |

**Examples:**

```bash
# Rotate to a new 3-of-5 split
xkmsctl barrier rekey --threshold 3 --shares 5

# Change to a 2-of-3 split
xkmsctl barrier rekey --threshold 2 --shares 3
```

The new shares are displayed once and will not be shown again. Distribute them securely before discarding the old shares.

---

### barrier root-token

Generate a root token by reconstructing the root key from Shamir shares.

```bash
xkmsctl barrier root-token [flags]
```

Requires enough shares to meet the quorum threshold. The root token provides full access to the barrier.

**Flags:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--shares` | string | *required* | Comma-separated Shamir shares |

**Examples:**

```bash
# Generate root token from 3 shares
xkmsctl barrier root-token --shares "share1,share2,share3"
```

---

### barrier shares

Manage Shamir share metadata. The barrier must have been initialized with `--shamir` for these commands.

#### barrier shares list

Display share metadata including total count and required threshold.

```bash
xkmsctl barrier shares list
```

**Examples:**

```bash
xkmsctl barrier shares list

# JSON output
xkmsctl barrier shares list --output json
```

#### barrier shares verify

Verify that the stored Shamir shares are internally consistent.

```bash
xkmsctl barrier shares verify
```

Returns an error if the barrier was not initialized with Shamir mode.

**Examples:**

```bash
xkmsctl barrier shares verify
# Output: Shamir shares verified successfully
```

#### barrier shares delete

Delete a specific share by index or all shares.

```bash
xkmsctl barrier shares delete [index] [flags]
```

**Flags:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--all` | bool | `false` | Delete all Shamir shares |

**Examples:**

```bash
# Delete share at index 2
xkmsctl barrier shares delete 2

# Delete all shares
xkmsctl barrier shares delete --all
```

---

### barrier recovery

Manage recovery keys. Recovery keys provide an alternate mechanism to unseal the barrier when the primary shares or password are unavailable.

#### barrier recovery generate

Generate a set of recovery keys with the specified threshold and count.

```bash
xkmsctl barrier recovery generate [flags]
```

The barrier must be unsealed to generate recovery keys.

**Flags:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--threshold` | int | `2` | Minimum recovery keys required to recover |
| `--keys` | int | `3` | Total number of recovery keys to generate |

**Examples:**

```bash
# Generate 3 recovery keys requiring 2 to recover
xkmsctl barrier recovery generate --threshold 2 --keys 3

# Generate 5 recovery keys requiring 3 to recover
xkmsctl barrier recovery generate --threshold 3 --keys 5
```

The recovery keys are displayed once and will not be shown again. Store each key in a separate secure location.

#### barrier recovery recover

Unseal the barrier using recovery keys when the primary shares or password are unavailable.

```bash
xkmsctl barrier recovery recover [flags]
```

**Flags:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--keys` | string | *required* | Comma-separated recovery keys |

**Examples:**

```bash
# Recover with 2 recovery keys
xkmsctl barrier recovery recover --keys "key1,key2"
```

#### barrier recovery delete

Delete all recovery keys. This cannot be undone.

```bash
xkmsctl barrier recovery delete
```

**Examples:**

```bash
xkmsctl barrier recovery delete
# Output: Recovery keys deleted
```

## Workflows

### First-Time Setup (Password)

```bash
# 1. Initialize with password strategy
xkmsctl barrier init --secret my-secret

# 2. Verify status
xkmsctl barrier status
```

### First-Time Setup (Shamir)

```bash
# 1. Initialize with Shamir 3-of-5
xkmsctl barrier init --shamir --threshold 3 --shares 5 --secret my-secret

# 2. Securely distribute the 5 shares to separate operators

# 3. Verify status
xkmsctl barrier status
```

### Daily Unseal (Password)

```bash
# 1. Unseal barrier
xkmsctl barrier unseal --secret my-secret

# 2. Perform key operations
xkmsctl key list
xkmsctl key sign my-key "data"

# 3. Seal when done (optional, happens on shutdown)
xkmsctl barrier seal
```

### Daily Unseal (Shamir -- Incremental)

```bash
# Operator 1 submits their share
xkmsctl barrier unseal --share "operator1-share"
# Output: Share accepted: 1/3 shares submitted (need 2 more)

# Operator 2 submits their share
xkmsctl barrier unseal --share "operator2-share"
# Output: Share accepted: 2/3 shares submitted (need 1 more)

# Operator 3 submits their share
xkmsctl barrier unseal --share "operator3-share"
# Output: Barrier unsealed successfully (3/3 shares submitted)
```

### Daily Unseal (Shamir -- Batch)

```bash
# Submit all shares at once (e.g., from a secure aggregation script)
xkmsctl barrier unseal --shares "share1,share2,share3"
```

### Share Rotation

```bash
# 1. Ensure barrier is unsealed
xkmsctl barrier status

# 2. Rekey with new parameters
xkmsctl barrier rekey --threshold 3 --shares 5

# 3. Distribute new shares, discard old ones
```

### Emergency Recovery

```bash
# 1. Generate recovery keys while barrier is unsealed
xkmsctl barrier recovery generate --threshold 2 --keys 3

# 2. Store recovery keys in separate secure locations

# Later, if primary shares are lost:

# 3. Recover the barrier
xkmsctl barrier recovery recover --keys "recovery-key1,recovery-key2"

# 4. Immediately rekey to generate new shares
xkmsctl barrier rekey --threshold 3 --shares 5

# 5. Clean up recovery keys
xkmsctl barrier recovery delete
```

### Automated/Scripted Unseal

```bash
#!/bin/bash
# Unseal using environment variable (password mode)
xkmsctl barrier unseal --secret "$XKMS_SECRET"

# Verify unsealed
STATUS=$(xkmsctl barrier status --output json)
SEALED=$(echo "$STATUS" | jq -r '.sealed')
if [ "$SEALED" = "true" ]; then
    echo "ERROR: barrier failed to unseal" >&2
    exit 1
fi
```

## Exit Codes

| Code | Description |
|------|-------------|
| 0 | Success |
| 1 | General error (see stderr for details) |

Common error conditions:

- `barrier init` when already initialized returns `seal: barrier already initialized`
- `barrier unseal` when not initialized returns `seal: barrier not initialized`
- `barrier unseal` with wrong secret returns `seal: invalid credentials`
- `barrier unseal` without `--secret`, `--share`, or `--shares` returns an input error
- `barrier rekey` with invalid threshold/shares returns a parameter error
- `barrier shares verify` on a non-Shamir barrier returns `barrier not using Shamir strategy`
- Any storage operation while sealed returns `seal: barrier is sealed`

## Configuration File

Barrier settings can be specified in the configuration file:

```yaml
seal:
  strategy: auto           # auto, password, shamir
  root_key_path: "sys/barrier/root-key"
  shamir:
    threshold: 3           # Minimum shares required
    shares: 5              # Total shares to generate
```

## See Also

- [Barrier Architecture](../../seal/README.md)
- [PIN Commands](pin.md)
- [Configuration Reference](../../configuration/README.md)
