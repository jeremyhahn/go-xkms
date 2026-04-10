# CLI Reference: PIN Commands

PIN commands manage the dual-PIN authentication system used to control access to the barrier and key operations. The model follows the PKCS#11 standard with a Security Officer (SO) PIN for administration and a User PIN for daily operations.

## Commands

### pin set-so

Set the Security Officer PIN. On first call, no current PIN is required. On subsequent calls, the current SO PIN must be provided.

```bash
xkmsctl pin set-so [flags]
```

**Flags:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--strategy` | string | `auto` | PIN strategy: `auto`, `software`, `tpm2`, `pkcs11` |
| `--state-path` | string | platform default | Path to PIN state file |

**Examples:**

```bash
# First-time SO PIN setup (interactive prompt)
xkmsctl pin set-so

# Enter new SO PIN: ********
# Confirm SO PIN: ********
# SO PIN set successfully.

# Change existing SO PIN
xkmsctl pin set-so
# Enter current SO PIN: ********
# Enter new SO PIN: ********
# Confirm SO PIN: ********
# SO PIN changed successfully.
```

---

### pin set-user

Set the User PIN. Requires SO PIN authorization.

```bash
xkmsctl pin set-user [flags]
```

**Flags:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--strategy` | string | `auto` | PIN strategy |
| `--state-path` | string | platform default | Path to PIN state file |

**Examples:**

```bash
xkmsctl pin set-user

# Enter SO PIN: ********
# Enter new User PIN: ********
# Confirm User PIN: ********
# User PIN set successfully.
```

---

### pin change-so

Change the SO PIN. Requires the current SO PIN.

```bash
xkmsctl pin change-so [flags]
```

**Examples:**

```bash
xkmsctl pin change-so

# Enter current SO PIN: ********
# Enter new SO PIN: ********
# Confirm new SO PIN: ********
# SO PIN changed successfully.
```

---

### pin change-user

Change the User PIN. Requires the current User PIN.

```bash
xkmsctl pin change-user [flags]
```

**Examples:**

```bash
xkmsctl pin change-user

# Enter current User PIN: ********
# Enter new User PIN: ********
# Confirm new User PIN: ********
# User PIN changed successfully.
```

---

### pin verify

Verify a PIN without performing any other operation.

```bash
xkmsctl pin verify [flags]
```

**Flags:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--type` | string | `user` | PIN type to verify: `so`, `user` |
| `--output` | string | `text` | Output format: `text`, `json` |

**Examples:**

```bash
# Verify user PIN
xkmsctl pin verify

# Enter User PIN: ********
# PIN verified successfully.

# Verify SO PIN
xkmsctl pin verify --type so

# Enter SO PIN: ********
# PIN verified successfully.

# JSON output (for scripting)
xkmsctl pin verify --output json
# {"valid": true}
```

---

### pin status

Display the current PIN and lockout status.

```bash
xkmsctl pin status [flags]
```

**Flags:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--output` | string | `text` | Output format: `text`, `json` |

**Examples:**

```bash
# Text output
xkmsctl pin status

# PIN Status
#   Strategy:        software
#   SO PIN Set:      true
#   User PIN Set:    true
#   Failed Attempts: 0/5
#   Locked:          false

# JSON output
xkmsctl pin status --output json
# {
#   "strategy": "software",
#   "so_pin_set": true,
#   "user_pin_set": true,
#   "failed_attempts": 0,
#   "max_attempts": 5,
#   "is_locked": false,
#   "lockout_until": null,
#   "recovery_seconds": 0
# }

# Locked status example
xkmsctl pin status

# PIN Status
#   Strategy:        software
#   SO PIN Set:      true
#   User PIN Set:    true
#   Failed Attempts: 5/5
#   Locked:          true
#   Lockout Until:   2025-01-15T10:35:00Z
#   Recovery:        247s
```

---

### pin reset-lockout

Reset the lockout counter. Requires SO PIN authorization.

```bash
xkmsctl pin reset-lockout [flags]
```

**Examples:**

```bash
xkmsctl pin reset-lockout

# Enter SO PIN: ********
# Lockout reset successfully.
```

For PKCS#11 strategy, this command returns an error because hardware token lockout requires vendor-specific reset procedures.

## Workflows

### Initial PIN Setup

```bash
# Step 1: Set SO PIN (administrator)
xkmsctl pin set-so
# Choose a strong SO PIN (minimum 6 characters)

# Step 2: Set User PIN (requires SO PIN)
xkmsctl pin set-user
# SO PIN authorizes User PIN creation

# Step 3: Verify both PINs
xkmsctl pin verify --type so
xkmsctl pin verify --type user

# Step 4: Check status
xkmsctl pin status
```

### Daily Verification and Barrier Unseal

```bash
# The user PIN is typically used to unseal the barrier
xkmsctl pin verify
xkmsctl barrier unseal
```

### Lockout Recovery

```bash
# 1. Check lockout status
xkmsctl pin status
# Locked: true, Recovery: 247s

# Option A: Wait for lockout to expire
sleep 300
xkmsctl pin verify

# Option B: Reset with SO PIN (immediate)
xkmsctl pin reset-lockout
# Enter SO PIN: ********

# 3. Verify recovery
xkmsctl pin status
# Locked: false, Failed Attempts: 0/5
```

### PIN Rotation

```bash
# Rotate SO PIN
xkmsctl pin change-so

# Rotate User PIN
xkmsctl pin change-user
```

## PIN Requirements

- Minimum length: 6 characters
- No maximum length restriction
- Any printable characters allowed

## Lockout Behavior

| Setting | Default | Description |
|---------|---------|-------------|
| Max attempts | 5 | Failed attempts before lockout |
| Base duration | 5 minutes | Initial lockout duration |
| Backoff | Enabled | Exponential backoff on repeated lockouts |
| Max backoff | 1 hour | Backoff cap |

Backoff progression (5-minute base):

```
Attempt 5:  5 min lockout
Attempt 6:  10 min lockout
Attempt 7:  20 min lockout
Attempt 8:  40 min lockout
Attempt 9+: 60 min lockout (cap)
```

A successful verification resets the failed attempt counter to zero.

## Exit Codes

| Code | Description |
|------|-------------|
| 0 | Success |
| 1 | General error (invalid PIN, lockout, etc.) |

Common error messages:

- `pin: PIN must be at least 6 characters` -- PIN too short
- `pin: invalid PIN` -- Wrong PIN
- `pin: locked out due to too many failed attempts` -- Lockout active
- `pin: SO PIN authorization required` -- SO PIN needed for operation
- `pin: PIN not set` -- Operation requires a PIN that has not been set
- `pin: PIN already set, use Change instead` -- Use `change-so` or `change-user`

## Configuration File

PIN settings can be specified in the configuration file:

```yaml
pin:
  strategy: auto           # auto, software, tpm2, pkcs11
  min_length: 6
  state_path: ""           # Override default state file location
  lockout:
    max_attempts: 5
    duration: 5m
    backoff: true
```

## Unified PIN Mode (xkey)

When running the xkey FIDO2 daemon with `--unified-pin` (default: `true`), PIN changes made via CLI commands propagate to the FIDO2 authenticator and PKCS#11 token automatically. The PINCoordinator uses an observer pattern to fan out changes across all registered subsystems.

Standalone CLI commands (without the FIDO2 daemon running) only affect the file-based PIN state. Cross-system synchronization requires the daemon to be active so that the coordinator and its subscribers are wired up.

**Examples:**

```bash
# Start the FIDO2 daemon with cross-system PIN sync (default)
sudo xkey fido2 --unified-pin

# Start with independent PINs per subsystem
sudo xkey fido2 --unified-pin=false
```

See [Unified PIN Architecture](../../architecture/pin-architecture.md) for the full design.

## See Also

- [PIN Management Architecture](../../seal/pin.md)
- [Unified PIN Architecture](../../architecture/pin-architecture.md)
- [Barrier Commands](barrier.md)
- [Configuration Reference](../../configuration/README.md)
