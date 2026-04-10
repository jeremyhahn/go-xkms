# xKey Unified Configuration

xKey uses a single YAML configuration file that merges all subsystem settings (CLI, GUI, FIDO2, TPM, policy, etc.) into one location.

## File Locations

| Priority | Path | Description |
|----------|------|-------------|
| 1 | `~/.config/xkey/xkey.yaml` | User config (XDG standard) |
| 2 | `/etc/xkey/xkey.yaml` | System-wide fallback |
| 3 | Built-in defaults | Applied when no file exists |

If neither file exists, `DefaultConfig()` is returned. This is a valid first-run state.

## Environment Variable Overrides

All config fields can be overridden via environment variables with the `XKEY_` prefix. Nested keys use underscores:

```bash
XKEY_LOG_LEVEL=debug
XKEY_BACKEND_DEFAULT=tpm2
XKEY_GUI_THEME=dark
XKEY_TPM_DEVICE=/dev/tpmrm0
XKEY_FIDO2_ALWAYS_UV=true
```

## Config Sections

```yaml
policy:                  # SO-controlled security policy (see enterprise-mode.md)
backend:                 # Cryptographic backend selection
fido2:                   # FIDO2/WebAuthn authenticator settings
oath:                    # OATH TOTP/HOTP module
phone:                   # Phone-as-a-token backend
xkmsd:                   # xkmsd server connection
tpm:                     # Direct TPM access parameters
password_protection:     # Barrier/encryption at-rest settings
trust:                   # Root certificates and system trust
attestation:             # Attestation authority settings
log:                     # Logging configuration
gui:                     # Desktop application settings
state:                   # Runtime state persisted across restarts
```

### backend

```yaml
backend:
  default: "software"       # software | tpm2 | pkcs11 | phone
  tpm2:
    device: "/dev/tpmrm0"
    simulator: false
    hash: ""
```

### fido2

```yaml
fido2:
  storage: "file"           # Storage backend for credentials
  storage_path: ""          # Custom storage path (empty = default)
  attestation: "packed"     # Attestation format
  device_name: "xKey"       # Device name reported to relying parties
  rpid_hash: false
  always_uv: false          # Require user verification for all operations
  resident_key: false       # Default resident key preference
  conformance_mode: false
  extensions: {}            # Extension enable/disable map
```

### oath

```yaml
oath:
  storage: ""
  storage_path: ""
  algorithm: ""             # HMAC algorithm (SHA1, SHA256, SHA512)
  digits: 0                 # OTP digit count (6 or 8)
  period: 0                 # TOTP period in seconds
```

### phone

```yaml
phone:
  backend: ""
  server_address: ""
  server_protocol: ""
  server_tls_enabled: false
  device_filter: ""
  attestation_policy: ""
```

### xkmsd

```yaml
xkmsd:
  address: ""
  protocol: ""
  tls_enabled: false
  tls_skip_verify: false
  tls_ca_file: ""
  tls_cert_file: ""
  tls_key_file: ""
```

### tpm

```yaml
tpm:
  device: "/dev/tpmrm0"
  encrypt_sessions: true
  platform_pcr_bank: "sha256"
  seal_pcr_bank: ""
  srk_handle: 0
  ek_handle: 0
```

### password_protection

```yaml
password_protection:
  enabled: false
  mode: ""                  # tpm_sealed | aes_software | none
```

### trust

```yaml
trust:
  roots: []                 # Additional root certificate paths
  system_trust: false       # Include system trust store
```

### attestation

```yaml
attestation:
  mode: ""                  # Attestation mode
  ca_cert: ""               # CA certificate path
  ca_key: ""                # CA private key path
```

### log

```yaml
log:
  level: "info"             # trace | debug | info | warn | error
  file: ""                  # Log file path (empty = stderr)
```

### gui

```yaml
gui:
  theme: "system"           # system | light | dark
  auto_tray: true
  start_minimized: false
  notifications: true
  clipboard_timeout: 30     # Seconds (0 = no auto-clear)
  window_width: 1024        # Must be > 0
  window_height: 768        # Must be > 0
  remember_position: false
  window_x: 0
  window_y: 0
  fido2_authenticator_enabled: true
  server:
    address: ""
    protocol: ""
    tls_enabled: false
    tls_skip_verify: false
    tls_ca_file: ""
    auto_connect: false
  auto_unseal:
    enabled: false
    blob_id: ""
    pcrs: []
    pcr_bank: ""
    policy_type: ""
    policy_name: ""
    backend: ""
```

### state

```yaml
state:
  setup_complete: false
  storage_type: ""          # luks | barrier
  barrier_initialized: false
  barrier_strategy: ""      # software | tpm-pcr
```

## Validation Rules

- `log.level` must be one of: trace, debug, info, warn, error
- `backend.default` must be one of: software, tpm2, pkcs11, phone
- `gui.clipboard_timeout` must be >= 0
- `gui.window_width` and `gui.window_height` must be > 0

Validation runs automatically on both load and save.

## Migration from Legacy Config

On first load, xKey checks for legacy config files:

| Legacy File | Format | Contents |
|-------------|--------|----------|
| `~/.xkey/config.yaml` | YAML | CLI settings (backend, FIDO2, TPM, etc.) |
| `~/.config/xkey/gui.json` | JSON | GUI settings (theme, window, server, etc.) |

If the unified config does not exist but legacy files are found, migration runs automatically:

1. Start with `DefaultConfig()` defaults
2. Overlay values from the old CLI YAML (only explicitly set keys)
3. Overlay values from the old GUI JSON (flat fields mapped to nested structure)
4. Save the merged result to `~/.config/xkey/xkey.yaml`

Legacy files are preserved for rollback. Migration runs once and is skipped on subsequent loads.

## Atomic Writes

Both `Save()` and `WritePolicyHMAC()` use atomic write patterns:

1. Write to a temporary file in the same directory
2. `fsync` the temporary file
3. `chmod 0600` the temporary file
4. `rename` (atomic on POSIX) to the target path

This prevents partial writes from corrupting the config on crash or power loss.

## Programmatic Usage

```go
import "github.com/jeremyhahn/go-xkms/xkey/pkg/config"

// Load from default paths with env overlay
cfg, err := config.Load()

// Load from a specific path
cfg, err := config.LoadFromPath("/path/to/xkey.yaml")

// Save to default path
err := config.Save(cfg)

// Save to a specific path
err := config.SaveToPath(cfg, "/path/to/xkey.yaml")

// Run migration (idempotent)
cfg, migrated, err := config.Migrate()
```
