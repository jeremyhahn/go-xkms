# xKey Unified Configuration

> **Status: REFERENCE** · Last verified: 2026-10-13
> The `xkey.yaml` schema, defaults and loader, from `xkey/pkg/config`; cross-cutting, no feature folder.

xKey uses a single YAML configuration file that merges all subsystem settings (CLI, GUI, FIDO2, TPM, policy, etc.) into one location. The schema is the `Config` struct in `xkey/pkg/config/config.go:28-48`; defaults are `DefaultConfig()` (`config.go:399`).

## File Locations

| Priority | Path | Description |
|----------|------|-------------|
| 1 | `~/.config/xkey/xkey.yaml` | User config (XDG standard) |
| 2 | `/etc/xkey/xkey.yaml` | System-wide fallback |
| 3 | Built-in defaults | The base every load starts from |

`Load()` (`xkey/pkg/config/load.go:84`) reads the user file, else the system
file. If neither file exists, the built-in defaults are loaded and the `XKEY_`
environment overrides are still applied and validated on top of them, exactly
as they would be over a file. This is a valid first-run state: the active
configuration is defaults plus environment, never a file-less `DefaultConfig()`
that ignores the environment.

## Partial Sections Merge Over Defaults

A file does not have to be complete. Each section is merged over
`DefaultConfig()` **key by key**: a key the file sets wins, and a key the
file omits keeps its default — whether or not the file names the key's
section. The loader decodes onto a `DefaultConfig()`-initialised struct, so
this holds for every section and every nesting depth.

```yaml
policy:
  min_pin_length: 8     # set: 8
                        # omitted: require_user_pin, require_so_pin,
                        # require_encrypted_storage stay true;
                        # pin_max_attempts stays 5
```

Three consequences worth knowing:

- **An explicit zero value is honoured.** `require_user_pin: false` or
  `pin_max_attempts: 0` is a deliberate setting and is not replaced by the
  default. Omission means "default"; writing the value means "this value".
- **Lists replace, they do not append.** `allowed_backends: [tpm2]` yields
  exactly `[tpm2]`, not the default list with `tpm2` added.
- **The `Require*` policy gates cannot be switched off by omission.**
  Tightening one policy value never silently relaxes the rest of the
  section. Turning a gate off takes an explicit `false`, which is
  visible in the file and, in enterprise mode, covered by the policy HMAC.

## Environment Variable Overrides

Every scalar key, and every list of scalars, can be set by an environment
variable with the `XKEY_` prefix: the key path in upper case with `_` for `.`.
The environment wins over the file, and the file wins over the default. An
empty variable is the same as an absent one. Lists split on commas.

```bash
XKEY_LOG_LEVEL=debug
XKEY_BACKEND_DEFAULT=tpm2
XKEY_BACKEND_TPM2_DEVICE=/dev/tpmrm0
XKEY_GUI_THEME=dark
XKEY_GUI_SERVER_ADDRESS=xkmsd.example.com:8443
XKEY_TPM_DEVICE=/dev/tpmrm0
XKEY_FIDO2_ALWAYS_UV=true
XKEY_TRUST_ROOTS=/etc/xkey/root-a.pem,/etc/xkey/root-b.pem
XKEY_POLICY_ALLOWED_BACKENDS=software,tpm2
```

A value from the environment is validated exactly like one from the file.

Four keys cannot be set from the environment, because one variable cannot
express a map or a list of objects: `backends.local`, `backends.remote`,
`backends.defaults`, and `fido2.extensions`. A variable set for one of them
fails the load rather than being ignored (`load.go:178-181`).

## Config Sections

```yaml
policy:                  # SO-controlled security policy (see enterprise-mode.md)
backend:                 # Cryptographic backend selection
backends:                # Local and remote backend registry entries
fido2:                   # FIDO2/WebAuthn authenticator settings
piv:                     # PIV module backend and storage
oath:                    # OATH TOTP/HOTP module
phone:                   # Phone-as-a-token backend
xkmsd:                   # xkmsd server connection
oidc:                    # Local OAuth2 callback listener for OIDC and AWS login
agent:                   # Agent server bind address
tpm:                     # Direct TPM access parameters
password_protection:     # Password-store protection settings
trust:                   # Root certificates and system trust
attestation:             # Attestation authority settings
log:                     # Logging configuration
gui:                     # Desktop application settings
state:                   # Runtime state persisted across restarts
barrier:                 # Cloud KMS and PKCS#11 barrier strategy settings
device:                  # Paired-device commands
```

### backend

```yaml
backend:
  default: "software"       # software | tpm2 | pkcs11 | phone
  tpm2:
    device: ""
    simulator: false
    hash: ""
```

### backends

```yaml
backends:
  defaults: {}              # capability -> backend ID
  local:                    # default: one entry, the software backend
    - id: "software"
      category: "software"
      name: "Local software"
      # tpm2: {device, simulator}, pkcs11: {library_path, slot_id}, seal_strategy
  remote: []                # id, name, address, protocol, tls_enabled, spki_pin, auto_connect
```

### fido2

```yaml
fido2:
  storage: ""               # Storage backend for credentials (empty = the command's default)
  storage_path: ""          # Custom storage path (empty = default)
  attestation: "packed"     # Attestation format
  device_name: ""           # Device name reported to relying parties (empty = the command's default)
  rpid_hash: false
  always_uv: false          # Require user verification for all operations
  resident_key: false       # Default resident key preference
  conformance_mode: false
  extensions: {}            # Extension enable/disable map
```

`attestation` is the only FIDO2 key with a built-in default
(`config.go:424`).

### piv

```yaml
piv:
  backend: "software"       # software | tpm2 | pkcs11
  storage: ""               # file | tpm2 | pkcs11
  storage_path: ""
  tpm_device: "/dev/tpmrm0"
  pkcs11_library: "/usr/lib/softhsm/libsofthsm2.so"
  pkcs11_token: ""
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
  relay_listen_address: "127.0.0.1:8444"  # xkey device relay binds this (host:port); --listen overrides
  tpm_enrollment: false     # Offer TCG-CSR-IDEVID enrollment of this host's TPM over the phone bridge
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
  server_name: ""           # Names the server on a transport without TLS (Unix socket)
```

### oidc

```yaml
oidc:
  callback_host: "localhost"   # "localhost" = both loopback families; an address = that address; "" = every interface
  callback_port: 8085          # Port of the default redirect URL (1-65535)
```

`xkey oidc login` sends the browser to `http://localhost:<callback_port>/callback`
(`http://<callback_host>:<callback_port>/callback` for an address other than
`localhost` or `""`) and `xkey oidc aws` to
`http://127.0.0.1:<callback_port>/oauth/callback`. `xkey oidc login` listens
on `callback_host` at that port (the loopback pair for `localhost`).
`xkey oidc aws` serves `127.0.0.1:<callback_port>` for `localhost` or
`127.0.0.1`, every interface for `""`, and refuses any other callback host
before opening the browser, because AWS's redirect host is fixed at
`127.0.0.1`. `--callback-host` and `--callback-port` override the section per
command. The desktop GUI's OIDC login reads the same section (it has no
flags) and binds the same way.

### agent

```yaml
agent:
  listen_address: ":9443"   # xkey agent start binds this (host:port; ":port" = every interface)
```

`--listen` on `xkey agent start` overrides the section for one run.

### tpm

```yaml
tpm:
  device: "/dev/tpmrm0"
  platform_pcr_bank: "sha256"
  seal_pcr_bank: ""
  srk_handle: 0
  ek_handle: 0
```

### password_protection

```yaml
password_protection:
  enabled: false
  mode: ""
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
  storage_type: ""          # luks | barrier   (at-rest: LUKS volume vs plain dir)
  storage_engine: "file"    # file | pebble | memory  (go-qrdb storage engine)
  barrier_initialized: false
  barrier_strategy: ""      # Seal strategy ID the barrier uses (e.g. tpm2, passphrase)
  mode: ""                  # personal | enterprise
```

`storage_engine` selects the go-qrdb storage engine backing **all** local
persistence (barrier-sealed component stores, trust store, PIN, PIV, FIDO2,
OATH, passwords). It is orthogonal to `storage_type`, which chooses plain-disk
vs LUKS at-rest encryption for the data directory (`config.go:322-328`).

- `file` (default) — one flat file per key under the data directory
  (`<dir>/<key>`). This is xkey's historical on-disk layout, so switching to it
  (or staying on it) requires **no data migration**.
- `pebble` — an embedded PebbleDB (LSM-tree) database directory.
- `memory` — ephemeral, non-durable; for testing only.

All engines are reached through the go-qrdb SDK; the barrier still encrypts on
top of whichever engine is selected.

### barrier

```yaml
barrier:
  cloud_kms:
    aws_kms:  {region, access_key_id, secret_access_key, session_token, endpoint, key_id}
    gcp_kms:  {project_id, location_id, key_ring_id, credentials_file, ...}
    azure_kv: {vault_url, tenant_id, client_id, client_secret, ...}
    vault:    {address, token, namespace, mount_path, ...}
  pkcs11:
    library: ""
    token: ""
```

Provider settings for barrier seal strategies (`xkey/pkg/config/barrier_cloud.go`,
`barrier_pkcs11.go`); see [seal](../seal/) for how the barrier uses them.

### device

```yaml
device:
  trust_new_devices: false  # Accept a device with no stored expected key; mirrors --trust-new-devices
  scan_timeout: 30s         # Must be > 0
```

## Validation Rules

`Config.Validate()` (`config.go:507`) enforces:

- `log.level` must be one of: trace, debug, info, warn, error
- `gui.clipboard_timeout` must be >= 0
- `gui.window_width` and `gui.window_height` must be > 0
- `oidc.callback_port` must be 1-65535
- `device.scan_timeout` must be > 0
- `agent.listen_address` and `phone.relay_listen_address` (when set) must be `host:port` with a port of 1-65535
- `backend.default` must be one of: software, tpm2, pkcs11, phone
- `piv.backend` must be one of: software, tpm2, pkcs11; `piv.storage` one of: file, tpm2, pkcs11
- `policy.api_explorer_sandbox_policy` must be an allowed value
- `backends.local` / `backends.remote` entries are validated when present
- `state.mode` must be one of: personal, enterprise
- `state.storage_engine` must be one of: file, pebble, memory

Each enum rule applies only when the key is set. Validation runs on load
(`unmarshalAndValidate`, `load.go:250`) and on save (`save.go:38`).

## Atomic Writes

Both `Save()` and `WritePolicyHMAC()` write through `fsutil.WriteFileAtomic`
(`sdk/go/fsutil/fsutil.go:65`):

1. Write to a temporary file in the same directory
2. `fsync` the temporary file
3. `chmod 0600` the temporary file
4. `rename` (atomic on POSIX) to the target path
5. `fsync` the directory

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

// Read the policy section with its verification state. Fails closed with
// ErrPolicyUnverifiable when the directory is sealed and the section cannot
// be authenticated under soPIN (see enterprise-mode.md).
policy, err := config.LoadVerifiedPolicy(cfg, config.ConfigDir(), soPIN)
```
