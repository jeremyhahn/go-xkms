# xkey Configuration Guide

This guide covers all configuration options for xkey with detailed explanations and best practices.

## Configuration Methods

xkey is configured via command-line flags. All options have sensible defaults for quick startup.

## Storage Configuration

### Storage Type

The `--storage` flag selects the credential storage backend.

| Value | Description |
|-------|-------------|
| `memory` | In-memory storage (volatile, credentials lost on exit) |
| `file` | File-based storage (persistent across restarts) |

**Memory Storage** (Default):
```bash
sudo xkey fido2 --storage memory
```

Best for:
- Automated testing
- Development environments
- Ephemeral credentials

**File Storage**:
```bash
sudo xkey fido2 --storage file --storage-path /var/lib/xkey
```

Best for:
- Production deployments
- Long-running services
- Credential persistence requirements

### Storage Path

When using file storage, `--storage-path` specifies the directory for credential data.

```bash
sudo xkey fido2 --storage file --storage-path /var/lib/xkey
```

The directory is created if it does not exist. Ensure the xkey process has write permissions.

**Directory Structure**:
```
/var/lib/xkey/
  xkey/
    credentials/     # Stored credentials
    state.json       # Authenticator state (counters, PIN hash)
```

## Encrypted Storage

xkey uses a layered encryption architecture. The barrier is always active and provides application-level AES-256-GCM encryption for all stored values. LUKS is an optional base layer that adds kernel-level full-volume encryption underneath.

### Storage Stack

```
Without LUKS:  App --> Barrier (AES-256-GCM) --> filestorage.Backend --> ~/.xkey/data/
With LUKS:     App --> Barrier (AES-256-GCM) --> luks.Backend --> filestorage.Backend --> ~/.xkey/ (LUKS mount)
```

The barrier always wraps the base backend. When LUKS is selected, the barrier writes into the LUKS mount point, providing two independent encryption layers.

| Layer | Algorithm | Scope | Active |
|-------|-----------|-------|--------|
| Barrier | AES-256-GCM | Per-value with auth tag | Always |
| LUKS | AES-256-XTS | Full volume (dm-crypt) | When `storage_type: luks` |

### Barrier Configuration

The barrier is initialized during the setup wizard. These fields are managed automatically in `gui.json`:

| Field | Type | Description |
|-------|------|-------------|
| `barrier_initialized` | bool | Whether the barrier has been initialized |
| `barrier_strategy` | string | Active sealing strategy (`software`, `tpm2`, etc.) |
| `barrier_auto_unseal_blob_id` | string | TPM-sealed blob ID for automatic barrier unlock |

When `barrier_auto_unseal_blob_id` is set and TPM2 is available, the barrier password is automatically recovered from the TPM on startup. The blob is re-sealed with current PCR values on shutdown to handle kernel/firmware updates.

### LUKS (Optional Base Layer)

LUKS2 provides kernel-level full-volume encryption as an optional base layer:
- AES-256-XTS encryption via dm-crypt
- Password-based key derivation (Argon2id)
- Automatic container detection on startup
- Seamless migration from unencrypted storage
- Secure wipe functionality for data destruction

### Default Paths

| Path | Description |
|------|-------------|
| `~/.xkey` | Unencrypted data directory (mount point when using LUKS) |
| `~/.xkey.luks` | LUKS2 encrypted container file |

### Commands

All LUKS commands require root privileges (`sudo`).

#### seal

Creates a new LUKS container and migrates existing data.

```bash
sudo xkey luks2 seal [--path PATH] [--mount-point PATH] [--size SIZE]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--path` | `~/.xkey.luks` | LUKS container file path |
| `--mount-point` | `~/.xkey` | Mount point for the container |
| `--size` | `100M` | Container size (e.g., `32M`, `100M`, `500M`, `1G`) |

The `seal` command:
1. Creates a LUKS2 container at the specified path
2. Prompts for encryption passphrase (twice for confirmation)
3. Formats the container with ext4 filesystem
4. Migrates existing data from the mount point into the container
5. Locks the container

```bash
# Create encrypted container with defaults
sudo xkey luks2 seal

# Create 500MB container
sudo xkey luks2 seal --size 500M

# Create container at custom path
sudo xkey luks2 seal --path /secure/xkey.luks --size 256M
```

#### unseal

Unlocks an existing LUKS container for use.

```bash
sudo xkey luks2 unseal [--path PATH] [--mount-point PATH]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--path` | `~/.xkey.luks` | LUKS container file path |
| `--mount-point` | `~/.xkey` | Mount point for the container |

The `unseal` command:
1. Prompts for encryption passphrase
2. Sets up loop device
3. Opens the LUKS container
4. Mounts it at the mount point

```bash
# Unlock with defaults
sudo xkey luks2 unseal

# Unlock custom container
sudo xkey luks2 unseal --path /secure/xkey.luks
```

#### lock

Locks an open LUKS container.

```bash
sudo xkey luks2 lock [--path PATH] [--mount-point PATH]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--path` | `~/.xkey.luks` | LUKS container file path |
| `--mount-point` | `~/.xkey` | Mount point for the container |

The `lock` command:
1. Unmounts the container from the mount point
2. Closes the LUKS device
3. Detaches the loop device

```bash
sudo xkey luks2 lock
```

#### migrate

Migrates data to a new or larger LUKS container.

```bash
sudo xkey luks2 migrate [--size SIZE] [--path PATH] [--source-path PATH] [--keep-old] [--wipe] [--wipe-standard STANDARD]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--size` | 2x current | New container size |
| `--path` | same as current | New container path |
| `--source-path` | `~/.xkey.luks` | Source container path |
| `--keep-old` | `false` | Keep old container as backup |
| `--wipe` | `false` | Securely wipe old container after migration |
| `--wipe-standard` | `dod3` | Wipe standard: nist, dod3, dod7 |

The `migrate` command:
1. Locks current container if mounted
2. Renames existing container to .old
3. Creates new container with specified size
4. Copies all data to new container
5. Removes, wipes, or keeps old container based on flags

```bash
# Double the container size (default)
sudo xkey luks2 migrate

# Migrate to 500MB container
sudo xkey luks2 migrate --size 500M

# Migrate to new location
sudo xkey luks2 migrate --path /new/location.luks

# Keep old container as backup
sudo xkey luks2 migrate --keep-old

# Securely wipe old container after migration (DoD 3-pass default)
sudo xkey luks2 migrate --wipe

# NIST single-pass wipe (fastest)
sudo xkey luks2 migrate --wipe --wipe-standard nist

# DoD 7-pass secure wipe (most thorough)
sudo xkey luks2 migrate --wipe --wipe-standard dod7
```

#### wipe

Securely wipes a LUKS container and all its data using industry-standard methods.

```bash
sudo xkey luks2 wipe [--path PATH] [--mount-point PATH] [--standard STANDARD] [--force]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--path` | `~/.xkey.luks` | LUKS container file path |
| `--mount-point` | `~/.xkey` | Mount point for the container |
| `--standard` | `dod3` | Wipe standard: nist, dod3, dod7 |
| `--force` | `false` | Skip confirmation prompt |

The `wipe` command:
1. Locks the container if currently open
2. Prompts for confirmation by typing "DESTROY" (unless `--force`)
3. Overwrites the container using the selected wipe standard
4. Removes the container file

**Warning**: This operation is irreversible. All data in the container will be permanently destroyed.

```bash
# Wipe with confirmation prompt (DoD 3-pass default)
sudo xkey luks2 wipe

# NIST single-pass wipe (fastest)
sudo xkey luks2 wipe --standard nist

# DoD 7-pass secure wipe (most thorough)
sudo xkey luks2 wipe --standard dod7

# Skip confirmation (for scripting)
sudo xkey luks2 wipe --force

# Wipe custom container
sudo xkey luks2 wipe --path /secure/xkey.luks
```

### Wipe Standards

Xkey supports industry-standard wipe methods for secure data destruction:

| Standard | Name | Pattern | Description |
|----------|------|---------|-------------|
| `nist` | NIST SP 800-88 Rev 1 | Random (1 pass) | Single pass of random data. Fastest option, recommended by NIST for modern storage. |
| `dod3` | DoD 5220.22-M 3-pass | Zeros → Ones → Random | U.S. Department of Defense 3-pass standard. Default choice, balanced security. |
| `dod7` | DoD 5220.22-M ECE 7-pass | (Z→O→R) + R + (Z→O→R) | Extended 7-pass variant. Most thorough, slowest. |

**Recommendation:** For most use cases, the default `dod3` provides excellent security. Use `nist` when speed is important. Use `dod7` for maximum assurance on highly sensitive data.

### Auto-Detection on Startup

When xkey starts with file storage, it automatically detects LUKS containers:

1. If `~/.xkey.luks` exists and is not mounted:
   - Prompts for passphrase
   - Unlocks and mounts the container
   - Proceeds with normal startup

2. If `~/.xkey.luks` exists and is already mounted:
   - Uses the mounted container directly

3. If no LUKS container exists:
   - Uses unencrypted storage at `~/.xkey`

To disable auto-detection, use memory storage or specify a different storage path.

### Migration Workflow

**Migrating from unencrypted to encrypted storage:**

```bash
# 1. Stop xkey if running
sudo systemctl stop xkey

# 2. Create encrypted container (migrates existing data)
xkey luks2 seal

# 3. Verify data migrated successfully
ls ~/.xkey/

# 4. Restart xkey
sudo systemctl start xkey
```

**Starting fresh with encrypted storage:**

```bash
# Create container (no existing data to migrate)
xkey luks2 seal --size 64M

# Start xkey with file storage
sudo xkey fido2 --storage file --storage-path ~/.xkey
```

### Security Considerations

- **Passphrase strength**: Use a strong passphrase (16+ characters recommended)
- **Memory security**: Passphrase is cleared from memory after use
- **Lock on idle**: Consider using `xkey luks2 lock` when not in use
- **Backup**: Back up `~/.xkey.luks` file for disaster recovery
- **Container size**: Size cannot be changed after creation; plan accordingly
- **Secure wipe**: Use `xkey luks2 wipe` to securely destroy containers

### systemd Integration

For automatic unlock at boot with systemd, create a credentials file:

```ini
# /etc/systemd/system/xkey.service.d/luks.conf
[Service]
ExecStartPre=/usr/local/bin/xkey luks2 unseal
ExecStopPost=/usr/local/bin/xkey luks2 lock
```

For interactive passphrase entry, use `systemd-ask-password`:

```bash
# In a wrapper script
PASSPHRASE=$(systemd-ask-password "Xkey LUKS passphrase:")
echo "$PASSPHRASE" | xkey luks2 unseal
```

## Device Configuration

### Device Name

The `--name` flag sets the device name reported to the operating system.

```bash
sudo xkey fido2 --name "My Test Xkey"
```

Default: `Xkey Virtual Device (go-xkms)`

This name appears in:
- `lsusb` output
- Browser WebAuthn prompts
- System device managers

### Serial Number

The `--serial` flag sets the device serial number.

```bash
sudo xkey fido2 --serial "XKMSFIDO2-12345678"
```

Default: Auto-generated 16-character hexadecimal string.

Serial numbers should be unique per device instance to avoid conflicts when running multiple virtual authenticators.

## PIN Configuration

### Enabling PIN

The `--pin` flag enables PIN-based user verification.

```bash
sudo xkey fido2 --pin
```

When enabled:
- Relying parties can request user verification via PIN
- PIN must be set before use (via `--set-pin` or WebAuthn PIN management)
- PIN has 8 retry attempts before lockout

### Setting Initial PIN

The `--set-pin` flag sets the initial PIN during startup. Requires `--pin`.

```bash
sudo xkey fido2 --pin --set-pin 123456
```

PIN requirements:
- Minimum 4 characters
- No maximum length enforced by xkey

**Security Note**: Passing PIN on command line may expose it in process lists. For production, consider setting PIN via WebAuthn client after startup.

## Security Officer (SO) PIN Configuration

The SO PIN provides administrative access for protected operations that should not be available to regular users.

### Setting the SO PIN

The SO PIN is **not** a startup flag. It is managed by the `xkey pin` command
group, which prompts for the PIN rather than taking it on the command line, so
it never lands in shell history or the process list:

```bash
xkey pin set-so           # set the SO PIN for the first time
xkey pin change-so        # change an existing SO PIN
xkey pin status           # whether each PIN is set, and retry counts
xkey pin reset-lockout    # clear a lockout
```

`xkey pin set-so` accepts `--data-dir` to target a specific store. If the SO
PIN is already set, it prompts for the current one first.

The SO PIN must be set before user PINs can be configured:

```bash
xkey pin set-so
xkey pin set-user
```

SO PIN requirements (`pkg/authenticator/so_pin.go`):
- Minimum 6 characters, maximum 63 (UTF-8 bytes); 12+ recommended
- Should differ from the user PIN
- Supports alphanumeric and special characters

### SO PIN Retry Limit

The retry limit is a fixed authenticator constant, `DefaultSOPINMaxRetries`,
which is **8**. There is no flag to configure it.

**Warning**: When the SO PIN is locked, administrative operations are
permanently disabled. There is no recovery mechanism.

### Over CTAP2

The same operations are reachable over CTAP2.1 `authenticatorConfig`. Vendor
operations are nested: the subcommand is `AuthConfigCmdVendorPrototype` (0x80),
and the operation is selected by a vendor command ID inside it —
`VendorCmdSetSOPIN` (0x01), `VendorCmdChangeSOPIN` (0x02),
`VendorCmdUnlockWithSOPIN` (0x03), `VendorCmdResetUserPIN` (0x04),
`VendorCmdReplaceAttestKey` (0x05), `VendorCmdGetSOPINRetries` (0x06).

### Protected Operations

When SO PIN is enabled, these operations require SO PIN authentication:

| Operation | Description |
|-----------|-------------|
| Factory Reset | Wipe all credentials and state via `authenticatorReset` (0x07) |
| Replace Attestation Key | Install new attestation certificate via vendor command (0x84) |
| Reset User PIN | Reset locked user PIN via vendor command (0x83) |
| Change SO PIN | Update SO PIN via vendor command (0x81) |

### Key Hierarchy

SO PIN integrates with the key management hierarchy:

```
SO PIN --> Argon2id --> SMK (SO Master Key)
                              |
                              v (unwraps)
                        AK (Admin Key)
                              |
                   +----------+----------+
                   |                     |
                   v                     v (unwraps)
           Attestation Key              CMK (Credential Master Key)
                                              ^
User PIN --> Argon2id --> UMK ----------------+ (also unwraps CMK)
```

**Benefits:**
- User PIN protects daily credential operations
- SO PIN protects administrative operations
- SO can reset user PIN without losing credentials
- Attestation key accessible only via SO PIN

### SO PIN Examples

The SO PIN is set once, before the daemon runs, and is not part of the daemon's
command line in any of these.

**Development with SO PIN:**

```bash
xkey pin set-so                 # prompts for the SO PIN
sudo xkey fido2 \
  --pin --set-pin 123456 \
  --log-level debug
```

**Production with hardware-backed SO:**

```bash
xkey pin set-so
sudo xkey fido2 \
  --backend tpm2 \
  --tpm-device /dev/tpmrm0 \
  --storage file \
  --storage-path /var/lib/xkey \
  --pin \
  --attestation tpm
```

**High-security deployment:**

```bash
xkey pin set-so
sudo xkey fido2 \
  --backend tpm2 \
  --storage file \
  --storage-path /var/lib/xkey \
  --pin \
  --log-file /var/log/xkey.log
```

Because `xkey pin set-so` prompts, a secret file is read by the operator at the
prompt rather than interpolated into a command line where it would reach the
process list and the shell history.

### Security Recommendations

1. **Strong SO PIN**: Use at least 12 characters with mixed case, numbers, and symbols
2. **Different from User PIN**: Never use the same PIN for SO and user
3. **Secure Storage**: Store SO PIN in a secure location (HSM, vault, air-gapped system)
4. **Limited Retries**: The retry limit is fixed at 8 (`DefaultSOPINMaxRetries`) and is not configurable; plan recovery around that
5. **Audit Logging**: Enable logging to track SO PIN operations
6. **Physical Security**: Restrict physical access to systems with SO PIN configured

## User Presence Configuration

### Interactive Mode

The `--interactive` flag enables terminal-based user presence prompts.

```bash
sudo xkey fido2 --interactive
```

In interactive mode:
- User presence requests prompt for ENTER key
- PIN verification prompts for secure PIN entry (hidden input)
- Requires a TTY

**Constraints**:
- Requires stdin attached to a terminal

### User Presence Timeout

The `--timeout` flag sets the timeout for user presence requests.

```bash
sudo xkey fido2 --interactive --timeout 60s
```

Default: `30s`

Accepts Go duration strings: `10s`, `1m`, `1m30s`

In auto-grant mode, this timeout is not used as requests are approved immediately.

## Key Backend Configuration

### Backend Selection

The `--backend` flag selects the cryptographic key backend.

| Value | Description |
|-------|-------------|
| `software` | Software-based keys in memory |
| `tpm2` | Hardware-backed keys via TPM 2.0 |

**Software Backend** (Default):
```bash
sudo xkey fido2 --backend software
```

Features:
- Supports ES256, ES384, ES512, EdDSA algorithms
- Keys exportable in PKCS#8 format
- No hardware requirements

**TPM2 Backend**:
```bash
sudo xkey fido2 --backend tpm2 --tpm-device /dev/tpmrm0
```

Features:
- Hardware-protected keys
- Supports ES256, ES384 algorithms
- Keys cannot be exported
- Requires TPM 2.0 hardware

### TPM Device Path

The `--tpm-device` flag specifies the TPM device when using the tpm2 backend.

```bash
sudo xkey fido2 --backend tpm2 --tpm-device /dev/tpmrm0
```

Default: `/dev/tpmrm0`

Common paths:
- `/dev/tpmrm0` - TPM resource manager (recommended)
- `/dev/tpm0` - Direct TPM access (exclusive, may conflict with other TPM users)

## Attestation Configuration

### Attestation Format

The `--attestation` flag, or `fido2.attestation` in the xkey config file,
selects the attestation statement format. The flag overrides the config file.

| Value | Description | Requirements |
|-------|-------------|--------------|
| `none` | No attestation | Any backend |
| `packed` | Basic attestation, WebAuthn L2 §8.2 | A Security Officer-provisioned attestation key and certificate |
| `tpm` | TPM attestation | Not implemented; falls back to `none` |

**None** (Default):

```bash
sudo xkey fido2 --attestation none
```

Provides maximum privacy. Relying parties cannot verify authenticator identity.

**Packed**:

```bash
sudo xkey fido2 --attestation packed
```

Produces a WebAuthn Level 2 §8.2 packed statement carrying `alg`, a `sig` over
`authData ‖ clientDataHash`, and an `x5c` chain — that is, **Basic attestation**.
Self attestation (packed with no `x5c`) is not produced: §8.2 defines it as a
signature by the *credential* key over a zeroed AAGUID, and it conveys no device
provenance.

This requires provisioning, because the chain must come from an attestation CA
the relying party trusts. There is no built-in root:

1. Set an SO PIN and unlock with it.
2. Run the `replaceAttestKey` vendor command. The device generates a P-256
   attestation key — the private key never leaves it — and returns a PKCS#10
   certificate signing request carrying Subject-OU
   `Authenticator Attestation` and the `id-fido-gen-ce-aaguid` extension.
3. Have your attestation CA issue a certificate for that request. It must meet
   the §8.2.1 requirements: X.509 v3, Subject-C and Subject-O naming the vendor,
   Subject-OU exactly `Authenticator Attestation`, Basic Constraints CA:false,
   and a non-critical `id-fido-gen-ce-aaguid` extension holding this
   authenticator's AAGUID.
4. Install the chain with the `setAttestCert` vendor command: the leaf under
   `attestCert`, any intermediates (leaf-to-root, excluding the root) under
   `attestCertChain`. The device re-runs every check a relying party would, and
   rejects a chain that would fail on arrival.
5. Configure the relying party to trust your root.

Until a certificate is installed the device registers credentials with `none`.
Provisioning is not a prerequisite for registration; it is a prerequisite for
conveying provenance.

#### Where the attestation key lives

The attestation private key is held **only** as two AES-GCM wrapped copies —
one under the Admin Key (SO access) and one under the Credential Master Key
(user access). It is never written to storage in plaintext and never retained
unwrapped in process memory: each signature unwraps it into an mlocked buffer,
signs, and destroys the plaintext. The FIDO2 credential store is
barrier-encrypted only when a barrier is active and falls back to a plain file
otherwise, so storage encryption is not something the attestation identity is
allowed to depend on.

The consequence is that **attestation follows the key hierarchy**: the device
must be unlocked for the wrapped copy to be readable. A device that has not
been unlocked since boot registers with `none` and says so in its logs, rather
than signing with a key it cannot reach. Making attestation available on the
first registration after a reboot is deliberately not solved by keeping a
plaintext copy anywhere; see go-xkms#233.

**TPM**:

The `tpm` format is not implemented. No key backend produces TPM attestation
data, so requesting it falls back to `none`. Use `packed` with a TPM2 credential
backend if you want hardware-held credential keys attested by the device's
provisioned attestation identity.

### AAGUID

xkey reports a single AAGUID across the GUI, the CLI and the headless extension
server: `5150e208-1ab8-5162-bc67-f5e4f24adefa`, which is
UUIDv5(DNS, `xkey.automatethethings.com`). Once attestation carries an `x5c`,
the attestation certificate's `id-fido-gen-ce-aaguid` extension must hold this
value, and it is the value a relying party allowlists.

## Logging Configuration

### Log Level

The `--log-level` flag sets the logging verbosity.

| Level | Description |
|-------|-------------|
| `debug` | Verbose debugging (HID packets, CTAP commands) |
| `info` | Normal operation messages |
| `warn` | Warnings only |
| `error` | Errors only |

```bash
sudo xkey --log-level debug
```

Default: `info`

### Log File

The `--log-file` flag redirects logs to a file.

```bash
sudo xkey --log-file /var/log/xkey.log
```

Default: stdout

When running as a system service, a log file is recommended for troubleshooting.

## Configuration Validation

xkey validates configuration at startup and reports errors:

**Invalid storage type**:
```
Configuration error: invalid storage type
```

**Missing storage path for file storage**:
```
Configuration error: storage path required for file storage
```

**TPM attestation without TPM backend**:
```
Configuration error: TPM attestation requires TPM2 backend
```

## Configuration Examples

### Minimal (Testing)

```bash
sudo xkey
```

### Development with Debug Logging

```bash
sudo xkey fido2 \
  --log-level debug \
  --name "Xkey Dev"
```

### CI/CD Integration

```bash
sudo xkey fido2 \
  --storage memory \
  --pin --set-pin testpin \
  --log-level error
```

### Production Service

```bash
sudo xkey fido2 \
  --storage file \
  --storage-path /var/lib/xkey \
  --log-file /var/log/xkey.log \
  --log-level info \
  --pin
```

### Hardware-Backed Security

```bash
sudo xkey fido2 \
  --backend tpm2 \
  --tpm-device /dev/tpmrm0 \
  --attestation tpm \
  --storage file \
  --storage-path /var/lib/xkey \
  --pin
```

### Interactive Manual Testing

```bash
sudo xkey fido2 \
  --interactive \
  --timeout 60s \
  --log-level info \
  --pin --set-pin 123456
```

## SSH Agent Configuration

### SSH Agent Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--foreground` | `false` | Run in foreground (don't daemonize) |
| `--print-env` | `false` | Print SSH_AUTH_SOCK export for eval |
| `--shell` | `bash` | Shell for print-env (bash, fish, csh) |
| `--socket` | (auto) | Unix socket path |
| `--store` | (auto) | Local key store path (standalone mode) |
| `--require-touch` | `false` | Require touch confirmation for signing |

### SSH Configuration File

```yaml
# ~/.xkey/config.yaml
ssh:
  # Enable SSH agent auto-start with systemd/init
  enabled: true

  # Standalone mode: local key storage path
  # If set, standalone mode is used (xkmsd_url is ignored)
  store_path: ""

  # Server mode: xkmsd connection URL
  # Protocols: unix://, grpc://
  xkmsd_url: ""

  # Backend to use for SSH keys in server mode (software, tpm2, pkcs11)
  backend: "software"

  # Require touch confirmation for signing operations
  require_touch: false

  # Custom socket path (default: $XDG_RUNTIME_DIR/xkey/ssh-agent.sock)
  agent_socket: ""
```

### SSH Environment Variables

| Variable | Description |
|----------|-------------|
| `XKEY_SSH_ENABLED` | Enable SSH agent auto-start |
| `XKEY_SSH_STORE_PATH` | Local key storage path (standalone mode) |
| `XKEY_SSH_XKMSD_URL` | xkmsd connection URL (server mode) |
| `XKEY_SSH_BACKEND` | xkmsd backend to use |
| `XKEY_SSH_REQUIRE_TOUCH` | Require touch confirmation |
| `XKEY_SSH_AGENT_SOCKET` | Custom socket path |

### SSH Mode Selection Logic

1. If `--store` flag or `store_path` config is set: **Standalone mode**
2. Else if `--xkmsd-url` or `xkmsd_url` config is set: **Server mode**
3. Else: **Standalone mode** with default storage path (`~/.xkey/ssh/keys`)

---

## Running as a System Service

xkey does not include built-in daemon mode. Use your operating system's service manager to run xkey as a background service.

### systemd (Linux)

Create `/etc/systemd/system/xkey.service`:

```ini
[Unit]
Description=FIDO2 Authenticator (go-xkms)
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/xkey \
  --storage file \
  --storage-path /var/lib/xkey \
  --log-file /var/log/xkey.log \
  --log-level info \
  --pin
Restart=on-failure
RestartSec=5
User=root
Group=root

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/xkey /var/log/xkey.log
DeviceAllow=/dev/uhid rw
DeviceAllow=/dev/tpmrm0 rw

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable xkey
sudo systemctl start xkey
```

Check status:

```bash
sudo systemctl status xkey
sudo journalctl -u xkey -f
```

### OpenRC (Alpine/Gentoo)

Create `/etc/init.d/xkey`:

```sh
#!/sbin/openrc-run

name="xkey"
description="FIDO2 Authenticator (go-xkms)"
command="/usr/local/bin/xkey"
command_args="--storage file --storage-path /var/lib/xkey --log-file /var/log/xkey.log --pin"
command_background=true
pidfile="/var/run/${RC_SVCNAME}.pid"
```

```bash
sudo chmod +x /etc/init.d/xkey
sudo rc-update add xkey default
sudo rc-service xkey start
```

## OIDC Configuration

### OIDC Token Storage

Tokens are stored in JSON files with `0600` permissions.

| File | Default Path | Description |
|------|--------------|-------------|
| Token store | `~/.xkey/tokens.json` | OIDC tokens |
| Provider config | `~/.xkey/oidc-providers.json` | Saved providers |
| AWS session | `~/.xkey/aws-session.json` | AWS DPoP sessions |
| Logs | `~/.xkey/logs/` | Background refresh logs |
| PIDs | `~/.xkey/pids/` | Background process PIDs |

### OIDC Common Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--token-store` | `~/.xkey/tokens.json` | Token storage path |
| `--auto-refresh` | `0` | Auto-refresh interval (seconds, 0 disables) |
| `--background` | `false` | Run auto-refresh in background |
| `--log-file` | (auto-generated) | Log file for background refresh |
| `--exec` | | Script to execute after login |

### Standard OIDC Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--issuer` | (required) | OIDC provider issuer URL |
| `--client-id` | (required) | OAuth2 client ID |
| `--client-secret` | | OAuth2 client secret |
| `--redirect-url` | `http://localhost:8085/callback` | Callback URL |
| `--scopes` | `openid,profile,email` | Scopes to request |
| `--no-browser` | `false` | Print URL instead of opening browser |

### AWS OIDC Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--region`, `-r` | (required) | AWS region |
| `--profile` | `default` | AWS profile name |
| `--credentials-file` | `~/.aws/credentials` | AWS credentials file |
| `--output`, `-o` | `aws-credentials` | Output mode |
| `--cross-device` | `false` | Enable cross-device authentication |
| `--session-store` | `~/.xkey/aws-session.json` | Session storage path |

### OIDC Output Modes

| Mode | Description |
|------|-------------|
| `aws-credentials` | Write to `~/.aws/credentials` file |
| `json` | Output credentials as JSON to stdout |
| `exec` | Pass credentials to script via environment |
| `none` | Authenticate but don't output credentials |

### OIDC Provider Types

| Type | Description |
|------|-------------|
| `oidc` | Standard OpenID Connect provider with discovery |
| `aws` | AWS Console native login with DPoP |

### OIDC Environment Variables (from --exec)

| Variable | Description |
|----------|-------------|
| `OIDC_PROVIDER` | Provider issuer URL |
| `OIDC_ACCESS_TOKEN` | Access token |
| `OIDC_REFRESH_TOKEN` | Refresh token |
| `OIDC_ID_TOKEN` | ID token (JWT) |
| `OIDC_EXPIRES_AT` | Expiration (RFC3339) |
| `OIDC_EXPIRES_IN` | Seconds until expiration |
| `OIDC_SCOPES` | Granted scopes |
| `OIDC_SUBJECT` | User subject claim |
| `OIDC_EMAIL` | User email |
| `OIDC_NAME` | User name |

### OIDC Configuration Examples

**Add and use Google provider:**
```bash
xkey oidc providers add --name google \
  --issuer https://accounts.google.com \
  --client-id YOUR_CLIENT_ID

xkey oidc login --provider google
```

**Add AWS provider with auto-refresh:**
```bash
xkey oidc providers add --name aws-prod \
  --type aws \
  --region us-east-1 \
  --profile production \
  --auto-refresh 840 \
  --background

xkey oidc login --provider aws-prod
```

**Direct AWS login:**
```bash
xkey oidc aws --region us-east-1 --profile prod --auto-refresh 840 --background
```

---

## Environment Considerations

### Permissions

xkey requires access to:
- `/dev/uhid` - UHID device (root or `input` group membership)
- TPM device (if using tpm2 backend)
- Storage directory (if using file storage)

### Running as Non-Root

```bash
# Add user to input group
sudo usermod -a -G input $USER

# Set UHID device permissions (or use udev rules)
sudo chmod 660 /dev/uhid

# Run without sudo
xkey --storage file --storage-path ~/.xkey
```

### udev Rules

Create `/etc/udev/rules.d/99-uhid.rules`:

```
KERNEL=="uhid", GROUP="input", MODE="0660"
```

Reload rules:
```bash
sudo udevadm control --reload-rules
sudo udevadm trigger
```
