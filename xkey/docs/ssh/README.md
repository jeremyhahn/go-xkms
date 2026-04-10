# SSH Agent

xkey includes an SSH agent that supports two operational modes:

1. **Standalone Mode** - Keys stored locally on the filesystem (default)
2. **Server Mode** - Keys managed by xkmsd (TPM2, PKCS#11, or software backends)

This allows SSH authentication with flexible key storage options, from simple local storage to hardware-protected keys with touch confirmation.

## Quick Start

### Standalone Mode (Default)

No external services required. Keys are stored locally.

```bash
# Generate a new Ed25519 key (stored locally)
xkey ssh keys generate --id my-ssh-key

# List SSH keys
xkey ssh keys list

# Export public key for authorized_keys
xkey ssh keys export my-ssh-key >> ~/.ssh/authorized_keys

# Start the SSH agent
eval $(xkey ssh agent start --print-env)

# SSH will now use keys from local storage
ssh user@server
```

### Server Mode (xkmsd)

Keys are managed by xkmsd with support for TPM2, PKCS#11, and software backends.

```bash
# Start xkmsd (see xkmsd documentation)
xkmsd serve

# Generate a new key in xkmsd
xkey ssh keys generate --id my-ssh-key --xkmsd-url unix://xkms.sock

# Start the SSH agent with xkmsd backend
eval $(xkey ssh agent start --print-env --xkmsd-url unix://xkms.sock)

# SSH will now use keys from xkmsd
ssh user@server
```

---

## Operation Modes

### Standalone Mode

In standalone mode, keys are stored in a local directory. This is the default mode and requires no external services.

**Default storage path:** `~/.config/xkey/ssh/keys`

```bash
# Use default storage
xkey ssh keys generate --id my-key

# Use custom storage path
xkey ssh keys generate --id my-key --store /path/to/keys

# List keys from custom storage
xkey ssh keys list --store /path/to/keys
```

**Advantages:**
- No external dependencies
- Simple setup
- Works offline

**Limitations:**
- No hardware key protection
- Keys stored on filesystem

### Server Mode (xkmsd)

In server mode, keys are managed by xkmsd. This provides access to hardware-protected keys (TPM2, PKCS#11) and centralized key management.

**Connection protocols:**
- Unix socket: `unix:///path/to/xkms.sock`
- gRPC over TCP: `grpc://localhost:9090`

```bash
# Unix socket connection
xkey ssh keys list --xkmsd-url unix://xkms-data/xkms.sock

# gRPC over TCP connection
xkey ssh keys list --xkmsd-url grpc://localhost:9090

# Specify backend (software, tpm2, pkcs11)
xkey ssh keys list --xkmsd-url unix://xkms.sock --backend tpm2
```

**Advantages:**
- Hardware key protection (TPM2, HSM)
- Centralized key management
- Non-exportable keys
- Touch confirmation support

---

## Configuration

SSH agent settings can be configured via:
1. Command-line flags
2. Environment variables (prefixed with `XKEY_`)
3. Configuration file (`~/.config/xkey/config.yaml`)

### Configuration File

```yaml
# ~/.config/xkey/config.yaml
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

### Environment Variables

| Variable | Description |
|----------|-------------|
| `XKEY_SSH_ENABLED` | Enable SSH agent auto-start |
| `XKEY_SSH_STORE_PATH` | Local key storage path (standalone mode) |
| `XKEY_SSH_XKMSD_URL` | xkmsd connection URL (server mode) |
| `XKEY_SSH_BACKEND` | xkmsd backend to use |
| `XKEY_SSH_REQUIRE_TOUCH` | Require touch confirmation |
| `XKEY_SSH_AGENT_SOCKET` | Custom socket path |

### Mode Selection Logic

1. If `--store` flag or `store_path` config is set: **Standalone mode**
2. Else if `--xkmsd-url` or `xkmsd_url` config is set: **Server mode**
3. Else: **Standalone mode** with default storage path

---

## Commands

### xkey ssh agent start

Start the SSH agent daemon.

```
xkey ssh agent start [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--foreground` | `false` | Run in foreground (don't daemonize) |
| `--print-env` | `false` | Print SSH_AUTH_SOCK export for eval |
| `--shell` | `bash` | Shell for print-env (bash, fish, csh) |
| `--socket` | (auto) | Unix socket path |
| `--store` | (auto) | Local key storage path (standalone mode) |
| `--xkmsd-url` | (config) | xkmsd server URL (server mode) |
| `--backend` | (config) | xkmsd backend to use (server mode) |
| `--require-touch` | (config) | Require touch confirmation |

**Examples:**

```bash
# Standalone mode (default)
eval $(xkey ssh agent start --print-env)

# Standalone mode with custom storage
eval $(xkey ssh agent start --print-env --store /path/to/keys)

# Server mode via Unix socket
eval $(xkey ssh agent start --print-env --xkmsd-url unix://xkms.sock)

# Server mode via gRPC over TCP
eval $(xkey ssh agent start --print-env --xkmsd-url grpc://localhost:9090)

# Server mode with TPM2 backend
eval $(xkey ssh agent start --print-env --xkmsd-url unix://xkms.sock --backend tpm2)

# Start with touch confirmation required
xkey ssh agent start --require-touch
```

### xkey ssh agent stop

Stop the running SSH agent.

```
xkey ssh agent stop
```

### xkey ssh agent status

Show the status of the SSH agent.

```
xkey ssh agent status
```

**Example output:**
```
SSH agent: running
  Socket: /run/user/1000/xkey/ssh-agent.sock
  PID:    12345

To use: export SSH_AUTH_SOCK=/run/user/1000/xkey/ssh-agent.sock
```

---

### xkey ssh keys list

List all SSH-compatible keys.

```
xkey ssh keys list [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--store` | (auto) | Local key storage path (standalone mode) |
| `--backend` | (config) | xkmsd backend to use (server mode) |

**Example output:**
```
SSH Keys (2):

  ID:          my-ssh-key
  Type:        ed25519
  Algorithm:   ssh-ed25519
  Fingerprint: SHA256:abc123...

  ID:          work-key
  Type:        rsa
  Algorithm:   ssh-rsa
  Fingerprint: SHA256:xyz789...
```

### xkey ssh keys generate

Generate a new SSH key.

```
xkey ssh keys generate [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--id` | (required) | Key identifier |
| `--type` | `ed25519` | Key type (ed25519, rsa, ecdsa) |
| `--bits` | (varies) | Key size for RSA (2048, 3072, 4096) |
| `--curve` | `P-256` | Curve for ECDSA (P-256, P-384, P-521) |
| `--store` | (auto) | Local key storage path (standalone mode) |
| `--backend` | (config) | xkmsd backend to use (server mode) |

**Examples:**

```bash
# Generate Ed25519 key in standalone mode (recommended)
xkey ssh keys generate --id my-key

# Generate RSA 4096-bit key
xkey ssh keys generate --id my-rsa-key --type rsa --bits 4096

# Generate ECDSA P-384 key
xkey ssh keys generate --id my-ecdsa-key --type ecdsa --curve P-384

# Generate key in custom local store
xkey ssh keys generate --id my-key --store /path/to/keys

# Generate key in xkmsd TPM2 backend
xkey ssh keys generate --id tpm-key --xkmsd-url unix://xkms.sock --backend tpm2
```

### xkey ssh keys import

Import an existing SSH private key.

```
xkey ssh keys import [file] [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--id` | (filename) | Key identifier |
| `--store` | (auto) | Local key storage path (standalone mode) |
| `--backend` | (config) | xkmsd backend to use (server mode) |

**Examples:**

```bash
# Import into local storage (standalone mode)
xkey ssh keys import ~/.ssh/id_ed25519 --id my-imported-key

# Import into xkmsd
xkey ssh keys import ~/.ssh/id_rsa --id work-key --xkmsd-url unix://xkms.sock
```

### xkey ssh keys delete

Delete an SSH key.

```
xkey ssh keys delete [key-id] [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--force` | `false` | Skip confirmation prompt |
| `--store` | (auto) | Local key storage path (standalone mode) |
| `--backend` | (config) | xkmsd backend to use (server mode) |

**Examples:**

```bash
# Delete with confirmation
xkey ssh keys delete my-key

# Delete without confirmation
xkey ssh keys delete my-key --force
```

### xkey ssh keys export

Export an SSH public key in OpenSSH format.

```
xkey ssh keys export [key-id] [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--store` | (auto) | Local key storage path (standalone mode) |
| `--backend` | (config) | xkmsd backend to use (server mode) |

**Examples:**

```bash
# Print public key
xkey ssh keys export my-key

# Save to file
xkey ssh keys export my-key > ~/.ssh/id_xkey.pub

# Append to authorized_keys
xkey ssh keys export my-key >> ~/.ssh/authorized_keys

# Copy to remote server
xkey ssh keys export my-key | ssh user@server 'cat >> ~/.ssh/authorized_keys'
```

---

## Git SSH Signing

### xkey ssh git-config

Configure git to use an xkey SSH key for commit and tag signing.

```
xkey ssh git-config [key-id] [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--global` | `false` | Configure git globally instead of local repository |
| `--dry-run` | `false` | Show commands that would be run without executing |
| `--no-auto-sign` | `false` | Don't enable automatic commit/tag signing |

This command:
1. Exports the public key to `~/.ssh/xkey-<key-id>.pub`
2. Configures git to use SSH signing format (`gpg.format = ssh`)
3. Sets the signing key (`user.signingkey`)
4. Enables automatic commit/tag signing (unless `--no-auto-sign`)

**Examples:**

```bash
# Configure local repository to sign with 'my-key'
xkey ssh git-config my-key

# Configure globally (all repositories)
xkey ssh git-config my-key --global

# Preview commands without executing
xkey ssh git-config my-key --dry-run

# Configure without auto-signing
xkey ssh git-config my-key --no-auto-sign
```

**Usage with xkey SSH agent:**

```bash
# 1. Start the SSH agent
eval $(xkey ssh agent start --print-env)

# 2. Configure git for signing
xkey ssh git-config my-ssh-key --global

# 3. Make signed commits
git commit -m "Signed commit"

# 4. Verify signatures
git log --show-signature
```

**Verification:**

After configuration, you can verify the setup:

```bash
# Show git signing configuration
git config --list | grep -E '(gpg|signing)'

# Test signing a commit
git commit --allow-empty -m "Test signed commit"
git log -1 --show-signature
```

---

## Systemd Integration

### User Service

Create `~/.config/systemd/user/xkey-ssh-agent.service`:

```ini
[Unit]
Description=Xkey SSH Agent
After=xkmsd.service

[Service]
Type=simple
ExecStart=/usr/local/bin/xkey ssh agent start --foreground
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
```

Enable and start:

```bash
systemctl --user daemon-reload
systemctl --user enable --now xkey-ssh-agent
```

### Shell Integration

Add to `~/.bashrc` or `~/.zshrc`:

```bash
# Use xkey SSH agent if running
if [ -S "$XDG_RUNTIME_DIR/xkey/ssh-agent.sock" ]; then
    export SSH_AUTH_SOCK="$XDG_RUNTIME_DIR/xkey/ssh-agent.sock"
fi
```

Or for fish shell, add to `~/.config/fish/config.fish`:

```fish
# Use xkey SSH agent if running
if test -S "$XDG_RUNTIME_DIR/xkey/ssh-agent.sock"
    set -gx SSH_AUTH_SOCK "$XDG_RUNTIME_DIR/xkey/ssh-agent.sock"
end
```

---

## Touch Confirmation

When `require_touch` is enabled, signing operations require user confirmation. This provides YubiKey-style touch-to-sign security for SSH authentication.

```bash
# Enable touch confirmation
xkey ssh agent start --require-touch

# Or in config.yaml
ssh:
  require_touch: true
```

When a signing request comes in:
1. A desktop notification appears (via D-Bus on Linux)
2. Run `xkey touch` to approve the signing operation
3. SSH authentication proceeds

---

## Security Considerations

1. **Socket Permissions**: The agent socket is created with mode 0600 (owner read/write only)

2. **Key Storage**:
   - Standalone mode: Keys stored on filesystem with 0600 permissions
   - Server mode: Keys stored in xkmsd (optionally hardware-protected)

3. **Touch Confirmation**: Enable `require_touch` for high-security environments to prevent unauthorized signing.

4. **Backend Selection**: Use `tpm2` backend in server mode for hardware-protected keys that cannot be exported.

5. **PID Files**: The agent writes a PID file next to the socket for process management.

---

## Troubleshooting

### Agent not starting

```bash
# Check if socket already exists
ls -la $XDG_RUNTIME_DIR/xkey/

# Run in foreground to see error messages
xkey ssh agent start --foreground

# Check local store path exists
ls -la ~/.config/xkey/ssh/keys/

# Check xkmsd connection (server mode)
xkey ssh keys list --xkmsd-url unix://xkms.sock
```

### SSH not finding agent

```bash
# Verify SSH_AUTH_SOCK is set
echo $SSH_AUTH_SOCK

# Check agent status
xkey ssh agent status

# Test agent connection
ssh-add -l
```

### No keys showing

```bash
# List keys directly (standalone mode)
xkey ssh keys list

# List keys from specific store
xkey ssh keys list --store ~/.config/xkey/ssh/keys

# List keys from xkmsd (server mode)
xkey ssh keys list --xkmsd-url unix://xkms.sock
xkey ssh keys list --xkmsd-url unix://xkms.sock --backend tpm2
```

### Touch not working

```bash
# Check if touch handler is available
xkey touch  # Should show "no pending request" if agent is idle

# Verify D-Bus notifications are working
notify-send "Test" "Notification test"
```
