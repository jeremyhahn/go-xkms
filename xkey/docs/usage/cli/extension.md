# Browser Extension

The xKey browser extension provides secure credential autofill for web browsers. It communicates with the xKey desktop application (or headless server) via a Unix socket IPC protocol, enabling password and TOTP code filling directly into web forms.

## Architecture

### Communication Path

```
Chrome Extension  <-->  Native Messaging Host  <-->  IPC Server (xkey GUI or headless)
   (MV3 SW)             (stdin/stdout)               (Unix socket)
```

The browser launches the native messaging host process (`xkey extension host`) via Chrome's native messaging API. The host bridges the browser's stdin/stdout pipe to the xKey IPC server over a Unix domain socket. All messages after the initial handshake are encrypted end-to-end.

### Two-Layer Security Model

| Layer | Mechanism |
|-------|-----------|
| Transport | Chrome native messaging (stdin/stdout) to Unix socket IPC |
| Channel security | X25519 ECDH + HKDF-SHA256 + AES-256-GCM session encryption |
| Identity binding | Ed25519 long-lived key per browser profile |
| Pairing ceremony | 6-digit code displayed in xKey GUI, entered in extension |
| Replay protection | Monotonic nonce counter per session direction |
| Browser binding | Parent process verification via `/proc/$PPID/exe` |

### Session Encryption

Every native messaging session begins with an X25519 ECDH handshake:

1. Extension generates an ephemeral X25519 keypair
2. Extension sends `{type: "handshake", pubkey: "<base64>"}` via native messaging
3. Host generates its own ephemeral X25519 keypair
4. Host performs ECDH, derives two directional AES-256-GCM keys via HKDF-SHA256
5. Host responds `{type: "handshake_ok", pubkey: "<base64>"}`
6. All subsequent messages are encrypted: `{type: "encrypted", nonce: <uint64>, ciphertext: "<base64>"}`

Key derivation uses directional info strings (`xkey-nativemsg-v1-send` / `xkey-nativemsg-v1-recv`) with lexicographic public key comparison to assign send/recv roles. The nonce is an 8-byte little-endian counter (starting at 1) padded to 12 bytes for GCM. Messages with nonces less than or equal to the last accepted nonce are rejected.

### Extension Pairing

First-time setup requires a pairing ceremony:

1. Extension generates an Ed25519 keypair (stored in `chrome.storage.local`)
2. Extension includes its Ed25519 public key and origin in the handshake
3. Host responds `{type: "handshake_pair", pairing_required: true}`
4. xKey GUI displays a 6-digit verification code (expires in 5 minutes)
5. User enters the code in the extension popup
6. Host stores the extension's Ed25519 public key + origin at `~/.xkey/pairing.json`

Subsequent connections use Ed25519 signature verification:

- Extension signs `SHA-256(X25519_ephemeral_pubkey || origin || "xkey-ext-v1")` with its Ed25519 private key
- Host verifies the signature against the stored public key and origin
- Mismatched keys or origins are rejected

### Autofill IPC Protocol

After the encrypted session is established, the extension sends IPC messages as encrypted payloads. The autofill protocol supports these actions:

| Action | Description | Required Fields |
|--------|-------------|-----------------|
| `search` | Search credentials by domain | `domain` |
| `get` | Get credential + password for fill | `id`, `challenge` (optional) |
| `totp` | Get TOTP code for domain | `domain` |
| `totp_by_id` | Get TOTP by account ID | `id` |
| `status` | Check app lock state + policy | none |
| `policy` | Get current policy | none |

When CTAP2 authentication is enabled, the `get` action requires a `challenge` field (base64-encoded 32-byte random value). The response includes an `AutofillAssertion` containing authenticator data and signature for the extension to verify.

### Wire Format

Native messaging uses Chrome's length-prefixed format:

```
[4-byte little-endian uint32 length][JSON payload]
```

Maximum message size is 1 MB (Chrome's limit). The native host name is `com.automatethethings.xkey`.

## CLI Usage

### Native Messaging Setup

Install the native messaging manifest so the browser can launch xKey:

```bash
# Install for all supported browsers
xkey extension install

# Install for Chrome only
xkey extension install chrome

# Install for Firefox only
xkey extension install firefox

# Install with custom Chrome extension origin (unpacked extension)
xkey extension install chrome --allowed-origin "chrome-extension://your_extension_id/"

# Check installation status
xkey extension status

# Remove manifests
xkey extension uninstall
xkey extension uninstall chrome
```

**Example status output:**

```
BROWSER    INSTALLED  PATH
chrome     yes        /home/user/.config/google-chrome/NativeMessagingHosts/com.automatethethings.xkey.json
firefox    no         /home/user/.mozilla/native-messaging-hosts/com.automatethethings.xkey.json
```

**Manifest Paths:**

| OS | Browser | Path |
|----|---------|------|
| Linux | Chrome | `~/.config/google-chrome/NativeMessagingHosts/com.automatethethings.xkey.json` |
| Linux | Firefox | `~/.mozilla/native-messaging-hosts/com.automatethethings.xkey.json` |
| macOS | Chrome | `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/com.automatethethings.xkey.json` |
| macOS | Firefox | `~/Library/Application Support/Mozilla/NativeMessagingHosts/com.automatethethings.xkey.json` |

### GUI Mode

The browser extension connects automatically when the xKey desktop app is running. The IPC server starts with the GUI and listens on the default socket path.

### Headless Mode

Run the autofill IPC server without a desktop environment:

```bash
# Start with barrier encryption (production)
xkey extension serve --barrier-password "secret"

# Read barrier password from environment
XKEY_BARRIER_PASSWORD=secret xkey extension serve

# Read barrier password from file (first line)
xkey extension serve --barrier-password-file /run/secrets/barrier

# Interactive password prompt (terminal only)
xkey extension serve

# TPM2-sealed barrier (no password needed)
xkey extension serve

# Skip barrier encryption (development/testing)
xkey extension serve --no-barrier

# Custom socket path and debug logging
xkey extension serve --socket /tmp/xkey.sock --log-level debug --log-file /var/log/xkey.log
```

The headless server auto-detects the barrier strategy from the stored root key (`~/.xkey/data/barrier/root_key`). For software-sealed barriers, a password is required. For TPM2-sealed barriers, the hardware unseals automatically.

**Barrier password resolution order:**

1. `--barrier-password` flag
2. `--barrier-password-file` flag (reads first line)
3. `XKEY_BARRIER_PASSWORD` environment variable
4. Interactive stdin prompt (if terminal is attached)

### Command Reference

**`xkey extension install [chrome|firefox|all]`**

| Flag | Default | Description |
|------|---------|-------------|
| `--allowed-origin` | (built-in Chrome extension ID) | Override Chrome extension allowed origin |

**`xkey extension uninstall [chrome|firefox|all]`**

No additional flags.

**`xkey extension status`**

No additional flags.

**`xkey extension host`** (invoked by browser, not run manually)

| Flag | Default | Description |
|------|---------|-------------|
| `--socket` | auto | IPC Unix socket path |
| `--no-pairing` | false | Disable extension identity verification (dev only) |

**`xkey extension serve`**

| Flag | Default | Description |
|------|---------|-------------|
| `--socket` | auto | IPC Unix socket path |
| `--barrier-password` | | Barrier encryption password |
| `--barrier-password-file` | | Read barrier password from file (first line) |
| `--no-barrier` | false | Skip barrier encryption (dev/testing) |
| `--log-level` | info | Log level (debug, info, warn, error) |
| `--log-file` | stderr | Log file path |
| `--auto-lock-minutes` | 15 | Inactivity lock timeout (0=disabled) |
| `--pin-state` | auto | PIN state file path |

### Default Socket Path

The IPC socket location is determined automatically:

- `$XDG_RUNTIME_DIR/xkey/xkey.sock` when `XDG_RUNTIME_DIR` is set
- `/tmp/xkey-$UID/xkey.sock` otherwise

When running via `sudo`, the original user's UID from `SUDO_UID` is used so the daemon and client resolve to the same path.

## Security

### Attack Mitigations

| Attack | Mitigation |
|--------|------------|
| Rogue extension | Ed25519 identity verification -- different key rejected |
| Rogue local process | No Ed25519 key -- rejected; parent process check (`/proc/$PPID/exe`) |
| Extension reinstall | New Ed25519 key generated -- requires re-pairing |
| Replay handshake | Ed25519 signature binds to ephemeral X25519 pubkey |
| Replay messages | Monotonic nonce counter per direction; out-of-order rejected |
| Message tampering | AES-256-GCM authenticated encryption detects modification |
| DDoS pairing | Rate limit: 3 failed attempts -- 15-minute lockout |
| DDoS identity | Rate limit: 5 failed verifications -- 5-minute lockout |
| Pairing code bruteforce | 6-digit code expires after 5 minutes |

### Browser Sandboxing

The Chrome extension MV3 architecture provides additional isolation:

- **No `externally_connectable`** -- other extensions and pages cannot message xKey
- **Chrome isolated worlds** -- content script has separate JS globals from page scripts
- **Service worker sole handler** -- content scripts cannot directly reach the native host
- **User-initiated only** -- credential fills require explicit user action

### Parent Process Verification

On Linux, the native messaging host verifies its parent process by reading `/proc/$PPID/exe`. Only known browser binaries are accepted:

`chrome`, `chromium`, `google-chrome`, `google-chrome-stable`, `chromium-browser`, `brave-browser`, `vivaldi-bin`, `opera`, `microsoft-edge`

On non-Linux platforms this check is skipped (defense in depth, not sole control).

### Barrier Encryption

When barrier mode is active, all credential data on disk is encrypted with AES-256-GCM. The barrier root key can be sealed with:

- **Software strategy** -- Argon2id-derived key from a password
- **TPM2 strategy** -- Hardware-sealed key (no password required)

The headless server reads the strategy from the root key envelope and initializes only the required backend.

### Unpair Extension

To remove a paired extension:

- **GUI**: Settings -- unpair action
- **CLI**: Delete `~/.xkey/pairing.json`
- **Automatic**: Extension reinstall generates a new Ed25519 key, triggering re-pairing

## Data Storage

| Path | Contents | Encrypted |
|------|----------|-----------|
| `~/.xkey/pairing.json` | Ed25519 public key + origin of paired extension | No (public key only) |
| `~/.xkey/data/staticpw/` | Static password entries | Yes (barrier) |
| `~/.xkey/data/oath.json` | OATH/TOTP account data | Yes (barrier) |
| `~/.xkey/data/barrier/root_key` | Sealed barrier root key envelope | Sealed |
| `~/.xkey/data/pin-state.json` | PIN lockout state | No (lockout metadata only) |

## Deployment Patterns

### systemd Service

```ini
[Unit]
Description=xkey extension daemon
After=network.target

[Service]
Type=simple
User=xkey
ExecStart=/usr/local/bin/xkey extension serve \
    --barrier-password-file /etc/xkey/barrier-pw \
    --log-file /var/log/xkey/extension.log \
    --auto-lock-minutes 0
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### Docker

```bash
docker run -d --name xkey-ext \
  -v xkey-data:/home/xkey/.xkey \
  -v /tmp/xkey-sock:/sock \
  -e XKEY_BARRIER_PASSWORD=secret \
  xkey extension serve --socket /sock/xkey.sock
```

### SSH Socket Forwarding

Forward the daemon socket from a remote machine to localhost:

```bash
ssh -L /tmp/xkey-$(id -u)/xkey.sock:/tmp/xkey-1000/xkey.sock remote-host
```

The local browser extension then connects to the forwarded socket transparently.

## Integration Testing

The extension integration tests exercise the full autofill pipeline end-to-end:

```bash
cd xkey && make integration-test-extension
```

Tests connect directly to the IPC Unix socket (no browser dependency) to verify credential search, retrieval, TOTP generation, status queries, and error handling.

## Troubleshooting

### Extension Cannot Connect

**Symptoms:** Extension popup shows connection error.

**Solutions:**
1. Verify manifest is installed: `xkey extension status`
2. Verify IPC server is running (GUI open or `xkey extension serve` active)
3. Check socket exists: `ls -la /tmp/xkey-$(id -u)/xkey.sock`
4. Verify permissions on socket file (should be `0600`)

### Pairing Required After Extension Update

This is expected when the extension is reinstalled or `chrome.storage.local` is cleared. The new Ed25519 key does not match the stored one. Complete the pairing ceremony again.

### Barrier Password Prompt in Headless Mode

**Symptoms:** `extension serve: barrier password required`

**Solutions:**
1. Pass via flag: `--barrier-password "secret"`
2. Pass via environment: `XKEY_BARRIER_PASSWORD=secret`
3. Pass via file: `--barrier-password-file /run/secrets/barrier`
4. Use TPM2-sealed barrier (no password needed)
5. Use `--no-barrier` for development

### Identity Verification Locked

**Symptoms:** `nativemsg: identity verification locked due to too many failures`

Wait 5 minutes for the lockout to expire, or restart the native messaging host. If pairing was locked (3 failures), wait 15 minutes.

## See Also

- [FIDO2 CLI Commands](./fido2.md)
- [Getting Started Guide](../getting-started.md)
- [WebAuthn Documentation](../webauthn.md)

## References

- [Chrome Native Messaging](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging)
- [X25519 ECDH (RFC 7748)](https://datatracker.ietf.org/doc/html/rfc7748)
- [HKDF (RFC 5869)](https://datatracker.ietf.org/doc/html/rfc5869)
- [AES-GCM (NIST SP 800-38D)](https://csrc.nist.gov/pubs/sp/800/38/d/final)
