---
name: xkey-agent
description: "Automate xKey instance queries and operations from the CLI. Check status, verify setup, list keys and credentials, request certificates, and manage services. For headless agents and CI/CD. Human-only operations: barrier unseal, unlock, touch, ceremonies, PIN/key gen. Never log PINs, passphrases, or secrets."
---

# xkey-agent Skill

Enables AI agents to drive xKey instances via the CLI for automated status checks, key/credential listing, and certificate operations.

## When to Use

- Query barrier and daemon status before operations
- List and verify keys (PIV, OATH, SSH, passwords, platform-store, TPM)
- Request and inspect client certificates
- Generate OTP codes from stored credentials
- Manage agent server (start/status/stop)
- Check authentication status against servers
- Diagnose setup and readiness

## Global Flags

These apply to all commands:

```
--backend string      xkmsd backend to use (software, tpm2, pkcs11)
--config string       config file path (default: ~/.config/xkey/xkey.yaml)
--log-file string     log output file path (default: stderr)
--log-level string    log level (debug, info, warn, error) (default "info")
--xkmsd-url string    xkmsd server URL (unix:// or grpc://)
```

## Barrier Commands

Encrypt-at-rest state management. Barrier uses AES-256-GCM.

### barrier status [flags]

Query seal state and strategy.

**Flags:**
- `--json` - Output JSON
- `--socket string` - IPC socket path (auto-detect)
- `--source string` - Where to read state: auto, daemon, disk (default "auto")

**Example:** `xkey barrier status --json` returns sealed state, strategy (software|tpm2|pkcs11), and hardware_backed flag.

### barrier seal

Lock encrypted storage. Idempotent.

### barrier unseal [flags]

**Human-only operation.** Decrypt root key and derive DEK. Requires password input.

## Cert Commands

Client certificate lifecycle for mTLS.

### cert show [flags]

Display certificate details from PIV slot.

**Flags:**
- `--slot string` - PIV slot (9a, 9c, 9d, 9e) (default "9a")

### cert export [flags]

Export certificate to PEM file.

**Flags:**
- `--file string` - Output file (required)
- `--slot string` - PIV slot (default "9a")

### cert request [flags]

**Human-friendly operation:** Request cert from server CA, sign with slot key.

**Flags:**
- `--cn string` - Common Name (required)
- `--server string` - xkms server URL (required)
- `--slot string` - PIV slot for key (default "9a")
- `--spki-pin string` - SPKI SHA-256 pin for server cert pinning (first-contact trust)
- `--organization string` - Organization for subject
- `--profile string` - Certificate profile (client, server) (default "client")
- `--validity-days int` - Certificate validity days (0 for server default)

## PIV Commands

Smart card certificate and key management.

### piv list [flags]

List all certificates in slots. Suitable for inventory.

### piv show <slot> [flags]

Display certificate details for a slot.

**Example:** `xkey piv show 9a`

### piv status [flags]

Show PIV storage backend status.

### piv export <slot> [flags]

**Read-only:** Export certificate from slot.

**Flags:**
- `--format string` - pem or der
- `--output string` - Output file

### piv csr <slot> [flags]

**Read-only:** Generate CSR for slot's key.

**Flags:**
- `--cn string` - Common Name (required)
- `--organization string` - Organization
- `--country string` - Country code
- `--output string` - Output file (default: stdout)
- `--san strings` - Email SAN (repeatable)
- `--san-dns strings` - DNS SAN (repeatable)
- `--san-ip strings` - IP SAN (repeatable)

### piv delete <slot> [flags]

**Human confirmation required:** Delete certificate from slot.

**Flags:**
- `--force` - Skip confirmation

## FIDO2 Commands

Virtual USB FIDO2/WebAuthn device.

### fido2 status [flags]

Query daemon over IPC. Exits non-zero if not running (for shell conditionals).

**Flags:**
- `--socket string` - IPC socket path (auto-detect)

### fido2 start [flags]

**Human-facing daemon:** Start virtual FIDO2 device (foreground). Requires `/dev/uhid` access.

**Key flags:**
- `--backend string` - Key backend (software, tpm2, phone) (default "software")
- `--storage string` - Storage type (memory, file, barrier) (default "memory")
- `--storage-path string` - Path for file storage (default "./data")
- `--pin` - Enable PIN support (default true)
- `--require-touch` - Require touch after PIN (default true)
- `--attestation string` - Attestation format (none, packed, tpm) (default "none")
- `--notify string` - Notification type (dialog, passive, log, none) (default "dialog")

### fido2 init-token [flags]

**Human-only:** Establish Security Officer PIN for admin ops. One-time setup.

## OATH Commands

TOTP/HOTP credential management.

### oath list [flags]

List all OATH credentials. Secrets hidden by default.

**Flags:**
- `--secrets`, `--uri` - Print the shared secret / otpauth:// URI. **Never use these from an agent**: the output is key material.

### oath generate [name] [flags]

Generate OTP code(s).

**Example:** `xkey oath generate "GitHub"` or `xkey oath generate --all`

**Flags:**
- `--all` - Generate for all credentials

## Agent Commands

Server-side remote key proxy.

### agent status

Show whether agent server is running and list enrolled remote agents.

### agent start [flags]

**Human-facing:** Start server for remote device connections. Enrolling agents require xkmsd CA.

**Flags:**
- `--xkmsd-url string` - CA server URL (required)
- `--listen string` - Listen address (default ":9443")
- `--tls-cert string` - TLS certificate file
- `--tls-key string` - TLS private key file
- `--tls-ca string` - TLS CA for verifying agents

### agent stop

Gracefully stop running server. Sends SIGTERM, waits 10 seconds, then SIGKILL.

## Auth Commands

Server authentication and token management.

### auth status

Show authentication status for all registered servers.

### auth token [flags]

Print current JWT token for a server.

**Flags:**
- `--server string` - Server URL (required)

## Other Commands

### touch [flags]

**Human-only simulation:** Approve pending WebAuthn request or type password.

**Flags:**
- `--password string` - Named password to type
- `--socket string` - IPC socket path (auto-detect)

### unlock [flags]

**Human-only:** Send PIN to unlock instance. Refuses CTAP2 when locked.

**Flags:**
- `--pin-stdin` - Read PIN from stdin (preferred)
- `--socket string` - IPC socket path (auto-detect)

An agent never supplies the PIN, by `--pin-stdin` or by environment. Ask the human to run `unlock`.

### version

Display version, commit, date, Go version, platform.

## Safety Rules

1. **Never ask for or log PINs, passphrases, or key material.** These are human secrets.

2. **Human-only ceremonies:** barrier unseal, unlock, touch, fido2 init-token, cert request, auth login/register, piv generate/delete, oath add/scan/remove. Do not attempt to automate these.

3. **Use structured output:** Where `--json` exists, use it for parsing. Example: `barrier status --json | jq .sealed`.

4. **Check daemon readiness:** Before FIDO2 operations, verify `fido2 status` succeeds.

5. **Fail closed on trust:** For first-time cert request, require explicit `--spki-pin` or configure `--tls-ca` beforehand.

6. **Never place secrets in the environment or on the command line:** do not set a PIN variable, pipe a PIN, or pass `oath list --secrets`/`--uri`. Those paths exist for a human at the terminal.

## Integration Examples

**Check if barrier is sealed:**
```bash
if xkey barrier status --json | jq -e '.sealed' >/dev/null; then
  echo "sealed"
fi
```

**List PIV certificates:**
```bash
xkey piv list
```

**Generate OTP code:**
```bash
xkey oath generate "GitHub"
```

**Check agent status:**
```bash
xkey agent status
```

**Verify setup is running:**
```bash
xkey fido2 status && echo "FIDO2 daemon running"
```
