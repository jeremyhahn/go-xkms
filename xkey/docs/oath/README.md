# OATH TOTP/HOTP One-Time Passwords

xkey includes built-in support for OATH one-time passwords (OTP), compatible with services like Google, GitHub, AWS, and any other service using standard TOTP or HOTP.

## Quick Start

```bash
# Scan QR code from screen (easiest method)
xkey oath scan

# Or add manually with secret
xkey oath add --name "GitHub" --secret JBSWY3DPEHPK3PXP

# Generate a code
xkey oath generate "GitHub"

# List all credentials
xkey oath list
```

## Command Reference

### oath add

Add a new OATH credential.

```
xkey oath add [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--name` | (required) | Credential name (e.g., "GitHub") |
| `--issuer` | | Service issuer name |
| `--secret` | | Base32-encoded secret key |
| `--uri` | | otpauth:// URI (from QR code) |
| `--type` | `totp` | OTP type: `totp` or `hotp` |
| `--algorithm` | `SHA1` | Hash algorithm: `SHA1`, `SHA256`, `SHA512` |
| `--digits` | `6` | Number of digits: 6, 7, or 8 |
| `--period` | `30` | Time period in seconds (TOTP only) |
| `--store` | `/var/lib/xkey/oath.json` | Path to credential store. An explicit value always selects a plain file, bypassing the barrier (see [At-Rest Encryption](#at-rest-encryption)) |
| `--barrier-password` | | Barrier password, when the default store location is barrier-encrypted |
| `--barrier-password-file` | | Read the barrier password from a file (first line) |

**Examples:**

```bash
# Add TOTP credential with secret
xkey oath add --name "GitHub" --secret JBSWY3DPEHPK3PXP --issuer "GitHub"

# Add TOTP with SHA256 and 8 digits
xkey oath add --name "AWS" --secret JBSWY3DPEHPK3PXP --algorithm SHA256 --digits 8

# Add HOTP credential (counter-based)
xkey oath add --name "MyService" --secret JBSWY3DPEHPK3PXP --type hotp

# Add from otpauth:// URI (from QR code scanning)
xkey oath add --uri "otpauth://totp/GitHub:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"

# Override name when using URI
xkey oath add --uri "otpauth://totp/..." --name "My GitHub"
```

### oath list

List all OATH credentials.

```
xkey oath list [flags]
```

Aliases: `ls`

| Flag | Default | Description |
|------|---------|-------------|
| `--store` | `/var/lib/xkey/oath.json` | Path to credential store |
| `--barrier-password` | | Barrier password, when the default store location is barrier-encrypted |
| `--barrier-password-file` | | Read the barrier password from a file (first line) |
| `--secrets` | `false` | Show secret keys |
| `--uri` | `false` | Show otpauth:// URIs |

**Examples:**

```bash
# List all credentials
xkey oath list

# Show secret keys (for backup)
xkey oath list --secrets

# Show otpauth:// URIs (for QR code generation)
xkey oath list --uri

# Use custom store path
xkey oath list --store ~/.xkey/oath.json
```

**Output format:**

```
OATH Credentials (2):

  Name:      GitHub
  Issuer:    GitHub
  Type:      TOTP
  Algorithm: SHA1
  Digits:    6
  Period:    30s

  Name:      AWS
  Type:      TOTP
  Algorithm: SHA256
  Digits:    8
  Period:    30s
```

### oath generate

Generate OTP codes.

```
xkey oath generate [name...] [flags]
```

Aliases: `gen`, `code`

| Flag | Default | Description |
|------|---------|-------------|
| `--store` | `/var/lib/xkey/oath.json` | Path to credential store |
| `--barrier-password` | | Barrier password, when the default store location is barrier-encrypted |
| `--barrier-password-file` | | Read the barrier password from a file (first line) |
| `--all` | `false` | Generate codes for all credentials |

**Examples:**

```bash
# Generate code for a specific credential
xkey oath generate "GitHub"
# Output: 123456  (expires in 15s)

# Generate codes for all credentials
xkey oath generate --all
# Output:
#   GitHub       123456  (expires in 15s)
#   AWS          78901234  (expires in 22s)

# Generate codes for multiple credentials
xkey oath generate "GitHub" "AWS"
```

### oath scan

Scan the screen for QR codes and add credentials automatically.

```
xkey oath scan [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--store` | `/var/lib/xkey/oath.json` | Path to credential store |
| `--barrier-password` | | Barrier password, when the default store location is barrier-encrypted |
| `--barrier-password-file` | | Read the barrier password from a file (first line) |
| `--name` | (from QR) | Override the credential name |
| `--display` | `-1` | Display index to scan (-1 for all) |
| `--list-displays` | `false` | List available displays and exit |
| `-y, --yes` | `false` | Skip confirmation prompt |
| `--index` | `-1` | Select QR code by index when multiple found |

**Examples:**

```bash
# Scan all screens for QR code
xkey oath scan

# Scan specific display
xkey oath scan --display 0

# Scan and override name
xkey oath scan --name "My GitHub"

# Scan without confirmation
xkey oath scan --yes

# List available displays
xkey oath scan --list-displays

# Select specific QR when multiple found
xkey oath scan --index 1
```

**Output:**
```
Scanning 2 display(s) for QR codes...

Found credential:
  Name:      GitHub:user@example.com
  Issuer:    GitHub
  Type:      TOTP
  Algorithm: SHA1
  Digits:    6
  Period:    30s

Add this credential? [Y/n]: y
Added OATH credential: GitHub:user@example.com
```

### oath remove

Remove OATH credentials.

```
xkey oath remove [name...] [flags]
```

Aliases: `rm`, `delete`

| Flag | Default | Description |
|------|---------|-------------|
| `--store` | `/var/lib/xkey/oath.json` | Path to credential store |
| `--barrier-password` | | Barrier password, when the default store location is barrier-encrypted |
| `--barrier-password-file` | | Read the barrier password from a file (first line) |
| `--force` | `false` | Don't prompt for confirmation |

**Examples:**

```bash
# Remove with confirmation prompt
xkey oath remove "GitHub"

# Remove without confirmation
xkey oath remove --force "GitHub"

# Remove multiple credentials
xkey oath remove "GitHub" "AWS" "Slack"
```

## otpauth:// URI Format

xkey supports importing credentials from otpauth:// URIs, the standard format used by QR codes:

```
otpauth://TYPE/LABEL?PARAMETERS
```

**Components:**
- **TYPE**: `totp` or `hotp`
- **LABEL**: Account identifier (e.g., `GitHub:user@example.com`)
- **PARAMETERS**: Query parameters for configuration

**Common parameters:**
- `secret`: Base32-encoded secret key (required)
- `issuer`: Service name
- `algorithm`: `SHA1`, `SHA256`, or `SHA512`
- `digits`: Code length (6, 7, or 8)
- `period`: Time period in seconds (TOTP only)
- `counter`: Initial counter value (HOTP only)

**Example URI:**

```
otpauth://totp/GitHub:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA1&digits=6&period=30
```

## Storage

### Default Location

By default, credentials go through the barrier-encrypted store when a
barrier is initialized, or the plain file (`/var/lib/xkey/oath.json`) when
one is not -- see [At-Rest Encryption](#at-rest-encryption) below.

### Custom Location

Use `--store` to specify a different location:

```bash
xkey oath add --name "Test" --secret ABC123 --store ~/.xkey/oath.json
xkey oath generate --all --store ~/.xkey/oath.json
```

### At-Rest Encryption

(go-xkms#134, go-xkms#148)

`xkey oath`, `xkey backup`, and `xkey device oath-sync` all resolve the OATH
store the same way, at the default `--store`/`--oath-store` location only:

- **A barrier is initialized** (`xkey barrier init`, or the GUI's barrier
  setup): every read and write goes through the barrier-encrypted store
  (`oath.NewBackendStore` over the unsealed barrier backend), the exact
  mechanism the GUI and `xkey extension serve` already use. Nothing here is a
  second encryption scheme layered on top of the JSON shown below -- the
  barrier encrypts the whole entry opaquely before it ever reaches disk, so
  the plaintext JSON form never exists there. Supply the password with
  `--barrier-password`, `--barrier-password-file`, or the
  `XKEY_BARRIER_PASSWORD` environment variable; without one of those, an
  interactive terminal is prompted.
- **No barrier is initialized:** the command falls back to the historical
  plain `oath.json` file below, and logs one warning naming the store and
  pointing at `xkey barrier init` -- never a silent, unannounced plaintext
  write.
- **A barrier is initialized but cannot be opened** (missing or wrong
  password, unsupported strategy, corrupt root key): the command refuses
  with a typed error. It never falls back to writing plaintext.
- **An explicit `--store` (or `--oath-store`) path** always selects the
  plain file at that path, bypassing the barrier decision entirely -- the
  operator asked for a specific file.

Once a barrier protects the store, its on-disk shape is opaque
ciphertext, not the JSON form documented below -- there is nothing for an
operator to inspect directly on disk; use `xkey oath list` (optionally
`--secrets`) to read the credentials back.

### Storage Format (no barrier)

Without a barrier, credentials are stored as JSON, unencrypted at rest
(protect the file with filesystem permissions, or initialize a barrier):

```json
{
  "credentials": [
    {
      "id": "github",
      "name": "GitHub",
      "issuer": "GitHub",
      "secret": "JBSWY3DPEHPK3PXP",
      "type": "totp",
      "algorithm": "SHA1",
      "digits": 6,
      "period": 30,
      "created_at": "2025-01-31T12:00:00Z"
    }
  ]
}
```

## Algorithm Support

### TOTP (Time-based One-Time Password)

RFC 6238 compliant implementation:

- Generates codes based on current time
- Default 30-second time window
- Codes automatically expire and regenerate

### HOTP (HMAC-based One-Time Password)

RFC 4226 compliant implementation:

- Generates codes based on a counter value
- Counter increments after each use
- Must stay synchronized with server

### Hash Algorithms

| Algorithm | Description |
|-----------|-------------|
| `SHA1` | Default, most compatible |
| `SHA256` | More secure, less common |
| `SHA512` | Highest security, rare |

## Security Considerations

### Secret Storage

- The shared secret is protected at rest by the xkey barrier whenever one is
  initialized -- run `xkey barrier init` to turn this on. See
  [At-Rest Encryption](#at-rest-encryption) for exactly which commands and
  flags this applies to.
- Without a barrier, the secret is plaintext in the JSON store file (the CLI
  logs a warning naming the store every time it opens one this way); protect
  the file with filesystem permissions in that case.
- In memory, the secret lives in mlocked, guard-paged protected memory for
  its whole lifetime as a `Credential`, never as a plain Go string
  (go-xkms#210) -- see `xkey/pkg/oath/credential.go`. The one accepted
  residue is `crypto/hmac`'s internal ipad/opad copy of the key during TOTP
  and HOTP computation: `crypto/hmac` exposes no way to wipe it, and hand
  rolling HMAC to keep it wipeable would forfeit FIPS validation on the exact
  path this code makes FIPS-safe. That trade-off, and why it is the right
  one, is documented at the call site in `GenerateCounter`
  (`xkey/pkg/oath/generator.go`).

### Backup

To backup credentials:

```bash
# Export with secrets visible
xkey oath list --secrets

# Or export as URIs for QR code generation
xkey oath list --uri
```

### Migration

To migrate between systems:

1. Export credentials as URIs: `xkey oath list --uri`
2. Copy the URIs or regenerate QR codes
3. Import on the new system: `xkey oath add --uri "..."`
