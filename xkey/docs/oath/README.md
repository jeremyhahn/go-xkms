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
| `--store` | `/var/lib/xkey/oath.json` | Path to credential store |

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

OATH credentials are stored in `/var/lib/xkey/oath.json` by default.

### Custom Location

Use `--store` to specify a different location:

```bash
xkey oath add --name "Test" --secret ABC123 --store ~/.xkey/oath.json
xkey oath generate --all --store ~/.xkey/oath.json
```

### Storage Format

Credentials are stored as JSON:

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

- Secrets are stored in plaintext in the JSON file
- Protect the store file with appropriate permissions
- Consider storing in an encrypted filesystem for production

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
