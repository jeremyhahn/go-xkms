# Admin Account Management

The `admin` command group manages administrator accounts. All accounts created
through these commands receive the `admin` role with full system access.

## Creating Admin Accounts

```bash
xkmsctl admin create <username> [flags]
```

### FIDO2 Enrollment (default)

```bash
xkmsctl admin create admin@example.com --method fido2
xkmsctl admin create admin@example.com --display-name "Admin User" --user-verification
```

### mTLS Enrollment with PKCS#11

Reads the client certificate from a hardware token and binds its SHA-256
fingerprint to the new admin account.

```bash
xkmsctl admin create admin@example.com \
  --method mtls \
  --pkcs11-module /usr/lib/libxkey11.so \
  --pkcs11-pin 123456
```

### mTLS Enrollment with PEM Certificate

```bash
xkmsctl admin create admin@example.com \
  --method mtls \
  --cert-file /path/to/client.pem
```

### Flags

| Flag | Description |
|------|-------------|
| `--method` | `fido2` (default) or `mtls` |
| `--display-name` | Human-readable name (defaults to username) |
| `--cert-file` | PEM certificate for mTLS enrollment |
| `--storage-path` | User store path (default: `$XKMS_STORAGE_PATH` or `/var/lib/xkms`) |
| `--device` | Specific FIDO2 device path |
| `--user-verification` | Require PIN on the security key |
| `--timeout` | FIDO2 user presence timeout (default: 30s) |

## Listing Admin Accounts

```bash
xkmsctl admin list
xkmsctl admin list --output json
```

## Getting Admin Details

```bash
xkmsctl admin get admin@example.com
```

## Deleting Admin Accounts

```bash
xkmsctl admin delete admin@example.com
```

The last remaining admin account cannot be deleted.

## Enabling / Disabling

```bash
xkmsctl admin disable admin@example.com
xkmsctl admin enable admin@example.com
```

Disabled accounts remain in the system but cannot authenticate.

## Checking Setup Status

```bash
xkmsctl admin status
```

Reports whether any admin accounts are configured and the total count.
