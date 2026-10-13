# Admin Account Management

> **Status: REFERENCE** · Last verified: 2026-10-13
> Scope: `xkmsctl admin`, the go-xkms server CLI (`cmd/xkmsctl/admin.go`).

> **Scope:** this page documents the go-xkms **server** CLI `xkmsctl admin`
> (source: `cmd/xkmsctl/`), **not** the `xkey` desktop CLI. It lives under
> `xkey/docs/` for historical reasons.
> There is no `xkey` equivalent. For the xkey command tree see
> [the xkey CLI reference](README.md).

The `admin` command group manages administrator accounts. All accounts created
through these commands receive the `admin` role with full system access.

## Creating Admin Accounts

```bash
xkmsctl admin create <username> [flags]
```

### FIDO2 (default)

The FIDO2 method requires `--email`, the canonical login key WebAuthn resolves
the account by. It does not enroll a passkey inline: it creates the account
pending and prints a one-time activation invitation, which the invitee redeems
from the machine holding the security key with `xkmsctl user invite redeem`
(`cmd/xkmsctl/admin.go:46`).

```bash
xkmsctl admin create admin --email admin@example.com
xkmsctl admin create admin --email admin@example.com --display-name "Admin User"
```

### mTLS with PKCS#11

Reads the client certificate from a hardware token. The admin is resolved by
the certificate's SPKI thumbprint and is created active, with no login key and
no invitation.

```bash
xkmsctl admin create admin \
  --method mtls \
  --pkcs11-module /usr/lib/libxkey11.so \
  --pkcs11-pin 123456
```

### mTLS with a PEM certificate

```bash
xkmsctl admin create admin \
  --method mtls \
  --cert-file /path/to/client.pem
```

### Flags

Defined in `cmd/xkmsctl/admin.go:729`.

| Flag | Description |
|------|-------------|
| `--method` | `fido2` (default) or `mtls` |
| `--email` | Canonical login key; required for `fido2` |
| `--display-name` | Human-readable name (defaults to username) |
| `--cert-file` | PEM certificate for mTLS enrollment (alternative to `--pkcs11-module`) |
| `--storage-path` | Storage path, on every `admin` subcommand (default: `$XKMS_STORAGE_PATH` or `/var/lib/xkms`) |

## Listing Admin Accounts

```bash
xkmsctl admin list
xkmsctl admin list --output json
```

## Getting Admin Details

```bash
xkmsctl admin get admin
```

## Deleting Admin Accounts

```bash
xkmsctl admin delete admin
```

The last remaining admin account cannot be deleted.

## Enabling / Disabling

```bash
xkmsctl admin disable admin
xkmsctl admin enable admin
```

Disabled accounts remain in the system but cannot authenticate.

## Checking Setup Status

```bash
xkmsctl admin status
```

Reports whether any admin accounts are configured and the total count.
