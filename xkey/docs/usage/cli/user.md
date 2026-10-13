# User Management CLI

> **Status: REFERENCE** · Last verified: 2026-10-13
> Scope: `xkmsctl user`, the go-xkms server CLI (`cmd/xkmsctl/user.go`, `cmd/xkmsctl/user_invite.go`).

> **Scope:** this page documents the go-xkms **server** CLI `xkmsctl user`
> (source: `cmd/xkmsctl/`), **not** the `xkey` desktop CLI. It lives under
> `xkey/docs/` for historical reasons.
> There is no `xkey` equivalent. For the xkey command tree see
> [the xkey CLI reference](README.md).

## Overview

The `user` command group manages user accounts on an xkmsd server. Every
subcommand connects to the server named by the global `--server` flag. Accounts
are created **pending** with no credential; the invitee activates the account
by redeeming a one-time invitation from the machine that holds their security
key.

```
xkmsctl user
├── register <username>                # Create a pending account and print an invitation
├── invite redeem <link-or-token>      # Enroll the first credential and activate
├── login <email>                      # FIDO2 login; prints a JWT
├── list
├── get <username>
├── credentials <username>             # FIDO2 credentials registered for a user
├── bind-cert <username>               # Bind an mTLS certificate
├── update <username> --enable|--disable
├── enable <username>
├── disable <username>
├── delete <username>
└── status                             # Whether any users exist
```

Every `user` subcommand also declares `--storage-path`
(`cmd/xkmsctl/user.go:1126`), but none of them reads it: they act through the
server, not on local storage.

## Commands

### user register

Creates the account pending and prints a one-time activation invitation. The
invitation is shown exactly once, since the server stores only its digest. Send
the link to the invitee, or redeem it yourself with `user invite redeem`
(`cmd/xkmsctl/user.go:138`).

| Flag | Description |
|------|-------------|
| `--email` | Canonical login key; required, and must be an email address |
| `--display-name` | Display name; defaults to the username |
| `--role` | `so`, `admin`, `operator`, `user` or `auditor` (`cmd/xkmsctl/roles.go:39`); defaults to `user` |

The first user registered always gets `admin`, whatever `--role` says
(`cmd/xkmsctl/user.go:220`).

```bash
xkmsctl user register admin --email admin@example.com --display-name "Admin User"
xkmsctl user register operator --email operator@example.com --role operator
```

### user invite redeem

Redeems an invitation from `user register` or `admin create`. It enrolls the
invitee's first credential and activates the account. It takes either the full
invitation link, which carries the tenant and token, or a bare token with
`--tenant-id` (`cmd/xkmsctl/user_invite.go:123`).

| Flag | Default | Description |
|------|---------|-------------|
| `--method` | `fido2` | `fido2` or `piv` |
| `--tenant-id` | | Tenant ID; needed only with a bare token |
| `--device` | | FIDO2 device path (`fido2`) |
| `--user-verification` | `false` | Require user verification (`fido2`) |
| `--timeout` | `30s` | Time allowed for user presence (`fido2`) |
| `--piv-cert-file` | | PIV certificate PEM to present (`piv`) |
| `--origin` | from `--server` | WebAuthn origin, see below |
| `--pin`, `--pin-stdin` | | Authenticator PIN, see below |

```bash
xkmsctl --server https://kms.example.com:8443 user invite redeem '<invitation-link>'
xkmsctl user invite redeem '<invitation-link>' --method piv --piv-cert-file alice-piv.pem
```

### user login

Runs the WebAuthn authentication ceremony with the local FIDO2 key and prints a
JWT for later calls. The argument is the account's email address
(`cmd/xkmsctl/user.go:315`).

| Flag | Default | Description |
|------|---------|-------------|
| `--device` | | FIDO2 device path |
| `--user-verification` | `false` | Require user verification (PIN) |
| `--timeout` | `30s` | Time allowed for user presence |
| `--origin` | from `--server` | WebAuthn origin, see below |
| `--pin`, `--pin-stdin` | | Authenticator PIN, see below |

```bash
export XKMS_TOKEN=$(xkmsctl --server https://kms.example.com:8443 user login admin@example.com)
xkmsctl key list --token "$XKMS_TOKEN"

# A PIN-protected authenticator, with no PIN in the process list
printf '%s' "$PIN" | xkmsctl user login admin@example.com --pin-stdin --origin https://kms.example.com
```

**Origin.** `--origin` names the WebAuthn origin bound into the ceremony. When
it is omitted, the origin is taken from an `http://` or `https://` `--server`
URL. Any other transport, including the default unix socket, has no origin to
derive, so `--origin` is then required (`cmd/xkmsctl/webauthn_origin.go:44`).

**PIN.** An authenticator with a CTAP2 PIN set refuses the ceremony without
it. Supply it, in precedence order, with `--pin-stdin`, the `XKMS_FIDO2_PIN`
environment variable or `--pin`; `--pin` is visible in the process list
(`cmd/xkmsctl/pin_input.go:56`).

### user list, get, status

```bash
xkmsctl user list
xkmsctl user get admin
xkmsctl user status
```

`status` reports whether any user accounts exist and how many are admins. All
three accept the global `--output json`.

### user credentials

Lists the FIDO2 credentials registered for a user. The server supplies the
allow-list during `user login` by itself, so these IDs are informational
(`cmd/xkmsctl/user.go:850`).

```bash
xkmsctl user credentials admin@example.com
```

### user bind-cert

Binds an mTLS client certificate to a user. The binding identifier is the qrdb
SPKI SHA-256 thumbprint (`cmd/xkmsctl/user.go:1007`).

| Flag | Description |
|------|-------------|
| `--cert-file` | Client certificate PEM; the thumbprint and expiry are computed from it |
| `--thumbprint` | Precomputed SPKI SHA-256 thumbprint (hex) |
| `--not-after` | Binding expiry in Unix seconds, with `--thumbprint` |

```bash
xkmsctl user bind-cert alice --cert-file alice.pem
xkmsctl user bind-cert alice --thumbprint <hex-thumbprint> --not-after 1767225600
```

### user update, enable, disable

`update` needs exactly one of `--enable` or `--disable`
(`cmd/xkmsctl/user.go:922`). `enable` and `disable` do the same without a flag.
A disabled account cannot authenticate.

```bash
xkmsctl user update alice --disable
xkmsctl user enable alice
```

### user delete

```bash
xkmsctl user delete alice
```

The last administrator account cannot be deleted.

## Roles

`--role` accepts the canonical qrdb role names (`cmd/xkmsctl/roles.go:23`):

| Role | Purpose |
|------|---------|
| `so` | Security Officer, for FIPS 140 separation of duties |
| `admin` | Manages the server and other users |
| `operator` | Manages keys and certificates, not users |
| `user` | Uses keys for cryptographic operations without managing them |
| `auditor` | Views audit logs and key metadata |

## Troubleshooting

### No FIDO2 device found

On Linux the user needs access to the key's `hidraw` node. A udev rule that
grants it:

```
# /etc/udev/rules.d/70-u2f.rules
KERNEL=="hidraw*", SUBSYSTEM=="hidraw", MODE="0660", GROUP="plugdev", TAG+="uaccess"
```

Reload with `sudo udevadm control --reload-rules`, then replug the key.

### Timeout while touching the key

Raise `--timeout` (for example `--timeout 60s`) on `user login` or
`user invite redeem`.

## See Also

- [Admin Management CLI](./admin.md)
- [WebAuthn Guide](../webauthn.md)
- [Getting Started](../getting-started.md)
