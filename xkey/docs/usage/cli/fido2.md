# FIDO2 CLI Commands

> **Status: REFERENCE** · Last verified: 2026-10-13
> Scope: `xkmsctl fido2`, the go-xkms server CLI (`cmd/xkmsctl/fido2.go`); the normative reference is [`docs/fido2-ctap2/cli.md`](../../../../docs/fido2-ctap2/cli.md).

> **This page documents `xkmsctl fido2`**, the go-xkms **server** CLI, which
> drives *external* FIDO2 hardware security keys over CTAP2/HID. It is **not**
> `xkey fido2`, which runs xKey's own virtual authenticator. For that, see
> [../../fido2/architecture.md](../../fido2/architecture.md) and
> [../../virtual-authenticator/cli.md](../../virtual-authenticator/cli.md).

The `fido2` commands talk to a security key attached to the machine running
`xkmsctl`. They do not contact a server. The release binary always enumerates
physical authenticators; no environment variable switches it to a software
one (`cmd/xkmsctl/fido2.go:45`). `register` and `authenticate` together derive
a secret from the key's hmac-secret extension, for use as an encryption key.

```
xkmsctl fido2
├── list-devices           # Connected FIDO2 security keys
├── wait-device            # Block until a key is connected
├── info                   # Details of one key
├── register <username>    # Create a credential; prints its ID and salt
└── authenticate           # Derive the secret from a credential ID and salt
```

On Linux a HID device counts as a FIDO2 key when its report descriptor
declares the FIDO usage page `0xF1D0` (`pkg/fido2/hid_linux.go:261`); the
vendor does not matter.

All commands take the global `-o/--output` (`text`, `json` or `table`).

## Commands

### fido2 list-devices

Lists every connected key with its path, product, manufacturer, vendor and
product IDs, and transport. With no key connected it prints
`No FIDO2 devices found` and exits 0.

```bash
xkmsctl fido2 list-devices
xkmsctl fido2 list-devices -o json | jq -r '.devices[].path'
```

### fido2 wait-device

Waits until a key is connected, then prints `Device found: <product> (<path>)`.

| Flag | Default | Description |
|------|---------|-------------|
| `--timeout` | `1m0s` | Time to wait for a device |

```bash
xkmsctl fido2 wait-device --timeout 2m
```

### fido2 info

Shows the same fields as `list-devices`, plus the serial number when the key
reports one, for a single key: the one at `--device`, or else the first one
found. Exits non-zero when no key is connected or `--device` matches none.

```bash
xkmsctl fido2 info --device /dev/hidraw0
```

### fido2 register

Creates a credential for `<username>` on the key. The output includes the
credential ID and salt, base64-encoded. Store them: `authenticate` needs both.

| Flag | Default | Description |
|------|---------|-------------|
| `--rp-id` | `go-xkms` | Relying party ID |
| `--rp-name` | `Go xKMS` | Relying party name |
| `--display-name` | the username | User display name |
| `--device` | first key found | Device path |
| `--timeout` | `30s` | Time allowed for user presence |
| `--user-verification` | `false` | Require user verification (PIN) |

```bash
xkmsctl fido2 register alice --rp-id app.example.com --display-name "Alice Smith"
```

```
FIDO2 Credential Registration Successful!

Credential Information:
  User:          alice (Alice Smith)
  Relying Party: app.example.com
  Created:       <timestamp>

Store these values securely for authentication:
  Credential ID: <base64>
  Salt:          <base64>
```

With `-o json` the result has `credential_id`, `public_key`, `aaguid`, `salt`
(all base64), `user_name`, `user_display`, `relying_party` and `created`, and
the touch prompt is suppressed.

### fido2 authenticate

Derives the secret from a stored credential ID and salt. The key must be the
one that registered the credential, and `--rp-id` must match the registration.

| Flag | Default | Description |
|------|---------|-------------|
| `--credential-id` | | Credential ID (required) |
| `--salt` | | Salt (required) |
| `--rp-id` | `go-xkms` | Relying party ID |
| `--device` | first key found | Device path |
| `--timeout` | `30s` | Time allowed for user presence |
| `--user-verification` | `false` | Require user verification (PIN) |
| `--hex` | `false` | Print the derived key in hex instead of base64 |

`--credential-id` and `--salt` accept standard base64, URL-safe base64 or hex,
tried in that order (`cmd/xkmsctl/fido2.go:514`).

Text output is `Authentication successful` followed by
`Derived Key (<n> bytes): <key>`. With `-o json` it is an object with
`success`, `derived_key` and `key_length`:

```bash
KEY=$(xkmsctl fido2 authenticate --credential-id "$CRED_ID" --salt "$SALT" \
  --hex -o json | jq -r '.derived_key')
```

## Example: derive a key from a security key

```bash
xkmsctl fido2 wait-device
REG=$(xkmsctl fido2 register backup --rp-id backup.example.com -o json)
CRED_ID=$(echo "$REG" | jq -r '.credential_id')
SALT=$(echo "$REG" | jq -r '.salt')

# Later, with the same key attached:
KEY=$(xkmsctl fido2 authenticate --credential-id "$CRED_ID" --salt "$SALT" \
  --rp-id backup.example.com --hex -o json | jq -r '.derived_key')
```

Without the credential ID and salt the derived key cannot be reproduced; keep
them with the data they protect.

## Troubleshooting

**No FIDO2 devices found, or permission denied.** On Linux the user needs read
and write access to the key's `hidraw` node. A udev rule that grants it:

```
# /etc/udev/rules.d/70-u2f.rules
KERNEL=="hidraw*", SUBSYSTEM=="hidraw", MODE="0660", GROUP="plugdev", TAG+="uaccess"
```

Reload with `sudo udevadm control --reload-rules && sudo udevadm trigger`, then
replug the key. A U2F-only key without CTAP2 cannot be used.

**Timeout.** Touch the key when prompted, or raise `--timeout`.

**Authentication fails.** Check that the credential ID, salt and `--rp-id` are
the registration's values and that the same key is attached. A credential
registered with `--user-verification` needs a key with a PIN set.

## See Also

- [FIDO2 / CTAP2 client](../../../../docs/fido2-ctap2/user.md) — the normative feature folder
- [WebAuthn Documentation](../webauthn.md)
- [CTAP2 Specification](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html)
