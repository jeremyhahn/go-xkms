# OATH TOTP/HOTP — CLI

> **Status: NORMATIVE** · Feature: `oath` · Module: `go-xkms/xkey` · Last verified: 2026-09-25

Every flag below is read from `cmd/xkey/cmd/oath.go`'s `init()` and matches
`xkey oath <verb> --help` built from this checkout.

## `xkey oath add`

| Flag | Default | Description |
|---|---|---|
| `--name` | (required unless `--uri` supplies one) | Credential name (e.g., "GitHub") |
| `--issuer` | | Service issuer name |
| `--secret` | | Base32-encoded secret key |
| `--uri` | | `otpauth://` URI (from a QR code) |
| `--type` | `totp` | `totp` or `hotp` |
| `--algorithm` | `SHA1` | `SHA1`, `SHA256`, `SHA512` |
| `--digits` | `6` | `6`, `7`, or `8` |
| `--period` | `30` | TOTP time step, seconds |
| `--store` | `~/.xkey/data/oath.json` (resolved via `resolveDataDir`, go-xkms#929) | Store path. An explicit value always selects a plain file, bypassing the barrier — see [architecture.md](architecture.md) |
| `--barrier-password` | | Barrier password, when the default store resolves to the barrier |
| `--barrier-password-file` | | Read the barrier password from a file (first line) |

```bash
xkey oath add --name "GitHub" --secret JBSWY3DPEHPK3PXP --issuer "GitHub"
xkey oath add --name "AWS" --secret JBSWY3DPEHPK3PXP --algorithm SHA256 --digits 8
xkey oath add --name "MyService" --secret JBSWY3DPEHPK3PXP --type hotp
xkey oath add --uri "otpauth://totp/GitHub:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"
xkey oath add --uri "otpauth://totp/..." --name "My GitHub"
```

## `xkey oath list` (alias `ls`)

| Flag | Default | Description |
|---|---|---|
| `--store` | `~/.xkey/data/oath.json` | Store path |
| `--secrets` | `false` | Show secret keys |
| `--uri` | `false` | Show `otpauth://` URIs |
| `--barrier-password`, `--barrier-password-file` | | Same as `add` |

```bash
xkey oath list
xkey oath list --secrets
xkey oath list --uri
```

## `xkey oath generate [name...]` (aliases `gen`, `code`)

| Flag | Default | Description |
|---|---|---|
| `--store` | `~/.xkey/data/oath.json` | Store path |
| `--all` | `false` | Generate codes for every credential |
| `--barrier-password`, `--barrier-password-file` | | Same as `add` |

```bash
xkey oath generate "GitHub"
xkey oath generate --all
xkey oath generate "GitHub" "AWS"
```

## `xkey oath remove [name...]` (aliases `rm`, `delete`)

| Flag | Default | Description |
|---|---|---|
| `--store` | `~/.xkey/data/oath.json` | Store path |
| `--force` | `false` | Skip the confirmation prompt |
| `--barrier-password`, `--barrier-password-file` | | Same as `add` |

```bash
xkey oath remove "GitHub"
xkey oath remove --force "GitHub"
xkey oath remove "GitHub" "AWS" "Slack"
```

## `xkey oath scan`

Captures the desktop display(s) and decodes a QR code into a credential.

| Flag | Default | Description |
|---|---|---|
| `--store` | `~/.xkey/data/oath.json` | Store path |
| `--name` | (from QR) | Override the credential name |
| `--display` | `-1` | Display index to scan (`-1` = all) |
| `--list-displays` | `false` | List available displays and exit |
| `-y, --yes` | `false` | Skip the confirmation prompt |
| `--index` | `-1` | Select a QR code by index when multiple are found |
| `--barrier-password`, `--barrier-password-file` | | Same as `add` |

```bash
xkey oath scan
xkey oath scan --display 0
xkey oath scan --name "My GitHub"
xkey oath scan --yes
xkey oath scan --list-displays
xkey oath scan --index 1
```

## `otpauth://` URI format

```
otpauth://TYPE/LABEL?secret=...&issuer=...&algorithm=...&digits=...&period=...
```

`TYPE` is `totp` or `hotp`; `LABEL` is the account identifier (e.g.
`GitHub:user@example.com`). `counter` (HOTP only) sets the initial counter.

## Store resolution

Shared by every verb above (`openOATHStore`, `cmd/xkey/cmd/oath.go`):

1. `--store` explicitly set (`cmd.Flags().Changed("store")`) → plain
   `FileStore` at that path, no barrier involved.
2. Otherwise, the default data directory's barrier-or-file decision
   (`resolveSecretStoreBackend`, shared with `xkey backup` and `xkey oath
   sync`) — see [architecture.md](architecture.md) and
   [seal/cli.md](../seal/cli.md).

## Phone sync

`xkey oath sync`, `xkey oath push <name-or-id>` and `xkey oath pull` move
credentials to and from a paired phone. They take the same `--store`,
`--barrier-password`/`--barrier-password-file` flags as above, plus
`--device` (paired device name) and `--timeout` (default `1m0s`). Documented
in full, alongside the rest of the phone-pairing verb catalog, in
[phone-hsm/cli.md](../phone-hsm/cli.md#oath-sharing-and-sync).
