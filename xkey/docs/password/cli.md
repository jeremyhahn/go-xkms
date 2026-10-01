# Static Passwords — CLI

> **Status: NORMATIVE** · Feature: `password` · Module: `go-xkms/xkey` · Last verified: 2026-10-01

Every flag below is read from `cmd/xkey/cmd/password.go`/`touch.go`'s
`init()` and matches `xkey password <verb> --help`/`xkey touch --help`
built from this checkout. See [architecture.md](architecture.md) for why
the store's location and its session state have different authorities.

## `xkey password add`

| Flag | Default | Description |
|---|---|---|
| `--name` | (required) | Password name/identifier |
| `--password-stdin` | `false` | Read the password from standard input (mutually exclusive with `--generate`; one source is required) |
| `--generate` | `false` | Generate a random password (mutually exclusive with the password value; one is required) |
| `--length` | `32` | Generated password length (8–128) |
| `--charset` | `all` | `all` or `alphanumeric` |
| `--notes` | | Optional notes |
| `--title` | | Display title for the credential |
| `--username` | | Username or login |
| `--url` | | Website URL, used by the browser extension for domain matching |
| `--store` | `~/.xkey/data/staticpw` (resolved via `featureDataDir`, `datadir.go`, go-xkms#929) | Path to the password store |

There is no `--password` value flag: a value on the command line is visible
to every other process on the host via `ps`. The password comes from
`--password-stdin` or the `XKEY_STATIC_PASSWORD` environment variable.

```bash
xkey password add --name "DatabaseProd" --password-stdin < password.txt
XKEY_STATIC_PASSWORD="tok_abc123" xkey password add --name "GitHubWork" \
  --title "GitHub (Work)" --username "jdoe" --url "https://github.com"
xkey password add --name "ServiceAccount" --generate
xkey password add --name "WiFi" --generate --length 64 --charset alphanumeric --notes "Office WiFi"
```

## `xkey password list` (alias `ls`)

| Flag | Default | Description |
|---|---|---|
| `--store` | `~/.xkey/data/staticpw` | Path to the password store |
| `--show-passwords` | `false` | Reveal values; requires `--source disk` |
| `--socket` | auto-detect | IPC socket of a running daemon |
| `--source` | `auto` | `auto`, `daemon`, or `disk` |

```bash
xkey password list
xkey password list --source disk --show-passwords
xkey password list --source disk --store /tmp/passwords
```

## `xkey password get [name]` (alias `show`)

Outputs only the password value to stdout (no trailing newline), for piping.

| Flag | Default | Description |
|---|---|---|
| `--store` | `~/.xkey/data/staticpw` | Path to the password store |

```bash
xkey password get "DatabaseProd"
xkey password get "DatabaseProd" | xclip -selection clipboard
DB_PASS=$(xkey password get "DatabaseProd")
```

## `xkey password remove [name...]` (aliases `rm`, `delete`)

| Flag | Default | Description |
|---|---|---|
| `--force` | `false` | Skip the confirmation prompt |
| `--store` | `~/.xkey/data/staticpw` | Path to the password store |

```bash
xkey password remove "DatabaseProd"
xkey password remove --force "DatabaseProd" "ServiceAccount" "WiFi"
```

## `xkey password type [name]` (alias `emit`)

Connects to the running `xkey fido2` daemon and types the password through
the virtual USB keyboard.

| Flag | Default | Description |
|---|---|---|
| `--socket` | auto-detect | IPC socket path |

```bash
xkey password type "DatabaseProd"
xkey password type "DatabaseProd" --socket "$XDG_RUNTIME_DIR/xkey/xkey.sock"
```

## `xkey password unlock`

Acts on an `xkmsd` server's session; requires `--xkmsd-url`. In
`session_based` mode, unlocks decryption until locked. Has no effect in
`pin_per_operation` mode.

| Flag | Default | Description |
|---|---|---|
| `--passphrase-stdin` | `false` | Read your vault passphrase from standard input |

The session opens with your own vault passphrase, never a device or
deployment PIN. There is no `--passphrase` value flag: a value on the command
line is visible to every other process on the host via `ps`. The passphrase
comes from `--passphrase-stdin` or the `XKEY_VAULT_PASSPHRASE` environment
variable.

```bash
xkey password unlock --passphrase-stdin < passphrase.txt
XKEY_VAULT_PASSPHRASE=... xkey password unlock
```

## `xkey password vault`

Manages your personal vault on the `xkmsd` server: the factors your personal
entries' key is wrapped under. Requires `--xkmsd-url`.

| Verb | Flags | Does |
|---|---|---|
| `vault status` | | whether your vault exists and is unlocked, and your factors |
| `vault enroll` | `--passphrase-stdin`, `--passkey`, `--key-factor`, `--label` | enroll a passphrase, passkey or key; the first enrollment prints the one-time recovery code |
| `vault rotate` | `--factor-id`, `--passphrase-stdin`, `--label` | replace a passphrase (the label is kept unless given) |
| `vault remove` | `--factor-id` | remove a factor (not the recovery code, not the last unlock factor) |
| `vault recover` | `--recovery-code-stdin`, `--passphrase-stdin`, `--passkey`, `--key-factor`, `--label` | enroll a new factor with the recovery code; prints the replacement code once |

Secrets come from `--passphrase-stdin` / `XKEY_VAULT_PASSPHRASE` and
`--recovery-code-stdin` / `XKEY_VAULT_RECOVERY_CODE`; at most one may read
standard input.

`--passkey` replaces the passphrase on `unlock`, `vault enroll` and
`vault recover`: the factor is a credential on your FIDO2 security key
(relying party: the server's `passkey_rp_id`, WebAuthn prf salt transform; see
go-xkms `docs/password-vault/architecture.md`). The key's PIN is always
required and comes from `--pin-stdin` or `XKEY_PIN`; a PIN given without
`--passkey` is refused. A passkey cannot be rotated: enroll a new one and
remove the old one.

`--key-factor piv|certificate|tpm` enrolls (or recovers with) a key held in
one of xKey's key backends -- the same local key store the xkey app runs,
opened with the barrier password (`--barrier-password-stdin`,
`--barrier-password-file`, `XKEY_BARRIER_PASSWORD`):

| Flag | Meaning |
|---|---|
| `--key-factor` | `piv` (the backend's slot 9d key), `certificate` (key `--key-id` with its certificate in the backend) or `tpm` (TPM key `--key-id`) |
| `--key-backend` | the xKey key backend holding the key (e.g. `pkcs11`, `tpm2`, `software`) |
| `--key-id` | the key's ID in the backend (`piv` defaults to slot 9d) |
| `--tpm-policy` | the named TPM policy the TPM key is bound to, recorded on the factor |
| `--pkcs11-library`, `--pkcs11-token` | the PKCS#11 module and token label of a PIV card or token (`--key-backend pkcs11`); default: the config's `piv.pkcs11_library` / `piv.pkcs11_token`, as for `xkey piv`. The token PIN comes from `XKEY_PIV_PKCS11_PIN` |

`xkey password unlock --key` unlocks with the first of the vault's key
factors whose key is in xKey's backends. The token is self-tested before
enrollment; the key never leaves its backend.

```bash
XKEY_VAULT_PASSPHRASE=... xkey password vault enroll --label laptop
XKEY_VAULT_PASSPHRASE=... xkey password vault recover --recovery-code-stdin < code.txt
XKEY_PIN=... xkey password vault enroll --passkey --label yubikey
XKEY_PIN=... xkey password unlock --passkey
```

## `xkey password lock`

Ends the current `xkmsd` session. Requires `--xkmsd-url`. No flags.

```bash
xkey password lock
```

## `xkey password status`

Reports where the store lives and, when read from `xkmsd`, its access mode
and auto-unseal state. Neither `--source auto/daemon/disk` requires an
`xkmsd` server.

| Flag | Default | Description |
|---|---|---|
| `--store` | `~/.xkey/data/staticpw` | Path to the password store |
| `--socket` | auto-detect | IPC socket of a running daemon |
| `--source` | `auto` | `auto`, `daemon`, `disk`, or `xkmsd` |

```bash
xkey password status
xkey password status --source xkmsd --xkmsd-url https://xkms.example.com
```

## `xkey password access-mode`

Acts on an `xkmsd` server's session; requires `--xkmsd-url`.

| Flag | Default | Description |
|---|---|---|
| `--mode` | | `pin_per_operation` or `session_based` (required) |

```bash
xkey password access-mode --mode session_based
xkey password access-mode --mode pin_per_operation
```

## `xkey touch`

Approves a pending WebAuthn user-presence request, or types a password via
the virtual keyboard. Communicates with the running `xkey` daemon over IPC.

| Flag | Default | Description |
|---|---|---|
| `--password` | | Name of a password to type explicitly |
| `--socket` | auto-detect | IPC socket path |

```bash
xkey touch                                  # approve pending request, or type the default password
xkey touch --password "DatabaseProd"        # type a specific named password
xkey touch --socket "$XDG_RUNTIME_DIR/xkey/xkey.sock"
```

## `xkey fido2` password/touch flags

`xkey fido2` accepts these flags for password-typing and touch support
while the daemon runs. Each is bound to a Viper key (`fido2.*`) with
`viper.BindPFlag` (`xkey/cmd/xkey/cmd/fido2.go:436-440`), but that call is on
the global Viper singleton, which the `xkey` command tree never points at a
config file (`ReadInConfig`) and never enables for the environment
(`AutomaticEnv`/`SetEnvPrefix`). No `XKEY_FIDO2_*` environment variable
reaches these settings today, whatever the command's own `--help` text
says — only the flag does. Env-var and config-file support for `fido2.*` is
tracked in #871; until it lands, set these via flags:

| Flag | Default | Description |
|---|---|---|
| `--password-store` | `~/.xkey/data/staticpw` | Path to the static password store |
| `--socket` | `$XDG_RUNTIME_DIR/xkey/xkey.sock` | IPC socket path |
| `--default-password` | (none) | Password name typed on a bare `xkey touch` |
| `--notify-command` | (none) | Custom notification command (argv only, no shell); request data via `XKEY_OPERATION`/`XKEY_RP_ID`/`XKEY_RP_NAME`/`XKEY_USER_NAME` env vars |
| `--notify` | `dialog` | `dialog`, `passive`, `log`, or `none` |
