# SSH Keys, Known Hosts & Authorized Keys — CLI

> **Status: NORMATIVE** · Feature: `ssh-keys` · Repo: `go-xkms` · Last verified: 2026-09-24

`xkmsctl ssh` (`cmd/xkmsctl/ssh.go`) needs no build tag. It honors the global
`--server` / `--transport` / `--tls-ca` flags every command group shares
(see [`../key-management/cli.md`](../key-management/cli.md) §"Global
flags"): omit `--server` to run against the embedded (in-process) transport;
set it to a `http(s)://`, `grpc(s)://`, `unix://`, `quic://`, or `mcp(s)://`
URL to reach a remote `xkmsd`.

Every subcommand takes `--scope` (default `user`) and `--owner` (default
`default`) (`cmd/xkmsctl/ssh.go:219-220`) except `authorized-keys emit`,
which is a pure local formatting helper with no identity coordinates.

## `xkmsctl ssh keys`

### `generate`

| Flag | Default | Meaning |
|---|---|---|
| `--name` | — | Key name (required). |
| `--type` | `ed25519` | `ed25519`, `rsa`, `ecdsa-p256`, `ecdsa-p384`, `ecdsa-p521`. |
| `--bits` | `0` | RSA modulus size (RSA only); `0` means the SDK default (4096). |
| `--comment` | — | Key comment. |
| `--key-backend` | — | Crypto backend to generate on (`software`, `tpm2`, `pkcs11`, cloud backend name). Empty generates a software key sealed in-process. |

```bash
xkmsctl ssh keys generate --name laptop --type ed25519
xkmsctl ssh keys generate --name laptop --type ecdsa-p256 --key-backend tpm2
```

### `list`

```bash
xkmsctl --server grpcs://kms.example.com:9443 --tls-ca ca.crt ssh keys list --scope user --owner alice
```

### `get` / `export` / `delete`

Each takes `--name` (required).

```bash
xkmsctl ssh keys get --name laptop
xkmsctl ssh keys export --name laptop        # prints the authorized_keys-format public line
xkmsctl ssh keys delete --name laptop
```

### `sign`

| Flag | Default | Meaning |
|---|---|---|
| `--name` | — | Key name (required). |
| `--data` | `xkmsctl-ssh-sign` | Data to sign (raw bytes of this string — no hashing applied by the CLI). |

```bash
xkmsctl ssh keys sign --name laptop --data "prove it"
```

### `import`

| Flag | Meaning |
|---|---|
| `--file` | Path to a PEM-encoded private key (required). |
| `--name` | Defaults to the file's base name without extension. |
| `--comment` | Key comment. |

An encrypted PEM's passphrase is read without echo from a TTY, or from
stdin when not attached to one — the plaintext lands directly in an
enclaved buffer (`cmd/xkmsctl/ssh.go`'s `sshPassphraseProvider`), never a
plain Go string.

```bash
xkmsctl ssh keys import --file ~/.ssh/id_ed25519 --name laptop
```

## `xkmsctl ssh known-hosts`

### `add`

| Flag | Meaning |
|---|---|
| `--host` | Host address (required). |
| `--key` | Host key as an `authorized_keys`-format line (required unless `--file`). |
| `--file` | Read the host key from a file instead of `--key`. |
| `--source` | Pin provenance; defaults to `xkmsctl`. |

```bash
xkmsctl ssh known-hosts add --host git.example.com --key "ssh-ed25519 AAAA..."
```

### `list` / `remove`

`remove` takes `--host` (required).

### `verify`

| Flag | Meaning |
|---|---|
| `--host` | Host address (required). |
| `--key` / `--file` | The key to check, as a line or a file — exactly one form is needed. |

```bash
xkmsctl ssh known-hosts verify --host git.example.com --file host.pub
```

A pin can no longer be created or matched from a bare fingerprint — both
`add` and `verify` require the full public key, as an `authorized_keys`
line or a file containing one.

## `xkmsctl ssh authorized-keys`

### `add`

| Flag | Meaning |
|---|---|
| `--name` | Entry name (required). |
| `--line` | `authorized_keys` line (required). |
| `--option` | Repeatable OpenSSH restriction option (e.g. `no-pty`, `command="..."`). |
| `--comment` | Entry comment. |

```bash
xkmsctl ssh authorized-keys add --name ci-runner --line "ssh-ed25519 AAAA..." --option no-pty
```

### `get` / `list` / `remove`

`get` and `remove` take `--name` (required).

### `emit`

Pure local formatting — never contacts the server, and takes no
`--scope`/`--owner`.

| Flag | Meaning |
|---|---|
| `--line` | Public key as an `authorized_keys`-format line (required). |
| `--option` | Repeatable restriction option. |
| `--comment` | Entry comment. |

```bash
xkmsctl ssh authorized-keys emit --line "ssh-ed25519 AAAA..." --option no-pty
```

### `verify`

| Flag | Meaning |
|---|---|
| `--key` / `--file` | The public key to check — exactly one form is needed. |

```bash
xkmsctl ssh authorized-keys verify --key "ssh-ed25519 AAAA..."
```

## What this CLI does not cover

Interactive console sessions (`xkey ssh console`), hostless agent-signing
sessions (`git commit -S` under `gpg.format=ssh`, `ssh-keygen -Y sign`), and
saved connection profiles are separate surfaces of the `xkey` CLI/GUI built
on top of this feature and on
[`../ssh-agent-sessions/`](../ssh-agent-sessions/) — see
[`../ssh/README.md`](../ssh/README.md) for those, which remains the
reference for that part of the surface until it gets its own folder.
