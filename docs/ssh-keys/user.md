# SSH Keys, Known Hosts & Authorized Keys — User Guide

> **Status: NORMATIVE** · Feature: `ssh-keys` · Repo: `go-xkms` · Last verified: 2026-09-24

## What this is for

`xkmsctl ssh` manages three things your SSH tooling already understands, but
generated and stored by xkms instead of on local disk:

- **Keys** — SSH identities. A key can be a plain software key, or one
  generated inside a hardware backend (TPM 2.0, a PKCS#11 token, a cloud
  KMS) so the private half never leaves that device.
- **Known hosts** — pinned host keys, the `known_hosts` equivalent, checked
  before xkms will trust a remote host during a session dial.
- **Authorized keys** — the `authorized_keys` equivalent: which public keys
  are allowed to authenticate as a given identity.

This works the same way whether you run it against a local (embedded)
instance or a remote `xkmsd` over REST, gRPC, a Unix socket, QUIC, or MCP —
add `--server <url>` (and `--tls-ca` for TLS transports) to any command
below to point it at a remote server; omit it to run entirely in-process.

## Generate a key

```bash
# A software ed25519 key, generated and sealed locally
xkmsctl ssh keys generate --name laptop --type ed25519

# A hardware-backed key: the private half never leaves the TPM
xkmsctl ssh keys generate --name laptop --type ecdsa-p256 --key-backend tpm2

# Against a remote server
xkmsctl --server grpcs://kms.example.com:9443 --tls-ca ca.crt \
  ssh keys generate --name deploy-key --key-backend pkcs11
```

TPM 2.0 cannot generate an Ed25519 key (no native Ed25519 key object in the
TPM 2.0 spec) — use `--type ecdsa-p256` or `--type rsa` with `--key-backend
tpm2`.

## Use the key with a real `ssh` client

Export the public key and add it wherever it needs to be authorized:

```bash
xkmsctl ssh keys export --name laptop
# ssh-ed25519 AAAA... laptop
```

Getting a *local* OpenSSH client to actually use an xkms-held key for a real
connection (rather than just producing signatures on demand) is the job of
[`../ssh-agent-sessions/`](../ssh-agent-sessions/) — start there for the
`git commit -S`-style hostless signing walkthrough — or the `xkey` desktop
app's connection manager, documented in
[`../ssh/README.md`](../ssh/README.md).

## Pin a host key before you trust it

```bash
xkmsctl ssh known-hosts add --host git.example.com --key "ssh-ed25519 AAAA..."
xkmsctl ssh known-hosts verify --host git.example.com --file host.pub
```

Verification always fails closed: an unpinned host, or a host whose pinned
key does not match, is rejected. There is no "accept the first key we see"
mode in this CLI — you always add the pin deliberately before verifying
against it.

## Authorize a key to act as an identity

```bash
xkmsctl ssh authorized-keys add --name ci-runner \
  --line "ssh-ed25519 AAAA..." --option no-pty --option 'command="/usr/local/bin/deploy"'

xkmsctl ssh authorized-keys verify --key "ssh-ed25519 AAAA..."
```

`--option` is repeatable and the values are passed straight through to
whatever enforces them (typically `sshd`) — xkms does not interpret
`no-pty`, `command="..."`, `from="..."`, etc. itself, it only stores and
re-emits them.

`emit` is a local formatting helper for producing a well-formed
`authorized_keys` line from a bare public key plus options — it never
contacts the server, so it works the same with or without `--server`:

```bash
xkmsctl ssh authorized-keys emit --line "ssh-ed25519 AAAA..." --option no-pty
```

## Import an existing key instead of generating one

```bash
xkmsctl ssh keys import --file ~/.ssh/id_ed25519 --name laptop
```

If the file is passphrase-encrypted, you will be prompted (no echo) unless
stdin is piped, in which case the passphrase is read from stdin.

## Scoping keys to a tenant, user, or service

Every command takes `--scope` (`tenant`, `user`, or `service`; default
`user`) and `--owner` (default `default`). Use these to keep, e.g., a CI
service's keys separate from an individual operator's:

```bash
xkmsctl ssh keys generate --name ci --scope service --owner ci-pipeline
xkmsctl ssh keys list --scope service --owner ci-pipeline
```

## Things that will surprise you

- **A pin needs the full public key, not a fingerprint.** Older
  fingerprint-only pins are rejected outright (`known-hosts verify`/`get`
  fail with a "must be re-pinned" error) — re-add the host with the full
  key.
- **`--data` on `ssh keys sign` is not hashed for you.** It is signed as the
  raw bytes of the string you pass; if you need to sign a digest, compute it
  yourself before invoking the command (or use the REST/MCP `sign` endpoint,
  which takes the same raw-bytes contract — see [`api.md`](api.md)).
- **`emit` and `verify` cost different things depending on transport.**
  Over gRPC, `known-hosts verify` and `authorized-keys emit`/`verify` are
  computed client-side from a full `list` call rather than a single
  server-side lookup — functionally identical, but worth knowing if you are
  scripting against a host with many pins/entries. See
  [`architecture.md`](architecture.md).
