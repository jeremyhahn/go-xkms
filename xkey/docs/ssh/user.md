# SSH — User Guide

> **Status: NORMATIVE** · Feature: `ssh` · Module: `go-xkms/xkey` · Last verified: 2026-09-27

## Generate a key and use it

```bash
xkey ssh keys generate --name laptop --type ed25519
xkey ssh keys list
xkey ssh keys export --name laptop >> ~/.ssh/authorized_keys
```

Use `--backend tpm2` or `--backend pkcs11` to generate on hardware
instead of the software store — the private key then never leaves the
device; see [`../pkcs11/user.md`](../pkcs11/user.md) for the PKCS#11
case. Keys generated from the CLI and the GUI share one store, so a key
made in either front end shows up in the other immediately.

## Save a profile and connect

```bash
xkey ssh profile add --name prod-web --host web1 --user deploy --key laptop
xkey ssh connect prod-web
```

`connect` opens the session in your current terminal, using the native
`ssh` client — the first time you connect to an unpinned host you'll see
the usual OpenSSH fingerprint prompt; accepting it pins the host key into
xkey's store for next time.

For a one-time connection without saving a profile:

```bash
xkey ssh connect deploy@web1 --key laptop
```

## Prefer an in-app terminal instead

```bash
xkey ssh console prod-web
```

Runs the same session in-process rather than spawning `ssh` — no
subprocess, same key, same host-key pins. In the desktop app this is the
**embedded console** tab in the SSH application; check **Persistent
session** (or add `--persist-session` to a profile) to have the tab
survive a reload or app restart — it comes back disconnected, with
Reconnect one click away. List or clean up saved sessions with:

```bash
xkey ssh sessions list
xkey ssh sessions remove <id>
```

## Connect with your own SSH setup instead of an xkey key

If you'd rather use your existing `ssh_config`/`ssh-agent` setup for a
particular connection, xkey gets out of the way entirely — no in-process
agent, no known_hosts override, no added options:

```bash
xkey ssh local hosts                                    # see what ssh_config already knows
xkey ssh local keys                                     # see what your agent/~/.ssh offer
xkey ssh connect --local --ssh-config-alias prod-bastion # plain `ssh prod-bastion`
xkey ssh connect deploy@web1 --identity ~/.ssh/id_ed25519
xkey ssh connect deploy@web1 --identity agent:SHA256:pNYoqv...
```

A profile can be pinned to this mode permanently:

```bash
xkey ssh profile add --name bastion --ssh-config-alias prod-bastion
```

Connecting with **no key at all** (`xkey ssh connect deploy@web1`) also
falls back to this plain passthrough — the system agent or a password
prompt authenticates, exactly like typing `ssh` yourself.

## Manage host-key pins

```bash
xkey ssh host-keys add --host bastion.example.com --key "ssh-ed25519 AAAA..."
xkey ssh host-keys list
xkey ssh host-keys remove --host bastion.example.com
```

A pin must be created from the **full public key** (`--key` or `--file`)
— a fingerprint alone is not accepted. Choose `--known-hosts-policy` on
`connect` (`barrier`, `system`, or `both`) to control whether new pins
also land in `~/.ssh/known_hosts`.

## Manage authorized_keys entries

```bash
xkey ssh authorized-keys add "ssh-ed25519 AAAA... ci-runner" --name ci-runner
xkey ssh authorized-keys list
```

## Work against a remote xkmsd instead of your local store

Every `keys`/`host-keys`/`authorized-keys`/`connect`/`console` command
accepts `--server`:

```bash
xkey ssh keys list --server grpcs://kms.example.com:9443 --tls-ca ca.crt
```

Without `--server`, setting `XKMSD_URL` (or the `xkmsd_url` config key)
has the same effect; otherwise commands use your local store.

## If SSH commands fail with "local store is barrier-encrypted"

The CLI cannot unlock a barrier-encrypted SSH store on its own. Unlock the
barrier through the xkey desktop app (TPM/PCR-policy auto-unseal, or a
manual unlock), then retry the CLI command. See
[`../seal/user.md`](../seal/user.md).

## See also

- [CLI](cli.md) — every verb and flag
- [Architecture](architecture.md) — why some things (barrier unlock,
  local passthrough) work the way they do
- Root SSH docs (backend-native key generation, the console protocol,
  agent-only signing sessions for `git commit -S`):
  [`../../../docs/ssh/README.md`](../../../docs/ssh/README.md),
  [`../../../docs/ssh-agent-sessions/user.md`](../../../docs/ssh-agent-sessions/user.md)
