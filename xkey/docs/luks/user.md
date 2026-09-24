# LUKS2 Encrypted Storage — User Guide

> **Status: NORMATIVE** · Feature: `luks` · Module: `go-xkms/xkey` · Last verified: 2026-09-27

LUKS is an optional, additional encryption layer under `~/.xkey/`, on top of
whatever the [Barrier](../seal/) already does for individual values. Use it
if you want the whole data directory unreadable at rest, not just the values
the barrier protects.

## Turn it on

```
sudo xkey luks2 seal
```

You will be prompted for a passphrase twice. If `~/.xkey/` already has data
in it, `seal` migrates it into the new encrypted container automatically —
pass `--skip-migrate` if you would rather start empty. By default the
container is left locked when `seal` finishes; add `--unseal` to leave it
unlocked and mounted so xkey can use it right away.

```
sudo xkey luks2 seal --size 500M --unseal
```

## Day to day: unlock before use, lock when done

```
sudo xkey luks2 unseal
# ... use xkey normally ...
sudo xkey luks2 lock
```

Nothing under `~/.xkey/` is readable while the container is locked — every
other `xkey` command that needs its data directory will fail until you run
`unseal` again.

## Need more space, or want to move the container?

```
sudo xkey luks2 migrate                    # doubles the current size
sudo xkey luks2 migrate --size 1G
sudo xkey luks2 migrate --path /secure/xkey.luks
```

By default `migrate` removes the old container once the new one is verified
working. Keep it as a backup with `--keep-old`, or destroy it securely
instead of a plain delete with `--wipe`.

## Destroy a container permanently

```
sudo xkey luks2 wipe
```

This overwrites the container's contents (DoD 3-pass by default) before
removing the file — the data is not recoverable afterward. You will be asked
to type `DESTROY` to confirm; `--force` skips that for scripted use, so
double-check the `--path` before using it.

## Bring existing data into an already-created container

If you created a container without migrating data (`--skip-migrate`, or a
container made for a different purpose), import it afterward:

```
sudo xkey luks2 import-data --source ~/.xkey --path ~/.xkey.luks --cleanup --unseal
```

`--cleanup` removes the plaintext source once the copy succeeds; add
`--backup` to rename it to `<source>-backup` instead of deleting it outright.

## Troubleshooting

- **"kernel keyring preflight failed"** — your container's seccomp profile
  (Docker's default profile does this) or kernel is blocking the
  `add_key`/`keyctl`/`request_key` syscalls dm-crypt needs. Run on the host,
  or allow those three syscalls in a custom seccomp profile.
- **"Device or resource busy"** — the container is already open or mounted;
  run `xkey luks2 lock` first.
- **Wrong passphrase** — there is no recovery; keep a secure backup of your
  passphrase, since LUKS provides none.
- **Automation** — pipe the passphrase (and confirmation, for `seal`) over
  stdin instead of a terminal; see [cli.md](cli.md#automation) for the exact
  form and an example systemd unit for unlocking at boot.
