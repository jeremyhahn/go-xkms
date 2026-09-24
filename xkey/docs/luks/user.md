# LUKS2 Encrypted Storage — User Guide

> **Status: NORMATIVE** · Feature: `luks` · Module: `go-xkms/xkey` · Last verified: 2026-09-24

## What this protects, and what it doesn't

LUKS2 encrypts the **whole xKey home directory** at the filesystem level —
your credentials, passwords, trust anchors, OIDC tokens, and every other
file xKey writes, all at once, using kernel-level AES-256-XTS via dm-crypt.
It protects data **at rest**: someone who steals the disk, or reads it
through another OS, cannot read anything in it without the passphrase (or a
TPM-sealed key, if you set up auto-unseal).

It does **not** replace the Barrier (`xkey barrier init`), which encrypts
each secret individually and is always active. Choosing LUKS gives you both
layers; not choosing it still gives you the Barrier alone.

## Setting it up

During first-run setup (GUI wizard, or `xkey luks2 seal` from the CLI before
running anything else), choose the encrypted-storage option and pick a size
(100MB is the default and plenty for most installs; you can grow it later
with `xkey luks2 migrate`). You'll be asked for a passphrase — write it down
somewhere safe; it cannot be recovered if lost, and there is no backdoor.

## Using xKey day to day

**GUI**: if you set up LUKS, xKey shows an unlock screen at startup when the
volume isn't already open (for example, after a reboot). Enter your
passphrase there. If you configured TPM-backed auto-unseal, this step is
skipped automatically when the platform state matches what was sealed. Until
you unlock, none of your stores (passwords, passkeys, SSH keys, ...) are
available — this is intentional: xKey refuses to create or touch any of
those stores while the volume is locked, so nothing can end up written to
your disk unencrypted.

**CLI**: if a command touches your data and the volume is locked, xKey asks
you to unlock it:

```
$ xkey oath totp generate --account myservice
Encrypted storage detected at /home/you/.xkey.luks
Run with sudo to unlock: sudo xkey luks2 unseal
```

Run `sudo xkey luks2 unseal`, enter your passphrase, then re-run your
original command. If you're already root, xKey prompts for the passphrase
directly, inline, and continues.

A few commands are exceptions and run without unlocking, because they exist
specifically to manage the encrypted container or the parts of xKey that
must work before it's open: `xkey luks2 *` itself, `xkey barrier *`, `xkey
pin *`, and `xkey usb *`.

## Locking it again

```bash
sudo xkey luks2 lock       # CLI
```

or the "Lock" action in the GUI's storage settings. Locking closes the
mount; everything under it becomes unreadable again until the next unlock.

## If you forget your passphrase

There is no recovery. Back up your passphrase somewhere durable (a password
manager, a printed copy in a safe) before you rely on this. If you also
enabled TPM auto-unseal, losing the TPM (a new motherboard, a firmware
reset that changes PCR values) has the same effect as forgetting the
passphrase unless you kept a manual copy.

## Migrating and resizing

```bash
sudo xkey luks2 migrate --size 500M          # grow, keep same passphrase
sudo xkey luks2 migrate --wipe --wipe-standard dod7   # grow and securely erase the old container
```

## Destroying an encrypted volume for good

```bash
sudo xkey luks2 wipe --standard dod7
```

This overwrites the container file with the selected pattern before
removing it. There is a confirmation prompt (type `DESTROY`) unless you pass
`--force`. This is irreversible.
