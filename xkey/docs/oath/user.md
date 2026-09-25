# OATH TOTP/HOTP — User Guide

> **Status: NORMATIVE** · Feature: `oath` · Module: `go-xkms/xkey` · Last verified: 2026-09-24

## Add a credential

```bash
# Easiest: scan the QR code a service shows on screen
xkey oath scan

# Or paste the secret directly
xkey oath add --name "GitHub" --secret JBSWY3DPEHPK3PXP --issuer "GitHub"

# Or paste the otpauth:// URI from the QR code
xkey oath add --uri "otpauth://totp/GitHub:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"
```

## Generate a code

```bash
xkey oath generate "GitHub"
# 123456  (expires in 15s)

xkey oath generate --all
```

## List credentials

```bash
xkey oath list

# Reveal secrets (for backup)
xkey oath list --secrets

# Export as otpauth:// URIs (for regenerating a QR code)
xkey oath list --uri
```

## Remove a credential

```bash
xkey oath remove "GitHub"
xkey oath remove --force "GitHub" "AWS"
```

## At-rest protection

Once you run `xkey barrier init`, every `xkey oath` command at the default
store location encrypts credentials transparently — nothing else to do. See
[seal/user.md](../seal/user.md) to set the barrier up (including
TPM auto-unseal, so an agent never needs a password). Without a barrier,
credentials are stored as plain JSON at `~/.xkey/data/oath.json` (or
wherever `--store` points); protect that file with filesystem permissions.

## Migrate credentials to a new machine

```bash
# On the old machine
xkey oath list --uri > oath-export.txt

# On the new machine, for each line
xkey oath add --uri "otpauth://totp/..."
```

## Back up credentials

```bash
xkey oath list --secrets   # human-readable backup
xkey oath list --uri       # machine-readable, re-importable
```
