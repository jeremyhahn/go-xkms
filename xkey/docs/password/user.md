# Static Passwords — User Guide

> **Status: NORMATIVE** · Feature: `password` · Module: `go-xkms/xkey` · Last verified: 2026-09-27

## Store a password

```bash
xkey password add --name "DatabaseProd" --password "s3cretP@ss!"

# With metadata the browser extension uses for autofill matching
xkey password add --name "GitHubWork" --password "tok_abc123" \
  --title "GitHub (Work)" --username "jdoe" --url "https://github.com"

# Generate one instead of typing it
xkey password add --name "ServiceAccount" --generate --length 64
```

## Retrieve a password

```bash
# Print just the password, for piping
xkey password get "DatabaseProd"
DB_PASS=$(xkey password get "DatabaseProd")

# List everything (values masked by default)
xkey password list

# Reveal values -- reads the on-disk store directly, not the daemon
xkey password list --source disk --show-passwords
```

## Type a password without copy/paste

With `xkey fido2` running, either of these types the password as if a
physical keyboard entered it:

```bash
xkey password type "DatabaseProd"
xkey touch --password "DatabaseProd"
```

`xkey touch` with no `--password` approves a pending WebAuthn user-presence
request instead, or types the configured `--default-password` — this is
the YubiKey-style "just touch it" behavior.

## Remove a password

```bash
xkey password remove "DatabaseProd"           # asks to confirm
xkey password remove --force "ServiceAccount" "WiFi"
```

## Check where the store lives

```bash
xkey password status
```

Reports whether a running daemon answered (it holds the barrier and can
see a barrier-encrypted store) or the on-disk store directory did.

## Session-based access (requires an `xkmsd` server)

These three verbs manage a password session on a remote `xkmsd` server, not
the local store's location:

```bash
# Switch to session mode: one PIN entry unlocks everything until locked
xkey password access-mode --mode session_based --xkmsd-url https://xkms.example.com

xkey password unlock --pin "1234" --xkmsd-url https://xkms.example.com
xkey password lock --xkmsd-url https://xkms.example.com

# See the session's access mode and lock state
xkey password status --source xkmsd --xkmsd-url https://xkms.example.com
```

## At-rest protection

Run `xkey barrier init` once; every password store then encrypts at rest
automatically. See [seal/user.md](../seal/user.md), including TPM
auto-unseal so an agent or headless daemon never needs the barrier
password.
