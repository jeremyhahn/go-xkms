# Static Passwords — User Guide

> **Status: NORMATIVE** · Feature: `password` · Module: `go-xkms/xkey` · Last verified: 2026-10-01

## Store a password

```bash
xkey password add --name "DatabaseProd" --password-stdin < password.txt

# With metadata the browser extension uses for autofill matching
XKEY_STATIC_PASSWORD="tok_abc123" xkey password add --name "GitHubWork" \
  --title "GitHub (Work)" --username "jdoe" --url "https://github.com"

# Generate one instead of typing it
xkey password add --name "ServiceAccount" --generate --length 64
```

There is no `--password` value flag: a value on the command line is visible
to every other process on the host via `ps`. The password comes from
`--password-stdin` or `XKEY_STATIC_PASSWORD` instead.

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
# First time: create your personal vault (prints a one-time recovery code)
XKEY_VAULT_PASSPHRASE=... xkey password vault enroll --xkmsd-url https://xkms.example.com

# Unlock your personal entries with your own passphrase until you lock
XKEY_VAULT_PASSPHRASE=... xkey password unlock --xkmsd-url https://xkms.example.com
xkey password lock --xkmsd-url https://xkms.example.com

# See the session's access mode and lock state
xkey password status --source xkmsd --xkmsd-url https://xkms.example.com
```

## Unlock your server vault with a key

Your personal vault on an `xkmsd` server can open with a key xKey holds: a
PIV card (slot 9d), a certificate's key, or a TPM key bound to a named TPM
policy. In the app's vault panel, *Add key* enrolls one (pick the factor,
the xKey backend and the key) and *Unlock with key* uses it; on the command
line, `xkey password vault enroll --key-factor ...` and
`xkey password unlock --key`.

**From the web console.** The console's *Unlock with xKey* reaches the app
through the xKey browser extension. The app shows *Unlock your password
vault?* with the page's address and the key; approve it only if you just
asked the console to unlock. xKey then unlocks the vault itself -- the page
never receives a key or a secret. A page that is not your server's console
is refused without asking you, and a request nobody approves expires after
two minutes. The headless `xkey extension serve` has no window to ask in and
refuses these requests; run the app.

## Back up the vault from the GUI

**Passwords → Backup** writes either plain JSON or, with **Encrypt**
checked, an encrypted `.enc` file under a password you choose. The password
is stretched with Argon2id (64 MiB, random salt), so a stolen backup file
resists offline guessing. **Restore** needs the same password and the same
AES size you chose when backing up.

Encrypted backups made before go-xkms#1202 are refused ("not a salted
password backup"): they used an unsalted hash of the password. Restore is
not possible from them in this release; make a fresh backup.

## At-rest protection

Run `xkey barrier init` once; every password store then encrypts at rest
automatically. See [seal/user.md](../seal/user.md), including TPM
auto-unseal so an agent or headless daemon never needs the barrier
password.
