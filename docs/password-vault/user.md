# Password Vault — User Guide

> **Status: NORMATIVE** · Feature: `password-vault` · Repo: `go-xkms` · Last verified: 2026-10-01

## What goes in here

Ordinary secrets — the ones a person reads: a login for an upstream service, a
database password, a credential your browser fills in.

| If you have… | Use |
|---|---|
| a cryptographic key | [`../key-management/user.md`](../key-management/user.md) |
| a platform credential nobody reads | [`../platform-secrets/user.md`](../platform-secrets/user.md) |
| a password a human uses | this |

The same store backs `xkmsctl password`, `xkey password`, and the browser
extension's autofill. One vault, several front doors.

## Set up your vault, then unlock

Your personal entries are sealed with your own key. Enroll a passphrase
once; that creates your vault, unlocks it, and prints a **recovery code**
that is never shown again -- store it somewhere safe now:

```
xkmsctl password vault enroll --label laptop
```

After that, unlock with your passphrase:

```
xkmsctl password unlock --passphrase -
xkmsctl password status -o json
```

You can use your FIDO2 security key instead of, or as well as, a passphrase:
`xkmsctl password vault enroll --passkey` adds it (you are asked for the
key's PIN and to touch it), and `xkmsctl password unlock --passkey` unlocks
with it. A key enrolled from one tool -- xkmsctl, xkey, the xkey app, or the
web console -- works in all of them. Passkeys belong to the server's web
console domain; a server without a WebAuthn relying party configured offers
none.

You can also unlock with a key you already hold: a **PIV card** (its key
management slot, 9d), a **certificate's key** (a client certificate, in a
file, on a token or in a TPM), or a **TPM key** bound to a named TPM policy,
which opens only on that machine in the state the policy expects. Enroll it
with `xkey password vault enroll --key-factor piv|certificate|tpm ...`,
*Add key* in the xkey app, or -- for a certificate key in a file or a TPM key,
not a PIV card or PKCS#11 token -- `xkmsctl password vault enroll --key-factor
certificate|tpm ...`;
unlock with `--key`, *Unlock with key*, or, in the web console, *Unlock with
xKey*. The key never leaves its card, token or TPM, and the server cannot
open your vault with it alone.

Nobody else can open your personal entries: not another user, not a tenant
administrator, not someone holding the tenant's key. If you forget your
passphrase, `xkmsctl password vault recover --recovery-code -` enrolls a new
one with the recovery code and gives you a new code. Without your passphrase
or your recovery code, your personal entries cannot be recovered.

**In the web console** (Passwords): the first visit offers *Create your
vault* with a passphrase and shows the recovery code once. A locked vault
unlocks with your passphrase, or with *Use recovery code*, which takes the code
and a new passphrase and shows your next code. While unlocked, *Vault factors*
lists your factors and lets you add a passphrase or a passkey, change a
passphrase, or remove a factor (the last unlock factor, and the recovery code,
cannot be removed). *Create with a passkey*, *Unlock with passkey* and
*Recover with a new passkey* use your security key or platform passkey; a
browser or key without the WebAuthn PRF extension is told so, and you use your
passphrase instead.

A PIV card, certificate key or TPM key never enters the browser. *Unlock with
xKey* asks the xKey browser extension, which asks the xKey app; xKey shows the
request -- the page's address and the key -- and unlocks your vault itself
once you approve. Without the extension the console says the factor needs it.
Add such keys with xKey (or, for a certificate file or TPM key, xkmsctl).

You unlock once and your personal entries are readable until you lock again.
The session is yours alone: unlocking does not open anyone else's personal
entries, and another user locking does not lock you.

Shared entries (`--shared`) need no unlock. Every user of your tenant can read
them whenever the tenant is unsealed; only their owner or a tenant Admin can
change or delete them.

`password status` tells you whether your session is unlocked, and it works
while locked.

## Adding and reading

```
xkmsctl password add "upstream-portal" \
    --username ops@example.com --url https://portal.example.com \
    --folder infra --password -

xkmsctl password list --folder infra -o json
xkmsctl password get pw-123 -o json
```

`password get` returns the entry, including the password field, exactly as it
was stored once the store is unlocked -- there is no separate plaintext/
metadata mode and no `--decrypt` flag: confidentiality at rest is provided by
the tenant barrier, not by anything on a `get` request. `password list` never
returns the password field, whether or not the store is unlocked.

Omit `--password` and it prompts. `-` reads stdin. Typing the value on the
command line puts it in your shell history.

**Do not put passwords in `--notes`.** It is free-form and it reaches durable
storage exactly like the `password` field does.

## Access mode

```
xkmsctl password access-mode session_based
```

`session_based` is the only mode that actually takes effect: the mode is
fixed by how the store was set up when the server started, and
`pin_per_operation` cannot be switched to at runtime. Requesting
`pin_per_operation` on a store that is not already in that mode fails rather
than silently staying on `session_based`.

`password lock` when you walk away — while your session is unlocked, anything
that can act as you can read your personal entries.

## Sharing within a team

```
xkmsctl password add "shared-vpn" --shared --tenant-id acme --password -
xkmsctl password list --scope all --tenant-id acme
```

`--scope own | shared | all` decides what a listing shows. An entry outside your
scope reports as **not found**, not "forbidden" — so a 404 does not prove the
entry does not exist somewhere else.

## Expiry

```
xkmsctl password add "rotating-token" --expires-at 2027-01-01T00:00:00Z --password -
```

`expires_at` is a **note to yourself**. Nothing here disables the credential
when the date passes; it marks the entry so you know to rotate it. The upstream
service is what actually enforces expiry, or does not.

## Generating

```
xkmsctl password generate --length 32
```

## Troubleshooting

| What you see | What it means | What to do |
|---|---|---|
| reads fail with "locked" | you have not unlocked the store | `password unlock --passphrase -` (first time: `password vault enroll`) |
| an entry you created is "not found" | wrong scope or tenant | `--scope all`, and check `--tenant-id` |
| `password` routes return 404 | the vault is not configured on this server | server-side configuration |
| an expired entry still works | expiry is metadata, not enforcement | rotate it |
| plaintext appeared in a log | `password get` logged or printed the response | avoid logging `get` output; use `password list` in scripts |
| the browser extension cannot reach the vault | xkey's IPC socket | check the daemon and the socket path |

## Where to go next

- Autofill and the browser extension: the xkey documentation
- Where the encryption comes from: [`../sealing-and-barrier/user.md`](../sealing-and-barrier/user.md)
- Team and tenant scoping: [`../multi-tenancy/user.md`](../multi-tenancy/user.md)
- Who read what, and when: [`../audit-log/user.md`](../audit-log/user.md)
