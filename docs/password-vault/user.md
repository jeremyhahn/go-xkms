# Password Vault — User Guide

> **Status: NORMATIVE** · Feature: `password-vault` · Repo: `go-xkms` · Last verified: 2026-08-19

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

## Unlock first

```
xkmsctl password unlock --user-pin -
xkmsctl password status -o json
```

Under `session_based` mode you unlock once and reads work until you lock again.
Under `pin_per_operation` there is no unlock — every read carries the PIN.

`password status` tells you which mode you are in, and it works while locked.

## Adding and reading

```
xkmsctl password add "upstream-portal" \
    --username ops@example.com --url https://portal.example.com \
    --folder infra --password -

xkmsctl password list --folder infra -o json
xkmsctl password get pw-123 -o json                  # metadata only
xkmsctl password get pw-123 --decrypt --user-pin -   # the actual password
```

**Plaintext is opt-in.** Without `--decrypt` you get metadata — which is what
you want in a script, in a log, and on a screen-share.

Omit `--password` and it prompts. `-` reads stdin. Typing the value on the
command line puts it in your shell history.

**Do not put passwords in `--notes`.** It is free-form, it reaches durable
storage, and it is not what the decrypt gate protects.

## Choosing the access mode

```
xkmsctl password access-mode session_based
xkmsctl password access-mode pin_per_operation
```

This is a real security decision:

- **`session_based`** — convenient. While the store is unlocked, anything that
  can reach it can read every entry in your scope.
- **`pin_per_operation`** — the PIN on every single read. Annoying, and the
  exposure window is one operation instead of one session.

Pick deliberately, and `password lock` when you walk away.

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
| reads fail with "locked" | `session_based`, and you have not unlocked | `password unlock --user-pin -` |
| every read asks for a PIN | `pin_per_operation` mode | expected; or change the mode deliberately |
| an entry you created is "not found" | wrong scope or tenant | `--scope all`, and check `--tenant-id` |
| `password` routes return 404 | the vault is not configured on this server | server-side configuration |
| an expired entry still works | expiry is metadata, not enforcement | rotate it |
| plaintext appeared in a log | something asked for `--decrypt` and printed it | use metadata-only reads in scripts |
| the browser extension cannot reach the vault | xkey's IPC socket | check the daemon and the socket path |

## Where to go next

- Autofill and the browser extension: the xkey documentation
- Where the encryption comes from: [`../sealing-and-barrier/user.md`](../sealing-and-barrier/user.md)
- Team and tenant scoping: [`../multi-tenancy/user.md`](../multi-tenancy/user.md)
- Who read what, and when: [`../audit-log/user.md`](../audit-log/user.md)
