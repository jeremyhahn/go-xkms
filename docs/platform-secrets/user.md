# Platform Secrets — User Guide

> **Status: NORMATIVE** · Feature: `platform-secrets` · Repo: `go-xkms` · Last verified: 2026-08-19

## What this is for

A small store of named secrets belonging to the platform itself — an upstream
API token, a webhook secret, a bootstrap credential. Not keys, not user
passwords, not application data.

| If you have… | Use |
|---|---|
| a cryptographic key | [`../key-management/user.md`](../key-management/user.md) |
| a user's password | the password vault (`pkg/staticpw`, xkey) |
| a platform credential | this |

## The commands

```
xkmsctl platform put upstream-api-token --value -
xkmsctl platform get upstream-api-token --output /run/secrets/token
xkmsctl platform list -o json
xkmsctl platform delete upstream-api-token
xkmsctl platform status -o json
```

`put` prompts when `--value` is omitted, and `-` reads stdin:

```
printf '%s' "$TOKEN" | xkmsctl platform put upstream-api-token --value -
xkmsctl platform put webhook-secret --file ./webhook.key
```

`get` without `--output` writes the secret to stdout, which means into your
scrollback. Use `--output`; it writes at mode 0600.

`list` returns **names**. Names are not secret; values are.

## Overwriting is permanent

`put` over an existing name replaces it with a fresh seal. There is no version
history and no previous value to recover. If the old value matters, read it out
before overwriting.

## The failure you will actually hit

On a TPM-sealed deployment, secrets are bound to the machine's measured state.
After a firmware update, a kernel change, or anything else that moves the PCRs,
existing secrets stop opening.

```
xkmsctl platform reseal upstream-api-token
```

`reseal` reads the current plaintext, throws away the old sealed copy, and
writes it back sealed against the machine's state **now**.

Two things to be careful about:

- It is a separate command on purpose. Resealing silently on every read would
  quietly re-bind your secrets to whatever state the machine is in — including a
  state you would not have approved.
- Run it only on a machine whose state you have verified. Resealing on a
  compromised machine blesses that machine.

## "Not found" is not the same as "will not open"

If `get` fails, ask which one it is:

- **Not found** — the name was never stored, or was deleted.
- **Cannot open in the current state** — the secret is there and the platform
  changed.

The second one needs `reseal`, not a fresh `put`. Treating it as the first is
how a recoverable state change turns into a lost secret.

## Is your store actually sealed?

The store does not encrypt anything itself — its backend does. In production
that backend is sealed under the barrier, so protection follows whichever
strategy the barrier uses. In a test setup it may be a plain file, in which case
**secrets are stored as-is**.

The commands behave identically either way, which is convenient and also means
you cannot tell from the client side. Confirm the backend before treating this
as protected storage.

## Troubleshooting

| What you see | What it means | What to do |
|---|---|---|
| `platform` routes return 404 | the platform store is not configured | server-side configuration |
| "not found" for a secret you stored | wrong name, or it was deleted | `platform list` |
| get fails after a firmware or kernel update | the sealed value is bound to the old platform state | `platform reseal <name>` |
| reseal fails | the current plaintext could not be read | the secret may be unrecoverable in this state |
| the old value is gone after a `put` | overwrite is destructive by design | read before overwriting |
| secrets readable straight off disk | the backend is not a sealed one | server-side configuration |

## Where to go next

- What does the sealing: [`../sealing-and-barrier/user.md`](../sealing-and-barrier/user.md)
- Why platform state changes break sealed data: [`../tpm2/user.md`](../tpm2/user.md)
- Per-tenant stores: [`../multi-tenancy/user.md`](../multi-tenancy/user.md)
