# FIDO2 / CTAP2 Client — User Guide

> **Status: NORMATIVE** · Feature: `fido2-ctap2` · Repo: `go-xkms` · Last verified: 2026-08-19

## What this does

Talks to the security key plugged into your machine, with no browser involved.
Two things: enroll a credential on the key, and use the key to derive a secret.

The second one is the interesting one. A FIDO2 key can compute a stable secret
from a salt you give it — the same salt always gives the same answer, only that
key can produce it, and it will not do so without a touch. That is a key you
cannot copy off a laptop.

## Prerequisites

- A FIDO2 authenticator on USB, or an xkey acting as one.
- On Linux, permission to open the HID device. "No devices found" with the key
  plugged in is almost always a udev rule, not a broken key.

## First run

```
xkmsctl fido2 list-devices
xkmsctl fido2 info
```

If `list-devices` is empty and the key's light is on, check device permissions
before anything else.

## Enrolling a key

```
xkmsctl fido2 register alice \
    --rp-id kms.example.com \
    --rp-name "Example KMS" \
    --user-verification
```

Touch the key when it blinks. You get back a credential id — save it; you need
it to authenticate.

**Set `--rp-id` to your real relying-party id.** The default is `go-xkms`, a
development value. The id is recorded on the credential, and if you enroll under
one and authenticate under another, the key simply reports that it has no such
credential.

`--user-verification` requires a PIN as well as a touch. Without it, a touch is
enough — which means anyone with physical access to the plugged-in key can use
it.

## Deriving a key

```
xkmsctl fido2 authenticate \
    --rp-id kms.example.com \
    --credential-id "$CRED_ID" \
    --salt "$SALT" \
    --user-verification --hex
```

The output is a secret. It goes to stdout so you can pipe it — and it lands in
your scrollback if you do not.

The same credential and the same salt always produce the same output. Different
salts give unrelated keys from one credential, which is how one key can protect
several things independently.

## Waiting for a key to be inserted

Useful in scripts:

```
xkmsctl fido2 wait-device --timeout 2m
```

## Troubleshooting

| What you see | What it means | What to do |
|---|---|---|
| "no devices found", key is plugged in | the process cannot open the HID device | fix device permissions (udev on Linux) |
| operation times out with no prompt | nobody touched the key | the key blinks; touch it within `--timeout` |
| "credential not found" | `--rp-id` differs from enrollment | use the same value you registered with |
| PIN rejected | wrong PIN | note the remaining attempts — keys lock out permanently |
| key stopped responding entirely | it locked out after too many wrong PINs | that is the key's design; it cannot be reset |
| a specific device is picked and it is the wrong one | multiple keys attached | pass `--device` |

**BREAKING (2026-09-22):** the `--legacy-hmac-derivation` flag is gone. The
CTAP 2.1 §12.5 derivation is the only one; a volume keyed with the removed
insecure derivation must be re-enrolled — there is no flag to unlock it.

## Where to go next

- Using the key to log in to a server: [`../webauthn/user.md`](../webauthn/user.md)
- Using the key as an authentication factor: [`../auth-factors/user.md`](../auth-factors/user.md)
- Being an authenticator instead of driving one: [`../../xkey/docs/virtual-authenticator/user.md`](../../xkey/docs/virtual-authenticator/user.md)
