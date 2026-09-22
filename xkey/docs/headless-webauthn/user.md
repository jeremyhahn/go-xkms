# Headless WebAuthn — User Guide

> **Status: NORMATIVE** · Feature: `headless-webauthn` · Module: `go-xkms/xkey` · Last verified: 2026-09-06

## What this is for

Signing in with a security key, with no browser and nobody present. It is how an
agent, a CI job or a daemon gets a real credential instead of a token sitting in
a file.

## Prerequisites

- A running `xkey fido2` daemon — it holds the credential. See
  [`../virtual-authenticator/user.md`](../virtual-authenticator/user.md).
- The server's URL and its **SPKI pin**.
- A setup token, if the server requires pre-authorization to enrol.
- The authenticator's **CTAP2 PIN**, if it has one. The quick-setup wizard sets
  one, so on a default install you need it.

## Enrolling

```
xkey auth register \
    --server https://kms.example.com:8443 \
    --spki-pin "$PIN" \
    --setup-token "$SETUP_TOKEN" \
    --email agent-build@example.com --display-name "Build agent"
```

Two things people get wrong here:

**Pass `--spki-pin`.** At enrolment you may not have the CA bundle yet. Without
the pin you are creating a credential for whatever answered.

**Pass `--email`.** It is the canonical login key the server resolves the
account by, and it has no default: an OS account name (in a container usually
`root` or a bare number) is a different identifier, and the ceremony would look
it up as an email and miss.

## When your key has a PIN

There is no browser here to prompt you, so a key with a PIN set refuses the
ceremony until you supply it. Pipe it in — that keeps it out of the process list
and your shell history:

```
printf '%s' "$CTAP_PIN" | xkey auth register --pin-stdin \
    --server https://kms.example.com:8443 \
    --spki-pin "$SPKI_PIN" --email agent-build@example.com
```

`XKEY_PIN` works too, and `--pin` exists for local development only — anyone on
the machine can read it out of `ps`.

If you leave the PIN out, the command tells you so by name rather than reporting
a CTAP error. If you get it wrong, it tells you how many attempts remain. **Do
not keep guessing**: a key that runs out locks itself, and getting it back means
a power cycle or a factory reset that destroys the credentials on it.

A key with no PIN configured needs none of this and works as before.

## Signing in

```
printf '%s' "$CTAP_PIN" | xkey auth login --pin-stdin \
    --server https://kms.example.com:8443 --email agent-build@example.com
xkey auth status -o json
```

Drop the `--pin-stdin` pipe if your authenticator has no PIN.

Then use the session anywhere:

```
export TOKEN=$(xkey auth token --server https://kms.example.com:8443)
xkmsctl --server https://kms.example.com:8443 --token "$TOKEN" key list
```

`xkey auth refresh` renews; `xkey auth logout` ends it.

## The PIV alternative

If the server already trusts a certificate in one of your PIV slots:

```
xkey auth login --server https://kms.example.com:8443 --piv --slot 9a --backend pkcs11
```

This is mTLS rather than WebAuthn — a different kind of evidence for the same
outcome.

## A CI job, start to finish

```
xkey fido2 --storage file --storage-path "$XDG_DATA_HOME/xkey" \
           --backend tpm2 --require-touch=false --notify none &

# $PIN is the server's SPKI pin; $XKEY_PIN is the authenticator's CTAP2 PIN.
printf '%s' "$XKEY_PIN" | xkey auth register --pin-stdin \
                   --server "$XKMS" --spki-pin "$PIN" \
                   --setup-token "$SETUP_TOKEN" --email agent-build@example.com
printf '%s' "$XKEY_PIN" | xkey auth login --pin-stdin \
                   --server "$XKMS" --email agent-build@example.com

xkmsctl --server "$XKMS" --token "$(xkey auth token --server "$XKMS")" key list
```

The PIN sent with each ceremony is the user verification, and
`--require-touch=false` tells the daemon not to ask for a touch on top of it.
`--notify none` stops it prompting for someone who is not there. Both flags are
right here and wrong on a laptop. There is no flag that reports a verification
nobody performed: a ceremony that carries no PIN waits for `xkey touch`, and
its credential is registered without user verification.

`--backend tpm2` is what makes this credential better than a file: it cannot be
copied off the machine.

## Troubleshooting

| What you see | What it means | What to do |
|---|---|---|
| SPKI pin mismatch | the server did not verify | **stop.** Confirm the pin out of band |
| "authenticator not found" | no `xkey fido2` daemon running | start it first |
| enrolment created an account nobody asked for | the login key defaulted to the OS user, which the server looked up as an email and missed | pass `--email`; there is no default and no `--username` flag |
| a bare 401 with no detail | intentional — the server does not say why | read the client's error, then the server log |
| routes return 404 | the server has no token issuer configured | server-side |
| it hangs at login | the authenticator is waiting for a touch: no PIN was sent, or `--require-touch` is still on | send the PIN with `--pin-stdin` and run the daemon with `--require-touch=false`; or answer with `xkey touch` |
| the token works, then stops | the session expired | `xkey auth refresh` |
| 429 | login rate limiter | back off |

## Where to go next

- The authenticator holding the credential: [`../virtual-authenticator/user.md`](../virtual-authenticator/user.md)
- Running unattended: [`../agent-automation/user.md`](../agent-automation/user.md)
- Getting the SPKI pin and the CA bundle: [`../platform-trust/user.md`](../platform-trust/user.md)
- The server side: [`../../../docs/webauthn/user.md`](../../../docs/webauthn/user.md)
