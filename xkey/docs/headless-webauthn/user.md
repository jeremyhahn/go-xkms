# Headless WebAuthn — User Guide

> **Status: NORMATIVE** · Feature: `headless-webauthn` · Module: `go-xkms/xkey` · Last verified: 2026-08-19

## What this is for

Signing in with a security key, with no browser and nobody present. It is how an
agent, a CI job or a daemon gets a real credential instead of a token sitting in
a file.

## Prerequisites

- A running `xkey fido2` daemon — it holds the credential. See
  [`../virtual-authenticator/user.md`](../virtual-authenticator/user.md).
- The server's URL and its **SPKI pin**.
- A setup token, if the server requires pre-authorization to enrol.

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

## Signing in

```
xkey auth login --server https://kms.example.com:8443 --email agent-build@example.com
xkey auth status -o json
```

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
           --backend tpm2 --auto-uv --notify none &

xkey auth register --server "$XKMS" --spki-pin "$PIN" \
                   --setup-token "$SETUP_TOKEN" --email agent-build@example.com
xkey auth login --server "$XKMS" --email agent-build@example.com

xkmsctl --server "$XKMS" --token "$(xkey auth token --server "$XKMS")" key list
```

`--auto-uv` satisfies user verification with no human, and `--notify none` stops
it waiting for a prompt nobody will see. Both are right here and wrong on a
laptop.

`--backend tpm2` is what makes this credential better than a file: it cannot be
copied off the machine.

## Troubleshooting

| What you see | What it means | What to do |
|---|---|---|
| SPKI pin mismatch | the server did not verify | **stop.** Confirm the pin out of band |
| "authenticator not found" | no `xkey fido2` daemon running | start it first |
| enrolment created an account nobody asked for | `--username` defaulted to the OS user, which the server looked up as an email and missed | pass `--email`; the OS-user default is gone |
| a bare 401 with no detail | intentional — the server does not say why | read the client's error, then the server log |
| routes return 404 | the server has no token issuer configured | server-side |
| it hangs at login | the authenticator is waiting for a touch | `--auto-uv`, and `--notify none` |
| the token works, then stops | the session expired | `xkey auth refresh` |
| 429 | login rate limiter | back off |

## Where to go next

- The authenticator holding the credential: [`../virtual-authenticator/user.md`](../virtual-authenticator/user.md)
- Running unattended: [`../agent-automation/user.md`](../agent-automation/user.md)
- Getting the SPKI pin and the CA bundle: [`../platform-trust/user.md`](../platform-trust/user.md)
- The server side: [`../../../docs/webauthn/user.md`](../../../docs/webauthn/user.md)
