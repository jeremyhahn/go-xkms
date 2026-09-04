# Headless WebAuthn — CLI

> **Status: NORMATIVE** · Feature: `headless-webauthn` · Module: `go-xkms/xkey` · Last verified: 2026-09-03

Binary: `xkey`, group `auth` (`xkey/cmd/xkey/cmd/auth.go`). Needs a running
`xkey fido2` daemon to hold the credential — see
[`../virtual-authenticator/cli.md`](../virtual-authenticator/cli.md).

## `xkey auth register`

| Flag | Type | Default | Required |
|---|---|---|---|
| `--server` | string | — | **yes** |
| `--spki-pin` | string | `""` | when the CA is not yet trusted |
| `--tls-ca` | string | `""` | when the CA is in neither the trust store nor the system store |
| `--setup-token` | string | `""` | when the server requires pre-authorization |
| `--email` | string | — | **yes** |
| `--display-name` | string | the login key | no |

```
xkey auth register \
    --server https://kms.example.com:8443 \
    --spki-pin 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 \
    --setup-token "$SETUP_TOKEN" \
    --email agent-build@example.com --display-name "Build agent"
```

### How the server is verified

`auth register` and `auth login` accept three CA sources, and they combine:

| Situation | What to pass | What is verified |
|---|---|---|
| the CA is in the xKey trust store (`xkey trust add`) | nothing | the chain, against the trust store plus the system roots |
| the CA is in a PEM file | `--tls-ca ca-chain.crt` | the chain, against that file plus the trust store and system roots |
| you have no CA, only a pin | `--spki-pin <hex>` | the server's public key, which is the trust anchor |
| you have both a CA file and a pin | `--tls-ca` and `--spki-pin` | the chain **and** the pin, on top of each other |

The trust store is read on every `auth` connection, so a CA added with
`xkey trust add ca-chain.crt --purpose user-ca` is enough on its own — pinning
is no longer the only route to a server whose CA you already trust.

A bare `--spki-pin` with no `--tls-ca` stays trust-on-first-use: the pin *is*
the trust anchor and no chain is built, so an unrelated CA sitting in the trust
store cannot break a working pinned invocation.

**Pass `--spki-pin` when enrolling against a server whose CA you do not have
yet.** It verifies the server before a credential is created for it.

**Pass `--email`.** It is the canonical login key the server resolves the
account by, and it has no default. The old `--username` default was the current
OS user — in a container usually `root` or a numeric UID — which the ceremony
then looked up as an email and missed.

## `xkey auth login`

| Flag | Type | Default | Purpose |
|---|---|---|---|
| `--server` | string | — | **required** |
| `--email` | string | — | **required**, the canonical login key |
| `--piv` | bool | `false` | authenticate with a PIV slot certificate over mTLS instead of WebAuthn |
| `--tls-ca` | string | `""` | extra PEM CA bundle, on top of the xKey trust store |
| `--slot` | string | `9a` | PIV slot, with `--piv` |
| `--backend` | string | `software` | PIV backend: `software` or `pkcs11`, with `--piv` |

```
xkey auth login --server https://kms.example.com:8443 --email agent-build@example.com
xkey auth login --server https://kms.example.com:8443 --piv --slot 9a --backend pkcs11
```

`login` reuses the SPKI pin recorded at registration as the server's trust
anchor, and reads the same CA sources `register` does — so a server registered
by pin can later be reached by CA trust, and the reverse. The same applies to
`login --piv`, `auth refresh` and `auth logout`: a server registered without a
pin is verified against the trust store rather than the system store alone.

`--piv` is a different route, not a fallback: mTLS with a slot certificate
rather than a WebAuthn assertion. Useful where the relying party already trusts
a certificate.

## Session management

| Verb | Flags |
|---|---|
| `auth status` | `--server` (filter to one server) |
| `auth token` | `--server` (**required**) |
| `auth refresh` | — |
| `auth logout` | — |

```
xkey auth status -o json
export TOKEN=$(xkey auth token --server https://kms.example.com:8443)
xkmsctl --server https://kms.example.com:8443 --token "$TOKEN" key list
```

`auth token` is the bridge to everything else: it prints a session token that
`xkmsctl` and any SDK consumer can use.

## A CI enrolment, end to end

```
xkey fido2 --storage file --storage-path "$XDG_DATA_HOME/xkey" \
           --backend tpm2 --auto-uv --notify none &

xkey auth register --server "$XKMS" --spki-pin "$PIN" \
                   --setup-token "$SETUP_TOKEN" --email agent-build@example.com
xkey auth login --server "$XKMS" --email agent-build@example.com
xkmsctl --server "$XKMS" --token "$(xkey auth token --server "$XKMS")" key list
```

`--auto-uv` and `--notify none` are what make it work unattended, and are
exactly what you would not set on a workstation.

## Exit codes

`0` on success. Non-zero for an SPKI mismatch, an unreachable server, a missing
authenticator daemon, an invalid setup token, or a failed ceremony.

An SPKI mismatch is the one to stop on rather than retry.

## Parity coverage

The `go-xkms` parity runner covers `xkmsctl`, not `xkey`. This feature's real
coverage is `go-xkms/test/integration/logins`, which builds `xkey` and drives
registration and login against a live server.
