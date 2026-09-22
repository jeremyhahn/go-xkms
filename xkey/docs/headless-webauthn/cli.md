# Headless WebAuthn — CLI

> **Status: NORMATIVE** · Feature: `headless-webauthn` · Module: `go-xkms/xkey` · Last verified: 2026-09-06

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
| `--pin-stdin` | bool | `false` | when the authenticator has a CTAP2 PIN set |
| `--pin` | string | `""` | alternative to `--pin-stdin`; visible in `ps` |

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
account by, and it has no default. There is no `--username` flag: the old
default was the current OS user — in a container usually `root` or a numeric
UID — which the ceremony then looked up as an email and missed.

### Supplying the authenticator's CTAP2 PIN

An authenticator with a PIN set refuses both ceremonies outright
(`CTAP2_ERR_PIN_REQUIRED`) unless the request carries the PIN — there is no
browser here to prompt for one. **The quick-setup wizard configures a PIN, so
this applies to a default install.** An authenticator with no PIN configured
needs none, and both verbs work unchanged without these flags.

`--pin` is the **authenticator's** PIN. It is unrelated to `--spki-pin`, which
is the server's public-key pin — the two are easy to confuse on `auth register`,
where both appear.

The PIN is resolved in the same precedence order `xkey unlock` uses:

| Source | Precedence | Notes |
|---|---|---|
| `--pin-stdin` | 1 | **preferred** — keeps the PIN out of `ps` and shell history |
| `XKEY_PIN` | 2 | environment variable |
| `--pin` | 3 | visible in the process list; local development only |

```
printf '%s' "$PIN" | xkey auth register --pin-stdin \
    --server https://kms.example.com:8443 --email agent-build@example.com

printf '%s' "$PIN" | xkey auth login --pin-stdin \
    --server https://kms.example.com:8443 --email agent-build@example.com
```

`--pin-stdin` with nothing on standard input is an error, not an empty PIN:
continuing silently would fail later inside the authenticator with a CTAP error
that names neither the PIN nor the flag.

`login --piv` takes no PIN — possession of the slot key is the credential, and
no authenticator ceremony runs.

### When the PIN is missing or wrong

| What happened | What you see |
|---|---|
| the key has a PIN and none was supplied | `this authenticator requires a PIN; supply it with --pin-stdin …` |
| the PIN was wrong | `invalid PIN (N attempts remaining before lockout)` |
| the attempts ran out | `PIN blocked` — the key needs a power cycle or a reset |
| the key has no PIN but one was supplied | `no PIN is set on this authenticator` |

The remaining-attempts count comes from the authenticator's own counter, so it
is what the device will actually enforce. Take it seriously: a key that reaches
zero is locked out.

## `xkey auth login`

| Flag | Type | Default | Purpose |
|---|---|---|---|
| `--server` | string | — | **required** |
| `--email` | string | — | **required**, the canonical login key |
| `--piv` | bool | `false` | authenticate with a PIV slot certificate over mTLS instead of WebAuthn |
| `--tls-ca` | string | `""` | extra PEM CA bundle, on top of the xKey trust store |
| `--slot` | string | `9a` | PIV slot, with `--piv` |
| `--backend` | string | `software` | PIV backend: `software` or `pkcs11`, with `--piv` |
| `--pin-stdin` | bool | `false` | when the authenticator has a CTAP2 PIN set |
| `--pin` | string | `""` | alternative to `--pin-stdin`; visible in `ps` |

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
           --backend tpm2 --require-touch=false --notify none &

# $SPKI_PIN is the server's SPKI pin; $CTAP_PIN is the authenticator's PIN.
printf '%s' "$CTAP_PIN" | xkey auth register --pin-stdin \
                   --server "$XKMS" --spki-pin "$SPKI_PIN" \
                   --setup-token "$SETUP_TOKEN" --email agent-build@example.com
printf '%s' "$CTAP_PIN" | xkey auth login --pin-stdin \
                   --server "$XKMS" --email agent-build@example.com
xkmsctl --server "$XKMS" --token "$(xkey auth token --server "$XKMS")" key list
```

`--require-touch=false` and `--notify none` are what make it work unattended,
and are exactly what you would not set on a workstation. The PIN on each
ceremony is the user verification: the daemon asks for no touch after
verifying it, and reports UV because it did. Nothing here claims a
verification that did not happen.

## Exit codes

`0` on success. Non-zero for an SPKI mismatch, an unreachable server, a missing
authenticator daemon, an invalid setup token, a missing or wrong CTAP2 PIN, or a
failed ceremony.

An SPKI mismatch is the one to stop on rather than retry.

## Parity coverage

The `go-xkms` parity runner covers `xkmsctl`, not `xkey`. This feature's real
coverage is `go-xkms/test/integration/logins`, which builds `xkey` and drives
registration and login against a live server.
