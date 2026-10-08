# PKCS#11 Provider Module — User Guide

> **Status: NORMATIVE** · Feature: `pkcs11-provider-module` · Repo: `go-xkms` · Last verified: 2026-10-08

## What you get

A `.so` you hand to software that already speaks PKCS#11 — OpenSSL, NSS, Java,
`ssh-agent`, disk encryption, TLS terminators. From their point of view they
have acquired a cryptographic token. From yours, their keys are now in xkms and
under whatever backend and policy you configured.

Nothing about the consumer changes. That is the entire value.

## Which direction am I going?

Ask this before anything else, because both directions involve PKCS#11 and they
are opposites:

- **Other software should use xkms keys** → this feature. Build the `.so`, point
  the consumer at it.
- **xkms should use a token's keys** → not this feature. Use `--backend pkcs11`
  and see [`../crypto-backends/user.md`](../crypto-backends/user.md).

## Building it

```
CGO_ENABLED=1 go build -buildmode=c-shared -o build/lib/libxkms_pkcs11.so ./cmd/pkcs11-module
```

## Offline mode — no server needed

The mode to start with, and the mode you need at boot time or on an isolated
host:

```
export XKMS_PKCS11_MODE=local
export XKMS_PKCS11_LOCAL_KEYDIR="$XDG_DATA_HOME/xkms/pkcs11-keys"
export XKMS_PKCS11_USER_PIN='…'

pkcs11-tool --module ./build/lib/libxkms_pkcs11.so --list-slots
```

Key material at rest is protected under your user PIN by default. You can turn
that off:

```
export XKMS_PKCS11_SEAL_STRATEGY=none    # cleartext on disk — development only
```

`none` stores keys in the clear, the same way SoftHSM does by default. The
default is `passphrase`, which is the one you want anywhere real.

## Remote mode — shared token state

The default. Omit `XKMS_PKCS11_MODE` and point it at a server:

```
export XKMS_PKCS11_TARGET=kms.example.com:9443
export XKMS_PKCS11_TLS_ENABLED=true
export XKMS_PKCS11_TLS_CA=/etc/xkms/ca-bundle.pem
export XKMS_PKCS11_TLS_CERT=/etc/xkms/client.crt
export XKMS_PKCS11_TLS_KEY=/etc/xkms/client.key
export XKMS_PKCS11_TOKEN_LABEL=example-token
export XKMS_PKCS11_USER_PIN='…'
```

Token state lives on the server, so several hosts can share one token view.
Hosts share a token only if they authenticate as the same tenant. The server
files token state under the tenant of the client certificate or identity, not
under any `tenant_id` in the module's configuration. If the configured
`tenant_id` names a different tenant, every state call fails with an
invalid-argument error, so the token can neither load nor persist its state.
Leave `tenant_id` unset, or set it to your own tenant.

There is an `XKMS_PKCS11_ALLOW_INSECURE_TRANSPORT` and it defaults to off.
Turning it on sends token operations over an unauthenticated channel.

### Remote mode against a node-local sign server

A daemon that embeds the [sign server](../sign-server/user.md) creates the
keys and serves a unix socket. Point the consumer's module at it:

```
export XKMS_PKCS11_TARGET=unix:///run/<daemon>/ike.sock
export XKMS_PKCS11_STORAGE_TYPE=remote
export XKMS_PKCS11_TOKEN_LABEL=ike
export XKMS_PKCS11_DEFAULT_BACKEND=tpm2
```

The consumer finds its key by the `CKA_LABEL` or `CKA_ID` the daemon chose, and
signs with `CKM_ECDSA`. A process whose uid the server does not list fails at
`C_Initialize` with `CKR_DEVICE_ERROR`.

Upgrading from an earlier release: the server now keeps remote token state as
records in its `pkcs11state` database, and does not read state written by an
earlier release. Re-provision every remote token; there is no migration.

## PINs come from the environment

Cryptoki gives the module no way to prompt you, so `XKMS_PKCS11_SO_PIN` and
`XKMS_PKCS11_USER_PIN` are environment variables. Anything that can read the
process environment can read them — scope the environment to the process that
needs it, and do not export them in a shared shell profile.

## Using it with common consumers

```
# Enumerate
pkcs11-tool --module ./build/lib/libxkms_pkcs11.so --list-slots
pkcs11-tool --module ./build/lib/libxkms_pkcs11.so --list-objects --login

# OpenSSL, via the pkcs11 engine/provider
openssl pkeyutl -engine pkcs11 -keyform engine -sign \
    -inkey "pkcs11:token=example-token;object=web-tls" -in digest.bin
```

## Troubleshooting

| What you see | What it means | What to do |
|---|---|---|
| `C_Initialize` fails naming a backend | the module was built without that backend's build tag | rebuild with the tag; the environment can only select what was compiled in |
| state calls fail with `tenant_id does not match the authenticated identity's tenant` | the module's configured `tenant_id` is not the tenant its credentials authenticate as | unset `tenant_id` or correct it; the server always uses the authenticated tenant |
| `C_Initialize` fails in remote mode | target unreachable, TLS material wrong, or storage unusable | it fails closed on purpose — fix the cause, do not look for a fallback |
| `CKR_FUNCTION_NOT_SUPPORTED` (`0x54`) | this token will never do that operation | not a transient failure; four v3.2 surfaces are deliberately unimplemented |
| `CKR_USER_NOT_LOGGED_IN` | the mechanism needs a login first | supply the user PIN |
| two processes fight over token state | concurrent sessions | this is what the compare-and-swap state operations are for; a plain put in that path is a bug |
| offline keys are readable on disk | `XKMS_PKCS11_SEAL_STRATEGY=none` | unset it — the default protects them |
| a bare hex code in the consumer's log | a `CK_RV` | look it up in `pkg/pkcs11/module/errors.go` |

## What is not implemented

Four PKCS#11 v3.2 surfaces exist in the ABI and answer "not supported": KEM
operations, authenticated wrapping, signature-first post-quantum verification,
and asynchronous operations. That is the standards-conformant way to ship a
partial version — the function is there and the token tells you honestly that it
does not implement it. A consumer that needs one of these will get a clean
answer rather than a wrong result.

## Where to go next

- The keys behind the token: [`../key-management/user.md`](../key-management/user.md)
- Choosing which backend holds them: [`../crypto-backends/user.md`](../crypto-backends/user.md)
- PINs and lockout: [`../pin-management/user.md`](../pin-management/user.md)
