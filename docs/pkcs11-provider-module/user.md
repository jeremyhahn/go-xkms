# PKCS#11 Provider Module — User Guide

> **Status: NORMATIVE** · Feature: `pkcs11-provider-module` · Repo: `go-xkms` · Last verified: 2026-10-12

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
make build-pkcs11-module
```

This writes `build/lib/libxkms_pkcs11.so` with every default backend,
including TPM 2.0. Pass `WITH_TPM2=0` to leave the TPM backend out.

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

## Configuration file

In remote mode the module also reads `/etc/xkms/pkcs11.conf` if it exists; the
environment overrides it. Offline mode reads only the environment.

```ini
target = unix:///var/run/xkms/xkms.sock
tls_enabled = true
tls_cert = /etc/xkms/pkcs11-client.pem
tls_key = /etc/xkms/pkcs11-client-key.pem
tls_ca = /etc/xkms/ca.pem
default_backend = software
token_label = example-token
piv_backends = software
```

xkmsd's socket is its embedded node's TLS listener, which refuses anonymous
callers, so a module pointed at it sets `tls_enabled` and presents a client
certificate xkmsd trusts (`module.go:1061-1066`). A sign server's socket is
plain gRPC and needs none of the `tls_*` keys.

The file must not be readable or writable by group or other (`chmod 600`), or
`C_Initialize` fails. Every key is listed in
[engineering.md](engineering.md#configuration--environment-and-an-optional-file).

## PINs

Cryptoki gives the module no way to prompt you, so `XKMS_PKCS11_SO_PIN` and
`XKMS_PKCS11_USER_PIN` come from the environment (or `so_pin` / `user_pin` in
the file). Anything that can read the process environment can read them — scope
the environment to the process that needs it, and do not export them in a
shared shell profile.

## Using it with common consumers

```
# Enumerate
pkcs11-tool --module ./build/lib/libxkms_pkcs11.so --list-slots
pkcs11-tool --module ./build/lib/libxkms_pkcs11.so --list-objects --login
```

Every behaviour below is pinned by an integration test in
`test/integration/pkcs11/module/` (`make integration-test-pkcs11-openssl-all`)
that checks the result outside the module.

**OpenSSL 3+ — pkcs11-provider** (the supported path). Configure it in
`openssl.cnf` and point `OPENSSL_CONF` at it; keep the default provider active
for verification:

```ini
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
pkcs11 = pkcs11_sect

[default_sect]
activate = 1

[pkcs11_sect]
module = <ossl-modules-dir>/pkcs11.so
pkcs11-module-path = <install-dir>/libxkms_pkcs11.so
pkcs11-module-quirks = no-deinit
activate = 1
```

`no-deinit` is pkcs11-provider's workaround for OpenSSL 4.0's late cleanup,
which can crash on exit after the operation succeeded. RSA (v1.5, PSS, OAEP),
ECDSA (P-256/384/521), Ed25519 (`-rawin`), CSR and certificate issuance and a
TLS server with a token-resident key all work (`openssl_provider_test.go`,
`openssl_x509_tls_test.go`). Address keys by RFC 7512 URI:
`pkcs11:object=web-tls;type=private`.

**OpenSSL — legacy libp11 ENGINE.** Set `MODULE_PATH` to the module, or libp11
silently probes for OpenSC instead. Two limits are pinned by tests
(`openssl_engine_test.go:378`, `:431`): `openssl genpkey -engine pkcs11`
generates the key **in software**, so generate with `pkcs11-tool --keypairgen`;
and the ENGINE cannot carry an Ed25519 key.

**OpenSSH.** `ssh-add -s <install-dir>/libxkms_pkcs11.so`, `ssh -I …`, or
`PKCS11Provider` in `~/.ssh/config`. RSA and ECDSA keys work on any version; an
Ed25519 token key needs **OpenSSH 10.1 or later**
(`openssl_ssh_test.go:1615`).

**OpenSC `pkcs11-tool`** cannot rebuild a P-384 public key with
`--read-object --type pubkey`; that is an OpenSC bug. Export it through the
provider: `openssl pkey -in "pkcs11:object=my-key;type=public" -pubout`.

Key objects answer all twelve boolean usage attributes, defaulting to false
(`applyKeyUsageDefaults`, `pkg/pkcs11/module/object.go:2838`), and RSA private
key objects carry the public components (`module.go:7044`), because libp11
refuses keys without them.

## Hardening

Each item is enforced by the code cited.

- **Use TLS or a unix socket.** A non-`unix://` target without TLS fails
  `C_Initialize` (`config.go:228`); leave
  `XKMS_PKCS11_ALLOW_INSECURE_TRANSPORT` off. xkmsd's own unix socket
  needs TLS as well (see the configuration file above).
- **Protect the config file.** Group- or world-accessible files are refused
  (`config.go:507-512`); it may hold PINs.
- **Keep the seal strategy at `passphrase`** in offline mode.
- **PINs are slow to guess.** They are stored as Argon2id hashes with a 16-byte
  salt (`token.go:796`, `:854`), compared in constant time (`token.go:931`),
  and locked after 3 failures shared by every process on the token
  (`session.go:1204`).
- **Sessions see only what they may.** Every key lookup goes through the
  session's access context (`GetObjectFor`, `object.go:3170`), private objects
  need a login (`requireLogin`, `module.go:3039`), and a key whose type does
  not fit the mechanism is `CKR_KEY_TYPE_INCONSISTENT` (`module.go:2800`).
- **Sensitive values never leave.** `CKA_VALUE` and private components of a
  sensitive or non-extractable key are not returned (`object.go:810`,
  `:1684`). `C_GenerateKey` makes secret keys sensitive and non-extractable
  unless the template says otherwise (`module.go:8776-8788`); keys imported
  with `C_CreateObject` are never `CKA_LOCAL`, `CKA_ALWAYS_SENSITIVE` or
  `CKA_NEVER_EXTRACTABLE` (`object.go:2586-2594`), and computed attributes
  cannot be supplied (`object.go:866`).
- **Leave legacy wrapping off.** `crypto.allow_legacy_key_wrap` and
  `crypto.allow_weak_hashes` default off in xkmsd; so does
  `XKMS_PKCS11_ALLOW_WEAK_HASH_SIGNING` in the module.
- **Finalize wipes.** `C_Finalize` destroys session objects and zeroizes the
  object store (`module.go:1079`, `:1087`).

## Troubleshooting

| What you see | What it means | What to do |
|---|---|---|
| `C_Initialize` fails naming a backend | the module was built without that backend's build tag | rebuild with the tag; the environment can only select what was compiled in |
| state calls fail with `tenant_id does not match the authenticated identity's tenant` | the module's configured `tenant_id` is not the tenant its credentials authenticate as | unset `tenant_id` or correct it; the server always uses the authenticated tenant |
| `C_Initialize` fails in remote mode | target unreachable, TLS material wrong, or storage unusable | it fails closed on purpose — fix the cause, do not look for a fallback |
| `CKR_FUNCTION_NOT_SUPPORTED` (`0x54`) | this token will never do that operation | not a transient failure; asynchronous operations and blocking `C_WaitForSlotEvent` are unimplemented |
| `CKR_USER_NOT_LOGGED_IN` | the mechanism needs a login first | supply the user PIN |
| two processes fight over token state | concurrent sessions | this is what the compare-and-swap state operations are for; a plain put in that path is a bug |
| offline keys are readable on disk | `XKMS_PKCS11_SEAL_STRATEGY=none` | unset it — the default protects them |
| a bare hex code in the consumer's log | a `CK_RV` | look it up in `pkg/pkcs11/module/errors.go` |

## What is not implemented

Asynchronous operations and a blocking `C_WaitForSlotEvent` answer
`CKR_FUNCTION_NOT_SUPPORTED`; message-based signature-first verification is
absent. KEM, authenticated wrapping, `C_VerifySignature` and
`C_GetSessionValidationFlags` work through the v3.2 interface. The module is not
fork-safe. The full list is in
[engineering.md](engineering.md#deviations-and-limits).

## Where to go next

- The keys behind the token: [`../key-management/user.md`](../key-management/user.md)
- Choosing which backend holds them: [`../crypto-backends/user.md`](../crypto-backends/user.md)
- PINs and lockout: [`../pin-management/user.md`](../pin-management/user.md)
