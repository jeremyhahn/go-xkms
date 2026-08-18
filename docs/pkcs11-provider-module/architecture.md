# PKCS#11 Provider Module — Architecture

> **Status: NORMATIVE** · Feature: `pkcs11-provider-module` · Repo: `go-xkms` · Last verified: 2026-08-19

## The problem

An enormous amount of software already knows how to talk to a cryptographic
token: OpenSSL, NSS, Java, `ssh-agent`, disk encryption, TLS terminators. All of
it speaks Cryptoki (PKCS#11) and loads a `.so`. None of it is going to grow an
xkms client.

`cmd/pkcs11-module` builds that `.so`. It presents xkms **as a token**, so every
Cryptoki consumer gains hardware-backed, policy-governed keys without changing a
line of code.

This is a shipped product surface — capability row **"PKCS#11 provider module —
Cryptoki `.so`" (tier 1)** — not merely a `SealingStrategy` implementation. It is
the direction of the arrow that matters: everywhere else in this repo, PKCS#11
is a backend go-xkms *consumes*; here, PKCS#11 is an interface go-xkms
*presents*.

## Shape chosen: a C-shared library over the SDK, with two state modes

`go build -buildmode=c-shared -o libxkms_pkcs11.so ./cmd/pkcs11-module`.

The Cryptoki entry points are `cmd/pkcs11-module/exports.go` (92 `C_*`
functions) and `exports_v32.go` (12 more, the v3.2 additions), with
`function_list.go` publishing the dispatch table and `mechparam.go` handling
mechanism parameters. The logic lives in `pkg/pkcs11/module`, so the CGO layer
stays thin.

Two modes, selected by `XKMS_PKCS11_MODE`:

| Mode | Value | What it is |
|---|---|---|
| **remote** | anything else, including unset — the default | the module is a client of an xkmsd; token and object state travel over the `PKCS11State*` RPCs |
| **local / offline** | `local` or `offline` | the module runs the SDK's embedded service against local key material; no server, no network |

Offline mode exists because a Cryptoki consumer often has no network at the
moment it needs a key — early boot, a disk-unlock hook, an air-gapped host.

Rejected alternatives:

- **A daemon plus a thin `.so` shim.** Rejected: it makes early-boot use
  impossible, which is one of the cases the module exists for.
- **Requiring a server always.** Same objection; offline mode is the answer.
- **Reimplementing Cryptoki semantics per consumer.** Rejected — the point is
  that consumers are unmodified.

## Component boundaries

| Piece | Location |
|---|---|
| Cryptoki C entry points, v3.0 set | `cmd/pkcs11-module/exports.go` |
| Cryptoki C entry points, v3.2 additions | `cmd/pkcs11-module/exports_v32.go` |
| Function list / dispatch table | `cmd/pkcs11-module/function_list.go` |
| Mechanism parameter marshalling | `cmd/pkcs11-module/mechparam.go` |
| Offline-mode wiring | `cmd/pkcs11-module/offline.go` |
| Module logic — sessions, objects, mechanisms, crypto | `pkg/pkcs11/module` |
| At-rest sealing for offline mode | `pkg/pkcs11/localseal` |
| Token/object state store (remote mode) | `pkg/pkcs11state`, `PKCS11State*` RPCs |
| Token manager | `pkg/pkcs11/manager` |
| Crypto operations | `sdk/go` → the keystore → the chosen backend |

Note the deliberate separation: `pkg/pkcs11` (the module, presenting a token) is
a different thing from `pkg/backend/pkcs11` (the backend, consuming a token).
Both exist; they point opposite ways.

## Data flow

**Remote mode** — token state is server-side, so several hosts can share one
token view:

```
OpenSSL / NSS / Java  →  libxkms_pkcs11.so
   → pkg/pkcs11/module: session, object, mechanism handling
     → token + object state:  PKCS11StatePut / PutIfAbsent / CAS / Get / Delete / List
     → crypto operations:     sdk/go → xkmsd → keystore backend
```

`PKCS11StateCAS` is the interesting one: compare-and-swap is what keeps two
concurrent sessions from clobbering each other's token state.

**Offline mode** — everything is local:

```
consumer  →  libxkms_pkcs11.so  (XKMS_PKCS11_MODE=local)
   → SDK embedded service
     → key material under XKMS_PKCS11_LOCAL_KEYDIR (default <StoragePath>/keys)
       → at-rest protection per XKMS_PKCS11_SEAL_STRATEGY
```

## Trust boundaries

- **The `.so` runs inside the consumer's process.** It inherits that process's
  privileges and lifetime; it is not a sandbox.
- **Offline at-rest protection is a choice with a default.**
  `XKMS_PKCS11_SEAL_STRATEGY` is `passphrase` by default — key material is keyed
  under the user PIN via go-qrdb's barrier. `none` stores it in **cleartext**,
  matching SoftHSM's unencrypted default, and is for development only. The
  default is the secure one; that is deliberate.
- **The module must never build its own sealer.** `offline.go` records the rule
  and the reason: it consumes go-qrdb's barrier. A local sealer would be a
  second, unreviewed barrier implementation.
- **`XKMS_PKCS11_ALLOW_INSECURE_TRANSPORT` exists and defaults off.** Turning it
  on sends token operations over an unauthenticated channel.
- **PINs come from the environment in this module** (`XKMS_PKCS11_SO_PIN`,
  `XKMS_PKCS11_USER_PIN`) because Cryptoki consumers have no way to prompt.
  Environment variables are visible to anything that can read the process
  environment — scope them accordingly.
- **`CKR_FUNCTION_NOT_SUPPORTED` is a deliberate, distinguishable answer.**
  `crypto.go:3327` documents the intent: the caller can tell "this token will
  never do that" from "that failed".

## Known state: v3.2 is partially implemented

Four v3.2 surfaces exist as API and return `CKR_FUNCTION_NOT_SUPPORTED`:

| Surface | File |
|---|---|
| KEM operations | `pkg/pkcs11/module/module_kem.go`, `module_kem_quantum.go` |
| Authenticated wrapping | `module_authwrap.go` |
| Signature-first PQC verification (9 functions) | `module_verifysig.go`, `module_verifysig_quantum.go` |
| Asynchronous operations | `module_async.go` |

Each has a test suite covering the not-supported path, so the behaviour is
intentional rather than accidental. Implementing them is feature work, tracked
in `docs/pkcs11/ROADMAP.md`.

## What this feature deliberately does not do

- **It is not the PKCS#11 backend.** Consuming a third-party token is
  [`../crypto-backends/`](../crypto-backends/architecture.md).
- **It does not implement a barrier.** Offline at-rest protection is go-qrdb's
  barrier, by rule.
- **It does not manage users or policy.** Cryptoki's model is SO PIN plus user
  PIN; RBAC lives above.
- **It does not ship the whole of PKCS#11 v3.2** — see above.
