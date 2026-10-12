# PKCS#11 Provider Module — Architecture

> **Status: NORMATIVE** · Feature: `pkcs11-provider-module` · Repo: `go-xkms` · Last verified: 2026-10-12

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
     → token + object state:  PKCS11StatePut / PutIfAbsent / CAS / CAD / Get / Delete / List
     → crypto operations:     sdk/go → xkmsd → keystore backend
```

`PKCS11StateCAS` is the interesting one: compare-and-swap is what keeps two
concurrent sessions from clobbering each other's token state. `PKCS11StateCAD`
is its counterpart for release: a delete guarded on the value the caller last
observed, evaluated by xkmsd where the writes of every host sharing the token
serialise, so a record one client claimed cannot be removed by another client's
stale view of it.

**Offline mode** — everything is local:

```
consumer  →  libxkms_pkcs11.so  (XKMS_PKCS11_MODE=local)
   → SDK embedded service
     → key material under XKMS_PKCS11_LOCAL_KEYDIR (default <StoragePath>/keys)
       → at-rest protection per XKMS_PKCS11_SEAL_STRATEGY
```

### Provisioning a remote-mode token from a CGO-free process

A daemon built with `CGO_ENABLED=0` cannot load the `.so`, but it often has to
create the key a separate Cryptoki consumer (an IKE daemon) later signs with.
`module.ProvisionECKeyPair` does that without writing token records by hand: it
drives a `Module` in process, against the same key service and the same token
store the loaded module will use, and asks it for `C_GenerateKeyPair` with the
requested `CKA_LABEL` and `CKA_ID`. The objects on the token are therefore
exactly the objects the module itself creates. `module.NewRemoteStorage` is the
token store a remote-mode module keeps its records in; any `PKCS11StateClient`
(a transport, or an in-process `*xkms.XKMSService`) backs it.

The node-local, sign-only server a consumer's remote-mode module connects to is
[`../sign-server/`](../sign-server/architecture.md).

### Remote token-store layout

Each record is one go-qrdb DAO entity (`pkcs11state.Record`,
`pkg/pkcs11state/entity.go:20`) of type `pkcs11_state_records` in the
`pkcs11state` database. Its name, `<tenant>/<token>/<key>`, is the natural key
the entity ID is hashed from (`pkg/pkcs11state/store.go:73-92`). The system
scope (no tenant identity) is stored under the system tenant's ID,
`system/<token>/`. `List` reads the entity type page by page and keeps the
records of the requested scope and prefix; the go-qrdb SDK cannot register an
index on a context-bound DAO yet, so it is a scan, not an index lookup.
`PutIfAbsent`, `CompareAndSwap` and `CompareAndDelete` are the DAO's
`SaveIfAbsent`, `CompareAndSwap` and `DeleteIfMatch`: one guarded store
operation each, never a read followed by an unguarded write.

The service still refuses a token label of `.` or `..`
(`ErrPKCS11StateTokenDotSegment`) and a key or list prefix carrying a `.` or
`..` segment, an empty interior segment or a leading `/`
(`ErrPKCS11StateKeyPath`), so a record name always reads as exactly one
tenant, token and key. This is a pre-release layout change with no migration:
records written under the old `pkcs11state/` storage prefix are not read, and
existing remote tokens are re-provisioned.

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
- **Remote state is confined to the caller's tenant by the server, not by
  the request.** xkmsd keeps every tenant's token state in one shared
  `pkcs11state` database, opened and written as the embedded node's service
  principal (`initializePKCS11StateStore`, `pkg/server/server.go:1674-1678`).
  It is not behind a tenant barrier. Records are named
  `<tenant>/<token>/<key>` (`pkg/pkcs11state/store.go:81-92`), and
  the service fills the tenant segment from the authenticated identity
  (`XKMSService.pkcs11StateScope`, `pkg/xkms/servicer_pkcs11state.go:79`,
  reusing `scopedTenantIDFromContext`). A request's `tenant_id` is only a
  statement of that tenant. A value naming any other tenant is refused with
  `ErrPKCS11StateTenantMismatch`, and so is a token label containing `/`, which
  could otherwise alias another token's keys (`ErrPKCS11StateTokenSeparator`).
  Keys may contain `/`, because they are the last segment. The check runs once,
  in the service, for REST, QUIC, gRPC and Unix.
- **`XKMS_PKCS11_ALLOW_INSECURE_TRANSPORT` exists and defaults off.** Turning it
  on sends token operations over an unauthenticated channel.
- **PINs come from the environment in this module** (`XKMS_PKCS11_SO_PIN`,
  `XKMS_PKCS11_USER_PIN`) because Cryptoki consumers have no way to prompt.
  Environment variables are visible to anything that can read the process
  environment — scope them accordingly.
- **`CKR_FUNCTION_NOT_SUPPORTED` is a deliberate, distinguishable answer.**
  `crypto.go:3327` documents the intent: the caller can tell "this token will
  never do that" from "that failed".

### Rejected: taking the tenant from the request body

Earlier servers used the body's `tenant_id` as the key prefix, so any caller
holding a `keys:*` state-store permission — `get`, `create`, `update`, or
`delete` — could read, overwrite, swap or delete another tenant's token
records and lockout counters. The route permission is self-scope and is
always resolved against the caller's own tenant, so it could not catch this.

We also considered accepting only an empty `tenant_id`, the rule the key-op
transports apply (`tenantForRequest`). It was rejected because the module sends
its configured `tenant_id` on every call (`pkg/pkcs11/module/module.go:722`).
Refusing a correct statement of the caller's own tenant would break every
module that sets one.

A mismatch is answered as an invalid argument, not as not-found. Not-found
would be wrong for writes. On a read it would make a misconfigured module see
an empty namespace and initialise a fresh token over it. The check compares the
supplied value only with the caller's own identity, so the refusal reveals
nothing about the other tenant.

### Open question: a tenant-barrier-backed store

The store is shared and encrypted only as far as the configured storage
backend is. A tenant's barrier does not protect its records, so sealing a
tenant does not make its PKCS#11 token state unreadable to the server. Moving
the store behind each tenant's barrier would add that property. It would also
make remote-mode token state unavailable while that tenant is sealed, and it
needs a per-tenant store resolver like the password vault's
(`resolvePasswordStore`). This is recorded, not decided.

## Known state: v3.2

KEM (`module_kem.go`, `module_kem_quantum.go`), authenticated wrapping
(`module_authwrap.go`), `C_VerifySignature*` (`module_verifysig.go`) and
`C_GetSessionValidationFlags` (`module_validation.go`) are implemented and
reachable only through the v3.2 function list. Asynchronous operations
(`module_async.go`) answer `CKR_FUNCTION_NOT_SUPPORTED`, and message-based
signature-first verification is absent. Remaining work is tracked in
[`../pkcs11/ROADMAP.md`](../pkcs11/ROADMAP.md); detail is in
[engineering.md](engineering.md#interfaces-and-v32-status).

## What this feature deliberately does not do

- **It is not the PKCS#11 backend.** Consuming a third-party token is
  [`../crypto-backends/`](../crypto-backends/architecture.md).
- **It does not implement a barrier.** Offline at-rest protection is go-qrdb's
  barrier, by rule.
- **It does not manage users or policy.** Cryptoki's model is SO PIN plus user
  PIN; RBAC lives above.
- **It does not ship the whole of PKCS#11 v3.2** — see above.
