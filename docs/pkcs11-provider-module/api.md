# PKCS#11 Provider Module — API

> **Status: NORMATIVE** · Feature: `pkcs11-provider-module` · Repo: `go-xkms` · Last verified: 2026-08-19

Transport shapes for the rest of the repo:
[`../key-management/api.md`](../key-management/api.md).

## The module's API is the Cryptoki C ABI

This feature's public interface is **PKCS#11 itself** — 92 `C_*` functions from
v3.0 (`cmd/pkcs11-module/exports.go`) plus 12 v3.2 additions
(`exports_v32.go`), published through `C_GetFunctionList`
(`function_list.go`). That is a standards-defined ABI, not one of the six
portfolio transports, and it is the whole point: consumers are unmodified.

The six-transport rule applies to the capabilities the module *uses*, which are
already documented — crypto operations are
[`../key-management/api.md`](../key-management/api.md), and the state plane is
below.

## The `PKCS11State*` RPCs — remote-mode token state

In remote mode the module keeps token and object state server-side. Seven
operations, backed by `pkg/pkcs11state.Store`:

| Capability | REST | gRPC / Unix (`KeystoreService.`) | QUIC (HTTP/3) | MCP | Embedded | Auth |
|---|---|---|---|---|---|---|
| Put state | `pkg/api/rest/pkcs11state_handlers.go` | `PKCS11StatePut` | same as REST | **MISSING — docs/13** | `pkcs11state.Store` | session |
| Put if absent | same handler set | `PKCS11StatePutIfAbsent` | same as REST | **MISSING — docs/13** | `pkcs11state.Store` | session |
| Compare-and-swap | same handler set | `PKCS11StateCAS` | same as REST | **MISSING — docs/13** | `pkcs11state.Store` | session |
| Compare-and-delete | same handler set | `PKCS11StateCAD` | same as REST | **MISSING — docs/13** | `pkcs11state.Store` | session |
| Get state | same handler set | `PKCS11StateGet` | same as REST | **MISSING — docs/13** | `pkcs11state.Store` | session |
| Delete state | same handler set | `PKCS11StateDelete` | same as REST | **MISSING — docs/13** | `pkcs11state.Store` | session |
| List state | same handler set | `PKCS11StateList` | same as REST | **MISSING — docs/13** | `pkcs11state.Store` | session |

The REST client side asserts its own narrower interface —
`var _ pkcs11StateClient = (*Transport)(nil)`
(`pkg/api/transport/rest/transport_pkcs11state.go`) — rather than the full
`transport.Client`, because these seven are all the state plane needs.

REST and QUIC serve the state plane on `POST /api/v1/pkcs11state/<verb>` with
the verb spelled `put`, `put-if-absent`, `compare-and-swap`,
`compare-and-delete`, `get`, `delete` and `list`; the body is the transport
DTO as JSON. Every verb gates on the keys resource: the guarded delete needs
`delete`, the swap `update`, the two puts `create`, and get/list `get`/`list`.
Over gRPC and Unix every state RPC carries `keys:write` or `keys:read`.

Types: `pkg/api/transport/types_pkcs11state.go`.

**`PKCS11StateCAS` and `PKCS11StatePutIfAbsent` are not conveniences.** Two
concurrent Cryptoki sessions against the same token will otherwise clobber each
other's state. A plain `Put` where a CAS belongs is a correctness defect, not a
style choice.

**`PKCS11StateCAD` is the release half of `PKCS11StatePutIfAbsent`.** It
removes the record only if its current value equals `expected`, evaluated by
xkmsd on its own store, where the writes of every host sharing the token
serialise. An absent key or a different value answers `deleted: false` with a
successful response; only a transport or store failure is an error, and an
error means the outcome is unknown. Unlike the swap there is no absent flag:
`expected` is never a wildcard and a nil or empty value matches a stored empty
value only. The module's remote backend exposes it as
`storage.CompareAndDeleter`, held to the shared conformance suite in
`pkg/storage/storagetest` like every backend that claims the capability.

MCP carries none of the state plane, recorded as seven gaps. Unlike the WebAuthn
and PIN cases this one is close to unarguable — a model-driven tool server has
no business holding a Cryptoki token's object state — but it is written down so
the reasoning is visible.

## Offline mode has no wire surface

With `XKMS_PKCS11_MODE=local`, the module runs the SDK's embedded service
against local key material. There are no RPCs, no server, and no network. That
is the mode's purpose: a Cryptoki consumer at early boot or on an air-gapped
host still gets keys.

## Status and error mapping

Cryptoki has its own return-value space; `pkg/pkcs11/module/errors.go` maps
between it and Go errors in both directions.

| Situation | `CK_RV` | Meaning to the consumer |
|---|---|---|
| success | `CKR_OK` | — |
| operation the token will never support | `CKR_FUNCTION_NOT_SUPPORTED` (`0x54`) | do not retry; the answer is permanent |
| backend refused | mapped by `backendCKRV(err, fallback)` | depends |
| not logged in | `CKR_USER_NOT_LOGGED_IN` | `C_Login` first |
| state conflict (CAS lost) | mapped as a general failure | retry the operation |

The distinction `CKR_FUNCTION_NOT_SUPPORTED` carries is deliberate and
documented at `crypto.go:3327`: a caller must be able to tell "this token will
never do that" from "that failed". Collapsing it loses information consumers act
on.

## Pagination

`PKCS11StateList` returns the token's object state. It is bounded by the number
of objects on the token rather than paged.

## Versioning and deprecation

PKCS#11 versions are the standard's: the module publishes v3.0 plus the v3.2
additions. Four v3.2 surfaces — KEM, authenticated wrapping, signature-first PQC
verification, asynchronous operations — are present in the ABI and answer
`CKR_FUNCTION_NOT_SUPPORTED`. That is the specification-conformant way to ship a
partial version: the function exists, and the token honestly reports that it
does not implement it.

Detail: `docs/pkcs11/module/v32-compliance.md`,
`docs/references/pkcs11-v3.0-to-v3.2-changes.md`.
