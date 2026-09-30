# Password Vault — API

> **Status: NORMATIVE** · Feature: `password-vault` · Repo: `go-xkms` · Last verified: 2026-09-30 (#1249)

Transport shapes: [`../key-management/api.md`](../key-management/api.md)
§"How the six transports are shaped".

Routes are registered under `/api/v1/passwords` on the `hasPasswords`
predicate. Every route is `RouteAuthPermission` and demands the same
`passwords:*` pair gRPC and MCP enforce for the same operation (the
**Permission** column), so REST, QUIC, gRPC/Unix and MCP ask for one grant per
operation. Admin and Owner hold every one of them by default.

`POST /api/v1/passwords/access-mode` used to be the one route in this family
served to any authenticated session (`RouteAuthSession`) with no RBAC
permission of its own; go-xkms#1249 closed that gap (the owner's 2026-09-29
ruling that the password vault is not a login feature) by gating it on
`passwords:write`, the same permission its other mutating siblings already
required.

## Capability matrix

| Capability | REST | gRPC / Unix (`KeystoreService.`) | QUIC | MCP | Embedded (`PasswordService.`) | Permission |
|---|---|---|---|---|---|---|
| Add entry | `POST /api/v1/passwords/` | `PasswordAdd` | same as REST | `password.add` | `PasswordAdd` | `passwords:write` |
| List entries | `GET /api/v1/passwords/` | `PasswordList` | same as REST | `password.list` | `PasswordList` | `passwords:read` |
| Get entry | `GET /api/v1/passwords/{id}` | `PasswordGet` | same as REST | `password.get` | `PasswordGet` | `passwords:read` |
| Update entry | `PUT /api/v1/passwords/{id}` | `PasswordUpdate` | same as REST | `password.update` | `PasswordUpdate` | `passwords:write` |
| Delete entry | `DELETE /api/v1/passwords/{id}` | `PasswordDelete` | same as REST | `password.delete` | `PasswordDelete` | `passwords:delete` |
| Unlock store | `POST /api/v1/passwords/unlock` | `PasswordStoreUnlock` | same as REST | `password.unlock` | `PasswordStoreUnlock` | `passwords:unlock` |
| Lock store | `POST /api/v1/passwords/lock` | `PasswordStoreLock` | same as REST | `password.lock` | `PasswordStoreLock` | `passwords:lock` |
| Store status | `GET /api/v1/passwords/status` | `PasswordStoreStatus` | same as REST | `password.status` | `PasswordStoreStatus` | `passwords:read` |
| Set access mode | `POST /api/v1/passwords/access-mode` | `PasswordStoreSetAccessMode` | same as REST | `password.setAccessMode` | `PasswordStoreSetAccessMode` | `passwords:write` |
| Generate password | `POST /api/v1/passwords/generate` | `PasswordGenerate` | same as REST | `password.generate` | `PasswordGenerate` | `passwords:generate` |

Unlock, lock and status act on the **caller's own** personal session
(`(tenant, subject)` of the authenticated identity); none of them addresses
another user or the tenant as a whole. A system-tenant identity is served from
the system tenant's own store. Every transport delegates to the
`XKMSService` password servicer, so the answers below are identical across
REST, gRPC, QUIC, MCP and embedded:

| Condition | Answer |
|---|---|
| personal operation while the caller's session is locked | `ErrStoreLocked` (REST 423) |
| another user's personal entry, or another tenant's entry | not found (REST 404) — indistinguishable from a missing entry |
| update/delete of a shared entry by neither its owner nor a tenant Admin/SO | `ErrNotOwner` (REST 403) |
| unlock/lock with no identity on the request | not supported (REST 501) |
| tenant barrier sealed | sealed (REST 503) |

**This is one of only three features with complete MCP coverage** (the others
are the barrier and SSH). Ten `password.*` methods, all carrying the same
permission on every transport that exposes them
(`pkg/api/authz_consistency_test`).

The seventh, product-specific **USB** transport (`pkg/api/transport/usb/transport.go`)
proxies nine of the ten `PasswordService` methods to the phone's embedded
xkmsd instance over the Noise-encrypted USB channel, using the same JSON-RPC
envelope (`Request`/`Response`) as its other operations, with method names
matching the servicer verbatim (`PasswordAdd`, `PasswordGet`, ...). The tenth,
`PasswordStoreSetAccessMode`, still returns `ErrNotSupported` — access-mode
changes are scoped separately (go-xkms#691).

## `PasswordGet` returns entries exactly as stored

There is no per-request decryption step and no plaintext/metadata split:
`PasswordGet` returns the password field the same way on every call
(`pkg/xkms/servicer_password.go:168`). Confidentiality at rest is provided by
the tenant barrier at the storage layer, and every store reachable through
this servicer -- `staticpw.BackendStore`, `staticpw.ScopedStore`,
`staticpw.DAOStore` -- returns the entry as stored; none implements a
field-level decryption entry point. `PasswordList` never returns plaintext
under any parameter, matching `PasswordGet`.

An earlier revision of this API accepted `decrypt` and `user_pin` fields on
the request and silently dropped them. They were removed (go-xkms#1061)
rather than kept as accepted-but-ignored fields, since a client could not
tell "the server did what I asked" from "the server ignored a
security-relevant field."

## Access mode

`PasswordStoreSetAccessMode` accepts `pin_per_operation` and `session_based`,
but only `session_based` is reachable today: the strategy is fixed at
composition time by which store is wired at startup, and
`XKMSService.PasswordStoreSetAccessMode` only succeeds when the requested
mode already matches the store's active mode
(`pkg/xkms/servicer_password.go:452`-`474`). There is no store implementation
of `pin_per_operation` (`pkg/staticpw/access.go:17`-`26`).

`PasswordStoreStatus` reports which mode is in force and whether the store is
unlocked, and **works while locked** — a client should call it before assuming
it needs to prompt.

## Request and response schemas

`pkg/api/transport/types.go`: `PasswordAddRequest`/`Response`,
`PasswordGetRequest`/`Response`, `PasswordListRequest`/`Response`,
`PasswordUpdateRequest`, `PasswordDeleteRequest`,
`PasswordStoreUnlockRequest`, `PasswordStoreStatusResponse`,
`PasswordStoreSetAccessModeRequest`, `PasswordGenerateRequest`/`Response`.

Entry fields: name, username, URL, notes, folder, `expires_at` (RFC 3339),
`tenant_id`, `shared`. Listing filters: folder, tenant, scope
(`own | shared | all`).

`expires_at` is **metadata**. Nothing in this API invalidates a credential when
it passes; an expired entry is a signal to rotate.

## Status and error mapping

| Condition | REST | gRPC / Unix | MCP |
|---|---|---|---|
| success | 200 | `OK` | `result` |
| caller lacks the route's `passwords:*` permission | 403 | `PermissionDenied` | error object |
| store locked (any operation) | 423 | `FailedPrecondition` | error object |
| unlock: user PIN required, none sent | 400 | `InvalidArgument` | error object |
| unlock: user PIN not provisioned | 412 | `FailedPrecondition` | error object |
| unlock: user PIN verification failed | 401 | `PermissionDenied` | error object |
| entry not found **or out of scope** | 404 | `NotFound` | error object |
| validation failure | 400 | `InvalidArgument` | JSON-RPC `-32602` |
| vault not configured | route absent (404) | `Unimplemented` | error object |

The three PIN rows apply to `PasswordStoreUnlock` only
(`pkg/api/rest/password_handlers.go:769`-`784`,
`pkg/api/grpc/service_password.go:437`-`450`); `PasswordGet` has no PIN
parameter to validate.

Out-of-scope entries return **404, not 403**, so entry existence is not
enumerable across scopes and tenants. The `403` above is the permission gate,
which decides from the caller's grant alone before any entry is looked up, so
it reveals nothing about which entries exist.

## Pagination

`PasswordList` takes folder, tenant and scope filters. A vault is bounded by
what humans put in it; results are returned filtered rather than paged.

## Versioning and deprecation

`/api/v1/passwords/*`, gRPC package `xkmsv1`. This is a pre-release API: a
capability that cannot work is removed outright rather than deprecated. The
gRPC `PasswordGetRequest.decrypt` field (`2`) was removed this way in
go-xkms#1061; its number and name are `reserved` in the proto
(`pkg/api/grpc/proto/xkmsv1/xkms.proto:3163`-`3166`) and must not be reused.

One contract callers rely on: out-of-scope entries reporting as not-found.
That is a security property rather than a convenience.
