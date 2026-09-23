# Password Vault — API

> **Status: NORMATIVE** · Feature: `password-vault` · Repo: `go-xkms` · Last verified: 2026-09-23

Transport shapes: [`../key-management/api.md`](../key-management/api.md)
§"How the six transports are shaped".

Routes are registered under `/api/v1/passwords` on the `hasPasswords`
predicate. Every route with a gRPC or MCP counterpart is `RouteAuthPermission`
and demands the same `passwords:*` pair those transports enforce (the
**Permission** column), so REST, QUIC, gRPC/Unix and MCP ask for one grant per
operation. Admin and Owner hold every one of them by default.

`POST /api/v1/passwords/access-mode` is the one route still served to any
authenticated session (`RouteAuthSession`): it has no counterpart on any other
transport, so there is no canonical permission for it to adopt yet (see the
asymmetry below).

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
| Set access mode | `POST /api/v1/passwords/access-mode` | — | same as REST | — | `PasswordStoreSetAccessMode` | session |
| Generate password | `POST /api/v1/passwords/generate` | `PasswordGenerate` | same as REST | `password.generate` | `PasswordGenerate` | `passwords:generate` |

**This is one of only three features with complete MCP coverage** (the others
are the barrier and SSH). Nine `password.*` methods.

The one asymmetry: `PasswordStoreSetAccessMode` has a REST route and an embedded
method but no gRPC RPC and no MCP method. Given that the access mode is a
security policy rather than an operation, restricting where it can be changed is
defensible — but it is an inconsistency, not a stated decision.

The seventh, product-specific **USB** transport (`pkg/api/transport/usb/transport.go`)
proxies nine of the ten `PasswordService` methods to the phone's embedded
xkmsd instance over the Noise-encrypted USB channel, using the same JSON-RPC
envelope (`Request`/`Response`) as its other operations, with method names
matching the servicer verbatim (`PasswordAdd`, `PasswordGet`, ...). The tenth,
`PasswordStoreSetAccessMode`, still returns `ErrNotSupported` — access-mode
changes are scoped separately (go-xkms#691).

## The plaintext boundary is in the request

`PasswordGet` returns the plaintext **only when the request asks for it**. That
is a field on the request, not a separate endpoint, and it is what the CLI's
`--decrypt` sets. `PasswordList` never returns plaintext under any parameter.

A client that wants metadata should not ask for plaintext — the read is
audited either way, and the audit record is more useful when the two are
distinguishable.

## Access mode gates every plaintext read

| Mode | What a `PasswordGet` with plaintext requires |
|---|---|
| `pin_per_operation` | the user PIN **on that request** |
| `session_based` | a prior successful `PasswordStoreUnlock` |

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
| store locked, plaintext requested | 423 | `FailedPrecondition` | error object |
| PIN required (`pin_per_operation`) | 401 | `Unauthenticated` | error object |
| PIN invalid | 401 | `Unauthenticated` | error object |
| entry not found **or out of scope** | 404 | `NotFound` | error object |
| validation failure | 400 | `InvalidArgument` | JSON-RPC `-32602` |
| vault not configured | route absent (404) | `Unimplemented` | error object |

Out-of-scope entries return **404, not 403**, so entry existence is not
enumerable across scopes and tenants. The `403` above is the permission gate,
which decides from the caller's grant alone before any entry is looked up, so
it reveals nothing about which entries exist.

## Pagination

`PasswordList` takes folder, tenant and scope filters. A vault is bounded by
what humans put in it; results are returned filtered rather than paged.

## Versioning and deprecation

`/api/v1/passwords/*`, gRPC package `xkmsv1`. Nothing deprecated.

Two contracts callers rely on: plaintext being opt-in per request, and
out-of-scope reporting as not-found. Both are security properties rather than
conveniences.
