# Backend Credentials — API

> **Status: NORMATIVE** · Feature: `backend-credentials` · Repo: `go-xkms` · Last verified: 2026-10-12

Transport shapes: [`../key-management/api.md`](../key-management/api.md)
§"How the six transports are shaped". Every transport goes through the
`XKMSService` methods (`pkg/xkms/servicer_credentials.go`).

## Capability matrix

| Capability | REST | gRPC | Unix / QUIC | MCP | Embedded | TS SDK |
|---|---|---|---|---|---|---|
| Submit | `POST /api/v1/credentials/submit` | **not supported** | same as REST | `credentials.submit` | `SubmitCredential` | `CredentialsClient.submit` |
| Strategy | `GET /api/v1/credentials/strategy` | **not supported** | same as REST | `credentials.strategy` | `GetCredentialStrategy` | `CredentialsClient.strategy` |
| List names | `GET /api/v1/credentials` | — | — | — | — | — |

Sources:

- **REST routes:** `pkg/api/rest/routes.go:415-417`. They are mounted when
  an `XKMSService` is composed (`pkg/api/rest/server.go:443`).
- **Go SDK interface:** `transport.CredentialManagementService`, which has
  submit and strategy only (`pkg/api/transport/client.go:493-499`).
- **REST client:** `pkg/api/transport/rest/transport.go:2696`, `:2715`.
- **Unix client:** `pkg/api/transport/unix/transport.go:2658`, `:2677`.
- **QUIC client:** `pkg/api/transport/quic/transport.go:2672`, `:2691`.
  The Unix and QUIC clients send the same REST paths.
- **gRPC client:** returns `ErrNotSupported`
  (`pkg/api/transport/grpc/transport.go:1842-1855`).
- **MCP:** server dispatch at `pkg/api/mcp/server.go:379-380`; client at
  `pkg/api/transport/mcp/transport.go:2000`, `:2009`.
- **Embedded client:** `pkg/api/transport/embedded/transport.go:1270`,
  `:1278`.
- **TS SDK:** `sdk/ts/src/clients/credentials.ts:21-36`.

Listing has a REST route and nothing else. There is no gRPC RPC and no MCP
method for it, and `transport.CredentialManagementService` has no list
method, so no Go client (REST, Unix, QUIC, gRPC, MCP or embedded) and no TS
SDK method calls it. The route table records this
(`pkg/api/rest/routes.go:410-413`). `xkmsctl credential list` sends the REST
request itself (`cmd/xkmsctl/credential.go:239`).

## Authorization

| Operation | REST | MCP | Scope |
|---|---|---|---|
| Submit | `credentials:submit` (`routes.go:415`) | `credentials:submit` (`pkg/api/mcp/server.go:380`) | platform only |
| Strategy | `credentials:strategy` (`routes.go:416`) | `credentials:strategy` (`authz.go:264`) | any |
| List | authenticated session, no permission pair (`routes.go:407-417`) | — | platform only |

The constants are `auth.ResourceCredentials`, `auth.ActionSubmit` and
`auth.ActionStrategy` (`pkg/auth/permissions.go:93`, `:247-248`). The
platform-only check is `qrdbsdk.IdentityIsSystemTenant`
(`pkg/xkms/servicer_credentials.go:35`, `:78`). A tenant-scoped caller is
refused with an answer that reads as not-found. For which roles hold these
pairs, see [`../rbac/`](../rbac/).

## Bodies

`POST /api/v1/credentials/submit`, and MCP `credentials.submit` params:

```json
{"name": "pkcs11-user-pin", "value": "<base64 of the raw value>"}
```

Response: `{"status": "accepted"}`.

`GET /api/v1/credentials/strategy`: `{"strategy": "manual", "auto_unseal": false}`.

`GET /api/v1/credentials`: `{"names": ["pkcs11-user-pin"]}`. An empty store
returns `[]`, never `null` (`pkg/api/rest/handlers_credentials.go:178-184`).

Sources: `pkg/api/transport/types_init.go:18-33` and
`pkg/api/rest/handlers_credentials.go:49-71`. `value` is standard base64 and
the service decodes it (`pkg/xkms/servicer_credentials.go:43-46`).

## Errors

| Condition | REST | MCP | Source |
|---|---|---|---|
| Body not JSON, or `name`/`value` empty | 400 | invalid params | `handlers_credentials.go:115-127`; MCP `pkg/api/mcp/handlers_credentials.go:40-41` |
| `value` not base64 | 400 | invalid params | `xkms.ErrInvalidEncoding`: `handlers_credentials.go:86`, MCP `:55` |
| `manual` name already submitted | 409 | duplicate | `ErrCredentialAlreadySubmitted`: `handlers_credentials.go:84`, MCP `:42` |
| Not found, or tenant-scoped caller | 404 | not found | `handlers_credentials.go:83`, `:90`; MCP `:43`, `:48` |
| No credential service wired | 503 | service unavailable | `xkms.ErrNotConfigured`: `handlers_credentials.go:87`, MCP `:56` |
| Anything else | 500 | internal error | `handlers_credentials.go:188-195`; MCP `:63-73` |

In the REST rows, `handlers_credentials.go` means
`pkg/api/rest/handlers_credentials.go`.
