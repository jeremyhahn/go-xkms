# Client Embedded API

> **Status: REFERENCE** · Last verified: 2026-10-12
> Legacy, unabsorbed reference for the client router in `pkg/acme/gui/client/api/router.go`.

`clientapi.NewRouter(wf workflow.Workflow, service *svc.Service, logger, opts...)`
(`pkg/acme/gui/client/api/router.go:42`) serves these routes under `/api/v1`,
behind the `pkg/acme/gui/guard` middleware. The desktop app mounts the router
in the Wails asset server: it runs in-process and same-origin, and no port is
bound. `trusted-acme-client serve` serves the same router over TCP/TLS, with a
nil workflow (`cmd/acme-client/serve.go:96`).

## Endpoints (`router.go:52-72`)

### Accounts

| Method | Path | Description |
|--------|------|-------------|
| GET | `/accounts` | List configured accounts |
| POST | `/accounts` | Add an account |
| GET | `/accounts/{name}` | Get an account |
| DELETE | `/accounts/{name}` | Remove an account |
| POST | `/account/register` | Register through the workflow |

**Add account request** (`addAccountRequest`, `acme_handlers.go:84`):
```json
{
  "name": "prod",
  "email": "admin@example.com",
  "directory": "https://kms.example.com/acme/directory",
  "key": { },
  "eab": { },
  "transport": "",
  "server_addr": "",
  "trusted_roots": [],
  "request_server_bundle": false
}
```
`name`, `email` and `directory` are the core fields; the rest are optional.

**Register request / response** (`acme_handlers.go:28`, `:33`):
```json
{ "email": "admin@example.com" }
{ "data": { "accountUrl": "...", "status": "valid", "contact": ["mailto:admin@example.com"] } }
```

### Certificates

| Method | Path | Description |
|--------|------|-------------|
| GET | `/certificates` | List certificate specs (optional `?account=` filter) |
| GET | `/certificates/{name}` | Get managed certificate info |
| POST | `/certificates/{name}/deploy` | Deploy a managed certificate |
| POST | `/certificate/request` | Request a certificate by spec name |
| POST | `/certificate/renew` | Renew a certificate by spec name |
| POST | `/certificate/revoke` | Revoke a certificate |

Request and renew take `{ "name": "<spec>" }` (`acme_handlers.go:179`) and
return `{ subject, notBefore, notAfter }`. Revoke takes
`{ "name" | "certFile" | "certificate", "reason": <int> }`
(`acme_handlers.go:238`).

### Device (TPM)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/device/enroll` | Enroll the named device |
| POST | `/device/attest` | Attest the named device |

Both take `{ "name": "<device>" }` (`device_handlers.go:22`) and reject a
missing `name` with 400.
- Enroll returns `{ name, iakSubject, idevidSubject, idevidNotBefore, idevidNotAfter, issuingChainCount }`.
- Attest returns `{ name, subject, notBefore, notAfter }`.

There are no `/config` or `/renewal/*` routes.

## Response envelope (`handlers.go:47-50`)

```json
{ "data": { } }
{ "error": "certificate not found" }
```

`data` and `error` are omitted when empty. There is no `success` field, and
`error` is a plain string.

## Origin check and CORS

The `guard` middleware (`pkg/acme/gui/guard/guard.go:101`) works as follows:

- It rejects an `Origin` whose host differs from the request `Host`.
- In-process it answers `Access-Control-Allow-Origin: *`.
- It answers `OPTIONS` with 204.
- It allows `GET, POST, PUT, DELETE, OPTIONS` and `Content-Type, Authorization`.
