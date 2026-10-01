# OIDC Credentials — API

> **Status: NORMATIVE** · Feature: `oidc-credentials` · Repo: `go-xkms` · Last verified: 2026-09-30

Design: [`architecture.md`](architecture.md). Service:
`pkg/oidc/credential.Service`, reached only through `XKMSService`
(`pkg/xkms/servicer_oidc_credential.go`), which every transport calls. The
transport model is in [key-management/api.md](../key-management/api.md).

## Tenancy and ownership

- `tenant_id` empty is the caller's tenant. A tenant caller cannot name
  another tenant; a system caller can name any tenant's **shared**
  credentials.
- `scope` is `tenant` (shared) or `user` (personal). A personal credential's
  `owner` defaults to the caller and is served to that owner only — a system
  caller is refused like anyone else (PermissionDenied).

## Operations

| Operation | REST | gRPC / Unix | MCP | Permission |
|---|---|---|---|---|
| List | `GET /api/v1/oidc/credentials?tenant_id=` | `OIDCCredentialList` | `oidc.credential.list` | `oidc_credentials:list` |
| Create | `POST /api/v1/oidc/credentials` (201) | `OIDCCredentialCreate` | `oidc.credential.create` | `oidc_credentials:create` |
| Get | `GET /api/v1/oidc/credentials/{scope}/{name}` | `OIDCCredentialGet` | `oidc.credential.get` | `oidc_credentials:get` |
| Delete | `DELETE /api/v1/oidc/credentials/{scope}/{name}` (204) | `OIDCCredentialDelete` | `oidc.credential.delete` | `oidc_credentials:delete` |
| Import | `POST .../{scope}/{name}/import` | `OIDCCredentialImport` | `oidc.credential.import` | `oidc_credentials:update` |
| Refresh | `POST .../{scope}/{name}/refresh` | `OIDCCredentialRefresh` | `oidc.credential.refresh` | `oidc_credentials:update` |
| Access token | `POST .../{scope}/{name}/token` (`Cache-Control: no-store`) | `OIDCCredentialGetAccessToken` | `oidc.credential.token` | `oidc_credentials:token` |
| Device login start | `POST .../{scope}/{name}/device` | `OIDCCredentialDeviceStart` | `oidc.credential.device.start` | `oidc_credentials:update` |
| Device login poll | `POST .../{scope}/{name}/device/poll` | `OIDCCredentialDevicePoll` | `oidc.credential.device.poll` | `oidc_credentials:update` |

On REST the credential's `tenant_id` and `owner` are query parameters of the
per-credential routes. The access token is served by `POST` so no cache keeps
it. QUIC uses the REST routes over HTTP/3; USB (the paired phone) does not
serve this API (`ErrNotSupported`); the embedded transport calls the
service directly.

## Shapes (JSON; protobuf fields mirror them)

```jsonc
// Create
{ "scope": "tenant", "name": "codex", "tenant_id": "", "owner": "",
  "config": {
    "template": "openai",            // fills every empty field
    "issuer": "", "client_id": "", "client_secret": "", "scopes": [],
    "authorization_endpoint": "", "token_endpoint": "",   // token_endpoint set: no discovery
    "device_authorization_endpoint": "",
    "token_encoding": "form|json", "device_style": "rfc8628|openai",
    "no_refresh": false, "token_lifetime_seconds": 0, "refresh_margin_seconds": 0 },
  "tokens": {                        // optional: create already logged in
    "access_token": "...", "refresh_token": "...", "id_token": "...",
    "token_type": "Bearer", "scope": "", "expires_at": "2026-10-01T00:00:00Z" } }

// Import body
{ "tokens": { "access_token": "...", "refresh_token": "..." } }

// Credential (every response but token and delete)
{ "tenant_id": "acme", "scope": "tenant", "owner": "", "name": "codex",
  "config": { ... no client_secret ... },
  "status": "pending|active|relogin_required|expired", "status_reason": "",
  "expires_at": "...", "refreshable": true, "last_refresh": "...", "last_error": "",
  "device_login": { "user_code": "ABCD-EFGH", "verification_uri": "...",
                    "verification_uri_complete": "", "interval_seconds": 5,
                    "expires_at": "..." },
  "created_at": "...", "updated_at": "...", "created_by": "alice" }

// Access token
{ "access_token": "...", "token_type": "Bearer", "expires_at": "...",
  "id_token": "...", "scope": "" }
```

Absent times are omitted (protobuf: unset `google.protobuf.Timestamp`).

## Device login

`device` returns the credential with `device_login`. Poll `device/poll` no
more often than `interval_seconds`; the credential stays `pending` (with
`device_login`) until the user approves, then becomes `active` without it.
A provider `slow_down` raises `interval_seconds` by five. A denied or expired
login clears `device_login` and answers FailedPrecondition.

## Errors

The single classification is `apierrors.OIDCCredentialClassOf`:

| Class | REST | gRPC | Cases |
|---|---|---|---|
| InvalidArgument | 400 | `InvalidArgument` | bad name or scope, invalid configuration (unknown template, no issuer, non-https endpoint, discovery failure), no access token in an import |
| NotFound | 404 | `NotFound` | no such credential; unknown tenant |
| AlreadyExists | 409 | `AlreadyExists` | name taken |
| PermissionDenied | 403 | `PermissionDenied` | another user's personal credential; another tenant |
| FailedPrecondition | 409 | `FailedPrecondition` | `relogin_required`, `expired`, no login yet, not refreshable, no device login, flow not supported by the template, lost compare-and-swap, device login denied/expired |
| Unavailable | 503 | `Unavailable` | service not configured, barrier sealed, provider unreachable during a forced refresh |
| DataLoss | 500 | `DataLoss` | an undecodable record |

MCP maps the classes through its shared table (FailedPrecondition and
DataLoss answer the JSON-RPC internal-error code with the message).

## SDKs

- **Go** (`sdk/go`): every transport client carries the nine methods
  (`OIDCCredentialCreate`, ...). `CodexAuthFile(token, now)` renders the codex
  `auth.json` for an `OIDCAccessToken`; `ParseCodexAuth` reads one for import;
  `BuildOIDCCredentialService` and `OIDCCredentialService` serve an
  embedding host.
- **TypeScript** (`sdk/ts`): `client.oidcCredentials.{list, create, get,
  delete, importTokens, refresh, getAccessToken, startDeviceLogin,
  pollDeviceLogin, waitForDeviceLogin}`.

The web console advertises the feature as the `oidc_credentials` capability
of `GET /api/v1/capabilities`.
