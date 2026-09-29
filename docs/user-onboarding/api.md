# User Onboarding (Enrollment Invitations) — API

> **Status: NORMATIVE** · Feature: `user-onboarding` · Repo: `go-xkms` · Last verified: 2026-09-29

## Transport coverage

| Capability | REST | gRPC | Unix (gRPC) | QUIC | MCP | Embedded |
|---|---|---|---|---|---|---|
| `CreateUser` (mints the invitation) | yes | yes | yes | yes | yes | yes |
| `GetInvite` (metadata lookup) | yes | yes | yes | yes | yes | yes |
| `BeginInviteRegistration` / `FinishInviteRegistration` (FIDO2) | yes | yes | yes | yes | excluded (see below) | yes |
| `ActivateInvitePIV` | yes | yes | yes | yes | yes | yes |

`CreateUser` is pre-existing shared surface (`transport.XKMSServicer`); its
request/response were extended (`InviteTTLSeconds`, `Invite`) and that
extension reaches every transport — see `pkg/api/grpc/proto/xkmsv1/xkms.proto`
`CreateUserRequest.invite_ttl_seconds` / `UserResponse.invite`.

Invite **redemption** (`GetInvite`, the FIDO2 ceremony pair,
`ActivateInvitePIV`) is composed surface too: `InviteServicer` /
`InviteService` in `pkg/api/transport/{servicer,client}.go`, embedded into
`transport.XKMSServicer` / `transport.Client`. Every implementation is
public/unauthenticated and carries the same opaque errors this doc
describes for REST — there is no credential yet to authenticate a request
with, the same reason the pre-existing FIDO2/WebAuthn ceremony RPCs
(`BeginRegistration`/`FinishRegistration`/`BeginAuthentication`/
`FinishAuthentication`) are ungated.

**MCP exclusion.** `BeginInviteRegistration`/`FinishInviteRegistration` are
NOT exposed as MCP tools (`pkg/api/transport/mcp/transport.go` returns
`ErrIdentityCeremonyExcluded` for both). This is the exact go-xkms#193
ruling already applied to `BeginRegistration`/`FinishRegistration`: MCP
holds no state to correlate a Begin call with its matching Finish call, and
an agent-facing tool surface must not mint sessions or enroll credentials.
`GetInvite` and `ActivateInvitePIV` have no such problem — neither is a
Begin/Finish pair — so both are ordinary MCP methods, `invite.get` and
`invite.pivActivate` (`pkg/api/mcp/handlers_invite.go`).

Server-side, gRPC and Unix share one implementation
(`pkg/api/grpc/service_invite.go`, registered on `KeystoreService`, which
the Unix transport dials over a Unix listener exactly as it does for every
other RPC). QUIC has no separate server package; it reuses REST's HTTP
handlers directly over HTTP/3, so the REST section below is also the QUIC
contract. See this feature's `cli.md` for `xkmsctl user invite redeem`, the
CLI's redemption path over its default transport.

The four RPCs' deliberate absence from `option (qrdb.v1.permission)` is
pinned by `pkg/api/grpc/authz_proto_option_test.go`'s
`TestRPCPermissions_UnannotatedRPCsAreTheUngatedOnes` — an unannotated RPC
is DEFAULT-DENY on the unified server, so this golden is the explicit
register of "deliberately public"; an RPC cannot join it silently. `GetInvite`,
`BeginInviteRegistration`, `FinishInviteRegistration`, and
`ActivateInvitePIV` are registered there alongside the pre-existing
`BeginRegistration`/`FinishRegistration`/`BeginAuthentication`/
`FinishAuthentication`.

## REST

All four routes are public (`RouteAuthPublic`, `GroupInvite`) — there is no
credential yet to authenticate a request with — and sit behind the login
rate limiter, matching the WebAuthn ceremony routes.

### `GET /api/v1/invites/{tenant_id}/{token}`

Returns still-usable invitation metadata.

```json
{
  "email": "invitee@example.com",
  "display_name": "Invitee",
  "expires_at": "2026-09-30T12:00:00Z",
  "methods": ["webauthn", "piv"]
}
```

404 (`{"error":"invite_unusable","message":"invite: link is not valid",...}`)
for an absent, expired, or already-redeemed token — the same response for
all three (see `architecture.md` "Opacity").

### `POST /api/v1/invites/{tenant_id}/{token}/fido2/begin`

No request body. Returns the WebAuthn registration ceremony:

```json
{"session_id": "...", "options_json": "{\"publicKey\":{...}}"}
```

`options_json` is a JSON-encoded `protocol.CredentialCreation` — unmarshal
it, take `.publicKey`, and drive it through `navigator.credentials.create()`
or an SDK authenticator adapter exactly as the ordinary registration
ceremony (`pkg/webauthn/http`) is driven. 404 `invite_unusable` for a bad
token; 503 if WebAuthn is not configured on this server.

### `POST /api/v1/invites/{tenant_id}/{token}/fido2/finish`

```json
{"session_id": "...", "attestation_json": "{...}"}
```

`attestation_json` is the authenticator's raw `PublicKeyCredential`
attestation response JSON. On success:

```json
{"user_id": "42", "message": "activation successful"}
```

400 for a missing `session_id`/`attestation_json`; 404 `invite_unusable` for
a bad or already-redeemed token; the underlying WebAuthn verification
failure (wrong attestation, session expired) is also reported as
`invite_unusable` — an invite redemption failure carries no more detail than
a bad token, for the same opacity reason.

### `POST /api/v1/invites/{tenant_id}/{token}/piv/activate`

```json
{"cert_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n"}
```

On success, the same `{"user_id":..., "message":"PIV activation successful"}`
shape. 400 for a missing/malformed `cert_pem` (`ErrPIVCertDecode`); 422 for a
certificate that does not chain to the CA's trust pool (`ErrPIVCertRejected`
— reported with detail, since the caller's own certificate is not a secret);
404 `invite_unusable` for a bad token; 503 if no CA is configured.

## gRPC / Unix

`KeystoreService` (`pkg/api/grpc/proto/xkmsv1/xkms.proto`) carries the same
four RPCs, deliberately with no `option (qrdb.v1.permission)` — its absence
is this codebase's established marker for "ungated", the pattern the
pre-existing FIDO2 ceremony RPCs use:

- `GetInvite(GetInviteRequest{tenant_id, token}) → GetInviteResponse{email, display_name, expires_at, methods}`
- `BeginInviteRegistration(BeginInviteRegistrationRequest{tenant_id, token}) → BeginInviteRegistrationResponse{session_id, options_json}`
- `FinishInviteRegistration(FinishInviteRegistrationRequest{tenant_id, token, session_id, attestation_json}) → FinishInviteRegistrationResponse{user_id}`
- `ActivateInvitePIV(ActivateInvitePIVRequest{tenant_id, token, cert_pem}) → ActivateInvitePIVResponse{user_id}`

Errors map to gRPC status codes the same way REST maps them to HTTP status:
`ErrInviteUnusable` → `NotFound`; a PIV cert decode failure →
`InvalidArgument`; a PIV cert the CA's trust pool rejects →
`FailedPrecondition`; nothing configured → `Unavailable`
(`pkg/api/grpc/service_invite.go` `invitationErrorStatus`). The Unix
transport dials the identical `KeystoreService` over a Unix-socket
listener, so it gets these RPCs and this error mapping for free.

## MCP

`invite.get` and `invite.pivActivate` are ordinary public JSON-RPC methods
(`publicMethods` in `pkg/api/mcp/authz.go`), taking and returning the same
`transport.GetInviteRequest`/`Response` and
`transport.ActivateInvitePIVRequest`/`Response` shapes as every other
transport. Errors map to JSON-RPC codes the same way: `ErrInviteUnusable` →
not-found; a PIV cert error → invalid-params; nothing configured →
internal-error (`pkg/api/mcp/handlers_invite.go` `mapInviteError`).

`invite.beginRegistration` / `invite.finishRegistration` do not exist: the
SDK client's `BeginInviteRegistration`/`FinishInviteRegistration` return
`ErrIdentityCeremonyExcluded` when dialed over MCP
(`pkg/api/transport/mcp/transport.go`), the same behavior
`BeginRegistration`/`FinishRegistration` already have on this transport.

## `CreateUser` (extended)

`POST /api/v1/users/` — request gains `invite_ttl_seconds` (optional
override, seconds); response becomes `{"user": {...}, "invite": {...}}`
where `invite` is present only for an account with an email login key
(`without_email_login_key: false`, the default):

```json
{
  "user": {"id": "42", "username": "alice", "email": "alice@example.com", "enabled": false, ...},
  "invite": {
    "token": "b64url-secret",
    "url": "https://kms.example.com/ui/#/invite/acme/b64url-secret",
    "expires_at": "2026-09-30T12:00:00Z"
  }
}
```

The same shape is carried by every transport's `CreateUser` (gRPC
`UserResponse.invite`, MCP `user.create`'s JSON-RPC result, the embedded SDK,
QUIC). `enabled` is `false` on this response for an invited account: it is
`LifecyclePending`, not yet active.
