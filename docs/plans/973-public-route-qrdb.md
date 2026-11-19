# 973: public-route qrdb lookups through the node user service

## Objective

Tenant Agent ruling 973, items (1), (2) and (4):

- (1) The WebAuthn user store does qrdb lookups through the datastore client
  with no credentials ("webauthn begin registration: get user by email: qrdb
  user lookup: qrdb/auth: unauthenticated"); registration/begin and
  login/begin answer 500. Resolve users through the embedded node's user
  service, the way nodeCertUsers does in pkg/server/server.go, not through an
  access-check bypass. Fix the whole anonymous-context family (#2287/#2292).
- (2) Invite redemption answers 404 "link is not valid" on a fresh token:
  servicer_invite.go maps every GetUser error to ErrInviteUnusable. Prove the
  cause and fix it.
- (4) The WebAuthn handler logs service errors only at Debug, without the
  server logger. Log a 500's cause at Error, never secrets or challenges.

Rulings 946/953 hold: no new permissions in pkg/embeddednode/serviceprincipal/,
no path that skips the access check, the identity a lookup acts for comes only
from server-side state.

## Public-route qrdb calls

From pkg/api/rest/routes.go, routes with Auth: RouteAuthPublic. Before the
fix every user call below ran through the datastore client under the
anonymous request context, refused by an auth-enforcing node with
qrdb/auth: unauthenticated. After it they run through the embedded node's
user service (auth.NodeUserClient, the nodeCertUsers path), wired as
NodeUsers on xkmsd (Server.nodeUserSource) and on a host
(rest.HostConfig.NodeUsers, apimodule.WithNodeUsers). No service-principal
call and no serviceprincipal permission is added.

| Route | Handler | qrdb call | Fixed in |
|---|---|---|---|
| POST /api/v1/webauthn/registration/begin, /finish | webauthnHandler.BeginRegistration/FinishRegistration | qrdbUserStore GetUserByEmail, CreateUser, UpdateUser | fix(webauthn) |
| POST /api/v1/webauthn/login/begin, /finish | webauthnHandler.BeginLogin/FinishLogin | qrdbUserStore GetUserByEmail, GetUser | fix(webauthn) |
| POST /api/v1/webauthn/sdk/{registration,authentication}/{begin,finish} | handleSDK* | same user store | fix(webauthn) |
| GET /api/v1/invites/{tenant_id}/{token} | handleGetInvite | XKMSService.GetInvite: GetUser | fix(xkms) |
| POST /api/v1/invites/{tenant_id}/{token}/fido2/{begin,finish} | handleInviteBeginFIDO2/FinishFIDO2 | GetUser, UpdateUser (activate) | fix(xkms) |
| POST /api/v1/invites/{tenant_id}/{token}/piv/activate | handleInviteActivatePIV | GetUser, AddCertBinding, UpdateUser | fix(xkms) |
| POST /api/v1/auth/refresh | handleAuthRefresh | QRDBUserResolver GetUser/GetUserByUsername | fix(auth) |
| POST /api/v1/auth/login/piv | handlePIVLogin | UserByCertThumbprint via nodeCertUsers | already node-backed (#2287) |

Invite and credential KV reads (invite store, WebAuthn credential DAO,
refresh-token store) run through the datastore's service context, not the
user client, and were not refused. /health*, /api/v1/algorithms,
/api/v1/capabilities and /v1/ca/bootstrap make no qrdb user call.

## Slices

1. test(server): xkmsd wiring over an auth-enforcing embedded node:
   registration/begin, login/begin answer 200; a fresh invite redeems.
2. fix(webauthn): node-backed user lookup for the WebAuthn user store.
3. fix(xkms): invite GetUser through the node user service.
4. fix(auth): #2292 refresh re-check through the node user service.
5. test(webauthn/http) + fix: 500 cause logged at Error via the server logger.
6. Playwright spec test/integration/web/tests/passkey-node.spec.ts.
7. docs/plans/2292.md and the changelog.

## Out of scope

docs/SPEC.md, .github/workflows/, web/app/, pkg/embeddednode/serviceprincipal/.
