# Plan: invitations minted under users:invite (row authz-device-onboarding, epic #2091)

## Objective

`XKMSService.CreateUser` mints an activation invitation for every account
created with an email login key, but only users:create is checked (at the
transports). go-qrdb's users:invite permission, which governs inviting a user
into the caller's tenant, is never asked. After this slice an invitation is
minted only for a caller allowed users:invite.

## Steps

1. Test commit: `pkg/xkms/servicer_user_invite_authz_test.go` wires the service
   to a real `auth.Authorizer` over go-qrdb's RBAC and checks:
   - users:create without users:invite: refused with
     `*qrdbsdk.PermissionDeniedError`, no user left behind;
   - users:create and users:invite: the invitation is minted;
   - `WithoutEmailLoginKey` (bootstrap, no invite): users:create suffices;
   - no authorizer (RBAC disabled): unchanged behaviour.
2. Fix commit: `CreateUser` calls `AuthorizeCaller` for users:invite before it
   creates the account when an invitation will be minted, and returns the
   refusal unchanged (no create-then-rollback).
3. Docs commit: one paragraph in `docs/user-onboarding/engineering.md` and a
   changelog entry.

## Out of scope

- Device onboarding: go-qrdb registers no device-onboarding permission yet, so
  the SPEC row stays planned.
- docs/SPEC.md (the coordinator corrects the stale "not re-exported" clause).

## Upstream remainder (go-qrdb)

Register a device-onboarding permission (e.g. `devices:onboard`, tenant
self-scope, governance duty), granted by the built-in Admin and Operator roles
and re-exported by sdk/go as `PermissionDevicesOnboard`. Absent from sdk/go
v0.51.0-alpha and v0.58.2-alpha.

## Results

- Test commit: the users:create-only case failed (no error); the other three passed.
- After the fix: `go test -count=1 -tags "codec_cbor codec_json codec_msgpack" ./pkg/xkms/... ./pkg/api/rest/... ./pkg/api/mcp/... ./pkg/api/grpc/...` passed.
- `make lint` passed (0 issues on every module and tag set).
- No other invitation-minting path: `createInvite` (pkg/xkms/servicer_invite.go) has one caller, `CreateUser`.

## Slice 2 (PR #2114): transports and SPEC row

- `pkg/api/rest/routes.go` and `pkg/api/mcp/server.go` need no change: their
  invite routes only redeem an invitation (public; the single-use token is the
  credential), and the user-create route must stay gated on users:create
  alone, because the bootstrap path (`WithoutEmailLoginKey`) mints no
  invitation. users:invite is asked in `CreateUser`, below every transport.
- docs/SPEC.md row text (slice 2b, LANE_POLICY_ALLOW docs/SPEC.md): the
  clause from "with invites created under users:create" up to "Parent:" now
  says users:invite decides who mints an invitation (`CreateUser`,
  `pkg/xkms/servicer_user.go:147-150`); the invite-route citations were
  re-pointed to `pkg/api/rest/routes.go:559-565` and
  `pkg/api/mcp/server.go:447-448`.
- Status `in progress`: the users:invite half is done; the device half stays
  planned until go-qrdb registers the device-onboarding permission (absent
  from sdk/go v0.51.0-alpha and v0.58.2-alpha; upstream remainder above).

## Slice 3: nothing left in go-xkms

- The brief named `pkg/api/rest/routes.go` as the first edit; slice 2 already
  shows the transports need no change (redemption is public, users:create
  stays the create gate, users:invite is asked in `CreateUser`). No route or
  MCP edit was made, so no test was added.
- Main still pins go-qrdb and sdk/go v0.51.0-alpha. The row's only remainder
  is go-qrdb registering a device-onboarding permission and tagging it; this
  row then bumps the pin, grants it on the default roles and marks the row
  shipped. Until then the row is blocked upstream.

## Slice 4 (lane row2091c): Codex P1 findings on 9b3375e75f3c

1. Self-built ServiceModule host left the service authorizer nil, so a
   users:create-only caller still got an invitation. Test 04ce9aa77 (role ID
   set-up corrected in cd7c89fe6): `pkg/apimodule/module_host_invite_authz_test.go`
   mounts the module without pkg/server over a real qrdb node. Fix ac6c0e378:
   `hostStores` wires `auth.NewAuthorizer(client.RBAC())` into the service.
2. The refusal surfaced as a server fault. Test 9b9cdb272: one assertion per
   transport (REST 403, gRPC PermissionDenied, MCP ErrCodeForbidden). Fix
   8c00ce10f: `handleCreateUser`, `createUserErrorCode` and `mapUserError`
   classify `PermissionDeniedError` (and `auth.ErrUnauthenticated`) with each
   gate's own message.

## Slice 5 (lane row2091c): Codex P1 findings on 358219ec3

1. The self-built host wired the qrdb RBAC plane whenever a client existed,
   so a host that runs with authorization disabled refused invitations.
   Test eb924a2df: `TestModule_HostMount_AuthDisabledAllowsInvite`. Fix
   5a75c2e78: `WithAuthorization(false)` (sdk/go
   `WithServiceModuleAuthorization`) keeps the service authorizer nil; unset,
   the module enforces (fail closed).
2. `AuthorizeCaller` decided through `bindIdentity`'s SDK projection, which
   drops ScopePermissions, so a delegated caller granted users:invite there
   was refused. Test d185f1ec4: `TestIdentityAuthorizer_DecidesOnScopePermissions`
   (pkg/auth) and `TestModule_HostMount_DelegatedInviteUsesNodeAuthorizer`.
   Fix 4f0f00612: `auth.NewIdentityAuthorizer` decides on the original
   identity through the node's own authorizer; the module uses it under
   `WithNodeAuthorizer` (sdk/go `WithServiceModuleNodeAuthorizer`).

## Slice 6 (lane row2091c): finish PR #2114

- Merge c615e57d0: origin/main 81a1a5fb3.
- Audit (security): test ce046ba16, fix 358a722fe. `CreateUser` decides
  users:invite through `authorizeAudited`: allow and deny are both emitted;
  a failed audit write returns `AuditGateError` and creates nothing. pkg/server
  hands the service its audit sink.
- xkmsd full identity: test 7961e2ecb, fix 873cad9ca. `initializeAuthorization`
  builds `auth.NewNodeAuthorizer(qrdbClient.RBAC(), node.Authorizer())`, so
  ScopePermissions count. This replaces slice 5's open note.
- Surface: test fc14d1b3f, fix 5b8bd8b97. `WithAuthorization`,
  `WithNodeAuthorizer`, their sdk/go re-exports, `auth.IdentityAuthorizer`,
  `ErrNoPermissionLister`, `NewIdentityAuthorizer` and `WithRBAC` are removed.
  A host sets its own service's authorizer: `auth.NewAuthorizer(nil)` when
  auth is off, `auth.NewNodeAuthorizer` for the full identity. `hostStores`
  wires the RBAC plane only when none is set (`XKMSService.Authorizer`).
  `auth.NewNodeAuthorizer` and that accessor are the two new exports.
- SPEC: 90aa9bf11 restores main's authz-device-onboarding row text. Its
  revision is left to the owner or coordinator.

## Slice 7 (lane row2091c): Codex findings on f30418821

- Merge 3b1fb9b73: origin/main a4d3c0924.
- Audit on the self-built host (security): test ee1dd45e2, fix 946427788.
  When `hostStores` wires the default authorizer, it also sets the
  service's audit sink to the host node's audit plane: an unexported
  `clientAuditSink` over `client.Audit()`, bound to `WithServiceContext`.
  The users:invite denial now lands in the node's trail, and a failed write
  returns `AuditGateError`. A host that sets its own authorizer also sets its
  own sink (`SetAuditLogger`).
- `.github/workflows/scans.yml` and `code-review.yml` (two findings): both
  files are main's (ruling 742, #2245), merged in through main. After this
  merge the branch does not change them (`git diff origin/main...HEAD --
  .github` is empty), so no change was made in this row.
