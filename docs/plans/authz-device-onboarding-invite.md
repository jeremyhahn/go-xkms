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

Results to follow.
