# Plan: authz-xkey-uid0, slice 1: wire the go-qrdb authorizer into xkey audit reads

SPEC row: authz-xkey-uid0 (docs/SPEC.md:76). The row stays planned until the
audit-store slice lands.

## Objective

xkey's `AdminService.authorizeAuditRead` refuses every audit read because
`xkey/pkg/gui/app.go` never calls `SetAuthorizer`. When xkey runs on the
embedded xkms service, that service already holds the process's go-qrdb-backed
`*auth.Authorizer`. Expose it and wire it, without ever turning "refuse" into
"allow all": a nil or disabled `*auth.Authorizer` stored in the
`QRDBAuthorizer` interface is non-nil and allows everything.

## Steps

1. Test commit: `pkg/xkms/service_authorizer_accessor_test.go` (accessor is a
   nil interface with no authorizer and with a disabled one; returns the
   wired authorizer when enabled) and
   `xkey/pkg/gui/services/admin_service_authorizer_test.go` (no RBAC: audit
   reads still refused with `*AuditReadDeniedError`; enabled authorizer:
   identity with `audit:read` reads, without it is refused).
2. Feat commit: `Service.Authorizer() qrdbsdk.Authorizer` in
   `pkg/xkms/service.go`, nil unless enabled; `app.go` calls
   `adminService.SetAuthorizer` only with a non-nil result.
3. Changelog entry.

## Next slice (out of scope here)

Move xkey audit events into go-qrdb's audit store through sdk/go instead of
the local `xkey/pkg/audit/dao_store.go` store. Results to follow.

## Results
