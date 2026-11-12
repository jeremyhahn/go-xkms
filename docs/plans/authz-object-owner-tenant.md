# authz-object-owner: object tenancy by go-qrdb's OwnTenant

Row: authz-object-owner (docs/SPEC.md). The row stays planned: this slice
covers the tenant half only.

## Objective

`scope.Principal.Authorize` (pkg/scope/principal.go) compares tenant names by
hand. go-qrdb's pinned sdk/go (v0.51.0-alpha) already carries the one
"no caller acts on another tenant" rule, `qrdbsdk.OwnTenant`. Move the tenant
step of `Authorize` onto it, so the owner and service-scope checks are the
row's only gap.

## Steps

1. test(scope): pkg/scope/owntenant_test.go: a cross-tenant refusal matches
   `scope.ErrRefused` and, through `errors.As`, `*qrdbsdk.CrossTenantDeniedError`;
   the system tenant written as "" and as `SystemTenant` is one tenant on
   either side; a system-tenant principal addressing another tenant is
   refused. The `errors.As` case fails before step 2.
2. refactor(scope): the tenant step calls
   `qrdbsdk.OwnTenant(qrdbsdk.ContextWithTenant(ctx, caller), target, "scope.authorize")`
   with both sides normalized to go-qrdb tenant IDs; `*CrossTenantError`
   keeps its fields and `Is(ErrRefused)` and gains `Unwrap` returning the
   go-qrdb error. Owner and service checks are unchanged.
3. Changelog entry.

Out of scope: the owner/service ABAC half (upstream), docs/SPEC.md, the
`Authorize(Target)` signature and its call sites.

## Upstream remainder (go-qrdb issue draft, filed by the coordinator)

Title: sdk/go: object-owner ABAC decision for personal and service-scoped objects
API needed: a go-qrdb decision, re-exported by sdk/go, that admits an identity
to an object by the object's owner and scope (tenant / user-owned /
service-owned) with a service-scope permission check, returning a typed
refusal (cross-user, service-scope) that matches go-qrdb's
PermissionDeniedError family.
Why: go-xkms `Principal.Authorize` keeps its own owner and ServiceAccess
checks (row authz-object-owner); go-xkms must keep no authorization check
beside go-qrdb's IAM/RBAC model (parent row authz-tenant-iam). Not in sdk/go
v0.51.0-alpha nor v0.58.2-alpha.

## Results

Results to follow.
