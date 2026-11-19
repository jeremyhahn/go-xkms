# authz-object-owner: object tenancy by go-qrdb's OwnTenant

Row: authz-object-owner (docs/SPEC.md). The SPEC row stays planned (slice 4):
the tenant half is shipped, the owner half waits on go-qrdb.

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

- before refactor: go test ./pkg/scope/... FAIL (owntenant_test.go:43, :69, errors.As to *CrossTenantDeniedError), as intended.
- after refactor: go test -tags "codec_cbor codec_json codec_msgpack" ./pkg/scope/... ./pkg/oidc/credential/... ./pkg/ssh/tenancy/... ./pkg/xkms/... ok.
- cd sdk/go && go build ./... ok.
- make lint ok (actionlint, golangci-lint 0 issues on every module and tag set).
- owner half: sdk/go v0.51.0-alpha has no owner/ABAC decision (only the PermissionDeniedError type); the upstream remainder stands.

## Slice 2: SPEC row text

docs/SPEC.md row `authz-object-owner` moves from planned to in progress: it
cites the tenant step (`ownTenant` calling `qrdbsdk.OwnTenant`, and
`*CrossTenantError.Unwrap` to go-qrdb's CrossTenantDeniedError) at
file:line and names the owner/ServiceAccess half as blocked on the go-qrdb
object-owner ABAC decision above. No code change; checks: go test of
./pkg/scope/... and make lint.

## Slice 3: upstream re-check

sdk/go v0.58.3-alpha and v0.58.4-alpha (latest on the proxy, 2026-11-14)
add `SystemRoleIDs`, `TenantFromCert` and `DelegationPolicy` (tenant cert
delegation, #1186) beyond v0.58.2-alpha: no object-owner ABAC decision. The
owner and ServiceAccess half stays blocked.

## Slice 4: SPEC row restored pending owner approval (Codex P1)

Codex review 5951392029: slice 2's rewrite of the `authz-object-owner`
requirements had no recorded owner approval. docs/SPEC.md is back to
main's row text (status planned); the status flip and tenant-step
citations wait for the owner's approval. Docs-only revert, no test.
