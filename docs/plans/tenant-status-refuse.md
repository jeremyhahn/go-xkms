# Plan: refuse tenant status (set and filter), row tenant-status (#2092)

Row: docs/SPEC.md:129. Until go-qrdb carries a tenant status, go-xkms refuses a
tenant status, set or used as a filter, with a typed unsupported-field error.
Main pins go-qrdb v0.51.0-alpha, whose pkg/tenant has no status.

## Slice (lane stenstc)

1. Test commit: `UpdateTenantStatus` with any status and `ListTenants` with a
   non-empty `Status` return an error where `errors.Is(err,
   ErrTenantStatusUnsupported)` holds and `errors.As` yields
   `*UnsupportedFieldError{Field: "status"}`; the tenant record is unchanged
   after the refused call; REST and QUIC adapters answer with the existing
   input-error status and a stable error code.
2. Fix commit: add `UnsupportedFieldError` and the sentinel; refuse in both
   paths before any storage read.
3. Docs: OpenAPI/docs that advertise the status setter or filter; changelog.

## Decisions

- Internal deleted marker (`DeleteTenant`/`GetTenant`/list) is kept: it is not
  a caller-set status, and the refusal does not need its removal. Test
  fixtures set it through the tenant DAO (`markTenantDeleted`).
- `UpdateTenantStatus` checks the tenant ID and runs `admitTenant` first, so a
  cross-tenant caller still gets not-found; the refusal follows, before any
  storage read. `ListTenants` refuses a non-empty `Status` before any read.
- Stable code: problem type `urn:trusted-ca:error:tenant-status-unsupported`
  (`admin.ProblemTypeTenantStatusUnsupported`) with HTTP 400, the existing
  input-error status. The REST client maps that type back to the typed error.
- The list route is served by the core module, so the REST and QUIC clients
  refuse a status filter locally without sending a request. gRPC answers
  InvalidArgument through `IsValidationError`.
- One constructor, `admin.TenantStatusUnsupported()`, builds the error.

## Out of scope

- Bump to a go-qrdb release that carries `tenant.Status` (dependency lane,
  owner freeze). docs/SPEC.md is not edited.
- `pkg/acme/api/tenants.go` `TenantListPath` and the GUI status handler are
  outside the slice's file list; the clients no longer reach the former.

## Slice (lane stenstd): transports

4. Test commit: the REST status handler hands every value to the service and
   answers 400 `urn:trusted-ca:error:tenant-status-unsupported`; the gRPC list
   path answers the refusal as InvalidArgument (via `IsValidationError`).
5. Fix commit: the handler no longer judges the status value itself.
6. Docs: engineering.md tenant row; changelog entry.

## Checks

Lane stenstc:

- 2026-11-12 `go test -count=1 -tags "codec_cbor codec_json codec_msgpack" ./pkg/acme/admin/... ./pkg/acme/api/...`: fail, rest TestListTenants/successful_list adapter_test.go:653 (expected query kept status=active); expectation fixed in the fix commit.
- 2026-11-12 same command after the fix and docs: pass (admin, api, mcp, quic, rest, server, swagger ok).
- 2026-11-12 `make lint`: pass (actionlint clean; golangci-lint 0 issues on ., sdk/go, xkey, web/desktop and the backend/raft tag sets).

Lane stenstd:

- `go test -count=1 -tags "codec_cbor codec_json codec_msgpack" ./pkg/acme/admin/... ./pkg/acme/api/...`: pass.
- `make lint`: pass (0 issues on all modules and tag sets). A first run with
  GOMODCACHE=/tmp/gomod failed with two typecheck errors on missing
  /gocache files (the lint cache, not the code); the rerun in the default
  environment passed.
