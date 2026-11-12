# Tenant status: typed refusal of the xkms tenant list status filter (#2092)

Row (docs/SPEC.md:129): "Until go-qrdb carries it, go-xkms refuses a tenant
status, set or used as a filter, with a typed unsupported-field error".

## Prior lanes

- stenstc: `UnsupportedFieldError`, `ErrTenantStatusUnsupported` in
  pkg/acme/admin; the ACME service refuses set and filter; REST and QUIC
  client adapters refuse a filter.
- stenstd: ACME REST handler answers 400
  `urn:trusted-ca:error:tenant-status-unsupported`; gRPC answers
  InvalidArgument.
- stenste: gRPC/MCP/QUIC client adapters refuse filter and set; the admin
  GUI API answers 400 TENANT_STATUS_UNSUPPORTED.

## This slice

- `XKMSService.ListTenantDetails` refuses a non-empty status with
  `*xkms.TenantUnsupportedFieldError{Field: "status"}` (matching
  `xkms.ErrTenantStatusUnsupported`) before any lookup; an empty status
  lists as before.
- REST `GET /api/v1/tenants/?status=` answers 400.

Slices in order:

1. Test commit: TestListTenantDetails_StatusRefused (pkg/xkms) and
   TestListTenantsHandler_StatusFilterRefused (pkg/api/rest); both fail on
   the branch tip.
2. Fix commit: pkg/xkms/errors.go, servicer_tenant.go,
   pkg/api/rest/handlers_tenant.go.
3. Docs commit: docs/multi-tenancy/api.md and the changelog sentence.

## Decision

`TenantRecord.Status` reporting and the internal deleted marker stay: they
are not a caller-set status.

## Out of scope

The go-qrdb bump, docs/SPEC.md, an sdk/go typed error, the GUI Svelte view.

## Results

Step 0 (merge of 47d09162b) not done: the object is absent from the lane object store and origin has no refs to fetch from; the coordinator merges it.

- go build ./...: pass.
- go test -run Tenant ./pkg/xkms/ (codec tags): pass.
- go test ./pkg/api/rest/ (codec tags): pass.
- make lint: pass (third run; the first two were cut by the 540 s timeout, warm cache finished it).
