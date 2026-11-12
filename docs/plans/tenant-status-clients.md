# Tenant status: client adapters and admin GUI refuse (lane stenste, #2092)

Row (docs/SPEC.md:129): "Until go-qrdb carries it, go-xkms refuses a tenant
status, set or used as a filter, with a typed unsupported-field error".

## Prior lanes

- stenstc: `UnsupportedFieldError`, `ErrTenantStatusUnsupported`,
  `TenantStatusUnsupported()` in pkg/acme/admin; the service refuses set and
  filter; the REST and QUIC client adapters refuse a list filter.
- stenstd: the REST handler answers 400
  `urn:trusted-ca:error:tenant-status-unsupported`, the gRPC server answers
  InvalidArgument.

## This slice

1. Tests (fail on the branch tip):
   - grpc adapter: TestListTenants_StatusFilterRefused (no RPC sent),
     TestUpdateTenantStatus_Refused.
   - mcp adapter: ListTenants status filter subtest (no call sent);
     UpdateTenantStatus asserts `ErrTenantStatusUnsupported`.
   - quic adapter: TestUpdateTenantStatus_Refused.
   - admin GUI API: TestUpdateTenantStatus_Unsupported (400
     TENANT_STATUS_UNSUPPORTED); InternalError keeps 500.
2. Fix: the gRPC and MCP client adapters refuse a status filter; the
   gRPC/MCP/QUIC adapters refuse a status set with
   `admin.TenantStatusUnsupported()` instead of ErrRESTOnly; the admin GUI
   API maps InvalidInput to 400 TENANT_STATUS_UNSUPPORTED.
3. Docs: engineering.md Tenant row, changelog sentence.
4. Runs: go build, package tests, make lint; results below.

## Out of scope

The go-qrdb bump, docs/SPEC.md, an sdk/go typed error, the GUI Svelte view.
