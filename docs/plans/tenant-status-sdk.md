# Tenant status: the sdk/go ACME admin client refuses a status set and filter

Row: tenant-status (docs/SPEC.md:129), epic #2092, lane stenstg (slice 7).

## Objective

Until go-qrdb carries a tenant status, the public sdk/go ACME admin client
refuses a tenant status set and a tenant list status filter with a typed
unsupported-field error and sends no request.

## Names (package sdk/go/acme/client/admin)

- Sentinel `ErrTenantStatusUnsupported` (standard library `errors.New`).
- `TenantStatusUnsupportedError struct { errors.CAError; Field string }`,
  `Is` true for the sentinel, otherwise `CAError.Is`.
- `NewTenantStatusUnsupported(op string)`: `Field: "status"`, built on
  `errors.NewInvalidInput`, so `errors.IsInvalidInput` holds. No new code.

## Refusals

- `tenantCAClient.UpdateTenantStatus` (op `admin.tenant.ca.UpdateTenantStatus`).
- `tenantClient.List` with a non-empty `Status` (op `admin.tenant.List`).
- The admin GUI API maps the SDK sentinel to 400 `TENANT_STATUS_UNSUPPORTED`.

## Files

sdk/go/acme/client/admin/{errors,tenant_ca,tenant,types}.go and their tests,
pkg/acme/gui/admin/api/tenant_status.go, admin_api_test.go,
docs/acme/gui/admin/api.md, .changelog/unreleased/changed-2092-sdk-tenant-status.md.

## Checks

- `cd sdk/go && go test -count=1 -race ./acme/client/admin/...`
- `cd sdk/go && go build ./...`
- `go test -count=1 -race -tags "codec_cbor codec_json codec_msgpack" ./pkg/acme/gui/admin/...`
- `make lint`

## Results

- Error: `TenantStatusUnsupportedError`, `ErrTenantStatusUnsupported` and
  `NewTenantStatusUnsupported` in sdk/go/acme/client/admin/errors.go; it also
  unwraps to its CAError so `errors.IsInvalidInput` holds.
- Refusals: tenant_ca.go `UpdateTenantStatus` (the unused
  `updateTenantStatusTransportRequest` is gone) and tenant.go `List`.
- GUI: tenant_status.go matches the SDK sentinel for 400 `TENANT_STATUS_UNSUPPORTED`.
- sdk/go `go test -race ./acme/client/admin/...`: pass.
- sdk/go `go build ./...`: pass.
- GUI `go test -race ./pkg/acme/gui/admin/...` (codec tags): pass.
- `make lint`: first run timed out at 540 s (rc=124), second run pass, 0 issues.
