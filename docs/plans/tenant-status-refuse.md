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
  a caller-set status, and the refusal does not need its removal.

## Out of scope

- Bump to a go-qrdb release that carries `tenant.Status` (dependency lane,
  owner freeze). docs/SPEC.md is not edited.

## Slice (lane stenstd): transports

4. Test commit: the REST status handler hands every value to the service and
   answers 400 `urn:trusted-ca:error:tenant-status-unsupported`; the gRPC list
   path answers the refusal as InvalidArgument (via `IsValidationError`).
5. Fix commit: the handler no longer judges the status value itself.
6. Docs: engineering.md tenant row; changelog entry.

## Checks

- `go test -count=1 -tags "codec_cbor codec_json codec_msgpack" ./pkg/acme/admin/... ./pkg/acme/api/...`: pass.
