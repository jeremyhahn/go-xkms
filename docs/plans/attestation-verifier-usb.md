# attestation-verifier (go-xkms#1660), slice 4: one appraisal error table and the USB transport

SPEC row: docs/SPEC.md:43 (attestation-verifier).

## (b) One appraisal error table

`appraisalSentinelClasses` exists in three identical copies. It moves to
`apierrors.AttestationAppraisalSentinelClasses` with
`apierrors.AttestationAppraisalClassOf`, after `SigningKeyClassOf` in
pkg/api/apierrors/tables.go. Entries, in order:

1. `xkms.ErrNotConfigured` Unavailable
2. `appraisal.ErrNilRequest` InvalidArgument
3. `appraisal.ErrInvalidName` InvalidArgument
4. `appraisal.ErrInvalidTenant` InvalidArgument
5. `appraisal.ErrInvalidRepository` InvalidArgument
6. `appraisal.ErrEndorsementInvalid` InvalidArgument
7. `appraisal.ErrReferenceValuesRejected` InvalidArgument
8. `appraisal.ErrInvalidAKIntermediate` InvalidArgument
9. `appraisal.ErrRecordNotFound` NotFound
10. `appraisal.ErrStoreUnavailable` Unavailable

Files that drop their copy:

- pkg/api/rest/handlers_attestation_appraisal.go (`appraisalClassOf`)
- pkg/api/mcp/handlers_attestation_appraisal.go (`mapAttestationAppraisalError`)
- pkg/api/grpc/service_attestation_appraisal.go (`mapAttestationAppraisalError`)

Test: pkg/api/apierrors/attestation_appraisal_test.go
(`TestAttestationAppraisalClassOf`, `TestAttestationAppraisalClassOf_Unclassified`).

## (a) USB transport

A USB device holds no tenant endorsements or reference values, so the 8
`transport.AttestationAppraisalService` methods on `usb.Transport` return
`ErrNotSupported`, as the repository signing-key verbs do
(pkg/api/transport/usb/transport_signing_key.go). New file
pkg/api/transport/usb/transport_attestation_appraisal.go; test
`TestAttestationAppraisal_NotSupported`.

## Checks

- go test (codec tags) of apierrors, rest, mcp, grpc, transport/usb
- sdk/go build
- make lint

## Out of scope

- Adding `AttestationAppraisalService` to `transport.Client` (touches mocks in
  cmd/xkmsctl, sdk/go, test/integration and xkey): follow-up.

## Results

- (b) done: `apierrors.AttestationAppraisalSentinelClasses` / `AttestationAppraisalClassOf`
  (pkg/api/apierrors/tables.go:355-370); REST, MCP and gRPC call it; the
  three copies were identical. Simplify pass: MCP passes the classifier directly.
- (a) done: 8 USB methods return `ErrNotSupported`
  (pkg/api/transport/usb/transport_attestation_appraisal.go:27-67).
- go test (codec tags) apierrors, rest, mcp, grpc, transport/usb: pass.
- sdk/go `go build ./...`: pass.
- make lint: pass (0 issues on every module and tag set).
- Follow-up: add `AttestationAppraisalService` to `transport.Client`.
