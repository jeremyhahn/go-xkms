# xkey-sdk-only: pkg/fido2/authenticator/keybackend through sdk/go/fido2/keybackend

Row: xkey-sdk-only (docs/SPEC.md:180), epic #2084, lane sxsdki.

## Gap

SPEC.md:180: xkey reaches go-xkms through sdk/go only; a surface sdk/go lacks
becomes an sdk/go addition. Seven xkey test files still import
`github.com/jeremyhahn/go-xkms/pkg/fido2/authenticator/keybackend`:

- xkey/cmd/xkey/cmd/fido2_cdp_test.go
- xkey/cmd/xkey/cmd/fido2_provision_attestation_test.go
- xkey/cmd/xkey/cmd/fido2_status_daemon_test.go
- xkey/cmd/xkey/cmd/fido2_storage_test.go
- xkey/pkg/gui/services/fido2_service_test.go
- xkey/pkg/phone/phone_test.go
- xkey/test/integration/fido2/backend_test.go

## Slice

1. test(sdk): sdk/go/fido2/keybackend/reexport_test.go,
   `TestReexport_AttestationNames`.
2. feat(sdk): five aliases in sdk/go/fido2/keybackend/keybackend.go:
   `AttestationCertificateOU`, `ErrAttestationAAGUIDMismatch`,
   `ErrAttestationCertInvalid`, `MarshalAAGUIDExtensionValue`,
   `OIDFIDOGenCEAAGUID`.
3. refactor(xkey): import path swap in the seven files (cmd, pkg, integration).

## Checks

- sdk/go: go test ./fido2/keybackend/ (race, codec tags); go build ./...
- xkey: go build ./...; go vet (codec tags; integration tags for test/integration/fido2)
- xkey: go test -run FIDO2|CDP|... ./cmd/xkey/cmd/ ./pkg/gui/services/; go test ./pkg/phone/
- make lint

## Results

- sdk/go go test -race ./fido2/keybackend/: ok
- sdk/go go build ./...: ok
- xkey go build ./... + go vet (codec tags; integration linux pkcs11 tags): ok
- xkey go test -race -run FIDO2|CDP|... ./cmd/xkey/cmd/ ./pkg/gui/services/: ok
- xkey go test -race ./pkg/phone/: ok
- make lint: ok (0 issues, all modules and tag sets)
- Done-check grep over xkey for the pkg keybackend import: no hits.
- gofmt -l lists pre-existing files in xkey/cmd/xkey/cmd (device_*_test.go)
  and xkey/pkg/phone (13 *_test.go) that this slice does not touch.
