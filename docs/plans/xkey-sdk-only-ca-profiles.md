# xkey CA profile tests through sdk/go (issue 729, first slice)

## Gap

docs/SPEC.md:180 (row xkey-sdk-only): xkey reaches go-xkms through sdk/go
only; a name sdk/go lacks becomes an sdk/go alias, never a raw import.

Two xkey test files import `github.com/jeremyhahn/go-xkms/pkg/ca`:

- xkey/cmd/xkey/cmd/ca_profile_registry_test.go (`NewDefaultProfileRegistry`)
- xkey/cmd/xkey/cmd/device_enroll_phone_ca_test.go, build tag `ble`
  (`NewDefaultProfileRegistry`, `CertificateRequest`, `ErrProfileNotFound`)

sdk/go already has `NewDefaultProfileRegistry` and
`TrustedCACertificateRequest`; it lacks the sentinel `ErrProfileNotFound` and
its sibling `ErrInvalidProfile` (pkg/ca/errors.go).

Out of scope: xkey/cmd/xkey/cmd/xkmsd_harness_test.go (keeps pkg/ca in this
slice), non-test xkey files, pkg/, web/desktop, docs/SPEC.md.

## Slices

1. test(sdk): sdk/go/ca_profile_errors_test.go — `TestReexport_ProfileErrors`,
   `TestDefaultProfileRegistry_UnknownNameIsErrProfileNotFound`.
2. feat(sdk): `ErrProfileNotFound`, `ErrInvalidProfile` aliases in sdk/go/ca.go.
3. refactor(xkey): both files import sdk/go instead of pkg/ca.

## Checks

- sdk/go: go test -race -run 'TestReexport_ProfileErrors|TestDefaultProfileRegistry_'
- sdk/go: go build ./...
- xkey: go build ./... and go vet ./cmd/xkey/cmd/ with and without `ble`
- xkey: go test -race TestHelpProfileNames|TestCAIssueHelpProfilesAreRegistered|TestCertProfileDefaultsAreRegistered
- xkey: go test -race -tags ble TestEnrollmentCertProfile
- make lint

## Results

Results to follow.
