# xkey CA profile tests through sdk/go (issue 729, first slice)

## What the row does

docs/SPEC.md:180 (row xkey-sdk-only): xkey reaches go-xkms through sdk/go
only; a name sdk/go lacks becomes an sdk/go alias, never a raw import.

This slice moves two xkey test files off `github.com/jeremyhahn/go-xkms/pkg/ca`:

- xkey/cmd/xkey/cmd/ca_profile_registry_test.go (`NewDefaultProfileRegistry`)
- xkey/cmd/xkey/cmd/device_enroll_phone_ca_test.go, build tag `ble`
  (`NewDefaultProfileRegistry`, `CertificateRequest`, `ErrProfileNotFound`)

sdk/go already had `NewDefaultProfileRegistry` and
`TrustedCACertificateRequest`; sdk/go/ca.go now re-exports the sentinels
`ErrProfileNotFound` and `ErrInvalidProfile` (pkg/ca/errors.go).

## Slices (done)

1. test(sdk): sdk/go/ca_profile_errors_test.go — `TestReexport_ProfileErrors`,
   `TestDefaultProfileRegistry_UnknownNameIsErrProfileNotFound`.
2. feat(sdk): `ErrProfileNotFound`, `ErrInvalidProfile` aliases in sdk/go/ca.go.
3. refactor(xkey): both files import sdk/go instead of pkg/ca.
4. docs(changelog): unreleased entry.

## Tests

- sdk/go: the two tests above (sentinel identity with pkg/ca; unknown
  profile name returns `ErrProfileNotFound`).
- xkey: TestHelpProfileNames, TestCAIssueHelpProfilesAreRegistered,
  TestCertProfileDefaultsAreRegistered; with `ble`, TestEnrollmentCertProfile*.

## Checks (2026-11-16, branch 1 commit behind main, merges cleanly)

T="codec_cbor codec_json codec_msgpack"

- (cd sdk/go && go test -count=1 -race -tags "$T" .): pass
- (cd xkey && go test -count=1 -race -tags "$T" ./cmd/xkey/cmd/): pass
- make lint: pass (0 issues on every module and tag set)

## Still open for the row

- xkey/cmd/xkey/cmd/xkmsd_harness_test.go still imports pkg/ca (next slice).
- Non-test xkey files are not yet audited for raw go-xkms imports.

Out of scope: pkg/, web/desktop, docs/SPEC.md.
