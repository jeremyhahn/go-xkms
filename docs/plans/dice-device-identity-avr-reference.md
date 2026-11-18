# dice-device-identity slice 2: AVR backend holds alias certificates to a registered application reference

Row: docs/SPEC.md:90 (epic #2087). Stacked on slice 1 (lane sdiceida).

## Objective

The operator registers the device's application reference (the 32 bytes the
alias certificate's application evidence, DICE measurement 273, must equal)
in the AVR backend's attestation configuration. The backend refuses a
malformed reference at `NewBackend`, and every alias certificate is held to
it through `dice.Verify`.

## Names

- `AttestationConfig.ApplicationReference []byte`,
  `yaml:"application_reference" json:"application_reference"`; optional,
  nil keeps today's behaviour.
- unexported `Backend.applicationReference []byte`, a copy set by
  `initAttestation`.
- `checkAliasCertificate` passes it as `dice.VerifyOptions.ApplicationReference`.

## Refusals

- `initAttestation` (so `NewBackend`): a reference neither empty nor 32 bytes
  -> `&errs.Detail{Err: dice.ErrInvalidApplicationReference, Detail:
  "attestation.application_reference: expected 32 bytes, got N"}`.
- `checkAliasCertificate`: evidence differing from the reference ->
  `dice.ErrApplicationEvidenceMismatch` (from `dice.Verify`).
- No new error.

## Files

- pkg/backend/avr/attestation.go, pkg/backend/avr/backend.go
- pkg/backend/avr/attestation_reference_test.go (new)
- docs/dice-device-identity/engineering.md (one sentence)
- .changelog/unreleased/added-2087-avr-application-reference.md (new)
- this plan

## Tests (test commit before feat commit)

- matching reference accepted, leaf returned; last byte flipped refused with
  `ErrApplicationEvidenceMismatch`; nil reference accepted.
- `NewBackend` with a 31-byte reference refused with
  `ErrInvalidApplicationReference`; 32-byte reference with no trust store
  accepted.

## Checks

- go test -race -tags "codec_cbor codec_json codec_msgpack" ./pkg/backend/avr/... ./pkg/attestation/dice/...
- sdk/go go build ./...
- make lint

## Out of scope

device-attest-01 and the finalize match (acme-issuance lane),
pkg/attestation/verifier.go, the device registry, sdk/go, docs/SPEC.md.

## Results

- Field: `AttestationConfig.ApplicationReference` (pkg/backend/avr/attestation.go:61),
  `[]byte` as in `dice.VerifyOptions`.
- Refusal at NewBackend: pkg/backend/avr/backend.go:196; reaches dice.Verify at
  pkg/backend/avr/attestation.go:223.
- Left: the acme-issuance lane's device-attest-01 finalize match, and a
  reference held by the device registry rather than one per backend config.
- Run: go test -race ./pkg/backend/avr/... ./pkg/attestation/dice/...: pass.
- Run: sdk/go go build ./...: pass.
- Run: make lint: first run timed out at 540 s in golangci-lint (web/desktop);
  rerun pass, 0 issues in every module and tag set.

## Slice 3: SPEC.md row text (applied)

Lane row2087b ran with LANE_POLICY_ALLOW for docs/SPEC.md and applied the
text below to the row (docs/SPEC.md:89); each citation was checked against
ea93b2af2. The row stays in progress: the acme-issuance match is open.

- Replace the row's last sentence ("Open: the reference match of
  acme-issuance; nothing matches the 32 bytes against a registered reference
  yet.", docs/SPEC.md:90) with:
  "`dice.Verify` matches the 32 bytes in constant time when its caller sets
  `VerifyOptions.ApplicationReference` (`pkg/attestation/dice/verify.go:59`,
  `:282`), refusing a differing one with `ErrApplicationEvidenceMismatch`; the
  AVR backend sets it from the operator's `attestation.application_reference`
  (`pkg/backend/avr/attestation.go:61`, `:223`) and refuses a reference that
  is not 32 bytes at `NewBackend` (`backend.go:196`). Open: the reference
  match of acme-issuance (device-attest-01 and finalize hold no registered
  reference yet)."
- Stale verify.go citations in the same row after slice 1 (1-based on f378cbe60):
  `verify.go:139` -> `:148` (Evidence.RootType), `:229` -> `:241`
  (`RootTypeFromPaths(paths)`), `:512` -> `:551` (`verifyRootTypePermitted`).
- 2026-11-14: applied as above, with `backend.go:196` written in full as
  `pkg/backend/avr/backend.go:196`. Left before the row ships: the
  acme-issuance reference match.

## Slice 4: device-attest-01 and finalize match the registered reference

Lane row2087c closes the row's last open item, the acme-issuance reference
match.

- Test (f13676345): `reference_test.go` mints aliases carrying a ruled 273 and
  holds them to a registry record's reference: the registered application is
  accepted, another one, a leaf without 273 and an endorsed device without it
  are refused with `dice.ErrApplicationEvidenceMismatch`, a 31-byte reference
  is an invalid record, no reference checks nothing; at finalization a
  reference changed after validation is refused under `ErrDeviceNotAuthorized`.
- Fix: `ProvisionedDevice.ApplicationReference`; `verifyDICEClaims` passes it
  to `dice.Verify` on both paths; `ConfirmRegisteredDevice` takes the recorded
  leaf and re-checks it through the now-exported
  `dice.VerifyApplicationReference`.
- engineering.md names the wiring. The SPEC.md row text and status flip were
  reverted pending owner approval (Slice 5).
- Out of scope: filling the reference in a production registry (the
  `DeviceResolver` implementation is the caller's, e.g. go-quicbaas); the
  acme-issuance row's own "Open: nothing matches the 32 bytes" sentence
  (docs/SPEC.md:40) is now stale and is that row's edit.

## Slice 5: Codex review of the lane tip

- Fixed: `NewBackend` (`pkg/backend/avr/backend.go:194`) let a non-nil empty
  `AttestationConfig.ApplicationReference` skip the 32-byte check, which left
  the application unchecked. Now only nil means no reference; an empty slice is
  refused with `dice.ErrInvalidApplicationReference`. Regression test
  `TestNewBackendRefusesAnEmptyApplicationReference` (f1adf88d0, fix f57db64fa).
- SPEC row 90 (Codex P1, no owner approval recorded): the row's edits are
  reverted to main's text. The row stays `in progress` with its earlier
  "Open:" sentence until the owner approves the device-attest-01 match
  contract and the `shipped` flip.
