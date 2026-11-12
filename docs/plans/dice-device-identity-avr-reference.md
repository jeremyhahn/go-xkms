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

Results to follow.
