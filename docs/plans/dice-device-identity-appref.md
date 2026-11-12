# dice-device-identity: application reference match in dice.Verify

Row: dice-device-identity (docs/SPEC.md:90). Lane sdiceida.

## Objective

Every DICE verifier, not only device-attest-01, can hold a device to its
registered application: `dice.Verify` reads the alias certificate's 273
measurements (CoSWID evidence) and, when `VerifyOptions.ApplicationReference`
is set, refuses an alias chain whose application evidence is not the
expected reference.

## Slices, in order

1. Refactor: move the 273 shape parser from
   pkg/acme/challenges/device-attest-01/possession.go into
   pkg/attestation/dice/measurements.go as
   `ApplicationEvidence(measurements []byte) ([]byte, error)` and
   `ErrMeasurementsShape`. `ErrPossessionMeasurementsShape` stays and wraps
   `dice.ErrMeasurementsShape`. `TestPossessionMeasurementsShape` passes
   unchanged.
2. Tests: pkg/attestation/dice accepts the trusted-firmware CoSWID vector,
   refuses each shape violation; `Verify` with `ApplicationReference` refuses
   a differing 273 evidence (`ErrApplicationEvidenceMismatch`), refuses a
   leaf with no 273, and is unchanged when no reference is set.
3. Feat: `VerifyOptions.ApplicationReference []byte` (32 bytes or nil; any
   other length is a config error); constant-time check after the nonce
   check.
4. Docs: docs/dice-device-identity/engineering.md names the export and the
   option; one changelog entry.

## Out of scope

`VerifyPossessionCSR`, anchors.go, registry.go (lane sacmeia); SPEC.md;
dependency changes.

## Checks

- `go test -count=1 -tags "codec_cbor codec_json codec_msgpack"
  ./pkg/attestation/dice/... ./pkg/acme/challenges/device-attest-01/...
  ./pkg/backend/avr/...`
- `make lint`

## Results

Results to follow.
