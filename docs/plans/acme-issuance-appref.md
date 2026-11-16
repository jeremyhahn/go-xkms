# acme-issuance: device-attest-01 application reference (row acme-issuance, epic #1667)

Row acme-issuance (docs/SPEC.md:41), PR #2102.

## What the row does

- device-attest-01 finalize matches the possession request's 32-byte
  application evidence against the reference registered on the provisioned
  device (constant-time compare); a mismatch is refused with
  `ErrPossessionApplicationEvidenceMismatch`.
- `ProvisionedDevice.ApplicationReference` is exactly 32 bytes when set.
- Unregistered device: gated on `DICEPolicy.RequireApplicationReference`
  (refuse when set; admit without the comparison when off, the default), so
  `TestDeviceAttestDICEEnrollsTheRealFirmware` (no reference registered)
  still enrolls. Policy in docs/plans/acme-issuance-appref-policy.md.
- sdk/go/acme exports the possession-request assembly
  (`AssemblePossessionCSR` and friends, aliases only); plan in
  docs/plans/acme-issuance-sdk-possession.md.

## Tests

- `TestApplicationReference` (registry_test.go): match, wrong length,
  missing.
- `TestVerifyPossessionCSRApplicationEvidence` (possession_test.go): match,
  one-byte mismatch, missing reference, wrong-length reference.
- sdk/go/acme: `TestAssemblePossessionCSR_SigningVector`,
  `TestAssemblePossessionCSR_Refusals`, `TestDICENonce`.

## Verify-ready check (lane row1667a, 2026-11-16, HEAD 491a28437)

T="codec_cbor codec_json codec_msgpack"

- `go test -count=1 -race -tags "$T" ./pkg/acme/challenges/device-attest-01/...
  ./pkg/acme/server/handlers/... ./pkg/config/... ./cmd/xkmsd/`: pass.
- `(cd sdk/go && go test -count=1 -race -tags "$T" ./acme/...)`: pass.
- `make lint`: pass (0 issues in every module and tag set, actionlint pass).
- No code change was needed.

## Still open

- The DICE e2e tests in pkg/acme/client need the tfwsim-atecc608a binary,
  which CI builds; not run in a lane container.
- Device registry (row device-registry) is the producer of
  `ApplicationReference`; out of scope for this row.
- Main is red on Devcontainer, Soak and Integration (ruling 648); not this
  row's to fix.
