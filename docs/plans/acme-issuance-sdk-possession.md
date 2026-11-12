# acme-issuance: sdk/go exports the device-attest-01 possession-request assembly

Row acme-issuance (docs/SPEC.md:41), epic #1667, slice 3 (lane sacmeic).

## Gap

- SPEC.md:41's first claim: "`sdk/go` exports `AssemblePossessionCSR`, the
  device-attest-01 possession-request assembly".
- ROADMAP "Now" acme-issuance item for the same claim.
- trusted-firmware #28: the xkms adapter is written against
  `AssemblePossessionCSR` and may import only sdk/go.

On the base 4f5437c73 `AssemblePossessionCSR` exists only in
pkg/acme/challenges/device-attest-01/possession.go; nothing under sdk/go
exports it.

## Names (package `trustedca`, sdk/go/acme)

Aliases of the deviceattest01 values, never copies or wrappers:
`AssemblePossessionCSR`, `BuildPossessionCRI`, `SignPossessionCSR`,
`DICENonce`, `ParsePossessionCSR`, `PossessionRequest` (type alias), and the
sentinels `ErrPossessionCSRMalformed`, `ErrPossessionSignatureInvalid`,
`ErrPossessionSigningFailed`, `ErrPossessionMeasurementsShape`.

## Files

- sdk/go/acme/possession_test.go (test commit first, ruling 286)
- sdk/go/acme/possession.go (aliases only)
- docs/acme-issuance/api.md (one paragraph in the device-attest-01 finalize section)
- .changelog/unreleased/added-1667-sdk-assemble-possession-csr.md

## Checks

- `cd sdk/go && go test -count=1 -race -tags "codec_cbor codec_json codec_msgpack" ./acme/`
- `cd sdk/go && go build ./...`
- `go test -count=1 -race -tags "codec_cbor codec_json codec_msgpack" ./pkg/acme/challenges/device-attest-01/...`
- `make lint`

## Out of scope

Device registry (row device-registry), evidence endpoints, csr-attestation,
pkg/acme/challenges/device-attest-01/*, docs/SPEC.md, ROADMAP.md.

## Results

Results to follow.
