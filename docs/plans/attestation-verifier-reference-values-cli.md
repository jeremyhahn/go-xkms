# Plan: xkmsctl attestation reference-values verbs (row 1660, slice 7)

## Gap

docs/SPEC.md:43 makes go-xkms the Verifier: a tenant loads signed CoRIM
reference values and appraises evidence against them. The four
reference-value verbs are served on every transport and are on the sdk/go
`Client`, but `xkmsctl` has no surface for them: an operator can reach them
only through a raw API call. Slice 6 added `xkmsctl attestation endorsement`;
this slice follows it.

## Verbs

- `xkmsctl attestation reference-values put <name> --corim <file> [--repository <ref>]`:
  reads the COSE_Sign1 signed CoRIM file, refuses a missing `--corim`, a
  missing file or an empty file before any call, and calls
  `PutAttestationReferenceValues`. The CLI does not parse the CoRIM; xkmsd
  verifies it.
- `xkmsctl attestation reference-values get <name>`: `GetAttestationReferenceValues`.
- `xkmsctl attestation reference-values list`: `ListAttestationReferenceValues`.
- `xkmsctl attestation reference-values delete <name>`: `DeleteAttestationReferenceValues`.

Every verb honours `-o json`. Permissions: attestation_reference_values:create,
:get, :list, :delete.

## Tests (cmd/xkmsctl/attestation_reference_values_test.go)

- `TestAttestationReferenceValuesCmds_Registered`
- `TestAttestationReferenceValuesPutCmd`
- `TestAttestationReferenceValuesPutCmd_Refusals`
- `TestAttestationReferenceValuesGetCmd`
- `TestAttestationReferenceValuesListCmd`
- `TestAttestationReferenceValuesDeleteCmd`

## Checks

- `go test -count=1 -race -tags "codec_cbor codec_json codec_msgpack" ./cmd/xkmsctl/`
- `go build ./...` at the root and in sdk/go
- `make lint`

## Out of scope

The appraise verbs (the next slice), xkey, server and transport code, the
proto, sdk/go, docs/SPEC.md.

## Results

- `go test -count=1 -race -tags "codec_cbor codec_json codec_msgpack" ./cmd/xkmsctl/`: ok.
- `go build ./...` at the root: ok.
- `go build ./...` in sdk/go: ok.
- `make lint`: ok, 0 issues in every module and tag set.
