# Attestation Verifier: xkmsctl endorsement verbs (row 1660, slice 6)

## Gap

SPEC.md:43 makes go-xkms the Verifier with a tenant-scoped endorsement
store. The eight appraisal verbs are served on every transport and the
sdk/go `Client` carries them (slice 5), but xkmsctl has no surface:
docs/attestation-verifier/cli.md says "No xkmsctl surface", so a tenant
can load an AK root or a reference signer only through a raw API call.

## Verbs

- `xkmsctl attestation endorsement put <name> --kind ak-root|reference-signer
  (--cert <pem file> | --public-key <pem file>)`: exactly one of `--cert`
  and `--public-key`; the CLI reads the file and does not parse the PEM
  (xkmsd validates it). Permission `attestation_endorsements:create`.
- `xkmsctl attestation endorsement list [--kind ak-root|reference-signer]`.
  Permission `attestation_endorsements:list`.
- `xkmsctl attestation endorsement delete <name>`. Permission
  `attestation_endorsements:delete`.

Each goes through `runClientCall`; `-o json` prints the response as JSON.
Sentinels: `ErrPutAttestationEndorsementFailed`,
`ErrListAttestationEndorsementsFailed`,
`ErrDeleteAttestationEndorsementFailed`.

## Tests (cmd/xkmsctl/attestation_endorsement_test.go)

- `TestAttestationEndorsementCmds_Registered`
- `TestAttestationEndorsementPutCmd`
- `TestAttestationEndorsementPutCmd_Refusals`
- `TestAttestationEndorsementListCmd`
- `TestAttestationEndorsementDeleteCmd`

## Checks

- `go test -count=1 -race -tags "codec_cbor codec_json codec_msgpack" ./cmd/xkmsctl/`
- `go build ./...` at the root; `go build ./...` in sdk/go
- `make lint`

## Next slice

Reference values (put/list/delete) and the appraise verbs in xkmsctl.

## Results

Results to follow.
