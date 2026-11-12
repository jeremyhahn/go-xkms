# Plan: xkmsctl attestation appraise (row 1660, slice 8)

## Gap

After slice 7 an operator can load endorsements and reference values from
`xkmsctl`, but cannot run the appraisal itself: `AppraiseAttestationQuote`
is served on every transport and on the sdk/go `Client`, yet has no CLI verb.

## Verb

`xkmsctl attestation appraise` sends a TPM quote with its evidence to
`AppraiseAttestationQuote` and prints the attestation result.

Flags:

- `--reference-values <name>` (required): the stored reference-values name.
- `--ak-cert <file>`: AK certificate chain, PEM, leaf first.
- `--quote <file>`: marshaled TPMS_ATTEST.
- `--signature <file>`: the quote signature.
- `--nonce <hex>`: the qualifying data the quote was taken over.
- `--pcr <index>=<hex>` (repeatable): PCR value, index 0-23, each index once.
- `--event-log <file>` (optional): the measured-boot event log.

All input is checked before any call; empty files are refused. The CLI does
not parse the quote or the certificate; xkmsd does.

## Exit rule

Exit 0 only when the result is verified. Otherwise the result is still
printed, then the command exits non-zero with `ErrAttestationNotVerified`,
noting a cryptographic failure when `CryptographicFailure` is set.

## Tests (cmd/xkmsctl/attestation_appraise_test.go)

- `TestAttestationAppraiseCmd_Registered`
- `TestAttestationAppraiseCmd_SendsEvidence`
- `TestAttestationAppraiseCmd_Verified`
- `TestAttestationAppraiseCmd_NotVerified`
- `TestAttestationAppraiseCmd_Refusals`
- `TestAttestationAppraiseCmd_CallFails`

## Checks

- `go test -count=1 -race -tags "codec_cbor codec_json codec_msgpack" ./cmd/xkmsctl/`
- `go build ./...` at the root
- `cd sdk/go && go build ./...`
- `make lint`

## Out of scope

A JSON evidence-file input, xkey, server and transport code, the proto,
sdk/go, docs/SPEC.md.

## Results

Results to follow.
