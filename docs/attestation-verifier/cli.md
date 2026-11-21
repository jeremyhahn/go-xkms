# Attestation Verifier — CLI

> **Status: NORMATIVE** · Feature: `attestation-verifier` · Module: `go-xkms` · Last verified: 2026-11-12

## `xkmsctl attestation endorsement`

The tenant's endorsement store, the trust anchors the Verifier appraises
evidence against, is managed with three verbs in
`cmd/xkmsctl/attestation_endorsement.go`. Each calls the sdk/go `Client`
verb of the same name through `runClientCall`; `-o json` prints the
response as JSON. The CLI does not parse the PEM: xkmsd validates it.

| Verb | Usage | Permission |
|---|---|---|
| put | `xkmsctl attestation endorsement put <name> --kind ak-root\|reference-signer (--cert <pem file> \| --public-key <pem file>)` | `attestation_endorsements:create` |
| list | `xkmsctl attestation endorsement list [--kind ak-root\|reference-signer]` | `attestation_endorsements:list` |
| delete | `xkmsctl attestation endorsement delete <name>` | `attestation_endorsements:delete` |

- `--kind` is required on `put`: `ak-root` anchors attestation-key
  certificates, `reference-signer` anchors the keys that sign CoRIM
  reference values. Any other kind is refused before a call.
- `put` takes exactly one of `--cert` and `--public-key`; both, neither or
  an unreadable file is refused before a call.
- Failures carry `ErrPutAttestationEndorsementFailed`,
  `ErrListAttestationEndorsementsFailed` or
  `ErrDeleteAttestationEndorsementFailed` (`cmd/xkmsctl/errors.go`).

## `xkmsctl attestation reference-values`

The tenant's reference values, the signed CoRIM manifests the Verifier
appraises evidence against, are managed with four verbs in
`cmd/xkmsctl/attestation_reference_values.go`. Each calls the sdk/go
`Client` verb of the same name (`PutAttestationReferenceValues`,
`GetAttestationReferenceValues`, `ListAttestationReferenceValues`,
`DeleteAttestationReferenceValues`) through `runClientCall`; `-o json`
prints the response as JSON. The CLI does not parse the CoRIM: xkmsd
verifies its COSE_Sign1 signature against a `reference-signer` endorsement.

| Verb | Usage | Permission |
|---|---|---|
| put | `xkmsctl attestation reference-values put <name> --corim <signed corim file> [--repository <ref>]` | `attestation_reference_values:create` |
| get | `xkmsctl attestation reference-values get <name>` | `attestation_reference_values:get` |
| list | `xkmsctl attestation reference-values list` | `attestation_reference_values:list` |
| delete | `xkmsctl attestation reference-values delete <name>` | `attestation_reference_values:delete` |

- `--corim` is required on `put`; a missing flag, an unreadable file or an
  empty file is refused before a call. `--repository` is optional and is
  stored with the record.
- In text output `get` and `list` print one line per record: the name,
  manifest ID, profile, PCR indices and not-after time; the CoRIM bytes are
  printed only with `-o json`.
- Failures carry `ErrPutAttestationReferenceValuesFailed`,
  `ErrGetAttestationReferenceValuesFailed`,
  `ErrListAttestationReferenceValuesFailed`,
  `ErrDeleteAttestationReferenceValuesFailed` or
  `ErrInvalidReferenceValuesFlags` (`cmd/xkmsctl/errors.go`).

## `xkmsctl attestation appraise`

`xkmsctl attestation appraise`, in `cmd/xkmsctl/attestation_appraise.go`,
sends TPM quote evidence to the sdk/go `Client` verb
`AppraiseAttestationQuote` through `runClientCall` and prints the
attestation result. It needs `attestation_verifier:verify`. The CLI does not
parse the quote or the certificate: xkmsd does.

```
xkmsctl attestation appraise --reference-values <name> \
  --ak-cert <pem file> --quote <file> --signature <file> \
  --nonce <hex> --pcr <index>=<hex> [--pcr <index>=<hex> ...] \
  [--event-log <file>]
```

| Flag | Value |
|---|---|
| `--reference-values` | Name of the stored reference values to appraise against (required). |
| `--ak-cert` | Attestation-key certificate PEM file, leaf first, intermediates after (required). |
| `--quote` | Marshaled TPMS_ATTEST file (required). |
| `--signature` | The attestation key's signature over the quote (required). |
| `--nonce` | The qualifying data the quote carries, hex (required). |
| `--pcr` | A quoted PCR value, `<index>=<hex>` (at least one required). |
| `--event-log` | TCG crypto-agile event log file (optional). |

- `--pcr` is repeatable and also takes a comma-separated list
  (`--pcr 0=<hex>,7=<hex>`). The index is 0-23 and each index is given
  once; the value is non-empty hex.
- Every input is checked before any call: a missing flag, an unreadable or
  empty file, a nonce that is not hex or a malformed `--pcr` is refused with
  `ErrInvalidAppraiseFlags` or `ErrReadDataFileFailed`.
- Text output prints the verdict, the baseline (reference values, manifest
  ID, signer, baseline source, appraisal time) and one line per check with
  its outcome (`pass`, `forged`, `absent`, `skipped`) and reason; `-o json`
  prints the result as JSON.
- Exit rule: the command exits 0 only when the result is verified. Otherwise
  it prints the result, then exits non-zero with `ErrAttestationNotVerified`,
  adding "cryptographic failure: evidence present and wrong" when
  `CryptographicFailure` is set (a forged check, as opposed to missing
  evidence). A provisioning script can gate on the exit status.
- A failed call carries `ErrAppraiseAttestationQuoteFailed`
  (`cmd/xkmsctl/errors.go`).

`pkg/attestation`'s `Verifier`/`VerifyInvariants` still run server-side,
automatically, whenever a CSR carries attestation fields
(`AttestationFormat`/`AttestationChain`/`AttestationNonce`); no `xkmsctl`
verb invokes that verification directly.

xkey's verbs reach the same `Verifier` through the SDK aliases in
`sdk/go/attestation_verifier.go` (`NewAttestationVerifier` with
`WithAttestationTrustStore`). See [`architecture.md`](architecture.md)
§"Purpose-pooled checks". The calls are:

- `xkey device attest` (`xkey/cmd/xkey/cmd/device_attest.go:260`) builds
  the Android hardware pool;
- `xkey device enroll-phone`
  (`xkey/cmd/xkey/cmd/device_enroll_phone_ca.go:73`) does the same;
- `xkey tpm ek show` (`xkey/cmd/xkey/cmd/tpm_ek.go:401`) verifies the EK
  certificate.

Two related but distinct CLI surfaces exist, neither of which is this
feature:

- **Generating** an attestation statement is `xkmsctl key attest <key-id>`,
  documented in [`../key-management/cli.md`](../key-management/cli.md) — it
  calls a backend's `AttestKey`, not anything in this package.
- **Configuring** the trust anchors this feature verifies against is a
  server-config change (`attestation.formats.<format>` in the xkmsd YAML),
  not a CLI verb — see [`engineering.md`](engineering.md) §"Configuration".
  There is no `xkmsctl` command that edits it; it takes effect on server
  restart, wired in `pkg/server/server.go:916-926`.
