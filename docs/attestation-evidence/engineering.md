# Attestation Evidence — Engineering

> **Status: NORMATIVE** · Feature: `attestation-evidence` · Repo: `go-xkms` · Last verified: 2026-10-01

## Exported surface — `pkg/attestation/evidence`

| Name | Purpose |
|---|---|
| `ParseQuote(attest []byte) (*Quote, error)` | parse and structurally check a TPMS_ATTEST quote |
| `(*Quote).VerifySignature(key, sig) error` | RSA PKCS#1 v1.5 / PSS, ECDSA DER or raw r‖s, under the quote's hash |
| `(*Quote).VerifyQualifyingData(expected) error` | constant-time extraData check |
| `(*Quote).VerifyPCRValues(map[int][]byte) error` | reported set equals selection; values hash to the signed digest |
| `(*Quote).Covers(idx) bool` | whether a register was quoted |
| `VerifyQuote(QuoteInput) (*Quote, error)` | all four checks in order |
| `ComparePCRs(proven, reference) error` | proven values against reference values |
| `BankDigestSize(bank) (int, bool)` | accepted banks and their register size |
| `ParseCertificatesPEM(pem) (leaf, intermediates, error)` | split a PEM bundle |
| `VerifyAKCertificate(leaf, extra, AKCertificateOptions) (crypto.PublicKey, error)` | AK chain + verifiedTPMRestricted |
| `CarriesVerifiedTPMRestricted(cert) bool` | policy check, both OID forms |
| `ParseEKCertificateChain(raw) (leaf, intermediates, error)` | DER or PEM bundle |
| `VerifyEKCertificate(leaf, intermediates, EKCertificateOptions) error` | EK chain + tcg-kp-EKCertificate |
| `HasEKCertificateEKU(cert) bool`, `StripEKCertificateQuirks(cert)` | the two EK helpers |
| `ParseEventLog(data []byte) (*EventLog, error)` | strict crypto-agile log parser |
| `(*EventLog).Replay(bank) (map[int][]byte, error)` | registers the log touches |
| `VerifyEventLog(log, bank, quoted) error` | log explains quoted values |
| `ResetValue(pcr, size) []byte` | power-on value (0x00, or 0xFF for PCRs 17–22) |

Constants: `ClassForged`, `ClassAbsent`, the `Check*` names,
`EventNoAction`, `MaxEventDataSize`, `MaxEvents`, `MaxAlgorithms`.
OIDs: `OIDTCGVerifiedTPMRestricted`, `OIDTCGVerifiedTPMRestrictedPolicy`,
`OIDTCGKpEKCertificate` (pkg/ca's `OIDTCGKpEKCertificate` is this value).

## Errors

- `*Error{Class, Check, Reason, Cause}` for every check. `errors.Is(err,
  ErrForged)` / `errors.Is(err, ErrAbsent)` match by class.
- `*EventLogError{Offset, Event, Reason}` for a log that does not parse;
  matches `ErrEventLogMalformed`. Offsets are absolute byte offsets.

## Invariants

- No SHA-1 bank is accepted, for quotes or replay.
- A quote must select exactly one bank; multi-bank and empty selections are
  absences.
- Replay never extends EV_NO_ACTION. A StartupLocality event sets PCR 0's
  initial value to its locality; every other register starts at zero.
- Event-log digest sizes come only from the Spec ID header; a record naming
  an undeclared algorithm, or the same algorithm twice, is malformed.

## Event-log replay scope

The parser and replay cover the SRTM log a PC Client firmware produces. A
DRTM log, and H-CRTM sequences beyond the StartupLocality initial value, are
not replayed; a quoted register 17–22 the log does not touch is compared
against its reset value.

## Signed reference values (CoRIM)

`VerifySigned(data, VerifyOptions) (*Manifest, error)` requires exactly one
trust source, otherwise `ErrTrustSource`:

- `PublicKey` — a pinned signer key; or
- `Roots` (plus optional `Intermediates`) — the signer chain is taken from the
  COSE `x5chain` header (label 33; protected preferred, unprotected accepted per
  RFC 9360), verified at `Now` with `ExtKeyUsageAny`, and the signature is
  verified under the leaf key.

Both the corim-meta signature validity and the unsigned CoRIM's RIM validity
are enforced when present (`ErrNotYetValid`, `ErrExpired`). Every failure wraps
a sentinel: `ErrMalformed`, `ErrSignerChain`, `ErrSignature`, `ErrTrustSource`,
`ErrNotYetValid`, `ErrExpired`.

`(*Manifest).PCRDigests(hash)` follows the TPM CoRIM convention of uint
measurement keys as PCR indices and returns, per PCR, every digest of the
requested SHA-2 hash. An index above 23 is `ErrPCRIndex`, a wrong-length digest
`ErrDigestLength`, and a hash other than SHA-256, SHA-384 or SHA-512
`ErrUnsupportedHash`. Results never alias the decoded CoRIM.

Types: `VerifyOptions`, `Manifest` (`ID`, `Profile`, `Signer`, `NotBefore`,
`NotAfter`, `ReferenceValues`), `ReferenceValue`, `Environment`, `Measurement`
(exact `SVN` and `MinSVN` kept apart), `MeasurementKey`, `Digest` (with
`Hash()`), and the `KeyKind*` constants.

## SDK

`sdk/go/evidence` aliases every name above, plus `pkg/tpm2`
`VerifyCertify`, `VerifyCertifyByCertificate`, `VerifyCertifyRaw`,
`CertifyVerification`, `VerifyCertifyOptions` and the `ErrCertify*`
sentinels, and `pkg/attestation/peer` `VerifyIAK`, `VerifyIDevID`,
`IsIAK`, `IsIDevID`, `DevIDPolicy`.

## Tests

`pkg/attestation/evidence` builds real TPMS_ATTEST structures with go-tpm
and signs them with software ECDSA P-256/P-384 and RSA keys; event logs are
built byte-for-byte by a test writer (Spec ID header with SHA-1, SHA-256 and
SHA-384, a StartupLocality event, post-code and separator events) and replay
is checked against hand-computed values. Every malformed-log rule has a case.
Run with `make test-pkg`-style invocations or
`go test ./pkg/attestation/evidence/`.
