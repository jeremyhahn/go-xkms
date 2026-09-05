# Attested Peer — Engineering Contract

> **Status: NORMATIVE** · Feature: `attested-peer` · Repo: `go-xkms` · Last verified: 2026-09-05

## Exported surface — `pkg/attestation/peer`

| Identifier | Role |
|---|---|
| `Verifier` (interface), `NewVerifier(opts ...Option) Verifier` | The primitive. `Verify(ctx, Evidence, Policy) (Verdict, error)`. Safe for concurrent use. |
| `WithClock(func() time.Time) Option` | Pins the clock used for certificate validity, `VerifiedAt` and freshness. Tests use it; production leaves the default (`time.Now().UTC()`). |
| `Evidence` | `Quote`, `Signature`, `Nonce`, `PCRs map[int][]byte`, `AKCertificatePEM`, `CollectedAt`. |
| `Policy` | `Anchors`, `Intermediates`, `AllowUnrestrictedAK`, `Baseline map[int][]byte`, `RequiredPCRs []int`, `MaxEvidenceAge`, `ChannelBinding`. |
| `Verdict` | `Passed`, `Checks`, `Failure FailureClass`, `Reason`, `PCRs` (proven values), `Clock ClockInfo`, `FirmwareVersion`, `VerifiedAt`, `EvidenceAge`. |
| `Checks` | Eight booleans: `AKCertificate`, `Signature`, `Nonce`, `ChannelBinding`, `PCRDigest`, `RequiredPCRs`, `Baseline`, `Freshness`. |
| `FailureClass` | `FailureNone`, `FailureAbsence`, `FailureCryptographic`; `String`, `MarshalText`, `UnmarshalText`. |
| `ClockInfo` | The quote's `TPMS_CLOCK_INFO`. |
| `QualifyingData(nonce, channelBinding []byte) []byte` | `SHA-256(nonce ‖ binding)`, or a copy of the nonce when the binding is empty. Used by both the quoting and the verifying side. |
| `ChannelBinding(*tls.ConnectionState) ([]byte, error)` | 32 bytes of exported keying material under `ExporterLabel`. |
| `ExporterLabel`, `ChannelBindingLength` | `"EXPORTER-attested-peer"`, `32`. |
| `*PolicyError`, `*ContextError`, `*ChannelBindingError`, `*FailureClassError` | The typed errors. |

SDK aliases in `sdk/go/attestation_peer.go` carry a `Peer` prefix
(`PeerAttestationVerifier`, `PeerEvidence`, `PeerPolicy`, `PeerVerdict`,
`PeerChecks`, `PeerFailureClass` and constants, `NewPeerAttestationVerifier`,
`WithPeerVerifierClock`, `PeerQualifyingData`, `PeerChannelBinding`,
`PeerChannelBindingExporterLabel`, `PeerChannelBindingLength`,
`PeerPolicyError`, `PeerContextError`, `PeerChannelBindingError`) because
`Evidence`, `Verifier` and `VerifyOptions` already name the x509
key-attestation surface in the flat `xkms` namespace.

## Invariants

1. **Fail closed.** A check that cannot run is an absence failure, never a
   pass. `Verdict.Passed` is true only when all eight `Checks` hold.
2. **Nothing from the peer is trusted until proven.** The certificate is
   chained before its key is used; the quote is parsed before any field is
   read; PCR values are "proven" only when `AKCertificate`, `Signature`,
   `Nonce` and `PCRDigest` all hold, and only then are they compared to the
   baseline or reported in `Verdict.PCRs`.
3. **The failure class is derived in one place.** `outcome.finish` reads the
   accumulated failures; a check records `absent(...)` or `wrong(...)` and
   nothing else decides the class. Cryptographic dominates absence.
4. **Every failure is named.** `Reason` joins every failed check's reason in
   check order. A verdict with a bad signature and stale evidence says both.
5. **Errors are for the caller's mistakes only.** `Verify` returns
   `*PolicyError` for a policy that cannot be evaluated and `*ContextError`
   for a done context. It never returns an error about the evidence.
6. **No allocation aliases the evidence.** `Verdict.PCRs` and the result of
   `QualifyingData` are copies.
7. **Constant-time comparison** for qualifying data, PCR digest and baseline
   values (`crypto/subtle`).
8. **No `fmt.Errorf`, no ignored errors, no `time.Sleep`, no stubs.**

## Fail-closed paths, by condition

| Condition | Check reported false | Class |
|---|---|---|
| `AKCertificatePEM` empty | `AKCertificate` (and `Signature`, `Baseline` as "not evaluated") | absence |
| PEM has no `CERTIFICATE` block, or DER does not parse | `AKCertificate` | cryptographic |
| `Policy.Anchors` nil | `AKCertificate` | absence |
| Certificate does not chain / expired / missing intermediate | `AKCertificate` | cryptographic |
| Certificate lacks 2.23.133.11.1.3 and `AllowUnrestrictedAK` false | `AKCertificate` | cryptographic |
| Certificate key is not RSA or ECDSA | `AKCertificate` | cryptographic |
| `Quote` empty | `Signature`, `Nonce`, `PCRDigest`, `RequiredPCRs` (if any) | absence |
| `Quote` is not a `TPMS_ATTEST`, wrong magic, not `TPM_ST_ATTEST_QUOTE`, unknown digest length | same, plus the parse reason | cryptographic |
| Selection empty, multi-bank, or SHA-1 bank | `Signature`, `Nonce`, `PCRDigest` | absence |
| `Signature` empty | `Signature` | absence |
| Signature does not verify | `Signature` | cryptographic |
| `Nonce` empty | `Nonce`, `ChannelBinding` | absence |
| extraData ≠ expected qualifying data | `Nonce` (and `ChannelBinding` when bound) | cryptographic |
| extraData = bare nonce under a binding policy | `ChannelBinding` only | cryptographic |
| `PCRs` empty | `PCRDigest` | absence |
| Reported index set ≠ selection, wrong value length, digest mismatch | `PCRDigest` | cryptographic |
| A `RequiredPCRs` register not in the selection | `RequiredPCRs` | absence |
| Values unproven (any of 1, 2, 3, 5 false) | `Baseline` | absence |
| `Policy.Baseline` empty | `Baseline` | absence |
| Proven index set ≠ baseline index set | `Baseline` | absence |
| A proven value differs from the baseline | `Baseline` | cryptographic |
| `MaxEvidenceAge > 0` and `CollectedAt` zero, in the future, or older than the bound | `Freshness` | absence |

## Errors

| Error | When | Carries |
|---|---|---|
| `*PolicyError` | `MaxEvidenceAge < 0`; a negative PCR index in `Baseline` or `RequiredPCRs`; an empty `Baseline` value; a required PCR with no baseline entry while the baseline is non-empty | `Field`, `Reason` |
| `*ContextError` | `ctx.Err() != nil` before verification | `Cause` (unwraps to the context error) |
| `*ChannelBindingError` | nil state; handshake not complete; the TLS stack refuses to export (TLS 1.2 without extended master secret) | `Reason`, `Cause` |
| `*FailureClassError` | `FailureClass.UnmarshalText` on an unknown name; `MarshalText` on an out-of-range value | `Text` |

A required PCR beside an **empty** baseline is not a `PolicyError`: the empty
baseline is a verdict-level absence and the required-PCR check is evaluated
against the quote's selection alone.

## Tests

`pkg/attestation/peer/*_test.go` — no simulator, no network beyond an
in-memory `net.Pipe` TLS pair, no host modification:

- Real `TPMS_ATTEST` structures built with `go-tpm` `tpm2.Marshal`, signed
  with real RSA (PKCS #1 v1.5 and PSS) and ECDSA (P-256 ASN.1 and raw, P-384
  with a SHA-384 bank) keys; a two-tier test CA issuing Restricted and
  unrestricted attestation certificates.
- Every check has a pass test and a fail test; every absence/cryptographic
  classification in the table above has a test that asserts the class.
- Channel binding: both ends of a TLS 1.3 and a TLS 1.2 loopback derive the
  same 32 bytes; two connections derive different values; nil and
  incomplete-handshake states are refused.
- The Restricted OID is pinned to `pkg/ca`'s `OIDTCGVerifiedTPMRestricted` /
  `TCGVerifiedTPMRestrictedPolicy` so issuer and verifier cannot drift.
- **Mutation-checked** (each mutant applied by hand and the suite run): drop
  the Restricted requirement; drop chain verification; accept the bare nonce
  under a binding policy; drop the binding from the expected qualifying data;
  drop the PCR digest comparison; drop the baseline value comparison; drop
  RSA signature verification; drop the freshness bound; classify baseline
  divergence as absence; drop required-PCR coverage. Every mutant is killed
  by at least one named test.

Coverage: 98% of statements. The uncovered lines are the TLS exporter
refusal (Go's TLS stack always negotiates extended master secret, so it
cannot be provoked in-process) and two defensive branches that the preceding
checks make unreachable.

Run with the repo's unit tag set:

```
go test -race -tags="codec_cbor codec_json codec_msgpack tpm_simulator" ./pkg/attestation/peer/
```
