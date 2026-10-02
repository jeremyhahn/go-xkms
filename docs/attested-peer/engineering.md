# Attested Peer — Engineering Contract

> **Status: NORMATIVE** · Feature: `attested-peer` · Repo: `go-xkms` · Last verified: 2026-10-02

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
| `VerifyIDevID(ctx, *x509.Certificate, DevIDPolicy) error` | Is this certificate a usable TCG device identity credential? Validity, chain, key usage, class assertion, device names. |
| `VerifyIAK(ctx, *x509.Certificate, DevIDPolicy) error` | The same for the attestation credential: Restricted asserted, Fixed refused. |
| `IsIDevID(*x509.Certificate) bool`, `IsIAK(*x509.Certificate) bool` | Shape only — class assertion and the two §8.1 otherNames. No chain, no clock. For routing, never for admission. |
| `DevIDPolicy` | `Anchors`, `Intermediates`, `CurrentTime` (zero means `time.Now().UTC()`). |
| `EvidenceFromTLS(*tls.ConnectionState, Evidence) (TLSEvidence, error)` | Copies the reported evidence and pairs it with the connection's channel binding. Fails closed with `*ChannelBindingError`. |
| `TLSEvidence` | `Evidence`, `ChannelBinding`, and `BindPolicy(Policy) Policy`, which returns a copy of the policy carrying this connection's binding. |
| `QualifyingDataFromTLS(*tls.ConnectionState, nonce []byte) ([]byte, error)` | The quoting side: binding plus `QualifyingData` in one call, so binding cannot be half-performed. |
| `VerifySameDevice(identity, attestation *x509.Certificate) error` | Do an IDevID/LDevID and an IAK/LAK name the same TPM? Compares the two TCG DevID §8.1 otherNames; builds no chain. `*DevIDError` when either names no TPM, `*DeviceMismatchError` when they differ. |
| `*PolicyError`, `*ContextError`, `*ChannelBindingError`, `*FailureClassError`, `*DevIDError`, `*DevIDPolicyError`, `*DeviceMismatchError` | The typed errors. |

## Exported surface — `pkg/attestation/peergate`

| Identifier | Role |
|---|---|
| `Verifier`, `NewVerifier(VerifierConfig, ...Option) (*Verifier, error)` | go-qrdb's `PeerAttestationVerifier` (compile-time checked). `VerifyPeer(ctx, qrdbsdk.AttestedPeer) (*qrdbsdk.PeerAttestation, error)`. |
| `VerifierConfig` | `Store` (required), `Policy peer.Policy` (`Anchors` and a non-empty `Baseline` required, `ChannelBinding` must be empty, must evaluate), `DeviceIdentity *peer.DevIDPolicy` (optional; `Anchors` required when set). |
| `Collector`, `NewCollector(CollectorConfig, ...Option) (*Collector, error)` | `Challenge(ctx, *tls.ConnectionState) (Challenge, error)`, `Submit(ctx, *tls.ConnectionState, peer.Evidence) error`. |
| `CollectorConfig` | `Store` (required), `ChallengeTTL` (zero: `DefaultChallengeTTL`, one minute), `MaxPendingChallenges` (zero: `DefaultMaxPeers`). |
| `Challenge` | `Nonce` (`NonceLength` = 32 bytes), `ExpiresAt`. |
| `EvidenceStore` (interface) | `Put(ctx, Record)`, `Get(ctx, thumbprint) (Record, bool, error)`, `Delete(ctx, thumbprint)`. |
| `Record` | `Thumbprint`, `Evidence peer.Evidence`, `ChannelBinding`. |
| `MemoryStore`, `NewMemoryStore(MemoryStoreConfig, ...Option) (*MemoryStore, error)`, `Len()` | The in-process store. |
| `MemoryStoreConfig` | `MaxPeers` (zero: `DefaultMaxPeers`, 100 000), `Retention` (zero: `DefaultRetention`, 24 h). |
| `Option`, `WithClock(func() time.Time)` | Pins the clock of a collector, verifier or memory store. |
| `Quoter` (interface), `QuoteEvidence(state, nonce, Quoter, pcrs, akCertificatePEM) (peer.Evidence, error)` | The quoting side. `*tpm2.TPM2` is a `Quoter`. |
| `*ConfigError`, `*PeerCertificateError`, `*ChallengeError`, `*AttestedPeerError`, `*CapacityError`, `*StoreError`, `*QuoteError`, `*NonceError` | The typed errors. |

SDK aliases in `sdk/go/attestation_peergate.go`: `PeerGateVerifier`,
`PeerGateVerifierConfig`, `NewPeerGateVerifier`, `PeerEvidenceCollector`,
`PeerEvidenceCollectorConfig`, `NewPeerEvidenceCollector`, `PeerChallenge`,
`PeerEvidenceStore`, `PeerEvidenceRecord`, `PeerMemoryEvidenceStore`,
`PeerMemoryEvidenceStoreConfig`, `NewPeerMemoryEvidenceStore`,
`PeerGateOption`, `WithPeerGateClock`, `PeerQuoter`, `PeerQuoteEvidence`,
`PeerVerifySameDevice`, `PeerDeviceMismatchError`, `PeerGateConfigError`,
`PeerCertificateError`, `PeerChallengeError`, `PeerGateAttestedPeerError`,
`PeerGateCapacityError`, `PeerEvidenceStoreError`, `PeerQuoteError`,
`PeerNonceError`, and the constants `PeerChallengeNonceLength`,
`DefaultPeerChallengeTTL`, `DefaultPeerGateMaxPeers`,
`DefaultPeerEvidenceRetention`.

SDK aliases in `sdk/go/attestation_peer.go` carry a `Peer` prefix
(`PeerAttestationVerifier`, `PeerEvidence`, `PeerPolicy`, `PeerVerdict`,
`PeerChecks`, `PeerFailureClass` and constants, `NewPeerAttestationVerifier`,
`WithPeerVerifierClock`, `PeerQualifyingData`, `PeerChannelBinding`,
`PeerChannelBindingExporterLabel`, `PeerChannelBindingLength`,
`PeerPolicyError`, `PeerContextError`, `PeerChannelBindingError`,
`PeerFailureClassError`, `PeerVerifyIDevID`, `PeerVerifyIAK`, `PeerIsIDevID`,
`PeerIsIAK`, `PeerDevIDPolicy`, `PeerDevIDError`, `PeerDevIDPolicyError`,
`PeerEvidenceFromTLS`, `PeerTLSEvidence`, `PeerQualifyingDataFromTLS`) because
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
9. **A credential is answered with an error, not a verdict.** Evidence can be
   partially absent, and absent-versus-wrong decides whether a peer may be
   quarantined; a certificate cannot be partial. `VerifyIDevID`/`VerifyIAK`
   return `*DevIDError` for the certificate, `*DevIDPolicyError` for the
   caller's configuration, `*ContextError` for a done context, and `nil` only
   when every check held.
10. **The two credential classes refuse each other.** TCG DevID §8.2 forbids
    combining `verifiedTPMFixed` and `verifiedTPMRestricted`, so each class
    requires its own assertion *and* rejects the other's. An IAK presented as
    an IDevID fails.
11. **The validator cannot drift from the issuer.** Every TCG OID
    `pkg/attestation/peer` recognises is pinned by test to the value `pkg/ca`
    stamps. They are declared separately so verification does not link the CA.
12. **Binding is all-or-nothing.** `EvidenceFromTLS` and
    `QualifyingDataFromTLS` return an error and no data when the connection
    cannot export keying material. Neither inspects the evidence, so a caller
    never receives an error about the peer from them.

### Gate verifier invariants (`pkg/attestation/peergate`)

13. **The peer is the verified certificate.** Collector and verifier key on
    `qrdbsdk.ComputeSPKIThumbprint` of `VerifiedChains[0][0]`, go-qrdb's own
    rule; a merely presented, unverified certificate is no peer.
    `VerifyPeer` refuses (`*AttestedPeerError`) an `AttestedPeer` whose
    thumbprint is not its certificate's.
14. **A nonce is answered once.** `Submit` removes the challenge before
    checking anything, so a failed submission consumes it too. The nonce is
    compared in constant time.
15. **Nothing unbound is stored or verified.** `Submit` stores only evidence
    `EvidenceFromTLS` bound to the submitting connection; `VerifyPeer` refuses,
    as an absence, a record whose binding is not `ChannelBindingLength` bytes.
16. **The collector stamps time.** `CollectedAt` is the receipt time; a peer's
    own claim is overwritten.
17. **The request path never collects,** and always re-verifies: each
    `VerifyPeer` runs `peer.Verify` over the stored record under the current
    policy and clock.
18. **The verdict names the record's thumbprint,** not the lookup key, so the
    gate can catch a store that returned another peer's record.
19. **Construction refuses a gate that could never pass** (no store, no
    anchors, no baseline, a fixed channel binding, a policy `peer.Verify`
    rejects, a device policy with no anchors) with `*ConfigError`.
20. **Bounded memory.** Outstanding challenges and stored records are capped;
    at the cap only expired challenges and evidence past `Retention` are
    evicted, and a new peer is otherwise refused with `*CapacityError`.
21. **Records never alias.** `MemoryStore` deep-copies on `Put` and `Get`.

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
| `*DevIDError` | `VerifyIDevID` / `VerifyIAK` rejected the certificate | `Credential`, `Reason`, `Cause` (unwraps to the `crypto/x509` chain error where there is one) |
| `*DevIDPolicyError` | `DevIDPolicy` with no `Anchors` | `Field`, `Reason` |

A required PCR beside an **empty** baseline is not a `PolicyError`: the empty
baseline is a verdict-level absence and the required-PCR check is evaluated
against the quote's selection alone.

## Fail-closed paths: device credentials

Every row is a `*DevIDError` carrying `Credential` ("IDevID" or "IAK") and a
`Reason`, except where noted. The order is the order they are checked, and the
first failure is returned.

| Condition | Error |
|---|---|
| Context done | `*ContextError` |
| `cert` nil | `*DevIDError` "no certificate" |
| `DevIDPolicy.Anchors` nil | `*DevIDPolicyError` on `Anchors` |
| `CurrentTime` before `NotBefore` / after `NotAfter` | "not valid until" / "expired at" — checked before the chain so expiry is named as itself |
| Does not chain to the anchors | "does not chain to a trusted anchor"; `Cause` unwraps to the `crypto/x509` error |
| No `digitalSignature` key usage | names §8.1 Table 22 |
| `IsCA`, or a certificate/CRL-signing key usage | a device credential is an end entity and signs neither |
| Class assertion absent (neither a certificate policy nor an extended key usage carries it) | names the missing assertion |
| The other class's assertion present | names it and §8.2's prohibition |
| No subjectAltName, or it does not decode | names the two §8.1 otherNames |
| No hardwareModuleName, or `hwType` ≠ 2.23.133.1.2, or empty `hwSerialNum` | the credential names no TPM 2.0 |
| No permanentIdentifier, empty `identifierValue`, missing assigner, or assigner ≠ 2.23.133.12.1 | §8.1 requires both fields |

`IsIDevID` / `IsIAK` run the class-assertion and device-name rows only and
return `false` for any of them, including a nil certificate.

## Fail-closed paths: the gate verifier

| Condition | Result of `VerifyPeer` |
|---|---|
| Context done | `*peer.ContextError` |
| `AttestedPeer.Certificate` nil, or `Thumbprint` is not the certificate's | `*AttestedPeerError` |
| Store `Get` fails | `*StoreError` (`Op` "get") |
| No record | verdict: not passed, absence, zero `CollectedAt` (the gate refuses it as `no-evidence`) |
| Record's channel binding missing or the wrong length | verdict: absence |
| `peer.Verify` refuses the evidence | verdict with the primitive's class and reason (see the table above) |
| `DeviceIdentity` set, connection certificate not a usable IDevID | verdict: absence |
| `DeviceIdentity` set, no attestation key certificate, or one that does not parse | verdict: "device binding not evaluated" added as an absence |
| `DeviceIdentity` set, the two credentials name different TPMs | verdict: cryptographic |

| `Collector` condition | Error |
|---|---|
| Context done | `*peer.ContextError` |
| No TLS state, or no verified client certificate | `*PeerCertificateError` |
| `MaxPendingChallenges` unexpired challenges for other peers | `*CapacityError` (`What` "challenges") |
| No outstanding challenge, expired, or a different nonce | `*ChallengeError`; the challenge is consumed |
| Connection cannot export keying material | `*peer.ChannelBindingError` |
| Store `Put` fails | `*StoreError` (`Op` "put"); with a `MemoryStore` at capacity it wraps `*CapacityError` |

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
- Device credentials: a canonical IDevID and a canonical IAK are accepted;
  each class refuses the other's certificate. Rejected: no TCG assertion at
  all, the other class's assertion, every wrong key usage (no
  `digitalSignature`, certificate signer, CRL signer, CA), expired and
  not-yet-valid, a foreign CA, a missing intermediate, a self-issued
  certificate, and each of the eight device-name defects (no SAN, no
  hardwareModuleName, no permanentIdentifier, non-TPM `hwType`, empty
  `hwSerialNum`, empty `identifierValue`, missing assigner, wrong assigner).
  The assertion is proven to be accepted in **both** TCG encodings — as a
  certificate policy and as an extended key usage alone.
- Every TCG OID the validator recognises is pinned to the `pkg/ca` constant
  that issues it, so the validator cannot drift into rejecting its own CA's
  credentials.
- `DevIDPolicy.CurrentTime` zero means now, proven against a CA and credential
  minted at the real clock — the zero instant would reject everything as not
  yet valid.
- Connection binding, end to end over a real TLS 1.3 `net.Pipe` pair: the
  quoting end computes qualifying data from its own `ConnectionState`, the
  verifying end builds evidence and policy from the other, and the verdict
  passes with all eight checks. A quote bound to a **different** connection
  and a quote carrying the **bare nonce** both fail `ChannelBinding` as
  cryptographic failures while the rest of the verdict is unaffected.
- `EvidenceFromTLS` returns no evidence at all on a nil state or an
  incomplete handshake, does not alias any caller buffer or map, and
  `BindPolicy` neither writes into the provisioned policy nor lets two
  connections produce the same bound policy.
- **Mutation-checked** (each mutant applied by hand and the suite run): drop
  the Restricted requirement; drop chain verification; accept the bare nonce
  under a binding policy; drop the binding from the expected qualifying data;
  drop the PCR digest comparison; drop the baseline value comparison; drop
  RSA signature verification; drop the freshness bound; classify baseline
  divergence as absence; drop required-PCR coverage. Every mutant is killed
  by at least one named test.

Coverage: 96.3% of statements across the package. The uncovered lines are the
TLS exporter refusal (Go's TLS stack always negotiates extended master secret,
so it cannot be provoked in-process), the ASN.1 decoding failures inside the
subjectAltName walk that `x509.ParseCertificate` rejects before this code sees
them, and defensive branches the preceding checks make unreachable.

`VerifySameDevice` has an acceptance test for a pair from one TPM, a
mismatch test for each of the four device-name fields, and a refusal test for
each missing credential or name, asserting `*DeviceMismatchError` versus
`*DevIDError`.

`pkg/attestation/peergate/*_test.go` (97% of statements) — real TLS 1.3
handshakes over `net.Pipe`, real `TPMS_ATTEST` structures signed by a software
attestation key, a test CA issuing IDevID and IAK certificates through `pkg/ca`'s
own subjectAltName encoder:

- An honest round (challenge, quote bound to the connection, submit) passes;
  the record is keyed by the connection certificate's thumbprint, carries the
  server side's exporter value and the collector's clock.
- Refused as **cryptographic**: a quote bound to another connection, a quote
  over the bare nonce, a forged signature under the genuine certificate, an
  attestation key from an untrusted CA, a PCR 10 value off the baseline,
  reported values that are not the quoted ones, a device mismatch.
- Refused as **absence**: no evidence, evidence past the policy's age bound, a
  withdrawn record, an unbound record from a foreign store, a connection
  certificate that is not an IDevID, an attestation key certificate naming no
  TPM.
- The latest evidence wins: a bad quote after a good one is refused.
- Collector: never-challenged, wrong-nonce (and the nonce is then dead),
  expired, answered-twice, unbindable connection, no verified peer, the
  challenge bound and its expiry, a store failure.
- `MemoryStore`: no aliasing in or out, capacity with eviction of only expired
  evidence, context and configuration errors.
- `QuoteEvidence`: the evidence it assembles passes the verifier; a PCR
  extended between quote and read is re-quoted, one that never settles is
  refused; no quoter, nonce, PCRs, bank or value; no binding means no quote.
- The verifier builds a go-qrdb `PeerAttestationGate`.

`test/integration/tpm2/peergate_qrdb_node_test.go` composes a go-qrdb
standalone node with `WithPeerAttestationGate` over this verifier, gating
`admin:status`, and drives a peer whose quotes come from a real TPM (swtpm)
through a collector mounted on a separate mTLS HTTP listener. The gated route
refuses the peer with no evidence, admits it after an honest round, and
refuses it after a forged quote, a quote bound to another TLS session, and
valid evidence older than the gate's maximum age; a replayed nonce is refused
at collection. Run it with `make integration-test-peergate` (it also runs in
`make integration-test-tpm2`).

Run with the repo's unit tag set:

```
go test -race -tags="codec_cbor codec_json codec_msgpack tpm_simulator" ./pkg/attestation/peer/ ./pkg/attestation/peergate/
```
