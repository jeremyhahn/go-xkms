# Attestation Evidence — Architecture

> **Status: NORMATIVE** · Feature: `attestation-evidence` · Repo: `go-xkms` · Last verified: 2026-10-01

## The problem

A relying party that receives TPM evidence has to answer a narrow question
before any policy question: *what does this evidence prove?* Is the quote
signed by the key it claims, over the PCR values reported with it, carrying
the verifier's nonce? Does the attestation key chain to an anchor that
vouches for it being TPM-resident? Does the endorsement key belong to a
genuine TPM? Does the firmware event log explain the quoted PCR values?

Those answers are cryptography and format parsing. They are the same for
every product that consumes TPM evidence, so they live once, here.

## Where this sits in RATS (RFC 9334)

| Role | Owner | What it does |
|---|---|---|
| Evidence primitives | go-xkms (this feature) | quote, AK/EK chain, event log, TPM2_Certify and signed reference-value verification |
| Verifier (appraisal) | go-xkms (attestation-verifier); go-quicbaas re-exports it | compares proven state with reference values and endorsements, produces attestation results |
| Attester | go-trusted-platform | selects PCRs per boot path and collects evidence |
| Relying party | go-trusted-platform | admits, evicts, issues credentials on an attestation result |

The test for what belongs here: a check that needs no knowledge of a fleet,
a boot path or a policy is a primitive. Comparing a proven value against a
*reference* is still primitive (`ComparePCRs`); deciding *which* reference
applies, and what to do with the answer, is appraisal and is not.

## Shape chosen

One pure-Go package, `pkg/attestation/evidence`, with no device access. It
imports the standard library and go-tpm's structure definitions only, so a
CGO-free verifier links it without a TPM.

- **Quotes.** `ParseQuote` checks the TPMS_ATTEST is TPM-generated, is a
  quote, selects exactly one accepted bank (SHA-256/384/512; never SHA-1) and
  carries a digest of a supported length. `VerifySignature`,
  `VerifyQualifyingData` and `VerifyPCRValues` then prove the signature,
  the nonce and the reported values. `VerifyQuote` runs all four.
- **Attestation key certificates.** `VerifyAKCertificate` chains to the
  caller's anchors and requires tcg-cap-verifiedTPMRestricted (TCG DevID v1
  r12 §8.2) unless explicitly waived.
- **Endorsement key certificates.** `VerifyEKCertificate` chains to
  TPM-manufacturer anchors and requires tcg-kp-EKCertificate. It tolerates
  the one manufacturer encoding quirk Go rejects (a critical SAN carrying only
  a directoryName) and nothing else.
- **Event logs.** `ParseEventLog` parses a TCG PC Client crypto-agile log
  from bytes: digest sizes come from the Spec ID header, never from guesses.
  `VerifyEventLog` replays one bank and requires every quoted register to
  equal its replayed value, or its reset value when the log never touches it.
- **TPM2_Certify** is verified by `pkg/tpm2` `VerifyCertify*`, and IAK /
  IDevID certificates by `pkg/attestation/peer` `VerifyIAK` /
  `VerifyIDevID`. They stay with their types and are re-exported with the
  rest from `sdk/go/evidence`.

Every failure is classified: **forged** (the evidence was present and is
wrong) or **absent** (a check could not run). A verifier needs the
distinction — a forgery is an incident, an absence is a configuration or
collection gap — and the peer verifier's verdict classes are derived from it.

## One implementation

The attested-peer verifier and the CA's IAK/IDevID issuance path both run
these primitives rather than private copies: `pkg/attestation/peer` maps
`*evidence.Error` classes onto its verdict, and `pkg/ca` verifies EK
certificates with `VerifyEKCertificate` against its configured anchors.

## Signed reference values (CoRIM)

Signed reference values are the RFC 9334 Reference Value Provider's output, and
go-xkms owns only their verification, as an evidence-level primitive.
`pkg/attestation/refvalue` accepts a CoRIM wrapped in COSE_Sign1 (RFC 9052). It
proves who signed it and returns its reference-value triples; it makes no
appraisal decision. Comparing evidence against those values is the Verifier's
job, in go-xkms's attestation-verifier.

Decoding, CoRIM validation and the COSE signature check are delegated to the
Veraison reference implementation (`veraison/corim`, `veraison/go-cose`) rather
than a hand-written CDDL decoder. This package adds the trust decision, the
validity windows and a library-neutral result type. Endorsed values,
attester-verification keys and device-identity keys are out of scope: a CoRIM
carrying them still verifies, and they are ignored.

The decoder sees unauthenticated CBOR before the signature is checked. Nothing
it returns is trusted until the signature verifies.

## Rejected alternatives

- **Fixing the display parser in `pkg/tpm2` in place.** `tpm2.ParseEventLog`
  reads a file and is shaped for display (hex digests, a heuristic event
  string, guessed sizes for unknown algorithms). Verification needs exact
  sizes from the Spec ID header and must not guess, so the verification
  parser is a separate, strict function over bytes.
- **Returning a single bool.** A verifier cannot tell a forgery from a gap.

## Trust boundaries

Nothing here trusts the attester. Every input is evidence; the only trusted
inputs are the anchors, keys and expected values the caller supplies.
Comparisons of secrets-derived values (digests, qualifying data) are
constant-time. Parsing is bounded: at most 1 MiB of data per event, 65536
events, 16 algorithms.

## Device security-event record

SPEC row `device-security-event-evidence` (planned, #1765). An HSM device's
tamper-response record (trusted-firmware#50, A6) is RFC 9334 Evidence about
its Attesting Environment (§8.1). go-xkms owns the format and its check.

**Encoding.** The record is one CBOR Claims-Set and is carried as an EAT
submodule (RFC 9711 §4.2.18). EAT registers no claim for it, so its claim key
is go-xkms's own until one is registered. The adapter reads entries one index
at a time with `HSM_RECORD_READ` (0x7C), and every reply repeats the header:

| Reply bytes | Claims-Set member | Meaning |
|---|---|---|
| `count:1` | entry count | entries held, `0..count-1` |
| `dropped:2 LE` | dropped | entries lost after the log filled, u16, saturating |
| `at:4 LE` | entry `at` | the engine's clock, u32. It is not a time, so it is never `iat` |
| `kind:1` | entry `kind` | signal, decision or action |
| `what:1` | entry `what` | what was signalled, decided or done |
| `result:1` | entry `result` | its outcome |

A CMW (RFC 9999 §3.1 record, §3.3 collection) could label the record next to
the DICE evidence. It protects nothing by itself (§8.1), so it does not
answer the binding question.

**Binding options, and what the Verifier may conclude.**

- **(a) Channel only.** The record arrives unsigned, as a UCCS. RFC 9781 §4
  accepts that only when the receiver authenticated the sender and the
  channel provides integrity. Out of the channel the record is unprotected,
  and once forwarded it counts as originating at the forwarder (§4). go-xkms
  receives it from the adapter, not from the device, so the Verifier may
  conclude only that the adapter reported it. It may not conclude that the
  device's Attesting Environment produced it, or that nothing was left out.
- **(b) Detached digest in signed evidence.** The device signs evidence that
  carries a Detached Submodule Digest of the record (RFC 9711 §4.2.18.2) and
  the Verifier's `eat_nonce` (RFC 9711 §4.1). The alias certificate is
  issued at boot, before the record is written, so it cannot carry the
  digest; the evidence must be signed after the record's last entry. The
  Verifier may then conclude that the device's key vouched for this exact
  record, and that the record is fresh (RFC 9334 §10). This needs a
  trusted-firmware change.
- **(c) Inline submodule in signed evidence.** The same, with the record
  inside the signed token as a Claims-Set submodule (RFC 9711 §4.2.18.1).

Which of these is required is open for the owner to rule on.

**Hook: none yet.** A backend registered with `RegisterExternalBackend`
(`pkg/xkms/registry_external.go:54`, SPEC backend-registry) has no call that
hands go-xkms device evidence. The backend contract's only attestation
capability, `types.AttestingKeyProvider.AttestKey`
(`pkg/types/types.go:1936`), attests one key. The device's DICE claims
arrive in `dice.Evidence` (`pkg/attestation/dice/verify.go:114`), which has no
submodule field: its `Claims.Other` (`:125`) only holds the claims go-xkms
does not model.

The planned row adds one optional capability interface to the backend
contract, in the `AttestingKeyProvider` pattern. It embeds `KeyProvider` and
adds one method, `AttestSecurityEvents(ctx, nonce)`, which returns the
record's Claims-Set, or `ErrNotSupported` when the backend keeps no record.
The nonce is the Verifier's `eat_nonce` under (b) and (c), and is unused
under (a). Which of these applies is still the owner's ruling.

**Recommendation (not a decision): (b).** A tamper record is worth having
only if a compromised host cannot hide or rewrite it. Under (a) the record
is the adapter's word (RFC 9781 §4). (b) binds it to the device's key and
the Verifier's nonce, and adds only a digest to the signed evidence. (c)
puts the whole log inside the signed token.
