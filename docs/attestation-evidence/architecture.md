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
| Verifier (appraisal) | go-quicbaas | compares proven state with reference values and endorsements, produces attestation results |
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
job, in go-quicbaas.

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
