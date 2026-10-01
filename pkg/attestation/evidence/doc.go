// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

// Package evidence holds the attestation evidence primitives of the stack:
// the checks that establish what a piece of TPM evidence proves, with no
// opinion about whether that is good enough.
//
// In the RATS architecture (RFC 9334) these are evidence-level primitives.
// go-xkms owns them. Appraisal -- comparing proven state with reference
// values and producing an attestation result -- is the Verifier role, which
// belongs to go-quicbaas. Collecting evidence (the Attester) and acting on
// a result (the Relying Party) belong to go-trusted-platform.
//
// The package covers:
//
//   - TPM2_Quote: parsing a TPMS_ATTEST, verifying the attestation key's
//     signature, the qualifying data and the PCR digest (ParseQuote,
//     VerifyQuote).
//   - Attestation key certificates: chaining to anchors and requiring
//     tcg-cap-verifiedTPMRestricted (VerifyAKCertificate).
//   - Endorsement key certificates: chaining to TPM-manufacturer anchors and
//     requiring tcg-kp-EKCertificate (VerifyEKCertificate).
//   - TCG PC Client crypto-agile event logs: parsing, replay and comparison
//     with quoted PCR values (ParseEventLog, VerifyEventLog).
//
// Two neighbouring primitives live where their types do: TPM2_Certify
// verification is pkg/tpm2 VerifyCertify, VerifyCertifyByCertificate and
// VerifyCertifyRaw; IAK and IDevID certificate checks are
// pkg/attestation/peer VerifyIAK and VerifyIDevID. Signed reference values
// (CoRIM) are pkg/attestation/refvalue. The SDK package sdk/go/evidence
// re-exports all of them in one place.
//
// Every failure is an *Error carrying a Class: ClassForged when the evidence
// was present and is cryptographically wrong, ClassAbsent when a check could
// not run because something it needs is missing.
package evidence
