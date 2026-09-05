// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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

// Package peer answers one question about the other end of a connection:
// is it a currently attested system, not merely the holder of a certificate
// a trusted CA issued?
//
// A valid mTLS certificate proves identity. It does not prove state, and a
// compromised peer still holds its key. This package verifies a TPM 2.0
// quote the peer produced against a policy the verifier already holds:
//
//   - the attestation key certificate chains to the configured anchors and
//     carries tcg-cap-verifiedTPMRestricted, the check TCG "TPM 2.0 Keys for
//     Device Identity and Attestation" v1 r12 §8.2 makes a MUST before a
//     relying party trusts a quote;
//   - the signature over the marshaled TPMS_ATTEST verifies under that key;
//   - the quote's qualifying data echoes the verifier's nonce, bound to the
//     TLS channel when the policy demands it, so a genuine quote cannot be
//     replayed onto a different connection;
//   - the PCR values the peer reported hash to the digest the TPM signed;
//   - every PCR the policy requires (PCR 10 for measured userspace, say) was
//     quoted and has a baseline value;
//   - the proven values equal the policy's baseline;
//   - the evidence is no older than the policy allows.
//
// The result is a Verdict, not a bare boolean. Every check is reported
// individually, and a negative verdict carries a FailureClass that separates
// evidence that was present and wrong (FailureCryptographic) from a check
// that could not run at all (FailureAbsence). Consumers that take automated
// action on a verdict need that distinction: a bad signature is grounds for
// quarantine, a missing certificate is grounds for denial only.
//
// The package fails closed throughout. A check that cannot run is an absence
// failure, never a pass, and Verify returns an error only when the caller's
// policy is unusable or the context is done. Everything about the evidence
// itself is answered in the Verdict, so a transport gate can deny on either.
//
// This is the verification half. Producing the quote is TPM2.Quote in
// pkg/tpm2, which passes the qualifying data through to the TPM verbatim;
// the quoting side computes it with QualifyingData so both ends agree.
package peer
