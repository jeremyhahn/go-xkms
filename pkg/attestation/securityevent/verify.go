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

package securityevent

import (
	"crypto/subtle"
	"errors"
	"fmt"
)

var (
	// ErrEvidence reports signed evidence that did not verify, or a
	// missing evidence verifier.
	ErrEvidence = errors.New("securityevent: evidence did not verify")

	// ErrNonceMismatch reports evidence whose eat_nonce is not the
	// Verifier's challenge, or a missing challenge.
	ErrNonceMismatch = errors.New("securityevent: eat_nonce does not match the challenge")
)

// EvidenceVerifier authenticates the device-signed EAT evidence that
// travels with a security-event record (types.SecurityEventEvidence). It
// checks the evidence's signature against the device's attestation key
// and, only when that holds, returns the evidence's eat_nonce and the
// record's Detached Submodule Digest (RFC 9711 §4.2.18.2) from its
// signed claims. The evidence format (EAT in COSE_Sign1, a DICE or TPM
// quote) is the backend's; the verifier is the Verifier's appraisal of it.
type EvidenceVerifier func(evidence []byte) (eatNonce, dsd []byte, err error)

// Verify authenticates a security-event record as owner ruling 7dbbb72
// item 181 (b) binds it: verifyEvidence checks the device's signature on
// evidence, the evidence's eat_nonce must equal nonce (the Verifier's
// challenge, so the record is fresh), and its Detached Submodule Digest
// must cover claimsSet. It returns the decoded record only when all three
// hold.
func Verify(claimsSet, evidence, nonce []byte, verifyEvidence EvidenceVerifier) (Record, error) {
	if verifyEvidence == nil {
		return Record{}, fmt.Errorf("%w: no evidence verifier", ErrEvidence)
	}
	if len(nonce) == 0 {
		return Record{}, fmt.Errorf("%w: no challenge", ErrNonceMismatch)
	}
	eatNonce, dsd, err := verifyEvidence(evidence)
	if err != nil {
		return Record{}, fmt.Errorf("%w: %w", ErrEvidence, err)
	}
	if len(eatNonce) != len(nonce) || subtle.ConstantTimeCompare(eatNonce, nonce) != 1 {
		return Record{}, ErrNonceMismatch
	}
	return VerifyDetached(claimsSet, dsd)
}
