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

import "errors"

var (
	// ErrNilEvidence indicates Appraise was given no evidence.
	ErrNilEvidence = errors.New("securityevent: nil evidence")

	// ErrNilOptions indicates Appraise was given no options.
	ErrNilOptions = errors.New("securityevent: nil options")

	// ErrNonceRequired indicates the caller supplied no Verifier nonce. The
	// nonce is the only freshness the evidence carries (RFC 9334 §10).
	ErrNonceRequired = errors.New("securityevent: a verifier nonce is required")

	// ErrTrustedRootsRequired indicates the caller configured no trusted
	// roots. Without them the signer's chain is not anchored, so the evidence
	// cannot be attributed to a device.
	ErrTrustedRootsRequired = errors.New("securityevent: trusted roots are required")

	// ErrMalformedChain indicates the signer's certificate chain is empty or
	// a certificate in it does not parse.
	ErrMalformedChain = errors.New("securityevent: malformed signer certificate chain")

	// ErrUntrustedSigner indicates the signer's chain failed DICE verification,
	// so nothing it signed can be attributed to the device.
	ErrUntrustedSigner = errors.New("securityevent: signer chain failed DICE verification")

	// ErrMalformedEvidence indicates the evidence is not a COSE_Sign1 whose
	// payload is an EAT Claims-Set.
	ErrMalformedEvidence = errors.New("securityevent: malformed evidence")

	// ErrSignature indicates the evidence's signature does not verify under
	// the DICE leaf's key.
	ErrSignature = errors.New("securityevent: evidence signature does not verify")

	// ErrNonceMismatch indicates the evidence's eat_nonce is not the nonce
	// this Verifier issued, so the evidence may be a replay.
	ErrNonceMismatch = errors.New("securityevent: eat_nonce mismatch")

	// ErrNoDetachedDigest indicates the evidence carries no
	// Detached-Submodule-Digest for the security-event record.
	ErrNoDetachedDigest = errors.New("securityevent: no detached submodule digest for the record")

	// ErrUnsupportedHashAlgorithm indicates the detached digest names a hash
	// algorithm this Verifier does not compute.
	ErrUnsupportedHashAlgorithm = errors.New("securityevent: unsupported detached digest hash algorithm")

	// ErrRecordDigestMismatch indicates the record's digest is not the one the
	// device signed: the record was changed, truncated or substituted.
	ErrRecordDigestMismatch = errors.New("securityevent: record digest mismatch")

	// ErrMalformedRecord indicates the record is not a well-formed CBOR
	// Claims-Set.
	ErrMalformedRecord = errors.New("securityevent: malformed record")
)
