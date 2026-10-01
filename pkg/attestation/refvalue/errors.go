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

package refvalue

import "errors"

// Sentinel errors. Every error this package returns either is one of these or
// wraps one (through pkg/errs), so callers match with errors.Is.
var (
	// ErrTrustSource reports VerifyOptions that name no trust source, or
	// both: exactly one of PublicKey and Roots must be set.
	ErrTrustSource = errors.New("refvalue: exactly one of PublicKey and Roots must be set")

	// ErrMalformed reports input that is not a well-formed signed CoRIM: not
	// a COSE_Sign1 message, a missing or wrong content type, missing
	// corim-meta, or an unsigned CoRIM that fails validation.
	ErrMalformed = errors.New("refvalue: not a well-formed signed CoRIM")

	// ErrSignerChain reports a COSE x5chain header that is absent, does not
	// parse, or does not chain to the configured roots.
	ErrSignerChain = errors.New("refvalue: signer certificate chain is not trusted")

	// ErrSignature reports a COSE_Sign1 signature that does not verify under
	// the trusted signer key.
	ErrSignature = errors.New("refvalue: signed CoRIM signature does not verify")

	// ErrNotYetValid reports a CoRIM whose signature or RIM validity period
	// starts after the verification time.
	ErrNotYetValid = errors.New("refvalue: signed CoRIM is not yet valid")

	// ErrExpired reports a CoRIM whose signature or RIM validity period ended
	// before the verification time.
	ErrExpired = errors.New("refvalue: signed CoRIM has expired")

	// ErrPCRIndex reports a uint measurement key that cannot name a PCR.
	ErrPCRIndex = errors.New("refvalue: measurement key is not a PCR index (0-23)")

	// ErrDigestLength reports a digest whose length does not match its
	// declared hash algorithm.
	ErrDigestLength = errors.New("refvalue: digest length does not match its algorithm")

	// ErrUnsupportedHash reports a hash PCRDigests cannot select.
	ErrUnsupportedHash = errors.New("refvalue: hash is not one of SHA-256, SHA-384, SHA-512")
)
