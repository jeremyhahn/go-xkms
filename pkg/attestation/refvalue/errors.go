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

	// ErrComponentDigest is returned when a component measurement does not
	// carry exactly one digest of the requested hash.
	ErrComponentDigest = errors.New("refvalue: component measurement needs exactly one digest of the requested hash")

	// ErrComponentOrdinal is returned when a component's class index is too
	// large to name an event.
	ErrComponentOrdinal = errors.New("refvalue: component class index is out of range")

	// ErrSignerKey reports a nil signer, or a signer whose key has no COSE
	// algorithm Sign produces: ECDSA P-256, P-384 or P-521, RSA of at least
	// 2048 bits, or Ed25519.
	ErrSignerKey = errors.New("refvalue: signer key must be ECDSA P-256/P-384/P-521, RSA of at least 2048 bits, or Ed25519")

	// ErrMeta reports corim-meta that is not a valid corim-meta-map: an
	// empty signer name, or a signature validity that ends before it starts.
	ErrMeta = errors.New("refvalue: corim-meta is not valid")

	// ErrSign reports a signer that failed to produce the COSE_Sign1
	// signature.
	ErrSign = errors.New("refvalue: signing the CoRIM failed")
)
