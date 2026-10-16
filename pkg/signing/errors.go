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

package signing

import "errors"

var (
	// ErrSignerRequired indicates a nil signer was provided
	ErrSignerRequired = errors.New("signing: signer is required")

	// ErrInvalidSignerOpts indicates invalid signing options
	ErrInvalidSignerOpts = errors.New("signing: invalid signer options")

	// ErrUnsupportedAlgorithm indicates the signing algorithm is not supported
	ErrUnsupportedAlgorithm = errors.New("signing: unsupported signing algorithm")

	// ErrInvalidHashFunction indicates an invalid or unavailable hash function
	ErrInvalidHashFunction = errors.New("signing: invalid or unavailable hash function")

	// ErrSigningFailed indicates the signing operation failed
	ErrSigningFailed = errors.New("signing: operation failed")

	// ErrPublicKeyRequired indicates a nil public key was given to Verify
	ErrPublicKeyRequired = errors.New("signing: public key is required")

	// ErrSignatureRequired indicates an empty signature was given to Verify
	ErrSignatureRequired = errors.New("signing: signature is required")

	// ErrUnsupportedKeyType indicates Verify was given a key that is not RSA
	ErrUnsupportedKeyType = errors.New("signing: unsupported key type, RSA required")

	// ErrVerificationFailed indicates the signature does not verify
	ErrVerificationFailed = errors.New("signing: signature verification failed")
)
