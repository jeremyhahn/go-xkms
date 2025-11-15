// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
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
)
