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

package software

import "errors"

var (
	// ErrStorageClosed indicates the backend storage is closed
	ErrStorageClosed = errors.New("storage is closed")

	// ErrCurveMismatch indicates that the curves of the private and public keys do not match
	ErrCurveMismatch = errors.New("curve mismatch between private and public keys")

	// ErrUnsupportedCurve indicates that the specified curve is not supported
	ErrUnsupportedCurve = errors.New("unsupported elliptic curve")

	// ErrInvalidPublicKey indicates the provided public key is malformed or invalid
	ErrInvalidPublicKey = errors.New("invalid public key")

	// ErrUnsupportedKeyType indicates that the key type is not supported for key agreement
	ErrUnsupportedKeyType = errors.New("key type not supported for key agreement")

	// ErrInvalidKDFParams indicates that the KDF parameters are invalid
	ErrInvalidKDFParams = errors.New("invalid KDF parameters")

	// ErrDerivationModeNotSupported indicates that the key derivation mode is not supported
	// by this backend. Software backend only supports EXPORT mode.
	ErrDerivationModeNotSupported = errors.New("derivation mode not supported")
)

// ErrContradictoryAlgorithmFamilies indicates that a types.KeyAttributes
// declares more than one algorithm family -- for example an asymmetric
// KeyAlgorithm alongside a SymmetricAlgorithm. The backend routes on the
// family and addresses the key by a different resolution of it, so such
// attributes name one key and operate on another. Errors carrying it also
// satisfy errors.Is for backend.ErrInvalidAttributes.
var ErrContradictoryAlgorithmFamilies = errors.New("software: attributes declare more than one algorithm family")
