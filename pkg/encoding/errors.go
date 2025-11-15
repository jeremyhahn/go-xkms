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

package encoding

import "errors"

var (
	// ErrInvalidPrivateKey is returned when a private key is nil or invalid
	ErrInvalidPrivateKey = errors.New("encoding: invalid private key")

	// ErrInvalidPublicKey is returned when a public key is nil or invalid
	ErrInvalidPublicKey = errors.New("encoding: invalid public key")

	// ErrInvalidCertificate is returned when a certificate is nil or invalid
	ErrInvalidCertificate = errors.New("encoding: invalid certificate")

	// ErrInvalidData is returned when data is nil, empty, or malformed
	ErrInvalidData = errors.New("encoding: invalid data")

	// ErrInvalidPassword is returned when a password is incorrect
	ErrInvalidPassword = errors.New("encoding: invalid password")

	// ErrPasswordRequired is returned when a password is required but not provided
	ErrPasswordRequired = errors.New("encoding: password required")

	// ErrInvalidPEMEncoding is returned when PEM decoding fails
	ErrInvalidPEMEncoding = errors.New("encoding: invalid PEM encoding")
)
