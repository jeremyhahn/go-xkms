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

package verification

import "errors"

var (
	// ErrInvalidPublicKeyRSA indicates the RSA public key is invalid or has wrong type.
	ErrInvalidPublicKeyRSA = errors.New("verification: invalid RSA public key")

	// ErrInvalidPublicKeyECDSA indicates the ECDSA public key is invalid or has wrong type.
	ErrInvalidPublicKeyECDSA = errors.New("verification: invalid ECDSA public key")

	// ErrInvalidPublicKeyEd25519 indicates the Ed25519 public key is invalid or has wrong type.
	ErrInvalidPublicKeyEd25519 = errors.New("verification: invalid Ed25519 public key")

	// ErrSignatureVerification indicates the signature verification failed.
	ErrSignatureVerification = errors.New("verification: signature verification failed")

	// ErrInvalidSignatureAlgorithm indicates an unsupported signature algorithm.
	ErrInvalidSignatureAlgorithm = errors.New("verification: invalid signature algorithm")

	// ErrFileIntegrityCheckFailed indicates the file integrity check failed.
	ErrFileIntegrityCheckFailed = errors.New("verification: file integrity check failed")

	// ErrInvalidBlobName indicates the blob name is invalid or missing.
	ErrInvalidBlobName = errors.New("verification: invalid blob name")

	// ErrChecksumNotFound indicates the checksum was not found in the store.
	ErrChecksumNotFound = errors.New("verification: checksum not found")
)
