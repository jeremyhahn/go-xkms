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

package keybackend

import "errors"

// Key backend errors.
var (
	// ErrKeyNotFound indicates the requested key does not exist.
	ErrKeyNotFound = errors.New("keybackend: key not found")

	// ErrUnsupportedAlgorithm indicates the algorithm is not supported by this backend.
	ErrUnsupportedAlgorithm = errors.New("keybackend: unsupported algorithm")

	// ErrExportNotSupported indicates private key export is not supported.
	ErrExportNotSupported = errors.New("keybackend: export not supported")

	// ErrImportNotSupported indicates private key import is not supported.
	ErrImportNotSupported = errors.New("keybackend: import not supported")

	// ErrInvalidKeyHandle indicates the key handle is invalid or corrupt.
	ErrInvalidKeyHandle = errors.New("keybackend: invalid key handle")

	// ErrKeyGenerationFailed indicates key generation failed.
	ErrKeyGenerationFailed = errors.New("keybackend: key generation failed")

	// ErrSigningFailed indicates the signing operation failed.
	ErrSigningFailed = errors.New("keybackend: signing failed")

	// ErrAttestationNotSupported indicates attestation is not supported.
	ErrAttestationNotSupported = errors.New("keybackend: attestation not supported")

	// ErrBackendClosed indicates the backend has been closed.
	ErrBackendClosed = errors.New("keybackend: backend closed")

	// ErrInvalidCredentialID indicates the credential ID is invalid.
	ErrInvalidCredentialID = errors.New("keybackend: invalid credential ID")

	// ErrInvalidPKCS8Key indicates the PKCS#8 key data is invalid.
	ErrInvalidPKCS8Key = errors.New("keybackend: invalid PKCS#8 key")
)
