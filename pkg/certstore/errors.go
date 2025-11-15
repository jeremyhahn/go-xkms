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

package certstore

import "errors"

// Certificate operation errors
var (
	// ErrCertNotFound is returned when a certificate is not found.
	ErrCertNotFound = errors.New("certstore: certificate not found")

	// ErrCertAlreadyExists is returned when attempting to store a certificate that already exists.
	ErrCertAlreadyExists = errors.New("certstore: certificate already exists")

	// ErrCertInvalid is returned when a certificate is invalid or malformed.
	ErrCertInvalid = errors.New("certstore: invalid certificate")

	// ErrCertExpired is returned when a certificate has expired.
	ErrCertExpired = errors.New("certstore: certificate expired")

	// ErrCertNotYetValid is returned when a certificate is not yet valid.
	ErrCertNotYetValid = errors.New("certstore: certificate not yet valid")

	// ErrCertRevoked is returned when a certificate has been revoked.
	ErrCertRevoked = errors.New("certstore: certificate revoked")
)

// Chain operation errors
var (
	// ErrChainNotFound is returned when a certificate chain is not found.
	ErrChainNotFound = errors.New("certstore: certificate chain not found")

	// ErrChainInvalid is returned when a certificate chain is invalid.
	ErrChainInvalid = errors.New("certstore: invalid certificate chain")

	// ErrChainEmpty is returned when a certificate chain is empty.
	ErrChainEmpty = errors.New("certstore: empty certificate chain")

	// ErrChainVerificationFailed is returned when chain verification fails.
	ErrChainVerificationFailed = errors.New("certstore: chain verification failed")
)

// CRL operation errors
var (
	// ErrCRLNotFound is returned when a CRL is not found.
	ErrCRLNotFound = errors.New("certstore: CRL not found")

	// ErrCRLInvalid is returned when a CRL is invalid or malformed.
	ErrCRLInvalid = errors.New("certstore: invalid CRL")

	// ErrCRLExpired is returned when a CRL has expired.
	ErrCRLExpired = errors.New("certstore: CRL expired")
)

// Configuration errors
var (
	// ErrStorageRequired is returned when certificate storage is required but not provided.
	ErrStorageRequired = errors.New("certstore: certificate storage is required")

	// ErrStorageClosed is returned when the storage has been closed.
	ErrStorageClosed = errors.New("certstore: storage is closed")

	// ErrInvalidConfig is returned when the configuration is invalid.
	ErrInvalidConfig = errors.New("certstore: invalid configuration")
)

// Validation errors
var (
	// ErrVerificationFailed is returned when certificate verification fails.
	ErrVerificationFailed = errors.New("certstore: verification failed")

	// ErrNoRoots is returned when no root certificates are provided for verification.
	ErrNoRoots = errors.New("certstore: no root certificates provided")

	// ErrInvalidCN is returned when a Common Name is invalid or empty.
	ErrInvalidCN = errors.New("certstore: invalid common name")

	// ErrInvalidIssuer is returned when an issuer identifier is invalid or empty.
	ErrInvalidIssuer = errors.New("certstore: invalid issuer")
)
