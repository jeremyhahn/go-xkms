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

package truststore

import (
	"errors"
	"fmt"
)

var (
	// ErrCertificateExists indicates the certificate is already in the trust store.
	ErrCertificateExists = errors.New("truststore: certificate already exists")

	// ErrCertificateNotFound indicates the certificate was not found in the trust store.
	ErrCertificateNotFound = errors.New("truststore: certificate not found")

	// ErrInvalidCertificate indicates the certificate data is invalid or malformed.
	ErrInvalidCertificate = errors.New("truststore: invalid certificate")

	// ErrStoreClosed indicates the trust store has been closed.
	ErrStoreClosed = errors.New("truststore: store closed")

	// ErrInvalidFingerprint indicates the fingerprint format is invalid.
	ErrInvalidFingerprint = errors.New("truststore: invalid fingerprint")

	// ErrStorageWrite indicates a failure writing to the storage backend.
	ErrStorageWrite = errors.New("truststore: storage write failed")

	// ErrStorageRead indicates a failure reading from the storage backend.
	ErrStorageRead = errors.New("truststore: storage read failed")

	// ErrInvalidPurpose indicates an invalid certificate purpose was specified.
	ErrInvalidPurpose = errors.New("truststore: invalid certificate purpose")

	// ErrUnsupportedDistro indicates the Linux distribution is not recognized
	// or supported for OS trust store management.
	ErrUnsupportedDistro = errors.New("truststore: unsupported Linux distribution")

	// ErrInvalidLabel indicates the certificate label contains invalid characters.
	// Labels must contain only alphanumeric characters, hyphens, and underscores.
	ErrInvalidLabel = errors.New("truststore: invalid certificate label")

	// ErrSystemStoreRefresh indicates the OS command to rebuild the system
	// certificate trust store failed.
	ErrSystemStoreRefresh = errors.New("truststore: system trust store refresh failed")

	// ErrInstallFailed indicates a failure installing a certificate into
	// the OS trust store.
	ErrInstallFailed = errors.New("truststore: certificate installation failed")

	// ErrRemoveFailed indicates a failure removing a certificate from
	// the OS trust store.
	ErrRemoveFailed = errors.New("truststore: certificate removal failed")

	// ErrPermissionDenied indicates insufficient privileges for the requested
	// OS trust store operation. Root or sudo access is typically required.
	ErrPermissionDenied = errors.New("truststore: permission denied")

	// ErrNilKVStore is returned when a nil KVStore is provided to NewDAOStore.
	ErrNilKVStore = errors.New("truststore: nil kvstore")
)

// ErrDAOCreation is returned when the DAO layer fails to initialize.
type ErrDAOCreation struct {
	Cause error
}

// Error implements the error interface.
func (e ErrDAOCreation) Error() string {
	return fmt.Sprintf("truststore: failed to create DAO: %v", e.Cause)
}

// Unwrap returns the underlying cause.
func (e ErrDAOCreation) Unwrap() error {
	return e.Cause
}
