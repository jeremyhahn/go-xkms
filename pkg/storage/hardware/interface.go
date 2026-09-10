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

// Package hardware provides hardware-backed certificate storage implementations
// for PKCS#11 HSMs and TPM2 devices.
package hardware

import (
	"crypto/x509"
)

// HardwareCertStorage defines the interface for hardware-backed certificate storage.
// This interface is implemented by PKCS#11 and TPM2 certificate storage backends.
//
// Implementations MUST be thread-safe.
type HardwareCertStorage interface {
	// SaveCert stores a certificate by ID.
	// If a certificate with the same ID exists, it will be overwritten.
	SaveCert(id string, cert *x509.Certificate) error

	// GetCert retrieves a certificate by ID.
	// Returns ErrNotFound if the certificate does not exist.
	GetCert(id string) (*x509.Certificate, error)

	// DeleteCert removes the certificate stored under id and leaves any
	// chain stored under the same id in place. Returns ErrNotFound if the
	// certificate does not exist.
	//
	// The certificate and its chain are two records of a pair that share an
	// id; each is released by its own method so a caller can address one
	// record without taking its sibling. Hardware that keeps one NV index
	// per id (TPM2 holds whichever of SaveCert and SaveCertChain wrote last)
	// records the kind in the record itself, and every method addresses
	// the record only when it is of its kind: DeleteCert, GetCert and
	// CertExists on an index that holds a chain answer ErrNotFound, absence
	// and false, and leave it, exactly as they would a stored sibling.
	DeleteCert(id string) error

	// DeleteCertChain removes the certificate chain stored under id and
	// leaves the certificate stored under the same id in place. Returns
	// ErrNotFound if no chain is stored under id.
	DeleteCertChain(id string) error

	// SaveCertChain stores a certificate chain by ID.
	// If a chain with the same ID exists, it will be overwritten.
	SaveCertChain(id string, chain []*x509.Certificate) error

	// GetCertChain retrieves a certificate chain by ID.
	// Returns ErrNotFound if the chain does not exist.
	GetCertChain(id string) ([]*x509.Certificate, error)

	// ListCerts returns all certificate IDs stored.
	ListCerts() ([]string, error)

	// CertExists checks if a certificate exists by ID.
	CertExists(id string) (bool, error)

	// Close releases any resources held by the storage backend.
	Close() error

	// GetCapacity returns the total and available certificate storage capacity.
	// For PKCS#11, this queries token info. For TPM2, this queries NV RAM.
	// Returns (total slots, available slots, error).
	// Returns ErrNotSupported if the hardware doesn't report capacity.
	GetCapacity() (total int, available int, err error)

	// SupportsChains returns true if the hardware supports storing certificate chains.
	// PKCS#11 typically stores individual certificates with relationships.
	// TPM2 stores chains as serialized blobs in NV RAM.
	SupportsChains() bool

	// IsHardwareBacked returns true to distinguish from external storage.
	// This allows runtime type checking without reflection.
	IsHardwareBacked() bool

	// Compact performs storage optimization if supported by hardware.
	// For PKCS#11, this is a no-op. For TPM2, this may defragment NV RAM.
	// Returns ErrNotSupported if compaction is not available.
	Compact() error
}

// CertStorageMode defines where certificates are stored
type CertStorageMode string

const (
	// CertStorageModeExternal stores all certificates in external storage (default)
	CertStorageModeExternal CertStorageMode = "external"

	// CertStorageModeHardware stores all certificates in hardware
	CertStorageModeHardware CertStorageMode = "hardware"

	// CertStorageModeHybrid stores new certificates in hardware, reads from both
	CertStorageModeHybrid CertStorageMode = "hybrid"
)
