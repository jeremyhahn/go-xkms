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

package xkms

import (
	"github.com/jeremyhahn/go-xkms/pkg/certstore"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	filestorage "github.com/jeremyhahn/go-xkms/pkg/storage/file"
)

// Storage interface and types re-exported from pkg/storage.
// These allow SDK consumers to configure storage backends directly
// through the SDK without importing internal packages.
type (
	// StorageBackend is the interface for key-value storage backends.
	// All implementations are thread-safe.
	StorageBackend = storage.Backend

	// StorageCertAdapter wraps a StorageBackend to provide certificate-specific
	// operations including marshaling/unmarshaling of x509.Certificate objects.
	StorageCertAdapter = storage.CertAdapter

	// CertificateStorageAdapter is the interface for certificate storage operations.
	// It provides Save/Get/Delete/List operations for X.509 certificates and chains.
	CertificateStorageAdapter = certstore.CertificateStorageAdapter

	// CertStore is the primary certificate store interface providing save/get/delete/list
	// operations for X.509 certificates, chains, and CRLs.
	CertStore = certstore.CertStore

	// CertStoreConfig configures the certificate store.
	CertStoreConfig = certstore.Config

	// CRLEntry holds information about a revoked certificate in a CRL.
	CRLEntry = certstore.CRLEntry

	// CertStoreInfo holds metadata about a certificate in the cert store.
	CertStoreInfo = certstore.CertificateInfo

	// ChainInfo holds metadata about a certificate chain.
	ChainInfo = certstore.ChainInfo

	// TCGAttributes holds TCG-specific certificate attributes.
	TCGAttributes = certstore.TCGAttributes
)

// Storage backend constructors re-exported from pkg/storage and subpackages.
var (
	// NewMemoryBackend creates a new in-memory storage backend.
	// Returns (StorageBackend, error).
	NewMemoryBackend = storage.NewMemoryBackend

	// NewStorageMemory creates a new in-memory storage backend without error return.
	// This is a convenience wrapper that panics on error (which should never happen
	// for memory backends). Useful for cert storage initialization.
	NewStorageMemory = storage.NewMemory

	// NewFileStorageBackend creates a new file-based storage backend
	// rooted at the given directory. The directory is created with 0700
	// permissions if it does not exist.
	// Returns (StorageBackend, error).
	NewFileStorageBackend = filestorage.New

	// NewStorageCertAdapter creates a new certificate adapter wrapping
	// the given storage backend.
	NewStorageCertAdapter = storage.NewCertAdapter

	// NewCertStore creates a new CertStore from the given configuration.
	NewCertStore = certstore.New

	// CertToString returns a human-readable string representation of an X.509 certificate.
	CertToString = certstore.ToString

	// CertChainToString returns a human-readable string representation of an X.509 certificate chain.
	CertChainToString = certstore.ChainToString

	// ErrCertNotFound is returned when a certificate is not found in the cert store.
	ErrCertNotFound = certstore.ErrCertNotFound
)

// Storage helper functions re-exported from pkg/storage.
var (
	// StorageGetKey retrieves a key's DER bytes from a storage backend.
	// It prepends the "keys/" prefix and ".key" suffix matching the PKCS8
	// backend's storage convention.
	StorageGetKey = storage.GetKey
)

// Storage error sentinels re-exported from pkg/storage.
var (
	// ErrStorageClosed is returned when attempting to use a closed storage backend.
	ErrStorageClosed = storage.ErrClosed

	// ErrStorageNotFound is returned when a key or certificate is not found.
	ErrStorageNotFound = storage.ErrNotFound

	// ErrStorageAlreadyExists is returned when attempting to save a key or
	// certificate that already exists.
	ErrStorageAlreadyExists = storage.ErrAlreadyExists

	// ErrStorageInvalidID is returned when an ID is invalid or empty.
	ErrStorageInvalidID = storage.ErrInvalidID

	// ErrStorageInvalidData is returned when data is invalid or malformed.
	ErrStorageInvalidData = storage.ErrInvalidData
)
