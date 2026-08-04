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
	qrdbstorage "github.com/jeremyhahn/go-xkms/pkg/storage/qrdb"

	objstorecommon "github.com/jeremyhahn/go-objstore/pkg/common"
	objstorelocal "github.com/jeremyhahn/go-objstore/pkg/local"
	objstorememory "github.com/jeremyhahn/go-objstore/pkg/memory"
)

// Storage interface and types re-exported from pkg/storage.
// These allow SDK consumers to configure storage backends directly
// through the SDK without importing internal packages.
//
// ObjectStorage aliases are re-exported from go-objstore/pkg/common so that
// xkms-layer consumers (and, transitively, go-quicbaas consumers) can work
// with object/blob storage without naming go-objstore in their own imports.
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

	// ObjectStorage is the canonical object/blob storage interface re-exported
	// from go-objstore/pkg/common. xkms-layer consumers should reference this
	// alias rather than importing go-objstore directly; go-quicbaas in turn
	// re-exports ObjectStorage so service-level consumers can reach the full
	// stack without naming go-objstore in their go.mod.
	ObjectStorage = objstorecommon.Storage

	// ObjectMetadata holds object-level metadata (content-type, size, custom tags).
	// Re-exported so that all ObjectStorage method signatures are usable through
	// this alias chain without a direct go-objstore import.
	ObjectMetadata = objstorecommon.Metadata

	// ObjectListOptions configures paginated object listing.
	// Re-exported alongside ObjectStorage for the same reason as ObjectMetadata.
	ObjectListOptions = objstorecommon.ListOptions

	// ObjectInfo holds key and metadata for a single listed object.
	ObjectInfo = objstorecommon.ObjectInfo

	// ObjectListResult is the paginated result returned by ObjectStorage.ListWithOptions.
	ObjectListResult = objstorecommon.ListResult

	// ObjectArchiver is the destination interface used by ObjectStorage.Archive.
	ObjectArchiver = objstorecommon.Archiver

	// ObjectLifecyclePolicy configures retention and expiry rules on a storage backend.
	ObjectLifecyclePolicy = objstorecommon.LifecyclePolicy
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

	// NewQRDBStorageBackend adapts a go-qrdb transport KV client into a
	// replicated storage.Backend. A composition root uses it to place data (e.g.
	// the cluster CA key under the barrier strategy) in the replicated,
	// barrier-encrypted datastore so every node can read it.
	NewQRDBStorageBackend = qrdbstorage.NewBackend

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

// Object-storage constructors re-exported from go-objstore so that
// downstream layers (go-quicbaas → go-trusted-platform) never name
// go-objstore in their own imports.
var (
	// NewObjectStorageLocal constructs a filesystem-backed ObjectStorage
	// implementation rooted at the given directory.
	NewObjectStorageLocal = objstorelocal.New

	// NewObjectStorageMemory constructs an in-memory ObjectStorage
	// implementation suitable for testing and embedded use.
	NewObjectStorageMemory = objstorememory.New
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
