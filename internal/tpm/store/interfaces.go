// Package store provides storage interfaces and implementations for TPM operations.
// This internal package re-exports the public store package for internal use.
package store

import (
	"github.com/jeremyhahn/go-keychain/pkg/tpm2/store"
)

// Re-export types from the public package
type (
	SignerOpts        = store.SignerOpts
	FSExtension       = store.FSExtension
	BlobStorer        = store.BlobStorer
	CertificateStorer = store.CertificateStorer
	KeyBackend        = store.KeyBackend
	SignerStorer      = store.SignerStorer
	Logger            = store.Logger
)

// Re-export constants
const (
	FSEXT_PRIVATE_BLOB = store.FSEXT_PRIVATE_BLOB
	FSEXT_PUBLIC_BLOB  = store.FSEXT_PUBLIC_BLOB
	FSEXT_TPM_CONTEXT  = store.FSEXT_TPM_CONTEXT
)

// Re-export errors
var (
	ErrCertNotFound            = store.ErrCertNotFound
	ErrCorruptCopy             = store.ErrCorruptCopy
	ErrInvalidParentAttributes = store.ErrInvalidParentAttributes
	ErrAlreadyInitialized      = store.ErrAlreadyInitialized
	ErrInvalidKeyedHashSecret  = store.ErrInvalidKeyedHashSecret
	ErrInvalidHashFunction     = store.ErrInvalidHashFunction
	ErrInvalidSignerOpts       = store.ErrInvalidSignerOpts
	ErrInvalidKeyAttributes    = store.ErrInvalidKeyAttributes
	ErrInvalidKeyAlgorithm     = store.ErrInvalidKeyAlgorithm
	ErrUnsupportedKeyAlgorithm = store.ErrUnsupportedKeyAlgorithm
	ErrPasswordRequired        = store.ErrPasswordRequired
)

// Re-export factory type
type StorageFactory = store.StorageFactory

// NewStorageFactory creates a new storage factory
var NewStorageFactory = store.NewStorageFactory

// NewMemoryStorageFactory creates a storage factory using in-memory storage
var NewMemoryStorageFactory = store.NewMemoryStorageFactory
