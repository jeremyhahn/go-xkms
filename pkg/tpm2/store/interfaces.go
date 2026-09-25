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

// Package store provides storage interfaces and implementations for TPM operations
package store

import (
	"crypto"
	"crypto/x509"
	"errors"
	"log/slog"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// Logger is a type alias for *slog.Logger
type Logger = *slog.Logger

// SignerOpts provides TPM-specific signer options
type SignerOpts struct {
	// KeyAttributes specifies the key to use for signing
	KeyAttributes *types.KeyAttributes

	// Backend specifies the key backend (optional)
	Backend KeyBackend

	// PSSOptions specifies RSA-PSS options (optional)
	PSSOptions interface{}
}

// HashFunc implements crypto.SignerOpts
func (opts *SignerOpts) HashFunc() crypto.Hash {
	if opts.KeyAttributes != nil {
		return opts.KeyAttributes.Hash
	}
	return 0
}

// File extension constants for TPM key storage
const (
	FSEXT_PRIVATE_BLOB = ".blob"
	FSEXT_PUBLIC_BLOB  = ".pub"
	FSEXT_TPM_CONTEXT  = ".ctx"

	// FSEXT_PLATFORM_POLICY holds the PlatformPolicyPin record of an object
	// created under the platform policy: the PCR selection and PCR digest
	// its AuthPolicy was computed from. It lives beside the object's public
	// and private areas because it describes that specific object and has
	// exactly the same lifetime. Objects created before the record existed
	// simply have none; see PlatformPolicyPin for how they are handled.
	FSEXT_PLATFORM_POLICY = ".policy"
)

// FSExtension is re-exported from types for compatibility
type FSExtension = types.FSExtension

var (
	// ErrCertNotFound indicates a certificate was not found
	ErrCertNotFound = errors.New("certificate not found")

	// ErrEmptyKeyCN reports a storage operation on key attributes with no
	// Common Name. The storage key is the CN plus an extension, so an empty CN
	// would degenerate to the bare extension -- one slot shared by every key
	// that lacks a name, last writer wins. Refused rather than composed.
	ErrEmptyKeyCN = errors.New("store: key attributes carry no common name; refusing to compose a storage key from an empty CN")

	// ErrCorruptCopy indicates a corrupt copy operation
	ErrCorruptCopy = errors.New("corrupt copy")

	// ErrInvalidParentAttributes indicates invalid parent key attributes
	ErrInvalidParentAttributes = errors.New("invalid parent key attributes")

	// ErrAlreadyInitialized indicates the store is already initialized
	ErrAlreadyInitialized = errors.New("already initialized")

	// ErrInvalidKeyedHashSecret indicates an invalid keyed hash secret
	ErrInvalidKeyedHashSecret = errors.New("invalid keyed hash secret")

	// ErrInvalidHashFunction indicates an invalid hash function
	ErrInvalidHashFunction = errors.New("invalid hash function")

	// ErrInvalidSignerOpts indicates invalid signer options
	ErrInvalidSignerOpts = errors.New("invalid signer options")

	// ErrInvalidKeyAttributes indicates invalid key attributes
	ErrInvalidKeyAttributes = errors.New("invalid key attributes")

	// ErrInvalidKeyAlgorithm indicates an invalid key algorithm
	ErrInvalidKeyAlgorithm = errors.New("invalid key algorithm")

	// ErrUnsupportedKeyAlgorithm indicates an unsupported key algorithm
	ErrUnsupportedKeyAlgorithm = errors.New("unsupported key algorithm")

	// ErrPasswordRequired indicates a password is required but not provided
	ErrPasswordRequired = errors.New("password required")

	// ErrInvalidPublicKey indicates an invalid public key
	ErrInvalidPublicKey = errors.New("invalid public key")
)

// BlobStorer provides binary blob storage
type BlobStorer interface {
	Read(name string) ([]byte, error)
	Write(name string, data []byte) error
	Delete(name string) error
}

// CertificateStorer provides certificate storage operations
type CertificateStorer interface {
	Get(attrs *types.KeyAttributes) (*x509.Certificate, error)
	Save(attrs *types.KeyAttributes, cert *x509.Certificate) error
	Delete(attrs *types.KeyAttributes) error
	ImportCertificate(attrs *types.KeyAttributes, certPEM []byte) (*x509.Certificate, error)
}

// KeyBackend provides key storage operations for TPM keys
type KeyBackend interface {
	Get(attrs *types.KeyAttributes, fsext types.FSExtension) ([]byte, error)
	Save(attrs *types.KeyAttributes, data []byte, fsext types.FSExtension, overwrite bool) error
	Delete(attrs *types.KeyAttributes) error
}
