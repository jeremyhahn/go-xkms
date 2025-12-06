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

// Package store provides storage interfaces and implementations for TPM operations
package store

import (
	"crypto"
	"crypto/x509"
	"errors"

	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// SignerOpts provides TPM-specific signer options
type SignerOpts struct {
	// KeyAttributes specifies the key to use for signing
	KeyAttributes *types.KeyAttributes

	// Backend specifies the key backend (optional)
	Backend KeyBackend

	// PSSOptions specifies RSA-PSS options (optional)
	PSSOptions interface{}

	// BlobCN is the common name for blob storage (optional)
	BlobCN *string
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
)

// FSExtension is re-exported from types for compatibility
type FSExtension = types.FSExtension

var (
	// ErrCertNotFound indicates a certificate was not found
	ErrCertNotFound = errors.New("certificate not found")

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

// SignerStorer provides crypto.Signer storage operations
type SignerStorer interface {
	Get(attrs *types.KeyAttributes) (interface{}, error)
	Save(attrs *types.KeyAttributes, signer interface{}) error
	Delete(attrs *types.KeyAttributes) error
	SaveSignature(opts *SignerOpts, signature, digest []byte) error
}

// Logger defines the minimal logging interface required by the store package
type Logger interface {
	Debugf(format string, args ...any)
	Warnf(format string, args ...any)
	Errorf(format string, args ...any)
}
