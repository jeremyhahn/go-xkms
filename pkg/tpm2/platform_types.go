package tpm2

import (
	"crypto/x509"
	"errors"

	"github.com/jeremyhahn/go-keychain/pkg/tpm2/store"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// Re-export types from go-keychain/pkg/types for convenience

// KeyAttributes is provided by go-keychain/pkg/types
type KeyAttributes = types.KeyAttributes

// Password is provided by go-keychain/pkg/types
type Password = types.Password

// DEFAULT_PASSWORD is the default password
const DEFAULT_PASSWORD = "changeme"

// CertificateStorer interface for certificate storage operations
type CertificateStorer interface {
	Get(cn string) (*x509.Certificate, error)
	Save(cn string, cert *x509.Certificate) error
	Delete(cn string) error
}

// PlatformKeyStorer defines the interface for a TPM-backed platform key store
// that provides access to Storage Root Key (SRK) attributes and key backend.
type PlatformKeyStorer interface {
	// SRKAttributes returns the Storage Root Key attributes
	SRKAttributes() *types.KeyAttributes

	// Backend returns the key backend used by this store
	Backend() store.KeyBackend
}

// Errors
var (
	ErrCertNotFound = errors.New("certificate not found")
	ErrCorruptCopy  = errors.New("corrupt copy")
)
