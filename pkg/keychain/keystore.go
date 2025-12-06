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

package keychain

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"

	"github.com/jeremyhahn/go-keychain/pkg/certstore"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// KeyStore provides a unified interface for cryptographic key and certificate management.
//
// It composes a backend (for key operations) with certificate storage (always external),
// providing a complete solution for PKI management. This design allows maximum flexibility:
//   - PKCS#11 keys in HSM + certificates in Raft
//   - TPM2 keys in hardware + certificates in S3
//   - PKCS#8 keys in filesystem + certificates in database
//
// All implementations must be thread-safe.
type KeyStore interface {
	// ========================================================================
	// Key Operations (delegated to backend)
	// ========================================================================

	// GenerateRSA generates a new RSA key pair.
	// The key size must be specified in attrs.RSAAttributes.KeySize.
	// Common sizes are 2048, 3072, and 4096 bits.
	GenerateRSA(attrs *types.KeyAttributes) (crypto.PrivateKey, error)

	// GenerateECDSA generates a new ECDSA key pair.
	// The elliptic curve must be specified in attrs.ECCAttributes.Curve.
	// Common curves include P-256, P-384, and P-521.
	GenerateECDSA(attrs *types.KeyAttributes) (crypto.PrivateKey, error)

	// GenerateEd25519 generates a new Ed25519 key pair.
	// Ed25519 keys have a fixed size and do not require additional parameters.
	GenerateEd25519(attrs *types.KeyAttributes) (crypto.PrivateKey, error)

	// GetKey retrieves an existing private key by its attributes.
	GetKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error)

	// DeleteKey removes a key identified by its attributes.
	DeleteKey(attrs *types.KeyAttributes) error

	// ListKeys returns attributes for all keys managed by this keychain.
	ListKeys() ([]*types.KeyAttributes, error)

	// RotateKey replaces an existing key with a newly generated key.
	// This operation atomically deletes the old key and generates a new one
	// with the same attributes.
	RotateKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error)

	// ========================================================================
	// Crypto Operations (delegated to backend)
	// ========================================================================

	// Signer returns a crypto.Signer for the specified key.
	// The returned signer can be used for signing operations without
	// exposing the private key material.
	Signer(attrs *types.KeyAttributes) (crypto.Signer, error)

	// Decrypter returns a crypto.Decrypter for the specified key.
	// The returned decrypter can be used for decryption operations without
	// exposing the private key material.
	Decrypter(attrs *types.KeyAttributes) (crypto.Decrypter, error)

	// ========================================================================
	// Certificate Operations (uses CertificateStorage)
	// ========================================================================

	// SaveCert stores a certificate for the given key ID.
	// The keyID typically matches the key's identifier/CN.
	SaveCert(keyID string, cert *x509.Certificate) error

	// GetCert retrieves a certificate by key ID.
	GetCert(keyID string) (*x509.Certificate, error)

	// DeleteCert removes a certificate by key ID.
	DeleteCert(keyID string) error

	// SaveCertChain stores a certificate chain for the given key ID.
	// The chain should be ordered from leaf to root.
	SaveCertChain(keyID string, chain []*x509.Certificate) error

	// GetCertChain retrieves a certificate chain by key ID.
	GetCertChain(keyID string) ([]*x509.Certificate, error)

	// ListCerts returns all certificate IDs currently stored.
	ListCerts() ([]string, error)

	// CertExists checks if a certificate exists for the given key ID.
	CertExists(keyID string) (bool, error)

	// ========================================================================
	// TLS Helpers (convenience methods)
	// ========================================================================

	// GetTLSCertificate returns a complete tls.Certificate ready for use.
	// This combines the private key from the backend with the certificate
	// from storage into a single tls.Certificate structure.
	//
	// The keyID is used to locate both the key (via attrs) and certificate.
	GetTLSCertificate(keyID string, attrs *types.KeyAttributes) (tls.Certificate, error)

	// ========================================================================
	// Unified Key ID Methods
	// ========================================================================

	// GetKeyByID retrieves a key using the unified Key ID format.
	// The Key ID is parsed to determine the backend and key name.
	// Returns the key wrapped in an OpaqueKey for safe operations.
	//
	// Format: backend:keyname
	//
	// Example:
	//   key, err := keystore.GetKeyByID("pkcs11:my-signing-key")
	GetKeyByID(keyID string) (crypto.PrivateKey, error)

	// GetSignerByID retrieves a crypto.Signer using the unified Key ID format.
	// This is a convenience method that calls GetKeyByID and returns the
	// crypto.Signer interface for signing operations.
	//
	// Example:
	//   signer, err := keystore.GetSignerByID("tpm2:attestation-key")
	//   signature, _ := signer.Sign(rand.Reader, digest, crypto.SHA256)
	GetSignerByID(keyID string) (crypto.Signer, error)

	// GetDecrypterByID retrieves a crypto.Decrypter using the unified Key ID format.
	// This is a convenience method for RSA decryption operations.
	//
	// Example:
	//   decrypter, err := keystore.GetDecrypterByID("awskms:rsa-key")
	//   plaintext, _ := decrypter.Decrypt(rand.Reader, ciphertext, opts)
	GetDecrypterByID(keyID string) (crypto.Decrypter, error)

	// ========================================================================
	// Sealing Operations (delegated to backend)
	// ========================================================================

	// Seal encrypts/protects data using the backend's native sealing mechanism.
	// Different backends provide different security guarantees:
	//   - TPM2: PCR-bound hardware sealing
	//   - PKCS#11: HSM-backed AES-GCM encryption
	//   - AWS/Azure/GCP KMS: Cloud-managed envelope encryption
	//   - PKCS#8: Software-based HKDF + AES-GCM
	Seal(ctx context.Context, data []byte, opts *types.SealOptions) (*types.SealedData, error)

	// Unseal decrypts/recovers data that was previously sealed.
	// The sealed data must have been created by the same backend type.
	Unseal(ctx context.Context, sealed *types.SealedData, opts *types.UnsealOptions) ([]byte, error)

	// CanSeal returns true if the backend supports sealing operations.
	CanSeal() bool

	// ========================================================================
	// Lifecycle
	// ========================================================================

	// Backend returns the underlying backend for direct access if needed.
	Backend() types.Backend

	// CertStorage returns the underlying certificate storage for direct access if needed.
	CertStorage() certstore.CertificateStorageAdapter

	// Close releases all resources held by the keychain.
	// This closes both the backend and certificate storage.
	Close() error
}

// Config provides configuration for creating a new KeyStore instance.
type Config struct {
	// Backend provides key generation and cryptographic operations.
	// Required.
	Backend types.Backend

	// CertStorage provides certificate storage.
	// Required - certificates are ALWAYS stored externally, even for
	// backends like PKCS#11 or TPM2 that support internal cert storage.
	CertStorage storage.Backend
}

// New creates a new KeyStore instance with the provided configuration.
//
// Example (PKCS#8 with file storage):
//
//	keyStorage := file.NewKeyStorage("/var/lib/keys")
//	certStorage := file.NewCertStorage("/var/lib/certs")
//	pkcs8Backend := pkcs8.NewBackend(keyStorage)
//	keystore := keychain.New(&keychain.Config{
//	    Backend:     pkcs8Backend,
//	    CertStorage: certStorage,
//	})
//
// Example (PKCS#11 with Raft storage):
//
//	pkcs11Backend := pkcs11.NewBackend(...)
//	raftCertStorage := dragondb.NewRaftCertStorage(nodeHost)
//	keystore := keychain.New(&keychain.Config{
//	    Backend:     pkcs11Backend,
//	    CertStorage: raftCertStorage,  // Certs in Raft, keys in HSM
//	})
func New(config *Config) (KeyStore, error) {
	if config.Backend == nil {
		return nil, ErrBackendRequired
	}
	if config.CertStorage == nil {
		return nil, ErrCertStorageRequired
	}

	// Wrap the certificate storage backend with an adapter that provides
	// certificate-specific operations (SaveCert, GetCert, etc.)
	certAdapter := storage.NewCertAdapter(config.CertStorage)

	return &compositeKeyStore{
		backend:     config.Backend,
		certStorage: certAdapter,
	}, nil
}

// compositeKeyStore is the internal implementation of KeyStore.
// It composes a backend (for keys) with certificate storage (always external).
type compositeKeyStore struct {
	backend     types.Backend
	certStorage *storage.CertAdapter
}

// Verify interface compliance at compile time
var _ KeyStore = (*compositeKeyStore)(nil)

// Backend implementations will be in separate files following this pattern:
//   - composite_keys.go: Key operation methods
//   - composite_certs.go: Certificate operation methods
//   - composite_tls.go: TLS helper methods
