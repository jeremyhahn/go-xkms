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

package tpm2

import (
	"crypto"
	"crypto/elliptic"
	"crypto/x509"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/logging"
	"github.com/jeremyhahn/go-keychain/pkg/storage/file"
	pkgtpm2 "github.com/jeremyhahn/go-keychain/pkg/tpm2"
	"github.com/jeremyhahn/go-keychain/pkg/tpm2/store"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// Backend implements types.Backend for TPM 2.0 hardware security modules.
// It wraps the low-level pkg/tpm2 library to provide a unified Backend interface.
type Backend struct {
	config      *Config
	tpm         pkgtpm2.TrustedPlatformModule
	keyBackend  store.KeyBackend
	logger      *logging.Logger
	srkAttrs    *types.KeyAttributes
	tracker     types.AEADSafetyTracker
	mu          sync.RWMutex
	closed      bool
	externalTPM bool // If true, TPM was provided externally and should not be closed
}

// ExternalTPMConfig holds configuration for creating a backend with an external TPM.
type ExternalTPMConfig struct {
	// TPM is the existing TPM instance to use
	TPM pkgtpm2.TrustedPlatformModule

	// KeyBackend is the storage backend for TPM key blobs
	KeyBackend store.KeyBackend

	// Logger is the logger instance to use (optional)
	Logger *logging.Logger

	// Tracker is the AEAD safety tracker (optional)
	Tracker types.AEADSafetyTracker
}

// NewBackendWithTPM creates a new TPM2 backend using an existing TPM instance.
// This is useful when the TPM has already been initialized and provisioned by
// another component (e.g., go-trusted-platform's app.TPM).
//
// The caller is responsible for managing the TPM lifecycle (closing it when done).
// The backend will not close the TPM when Backend.Close() is called.
func NewBackendWithTPM(config *ExternalTPMConfig) (*Backend, error) {
	if config == nil {
		return nil, fmt.Errorf("%w: config is nil", ErrInvalidConfig)
	}
	if config.TPM == nil {
		return nil, fmt.Errorf("%w: TPM is nil", ErrInvalidConfig)
	}
	if config.KeyBackend == nil {
		return nil, fmt.Errorf("%w: KeyBackend is nil", ErrInvalidConfig)
	}

	// Create logger if not provided
	logger := config.Logger
	if logger == nil {
		logger = logging.DefaultLogger()
	}

	// Initialize AEAD tracker
	tracker := config.Tracker
	if tracker == nil {
		tracker = backend.NewMemoryAEADTracker()
	}

	// Get the SRK attributes for key creation
	srkAttrs, err := config.TPM.SSRKAttributes()
	if err != nil {
		return nil, fmt.Errorf("failed to get SRK attributes: %w", err)
	}

	return &Backend{
		config:      nil, // No config when using external TPM
		tpm:         config.TPM,
		keyBackend:  config.KeyBackend,
		logger:      logger,
		srkAttrs:    srkAttrs,
		tracker:     tracker,
		externalTPM: true, // Mark as external so Close() doesn't close the TPM
	}, nil
}

// NewBackend creates a new TPM2 backend instance.
// The backend is initialized and ready for use upon return.
func NewBackend(config *Config) (*Backend, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidConfig, err)
	}

	// Create logger if not provided
	logger := config.Logger
	if logger == nil {
		logger = logging.DefaultLogger()
	}

	// Initialize AEAD tracker
	tracker := config.Tracker
	if tracker == nil {
		tracker = backend.NewMemoryAEADTracker()
	}

	// Ensure key directory exists
	if err := os.MkdirAll(config.KeyDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create key directory: %w", err)
	}

	// Create file-based key backend for storing TPM key blobs
	fsBackend, err := file.New(config.KeyDir)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage backend: %w", err)
	}
	keyBackend := store.NewFileBackend(logger, fsBackend)

	// Create TPM2 configuration
	tpmConfig := config.ToTPMConfig()

	// Create TPM2 instance
	tpm, err := pkgtpm2.NewTPM2(&pkgtpm2.Params{
		Config:  tpmConfig,
		Backend: keyBackend,
		Logger:  logger,
		Tracker: tracker,
	})
	if err != nil {
		// Check for initialization error - TPM may need provisioning
		if err == pkgtpm2.ErrNotInitialized {
			return nil, fmt.Errorf("%w: TPM needs provisioning", ErrNotInitialized)
		}
		return nil, fmt.Errorf("failed to initialize TPM: %w", err)
	}

	// Get the SRK attributes for key creation
	srkAttrs, err := tpm.SSRKAttributes()
	if err != nil {
		_ = tpm.Close()
		return nil, fmt.Errorf("failed to get SRK attributes: %w", err)
	}

	return &Backend{
		config:     config,
		tpm:        tpm,
		keyBackend: keyBackend,
		logger:     logger,
		srkAttrs:   srkAttrs,
		tracker:    tracker,
	}, nil
}

// Type returns the backend type (TPM2).
func (b *Backend) Type() types.BackendType {
	return backend.BackendTypeTPM2
}

// Capabilities returns the capabilities of this backend.
// TPM2 is a hardware-backed security module.
func (b *Backend) Capabilities() types.Capabilities {
	caps := types.NewHardwareCapabilities()
	caps.SymmetricEncryption = true // TPM supports sealing/unsealing
	caps.Sealing = true             // TPM supports seal/unseal operations
	return caps
}

// GenerateKey generates a new key in the TPM with the given attributes.
// The private key never leaves the TPM hardware.
func (b *Backend) GenerateKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return nil, ErrNotInitialized
	}

	if attrs == nil {
		return nil, ErrInvalidKeyAttributes
	}

	// Set parent to SRK if not specified
	if attrs.Parent == nil {
		attrs.Parent = b.srkAttrs
	}

	// Set store type
	attrs.StoreType = types.StoreTPM2

	switch attrs.KeyAlgorithm {
	case x509.RSA:
		pub, err := b.tpm.CreateRSA(attrs, b.keyBackend, false)
		if err != nil {
			return nil, fmt.Errorf("failed to create RSA key: %w", err)
		}
		// Return a TPM signer that wraps the key
		return &tpm2Signer{
			backend:   b,
			attrs:     attrs,
			publicKey: pub,
		}, nil

	case x509.ECDSA:
		// Set default curve if not specified
		if attrs.ECCAttributes == nil || attrs.ECCAttributes.Curve == nil {
			attrs.ECCAttributes = &types.ECCAttributes{
				Curve: elliptic.P256(),
			}
		}
		pub, err := b.tpm.CreateECDSA(attrs, b.keyBackend, false)
		if err != nil {
			return nil, fmt.Errorf("failed to create ECDSA key: %w", err)
		}
		// Return a TPM signer that wraps the key
		return &tpm2Signer{
			backend:   b,
			attrs:     attrs,
			publicKey: pub,
		}, nil

	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedKeyAlgorithm, attrs.KeyAlgorithm)
	}
}

// GetKey retrieves an existing key from the TPM by its attributes.
// Returns a crypto.Signer that performs operations using the TPM.
func (b *Backend) GetKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrNotInitialized
	}

	if attrs == nil {
		return nil, ErrInvalidKeyAttributes
	}

	// Set parent to SRK if not specified
	if attrs.Parent == nil {
		attrs.Parent = b.srkAttrs
	}

	// Set store type
	attrs.StoreType = types.StoreTPM2

	// Try to load the key from the backend to verify it exists
	_, err := b.keyBackend.Get(attrs, store.FSEXT_PRIVATE_BLOB)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrKeyNotFound, attrs.CN)
	}

	// Get the public blob to determine key type
	pubData, err := b.keyBackend.Get(attrs, store.FSEXT_PUBLIC_BLOB)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrKeyNotFound, attrs.CN)
	}

	// Parse the public key to determine algorithm
	pubKey, err := b.parsePublicKey(pubData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	return &tpm2Signer{
		backend:   b,
		attrs:     attrs,
		publicKey: pubKey,
	}, nil
}

// DeleteKey removes a key from the TPM and its associated storage.
func (b *Backend) DeleteKey(attrs *types.KeyAttributes) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return ErrNotInitialized
	}

	if attrs == nil {
		return ErrInvalidKeyAttributes
	}

	// Set parent to SRK if not specified
	if attrs.Parent == nil {
		attrs.Parent = b.srkAttrs
	}

	// Delete the key using TPM2 library
	if err := b.tpm.DeleteKey(attrs, b.keyBackend); err != nil {
		return fmt.Errorf("failed to delete key: %w", err)
	}

	return nil
}

// ListKeys returns attributes for all keys managed by this backend.
func (b *Backend) ListKeys() ([]*types.KeyAttributes, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrNotInitialized
	}

	// List files in the key directory with .blob extension (private blobs)
	keyDir := b.config.KeyDir
	entries, err := os.ReadDir(keyDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []*types.KeyAttributes{}, nil
		}
		return nil, fmt.Errorf("failed to list key directory: %w", err)
	}

	var keys []*types.KeyAttributes
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		// Look for private blob files
		if ext := filepath.Ext(name); ext == store.FSEXT_PRIVATE_BLOB {
			cn := name[:len(name)-len(ext)]
			keys = append(keys, &types.KeyAttributes{
				CN:        cn,
				StoreType: types.StoreTPM2,
			})
		}
	}

	return keys, nil
}

// Signer returns a crypto.Signer for the key identified by attrs.
func (b *Backend) Signer(attrs *types.KeyAttributes) (crypto.Signer, error) {
	key, err := b.GetKey(attrs)
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("%w: key does not implement crypto.Signer", ErrUnsupportedOperation)
	}
	return signer, nil
}

// Decrypter returns a crypto.Decrypter for the key identified by attrs.
// Note: Decryption requires the key to be created with encryption capability.
func (b *Backend) Decrypter(attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	key, err := b.GetKey(attrs)
	if err != nil {
		return nil, err
	}
	decrypter, ok := key.(crypto.Decrypter)
	if !ok {
		return nil, fmt.Errorf("%w: key does not implement crypto.Decrypter", ErrDecryptionNotSupported)
	}
	return decrypter, nil
}

// RotateKey is not supported for TPM2 keys as they are hardware-backed.
func (b *Backend) RotateKey(attrs *types.KeyAttributes) error {
	return ErrKeyRotationNotSupported
}

// Close releases any resources held by the backend.
func (b *Backend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return nil
	}

	b.closed = true

	// Don't close the TPM if it was provided externally
	// The caller is responsible for managing its lifecycle
	if b.tpm != nil && !b.externalTPM {
		if err := b.tpm.Close(); err != nil {
			return fmt.Errorf("failed to close TPM: %w", err)
		}
	}

	return nil
}

// TPM returns the underlying TPM2 instance for advanced operations.
func (b *Backend) TPM() pkgtpm2.TrustedPlatformModule {
	return b.tpm
}

// KeyBackend returns the underlying key storage backend.
func (b *Backend) KeyBackend() store.KeyBackend {
	return b.keyBackend
}

// SRKAttributes returns the Storage Root Key attributes.
func (b *Backend) SRKAttributes() *types.KeyAttributes {
	return b.srkAttrs
}

// parsePublicKey parses a TPM2B_PUBLIC blob and returns the crypto.PublicKey
func (b *Backend) parsePublicKey(pubData []byte) (crypto.PublicKey, error) {
	return b.tpm.ParsePublicKey(pubData)
}

// tpm2Signer implements crypto.Signer using the TPM
type tpm2Signer struct {
	backend   *Backend
	attrs     *types.KeyAttributes
	publicKey crypto.PublicKey
}

// Public returns the public key corresponding to the opaque private key.
func (s *tpm2Signer) Public() crypto.PublicKey {
	return s.publicKey
}

// Sign signs digest with the private key using the TPM.
func (s *tpm2Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	s.backend.mu.RLock()
	defer s.backend.mu.RUnlock()

	if s.backend.closed {
		return nil, ErrNotInitialized
	}

	// Create TPM signer opts
	signerOpts := &store.SignerOpts{
		KeyAttributes: s.attrs,
		Backend:       s.backend.keyBackend,
	}

	// If opts contains hash info, use it
	if opts != nil {
		s.attrs.Hash = opts.HashFunc()
	}

	// Sign using TPM
	signature, err := s.backend.tpm.Sign(rand, digest, signerOpts)
	if err != nil {
		return nil, fmt.Errorf("TPM sign failed: %w", err)
	}

	return signature, nil
}

// tpm2Decrypter implements crypto.Decrypter using the TPM
type tpm2Decrypter struct {
	*tpm2Signer
}

// Decrypt decrypts ciphertext with the private key using the TPM.
func (d *tpm2Decrypter) Decrypt(rand io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	d.backend.mu.RLock()
	defer d.backend.mu.RUnlock()

	if d.backend.closed {
		return nil, ErrNotInitialized
	}

	// For RSA keys, use TPM's RSADecrypt
	if d.attrs.KeyAlgorithm == x509.RSA {
		// Load the key first to get the handle
		loadResp, err := d.backend.tpm.LoadKeyPair(d.attrs, nil, d.backend.keyBackend)
		if err != nil {
			return nil, fmt.Errorf("failed to load key: %w", err)
		}
		defer d.backend.tpm.Flush(loadResp.ObjectHandle)

		// Read the public to get the name
		pub, err := tpm2.ReadPublic{
			ObjectHandle: loadResp.ObjectHandle,
		}.Execute(d.backend.tpm.Transport())
		if err != nil {
			return nil, fmt.Errorf("failed to read public: %w", err)
		}

		// Decrypt
		plaintext, err := d.backend.tpm.RSADecrypt(loadResp.ObjectHandle, pub.Name, ciphertext)
		if err != nil {
			return nil, fmt.Errorf("TPM decrypt failed: %w", err)
		}
		return plaintext, nil
	}

	return nil, fmt.Errorf("%w: only RSA decryption is supported", ErrDecryptionNotSupported)
}

// Ensure interfaces are implemented at compile time
var _ types.Backend = (*Backend)(nil)
var _ crypto.Signer = (*tpm2Signer)(nil)
var _ crypto.Decrypter = (*tpm2Decrypter)(nil)
