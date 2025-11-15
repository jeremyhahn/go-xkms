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

//go:build pkcs11

package smartcardhsm

import (
	"crypto"
	"fmt"
	"sync"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/backend/pkcs11"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// Backend implements the types.Backend interface for SmartCard-HSM devices.
// It wraps a PKCS#11 backend and adds DKEK (Device Key Encryption Key) support
// for secure key backup and restore operations.
//
// SmartCard-HSM is a lightweight hardware security module that uses the PKCS#11
// interface for standard cryptographic operations and provides DKEK for key
// backup/restore functionality using Shamir's Secret Sharing scheme.
//
// Thread Safety:
// All operations are protected by mutexes, making the backend safe for
// concurrent access from multiple goroutines.
type Backend struct {
	config        *Config
	pkcs11Backend *pkcs11.Backend
	dkek          *DKEK
	mu            sync.RWMutex
	types.Backend
}

// NewBackend creates a new SmartCard-HSM backend instance.
// It wraps a PKCS#11 backend and adds DKEK functionality on top.
//
// Parameters:
//   - config: SmartCard-HSM configuration including PKCS#11 config and DKEK parameters
//
// Returns an error if the configuration is invalid or PKCS#11 backend creation fails.
func NewBackend(config *Config) (*Backend, error) {
	// Set defaults
	config.SetDefaults()

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	// Create underlying PKCS#11 backend
	pkcs11Backend, err := pkcs11.NewBackend(config.PKCS11Config)
	if err != nil {
		return nil, fmt.Errorf("failed to create pkcs11 backend: %w", err)
	}

	// Create DKEK handler
	dkek, err := NewDKEK(config.DKEKThreshold, config.DKEKShares, config.DKEKStorage)
	if err != nil {
		return nil, fmt.Errorf("failed to create dkek handler: %w", err)
	}

	return &Backend{
		config:        config,
		pkcs11Backend: pkcs11Backend,
		dkek:          dkek,
	}, nil
}

// Type returns the backend type (SmartCard-HSM).
func (b *Backend) Type() types.BackendType {
	return backend.BackendTypeSmartCardHSM
}

// Config returns the SmartCard-HSM configuration.
func (b *Backend) Config() *Config {
	return b.config
}

// Capabilities returns the capabilities of this backend.
// SmartCard-HSM is a hardware-backed security module with DKEK support.
func (b *Backend) Capabilities() types.Capabilities {
	caps := types.NewHardwareCapabilities()
	caps.SymmetricEncryption = true
	caps.Import = true
	caps.Export = true // Supports DKEK-based export
	return caps
}

// Initialize initializes the SmartCard-HSM token.
// This delegates to the underlying PKCS#11 backend.
func (b *Backend) Initialize(soPIN, userPIN string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.pkcs11Backend.Initialize(soPIN, userPIN)
}

// Login authenticates to the SmartCard-HSM token.
// This delegates to the underlying PKCS#11 backend.
func (b *Backend) Login() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.pkcs11Backend.Login()
}

// Close closes the SmartCard-HSM backend and releases resources.
func (b *Backend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.pkcs11Backend.Close()
}

// GenerateKey generates a new cryptographic key with the given attributes.
// This delegates to the underlying PKCS#11 backend.
func (b *Backend) GenerateKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.pkcs11Backend.GenerateKey(attrs)
}

// GetKey retrieves an existing key identified by its attributes.
// This delegates to the underlying PKCS#11 backend.
func (b *Backend) GetKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.pkcs11Backend.GetKey(attrs)
}

// DeleteKey deletes a key identified by its attributes.
// This delegates to the underlying PKCS#11 backend.
func (b *Backend) DeleteKey(attrs *types.KeyAttributes) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.pkcs11Backend.DeleteKey(attrs)
}

// ListKeys lists all keys managed by this backend.
// This delegates to the underlying PKCS#11 backend.
func (b *Backend) ListKeys() ([]*types.KeyAttributes, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.pkcs11Backend.ListKeys()
}

// Signer returns a crypto.Signer for the key identified by attrs.
// This delegates to the underlying PKCS#11 backend.
func (b *Backend) Signer(attrs *types.KeyAttributes) (crypto.Signer, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.pkcs11Backend.Signer(attrs)
}

// Decrypter returns a crypto.Decrypter for the key identified by attrs.
// This delegates to the underlying PKCS#11 backend.
func (b *Backend) Decrypter(attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.pkcs11Backend.Decrypter(attrs)
}

// RotateKey rotates/updates a key identified by attrs.
// This delegates to the underlying PKCS#11 backend.
func (b *Backend) RotateKey(attrs *types.KeyAttributes) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.pkcs11Backend.RotateKey(attrs)
}

// DKEK returns the DKEK handler for this SmartCard-HSM.
// This allows access to DKEK-specific operations like share generation,
// reconstruction, and key backup/restore.
func (b *Backend) DKEK() *DKEK {
	return b.dkek
}
