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

package canokey

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"sync"

	"github.com/jeremyhahn/go-keychain/pkg/backend/pkcs11"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	pkcs11lib "github.com/miekg/pkcs11"
)

// Backend implements types.Backend for CanoKey hardware tokens
// It wraps PKCS#11 operations with CanoKey PIV-specific features
type Backend struct {
	config      *Config
	pkcs11      *pkcs11.Backend // Underlying PKCS#11 backend
	p11ctx      *pkcs11lib.Ctx  // Direct PKCS#11 context for admin operations
	session     pkcs11lib.SessionHandle
	slotID      uint
	firmwareVer *FirmwareVersion // CanoKey firmware version
	initialized bool
	mu          sync.RWMutex
}

// FirmwareVersion represents CanoKey firmware version (semantic versioning)
type FirmwareVersion struct {
	Major uint8
	Minor uint8
	Patch uint8
}

var _ types.Backend = (*Backend)(nil)

// NewBackend creates a new CanoKey backend instance
func NewBackend(config *Config) (*Backend, error) {
	if config == nil {
		return nil, ErrConfigRequired
	}

	// Apply defaults
	config.SetDefaults()

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConfigRequired, err)
	}

	b := &Backend{
		config: config,
	}

	return b, nil
}

// Initialize initializes the CanoKey backend
// This discovers the CanoKey token and sets up PKCS#11 context
func (b *Backend) Initialize() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.initialized {
		return nil
	}

	// Create underlying PKCS#11 backend first (it will initialize the library)
	var slot *int
	if b.config.Slot != nil {
		slotInt := int(*b.config.Slot)
		slot = &slotInt
	}

	pkcs11Config := &pkcs11.Config{
		Library:     b.config.Library,
		TokenLabel:  b.config.TokenLabel,
		PIN:         b.config.PIN,
		Slot:        slot,
		KeyStorage:  b.config.KeyStorage,
		CertStorage: b.config.CertStorage,
	}

	pkcs11Backend, err := pkcs11.NewBackend(pkcs11Config)
	if err != nil {
		return fmt.Errorf("canokey: failed to create PKCS#11 backend: %w", err)
	}

	// Login to PKCS#11 backend (this initializes the library)
	if err := pkcs11Backend.Login(); err != nil {
		return fmt.Errorf("canokey: failed to login to PKCS#11 backend: %w", err)
	}

	b.pkcs11 = pkcs11Backend

	// Now create our own session on the already-initialized library for management operations
	p11ctx := pkcs11lib.New(b.config.Library)
	if p11ctx == nil {
		return fmt.Errorf("%w: %s", ErrLibraryLoadFailed, b.config.Library)
	}

	// Initialize with already-initialized library (should return CKR_CRYPTOKI_ALREADY_INITIALIZED)
	err = p11ctx.Initialize()
	if err != nil && err != pkcs11lib.Error(pkcs11lib.CKR_CRYPTOKI_ALREADY_INITIALIZED) {
		return fmt.Errorf("canokey: failed to initialize PKCS#11: %w", err)
	}

	// Get slot list
	slots, err := p11ctx.GetSlotList(true)
	if err != nil {
		return fmt.Errorf("canokey: failed to get slot list: %w", err)
	}

	if len(slots) == 0 {
		return ErrNoDeviceFound
	}

	b.slotID = slots[0]

	// Open session for management operations
	session, err := p11ctx.OpenSession(b.slotID, pkcs11lib.CKF_SERIAL_SESSION|pkcs11lib.CKF_RW_SESSION)
	if err != nil {
		return fmt.Errorf("canokey: failed to open session: %w", err)
	}

	// Login with PIN
	err = p11ctx.Login(session, pkcs11lib.CKU_USER, b.config.PIN)
	if err != nil && err != pkcs11lib.Error(pkcs11lib.CKR_USER_ALREADY_LOGGED_IN) {
		p11ctx.CloseSession(session)
		return fmt.Errorf("canokey: failed to login with PIN: %w", err)
	}

	b.p11ctx = p11ctx
	b.session = session

	// Detect firmware version for feature capability checks
	if err := b.detectFirmwareVersion(); err != nil {
		// Non-fatal - continue with unknown version (assume 2.0.0)
		b.firmwareVer = &FirmwareVersion{Major: 2, Minor: 0, Patch: 0}
	}

	b.initialized = true

	return nil
}

// detectFirmwareVersion attempts to detect the CanoKey firmware version
// CanoKey uses semantic versioning (e.g., 3.0.0) unlike YubiKey's encoded format
func (b *Backend) detectFirmwareVersion() error {
	// Query token info to get firmware version
	tokenInfo, err := b.p11ctx.GetTokenInfo(b.slotID)
	if err != nil {
		return fmt.Errorf("canokey: failed to get token info: %w", err)
	}

	// CanoKey firmware version is stored in semantic versioning format
	// Unlike YubiKey which encodes it, CanoKey stores it directly
	major := tokenInfo.FirmwareVersion.Major
	minor := tokenInfo.FirmwareVersion.Minor

	// CanoKey typically has patch version as 0
	// The firmware version structure only has Major and Minor
	b.firmwareVer = &FirmwareVersion{
		Major: major,
		Minor: minor,
		Patch: 0,
	}

	return nil
}

// SupportsEd25519 returns true if the CanoKey supports Ed25519 keys
// Requires firmware 3.0.0+ for Ed25519/X25519 support
func (b *Backend) SupportsEd25519() bool {
	if b.firmwareVer == nil {
		return false
	}
	return b.firmwareVer.Major >= 3
}

// SupportsX25519 returns true if the CanoKey supports X25519 keys
// Requires firmware 3.0.0+ for Ed25519/X25519 support
func (b *Backend) SupportsX25519() bool {
	if b.firmwareVer == nil {
		return false
	}
	return b.firmwareVer.Major >= 3
}

// GetFirmwareVersion returns the CanoKey firmware version
func (b *Backend) GetFirmwareVersion() *FirmwareVersion {
	return b.firmwareVer
}

// GenerateRandom generates cryptographically secure random bytes using the CanoKey's
// hardware random number generator (or software RNG for QEMU virtual mode).
//
// The CanoKey provides high-quality randomness suitable for cryptographic key
// generation, nonces, IVs, and other security-critical random values.
//
// Parameters:
//   - length: Number of random bytes to generate (max 1024 per call recommended)
//
// Returns random bytes or an error if the CanoKey RNG is unavailable.
func (b *Backend) GenerateRandom(length int) ([]byte, error) {
	if !b.initialized {
		return nil, ErrNotInitialized
	}

	if length <= 0 {
		return nil, ErrInvalidLength
	}

	// Recommended max is 1024 bytes per call
	if length > 1024 {
		return nil, ErrLengthExceedsMaximum
	}

	// Use PKCS#11 C_GenerateRandom
	randomBytes, err := b.p11ctx.GenerateRandom(b.session, length)
	if err != nil {
		return nil, fmt.Errorf("canokey: failed to generate random bytes: %w", err)
	}

	return randomBytes, nil
}

// Close closes the CanoKey backend and releases resources
func (b *Backend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if !b.initialized {
		return nil
	}

	// Close PKCS#11 backend
	if b.pkcs11 != nil {
		b.pkcs11.Close()
		b.pkcs11 = nil
	}

	// Close direct PKCS#11 context
	if b.p11ctx != nil {
		b.p11ctx.Logout(b.session)
		b.p11ctx.CloseSession(b.session)
		b.p11ctx.Finalize()
		b.p11ctx.Destroy()
		b.p11ctx = nil
	}

	b.initialized = false
	return nil
}

// Type returns the backend type identifier
func (b *Backend) Type() types.BackendType {
	return "canokey"
}

// Capabilities returns the backend capabilities
func (b *Backend) Capabilities() types.Capabilities {
	return types.Capabilities{
		Keys:                true,
		HardwareBacked:      !b.config.IsVirtual, // false for QEMU virtual key
		Signing:             true,
		Decryption:          true,
		SymmetricEncryption: true,  // Envelope encryption with CanoKey PIV key
		Sealing:             true,  // Envelope encryption via key wrap
		Import:              false, // PIV keys are non-exportable
		Export:              false, // PIV keys are non-exportable
	}
}

// ensureInitialized checks if the backend is initialized
func (b *Backend) ensureInitialized() error {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if !b.initialized {
		return ErrNotInitialized
	}
	return nil
}

// GenerateKey generates a key pair on the CanoKey
func (b *Backend) GenerateKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	if err := b.ensureInitialized(); err != nil {
		return nil, err
	}

	// Delegate to PKCS#11 backend for key generation
	// CanoKey supports standard PKCS#11 key generation mechanisms
	return b.pkcs11.GenerateKey(attrs)
}

// GetKey retrieves a key from the CanoKey
func (b *Backend) GetKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	if err := b.ensureInitialized(); err != nil {
		return nil, err
	}

	return b.pkcs11.GetKey(attrs)
}

// DeleteKey deletes a key from the CanoKey
func (b *Backend) DeleteKey(attrs *types.KeyAttributes) error {
	if err := b.ensureInitialized(); err != nil {
		return err
	}

	return b.pkcs11.DeleteKey(attrs)
}

// ListKeys returns a list of all keys stored on the CanoKey
func (b *Backend) ListKeys() ([]*types.KeyAttributes, error) {
	if err := b.ensureInitialized(); err != nil {
		return nil, err
	}

	return b.pkcs11.ListKeys()
}

// Signer returns a crypto.Signer for the key identified by attrs
func (b *Backend) Signer(attrs *types.KeyAttributes) (crypto.Signer, error) {
	if err := b.ensureInitialized(); err != nil {
		return nil, err
	}

	return b.pkcs11.Signer(attrs)
}

// Decrypter returns a crypto.Decrypter for the key identified by attrs
func (b *Backend) Decrypter(attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	if err := b.ensureInitialized(); err != nil {
		return nil, err
	}

	return b.pkcs11.Decrypter(attrs)
}

// RotateKey rotates a key on the CanoKey
func (b *Backend) RotateKey(attrs *types.KeyAttributes) error {
	if err := b.ensureInitialized(); err != nil {
		return err
	}

	return b.pkcs11.RotateKey(attrs)
}

// AvailableSlots returns a list of available PIV slots on the CanoKey
func (b *Backend) AvailableSlots() ([]PIVSlot, error) {
	if err := b.ensureInitialized(); err != nil {
		return nil, err
	}

	// Return all valid PIV slots
	return AllSlots(), nil
}

// GenerateRSA generates an RSA key pair on the CanoKey
// This is a convenience method that wraps GenerateKey
func (b *Backend) GenerateRSA(attrs *types.KeyAttributes) (crypto.Signer, error) {
	attrs.KeyAlgorithm = x509.RSA
	key, err := b.GenerateKey(attrs)
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, ErrNotSigner
	}
	return signer, nil
}

// GenerateECDSA generates an ECDSA key pair on the CanoKey
// This is a convenience method that wraps GenerateKey
func (b *Backend) GenerateECDSA(attrs *types.KeyAttributes) (crypto.Signer, error) {
	attrs.KeyAlgorithm = x509.ECDSA
	key, err := b.GenerateKey(attrs)
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, ErrNotSigner
	}
	return signer, nil
}

// GenerateEd25519 generates an Ed25519 key pair on the CanoKey
// This is a convenience method that wraps GenerateKey
// Requires CanoKey firmware 3.0.0+
func (b *Backend) GenerateEd25519(attrs *types.KeyAttributes) (crypto.Signer, error) {
	if !b.SupportsEd25519() {
		return nil, ErrFirmwareRequired
	}

	attrs.KeyAlgorithm = x509.Ed25519
	key, err := b.GenerateKey(attrs)
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, ErrNotSigner
	}
	return signer, nil
}
