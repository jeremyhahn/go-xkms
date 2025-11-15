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

package yubikey

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"sync"

	"github.com/jeremyhahn/go-keychain/pkg/backend/pkcs11"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	pkcs11lib "github.com/miekg/pkcs11"
)

// Backend implements types.Backend for YubiKey hardware tokens
// It wraps PKCS#11 operations with YubiKey PIV-specific features
type Backend struct {
	config      *Config
	pkcs11      *pkcs11.Backend // Underlying PKCS#11 backend
	p11ctx      *pkcs11lib.Ctx  // Direct PKCS#11 context for admin operations
	session     pkcs11lib.SessionHandle
	slotID      uint
	firmwareVer *FirmwareVersion // YubiKey firmware version
	initialized bool
	mu          sync.RWMutex
}

// FirmwareVersion represents YubiKey firmware version
type FirmwareVersion struct {
	Major uint8
	Minor uint8
	Patch uint8
}

var _ types.Backend = (*Backend)(nil)

// NewBackend creates a new YubiKey backend instance
func NewBackend(config *Config) (*Backend, error) {
	if config == nil {
		return nil, fmt.Errorf("yubikey: config is required")
	}

	// Apply defaults
	config.SetDefaults()

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("yubikey: invalid configuration: %w", err)
	}

	b := &Backend{
		config: config,
	}

	return b, nil
}

// Initialize initializes the YubiKey backend
// This discovers the YubiKey token and sets up PKCS#11 context
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
		return fmt.Errorf("yubikey: failed to create PKCS#11 backend: %w", err)
	}

	// Login to PKCS#11 backend (this initializes the library)
	if err := pkcs11Backend.Login(); err != nil {
		return fmt.Errorf("yubikey: failed to login to PKCS#11 backend: %w", err)
	}

	b.pkcs11 = pkcs11Backend

	// Now create our own session on the already-initialized library for management operations
	p11ctx := pkcs11lib.New(b.config.Library)
	if p11ctx == nil {
		return fmt.Errorf("yubikey: failed to load PKCS#11 library: %s", b.config.Library)
	}

	// Initialize with already-initialized library (should return CKR_CRYPTOKI_ALREADY_INITIALIZED)
	err = p11ctx.Initialize()
	if err != nil && err != pkcs11lib.Error(pkcs11lib.CKR_CRYPTOKI_ALREADY_INITIALIZED) {
		return fmt.Errorf("yubikey: failed to initialize PKCS#11: %w", err)
	}

	// Get slot list
	slots, err := p11ctx.GetSlotList(true)
	if err != nil {
		return fmt.Errorf("yubikey: failed to get slot list: %w", err)
	}

	if len(slots) == 0 {
		return fmt.Errorf("yubikey: no YubiKey device found")
	}

	b.slotID = slots[0]

	// Open session for management operations
	session, err := p11ctx.OpenSession(b.slotID, pkcs11lib.CKF_SERIAL_SESSION|pkcs11lib.CKF_RW_SESSION)
	if err != nil {
		return fmt.Errorf("yubikey: failed to open session: %w", err)
	}

	// Login with PIN
	err = p11ctx.Login(session, pkcs11lib.CKU_USER, b.config.PIN)
	if err != nil && err != pkcs11lib.Error(pkcs11lib.CKR_USER_ALREADY_LOGGED_IN) {
		p11ctx.CloseSession(session)
		return fmt.Errorf("yubikey: failed to login with PIN: %w", err)
	}

	b.p11ctx = p11ctx
	b.session = session

	// Detect firmware version for feature capability checks
	if err := b.detectFirmwareVersion(); err != nil {
		// Non-fatal - continue with unknown version
		b.firmwareVer = &FirmwareVersion{Major: 5, Minor: 0, Patch: 0}
	}

	b.initialized = true

	return nil
}

// detectFirmwareVersion attempts to detect the YubiKey firmware version
func (b *Backend) detectFirmwareVersion() error {
	// Query token info to get firmware version
	tokenInfo, err := b.p11ctx.GetTokenInfo(b.slotID)
	if err != nil {
		return fmt.Errorf("failed to get token info: %w", err)
	}

	// Parse firmware version from token info
	// YubiKey encodes firmware version in a special way:
	// - Major is straightforward (e.g., 5)
	// - Minor encodes both minor and patch: Minor = (minor * 10) + patch
	//   For example, firmware 5.4.3 is encoded as Major=5, Minor=43
	major := tokenInfo.FirmwareVersion.Major
	minorEncoded := tokenInfo.FirmwareVersion.Minor

	// Decode minor and patch
	var minor, patch uint8
	if minorEncoded >= 10 {
		minor = minorEncoded / 10
		patch = minorEncoded % 10
	} else {
		minor = minorEncoded
		patch = 0
	}

	b.firmwareVer = &FirmwareVersion{
		Major: major,
		Minor: minor,
		Patch: patch,
	}

	return nil
}

// SupportsRSA3072 returns true if the YubiKey supports RSA 3072-bit keys
// Requires firmware 5.7+ according to Yubico documentation
func (b *Backend) SupportsRSA3072() bool {
	if b.firmwareVer == nil {
		return false
	}
	return b.firmwareVer.Major > 5 || (b.firmwareVer.Major == 5 && b.firmwareVer.Minor >= 7)
}

// SupportsRSA4096 returns true if the YubiKey supports RSA 4096-bit keys
// Requires firmware 5.7+ according to Yubico documentation
func (b *Backend) SupportsRSA4096() bool {
	if b.firmwareVer == nil {
		return false
	}
	return b.firmwareVer.Major > 5 || (b.firmwareVer.Major == 5 && b.firmwareVer.Minor >= 7)
}

// SupportsEd25519 returns true if the YubiKey supports Ed25519 keys
func (b *Backend) SupportsEd25519() bool {
	if b.firmwareVer == nil {
		return false
	}
	return b.firmwareVer.Major > 5 || (b.firmwareVer.Major == 5 && b.firmwareVer.Minor >= 7)
}

// SupportsX25519 returns true if the YubiKey supports X25519 keys
func (b *Backend) SupportsX25519() bool {
	if b.firmwareVer == nil {
		return false
	}
	return b.firmwareVer.Major > 5 || (b.firmwareVer.Major == 5 && b.firmwareVer.Minor >= 7)
}

// SupportsAES returns true if the YubiKey supports AES symmetric encryption
func (b *Backend) SupportsAES() bool {
	if b.firmwareVer == nil {
		return false
	}
	return b.firmwareVer.Major > 5 || (b.firmwareVer.Major == 5 && b.firmwareVer.Minor >= 4)
}

// GetFirmwareVersion returns the YubiKey firmware version
func (b *Backend) GetFirmwareVersion() *FirmwareVersion {
	return b.firmwareVer
}

// GenerateRandom generates cryptographically secure random bytes using the YubiKey's
// hardware random number generator. This provides true hardware entropy.
//
// The YubiKey uses NIST-certified RNG sources providing high-quality randomness
// suitable for cryptographic key generation, nonces, IVs, and other security-critical
// random values.
//
// Parameters:
//   - length: Number of random bytes to generate (max 1024 per call recommended)
//
// Returns random bytes or an error if the YubiKey RNG is unavailable.
func (b *Backend) GenerateRandom(length int) ([]byte, error) {
	if !b.initialized {
		return nil, fmt.Errorf("yubikey: backend not initialized")
	}

	if length <= 0 {
		return nil, fmt.Errorf("yubikey: invalid length %d, must be > 0", length)
	}

	// YubiKey PKCS#11 has limits on single RNG calls
	// Recommended max is 1024 bytes per call
	if length > 1024 {
		return nil, fmt.Errorf("yubikey: length %d exceeds maximum 1024 bytes per call", length)
	}

	// Use PKCS#11 C_GenerateRandom
	randomBytes, err := b.p11ctx.GenerateRandom(b.session, length)
	if err != nil {
		return nil, fmt.Errorf("yubikey: failed to generate random bytes: %w", err)
	}

	return randomBytes, nil
}

// Close closes the YubiKey backend and releases resources
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
	return "yubikey"
}

// Capabilities returns the backend capabilities
func (b *Backend) Capabilities() types.Capabilities {
	return types.Capabilities{
		Keys:                true,
		HardwareBacked:      true,
		Signing:             true,
		Decryption:          true,
		SymmetricEncryption: false, // YubiKey PIV doesn't support symmetric encryption directly
		Import:              false, // YubiKey keys are non-exportable (can't import wrapped keys)
		Export:              false, // YubiKey keys are non-exportable
	}
}

// ensureInitialized checks if the backend is initialized
func (b *Backend) ensureInitialized() error {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if !b.initialized {
		return fmt.Errorf("yubikey: backend not initialized")
	}
	return nil
}

// GenerateKey generates a key pair on the YubiKey with management key authentication
func (b *Backend) GenerateKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	if err := b.ensureInitialized(); err != nil {
		return nil, err
	}

	if b.config.Slot == nil {
		return nil, fmt.Errorf("yubikey: PIV slot must be specified in config")
	}

	// YubiKey PIV key generation requires:
	// 1. Management key authentication (CKU_SO)
	// 2. Direct C_GenerateKeyPair call with proper templates
	// We can't delegate to crypto11 because it uses its own session

	b.mu.Lock()
	defer b.mu.Unlock()

	// Map PIV slot to CKA_ID (same mapping used in PKCS#11 backend)
	var ckaid byte
	switch *b.config.Slot {
	case 0x9a:
		ckaid = 0x01
	case 0x9c:
		ckaid = 0x02
	case 0x9d:
		ckaid = 0x03
	case 0x9e:
		ckaid = 0x04
	case 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b,
		0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95:
		ckaid = byte(*b.config.Slot - 0x82 + 0x05)
	default:
		ckaid = byte(*b.config.Slot)
	}

	// PKCS#11 login states are per-slot, not per-session
	// We must logout from user session before logging in as SO
	err := b.p11ctx.Logout(b.session)
	if err != nil && err != pkcs11lib.Error(pkcs11lib.CKR_USER_NOT_LOGGED_IN) {
		return nil, fmt.Errorf("yubikey: failed to logout from user session: %w", err)
	}

	// Create a separate session for SO (management key) operations
	soSession, err := b.p11ctx.OpenSession(b.slotID, pkcs11lib.CKF_SERIAL_SESSION|pkcs11lib.CKF_RW_SESSION)
	if err != nil {
		return nil, fmt.Errorf("yubikey: failed to open SO session: %w", err)
	}
	defer b.p11ctx.CloseSession(soSession)

	// Login with management key for key generation
	// YubiKey PIV: The SO's PIN is the management key
	// Try hex-encoded format first (some PKCS#11 implementations expect this)
	mgmtKeyHex := fmt.Sprintf("%x", b.config.ManagementKey)
	err = b.p11ctx.Login(soSession, pkcs11lib.CKU_SO, mgmtKeyHex)
	if err != nil {
		// Re-login with PIN on original session if SO login fails
		b.p11ctx.Login(b.session, pkcs11lib.CKU_USER, b.config.PIN)
		return nil, fmt.Errorf("yubikey: management key authentication failed (hex format): %w", err)
	}

	// Ensure we logout from SO and re-login as user
	defer func() {
		b.p11ctx.Logout(soSession)
		b.p11ctx.Login(b.session, pkcs11lib.CKU_USER, b.config.PIN)
	}()

	// Use the SO session for key generation
	savedSession := b.session
	b.session = soSession
	defer func() {
		b.session = savedSession
	}()

	// Generate key based on algorithm
	switch attrs.KeyAlgorithm {
	case x509.RSA:
		return b.generateRSAKeyPair(attrs, []byte{ckaid})
	case x509.ECDSA:
		return b.generateECDSAKeyPair(attrs, []byte{ckaid})
	default:
		return nil, fmt.Errorf("yubikey: unsupported key algorithm: %v", attrs.KeyAlgorithm)
	}
}

// generateRSAKeyPair generates an RSA key pair using direct PKCS#11 calls
func (b *Backend) generateRSAKeyPair(attrs *types.KeyAttributes, ckaid []byte) (crypto.PrivateKey, error) {
	keySize := 2048
	if attrs.RSAAttributes != nil && attrs.RSAAttributes.KeySize > 0 {
		keySize = attrs.RSAAttributes.KeySize
	}

	// Check firmware version for larger key sizes
	if keySize == 3072 && !b.SupportsRSA3072() {
		return nil, fmt.Errorf("yubikey: RSA 3072 requires firmware 5.7+, have %d.%d",
			b.firmwareVer.Major, b.firmwareVer.Minor)
	}
	if keySize == 4096 && !b.SupportsRSA4096() {
		return nil, fmt.Errorf("yubikey: RSA 4096 requires firmware 5.7+, have %d.%d",
			b.firmwareVer.Major, b.firmwareVer.Minor)
	}

	// Validate key size
	switch keySize {
	case 1024, 2048, 3072, 4096:
		// Valid sizes
	default:
		return nil, fmt.Errorf("yubikey: invalid RSA key size: %d (must be 1024, 2048, 3072, or 4096)", keySize)
	}

	label := attrs.CN
	if label == "" {
		label = "yubikey-rsa-key"
	}

	// Public key template - YubiKey PIV minimal attributes
	publicKeyTemplate := []*pkcs11lib.Attribute{
		pkcs11lib.NewAttribute(pkcs11lib.CKA_ID, ckaid),
		pkcs11lib.NewAttribute(pkcs11lib.CKA_LABEL, label),
		pkcs11lib.NewAttribute(pkcs11lib.CKA_MODULUS_BITS, keySize),
		pkcs11lib.NewAttribute(pkcs11lib.CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}), // 65537
	}

	// Private key template - YubiKey PIV minimal attributes
	privateKeyTemplate := []*pkcs11lib.Attribute{
		pkcs11lib.NewAttribute(pkcs11lib.CKA_ID, ckaid),
		pkcs11lib.NewAttribute(pkcs11lib.CKA_LABEL, label),
		pkcs11lib.NewAttribute(pkcs11lib.CKA_SENSITIVE, true),
		pkcs11lib.NewAttribute(pkcs11lib.CKA_SIGN, true),
	}

	// Generate key pair
	mechanism := []*pkcs11lib.Mechanism{pkcs11lib.NewMechanism(pkcs11lib.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)}
	pubHandle, privHandle, err := b.p11ctx.GenerateKeyPair(
		b.session,
		mechanism,
		publicKeyTemplate,
		privateKeyTemplate,
	)
	if err != nil {
		return nil, fmt.Errorf("yubikey: RSA key generation failed: %w", err)
	}

	// Return a signer that uses the PKCS#11 backend (which now has the key)
	// The key was generated on our session, but the PKCS#11 backend can find it by CKA_ID
	_ = pubHandle
	_ = privHandle
	return b.pkcs11.GetKey(attrs)
}

// generateECDSAKeyPair generates an ECDSA key pair using direct PKCS#11 calls
func (b *Backend) generateECDSAKeyPair(attrs *types.KeyAttributes, ckaid []byte) (crypto.PrivateKey, error) {
	if attrs.ECCAttributes == nil || attrs.ECCAttributes.Curve == nil {
		return nil, fmt.Errorf("yubikey: ECC curve is required")
	}

	// Map curve to PKCS#11 OID
	var curve []byte
	switch attrs.ECCAttributes.Curve.Params().Name {
	case "P-256":
		curve = []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}
	case "P-384":
		curve = []byte{0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22}
	case "P-521":
		return nil, fmt.Errorf("yubikey: P-521 not supported by YubiKey PIV")
	default:
		return nil, fmt.Errorf("yubikey: unsupported curve: %s", attrs.ECCAttributes.Curve.Params().Name)
	}

	label := attrs.CN
	if label == "" {
		label = "yubikey-ecdsa-key"
	}

	// Public key template - YubiKey PIV minimal attributes
	publicKeyTemplate := []*pkcs11lib.Attribute{
		pkcs11lib.NewAttribute(pkcs11lib.CKA_ID, ckaid),
		pkcs11lib.NewAttribute(pkcs11lib.CKA_LABEL, label),
		pkcs11lib.NewAttribute(pkcs11lib.CKA_EC_PARAMS, curve),
	}

	// Private key template - YubiKey PIV minimal attributes
	privateKeyTemplate := []*pkcs11lib.Attribute{
		pkcs11lib.NewAttribute(pkcs11lib.CKA_ID, ckaid),
		pkcs11lib.NewAttribute(pkcs11lib.CKA_LABEL, label),
		pkcs11lib.NewAttribute(pkcs11lib.CKA_SENSITIVE, true),
		pkcs11lib.NewAttribute(pkcs11lib.CKA_SIGN, true),
	}

	// Generate key pair
	mechanism := []*pkcs11lib.Mechanism{pkcs11lib.NewMechanism(pkcs11lib.CKM_EC_KEY_PAIR_GEN, nil)}
	pubHandle, privHandle, err := b.p11ctx.GenerateKeyPair(
		b.session,
		mechanism,
		publicKeyTemplate,
		privateKeyTemplate,
	)
	if err != nil {
		return nil, fmt.Errorf("yubikey: ECDSA key generation failed: %w", err)
	}

	// Return a signer that uses the PKCS#11 backend (which now has the key)
	_ = pubHandle
	_ = privHandle
	return b.pkcs11.GetKey(attrs)
}

// GetKey retrieves a key from the YubiKey
func (b *Backend) GetKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	if err := b.ensureInitialized(); err != nil {
		return nil, err
	}

	return b.pkcs11.GetKey(attrs)
}

// DeleteKey deletes a key from the YubiKey
func (b *Backend) DeleteKey(attrs *types.KeyAttributes) error {
	if err := b.ensureInitialized(); err != nil {
		return err
	}

	return b.pkcs11.DeleteKey(attrs)
}

// ListKeys returns a list of all keys stored on the YubiKey
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

// RotateKey rotates a key on the YubiKey
func (b *Backend) RotateKey(attrs *types.KeyAttributes) error {
	if err := b.ensureInitialized(); err != nil {
		return err
	}

	return b.pkcs11.RotateKey(attrs)
}

// AvailableSlots returns a list of available PIV slots on the YubiKey
func (b *Backend) AvailableSlots() ([]PIVSlot, error) {
	if err := b.ensureInitialized(); err != nil {
		return nil, err
	}

	// Return all valid PIV slots
	return AllSlots(), nil
}

// GenerateRSA generates an RSA key pair on the YubiKey
// This is a convenience method that wraps GenerateKey
func (b *Backend) GenerateRSA(attrs *types.KeyAttributes) (crypto.Signer, error) {
	attrs.KeyAlgorithm = x509.RSA
	key, err := b.GenerateKey(attrs)
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("yubikey: generated key does not implement crypto.Signer")
	}
	return signer, nil
}

// GenerateECDSA generates an ECDSA key pair on the YubiKey
// This is a convenience method that wraps GenerateKey
func (b *Backend) GenerateECDSA(attrs *types.KeyAttributes) (crypto.Signer, error) {
	attrs.KeyAlgorithm = x509.ECDSA
	key, err := b.GenerateKey(attrs)
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("yubikey: generated key does not implement crypto.Signer")
	}
	return signer, nil
}

// GenerateEd25519 generates an Ed25519 key pair on the YubiKey
// This is a convenience method that wraps GenerateKey
func (b *Backend) GenerateEd25519(attrs *types.KeyAttributes) (crypto.Signer, error) {
	attrs.KeyAlgorithm = x509.Ed25519
	key, err := b.GenerateKey(attrs)
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("yubikey: generated key does not implement crypto.Signer")
	}
	return signer, nil
}
