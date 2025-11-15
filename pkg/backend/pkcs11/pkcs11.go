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

package pkcs11

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io"
	"sync"

	"github.com/ThalesGroup/crypto11"
	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/miekg/pkcs11"
)

// PKCS#11 v3.0 Edwards curve constants
// These are defined in PKCS#11 v3.0 specification but may not be in older versions of miekg/pkcs11
const (
	CKK_EC_EDWARDS              = 0x00000040 // Edwards curve key type
	CKM_EC_EDWARDS_KEY_PAIR_GEN = 0x00001055 // Edwards curve key pair generation mechanism
	CKM_EDDSA                   = 0x00001057 // EdDSA signature mechanism
)

// contextRef tracks reference count for a cached context
type contextRef struct {
	ctx      *crypto11.Context
	refCount int
}

// contextCache stores PKCS#11 contexts keyed by library path and token label.
// This prevents multiple initializations of the same PKCS#11 token.
var (
	contextCache   = make(map[string]*contextRef)
	contextCacheMu sync.RWMutex
)

// Backend implements the types.Backend interface for PKCS#11 hardware security modules.
// It provides secure key storage where private keys never leave the HSM hardware.
//
// The backend uses the crypto11 library for high-level PKCS#11 operations and maintains
// a context cache to prevent re-initialization of the same token across multiple instances.
//
// Thread Safety:
// All operations are protected by read-write mutexes, making the backend safe for
// concurrent access from multiple goroutines.
//
// HSM Support:
// - SoftHSM (software HSM for testing)
// - YubiKey HSM
// - Thales nShield
// - Any PKCS#11 compatible HSM
type Backend struct {
	config  *Config
	ctx     *crypto11.Context
	p11ctx  *pkcs11.Ctx
	ownsCtx bool // tracks if this backend owns the context (not from cache)
	tracker types.AEADSafetyTracker
	mu      sync.RWMutex
	types.Backend
}

// NewBackend creates a new PKCS#11 backend instance.
// It validates the configuration but does not initialize the PKCS#11 context.
// Call Initialize() to set up the HSM token and Login() to authenticate.
//
// Parameters:
//   - config: PKCS#11 configuration including library path, token label, and PINs
//
// Returns an error if the configuration is invalid.
func NewBackend(config *Config) (*Backend, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	// Initialize tracker
	tracker := config.Tracker
	if tracker == nil {
		tracker = backend.NewMemoryAEADTracker()
	}

	return &Backend{
		config:  config,
		tracker: tracker,
	}, nil
}

// Type returns the backend type (PKCS#11).
func (b *Backend) Type() types.BackendType {
	return backend.BackendTypePKCS11
}

// Config returns the PKCS#11 configuration.
func (b *Backend) Config() *Config {
	return b.config
}

// Capabilities returns the capabilities of this backend.
// PKCS#11 is a hardware-backed security module interface.
func (b *Backend) Capabilities() types.Capabilities {
	caps := types.NewHardwareCapabilities()
	caps.SymmetricEncryption = true
	caps.Import = true // PKCS#11 supports key import
	caps.Export = true // PKCS#11 supports key export (if CKA_EXTRACTABLE=true)
	return caps
}

// Get retrieves a key handle from the PKCS#11 backend by CN.
// This returns the public key material, as private keys cannot be exported from HSM.
//
// Note: For PKCS#11, use the Signer() method to perform operations with keys.
// Direct private key material retrieval is not possible for security.
func (b *Backend) Get(attrs *types.KeyAttributes, extension types.FSExtension) ([]byte, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.ctx == nil {
		return nil, ErrNotInitialized
	}

	// Find the key pair
	id := []byte(createKeyID(attrs))
	signer, err := b.ctx.FindKeyPair(id, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to find key: %w", err)
	}
	if signer == nil {
		return nil, fmt.Errorf("%w: %s", backend.ErrKeyNotFound, attrs.CN)
	}

	// For PKCS#11, we can only return public key
	// Private key material never leaves the HSM
	return nil, fmt.Errorf("%w: PKCS#11 private keys cannot be exported", backend.ErrNotSupported)
}

// Save stores key metadata to the PKCS#11 backend.
// Note: This doesn't store the actual key material - keys are created via GenerateKey methods
// and live only within the HSM.
//
// This method can be used to store associated metadata if needed.
func (b *Backend) Save(attrs *types.KeyAttributes, data []byte, extension types.FSExtension, overwrite bool) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.ctx == nil {
		return ErrNotInitialized
	}

	// For PKCS#11, saving key material directly is not supported
	// Keys must be generated on the HSM using GenerateRSA/GenerateECDSA
	return fmt.Errorf("%w: use GenerateKey methods to create keys on HSM", backend.ErrNotSupported)
}

// DeleteKey removes a key from the PKCS#11 backend.
// This finds the key object and destroys it using the low-level PKCS#11 API.
//
// Note: Some HSMs may not support key deletion or may require special permissions.
// The behavior depends on the specific HSM and its configuration.
func (b *Backend) DeleteKey(attrs *types.KeyAttributes) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.ctx == nil {
		return ErrNotInitialized
	}

	// Initialize p11ctx if needed
	if b.p11ctx == nil {
		p := pkcs11.New(b.config.Library)
		if p == nil {
			return fmt.Errorf("failed to load PKCS#11 library: %s", b.config.Library)
		}
		if err := p.Initialize(); err != nil {
			if err != pkcs11.Error(pkcs11.CKR_CRYPTOKI_ALREADY_INITIALIZED) {
				return fmt.Errorf("failed to initialize PKCS#11: %w", err)
			}
		}
		b.p11ctx = p
	}

	// Get slot list
	slots, err := b.p11ctx.GetSlotList(true)
	if err != nil {
		return fmt.Errorf("failed to get slot list: %w", err)
	}
	if len(slots) == 0 {
		return fmt.Errorf("no slots available")
	}

	// Use first available slot or configured slot
	var slot uint
	if b.config.Slot != nil {
		slot = uint(*b.config.Slot)
	} else {
		slot = slots[0]
	}

	// Open session
	session, err := b.p11ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return fmt.Errorf("failed to open session for key deletion: %w", err)
	}
	defer b.p11ctx.CloseSession(session)

	// Login if not already logged in
	// Note: We don't logout because C_Logout affects ALL sessions, not just this one
	if b.config.PIN != "" {
		if err := b.p11ctx.Login(session, pkcs11.CKU_USER, b.config.PIN); err != nil {
			if err != pkcs11.Error(pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
				return fmt.Errorf("failed to login for key deletion: %w", err)
			}
		}
		// DO NOT LOGOUT - it would logout from all sessions including crypto11's session
	}

	// Create label for finding objects
	label := createKeyID(attrs)

	// Find and delete private key
	privateTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}

	if err := b.p11ctx.FindObjectsInit(session, privateTemplate); err != nil {
		return fmt.Errorf("failed to init find private key: %w", err)
	}

	privObjs, _, err := b.p11ctx.FindObjects(session, 10)
	if err != nil {
		b.p11ctx.FindObjectsFinal(session)
		return fmt.Errorf("failed to find private key: %w", err)
	}

	if err := b.p11ctx.FindObjectsFinal(session); err != nil {
		return fmt.Errorf("failed to finalize find private key: %w", err)
	}

	// Delete all matching private keys
	for _, obj := range privObjs {
		if err := b.p11ctx.DestroyObject(session, obj); err != nil {
			return fmt.Errorf("failed to destroy private key: %w", err)
		}
	}

	// Find and delete public key
	publicTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}

	if err := b.p11ctx.FindObjectsInit(session, publicTemplate); err != nil {
		return fmt.Errorf("failed to init find public key: %w", err)
	}

	pubObjs, _, err := b.p11ctx.FindObjects(session, 10)
	if err != nil {
		b.p11ctx.FindObjectsFinal(session)
		return fmt.Errorf("failed to find public key: %w", err)
	}

	if err := b.p11ctx.FindObjectsFinal(session); err != nil {
		return fmt.Errorf("failed to finalize find public key: %w", err)
	}

	// Delete all matching public keys
	for _, obj := range pubObjs {
		if err := b.p11ctx.DestroyObject(session, obj); err != nil {
			return fmt.Errorf("failed to destroy public key: %w", err)
		}
	}

	if len(privObjs) == 0 && len(pubObjs) == 0 {
		return fmt.Errorf("%w: %s", backend.ErrKeyNotFound, attrs.CN)
	}

	return nil
}

// Delete removes a key from the PKCS#11 backend.
// This is an alias for DeleteKey to satisfy the Storage interface.
func (b *Backend) Delete(attrs *types.KeyAttributes) error {
	return b.DeleteKey(attrs)
}

// ListKeys returns attributes for all keys managed by this backend.
// Note: This is a placeholder implementation. Full implementation would require
// enumerating all key objects in the PKCS#11 token using FindObjects.
func (b *Backend) ListKeys() ([]*types.KeyAttributes, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.ctx == nil {
		return nil, ErrNotInitialized
	}

	// This would require using the low-level PKCS#11 API to enumerate objects
	// For now, return an empty list
	return []*types.KeyAttributes{}, nil
}

// Decrypter returns a crypto.Decrypter for the specified key.
// This allows the key to be used for decryption operations without
// exposing the private key material.
func (b *Backend) Decrypter(attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	// For PKCS#11, decryption is handled through the HSM
	// The crypto11 library doesn't expose a direct Decrypter interface,
	// but RSA keys returned by FindKeyPair may implement crypto.Decrypter
	signer, err := b.Signer(attrs)
	if err != nil {
		return nil, err
	}

	// Check if the signer also implements crypto.Decrypter
	if decrypter, ok := signer.(crypto.Decrypter); ok {
		return decrypter, nil
	}

	return nil, fmt.Errorf("%w: key does not support decryption", backend.ErrOperationNotSupported)
}

// RotateKey rotates/updates a key identified by attrs.
// For PKCS#11, this is not typically supported as keys are managed on the HSM.
func (b *Backend) RotateKey(attrs *types.KeyAttributes) error {
	return fmt.Errorf("%w: key rotation not supported for PKCS#11", backend.ErrOperationNotSupported)
}

// GenerateRandom generates cryptographically secure random bytes using the HSM's
// hardware random number generator. This provides true hardware entropy from the PKCS#11 device.
//
// Parameters:
//   - length: Number of random bytes to generate (must be > 0)
//
// Returns the random bytes or an error if generation fails.
//
// Note: Some PKCS#11 devices have limits on the maximum number of bytes that can
// be generated in a single call. If you need more than 1024 bytes, consider making
// multiple calls.
func (b *Backend) GenerateRandom(length int) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.ctx == nil {
		return nil, ErrNotInitialized
	}

	if length <= 0 {
		return nil, fmt.Errorf("pkcs11: invalid length %d, must be > 0", length)
	}

	// Initialize p11ctx if needed
	if b.p11ctx == nil {
		p := pkcs11.New(b.config.Library)
		if p == nil {
			return nil, fmt.Errorf("pkcs11: failed to load PKCS#11 library: %s", b.config.Library)
		}
		if err := p.Initialize(); err != nil {
			if err != pkcs11.Error(pkcs11.CKR_CRYPTOKI_ALREADY_INITIALIZED) {
				return nil, fmt.Errorf("pkcs11: failed to initialize PKCS#11: %w", err)
			}
		}
		b.p11ctx = p
	}

	// Get slot list to find the slot we're using
	slots, err := b.p11ctx.GetSlotList(true)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: failed to get slot list: %w", err)
	}
	if len(slots) == 0 {
		return nil, fmt.Errorf("pkcs11: no slots available")
	}

	// Use first available slot or configured slot
	var slot uint
	if b.config.Slot != nil {
		slot = uint(*b.config.Slot)
	} else {
		slot = slots[0]
	}

	// Open session for random generation
	session, err := b.p11ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: failed to open session for random generation: %w", err)
	}
	defer b.p11ctx.CloseSession(session)

	// Login if not already logged in
	// Note: We don't logout because C_Logout affects ALL sessions, not just this one
	if b.config.PIN != "" {
		if err := b.p11ctx.Login(session, pkcs11.CKU_USER, b.config.PIN); err != nil {
			// Ignore already logged in error - backend is already authenticated
			if err != pkcs11.Error(pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
				return nil, fmt.Errorf("pkcs11: failed to login for random generation: %w", err)
			}
		}
		// DO NOT LOGOUT - it would logout from all sessions including crypto11's session
	}

	// Use PKCS#11 C_GenerateRandom
	randomBytes, err := b.p11ctx.GenerateRandom(session, length)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: failed to generate random bytes: %w", err)
	}

	return randomBytes, nil
}

// Close releases the PKCS#11 context and any associated resources.
// This method is idempotent and can be called multiple times safely.
// It uses reference counting for cached contexts to prevent premature closure
// when multiple backend instances share the same context.
func (b *Backend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Recover from potential panics in crypto11 Close()
	defer func() {
		if r := recover(); r != nil {
			b.ctx = nil
		}
	}()

	if b.ctx != nil {
		cacheKey := contextCacheKey(b.config)

		contextCacheMu.Lock()
		if ref, exists := contextCache[cacheKey]; exists {
			// Decrement reference count
			ref.refCount--
			if ref.refCount <= 0 {
				// Last reference - close the context and remove from cache
				delete(contextCache, cacheKey)
				contextCacheMu.Unlock()

				if err := b.ctx.Close(); err != nil {
					b.ctx = nil
					return fmt.Errorf("failed to close PKCS#11 context: %w", err)
				}
			} else {
				// Other backends still using this context
				contextCacheMu.Unlock()
			}
		} else {
			contextCacheMu.Unlock()
			// Context not in cache, close directly if we own it
			if b.ownsCtx {
				if err := b.ctx.Close(); err != nil {
					b.ctx = nil
					return fmt.Errorf("failed to close PKCS#11 context: %w", err)
				}
			}
		}
		b.ctx = nil
	}

	if b.p11ctx != nil {
		b.p11ctx.Destroy()
		b.p11ctx.Finalize()
		b.p11ctx = nil
	}

	return nil
}

// Initialize sets up the PKCS#11 token with the provided SO PIN and user PIN.
// This is typically done once during initial token setup.
//
// For SoftHSM, this will automatically configure and initialize the token.
// For hardware HSMs, ensure the token is properly set up before calling this method.
//
// Parameters:
//   - soPIN: Security Officer PIN (administrative)
//   - userPIN: User PIN (for normal operations)
//
// Returns ErrAlreadyInitialized if the token is already initialized.
func (b *Backend) Initialize(soPIN, userPIN string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Validate PIN lengths
	if len(soPIN) < 4 {
		return ErrInvalidSOPINLength
	}
	if len(userPIN) < 4 {
		return ErrInvalidPINLength
	}

	b.config.SOPIN = soPIN
	b.config.PIN = userPIN

	// Check if already in cache
	cacheKey := contextCacheKey(b.config)
	contextCacheMu.RLock()
	if ref, exists := contextCache[cacheKey]; exists {
		contextCacheMu.RUnlock()
		b.ctx = ref.ctx
		// Increment reference count
		contextCacheMu.Lock()
		ref.refCount++
		contextCacheMu.Unlock()
		return ErrAlreadyInitialized
	}
	contextCacheMu.RUnlock()

	// Initialize token using low-level PKCS#11
	if err := b.initializeToken(soPIN, userPIN); err != nil {
		// If already initialized, that's okay
		if err != ErrAlreadyInitialized {
			return fmt.Errorf("failed to initialize token: %w", err)
		}
	}

	// Login to establish context
	return b.loginUser(userPIN)
}

// Login authenticates with the PKCS#11 token using the user PIN.
// This must be called before performing cryptographic operations.
//
// The method uses a cached context if available to avoid re-initialization.
//
// Returns an error if login fails or if the token is not initialized.
func (b *Backend) Login() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.config.PIN == "" {
		return ErrInvalidUserPIN
	}

	return b.loginUser(b.config.PIN)
}

// loginUser performs the actual login to the PKCS#11 token.
// Must be called with mutex held.
func (b *Backend) loginUser(pin string) error {
	// Check cache first
	cacheKey := contextCacheKey(b.config)
	contextCacheMu.Lock()
	if ref, exists := contextCache[cacheKey]; exists {
		// Use cached context and increment reference count
		b.ctx = ref.ctx
		b.ownsCtx = false
		ref.refCount++
		contextCacheMu.Unlock()
		return nil
	}

	// Create new context
	ctx, err := crypto11.Configure(&crypto11.Config{
		Path:       b.config.Library,
		TokenLabel: b.config.TokenLabel,
		Pin:        pin,
	})
	if err != nil {
		contextCacheMu.Unlock()
		return fmt.Errorf("failed to configure PKCS#11 context: %w", err)
	}

	b.ctx = ctx
	b.ownsCtx = false // Will be cached, so not owned by this backend

	// Cache the context with reference count of 1
	contextCache[cacheKey] = &contextRef{
		ctx:      ctx,
		refCount: 1,
	}
	contextCacheMu.Unlock()

	return nil
}

// initializeToken initializes a PKCS#11 token with SO and user PINs.
// Must be called with mutex held.
func (b *Backend) initializeToken(soPIN, userPIN string) error {
	// Initialize low-level PKCS#11 context
	p := pkcs11.New(b.config.Library)
	if p == nil {
		return fmt.Errorf("failed to load PKCS#11 library: %s", b.config.Library)
	}

	if err := p.Initialize(); err != nil {
		// Check if already initialized
		if err == pkcs11.Error(pkcs11.CKR_CRYPTOKI_ALREADY_INITIALIZED) {
			p.Destroy()
			return ErrAlreadyInitialized
		}
		p.Destroy()
		return fmt.Errorf("failed to initialize PKCS#11: %w", err)
	}

	defer p.Destroy()
	defer p.Finalize()

	// Get token slot
	slots, err := p.GetSlotList(true)
	if err != nil {
		return fmt.Errorf("failed to get slot list: %w", err)
	}

	if len(slots) == 0 {
		return ErrTokenNotFound
	}

	slot := slots[0]
	if b.config.Slot != nil {
		slot = uint(*b.config.Slot)
	}

	// Get token info to check initialization status
	tokenInfo, err := p.GetTokenInfo(slot)
	if err != nil {
		return fmt.Errorf("failed to get token info: %w", err)
	}

	// Check if token needs initialization
	if tokenInfo.Flags&pkcs11.CKF_TOKEN_INITIALIZED == 0 {
		// Initialize token
		if err := p.InitToken(slot, soPIN, b.config.TokenLabel); err != nil {
			return fmt.Errorf("failed to init token: %w", err)
		}

		// Open session and init user PIN
		session, err := p.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
		if err != nil {
			return fmt.Errorf("failed to open session: %w", err)
		}
		defer p.CloseSession(session)

		// Login as SO
		if err := p.Login(session, pkcs11.CKU_SO, soPIN); err != nil {
			return fmt.Errorf("failed to login as SO: %w", err)
		}
		defer p.Logout(session)

		// Initialize user PIN
		if err := p.InitPIN(session, userPIN); err != nil {
			return fmt.Errorf("failed to init user PIN: %w", err)
		}
	} else {
		return ErrAlreadyInitialized
	}

	return nil
}

// GenerateKey dispatches key generation to the appropriate algorithm-specific method.
func (b *Backend) GenerateKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	switch attrs.KeyAlgorithm {
	case x509.RSA:
		return b.GenerateRSA(attrs)
	case x509.ECDSA:
		return b.GenerateECDSA(attrs)
	case x509.Ed25519:
		return b.GenerateEd25519(attrs)
	default:
		return nil, fmt.Errorf("%w: %s", backend.ErrInvalidAlgorithm, attrs.KeyAlgorithm)
	}
}

// GenerateRSA creates an RSA key pair on the HSM with the specified key size.
// The private key never leaves the HSM hardware.
//
// Parameters:
//   - attrs: Key attributes (CN, key type, algorithm, etc.)
//   - keySize: RSA key size in bits (e.g., 2048, 3072, 4096)
//
// Default key size is 2048 bits if keySize is 0 or invalid.
func (b *Backend) GenerateRSAWithSize(attrs *types.KeyAttributes, keySize int) (crypto.Signer, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.ctx == nil {
		return nil, ErrNotInitialized
	}

	// Apply default key size if not specified or invalid
	if keySize == 0 || keySize < 512 {
		keySize = 2048
	}

	// Generate key ID: use YubiKey PIV slot mapping or standard PKCS#11 formatted ID
	var id []byte
	if b.config.IsYubiKeyPIV() && b.config.Slot != nil {
		// YubiKey PIV mode: use PIV slot to CKA_ID mapping
		id = createSlotID(uint(*b.config.Slot))
	} else {
		// Standard PKCS#11 mode: use formatted string ID
		id = []byte(createKeyID(attrs))
	}

	signer, err := b.ctx.GenerateRSAKeyPairWithLabel(id, id, keySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	return signer, nil
}

// GenerateRSA creates an RSA key pair on the HSM with default 2048-bit key size.
// The private key never leaves the HSM hardware.
//
// For custom key sizes, use GenerateRSAWithSize instead.
func (b *Backend) GenerateRSA(attrs *types.KeyAttributes) (crypto.Signer, error) {
	// Extract key size from attributes, default to 2048 if not specified
	keySize := 2048
	if attrs.RSAAttributes != nil && attrs.RSAAttributes.KeySize > 0 {
		keySize = attrs.RSAAttributes.KeySize
	}
	return b.GenerateRSAWithSize(attrs, keySize)
}

// GenerateECDSAWithCurve creates an ECDSA key pair on the HSM with the specified curve.
// The private key never leaves the HSM hardware.
//
// Parameters:
//   - attrs: Key attributes (CN, key type, algorithm, etc.)
//   - curve: Elliptic curve (e.g., P-256, P-384, P-521)
//
// Default curve is P-256 if curve is nil.
func (b *Backend) GenerateECDSAWithCurve(attrs *types.KeyAttributes, curve elliptic.Curve) (crypto.Signer, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.ctx == nil {
		return nil, ErrNotInitialized
	}

	// Apply default curve if not specified
	if curve == nil || curve.Params() == nil {
		curve = elliptic.P256()
	}

	// Generate key ID: use YubiKey PIV slot mapping or standard PKCS#11 formatted ID
	var id []byte
	if b.config.IsYubiKeyPIV() && b.config.Slot != nil {
		// YubiKey PIV mode: use PIV slot to CKA_ID mapping
		id = createSlotID(uint(*b.config.Slot))
	} else {
		// Standard PKCS#11 mode: use formatted string ID
		id = []byte(createKeyID(attrs))
	}

	signer, err := b.ctx.GenerateECDSAKeyPairWithLabel(id, id, curve)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ECDSA key: %w", err)
	}

	return signer, nil
}

// GenerateECDSA creates an ECDSA key pair on the HSM with default P-256 curve.
// The private key never leaves the HSM hardware.
//
// For custom curves, use GenerateECDSAWithCurve instead.
func (b *Backend) GenerateECDSA(attrs *types.KeyAttributes) (crypto.Signer, error) {
	// Extract curve from attributes, default to P-256 if not specified
	var curve elliptic.Curve
	if attrs.ECCAttributes != nil && attrs.ECCAttributes.Curve != nil {
		curve = attrs.ECCAttributes.Curve
	} else {
		curve = elliptic.P256()
	}
	return b.GenerateECDSAWithCurve(attrs, curve)
}

// GenerateEd25519 creates an Ed25519 key pair on the HSM.
// The private key never leaves the HSM hardware.
//
// Note: Ed25519 support requires PKCS#11 v3.0 or later and HSM support for Edwards curves.
// SoftHSM v2.6+ supports Ed25519.
func (b *Backend) GenerateEd25519(attrs *types.KeyAttributes) (crypto.Signer, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.ctx == nil {
		return nil, ErrNotInitialized
	}

	// Initialize low-level PKCS#11 context if not already done
	if b.p11ctx == nil {
		p := pkcs11.New(b.config.Library)
		if p == nil {
			return nil, fmt.Errorf("failed to load PKCS#11 library: %s", b.config.Library)
		}
		if err := p.Initialize(); err != nil {
			return nil, fmt.Errorf("failed to initialize PKCS#11: %w", err)
		}
		b.p11ctx = p
	}

	// Get session from crypto11 context
	// We need to access the internal session, which requires using reflection or
	// direct PKCS#11 calls. For now, we'll create a new session.

	// Find the token
	slots, err := b.p11ctx.GetSlotList(true)
	if err != nil {
		return nil, fmt.Errorf("failed to get slot list: %w", err)
	}
	if len(slots) == 0 {
		return nil, fmt.Errorf("no slots available")
	}

	// Use first available slot or configured slot
	var slot uint
	if b.config.Slot != nil {
		slot = uint(*b.config.Slot)
	} else {
		slot = slots[0]
	}

	// Open session
	session, err := b.p11ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nil, fmt.Errorf("failed to open session: %w", err)
	}
	defer b.p11ctx.CloseSession(session)

	// Login if PIN is set
	if b.config.PIN != "" {
		if err := b.p11ctx.Login(session, pkcs11.CKU_USER, b.config.PIN); err != nil {
			// Ignore already logged in error
			if err != pkcs11.Error(pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
				return nil, fmt.Errorf("failed to login: %w", err)
			}
		}
	}

	// Create key ID and label
	id := []byte(createKeyID(attrs))
	label := []byte(attrs.CN)

	// Ed25519 OID (1.3.101.112) - RFC 8410
	ed25519OID := []byte{0x06, 0x03, 0x2b, 0x65, 0x70}

	// Public key template
	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, CKK_EC_EDWARDS),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, ed25519OID),
	}

	// Private key template
	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, CKK_EC_EDWARDS),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
	}

	// Generate key pair
	pubKey, privKey, err := b.p11ctx.GenerateKeyPair(
		session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(CKM_EC_EDWARDS_KEY_PAIR_GEN, nil)},
		publicKeyTemplate,
		privateKeyTemplate,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Ed25519 key pair: %w", err)
	}

	// Create a signer wrapper that uses the PKCS#11 key
	signer := &pkcs11Ed25519Signer{
		backend:        b,
		publicHandle:   pubKey,
		privateHandle:  privKey,
		label:          string(label),
		publicKeyBytes: nil, // Will be populated on first Public() call
	}

	return signer, nil
}

// GenerateSecretKey generates an AES secret key on the HSM.
// The secret key never leaves the HSM hardware and can be used for symmetric
// encryption/decryption operations.
//
// Supported key sizes:
//   - 128 bits (16 bytes) - AES-128
//   - 256 bits (32 bytes) - AES-256
//
// Parameters:
//   - attrs: Key attributes (CN, key type, etc.)
//   - keySize: AES key size in bits (128 or 256)
//
// Returns the object handle of the generated secret key, or an error if generation fails.
func (b *Backend) GenerateSecretKey(attrs *types.KeyAttributes, keySize int) (pkcs11.ObjectHandle, error) {
	// NOTE: Caller must hold b.mu.Lock()
	if b.ctx == nil {
		return 0, ErrNotInitialized
	}

	// Validate key size
	if keySize != 128 && keySize != 256 {
		return 0, fmt.Errorf("%w: AES key size %d bits (only 128 and 256 are supported)", backend.ErrInvalidAlgorithm, keySize)
	}

	// Get session handle from crypto11 context
	// We need to use the low-level PKCS#11 interface to generate secret keys
	// as crypto11 doesn't expose secret key generation

	// Initialize low-level PKCS#11 context if not already done
	if b.p11ctx == nil {
		p := pkcs11.New(b.config.Library)
		if p == nil {
			return 0, fmt.Errorf("failed to load PKCS#11 library: %s", b.config.Library)
		}

		if err := p.Initialize(); err != nil {
			if err != pkcs11.Error(pkcs11.CKR_CRYPTOKI_ALREADY_INITIALIZED) {
				return 0, fmt.Errorf("failed to initialize PKCS#11: %w", err)
			}
		}

		b.p11ctx = p
	}

	// Get token slot
	slots, err := b.p11ctx.GetSlotList(true)
	if err != nil {
		return 0, fmt.Errorf("failed to get slot list: %w", err)
	}

	if len(slots) == 0 {
		return 0, ErrTokenNotFound
	}

	slot := slots[0]
	if b.config.Slot != nil {
		slot = uint(*b.config.Slot)
	}

	// Open session
	session, err := b.p11ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return 0, fmt.Errorf("failed to open session: %w", err)
	}
	defer b.p11ctx.CloseSession(session)

	// Login as user
	// Note: We don't logout because C_Logout affects ALL sessions, not just this one
	if err := b.p11ctx.Login(session, pkcs11.CKU_USER, b.config.PIN); err != nil {
		// Ignore error if already logged in
		if err != pkcs11.Error(pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
			return 0, fmt.Errorf("failed to login: %w", err)
		}
	}
	// DO NOT LOGOUT - it would logout from all sessions including crypto11's session

	// Create key label
	label := createKeyID(attrs)
	valueLenBytes := uint(keySize / 8) // Convert bits to bytes

	// Define secret key template
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(label)),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, valueLenBytes),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
	}

	// Generate secret key using CKM_AES_KEY_GEN mechanism
	mechanism := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_GEN, nil)}
	handle, err := b.p11ctx.GenerateKey(session, mechanism, template)
	if err != nil {
		return 0, fmt.Errorf("failed to generate AES secret key: %w", err)
	}

	return handle, nil
}

// FindSecretKey finds an existing secret key by label.
//
// Parameters:
//   - attrs: Key attributes including the CN to search for
//
// Returns the object handle of the secret key, or an error if not found.
func (b *Backend) FindSecretKey(attrs *types.KeyAttributes) (pkcs11.ObjectHandle, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.ctx == nil {
		return 0, ErrNotInitialized
	}

	// Initialize low-level PKCS#11 context if not already done
	if b.p11ctx == nil {
		p := pkcs11.New(b.config.Library)
		if p == nil {
			return 0, fmt.Errorf("failed to load PKCS#11 library: %s", b.config.Library)
		}

		if err := p.Initialize(); err != nil {
			if err != pkcs11.Error(pkcs11.CKR_CRYPTOKI_ALREADY_INITIALIZED) {
				return 0, fmt.Errorf("failed to initialize PKCS#11: %w", err)
			}
		}

		// Note: Casting to *Backend to modify p11ctx requires Lock, not RLock
		// This is a limitation - caller should use the non-find methods first
		return 0, fmt.Errorf("PKCS#11 context not initialized for secret key operations")
	}

	// Get token slot
	slots, err := b.p11ctx.GetSlotList(true)
	if err != nil {
		return 0, fmt.Errorf("failed to get slot list: %w", err)
	}

	if len(slots) == 0 {
		return 0, ErrTokenNotFound
	}

	slot := slots[0]
	if b.config.Slot != nil {
		slot = uint(*b.config.Slot)
	}

	// Open session
	session, err := b.p11ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION)
	if err != nil {
		return 0, fmt.Errorf("failed to open session: %w", err)
	}
	defer b.p11ctx.CloseSession(session)

	// Login as user
	// Note: We don't logout because C_Logout affects ALL sessions, not just this one
	if err := b.p11ctx.Login(session, pkcs11.CKU_USER, b.config.PIN); err != nil {
		// Ignore error if already logged in
		if err != pkcs11.Error(pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
			return 0, fmt.Errorf("failed to login: %w", err)
		}
	}
	// DO NOT LOGOUT - it would logout from all sessions including crypto11's session

	// Create search template
	label := createKeyID(attrs)
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}

	// Find objects
	if err := b.p11ctx.FindObjectsInit(session, template); err != nil {
		return 0, fmt.Errorf("failed to init object search: %w", err)
	}
	defer b.p11ctx.FindObjectsFinal(session)

	handles, _, err := b.p11ctx.FindObjects(session, 1)
	if err != nil {
		return 0, fmt.Errorf("failed to find objects: %w", err)
	}

	if len(handles) == 0 {
		return 0, fmt.Errorf("%w: %s", backend.ErrKeyNotFound, attrs.CN)
	}

	return handles[0], nil
}

// GetKey retrieves an existing private key by its attributes.
// For PKCS#11, this returns a crypto.Signer that performs operations on the HSM.
// The private key material never leaves the hardware module.
func (b *Backend) GetKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	// Delegate to Signer since PKCS#11 keys are always hardware-backed signers
	return b.Signer(attrs)
}

// GetSignerByID retrieves a crypto.Signer for the specified key by name.
func (b *Backend) GetSignerByID(keyID string) (crypto.Signer, error) {
	attrs := &types.KeyAttributes{
		CN:        keyID,
		KeyType:   backend.KEY_TYPE_SIGNING,
		StoreType: backend.STORE_PKCS11,
	}
	key, err := b.GetKey(attrs)
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("%w: key %s does not implement crypto.Signer", backend.ErrInvalidKeyType, keyID)
	}
	return signer, nil
}

// GetDecrypterByID retrieves a crypto.Decrypter for the specified key by name.
func (b *Backend) GetDecrypterByID(keyID string) (crypto.Decrypter, error) {
	attrs := &types.KeyAttributes{
		CN:        keyID,
		KeyType:   backend.KEY_TYPE_ENCRYPTION,
		StoreType: backend.STORE_PKCS11,
	}
	key, err := b.GetKey(attrs)
	if err != nil {
		return nil, err
	}
	decrypter, ok := key.(crypto.Decrypter)
	if !ok {
		return nil, fmt.Errorf("%w: key %s does not implement crypto.Decrypter", backend.ErrInvalidKeyType, keyID)
	}
	return decrypter, nil
}

// Signer returns a crypto.Signer for the specified key.
// The signer performs operations using the HSM without exposing private key material.
func (b *Backend) Signer(attrs *types.KeyAttributes) (crypto.Signer, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.ctx == nil {
		return nil, ErrNotInitialized
	}

	// Find key ID: use YubiKey PIV slot mapping or standard PKCS#11 formatted ID
	var id []byte
	if b.config.IsYubiKeyPIV() && b.config.Slot != nil {
		// YubiKey PIV mode: use PIV slot to CKA_ID mapping
		id = createSlotID(uint(*b.config.Slot))
	} else {
		// Standard PKCS#11 mode: use formatted string ID
		id = []byte(createKeyID(attrs))
	}

	signer, err := b.ctx.FindKeyPair(id, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to find key: %w", err)
	}
	if signer == nil {
		return nil, fmt.Errorf("%w: %s", backend.ErrKeyNotFound, attrs.CN)
	}

	return signer, nil
}

// Sign signs a digest using the specified key on the HSM.
func (b *Backend) Sign(attrs *types.KeyAttributes, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	signer, err := b.Signer(attrs)
	if err != nil {
		return nil, err
	}

	return signer.Sign(nil, digest, opts)
}

// Verify verifies a signature using the public key.
// This is performed in software using the public key retrieved from the HSM.
func (b *Backend) Verify(attrs *types.KeyAttributes, digest, signature []byte) error {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.ctx == nil {
		return ErrNotInitialized
	}

	// Get the signer (which has the public key)
	id := []byte(createKeyID(attrs))
	signer, err := b.ctx.FindKeyPair(id, nil)
	if err != nil {
		return fmt.Errorf("failed to find key: %w", err)
	}
	if signer == nil {
		return fmt.Errorf("%w: %s", backend.ErrKeyNotFound, attrs.CN)
	}

	pubKey := signer.Public()

	// Verify based on key type
	switch pub := pubKey.(type) {
	case *rsa.PublicKey:
		// For RSA, we'd need to know the hash algorithm
		return fmt.Errorf("%w: RSA verification requires hash algorithm specification", backend.ErrInvalidAlgorithm)
	case *ecdsa.PublicKey:
		// Verify ECDSA signature
		if !ecdsa.VerifyASN1(pub, digest, signature) {
			return fmt.Errorf("signature verification failed")
		}
		return nil
	default:
		return fmt.Errorf("%w: unsupported key type for verification", backend.ErrInvalidKeyType)
	}
}

// Context returns the underlying crypto11 context.
// Returns ErrNotInitialized if Login has not been called.
func (b *Backend) Context() (*crypto11.Context, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.ctx == nil {
		return nil, ErrNotInitialized
	}

	return b.ctx, nil
}

// findKey finds a key object by label.
// Must be called with mutex held.
func (b *Backend) findKey(attrs *types.KeyAttributes) (crypto.Signer, error) {
	if b.ctx == nil {
		return nil, ErrNotInitialized
	}

	id := []byte(createKeyID(attrs))
	signer, err := b.ctx.FindKeyPair(id, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to find key: %w", err)
	}
	if signer == nil {
		return nil, fmt.Errorf("%w: %s", backend.ErrKeyNotFound, attrs.CN)
	}

	return signer, nil
}

// contextCacheKey generates a unique cache key for a PKCS#11 configuration.
// The key is based on the library path, token label, and PIN to prevent
// cross-contamination between different authentication sessions.
func contextCacheKey(config *Config) string {
	return fmt.Sprintf("%s:%s:%s", config.Library, config.TokenLabel, config.PIN)
}

// createKeyID generates a PKCS#11 object identifier for a key.
// Format: {CN}.{algorithm}
func createKeyID(attrs *types.KeyAttributes) string {
	return fmt.Sprintf("%s.%s", attrs.CN, attrs.KeyAlgorithm)
}

// createSlotID generates a PKCS#11 CKA_ID from a YubiKey PIV slot number.
// YubiKey PIV uses a specific mapping from slot numbers to CKA_ID values:
//   - Slot 0x9a (Authentication) -> CKA_ID 0x01
//   - Slot 0x9c (Signature) -> CKA_ID 0x02
//   - Slot 0x9d (Key Management) -> CKA_ID 0x03
//   - Slot 0x9e (Card Auth) -> CKA_ID 0x04
//   - Retired slots 0x82-0x95 -> CKA_ID 0x05-0x18
func createSlotID(slot uint) []byte {
	var ckaid byte
	switch slot {
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
		// Retired slots: 0x82-0x95 map to CKA_ID 0x05-0x18
		ckaid = byte(slot - 0x82 + 0x05)
	default:
		// Unknown slot, use raw value
		ckaid = byte(slot)
	}
	return []byte{ckaid}
}

// pkcs11Ed25519Signer implements crypto.Signer for Ed25519 keys stored in PKCS#11.
// It wraps the PKCS#11 key handles and performs signing operations using the HSM.
type pkcs11Ed25519Signer struct {
	backend        *Backend
	publicHandle   pkcs11.ObjectHandle
	privateHandle  pkcs11.ObjectHandle
	label          string
	publicKeyBytes ed25519.PublicKey
	mu             sync.RWMutex
}

// Public returns the public key corresponding to the opaque private key.
func (s *pkcs11Ed25519Signer) Public() crypto.PublicKey {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Return cached public key if available
	if s.publicKeyBytes != nil {
		return s.publicKeyBytes
	}

	// Retrieve public key from PKCS#11
	if s.backend.p11ctx == nil {
		return nil
	}

	// Get session
	slots, err := s.backend.p11ctx.GetSlotList(true)
	if err != nil || len(slots) == 0 {
		return nil
	}

	var slot uint
	if s.backend.config.Slot != nil {
		slot = uint(*s.backend.config.Slot)
	} else {
		slot = slots[0]
	}

	session, err := s.backend.p11ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nil
	}
	defer s.backend.p11ctx.CloseSession(session)

	// Get CKA_EC_POINT attribute which contains the public key for Ed25519
	attrs, err := s.backend.p11ctx.GetAttributeValue(session, s.publicHandle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
	})
	if err != nil {
		return nil
	}

	if len(attrs) == 0 || len(attrs[0].Value) == 0 {
		return nil
	}

	// Ed25519 public key is 32 bytes
	// The CKA_EC_POINT is DER-encoded OCTET STRING, so we need to unwrap it
	ecPoint := attrs[0].Value

	// Skip DER encoding: typical format is 0x04 <length> <32 bytes>
	// For Ed25519, we expect the point to be exactly 32 bytes after unwrapping
	var publicKey ed25519.PublicKey
	if len(ecPoint) >= 34 && ecPoint[0] == 0x04 {
		// DER-encoded: 0x04 (OCTET STRING tag) + length + data
		publicKey = ed25519.PublicKey(ecPoint[2:34])
	} else if len(ecPoint) == 32 {
		// Raw public key
		publicKey = ed25519.PublicKey(ecPoint)
	} else {
		return nil
	}

	s.publicKeyBytes = publicKey
	return publicKey
}

// Sign signs the given digest using Ed25519 with the PKCS#11 private key.
// For Ed25519, the digest parameter is actually the full message, not a hash.
// Ed25519 performs its own hashing internally.
func (s *pkcs11Ed25519Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.backend.p11ctx == nil {
		return nil, fmt.Errorf("PKCS#11 context not initialized")
	}

	// Get session
	slots, err := s.backend.p11ctx.GetSlotList(true)
	if err != nil {
		return nil, fmt.Errorf("failed to get slot list: %w", err)
	}
	if len(slots) == 0 {
		return nil, fmt.Errorf("no slots available")
	}

	var slot uint
	if s.backend.config.Slot != nil {
		slot = uint(*s.backend.config.Slot)
	} else {
		slot = slots[0]
	}

	session, err := s.backend.p11ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nil, fmt.Errorf("failed to open session: %w", err)
	}
	defer s.backend.p11ctx.CloseSession(session)

	// Login if PIN is set
	if s.backend.config.PIN != "" {
		if err := s.backend.p11ctx.Login(session, pkcs11.CKU_USER, s.backend.config.PIN); err != nil {
			if err != pkcs11.Error(pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
				return nil, fmt.Errorf("failed to login: %w", err)
			}
		}
	}

	// Initialize signing operation with CKM_EDDSA
	err = s.backend.p11ctx.SignInit(session, []*pkcs11.Mechanism{
		pkcs11.NewMechanism(CKM_EDDSA, nil),
	}, s.privateHandle)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize signing: %w", err)
	}

	// Perform signing
	// For Ed25519, we pass the full message, not a hash
	signature, err := s.backend.p11ctx.Sign(session, digest)
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	return signature, nil
}

// Ensure interface is implemented at compile time
var _ types.Backend = (*Backend)(nil)
var _ crypto.Signer = (*pkcs11Ed25519Signer)(nil)
