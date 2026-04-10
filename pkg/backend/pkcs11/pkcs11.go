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
	"strings"
	"sync"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage/hardware"
	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
	pivpkcs11 "github.com/jeremyhahn/go-xkms/pkg/pivcert/pkcs11"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/miekg/pkcs11"
)

// PKCS#11 v3.0 Edwards curve constants
// These are defined in PKCS#11 v3.0 specification but may not be in older versions of miekg/pkcs11
const (
	CKK_EC_EDWARDS              = 0x00000040 // Edwards curve key type
	CKM_EC_EDWARDS_KEY_PAIR_GEN = 0x00001055 // Edwards curve key pair generation mechanism
	CKM_EDDSA                   = 0x00001057 // EdDSA signature mechanism
)

// PKCS#11 v3.2 post-quantum cryptography constants
// These are defined in OASIS PKCS#11 v3.2 CSD01 (pkcs11t.h) for ML-DSA and ML-KEM algorithms.
// The key type values (CKK_*) follow the official PKCS#11 v3.2 specification numbering.
// The mechanism values (CKM_*) match the standard mechanism type assignments.
const (
	// CKK_ML_DSA is the ML-DSA (FIPS 204) key type for post-quantum digital signatures.
	CKK_ML_DSA = 0x0000004A

	// CKM_ML_DSA_KEY_PAIR_GEN generates ML-DSA key pairs on the HSM.
	CKM_ML_DSA_KEY_PAIR_GEN = 0x0000001c

	// CKM_ML_DSA performs ML-DSA signing and verification on the HSM.
	CKM_ML_DSA = 0x0000001d

	// CKK_ML_KEM is the ML-KEM (FIPS 203) key type for post-quantum key encapsulation.
	CKK_ML_KEM = 0x00000049

	// CKM_ML_KEM_KEY_PAIR_GEN generates ML-KEM key pairs on the HSM.
	CKM_ML_KEM_KEY_PAIR_GEN = 0x0000000f

	// CKM_ML_KEM performs ML-KEM encapsulation and decapsulation on the HSM.
	CKM_ML_KEM = 0x00000017
)

// Backend implements the types.KeyProvider interface for PKCS#11 hardware security modules.
// It provides secure key storage where private keys never leave the HSM hardware.
//
// The backend uses a channel-based session pool over miekg/pkcs11 for all operations.
// This eliminates the dual-init conflict that occurred with the crypto11 wrapper library.
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
	config        *Config
	p11ctx        *pkcs11.Ctx
	pool          *SessionPool
	ownsP11ctx    bool // tracks if this backend owns the PKCS#11 context (should Finalize/Destroy)
	tracker       types.AEADSafetyTracker
	supportsMLDSA bool // dynamically detected ML-DSA mechanism support
	supportsMLKEM bool // dynamically detected ML-KEM mechanism support
	slotModel     pivcert.SlotModel // nil for generic (non-PIV) tokens
	mu            sync.RWMutex
	types.KeyProvider
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

// SlotModel returns the slot model for this backend, or nil if the token
// does not use predefined slots (e.g., generic SoftHSM tokens).
func (b *Backend) SlotModel() pivcert.SlotModel {
	return b.slotModel
}

// Capabilities returns the capabilities of this backend.
// PKCS#11 is a hardware-backed security module interface.
// Quantum capabilities (QuantumSigning and KeyEncapsulation) are dynamically
// detected from the token's mechanism list during initialization.
// SecurityLevel is High - keys are protected by local HSM hardware.
func (b *Backend) Capabilities() types.Capabilities {
	caps := types.NewHardwareCapabilities()
	caps.SymmetricEncryption = true
	caps.Import = true // PKCS#11 supports key import
	caps.Export = true // PKCS#11 supports key export (if CKA_EXTRACTABLE=true)
	caps.QuantumSigning = b.supportsMLDSA
	caps.KeyEncapsulation = b.supportsMLKEM
	caps.SecurityLevel = types.SecurityLevelHigh // Explicit for clarity
	return caps
}

// probeQuantumMechanisms queries the token's mechanism list to detect
// support for PKCS#11 v3.2 post-quantum mechanisms (ML-DSA and ML-KEM).
// Results are stored in supportsMLDSA and supportsMLKEM fields.
// This method is safe to call when p11ctx is nil (no-op).
func (b *Backend) probeQuantumMechanisms() {
	if b.p11ctx == nil {
		return
	}

	slots, err := b.p11ctx.GetSlotList(true)
	if err != nil || len(slots) == 0 {
		return
	}

	var slot uint
	if b.config.Slot != nil {
		slot = uint(*b.config.Slot)
	} else {
		slot = slots[0]
	}

	mechs, err := b.p11ctx.GetMechanismList(slot)
	if err != nil {
		return
	}

	for _, mech := range mechs {
		switch mech.Mechanism {
		case CKM_ML_DSA_KEY_PAIR_GEN:
			b.supportsMLDSA = true
		case CKM_ML_KEM_KEY_PAIR_GEN:
			b.supportsMLKEM = true
		}
	}
}

// Get retrieves a key handle from the PKCS#11 backend by CN.
// This returns the public key material, as private keys cannot be exported from HSM.
//
// Note: For PKCS#11, use the Signer() method to perform operations with keys.
// Direct private key material retrieval is not possible for security.
func (b *Backend) Get(attrs *types.KeyAttributes, extension types.FSExtension) ([]byte, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.pool == nil {
		return nil, ErrNotInitialized
	}

	// Find the key pair
	id := []byte(createKeyID(attrs))
	signer, err := findKeyPairByID(b.pool, id)
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

	if b.pool == nil {
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
// findObjectsByClassAndID locates all PKCS#11 objects with the given CKA_CLASS
// and CKA_ID within an open session. Caller must hold b.mu.
func (b *Backend) findObjectsByClassAndID(session pkcs11.SessionHandle, class uint, id []byte) ([]pkcs11.ObjectHandle, error) {
	tmpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, class),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
	}
	if err := b.p11ctx.FindObjectsInit(session, tmpl); err != nil {
		return nil, fmt.Errorf("failed to init find objects: %w", err)
	}
	objs, _, err := b.p11ctx.FindObjects(session, 10)
	if err != nil {
		b.p11ctx.FindObjectsFinal(session)
		return nil, fmt.Errorf("failed to find objects: %w", err)
	}
	if err := b.p11ctx.FindObjectsFinal(session); err != nil {
		return nil, fmt.Errorf("failed to finalize find objects: %w", err)
	}
	return objs, nil
}

// deleteKeyInSession performs the find+destroy sequence for both the private
// and public key objects matching id. It returns an error that wraps
// hardware.ErrDeleteNotSupportedOnToken when the object survives DestroyObject,
// which happens on YubiKey PIV because libykcs11 silently no-ops the call.
func (b *Backend) deleteKeyInSession(session pkcs11.SessionHandle, id []byte, cn string) error {
	privObjs, err := b.findObjectsByClassAndID(session, pkcs11.CKO_PRIVATE_KEY, id)
	if err != nil {
		return err
	}
	for _, obj := range privObjs {
		if err := b.p11ctx.DestroyObject(session, obj); err != nil {
			return fmt.Errorf("failed to destroy private key: %w", err)
		}
	}

	pubObjs, err := b.findObjectsByClassAndID(session, pkcs11.CKO_PUBLIC_KEY, id)
	if err != nil {
		return err
	}
	for _, obj := range pubObjs {
		if err := b.p11ctx.DestroyObject(session, obj); err != nil {
			return fmt.Errorf("failed to destroy public key: %w", err)
		}
	}

	if len(privObjs) == 0 && len(pubObjs) == 0 {
		return fmt.Errorf("%w: %s", backend.ErrKeyNotFound, cn)
	}

	// Verify objects are actually gone. YubiKey PIV libykcs11 accepts
	// C_DestroyObject under CKU_SO but leaves PIV slot contents in place.
	if remaining, verr := b.findObjectsByClassAndID(session, pkcs11.CKO_PRIVATE_KEY, id); verr == nil && len(remaining) > 0 {
		return fmt.Errorf("%w: private key %q still present after DestroyObject -- token does not support deletion (YubiKey PIV slots must be overwritten or reset via 'ykman piv reset')",
			hardware.ErrDeleteNotSupportedOnToken, cn)
	}
	if remaining, verr := b.findObjectsByClassAndID(session, pkcs11.CKO_PUBLIC_KEY, id); verr == nil && len(remaining) > 0 {
		return fmt.Errorf("%w: public key %q still present after DestroyObject -- token does not support deletion (YubiKey PIV slots must be overwritten or reset via 'ykman piv reset')",
			hardware.ErrDeleteNotSupportedOnToken, cn)
	}

	return nil
}

// DeleteKey removes a private/public key pair from the PKCS#11 token.
//
// For YubiKey PIV, C_DestroyObject is rejected under CKU_USER with
// CKR_USER_TYPE_INVALID, so the delete is executed under CKU_SO
// (management key) via SessionPool.WithSOSession. Even then, libykcs11
// may silently accept the call without actually clearing the slot, so
// the operation verifies removal and returns hardware.ErrDeleteNotSupportedOnToken
// with actionable guidance when the object persists.
func (b *Backend) DeleteKey(attrs *types.KeyAttributes) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.pool == nil {
		return ErrNotInitialized
	}

	id, err := b.resolveKeyID(attrs)
	if err != nil {
		return err
	}

	fn := func(session pkcs11.SessionHandle) error {
		return b.deleteKeyInSession(session, id, attrs.CN)
	}

	if b.config.IsYubiKeyPIV() && b.config.SOPIN != "" {
		return b.pool.WithSOSession(b.config.SOPIN, b.config.PIN, fn)
	}
	return b.pool.WithSession(fn)
}

// Delete removes a key from the PKCS#11 backend.
// This is an alias for DeleteKey to satisfy the Storage interface.
func (b *Backend) Delete(attrs *types.KeyAttributes) error {
	return b.DeleteKey(attrs)
}

// ListKeys returns attributes for all keys managed by this backend.
// It enumerates all private key objects on the PKCS#11 token and returns
// their key attributes including algorithm type and PIV slot mapping.
func (b *Backend) ListKeys() ([]*types.KeyAttributes, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.pool == nil {
		return nil, ErrNotInitialized
	}

	var results []*types.KeyAttributes
	err := b.pool.WithSession(func(session pkcs11.SessionHandle) error {
		template := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		}
		if err := b.p11ctx.FindObjectsInit(session, template); err != nil {
			return fmt.Errorf("list keys: init search: %w", err)
		}
		defer b.p11ctx.FindObjectsFinal(session)

		handles, _, err := b.p11ctx.FindObjects(session, 256)
		if err != nil {
			return fmt.Errorf("list keys: find objects: %w", err)
		}

		for _, h := range handles {
			readAttrs, err := b.p11ctx.GetAttributeValue(session, h, []*pkcs11.Attribute{
				pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
				pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
				pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
			})
			if err != nil || len(readAttrs) < 3 {
				continue
			}

			ka := &types.KeyAttributes{
				StoreType: types.StorePKCS11,
			}

			// Set CN from label
			if len(readAttrs[1].Value) > 0 {
				ka.CN = string(readAttrs[1].Value)
			}

			// Map CKA_ID to PIV slot if applicable
			if len(readAttrs[0].Value) == 1 {
				if slot, ok := pivpkcs11.CKAIDToPIVSlot(readAttrs[0].Value[0]); ok {
					ka.PIVSlot = string(slot)
				}
			}

			// Determine algorithm from key type
			if len(readAttrs[2].Value) > 0 {
				keyType := readAttrs[2].Value[0]
				switch keyType {
				case 0x00: // CKK_RSA
					ka.KeyAlgorithm = x509.RSA
				case 0x03: // CKK_EC
					ka.KeyAlgorithm = x509.ECDSA
				}
			}

			results = append(results, ka)
		}
		return nil
	})

	return results, err
}

// Decrypter returns a crypto.Decrypter for the specified key.
// This allows the key to be used for decryption operations without
// exposing the private key material.
func (b *Backend) Decrypter(attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	// For PKCS#11, decryption is handled through the HSM.
	// RSA signers implement crypto.Decrypter (PKCS1v15 and OAEP).
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
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.pool == nil {
		return nil, ErrNotInitialized
	}

	if length <= 0 {
		return nil, fmt.Errorf("pkcs11: invalid length %d, must be > 0", length)
	}

	var randomBytes []byte
	err := b.pool.WithSession(func(session pkcs11.SessionHandle) error {
		var err error
		randomBytes, err = b.p11ctx.GenerateRandom(session, length)
		if err != nil {
			return fmt.Errorf("pkcs11: failed to generate random bytes: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return randomBytes, nil
}

// Close releases the PKCS#11 session pool and any associated resources.
// This method is idempotent and can be called multiple times safely.
func (b *Backend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.pool != nil {
		b.pool.Close()
		b.pool = nil
	}

	if b.p11ctx != nil && b.ownsP11ctx {
		b.p11ctx.Finalize()
		b.p11ctx.Destroy()
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

	// If pool already exists, we're already initialized
	if b.pool != nil {
		return ErrAlreadyInitialized
	}

	// Initialize token using low-level PKCS#11
	if err := b.initializeToken(soPIN, userPIN); err != nil {
		// If already initialized, that's okay
		if err != ErrAlreadyInitialized {
			return fmt.Errorf("failed to initialize token: %w", err)
		}
	}

	// Login to establish session pool
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

// loginUser initializes the raw PKCS#11 context and creates the session pool.
// Must be called with mutex held.
func (b *Backend) loginUser(pin string) error {
	// Initialize raw PKCS#11 context if not already done
	if b.p11ctx == nil {
		p := pkcs11.New(b.config.Library)
		if p == nil {
			return fmt.Errorf("failed to load PKCS#11 library: %s", b.config.Library)
		}
		if err := p.Initialize(); err != nil {
			if err != pkcs11.Error(pkcs11.CKR_CRYPTOKI_ALREADY_INITIALIZED) {
				p.Destroy()
				return fmt.Errorf("failed to initialize PKCS#11: %w", err)
			}
		}
		b.p11ctx = p
		b.ownsP11ctx = true
	}

	// Resolve slot by token label or configured slot number
	slotID, err := b.resolveSlot()
	if err != nil {
		return fmt.Errorf("failed to resolve slot: %w", err)
	}

	// Create session pool
	poolSize := b.config.SessionPoolSize
	if poolSize <= 0 {
		poolSize = DefaultSessionPoolSize
	}
	pool, err := NewSessionPool(b.p11ctx, slotID, pin, poolSize)
	if err != nil {
		return fmt.Errorf("failed to create session pool: %w", err)
	}
	b.pool = pool

	// Attach PIV slot model for YubiKey PIV tokens.
	if b.config.IsYubiKeyPIV() {
		sm, smErr := pivpkcs11.NewPIVSlotModel(b.pool)
		if smErr == nil {
			b.slotModel = sm
		}
		// Non-fatal: slot model is optional enhancement
	}

	// Probe for quantum mechanism support after establishing context
	b.probeQuantumMechanisms()

	return nil
}

// resolveSlot determines the PKCS#11 slot ID based on configuration.
// If a slot number is configured, it is used directly. Otherwise, the slot
// is resolved by matching the token label against available tokens.
func (b *Backend) resolveSlot() (uint, error) {
	if b.config.Slot != nil {
		return uint(*b.config.Slot), nil
	}

	slots, err := b.p11ctx.GetSlotList(true)
	if err != nil {
		return 0, fmt.Errorf("failed to get slot list: %w", err)
	}
	if len(slots) == 0 {
		return 0, ErrTokenNotFound
	}

	// If token label is set, find the matching slot
	if b.config.TokenLabel != "" {
		for _, slot := range slots {
			tokenInfo, err := b.p11ctx.GetTokenInfo(slot)
			if err != nil {
				continue
			}
			// PKCS#11 pads token labels with spaces to 32 characters
			if strings.TrimRight(tokenInfo.Label, " ") == strings.TrimRight(b.config.TokenLabel, " ") {
				return slot, nil
			}
		}
		return 0, fmt.Errorf("%w: token label %q not found", ErrTokenNotFound, b.config.TokenLabel)
	}

	// Default to first available slot
	return slots[0], nil
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
// Supports RSA, ECDSA, Ed25519, and post-quantum algorithms (ML-DSA, ML-KEM)
// when QuantumAttributes are specified.
func (b *Backend) GenerateKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	// Check for quantum key generation first
	if attrs.QuantumAttributes != nil {
		return b.generateQuantumKey(attrs)
	}

	switch attrs.KeyAlgorithm {
	case x509.RSA:
		return b.GenerateRSA(attrs)
	case x509.ECDSA:
		return b.GenerateECDSA(attrs)
	case x509.Ed25519:
		return b.GenerateEd25519(attrs)
	default:
		return nil, ErrUnsupportedKeyAlgorithm
	}
}

// generateQuantumKey generates a post-quantum key pair on the HSM using PKCS#11 v3.2 mechanisms.
// It supports ML-DSA (signing) and ML-KEM (key encapsulation) algorithms. The private key
// never leaves the HSM hardware; a wrapper signer type is returned that delegates cryptographic
// operations to the HSM.
//
// For ML-DSA, the returned signer implements crypto.Signer and can be used for signing.
// For ML-KEM, key encapsulation handles are returned (currently wrapped as a signer).
func (b *Backend) generateQuantumKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.pool == nil {
		return nil, ErrNotInitialized
	}

	if attrs.QuantumAttributes == nil {
		return nil, ErrInvalidKeyAttributes
	}

	algorithm := string(attrs.QuantumAttributes.Algorithm)

	// Determine key type and mechanism based on quantum algorithm
	var keyType uint
	var keyPairGenMechanism uint
	var signMechanism uint

	switch {
	case strings.HasPrefix(algorithm, "ML-DSA"):
		if !b.supportsMLDSA {
			return nil, fmt.Errorf("%w: token does not support ML-DSA", ErrUnsupportedKeyAlgorithm)
		}
		keyType = CKK_ML_DSA
		keyPairGenMechanism = CKM_ML_DSA_KEY_PAIR_GEN
		signMechanism = CKM_ML_DSA

	case strings.HasPrefix(algorithm, "ML-KEM"):
		if !b.supportsMLKEM {
			return nil, fmt.Errorf("%w: token does not support ML-KEM", ErrUnsupportedKeyAlgorithm)
		}
		keyType = CKK_ML_KEM
		keyPairGenMechanism = CKM_ML_KEM_KEY_PAIR_GEN
		signMechanism = CKM_ML_KEM

	default:
		return nil, fmt.Errorf("%w: unsupported quantum algorithm: %s", ErrUnsupportedKeyAlgorithm, algorithm)
	}

	// Create key ID and label
	id := []byte(createQuantumKeyID(attrs))
	label := []byte(attrs.CN)

	// Public key template
	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, keyType),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
	}

	// Private key template
	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, keyType),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
	}

	var pubHandle, privHandle pkcs11.ObjectHandle
	err := b.pool.WithSession(func(session pkcs11.SessionHandle) error {
		var err error
		pubHandle, privHandle, err = b.p11ctx.GenerateKeyPair(
			session,
			[]*pkcs11.Mechanism{pkcs11.NewMechanism(keyPairGenMechanism, nil)},
			publicKeyTemplate,
			privateKeyTemplate,
		)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("failed to generate %s key pair: %w", algorithm, err)
	}

	// Create a signer wrapper that delegates operations to the HSM
	signer := &pkcs11MLDSASigner{
		pool:          b.pool,
		publicHandle:  pubHandle,
		privateHandle: privHandle,
		label:         string(label),
		algorithm:     algorithm,
		signMechanism: signMechanism,
	}

	return signer, nil
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

	if b.pool == nil {
		return nil, ErrNotInitialized
	}

	// Apply default key size if not specified or invalid
	if keySize == 0 || keySize < 512 {
		keySize = 2048
	}

	id, err := b.resolveKeyID(attrs)
	if err != nil {
		return nil, err
	}

	signer, err := generateRSAKeyPair(b.pool, id, id, keySize, b.config.IsYubiKeyPIV(), b.config.SOPIN, b.config.PIN)
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

	if b.pool == nil {
		return nil, ErrNotInitialized
	}

	// Apply default curve if not specified
	if curve == nil || curve.Params() == nil {
		curve = elliptic.P256()
	}

	id, err := b.resolveKeyID(attrs)
	if err != nil {
		return nil, err
	}

	signer, err := generateECDSAKeyPair(b.pool, id, id, curve, b.config.IsYubiKeyPIV(), b.config.SOPIN, b.config.PIN)
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

	if b.config != nil && b.config.IsYubiKeyPIV() {
		return nil, fmt.Errorf("%w: YubiKey PIV does not support Ed25519 keys; use ECDSA P-256 or RSA instead", ErrUnsupportedKeyAlgorithm)
	}

	if b.pool == nil {
		return nil, ErrNotInitialized
	}

	id, err := b.resolveKeyID(attrs)
	if err != nil {
		return nil, err
	}
	label := []byte(attrs.CN)

	// Ed25519 OID (1.3.101.112) - RFC 8410
	ed25519OID := []byte{0x06, 0x03, 0x2b, 0x65, 0x70}

	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, CKK_EC_EDWARDS),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, ed25519OID),
	}

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

	var pubKey, privKey pkcs11.ObjectHandle
	err = b.pool.WithSession(func(session pkcs11.SessionHandle) error {
		var err error
		pubKey, privKey, err = b.p11ctx.GenerateKeyPair(
			session,
			[]*pkcs11.Mechanism{pkcs11.NewMechanism(CKM_EC_EDWARDS_KEY_PAIR_GEN, nil)},
			publicKeyTemplate,
			privateKeyTemplate,
		)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("failed to generate Ed25519 key pair: %w", err)
	}

	signer := &pkcs11Ed25519Signer{
		pool:           b.pool,
		publicHandle:   pubKey,
		privateHandle:  privKey,
		label:          string(label),
		publicKeyBytes: nil,
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
	if b.pool == nil {
		return 0, ErrNotInitialized
	}

	if keySize != 128 && keySize != 256 {
		return 0, fmt.Errorf("%w: AES key size %d bits (only 128 and 256 are supported)", backend.ErrInvalidAlgorithm, keySize)
	}

	label := createKeyID(attrs)
	valueLenBytes := uint(keySize / 8)

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

	mechanism := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_GEN, nil)}

	var handle pkcs11.ObjectHandle
	err := b.pool.WithSession(func(session pkcs11.SessionHandle) error {
		var err error
		handle, err = b.p11ctx.GenerateKey(session, mechanism, template)
		return err
	})
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
	if b.pool == nil {
		return 0, ErrNotInitialized
	}

	label := createKeyID(attrs)
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}

	var handle pkcs11.ObjectHandle
	err := b.pool.WithSession(func(session pkcs11.SessionHandle) error {
		if err := b.p11ctx.FindObjectsInit(session, template); err != nil {
			return fmt.Errorf("failed to init object search: %w", err)
		}
		handles, _, err := b.p11ctx.FindObjects(session, 1)
		if err != nil {
			b.p11ctx.FindObjectsFinal(session)
			return fmt.Errorf("failed to find objects: %w", err)
		}
		if err := b.p11ctx.FindObjectsFinal(session); err != nil {
			return fmt.Errorf("failed to finalize object search: %w", err)
		}
		if len(handles) == 0 {
			return fmt.Errorf("%w: %s", backend.ErrKeyNotFound, attrs.CN)
		}
		handle = handles[0]
		return nil
	})
	if err != nil {
		return 0, err
	}
	return handle, nil
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

	if b.pool == nil {
		return nil, ErrNotInitialized
	}

	id, err := b.resolveKeyID(attrs)
	if err != nil {
		return nil, err
	}

	signer, err := findKeyPairByID(b.pool, id)
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

	if b.pool == nil {
		return ErrNotInitialized
	}

	id := []byte(createKeyID(attrs))
	signer, err := findKeyPairByID(b.pool, id)
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

// Pool returns the session pool. Returns nil if not initialized.
func (b *Backend) Pool() *SessionPool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.pool
}

// SetSessionPool allows an external manager to inject a pre-created session pool.
// This is the key integration point that eliminates the dual-init problem — the
// PKCS#11 module manager can create a pool and share it with the backend.
func (b *Backend) SetSessionPool(pool *SessionPool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.pool = pool
	b.p11ctx = pool.Ctx()
	b.ownsP11ctx = false
	b.probeQuantumMechanisms()
}

// SetP11Ctx allows an external manager to inject a raw PKCS#11 context.
// Use SetSessionPool when possible; this is for backward compatibility.
func (b *Backend) SetP11Ctx(ctx *pkcs11.Ctx) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.p11ctx = ctx
	b.ownsP11ctx = false
}

// findKey finds a key object by label.
// Must be called with mutex held.
func (b *Backend) findKey(attrs *types.KeyAttributes) (crypto.Signer, error) {
	if b.pool == nil {
		return nil, ErrNotInitialized
	}

	id := []byte(createKeyID(attrs))
	signer, err := findKeyPairByID(b.pool, id)
	if err != nil {
		return nil, fmt.Errorf("failed to find key: %w", err)
	}
	if signer == nil {
		return nil, fmt.Errorf("%w: %s", backend.ErrKeyNotFound, attrs.CN)
	}

	return signer, nil
}

// findKeyPairByID locates a key pair on the token by CKA_ID and returns the
// appropriate crypto.Signer based on the key type (RSA, ECDSA, Ed25519).
// Returns nil, nil if no key is found.
func findKeyPairByID(pool *SessionPool, id []byte) (crypto.Signer, error) {
	var keyType uint
	var privHandle, pubHandle pkcs11.ObjectHandle
	var found bool

	err := pool.WithSession(func(session pkcs11.SessionHandle) error {
		// Find private key (any type)
		if err := pool.Ctx().FindObjectsInit(session, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		}); err != nil {
			return fmt.Errorf("pkcs11: FindObjectsInit for private key: %w", err)
		}
		privObjs, _, err := pool.Ctx().FindObjects(session, 1)
		if err != nil {
			pool.Ctx().FindObjectsFinal(session)
			return fmt.Errorf("pkcs11: FindObjects for private key: %w", err)
		}
		if err := pool.Ctx().FindObjectsFinal(session); err != nil {
			return fmt.Errorf("pkcs11: FindObjectsFinal for private key: %w", err)
		}
		if len(privObjs) == 0 {
			return nil // not found
		}
		privHandle = privObjs[0]

		// Get key type
		attrs, err := pool.Ctx().GetAttributeValue(session, privHandle, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
		})
		if err != nil {
			return fmt.Errorf("pkcs11: GetAttributeValue for key type: %w", err)
		}
		if len(attrs) == 0 || len(attrs[0].Value) == 0 {
			return fmt.Errorf("pkcs11: could not determine key type")
		}
		// CKA_KEY_TYPE is a CK_ULONG, encoded as little-endian bytes
		for i, b := range attrs[0].Value {
			keyType |= uint(b) << (8 * i)
		}

		// Find public key
		if err := pool.Ctx().FindObjectsInit(session, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		}); err != nil {
			return fmt.Errorf("pkcs11: FindObjectsInit for public key: %w", err)
		}
		pubObjs, _, err := pool.Ctx().FindObjects(session, 1)
		if err != nil {
			pool.Ctx().FindObjectsFinal(session)
			return fmt.Errorf("pkcs11: FindObjects for public key: %w", err)
		}
		if err := pool.Ctx().FindObjectsFinal(session); err != nil {
			return fmt.Errorf("pkcs11: FindObjectsFinal for public key: %w", err)
		}
		if len(pubObjs) > 0 {
			pubHandle = pubObjs[0]
		}
		found = true
		return nil
	})
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}

	// Dispatch to type-specific signer construction
	switch keyType {
	case pkcs11.CKK_RSA:
		pub, err := exportRSAPublicKey(pool, pubHandle)
		if err != nil {
			return nil, err
		}
		return &pkcs11RSASigner{
			pool:          pool,
			privateHandle: privHandle,
			publicKey:     pub,
			label:         string(id),
		}, nil

	case pkcs11.CKK_EC:
		pub, err := exportECDSAPublicKey(pool, pubHandle)
		if err != nil {
			return nil, err
		}
		return &pkcs11ECDSASigner{
			pool:          pool,
			privateHandle: privHandle,
			publicKey:     pub,
			label:         string(id),
		}, nil

	case CKK_EC_EDWARDS:
		return &pkcs11Ed25519Signer{
			pool:          pool,
			publicHandle:  pubHandle,
			privateHandle: privHandle,
			label:         string(id),
		}, nil

	default:
		return nil, fmt.Errorf("%w: unknown key type 0x%04x", ErrUnsupportedKeyAlgorithm, keyType)
	}
}

// resolveKeyID determines the PKCS#11 CKA_ID for a key based on:
//  1. KeyAttributes.PIVSlot (explicit PIV slot from caller) - highest priority
//  2. Config.Slot for YubiKey PIV (existing behavior)
//  3. createKeyID for generic PKCS#11 tokens (CN.algorithm format)
func (b *Backend) resolveKeyID(attrs *types.KeyAttributes) ([]byte, error) {
	if attrs.PIVSlot != "" {
		slot := pivcert.PIVSlot(attrs.PIVSlot)
		if !slot.IsValid() {
			return nil, fmt.Errorf("%w: invalid PIV slot: %s", ErrInvalidKeyAttributes, attrs.PIVSlot)
		}
		ckaID, ok := pivpkcs11.PIVSlotToCKAID(slot)
		if !ok {
			return nil, fmt.Errorf("%w: no CKA_ID mapping for slot %s", ErrInvalidKeyAttributes, attrs.PIVSlot)
		}
		return []byte{ckaID}, nil
	}
	if b.config.IsYubiKeyPIV() && b.config.Slot != nil {
		return createSlotID(uint(*b.config.Slot)), nil
	}
	return []byte(createKeyID(attrs)), nil
}

// createKeyID generates a PKCS#11 object identifier for a key.
// Format: {CN}.{algorithm}
func createKeyID(attrs *types.KeyAttributes) string {
	if attrs.KeyAlgorithm == x509.UnknownPublicKeyAlgorithm {
		return fmt.Sprintf("%s.", attrs.CN)
	}
	return fmt.Sprintf("%s.%s", attrs.CN, strings.ToLower(attrs.KeyAlgorithm.String()))
}

// createQuantumKeyID generates a PKCS#11 object identifier for a quantum key.
// Format: {CN}.{quantum-algorithm}
func createQuantumKeyID(attrs *types.KeyAttributes) string {
	if attrs.QuantumAttributes == nil {
		return fmt.Sprintf("%s.", attrs.CN)
	}
	return fmt.Sprintf("%s.%s", attrs.CN, strings.ToLower(string(attrs.QuantumAttributes.Algorithm)))
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
	pool           *SessionPool
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

	if s.publicKeyBytes != nil {
		return s.publicKeyBytes
	}

	if s.pool == nil {
		return nil
	}

	_ = s.pool.WithSession(func(session pkcs11.SessionHandle) error {
		attrs, err := s.pool.Ctx().GetAttributeValue(session, s.publicHandle, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
		})
		if err != nil || len(attrs) == 0 || len(attrs[0].Value) == 0 {
			return err
		}

		ecPoint := attrs[0].Value

		// Skip DER encoding: typical format is 0x04 <length> <32 bytes>
		if len(ecPoint) >= 34 && ecPoint[0] == 0x04 {
			s.publicKeyBytes = ed25519.PublicKey(ecPoint[2:34])
		} else if len(ecPoint) == 32 {
			s.publicKeyBytes = ed25519.PublicKey(ecPoint)
		}
		return nil
	})

	return s.publicKeyBytes
}

// Sign signs the given digest using Ed25519 with the PKCS#11 private key.
// For Ed25519, the digest parameter is actually the full message, not a hash.
// Ed25519 performs its own hashing internally.
func (s *pkcs11Ed25519Signer) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	if s.pool == nil {
		return nil, fmt.Errorf("pkcs11: session pool not initialized")
	}

	var signature []byte
	err := s.pool.WithSession(func(session pkcs11.SessionHandle) error {
		if err := s.pool.Ctx().SignInit(session, []*pkcs11.Mechanism{
			pkcs11.NewMechanism(CKM_EDDSA, nil),
		}, s.privateHandle); err != nil {
			return fmt.Errorf("pkcs11: Ed25519 SignInit: %w", err)
		}

		var err error
		signature, err = s.pool.Ctx().Sign(session, digest)
		if err != nil {
			return fmt.Errorf("pkcs11: Ed25519 Sign: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return signature, nil
}

// pkcs11MLDSASigner implements crypto.Signer for ML-DSA and ML-KEM keys stored in PKCS#11.
// It wraps the PKCS#11 key handles and delegates all cryptographic operations to the HSM.
// The private key material never leaves the hardware module.
type pkcs11MLDSASigner struct {
	pool          *SessionPool
	publicHandle  pkcs11.ObjectHandle
	privateHandle pkcs11.ObjectHandle
	label         string
	algorithm     string // e.g., "ML-DSA-44", "ML-DSA-65", "ML-KEM-768"
	signMechanism uint   // CKM_ML_DSA or CKM_ML_KEM
	publicKey     crypto.PublicKey
	mu            sync.RWMutex
}

// Public returns the public key corresponding to the opaque private key.
// For ML-DSA/ML-KEM, we return a pkcs11QuantumPublicKey wrapper since Go's
// standard library does not have native types for post-quantum keys.
func (s *pkcs11MLDSASigner) Public() crypto.PublicKey {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.publicKey != nil {
		return s.publicKey
	}

	// Wrap the public handle in a quantum public key type
	s.publicKey = &pkcs11QuantumPublicKey{
		handle:    s.publicHandle,
		algorithm: s.algorithm,
	}
	return s.publicKey
}

// Sign signs the given digest using ML-DSA with the PKCS#11 private key.
// The signing operation is performed entirely within the HSM hardware.
func (s *pkcs11MLDSASigner) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.pool == nil {
		return nil, fmt.Errorf("pkcs11: session pool not initialized")
	}

	var signature []byte
	err := s.pool.WithSession(func(session pkcs11.SessionHandle) error {
		if err := s.pool.Ctx().SignInit(session, []*pkcs11.Mechanism{
			pkcs11.NewMechanism(s.signMechanism, nil),
		}, s.privateHandle); err != nil {
			return fmt.Errorf("pkcs11: %s SignInit: %w", s.algorithm, err)
		}

		var err error
		signature, err = s.pool.Ctx().Sign(session, digest)
		if err != nil {
			return fmt.Errorf("pkcs11: %s Sign: %w", s.algorithm, err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return signature, nil
}

// pkcs11QuantumPublicKey wraps a PKCS#11 object handle for a quantum public key.
// Since Go's crypto library has no native ML-DSA/ML-KEM key types, this wrapper
// provides a type-safe representation that carries the algorithm metadata.
type pkcs11QuantumPublicKey struct {
	handle    pkcs11.ObjectHandle
	algorithm string // e.g., "ML-DSA-44", "ML-KEM-768"
}

// Algorithm returns the quantum algorithm name for this public key.
func (k *pkcs11QuantumPublicKey) Algorithm() string {
	return k.algorithm
}

// Handle returns the PKCS#11 object handle for this public key.
func (k *pkcs11QuantumPublicKey) Handle() pkcs11.ObjectHandle {
	return k.handle
}

// Ensure interface is implemented at compile time
var _ types.KeyProvider = (*Backend)(nil)
var _ crypto.Signer = (*pkcs11Ed25519Signer)(nil)
var _ crypto.Signer = (*pkcs11MLDSASigner)(nil)
