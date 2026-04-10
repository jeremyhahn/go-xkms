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

package authenticator

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"sync"

	"golang.org/x/crypto/argon2"
)

// KeyManager error types define error conditions for key management operations.
var (
	// ErrKeyManagerLocked indicates keys are not available because the manager is locked.
	ErrKeyManagerLocked = errors.New("authenticator: key manager locked")

	// ErrKeyManagerNoSOPIN indicates SO PIN is not configured.
	ErrKeyManagerNoSOPIN = errors.New("authenticator: SO PIN not configured")

	// ErrKeyManagerNoCMK indicates the Credential Master Key is not available.
	ErrKeyManagerNoCMK = errors.New("authenticator: CMK not available")

	// ErrKeyManagerNoAK indicates the Admin Key is not available.
	ErrKeyManagerNoAK = errors.New("authenticator: AK not available")

	// ErrKeyManagerNoAttestKey indicates the attestation key is not available.
	ErrKeyManagerNoAttestKey = errors.New("authenticator: attestation key not available")

	// ErrKeyManagerInvalidKey indicates an invalid key was provided.
	ErrKeyManagerInvalidKey = errors.New("authenticator: invalid key")

	// ErrKeyManagerAlreadyInitialized indicates SO PIN is already configured.
	ErrKeyManagerAlreadyInitialized = errors.New("authenticator: SO PIN already initialized")

	// ErrKeyManagerUserPINNotSet indicates user PIN is not configured.
	ErrKeyManagerUserPINNotSet = errors.New("authenticator: user PIN not set")
)

// UMK derivation constants for Argon2id.
// These parameters provide strong security for deriving UMK from user PIN hash.
const (
	// umkDerivedKeySize is the size of the User Master Key (32 bytes for AES-256).
	umkDerivedKeySize = 32

	// umkIterations is the Argon2id time parameter for UMK derivation.
	umkIterations = 3

	// umkMemory is the Argon2id memory parameter in KiB (64 MiB).
	umkMemory = 64 * 1024

	// umkParallelism is the Argon2id parallelism parameter.
	umkParallelism = 4

	// umkSaltSize is the size of the UMK derivation salt.
	umkSaltSize = 32
)

// KeyManager provides centralized key management for the authenticator.
// It handles the full key hierarchy:
//
//	SO PIN -> Argon2id -> SMK -> Unwraps AK -> Unwraps AttestKey, CMK
//	User PIN -> Argon2id -> UMK -> Unwraps CMK -> Unwraps CredentialKeys
//
// The CMK (Credential Master Key) is dual-wrapped:
//   - Once by UMK (for user access to credentials)
//   - Once by AK (for SO access to reset user PIN)
//
// All public methods are safe for concurrent use.
type KeyManager struct {
	state  *AuthenticatorState
	config *Config

	// mu protects all cached key material
	mu sync.RWMutex

	// adminKey is the unwrapped Admin Key (from SMK)
	adminKey []byte

	// cmk is the Credential Master Key (unwrapped)
	cmk []byte

	// smk is the Storage Master Key (derived from SO PIN)
	smk []byte

	// umk is the User Master Key (derived from User PIN)
	umk []byte

	// unlockSource tracks how the manager was unlocked
	unlockSource unlockSource

	// umkSalt is the salt used for UMK derivation from PIN hash
	umkSalt []byte
}

// unlockSource indicates which PIN was used to unlock the KeyManager.
type unlockSource uint8

const (
	unlockSourceNone unlockSource = iota
	unlockSourceSOPIN
	unlockSourceUserPIN
)

// NewKeyManager creates a new KeyManager with the given state and config.
// The manager starts in a locked state; call UnlockWithSOPIN or UnlockWithUserPIN
// to make keys available.
func NewKeyManager(state *AuthenticatorState, config *Config) *KeyManager {
	return &KeyManager{
		state:  state,
		config: config,
	}
}

// IsSOPINConfigured returns true if SO PIN has been configured.
func (km *KeyManager) IsSOPINConfigured() bool {
	if km.state == nil || km.state.SOPINManager == nil {
		return false
	}
	return km.state.SOPINManager.IsSet
}

// IsUnlocked returns true if keys are available (manager is unlocked).
func (km *KeyManager) IsUnlocked() bool {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return km.unlockSource != unlockSourceNone
}

// IsSOUnlocked returns true if the manager was unlocked with SO PIN.
func (km *KeyManager) IsSOUnlocked() bool {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return km.unlockSource == unlockSourceSOPIN
}

// IsUserUnlocked returns true if the manager was unlocked with User PIN.
func (km *KeyManager) IsUserUnlocked() bool {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return km.unlockSource == unlockSourceUserPIN
}

// Lock clears all cached key material and locks the manager.
// After calling Lock, keys must be re-derived by calling UnlockWithSOPIN
// or UnlockWithUserPIN.
func (km *KeyManager) Lock() {
	km.mu.Lock()
	defer km.mu.Unlock()

	// Securely clear key material
	km.clearKeyMaterial()
}

// clearKeyMaterial zeroes and clears all cached keys.
// Must be called with km.mu held.
func (km *KeyManager) clearKeyMaterial() {
	if km.adminKey != nil {
		clearBytes(km.adminKey)
		km.adminKey = nil
	}
	if km.cmk != nil {
		clearBytes(km.cmk)
		km.cmk = nil
	}
	if km.smk != nil {
		clearBytes(km.smk)
		km.smk = nil
	}
	if km.umk != nil {
		clearBytes(km.umk)
		km.umk = nil
	}
	km.unlockSource = unlockSourceNone
}

// UnlockWithSOPIN unlocks the key manager using the Security Officer PIN.
// This derives SMK from the SO PIN, then unwraps AK, and uses AK to unwrap
// the SO copy of CMK.
//
// Returns ErrKeyManagerNoSOPIN if SO PIN is not configured.
// Returns an error if PIN verification or key unwrapping fails.
func (km *KeyManager) UnlockWithSOPIN(pin string) error {
	if !km.IsSOPINConfigured() {
		return ErrKeyManagerNoSOPIN
	}

	// Verify SO PIN and get SMK
	smk, err := km.state.SOPINManager.Verify(pin)
	if err != nil {
		return err
	}

	km.mu.Lock()
	defer km.mu.Unlock()

	// Store SMK
	km.smk = smk

	// Unwrap AK using SMK
	if len(km.state.WrappedAK) > 0 {
		akWrapper, err := NewAESGCMKeyWrapper(smk)
		if err != nil {
			km.clearKeyMaterial()
			return err
		}

		ak, err := akWrapper.Unwrap(km.state.WrappedAK)
		if err != nil {
			// AES-GCM authenticated unwrap failure means the SMK (and thus SO PIN)
			// is incorrect. Map the raw crypto error to a meaningful PIN error.
			km.state.SOPINManager.DecrementRetries()
			km.clearKeyMaterial()
			return ErrSOPINInvalid
		}
		km.adminKey = ak

		// Unwrap CMK using AK (SO copy)
		if len(km.state.WrappedCMKSO) > 0 {
			cmkWrapper, err := NewAESGCMKeyWrapper(ak)
			if err != nil {
				km.clearKeyMaterial()
				return err
			}

			cmk, err := cmkWrapper.Unwrap(km.state.WrappedCMKSO)
			if err != nil {
				km.clearKeyMaterial()
				return err
			}
			km.cmk = cmk
		}
	}

	km.unlockSource = unlockSourceSOPIN

	// Handle deferred PIN sync: if a FIDO2 PIN was set before SO PIN was
	// configured, sync the KeyManager now that SO is unlocked.
	if km.state.PINSyncPending && km.state.PINSet && len(km.state.PINHash) > 0 {
		if len(km.state.WrappedCMKUser) == 0 {
			_ = km.InitializeUserPIN(km.state.PINHash)
		} else {
			_ = km.ResetUserPIN(km.state.PINHash)
		}
		km.state.PINSyncPending = false
	}

	return nil
}

// UnlockWithUserPIN unlocks the key manager using the User PIN hash.
// This derives UMK from the PIN hash using Argon2id, then uses UMK to unwrap
// the user copy of CMK.
//
// The pinHash parameter should be the CTAP2-style PIN hash (left 16 bytes of SHA-256(PIN)).
//
// Returns ErrKeyManagerUserPINNotSet if user PIN is not configured.
// Returns an error if key unwrapping fails.
func (km *KeyManager) UnlockWithUserPIN(pinHash []byte) error {
	if km.state == nil || !km.state.PINSet {
		return ErrKeyManagerUserPINNotSet
	}

	// Derive UMK from PIN hash using Argon2id
	umk := km.deriveUMK(pinHash)
	if umk == nil {
		return ErrKeyManagerInvalidKey
	}

	km.mu.Lock()
	defer km.mu.Unlock()

	// Store UMK
	km.umk = umk

	// Unwrap CMK using UMK (user copy)
	if len(km.state.WrappedCMKUser) > 0 {
		cmkWrapper, err := NewAESGCMKeyWrapper(umk)
		if err != nil {
			km.clearKeyMaterial()
			return err
		}

		cmk, err := cmkWrapper.Unwrap(km.state.WrappedCMKUser)
		if err != nil {
			km.clearKeyMaterial()
			return err
		}
		km.cmk = cmk
	}

	km.unlockSource = unlockSourceUserPIN
	return nil
}

// deriveUMK derives the User Master Key from the PIN hash using Argon2id.
// Returns nil if the salt is not available.
func (km *KeyManager) deriveUMK(pinHash []byte) []byte {
	// Use a deterministic salt derived from state if not stored
	salt := km.getUMKSalt()
	if salt == nil {
		return nil
	}

	return argon2.IDKey(
		pinHash,
		salt,
		umkIterations,
		umkMemory,
		umkParallelism,
		umkDerivedKeySize,
	)
}

// getUMKSalt returns the salt for UMK derivation.
// If no salt is stored, it creates a deterministic salt from the SO PIN salt.
func (km *KeyManager) getUMKSalt() []byte {
	if km.umkSalt != nil {
		return km.umkSalt
	}

	// Use SO PIN salt as base for UMK salt if available
	if km.state.SOPINManager != nil && len(km.state.SOPINManager.Salt) > 0 {
		// Derive a distinct salt by XOR with a domain separator
		salt := make([]byte, umkSaltSize)
		copy(salt, km.state.SOPINManager.Salt)
		// XOR with domain separator "UMK-SALT" repeated
		domain := []byte("UMK-SALT")
		for i := range salt {
			salt[i] ^= domain[i%len(domain)]
		}
		return salt
	}

	// Fallback: generate from AAGUID (deterministic per authenticator)
	salt := make([]byte, umkSaltSize)
	copy(salt, km.state.AAGUID[:])
	// Pad with domain separator
	domain := []byte("UMK-SALT-FALLBACK")
	for i := 16; i < umkSaltSize; i++ {
		salt[i] = domain[(i-16)%len(domain)]
	}
	return salt
}

// InitializeSOPIN sets up the SO PIN for the first time.
// This generates AK and CMK, then wraps them appropriately:
//   - AK is wrapped with SMK (derived from SO PIN)
//   - CMK is wrapped with AK (SO copy)
//   - Attestation key is generated and wrapped with both AK and CMK
//
// Returns ErrKeyManagerAlreadyInitialized if SO PIN is already configured.
// Returns ErrSOPINPolicyViolation if the PIN does not meet policy requirements.
func (km *KeyManager) InitializeSOPIN(soPin string) error {
	if km.IsSOPINConfigured() {
		return ErrKeyManagerAlreadyInitialized
	}

	// Create SO PIN manager if not exists
	if km.state.SOPINManager == nil {
		km.state.SOPINManager = NewSOPINManager()
	}

	// Initialize SO PIN and get SMK
	smk, err := km.state.SOPINManager.Initialize(soPin)
	if err != nil {
		return err
	}

	// Generate random AK (32 bytes for AES-256)
	ak := make([]byte, AESGCMKeySize)
	if _, err := rand.Read(ak); err != nil {
		return ErrCryptoError
	}

	// Generate random CMK (32 bytes for AES-256)
	cmk := make([]byte, AESGCMKeySize)
	if _, err := rand.Read(cmk); err != nil {
		clearBytes(ak)
		return ErrCryptoError
	}

	// Wrap AK with SMK
	akWrapper, err := NewAESGCMKeyWrapper(smk)
	if err != nil {
		clearBytes(ak)
		clearBytes(cmk)
		return err
	}

	wrappedAK, err := akWrapper.Wrap(ak)
	if err != nil {
		clearBytes(ak)
		clearBytes(cmk)
		return err
	}

	// Wrap CMK with AK (SO copy)
	cmkWrapper, err := NewAESGCMKeyWrapper(ak)
	if err != nil {
		clearBytes(ak)
		clearBytes(cmk)
		return err
	}

	wrappedCMKSO, err := cmkWrapper.Wrap(cmk)
	if err != nil {
		clearBytes(ak)
		clearBytes(cmk)
		return err
	}

	// Generate attestation key
	attestKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		clearBytes(ak)
		clearBytes(cmk)
		return ErrKeyGenerationFailed
	}

	// Marshal attestation key to PKCS#8
	attestKeyPKCS8, err := x509.MarshalPKCS8PrivateKey(attestKey)
	if err != nil {
		clearBytes(ak)
		clearBytes(cmk)
		return ErrCryptoError
	}

	// Wrap attestation key with AK (SO copy)
	wrappedAttestSO, err := cmkWrapper.Wrap(attestKeyPKCS8)
	if err != nil {
		clearBytes(ak)
		clearBytes(cmk)
		clearBytes(attestKeyPKCS8)
		return err
	}

	// Wrap attestation key with CMK (User copy)
	attestUserWrapper, err := NewAESGCMKeyWrapper(cmk)
	if err != nil {
		clearBytes(ak)
		clearBytes(cmk)
		clearBytes(attestKeyPKCS8)
		return err
	}

	wrappedAttestUser, err := attestUserWrapper.Wrap(attestKeyPKCS8)
	if err != nil {
		clearBytes(ak)
		clearBytes(cmk)
		clearBytes(attestKeyPKCS8)
		return err
	}

	// Store wrapped keys in state
	km.state.WrappedAK = wrappedAK
	km.state.WrappedCMKSO = wrappedCMKSO
	km.state.WrappedAttestSO = wrappedAttestSO
	km.state.WrappedAttestUser = wrappedAttestUser
	km.state.AttestationKey = attestKey

	// Cache unwrapped keys
	km.mu.Lock()
	km.smk = smk
	km.adminKey = ak
	km.cmk = cmk
	km.unlockSource = unlockSourceSOPIN
	km.mu.Unlock()

	// Clear temporary PKCS#8 buffer
	clearBytes(attestKeyPKCS8)

	return nil
}

// InitializeUserPIN sets up the User PIN for the first time when SO PIN is active.
// This wraps the CMK with the UMK derived from the user PIN hash.
//
// Must be called while the manager is SO-unlocked.
//
// Returns ErrKeyManagerLocked if not unlocked with SO PIN.
// Returns ErrKeyManagerNoCMK if CMK is not available.
func (km *KeyManager) InitializeUserPIN(pinHash []byte) error {
	km.mu.Lock()
	defer km.mu.Unlock()

	if km.unlockSource != unlockSourceSOPIN {
		return ErrKeyManagerLocked
	}

	if km.cmk == nil {
		return ErrKeyManagerNoCMK
	}

	// Derive UMK from PIN hash
	umk := km.deriveUMK(pinHash)
	if umk == nil {
		return ErrKeyManagerInvalidKey
	}

	// Wrap CMK with UMK (user copy)
	cmkWrapper, err := NewAESGCMKeyWrapper(umk)
	if err != nil {
		clearBytes(umk)
		return err
	}

	wrappedCMKUser, err := cmkWrapper.Wrap(km.cmk)
	if err != nil {
		clearBytes(umk)
		return err
	}

	// Store wrapped CMK for user
	km.state.WrappedCMKUser = wrappedCMKUser
	km.umk = umk

	return nil
}

// WrapCredentialKey wraps a credential private key (PKCS#8 encoded) with CMK.
//
// Returns ErrKeyManagerLocked if the manager is not unlocked.
// Returns ErrKeyManagerNoCMK if CMK is not available.
func (km *KeyManager) WrapCredentialKey(privateKeyPKCS8 []byte) ([]byte, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()

	if km.unlockSource == unlockSourceNone {
		return nil, ErrKeyManagerLocked
	}

	if km.cmk == nil {
		return nil, ErrKeyManagerNoCMK
	}

	wrapper, err := NewAESGCMKeyWrapper(km.cmk)
	if err != nil {
		return nil, err
	}

	return wrapper.Wrap(privateKeyPKCS8)
}

// UnwrapCredentialKey unwraps a credential private key (PKCS#8 encoded) using CMK.
//
// Returns ErrKeyManagerLocked if the manager is not unlocked.
// Returns ErrKeyManagerNoCMK if CMK is not available.
func (km *KeyManager) UnwrapCredentialKey(wrapped []byte) ([]byte, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()

	if km.unlockSource == unlockSourceNone {
		return nil, ErrKeyManagerLocked
	}

	if km.cmk == nil {
		return nil, ErrKeyManagerNoCMK
	}

	wrapper, err := NewAESGCMKeyWrapper(km.cmk)
	if err != nil {
		return nil, err
	}

	return wrapper.Unwrap(wrapped)
}

// WrapAttestationKey wraps an attestation key for both SO and User access.
// The key is wrapped with AK (for SO) and CMK (for User).
//
// Must be called while the manager is SO-unlocked.
//
// Returns ErrKeyManagerLocked if not unlocked with SO PIN.
// Returns ErrKeyManagerNoAK if AK is not available.
// Returns ErrKeyManagerNoCMK if CMK is not available.
func (km *KeyManager) WrapAttestationKey(attestKeyPKCS8 []byte) error {
	km.mu.Lock()
	defer km.mu.Unlock()

	if km.unlockSource != unlockSourceSOPIN {
		return ErrKeyManagerLocked
	}

	if km.adminKey == nil {
		return ErrKeyManagerNoAK
	}

	// Wrap with AK (SO copy)
	akWrapper, err := NewAESGCMKeyWrapper(km.adminKey)
	if err != nil {
		return err
	}

	wrappedAttestSO, err := akWrapper.Wrap(attestKeyPKCS8)
	if err != nil {
		return err
	}

	// Wrap with CMK (User copy) if available
	var wrappedAttestUser []byte
	if km.cmk != nil {
		cmkWrapper, err := NewAESGCMKeyWrapper(km.cmk)
		if err != nil {
			return err
		}

		wrappedAttestUser, err = cmkWrapper.Wrap(attestKeyPKCS8)
		if err != nil {
			return err
		}
	}

	// Store wrapped keys
	km.state.WrappedAttestSO = wrappedAttestSO
	km.state.WrappedAttestUser = wrappedAttestUser

	// Parse and cache the attestation key
	key, err := x509.ParsePKCS8PrivateKey(attestKeyPKCS8)
	if err != nil {
		return ErrKeyManagerInvalidKey
	}

	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return ErrKeyManagerInvalidKey
	}

	km.state.AttestationKey = ecKey

	return nil
}

// GetAttestationKey returns the unwrapped attestation key.
// The key is unwrapped from the appropriate wrapped copy based on
// how the manager was unlocked.
//
// Returns ErrKeyManagerLocked if the manager is not unlocked.
// Returns ErrKeyManagerNoAttestKey if the attestation key is not available.
func (km *KeyManager) GetAttestationKey() (*ecdsa.PrivateKey, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()

	if km.unlockSource == unlockSourceNone {
		return nil, ErrKeyManagerLocked
	}

	// If already cached in state, return it
	if km.state.AttestationKey != nil {
		return km.state.AttestationKey, nil
	}

	var wrapped []byte
	var wrapper KeyWrapper

	switch km.unlockSource {
	case unlockSourceSOPIN:
		// Use AK to unwrap SO copy
		if km.adminKey == nil {
			return nil, ErrKeyManagerNoAK
		}
		if len(km.state.WrappedAttestSO) == 0 {
			return nil, ErrKeyManagerNoAttestKey
		}
		wrapped = km.state.WrappedAttestSO
		w, err := NewAESGCMKeyWrapper(km.adminKey)
		if err != nil {
			return nil, err
		}
		wrapper = w

	case unlockSourceUserPIN:
		// Use CMK to unwrap User copy
		if km.cmk == nil {
			return nil, ErrKeyManagerNoCMK
		}
		if len(km.state.WrappedAttestUser) == 0 {
			return nil, ErrKeyManagerNoAttestKey
		}
		wrapped = km.state.WrappedAttestUser
		w, err := NewAESGCMKeyWrapper(km.cmk)
		if err != nil {
			return nil, err
		}
		wrapper = w

	default:
		return nil, ErrKeyManagerLocked
	}

	// Unwrap the attestation key
	attestKeyPKCS8, err := wrapper.Unwrap(wrapped)
	if err != nil {
		return nil, err
	}
	defer clearBytes(attestKeyPKCS8)

	// Parse PKCS#8
	key, err := x509.ParsePKCS8PrivateKey(attestKeyPKCS8)
	if err != nil {
		return nil, ErrKeyManagerInvalidKey
	}

	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, ErrKeyManagerInvalidKey
	}

	return ecKey, nil
}

// ChangeSOPIN changes the SO PIN from the current PIN to a new PIN.
// This re-wraps AK with the new SMK derived from the new SO PIN.
//
// The currentSMK must be a valid SMK from the current SO PIN.
//
// Returns ErrKeyManagerNoSOPIN if SO PIN is not configured.
// Returns an error if PIN verification or key re-wrapping fails.
func (km *KeyManager) ChangeSOPIN(currentSMK []byte, newPIN string) error {
	if !km.IsSOPINConfigured() {
		return ErrKeyManagerNoSOPIN
	}

	// Change SO PIN in the manager (validates current SMK)
	newSMK, err := km.state.SOPINManager.Change(currentSMK, newPIN)
	if err != nil {
		return err
	}

	km.mu.Lock()
	defer km.mu.Unlock()

	// Unwrap AK using old SMK
	if len(km.state.WrappedAK) == 0 {
		clearBytes(newSMK)
		return ErrKeyManagerNoAK
	}

	oldWrapper, err := NewAESGCMKeyWrapper(currentSMK)
	if err != nil {
		clearBytes(newSMK)
		return err
	}

	ak, err := oldWrapper.Unwrap(km.state.WrappedAK)
	if err != nil {
		clearBytes(newSMK)
		// AES-GCM authenticated unwrap failure means the SMK (and thus SO PIN)
		// is incorrect. Map the raw crypto error to a meaningful PIN error.
		km.state.SOPINManager.DecrementRetries()
		return ErrSOPINInvalid
	}

	// Re-wrap AK with new SMK
	newWrapper, err := NewAESGCMKeyWrapper(newSMK)
	if err != nil {
		clearBytes(ak)
		clearBytes(newSMK)
		return err
	}

	newWrappedAK, err := newWrapper.Wrap(ak)
	if err != nil {
		clearBytes(ak)
		clearBytes(newSMK)
		return err
	}

	// Update state
	km.state.WrappedAK = newWrappedAK
	km.smk = newSMK
	km.adminKey = ak

	return nil
}

// ResetUserPIN resets the user PIN by re-wrapping CMK with a new UMK.
// This operation requires SO unlock to access CMK via the AK path.
//
// The newPINHash is the CTAP2-style PIN hash for the new PIN.
//
// Returns ErrKeyManagerLocked if not unlocked with SO PIN.
// Returns ErrKeyManagerNoCMK if CMK is not available.
func (km *KeyManager) ResetUserPIN(newPINHash []byte) error {
	km.mu.Lock()
	defer km.mu.Unlock()

	if km.unlockSource != unlockSourceSOPIN {
		return ErrKeyManagerLocked
	}

	if km.cmk == nil {
		return ErrKeyManagerNoCMK
	}

	// Derive new UMK from new PIN hash
	newUMK := km.deriveUMK(newPINHash)
	if newUMK == nil {
		return ErrKeyManagerInvalidKey
	}

	// Re-wrap CMK with new UMK
	cmkWrapper, err := NewAESGCMKeyWrapper(newUMK)
	if err != nil {
		clearBytes(newUMK)
		return err
	}

	newWrappedCMKUser, err := cmkWrapper.Wrap(km.cmk)
	if err != nil {
		clearBytes(newUMK)
		return err
	}

	// Update state
	km.state.WrappedCMKUser = newWrappedCMKUser

	// Update cached UMK
	if km.umk != nil {
		clearBytes(km.umk)
	}
	km.umk = newUMK

	return nil
}

// GetCMK returns a copy of the Credential Master Key.
// This is useful for external operations that need direct CMK access.
//
// Returns ErrKeyManagerLocked if the manager is not unlocked.
// Returns ErrKeyManagerNoCMK if CMK is not available.
func (km *KeyManager) GetCMK() ([]byte, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()

	if km.unlockSource == unlockSourceNone {
		return nil, ErrKeyManagerLocked
	}

	if km.cmk == nil {
		return nil, ErrKeyManagerNoCMK
	}

	// Return a copy to prevent external modification
	cmkCopy := make([]byte, len(km.cmk))
	copy(cmkCopy, km.cmk)
	return cmkCopy, nil
}

// SetUMKSalt sets the salt used for UMK derivation.
// This should be called during state initialization if a custom salt is stored.
func (km *KeyManager) SetUMKSalt(salt []byte) {
	km.mu.Lock()
	defer km.mu.Unlock()

	km.umkSalt = make([]byte, len(salt))
	copy(km.umkSalt, salt)
}

// GetUMKSalt returns a copy of the UMK derivation salt.
// Returns nil if no salt is configured.
func (km *KeyManager) GetUMKSalt() []byte {
	km.mu.RLock()
	defer km.mu.RUnlock()

	salt := km.getUMKSalt()
	if salt == nil {
		return nil
	}

	saltCopy := make([]byte, len(salt))
	copy(saltCopy, salt)
	return saltCopy
}
