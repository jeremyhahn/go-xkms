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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"io"
	"sync"

	"golang.org/x/crypto/argon2"

	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// KeyManager error types define error conditions for key management operations.
var (
	// ErrKeyManagerProtectedMemory indicates key material could not be placed
	// in memguard-backed protected memory. The plaintext is wiped before this
	// is returned; the operation fails rather than falling back to the heap.
	ErrKeyManagerProtectedMemory = errors.New("authenticator: cannot place key material in protected memory")

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

	// adminKey is the unwrapped Admin Key (from SMK).
	//
	// This and the three keys below are held in memguard-backed protected
	// memory: mlocked so they cannot be swapped to disk, canary-guarded, and
	// wiped deterministically by Destroy rather than by convention. They are
	// the keys that unwrap everything else in the hierarchy, so an attacker
	// who reads them does not need any of the keys they protect.
	//
	// Read them through WithBytes, not Bytes: only WithBytes holds the borrow
	// across the read, and a memguard failure anywhere in the process unmaps
	// every live enclave.
	//
	// Each key is decrypted DIRECTLY into its protected buffer:
	// unwrapIntoProtected allocates the destination before the borrow on the
	// wrapping key and KeyWrapper.UnwrapInto writes into it in place, so the
	// plaintext never transits the ordinary Go heap (#291 closed the heap
	// hop #285 had to leave open). This protects both the long-lived
	// exposure — material held for a whole unlocked session — and the
	// unwrap transit.
	adminKey *secure.Buffer

	// cmk is the Credential Master Key (unwrapped).
	cmk *secure.Buffer

	// smk is the Storage Master Key (derived from SO PIN).
	smk *secure.Buffer

	// umk is the User Master Key (derived from User PIN).
	umk *secure.Buffer

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
	km.adminKey.Destroy()
	km.adminKey = nil
	km.cmk.Destroy()
	km.cmk = nil
	km.smk.Destroy()
	km.smk = nil
	km.umk.Destroy()
	km.umk = nil
	km.unlockSource = unlockSourceNone
}

// adoptKeyMaterial moves plaintext into protected memory, destroying whatever
// the field held before and wiping the caller's copy.
//
// The caller must not use plaintext afterwards: secure.NewBufferFromBytes
// wipes it. Taking ownership here is deliberate — it makes a heap copy of key
// material short-lived by construction rather than by the caller remembering
// to clear it.
//
// The caller must hold km.mu for writing.
func adoptKeyMaterial(dst **secure.Buffer, plaintext []byte) error {
	buf, err := secure.NewBufferFromBytes(plaintext)
	if err != nil {
		secure.Wipe(plaintext)
		return &SentinelCauseError{Sentinel: ErrKeyManagerProtectedMemory, Cause: err}
	}
	(*dst).Destroy()
	*dst = buf
	return nil
}

// adoptProtected installs an already-protected buffer into a key field,
// destroying whatever the field held before. It is adoptKeyMaterial for
// material that never existed on the ordinary heap.
//
// The caller must hold km.mu for writing.
func adoptProtected(dst **secure.Buffer, buf *secure.Buffer) {
	(*dst).Destroy()
	*dst = buf
}

// unwrapIntoProtected unwraps AES-GCM wrapped key material directly into a
// freshly allocated protected buffer, borrowing the protected wrapping key
// only for the decrypt. The plaintext never exists on the ordinary Go heap.
//
// The order of operations is load-bearing, not stylistic: secure.NewBuffer is
// purge-class and takes the same purgeMu that WithBytes holds as a reader, so
// the destination MUST be allocated before the borrow on key is entered — a
// purge-class call inside a borrow self-deadlocks (go-qrdb pkg/secure:
// "Nested borrows are forbidden"). The AES-GCM format makes that possible:
// the plaintext length is derivable from the wrapped data without the key,
// and the callback then touches only a plain slice, never pkg/secure.
//
// On any failure the destination buffer is destroyed before returning, so no
// half-filled protected allocation leaks. Returns ErrKeyManagerLocked when
// key is nil, ErrKeyManagerProtectedMemory (wrapped) when the protected
// allocation fails, and the KeyWrapper errors otherwise.
func unwrapIntoProtected(key *secure.Buffer, wrapped []byte) (*secure.Buffer, error) {
	plainLen, err := aesGCMUnwrappedLen(wrapped)
	if err != nil {
		return nil, err
	}
	if plainLen == 0 {
		return nil, ErrInvalidWrappedData
	}

	dst, err := secure.NewBuffer(plainLen)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrKeyManagerProtectedMemory, Cause: err}
	}

	// Borrow-class read, released before the withKeyWrapper borrow below.
	// The slice stays valid for the life of dst; holding it across the
	// callback is the documented Bytes residue (go-qrdb#74), accepted because
	// no shape that holds the borrow instead can allocate or write without
	// nesting.
	raw := dst.Bytes()

	if err := withKeyWrapper(key, func(w KeyWrapper) error {
		return w.UnwrapInto(wrapped, raw)
	}); err != nil {
		dst.Destroy()
		return nil, err
	}

	return dst, nil
}

// wrapFromProtected wraps the key material held in src under the protected
// wrapping key, so neither the plaintext nor the wrapping key ever exists on
// the ordinary Go heap. It is the wrap-side counterpart of unwrapIntoProtected
// (go-xkms#387).
//
// The order of operations is load-bearing, not stylistic: borrows must not
// nest (go-qrdb pkg/secure: "Nested borrows are forbidden"), and WrapFrom
// borrows src. So the wrapping key is borrowed first, only long enough to
// expand it into the cipher's key schedule, and that borrow is released
// BEFORE WrapFrom takes its own on src. The wrapper outliving the key borrow
// is safe: aes.NewCipher copies the key into its schedule and retains no
// reference to the borrowed slice, so the wrapper holds exactly what a
// withKeyWrapper callback holds, for exactly as long — the rest of this call.
//
// Returns ErrKeyManagerLocked when key is nil, ErrInvalidWrapSource when src
// is nil or destroyed, and the KeyWrapper errors otherwise.
func wrapFromProtected(key, src *secure.Buffer) ([]byte, error) {
	var wrapper *AESGCMKeyWrapper
	if err := withKeyBytes(key, func(b []byte) error {
		w, err := NewAESGCMKeyWrapper(b)
		if err != nil {
			return err
		}
		wrapper = w
		return nil
	}); err != nil {
		return nil, err
	}
	return wrapper.WrapFrom(src)
}

// newRandomKeyBuffer allocates a protected buffer of size bytes and fills it
// from crypto/rand, so a freshly generated key never touches the ordinary Go
// heap. The purge-class allocation happens before the fill's borrow, never
// inside one. Returns ErrKeyManagerProtectedMemory (wrapped) if the
// allocation fails and ErrCryptoError (wrapped) if the random source fails.
func newRandomKeyBuffer(size int) (*secure.Buffer, error) {
	buf, err := secure.NewBuffer(size)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrKeyManagerProtectedMemory, Cause: err}
	}
	if err := buf.WithBytes(func(b []byte) error {
		_, err := rand.Read(b)
		return err
	}); err != nil {
		buf.Destroy()
		return nil, &SentinelCauseError{Sentinel: ErrCryptoError, Cause: err}
	}
	return buf, nil
}

// withKeyWrapper runs fn with an AES-GCM KeyWrapper built from a protected
// key, holding the memguard borrow for the whole call. The wrapper must not
// outlive fn.
//
// This is the shape every consumer of a protected key wants: the key's
// plaintext is borrowed, expanded into the cipher's key schedule, used, and
// the borrow released — without the plaintext ever being assigned to a
// variable the caller holds.
func withKeyWrapper(key *secure.Buffer, fn func(KeyWrapper) error) error {
	return withKeyBytes(key, func(b []byte) error {
		w, err := NewAESGCMKeyWrapper(b)
		if err != nil {
			return err
		}
		return fn(w)
	})
}

// withKeyBytes runs fn against a protected key's plaintext, holding the
// memguard borrow for the whole call. Returns ErrKeyManagerLocked when the key
// is absent, which is the state every caller previously spelled as a nil check.
func withKeyBytes(key *secure.Buffer, fn func([]byte) error) error {
	if key == nil {
		return ErrKeyManagerLocked
	}
	return key.WithBytes(fn)
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

	manager := km.state.SOPINManager

	// The retry is spent here, before the PIN is known to be right.
	smk, err := manager.BeginVerify(pin)
	if err != nil {
		return err
	}

	km.mu.Lock()
	defer km.mu.Unlock()

	// The wrapped Admin Key is the only thing that can prove the SMK, and
	// therefore the SO PIN, is correct. Without it there is nothing to verify
	// against, so any PIN would appear to succeed: refuse instead.
	if len(km.state.WrappedAK) == 0 {
		clearBytes(smk)
		return ErrKeyManagerNoAK
	}

	// Store SMK. adoptKeyMaterial wipes smk, so every later use reads the
	// protected copy through withKeyBytes rather than the heap slice.
	if err := adoptKeyMaterial(&km.smk, smk); err != nil {
		km.clearKeyMaterial()
		return err
	}

	// Unwrap AK using SMK, directly into protected memory: the plaintext
	// never touches the ordinary Go heap (go-xkms#291).
	akBuf, unwrapErr := unwrapIntoProtected(km.smk, km.state.WrappedAK)
	if unwrapErr != nil {
		km.clearKeyMaterial()
		if errors.Is(unwrapErr, ErrKeyManagerProtectedMemory) {
			// The protected allocation failing says nothing about the PIN;
			// charging it to the retry counter would burn attempts over a
			// memory condition the Security Officer cannot influence.
			return unwrapErr
		}
		// AES-GCM authenticated unwrap failure means the SMK (and thus SO PIN)
		// is incorrect. Map the raw crypto error to a meaningful PIN error.
		return manager.RecordFailure()
	}
	adoptProtected(&km.adminKey, akBuf)

	// The Admin Key unwrapped, so the SO PIN is proven. Restore the budget here
	// rather than after the CMK unwrap below: a corrupt CMK is a state problem,
	// not a failed authentication, and charging it to the retry counter would
	// lock the token out over something the Security Officer got right.
	manager.ConfirmVerified()

	// Unwrap CMK using AK (SO copy), directly into protected memory — the
	// wrapper is built from the protected AK inside the borrow, and the
	// plaintext CMK never touches the ordinary Go heap (go-xkms#291).
	if len(km.state.WrappedCMKSO) > 0 {
		cmkBuf, cmkErr := unwrapIntoProtected(km.adminKey, km.state.WrappedCMKSO)
		if cmkErr != nil {
			km.clearKeyMaterial()
			return cmkErr
		}
		adoptProtected(&km.cmk, cmkBuf)
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
	if err := adoptKeyMaterial(&km.umk, umk); err != nil {
		km.clearKeyMaterial()
		return err
	}

	// Unwrap CMK using UMK (user copy), directly into protected memory. umk
	// was wiped by adoptKeyMaterial above, so the wrapper is built from the
	// protected copy, and the plaintext CMK never touches the ordinary Go
	// heap (go-xkms#291).
	if len(km.state.WrappedCMKUser) > 0 {
		cmkBuf, cmkErr := unwrapIntoProtected(km.umk, km.state.WrappedCMKUser)
		if cmkErr != nil {
			km.clearKeyMaterial()
			return cmkErr
		}
		adoptProtected(&km.cmk, cmkBuf)
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

	// Generate AK and CMK (32 bytes each for AES-256) straight into protected
	// memory. Neither key ever exists on the ordinary Go heap: the random
	// bytes are written into the mlocked pages and every wrap below reads
	// them from there (go-xkms#387). Both purge-class allocations happen
	// before any borrow is taken.
	akBuf, err := newRandomKeyBuffer(AESGCMKeySize)
	if err != nil {
		clearBytes(smk)
		return err
	}
	cmkBuf, err := newRandomKeyBuffer(AESGCMKeySize)
	if err != nil {
		akBuf.Destroy()
		clearBytes(smk)
		return err
	}

	// Until the keys are adopted into the manager every failure path destroys
	// the protected buffers and wipes the SMK's heap copy.
	adopted := false
	defer func() {
		if !adopted {
			akBuf.Destroy()
			cmkBuf.Destroy()
			clearBytes(smk)
		}
	}()

	// Wrap AK with SMK. smk is the heap slice SOPINManager derived, so no
	// borrow is held here and WrapFrom's own borrow on akBuf does not nest.
	akWrapper, err := NewAESGCMKeyWrapper(smk)
	if err != nil {
		return err
	}
	wrappedAK, err := akWrapper.WrapFrom(akBuf)
	if err != nil {
		return err
	}

	// Wrap CMK with AK (SO copy)
	wrappedCMKSO, err := wrapFromProtected(akBuf, cmkBuf)
	if err != nil {
		return err
	}

	// Generate attestation key
	attestKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return ErrKeyGenerationFailed
	}

	// Marshal the attestation key to PKCS#8 and move the encoding into
	// protected memory at once: x509 can only marshal onto the heap, and
	// NewBufferFromBytes wipes that copy as it adopts it.
	attestKeyPKCS8, err := x509.MarshalPKCS8PrivateKey(attestKey)
	if err != nil {
		return ErrCryptoError
	}
	attestBuf, err := secure.NewBufferFromBytes(attestKeyPKCS8)
	if err != nil {
		clearBytes(attestKeyPKCS8)
		return &SentinelCauseError{Sentinel: ErrKeyManagerProtectedMemory, Cause: err}
	}
	defer attestBuf.Destroy()

	// Wrap attestation key with AK (SO copy) and with CMK (User copy)
	wrappedAttestSO, err := wrapFromProtected(akBuf, attestBuf)
	if err != nil {
		return err
	}
	wrappedAttestUser, err := wrapFromProtected(cmkBuf, attestBuf)
	if err != nil {
		return err
	}

	// Store wrapped keys in state
	km.state.WrappedAK = wrappedAK
	km.state.WrappedCMKSO = wrappedCMKSO
	km.state.WrappedAttestSO = wrappedAttestSO
	km.state.WrappedAttestUser = wrappedAttestUser

	// Cache the unwrapped keys. AK and CMK were born in protected memory and
	// are adopted as they are; adoptKeyMaterial moves the SMK in and wipes the
	// heap copy SOPINManager handed back.
	km.mu.Lock()
	defer km.mu.Unlock()
	if err := adoptKeyMaterial(&km.smk, smk); err != nil {
		km.clearKeyMaterial()
		return err
	}
	adoptProtected(&km.adminKey, akBuf)
	adoptProtected(&km.cmk, cmkBuf)
	adopted = true
	km.unlockSource = unlockSourceSOPIN

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

	// Wrap CMK with UMK (user copy). umk is a heap slice until the wrap
	// succeeds, so no borrow is held here and WrapFrom's own borrow on the
	// protected CMK does not nest; umk moves into protected memory only after
	// the wrap succeeds.
	cmkWrapper, err := NewAESGCMKeyWrapper(umk)
	if err != nil {
		secure.Wipe(umk)
		return err
	}

	wrappedCMKUser, err := cmkWrapper.WrapFrom(km.cmk)
	if err != nil {
		secure.Wipe(umk)
		return err
	}

	// Store wrapped CMK for user
	km.state.WrappedCMKUser = wrappedCMKUser
	if err := adoptKeyMaterial(&km.umk, umk); err != nil {
		return err
	}

	return nil
}

// WrapCredentialKey wraps a credential private key (PKCS#8 encoded, held in
// protected memory) with CMK.
//
// The caller keeps ownership of privateKeyPKCS8 and destroys it once the
// wrapped copy is stored. The plaintext is read from protected memory and is
// never copied onto the ordinary Go heap (go-xkms#387).
//
// Returns ErrKeyManagerLocked if the manager is not unlocked.
// Returns ErrKeyManagerNoCMK if CMK is not available.
// Returns ErrInvalidWrapSource if privateKeyPKCS8 is nil or destroyed.
func (km *KeyManager) WrapCredentialKey(privateKeyPKCS8 *secure.Buffer) ([]byte, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()

	if km.unlockSource == unlockSourceNone {
		return nil, ErrKeyManagerLocked
	}

	if km.cmk == nil {
		return nil, ErrKeyManagerNoCMK
	}

	return wrapFromProtected(km.cmk, privateKeyPKCS8)
}

// UnwrapCredentialKey unwraps a credential private key (PKCS#8 encoded) using CMK.
//
// The returned slice is allocated here, outside the borrow on CMK, and the
// decrypt writes into it in place — no plaintext copy exists that the caller
// does not own (go-xkms#291). The caller MUST wipe it (secure.Wipe) as soon
// as the key has been parsed or adopted into protected memory.
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

	plainLen, err := aesGCMUnwrappedLen(wrapped)
	if err != nil {
		return nil, err
	}
	plaintext := make([]byte, plainLen)
	if err := withKeyWrapper(km.cmk, func(w KeyWrapper) error {
		return w.UnwrapInto(wrapped, plaintext)
	}); err != nil {
		return nil, err
	}

	return plaintext, nil
}

// WrapAttestationKey wraps an attestation key (PKCS#8 encoded, held in
// protected memory) for both SO and User access. The key is wrapped with AK
// (for SO) and CMK (for User).
//
// The caller keeps ownership of attestKeyPKCS8 and destroys it afterwards.
// The plaintext is read from protected memory and is never copied onto the
// ordinary Go heap (go-xkms#387).
//
// Must be called while the manager is SO-unlocked.
//
// Returns ErrKeyManagerLocked if not unlocked with SO PIN.
// Returns ErrKeyManagerNoAK if AK is not available.
// Returns ErrKeyManagerInvalidKey if the material is not an ECDSA private key.
// Returns ErrInvalidWrapSource if attestKeyPKCS8 is nil or destroyed.
func (km *KeyManager) WrapAttestationKey(attestKeyPKCS8 *secure.Buffer) error {
	km.mu.Lock()
	defer km.mu.Unlock()

	if km.unlockSource != unlockSourceSOPIN {
		return ErrKeyManagerLocked
	}

	if km.adminKey == nil {
		return ErrKeyManagerNoAK
	}

	// Reject material that is not a usable attestation key before wrapping
	// anything, so a device cannot end up holding a wrapped blob it can never
	// sign with. The parse is a plain read of the borrowed bytes, and the
	// borrow is released before the wraps below take theirs.
	if err := attestKeyPKCS8.WithBytes(func(b []byte) error {
		key, err := x509.ParsePKCS8PrivateKey(b)
		if err != nil {
			return ErrKeyManagerInvalidKey
		}
		if _, ok := key.(*ecdsa.PrivateKey); !ok {
			return ErrKeyManagerInvalidKey
		}
		return nil
	}); err != nil {
		if errors.Is(err, ErrKeyManagerInvalidKey) {
			return err
		}
		return &SentinelCauseError{Sentinel: ErrInvalidWrapSource, Cause: err}
	}

	// Wrap with AK (SO copy)
	wrappedAttestSO, err := wrapFromProtected(km.adminKey, attestKeyPKCS8)
	if err != nil {
		return err
	}

	// Wrap with CMK (User copy) if available
	var wrappedAttestUser []byte
	if km.cmk != nil {
		wrappedAttestUser, err = wrapFromProtected(km.cmk, attestKeyPKCS8)
		if err != nil {
			return err
		}
	}

	// Only the wrapped copies are retained. The unwrapped key is never cached
	// on the Go heap: an *ecdsa.PrivateKey cannot be mlocked or reliably wiped,
	// so every use unwraps into protected memory and destroys it again.
	km.state.WrappedAttestSO = wrappedAttestSO
	km.state.WrappedAttestUser = wrappedAttestUser

	return nil
}

// AttestationSigner returns a crypto.Signer over the device attestation key.
//
// The key is never held unwrapped between operations. Each call to Sign unwraps
// the copy that matches how the manager was unlocked into protected memory,
// signs, and destroys the plaintext before returning. Only the AES-GCM wrapped
// copies are persisted, so neither the storage barrier nor the serialized state
// ever contains usable attestation key material.
//
// The manager must be unlocked. That makes attestation follow the SO/user key
// hierarchy rather than sitting outside it; a device that has not been unlocked
// since boot conveys no provenance and registers with the "none" format.
//
// Returns ErrKeyManagerLocked if the manager is not unlocked.
// Returns ErrKeyManagerNoAttestKey if no attestation key is provisioned.
func (km *KeyManager) AttestationSigner() (crypto.Signer, error) {
	// Resolving the public key proves the wrapped copy is present, unwrappable
	// and an ECDSA key, so callers see a provisioning failure here rather than
	// at signing time. The plaintext is destroyed before this returns.
	var publicKey *ecdsa.PublicKey
	err := km.withAttestationKey(func(key *ecdsa.PrivateKey) error {
		publicKey = key.Public().(*ecdsa.PublicKey)
		return nil
	})
	if err != nil {
		return nil, err
	}

	return &attestationSigner{keyManager: km, publicKey: publicKey}, nil
}

// attestationSigner signs with the device attestation key, unwrapping it for
// the duration of each signature and never retaining the private half.
type attestationSigner struct {
	keyManager *KeyManager

	// publicKey is the only part of the identity kept between operations; a
	// public key is not secret.
	publicKey *ecdsa.PublicKey
}

// Public returns the attestation public key.
func (s *attestationSigner) Public() crypto.PublicKey {
	return s.publicKey
}

// Sign unwraps the attestation key into protected memory, signs digest, and
// destroys the plaintext before returning.
// The parameter is named randReader rather than rand so the crypto/rand package
// stays reachable for the nil fallback below.
func (s *attestationSigner) Sign(randReader io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	// crypto.Signer callers may pass a nil reader; ECDSA needs one for its
	// hedged nonce, so fall back to the process CSPRNG rather than depending on
	// what the standard library does with nil.
	if randReader == nil {
		randReader = rand.Reader
	}

	var signature []byte
	err := s.keyManager.withAttestationKey(func(key *ecdsa.PrivateKey) error {
		sig, signErr := key.Sign(randReader, digest, opts)
		if signErr != nil {
			return signErr
		}
		signature = sig
		return nil
	})
	if err != nil {
		return nil, err
	}

	return signature, nil
}

// withAttestationKey unwraps the attestation key into an mlocked buffer, parses
// it, invokes fn, and destroys the buffer. The parsed *ecdsa.PrivateKey is
// transient — crypto/ecdsa cannot operate on protected memory directly — and is
// not retained beyond fn.
func (km *KeyManager) withAttestationKey(fn func(*ecdsa.PrivateKey) error) error {
	km.mu.RLock()
	defer km.mu.RUnlock()

	wrapped, unwrapKey, err := km.attestationUnwrapper()
	if err != nil {
		return err
	}

	// The destination buffer is allocated before the borrow on unwrapKey and
	// the decrypt writes straight into it, so the PKCS#8 plaintext never
	// exists on the ordinary Go heap (go-xkms#291). The ordering constraint
	// that used to force a heap hop here — NewBufferFromBytes is purge-class
	// and self-deadlocks inside a borrow — is honoured by unwrapIntoProtected
	// allocating first.
	buf, err := unwrapIntoProtected(unwrapKey, wrapped)
	if err != nil {
		return err
	}
	defer buf.Destroy()

	return buf.WithBytes(func(pkcs8 []byte) error {
		key, parseErr := x509.ParsePKCS8PrivateKey(pkcs8)
		if parseErr != nil {
			return ErrKeyManagerInvalidKey
		}

		ecKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return ErrKeyManagerInvalidKey
		}

		return fn(ecKey)
	})
}

// attestationUnwrapper selects the wrapped attestation copy and the protected
// key that unwraps it, matching how the manager was unlocked. The key is
// returned as the *secure.Buffer it is held in rather than as plaintext, so the
// borrow is taken by the caller for exactly the length of the unwrap.
// Must be called with km.mu held.
func (km *KeyManager) attestationUnwrapper() ([]byte, *secure.Buffer, error) {
	switch km.unlockSource {
	case unlockSourceSOPIN:
		// Use AK to unwrap SO copy
		if km.adminKey == nil {
			return nil, nil, ErrKeyManagerNoAK
		}
		if len(km.state.WrappedAttestSO) == 0 {
			return nil, nil, ErrKeyManagerNoAttestKey
		}
		return km.state.WrappedAttestSO, km.adminKey, nil

	case unlockSourceUserPIN:
		// Use CMK to unwrap User copy
		if km.cmk == nil {
			return nil, nil, ErrKeyManagerNoCMK
		}
		if len(km.state.WrappedAttestUser) == 0 {
			return nil, nil, ErrKeyManagerNoAttestKey
		}
		return km.state.WrappedAttestUser, km.cmk, nil

	default:
		return nil, nil, ErrKeyManagerLocked
	}
}

// ChangeSOPIN changes the SO PIN from the current PIN to a new PIN.
// This re-wraps AK with the new SMK derived from the new SO PIN.
//
// currentSMK must come from SOPINManager.BeginVerify: this method completes
// that exchange, calling ConfirmVerified on success (via Rekey) or
// RecordFailure when the Admin Key does not unwrap.
//
// Returns ErrKeyManagerNoSOPIN if SO PIN is not configured.
// Returns ErrKeyManagerNoAK if there is no wrapped Admin Key to authenticate
// against, ErrSOPINInvalid / ErrSOPINAuthBlocked / ErrSOPINBlocked when
// currentSMK is wrong, and ErrSOPINPolicyViolation for a malformed new PIN.
func (km *KeyManager) ChangeSOPIN(currentSMK []byte, newPIN string) error {
	if !km.IsSOPINConfigured() {
		return ErrKeyManagerNoSOPIN
	}

	km.mu.Lock()
	defer km.mu.Unlock()

	if len(km.state.WrappedAK) == 0 {
		return ErrKeyManagerNoAK
	}

	// Authenticate as Security Officer FIRST. Authenticated decryption of the
	// wrapped Admin Key is what proves currentSMK, and therefore the current SO
	// PIN, is correct. Nothing may be mutated before this succeeds: rotating
	// the salt on an unproven PIN would destroy the only key that can derive
	// the real SMK and brick the token.
	oldWrapper, err := NewAESGCMKeyWrapper(currentSMK)
	if err != nil {
		return err
	}

	// The Admin Key is decrypted directly into protected memory: the
	// destination is allocated first, and no borrow is held here (currentSMK
	// is the caller's heap slice), so there is no nesting hazard and no heap
	// transit (go-xkms#291).
	akLen, err := aesGCMUnwrappedLen(km.state.WrappedAK)
	if err != nil || akLen == 0 {
		return km.state.SOPINManager.RecordFailure()
	}
	akBuf, err := secure.NewBuffer(akLen)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrKeyManagerProtectedMemory, Cause: err}
	}
	akBytes := akBuf.Bytes()
	if err := oldWrapper.UnwrapInto(km.state.WrappedAK, akBytes); err != nil {
		akBuf.Destroy()
		return km.state.SOPINManager.RecordFailure()
	}

	newSMK, err := km.state.SOPINManager.Rekey(newPIN)
	if err != nil {
		akBuf.Destroy()
		return err
	}

	// Re-wrap AK with new SMK
	newWrapper, err := NewAESGCMKeyWrapper(newSMK)
	if err != nil {
		akBuf.Destroy()
		clearBytes(newSMK)
		return err
	}

	// newSMK is a heap slice, so no borrow is held here and WrapFrom's own
	// borrow on akBuf does not nest; the wrapped output it returns is
	// ciphertext and safe on the heap.
	newWrappedAK, err := newWrapper.WrapFrom(akBuf)
	if err != nil {
		akBuf.Destroy()
		clearBytes(newSMK)
		return err
	}

	// Update state
	km.state.WrappedAK = newWrappedAK
	if err := adoptKeyMaterial(&km.smk, newSMK); err != nil {
		akBuf.Destroy()
		km.clearKeyMaterial()
		return err
	}
	adoptProtected(&km.adminKey, akBuf)

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
		secure.Wipe(newUMK)
		return err
	}

	// newUMK is a heap slice until the wrap succeeds, so no borrow is held
	// here and WrapFrom's own borrow on the protected CMK does not nest.
	newWrappedCMKUser, err := cmkWrapper.WrapFrom(km.cmk)
	if err != nil {
		secure.Wipe(newUMK)
		return err
	}

	// Update state
	km.state.WrappedCMKUser = newWrappedCMKUser

	// Update cached UMK. adoptKeyMaterial destroys the previous buffer.
	if err := adoptKeyMaterial(&km.umk, newUMK); err != nil {
		return err
	}

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

	// Return a copy to prevent external modification.
	//
	// This hands a caller plaintext on the ordinary heap. The copy is the
	// caller's to wipe. (An earlier comment here justified the shape by
	// "callers mutate what they receive"; no non-test caller exists, so that
	// rationale described nobody and is withdrawn — recorded on #291.)
	var cmkCopy []byte
	if err := withKeyBytes(km.cmk, func(b []byte) error {
		cmkCopy = make([]byte, len(b))
		copy(cmkCopy, b)
		return nil
	}); err != nil {
		return nil, err
	}
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
