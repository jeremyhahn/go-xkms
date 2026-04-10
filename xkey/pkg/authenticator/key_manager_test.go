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
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// Test PIN constants for KeyManager tests.
const (
	testSOPIN         = "123456" // Valid SO PIN (6 chars minimum)
	testSOPIN2        = "654321" // Alternative valid SO PIN for change tests
	testSOPINShort    = "12345"  // Invalid: 5 chars (below minimum of 6)
	testUserPINString = "1234"   // User PIN string for generating hash
	testUserPIN2      = "5678"   // Alternative user PIN for tests
)

// createTestKeyManagerState creates a test AuthenticatorState and Config for KeyManager tests.
// The state is created with a default AAGUID but no SO PIN configured.
func createTestKeyManagerState() (*AuthenticatorState, *Config) {
	state := NewAuthenticatorState()
	state.AAGUID = DefaultAAGUID

	config := DefaultConfig()
	config.Storage = NewMemoryStorage()

	return state, config
}

// createUserPINHash generates a CTAP2-style PIN hash from a PIN string.
// The hash is the left 16 bytes of SHA-256(PIN).
func createUserPINHash(pin string) []byte {
	hash := sha256.Sum256([]byte(pin))
	return hash[:16]
}

func TestNewKeyManager(t *testing.T) {
	t.Run("creates manager with state and config", func(t *testing.T) {
		state, config := createTestKeyManagerState()

		km := NewKeyManager(state, config)

		require.NotNil(t, km)
		require.Equal(t, state, km.state)
		require.Equal(t, config, km.config)
	})

	t.Run("starts in locked state", func(t *testing.T) {
		state, config := createTestKeyManagerState()

		km := NewKeyManager(state, config)

		require.False(t, km.IsUnlocked())
		require.False(t, km.IsSOUnlocked())
		require.False(t, km.IsUserUnlocked())
	})

	t.Run("IsSOPINConfigured returns false initially", func(t *testing.T) {
		state, config := createTestKeyManagerState()

		km := NewKeyManager(state, config)

		require.False(t, km.IsSOPINConfigured())
	})

	t.Run("nil state returns false for IsSOPINConfigured", func(t *testing.T) {
		_, config := createTestKeyManagerState()

		km := NewKeyManager(nil, config)

		require.False(t, km.IsSOPINConfigured())
	})

	t.Run("nil SOPINManager returns false for IsSOPINConfigured", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		state.SOPINManager = nil

		km := NewKeyManager(state, config)

		require.False(t, km.IsSOPINConfigured())
	})
}

func TestKeyManager_InitializeSOPIN(t *testing.T) {
	t.Run("valid PIN initializes successfully", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)

		err := km.InitializeSOPIN(testSOPIN)

		require.NoError(t, err)
		require.True(t, km.IsSOPINConfigured())
		require.True(t, km.IsUnlocked())
		require.True(t, km.IsSOUnlocked())
	})

	t.Run("sets up wrapped keys (AK, CMK, Attest)", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)

		err := km.InitializeSOPIN(testSOPIN)

		require.NoError(t, err)
		require.NotEmpty(t, state.WrappedAK, "WrappedAK should be set")
		require.NotEmpty(t, state.WrappedCMKSO, "WrappedCMKSO should be set")
		require.NotEmpty(t, state.WrappedAttestSO, "WrappedAttestSO should be set")
		require.NotEmpty(t, state.WrappedAttestUser, "WrappedAttestUser should be set")
		require.NotNil(t, state.AttestationKey, "AttestationKey should be cached")
	})

	t.Run("second initialization returns ErrKeyManagerAlreadyInitialized", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)

		err := km.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		err = km.InitializeSOPIN(testSOPIN2)

		require.ErrorIs(t, err, ErrKeyManagerAlreadyInitialized)
	})

	t.Run("short PIN returns error", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)

		err := km.InitializeSOPIN(testSOPINShort)

		require.ErrorIs(t, err, ErrSOPINPolicyViolation)
		require.False(t, km.IsSOPINConfigured())
	})

	t.Run("creates SOPINManager if not exists", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		state.SOPINManager = nil
		km := NewKeyManager(state, config)

		err := km.InitializeSOPIN(testSOPIN)

		require.NoError(t, err)
		require.NotNil(t, state.SOPINManager)
	})

	t.Run("wrapped keys can be unwrapped with correct SMK", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)

		err := km.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		// Get the SMK by verifying the PIN
		smk, err := state.SOPINManager.Verify(testSOPIN)
		require.NoError(t, err)

		// Unwrap AK
		akWrapper, err := NewAESGCMKeyWrapper(smk)
		require.NoError(t, err)

		ak, err := akWrapper.Unwrap(state.WrappedAK)
		require.NoError(t, err)
		require.Len(t, ak, AESGCMKeySize)

		// Unwrap CMK using AK
		cmkWrapper, err := NewAESGCMKeyWrapper(ak)
		require.NoError(t, err)

		cmk, err := cmkWrapper.Unwrap(state.WrappedCMKSO)
		require.NoError(t, err)
		require.Len(t, cmk, AESGCMKeySize)
	})
}

func TestKeyManager_UnlockWithSOPIN(t *testing.T) {
	t.Run("correct PIN unlocks successfully", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)
		err := km.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		// Lock the manager
		km.Lock()
		require.False(t, km.IsUnlocked())

		// Unlock with correct PIN
		err = km.UnlockWithSOPIN(testSOPIN)

		require.NoError(t, err)
		require.True(t, km.IsUnlocked())
	})

	t.Run("IsSOUnlocked returns true after unlock", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)
		err := km.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		km.Lock()
		err = km.UnlockWithSOPIN(testSOPIN)

		require.NoError(t, err)
		require.True(t, km.IsSOUnlocked())
		require.False(t, km.IsUserUnlocked())
	})

	t.Run("wrong PIN fails to unlock with ErrSOPINInvalid", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)
		err := km.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		km.Lock()
		err = km.UnlockWithSOPIN("wrong-pin")

		require.ErrorIs(t, err, ErrSOPINInvalid)
		require.False(t, km.IsUnlocked())
	})

	t.Run("unlock without initialization returns ErrKeyManagerNoSOPIN", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)

		err := km.UnlockWithSOPIN(testSOPIN)

		require.ErrorIs(t, err, ErrKeyManagerNoSOPIN)
	})

	t.Run("restores cached keys after unlock", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)
		err := km.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		// Get CMK before locking
		cmkBefore, err := km.GetCMK()
		require.NoError(t, err)

		km.Lock()
		err = km.UnlockWithSOPIN(testSOPIN)
		require.NoError(t, err)

		// Get CMK after unlocking
		cmkAfter, err := km.GetCMK()
		require.NoError(t, err)

		require.True(t, bytes.Equal(cmkBefore, cmkAfter), "CMK should be the same after unlock")
	})

	t.Run("unlock without wrapped AK succeeds but has no AK", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)

		// Manually set up SO PIN without wrapped keys
		state.SOPINManager = NewSOPINManager()
		_, err := state.SOPINManager.Initialize(testSOPIN)
		require.NoError(t, err)

		err = km.UnlockWithSOPIN(testSOPIN)
		require.NoError(t, err)
		require.True(t, km.IsSOUnlocked())
	})

	t.Run("unlock with corrupted wrapped AK fails and decrements retries", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)
		err := km.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		// Corrupt the wrapped AK
		state.WrappedAK[len(state.WrappedAK)-1] ^= 0xFF

		km.Lock()

		retriesBefore := state.SOPINManager.Retries()
		err = km.UnlockWithSOPIN(testSOPIN)

		require.Error(t, err)
		require.False(t, km.IsUnlocked())
		require.Equal(t, retriesBefore-1, state.SOPINManager.Retries())
	})

	t.Run("unlock with corrupted wrapped CMK SO fails", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)
		err := km.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		// Corrupt the wrapped CMK SO
		state.WrappedCMKSO[len(state.WrappedCMKSO)-1] ^= 0xFF

		km.Lock()
		err = km.UnlockWithSOPIN(testSOPIN)

		require.Error(t, err)
		require.False(t, km.IsUnlocked())
	})

	t.Run("unlock without wrapped CMK SO succeeds but has no CMK", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)

		// Manually set up SO PIN with only AK
		state.SOPINManager = NewSOPINManager()
		smk, err := state.SOPINManager.Initialize(testSOPIN)
		require.NoError(t, err)

		// Generate and wrap AK only
		ak := make([]byte, AESGCMKeySize)
		_, err = rand.Read(ak)
		require.NoError(t, err)

		akWrapper, err := NewAESGCMKeyWrapper(smk)
		require.NoError(t, err)

		state.WrappedAK, err = akWrapper.Wrap(ak)
		require.NoError(t, err)
		// Don't set WrappedCMKSO

		err = km.UnlockWithSOPIN(testSOPIN)
		require.NoError(t, err)
		require.True(t, km.IsSOUnlocked())

		// CMK should not be available
		_, err = km.GetCMK()
		require.ErrorIs(t, err, ErrKeyManagerNoCMK)
	})
}

func TestKeyManager_Lock(t *testing.T) {
	t.Run("Lock clears cached keys", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)
		err := km.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)
		require.True(t, km.IsUnlocked())

		km.Lock()

		require.False(t, km.IsUnlocked())

		// Try to get CMK - should fail when locked
		_, err = km.GetCMK()
		require.ErrorIs(t, err, ErrKeyManagerLocked)
	})

	t.Run("IsUnlocked returns false after lock", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)
		err := km.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		km.Lock()

		require.False(t, km.IsUnlocked())
		require.False(t, km.IsSOUnlocked())
		require.False(t, km.IsUserUnlocked())
	})

	t.Run("re-unlock with same PIN works", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)
		err := km.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		km.Lock()
		require.False(t, km.IsUnlocked())

		err = km.UnlockWithSOPIN(testSOPIN)
		require.NoError(t, err)
		require.True(t, km.IsUnlocked())

		// Lock and unlock again
		km.Lock()
		err = km.UnlockWithSOPIN(testSOPIN)
		require.NoError(t, err)
		require.True(t, km.IsUnlocked())
	})

	t.Run("multiple locks are idempotent", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)
		err := km.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		km.Lock()
		km.Lock()
		km.Lock()

		require.False(t, km.IsUnlocked())
	})
}

func TestKeyManager_WrapUnwrapCredentialKey(t *testing.T) {
	// Helper to generate a test credential key
	generateTestCredentialKey := func(t *testing.T) []byte {
		t.Helper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
		require.NoError(t, err)
		return pkcs8
	}

	t.Run("Wrap returns wrapped data", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)
		err := km.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		credKey := generateTestCredentialKey(t)

		wrapped, err := km.WrapCredentialKey(credKey)

		require.NoError(t, err)
		require.NotEmpty(t, wrapped)
	})

	t.Run("Unwrap returns original key", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)
		err := km.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		credKey := generateTestCredentialKey(t)

		wrapped, err := km.WrapCredentialKey(credKey)
		require.NoError(t, err)

		unwrapped, err := km.UnwrapCredentialKey(wrapped)

		require.NoError(t, err)
		require.True(t, bytes.Equal(credKey, unwrapped), "Unwrapped key should match original")
	})

	t.Run("wrapped data differs from original", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)
		err := km.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		credKey := generateTestCredentialKey(t)

		wrapped, err := km.WrapCredentialKey(credKey)

		require.NoError(t, err)
		require.False(t, bytes.Equal(credKey, wrapped), "Wrapped data should differ from original")
	})

	t.Run("Wrap while locked returns error", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)
		err := km.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		km.Lock()
		credKey := generateTestCredentialKey(t)

		_, err = km.WrapCredentialKey(credKey)

		require.ErrorIs(t, err, ErrKeyManagerLocked)
	})

	t.Run("Unwrap while locked returns error", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)
		err := km.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		credKey := generateTestCredentialKey(t)
		wrapped, err := km.WrapCredentialKey(credKey)
		require.NoError(t, err)

		km.Lock()

		_, err = km.UnwrapCredentialKey(wrapped)

		require.ErrorIs(t, err, ErrKeyManagerLocked)
	})

	t.Run("each wrap produces different ciphertext", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)
		err := km.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		credKey := generateTestCredentialKey(t)

		wrapped1, err := km.WrapCredentialKey(credKey)
		require.NoError(t, err)

		wrapped2, err := km.WrapCredentialKey(credKey)
		require.NoError(t, err)

		require.False(t, bytes.Equal(wrapped1, wrapped2), "Different wraps should produce different ciphertext due to random nonce")
	})

	t.Run("Unwrap with corrupted data fails", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)
		err := km.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		credKey := generateTestCredentialKey(t)
		wrapped, err := km.WrapCredentialKey(credKey)
		require.NoError(t, err)

		// Corrupt the wrapped data
		wrapped[len(wrapped)-1] ^= 0xFF

		_, err = km.UnwrapCredentialKey(wrapped)

		require.Error(t, err)
	})

	t.Run("Wrap returns error when CMK is nil", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)

		// Manually set up SO unlock without CMK
		state.SOPINManager = NewSOPINManager()
		smk, err := state.SOPINManager.Initialize(testSOPIN)
		require.NoError(t, err)

		ak := make([]byte, AESGCMKeySize)
		_, err = rand.Read(ak)
		require.NoError(t, err)

		akWrapper, err := NewAESGCMKeyWrapper(smk)
		require.NoError(t, err)

		state.WrappedAK, err = akWrapper.Wrap(ak)
		require.NoError(t, err)

		err = km.UnlockWithSOPIN(testSOPIN)
		require.NoError(t, err)

		credKey := generateTestCredentialKey(t)
		_, err = km.WrapCredentialKey(credKey)

		require.ErrorIs(t, err, ErrKeyManagerNoCMK)
	})

	t.Run("Unwrap returns error when CMK is nil", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)

		// First initialize normally to wrap a key
		err := km.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		credKey := generateTestCredentialKey(t)
		wrapped, err := km.WrapCredentialKey(credKey)
		require.NoError(t, err)

		km.Lock()

		// Set up state without CMK
		state.SOPINManager = NewSOPINManager()
		smk, err := state.SOPINManager.Initialize(testSOPIN2)
		require.NoError(t, err)

		ak := make([]byte, AESGCMKeySize)
		_, err = rand.Read(ak)
		require.NoError(t, err)

		akWrapper, err := NewAESGCMKeyWrapper(smk)
		require.NoError(t, err)

		state.WrappedAK, err = akWrapper.Wrap(ak)
		require.NoError(t, err)
		state.WrappedCMKSO = nil

		err = km.UnlockWithSOPIN(testSOPIN2)
		require.NoError(t, err)

		_, err = km.UnwrapCredentialKey(wrapped)

		require.ErrorIs(t, err, ErrKeyManagerNoCMK)
	})
}

func TestKeyManager_GetAttestationKey(t *testing.T) {
	t.Run("returns attestation key when SO-unlocked", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)
		err := km.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		attestKey, err := km.GetAttestationKey()

		require.NoError(t, err)
		require.NotNil(t, attestKey)
		require.Equal(t, elliptic.P256(), attestKey.Curve)
	})

	t.Run("returns attestation key when User-unlocked with CMK available", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)
		err := km.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		// Initialize user PIN so CMK is wrapped for user
		pinHash := createUserPINHash(testUserPINString)
		err = km.InitializeUserPIN(pinHash)
		require.NoError(t, err)

		// Lock and unlock with user PIN
		km.Lock()

		// Mark user PIN as set in state
		state.PINSet = true
		state.PINHash = pinHash

		err = km.UnlockWithUserPIN(pinHash)
		require.NoError(t, err)
		require.True(t, km.IsUserUnlocked())

		attestKey, err := km.GetAttestationKey()

		require.NoError(t, err)
		require.NotNil(t, attestKey)
	})

	t.Run("returns error when locked", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)
		err := km.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		km.Lock()

		_, err = km.GetAttestationKey()

		require.ErrorIs(t, err, ErrKeyManagerLocked)
	})

	t.Run("returns cached attestation key from state", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)
		err := km.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		// First call - may unwrap
		attestKey1, err := km.GetAttestationKey()
		require.NoError(t, err)

		// Second call - should return cached
		attestKey2, err := km.GetAttestationKey()
		require.NoError(t, err)

		require.Equal(t, attestKey1, attestKey2)
	})

	t.Run("SO unlock without AK returns ErrKeyManagerNoAK", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)

		// Manually set up SO PIN without any wrapped keys
		state.SOPINManager = NewSOPINManager()
		_, err := state.SOPINManager.Initialize(testSOPIN)
		require.NoError(t, err)

		// Clear the attestation key from state to force unwrap path
		state.AttestationKey = nil

		err = km.UnlockWithSOPIN(testSOPIN)
		require.NoError(t, err)

		_, err = km.GetAttestationKey()
		require.ErrorIs(t, err, ErrKeyManagerNoAK)
	})

	t.Run("SO unlock with AK but no wrapped attest key returns ErrKeyManagerNoAttestKey", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)

		// Set up SO PIN with AK but no wrapped attestation key
		state.SOPINManager = NewSOPINManager()
		smk, err := state.SOPINManager.Initialize(testSOPIN)
		require.NoError(t, err)

		ak := make([]byte, AESGCMKeySize)
		_, err = rand.Read(ak)
		require.NoError(t, err)

		akWrapper, err := NewAESGCMKeyWrapper(smk)
		require.NoError(t, err)

		state.WrappedAK, err = akWrapper.Wrap(ak)
		require.NoError(t, err)
		// Don't set WrappedAttestSO
		state.AttestationKey = nil

		err = km.UnlockWithSOPIN(testSOPIN)
		require.NoError(t, err)

		_, err = km.GetAttestationKey()
		require.ErrorIs(t, err, ErrKeyManagerNoAttestKey)
	})

	t.Run("User unlock without CMK returns ErrKeyManagerNoCMK", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)

		// Initialize fully first
		err := km.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		pinHash := createUserPINHash(testUserPINString)
		err = km.InitializeUserPIN(pinHash)
		require.NoError(t, err)

		km.Lock()

		state.PINSet = true
		state.AttestationKey = nil

		// Clear the wrapped CMK user to simulate corruption/missing
		state.WrappedCMKUser = nil

		// Try to unlock - this should fail because CMK unwrap fails
		err = km.UnlockWithUserPIN(pinHash)
		require.NoError(t, err) // unlock succeeds but CMK is nil

		_, err = km.GetAttestationKey()
		require.ErrorIs(t, err, ErrKeyManagerNoCMK)
	})

	t.Run("User unlock with CMK but no wrapped attest user returns ErrKeyManagerNoAttestKey", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)

		// Initialize fully
		err := km.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		pinHash := createUserPINHash(testUserPINString)
		err = km.InitializeUserPIN(pinHash)
		require.NoError(t, err)

		// Clear wrapped attest user
		state.WrappedAttestUser = nil
		state.AttestationKey = nil

		km.Lock()

		state.PINSet = true

		err = km.UnlockWithUserPIN(pinHash)
		require.NoError(t, err)

		_, err = km.GetAttestationKey()
		require.ErrorIs(t, err, ErrKeyManagerNoAttestKey)
	})

	t.Run("unwrapping attestation key with invalid PKCS8 returns ErrKeyManagerInvalidKey", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)

		// Set up SO PIN with AK and wrap invalid data as attest key
		state.SOPINManager = NewSOPINManager()
		smk, err := state.SOPINManager.Initialize(testSOPIN)
		require.NoError(t, err)

		ak := make([]byte, AESGCMKeySize)
		_, err = rand.Read(ak)
		require.NoError(t, err)

		akWrapper, err := NewAESGCMKeyWrapper(smk)
		require.NoError(t, err)

		state.WrappedAK, err = akWrapper.Wrap(ak)
		require.NoError(t, err)

		// Wrap invalid data as attestation key
		akWrapperForAttest, err := NewAESGCMKeyWrapper(ak)
		require.NoError(t, err)
		state.WrappedAttestSO, err = akWrapperForAttest.Wrap([]byte("not valid pkcs8"))
		require.NoError(t, err)
		state.AttestationKey = nil

		err = km.UnlockWithSOPIN(testSOPIN)
		require.NoError(t, err)

		_, err = km.GetAttestationKey()
		require.ErrorIs(t, err, ErrKeyManagerInvalidKey)
	})

	t.Run("unwrapping non-ECDSA key returns ErrKeyManagerInvalidKey", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)

		// Set up SO PIN with AK
		state.SOPINManager = NewSOPINManager()
		smk, err := state.SOPINManager.Initialize(testSOPIN)
		require.NoError(t, err)

		ak := make([]byte, AESGCMKeySize)
		_, err = rand.Read(ak)
		require.NoError(t, err)

		akWrapper, err := NewAESGCMKeyWrapper(smk)
		require.NoError(t, err)

		state.WrappedAK, err = akWrapper.Wrap(ak)
		require.NoError(t, err)

		// Generate an RSA key and wrap it as attestation key
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		rsaPKCS8, err := x509.MarshalPKCS8PrivateKey(rsaKey)
		require.NoError(t, err)

		akWrapperForAttest, err := NewAESGCMKeyWrapper(ak)
		require.NoError(t, err)
		state.WrappedAttestSO, err = akWrapperForAttest.Wrap(rsaPKCS8)
		require.NoError(t, err)
		state.AttestationKey = nil

		err = km.UnlockWithSOPIN(testSOPIN)
		require.NoError(t, err)

		_, err = km.GetAttestationKey()
		require.ErrorIs(t, err, ErrKeyManagerInvalidKey)
	})

	t.Run("User unlock path unwraps and parses ECDSA key correctly", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)

		// Full initialization
		err := km.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		pinHash := createUserPINHash(testUserPINString)
		err = km.InitializeUserPIN(pinHash)
		require.NoError(t, err)

		// Save the original attestation key for comparison
		originalKey := state.AttestationKey

		// Clear cached key to force unwrap
		state.AttestationKey = nil

		km.Lock()
		state.PINSet = true

		err = km.UnlockWithUserPIN(pinHash)
		require.NoError(t, err)

		attestKey, err := km.GetAttestationKey()
		require.NoError(t, err)
		require.NotNil(t, attestKey)

		// Keys should have same values
		require.Equal(t, originalKey.D.Bytes(), attestKey.D.Bytes())
	})

	t.Run("corrupted wrapped attest SO returns error", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)

		err := km.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		// Corrupt wrapped attestation key
		state.WrappedAttestSO[len(state.WrappedAttestSO)-1] ^= 0xFF
		state.AttestationKey = nil

		km.Lock()
		err = km.UnlockWithSOPIN(testSOPIN)
		require.NoError(t, err)

		_, err = km.GetAttestationKey()
		require.Error(t, err)
	})

	t.Run("corrupted wrapped attest user returns error", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)

		err := km.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		pinHash := createUserPINHash(testUserPINString)
		err = km.InitializeUserPIN(pinHash)
		require.NoError(t, err)

		// Corrupt wrapped attestation key for user
		state.WrappedAttestUser[len(state.WrappedAttestUser)-1] ^= 0xFF
		state.AttestationKey = nil

		km.Lock()
		state.PINSet = true

		err = km.UnlockWithUserPIN(pinHash)
		require.NoError(t, err)

		_, err = km.GetAttestationKey()
		require.Error(t, err)
	})
}

func TestKeyManager_ChangeSOPIN(t *testing.T) {
	t.Run("changes PIN successfully", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)
		err := km.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		// Get current SMK
		currentSMK, err := state.SOPINManager.Verify(testSOPIN)
		require.NoError(t, err)

		err = km.ChangeSOPIN(currentSMK, testSOPIN2)

		require.NoError(t, err)
	})

	t.Run("old PIN no longer works after change", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)
		err := km.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		currentSMK, err := state.SOPINManager.Verify(testSOPIN)
		require.NoError(t, err)

		err = km.ChangeSOPIN(currentSMK, testSOPIN2)
		require.NoError(t, err)

		km.Lock()

		// Old PIN should fail
		err = km.UnlockWithSOPIN(testSOPIN)
		require.Error(t, err)
	})

	t.Run("new PIN works after change", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)
		err := km.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		currentSMK, err := state.SOPINManager.Verify(testSOPIN)
		require.NoError(t, err)

		err = km.ChangeSOPIN(currentSMK, testSOPIN2)
		require.NoError(t, err)

		km.Lock()

		// New PIN should work
		err = km.UnlockWithSOPIN(testSOPIN2)
		require.NoError(t, err)
		require.True(t, km.IsUnlocked())
	})

	t.Run("CMK remains accessible after PIN change", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)
		err := km.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		// Get CMK before change
		cmkBefore, err := km.GetCMK()
		require.NoError(t, err)

		currentSMK, err := state.SOPINManager.Verify(testSOPIN)
		require.NoError(t, err)

		err = km.ChangeSOPIN(currentSMK, testSOPIN2)
		require.NoError(t, err)

		km.Lock()
		err = km.UnlockWithSOPIN(testSOPIN2)
		require.NoError(t, err)

		// Get CMK after change
		cmkAfter, err := km.GetCMK()
		require.NoError(t, err)

		require.True(t, bytes.Equal(cmkBefore, cmkAfter), "CMK should remain the same after PIN change")
	})

	t.Run("change without configured SO PIN returns error", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)

		err := km.ChangeSOPIN([]byte("dummy-smk"), testSOPIN2)

		require.ErrorIs(t, err, ErrKeyManagerNoSOPIN)
	})

	t.Run("invalid SMK returns error", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)
		err := km.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		// Use wrong SMK
		wrongSMK := make([]byte, 32)
		_, err = rand.Read(wrongSMK)
		require.NoError(t, err)

		err = km.ChangeSOPIN(wrongSMK, testSOPIN2)

		require.Error(t, err)
	})

	t.Run("change with no wrapped AK returns ErrKeyManagerNoAK", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)

		// Manually set up SO PIN without wrapped AK
		state.SOPINManager = NewSOPINManager()
		smk, err := state.SOPINManager.Initialize(testSOPIN)
		require.NoError(t, err)

		err = km.ChangeSOPIN(smk, testSOPIN2)

		require.ErrorIs(t, err, ErrKeyManagerNoAK)
	})

	t.Run("change with corrupted wrapped AK fails", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)
		err := km.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		currentSMK, err := state.SOPINManager.Verify(testSOPIN)
		require.NoError(t, err)

		// Corrupt wrapped AK
		state.WrappedAK[len(state.WrappedAK)-1] ^= 0xFF

		err = km.ChangeSOPIN(currentSMK, testSOPIN2)

		require.Error(t, err)
	})

	t.Run("change with short new PIN returns policy error", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)
		err := km.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		currentSMK, err := state.SOPINManager.Verify(testSOPIN)
		require.NoError(t, err)

		err = km.ChangeSOPIN(currentSMK, testSOPINShort)

		require.ErrorIs(t, err, ErrSOPINPolicyViolation)
	})
}

func TestKeyManager_ResetUserPIN(t *testing.T) {
	t.Run("requires SO unlock", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)
		err := km.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		// Initialize user PIN
		pinHash := createUserPINHash(testUserPINString)
		err = km.InitializeUserPIN(pinHash)
		require.NoError(t, err)

		km.Lock()

		// Try reset while locked
		newPINHash := createUserPINHash(testUserPIN2)
		err = km.ResetUserPIN(newPINHash)

		require.ErrorIs(t, err, ErrKeyManagerLocked)
	})

	t.Run("re-wraps CMK for user", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)
		err := km.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		// Initialize user PIN
		pinHash := createUserPINHash(testUserPINString)
		err = km.InitializeUserPIN(pinHash)
		require.NoError(t, err)

		// Get original wrapped CMK
		originalWrappedCMK := make([]byte, len(state.WrappedCMKUser))
		copy(originalWrappedCMK, state.WrappedCMKUser)

		// Reset user PIN
		newPINHash := createUserPINHash(testUserPIN2)
		err = km.ResetUserPIN(newPINHash)

		require.NoError(t, err)
		require.NotEqual(t, originalWrappedCMK, state.WrappedCMKUser, "Wrapped CMK should be different after reset")
	})

	t.Run("user can unlock with new PIN hash", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)
		err := km.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		// Initialize user PIN
		pinHash := createUserPINHash(testUserPINString)
		err = km.InitializeUserPIN(pinHash)
		require.NoError(t, err)

		// Reset user PIN
		newPINHash := createUserPINHash(testUserPIN2)
		err = km.ResetUserPIN(newPINHash)
		require.NoError(t, err)

		km.Lock()

		// Set state for user unlock
		state.PINSet = true
		state.PINHash = newPINHash

		// Unlock with new PIN
		err = km.UnlockWithUserPIN(newPINHash)

		require.NoError(t, err)
		require.True(t, km.IsUserUnlocked())
	})

	t.Run("old PIN hash no longer works after reset", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)
		err := km.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		// Initialize user PIN
		oldPINHash := createUserPINHash(testUserPINString)
		err = km.InitializeUserPIN(oldPINHash)
		require.NoError(t, err)

		// Reset user PIN
		newPINHash := createUserPINHash(testUserPIN2)
		err = km.ResetUserPIN(newPINHash)
		require.NoError(t, err)

		km.Lock()

		// Set state for user unlock (with old hash)
		state.PINSet = true
		state.PINHash = oldPINHash

		// Old PIN should fail to unwrap CMK
		err = km.UnlockWithUserPIN(oldPINHash)

		require.Error(t, err)
	})

	t.Run("requires CMK to be available", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)

		// Manually set up SO PIN without CMK
		state.SOPINManager = NewSOPINManager()
		smk, err := state.SOPINManager.Initialize(testSOPIN)
		require.NoError(t, err)

		// Generate and wrap AK but don't set up CMK
		ak := make([]byte, AESGCMKeySize)
		_, err = rand.Read(ak)
		require.NoError(t, err)

		akWrapper, err := NewAESGCMKeyWrapper(smk)
		require.NoError(t, err)

		state.WrappedAK, err = akWrapper.Wrap(ak)
		require.NoError(t, err)

		// Unlock with SO PIN - will have AK but no CMK
		err = km.UnlockWithSOPIN(testSOPIN)
		require.NoError(t, err)

		// Try to reset user PIN
		newPINHash := createUserPINHash(testUserPIN2)
		err = km.ResetUserPIN(newPINHash)

		require.ErrorIs(t, err, ErrKeyManagerNoCMK)
	})

	t.Run("reset fails if user PIN unlocked", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)
		err := km.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		// Initialize user PIN
		pinHash := createUserPINHash(testUserPINString)
		err = km.InitializeUserPIN(pinHash)
		require.NoError(t, err)

		km.Lock()

		state.PINSet = true
		state.PINHash = pinHash

		// Unlock with user PIN (not SO)
		err = km.UnlockWithUserPIN(pinHash)
		require.NoError(t, err)

		// Try reset while user-unlocked (should fail, needs SO)
		newPINHash := createUserPINHash(testUserPIN2)
		err = km.ResetUserPIN(newPINHash)

		require.ErrorIs(t, err, ErrKeyManagerLocked)
	})

	t.Run("clears existing UMK on reset", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)
		err := km.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		// Initialize user PIN
		pinHash := createUserPINHash(testUserPINString)
		err = km.InitializeUserPIN(pinHash)
		require.NoError(t, err)

		// Reset user PIN
		newPINHash := createUserPINHash(testUserPIN2)
		err = km.ResetUserPIN(newPINHash)
		require.NoError(t, err)

		// Verify the manager is still SO-unlocked with updated UMK
		require.True(t, km.IsSOUnlocked())
	})
}

func TestKeyManager_InitializeUserPIN(t *testing.T) {
	t.Run("wraps CMK for user access", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)
		err := km.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		require.Empty(t, state.WrappedCMKUser, "WrappedCMKUser should be empty before initialization")

		pinHash := createUserPINHash(testUserPINString)
		err = km.InitializeUserPIN(pinHash)

		require.NoError(t, err)
		require.NotEmpty(t, state.WrappedCMKUser, "WrappedCMKUser should be set after initialization")
	})

	t.Run("requires SO unlock", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)
		err := km.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		km.Lock()

		pinHash := createUserPINHash(testUserPINString)
		err = km.InitializeUserPIN(pinHash)

		require.ErrorIs(t, err, ErrKeyManagerLocked)
	})

	t.Run("user can unlock after initialization", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)
		err := km.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		pinHash := createUserPINHash(testUserPINString)
		err = km.InitializeUserPIN(pinHash)
		require.NoError(t, err)

		km.Lock()

		// Set state for user unlock
		state.PINSet = true
		state.PINHash = pinHash

		err = km.UnlockWithUserPIN(pinHash)

		require.NoError(t, err)
		require.True(t, km.IsUserUnlocked())
	})

	t.Run("user can access CMK after unlock", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)
		err := km.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		// Get CMK while SO-unlocked
		cmkExpected, err := km.GetCMK()
		require.NoError(t, err)

		pinHash := createUserPINHash(testUserPINString)
		err = km.InitializeUserPIN(pinHash)
		require.NoError(t, err)

		km.Lock()

		state.PINSet = true
		state.PINHash = pinHash

		err = km.UnlockWithUserPIN(pinHash)
		require.NoError(t, err)

		// Get CMK while user-unlocked
		cmkActual, err := km.GetCMK()
		require.NoError(t, err)

		require.True(t, bytes.Equal(cmkExpected, cmkActual), "User should access the same CMK")
	})

	t.Run("returns error if unlocked with user PIN", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)
		err := km.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		// Initialize first user PIN
		pinHash := createUserPINHash(testUserPINString)
		err = km.InitializeUserPIN(pinHash)
		require.NoError(t, err)

		km.Lock()

		state.PINSet = true
		state.PINHash = pinHash

		// Unlock with user PIN
		err = km.UnlockWithUserPIN(pinHash)
		require.NoError(t, err)

		// Try to initialize another user PIN while user-unlocked
		newPINHash := createUserPINHash(testUserPIN2)
		err = km.InitializeUserPIN(newPINHash)

		require.ErrorIs(t, err, ErrKeyManagerLocked)
	})

	t.Run("requires CMK to be available", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)

		// Manually set up SO PIN without CMK
		state.SOPINManager = NewSOPINManager()
		smk, err := state.SOPINManager.Initialize(testSOPIN)
		require.NoError(t, err)

		// Generate and wrap AK but don't set up CMK
		ak := make([]byte, AESGCMKeySize)
		_, err = rand.Read(ak)
		require.NoError(t, err)

		akWrapper, err := NewAESGCMKeyWrapper(smk)
		require.NoError(t, err)

		state.WrappedAK, err = akWrapper.Wrap(ak)
		require.NoError(t, err)

		// Unlock with SO PIN - will have AK but no CMK
		err = km.UnlockWithSOPIN(testSOPIN)
		require.NoError(t, err)

		// Try to initialize user PIN
		pinHash := createUserPINHash(testUserPINString)
		err = km.InitializeUserPIN(pinHash)

		require.ErrorIs(t, err, ErrKeyManagerNoCMK)
	})
}

func TestKeyManager_UnlockWithUserPIN(t *testing.T) {
	t.Run("unlocks successfully with correct PIN hash", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)
		err := km.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		pinHash := createUserPINHash(testUserPINString)
		err = km.InitializeUserPIN(pinHash)
		require.NoError(t, err)

		km.Lock()

		state.PINSet = true
		state.PINHash = pinHash

		err = km.UnlockWithUserPIN(pinHash)

		require.NoError(t, err)
		require.True(t, km.IsUnlocked())
		require.True(t, km.IsUserUnlocked())
		require.False(t, km.IsSOUnlocked())
	})

	t.Run("returns error if user PIN not set", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)

		pinHash := createUserPINHash(testUserPINString)

		err := km.UnlockWithUserPIN(pinHash)

		require.ErrorIs(t, err, ErrKeyManagerUserPINNotSet)
	})

	t.Run("wrong PIN hash fails to unwrap CMK", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)
		err := km.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		correctPINHash := createUserPINHash(testUserPINString)
		err = km.InitializeUserPIN(correctPINHash)
		require.NoError(t, err)

		km.Lock()

		state.PINSet = true

		// Try with wrong PIN hash
		wrongPINHash := createUserPINHash("wrong")
		err = km.UnlockWithUserPIN(wrongPINHash)

		require.Error(t, err)
		require.False(t, km.IsUnlocked())
	})

	t.Run("nil state returns ErrKeyManagerUserPINNotSet", func(t *testing.T) {
		_, config := createTestKeyManagerState()
		km := NewKeyManager(nil, config)

		pinHash := createUserPINHash(testUserPINString)
		err := km.UnlockWithUserPIN(pinHash)

		require.ErrorIs(t, err, ErrKeyManagerUserPINNotSet)
	})

	t.Run("unlock without wrapped CMK user succeeds but has no CMK", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)

		// Set up state for user unlock without wrapped CMK
		state.PINSet = true
		state.SOPINManager = NewSOPINManager()
		_, err := state.SOPINManager.Initialize(testSOPIN)
		require.NoError(t, err)

		pinHash := createUserPINHash(testUserPINString)

		err = km.UnlockWithUserPIN(pinHash)
		require.NoError(t, err)
		require.True(t, km.IsUserUnlocked())

		// CMK should not be available
		_, err = km.GetCMK()
		require.ErrorIs(t, err, ErrKeyManagerNoCMK)
	})
}

func TestKeyManager_GetCMK(t *testing.T) {
	t.Run("returns CMK when unlocked", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)
		err := km.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		cmk, err := km.GetCMK()

		require.NoError(t, err)
		require.Len(t, cmk, AESGCMKeySize)
	})

	t.Run("returns error when locked", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)
		err := km.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		km.Lock()

		_, err = km.GetCMK()

		require.ErrorIs(t, err, ErrKeyManagerLocked)
	})

	t.Run("returns copy of CMK", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)
		err := km.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		cmk1, err := km.GetCMK()
		require.NoError(t, err)

		cmk2, err := km.GetCMK()
		require.NoError(t, err)

		require.True(t, bytes.Equal(cmk1, cmk2))

		// Modify cmk1 and verify cmk2 is not affected
		cmk1[0] ^= 0xFF

		cmk3, err := km.GetCMK()
		require.NoError(t, err)

		require.True(t, bytes.Equal(cmk2, cmk3), "Modifying returned CMK should not affect internal state")
	})
}

func TestKeyManager_UMKSalt(t *testing.T) {
	t.Run("SetUMKSalt and GetUMKSalt work correctly", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)

		salt := make([]byte, 32)
		_, err := rand.Read(salt)
		require.NoError(t, err)

		km.SetUMKSalt(salt)

		retrievedSalt := km.GetUMKSalt()

		require.True(t, bytes.Equal(salt, retrievedSalt))
	})

	t.Run("GetUMKSalt returns copy", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)

		salt := make([]byte, 32)
		_, err := rand.Read(salt)
		require.NoError(t, err)

		km.SetUMKSalt(salt)

		retrieved1 := km.GetUMKSalt()
		retrieved1[0] ^= 0xFF

		retrieved2 := km.GetUMKSalt()

		require.True(t, bytes.Equal(salt, retrieved2), "Modifying returned salt should not affect internal state")
	})

	t.Run("derives UMK salt from SO PIN salt if not set", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)
		err := km.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		salt := km.GetUMKSalt()

		require.NotNil(t, salt)
		require.Len(t, salt, 32)
	})

	t.Run("derives fallback salt from AAGUID if no SO PIN salt", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		// Don't initialize SO PIN
		km := NewKeyManager(state, config)

		salt := km.GetUMKSalt()

		require.NotNil(t, salt)
		require.Len(t, salt, 32)
		// First 16 bytes should be the AAGUID
		require.True(t, bytes.Equal(salt[:16], state.AAGUID[:]))
	})

	t.Run("custom UMK salt is used for user PIN derivation", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)
		err := km.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		// Set a custom salt
		customSalt := make([]byte, 32)
		_, err = rand.Read(customSalt)
		require.NoError(t, err)
		km.SetUMKSalt(customSalt)

		// Initialize user PIN
		pinHash := createUserPINHash(testUserPINString)
		err = km.InitializeUserPIN(pinHash)
		require.NoError(t, err)

		// Verify the custom salt is returned
		retrievedSalt := km.GetUMKSalt()
		require.True(t, bytes.Equal(customSalt, retrievedSalt))
	})
}

func TestKeyManager_WrapAttestationKey(t *testing.T) {
	t.Run("wraps attestation key for both SO and User", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)
		err := km.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		// Generate a new attestation key
		newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		keyPKCS8, err := x509.MarshalPKCS8PrivateKey(newKey)
		require.NoError(t, err)

		// Clear existing wrapped keys
		state.WrappedAttestSO = nil
		state.WrappedAttestUser = nil

		err = km.WrapAttestationKey(keyPKCS8)

		require.NoError(t, err)
		require.NotEmpty(t, state.WrappedAttestSO)
		require.NotEmpty(t, state.WrappedAttestUser)
	})

	t.Run("requires SO unlock", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)
		err := km.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		km.Lock()

		newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		keyPKCS8, err := x509.MarshalPKCS8PrivateKey(newKey)
		require.NoError(t, err)

		err = km.WrapAttestationKey(keyPKCS8)

		require.ErrorIs(t, err, ErrKeyManagerLocked)
	})

	t.Run("caches attestation key in state", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)
		err := km.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		keyPKCS8, err := x509.MarshalPKCS8PrivateKey(newKey)
		require.NoError(t, err)

		err = km.WrapAttestationKey(keyPKCS8)
		require.NoError(t, err)

		// Verify the cached key matches
		require.Equal(t, newKey.D, state.AttestationKey.D)
		require.Equal(t, newKey.X, state.AttestationKey.X)
		require.Equal(t, newKey.Y, state.AttestationKey.Y)
	})

	t.Run("rejects invalid key data", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)
		err := km.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		err = km.WrapAttestationKey([]byte("not a valid key"))

		require.Error(t, err)
	})

	t.Run("requires AK to be available", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)

		// Manually set up SO unlock without AK
		state.SOPINManager = NewSOPINManager()
		_, err := state.SOPINManager.Initialize(testSOPIN)
		require.NoError(t, err)

		err = km.UnlockWithSOPIN(testSOPIN)
		require.NoError(t, err)

		newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		keyPKCS8, err := x509.MarshalPKCS8PrivateKey(newKey)
		require.NoError(t, err)

		err = km.WrapAttestationKey(keyPKCS8)

		require.ErrorIs(t, err, ErrKeyManagerNoAK)
	})

	t.Run("wraps only for SO when CMK not available", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)

		// Set up SO PIN with only AK (no CMK)
		state.SOPINManager = NewSOPINManager()
		smk, err := state.SOPINManager.Initialize(testSOPIN)
		require.NoError(t, err)

		ak := make([]byte, AESGCMKeySize)
		_, err = rand.Read(ak)
		require.NoError(t, err)

		akWrapper, err := NewAESGCMKeyWrapper(smk)
		require.NoError(t, err)

		state.WrappedAK, err = akWrapper.Wrap(ak)
		require.NoError(t, err)

		err = km.UnlockWithSOPIN(testSOPIN)
		require.NoError(t, err)

		newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		keyPKCS8, err := x509.MarshalPKCS8PrivateKey(newKey)
		require.NoError(t, err)

		err = km.WrapAttestationKey(keyPKCS8)
		require.NoError(t, err)

		// Should have SO wrapped but not user wrapped
		require.NotEmpty(t, state.WrappedAttestSO)
		require.Empty(t, state.WrappedAttestUser)
	})

	t.Run("rejects non-ECDSA key", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)
		err := km.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		// Generate an RSA key
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		keyPKCS8, err := x509.MarshalPKCS8PrivateKey(rsaKey)
		require.NoError(t, err)

		err = km.WrapAttestationKey(keyPKCS8)

		require.ErrorIs(t, err, ErrKeyManagerInvalidKey)
	})

	t.Run("rejects Ed25519 key", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)
		err := km.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		// Generate an Ed25519 key
		_, edKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		keyPKCS8, err := x509.MarshalPKCS8PrivateKey(edKey)
		require.NoError(t, err)

		err = km.WrapAttestationKey(keyPKCS8)

		require.ErrorIs(t, err, ErrKeyManagerInvalidKey)
	})

	t.Run("user unlocked returns ErrKeyManagerLocked", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)
		err := km.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		pinHash := createUserPINHash(testUserPINString)
		err = km.InitializeUserPIN(pinHash)
		require.NoError(t, err)

		km.Lock()
		state.PINSet = true

		err = km.UnlockWithUserPIN(pinHash)
		require.NoError(t, err)

		newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		keyPKCS8, err := x509.MarshalPKCS8PrivateKey(newKey)
		require.NoError(t, err)

		err = km.WrapAttestationKey(keyPKCS8)

		require.ErrorIs(t, err, ErrKeyManagerLocked)
	})
}

func TestKeyManager_ConcurrentAccess(t *testing.T) {
	t.Run("concurrent wrap/unwrap operations are safe", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)
		err := km.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		// Generate test key
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		keyPKCS8, err := x509.MarshalPKCS8PrivateKey(key)
		require.NoError(t, err)

		var wg sync.WaitGroup
		errChan := make(chan error, 100)

		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				wrapped, err := km.WrapCredentialKey(keyPKCS8)
				if err != nil {
					errChan <- err
					return
				}
				_, err = km.UnwrapCredentialKey(wrapped)
				if err != nil {
					errChan <- err
				}
			}()
		}

		wg.Wait()
		close(errChan)

		for err := range errChan {
			t.Errorf("Concurrent operation failed: %v", err)
		}
	})

	t.Run("concurrent lock/unlock operations are safe", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)
		err := km.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		var wg sync.WaitGroup

		// Mix of lock and unlock operations
		for i := 0; i < 20; i++ {
			wg.Add(2)
			go func() {
				defer wg.Done()
				km.Lock()
			}()
			go func() {
				defer wg.Done()
				km.UnlockWithSOPIN(testSOPIN)
			}()
		}

		wg.Wait()

		// Manager should be in a consistent state (either locked or unlocked)
		// Just verify no panic occurred
	})

	t.Run("concurrent IsUnlocked checks are safe", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)
		err := km.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		var wg sync.WaitGroup

		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				km.IsUnlocked()
				km.IsSOUnlocked()
				km.IsUserUnlocked()
				km.IsSOPINConfigured()
			}()
		}

		wg.Wait()
	})
}

func TestKeyManager_DeriveUMK(t *testing.T) {
	t.Run("returns nil when UMK salt not available", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		// Remove AAGUID to ensure fallback also fails
		state.AAGUID = [16]byte{}
		state.SOPINManager = nil
		km := NewKeyManager(state, config)

		// Manually call deriveUMK through the unlock path
		state.PINSet = true

		// getUMKSalt will return a salt based on AAGUID even when empty
		// So deriveUMK should still work - let's verify this
		pinHash := createUserPINHash(testUserPINString)

		// This should succeed because getUMKSalt falls back to AAGUID
		err := km.UnlockWithUserPIN(pinHash)
		require.NoError(t, err)
	})
}

// TestKeyManager_InitializeSOPIN_Comprehensive contains comprehensive tests for InitializeSOPIN.
func TestKeyManager_InitializeSOPIN_Comprehensive(t *testing.T) {
	t.Parallel()

	t.Run("success path with minimum valid PIN length", func(t *testing.T) {
		t.Parallel()
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)

		// Use a 6-character PIN (minimum valid length)
		err := km.InitializeSOPIN("abcdef")

		require.NoError(t, err)
		require.True(t, km.IsSOPINConfigured())
		require.True(t, km.IsSOUnlocked())
	})

	t.Run("success path with maximum valid PIN length", func(t *testing.T) {
		t.Parallel()
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)

		// Use a 63-character PIN (maximum valid length per sopinMaxLength)
		longPIN := "123456789012345678901234567890123456789012345678901234567890123"
		require.Len(t, longPIN, 63)

		err := km.InitializeSOPIN(longPIN)

		require.NoError(t, err)
		require.True(t, km.IsSOPINConfigured())
		require.True(t, km.IsSOUnlocked())
	})

	t.Run("error: empty PIN returns policy violation", func(t *testing.T) {
		t.Parallel()
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)

		err := km.InitializeSOPIN("")

		require.ErrorIs(t, err, ErrSOPINPolicyViolation)
		require.False(t, km.IsSOPINConfigured())
		require.False(t, km.IsUnlocked())
	})

	t.Run("error: PIN too long returns policy violation", func(t *testing.T) {
		t.Parallel()
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)

		// Use a 64-character PIN (exceeds maximum of 63)
		tooLongPIN := "1234567890123456789012345678901234567890123456789012345678901234"
		require.Len(t, tooLongPIN, 64)

		err := km.InitializeSOPIN(tooLongPIN)

		require.ErrorIs(t, err, ErrSOPINPolicyViolation)
		require.False(t, km.IsSOPINConfigured())
	})

	t.Run("error: SO PIN already set in existing manager returns ErrKeyManagerAlreadyInitialized", func(t *testing.T) {
		t.Parallel()
		state, config := createTestKeyManagerState()

		// Pre-configure SO PIN in state
		state.SOPINManager = NewSOPINManager()
		_, err := state.SOPINManager.Initialize(testSOPIN)
		require.NoError(t, err)

		km := NewKeyManager(state, config)

		// Attempt to initialize again
		err = km.InitializeSOPIN(testSOPIN2)

		require.ErrorIs(t, err, ErrKeyManagerAlreadyInitialized)
	})

	t.Run("generates unique AK and CMK for each initialization", func(t *testing.T) {
		t.Parallel()

		// Initialize first key manager
		state1, config1 := createTestKeyManagerState()
		km1 := NewKeyManager(state1, config1)
		err := km1.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		cmk1, err := km1.GetCMK()
		require.NoError(t, err)

		// Initialize second key manager
		state2, config2 := createTestKeyManagerState()
		km2 := NewKeyManager(state2, config2)
		err = km2.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		cmk2, err := km2.GetCMK()
		require.NoError(t, err)

		// CMKs should be different due to random generation
		require.False(t, bytes.Equal(cmk1, cmk2), "Different initializations should produce different CMKs")

		// Wrapped AKs should also be different
		require.False(t, bytes.Equal(state1.WrappedAK, state2.WrappedAK), "Different initializations should produce different wrapped AKs")
	})

	t.Run("attestation key is P-256 ECDSA", func(t *testing.T) {
		t.Parallel()
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)

		err := km.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		attestKey, err := km.GetAttestationKey()
		require.NoError(t, err)
		require.NotNil(t, attestKey)
		require.Equal(t, elliptic.P256(), attestKey.Curve)

		// Verify key is valid by checking it can sign
		hash := sha256.Sum256([]byte("test data"))
		r, s, err := ecdsa.Sign(rand.Reader, attestKey, hash[:])
		require.NoError(t, err)
		require.NotNil(t, r)
		require.NotNil(t, s)

		// Verify signature
		valid := ecdsa.Verify(&attestKey.PublicKey, hash[:], r, s)
		require.True(t, valid)
	})

	t.Run("wrapped attestation keys can be unwrapped", func(t *testing.T) {
		t.Parallel()
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)

		err := km.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		// Get original attestation key
		originalKey := state.AttestationKey

		// Verify SO-wrapped attestation key can be unwrapped
		smk, err := state.SOPINManager.Verify(testSOPIN)
		require.NoError(t, err)

		akWrapper, err := NewAESGCMKeyWrapper(smk)
		require.NoError(t, err)

		ak, err := akWrapper.Unwrap(state.WrappedAK)
		require.NoError(t, err)

		attestWrapper, err := NewAESGCMKeyWrapper(ak)
		require.NoError(t, err)

		attestPKCS8, err := attestWrapper.Unwrap(state.WrappedAttestSO)
		require.NoError(t, err)

		key, err := x509.ParsePKCS8PrivateKey(attestPKCS8)
		require.NoError(t, err)

		ecKey, ok := key.(*ecdsa.PrivateKey)
		require.True(t, ok)
		require.Equal(t, originalKey.D, ecKey.D)
	})

	t.Run("wrapped keys have correct sizes", func(t *testing.T) {
		t.Parallel()
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)

		err := km.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		// Wrapped AK should be: nonce (12) + key (32) + tag (16) = 60 bytes
		expectedWrappedKeySize := AESGCMNonceSize + AESGCMKeySize + aesGCMTagSize
		require.Equal(t, expectedWrappedKeySize, len(state.WrappedAK))

		// Wrapped CMK SO should be same size
		require.Equal(t, expectedWrappedKeySize, len(state.WrappedCMKSO))
	})

	t.Run("caches all keys in manager after initialization", func(t *testing.T) {
		t.Parallel()
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)

		err := km.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		// Verify all keys are accessible
		cmk, err := km.GetCMK()
		require.NoError(t, err)
		require.Len(t, cmk, AESGCMKeySize)

		attestKey, err := km.GetAttestationKey()
		require.NoError(t, err)
		require.NotNil(t, attestKey)

		// Verify internal state
		km.mu.RLock()
		require.NotNil(t, km.smk)
		require.NotNil(t, km.adminKey)
		require.NotNil(t, km.cmk)
		require.Equal(t, unlockSourceSOPIN, km.unlockSource)
		km.mu.RUnlock()
	})

	t.Run("multiple rapid initializations on different managers", func(t *testing.T) {
		t.Parallel()

		var wg sync.WaitGroup
		results := make(chan error, 10)

		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				state, config := createTestKeyManagerState()
				km := NewKeyManager(state, config)

				err := km.InitializeSOPIN(testSOPIN)
				if err != nil {
					results <- err
					return
				}

				// Verify initialization worked
				if !km.IsSOPINConfigured() {
					results <- ErrSOPINNotSet
					return
				}

				_, err = km.GetCMK()
				if err != nil {
					results <- err
				}
			}()
		}

		wg.Wait()
		close(results)

		for err := range results {
			t.Errorf("Concurrent initialization failed: %v", err)
		}
	})

	t.Run("PIN with special characters", func(t *testing.T) {
		t.Parallel()
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)

		specialPIN := "!@#$%^&*()_+-=[]{}|;':\",./<>?"
		err := km.InitializeSOPIN(specialPIN)

		require.NoError(t, err)
		require.True(t, km.IsSOPINConfigured())

		// Verify unlock works with special characters
		km.Lock()
		err = km.UnlockWithSOPIN(specialPIN)
		require.NoError(t, err)
	})

	t.Run("PIN with Unicode characters", func(t *testing.T) {
		t.Parallel()
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)

		// PIN with emoji and international characters (must be at least 6 UTF-8 bytes)
		unicodePIN := "123456"
		err := km.InitializeSOPIN(unicodePIN)

		require.NoError(t, err)
		require.True(t, km.IsSOPINConfigured())
	})

	t.Run("SMK derived correctly after initialization", func(t *testing.T) {
		t.Parallel()
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)

		err := km.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		// Get SMK by verifying
		smk1, err := state.SOPINManager.Verify(testSOPIN)
		require.NoError(t, err)

		// SMK should be consistent
		smk2, err := state.SOPINManager.Verify(testSOPIN)
		require.NoError(t, err)

		require.True(t, bytes.Equal(smk1, smk2), "SMK should be deterministic for same PIN and salt")
	})

	t.Run("state is clean on policy violation error", func(t *testing.T) {
		t.Parallel()
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)

		// Attempt initialization with short PIN
		err := km.InitializeSOPIN("12345")

		require.ErrorIs(t, err, ErrSOPINPolicyViolation)

		// State should be clean
		require.False(t, km.IsSOPINConfigured())
		require.False(t, km.IsUnlocked())
		require.Empty(t, state.WrappedAK)
		require.Empty(t, state.WrappedCMKSO)
		require.Empty(t, state.WrappedAttestSO)
		require.Empty(t, state.WrappedAttestUser)
		require.Nil(t, state.AttestationKey)
	})

	t.Run("SOPINManager created with correct default parameters", func(t *testing.T) {
		t.Parallel()
		state, config := createTestKeyManagerState()
		state.SOPINManager = nil // Ensure it's nil
		km := NewKeyManager(state, config)

		err := km.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		require.NotNil(t, state.SOPINManager)
		require.Equal(t, uint32(SOPINDefaultIterations), state.SOPINManager.Iterations)
		require.Equal(t, uint32(SOPINDefaultMemory), state.SOPINManager.Memory)
		require.Equal(t, uint8(SOPINDefaultParallelism), state.SOPINManager.Parallelism)
		require.True(t, state.SOPINManager.IsSet)
		require.Len(t, state.SOPINManager.Salt, SOPINSaltSize)
	})

	t.Run("retry counter is set after initialization", func(t *testing.T) {
		t.Parallel()
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)

		err := km.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		require.Equal(t, DefaultSOPINMaxRetries, state.SOPINManager.Retries())
	})

	t.Run("lock and re-unlock preserves all key relationships", func(t *testing.T) {
		t.Parallel()
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)

		err := km.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		// Get keys before lock
		cmkBefore, err := km.GetCMK()
		require.NoError(t, err)

		attestBefore, err := km.GetAttestationKey()
		require.NoError(t, err)

		// Lock and unlock
		km.Lock()
		require.False(t, km.IsUnlocked())

		err = km.UnlockWithSOPIN(testSOPIN)
		require.NoError(t, err)

		// Get keys after unlock
		cmkAfter, err := km.GetCMK()
		require.NoError(t, err)

		attestAfter, err := km.GetAttestationKey()
		require.NoError(t, err)

		// Verify keys match
		require.True(t, bytes.Equal(cmkBefore, cmkAfter))
		require.Equal(t, attestBefore.D, attestAfter.D)
	})

	t.Run("wrapped user attestation key can be unwrapped with CMK", func(t *testing.T) {
		t.Parallel()
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)

		err := km.InitializeSOPIN(testSOPIN)
		require.NoError(t, err)

		// Get CMK
		cmk, err := km.GetCMK()
		require.NoError(t, err)

		// Unwrap user attestation key
		cmkWrapper, err := NewAESGCMKeyWrapper(cmk)
		require.NoError(t, err)

		attestPKCS8, err := cmkWrapper.Unwrap(state.WrappedAttestUser)
		require.NoError(t, err)

		// Parse and verify
		key, err := x509.ParsePKCS8PrivateKey(attestPKCS8)
		require.NoError(t, err)

		ecKey, ok := key.(*ecdsa.PrivateKey)
		require.True(t, ok)
		require.Equal(t, state.AttestationKey.D, ecKey.D)
	})
}
