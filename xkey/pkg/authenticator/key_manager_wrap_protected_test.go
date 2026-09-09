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
	"testing"

	"github.com/stretchr/testify/require"

	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

func TestWrapFromProtected(t *testing.T) {
	t.Run("wraps from protected memory and unwraps back into it", func(t *testing.T) {
		keyBuf, _ := protectedTestKey(t)
		plaintext := generateRandomKey(t, AESGCMKeySize)
		src := protectedBytes(t, plaintext)

		wrapped, err := wrapFromProtected(keyBuf, src)
		require.NoError(t, err)
		require.Len(t, wrapped, AESGCMNonceSize+len(plaintext)+aesGCMTagSize)

		out, err := unwrapIntoProtected(keyBuf, wrapped)
		require.NoError(t, err)
		defer out.Destroy()

		require.NoError(t, out.WithBytes(func(b []byte) error {
			require.Equal(t, plaintext, b)
			return nil
		}))
	})

	t.Run("output opens under the same key with an independent AES-256-GCM", func(t *testing.T) {
		keyBuf, heapKey := protectedTestKey(t)
		plaintext := generateRandomKey(t, 64)

		wrapped, err := wrapFromProtected(keyBuf, protectedBytes(t, plaintext))
		require.NoError(t, err)

		opened, err := openForTest(t, heapKey, wrapped)
		require.NoError(t, err)
		require.Equal(t, plaintext, opened)
	})

	t.Run("nil key returns ErrKeyManagerLocked", func(t *testing.T) {
		wrapped, err := wrapFromProtected(nil, protectedBytes(t, generateRandomKey(t, 32)))
		require.ErrorIs(t, err, ErrKeyManagerLocked)
		require.Nil(t, wrapped)
	})

	t.Run("destroyed key cannot be borrowed", func(t *testing.T) {
		keyBuf, err := secure.NewBuffer(AESGCMKeySize)
		require.NoError(t, err)
		keyBuf.Destroy()

		wrapped, err := wrapFromProtected(keyBuf, protectedBytes(t, generateRandomKey(t, 32)))
		var nilErr *secure.NilBufferError
		require.ErrorAs(t, err, &nilErr)
		require.Nil(t, wrapped)
	})

	t.Run("nil source returns ErrInvalidWrapSource", func(t *testing.T) {
		keyBuf, _ := protectedTestKey(t)

		wrapped, err := wrapFromProtected(keyBuf, nil)
		require.ErrorIs(t, err, ErrInvalidWrapSource)
		require.Nil(t, wrapped)
	})

	t.Run("destroyed source returns ErrInvalidWrapSource", func(t *testing.T) {
		keyBuf, _ := protectedTestKey(t)
		src, err := secure.NewBuffer(32)
		require.NoError(t, err)
		src.Destroy()

		wrapped, err := wrapFromProtected(keyBuf, src)
		require.ErrorIs(t, err, ErrInvalidWrapSource)
		require.Nil(t, wrapped)
	})

	t.Run("wrong-size key is refused as an invalid wrapping key", func(t *testing.T) {
		shortKey := protectedBytes(t, generateRandomKey(t, 16))

		wrapped, err := wrapFromProtected(shortKey, protectedBytes(t, generateRandomKey(t, 32)))
		require.ErrorIs(t, err, ErrInvalidWrappingKey)
		require.Nil(t, wrapped)
	})
}

func TestNewRandomKeyBuffer(t *testing.T) {
	t.Run("returns a protected buffer of the requested size filled from the CSPRNG", func(t *testing.T) {
		buf, err := newRandomKeyBuffer(AESGCMKeySize)
		require.NoError(t, err)
		defer buf.Destroy()

		require.Equal(t, AESGCMKeySize, buf.Size())
		require.NoError(t, buf.WithBytes(func(b []byte) error {
			require.NotEqual(t, make([]byte, AESGCMKeySize), b, "a fresh key must not be all zeros")
			return nil
		}))
	})

	t.Run("two keys differ", func(t *testing.T) {
		a, err := newRandomKeyBuffer(AESGCMKeySize)
		require.NoError(t, err)
		defer a.Destroy()
		b, err := newRandomKeyBuffer(AESGCMKeySize)
		require.NoError(t, err)
		defer b.Destroy()

		require.NotEqual(t, a.Bytes(), b.Bytes())
	})

	t.Run("zero size returns ErrKeyManagerProtectedMemory", func(t *testing.T) {
		buf, err := newRandomKeyBuffer(0)
		require.ErrorIs(t, err, ErrKeyManagerProtectedMemory)
		var sizeErr *secure.InvalidSizeError
		require.ErrorAs(t, err, &sizeErr)
		require.Nil(t, buf)
	})
}

// TestInitializeSOPIN_KeysAreBornProtected proves the AK and CMK produced by
// InitializeSOPIN are the ones the wrapped copies decrypt to — the keys are
// generated straight into protected memory and adopted without a heap copy,
// so the only way to check them is to unwrap the persisted blobs back out.
func TestInitializeSOPIN_KeysAreBornProtected(t *testing.T) {
	state, config := createTestKeyManagerState()
	km := NewKeyManager(state, config)
	require.NoError(t, km.InitializeSOPIN(testSOPIN))

	km.mu.RLock()
	adminKey, cmk, smk := km.adminKey, km.cmk, km.smk
	km.mu.RUnlock()
	require.NotNil(t, adminKey)
	require.NotNil(t, cmk)
	require.NotNil(t, smk)

	// AK unwraps under the SMK to the cached admin key.
	ak, err := unwrapIntoProtected(smk, state.WrappedAK)
	require.NoError(t, err)
	defer ak.Destroy()
	require.Equal(t, adminKey.Bytes(), ak.Bytes())

	// The SO copy of the CMK unwraps under the AK to the cached CMK.
	cmkSO, err := unwrapIntoProtected(adminKey, state.WrappedCMKSO)
	require.NoError(t, err)
	defer cmkSO.Destroy()
	require.Equal(t, cmk.Bytes(), cmkSO.Bytes())

	// Both attestation copies unwrap to the same PKCS#8 ECDSA key.
	attestSO, err := unwrapIntoProtected(adminKey, state.WrappedAttestSO)
	require.NoError(t, err)
	defer attestSO.Destroy()
	attestUser, err := unwrapIntoProtected(cmk, state.WrappedAttestUser)
	require.NoError(t, err)
	defer attestUser.Destroy()
	require.Equal(t, attestSO.Bytes(), attestUser.Bytes())
	parsed, err := x509.ParsePKCS8PrivateKey(attestSO.Bytes())
	require.NoError(t, err)
	require.IsType(t, &ecdsa.PrivateKey{}, parsed)
}

func TestKeyManager_WrapAttestationKey_ProtectedSource(t *testing.T) {
	t.Run("nil source returns ErrInvalidWrapSource", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)
		require.NoError(t, km.InitializeSOPIN(testSOPIN))

		require.ErrorIs(t, km.WrapAttestationKey(nil), ErrInvalidWrapSource)
	})

	t.Run("source is left intact for the caller to destroy", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)
		require.NoError(t, km.InitializeSOPIN(testSOPIN))

		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
		require.NoError(t, err)
		src := protectedBytes(t, pkcs8)

		require.NoError(t, km.WrapAttestationKey(src))
		require.Equal(t, pkcs8, src.Bytes())
	})
}

func TestKeyManager_WrapCredentialKey_ProtectedSource(t *testing.T) {
	t.Run("nil source returns ErrInvalidWrapSource", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)
		require.NoError(t, km.InitializeSOPIN(testSOPIN))

		wrapped, err := km.WrapCredentialKey(nil)
		require.ErrorIs(t, err, ErrInvalidWrapSource)
		require.Nil(t, wrapped)
	})

	t.Run("destroyed source returns ErrInvalidWrapSource", func(t *testing.T) {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)
		require.NoError(t, km.InitializeSOPIN(testSOPIN))

		src, err := secure.NewBuffer(32)
		require.NoError(t, err)
		src.Destroy()

		wrapped, err := km.WrapCredentialKey(src)
		require.ErrorIs(t, err, ErrInvalidWrapSource)
		require.Nil(t, wrapped)
	})
}

// TestWrapFromProtected_NoNestedBorrowDeadlock exercises every wrap path —
// initialization, user PIN setup, credential and attestation wraps, SO PIN
// change and user PIN reset — repeatedly while another goroutine hammers
// purge-class allocations. A borrow taken inside another borrow deadlocks
// only when a purge-class writer queues between the two, so the contention
// is what makes a re-nested borrow fail here instead of passing by luck;
// the test's protection is the -timeout on the run, which turns the hang
// into a failure (go-xkms#387, the mirror of #291's unwrap test).
func TestWrapFromProtected_NoNestedBorrowDeadlock(t *testing.T) {
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			buf, err := secure.NewBuffer(AESGCMKeySize)
			if err != nil {
				return
			}
			buf.Destroy()
		}
	}()
	defer func() {
		close(stop)
		<-done
	}()

	credKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	credPKCS8, err := x509.MarshalPKCS8PrivateKey(credKey)
	require.NoError(t, err)
	credBuf := protectedBytes(t, credPKCS8)

	pinHash := createUserPINHash(testUserPINString)
	newPINHash := createUserPINHash(testUserPIN2)

	for i := 0; i < 25; i++ {
		state, config := createTestKeyManagerState()
		km := NewKeyManager(state, config)
		require.NoError(t, km.InitializeSOPIN(testSOPIN))
		require.NoError(t, km.InitializeUserPIN(pinHash))

		wrapped, err := km.WrapCredentialKey(credBuf)
		require.NoError(t, err)
		require.NotEmpty(t, wrapped)
		require.NoError(t, km.WrapAttestationKey(credBuf))
		require.NoError(t, km.ResetUserPIN(newPINHash))

		currentSMK := state.SOPINManager.DeriveKey(testSOPIN)
		require.NotNil(t, currentSMK)
		require.NoError(t, km.ChangeSOPIN(currentSMK, testSOPIN2))
		km.Lock()
	}
}
