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
	"testing"

	"github.com/stretchr/testify/require"

	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// protectedTestKey returns a 32-byte wrapping key held in protected memory
// alongside a heap copy for building the test's own wrapper.
func protectedTestKey(t *testing.T) (*secure.Buffer, []byte) {
	t.Helper()
	keyBytes := generateRandomKey(t, AESGCMKeySize)
	heapCopy := make([]byte, len(keyBytes))
	copy(heapCopy, keyBytes)
	buf, err := secure.NewBufferFromBytes(keyBytes) // wipes keyBytes
	require.NoError(t, err)
	t.Cleanup(buf.Destroy)
	return buf, heapCopy
}

func TestUnwrapIntoProtected(t *testing.T) {
	t.Run("unwraps into protected memory without a heap transit", func(t *testing.T) {
		keyBuf, heapKey := protectedTestKey(t)
		wrapper, err := NewAESGCMKeyWrapper(heapKey)
		require.NoError(t, err)

		plaintext := generateRandomKey(t, AESGCMKeySize)
		wrapped, err := wrapper.Wrap(plaintext)
		require.NoError(t, err)

		out, err := unwrapIntoProtected(keyBuf, wrapped)
		require.NoError(t, err)
		defer out.Destroy()

		require.NoError(t, out.WithBytes(func(b []byte) error {
			require.Equal(t, plaintext, b)
			return nil
		}))
	})

	t.Run("nil key returns ErrKeyManagerLocked", func(t *testing.T) {
		keyBuf, heapKey := protectedTestKey(t)
		_ = keyBuf
		wrapper, err := NewAESGCMKeyWrapper(heapKey)
		require.NoError(t, err)
		wrapped, err := wrapper.Wrap(generateRandomKey(t, AESGCMKeySize))
		require.NoError(t, err)

		out, err := unwrapIntoProtected(nil, wrapped)
		require.ErrorIs(t, err, ErrKeyManagerLocked)
		require.Nil(t, out)
	})

	t.Run("malformed wrapped data returns ErrInvalidWrappedData", func(t *testing.T) {
		keyBuf, _ := protectedTestKey(t)

		out, err := unwrapIntoProtected(keyBuf, make([]byte, AESGCMNonceSize))
		require.ErrorIs(t, err, ErrInvalidWrappedData)
		require.Nil(t, out)
	})

	t.Run("zero-length plaintext is refused as malformed key material", func(t *testing.T) {
		keyBuf, heapKey := protectedTestKey(t)
		wrapper, err := NewAESGCMKeyWrapper(heapKey)
		require.NoError(t, err)
		wrapped, err := wrapper.Wrap([]byte{})
		require.NoError(t, err)

		out, err := unwrapIntoProtected(keyBuf, wrapped)
		require.ErrorIs(t, err, ErrInvalidWrappedData)
		require.Nil(t, out)
	})

	t.Run("authentication failure destroys the destination buffer", func(t *testing.T) {
		keyBuf, heapKey := protectedTestKey(t)
		wrapper, err := NewAESGCMKeyWrapper(heapKey)
		require.NoError(t, err)
		wrapped, err := wrapper.Wrap(generateRandomKey(t, AESGCMKeySize))
		require.NoError(t, err)
		wrapped[AESGCMNonceSize] ^= 0x01

		out, err := unwrapIntoProtected(keyBuf, wrapped)
		require.ErrorIs(t, err, ErrKeyUnwrapFailed)
		require.Nil(t, out)
	})
}

// TestUnwrapIntoProtected_NoNestedBorrowDeadlock exercises the full unlock
// paths — the ones that decrypt inside a withKeyWrapper borrow — repeatedly.
// The purge-lock nesting rule in go-qrdb pkg/secure makes a purge-class
// allocation inside a borrow deadlock rather than error, so this test's
// protection is the -timeout on the test run: a regression hangs here instead
// of failing an assertion (go-xkms#291).
func TestUnwrapIntoProtected_NoNestedBorrowDeadlock(t *testing.T) {
	state, config := createTestKeyManagerState()
	km := NewKeyManager(state, config)
	require.NoError(t, km.InitializeSOPIN(testSOPIN))

	pinHash := createUserPINHash(testUserPINString)
	require.NoError(t, km.UnlockWithSOPIN(testSOPIN))
	require.NoError(t, km.InitializeUserPIN(pinHash))
	state.PINSet = true
	state.PINHash = pinHash
	km.Lock()

	for i := 0; i < 25; i++ {
		require.NoError(t, km.UnlockWithSOPIN(testSOPIN))
		km.Lock()
		require.NoError(t, km.UnlockWithUserPIN(pinHash))
		km.Lock()
	}
}
