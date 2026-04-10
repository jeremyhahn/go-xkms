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

package module

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createAESKey generates a random AES-256 key (32 bytes).
func createAESKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	return key
}

// createWrappingKey creates a wrapping key with CKA_WRAP and CKA_VALUE.
func createWrappingKey(t *testing.T, m *Module, sessionHandle SessionHandle) ObjectHandle {
	t.Helper()
	template := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewBoolAttribute(CKA_WRAP, true),
		NewBoolAttribute(CKA_UNWRAP, true),
		NewAttribute(CKA_VALUE, createAESKey(t)),
	}
	handle, rv := m.CreateObject(sessionHandle, template)
	require.Equal(t, CKR_OK, rv)
	return handle
}

// createExtractableSecretKey creates an extractable secret key with CKA_VALUE.
func createExtractableSecretKey(t *testing.T, m *Module, sessionHandle SessionHandle) ObjectHandle {
	t.Helper()
	template := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewBoolAttribute(CKA_EXTRACTABLE, true),
		NewAttribute(CKA_VALUE, createAESKey(t)),
	}
	handle, rv := m.CreateObject(sessionHandle, template)
	require.Equal(t, CKR_OK, rv)
	return handle
}

// createAuthWrapTestObjects creates a module with a R/W session and returns:
//   - the module
//   - a R/W session handle
//   - a wrapping key handle (AES-256 with CKA_WRAP and CKA_UNWRAP)
//   - a target key handle (AES-256 extractable secret key)
func createAuthWrapTestObjects(t *testing.T) (*Module, SessionHandle, ObjectHandle, ObjectHandle) {
	t.Helper()
	m := initializeTestModule(t)

	sessionHandle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
	require.Equal(t, CKR_OK, rv)

	wrappingKeyValue := createAESKey(t)
	targetKeyValue := createAESKey(t)

	// Create wrapping key with CKA_WRAP and CKA_UNWRAP
	wrappingTemplate := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewStringAttribute(CKA_LABEL, "wrapping-key"),
		NewBoolAttribute(CKA_WRAP, true),
		NewBoolAttribute(CKA_UNWRAP, true),
		NewBoolAttribute(CKA_EXTRACTABLE, true),
		NewAttribute(CKA_VALUE, wrappingKeyValue),
	}
	wrappingKeyHandle, rv := m.CreateObject(sessionHandle, wrappingTemplate)
	require.Equal(t, CKR_OK, rv)

	// Create target key (extractable)
	targetTemplate := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewStringAttribute(CKA_LABEL, "target-key"),
		NewBoolAttribute(CKA_EXTRACTABLE, true),
		NewAttribute(CKA_VALUE, targetKeyValue),
	}
	targetKeyHandle, rv := m.CreateObject(sessionHandle, targetTemplate)
	require.Equal(t, CKR_OK, rv)

	return m, sessionHandle, wrappingKeyHandle, targetKeyHandle
}

// TestWrapKeyAuthenticated tests authenticated key wrapping with AES-GCM.
func TestWrapKeyAuthenticated(t *testing.T) {

	t.Run("wraps key successfully with associated data", func(t *testing.T) {
		m, sessionHandle, wrappingKeyHandle, targetKeyHandle := createAuthWrapTestObjects(t)
		defer m.Finalize()

		mechanism := NewMechanism(CKM_AES_GCM)
		aad := []byte("associated-data")

		wrappedKey, err := m.WrapKeyAuthenticated(sessionHandle, mechanism, wrappingKeyHandle, targetKeyHandle, aad)
		require.NoError(t, err)
		require.NotNil(t, wrappedKey)

		// Wrapped key must be at least GCMNonceSize + 1 byte + GCMTagSize
		assert.Greater(t, len(wrappedKey), GCMMinCiphertextSize)

		// Nonce should be the first 12 bytes; verify non-zero
		nonce := wrappedKey[:GCMNonceSize]
		assert.NotEqual(t, make([]byte, GCMNonceSize), nonce, "nonce should not be all zeros")
	})

	t.Run("wraps key successfully with nil associated data", func(t *testing.T) {
		m, sessionHandle, wrappingKeyHandle, targetKeyHandle := createAuthWrapTestObjects(t)
		defer m.Finalize()

		mechanism := NewMechanism(CKM_AES_GCM)

		wrappedKey, err := m.WrapKeyAuthenticated(sessionHandle, mechanism, wrappingKeyHandle, targetKeyHandle, nil)
		require.NoError(t, err)
		require.NotNil(t, wrappedKey)
		assert.Greater(t, len(wrappedKey), GCMMinCiphertextSize)
	})

	t.Run("wraps and unwraps round-trip preserves key material", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		sessionHandle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		aesKey := createAESKey(t)
		originalKeyValue := createAESKey(t)

		// Create wrapping key
		wkTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
			NewBoolAttribute(CKA_WRAP, true),
			NewBoolAttribute(CKA_UNWRAP, true),
			NewAttribute(CKA_VALUE, aesKey),
		}
		wkHandle, rv := m.CreateObject(sessionHandle, wkTemplate)
		require.Equal(t, CKR_OK, rv)

		// Create target key
		tkTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
			NewBoolAttribute(CKA_EXTRACTABLE, true),
			NewAttribute(CKA_VALUE, originalKeyValue),
		}
		tkHandle, rv := m.CreateObject(sessionHandle, tkTemplate)
		require.Equal(t, CKR_OK, rv)

		aad := []byte("round-trip-test")
		mechanism := NewMechanism(CKM_AES_GCM)

		// Wrap
		wrappedKey, err := m.WrapKeyAuthenticated(sessionHandle, mechanism, wkHandle, tkHandle, aad)
		require.NoError(t, err)

		// Unwrap
		unwrapTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
			NewBoolAttribute(CKA_EXTRACTABLE, true),
		}
		newHandle, err := m.UnwrapKeyAuthenticated(sessionHandle, mechanism, wkHandle, wrappedKey, unwrapTemplate, aad)
		require.NoError(t, err)
		assert.NotEqual(t, ObjectHandle(InvalidHandle), newHandle)

		// Verify the unwrapped key material matches the original
		unwrappedObj, err := m.objectManager.GetObject(newHandle)
		require.NoError(t, err)
		unwrappedValue := unwrappedObj.GetAttribute(CKA_VALUE)
		assert.True(t, bytes.Equal(originalKeyValue, unwrappedValue),
			"unwrapped key material should match original")
	})

	t.Run("produces unique nonces per invocation", func(t *testing.T) {
		m, sessionHandle, wrappingKeyHandle, targetKeyHandle := createAuthWrapTestObjects(t)
		defer m.Finalize()

		mechanism := NewMechanism(CKM_AES_GCM)

		wrapped1, err := m.WrapKeyAuthenticated(sessionHandle, mechanism, wrappingKeyHandle, targetKeyHandle, nil)
		require.NoError(t, err)

		wrapped2, err := m.WrapKeyAuthenticated(sessionHandle, mechanism, wrappingKeyHandle, targetKeyHandle, nil)
		require.NoError(t, err)

		nonce1 := wrapped1[:GCMNonceSize]
		nonce2 := wrapped2[:GCMNonceSize]
		assert.False(t, bytes.Equal(nonce1, nonce2), "nonces must be unique per wrapping")
	})

	t.Run("returns CKR_ARGUMENTS_BAD with nil mechanism", func(t *testing.T) {
		m, sessionHandle, _, keyHandle := createAuthWrapTestObjects(t)
		defer m.Finalize()

		wrappedKey, err := m.WrapKeyAuthenticated(sessionHandle, nil, keyHandle, keyHandle, nil)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_ARGUMENTS_BAD, pkcsErr.Code)
		assert.Nil(t, wrappedKey)
	})

	t.Run("returns CKR_MECHANISM_INVALID for non-GCM mechanism", func(t *testing.T) {
		m, sessionHandle, wrappingKeyHandle, targetKeyHandle := createAuthWrapTestObjects(t)
		defer m.Finalize()

		mechanism := NewMechanism(CKM_AES_CBC) // Not an AEAD mechanism
		wrappedKey, err := m.WrapKeyAuthenticated(sessionHandle, mechanism, wrappingKeyHandle, targetKeyHandle, nil)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_MECHANISM_INVALID, pkcsErr.Code)
		assert.Nil(t, wrappedKey)
	})

	t.Run("returns CKR_WRAPPING_KEY_HANDLE_INVALID with invalid wrapping key", func(t *testing.T) {
		m, sessionHandle, _, targetKeyHandle := createAuthWrapTestObjects(t)
		defer m.Finalize()

		mechanism := NewMechanism(CKM_AES_GCM)
		wrappedKey, err := m.WrapKeyAuthenticated(sessionHandle, mechanism, ObjectHandle(99999), targetKeyHandle, nil)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_WRAPPING_KEY_HANDLE_INVALID, pkcsErr.Code)
		assert.Nil(t, wrappedKey)
	})

	t.Run("returns CKR_KEY_HANDLE_INVALID with invalid key to wrap", func(t *testing.T) {
		m, sessionHandle, wrappingKeyHandle, _ := createAuthWrapTestObjects(t)
		defer m.Finalize()

		mechanism := NewMechanism(CKM_AES_GCM)
		wrappedKey, err := m.WrapKeyAuthenticated(sessionHandle, mechanism, wrappingKeyHandle, ObjectHandle(99999), nil)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_KEY_HANDLE_INVALID, pkcsErr.Code)
		assert.Nil(t, wrappedKey)
	})

	t.Run("returns CKR_KEY_FUNCTION_NOT_PERMITTED when CKA_WRAP is false", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		sessionHandle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		// Key without CKA_WRAP
		noWrapTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
			NewBoolAttribute(CKA_WRAP, false),
			NewAttribute(CKA_VALUE, createAESKey(t)),
		}
		noWrapHandle, rv := m.CreateObject(sessionHandle, noWrapTemplate)
		require.Equal(t, CKR_OK, rv)

		// Target key
		targetTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewBoolAttribute(CKA_EXTRACTABLE, true),
			NewAttribute(CKA_VALUE, createAESKey(t)),
		}
		targetHandle, rv := m.CreateObject(sessionHandle, targetTemplate)
		require.Equal(t, CKR_OK, rv)

		mechanism := NewMechanism(CKM_AES_GCM)
		wrappedKey, err := m.WrapKeyAuthenticated(sessionHandle, mechanism, noWrapHandle, targetHandle, nil)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_KEY_FUNCTION_NOT_PERMITTED, pkcsErr.Code)
		assert.Nil(t, wrappedKey)
	})

	t.Run("returns CKR_KEY_NOT_WRAPPABLE when target is not extractable", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		sessionHandle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		// Wrapping key
		wkTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewBoolAttribute(CKA_WRAP, true),
			NewAttribute(CKA_VALUE, createAESKey(t)),
		}
		wkHandle, rv := m.CreateObject(sessionHandle, wkTemplate)
		require.Equal(t, CKR_OK, rv)

		// Non-extractable target key
		targetTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewBoolAttribute(CKA_EXTRACTABLE, false),
			NewAttribute(CKA_VALUE, createAESKey(t)),
		}
		targetHandle, rv := m.CreateObject(sessionHandle, targetTemplate)
		require.Equal(t, CKR_OK, rv)

		mechanism := NewMechanism(CKM_AES_GCM)
		wrappedKey, err := m.WrapKeyAuthenticated(sessionHandle, mechanism, wkHandle, targetHandle, nil)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_KEY_NOT_WRAPPABLE, pkcsErr.Code)
		assert.Nil(t, wrappedKey)
	})

	t.Run("returns CKR_WRAPPING_KEY_SIZE_RANGE for invalid AES key size", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		sessionHandle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		// Wrapping key with invalid size (17 bytes)
		badKeyValue := make([]byte, 17)
		wkTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewBoolAttribute(CKA_WRAP, true),
			NewAttribute(CKA_VALUE, badKeyValue),
		}
		wkHandle, rv := m.CreateObject(sessionHandle, wkTemplate)
		require.Equal(t, CKR_OK, rv)

		// Target key
		targetTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewBoolAttribute(CKA_EXTRACTABLE, true),
			NewAttribute(CKA_VALUE, createAESKey(t)),
		}
		targetHandle, rv := m.CreateObject(sessionHandle, targetTemplate)
		require.Equal(t, CKR_OK, rv)

		mechanism := NewMechanism(CKM_AES_GCM)
		wrappedKey, err := m.WrapKeyAuthenticated(sessionHandle, mechanism, wkHandle, targetHandle, nil)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_WRAPPING_KEY_SIZE_RANGE, pkcsErr.Code)
		assert.Nil(t, wrappedKey)
	})

	t.Run("returns CKR_SESSION_READ_ONLY for read-only session", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		// Open read-only session
		roSession, rv := m.OpenSession(0, CKF_SERIAL_SESSION)
		require.Equal(t, CKR_OK, rv)

		mechanism := NewMechanism(CKM_AES_GCM)

		// We need valid key handles, so create them via a R/W session first
		rwSession, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		wkTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewBoolAttribute(CKA_WRAP, true),
			NewAttribute(CKA_VALUE, createAESKey(t)),
		}
		wkHandle, rv := m.CreateObject(rwSession, wkTemplate)
		require.Equal(t, CKR_OK, rv)

		targetTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewBoolAttribute(CKA_EXTRACTABLE, true),
			NewAttribute(CKA_VALUE, createAESKey(t)),
		}
		targetHandle, rv := m.CreateObject(rwSession, targetTemplate)
		require.Equal(t, CKR_OK, rv)

		// Try wrapping on the read-only session
		wrappedKey, err := m.WrapKeyAuthenticated(roSession, mechanism, wkHandle, targetHandle, nil)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_SESSION_READ_ONLY, pkcsErr.Code)
		assert.Nil(t, wrappedKey)
	})
}

// TestWrapKeyAuthenticatedNotInitialized tests that WrapKeyAuthenticated
// rejects calls when the module has not been initialized.
func TestWrapKeyAuthenticatedNotInitialized(t *testing.T) {

	t.Run("returns CKR_CRYPTOKI_NOT_INITIALIZED", func(t *testing.T) {
		m := createTestModule(t)

		mechanism := NewMechanism(CKM_AES_GCM)
		wrappedKey, err := m.WrapKeyAuthenticated(SessionHandle(1), mechanism, ObjectHandle(1), ObjectHandle(2), nil)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, pkcsErr.Code)
		assert.Nil(t, wrappedKey)
	})
}

// TestWrapKeyAuthenticatedInvalidSession tests that WrapKeyAuthenticated
// rejects calls with an invalid session handle.
func TestWrapKeyAuthenticatedInvalidSession(t *testing.T) {

	t.Run("returns CKR_SESSION_HANDLE_INVALID", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		mechanism := NewMechanism(CKM_AES_GCM)
		wrappedKey, err := m.WrapKeyAuthenticated(SessionHandle(99999), mechanism, ObjectHandle(1), ObjectHandle(2), nil)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_SESSION_HANDLE_INVALID, pkcsErr.Code)
		assert.Nil(t, wrappedKey)
	})
}

// TestUnwrapKeyAuthenticated tests authenticated key unwrapping with AES-GCM.
func TestUnwrapKeyAuthenticated(t *testing.T) {

	t.Run("unwraps key successfully with associated data", func(t *testing.T) {
		m, sessionHandle, wrappingKeyHandle, targetKeyHandle := createAuthWrapTestObjects(t)
		defer m.Finalize()

		mechanism := NewMechanism(CKM_AES_GCM)
		aad := []byte("associated-data")

		// Wrap first
		wrappedKey, err := m.WrapKeyAuthenticated(sessionHandle, mechanism, wrappingKeyHandle, targetKeyHandle, aad)
		require.NoError(t, err)

		// Unwrap
		unwrapTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		}
		handle, err := m.UnwrapKeyAuthenticated(sessionHandle, mechanism, wrappingKeyHandle, wrappedKey, unwrapTemplate, aad)
		require.NoError(t, err)
		assert.NotEqual(t, ObjectHandle(InvalidHandle), handle)
	})

	t.Run("unwraps key successfully with nil associated data", func(t *testing.T) {
		m, sessionHandle, wrappingKeyHandle, targetKeyHandle := createAuthWrapTestObjects(t)
		defer m.Finalize()

		mechanism := NewMechanism(CKM_AES_GCM)

		wrappedKey, err := m.WrapKeyAuthenticated(sessionHandle, mechanism, wrappingKeyHandle, targetKeyHandle, nil)
		require.NoError(t, err)

		unwrapTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		}
		handle, err := m.UnwrapKeyAuthenticated(sessionHandle, mechanism, wrappingKeyHandle, wrappedKey, unwrapTemplate, nil)
		require.NoError(t, err)
		assert.NotEqual(t, ObjectHandle(InvalidHandle), handle)
	})

	t.Run("returns CKR_AEAD_DECRYPT_FAILED with wrong AAD", func(t *testing.T) {
		m, sessionHandle, wrappingKeyHandle, targetKeyHandle := createAuthWrapTestObjects(t)
		defer m.Finalize()

		mechanism := NewMechanism(CKM_AES_GCM)
		aad := []byte("correct-aad")

		wrappedKey, err := m.WrapKeyAuthenticated(sessionHandle, mechanism, wrappingKeyHandle, targetKeyHandle, aad)
		require.NoError(t, err)

		// Unwrap with wrong AAD
		unwrapTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		}
		handle, err := m.UnwrapKeyAuthenticated(sessionHandle, mechanism, wrappingKeyHandle, wrappedKey, unwrapTemplate, []byte("wrong-aad"))
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_AEAD_DECRYPT_FAILED, pkcsErr.Code)
		assert.Equal(t, ObjectHandle(InvalidHandle), handle)
	})

	t.Run("returns CKR_AEAD_DECRYPT_FAILED with tampered ciphertext", func(t *testing.T) {
		m, sessionHandle, wrappingKeyHandle, targetKeyHandle := createAuthWrapTestObjects(t)
		defer m.Finalize()

		mechanism := NewMechanism(CKM_AES_GCM)

		wrappedKey, err := m.WrapKeyAuthenticated(sessionHandle, mechanism, wrappingKeyHandle, targetKeyHandle, nil)
		require.NoError(t, err)

		// Tamper with a byte in the ciphertext portion (after the nonce)
		tampered := make([]byte, len(wrappedKey))
		copy(tampered, wrappedKey)
		tampered[GCMNonceSize+1] ^= 0xFF

		unwrapTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		}
		handle, err := m.UnwrapKeyAuthenticated(sessionHandle, mechanism, wrappingKeyHandle, tampered, unwrapTemplate, nil)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_AEAD_DECRYPT_FAILED, pkcsErr.Code)
		assert.Equal(t, ObjectHandle(InvalidHandle), handle)
	})

	t.Run("returns CKR_AEAD_DECRYPT_FAILED with wrong unwrapping key", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		sessionHandle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		correctKey := createAESKey(t)
		wrongKey := createAESKey(t)

		// Wrapping key
		wkTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewBoolAttribute(CKA_WRAP, true),
			NewBoolAttribute(CKA_UNWRAP, true),
			NewAttribute(CKA_VALUE, correctKey),
		}
		wkHandle, rv := m.CreateObject(sessionHandle, wkTemplate)
		require.Equal(t, CKR_OK, rv)

		// Wrong key
		wrongKeyTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewBoolAttribute(CKA_UNWRAP, true),
			NewAttribute(CKA_VALUE, wrongKey),
		}
		wrongKeyHandle, rv := m.CreateObject(sessionHandle, wrongKeyTemplate)
		require.Equal(t, CKR_OK, rv)

		// Target
		targetTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewBoolAttribute(CKA_EXTRACTABLE, true),
			NewAttribute(CKA_VALUE, createAESKey(t)),
		}
		targetHandle, rv := m.CreateObject(sessionHandle, targetTemplate)
		require.Equal(t, CKR_OK, rv)

		mechanism := NewMechanism(CKM_AES_GCM)

		// Wrap with correct key
		wrappedKey, err := m.WrapKeyAuthenticated(sessionHandle, mechanism, wkHandle, targetHandle, nil)
		require.NoError(t, err)

		// Unwrap with wrong key
		unwrapTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		}
		handle, err := m.UnwrapKeyAuthenticated(sessionHandle, mechanism, wrongKeyHandle, wrappedKey, unwrapTemplate, nil)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_AEAD_DECRYPT_FAILED, pkcsErr.Code)
		assert.Equal(t, ObjectHandle(InvalidHandle), handle)
	})

	t.Run("returns CKR_ARGUMENTS_BAD with nil mechanism", func(t *testing.T) {
		m, sessionHandle, keyHandle, _ := createAuthWrapTestObjects(t)
		defer m.Finalize()

		handle, err := m.UnwrapKeyAuthenticated(sessionHandle, nil, keyHandle, []byte("wrapped"), nil, nil)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_ARGUMENTS_BAD, pkcsErr.Code)
		assert.Equal(t, ObjectHandle(InvalidHandle), handle)
	})

	t.Run("returns CKR_MECHANISM_INVALID for non-GCM mechanism", func(t *testing.T) {
		m, sessionHandle, wrappingKeyHandle, _ := createAuthWrapTestObjects(t)
		defer m.Finalize()

		mechanism := NewMechanism(CKM_AES_CBC)
		handle, err := m.UnwrapKeyAuthenticated(sessionHandle, mechanism, wrappingKeyHandle, []byte("wrapped-data-that-is-long-enough-for-gcm"), nil, nil)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_MECHANISM_INVALID, pkcsErr.Code)
		assert.Equal(t, ObjectHandle(InvalidHandle), handle)
	})

	t.Run("returns CKR_UNWRAPPING_KEY_HANDLE_INVALID with invalid unwrapping key", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		sessionHandle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		mechanism := NewMechanism(CKM_AES_GCM)
		handle, err := m.UnwrapKeyAuthenticated(sessionHandle, mechanism, ObjectHandle(99999), []byte("wrapped"), nil, nil)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_UNWRAPPING_KEY_HANDLE_INVALID, pkcsErr.Code)
		assert.Equal(t, ObjectHandle(InvalidHandle), handle)
	})

	t.Run("returns CKR_WRAPPED_KEY_INVALID with empty wrapped key", func(t *testing.T) {
		m, sessionHandle, wrappingKeyHandle, _ := createAuthWrapTestObjects(t)
		defer m.Finalize()

		mechanism := NewMechanism(CKM_AES_GCM)
		handle, err := m.UnwrapKeyAuthenticated(sessionHandle, mechanism, wrappingKeyHandle, []byte{}, nil, nil)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_WRAPPED_KEY_INVALID, pkcsErr.Code)
		assert.Equal(t, ObjectHandle(InvalidHandle), handle)
	})

	t.Run("returns CKR_WRAPPED_KEY_INVALID with too-short wrapped key", func(t *testing.T) {
		m, sessionHandle, wrappingKeyHandle, _ := createAuthWrapTestObjects(t)
		defer m.Finalize()

		mechanism := NewMechanism(CKM_AES_GCM)
		// Exactly GCMMinCiphertextSize bytes (28) -- needs at least 29 (nonce + 1 + tag)
		tooShort := make([]byte, GCMMinCiphertextSize)
		handle, err := m.UnwrapKeyAuthenticated(sessionHandle, mechanism, wrappingKeyHandle, tooShort, nil, nil)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_WRAPPED_KEY_INVALID, pkcsErr.Code)
		assert.Equal(t, ObjectHandle(InvalidHandle), handle)
	})

	t.Run("returns CKR_KEY_FUNCTION_NOT_PERMITTED when CKA_UNWRAP is false", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		sessionHandle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		// Key without CKA_UNWRAP
		noUnwrapTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewBoolAttribute(CKA_UNWRAP, false),
			NewAttribute(CKA_VALUE, createAESKey(t)),
		}
		noUnwrapHandle, rv := m.CreateObject(sessionHandle, noUnwrapTemplate)
		require.Equal(t, CKR_OK, rv)

		mechanism := NewMechanism(CKM_AES_GCM)
		// Use a wrapped key that is long enough to pass the length check
		fakeWrapped := make([]byte, GCMMinCiphertextSize+10)
		handle, err := m.UnwrapKeyAuthenticated(sessionHandle, mechanism, noUnwrapHandle, fakeWrapped, nil, nil)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_KEY_FUNCTION_NOT_PERMITTED, pkcsErr.Code)
		assert.Equal(t, ObjectHandle(InvalidHandle), handle)
	})

	t.Run("returns CKR_SESSION_READ_ONLY for read-only session", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		// Open read-only session
		roSession, rv := m.OpenSession(0, CKF_SERIAL_SESSION)
		require.Equal(t, CKR_OK, rv)

		// We need a valid key handle via a R/W session
		rwSession, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		keyTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewBoolAttribute(CKA_UNWRAP, true),
			NewAttribute(CKA_VALUE, createAESKey(t)),
		}
		keyHandle, rv := m.CreateObject(rwSession, keyTemplate)
		require.Equal(t, CKR_OK, rv)

		mechanism := NewMechanism(CKM_AES_GCM)
		fakeWrapped := make([]byte, GCMMinCiphertextSize+10)
		handle, err := m.UnwrapKeyAuthenticated(roSession, mechanism, keyHandle, fakeWrapped, nil, nil)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_SESSION_READ_ONLY, pkcsErr.Code)
		assert.Equal(t, ObjectHandle(InvalidHandle), handle)
	})

	t.Run("returns CKR_WRAPPING_KEY_SIZE_RANGE for invalid AES key size", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		sessionHandle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		// Bad key size (17 bytes)
		badKeyTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewBoolAttribute(CKA_UNWRAP, true),
			NewAttribute(CKA_VALUE, make([]byte, 17)),
		}
		badKeyHandle, rv := m.CreateObject(sessionHandle, badKeyTemplate)
		require.Equal(t, CKR_OK, rv)

		mechanism := NewMechanism(CKM_AES_GCM)
		fakeWrapped := make([]byte, GCMMinCiphertextSize+10)
		handle, err := m.UnwrapKeyAuthenticated(sessionHandle, mechanism, badKeyHandle, fakeWrapped, nil, nil)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_WRAPPING_KEY_SIZE_RANGE, pkcsErr.Code)
		assert.Equal(t, ObjectHandle(InvalidHandle), handle)
	})
}

// TestUnwrapKeyAuthenticatedNotInitialized tests that UnwrapKeyAuthenticated
// rejects calls when the module has not been initialized.
func TestUnwrapKeyAuthenticatedNotInitialized(t *testing.T) {

	t.Run("returns CKR_CRYPTOKI_NOT_INITIALIZED", func(t *testing.T) {
		m := createTestModule(t)

		mechanism := NewMechanism(CKM_AES_GCM)
		handle, err := m.UnwrapKeyAuthenticated(SessionHandle(1), mechanism, ObjectHandle(1), []byte("wrapped"), nil, nil)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, pkcsErr.Code)
		assert.Equal(t, ObjectHandle(InvalidHandle), handle)
	})
}

// TestUnwrapKeyAuthenticatedInvalidSession tests that UnwrapKeyAuthenticated
// rejects calls with an invalid session handle.
func TestUnwrapKeyAuthenticatedInvalidSession(t *testing.T) {

	t.Run("returns CKR_SESSION_HANDLE_INVALID", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		mechanism := NewMechanism(CKM_AES_GCM)
		handle, err := m.UnwrapKeyAuthenticated(SessionHandle(99999), mechanism, ObjectHandle(1), []byte("wrapped"), nil, nil)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_SESSION_HANDLE_INVALID, pkcsErr.Code)
		assert.Equal(t, ObjectHandle(InvalidHandle), handle)
	})
}

// TestValidAESKeySize validates the AES key size helper function.
func TestValidAESKeySize(t *testing.T) {

	t.Run("accepts valid AES key sizes", func(t *testing.T) {
		assert.True(t, validAESKeySize(16), "AES-128")
		assert.True(t, validAESKeySize(24), "AES-192")
		assert.True(t, validAESKeySize(32), "AES-256")
	})

	t.Run("rejects invalid AES key sizes", func(t *testing.T) {
		assert.False(t, validAESKeySize(0), "zero")
		assert.False(t, validAESKeySize(8), "too short")
		assert.False(t, validAESKeySize(15), "off by one low")
		assert.False(t, validAESKeySize(17), "off by one high")
		assert.False(t, validAESKeySize(33), "too long")
		assert.False(t, validAESKeySize(64), "way too long")
	})
}

// TestAuthWrapAESKeySizes tests wrapping with all valid AES key sizes.
func TestAuthWrapAESKeySizes(t *testing.T) {
	keySizes := []int{16, 24, 32}

	for _, size := range keySizes {
		t.Run(fmt.Sprintf("AES-%d", size*8), func(t *testing.T) {
			m := initializeTestModule(t)
			defer m.Finalize()

			sessionHandle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
			require.Equal(t, CKR_OK, rv)

			keyValue := make([]byte, size)
			_, err := rand.Read(keyValue)
			require.NoError(t, err)

			wkTemplate := []Attribute{
				NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
				NewBoolAttribute(CKA_WRAP, true),
				NewBoolAttribute(CKA_UNWRAP, true),
				NewAttribute(CKA_VALUE, keyValue),
			}
			wkHandle, rv := m.CreateObject(sessionHandle, wkTemplate)
			require.Equal(t, CKR_OK, rv)

			targetValue := createAESKey(t)
			targetTemplate := []Attribute{
				NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
				NewBoolAttribute(CKA_EXTRACTABLE, true),
				NewAttribute(CKA_VALUE, targetValue),
			}
			targetHandle, rv := m.CreateObject(sessionHandle, targetTemplate)
			require.Equal(t, CKR_OK, rv)

			mechanism := NewMechanism(CKM_AES_GCM)
			aad := []byte("aes-size-test")

			// Wrap
			wrappedKey, err := m.WrapKeyAuthenticated(sessionHandle, mechanism, wkHandle, targetHandle, aad)
			require.NoError(t, err)
			require.NotNil(t, wrappedKey)

			// Unwrap
			unwrapTemplate := []Attribute{
				NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
				NewBoolAttribute(CKA_EXTRACTABLE, true),
			}
			newHandle, err := m.UnwrapKeyAuthenticated(sessionHandle, mechanism, wkHandle, wrappedKey, unwrapTemplate, aad)
			require.NoError(t, err)

			// Verify round-trip
			newObj, err := m.objectManager.GetObject(newHandle)
			require.NoError(t, err)
			assert.True(t, bytes.Equal(targetValue, newObj.GetAttribute(CKA_VALUE)),
				"unwrapped key should match original for AES key size %d", size)
		})
	}
}

// TestWrapKeyAuthenticatedSize tests the size query method for authenticated wrapping.
func TestWrapKeyAuthenticatedSize(t *testing.T) {

	t.Run("returns correct size for AES-256 target key", func(t *testing.T) {
		m, sessionHandle, wkHandle, targetHandle := createAuthWrapTestObjects(t)
		defer m.Finalize()

		mechanism := NewMechanism(CKM_AES_GCM)

		// Query size
		size, err := m.WrapKeyAuthenticatedSize(sessionHandle, mechanism, wkHandle, targetHandle)
		require.NoError(t, err)

		// AES-256 key = 32 bytes, output = nonce(12) + ciphertext(32) + tag(16) = 60
		expectedSize := uint64(GCMNonceSize + 32 + GCMTagSize)
		assert.Equal(t, expectedSize, size)

		// Verify it matches the actual wrap output length
		wrappedKey, err := m.WrapKeyAuthenticated(sessionHandle, mechanism, wkHandle, targetHandle, nil)
		require.NoError(t, err)
		assert.Equal(t, expectedSize, uint64(len(wrappedKey)))
	})

	t.Run("returns CKR_CRYPTOKI_NOT_INITIALIZED when not initialized", func(t *testing.T) {
		m := &Module{}

		_, err := m.WrapKeyAuthenticatedSize(SessionHandle(1), NewMechanism(CKM_AES_GCM), ObjectHandle(1), ObjectHandle(2))
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, pkcsErr.Code)
	})

	t.Run("returns CKR_SESSION_HANDLE_INVALID for bad session", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		_, err := m.WrapKeyAuthenticatedSize(SessionHandle(9999), NewMechanism(CKM_AES_GCM), ObjectHandle(1), ObjectHandle(2))
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_SESSION_HANDLE_INVALID, pkcsErr.Code)
	})

	t.Run("returns CKR_ARGUMENTS_BAD with nil mechanism", func(t *testing.T) {
		m, sessionHandle, _, _ := createAuthWrapTestObjects(t)
		defer m.Finalize()

		_, err := m.WrapKeyAuthenticatedSize(sessionHandle, nil, ObjectHandle(1), ObjectHandle(2))
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_ARGUMENTS_BAD, pkcsErr.Code)
	})

	t.Run("returns CKR_MECHANISM_INVALID for non-GCM mechanism", func(t *testing.T) {
		m, sessionHandle, wkHandle, targetHandle := createAuthWrapTestObjects(t)
		defer m.Finalize()

		_, err := m.WrapKeyAuthenticatedSize(sessionHandle, NewMechanism(CKM_AES_CBC), wkHandle, targetHandle)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_MECHANISM_INVALID, pkcsErr.Code)
	})

	t.Run("returns CKR_WRAPPING_KEY_HANDLE_INVALID for bad wrapping key", func(t *testing.T) {
		m, sessionHandle, _, targetHandle := createAuthWrapTestObjects(t)
		defer m.Finalize()

		_, err := m.WrapKeyAuthenticatedSize(sessionHandle, NewMechanism(CKM_AES_GCM), ObjectHandle(9999), targetHandle)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_WRAPPING_KEY_HANDLE_INVALID, pkcsErr.Code)
	})

	t.Run("returns CKR_KEY_HANDLE_INVALID for bad target key", func(t *testing.T) {
		m, sessionHandle, wkHandle, _ := createAuthWrapTestObjects(t)
		defer m.Finalize()

		_, err := m.WrapKeyAuthenticatedSize(sessionHandle, NewMechanism(CKM_AES_GCM), wkHandle, ObjectHandle(9999))
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_KEY_HANDLE_INVALID, pkcsErr.Code)
	})

	t.Run("returns CKR_KEY_NOT_WRAPPABLE for non-extractable target", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		sessionHandle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		// Create wrapping key
		wkTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewBoolAttribute(CKA_WRAP, true),
			NewAttribute(CKA_VALUE, createAESKey(t)),
		}
		wkHandle, rv := m.CreateObject(sessionHandle, wkTemplate)
		require.Equal(t, CKR_OK, rv)

		// Create non-extractable target key
		targetTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewBoolAttribute(CKA_EXTRACTABLE, false),
			NewAttribute(CKA_VALUE, createAESKey(t)),
		}
		targetHandle, rv := m.CreateObject(sessionHandle, targetTemplate)
		require.Equal(t, CKR_OK, rv)

		_, err := m.WrapKeyAuthenticatedSize(sessionHandle, NewMechanism(CKM_AES_GCM), wkHandle, targetHandle)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_KEY_NOT_WRAPPABLE, pkcsErr.Code)
	})

	t.Run("returns CKR_KEY_FUNCTION_NOT_PERMITTED without CKA_WRAP", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		sessionHandle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		// Wrapping key without CKA_WRAP
		wkTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewAttribute(CKA_VALUE, createAESKey(t)),
		}
		wkHandle, rv := m.CreateObject(sessionHandle, wkTemplate)
		require.Equal(t, CKR_OK, rv)

		targetHandle := createExtractableSecretKey(t, m, sessionHandle)

		_, err := m.WrapKeyAuthenticatedSize(sessionHandle, NewMechanism(CKM_AES_GCM), wkHandle, targetHandle)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_KEY_FUNCTION_NOT_PERMITTED, pkcsErr.Code)
	})

	t.Run("returns CKR_WRAPPING_KEY_SIZE_RANGE for invalid key size", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		sessionHandle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		// Wrapping key with invalid 15-byte AES key
		wkTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewBoolAttribute(CKA_WRAP, true),
			NewAttribute(CKA_VALUE, make([]byte, 15)),
		}
		wkHandle, rv := m.CreateObject(sessionHandle, wkTemplate)
		require.Equal(t, CKR_OK, rv)

		targetHandle := createExtractableSecretKey(t, m, sessionHandle)

		_, err := m.WrapKeyAuthenticatedSize(sessionHandle, NewMechanism(CKM_AES_GCM), wkHandle, targetHandle)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_WRAPPING_KEY_SIZE_RANGE, pkcsErr.Code)
	})

	t.Run("returns CKR_WRAPPING_KEY_HANDLE_INVALID for wrapping key without CKA_VALUE", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		sessionHandle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		// Wrapping key with CKA_WRAP but no CKA_VALUE
		wkTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewBoolAttribute(CKA_WRAP, true),
		}
		wkHandle, rv := m.CreateObject(sessionHandle, wkTemplate)
		require.Equal(t, CKR_OK, rv)

		targetHandle := createExtractableSecretKey(t, m, sessionHandle)

		_, err := m.WrapKeyAuthenticatedSize(sessionHandle, NewMechanism(CKM_AES_GCM), wkHandle, targetHandle)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_WRAPPING_KEY_HANDLE_INVALID, pkcsErr.Code)
	})

	t.Run("returns CKR_KEY_NOT_WRAPPABLE for target key without CKA_VALUE", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		sessionHandle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		wkHandle := createWrappingKey(t, m, sessionHandle)

		// Target key with CKA_EXTRACTABLE but no CKA_VALUE
		targetTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewBoolAttribute(CKA_EXTRACTABLE, true),
		}
		targetHandle, rv := m.CreateObject(sessionHandle, targetTemplate)
		require.Equal(t, CKR_OK, rv)

		_, err := m.WrapKeyAuthenticatedSize(sessionHandle, NewMechanism(CKM_AES_GCM), wkHandle, targetHandle)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_KEY_NOT_WRAPPABLE, pkcsErr.Code)
	})
}

// TestWrapKeyAuthenticatedNoValue tests WrapKeyAuthenticated with keys missing CKA_VALUE.
func TestWrapKeyAuthenticatedNoValue(t *testing.T) {

	t.Run("returns error when wrapping key has no CKA_VALUE", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		sessionHandle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		// Wrapping key with CKA_WRAP but no CKA_VALUE
		wkTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewBoolAttribute(CKA_WRAP, true),
		}
		wkHandle, rv := m.CreateObject(sessionHandle, wkTemplate)
		require.Equal(t, CKR_OK, rv)

		targetHandle := createExtractableSecretKey(t, m, sessionHandle)

		_, err := m.WrapKeyAuthenticated(sessionHandle, NewMechanism(CKM_AES_GCM), wkHandle, targetHandle, nil)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_WRAPPING_KEY_HANDLE_INVALID, pkcsErr.Code)
	})

	t.Run("returns error when target key has no CKA_VALUE", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		sessionHandle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		wkHandle := createWrappingKey(t, m, sessionHandle)

		// Target key with CKA_EXTRACTABLE but no CKA_VALUE
		targetTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewBoolAttribute(CKA_EXTRACTABLE, true),
		}
		targetHandle, rv := m.CreateObject(sessionHandle, targetTemplate)
		require.Equal(t, CKR_OK, rv)

		_, err := m.WrapKeyAuthenticated(sessionHandle, NewMechanism(CKM_AES_GCM), wkHandle, targetHandle, nil)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_KEY_NOT_WRAPPABLE, pkcsErr.Code)
	})
}

// TestUnwrapKeyAuthenticatedNoValue tests UnwrapKeyAuthenticated with unwrapping key missing CKA_VALUE.
func TestUnwrapKeyAuthenticatedNoValue(t *testing.T) {

	t.Run("returns error when unwrapping key has no CKA_VALUE", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		sessionHandle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		// Unwrapping key with CKA_UNWRAP but no CKA_VALUE
		ukTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewBoolAttribute(CKA_UNWRAP, true),
		}
		ukHandle, rv := m.CreateObject(sessionHandle, ukTemplate)
		require.Equal(t, CKR_OK, rv)

		template := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		}
		// wrappedKey must be at least GCMMinCiphertextSize+1 = 29 bytes
		wrappedKey := make([]byte, 30)

		_, err := m.UnwrapKeyAuthenticated(sessionHandle, NewMechanism(CKM_AES_GCM), ukHandle, wrappedKey, template, nil)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_UNWRAPPING_KEY_HANDLE_INVALID, pkcsErr.Code)
	})
}

// TestAuthWrapWithGCMParams tests mechanism parameter (CK_GCM_PARAMS) handling
// for authenticated wrapping and unwrapping operations.
func TestAuthWrapWithGCMParams(t *testing.T) {

	t.Run("wrap uses caller-supplied IV from AESGCMParams", func(t *testing.T) {
		m, sessionHandle, wrappingKeyHandle, targetKeyHandle := createAuthWrapTestObjects(t)
		defer m.Finalize()

		// Caller-supplied 12-byte IV
		callerIV := make([]byte, GCMNonceSize)
		_, err := rand.Read(callerIV)
		require.NoError(t, err)

		gcmParams := NewAESGCMParams(callerIV, 128)
		mechanism := NewMechanismWithTypedParams(CKM_AES_GCM, gcmParams)

		wrappedKey, err := m.WrapKeyAuthenticated(sessionHandle, mechanism, wrappingKeyHandle, targetKeyHandle, nil)
		require.NoError(t, err)
		require.NotNil(t, wrappedKey)

		// When caller supplies IV, the nonce is NOT prepended to the output.
		// Output should be ciphertext (32 bytes for AES-256 key) + tag (16 bytes) = 48 bytes.
		assert.Equal(t, 32+GCMTagSize, len(wrappedKey),
			"output should be ciphertext+tag only when caller supplies IV")
	})

	t.Run("wrap without AESGCMParams prepends auto-generated nonce", func(t *testing.T) {
		m, sessionHandle, wrappingKeyHandle, targetKeyHandle := createAuthWrapTestObjects(t)
		defer m.Finalize()

		mechanism := NewMechanism(CKM_AES_GCM)

		wrappedKey, err := m.WrapKeyAuthenticated(sessionHandle, mechanism, wrappingKeyHandle, targetKeyHandle, nil)
		require.NoError(t, err)

		// Without params, output is nonce(12) + ciphertext(32) + tag(16) = 60 bytes.
		assert.Equal(t, GCMNonceSize+32+GCMTagSize, len(wrappedKey),
			"output should include prepended nonce when no params supplied")
	})

	t.Run("round-trip with caller-supplied IV preserves key material", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		sessionHandle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		aesKey := createAESKey(t)
		originalKeyValue := createAESKey(t)

		// Create wrapping key
		wkTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
			NewBoolAttribute(CKA_WRAP, true),
			NewBoolAttribute(CKA_UNWRAP, true),
			NewAttribute(CKA_VALUE, aesKey),
		}
		wkHandle, rv := m.CreateObject(sessionHandle, wkTemplate)
		require.Equal(t, CKR_OK, rv)

		// Create target key
		tkTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
			NewBoolAttribute(CKA_EXTRACTABLE, true),
			NewAttribute(CKA_VALUE, originalKeyValue),
		}
		tkHandle, rv := m.CreateObject(sessionHandle, tkTemplate)
		require.Equal(t, CKR_OK, rv)

		// Caller-supplied IV and AAD via mechanism parameters
		callerIV := make([]byte, GCMNonceSize)
		_, err := rand.Read(callerIV)
		require.NoError(t, err)
		aad := []byte("round-trip-gcm-params")

		gcmParams := NewAESGCMParamsWithAAD(callerIV, aad, 128)
		wrapMech := NewMechanismWithTypedParams(CKM_AES_GCM, gcmParams)

		// Wrap
		wrappedKey, err := m.WrapKeyAuthenticated(sessionHandle, wrapMech, wkHandle, tkHandle, nil)
		require.NoError(t, err)

		// Unwrap with the same caller-supplied IV and AAD
		unwrapGCMParams := NewAESGCMParamsWithAAD(callerIV, aad, 128)
		unwrapMech := NewMechanismWithTypedParams(CKM_AES_GCM, unwrapGCMParams)

		unwrapTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
			NewBoolAttribute(CKA_EXTRACTABLE, true),
		}
		newHandle, err := m.UnwrapKeyAuthenticated(sessionHandle, unwrapMech, wkHandle, wrappedKey, unwrapTemplate, nil)
		require.NoError(t, err)
		assert.NotEqual(t, ObjectHandle(InvalidHandle), newHandle)

		// Verify the unwrapped key material matches the original
		unwrappedObj, err := m.objectManager.GetObject(newHandle)
		require.NoError(t, err)
		unwrappedValue := unwrappedObj.GetAttribute(CKA_VALUE)
		assert.True(t, bytes.Equal(originalKeyValue, unwrappedValue),
			"unwrapped key material should match original")
	})

	t.Run("AESGCMParams AAD takes precedence over function argument", func(t *testing.T) {
		m, sessionHandle, wrappingKeyHandle, targetKeyHandle := createAuthWrapTestObjects(t)
		defer m.Finalize()

		callerIV := make([]byte, GCMNonceSize)
		_, err := rand.Read(callerIV)
		require.NoError(t, err)

		// Wrap with AAD in the mechanism params
		paramsAAD := []byte("params-aad")
		gcmParams := NewAESGCMParamsWithAAD(callerIV, paramsAAD, 128)
		mechanism := NewMechanismWithTypedParams(CKM_AES_GCM, gcmParams)

		// Pass a DIFFERENT AAD via the function argument -- should be ignored
		wrappedKey, err := m.WrapKeyAuthenticated(sessionHandle, mechanism, wrappingKeyHandle, targetKeyHandle, []byte("ignored-aad"))
		require.NoError(t, err)

		// Unwrap with the params AAD (the correct one)
		unwrapParams := NewAESGCMParamsWithAAD(callerIV, paramsAAD, 128)
		unwrapMech := NewMechanismWithTypedParams(CKM_AES_GCM, unwrapParams)
		unwrapTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		}

		handle, err := m.UnwrapKeyAuthenticated(sessionHandle, unwrapMech, wrappingKeyHandle, wrappedKey, unwrapTemplate, []byte("also-ignored"))
		require.NoError(t, err)
		assert.NotEqual(t, ObjectHandle(InvalidHandle), handle)
	})

	t.Run("returns CKR_MECHANISM_PARAM_INVALID for wrong IV length in wrap", func(t *testing.T) {
		m, sessionHandle, wrappingKeyHandle, targetKeyHandle := createAuthWrapTestObjects(t)
		defer m.Finalize()

		// Invalid IV length (8 bytes instead of 12)
		badIV := make([]byte, 8)
		gcmParams := NewAESGCMParams(badIV, 128)
		mechanism := NewMechanismWithTypedParams(CKM_AES_GCM, gcmParams)

		wrappedKey, err := m.WrapKeyAuthenticated(sessionHandle, mechanism, wrappingKeyHandle, targetKeyHandle, nil)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_MECHANISM_PARAM_INVALID, pkcsErr.Code)
		assert.Nil(t, wrappedKey)
	})

	t.Run("returns CKR_MECHANISM_PARAM_INVALID for wrong IV length in unwrap", func(t *testing.T) {
		m, sessionHandle, wrappingKeyHandle, _ := createAuthWrapTestObjects(t)
		defer m.Finalize()

		// Invalid IV length (16 bytes instead of 12)
		badIV := make([]byte, 16)
		gcmParams := NewAESGCMParams(badIV, 128)
		mechanism := NewMechanismWithTypedParams(CKM_AES_GCM, gcmParams)

		// Provide enough wrapped key data to pass the minimum size check
		fakeWrapped := make([]byte, GCMTagSize+10)
		unwrapTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		}

		handle, err := m.UnwrapKeyAuthenticated(sessionHandle, mechanism, wrappingKeyHandle, fakeWrapped, unwrapTemplate, nil)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_MECHANISM_PARAM_INVALID, pkcsErr.Code)
		assert.Equal(t, ObjectHandle(InvalidHandle), handle)
	})

	t.Run("returns CKR_AEAD_DECRYPT_FAILED with wrong caller-supplied IV", func(t *testing.T) {
		m, sessionHandle, wrappingKeyHandle, targetKeyHandle := createAuthWrapTestObjects(t)
		defer m.Finalize()

		// Wrap with one IV
		wrapIV := make([]byte, GCMNonceSize)
		_, err := rand.Read(wrapIV)
		require.NoError(t, err)

		wrapParams := NewAESGCMParams(wrapIV, 128)
		wrapMech := NewMechanismWithTypedParams(CKM_AES_GCM, wrapParams)

		wrappedKey, err := m.WrapKeyAuthenticated(sessionHandle, wrapMech, wrappingKeyHandle, targetKeyHandle, nil)
		require.NoError(t, err)

		// Unwrap with a different IV
		wrongIV := make([]byte, GCMNonceSize)
		_, err = rand.Read(wrongIV)
		require.NoError(t, err)

		unwrapParams := NewAESGCMParams(wrongIV, 128)
		unwrapMech := NewMechanismWithTypedParams(CKM_AES_GCM, unwrapParams)
		unwrapTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		}

		handle, err := m.UnwrapKeyAuthenticated(sessionHandle, unwrapMech, wrappingKeyHandle, wrappedKey, unwrapTemplate, nil)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_AEAD_DECRYPT_FAILED, pkcsErr.Code)
		assert.Equal(t, ObjectHandle(InvalidHandle), handle)
	})

	t.Run("unwrap with params rejects too-short wrapped key for params mode", func(t *testing.T) {
		m, sessionHandle, wrappingKeyHandle, _ := createAuthWrapTestObjects(t)
		defer m.Finalize()

		callerIV := make([]byte, GCMNonceSize)
		gcmParams := NewAESGCMParams(callerIV, 128)
		mechanism := NewMechanismWithTypedParams(CKM_AES_GCM, gcmParams)

		// With caller-supplied IV, minimum size is tag(16) + 1 = 17 bytes.
		// Provide exactly GCMTagSize (16 bytes) which is too short.
		tooShort := make([]byte, GCMTagSize)
		unwrapTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		}

		handle, err := m.UnwrapKeyAuthenticated(sessionHandle, mechanism, wrappingKeyHandle, tooShort, unwrapTemplate, nil)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_WRAPPED_KEY_INVALID, pkcsErr.Code)
		assert.Equal(t, ObjectHandle(InvalidHandle), handle)
	})
}

// TestAuthWrapSizeWithGCMParams tests WrapKeyAuthenticatedSize with CK_GCM_PARAMS.
func TestAuthWrapSizeWithGCMParams(t *testing.T) {

	t.Run("returns smaller size when caller supplies IV via params", func(t *testing.T) {
		m, sessionHandle, wkHandle, targetHandle := createAuthWrapTestObjects(t)
		defer m.Finalize()

		callerIV := make([]byte, GCMNonceSize)
		gcmParams := NewAESGCMParams(callerIV, 128)
		mechanism := NewMechanismWithTypedParams(CKM_AES_GCM, gcmParams)

		size, err := m.WrapKeyAuthenticatedSize(sessionHandle, mechanism, wkHandle, targetHandle)
		require.NoError(t, err)

		// With caller-supplied IV: ciphertext(32) + tag(16) = 48 (no nonce prefix)
		expectedSize := uint64(32 + GCMTagSize)
		assert.Equal(t, expectedSize, size)
	})

	t.Run("returns full size without params", func(t *testing.T) {
		m, sessionHandle, wkHandle, targetHandle := createAuthWrapTestObjects(t)
		defer m.Finalize()

		mechanism := NewMechanism(CKM_AES_GCM)

		size, err := m.WrapKeyAuthenticatedSize(sessionHandle, mechanism, wkHandle, targetHandle)
		require.NoError(t, err)

		// Without params: nonce(12) + ciphertext(32) + tag(16) = 60
		expectedSize := uint64(GCMNonceSize + 32 + GCMTagSize)
		assert.Equal(t, expectedSize, size)
	})

	t.Run("size matches actual wrap output with caller IV", func(t *testing.T) {
		m, sessionHandle, wkHandle, targetHandle := createAuthWrapTestObjects(t)
		defer m.Finalize()

		callerIV := make([]byte, GCMNonceSize)
		_, err := rand.Read(callerIV)
		require.NoError(t, err)

		gcmParams := NewAESGCMParams(callerIV, 128)
		mechanism := NewMechanismWithTypedParams(CKM_AES_GCM, gcmParams)

		// Query size
		size, err := m.WrapKeyAuthenticatedSize(sessionHandle, mechanism, wkHandle, targetHandle)
		require.NoError(t, err)

		// Actual wrap
		wrappedKey, err := m.WrapKeyAuthenticated(sessionHandle, mechanism, wkHandle, targetHandle, nil)
		require.NoError(t, err)

		assert.Equal(t, size, uint64(len(wrappedKey)),
			"predicted size must match actual output length")
	})
}

// TestUnwrapKeyAuthenticatedAttributes tests that unwrapped keys carry the
// PKCS#11 v3.2 mandatory attributes for imported/unwrapped keys.
func TestUnwrapKeyAuthenticatedAttributes(t *testing.T) {

	t.Run("unwrapped key has CKA_LOCAL set to false", func(t *testing.T) {
		m, sessionHandle, wrappingKeyHandle, targetKeyHandle := createAuthWrapTestObjects(t)
		defer m.Finalize()

		mechanism := NewMechanism(CKM_AES_GCM)
		wrappedKey, err := m.WrapKeyAuthenticated(sessionHandle, mechanism, wrappingKeyHandle, targetKeyHandle, nil)
		require.NoError(t, err)

		unwrapTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
			NewBoolAttribute(CKA_EXTRACTABLE, true),
		}
		newHandle, err := m.UnwrapKeyAuthenticated(sessionHandle, mechanism, wrappingKeyHandle, wrappedKey, unwrapTemplate, nil)
		require.NoError(t, err)

		obj, err := m.objectManager.GetObject(newHandle)
		require.NoError(t, err)

		localAttr := obj.GetAttribute(CKA_LOCAL)
		require.NotNil(t, localAttr, "CKA_LOCAL must be present on unwrapped key")
		assert.Equal(t, byte(0), localAttr[0], "CKA_LOCAL must be CK_FALSE for unwrapped keys")
	})

	t.Run("unwrapped key has CKA_ALWAYS_SENSITIVE set to false", func(t *testing.T) {
		m, sessionHandle, wrappingKeyHandle, targetKeyHandle := createAuthWrapTestObjects(t)
		defer m.Finalize()

		mechanism := NewMechanism(CKM_AES_GCM)
		wrappedKey, err := m.WrapKeyAuthenticated(sessionHandle, mechanism, wrappingKeyHandle, targetKeyHandle, nil)
		require.NoError(t, err)

		unwrapTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		}
		newHandle, err := m.UnwrapKeyAuthenticated(sessionHandle, mechanism, wrappingKeyHandle, wrappedKey, unwrapTemplate, nil)
		require.NoError(t, err)

		obj, err := m.objectManager.GetObject(newHandle)
		require.NoError(t, err)

		alwaysSensitive := obj.GetAttribute(CKA_ALWAYS_SENSITIVE)
		require.NotNil(t, alwaysSensitive, "CKA_ALWAYS_SENSITIVE must be present on unwrapped key")
		assert.Equal(t, byte(0), alwaysSensitive[0],
			"CKA_ALWAYS_SENSITIVE must be CK_FALSE for unwrapped keys")
	})

	t.Run("unwrapped key has CKA_NEVER_EXTRACTABLE set to false", func(t *testing.T) {
		m, sessionHandle, wrappingKeyHandle, targetKeyHandle := createAuthWrapTestObjects(t)
		defer m.Finalize()

		mechanism := NewMechanism(CKM_AES_GCM)
		wrappedKey, err := m.WrapKeyAuthenticated(sessionHandle, mechanism, wrappingKeyHandle, targetKeyHandle, nil)
		require.NoError(t, err)

		unwrapTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		}
		newHandle, err := m.UnwrapKeyAuthenticated(sessionHandle, mechanism, wrappingKeyHandle, wrappedKey, unwrapTemplate, nil)
		require.NoError(t, err)

		obj, err := m.objectManager.GetObject(newHandle)
		require.NoError(t, err)

		neverExtractable := obj.GetAttribute(CKA_NEVER_EXTRACTABLE)
		require.NotNil(t, neverExtractable, "CKA_NEVER_EXTRACTABLE must be present on unwrapped key")
		assert.Equal(t, byte(0), neverExtractable[0],
			"CKA_NEVER_EXTRACTABLE must be CK_FALSE for unwrapped keys")
	})

	t.Run("all three unwrap attributes present in round-trip", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		sessionHandle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		aesKey := createAESKey(t)
		originalKeyValue := createAESKey(t)

		wkTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
			NewBoolAttribute(CKA_WRAP, true),
			NewBoolAttribute(CKA_UNWRAP, true),
			NewAttribute(CKA_VALUE, aesKey),
		}
		wkHandle, rv := m.CreateObject(sessionHandle, wkTemplate)
		require.Equal(t, CKR_OK, rv)

		tkTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
			NewBoolAttribute(CKA_EXTRACTABLE, true),
			NewAttribute(CKA_VALUE, originalKeyValue),
		}
		tkHandle, rv := m.CreateObject(sessionHandle, tkTemplate)
		require.Equal(t, CKR_OK, rv)

		mechanism := NewMechanism(CKM_AES_GCM)
		wrappedKey, err := m.WrapKeyAuthenticated(sessionHandle, mechanism, wkHandle, tkHandle, nil)
		require.NoError(t, err)

		unwrapTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
			NewBoolAttribute(CKA_EXTRACTABLE, true),
		}
		newHandle, err := m.UnwrapKeyAuthenticated(sessionHandle, mechanism, wkHandle, wrappedKey, unwrapTemplate, nil)
		require.NoError(t, err)

		obj, err := m.objectManager.GetObject(newHandle)
		require.NoError(t, err)

		// Verify all three PKCS#11 unwrap attributes
		localAttr := obj.GetAttribute(CKA_LOCAL)
		require.NotNil(t, localAttr)
		assert.Equal(t, byte(0), localAttr[0], "CKA_LOCAL should be false")

		alwaysSensitive := obj.GetAttribute(CKA_ALWAYS_SENSITIVE)
		require.NotNil(t, alwaysSensitive)
		assert.Equal(t, byte(0), alwaysSensitive[0], "CKA_ALWAYS_SENSITIVE should be false")

		neverExtractable := obj.GetAttribute(CKA_NEVER_EXTRACTABLE)
		require.NotNil(t, neverExtractable)
		assert.Equal(t, byte(0), neverExtractable[0], "CKA_NEVER_EXTRACTABLE should be false")

		// Verify key material is correct
		unwrappedValue := obj.GetAttribute(CKA_VALUE)
		assert.True(t, bytes.Equal(originalKeyValue, unwrappedValue),
			"unwrapped key material should match original")
	})
}

// TestGetAESGCMParams tests the GetAESGCMParams accessor on Mechanism.
func TestGetAESGCMParams(t *testing.T) {

	t.Run("returns params when AESGCMParams is set", func(t *testing.T) {
		iv := make([]byte, GCMNonceSize)
		_, err := rand.Read(iv)
		require.NoError(t, err)

		gcmParams := NewAESGCMParamsWithAAD(iv, []byte("test-aad"), 128)
		mechanism := NewMechanismWithTypedParams(CKM_AES_GCM, gcmParams)

		params, ok := mechanism.GetAESGCMParams()
		assert.True(t, ok)
		require.NotNil(t, params)
		assert.Equal(t, iv, params.IV)
		assert.Equal(t, []byte("test-aad"), params.AAD)
		assert.Equal(t, uint32(128), params.TagBits)
	})

	t.Run("returns false when no typed parameter is set", func(t *testing.T) {
		mechanism := NewMechanism(CKM_AES_GCM)
		params, ok := mechanism.GetAESGCMParams()
		assert.False(t, ok)
		assert.Nil(t, params)
	})

	t.Run("returns false when typed parameter is wrong type", func(t *testing.T) {
		// Use HKDF params instead of GCM params
		hkdfParams := NewHKDFParams(CKM_SHA256, []byte("salt"), []byte("info"))
		mechanism := NewMechanismWithTypedParams(CKM_AES_GCM, hkdfParams)

		params, ok := mechanism.GetAESGCMParams()
		assert.False(t, ok)
		assert.Nil(t, params)
	})
}
