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

	// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
	// authenticates before exercising them.
	sessionHandle := loginAsNormalUser(t, m)

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

		// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
		// authenticates before exercising them.
		sessionHandle := loginAsNormalUser(t, m)

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
		unwrappedObj, err := m.objectManager.getObjectUnchecked(newHandle)
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

	t.Run("returns CKR_WRAPPING_KEY_TYPE_INCONSISTENT when CKA_WRAP is false", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
		// authenticates before exercising them.
		sessionHandle := loginAsNormalUser(t, m)

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
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
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
		assert.Equal(t, CKR_WRAPPING_KEY_TYPE_INCONSISTENT, pkcsErr.Code)
		assert.Nil(t, wrappedKey)
	})

	// CKR_KEY_UNEXTRACTABLE, not CKR_KEY_NOT_WRAPPABLE: PKCS#11 v3.2 §5.1
	// defines the former as the key's CKA_EXTRACTABLE being CK_FALSE and the
	// latter as the token being unable to wrap a key that IS extractable, and
	// C_WrapKey answers the former for this condition. The two wrap verbs must
	// not report different causes for one condition.
	t.Run("returns CKR_KEY_UNEXTRACTABLE when target is not extractable", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
		// authenticates before exercising them.
		sessionHandle := loginAsNormalUser(t, m)

		// Wrapping key
		wkTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
			NewBoolAttribute(CKA_WRAP, true),
			NewAttribute(CKA_VALUE, createAESKey(t)),
		}
		wkHandle, rv := m.CreateObject(sessionHandle, wkTemplate)
		require.Equal(t, CKR_OK, rv)

		// Non-extractable target key
		targetTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
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
		assert.Equal(t, CKR_KEY_UNEXTRACTABLE, pkcsErr.Code)
		assert.Nil(t, wrappedKey)
	})

	t.Run("returns CKR_WRAPPING_KEY_SIZE_RANGE for invalid AES key size", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
		// authenticates before exercising them.
		sessionHandle := loginAsNormalUser(t, m)

		// Wrapping key with invalid size (17 bytes)
		badKeyValue := make([]byte, 17)
		wkTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
			NewBoolAttribute(CKA_WRAP, true),
			NewAttribute(CKA_VALUE, badKeyValue),
		}
		wkHandle, rv := m.CreateObject(sessionHandle, wkTemplate)
		require.Equal(t, CKR_OK, rv)

		// Target key
		targetTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
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

		// Provision and authenticate first: C_InitToken refuses to run while
		// any session is open.
		rwSession := loginAsNormalUser(t, m)

		roSession, rv := m.OpenSession(0, CKF_SERIAL_SESSION)
		require.Equal(t, CKR_OK, rv)

		mechanism := NewMechanism(CKM_AES_GCM)

		// We need valid key handles, so create them via a R/W session first

		wkTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
			NewBoolAttribute(CKA_WRAP, true),
			NewAttribute(CKA_VALUE, createAESKey(t)),
		}
		wkHandle, rv := m.CreateObject(rwSession, wkTemplate)
		require.Equal(t, CKR_OK, rv)

		targetTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
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
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
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
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
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
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
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

		// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
		// authenticates before exercising them.
		sessionHandle := loginAsNormalUser(t, m)

		correctKey := createAESKey(t)
		wrongKey := createAESKey(t)

		// Wrapping key
		wkTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
			NewBoolAttribute(CKA_WRAP, true),
			NewBoolAttribute(CKA_UNWRAP, true),
			NewAttribute(CKA_VALUE, correctKey),
		}
		wkHandle, rv := m.CreateObject(sessionHandle, wkTemplate)
		require.Equal(t, CKR_OK, rv)

		// Wrong key
		wrongKeyTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
			NewBoolAttribute(CKA_UNWRAP, true),
			NewAttribute(CKA_VALUE, wrongKey),
		}
		wrongKeyHandle, rv := m.CreateObject(sessionHandle, wrongKeyTemplate)
		require.Equal(t, CKR_OK, rv)

		// Target
		targetTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
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
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
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

		// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
		// authenticates before exercising them.
		sessionHandle := loginAsNormalUser(t, m)

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

	t.Run("returns CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT when CKA_UNWRAP is false", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
		// authenticates before exercising them.
		sessionHandle := loginAsNormalUser(t, m)

		// Key without CKA_UNWRAP
		noUnwrapTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
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
		assert.Equal(t, CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT, pkcsErr.Code)
		assert.Equal(t, ObjectHandle(InvalidHandle), handle)
	})

	t.Run("returns CKR_SESSION_READ_ONLY for read-only session", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		// Provision and authenticate first: C_InitToken refuses to run while
		// any session is open.
		rwSession := loginAsNormalUser(t, m)

		roSession, rv := m.OpenSession(0, CKF_SERIAL_SESSION)
		require.Equal(t, CKR_OK, rv)

		// We need a valid key handle via a R/W session. It must be a TOKEN
		// object: a session object belongs to the session that created it and
		// is invisible to roSession (v3.0 §4.4), which would make this subtest
		// fail on CKR_UNWRAPPING_KEY_HANDLE_INVALID before ever reaching the
		// read-only-session rule it exists to check.
		keyTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
			NewBoolAttribute(CKA_TOKEN, true),
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

		// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
		// authenticates before exercising them.
		sessionHandle := loginAsNormalUser(t, m)

		// Bad key size (17 bytes)
		badKeyTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
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

			// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
			// authenticates before exercising them.
			sessionHandle := loginAsNormalUser(t, m)

			keyValue := make([]byte, size)
			_, err := rand.Read(keyValue)
			require.NoError(t, err)

			wkTemplate := []Attribute{
				NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
				NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
				NewBoolAttribute(CKA_WRAP, true),
				NewBoolAttribute(CKA_UNWRAP, true),
				NewAttribute(CKA_VALUE, keyValue),
			}
			wkHandle, rv := m.CreateObject(sessionHandle, wkTemplate)
			require.Equal(t, CKR_OK, rv)

			// The target matches the wrapping key's length. This test is about
			// the wrapping key's size being accepted, and a fixed 32-byte target
			// would instead have every case below AES-256 refused for a
			// different reason: a key may not be protected by a key of lesser
			// strength (NIST SP 800-57 Part 1 §5.6.2), which
			// requireWrappingKeyStrength enforces and
			// TestAuthWrapRefusesWeakerWrappingKey covers.
			targetValue := make([]byte, size)
			_, err = rand.Read(targetValue)
			require.NoError(t, err)

			targetTemplate := []Attribute{
				NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
				NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
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
				NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
				NewBoolAttribute(CKA_EXTRACTABLE, true),
			}
			newHandle, err := m.UnwrapKeyAuthenticated(sessionHandle, mechanism, wkHandle, wrappedKey, unwrapTemplate, aad)
			require.NoError(t, err)

			// Verify round-trip
			newObj, err := m.objectManager.getObjectUnchecked(newHandle)
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

	// The size query answers with the code the wrap itself would, so it moved
	// to CKR_KEY_UNEXTRACTABLE with WrapKeyAuthenticated.
	t.Run("returns CKR_KEY_UNEXTRACTABLE for non-extractable target", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
		// authenticates before exercising them.
		sessionHandle := loginAsNormalUser(t, m)

		// Create wrapping key
		wkTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
			NewBoolAttribute(CKA_WRAP, true),
			NewAttribute(CKA_VALUE, createAESKey(t)),
		}
		wkHandle, rv := m.CreateObject(sessionHandle, wkTemplate)
		require.Equal(t, CKR_OK, rv)

		// Create non-extractable target key
		targetTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
			NewBoolAttribute(CKA_EXTRACTABLE, false),
			NewAttribute(CKA_VALUE, createAESKey(t)),
		}
		targetHandle, rv := m.CreateObject(sessionHandle, targetTemplate)
		require.Equal(t, CKR_OK, rv)

		_, err := m.WrapKeyAuthenticatedSize(sessionHandle, NewMechanism(CKM_AES_GCM), wkHandle, targetHandle)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_KEY_UNEXTRACTABLE, pkcsErr.Code)
	})

	t.Run("returns CKR_WRAPPING_KEY_TYPE_INCONSISTENT without CKA_WRAP", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
		// authenticates before exercising them.
		sessionHandle := loginAsNormalUser(t, m)

		// Wrapping key without CKA_WRAP
		wkTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
			NewAttribute(CKA_VALUE, createAESKey(t)),
		}
		wkHandle, rv := m.CreateObject(sessionHandle, wkTemplate)
		require.Equal(t, CKR_OK, rv)

		targetHandle := createExtractableSecretKey(t, m, sessionHandle)

		_, err := m.WrapKeyAuthenticatedSize(sessionHandle, NewMechanism(CKM_AES_GCM), wkHandle, targetHandle)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_WRAPPING_KEY_TYPE_INCONSISTENT, pkcsErr.Code)
	})

	t.Run("returns CKR_WRAPPING_KEY_SIZE_RANGE for invalid key size", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
		// authenticates before exercising them.
		sessionHandle := loginAsNormalUser(t, m)

		// Wrapping key with invalid 15-byte AES key
		wkTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
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

		// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
		// authenticates before exercising them.
		sessionHandle := loginAsNormalUser(t, m)

		// Wrapping key with CKA_WRAP but no CKA_VALUE. C_CreateObject cannot
		// produce this state any more, but restore-from-storage and C_UnwrapKey
		// can, which is what this gate defends.
		wkHandle := createSecretKeyWithoutValue(t, m, sessionHandle,
			NewBoolAttribute(CKA_WRAP, true))

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

		// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
		// authenticates before exercising them.
		sessionHandle := loginAsNormalUser(t, m)

		wkHandle := createWrappingKey(t, m, sessionHandle)

		// Target key with CKA_EXTRACTABLE but no CKA_VALUE; see above.
		targetHandle := createSecretKeyWithoutValue(t, m, sessionHandle,
			NewBoolAttribute(CKA_EXTRACTABLE, true))

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

		// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
		// authenticates before exercising them.
		sessionHandle := loginAsNormalUser(t, m)

		// Wrapping key with CKA_WRAP but no CKA_VALUE. C_CreateObject cannot
		// produce this state any more, but restore-from-storage and C_UnwrapKey
		// can, which is what this gate defends.
		wkHandle := createSecretKeyWithoutValue(t, m, sessionHandle,
			NewBoolAttribute(CKA_WRAP, true))

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

		// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
		// authenticates before exercising them.
		sessionHandle := loginAsNormalUser(t, m)

		wkHandle := createWrappingKey(t, m, sessionHandle)

		// Target key with CKA_EXTRACTABLE but no CKA_VALUE; see above.
		targetHandle := createSecretKeyWithoutValue(t, m, sessionHandle,
			NewBoolAttribute(CKA_EXTRACTABLE, true))

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

		// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
		// authenticates before exercising them.
		sessionHandle := loginAsNormalUser(t, m)

		// Unwrapping key with CKA_UNWRAP but no CKA_VALUE; see the wrap side.
		ukHandle := createSecretKeyWithoutValue(t, m, sessionHandle,
			NewBoolAttribute(CKA_UNWRAP, true))

		template := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
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

		// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
		// authenticates before exercising them.
		sessionHandle := loginAsNormalUser(t, m)

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
		unwrappedObj, err := m.objectManager.getObjectUnchecked(newHandle)
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
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
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
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
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
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
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
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
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

		obj, err := m.objectManager.getObjectUnchecked(newHandle)
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

		obj, err := m.objectManager.getObjectUnchecked(newHandle)
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

		obj, err := m.objectManager.getObjectUnchecked(newHandle)
		require.NoError(t, err)

		neverExtractable := obj.GetAttribute(CKA_NEVER_EXTRACTABLE)
		require.NotNil(t, neverExtractable, "CKA_NEVER_EXTRACTABLE must be present on unwrapped key")
		assert.Equal(t, byte(0), neverExtractable[0],
			"CKA_NEVER_EXTRACTABLE must be CK_FALSE for unwrapped keys")
	})

	t.Run("all three unwrap attributes present in round-trip", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
		// authenticates before exercising them.
		sessionHandle := loginAsNormalUser(t, m)

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

		obj, err := m.objectManager.getObjectUnchecked(newHandle)
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

// TestWrapKeyAuthenticatedSizeReadOnlySession asserts the size query rejects a
// read-only session with the same code the wrap itself does.
//
// C_WrapKeyAuthenticated is a two-call function: an application asks for the
// output length with a NULL pWrappedKey, allocates that many bytes, and calls
// again. A size query that succeeds where the wrap can only return
// CKR_SESSION_READ_ONLY tells the application to allocate for a call that
// cannot run, which PKCS#11 v3.2 section 5.2 does not permit.
func TestWrapKeyAuthenticatedSizeReadOnlySession(t *testing.T) {
	t.Run("returns CKR_SESSION_READ_ONLY on a read-only session", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		rwSession := loginAsNormalUser(t, m)

		roSession, rv := m.OpenSession(0, CKF_SERIAL_SESSION)
		require.Equal(t, CKR_OK, rv)

		wkTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
			NewBoolAttribute(CKA_WRAP, true),
			NewAttribute(CKA_VALUE, createAESKey(t)),
		}
		wkHandle, rv := m.CreateObject(rwSession, wkTemplate)
		require.Equal(t, CKR_OK, rv)

		targetTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
			NewBoolAttribute(CKA_EXTRACTABLE, true),
			NewAttribute(CKA_VALUE, createAESKey(t)),
		}
		targetHandle, rv := m.CreateObject(rwSession, targetTemplate)
		require.Equal(t, CKR_OK, rv)

		mechanism := NewMechanism(CKM_AES_GCM)

		size, sizeErr := m.WrapKeyAuthenticatedSize(roSession, mechanism, wkHandle, targetHandle)
		require.Error(t, sizeErr, "the size query must not succeed where the wrap cannot run")
		var sizePkcsErr *PKCS11Error
		require.ErrorAs(t, sizeErr, &sizePkcsErr)
		assert.Equal(t, CKR_SESSION_READ_ONLY, sizePkcsErr.Code)
		assert.Zero(t, size)

		// The wrap the application would have made next returns the same code,
		// which is what makes the size query's answer the useful one.
		_, wrapErr := m.WrapKeyAuthenticated(roSession, mechanism, wkHandle, targetHandle, nil)
		require.Error(t, wrapErr)
		var wrapPkcsErr *PKCS11Error
		require.ErrorAs(t, wrapErr, &wrapPkcsErr)
		assert.Equal(t, CKR_SESSION_READ_ONLY, wrapPkcsErr.Code)
	})

	t.Run("returns the wrap output length on a read-write session", func(t *testing.T) {
		m, sessionHandle, wkHandle, targetHandle := createAuthWrapTestObjects(t)
		defer m.Finalize()

		mechanism := NewMechanism(CKM_AES_GCM)

		size, err := m.WrapKeyAuthenticatedSize(sessionHandle, mechanism, wkHandle, targetHandle)
		require.NoError(t, err, "the read-write check must not reject the session the wrap accepts")

		wrappedKey, err := m.WrapKeyAuthenticated(sessionHandle, mechanism, wkHandle, targetHandle, nil)
		require.NoError(t, err)
		assert.Equal(t, size, uint64(len(wrappedKey)))
	})
}

// authWrapPublicKeyPair creates a wrapping key and a target key that
// C_WrapKeyAuthenticated accepts, both CKA_PRIVATE=CK_FALSE and both carrying
// whatever extra attributes the caller names on top.
//
// The objects are deliberately public. A test that logs out to exercise the
// login gate needs objects that survive C_Logout (v3.2 §5.6.10 destroys private
// session objects) and that remain resolvable to a logged-out session, so that
// removing the gate makes the wrap SUCCEED rather than fail on a handle it can
// no longer see. A gate proved with private objects would pass just as well if
// it were deleted.
func authWrapPublicKeyPair(t *testing.T, m *Module, session SessionHandle, wrapExtra, targetExtra []Attribute) (ObjectHandle, ObjectHandle) {
	t.Helper()

	wrapTemplate := append([]Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewBoolAttribute(CKA_PRIVATE, false),
		NewBoolAttribute(CKA_WRAP, true),
		NewBoolAttribute(CKA_UNWRAP, true),
		NewAttribute(CKA_VALUE, createAESKey(t)),
	}, wrapExtra...)
	wrappingKey, rv := m.CreateObject(session, wrapTemplate)
	require.Equal(t, CKR_OK, rv)

	targetTemplate := append([]Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewBoolAttribute(CKA_PRIVATE, false),
		NewBoolAttribute(CKA_EXTRACTABLE, true),
		NewAttribute(CKA_VALUE, createAESKey(t)),
	}, targetExtra...)
	targetKey, rv := m.CreateObject(session, targetTemplate)
	require.Equal(t, CKR_OK, rv)

	return wrappingKey, targetKey
}

// soCreateTrustedWrappingKey provisions the token, creates a CKA_TRUSTED
// wrapping key as the Security Officer, and leaves the token ready for
// loginAsNormalUser to open a user session on.
//
// The SO detour is not incidental to the test, it is the subject: PKCS#11 v3.2
// Table 13 footnote 10 says CKA_TRUSTED "can only be set to CK_TRUE by the SO
// user", so a trusted wrapping key cannot come into being any other way. A
// fixture that minted one from a user session would be asserting the wrap gate
// against a key the token should never have issued.
//
// The key is public (CKA_PRIVATE=CK_FALSE) so that it survives the SO's
// C_Logout and stays resolvable to the user session that follows. That is also
// this token's default for a trusted object, for the reason applyTrustedPrivacyDefault
// records; it is stated explicitly here so the fixture does not depend on it.
func soCreateTrustedWrappingKey(t *testing.T, m *Module) ObjectHandle {
	t.Helper()

	require.Equal(t, CKR_OK, m.InitToken(0, []byte("so-pin-1234"), "Test Token"))

	soSession, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
	require.Equal(t, CKR_OK, rv)

	require.Equal(t, CKR_OK, m.Login(soSession, CKU_SO, []byte("so-pin-1234")))
	require.Equal(t, CKR_OK, m.InitPIN(soSession, []byte("user-pin-1234")))

	wrappingKey, rv := m.CreateObject(soSession, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		// A token object, not a session object: the SO's session ends here, and
		// v3.2 §4.1.3 destroys a session's objects with it. A trust anchor that
		// vanished when its provisioning session closed would be of no use to
		// the application anyway.
		NewBoolAttribute(CKA_TOKEN, true),
		NewBoolAttribute(CKA_PRIVATE, false),
		NewBoolAttribute(CKA_WRAP, true),
		NewBoolAttribute(CKA_UNWRAP, true),
		NewBoolAttribute(CKA_TRUSTED, true),
		NewAttribute(CKA_VALUE, createAESKey(t)),
	})
	require.Equal(t, CKR_OK, rv, "the SO must be able to create the trusted wrapping key")

	require.Equal(t, CKR_OK, m.Logout(soSession))
	require.Equal(t, CKR_OK, m.CloseSession(soSession))

	return wrappingKey
}

// authWrapPublicTargetKey creates the wrappable target half of the pair that
// authWrapPublicKeyPair would otherwise supply, for tests whose wrapping key
// had to be created separately by the SO.
func authWrapPublicTargetKey(t *testing.T, m *Module, session SessionHandle, targetExtra []Attribute) ObjectHandle {
	t.Helper()

	targetKey, rv := m.CreateObject(session, append([]Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewBoolAttribute(CKA_PRIVATE, false),
		NewBoolAttribute(CKA_EXTRACTABLE, true),
		NewAttribute(CKA_VALUE, createAESKey(t)),
	}, targetExtra...))
	require.Equal(t, CKR_OK, rv)

	return targetKey
}

// TestAuthenticatedWrapRequiresLogin proves the token's CKF_LOGIN_REQUIRED
// policy reaches C_WrapKeyAuthenticated, its size query and
// C_UnwrapKeyAuthenticated.
//
// The authenticated forms are an export path for key material exactly as
// C_WrapKey is, so the policy cannot depend on which verb the application
// names: a session that C_WrapKey refuses with CKR_USER_NOT_LOGGED_IN must not
// reach the same bytes through C_WrapKeyAuthenticated. Each subtest runs the
// call once while logged in, so a gate that refused unconditionally would fail
// here rather than pass.
func TestAuthenticatedWrapRequiresLogin(t *testing.T) {
	mechanism := NewMechanism(CKM_AES_GCM)

	t.Run("WrapKeyAuthenticated refuses a logged-out session", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		session := loginAsNormalUser(t, m)
		wrappingKey, targetKey := authWrapPublicKeyPair(t, m, session, nil, nil)

		wrapped, err := m.WrapKeyAuthenticated(session, mechanism, wrappingKey, targetKey, nil)
		require.NoError(t, err, "the wrap must succeed while the session is authenticated")
		require.NotEmpty(t, wrapped)

		require.Equal(t, CKR_OK, m.Logout(session))

		wrapped, err = m.WrapKeyAuthenticated(session, mechanism, wrappingKey, targetKey, nil)
		require.Error(t, err, "a logged-out session must not receive wrapped key material")
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_USER_NOT_LOGGED_IN, pkcsErr.Code)
		assert.Nil(t, wrapped)

		// The unauthenticated form answers the same code for the same objects,
		// which is the property the gate exists to preserve.
		_, rv := m.WrapKey(session, mechanism, wrappingKey, targetKey)
		assert.Equal(t, CKR_USER_NOT_LOGGED_IN, rv,
			"C_WrapKey and C_WrapKeyAuthenticated must answer alike for one session state")
	})

	t.Run("WrapKeyAuthenticatedSize refuses a logged-out session", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		session := loginAsNormalUser(t, m)
		wrappingKey, targetKey := authWrapPublicKeyPair(t, m, session, nil, nil)

		size, err := m.WrapKeyAuthenticatedSize(session, mechanism, wrappingKey, targetKey)
		require.NoError(t, err, "the size query must answer while the session is authenticated")
		require.NotZero(t, size)

		require.Equal(t, CKR_OK, m.Logout(session))

		size, err = m.WrapKeyAuthenticatedSize(session, mechanism, wrappingKey, targetKey)
		require.Error(t, err, "the size query is a wrap the module declines to perform, so it carries the same policy")
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_USER_NOT_LOGGED_IN, pkcsErr.Code)
		assert.Zero(t, size)
	})

	t.Run("UnwrapKeyAuthenticated refuses a logged-out session", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		session := loginAsNormalUser(t, m)
		wrappingKey, targetKey := authWrapPublicKeyPair(t, m, session, nil, nil)

		wrapped, err := m.WrapKeyAuthenticated(session, mechanism, wrappingKey, targetKey, nil)
		require.NoError(t, err)

		unwrapTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
			NewBoolAttribute(CKA_PRIVATE, false),
			NewBoolAttribute(CKA_EXTRACTABLE, true),
		}
		handle, err := m.UnwrapKeyAuthenticated(session, mechanism, wrappingKey, wrapped, unwrapTemplate, nil)
		require.NoError(t, err, "the unwrap must succeed while the session is authenticated")
		require.NotEqual(t, ObjectHandle(InvalidHandle), handle)

		require.Equal(t, CKR_OK, m.Logout(session))

		handle, err = m.UnwrapKeyAuthenticated(session, mechanism, wrappingKey, wrapped, unwrapTemplate, nil)
		require.Error(t, err, "a logged-out session must not import key material it supplied")
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_USER_NOT_LOGGED_IN, pkcsErr.Code)
		assert.Equal(t, ObjectHandle(InvalidHandle), handle)

		_, rv := m.UnwrapKey(session, mechanism, wrappingKey, wrapped, unwrapTemplate)
		assert.Equal(t, CKR_USER_NOT_LOGGED_IN, rv,
			"C_UnwrapKey and C_UnwrapKeyAuthenticated must answer alike for one session state")
	})
}

// TestAuthenticatedWrapHonoursWrapWithTrusted proves CKA_WRAP_WITH_TRUSTED
// reaches the authenticated wrap.
//
// PKCS#11 v3.2 §4.9 makes the attribute the only way to name the small set of
// wrapping keys a sensitive key may be exported under: a key carrying it may be
// wrapped solely by a key the token marked CKA_TRUSTED. A wrap verb that skips
// the check accepts every key on the token that carries CKA_WRAP, which is the
// whole population the attribute was written to exclude.
func TestAuthenticatedWrapHonoursWrapWithTrusted(t *testing.T) {
	mechanism := NewMechanism(CKM_AES_GCM)
	wrapWithTrusted := []Attribute{NewBoolAttribute(CKA_WRAP_WITH_TRUSTED, true)}

	t.Run("refuses an untrusted wrapping key", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		session := loginAsNormalUser(t, m)
		wrappingKey, targetKey := authWrapPublicKeyPair(t, m, session, nil, wrapWithTrusted)

		wrapped, err := m.WrapKeyAuthenticated(session, mechanism, wrappingKey, targetKey, nil)
		require.Error(t, err, "a CKA_WRAP_WITH_TRUSTED key must not leave under a wrapping key the token never trusted")
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_KEY_NOT_WRAPPABLE, pkcsErr.Code)
		assert.Nil(t, wrapped)

		size, err := m.WrapKeyAuthenticatedSize(session, mechanism, wrappingKey, targetKey)
		require.Error(t, err, "the size query must not size a buffer for a wrap that cannot run")
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_KEY_NOT_WRAPPABLE, pkcsErr.Code)
		assert.Zero(t, size)

		_, rv := m.WrapKey(session, mechanism, wrappingKey, targetKey)
		assert.Equal(t, CKR_KEY_NOT_WRAPPABLE, rv,
			"C_WrapKey and C_WrapKeyAuthenticated must answer alike for one pair of keys")
	})

	t.Run("accepts a CKA_TRUSTED wrapping key", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		// The trusted wrapping key is created by the SO, the only role that may
		// set CKA_TRUSTED (v3.2 Table 13 footnote 10); the target key and the
		// wrap itself then run from an ordinary user session.
		wrappingKey := soCreateTrustedWrappingKey(t, m)

		session := loginAsNormalUser(t, m)
		targetKey := authWrapPublicTargetKey(t, m, session, wrapWithTrusted)

		size, err := m.WrapKeyAuthenticatedSize(session, mechanism, wrappingKey, targetKey)
		require.NoError(t, err, "the gate must admit the wrapping key the token trusts")

		wrapped, err := m.WrapKeyAuthenticated(session, mechanism, wrappingKey, targetKey, nil)
		require.NoError(t, err, "the gate must admit the wrapping key the token trusts")
		assert.Equal(t, size, uint64(len(wrapped)))
	})
}

// TestUnwrapKeyAuthenticatedAgreesWithUnwrapKeyOnAlwaysAuthenticate pins what
// CKA_ALWAYS_AUTHENTICATE means for the two unwrap verbs, and that they mean the
// same thing by it.
//
// It does not gate them. PKCS#11 v3.2 §4.10 defines the attribute's "use" as "a
// cryptographic operation such as sign or decrypt", and gives re-authentication
// exactly one form: "calling C_Login with userType set to CKU_CONTEXT_SPECIFIC
// immediately after a cryptographic operation using the key has been initiated
// (e.g. after C_SignInit)", after which "the active key" is authenticated.
// C_UnwrapKey and C_UnwrapKeyAuthenticated have no Init phase, so there is no
// call an application could place between naming the key and using it.
//
// An operation of the same category CAN nevertheless be active on the key, if
// the application initiated one with another verb, and that is precisely why
// neither unwrap consults the attribute at all any more: the only grant either
// could ever have found belonged to that other operation. See
// TestKeyManagementVerbsDoNotConsumeADecryptContextAuthentication.
//
// This test used to assert the opposite, and passed only through the defect that
// made the grant key-blind: it initiated a decryption on a throwaway key that
// required no re-authentication purely so C_Login had "a category to grant for",
// and that grant then satisfied the unwrapping key's requirement. Once the grant
// is bound to the key of the operation it follows, that route is gone, and what
// is left for an unwrap is a gate no conforming application can pass — one a key
// marked CKA_UNWRAP without CKA_DECRYPT could never pass even in principle.
//
// The two verbs answering alike is the part that still matters: the authenticated
// form must not be the weaker or the stronger of the two.
func TestUnwrapKeyAuthenticatedAgreesWithUnwrapKeyOnAlwaysAuthenticate(t *testing.T) {
	mechanism := NewMechanism(CKM_AES_GCM)

	newFixture := func(t *testing.T) (*Module, SessionHandle, ObjectHandle, []byte, []Attribute) {
		t.Helper()

		m := initializeTestModule(t)
		session := loginAsNormalUser(t, m)

		// The wrapping key is created without CKA_ALWAYS_AUTHENTICATE so the
		// wrap that produces the blob is unencumbered, and the attribute is set
		// afterwards so it governs only the unwrap under test.
		wrappingKey, targetKey := authWrapPublicKeyPair(t, m, session, nil, nil)
		wrapped, err := m.WrapKeyAuthenticated(session, mechanism, wrappingKey, targetKey, nil)
		require.NoError(t, err)

		require.Equal(t, CKR_OK, m.SetAttributeValue(session, wrappingKey,
			[]Attribute{NewBoolAttribute(CKA_ALWAYS_AUTHENTICATE, true)}))

		template := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
			NewBoolAttribute(CKA_PRIVATE, false),
			NewBoolAttribute(CKA_EXTRACTABLE, true),
		}
		return m, session, wrappingKey, wrapped, template
	}

	t.Run("both verbs unwrap with the session login alone", func(t *testing.T) {
		m, session, wrappingKey, wrapped, template := newFixture(t)
		defer m.Finalize()

		handle, err := m.UnwrapKeyAuthenticated(session, mechanism, wrappingKey, wrapped, template, nil)
		require.NoError(t, err,
			"an unwrap has no Init phase, so §4.10's re-authentication cannot be placed before it; "+
				"refusing it would deny a legal use of the key outright")
		assert.NotEqual(t, ObjectHandle(InvalidHandle), handle)

		// C_UnwrapKey unwraps inside the backend, and this fixture's unwrapping
		// key was imported with C_CreateObject. That used to leave the key
		// naming no backend key, so the call could not reach one and the
		// assertion here could only say which refusal it was NOT. Since
		// C_CreateObject imports a secret key's material, the key names a real
		// backend key and the unwrap simply succeeds -- see
		// TestImportedKEKIsUsableForWrapAndUnwrap.
		//
		// CKR_OK is the stronger form of what this test has always measured:
		// the attribute must not turn a legal unwrap into
		// CKR_USER_NOT_LOGGED_IN. The weaker assertion is kept alongside it
		// because it names the specific regression, and it would still fail if
		// the gate came back while some unrelated refusal masked the success.
		_, rv := m.UnwrapKey(session, mechanism, wrappingKey, wrapped, template)
		assert.NotEqual(t, CKR_USER_NOT_LOGGED_IN, rv,
			"C_UnwrapKey and C_UnwrapKeyAuthenticated must answer alike about CKA_ALWAYS_AUTHENTICATE")
		assert.Equal(t, CKR_OK, rv,
			"an imported unwrapping key names a backend key, so nothing remains to refuse")
	})

	t.Run("a context-specific login cannot be obtained for the unwrapping key", func(t *testing.T) {
		m, session, wrappingKey, _, _ := newFixture(t)
		defer m.Finalize()

		// This is the other half of the reason the gate is gone: there is no
		// state in which an application could re-authenticate for an unwrap.
		// The wrapping key carries CKA_ALWAYS_AUTHENTICATE and no operation can
		// be initiated with it, so C_Login has no active key to authenticate.
		assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED,
			m.Login(session, CKU_CONTEXT_SPECIFIC, []byte("user-pin-1234")))
		assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED,
			m.LoginUser(session, CKU_CONTEXT_SPECIFIC, []byte("user-pin-1234"), "context"))

		// The attribute really is set on the key under test; without this the
		// subtest above would pass on a key that never required anything.
		attrs, rv := m.GetAttributeValue(session, wrappingKey, []Attribute{{Type: CKA_ALWAYS_AUTHENTICATE}})
		require.Equal(t, CKR_OK, rv)
		require.Len(t, attrs, 1)
		assert.Equal(t, byte(1), attrs[0].Value[0])
	})
}

// TestUnwrapKeyAuthenticatedDefaultsToExtractable proves the unwrap default
// PKCS#11 v3.2 §5.18.4 fixes for C_UnwrapKey -- "the CKA_EXTRACTABLE attribute
// is by default set to CK_TRUE" -- also holds for the authenticated form.
//
// C_UnwrapKey states the default explicitly in module.go; C_UnwrapKeyAuthenticated
// reaches it through the class defaults the object manager applies underneath
// CreateDerivedObject. The two arrive by different routes, so this asserts on
// the outcome: a key unwrapped without CKA_EXTRACTABLE in its template must be
// extractable, or its value can never be read back and it can never be
// re-wrapped.
func TestUnwrapKeyAuthenticatedDefaultsToExtractable(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()

	session := loginAsNormalUser(t, m)
	mechanism := NewMechanism(CKM_AES_GCM)
	wrappingKey, targetKey := authWrapPublicKeyPair(t, m, session, nil, nil)

	wrapped, err := m.WrapKeyAuthenticated(session, mechanism, wrappingKey, targetKey, nil)
	require.NoError(t, err)

	// The template names no CKA_EXTRACTABLE, which is the whole point.
	handle, err := m.UnwrapKeyAuthenticated(session, mechanism, wrappingKey, wrapped, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewBoolAttribute(CKA_PRIVATE, false),
	}, nil)
	require.NoError(t, err)

	unwrapped, err := m.objectManager.getObjectUnchecked(handle)
	require.NoError(t, err)
	assert.True(t, boolAttributeIsTrue(unwrapped.GetAttribute(CKA_EXTRACTABLE)),
		"an unwrapped key with no CKA_EXTRACTABLE in its template must default to CK_TRUE (v3.2 §5.18.4)")

	// A key that says it is extractable must actually be re-wrappable, which is
	// the bad-input half: an attribute that reads CK_TRUE while the wrap path
	// refuses it would be a default in name only.
	_, err = m.WrapKeyAuthenticated(session, mechanism, wrappingKey, handle, nil)
	require.NoError(t, err, "the unwrapped key reports CKA_EXTRACTABLE=CK_TRUE but cannot be wrapped")
}
