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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createKEMPublicKey creates a public key object with CKA_ENCAPSULATE and CKA_VALUE
// suitable for testing EncapsulateKey.
func createKEMPublicKey(t *testing.T, m *Module, sessionHandle SessionHandle) ObjectHandle {
	t.Helper()
	template := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_PUBLIC_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_ML_KEM)),
		NewStringAttribute(CKA_LABEL, "test-kem-public-key"),
		NewBoolAttribute(CKA_ENCAPSULATE, true),
		NewBoolAttribute(CKA_TOKEN, false),
		NewAttribute(CKA_VALUE, make([]byte, 32)), // mock public key material
	}
	handle, rv := m.CreateObject(sessionHandle, template)
	require.Equal(t, CKR_OK, rv)
	return handle
}

// createKEMPrivateKey creates a private key object with CKA_DECAPSULATE and CKA_VALUE
// suitable for testing DecapsulateKey.
func createKEMPrivateKey(t *testing.T, m *Module, sessionHandle SessionHandle) ObjectHandle {
	t.Helper()
	template := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_PRIVATE_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_ML_KEM)),
		NewStringAttribute(CKA_LABEL, "test-kem-private-key"),
		NewBoolAttribute(CKA_DECAPSULATE, true),
		NewBoolAttribute(CKA_TOKEN, false),
		NewAttribute(CKA_VALUE, make([]byte, 32)), // mock private key material
	}
	handle, rv := m.CreateObject(sessionHandle, template)
	require.Equal(t, CKR_OK, rv)
	return handle
}

// findAttr returns the first attribute matching the given type from a slice, or nil.
func findAttr(attrs []Attribute, attrType AttributeType) *Attribute {
	for i := range attrs {
		if attrs[i].Type == attrType {
			return &attrs[i]
		}
	}
	return nil
}

// TestEncapsulateKey tests KEM encapsulation validation and dispatch.
func TestEncapsulateKey(t *testing.T) {

	t.Run("returns CKR_MECHANISM_INVALID without quantum build tag", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		sessionHandle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		keyHandle := createKEMPublicKey(t, m, sessionHandle)
		mechanism := NewMechanism(CKM_ML_KEM)
		template := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		}

		handle, ciphertext, err := m.EncapsulateKey(sessionHandle, mechanism, keyHandle, template)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_MECHANISM_INVALID, pkcsErr.Code)
		assert.Equal(t, ObjectHandle(InvalidHandle), handle)
		assert.Nil(t, ciphertext)
	})

	t.Run("returns CKR_ARGUMENTS_BAD with nil mechanism", func(t *testing.T) {
		m, sessionHandle, keyHandle := createTestModuleWithKey(t)
		defer m.Finalize()

		handle, ciphertext, err := m.EncapsulateKey(sessionHandle, nil, keyHandle, nil)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_ARGUMENTS_BAD, pkcsErr.Code)
		assert.Equal(t, ObjectHandle(InvalidHandle), handle)
		assert.Nil(t, ciphertext)
	})

	t.Run("returns CKR_KEY_HANDLE_INVALID with invalid key handle", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		sessionHandle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		mechanism := NewMechanism(CKM_ML_KEM)
		handle, ciphertext, err := m.EncapsulateKey(sessionHandle, mechanism, ObjectHandle(99999), nil)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_KEY_HANDLE_INVALID, pkcsErr.Code)
		assert.Equal(t, ObjectHandle(InvalidHandle), handle)
		assert.Nil(t, ciphertext)
	})

	t.Run("returns CKR_KEY_FUNCTION_NOT_PERMITTED without CKA_ENCAPSULATE", func(t *testing.T) {
		m, sessionHandle, keyHandle := createTestModuleWithKey(t)
		defer m.Finalize()

		mechanism := NewMechanism(CKM_ML_KEM)
		handle, ciphertext, err := m.EncapsulateKey(sessionHandle, mechanism, keyHandle, nil)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_KEY_FUNCTION_NOT_PERMITTED, pkcsErr.Code)
		assert.Equal(t, ObjectHandle(InvalidHandle), handle)
		assert.Nil(t, ciphertext)
	})

	t.Run("returns CKR_KEY_HANDLE_INVALID when key has no CKA_VALUE", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		sessionHandle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		// Create a public key with CKA_ENCAPSULATE but no CKA_VALUE
		template := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_PUBLIC_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_ML_KEM)),
			NewBoolAttribute(CKA_ENCAPSULATE, true),
			NewBoolAttribute(CKA_TOKEN, false),
		}
		keyHandle, rv := m.CreateObject(sessionHandle, template)
		require.Equal(t, CKR_OK, rv)

		mechanism := NewMechanism(CKM_ML_KEM)
		handle, ciphertext, err := m.EncapsulateKey(sessionHandle, mechanism, keyHandle, nil)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_KEY_HANDLE_INVALID, pkcsErr.Code)
		assert.Equal(t, ObjectHandle(InvalidHandle), handle)
		assert.Nil(t, ciphertext)
	})

	t.Run("returns CKR_MECHANISM_INVALID for non-encapsulate mechanism", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		sessionHandle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		keyHandle := createKEMPublicKey(t, m, sessionHandle)
		mechanism := NewMechanism(CKM_AES_CBC) // not an encapsulate mechanism
		handle, ciphertext, err := m.EncapsulateKey(sessionHandle, mechanism, keyHandle, nil)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_MECHANISM_INVALID, pkcsErr.Code)
		assert.Equal(t, ObjectHandle(InvalidHandle), handle)
		assert.Nil(t, ciphertext)
	})

	t.Run("returns CKR_KEY_HANDLE_INVALID when key is not a public key", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		sessionHandle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		// Create a secret key -- EncapsulateKey requires a public key
		template := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
			NewBoolAttribute(CKA_ENCAPSULATE, true),
			NewBoolAttribute(CKA_TOKEN, false),
			NewAttribute(CKA_VALUE, make([]byte, 32)),
		}
		secretKeyHandle, rv := m.CreateObject(sessionHandle, template)
		require.Equal(t, CKR_OK, rv)

		mechanism := NewMechanism(CKM_ML_KEM)
		handle, ciphertext, err := m.EncapsulateKey(sessionHandle, mechanism, secretKeyHandle, nil)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_KEY_HANDLE_INVALID, pkcsErr.Code)
		assert.Equal(t, ObjectHandle(InvalidHandle), handle)
		assert.Nil(t, ciphertext)
	})
}

// TestEncapsulateKeyNotInitialized tests that EncapsulateKey rejects calls
// when the module has not been initialized.
func TestEncapsulateKeyNotInitialized(t *testing.T) {

	t.Run("returns CKR_CRYPTOKI_NOT_INITIALIZED", func(t *testing.T) {
		m := createTestModule(t)

		mechanism := NewMechanism(CKM_ML_KEM)
		handle, ciphertext, err := m.EncapsulateKey(SessionHandle(1), mechanism, ObjectHandle(1), nil)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, pkcsErr.Code)
		assert.Equal(t, ObjectHandle(InvalidHandle), handle)
		assert.Nil(t, ciphertext)
	})
}

// TestEncapsulateKeyInvalidSession tests that EncapsulateKey rejects calls
// with an invalid session handle.
func TestEncapsulateKeyInvalidSession(t *testing.T) {

	t.Run("returns CKR_SESSION_HANDLE_INVALID", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		mechanism := NewMechanism(CKM_ML_KEM)
		handle, ciphertext, err := m.EncapsulateKey(SessionHandle(99999), mechanism, ObjectHandle(1), nil)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_SESSION_HANDLE_INVALID, pkcsErr.Code)
		assert.Equal(t, ObjectHandle(InvalidHandle), handle)
		assert.Nil(t, ciphertext)
	})
}

// TestDecapsulateKey tests KEM decapsulation validation and dispatch.
func TestDecapsulateKey(t *testing.T) {

	t.Run("returns CKR_MECHANISM_INVALID without quantum build tag", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		sessionHandle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		keyHandle := createKEMPrivateKey(t, m, sessionHandle)
		mechanism := NewMechanism(CKM_ML_KEM)
		template := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		}
		ciphertext := []byte("mock-ciphertext-for-kem")

		handle, err := m.DecapsulateKey(sessionHandle, mechanism, keyHandle, template, ciphertext)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_MECHANISM_INVALID, pkcsErr.Code)
		assert.Equal(t, ObjectHandle(InvalidHandle), handle)
	})

	t.Run("returns CKR_ARGUMENTS_BAD with nil mechanism", func(t *testing.T) {
		m, sessionHandle, keyHandle := createTestModuleWithKey(t)
		defer m.Finalize()

		handle, err := m.DecapsulateKey(sessionHandle, nil, keyHandle, nil, []byte("ct"))
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_ARGUMENTS_BAD, pkcsErr.Code)
		assert.Equal(t, ObjectHandle(InvalidHandle), handle)
	})

	t.Run("returns CKR_UNWRAPPING_KEY_HANDLE_INVALID with invalid key handle", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		sessionHandle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		mechanism := NewMechanism(CKM_ML_KEM)
		handle, err := m.DecapsulateKey(sessionHandle, mechanism, ObjectHandle(99999), nil, []byte("ct"))
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_UNWRAPPING_KEY_HANDLE_INVALID, pkcsErr.Code)
		assert.Equal(t, ObjectHandle(InvalidHandle), handle)
	})

	t.Run("returns CKR_ARGUMENTS_BAD with empty ciphertext", func(t *testing.T) {
		m, sessionHandle, keyHandle := createTestModuleWithKey(t)
		defer m.Finalize()

		mechanism := NewMechanism(CKM_ML_KEM)
		handle, err := m.DecapsulateKey(sessionHandle, mechanism, keyHandle, nil, []byte{})
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_ARGUMENTS_BAD, pkcsErr.Code)
		assert.Equal(t, ObjectHandle(InvalidHandle), handle)
	})

	t.Run("returns CKR_ARGUMENTS_BAD with nil ciphertext", func(t *testing.T) {
		m, sessionHandle, keyHandle := createTestModuleWithKey(t)
		defer m.Finalize()

		mechanism := NewMechanism(CKM_ML_KEM)
		handle, err := m.DecapsulateKey(sessionHandle, mechanism, keyHandle, nil, nil)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_ARGUMENTS_BAD, pkcsErr.Code)
		assert.Equal(t, ObjectHandle(InvalidHandle), handle)
	})

	t.Run("returns CKR_UNWRAPPING_KEY_HANDLE_INVALID when key is public not private", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		sessionHandle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		// Create a public key -- DecapsulateKey requires a private key
		pubKeyHandle := createKEMPublicKey(t, m, sessionHandle)
		mechanism := NewMechanism(CKM_ML_KEM)
		handle, err := m.DecapsulateKey(sessionHandle, mechanism, pubKeyHandle, nil, []byte("ct"))
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_UNWRAPPING_KEY_HANDLE_INVALID, pkcsErr.Code)
		assert.Equal(t, ObjectHandle(InvalidHandle), handle)
	})

	t.Run("returns CKR_KEY_FUNCTION_NOT_PERMITTED without CKA_DECAPSULATE", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		sessionHandle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		// Private key without CKA_DECAPSULATE
		template := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_PRIVATE_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_ML_KEM)),
			NewBoolAttribute(CKA_TOKEN, false),
			NewAttribute(CKA_VALUE, make([]byte, 32)),
		}
		keyHandle, rv := m.CreateObject(sessionHandle, template)
		require.Equal(t, CKR_OK, rv)

		mechanism := NewMechanism(CKM_ML_KEM)
		handle, err := m.DecapsulateKey(sessionHandle, mechanism, keyHandle, nil, []byte("ct"))
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_KEY_FUNCTION_NOT_PERMITTED, pkcsErr.Code)
		assert.Equal(t, ObjectHandle(InvalidHandle), handle)
	})

	t.Run("returns CKR_MECHANISM_INVALID for non-decapsulate mechanism", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		sessionHandle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		keyHandle := createKEMPrivateKey(t, m, sessionHandle)
		mechanism := NewMechanism(CKM_AES_CBC) // not a decapsulate mechanism
		handle, err := m.DecapsulateKey(sessionHandle, mechanism, keyHandle, nil, []byte("ct"))
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_MECHANISM_INVALID, pkcsErr.Code)
		assert.Equal(t, ObjectHandle(InvalidHandle), handle)
	})

	t.Run("returns CKR_UNWRAPPING_KEY_HANDLE_INVALID when private key has no CKA_VALUE", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		sessionHandle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		// Private key with CKA_DECAPSULATE but no CKA_VALUE
		template := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_PRIVATE_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_ML_KEM)),
			NewBoolAttribute(CKA_DECAPSULATE, true),
			NewBoolAttribute(CKA_TOKEN, false),
		}
		keyHandle, rv := m.CreateObject(sessionHandle, template)
		require.Equal(t, CKR_OK, rv)

		mechanism := NewMechanism(CKM_ML_KEM)
		handle, err := m.DecapsulateKey(sessionHandle, mechanism, keyHandle, nil, []byte("ciphertext"))
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_UNWRAPPING_KEY_HANDLE_INVALID, pkcsErr.Code)
		assert.Equal(t, ObjectHandle(InvalidHandle), handle)
	})
}

// TestDecapsulateKeyNotInitialized tests that DecapsulateKey rejects calls
// when the module has not been initialized.
func TestDecapsulateKeyNotInitialized(t *testing.T) {

	t.Run("returns CKR_CRYPTOKI_NOT_INITIALIZED", func(t *testing.T) {
		m := createTestModule(t)

		mechanism := NewMechanism(CKM_ML_KEM)
		handle, err := m.DecapsulateKey(SessionHandle(1), mechanism, ObjectHandle(1), nil, []byte("ct"))
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, pkcsErr.Code)
		assert.Equal(t, ObjectHandle(InvalidHandle), handle)
	})
}

// TestDecapsulateKeyInvalidSession tests that DecapsulateKey rejects calls
// with an invalid session handle.
func TestDecapsulateKeyInvalidSession(t *testing.T) {

	t.Run("returns CKR_SESSION_HANDLE_INVALID", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		mechanism := NewMechanism(CKM_ML_KEM)
		handle, err := m.DecapsulateKey(SessionHandle(99999), mechanism, ObjectHandle(1), nil, []byte("ct"))
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_SESSION_HANDLE_INVALID, pkcsErr.Code)
		assert.Equal(t, ObjectHandle(InvalidHandle), handle)
	})
}

// TestBuildSecretKeyTemplate tests the helper function for building secret key templates.
func TestBuildSecretKeyTemplate(t *testing.T) {

	t.Run("builds template with defaults when empty", func(t *testing.T) {
		sharedSecret := []byte("shared-secret-data")
		attrs := buildSecretKeyTemplate(nil, sharedSecret, CKM_ML_KEM, true)

		// Should have CKA_CLASS, CKA_KEY_TYPE, CKA_VALUE, CKA_VALUE_LEN,
		// CKA_EXTRACTABLE, CKA_SENSITIVE, CKA_LOCAL, CKA_ALWAYS_SENSITIVE,
		// CKA_NEVER_EXTRACTABLE, CKA_KEY_GEN_MECHANISM
		assert.GreaterOrEqual(t, len(attrs), 10)

		// Verify CKA_VALUE contains the shared secret
		valueAttr := findAttr(attrs, CKA_VALUE)
		require.NotNil(t, valueAttr, "CKA_VALUE must be present")
		assert.Equal(t, sharedSecret, valueAttr.Value)
	})

	t.Run("overrides caller CKA_VALUE with shared secret", func(t *testing.T) {
		sharedSecret := []byte("actual-secret")
		callerTemplate := []Attribute{
			NewAttribute(CKA_VALUE, []byte("should-be-ignored")),
		}
		attrs := buildSecretKeyTemplate(callerTemplate, sharedSecret, CKM_ML_KEM, true)

		valueAttr := findAttr(attrs, CKA_VALUE)
		require.NotNil(t, valueAttr)
		assert.Equal(t, sharedSecret, valueAttr.Value)
	})

	t.Run("preserves caller-provided CKA_VALUE_LEN", func(t *testing.T) {
		callerTemplate := []Attribute{
			{Type: CKA_VALUE_LEN, Value: []byte{0x10, 0x00, 0x00, 0x00}}, // 16 in little-endian
		}
		attrs := buildSecretKeyTemplate(callerTemplate, []byte("secret"), CKM_ML_KEM, true)

		valueLenCount := 0
		for _, attr := range attrs {
			if attr.Type == CKA_VALUE_LEN {
				valueLenCount++
				assert.Equal(t, []byte{0x10, 0x00, 0x00, 0x00}, attr.Value)
			}
		}
		assert.Equal(t, 1, valueLenCount, "should not duplicate CKA_VALUE_LEN")
	})

	t.Run("preserves caller-provided CKA_CLASS and CKA_KEY_TYPE", func(t *testing.T) {
		callerTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		}
		attrs := buildSecretKeyTemplate(callerTemplate, []byte("secret"), CKM_ML_KEM, true)

		classCount := 0
		keyTypeCount := 0
		for _, attr := range attrs {
			if attr.Type == CKA_CLASS {
				classCount++
			}
			if attr.Type == CKA_KEY_TYPE {
				keyTypeCount++
			}
		}
		assert.Equal(t, 1, classCount, "should not duplicate CKA_CLASS")
		assert.Equal(t, 1, keyTypeCount, "should not duplicate CKA_KEY_TYPE")
	})

	t.Run("sets CKA_LOCAL true for encapsulation", func(t *testing.T) {
		attrs := buildSecretKeyTemplate(nil, []byte("secret"), CKM_ML_KEM, true)

		localAttr := findAttr(attrs, CKA_LOCAL)
		require.NotNil(t, localAttr, "CKA_LOCAL must be present")
		boolVal, err := localAttr.GetBool()
		require.NoError(t, err)
		assert.True(t, boolVal, "CKA_LOCAL should be true for encapsulation")
	})

	t.Run("sets CKA_LOCAL false for decapsulation", func(t *testing.T) {
		attrs := buildSecretKeyTemplate(nil, []byte("secret"), CKM_ML_KEM, false)

		localAttr := findAttr(attrs, CKA_LOCAL)
		require.NotNil(t, localAttr, "CKA_LOCAL must be present")
		boolVal, err := localAttr.GetBool()
		require.NoError(t, err)
		assert.False(t, boolVal, "CKA_LOCAL should be false for decapsulation")
	})

	t.Run("defaults CKA_EXTRACTABLE to false", func(t *testing.T) {
		attrs := buildSecretKeyTemplate(nil, []byte("secret"), CKM_ML_KEM, true)

		extractAttr := findAttr(attrs, CKA_EXTRACTABLE)
		require.NotNil(t, extractAttr, "CKA_EXTRACTABLE must be present")
		boolVal, err := extractAttr.GetBool()
		require.NoError(t, err)
		assert.False(t, boolVal, "CKA_EXTRACTABLE should default to false")
	})

	t.Run("preserves caller-provided CKA_EXTRACTABLE true", func(t *testing.T) {
		callerTemplate := []Attribute{
			NewBoolAttribute(CKA_EXTRACTABLE, true),
		}
		attrs := buildSecretKeyTemplate(callerTemplate, []byte("secret"), CKM_ML_KEM, true)

		extractAttr := findAttr(attrs, CKA_EXTRACTABLE)
		require.NotNil(t, extractAttr, "CKA_EXTRACTABLE must be present")
		boolVal, err := extractAttr.GetBool()
		require.NoError(t, err)
		assert.True(t, boolVal, "CKA_EXTRACTABLE should be true when caller sets it")
	})

	t.Run("sets CKA_ALWAYS_SENSITIVE true when CKA_SENSITIVE is true", func(t *testing.T) {
		callerTemplate := []Attribute{
			NewBoolAttribute(CKA_SENSITIVE, true),
		}
		attrs := buildSecretKeyTemplate(callerTemplate, []byte("secret"), CKM_ML_KEM, true)

		alwaysSensAttr := findAttr(attrs, CKA_ALWAYS_SENSITIVE)
		require.NotNil(t, alwaysSensAttr, "CKA_ALWAYS_SENSITIVE must be present")
		boolVal, err := alwaysSensAttr.GetBool()
		require.NoError(t, err)
		assert.True(t, boolVal, "CKA_ALWAYS_SENSITIVE should be true when CKA_SENSITIVE is true")
	})

	t.Run("sets CKA_ALWAYS_SENSITIVE false when CKA_SENSITIVE is false", func(t *testing.T) {
		callerTemplate := []Attribute{
			NewBoolAttribute(CKA_SENSITIVE, false),
		}
		attrs := buildSecretKeyTemplate(callerTemplate, []byte("secret"), CKM_ML_KEM, true)

		alwaysSensAttr := findAttr(attrs, CKA_ALWAYS_SENSITIVE)
		require.NotNil(t, alwaysSensAttr, "CKA_ALWAYS_SENSITIVE must be present")
		boolVal, err := alwaysSensAttr.GetBool()
		require.NoError(t, err)
		assert.False(t, boolVal, "CKA_ALWAYS_SENSITIVE should be false when CKA_SENSITIVE is false")
	})

	t.Run("sets CKA_ALWAYS_SENSITIVE false when CKA_SENSITIVE not provided", func(t *testing.T) {
		attrs := buildSecretKeyTemplate(nil, []byte("secret"), CKM_ML_KEM, true)

		alwaysSensAttr := findAttr(attrs, CKA_ALWAYS_SENSITIVE)
		require.NotNil(t, alwaysSensAttr, "CKA_ALWAYS_SENSITIVE must be present")
		boolVal, err := alwaysSensAttr.GetBool()
		require.NoError(t, err)
		assert.False(t, boolVal, "CKA_ALWAYS_SENSITIVE should be false when CKA_SENSITIVE is not provided")
	})

	t.Run("sets CKA_NEVER_EXTRACTABLE true when CKA_EXTRACTABLE is false", func(t *testing.T) {
		// Default: CKA_EXTRACTABLE is false
		attrs := buildSecretKeyTemplate(nil, []byte("secret"), CKM_ML_KEM, true)

		neverExtAttr := findAttr(attrs, CKA_NEVER_EXTRACTABLE)
		require.NotNil(t, neverExtAttr, "CKA_NEVER_EXTRACTABLE must be present")
		boolVal, err := neverExtAttr.GetBool()
		require.NoError(t, err)
		assert.True(t, boolVal, "CKA_NEVER_EXTRACTABLE should be true when CKA_EXTRACTABLE is false")
	})

	t.Run("sets CKA_NEVER_EXTRACTABLE false when CKA_EXTRACTABLE is true", func(t *testing.T) {
		callerTemplate := []Attribute{
			NewBoolAttribute(CKA_EXTRACTABLE, true),
		}
		attrs := buildSecretKeyTemplate(callerTemplate, []byte("secret"), CKM_ML_KEM, true)

		neverExtAttr := findAttr(attrs, CKA_NEVER_EXTRACTABLE)
		require.NotNil(t, neverExtAttr, "CKA_NEVER_EXTRACTABLE must be present")
		boolVal, err := neverExtAttr.GetBool()
		require.NoError(t, err)
		assert.False(t, boolVal, "CKA_NEVER_EXTRACTABLE should be false when CKA_EXTRACTABLE is true")
	})

	t.Run("sensitive and extractable interact correctly", func(t *testing.T) {
		// Sensitive=true, Extractable=true: ALWAYS_SENSITIVE=true, NEVER_EXTRACTABLE=false
		callerTemplate := []Attribute{
			NewBoolAttribute(CKA_SENSITIVE, true),
			NewBoolAttribute(CKA_EXTRACTABLE, true),
		}
		attrs := buildSecretKeyTemplate(callerTemplate, []byte("secret"), CKM_ML_KEM, false)

		alwaysSensAttr := findAttr(attrs, CKA_ALWAYS_SENSITIVE)
		require.NotNil(t, alwaysSensAttr)
		boolVal, err := alwaysSensAttr.GetBool()
		require.NoError(t, err)
		assert.True(t, boolVal)

		neverExtAttr := findAttr(attrs, CKA_NEVER_EXTRACTABLE)
		require.NotNil(t, neverExtAttr)
		boolVal, err = neverExtAttr.GetBool()
		require.NoError(t, err)
		assert.False(t, boolVal)

		// CKA_LOCAL should be false for decapsulation
		localAttr := findAttr(attrs, CKA_LOCAL)
		require.NotNil(t, localAttr)
		boolVal, err = localAttr.GetBool()
		require.NoError(t, err)
		assert.False(t, boolVal)
	})
}

// TestIsEncapsulateMechanism tests the encapsulation mechanism check.
func TestIsEncapsulateMechanism(t *testing.T) {

	t.Run("CKM_ML_KEM supports encapsulation", func(t *testing.T) {
		assert.True(t, isEncapsulateMechanism(CKM_ML_KEM))
	})

	t.Run("CKM_AES_CBC does not support encapsulation", func(t *testing.T) {
		assert.False(t, isEncapsulateMechanism(CKM_AES_CBC))
	})
}

// TestIsDecapsulateMechanism tests the decapsulation mechanism check.
func TestIsDecapsulateMechanism(t *testing.T) {

	t.Run("CKM_ML_KEM supports decapsulation", func(t *testing.T) {
		assert.True(t, isDecapsulateMechanism(CKM_ML_KEM))
	})

	t.Run("CKM_AES_CBC does not support decapsulation", func(t *testing.T) {
		assert.False(t, isDecapsulateMechanism(CKM_AES_CBC))
	})
}

// TestIsBoolAttributeTrue tests the bool attribute helper.
func TestIsBoolAttributeTrue(t *testing.T) {

	t.Run("returns true when attribute is set to true", func(t *testing.T) {
		obj := &Object{
			Attributes: map[AttributeType][]byte{
				CKA_ENCAPSULATE: {1},
			},
		}
		assert.True(t, isBoolAttributeTrue(obj, CKA_ENCAPSULATE))
	})

	t.Run("returns false when attribute is set to false", func(t *testing.T) {
		obj := &Object{
			Attributes: map[AttributeType][]byte{
				CKA_ENCAPSULATE: {0},
			},
		}
		assert.False(t, isBoolAttributeTrue(obj, CKA_ENCAPSULATE))
	})

	t.Run("returns false when attribute is not present", func(t *testing.T) {
		obj := &Object{
			Attributes: map[AttributeType][]byte{},
		}
		assert.False(t, isBoolAttributeTrue(obj, CKA_ENCAPSULATE))
	})
}

// ----------------------------------------------------------------------------
// KEMCiphertextSize
// ----------------------------------------------------------------------------

// TestKEMCiphertextSize tests the size-only query used by the CGO layer
// to handle PKCS#11 pCiphertext=NULL size queries without side effects.
func TestKEMCiphertextSize(t *testing.T) {

	t.Run("returns size for valid ML-KEM mechanism", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		sessionHandle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		keyHandle := createKEMPublicKey(t, m, sessionHandle)
		mechanism := NewMechanism(CKM_ML_KEM)

		size, err := m.KEMCiphertextSize(sessionHandle, mechanism, keyHandle)
		// Without quantum build tag, the stub returns CKR_MECHANISM_INVALID,
		// which is valid because the crypto backend is not available.
		if err != nil {
			var pkcsErr *PKCS11Error
			require.ErrorAs(t, err, &pkcsErr)
			assert.Equal(t, CKR_MECHANISM_INVALID, pkcsErr.Code)
		} else {
			assert.Greater(t, size, uint64(0))
		}
	})

	t.Run("returns CKR_CRYPTOKI_NOT_INITIALIZED when not initialized", func(t *testing.T) {
		m := createTestModule(t)

		mechanism := NewMechanism(CKM_ML_KEM)
		_, err := m.KEMCiphertextSize(SessionHandle(1), mechanism, ObjectHandle(1))
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, pkcsErr.Code)
	})

	t.Run("returns CKR_SESSION_HANDLE_INVALID for bad session", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		mechanism := NewMechanism(CKM_ML_KEM)
		_, err := m.KEMCiphertextSize(SessionHandle(99999), mechanism, ObjectHandle(1))
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_SESSION_HANDLE_INVALID, pkcsErr.Code)
	})

	t.Run("returns CKR_ARGUMENTS_BAD with nil mechanism", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		sessionHandle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		_, err := m.KEMCiphertextSize(sessionHandle, nil, ObjectHandle(1))
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_ARGUMENTS_BAD, pkcsErr.Code)
	})

	t.Run("returns CKR_MECHANISM_INVALID for non-encapsulate mechanism", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		sessionHandle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		keyHandle := createKEMPublicKey(t, m, sessionHandle)
		mechanism := NewMechanism(CKM_AES_CBC)

		_, err := m.KEMCiphertextSize(sessionHandle, mechanism, keyHandle)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_MECHANISM_INVALID, pkcsErr.Code)
	})

	t.Run("returns CKR_KEY_HANDLE_INVALID for invalid key handle", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		sessionHandle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		mechanism := NewMechanism(CKM_ML_KEM)
		_, err := m.KEMCiphertextSize(sessionHandle, mechanism, ObjectHandle(99999))
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_KEY_HANDLE_INVALID, pkcsErr.Code)
	})

	t.Run("returns CKR_KEY_HANDLE_INVALID for private key", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		sessionHandle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		// Create a private key -- KEMCiphertextSize requires a public key
		privKeyHandle := createKEMPrivateKey(t, m, sessionHandle)
		mechanism := NewMechanism(CKM_ML_KEM)

		_, err := m.KEMCiphertextSize(sessionHandle, mechanism, privKeyHandle)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_KEY_HANDLE_INVALID, pkcsErr.Code)
	})

	t.Run("returns CKR_KEY_FUNCTION_NOT_PERMITTED without CKA_ENCAPSULATE", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		sessionHandle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		// Public key without CKA_ENCAPSULATE
		template := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_PUBLIC_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_ML_KEM)),
			NewBoolAttribute(CKA_TOKEN, false),
			NewAttribute(CKA_VALUE, make([]byte, 32)),
		}
		keyHandle, rv := m.CreateObject(sessionHandle, template)
		require.Equal(t, CKR_OK, rv)

		mechanism := NewMechanism(CKM_ML_KEM)
		_, err := m.KEMCiphertextSize(sessionHandle, mechanism, keyHandle)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_KEY_FUNCTION_NOT_PERMITTED, pkcsErr.Code)
	})
}

// ----------------------------------------------------------------------------
// KEM R/W session enforcement
// ----------------------------------------------------------------------------

// TestEncapsulateKeyReadOnlySession tests that EncapsulateKey rejects
// read-only sessions since encapsulation creates a key object.
func TestEncapsulateKeyReadOnlySession(t *testing.T) {

	t.Run("returns CKR_SESSION_READ_ONLY for RO session", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		// Open a read-only session (no CKF_RW_SESSION)
		roSession, rv := m.OpenSession(0, CKF_SERIAL_SESSION)
		require.Equal(t, CKR_OK, rv)

		// Also open an RW session to create the key object
		rwSession, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		keyHandle := createKEMPublicKey(t, m, rwSession)
		mechanism := NewMechanism(CKM_ML_KEM)

		handle, ciphertext, err := m.EncapsulateKey(roSession, mechanism, keyHandle, nil)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_SESSION_READ_ONLY, pkcsErr.Code)
		assert.Equal(t, ObjectHandle(InvalidHandle), handle)
		assert.Nil(t, ciphertext)
	})
}

// TestDecapsulateKeyReadOnlySession tests that DecapsulateKey rejects
// read-only sessions since decapsulation creates a key object.
func TestDecapsulateKeyReadOnlySession(t *testing.T) {

	t.Run("returns CKR_SESSION_READ_ONLY for RO session", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		// Open a read-only session (no CKF_RW_SESSION)
		roSession, rv := m.OpenSession(0, CKF_SERIAL_SESSION)
		require.Equal(t, CKR_OK, rv)

		// Open an RW session to create the key object
		rwSession, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		keyHandle := createKEMPrivateKey(t, m, rwSession)
		mechanism := NewMechanism(CKM_ML_KEM)

		handle, err := m.DecapsulateKey(roSession, mechanism, keyHandle, nil, []byte("ciphertext"))
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_SESSION_READ_ONLY, pkcsErr.Code)
		assert.Equal(t, ObjectHandle(InvalidHandle), handle)
	})
}

// ----------------------------------------------------------------------------
// zeroize
// ----------------------------------------------------------------------------

func TestZeroize(t *testing.T) {

	t.Run("zeroes all bytes in slice", func(t *testing.T) {
		data := []byte{0x01, 0x02, 0x03, 0xFF, 0xAB}
		zeroize(data)
		for i, b := range data {
			assert.Equal(t, byte(0), b, "byte at index %d should be zero", i)
		}
	})

	t.Run("handles empty slice", func(t *testing.T) {
		data := []byte{}
		zeroize(data) // should not panic
		assert.Empty(t, data)
	})

	t.Run("handles nil slice", func(t *testing.T) {
		var data []byte
		zeroize(data) // should not panic
		assert.Nil(t, data)
	})

	t.Run("preserves slice length", func(t *testing.T) {
		data := make([]byte, 256)
		for i := range data {
			data[i] = byte(i)
		}
		zeroize(data)
		assert.Len(t, data, 256)
		for i, b := range data {
			assert.Equal(t, byte(0), b, "byte at index %d should be zero", i)
		}
	})
}
