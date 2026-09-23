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
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-enclave"
	"github.com/jeremyhahn/go-xkms/pkg/quantum/kyber768"
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

// TestEncapsulateKeyDecapsulateKeyCreatesSharedSecretObject proves
// C_EncapsulateKey and C_DecapsulateKey can actually create their output
// CKO_SECRET_KEY object, using real ML-KEM-768 key material from the
// reference kyber768 implementation rather than synthetic all-zero bytes:
// malformed key material (as createKEMPublicKey/createKEMPrivateKey use)
// fails inside the crypto backend before ever reaching object creation, so a
// test built on it cannot exercise -- or catch a regression in -- this path.
//
// Before the fix, buildSecretKeyTemplate handed ObjectManager.CreateObject a
// template carrying CKA_LOCAL, CKA_ALWAYS_SENSITIVE, CKA_NEVER_EXTRACTABLE
// and CKA_KEY_GEN_MECHANISM. CreateObject's computedAttributes guard rejects
// every one of those from any creation template, unconditionally, with
// CKR_ATTRIBUTE_READ_ONLY (wrapped here as CKR_FUNCTION_FAILED) -- so both
// C_EncapsulateKey and C_DecapsulateKey failed at that step for every input,
// with no path to success. This test fails exactly that way against the
// pre-fix code and passes once EncapsulateKey/DecapsulateKey create the
// object through ObjectManager.CreateDerivedObject instead.
func TestEncapsulateKeyDecapsulateKeyCreatesSharedSecretObject(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()
	sessionHandle := loginAsNormalUser(t, m)

	kem, err := kyber768.New()
	require.NoError(t, err)
	pub, err := kem.GenerateKeyPair()
	require.NoError(t, err)
	seed := kem.ExportSecretKey()
	defer kem.Clean()

	pubHandle, rv := m.CreateObject(sessionHandle, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_PUBLIC_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_ML_KEM)),
		NewStringAttribute(CKA_LABEL, "kem-roundtrip-pub"),
		NewBoolAttribute(CKA_TOKEN, false),
		NewBoolAttribute(CKA_ENCAPSULATE, true),
		NewAttribute(CKA_VALUE, pub),
	})
	require.Equal(t, CKR_OK, rv)

	privHandle, rv := m.CreateObject(sessionHandle, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_PRIVATE_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_ML_KEM)),
		NewStringAttribute(CKA_LABEL, "kem-roundtrip-priv"),
		NewBoolAttribute(CKA_TOKEN, false),
		NewBoolAttribute(CKA_DECAPSULATE, true),
		NewAttribute(CKA_VALUE, seed),
	})
	require.Equal(t, CKR_OK, rv)

	secretTemplate := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewStringAttribute(CKA_LABEL, "kem-roundtrip-secret"),
		NewBoolAttribute(CKA_TOKEN, false),
		NewBoolAttribute(CKA_EXTRACTABLE, true),
		NewBoolAttribute(CKA_SENSITIVE, false),
	}

	encMech := &Mechanism{Type: CKM_VENDOR_ML_KEM_768_ENCAPSULATE}
	encSecretHandle, ciphertext, err := m.EncapsulateKey(sessionHandle, encMech, pubHandle, secretTemplate)
	require.NoError(t, err, "C_EncapsulateKey must be able to create its output secret-key object")
	require.NotEmpty(t, ciphertext)

	// The created object's token-computed provenance attributes must reflect
	// that CreateDerivedObject -- not a caller-forged template -- set them:
	// neither C_EncapsulateKey nor C_DecapsulateKey is C_GenerateKey/
	// C_GenerateKeyPair (CKA_LOCAL) or a caller import (CKA_ALWAYS_SENSITIVE/
	// CKA_NEVER_EXTRACTABLE), and the imported public key was itself neither
	// always-sensitive nor never-extractable.
	encAttrs, encRV := m.GetAttributeValue(sessionHandle, encSecretHandle, []Attribute{
		{Type: CKA_VALUE},
		{Type: CKA_LOCAL},
		{Type: CKA_ALWAYS_SENSITIVE},
		{Type: CKA_NEVER_EXTRACTABLE},
	})
	require.Equal(t, CKR_OK, encRV)
	requireFalseBool(t, encAttrs, CKA_LOCAL)
	requireFalseBool(t, encAttrs, CKA_ALWAYS_SENSITIVE)
	requireFalseBool(t, encAttrs, CKA_NEVER_EXTRACTABLE)

	decMech := &Mechanism{Type: CKM_VENDOR_ML_KEM_768_DECAPSULATE}
	decSecretHandle, err := m.DecapsulateKey(sessionHandle, decMech, privHandle, secretTemplate, ciphertext)
	require.NoError(t, err, "C_DecapsulateKey must be able to create its output secret-key object")

	decAttrs, decRV := m.GetAttributeValue(sessionHandle, decSecretHandle, []Attribute{{Type: CKA_VALUE}})
	require.Equal(t, CKR_OK, decRV)

	assert.Equal(t, findAttr(encAttrs, CKA_VALUE).Value, findAttr(decAttrs, CKA_VALUE).Value,
		"C_EncapsulateKey and C_DecapsulateKey must agree on the shared secret")
}

// requireFalseBool fails the test unless attrs contains attrType with the
// CK_BBOOL value CK_FALSE.
func requireFalseBool(t *testing.T, attrs []Attribute, attrType AttributeType) {
	t.Helper()
	attr := findAttr(attrs, attrType)
	require.NotNil(t, attr, "%s must be present", attrType.String())
	val, err := attr.GetBool()
	require.NoError(t, err)
	assert.False(t, val, "%s should be CK_FALSE", attrType.String())
}

// TestEncapsulateKey tests KEM encapsulation validation and dispatch.
func TestEncapsulateKey(t *testing.T) {

	t.Run("returns CKR_MECHANISM_INVALID without quantum build tag", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
		// authenticates before exercising them.
		sessionHandle := loginAsNormalUser(t, m)

		keyHandle := createKEMPublicKey(t, m, sessionHandle)
		mechanism := NewMechanism(CKM_ML_KEM)
		template := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		}

		// CKM_ML_KEM is a standard v3.2 mechanism and now dispatches: the
		// mechanism itself is valid, so without the quantum build tag the
		// failure comes from the operation, not from mechanism lookup.
		handle, ciphertext, err := m.EncapsulateKey(sessionHandle, mechanism, keyHandle, template)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.NotEqual(t, CKR_MECHANISM_INVALID, pkcsErr.Code,
			"CKM_ML_KEM must be recognised as a valid mechanism")
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

		// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
		// authenticates before exercising them.
		sessionHandle := loginAsNormalUser(t, m)

		mechanism := NewMechanism(CKM_ML_KEM)
		handle, ciphertext, err := m.EncapsulateKey(sessionHandle, mechanism, ObjectHandle(99999), nil)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_KEY_HANDLE_INVALID, pkcsErr.Code)
		assert.Equal(t, ObjectHandle(InvalidHandle), handle)
		assert.Nil(t, ciphertext)
	})

	t.Run("returns CKR_KEY_TYPE_INCONSISTENT without CKA_ENCAPSULATE", func(t *testing.T) {
		m, sessionHandle, keyHandle := createTestModuleWithKey(t)
		defer m.Finalize()

		mechanism := NewMechanism(CKM_ML_KEM)
		handle, ciphertext, err := m.EncapsulateKey(sessionHandle, mechanism, keyHandle, nil)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_KEY_TYPE_INCONSISTENT, pkcsErr.Code)
		assert.Equal(t, ObjectHandle(InvalidHandle), handle)
		assert.Nil(t, ciphertext)
	})

	t.Run("returns CKR_KEY_HANDLE_INVALID when key has no CKA_VALUE", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
		// authenticates before exercising them.
		sessionHandle := loginAsNormalUser(t, m)

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

		// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
		// authenticates before exercising them.
		sessionHandle := loginAsNormalUser(t, m)

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

		// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
		// authenticates before exercising them.
		sessionHandle := loginAsNormalUser(t, m)

		// Create a secret key -- EncapsulateKey requires a public key
		template := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
			NewAttribute(CKA_VALUE, make([]byte, 32)),
			NewBoolAttribute(CKA_ENCAPSULATE, true),
			NewBoolAttribute(CKA_TOKEN, false),
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

		// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
		// authenticates before exercising them.
		sessionHandle := loginAsNormalUser(t, m)

		keyHandle := createKEMPrivateKey(t, m, sessionHandle)
		mechanism := NewMechanism(CKM_ML_KEM)
		template := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		}
		ciphertext := []byte("mock-ciphertext-for-kem")

		// CKM_ML_KEM is a standard v3.2 mechanism and now dispatches, so the
		// mechanism itself is valid and the failure comes from elsewhere.
		handle, err := m.DecapsulateKey(sessionHandle, mechanism, keyHandle, template, ciphertext)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.NotEqual(t, CKR_MECHANISM_INVALID, pkcsErr.Code,
			"CKM_ML_KEM must be recognised as a valid mechanism")
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

		// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
		// authenticates before exercising them.
		sessionHandle := loginAsNormalUser(t, m)

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

		// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
		// authenticates before exercising them.
		sessionHandle := loginAsNormalUser(t, m)

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

	t.Run("returns CKR_KEY_TYPE_INCONSISTENT without CKA_DECAPSULATE", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
		// authenticates before exercising them.
		sessionHandle := loginAsNormalUser(t, m)

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
		assert.Equal(t, CKR_KEY_TYPE_INCONSISTENT, pkcsErr.Code)
		assert.Equal(t, ObjectHandle(InvalidHandle), handle)
	})

	t.Run("returns CKR_MECHANISM_INVALID for non-decapsulate mechanism", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
		// authenticates before exercising them.
		sessionHandle := loginAsNormalUser(t, m)

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

		// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
		// authenticates before exercising them.
		sessionHandle := loginAsNormalUser(t, m)

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

// TestBuildSecretKeyTemplate tests the helper function for building secret
// key templates.
//
// buildSecretKeyTemplate deliberately never emits CKA_LOCAL,
// CKA_ALWAYS_SENSITIVE, CKA_NEVER_EXTRACTABLE or CKA_KEY_GEN_MECHANISM: those
// are token-computed (v3.2 section 4.9), and EncapsulateKey/DecapsulateKey
// pass this function's output to ObjectManager.CreateDerivedObject, which
// computes CKA_LOCAL/CKA_ALWAYS_SENSITIVE/CKA_NEVER_EXTRACTABLE itself. A
// version of this function that set them (the pre-fix behavior) would make
// object.go's computedAttributes guard reject the template unconditionally
// -- that guard makes no exception for the token's own code, by design (see
// object_test.go's TestObjectManager_CreateObject_RejectsComputedAttributes)
// -- which is exactly why C_EncapsulateKey/C_DecapsulateKey could never
// create their output object. See
// TestEncapsulateKeyDecapsulateKeyCreatesSharedSecretObject for the
// end-to-end proof that the real entry points now succeed.
func TestBuildSecretKeyTemplate(t *testing.T) {

	t.Run("builds template with defaults when empty", func(t *testing.T) {
		sharedSecret := []byte("shared-secret-data")
		attrs := buildSecretKeyTemplate(nil, sharedSecret)

		// Should have CKA_CLASS, CKA_KEY_TYPE, CKA_VALUE, CKA_VALUE_LEN,
		// CKA_EXTRACTABLE, CKA_SENSITIVE.
		assert.GreaterOrEqual(t, len(attrs), 6)

		// Verify CKA_VALUE contains the shared secret
		valueAttr := findAttr(attrs, CKA_VALUE)
		require.NotNil(t, valueAttr, "CKA_VALUE must be present")
		assert.Equal(t, sharedSecret, valueAttr.Value)
	})

	t.Run("never emits a token-computed attribute", func(t *testing.T) {
		// A template carrying any of these would be rejected outright by
		// ObjectManager.CreateObject's computedAttributes guard -- the exact
		// defect this function's redesign fixes. Exercise every combination
		// of inputs the other subtests use, plus a caller template that
		// (incorrectly) tries to supply one directly.
		computed := []AttributeType{
			CKA_LOCAL, CKA_ALWAYS_SENSITIVE, CKA_NEVER_EXTRACTABLE, CKA_KEY_GEN_MECHANISM,
		}

		attrs := buildSecretKeyTemplate(nil, []byte("secret"))
		for _, at := range computed {
			assert.Nil(t, findAttr(attrs, at), "%s must not be emitted", at.String())
		}

		// Even a caller template that tries to sneak one in must not survive:
		// buildSecretKeyTemplate does not special-case rejecting it, but it
		// also never re-adds it as a default, and CreateDerivedObject's own
		// completeKeyTemplate strips it before the object is built.
		callerTemplate := []Attribute{NewBoolAttribute(CKA_LOCAL, true)}
		attrs = buildSecretKeyTemplate(callerTemplate, []byte("secret"))
		localAttr := findAttr(attrs, CKA_LOCAL)
		if localAttr != nil {
			assert.Equal(t, callerTemplate[0].Value, localAttr.Value,
				"buildSecretKeyTemplate itself only ever passes through what the caller supplied")
		}
	})

	t.Run("overrides caller CKA_VALUE with shared secret", func(t *testing.T) {
		sharedSecret := []byte("actual-secret")
		callerTemplate := []Attribute{
			NewAttribute(CKA_VALUE, []byte("should-be-ignored")),
		}
		attrs := buildSecretKeyTemplate(callerTemplate, sharedSecret)

		valueAttr := findAttr(attrs, CKA_VALUE)
		require.NotNil(t, valueAttr)
		assert.Equal(t, sharedSecret, valueAttr.Value)
	})

	t.Run("preserves caller-provided CKA_VALUE_LEN", func(t *testing.T) {
		callerTemplate := []Attribute{
			{Type: CKA_VALUE_LEN, Value: []byte{0x10, 0x00, 0x00, 0x00}}, // 16 in little-endian
		}
		attrs := buildSecretKeyTemplate(callerTemplate, []byte("secret"))

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
		attrs := buildSecretKeyTemplate(callerTemplate, []byte("secret"))

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

	t.Run("defaults CKA_EXTRACTABLE to true", func(t *testing.T) {
		// v3.2 5.18.8/5.18.9 give KEM-created keys CKA_EXTRACTABLE CK_TRUE
		// unless the caller's template says otherwise.
		attrs := buildSecretKeyTemplate(nil, []byte("secret"))

		extractAttr := findAttr(attrs, CKA_EXTRACTABLE)
		require.NotNil(t, extractAttr, "CKA_EXTRACTABLE must be present")
		boolVal, err := extractAttr.GetBool()
		require.NoError(t, err)
		assert.True(t, boolVal, "CKA_EXTRACTABLE should default to true")
	})

	t.Run("preserves caller-provided CKA_EXTRACTABLE true", func(t *testing.T) {
		callerTemplate := []Attribute{
			NewBoolAttribute(CKA_EXTRACTABLE, true),
		}
		attrs := buildSecretKeyTemplate(callerTemplate, []byte("secret"))

		extractAttr := findAttr(attrs, CKA_EXTRACTABLE)
		require.NotNil(t, extractAttr, "CKA_EXTRACTABLE must be present")
		boolVal, err := extractAttr.GetBool()
		require.NoError(t, err)
		assert.True(t, boolVal, "CKA_EXTRACTABLE should be true when caller sets it")
	})

	t.Run("defaults CKA_SENSITIVE to false", func(t *testing.T) {
		attrs := buildSecretKeyTemplate(nil, []byte("secret"))

		sensAttr := findAttr(attrs, CKA_SENSITIVE)
		require.NotNil(t, sensAttr, "CKA_SENSITIVE must be present")
		boolVal, err := sensAttr.GetBool()
		require.NoError(t, err)
		assert.False(t, boolVal, "CKA_SENSITIVE should default to false")
	})

	t.Run("preserves caller-provided CKA_SENSITIVE true", func(t *testing.T) {
		callerTemplate := []Attribute{
			NewBoolAttribute(CKA_SENSITIVE, true),
		}
		attrs := buildSecretKeyTemplate(callerTemplate, []byte("secret"))

		sensAttr := findAttr(attrs, CKA_SENSITIVE)
		require.NotNil(t, sensAttr, "CKA_SENSITIVE must be present")
		boolVal, err := sensAttr.GetBool()
		require.NoError(t, err)
		assert.True(t, boolVal, "CKA_SENSITIVE should be true when caller sets it")
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

		// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
		// authenticates before exercising them.
		sessionHandle := loginAsNormalUser(t, m)

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

		// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
		// authenticates before exercising them.
		sessionHandle := loginAsNormalUser(t, m)

		_, err := m.KEMCiphertextSize(sessionHandle, nil, ObjectHandle(1))
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_ARGUMENTS_BAD, pkcsErr.Code)
	})

	t.Run("returns CKR_MECHANISM_INVALID for non-encapsulate mechanism", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
		// authenticates before exercising them.
		sessionHandle := loginAsNormalUser(t, m)

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

		// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
		// authenticates before exercising them.
		sessionHandle := loginAsNormalUser(t, m)

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

		// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
		// authenticates before exercising them.
		sessionHandle := loginAsNormalUser(t, m)

		// Create a private key -- KEMCiphertextSize requires a public key
		privKeyHandle := createKEMPrivateKey(t, m, sessionHandle)
		mechanism := NewMechanism(CKM_ML_KEM)

		_, err := m.KEMCiphertextSize(sessionHandle, mechanism, privKeyHandle)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_KEY_HANDLE_INVALID, pkcsErr.Code)
	})

	t.Run("returns CKR_KEY_TYPE_INCONSISTENT without CKA_ENCAPSULATE", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
		// authenticates before exercising them.
		sessionHandle := loginAsNormalUser(t, m)

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
		assert.Equal(t, CKR_KEY_TYPE_INCONSISTENT, pkcsErr.Code)
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

		// Provision and authenticate first: C_InitToken refuses to run while
		// any session is open.
		rwSession := loginAsNormalUser(t, m)

		roSession, rv := m.OpenSession(0, CKF_SERIAL_SESSION)
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

		// Provision and authenticate first: C_InitToken refuses to run while
		// any session is open.
		rwSession := loginAsNormalUser(t, m)

		roSession, rv := m.OpenSession(0, CKF_SERIAL_SESSION)
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
// enclave.Wipe
//
// pkg/crypto/mem was retired (go-xkms#623); the package-local zeroize helper
// that wrapped a hand-rolled zeroing loop is gone, and every former call site
// now defers directly to go-enclave's Wipe. These tests exercise that
// dependency the way this package's call sites use it, not go-enclave's own
// (already-covered) unit tests.
// ----------------------------------------------------------------------------

func TestEnclaveWipe(t *testing.T) {

	t.Run("zeroes all bytes in slice", func(t *testing.T) {
		data := []byte{0x01, 0x02, 0x03, 0xFF, 0xAB}
		enclave.Wipe(data)
		for i, b := range data {
			assert.Equal(t, byte(0), b, "byte at index %d should be zero", i)
		}
	})

	t.Run("handles empty slice", func(t *testing.T) {
		data := []byte{}
		enclave.Wipe(data) // should not panic
		assert.Empty(t, data)
	})

	t.Run("handles nil slice", func(t *testing.T) {
		var data []byte
		enclave.Wipe(data) // should not panic
		assert.Nil(t, data)
	})

	t.Run("preserves slice length", func(t *testing.T) {
		data := make([]byte, 256)
		for i := range data {
			data[i] = byte(i)
		}
		enclave.Wipe(data)
		assert.Len(t, data, 256)
		for i, b := range data {
			assert.Equal(t, byte(0), b, "byte at index %d should be zero", i)
		}
	})
}

// TestKEMCiphertextSizeReadOnlySession asserts the size query rejects a
// read-only session with the same code the encapsulation itself does.
//
// C_EncapsulateKey is a two-call function: an application asks for the
// ciphertext length with a NULL pCiphertext, allocates that many bytes, and
// calls again. EncapsulateKey creates a key object and so rejects a read-only
// session; a size query that succeeded there told the application to allocate
// for a call that cannot run.
func TestKEMCiphertextSizeReadOnlySession(t *testing.T) {
	t.Run("returns CKR_SESSION_READ_ONLY on a read-only session", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		rwSession := loginAsNormalUser(t, m)

		roSession, rv := m.OpenSession(0, CKF_SERIAL_SESSION)
		require.Equal(t, CKR_OK, rv)

		keyHandle := createKEMPublicKey(t, m, rwSession)
		mechanism := NewMechanism(CKM_ML_KEM)

		size, sizeErr := m.KEMCiphertextSize(roSession, mechanism, keyHandle)
		require.Error(t, sizeErr, "the size query must not succeed where the encapsulation cannot run")
		var sizePkcsErr *PKCS11Error
		require.ErrorAs(t, sizeErr, &sizePkcsErr)
		assert.Equal(t, CKR_SESSION_READ_ONLY, sizePkcsErr.Code)
		assert.Zero(t, size)

		// The encapsulation the application would have made next returns the
		// same code, which is what makes the size query's answer the useful one.
		_, _, encErr := m.EncapsulateKey(roSession, mechanism, keyHandle, nil)
		require.Error(t, encErr)
		var encPkcsErr *PKCS11Error
		require.ErrorAs(t, encErr, &encPkcsErr)
		assert.Equal(t, CKR_SESSION_READ_ONLY, encPkcsErr.Code)
	})

	t.Run("gets past the read-write check on a read-write session", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		sessionHandle := loginAsNormalUser(t, m)
		keyHandle := createKEMPublicKey(t, m, sessionHandle)
		mechanism := NewMechanism(CKM_ML_KEM)

		// Without the quantum build tag the mechanism itself is unavailable,
		// so the assertion is that the new check does not turn a read-write
		// session away: the call must reach the mechanism resolution and fail
		// there, or succeed outright.
		size, err := m.KEMCiphertextSize(sessionHandle, mechanism, keyHandle)
		if err != nil {
			var pkcsErr *PKCS11Error
			require.ErrorAs(t, err, &pkcsErr)
			assert.Equal(t, CKR_MECHANISM_INVALID, pkcsErr.Code,
				"a read-write session must not be rejected by the read-only check")
		} else {
			assert.Greater(t, size, uint64(0))
		}
	})
}

// TestBuildSecretKeyTemplate_ULongDefaultsAreNativeWidth proves the attributes
// this function supplies for a caller who did not are whole CK_ULONGs.
//
// CKA_CLASS is a CK_OBJECT_CLASS, CKA_KEY_TYPE a CK_KEY_TYPE and CKA_VALUE_LEN
// a CK_ULONG (PKCS#11 v3.2 §4.4, §6.10.3), all of which are ckULongSize bytes
// on the platforms this module targets. They are exactly the attributes an
// application reads back from a C_DecapsulateKey result whose template it left
// incomplete, and C_GetAttributeValue reports the stored length in ulValueLen
// (§5.7.5) — so a short value hands the caller half a CK_ULONG and leaves the
// rest of its buffer holding whatever was there before.
func TestBuildSecretKeyTemplate_ULongDefaultsAreNativeWidth(t *testing.T) {
	t.Run("token-supplied defaults are whole CK_ULONGs", func(t *testing.T) {
		sharedSecret := make([]byte, 32)
		attrs := buildSecretKeyTemplate(nil, sharedSecret)

		for _, tc := range []struct {
			attrType AttributeType
			want     uint64
		}{
			{attrType: CKA_CLASS, want: uint64(CKO_SECRET_KEY)},
			{attrType: CKA_KEY_TYPE, want: uint64(CKK_GENERIC_SECRET)},
			{attrType: CKA_VALUE_LEN, want: uint64(len(sharedSecret))},
		} {
			attr := findAttr(attrs, tc.attrType)
			require.NotNilf(t, attr, "%s must be supplied", tc.attrType.String())
			assert.Lenf(t, attr.Value, ckULongSize,
				"%s is a CK_ULONG and must be encoded as one", tc.attrType.String())
			assert.Equalf(t, tc.want, binary.LittleEndian.Uint64(attr.Value),
				"%s must carry the value the token computed", tc.attrType.String())
		}
	})

	t.Run("a caller's own values are passed through untouched", func(t *testing.T) {
		// The caller states the attribute, so this function supplies nothing and
		// must not rewrite what it was given; the object layer normalises the
		// width once, when the value is stored.
		callerTemplate := []Attribute{
			{Type: CKA_CLASS, Value: []byte{0x04, 0x00, 0x00, 0x00}},
			{Type: CKA_KEY_TYPE, Value: []byte{0x10, 0x00, 0x00, 0x00}},
			{Type: CKA_VALUE_LEN, Value: []byte{0x10, 0x00, 0x00, 0x00}},
		}
		attrs := buildSecretKeyTemplate(callerTemplate, make([]byte, 32))

		for _, want := range callerTemplate {
			attr := findAttr(attrs, want.Type)
			require.NotNilf(t, attr, "%s must be present", want.Type.String())
			assert.Equalf(t, want.Value, attr.Value,
				"%s must be the caller's value, unmodified", want.Type.String())
		}
	})
}

// ----------------------------------------------------------------------------
// KEM CKF_LOGIN_REQUIRED enforcement
// ----------------------------------------------------------------------------

// kemLoginFixture holds an authenticated read-write session, real ML-KEM-768
// key objects created under it, and the ciphertext a successful encapsulation
// produced -- everything each login subtest needs to run its verb once for real
// before logging out and running it again.
type kemLoginFixture struct {
	module     *Module
	session    SessionHandle
	publicKey  ObjectHandle
	privateKey ObjectHandle
	ciphertext []byte
	template   []Attribute
}

// newKEMLoginFixture builds a kemLoginFixture from real kyber768 key material.
// Synthetic key bytes fail inside the crypto backend before the operation can
// succeed, so a login test built on them could not tell a gate that refuses
// correctly from one that refuses unconditionally.
//
// Every object here is created with CKA_PRIVATE=CK_FALSE, and that is what makes
// the login subtests mean anything. A CKO_SECRET_KEY left to its default is a
// private object, so ObjectManager.createPolicyChecked refuses to create it for
// a logged-out session with CKR_USER_NOT_LOGGED_IN of its own accord -- after
// the encapsulation has already run. A fixture built on private objects
// therefore reports the expected code whether the login gate exists or not, and
// deleting the gate leaves the test passing. Public objects remove that second
// source of the same code, so the gate is the only thing that can produce it.
func newKEMLoginFixture(t *testing.T) *kemLoginFixture {
	t.Helper()

	m := initializeTestModule(t)
	session := loginAsNormalUser(t, m)

	kem, err := kyber768.New()
	require.NoError(t, err)
	pub, err := kem.GenerateKeyPair()
	require.NoError(t, err)
	seed := kem.ExportSecretKey()
	defer kem.Clean()

	publicKey, rv := m.CreateObject(session, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_PUBLIC_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_ML_KEM)),
		NewStringAttribute(CKA_LABEL, "kem-login-pub"),
		NewBoolAttribute(CKA_TOKEN, false),
		NewBoolAttribute(CKA_PRIVATE, false),
		NewBoolAttribute(CKA_ENCAPSULATE, true),
		NewAttribute(CKA_VALUE, pub),
	})
	require.Equal(t, CKR_OK, rv)

	privateKey, rv := m.CreateObject(session, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_PRIVATE_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_ML_KEM)),
		NewStringAttribute(CKA_LABEL, "kem-login-priv"),
		NewBoolAttribute(CKA_TOKEN, false),
		NewBoolAttribute(CKA_PRIVATE, false),
		NewBoolAttribute(CKA_DECAPSULATE, true),
		NewAttribute(CKA_VALUE, seed),
	})
	require.Equal(t, CKR_OK, rv)

	template := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewStringAttribute(CKA_LABEL, "kem-login-secret"),
		NewBoolAttribute(CKA_TOKEN, false),
		NewBoolAttribute(CKA_PRIVATE, false),
		NewBoolAttribute(CKA_EXTRACTABLE, true),
		NewBoolAttribute(CKA_SENSITIVE, false),
	}

	_, ciphertext, err := m.EncapsulateKey(session,
		&Mechanism{Type: CKM_VENDOR_ML_KEM_768_ENCAPSULATE}, publicKey, template)
	require.NoError(t, err)
	require.NotEmpty(t, ciphertext)

	return &kemLoginFixture{
		module:     m,
		session:    session,
		publicKey:  publicKey,
		privateKey: privateKey,
		ciphertext: ciphertext,
		template:   template,
	}
}

// requireNotLoggedIn fails the test unless err is a PKCS11Error carrying
// exactly CKR_USER_NOT_LOGGED_IN.
func requireNotLoggedIn(t *testing.T, err error) {
	t.Helper()
	require.Error(t, err)
	var pkcsErr *PKCS11Error
	require.ErrorAs(t, err, &pkcsErr)
	assert.Equal(t, CKR_USER_NOT_LOGGED_IN, pkcsErr.Code)
}

// TestKEMRequiresLogin proves the token's CKF_LOGIN_REQUIRED policy reaches
// C_EncapsulateKey, C_DecapsulateKey and the ciphertext size query.
//
// PKCS#11 v3.2 §5.18.8/§5.18.9 make the KEM verbs key-management functions:
// each creates a CKO_SECRET_KEY object on the token from a key the caller
// names, which is what C_WrapKey and C_UnwrapKey do, and those refuse an
// unauthenticated session with CKR_USER_NOT_LOGGED_IN. The policy cannot depend
// on which verb an application names, so a session C_UnwrapKey refuses must not
// reach a usable shared secret through C_DecapsulateKey.
//
// Each subtest runs its verb once while logged in, so a gate that refused
// unconditionally fails here rather than passing.
func TestKEMRequiresLogin(t *testing.T) {

	t.Run("EncapsulateKey refuses a logged-out session", func(t *testing.T) {
		f := newKEMLoginFixture(t)
		defer f.module.Finalize()
		mechanism := &Mechanism{Type: CKM_VENDOR_ML_KEM_768_ENCAPSULATE}

		handle, ciphertext, err := f.module.EncapsulateKey(f.session, mechanism, f.publicKey, f.template)
		require.NoError(t, err, "the encapsulation must succeed while the session is authenticated")
		require.NotEqual(t, ObjectHandle(InvalidHandle), handle)
		require.NotEmpty(t, ciphertext)

		require.Equal(t, CKR_OK, f.module.Logout(f.session))

		handle, ciphertext, err = f.module.EncapsulateKey(f.session, mechanism, f.publicKey, f.template)
		requireNotLoggedIn(t, err)
		assert.Equal(t, ObjectHandle(InvalidHandle), handle,
			"a logged-out session must not be handed a shared secret key object")
		assert.Nil(t, ciphertext, "a logged-out session must not be handed KEM ciphertext")
	})

	t.Run("DecapsulateKey refuses a logged-out session", func(t *testing.T) {
		f := newKEMLoginFixture(t)
		defer f.module.Finalize()
		mechanism := &Mechanism{Type: CKM_VENDOR_ML_KEM_768_DECAPSULATE}

		handle, err := f.module.DecapsulateKey(f.session, mechanism, f.privateKey, f.template, f.ciphertext)
		require.NoError(t, err, "the decapsulation must succeed while the session is authenticated")
		require.NotEqual(t, ObjectHandle(InvalidHandle), handle)

		require.Equal(t, CKR_OK, f.module.Logout(f.session))

		handle, err = f.module.DecapsulateKey(f.session, mechanism, f.privateKey, f.template, f.ciphertext)
		requireNotLoggedIn(t, err)
		assert.Equal(t, ObjectHandle(InvalidHandle), handle,
			"a logged-out session must not turn ciphertext it supplied into a key object")
	})

	t.Run("KEMCiphertextSize refuses a logged-out session", func(t *testing.T) {
		f := newKEMLoginFixture(t)
		defer f.module.Finalize()
		mechanism := NewMechanism(CKM_ML_KEM)

		size, err := f.module.KEMCiphertextSize(f.session, mechanism, f.publicKey)
		require.NoError(t, err, "the size query must answer while the session is authenticated")
		assert.Equal(t, uint64(MLKEM768CiphertextSize), size)

		require.Equal(t, CKR_OK, f.module.Logout(f.session))

		size, err = f.module.KEMCiphertextSize(f.session, mechanism, f.publicKey)
		requireNotLoggedIn(t, err)
		assert.Zero(t, size)
	})

	// The C ABI reaches KEMCiphertextSize before EncapsulateKey on both the
	// NULL-pCiphertext probe and the real call (exports_v32.go), so the two must
	// agree: a size query that answered CKR_OK where the encapsulation answers
	// CKR_USER_NOT_LOGGED_IN would be the only gate a C caller ever meets, and
	// it would be open.
	t.Run("the size query and the encapsulation answer alike", func(t *testing.T) {
		f := newKEMLoginFixture(t)
		defer f.module.Finalize()
		mechanism := NewMechanism(CKM_ML_KEM)

		size, sizeErr := f.module.KEMCiphertextSize(f.session, mechanism, f.publicKey)
		require.NoError(t, sizeErr)
		_, ciphertext, encErr := f.module.EncapsulateKey(f.session, mechanism, f.publicKey, f.template)
		require.NoError(t, encErr)
		assert.Equal(t, size, uint64(len(ciphertext)),
			"the size query must predict the ciphertext the encapsulation produces")

		require.Equal(t, CKR_OK, f.module.Logout(f.session))

		_, sizeErr = f.module.KEMCiphertextSize(f.session, mechanism, f.publicKey)
		requireNotLoggedIn(t, sizeErr)
		_, _, encErr = f.module.EncapsulateKey(f.session, mechanism, f.publicKey, f.template)
		requireNotLoggedIn(t, encErr)
	})
}

// ----------------------------------------------------------------------------
// KEM shared secret persistence (PKCS#11 v3.2 sections 4.4, 5.18.8, 5.18.9)
// ----------------------------------------------------------------------------

// mlkem768Material returns a real ML-KEM-768 public key and the matching seed,
// which is the private-key representation this module stores in CKA_VALUE.
// Synthetic bytes fail inside the crypto backend before object creation is
// reached, so a persistence test cannot be built on them.
func mlkem768Material(t *testing.T) (publicKey, seed []byte) {
	t.Helper()

	kem, err := kyber768.New()
	require.NoError(t, err)
	defer kem.Clean()

	publicKey, err = kem.GenerateKeyPair()
	require.NoError(t, err)

	return publicKey, kem.ExportSecretKey()
}

// createKEMKeyPairObjects imports an ML-KEM-768 pair as session objects usable
// by C_EncapsulateKey and C_DecapsulateKey.
func createKEMKeyPairObjects(t *testing.T, m *Module, session SessionHandle) (pub, priv ObjectHandle) {
	t.Helper()

	publicKey, seed := mlkem768Material(t)

	pub, rv := m.CreateObject(session, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_PUBLIC_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_ML_KEM)),
		NewStringAttribute(CKA_LABEL, "kem-persistence-pub"),
		NewBoolAttribute(CKA_TOKEN, false),
		NewBoolAttribute(CKA_ENCAPSULATE, true),
		NewAttribute(CKA_VALUE, publicKey),
	})
	require.Equal(t, CKR_OK, rv)

	priv, rv = m.CreateObject(session, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_PRIVATE_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_ML_KEM)),
		NewStringAttribute(CKA_LABEL, "kem-persistence-priv"),
		NewBoolAttribute(CKA_TOKEN, false),
		NewBoolAttribute(CKA_DECAPSULATE, true),
		NewAttribute(CKA_VALUE, seed),
	})
	require.Equal(t, CKR_OK, rv)

	return pub, priv
}

// storableSharedSecretTemplate describes a CKA_TOKEN shared secret whose
// material this module's plaintext store can hold whole: neither CKA_SENSITIVE
// nor CKA_EXTRACTABLE=CK_FALSE, so SaveObject writes its CKA_VALUE out with the
// rest of its attributes.
func storableSharedSecretTemplate(label string) []Attribute {
	return []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewStringAttribute(CKA_LABEL, label),
		NewBoolAttribute(CKA_TOKEN, true),
		NewBoolAttribute(CKA_PRIVATE, false),
		NewBoolAttribute(CKA_SENSITIVE, false),
		NewBoolAttribute(CKA_EXTRACTABLE, true),
	}
}

// TestKEMTokenSharedSecretsSurviveFinalize proves a CKA_TOKEN shared secret
// created by C_EncapsulateKey or C_DecapsulateKey is still on the token after
// the module is finalized and a new one is brought up over the same storage.
//
// Both verbs create their object through CreateDerivedObject, which only inserts
// it into the in-memory object manager; neither wrote it through to the store,
// while C_UnwrapKey — the verb they are modelled on — did. The result was a
// handle and, for encapsulation, a ciphertext already sent to the peer, for a
// key that C_FindObjects could not find at the next process start. Nothing
// warned at any layer, and an in-memory assertion cannot catch it, so the
// assertion has to be made against a second module reading the same files.
func TestKEMTokenSharedSecretsSurviveFinalize(t *testing.T) {
	const (
		encapsulatedLabel = "kem-token-secret-encapsulated"
		decapsulatedLabel = "kem-token-secret-decapsulated"
	)

	dir := t.TempDir()

	first := newPersistentModule(t, dir)
	session := loginAsNormalUser(t, first)
	pub, priv := createKEMKeyPairObjects(t, first, session)

	encHandle, ciphertext, err := first.EncapsulateKey(session,
		&Mechanism{Type: CKM_VENDOR_ML_KEM_768_ENCAPSULATE}, pub,
		storableSharedSecretTemplate(encapsulatedLabel))
	require.NoError(t, err)
	require.NotEmpty(t, ciphertext)

	decHandle, err := first.DecapsulateKey(session,
		&Mechanism{Type: CKM_VENDOR_ML_KEM_768_DECAPSULATE}, priv,
		storableSharedSecretTemplate(decapsulatedLabel), ciphertext)
	require.NoError(t, err)

	sharedSecret := sharedSecretValue(t, first, session, encHandle)
	require.NotEmpty(t, sharedSecret)
	require.Equal(t, sharedSecret, sharedSecretValue(t, first, session, decHandle),
		"the two halves must agree before the restart, or the restart proves nothing")
	require.Equal(t, CKR_OK, first.Finalize())

	second := newPersistentModule(t, dir)
	defer second.Finalize()
	restored := loginAsNormalUser(t, second)

	for _, label := range []string{encapsulatedLabel, decapsulatedLabel} {
		handles := findObjectByLabel(t, second, restored, label)
		require.Len(t, handles, 1, "%s must still be on the token after the restart", label)
		assert.Equal(t, sharedSecret, sharedSecretValue(t, second, restored, handles[0]),
			"%s must come back with the shared secret itself, not an empty key-shaped shell", label)
	}
}

// sharedSecretValue reads CKA_VALUE off a shared secret object.
func sharedSecretValue(t *testing.T, m *Module, session SessionHandle, handle ObjectHandle) []byte {
	t.Helper()

	attrs, rv := m.GetAttributeValue(session, handle, []Attribute{{Type: CKA_VALUE}})
	require.Equal(t, CKR_OK, rv)

	value := findAttr(attrs, CKA_VALUE)
	require.NotNil(t, value)

	return value.Value
}

// TestKEMRefusesUnstorableTokenSharedSecret proves both KEM verbs refuse a
// CKA_TOKEN shared secret they could not give back after a restart, rather than
// persisting a key-shaped shell with no key in it.
//
// A shared secret has no KeyID and no backend copy: its only material is
// CKA_VALUE on the object, and SaveObject withholds CKA_VALUE from a key object
// that protects its material because the token store is a plaintext file. Asking
// for CKA_TOKEN together with CKA_SENSITIVE=CK_TRUE — or with
// CKA_EXTRACTABLE=CK_FALSE — therefore asks this token both to keep a key and to
// protect its only copy of it, which is what CKR_TEMPLATE_INCONSISTENT names.
// Refusing at the point the request is made is the only place the application
// can still act on it; every later failure is a handle it already believes is a
// key.
func TestKEMRefusesUnstorableTokenSharedSecret(t *testing.T) {
	protectionCases := []struct {
		name       string
		protection []Attribute
	}{
		{
			name: "CKA_SENSITIVE withholds the only copy",
			protection: []Attribute{
				NewBoolAttribute(CKA_SENSITIVE, true),
				NewBoolAttribute(CKA_EXTRACTABLE, true),
			},
		},
		{
			name: "CKA_EXTRACTABLE=CK_FALSE withholds the only copy",
			protection: []Attribute{
				NewBoolAttribute(CKA_SENSITIVE, false),
				NewBoolAttribute(CKA_EXTRACTABLE, false),
			},
		},
	}

	for _, tc := range protectionCases {
		t.Run(tc.name, func(t *testing.T) {
			m := initializeTestModule(t)
			defer m.Finalize()
			session := loginAsNormalUser(t, m)
			pub, priv := createKEMKeyPairObjects(t, m, session)

			template := append([]Attribute{
				NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
				NewStringAttribute(CKA_LABEL, "unstorable-shared-secret"),
				NewBoolAttribute(CKA_TOKEN, true),
			}, tc.protection...)

			handle, ciphertext, err := m.EncapsulateKey(session,
				&Mechanism{Type: CKM_VENDOR_ML_KEM_768_ENCAPSULATE}, pub, template)
			var pkcsErr *PKCS11Error
			require.ErrorAs(t, err, &pkcsErr)
			assert.Equal(t, CKR_TEMPLATE_INCONSISTENT, pkcsErr.Code)
			assert.Equal(t, ObjectHandle(InvalidHandle), handle)
			assert.Nil(t, ciphertext,
				"a refused encapsulation must hand back no ciphertext: one released to the peer commits to a shared secret this token then discards")

			// The decapsulator is given a real ciphertext, so the only thing
			// that can refuse it is the template itself.
			_, realCiphertext, err := m.EncapsulateKey(session,
				&Mechanism{Type: CKM_VENDOR_ML_KEM_768_ENCAPSULATE}, pub,
				storableSharedSecretTemplate("storable-companion"))
			require.NoError(t, err)

			handle, err = m.DecapsulateKey(session,
				&Mechanism{Type: CKM_VENDOR_ML_KEM_768_DECAPSULATE}, priv, template, realCiphertext)
			require.ErrorAs(t, err, &pkcsErr)
			assert.Equal(t, CKR_TEMPLATE_INCONSISTENT, pkcsErr.Code)
			assert.Equal(t, ObjectHandle(InvalidHandle), handle)
		})
	}

	// The refusal is about persistence, so it must not reach a shared secret
	// that was never going to be persisted. A session object holds its material
	// in memory for as long as it exists and nothing is withheld from it, which
	// is the ordinary way to take a KEM shared secret: refusing it would break
	// the protective template every caller should be using.
	t.Run("a protected session shared secret is still allowed", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()
		session := loginAsNormalUser(t, m)
		pub, priv := createKEMKeyPairObjects(t, m, session)

		template := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewStringAttribute(CKA_LABEL, "protected-session-shared-secret"),
			NewBoolAttribute(CKA_TOKEN, false),
			NewBoolAttribute(CKA_SENSITIVE, true),
			NewBoolAttribute(CKA_EXTRACTABLE, false),
		}

		encHandle, ciphertext, err := m.EncapsulateKey(session,
			&Mechanism{Type: CKM_VENDOR_ML_KEM_768_ENCAPSULATE}, pub, template)
		require.NoError(t, err, "a sensitive session shared secret is storable nowhere and needs to be")
		assert.NotEqual(t, ObjectHandle(InvalidHandle), encHandle)

		decHandle, err := m.DecapsulateKey(session,
			&Mechanism{Type: CKM_VENDOR_ML_KEM_768_DECAPSULATE}, priv, template, ciphertext)
		require.NoError(t, err)
		assert.NotEqual(t, ObjectHandle(InvalidHandle), decHandle)
	})
}

// TestKEMTokenSharedSecretRejectedByStore proves a storable token shared secret
// the store nevertheless refuses is reported as CKR_DEVICE_ERROR and left
// nowhere, rather than handed back as a handle to an object that does not exist
// on the token.
func TestKEMTokenSharedSecretRejectedByStore(t *testing.T) {
	const label = "kem-secret-under-rejecting-store"

	m := newRejectingStoreModule(t, 0)
	defer m.Finalize()
	session := loginAsNormalUser(t, m)
	pub, priv := createKEMKeyPairObjects(t, m, session)

	handle, ciphertext, err := m.EncapsulateKey(session,
		&Mechanism{Type: CKM_VENDOR_ML_KEM_768_ENCAPSULATE}, pub,
		storableSharedSecretTemplate(label))
	var pkcsErr *PKCS11Error
	require.ErrorAs(t, err, &pkcsErr)
	assert.Equal(t, CKR_DEVICE_ERROR, pkcsErr.Code)
	assert.Equal(t, ObjectHandle(InvalidHandle), handle)
	assert.Nil(t, ciphertext)
	assert.ErrorIs(t, m.LastStorageError(), errObjectWriteRejected)
	assert.Empty(t, findObjectByLabel(t, m, session, label),
		"a shared secret the caller was told was not created must not be findable")

	// A real ciphertext, so only the store can be what fails the decapsulation.
	sessionTemplate := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewStringAttribute(CKA_LABEL, "kem-session-companion"),
		NewBoolAttribute(CKA_TOKEN, false),
	}
	_, realCiphertext, err := m.EncapsulateKey(session,
		&Mechanism{Type: CKM_VENDOR_ML_KEM_768_ENCAPSULATE}, pub, sessionTemplate)
	require.NoError(t, err, "a session shared secret must be unaffected by a store that refuses object writes")

	handle, err = m.DecapsulateKey(session,
		&Mechanism{Type: CKM_VENDOR_ML_KEM_768_DECAPSULATE}, priv,
		storableSharedSecretTemplate(label), realCiphertext)
	require.ErrorAs(t, err, &pkcsErr)
	assert.Equal(t, CKR_DEVICE_ERROR, pkcsErr.Code)
	assert.Equal(t, ObjectHandle(InvalidHandle), handle)
	assert.Empty(t, findObjectByLabel(t, m, session, label))
}
