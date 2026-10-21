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
	"encoding/binary"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupTestModuleWithKey creates an initialized module with a test key object.
// Returns the module, session handle, and key handle.
func setupTestModuleWithKey(t *testing.T) (*Module, SessionHandle, ObjectHandle) {
	t.Helper()
	m := initializeTestModule(t)

	// Open a session
	// The token sets CKF_LOGIN_REQUIRED at creation, so key-bearing operations
	// are refused until the session authenticates.
	sessionHandle := loginAsNormalUser(t, m)

	// Create a test key object
	keyTemplate := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewStringAttribute(CKA_LABEL, "test-key"),
		NewAttribute(CKA_VALUE, []byte("0123456789ABCDEF")), // 16 bytes for AES-128
		NewBoolAttribute(CKA_ENCRYPT, true),
		NewBoolAttribute(CKA_DECRYPT, true),
		NewBoolAttribute(CKA_SIGN, true),
		NewBoolAttribute(CKA_VERIFY, true),
		NewBoolAttribute(CKA_EXTRACTABLE, true),
		NewBoolAttribute(CKA_WRAP, true),
		NewBoolAttribute(CKA_UNWRAP, true),
	}

	keyHandle, rv := m.CreateObject(sessionHandle, keyTemplate)
	require.Equal(t, CKR_OK, rv, "CreateObject should succeed")

	// Set the key metadata in the object
	obj, err := m.objectManager.getObjectUnchecked(keyHandle)
	require.NoError(t, err)
	obj.KeyID = "test-key-id"
	obj.BackendName = "default"

	return m, sessionHandle, keyHandle
}

// setupTestModuleWithRSAKey creates an initialized module with a test RSA key object.
func setupTestModuleWithRSAKey(t *testing.T) (*Module, SessionHandle, ObjectHandle) {
	t.Helper()
	m := initializeTestModule(t)

	// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
	// authenticates before exercising them.
	sessionHandle := loginAsNormalUser(t, m)

	keyTemplate := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_PRIVATE_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_RSA)),
		NewStringAttribute(CKA_LABEL, "test-rsa-key"),
		NewBoolAttribute(CKA_SIGN, true),
		NewBoolAttribute(CKA_VERIFY, true),
	}

	keyHandle, rv := m.CreateObject(sessionHandle, keyTemplate)
	require.Equal(t, CKR_OK, rv)

	obj, err := m.objectManager.getObjectUnchecked(keyHandle)
	require.NoError(t, err)
	obj.KeyID = "test-rsa-key-id"
	obj.BackendName = "default"

	return m, sessionHandle, keyHandle
}

// ----------------------------------------------------------------------------
// SignUpdate / SignFinal Tests
// ----------------------------------------------------------------------------

func TestModule_SignUpdate_Success(t *testing.T) {
	m, sessionHandle, keyHandle := setupTestModuleWithRSAKey(t)
	defer m.Finalize()

	mechanism := &Mechanism{Type: CKM_SHA256_RSA_PKCS}

	// Initialize signing
	rv := m.SignInit(sessionHandle, mechanism, keyHandle)
	require.Equal(t, CKR_OK, rv, "SignInit should succeed")

	// SignUpdate with first part
	rv = m.SignUpdate(sessionHandle, []byte("first part"))
	assert.Equal(t, CKR_OK, rv, "SignUpdate should succeed for first part")

	// SignUpdate with second part
	rv = m.SignUpdate(sessionHandle, []byte(" second part"))
	assert.Equal(t, CKR_OK, rv, "SignUpdate should succeed for second part")

	// SignFinal
	signature, rv := m.SignFinal(sessionHandle)
	assert.Equal(t, CKR_OK, rv, "SignFinal should succeed")
	assert.NotEmpty(t, signature, "signature should not be empty")
}

func TestModule_SignUpdate_NotInitialized(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()

	// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
	// authenticates before exercising them.
	sessionHandle := loginAsNormalUser(t, m)

	// SignUpdate without SignInit
	rv := m.SignUpdate(sessionHandle, []byte("data"))
	assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, rv, "SignUpdate should fail without SignInit")
}

func TestModule_SignUpdate_InvalidSession(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()

	// SignUpdate with invalid session handle
	rv := m.SignUpdate(SessionHandle(99999), []byte("data"))
	assert.Equal(t, CKR_SESSION_HANDLE_INVALID, rv, "SignUpdate should fail with invalid session")
}

func TestModule_SignUpdate_ModuleNotInitialized(t *testing.T) {
	m := createTestModule(t)

	// SignUpdate without module initialization
	rv := m.SignUpdate(SessionHandle(1), []byte("data"))
	assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv, "SignUpdate should fail when module not initialized")
}

func TestModule_SignFinal_NotInitialized(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()

	// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
	// authenticates before exercising them.
	sessionHandle := loginAsNormalUser(t, m)

	// SignFinal without SignInit
	_, rv := m.SignFinal(sessionHandle)
	assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, rv, "SignFinal should fail without SignInit")
}

func TestModule_SignFinal_InvalidSession(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()

	// SignFinal with invalid session handle
	_, rv := m.SignFinal(SessionHandle(99999))
	assert.Equal(t, CKR_SESSION_HANDLE_INVALID, rv, "SignFinal should fail with invalid session")
}

func TestModule_SignFinal_ModuleNotInitialized(t *testing.T) {
	m := createTestModule(t)

	// SignFinal without module initialization
	_, rv := m.SignFinal(SessionHandle(1))
	assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv, "SignFinal should fail when module not initialized")
}

func TestModule_SignUpdate_WrongOperationType(t *testing.T) {
	m, sessionHandle, keyHandle := setupTestModuleWithKey(t)
	defer m.Finalize()

	// Initialize encryption instead of signing
	mechanism := NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(testGCMIV(), 128))
	rv := m.EncryptInit(sessionHandle, mechanism, keyHandle)
	require.Equal(t, CKR_OK, rv)

	// Try SignUpdate - should fail because encrypt op is active, not sign
	rv = m.SignUpdate(sessionHandle, []byte("data"))
	assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, rv, "SignUpdate should fail with wrong operation type")
}

func TestModule_SignFinal_WrongOperationType(t *testing.T) {
	m, sessionHandle, keyHandle := setupTestModuleWithKey(t)
	defer m.Finalize()

	// Initialize encryption instead of signing
	mechanism := NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(testGCMIV(), 128))
	rv := m.EncryptInit(sessionHandle, mechanism, keyHandle)
	require.Equal(t, CKR_OK, rv)

	// Try SignFinal - should fail because encrypt op is active, not sign
	_, rv = m.SignFinal(sessionHandle)
	assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, rv, "SignFinal should fail with wrong operation type")
}

func TestModule_SignUpdate_EmptyData(t *testing.T) {
	m, sessionHandle, keyHandle := setupTestModuleWithRSAKey(t)
	defer m.Finalize()

	mechanism := &Mechanism{Type: CKM_SHA256_RSA_PKCS}
	rv := m.SignInit(sessionHandle, mechanism, keyHandle)
	require.Equal(t, CKR_OK, rv)

	// SignUpdate with empty data should succeed
	rv = m.SignUpdate(sessionHandle, []byte{})
	assert.Equal(t, CKR_OK, rv, "SignUpdate with empty data should succeed")

	// SignUpdate with nil data should succeed
	rv = m.SignUpdate(sessionHandle, nil)
	assert.Equal(t, CKR_OK, rv, "SignUpdate with nil data should succeed")

	// Finalize should still work
	signature, rv := m.SignFinal(sessionHandle)
	assert.Equal(t, CKR_OK, rv, "SignFinal should succeed")
	assert.NotEmpty(t, signature, "signature should not be empty")
}

// ----------------------------------------------------------------------------
// VerifyUpdate / VerifyFinal Tests
// ----------------------------------------------------------------------------

func TestModule_VerifyUpdate_Success(t *testing.T) {
	m, sessionHandle, keyHandle := setupTestModuleWithRSAKey(t)
	defer m.Finalize()

	mechanism := &Mechanism{Type: CKM_SHA256_RSA_PKCS}

	// Initialize verification
	rv := m.VerifyInit(sessionHandle, mechanism, keyHandle)
	require.Equal(t, CKR_OK, rv, "VerifyInit should succeed")

	// VerifyUpdate with first part
	rv = m.VerifyUpdate(sessionHandle, []byte("first part"))
	assert.Equal(t, CKR_OK, rv, "VerifyUpdate should succeed for first part")

	// VerifyUpdate with second part
	rv = m.VerifyUpdate(sessionHandle, []byte(" second part"))
	assert.Equal(t, CKR_OK, rv, "VerifyUpdate should succeed for second part")

	// VerifyFinal - will fail with invalid signature but should process correctly
	rv = m.VerifyFinal(sessionHandle, []byte("mock-signature"))
	// The mock client returns valid=true, so this should succeed
	assert.Equal(t, CKR_OK, rv, "VerifyFinal should succeed with mock client")
}

func TestModule_VerifyUpdate_NotInitialized(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()

	// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
	// authenticates before exercising them.
	sessionHandle := loginAsNormalUser(t, m)

	// VerifyUpdate without VerifyInit
	rv := m.VerifyUpdate(sessionHandle, []byte("data"))
	assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, rv, "VerifyUpdate should fail without VerifyInit")
}

func TestModule_VerifyUpdate_InvalidSession(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()

	// VerifyUpdate with invalid session handle
	rv := m.VerifyUpdate(SessionHandle(99999), []byte("data"))
	assert.Equal(t, CKR_SESSION_HANDLE_INVALID, rv, "VerifyUpdate should fail with invalid session")
}

func TestModule_VerifyUpdate_ModuleNotInitialized(t *testing.T) {
	m := createTestModule(t)

	// VerifyUpdate without module initialization
	rv := m.VerifyUpdate(SessionHandle(1), []byte("data"))
	assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv, "VerifyUpdate should fail when module not initialized")
}

func TestModule_VerifyFinal_NotInitialized(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()

	// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
	// authenticates before exercising them.
	sessionHandle := loginAsNormalUser(t, m)

	// VerifyFinal without VerifyInit
	rv := m.VerifyFinal(sessionHandle, []byte("signature"))
	assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, rv, "VerifyFinal should fail without VerifyInit")
}

func TestModule_VerifyFinal_InvalidSession(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()

	// VerifyFinal with invalid session handle
	rv := m.VerifyFinal(SessionHandle(99999), []byte("signature"))
	assert.Equal(t, CKR_SESSION_HANDLE_INVALID, rv, "VerifyFinal should fail with invalid session")
}

func TestModule_VerifyFinal_ModuleNotInitialized(t *testing.T) {
	m := createTestModule(t)

	// VerifyFinal without module initialization
	rv := m.VerifyFinal(SessionHandle(1), []byte("signature"))
	assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv, "VerifyFinal should fail when module not initialized")
}

func TestModule_VerifyUpdate_WrongOperationType(t *testing.T) {
	m, sessionHandle, keyHandle := setupTestModuleWithRSAKey(t)
	defer m.Finalize()

	// Initialize signing instead of verification
	mechanism := &Mechanism{Type: CKM_SHA256_RSA_PKCS}
	rv := m.SignInit(sessionHandle, mechanism, keyHandle)
	require.Equal(t, CKR_OK, rv)

	// Try VerifyUpdate - should fail because sign op is active, not verify
	rv = m.VerifyUpdate(sessionHandle, []byte("data"))
	assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, rv, "VerifyUpdate should fail with wrong operation type")
}

func TestModule_VerifyFinal_WrongOperationType(t *testing.T) {
	m, sessionHandle, keyHandle := setupTestModuleWithRSAKey(t)
	defer m.Finalize()

	// Initialize signing instead of verification
	mechanism := &Mechanism{Type: CKM_SHA256_RSA_PKCS}
	rv := m.SignInit(sessionHandle, mechanism, keyHandle)
	require.Equal(t, CKR_OK, rv)

	// Try VerifyFinal - should fail because sign op is active, not verify
	rv = m.VerifyFinal(sessionHandle, []byte("signature"))
	assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, rv, "VerifyFinal should fail with wrong operation type")
}

func TestModule_VerifyUpdate_EmptyData(t *testing.T) {
	m, sessionHandle, keyHandle := setupTestModuleWithRSAKey(t)
	defer m.Finalize()

	mechanism := &Mechanism{Type: CKM_SHA256_RSA_PKCS}
	rv := m.VerifyInit(sessionHandle, mechanism, keyHandle)
	require.Equal(t, CKR_OK, rv)

	// VerifyUpdate with empty data should succeed
	rv = m.VerifyUpdate(sessionHandle, []byte{})
	assert.Equal(t, CKR_OK, rv, "VerifyUpdate with empty data should succeed")

	// VerifyUpdate with nil data should succeed
	rv = m.VerifyUpdate(sessionHandle, nil)
	assert.Equal(t, CKR_OK, rv, "VerifyUpdate with nil data should succeed")

	// VerifyFinal should still work
	rv = m.VerifyFinal(sessionHandle, []byte("mock-signature"))
	assert.Equal(t, CKR_OK, rv, "VerifyFinal should succeed")
}

// ----------------------------------------------------------------------------
// EncryptUpdate / EncryptFinal Tests
// ----------------------------------------------------------------------------

func TestModule_EncryptUpdate_Success(t *testing.T) {
	m, sessionHandle, keyHandle := setupTestModuleWithKey(t)
	defer m.Finalize()

	mechanism := NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(testGCMIV(), 128))

	// Initialize encryption
	rv := m.EncryptInit(sessionHandle, mechanism, keyHandle)
	require.Equal(t, CKR_OK, rv, "EncryptInit should succeed")

	// EncryptUpdate with first part
	_, rv = m.EncryptUpdate(sessionHandle, []byte("first part"))
	assert.Equal(t, CKR_OK, rv, "EncryptUpdate should succeed for first part")

	// EncryptUpdate with second part
	_, rv = m.EncryptUpdate(sessionHandle, []byte(" second part"))
	assert.Equal(t, CKR_OK, rv, "EncryptUpdate should succeed for second part")

	// EncryptFinal
	ciphertext, rv := m.EncryptFinal(sessionHandle)
	assert.Equal(t, CKR_OK, rv, "EncryptFinal should succeed")
	assert.NotNil(t, ciphertext, "ciphertext should not be nil")
}

func TestModule_EncryptUpdate_NotInitialized(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()

	// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
	// authenticates before exercising them.
	sessionHandle := loginAsNormalUser(t, m)

	// EncryptUpdate without EncryptInit
	_, rv := m.EncryptUpdate(sessionHandle, []byte("data"))
	assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, rv, "EncryptUpdate should fail without EncryptInit")
}

func TestModule_EncryptUpdate_InvalidSession(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()

	// EncryptUpdate with invalid session handle
	_, rv := m.EncryptUpdate(SessionHandle(99999), []byte("data"))
	assert.Equal(t, CKR_SESSION_HANDLE_INVALID, rv, "EncryptUpdate should fail with invalid session")
}

func TestModule_EncryptUpdate_ModuleNotInitialized(t *testing.T) {
	m := createTestModule(t)

	// EncryptUpdate without module initialization
	_, rv := m.EncryptUpdate(SessionHandle(1), []byte("data"))
	assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv, "EncryptUpdate should fail when module not initialized")
}

func TestModule_EncryptFinal_NotInitialized(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()

	// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
	// authenticates before exercising them.
	sessionHandle := loginAsNormalUser(t, m)

	// EncryptFinal without EncryptInit
	_, rv := m.EncryptFinal(sessionHandle)
	assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, rv, "EncryptFinal should fail without EncryptInit")
}

func TestModule_EncryptFinal_InvalidSession(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()

	// EncryptFinal with invalid session handle
	_, rv := m.EncryptFinal(SessionHandle(99999))
	assert.Equal(t, CKR_SESSION_HANDLE_INVALID, rv, "EncryptFinal should fail with invalid session")
}

func TestModule_EncryptFinal_ModuleNotInitialized(t *testing.T) {
	m := createTestModule(t)

	// EncryptFinal without module initialization
	_, rv := m.EncryptFinal(SessionHandle(1))
	assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv, "EncryptFinal should fail when module not initialized")
}

func TestModule_EncryptUpdate_WrongOperationType(t *testing.T) {
	m, sessionHandle, keyHandle := setupTestModuleWithKey(t)
	defer m.Finalize()

	// Initialize decryption instead of encryption
	mechanism := NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(testGCMIV(), 128))
	rv := m.DecryptInit(sessionHandle, mechanism, keyHandle)
	require.Equal(t, CKR_OK, rv)

	// Try EncryptUpdate - should fail because decrypt op is active
	_, rv = m.EncryptUpdate(sessionHandle, []byte("data"))
	assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, rv, "EncryptUpdate should fail with wrong operation type")
}

func TestModule_EncryptFinal_WrongOperationType(t *testing.T) {
	m, sessionHandle, keyHandle := setupTestModuleWithKey(t)
	defer m.Finalize()

	// Initialize decryption instead of encryption
	mechanism := NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(testGCMIV(), 128))
	rv := m.DecryptInit(sessionHandle, mechanism, keyHandle)
	require.Equal(t, CKR_OK, rv)

	// Try EncryptFinal - should fail because decrypt op is active
	_, rv = m.EncryptFinal(sessionHandle)
	assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, rv, "EncryptFinal should fail with wrong operation type")
}

func TestModule_EncryptUpdate_EmptyData(t *testing.T) {
	m, sessionHandle, keyHandle := setupTestModuleWithKey(t)
	defer m.Finalize()

	mechanism := NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(testGCMIV(), 128))
	rv := m.EncryptInit(sessionHandle, mechanism, keyHandle)
	require.Equal(t, CKR_OK, rv)

	// EncryptUpdate with empty data should succeed
	_, rv = m.EncryptUpdate(sessionHandle, []byte{})
	assert.Equal(t, CKR_OK, rv, "EncryptUpdate with empty data should succeed")

	// EncryptUpdate with nil data should succeed
	_, rv = m.EncryptUpdate(sessionHandle, nil)
	assert.Equal(t, CKR_OK, rv, "EncryptUpdate with nil data should succeed")

	// EncryptFinal should still work
	ciphertext, rv := m.EncryptFinal(sessionHandle)
	assert.Equal(t, CKR_OK, rv, "EncryptFinal should succeed")
	assert.NotNil(t, ciphertext, "ciphertext should not be nil")
}

// ----------------------------------------------------------------------------
// DecryptUpdate / DecryptFinal Tests
// ----------------------------------------------------------------------------

func TestModule_DecryptUpdate_Success(t *testing.T) {
	m, sessionHandle, keyHandle := setupTestModuleWithKey(t)
	defer m.Finalize()

	mechanism := NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(testGCMIV(), 128))

	// Initialize decryption
	rv := m.DecryptInit(sessionHandle, mechanism, keyHandle)
	require.Equal(t, CKR_OK, rv, "DecryptInit should succeed")

	// DecryptUpdate with first part
	_, rv = m.DecryptUpdate(sessionHandle, []byte("encrypted1"))
	assert.Equal(t, CKR_OK, rv, "DecryptUpdate should succeed for first part")

	// DecryptUpdate with second part
	_, rv = m.DecryptUpdate(sessionHandle, []byte("encrypted2"))
	assert.Equal(t, CKR_OK, rv, "DecryptUpdate should succeed for second part")

	// DecryptFinal
	plaintext, rv := m.DecryptFinal(sessionHandle)
	assert.Equal(t, CKR_OK, rv, "DecryptFinal should succeed")
	assert.NotNil(t, plaintext, "plaintext should not be nil")
}

func TestModule_DecryptUpdate_NotInitialized(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()

	// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
	// authenticates before exercising them.
	sessionHandle := loginAsNormalUser(t, m)

	// DecryptUpdate without DecryptInit
	_, rv := m.DecryptUpdate(sessionHandle, []byte("data"))
	assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, rv, "DecryptUpdate should fail without DecryptInit")
}

func TestModule_DecryptUpdate_InvalidSession(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()

	// DecryptUpdate with invalid session handle
	_, rv := m.DecryptUpdate(SessionHandle(99999), []byte("data"))
	assert.Equal(t, CKR_SESSION_HANDLE_INVALID, rv, "DecryptUpdate should fail with invalid session")
}

func TestModule_DecryptUpdate_ModuleNotInitialized(t *testing.T) {
	m := createTestModule(t)

	// DecryptUpdate without module initialization
	_, rv := m.DecryptUpdate(SessionHandle(1), []byte("data"))
	assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv, "DecryptUpdate should fail when module not initialized")
}

func TestModule_DecryptFinal_NotInitialized(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()

	// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
	// authenticates before exercising them.
	sessionHandle := loginAsNormalUser(t, m)

	// DecryptFinal without DecryptInit
	_, rv := m.DecryptFinal(sessionHandle)
	assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, rv, "DecryptFinal should fail without DecryptInit")
}

func TestModule_DecryptFinal_InvalidSession(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()

	// DecryptFinal with invalid session handle
	_, rv := m.DecryptFinal(SessionHandle(99999))
	assert.Equal(t, CKR_SESSION_HANDLE_INVALID, rv, "DecryptFinal should fail with invalid session")
}

func TestModule_DecryptFinal_ModuleNotInitialized(t *testing.T) {
	m := createTestModule(t)

	// DecryptFinal without module initialization
	_, rv := m.DecryptFinal(SessionHandle(1))
	assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv, "DecryptFinal should fail when module not initialized")
}

func TestModule_DecryptUpdate_WrongOperationType(t *testing.T) {
	m, sessionHandle, keyHandle := setupTestModuleWithKey(t)
	defer m.Finalize()

	// Initialize encryption instead of decryption
	mechanism := NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(testGCMIV(), 128))
	rv := m.EncryptInit(sessionHandle, mechanism, keyHandle)
	require.Equal(t, CKR_OK, rv)

	// Try DecryptUpdate - should fail because encrypt op is active
	_, rv = m.DecryptUpdate(sessionHandle, []byte("data"))
	assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, rv, "DecryptUpdate should fail with wrong operation type")
}

func TestModule_DecryptFinal_WrongOperationType(t *testing.T) {
	m, sessionHandle, keyHandle := setupTestModuleWithKey(t)
	defer m.Finalize()

	// Initialize encryption instead of decryption
	mechanism := NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(testGCMIV(), 128))
	rv := m.EncryptInit(sessionHandle, mechanism, keyHandle)
	require.Equal(t, CKR_OK, rv)

	// Try DecryptFinal - should fail because encrypt op is active
	_, rv = m.DecryptFinal(sessionHandle)
	assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, rv, "DecryptFinal should fail with wrong operation type")
}

func TestModule_DecryptUpdate_EmptyData(t *testing.T) {
	m, sessionHandle, keyHandle := setupTestModuleWithKey(t)
	defer m.Finalize()

	mechanism := NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(testGCMIV(), 128))
	rv := m.DecryptInit(sessionHandle, mechanism, keyHandle)
	require.Equal(t, CKR_OK, rv)

	// DecryptUpdate with empty data should succeed
	_, rv = m.DecryptUpdate(sessionHandle, []byte{})
	assert.Equal(t, CKR_OK, rv, "DecryptUpdate with empty data should succeed")

	// DecryptUpdate with nil data should succeed
	_, rv = m.DecryptUpdate(sessionHandle, nil)
	assert.Equal(t, CKR_OK, rv, "DecryptUpdate with nil data should succeed")

	// With nothing buffered there is no AES-GCM tag to authenticate, and a
	// ciphertext shorter than the tag cannot be valid (v3.2 6.13.7).
	_, rv = m.DecryptFinal(sessionHandle)
	assert.Equal(t, CKR_ENCRYPTED_DATA_LEN_RANGE, rv,
		"DecryptFinal should reject a buffer too short to hold a GCM tag")
}

// ----------------------------------------------------------------------------
// DigestUpdate / DigestFinal Tests
// ----------------------------------------------------------------------------

func TestModule_DigestUpdate_Success(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()

	// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
	// authenticates before exercising them.
	sessionHandle := loginAsNormalUser(t, m)

	mechanism := &Mechanism{Type: CKM_SHA256}

	// Initialize digest
	rv := m.DigestInit(sessionHandle, mechanism)
	require.Equal(t, CKR_OK, rv, "DigestInit should succeed")

	// DigestUpdate with first part
	rv = m.DigestUpdate(sessionHandle, []byte("first part"))
	assert.Equal(t, CKR_OK, rv, "DigestUpdate should succeed for first part")

	// DigestUpdate with second part
	rv = m.DigestUpdate(sessionHandle, []byte(" second part"))
	assert.Equal(t, CKR_OK, rv, "DigestUpdate should succeed for second part")

	// DigestFinal
	hash, rv := m.DigestFinal(sessionHandle)
	assert.Equal(t, CKR_OK, rv, "DigestFinal should succeed")
	assert.Len(t, hash, 32, "SHA-256 should produce 32-byte hash")
}

func TestModule_DigestUpdate_NotInitialized(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()

	// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
	// authenticates before exercising them.
	sessionHandle := loginAsNormalUser(t, m)

	// DigestUpdate without DigestInit
	rv := m.DigestUpdate(sessionHandle, []byte("data"))
	assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, rv, "DigestUpdate should fail without DigestInit")
}

func TestModule_DigestUpdate_InvalidSession(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()

	// DigestUpdate with invalid session handle
	rv := m.DigestUpdate(SessionHandle(99999), []byte("data"))
	assert.Equal(t, CKR_SESSION_HANDLE_INVALID, rv, "DigestUpdate should fail with invalid session")
}

func TestModule_DigestUpdate_ModuleNotInitialized(t *testing.T) {
	m := createTestModule(t)

	// DigestUpdate without module initialization
	rv := m.DigestUpdate(SessionHandle(1), []byte("data"))
	assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv, "DigestUpdate should fail when module not initialized")
}

func TestModule_DigestFinal_NotInitialized(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()

	// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
	// authenticates before exercising them.
	sessionHandle := loginAsNormalUser(t, m)

	// DigestFinal without DigestInit
	_, rv := m.DigestFinal(sessionHandle)
	assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, rv, "DigestFinal should fail without DigestInit")
}

func TestModule_DigestFinal_InvalidSession(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()

	// DigestFinal with invalid session handle
	_, rv := m.DigestFinal(SessionHandle(99999))
	assert.Equal(t, CKR_SESSION_HANDLE_INVALID, rv, "DigestFinal should fail with invalid session")
}

func TestModule_DigestFinal_ModuleNotInitialized(t *testing.T) {
	m := createTestModule(t)

	// DigestFinal without module initialization
	_, rv := m.DigestFinal(SessionHandle(1))
	assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv, "DigestFinal should fail when module not initialized")
}

func TestModule_DigestUpdate_WrongOperationType(t *testing.T) {
	m, sessionHandle, keyHandle := setupTestModuleWithKey(t)
	defer m.Finalize()

	// Initialize encryption instead of digest
	mechanism := NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(testGCMIV(), 128))
	rv := m.EncryptInit(sessionHandle, mechanism, keyHandle)
	require.Equal(t, CKR_OK, rv)

	// Try DigestUpdate - should fail because encrypt op is active
	rv = m.DigestUpdate(sessionHandle, []byte("data"))
	assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, rv, "DigestUpdate should fail with wrong operation type")
}

func TestModule_DigestFinal_WrongOperationType(t *testing.T) {
	m, sessionHandle, keyHandle := setupTestModuleWithKey(t)
	defer m.Finalize()

	// Initialize encryption instead of digest
	mechanism := NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(testGCMIV(), 128))
	rv := m.EncryptInit(sessionHandle, mechanism, keyHandle)
	require.Equal(t, CKR_OK, rv)

	// Try DigestFinal - should fail because encrypt op is active
	_, rv = m.DigestFinal(sessionHandle)
	assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, rv, "DigestFinal should fail with wrong operation type")
}

func TestModule_DigestFinal_MultipleChunks(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()

	// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
	// authenticates before exercising them.
	sessionHandle := loginAsNormalUser(t, m)

	// Test multiple hash algorithms
	algorithms := []MechanismType{CKM_SHA256, CKM_SHA384, CKM_SHA512}
	expectedLengths := []int{32, 48, 64}

	for i, algo := range algorithms {
		mechanism := &Mechanism{Type: algo}

		rv := m.DigestInit(sessionHandle, mechanism)
		require.Equal(t, CKR_OK, rv)

		// Add data in multiple chunks
		for j := 0; j < 5; j++ {
			rv = m.DigestUpdate(sessionHandle, []byte("chunk data "))
			require.Equal(t, CKR_OK, rv)
		}

		hash, rv := m.DigestFinal(sessionHandle)
		assert.Equal(t, CKR_OK, rv)
		assert.Len(t, hash, expectedLengths[i], "hash length should match expected for algorithm")

		// The digest stays active until the caller confirms it received the
		// output, so the next DigestInit needs it terminated first.
		require.Equal(t, CKR_OK, m.FinishOperation(sessionHandle, OperationDigest))
	}
}

func TestModule_DigestUpdate_EmptyData(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()

	// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
	// authenticates before exercising them.
	sessionHandle := loginAsNormalUser(t, m)

	mechanism := &Mechanism{Type: CKM_SHA256}
	rv := m.DigestInit(sessionHandle, mechanism)
	require.Equal(t, CKR_OK, rv)

	// DigestUpdate with empty data should succeed
	rv = m.DigestUpdate(sessionHandle, []byte{})
	assert.Equal(t, CKR_OK, rv, "DigestUpdate with empty data should succeed")

	// DigestUpdate with nil data should succeed
	rv = m.DigestUpdate(sessionHandle, nil)
	assert.Equal(t, CKR_OK, rv, "DigestUpdate with nil data should succeed")

	// DigestFinal should still produce a hash (of empty input)
	hash, rv := m.DigestFinal(sessionHandle)
	assert.Equal(t, CKR_OK, rv, "DigestFinal should succeed")
	assert.Len(t, hash, 32, "SHA-256 should produce 32-byte hash")
}

// ----------------------------------------------------------------------------
// WrapKey / UnwrapKey Tests
// ----------------------------------------------------------------------------

// TestModule_WrapKey_Success proves C_WrapKey emits a blob that recovers the
// original key bytes, rather than merely returning CKR_OK and some bytes.
//
// It used to assert only CKR_OK and a non-empty slice, which holds for any
// non-empty byte slice at all -- including the AES-GCM blob this module
// actually produced, whose token-generated nonce was discarded, so nothing
// could ever unwrap it. The round trip is the assertion that had been missing:
// see module_wrapframing_test.go for the same proof across every mechanism.
func TestModule_WrapKey_Success(t *testing.T) {
	value := []byte("SECRETKEYVALUE!!")
	m, oracle, sessionHandle, wrapKeyHandle, targetKeyHandle := newWrapRoundTripModule(t, value)
	defer m.Finalize()

	mechanism := NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(testGCMIV(), 128))
	if callerIVSealRefusedUnderFIPS(t, func() error {
		if _, rv := m.WrapKey(sessionHandle, mechanism, wrapKeyHandle, targetKeyHandle); rv != CKR_OK {
			return NewPKCS11Error(rv)
		}
		return nil
	}) {
		return
	}

	wrappedKey, rv := m.WrapKey(sessionHandle, mechanism, wrapKeyHandle, targetKeyHandle)
	require.Equal(t, CKR_OK, rv, "WrapKey should succeed")
	require.NotEmpty(t, wrappedKey, "wrapped key should not be empty")
	assert.NotEqual(t, value, wrappedKey, "the wrapped key must not be the plaintext")

	handle, rv := m.UnwrapKey(sessionHandle,
		NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(testGCMIV(), 128)),
		wrapKeyHandle, wrappedKey, unwrapTemplate())
	require.Equal(t, CKR_OK, rv, "the blob C_WrapKey produced must be one C_UnwrapKey can consume")
	require.NotEqual(t, ObjectHandle(InvalidHandle), handle)

	assert.Equal(t, value, oracle.unwrapped, "the round trip must recover the original key bytes")
}

func TestModule_WrapKey_InvalidWrappingKey(t *testing.T) {
	m, sessionHandle, targetKeyHandle := setupTestModuleWithKey(t)
	defer m.Finalize()

	mechanism := NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(testGCMIV(), 128))

	// WrapKey with invalid wrapping key handle
	_, rv := m.WrapKey(sessionHandle, mechanism, ObjectHandle(99999), targetKeyHandle)
	assert.Equal(t, CKR_WRAPPING_KEY_HANDLE_INVALID, rv, "WrapKey should fail with invalid wrapping key")
}

func TestModule_WrapKey_InvalidTargetKey(t *testing.T) {
	m, sessionHandle, wrapKeyHandle := setupTestModuleWithKey(t)
	defer m.Finalize()

	mechanism := NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(testGCMIV(), 128))

	// WrapKey with invalid target key handle
	_, rv := m.WrapKey(sessionHandle, mechanism, wrapKeyHandle, ObjectHandle(99999))
	assert.Equal(t, CKR_KEY_HANDLE_INVALID, rv, "WrapKey should fail with invalid target key")
}

func TestModule_WrapKey_KeyNotExtractable(t *testing.T) {
	m, sessionHandle, wrapKeyHandle := setupTestModuleWithKey(t)
	defer m.Finalize()

	// Create non-extractable key
	targetKeyTemplate := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewAttribute(CKA_VALUE, []byte("SECRETKEYVALUE!!")),
		NewBoolAttribute(CKA_EXTRACTABLE, false),
	}
	targetKeyHandle, rv := m.CreateObject(sessionHandle, targetKeyTemplate)
	require.Equal(t, CKR_OK, rv)

	mechanism := NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(testGCMIV(), 128))

	// WrapKey should fail because key is not extractable
	_, rv = m.WrapKey(sessionHandle, mechanism, wrapKeyHandle, targetKeyHandle)
	assert.Equal(t, CKR_KEY_UNEXTRACTABLE, rv, "WrapKey should fail for non-extractable key")
}

func TestModule_WrapKey_ModuleNotInitialized(t *testing.T) {
	m := createTestModule(t)

	mechanism := NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(testGCMIV(), 128))

	_, rv := m.WrapKey(SessionHandle(1), mechanism, ObjectHandle(1), ObjectHandle(2))
	assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv, "WrapKey should fail when module not initialized")
}

func TestModule_WrapKey_InvalidSession(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()

	mechanism := NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(testGCMIV(), 128))

	_, rv := m.WrapKey(SessionHandle(99999), mechanism, ObjectHandle(1), ObjectHandle(2))
	assert.Equal(t, CKR_SESSION_HANDLE_INVALID, rv, "WrapKey should fail with invalid session")
}

func TestModule_UnwrapKey_Success(t *testing.T) {
	m, sessionHandle, _ := setupTestModuleWithKey(t)
	defer m.Finalize()

	// Create unwrapping key
	unwrapKeyTemplate := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewStringAttribute(CKA_LABEL, "unwrap-key"),
		NewAttribute(CKA_VALUE, []byte("0123456789ABCDEF")),
		NewBoolAttribute(CKA_UNWRAP, true),
		NewBoolAttribute(CKA_DECRYPT, true),
	}
	unwrapKeyHandle, rv := m.CreateObject(sessionHandle, unwrapKeyTemplate)
	require.Equal(t, CKR_OK, rv)

	unwrapKeyObj, _ := m.objectManager.getObjectUnchecked(unwrapKeyHandle)
	unwrapKeyObj.KeyID = "unwrap-key-id"
	unwrapKeyObj.BackendName = "default"

	mechanism := NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(testGCMIV(), 128))
	wrappedKey := []byte("wrapped-key-data")

	newKeyTemplate := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewStringAttribute(CKA_LABEL, "unwrapped-key"),
	}

	// Unwrap the key
	newKeyHandle, rv := m.UnwrapKey(sessionHandle, mechanism, unwrapKeyHandle, wrappedKey, newKeyTemplate)
	assert.Equal(t, CKR_OK, rv, "UnwrapKey should succeed")
	assert.NotEqual(t, ObjectHandle(InvalidHandle), newKeyHandle, "new key handle should be valid")
}

func TestModule_UnwrapKey_InvalidUnwrappingKey(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()

	// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
	// authenticates before exercising them.
	sessionHandle := loginAsNormalUser(t, m)

	mechanism := NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(testGCMIV(), 128))

	_, rv := m.UnwrapKey(sessionHandle, mechanism, ObjectHandle(99999), []byte("data"), nil)
	assert.Equal(t, CKR_UNWRAPPING_KEY_HANDLE_INVALID, rv, "UnwrapKey should fail with invalid unwrapping key")
}

func TestModule_UnwrapKey_ModuleNotInitialized(t *testing.T) {
	m := createTestModule(t)

	mechanism := NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(testGCMIV(), 128))

	_, rv := m.UnwrapKey(SessionHandle(1), mechanism, ObjectHandle(1), []byte("data"), nil)
	assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv, "UnwrapKey should fail when module not initialized")
}

func TestModule_UnwrapKey_InvalidSession(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()

	mechanism := NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(testGCMIV(), 128))

	_, rv := m.UnwrapKey(SessionHandle(99999), mechanism, ObjectHandle(1), []byte("data"), nil)
	assert.Equal(t, CKR_SESSION_HANDLE_INVALID, rv, "UnwrapKey should fail with invalid session")
}

func TestModule_UnwrapKey_EmptyWrappedKey(t *testing.T) {
	m, sessionHandle, _ := setupTestModuleWithKey(t)
	defer m.Finalize()

	// Create unwrapping key
	unwrapKeyTemplate := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewStringAttribute(CKA_LABEL, "unwrap-key"),
		NewAttribute(CKA_VALUE, []byte("0123456789ABCDEF")),
		NewBoolAttribute(CKA_UNWRAP, true),
		NewBoolAttribute(CKA_DECRYPT, true),
	}
	unwrapKeyHandle, rv := m.CreateObject(sessionHandle, unwrapKeyTemplate)
	require.Equal(t, CKR_OK, rv)

	unwrapKeyObj, _ := m.objectManager.getObjectUnchecked(unwrapKeyHandle)
	unwrapKeyObj.KeyID = "unwrap-key-id"
	unwrapKeyObj.BackendName = "default"

	mechanism := NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(testGCMIV(), 128))

	newKeyTemplate := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
	}

	// An empty wrapped key carries no key material to unwrap, so it is
	// rejected rather than producing a zero-length key.
	newKeyHandle, rv := m.UnwrapKey(sessionHandle, mechanism, unwrapKeyHandle, []byte{}, newKeyTemplate)
	assert.Equal(t, CKR_WRAPPED_KEY_INVALID, rv, "UnwrapKey should reject an empty wrapped key")
	assert.Equal(t, ObjectHandle(InvalidHandle), newKeyHandle, "no key object should be created")
}

// ----------------------------------------------------------------------------
// GetObjectSize Tests
// ----------------------------------------------------------------------------

func TestModule_GetObjectSize_Success(t *testing.T) {
	m, sessionHandle, keyHandle := setupTestModuleWithKey(t)
	defer m.Finalize()

	size, rv := m.GetObjectSize(sessionHandle, keyHandle)
	assert.Equal(t, CKR_OK, rv, "GetObjectSize should succeed")
	assert.Greater(t, size, uint64(0), "object size should be greater than 0")
}

func TestModule_GetObjectSize_InvalidObject(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()

	// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
	// authenticates before exercising them.
	sessionHandle := loginAsNormalUser(t, m)

	_, rv := m.GetObjectSize(sessionHandle, ObjectHandle(99999))
	assert.Equal(t, CKR_OBJECT_HANDLE_INVALID, rv, "GetObjectSize should fail with invalid object handle")
}

func TestModule_GetObjectSize_InvalidSession(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()

	_, rv := m.GetObjectSize(SessionHandle(99999), ObjectHandle(1))
	assert.Equal(t, CKR_SESSION_HANDLE_INVALID, rv, "GetObjectSize should fail with invalid session")
}

func TestModule_GetObjectSize_ModuleNotInitialized(t *testing.T) {
	m := createTestModule(t)

	_, rv := m.GetObjectSize(SessionHandle(1), ObjectHandle(1))
	assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv, "GetObjectSize should fail when module not initialized")
}

func TestModule_GetObjectSize_WithAttributes(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()

	// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
	// authenticates before exercising them.
	sessionHandle := loginAsNormalUser(t, m)

	// Create object with various attributes
	template := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA)),
		NewStringAttribute(CKA_LABEL, "test-data-object-with-long-label"),
		NewAttribute(CKA_VALUE, bytes.Repeat([]byte{0x42}, 256)),
	}

	objHandle, rv := m.CreateObject(sessionHandle, template)
	require.Equal(t, CKR_OK, rv)

	size, rv := m.GetObjectSize(sessionHandle, objHandle)
	assert.Equal(t, CKR_OK, rv)
	// Size should include base overhead + attribute values
	assert.Greater(t, size, uint64(256), "size should include value attribute")
}

func TestModule_GetObjectSize_MinimalObject(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()

	// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
	// authenticates before exercising them.
	sessionHandle := loginAsNormalUser(t, m)

	// Create minimal object
	template := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA)),
	}

	objHandle, rv := m.CreateObject(sessionHandle, template)
	require.Equal(t, CKR_OK, rv)

	size, rv := m.GetObjectSize(sessionHandle, objHandle)
	assert.Equal(t, CKR_OK, rv)
	// Size should at least have base overhead
	assert.GreaterOrEqual(t, size, uint64(64), "size should include base overhead")
}

// ----------------------------------------------------------------------------
// GetOperationStateBytes / SetOperationStateBytes Tests
// ----------------------------------------------------------------------------

func TestModule_GetOperationStateBytes_ModuleNotInitialized(t *testing.T) {
	m := createTestModule(t)

	_, rv := m.GetOperationStateBytes(SessionHandle(1))
	assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv, "GetOperationStateBytes should fail when module not initialized")
}

func TestModule_GetOperationStateBytes_InvalidSession(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()

	_, rv := m.GetOperationStateBytes(SessionHandle(99999))
	assert.Equal(t, CKR_SESSION_HANDLE_INVALID, rv, "GetOperationStateBytes should fail with invalid session")
}

func TestModule_GetOperationStateBytes_NoActiveOperation(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()

	// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
	// authenticates before exercising them.
	sessionHandle := loginAsNormalUser(t, m)

	_, rv := m.GetOperationStateBytes(sessionHandle)
	assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, rv, "GetOperationStateBytes should fail without active operation")
}

func TestModule_GetOperationStateBytes_WithCryptoOp(t *testing.T) {
	m, sessionHandle, keyHandle := setupTestModuleWithRSAKey(t)
	defer m.Finalize()

	mechanism := &Mechanism{Type: CKM_SHA256_RSA_PKCS}
	rv := m.SignInit(sessionHandle, mechanism, keyHandle)
	require.Equal(t, CKR_OK, rv)

	// Operations with crypto state should return CKR_STATE_UNSAVEABLE
	_, rv = m.GetOperationStateBytes(sessionHandle)
	assert.Equal(t, CKR_STATE_UNSAVEABLE, rv, "GetOperationStateBytes should return STATE_UNSAVEABLE for complex operations")
}

func TestModule_SetOperationStateBytes_ModuleNotInitialized(t *testing.T) {
	m := createTestModule(t)

	rv := m.SetOperationStateBytes(SessionHandle(1), []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, 0, 0)
	assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv, "SetOperationStateBytes should fail when module not initialized")
}

func TestModule_SetOperationStateBytes_InvalidSession(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()

	rv := m.SetOperationStateBytes(SessionHandle(99999), []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, 0, 0)
	assert.Equal(t, CKR_SESSION_HANDLE_INVALID, rv, "SetOperationStateBytes should fail with invalid session")
}

func TestModule_SetOperationStateBytes_InvalidState(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()

	// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
	// authenticates before exercising them.
	sessionHandle := loginAsNormalUser(t, m)

	// State too short
	rv := m.SetOperationStateBytes(sessionHandle, []byte{0x01, 0x02, 0x03}, 0, 0)
	assert.Equal(t, CKR_SAVED_STATE_INVALID, rv, "SetOperationStateBytes should fail with invalid state")
}

func TestModule_SetOperationStateBytes_RejectsForgedState(t *testing.T) {
	// PKCS#11 v3.2 §5.6.7 restores state "obtained with C_GetOperationState".
	// This module's C_GetOperationState answers CKR_STATE_UNSAVEABLE for every
	// savable operation (§5.6.6: the running state lives in the backend and
	// cannot leave the token), so no byte string handed to this function can be
	// valid saved state, and §5.6.7 names the answer: CKR_SAVED_STATE_INVALID.
	//
	// These three cases previously asserted CKR_OK and so CERTIFIED the defects
	// rather than catching them. The blob was parsed and "restored", but the
	// accumulated data was silently ignored — a restored digest returned the
	// hash of only the bytes supplied afterwards — and an out-of-range operation
	// type wiped the session's whole operation map while still reporting
	// success.
	cases := []struct {
		name  string
		state []byte
	}{
		{
			// Format the old parser accepted: [opType][mechanism][keyHandle].
			name: "well-formed blob for a digest operation",
			state: []byte{
				byte(OperationDigest),
				0x00, 0x02, 0x50, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
		},
		{
			name: "blob carrying accumulated data",
			state: []byte{
				byte(OperationDigest),
				0x00, 0x02, 0x50, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0xAA, 0xBB, 0xCC, 0xDD,
			},
		},
		{
			// An operation type outside the dispatch range used to return
			// CKR_OK and cancel every operation on the session.
			name: "blob naming an out-of-range operation type",
			state: []byte{
				0xFF,
				0x00, 0x02, 0x50, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := initializeTestModule(t)
			defer m.Finalize()

			sessionHandle := loginAsNormalUser(t, m)

			rv := m.SetOperationStateBytes(sessionHandle, tc.state, 0, 0)
			assert.Equal(t, CKR_SAVED_STATE_INVALID, rv,
				"no blob can be valid saved state when C_GetOperationState never produces any")
		})
	}
}

func TestModule_SetOperationStateBytes_DoesNotDisturbAnActiveOperation(t *testing.T) {
	// §5.6.7 explicitly permits restoring over an active operation: "C_Set-
	// OperationState can successfully restore cryptographic operations state to
	// a session even if that session has active cryptographic or object search
	// operations". Refusing with CKR_OPERATION_ACTIVE, as this module used to,
	// contradicts that outright — so the refusal must be about the state being
	// invalid, and the running operation must survive untouched.
	m := initializeTestModule(t)
	defer m.Finalize()

	sessionHandle := loginAsNormalUser(t, m)

	rv := m.DigestInit(sessionHandle, &Mechanism{Type: CKM_SHA256})
	require.Equal(t, CKR_OK, rv)

	state := []byte{
		byte(OperationDigest),
		0x00, 0x02, 0x50, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	rv = m.SetOperationStateBytes(sessionHandle, state, 0, 0)
	assert.Equal(t, CKR_SAVED_STATE_INVALID, rv,
		"the refusal must be about the state, not about an operation being active")

	// The digest must still be usable, which is what proves the refusal did not
	// cancel it the way the old out-of-range path silently did.
	digest, rv := m.Digest(sessionHandle, []byte("still running"))
	assert.Equal(t, CKR_OK, rv, "the active digest must survive a rejected restore")
	assert.Len(t, digest, 32)
}

func TestModule_SetOperationStateBytes_InvalidKeyHandle(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()

	// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
	// authenticates before exercising them.
	sessionHandle := loginAsNormalUser(t, m)

	// Create state with non-zero key handle that doesn't exist
	state := []byte{
		byte(OperationSign),
		0x00, 0x00, 0x00, 0x01, // mechanism
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, // invalid key handle
	}

	// The blob is rejected as invalid saved state before its key handle is ever
	// reached, which is the correct order: §5.6.7's key-handle errors
	// (CKR_KEY_NEEDED, CKR_KEY_NOT_NEEDED, CKR_KEY_CHANGED) only apply to state
	// that IS valid saved state, and this module can produce none.
	rv := m.SetOperationStateBytes(sessionHandle, state, 0, 0)
	assert.Equal(t, CKR_SAVED_STATE_INVALID, rv,
		"a forged blob is rejected as invalid state, whatever key handle it names")
}

// ----------------------------------------------------------------------------
// Multi-part operation state management tests
// ----------------------------------------------------------------------------

func TestModule_SignUpdate_AccumulatesData(t *testing.T) {
	m, sessionHandle, keyHandle := setupTestModuleWithRSAKey(t)
	defer m.Finalize()

	mechanism := &Mechanism{Type: CKM_SHA256_RSA_PKCS}
	rv := m.SignInit(sessionHandle, mechanism, keyHandle)
	require.Equal(t, CKR_OK, rv)

	// Add multiple chunks
	chunks := []string{"Hello", " ", "World", "!"}
	for _, chunk := range chunks {
		rv = m.SignUpdate(sessionHandle, []byte(chunk))
		require.Equal(t, CKR_OK, rv)
	}

	// Finalize and verify the mock was called
	signature, rv := m.SignFinal(sessionHandle)
	assert.Equal(t, CKR_OK, rv)
	assert.NotEmpty(t, signature)
}

func TestModule_VerifyUpdate_AccumulatesData(t *testing.T) {
	m, sessionHandle, keyHandle := setupTestModuleWithRSAKey(t)
	defer m.Finalize()

	mechanism := &Mechanism{Type: CKM_SHA256_RSA_PKCS}
	rv := m.VerifyInit(sessionHandle, mechanism, keyHandle)
	require.Equal(t, CKR_OK, rv)

	// Add multiple chunks
	chunks := []string{"Hello", " ", "World", "!"}
	for _, chunk := range chunks {
		rv = m.VerifyUpdate(sessionHandle, []byte(chunk))
		require.Equal(t, CKR_OK, rv)
	}

	// Finalize with mock signature
	rv = m.VerifyFinal(sessionHandle, []byte("mock-signature"))
	assert.Equal(t, CKR_OK, rv)
}

func TestModule_EncryptUpdate_AccumulatesData(t *testing.T) {
	m, sessionHandle, keyHandle := setupTestModuleWithKey(t)
	defer m.Finalize()

	mechanism := NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(testGCMIV(), 128))
	rv := m.EncryptInit(sessionHandle, mechanism, keyHandle)
	require.Equal(t, CKR_OK, rv)

	// Add multiple chunks
	chunks := []string{"Secret", " ", "Data", "!"}
	for _, chunk := range chunks {
		_, rv = m.EncryptUpdate(sessionHandle, []byte(chunk))
		require.Equal(t, CKR_OK, rv)
	}

	// Finalize
	ciphertext, rv := m.EncryptFinal(sessionHandle)
	assert.Equal(t, CKR_OK, rv)
	assert.NotNil(t, ciphertext)
}

func TestModule_DecryptUpdate_AccumulatesData(t *testing.T) {
	m, sessionHandle, keyHandle := setupTestModuleWithKey(t)
	defer m.Finalize()

	mechanism := NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(testGCMIV(), 128))
	rv := m.DecryptInit(sessionHandle, mechanism, keyHandle)
	require.Equal(t, CKR_OK, rv)

	// Add multiple chunks
	chunks := []string{"Encrypted", "Data", "Chunks"}
	for _, chunk := range chunks {
		_, rv = m.DecryptUpdate(sessionHandle, []byte(chunk))
		require.Equal(t, CKR_OK, rv)
	}

	// Finalize
	plaintext, rv := m.DecryptFinal(sessionHandle)
	assert.Equal(t, CKR_OK, rv)
	assert.NotNil(t, plaintext)
}

func TestModule_DigestUpdate_AccumulatesData(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()

	// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
	// authenticates before exercising them.
	sessionHandle := loginAsNormalUser(t, m)

	mechanism := &Mechanism{Type: CKM_SHA256}
	rv := m.DigestInit(sessionHandle, mechanism)
	require.Equal(t, CKR_OK, rv)

	// Add multiple chunks
	chunks := []string{"Hash", "This", "Data"}
	for _, chunk := range chunks {
		rv = m.DigestUpdate(sessionHandle, []byte(chunk))
		require.Equal(t, CKR_OK, rv)
	}

	// Finalize
	hash, rv := m.DigestFinal(sessionHandle)
	assert.Equal(t, CKR_OK, rv)
	assert.Len(t, hash, 32)
}

// ----------------------------------------------------------------------------
// ReadOnly Session Tests for Wrap/Unwrap
// ----------------------------------------------------------------------------

func TestModule_WrapKey_ReadOnlySession(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()

	// Provision and authenticate first: C_InitToken refuses to run while
	// any session is open. The read-write session it returns is not the one
	// under test, so it is discarded; the read-only session opened below is.
	_ = loginAsNormalUser(t, m)

	sessionHandle, rv := m.OpenSession(0, CKF_SERIAL_SESSION)
	require.Equal(t, CKR_OK, rv)

	mechanism := NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(testGCMIV(), 128))

	// C_WrapKey creates no object, so a read-only session may wrap: the spec
	// does not list CKR_SESSION_READ_ONLY among its return values. Handle
	// validation is what rejects this call.
	_, rv = m.WrapKey(sessionHandle, mechanism, ObjectHandle(1), ObjectHandle(2))
	assert.Equal(t, CKR_WRAPPING_KEY_HANDLE_INVALID, rv,
		"WrapKey should reject an unknown wrapping key handle, not the read-only session")
}

func TestModule_UnwrapKey_ReadOnlySession(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()

	// Provision and authenticate first: CKF_LOGIN_REQUIRED gates key management,
	// and that gate is reported before the handle is even looked at.
	rwSession := loginAsNormalUser(t, m)
	require.NotEqual(t, SessionHandle(InvalidHandle), rwSession)

	// Open read-only session
	sessionHandle, rv := m.OpenSession(0, CKF_SERIAL_SESSION)
	require.Equal(t, CKR_OK, rv)

	mechanism := NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(testGCMIV(), 128))

	// C_UnwrapKey creates a session object by default (CKA_TOKEN is CK_FALSE),
	// which a read-only session may do. Only a token object would be refused
	// with CKR_SESSION_READ_ONLY, so the unknown handle is what fails here.
	_, rv = m.UnwrapKey(sessionHandle, mechanism, ObjectHandle(1), []byte("data"), nil)
	assert.Equal(t, CKR_UNWRAPPING_KEY_HANDLE_INVALID, rv,
		"UnwrapKey should reject an unknown unwrapping key handle")
}

// ----------------------------------------------------------------------------
// WrapKey permission tests
// ----------------------------------------------------------------------------

func TestModule_WrapKey_WrapNotPermitted(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()

	sessionHandle := loginAsNormalUser(t, m)

	// Create key that cannot wrap (CKA_WRAP = false)
	wrapKeyTemplate := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewAttribute(CKA_VALUE, []byte("0123456789ABCDEF")),
		NewBoolAttribute(CKA_WRAP, false),
		NewBoolAttribute(CKA_ENCRYPT, true),
	}
	wrapKeyHandle, rv := m.CreateObject(sessionHandle, wrapKeyTemplate)
	require.Equal(t, CKR_OK, rv)

	wrapKeyObj, _ := m.objectManager.getObjectUnchecked(wrapKeyHandle)
	wrapKeyObj.KeyID = "wrap-key-id"
	wrapKeyObj.BackendName = "default"

	// Create key to be wrapped
	targetKeyTemplate := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewAttribute(CKA_VALUE, []byte("SECRETKEYVALUE!!")),
		NewBoolAttribute(CKA_EXTRACTABLE, true),
	}
	targetKeyHandle, rv := m.CreateObject(sessionHandle, targetKeyTemplate)
	require.Equal(t, CKR_OK, rv)

	mechanism := NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(testGCMIV(), 128))

	// CKR_WRAPPING_KEY_TYPE_INCONSISTENT, not CKR_KEY_FUNCTION_NOT_PERMITTED:
	// the latter is absent from C_WrapKey's return table (v3.2 §5.18.3), so a
	// conforming application never learns to expect it here.
	_, rv = m.WrapKey(sessionHandle, mechanism, wrapKeyHandle, targetKeyHandle)
	assert.Equal(t, CKR_WRAPPING_KEY_TYPE_INCONSISTENT, rv, "WrapKey should fail when wrap not permitted")
}

func TestModule_UnwrapKey_UnwrapNotPermitted(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()

	// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
	// authenticates before exercising them.
	sessionHandle := loginAsNormalUser(t, m)

	// Create key that cannot unwrap (CKA_UNWRAP = false)
	unwrapKeyTemplate := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewAttribute(CKA_VALUE, []byte("0123456789ABCDEF")),
		NewBoolAttribute(CKA_UNWRAP, false),
		NewBoolAttribute(CKA_DECRYPT, true),
	}
	unwrapKeyHandle, rv := m.CreateObject(sessionHandle, unwrapKeyTemplate)
	require.Equal(t, CKR_OK, rv)

	unwrapKeyObj, _ := m.objectManager.getObjectUnchecked(unwrapKeyHandle)
	unwrapKeyObj.KeyID = "unwrap-key-id"
	unwrapKeyObj.BackendName = "default"

	mechanism := NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(testGCMIV(), 128))

	// CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT, not CKR_KEY_FUNCTION_NOT_PERMITTED:
	// the latter is absent from C_UnwrapKey's return table (v3.2 §5.18.4), so a
	// conforming application never learns to expect it here.
	_, rv = m.UnwrapKey(sessionHandle, mechanism, unwrapKeyHandle, []byte("wrapped-data"), nil)
	assert.Equal(t, CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT, rv, "UnwrapKey should fail when unwrap not permitted")
}

// ----------------------------------------------------------------------------
// WrapKey no value test
// ----------------------------------------------------------------------------

func TestModule_WrapKey_NoKeyValue(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()

	// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
	// authenticates before exercising them.
	sessionHandle := loginAsNormalUser(t, m)

	// Create wrapping key
	wrapKeyTemplate := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewAttribute(CKA_VALUE, []byte("0123456789ABCDEF")),
		NewBoolAttribute(CKA_WRAP, true),
		NewBoolAttribute(CKA_ENCRYPT, true),
	}
	wrapKeyHandle, rv := m.CreateObject(sessionHandle, wrapKeyTemplate)
	require.Equal(t, CKR_OK, rv)

	wrapKeyObj, _ := m.objectManager.getObjectUnchecked(wrapKeyHandle)
	wrapKeyObj.KeyID = "wrap-key-id"
	wrapKeyObj.BackendName = "default"

	// A key with no CKA_VALUE. C_CreateObject cannot produce this state any
	// more, but restore-from-storage and C_UnwrapKey can, which is what
	// C_WrapKey's refusal defends.
	targetKeyHandle := createSecretKeyWithoutValue(t, m, sessionHandle,
		NewBoolAttribute(CKA_EXTRACTABLE, true))

	mechanism := NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(testGCMIV(), 128))

	_, rv = m.WrapKey(sessionHandle, mechanism, wrapKeyHandle, targetKeyHandle)
	assert.Equal(t, CKR_KEY_NOT_WRAPPABLE, rv, "WrapKey should fail when key has no value")
}

// ----------------------------------------------------------------------------
// Large data tests
// ----------------------------------------------------------------------------

func TestModule_DigestUpdate_LargeData(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()

	// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
	// authenticates before exercising them.
	sessionHandle := loginAsNormalUser(t, m)

	mechanism := &Mechanism{Type: CKM_SHA256}
	rv := m.DigestInit(sessionHandle, mechanism)
	require.Equal(t, CKR_OK, rv)

	// Add large data in chunks
	chunkSize := 1024
	numChunks := 100
	for i := 0; i < numChunks; i++ {
		data := bytes.Repeat([]byte{byte(i)}, chunkSize)
		rv = m.DigestUpdate(sessionHandle, data)
		require.Equal(t, CKR_OK, rv)
	}

	hash, rv := m.DigestFinal(sessionHandle)
	assert.Equal(t, CKR_OK, rv)
	assert.Len(t, hash, 32)
}

func TestModule_EncryptUpdate_LargeData(t *testing.T) {
	m, sessionHandle, keyHandle := setupTestModuleWithKey(t)
	defer m.Finalize()

	mechanism := NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(testGCMIV(), 128))
	rv := m.EncryptInit(sessionHandle, mechanism, keyHandle)
	require.Equal(t, CKR_OK, rv)

	// Add large data in chunks
	chunkSize := 1024
	numChunks := 50
	for i := 0; i < numChunks; i++ {
		data := bytes.Repeat([]byte{byte(i)}, chunkSize)
		_, rv = m.EncryptUpdate(sessionHandle, data)
		require.Equal(t, CKR_OK, rv)
	}

	ciphertext, rv := m.EncryptFinal(sessionHandle)
	assert.Equal(t, CKR_OK, rv)
	assert.NotNil(t, ciphertext)
}

// ----------------------------------------------------------------------------
// Concurrent operation tests
// ----------------------------------------------------------------------------

func TestModule_MultipleSessionsDigest(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()

	// Open multiple sessions
	// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
	// authenticates before exercising them.
	session1 := loginAsNormalUser(t, m)

	// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
	// authenticates before exercising them.
	session2 := loginAsNormalUser(t, m)

	// Initialize digest on both sessions
	mechanism := &Mechanism{Type: CKM_SHA256}

	rv := m.DigestInit(session1, mechanism)
	require.Equal(t, CKR_OK, rv)

	rv = m.DigestInit(session2, mechanism)
	require.Equal(t, CKR_OK, rv)

	// Update session 1
	rv = m.DigestUpdate(session1, []byte("session 1 data"))
	assert.Equal(t, CKR_OK, rv)

	// Update session 2
	rv = m.DigestUpdate(session2, []byte("session 2 data"))
	assert.Equal(t, CKR_OK, rv)

	// Finalize both - each should produce different hashes
	hash1, rv := m.DigestFinal(session1)
	assert.Equal(t, CKR_OK, rv)

	hash2, rv := m.DigestFinal(session2)
	assert.Equal(t, CKR_OK, rv)

	// Hashes should be different (different input data)
	assert.NotEqual(t, hash1, hash2, "different inputs should produce different hashes")
}

// testGCMIVCounter numbers the IVs testGCMIV hands out.
var testGCMIVCounter atomic.Uint64

// testGCMIV returns a 12-byte AES-GCM IV no other call has produced.
// CKM_AES_GCM carries its IV in CK_GCM_PARAMS, and decryption cannot proceed
// without one.
//
// It used to return one fixed string for every fixture, which worked only
// while each CryptoManager tracked consumed (key, IV) pairs in a map of its
// own. NIST SP 800-38D section 8.2 constrains the pair and not the manager
// instance, so that tracking is now process-wide (see checkGCMNonce) and a
// shared constant would make every fixture after the first a reuse of the
// first one's IV under the same test key. Callers that need the same IV twice
// -- to decrypt what they encrypted -- must keep the value, which every caller
// already does.
func testGCMIV() []byte {
	iv := make([]byte, GCMNonceSize)
	binary.BigEndian.PutUint64(iv[GCMNonceSize-8:], testGCMIVCounter.Add(1))
	return iv
}
