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

// ----------------------------------------------------------------------------
// VerifySignatureInit
// ----------------------------------------------------------------------------

func TestVerifySignatureInit(t *testing.T) {

	t.Run("returns CKR_MECHANISM_INVALID without quantum build tag", func(t *testing.T) {
		m, sessionHandle, keyHandle := createTestModuleWithKey(t)
		defer m.Finalize()

		mechanism := NewMechanism(CKM_ML_DSA)
		signature := []byte("mock-pqc-signature")

		err := m.VerifySignatureInit(sessionHandle, mechanism, keyHandle, signature)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_MECHANISM_INVALID, pkcsErr.Code)
	})

	t.Run("cancels active operation with nil mechanism", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		sessionHandle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		// Plant an active VerifySignature operation
		_, session, findRV := m.findSession(sessionHandle)
		require.Equal(t, CKR_OK, findRV)

		session.SetOperationByType(OperationVerifySignature, &OperationState{
			Type:      OperationVerifySignature,
			Mechanism: CKM_ML_DSA,
		})
		require.True(t, session.HasOperationType(OperationVerifySignature))

		// Nil mechanism should cancel the operation and return CKR_OK
		err := m.VerifySignatureInit(sessionHandle, nil, ObjectHandle(0), nil)
		require.NoError(t, err)

		// Operation should be cleared
		assert.False(t, session.HasOperationType(OperationVerifySignature))
	})

	t.Run("nil mechanism returns CKR_OK even with no active operation", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		sessionHandle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		// Nil mechanism with no active operation should still return CKR_OK
		err := m.VerifySignatureInit(sessionHandle, nil, ObjectHandle(0), nil)
		require.NoError(t, err)
	})

	t.Run("returns CKR_KEY_HANDLE_INVALID with invalid key", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		sessionHandle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		mechanism := NewMechanism(CKM_ML_DSA)
		err := m.VerifySignatureInit(sessionHandle, mechanism, ObjectHandle(99999), []byte("sig"))
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_KEY_HANDLE_INVALID, pkcsErr.Code)
	})

	t.Run("returns CKR_ARGUMENTS_BAD with empty signature", func(t *testing.T) {
		m, sessionHandle, keyHandle := createTestModuleWithKey(t)
		defer m.Finalize()

		mechanism := NewMechanism(CKM_ML_DSA)
		err := m.VerifySignatureInit(sessionHandle, mechanism, keyHandle, []byte{})
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_ARGUMENTS_BAD, pkcsErr.Code)
	})

	t.Run("returns CKR_KEY_FUNCTION_NOT_PERMITTED when CKA_VERIFY is false", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		sessionHandle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		// Create a key with CKA_VERIFY explicitly set to false
		template := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_PUBLIC_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_RSA)),
			NewStringAttribute(CKA_LABEL, "test-no-verify-key"),
			NewBoolAttribute(CKA_VERIFY, false),
			NewBoolAttribute(CKA_TOKEN, false),
			NewBoolAttribute(CKA_MODIFIABLE, true),
		}
		keyHandle, createRV := m.CreateObject(sessionHandle, template)
		require.Equal(t, CKR_OK, createRV)

		mechanism := NewMechanism(CKM_ML_DSA)
		err := m.VerifySignatureInit(sessionHandle, mechanism, keyHandle, []byte("sig"))
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_KEY_FUNCTION_NOT_PERMITTED, pkcsErr.Code)
	})
}

func TestVerifySignatureInitNotInitialized(t *testing.T) {

	t.Run("returns CKR_CRYPTOKI_NOT_INITIALIZED", func(t *testing.T) {
		m := createTestModule(t)
		mechanism := NewMechanism(CKM_ML_DSA)

		err := m.VerifySignatureInit(SessionHandle(1), mechanism, ObjectHandle(1), []byte("sig"))
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, pkcsErr.Code)
	})
}

func TestVerifySignatureInitInvalidSession(t *testing.T) {

	t.Run("returns CKR_SESSION_HANDLE_INVALID", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		mechanism := NewMechanism(CKM_ML_DSA)
		err := m.VerifySignatureInit(SessionHandle(99999), mechanism, ObjectHandle(1), []byte("sig"))
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_SESSION_HANDLE_INVALID, pkcsErr.Code)
	})
}

// TestVerifySignatureInitOperationActive tests that a duplicate
// VerifySignatureInit call returns CKR_OPERATION_ACTIVE when an
// operation is already in progress on the session.
func TestVerifySignatureInitOperationActive(t *testing.T) {

	t.Run("returns CKR_OPERATION_ACTIVE on duplicate init", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		sessionHandle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		// Create a key with CKA_VERIFY set to true
		template := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_PUBLIC_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_ML_DSA)),
			NewStringAttribute(CKA_LABEL, "test-verify-key"),
			NewBoolAttribute(CKA_VERIFY, true),
			NewBoolAttribute(CKA_TOKEN, false),
			NewAttribute(CKA_VALUE, make([]byte, 32)),
		}
		keyHandle, rv := m.CreateObject(sessionHandle, template)
		require.Equal(t, CKR_OK, rv)

		mechanism := NewMechanism(CKM_ML_DSA)
		signature := []byte("mock-signature-data")

		// First init — may succeed or fail depending on quantum build tag,
		// but the OPERATION_ACTIVE check happens after verifySigInit().
		// Without quantum, the first call returns CKR_MECHANISM_INVALID.
		// We need to manually set the operation state to test the guard.
		_, session, findRV := m.findSession(sessionHandle)
		require.Equal(t, CKR_OK, findRV)

		// Manually plant an active VerifySignature operation
		session.SetOperationByType(OperationVerifySignature, &OperationState{
			Type:      OperationVerifySignature,
			Mechanism: CKM_ML_DSA,
			KeyHandle: keyHandle,
			Data:      signature,
		})

		// Second init should return CKR_OPERATION_ACTIVE
		err := m.VerifySignatureInit(sessionHandle, mechanism, keyHandle, signature)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_OPERATION_ACTIVE, pkcsErr.Code)
	})
}

// TestVerifySignatureInitKeyWithoutVerifyAttribute tests that VerifySignatureInit
// rejects a key that has no CKA_VERIFY attribute at all (not just false).
func TestVerifySignatureInitKeyWithoutVerifyAttribute(t *testing.T) {

	t.Run("returns CKR_KEY_FUNCTION_NOT_PERMITTED when CKA_VERIFY absent", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		sessionHandle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		// Create key without CKA_VERIFY attribute at all
		template := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_PUBLIC_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_RSA)),
			NewStringAttribute(CKA_LABEL, "test-no-verify-attr"),
			NewBoolAttribute(CKA_TOKEN, false),
		}
		keyHandle, rv := m.CreateObject(sessionHandle, template)
		require.Equal(t, CKR_OK, rv)

		mechanism := NewMechanism(CKM_ML_DSA)
		err := m.VerifySignatureInit(sessionHandle, mechanism, keyHandle, []byte("sig"))
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_KEY_FUNCTION_NOT_PERMITTED, pkcsErr.Code)
	})
}

// ----------------------------------------------------------------------------
// VerifySignature (single-part)
// ----------------------------------------------------------------------------

func TestVerifySignature(t *testing.T) {

	t.Run("returns CKR_OPERATION_NOT_INITIALIZED without prior init", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		sessionHandle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		err := m.VerifySignature(sessionHandle, []byte("data to verify"))
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, pkcsErr.Code)
	})

	t.Run("consumes operation and dispatches to verifySigVerify stub", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		sessionHandle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		// Plant a VerifySignature operation with a nil CryptoOp.
		// verifySigVerify receives a non-nil QuantumCryptoManager but a nil
		// CryptoOp, which fails the *QuantumVerifyOperation type assertion,
		// returning CKR_OPERATION_NOT_INITIALIZED. This confirms the dispatch
		// path executes through to verifySigVerify.
		_, session, findRV := m.findSession(sessionHandle)
		require.Equal(t, CKR_OK, findRV)

		session.SetOperationByType(OperationVerifySignature, &OperationState{
			Type:      OperationVerifySignature,
			Mechanism: CKM_ML_DSA,
			KeyHandle: ObjectHandle(1),
			Data:      []byte("planted-signature"),
			CryptoOp:  nil,
		})
		require.True(t, session.HasOperationType(OperationVerifySignature))

		// VerifySignature should consume the operation and call verifySigVerify,
		// which returns CKR_OPERATION_NOT_INITIALIZED due to nil CryptoOp.
		err := m.VerifySignature(sessionHandle, []byte("data to verify"))
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, pkcsErr.Code)

		// The operation should have been consumed (removed from session)
		assert.False(t, session.HasOperationType(OperationVerifySignature))
	})
}

func TestVerifySignatureNotInitialized(t *testing.T) {

	t.Run("returns CKR_CRYPTOKI_NOT_INITIALIZED", func(t *testing.T) {
		m := createTestModule(t)

		err := m.VerifySignature(SessionHandle(1), []byte("data"))
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, pkcsErr.Code)
	})
}

func TestVerifySignatureInvalidSession(t *testing.T) {

	t.Run("returns CKR_SESSION_HANDLE_INVALID", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		err := m.VerifySignature(SessionHandle(99999), []byte("data"))
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_SESSION_HANDLE_INVALID, pkcsErr.Code)
	})
}

// ----------------------------------------------------------------------------
// VerifySignatureUpdate (multi-part)
// ----------------------------------------------------------------------------

func TestVerifySignatureUpdate(t *testing.T) {

	t.Run("returns CKR_OPERATION_NOT_INITIALIZED without prior init", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		sessionHandle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		err := m.VerifySignatureUpdate(sessionHandle, []byte("data chunk"))
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, pkcsErr.Code)
	})

	t.Run("accumulates data with properly typed multi-part state", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		sessionHandle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		// Plant a VerifySignature operation with a properly typed multi-part state
		_, session, findRV := m.findSession(sessionHandle)
		require.Equal(t, CKR_OK, findRV)

		multiPartState := &verifySigMultiPartState{
			quantumOp:       nil,
			accumulatedData: nil,
		}
		session.SetOperationByType(OperationVerifySignature, &OperationState{
			Type:      OperationVerifySignature,
			Mechanism: CKM_ML_DSA,
			KeyHandle: ObjectHandle(1),
			Data:      []byte("planted-signature"),
			CryptoOp:  multiPartState,
		})

		// First chunk
		err := m.VerifySignatureUpdate(sessionHandle, []byte("chunk-1-"))
		require.NoError(t, err)
		assert.Equal(t, []byte("chunk-1-"), multiPartState.accumulatedData)

		// Second chunk -- data should be appended
		err = m.VerifySignatureUpdate(sessionHandle, []byte("chunk-2"))
		require.NoError(t, err)
		assert.Equal(t, []byte("chunk-1-chunk-2"), multiPartState.accumulatedData)

		// Operation should still be active
		assert.True(t, session.HasOperationType(OperationVerifySignature))
	})
}

func TestVerifySignatureUpdateNotInitialized(t *testing.T) {

	t.Run("returns CKR_CRYPTOKI_NOT_INITIALIZED", func(t *testing.T) {
		m := createTestModule(t)

		err := m.VerifySignatureUpdate(SessionHandle(1), []byte("chunk"))
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, pkcsErr.Code)
	})
}

func TestVerifySignatureUpdateInvalidSession(t *testing.T) {

	t.Run("returns CKR_SESSION_HANDLE_INVALID", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		err := m.VerifySignatureUpdate(SessionHandle(99999), []byte("chunk"))
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_SESSION_HANDLE_INVALID, pkcsErr.Code)
	})
}

// ----------------------------------------------------------------------------
// VerifySignatureFinal
// ----------------------------------------------------------------------------

func TestVerifySignatureFinal(t *testing.T) {

	t.Run("returns CKR_OPERATION_NOT_INITIALIZED without prior init", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		sessionHandle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		err := m.VerifySignatureFinal(sessionHandle)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, pkcsErr.Code)
	})

	t.Run("consumes multi-part operation and dispatches to verifySigVerify stub", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		sessionHandle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		// Plant a VerifySignature operation with a properly typed multi-part state
		// that has accumulated data, simulating Update calls that already occurred.
		_, session, findRV := m.findSession(sessionHandle)
		require.Equal(t, CKR_OK, findRV)

		multiPartState := &verifySigMultiPartState{
			quantumOp:       nil,
			accumulatedData: []byte("accumulated-data-from-updates"),
		}
		session.SetOperationByType(OperationVerifySignature, &OperationState{
			Type:      OperationVerifySignature,
			Mechanism: CKM_ML_DSA,
			KeyHandle: ObjectHandle(1),
			Data:      []byte("planted-signature"),
			CryptoOp:  multiPartState,
		})

		// VerifySignatureFinal should consume the operation and call verifySigVerify,
		// which returns CKR_OPERATION_NOT_INITIALIZED due to nil quantumOp.
		err := m.VerifySignatureFinal(sessionHandle)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, pkcsErr.Code)

		// The operation should have been consumed (removed from session)
		assert.False(t, session.HasOperationType(OperationVerifySignature))
	})
}

func TestVerifySignatureFinalNotInitialized(t *testing.T) {

	t.Run("returns CKR_CRYPTOKI_NOT_INITIALIZED", func(t *testing.T) {
		m := createTestModule(t)

		err := m.VerifySignatureFinal(SessionHandle(1))
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, pkcsErr.Code)
	})
}

func TestVerifySignatureFinalInvalidSession(t *testing.T) {

	t.Run("returns CKR_SESSION_HANDLE_INVALID", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		err := m.VerifySignatureFinal(SessionHandle(99999))
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_SESSION_HANDLE_INVALID, pkcsErr.Code)
	})
}

// ----------------------------------------------------------------------------
// CryptoOp type assertion failure paths
// ----------------------------------------------------------------------------

// TestVerifySignatureUpdateCryptoOpTypeMismatch tests that VerifySignatureUpdate
// returns CKR_OPERATION_NOT_INITIALIZED when the session's CryptoOp is not a
// *verifySigMultiPartState (e.g., when VerifySignatureInit stored a raw quantum
// operation for single-part use, but VerifySignatureUpdate is called instead).
func TestVerifySignatureUpdateCryptoOpTypeMismatch(t *testing.T) {

	t.Run("returns CKR_OPERATION_NOT_INITIALIZED with wrong CryptoOp type", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		sessionHandle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		// Directly inject an operation with a non-multipart CryptoOp type
		_, session, findRV := m.findSession(sessionHandle)
		require.Equal(t, CKR_OK, findRV)

		session.SetOperationByType(OperationVerifySignature, &OperationState{
			Type:     OperationVerifySignature,
			CryptoOp: "not-a-verifySigMultiPartState", // wrong type
		})

		err := m.VerifySignatureUpdate(sessionHandle, []byte("data"))
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, pkcsErr.Code)
	})
}

// TestVerifySignatureUpdateErrorTerminatesOperation verifies that per PKCS#11
// v3.2 spec section 5.15.9, if C_VerifySignatureUpdate returns an error, the
// active multi-part operation is terminated and the session is ready for a new
// operation. This is a spec-required behavior to prevent sessions from getting
// stuck in a bad state after an update failure.
func TestVerifySignatureUpdateErrorTerminatesOperation(t *testing.T) {

	t.Run("error from Update clears the active operation from session", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		sessionHandle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		// Plant a VerifySignature operation with a wrong CryptoOp type to
		// trigger an error inside WithOperation.
		_, session, findRV := m.findSession(sessionHandle)
		require.Equal(t, CKR_OK, findRV)

		session.SetOperationByType(OperationVerifySignature, &OperationState{
			Type:      OperationVerifySignature,
			Mechanism: CKM_ML_DSA,
			KeyHandle: ObjectHandle(1),
			Data:      []byte("signature"),
			CryptoOp:  42, // wrong type: int instead of *verifySigMultiPartState
		})
		require.True(t, session.HasOperationType(OperationVerifySignature))

		// VerifySignatureUpdate should fail due to type mismatch
		err := m.VerifySignatureUpdate(sessionHandle, []byte("some data"))
		require.Error(t, err)

		// The key assertion: after an error, the operation must be cleared
		// per PKCS#11 v3.2 spec. The session should be ready for a new operation.
		assert.False(t, session.HasOperationType(OperationVerifySignature),
			"operation must be terminated after VerifySignatureUpdate error per PKCS#11 v3.2 spec")
	})
}

// TestVerifySignatureMultiPartFlow tests the complete multi-part verification
// flow: plant a properly typed operation, accumulate data via Update, then
// finalize via Final. Without the quantum build tag, Final dispatches to the
// verifySigVerify stub which returns CKR_MECHANISM_INVALID, confirming the
// full data path executes.
func TestVerifySignatureMultiPartFlow(t *testing.T) {

	t.Run("Update accumulates data and Final dispatches to stub", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		sessionHandle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		_, session, findRV := m.findSession(sessionHandle)
		require.Equal(t, CKR_OK, findRV)

		multiPartState := &verifySigMultiPartState{
			quantumOp:       nil,
			accumulatedData: nil,
		}
		session.SetOperationByType(OperationVerifySignature, &OperationState{
			Type:      OperationVerifySignature,
			Mechanism: CKM_ML_DSA,
			KeyHandle: ObjectHandle(1),
			Data:      []byte("test-signature"),
			CryptoOp:  multiPartState,
		})

		// Feed data in multiple chunks
		err := m.VerifySignatureUpdate(sessionHandle, []byte("hello "))
		require.NoError(t, err)

		err = m.VerifySignatureUpdate(sessionHandle, []byte("world"))
		require.NoError(t, err)

		// Verify accumulated data
		assert.Equal(t, []byte("hello world"), multiPartState.accumulatedData)

		// Final should consume the operation and dispatch to verifySigVerify,
		// which returns CKR_OPERATION_NOT_INITIALIZED due to nil quantumOp.
		err = m.VerifySignatureFinal(sessionHandle)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, pkcsErr.Code)

		// Operation must be consumed after Final
		assert.False(t, session.HasOperationType(OperationVerifySignature))
	})

	t.Run("Final after error-terminated Update returns CKR_OPERATION_NOT_INITIALIZED", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		sessionHandle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		_, session, findRV := m.findSession(sessionHandle)
		require.Equal(t, CKR_OK, findRV)

		// Plant an operation with wrong CryptoOp type to force Update error
		session.SetOperationByType(OperationVerifySignature, &OperationState{
			Type:      OperationVerifySignature,
			Mechanism: CKM_ML_DSA,
			KeyHandle: ObjectHandle(1),
			Data:      []byte("test-signature"),
			CryptoOp:  "wrong-type",
		})

		// Update fails and terminates the operation
		err := m.VerifySignatureUpdate(sessionHandle, []byte("data"))
		require.Error(t, err)
		assert.False(t, session.HasOperationType(OperationVerifySignature))

		// Final should now return CKR_OPERATION_NOT_INITIALIZED since
		// the operation was terminated by the Update error
		err = m.VerifySignatureFinal(sessionHandle)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, pkcsErr.Code)
	})
}

// TestVerifySignatureFinalCryptoOpTypeMismatch tests that VerifySignatureFinal
// returns CKR_OPERATION_NOT_INITIALIZED when the session's CryptoOp is not a
// *verifySigMultiPartState.
func TestVerifySignatureFinalCryptoOpTypeMismatch(t *testing.T) {

	t.Run("returns CKR_OPERATION_NOT_INITIALIZED with wrong CryptoOp type", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		sessionHandle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		// Directly inject an operation with a non-multipart CryptoOp type
		_, session, findRV := m.findSession(sessionHandle)
		require.Equal(t, CKR_OK, findRV)

		session.SetOperationByType(OperationVerifySignature, &OperationState{
			Type:     OperationVerifySignature,
			CryptoOp: 42, // wrong type (int instead of *verifySigMultiPartState)
		})

		err := m.VerifySignatureFinal(sessionHandle)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, pkcsErr.Code)
	})
}
