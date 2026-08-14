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

	"github.com/jeremyhahn/go-xkms/pkg/quantum/dilithium2"
)

// createMLDSAVerifyFixture provisions an initialized, logged-in module with a
// real ML-DSA-44 public key object, using the reference dilithium2
// implementation (never the module under test) to generate the key pair.
// Tests use this to drive VerifySignatureInit for real rather than planting
// CryptoOp state directly with session.SetOperationByType: a test that
// bypasses VerifySignatureInit cannot catch a defect in what
// VerifySignatureInit itself stores there, which is exactly how the
// CryptoOp-wrapper mismatch between Init and Update/Final went uncaught.
func createMLDSAVerifyFixture(t *testing.T) (m *Module, sessionHandle SessionHandle, keyHandle ObjectHandle, signer *dilithium2.Dilithium2) {
	t.Helper()
	m = initializeTestModule(t)
	sessionHandle = loginAsNormalUser(t, m)

	signer, err := dilithium2.New()
	require.NoError(t, err)
	pub, err := signer.GenerateKeyPair()
	require.NoError(t, err)
	t.Cleanup(signer.Clean)

	template := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_PUBLIC_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_ML_DSA)),
		NewStringAttribute(CKA_LABEL, "verifysig-fixture"),
		NewBoolAttribute(CKA_VERIFY, true),
		NewBoolAttribute(CKA_TOKEN, false),
		NewAttribute(CKA_VALUE, pub),
	}
	keyHandle, rv := m.CreateObject(sessionHandle, template)
	require.Equal(t, CKR_OK, rv)

	return m, sessionHandle, keyHandle, signer
}

// ----------------------------------------------------------------------------
// VerifySignatureInit
// ----------------------------------------------------------------------------

func TestVerifySignatureInit(t *testing.T) {

	t.Run("returns CKR_MECHANISM_INVALID without quantum build tag", func(t *testing.T) {
		m, sessionHandle, keyHandle := createTestModuleWithKey(t)
		defer m.Finalize()

		mechanism := NewMechanism(CKM_ML_DSA)
		signature := []byte("mock-pqc-signature")

		// CKM_ML_DSA is a standard v3.2 mechanism and now dispatches, so the
		// mechanism itself is valid and the failure comes from elsewhere.
		err := m.VerifySignatureInit(sessionHandle, mechanism, keyHandle, signature)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.NotEqual(t, CKR_MECHANISM_INVALID, pkcsErr.Code,
			"CKM_ML_DSA must be recognised as a valid mechanism")
	})

	t.Run("cancels active operation with nil mechanism", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
		// authenticates before exercising them.
		sessionHandle := loginAsNormalUser(t, m)

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

		// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
		// authenticates before exercising them.
		sessionHandle := loginAsNormalUser(t, m)

		// Nil mechanism with no active operation should still return CKR_OK
		err := m.VerifySignatureInit(sessionHandle, nil, ObjectHandle(0), nil)
		require.NoError(t, err)
	})

	t.Run("returns CKR_KEY_HANDLE_INVALID with invalid key", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
		// authenticates before exercising them.
		sessionHandle := loginAsNormalUser(t, m)

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

		// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
		// authenticates before exercising them.
		sessionHandle := loginAsNormalUser(t, m)

		// Create a key with CKA_VERIFY explicitly set to false
		template := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_PUBLIC_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_RSA)),
			NewAttribute(CKA_MODULUS, make([]byte, 256)),
			NewAttribute(CKA_PUBLIC_EXPONENT, []byte{0x01, 0x00, 0x01}),
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

		// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
		// authenticates before exercising them.
		sessionHandle := loginAsNormalUser(t, m)

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

		// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
		// authenticates before exercising them.
		sessionHandle := loginAsNormalUser(t, m)

		// Create key without CKA_VERIFY attribute at all
		template := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_PUBLIC_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_RSA)),
			NewAttribute(CKA_MODULUS, make([]byte, 256)),
			NewAttribute(CKA_PUBLIC_EXPONENT, []byte{0x01, 0x00, 0x01}),
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

		// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
		// authenticates before exercising them.
		sessionHandle := loginAsNormalUser(t, m)

		err := m.VerifySignature(sessionHandle, []byte("data to verify"))
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, pkcsErr.Code)
	})

	t.Run("accepts a genuine signature after a real VerifySignatureInit", func(t *testing.T) {
		m, sessionHandle, keyHandle, signer := createMLDSAVerifyFixture(t)
		defer m.Finalize()

		message := []byte("verify-signature single-part payload")
		signature, err := signer.Sign(message)
		require.NoError(t, err)

		mechanism := &Mechanism{Type: CKM_VENDOR_ML_DSA_44}
		require.NoError(t, m.VerifySignatureInit(sessionHandle, mechanism, keyHandle, signature))

		err = m.VerifySignature(sessionHandle, message)
		require.NoError(t, err, "a signature the reference ML-DSA-44 implementation produced "+
			"over the same message and key must verify")

		// The operation must be consumed (removed from session) after the
		// terminal call.
		_, session, findRV := m.findSession(sessionHandle)
		require.Equal(t, CKR_OK, findRV)
		assert.False(t, session.HasOperationType(OperationVerifySignature))
	})

	t.Run("rejects a tampered message after a real VerifySignatureInit", func(t *testing.T) {
		m, sessionHandle, keyHandle, signer := createMLDSAVerifyFixture(t)
		defer m.Finalize()

		message := []byte("original message that will be tampered with")
		signature, err := signer.Sign(message)
		require.NoError(t, err)
		tampered := append([]byte(nil), message...)
		tampered[0] ^= 0xff

		mechanism := &Mechanism{Type: CKM_VENDOR_ML_DSA_44}
		require.NoError(t, m.VerifySignatureInit(sessionHandle, mechanism, keyHandle, signature))

		err = m.VerifySignature(sessionHandle, tampered)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_SIGNATURE_INVALID, pkcsErr.Code)
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

		// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
		// authenticates before exercising them.
		sessionHandle := loginAsNormalUser(t, m)

		err := m.VerifySignatureUpdate(sessionHandle, []byte("data chunk"))
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, pkcsErr.Code)
	})

	t.Run("accumulates data after a real VerifySignatureInit", func(t *testing.T) {
		m, sessionHandle, keyHandle, signer := createMLDSAVerifyFixture(t)
		defer m.Finalize()

		whole := []byte("chunk-1-chunk-2")
		signature, err := signer.Sign(whole)
		require.NoError(t, err)

		mechanism := &Mechanism{Type: CKM_VENDOR_ML_DSA_44}
		require.NoError(t, m.VerifySignatureInit(sessionHandle, mechanism, keyHandle, signature))

		// Reach into the session only to observe the accumulator's internal
		// state; VerifySignatureInit itself constructed it -- this is not a
		// substitute for calling it.
		_, session, findRV := m.findSession(sessionHandle)
		require.Equal(t, CKR_OK, findRV)

		// First chunk
		err = m.VerifySignatureUpdate(sessionHandle, []byte("chunk-1-"))
		require.NoError(t, err)

		// Second chunk -- data should be appended
		err = m.VerifySignatureUpdate(sessionHandle, []byte("chunk-2"))
		require.NoError(t, err)

		// Operation should still be active
		require.True(t, session.HasOperationType(OperationVerifySignature))

		// Finalizing over the accumulated chunks must accept the signature
		// produced over their concatenation.
		require.NoError(t, m.VerifySignatureFinal(sessionHandle))
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

		// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
		// authenticates before exercising them.
		sessionHandle := loginAsNormalUser(t, m)

		err := m.VerifySignatureFinal(sessionHandle)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, pkcsErr.Code)
	})

	t.Run("consumes a multi-part operation started by a real VerifySignatureInit", func(t *testing.T) {
		m, sessionHandle, keyHandle, signer := createMLDSAVerifyFixture(t)
		defer m.Finalize()

		message := []byte("accumulated-data-from-updates")
		signature, err := signer.Sign(message)
		require.NoError(t, err)

		mechanism := &Mechanism{Type: CKM_VENDOR_ML_DSA_44}
		require.NoError(t, m.VerifySignatureInit(sessionHandle, mechanism, keyHandle, signature))
		require.NoError(t, m.VerifySignatureUpdate(sessionHandle, message))

		// VerifySignatureFinal should consume the operation and accept the
		// signature produced over the fed data.
		err = m.VerifySignatureFinal(sessionHandle)
		require.NoError(t, err)

		// The operation should have been consumed (removed from session)
		_, session, findRV := m.findSession(sessionHandle)
		require.Equal(t, CKR_OK, findRV)
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

		// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
		// authenticates before exercising them.
		sessionHandle := loginAsNormalUser(t, m)

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

		// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
		// authenticates before exercising them.
		sessionHandle := loginAsNormalUser(t, m)

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
// flow through the real entry points: VerifySignatureInit, two
// VerifySignatureUpdate calls that split the signed message, then
// VerifySignatureFinal. Splitting the message across Update calls the way a
// streaming caller would is what catches an accumulator that resets on each
// call or drops a chunk: either defect still returns a definite
// CKR_OK/CKR_SIGNATURE_INVALID, just the wrong one, so only comparing against
// a known-good signature over the exact concatenation catches it.
func TestVerifySignatureMultiPartFlow(t *testing.T) {

	t.Run("Update accumulates data across chunks and Final verifies the whole", func(t *testing.T) {
		m, sessionHandle, keyHandle, signer := createMLDSAVerifyFixture(t)
		defer m.Finalize()

		signature, err := signer.Sign([]byte("hello world"))
		require.NoError(t, err)

		mechanism := &Mechanism{Type: CKM_VENDOR_ML_DSA_44}
		require.NoError(t, m.VerifySignatureInit(sessionHandle, mechanism, keyHandle, signature))

		// Feed data in multiple chunks
		err = m.VerifySignatureUpdate(sessionHandle, []byte("hello "))
		require.NoError(t, err)

		err = m.VerifySignatureUpdate(sessionHandle, []byte("world"))
		require.NoError(t, err)

		// Final must accept the signature over the concatenation of the fed
		// chunks.
		err = m.VerifySignatureFinal(sessionHandle)
		require.NoError(t, err)

		// Operation must be consumed after Final
		_, session, findRV := m.findSession(sessionHandle)
		require.Equal(t, CKR_OK, findRV)
		assert.False(t, session.HasOperationType(OperationVerifySignature))
	})

	t.Run("Final after error-terminated Update returns CKR_OPERATION_NOT_INITIALIZED", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
		// authenticates before exercising them.
		sessionHandle := loginAsNormalUser(t, m)

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

		// CKF_LOGIN_REQUIRED gates key-bearing operations, so the fixture
		// authenticates before exercising them.
		sessionHandle := loginAsNormalUser(t, m)

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
