// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package module

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pssMessageParams returns the CK_RSA_PKCS_PSS_PARAMS a C_MessageVerifyInit
// caller supplies for CKM_RSA_PKCS_PSS with SHA-256 and a full-length salt.
func pssMessageParams() *RSAPSSParams {
	return &RSAPSSParams{
		HashAlg: CKM_SHA256,
		MGF:     CKG_MGF1_SHA256,
		SaltLen: 32,
	}
}

// TestVerifyMessagePreservesMechanismParameters is the regression test for a
// message-based verification process losing its CK_MECHANISM parameters.
//
// PKCS#11 v3.2 §5.16.2: "A call to C_VerifyMessage starts and terminates a
// message verification operation. C_VerifyMessage does not finish the
// message-based verification process." The process must therefore survive each
// message with the mechanism the application named — parameters included.
//
// C_VerifyMessage used to re-establish the process from OperationState alone,
// which records only the CK_MECHANISM_TYPE. For CKM_RSA_PKCS_PSS that meant
// re-initializing with no CK_RSA_PKCS_PSS_PARAMS at all, which
// validateRSAPSSParams rejects: a valid signature was reported to the
// application as CKR_MECHANISM_PARAM_INVALID, and the process was left dead.
func TestVerifyMessagePreservesMechanismParameters(t *testing.T) {
	m, handle, keyHandle := createTestModuleWithVerifyKey(t)
	defer m.Finalize()

	mech := NewMechanismWithTypedParams(CKM_RSA_PKCS_PSS, pssMessageParams())

	require.Equal(t, CKR_OK, m.MessageVerifyInit(handle, mech, keyHandle))

	// The verdict for a valid signature must be CKR_OK, not the
	// CKR_MECHANISM_PARAM_INVALID a parameterless re-init produced.
	require.Equal(t, CKR_OK, m.VerifyMessage(handle, []byte("message-one"), []byte("mock-signature")),
		"a valid signature must be reported as CKR_OK, not as a parameter error")

	// The parameters must have reached the backend, not merely have been
	// accepted at the boundary: "pss" comes from the mechanism's
	// CK_RSA_PKCS_PSS_PARAMS, and a bare CKM_RSA_PKCS_PSS carries neither.
	client, ok := m.cryptoManager.client.(*mockClient)
	require.True(t, ok, "test fixture must drive the mock transport")
	require.NotNil(t, client.lastVerifyReq)
	assert.Equal(t, "pss", client.lastVerifyReq.Padding)
	assert.Equal(t, 32, client.lastVerifyReq.SaltLength)

	// §5.16.2 again: the process outlives the message, so a second message
	// must verify under the same mechanism and parameters.
	require.Equal(t, CKR_OK, m.VerifyMessage(handle, []byte("message-two"), []byte("mock-signature")),
		"the message-based process must survive the first message")
	assert.Equal(t, "pss", client.lastVerifyReq.Padding,
		"the re-established process must still carry CK_RSA_PKCS_PSS_PARAMS")
	assert.Equal(t, 32, client.lastVerifyReq.SaltLength)

	// Only C_MessageVerifyFinal tears the process down.
	assert.Equal(t, CKR_OK, m.MessageVerifyFinal(handle))
}

// TestVerifyMessageRestoredOperationCarriesTypedParameter asserts the restored
// operation is the one C_MessageVerifyInit built, by inspecting the mechanism
// the session still holds. Re-initializing from the mechanism type would leave
// TypedParameter nil even where validation happened to pass, so the request the
// next message builds would differ from the one the application asked for.
func TestVerifyMessageRestoredOperationCarriesTypedParameter(t *testing.T) {
	m, handle, keyHandle := createTestModuleWithVerifyKey(t)
	defer m.Finalize()

	mech := NewMechanismWithTypedParams(CKM_RSA_PKCS_PSS, pssMessageParams())
	require.Equal(t, CKR_OK, m.MessageVerifyInit(handle, mech, keyHandle))
	require.Equal(t, CKR_OK, m.VerifyMessage(handle, []byte("message"), []byte("mock-signature")))

	_, session, rv := m.findSession(handle)
	require.Equal(t, CKR_OK, rv)

	opState := session.GetOperationByType(OperationVerify)
	require.NotNil(t, opState, "the message verification process must still be active")

	verifyOp, ok := opState.CryptoOp.(*VerifyOperation)
	require.True(t, ok, "the restored operation must be the one C_MessageVerifyInit built")
	require.False(t, verifyOp.IsFinalized(), "the restored operation must be rearmed for the next message")

	params, ok := verifyOp.Mechanism().TypedParameter.(*RSAPSSParams)
	require.True(t, ok, "the restored operation must still carry CK_RSA_PKCS_PSS_PARAMS")
	assert.Equal(t, CKM_SHA256, params.HashAlg)
	assert.Equal(t, uint32(32), params.SaltLen)
}

// TestVerifyMessageInvalidSignatureKeepsProcessUsable covers the bad-input side
// of the same contract: an invalid signature is a verdict about the message,
// not a fault in the process, so the process must remain initialized.
func TestVerifyMessageInvalidSignatureKeepsProcessUsable(t *testing.T) {
	m, handle, keyHandle := createTestModuleWithVerifyKey(t)
	defer m.Finalize()

	client, ok := m.cryptoManager.client.(*mockClient)
	require.True(t, ok)
	client.verifyResponse.Valid = false

	mech := NewMechanismWithTypedParams(CKM_RSA_PKCS_PSS, pssMessageParams())
	require.Equal(t, CKR_OK, m.MessageVerifyInit(handle, mech, keyHandle))

	assert.Equal(t, CKR_SIGNATURE_INVALID, m.VerifyMessage(handle, []byte("message"), []byte("bad-signature")))

	// The verdict must not have consumed the process.
	client.verifyResponse.Valid = true
	assert.Equal(t, CKR_OK, m.VerifyMessage(handle, []byte("message"), []byte("mock-signature")))
	assert.Equal(t, CKR_OK, m.MessageVerifyFinal(handle))
}

// TestMessageOperationBindingRejectsBadInput covers the error paths of the two
// helpers C_VerifyMessage relies on.
func TestMessageOperationBindingRejectsBadInput(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()

	handle := loginAsNormalUser(t, m)

	t.Run("no operation initialized", func(t *testing.T) {
		opState, rv := m.messageOperationBinding(handle, OperationVerify)
		assert.Nil(t, opState)
		assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, rv)
	})

	t.Run("invalid session handle", func(t *testing.T) {
		opState, rv := m.messageOperationBinding(SessionHandle(99999), OperationVerify)
		assert.Nil(t, opState)
		assert.Equal(t, CKR_SESSION_HANDLE_INVALID, rv)
	})

	t.Run("restore refuses a nil operation", func(t *testing.T) {
		assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, m.restoreMessageOperation(handle, nil))
	})

	t.Run("restore refuses an invalid session handle", func(t *testing.T) {
		assert.Equal(t, CKR_SESSION_HANDLE_INVALID,
			m.restoreMessageOperation(SessionHandle(99999), &OperationState{Type: OperationVerify}))
	})
}

// bindObjectToBackend gives a key object the backend key id a
// backend-resident key would carry.
//
// C_CreateObject makes a key that exists only in this module's object store:
// it has no backend key id, so C_WrapKey cannot name it to the service as a
// wrapping key. Tests whose subject is something other than key residency use
// this to stand a created key in for a generated one.
func bindObjectToBackend(t *testing.T, m *Module, handle ObjectHandle, keyID string) {
	t.Helper()

	obj, err := m.objectManager.getObjectUnchecked(handle)
	require.NoError(t, err)
	obj.KeyID = keyID
	obj.BackendName = "default"
}

// requireBoundToBackend asserts that an object names a backend key, and returns
// the key id it names.
//
// It is the counterpart to bindObjectToBackend for the keys that no longer need
// binding by hand: C_CreateObject imports a secret key's material, so the
// object comes back already naming a key the backend holds. Asserting that,
// rather than assigning it, is what keeps a test honest about the import having
// happened -- a fixture that quietly assigned the id would still pass if the
// import silently stopped working.
func requireBoundToBackend(t *testing.T, m *Module, handle ObjectHandle) string {
	t.Helper()

	obj, err := m.objectManager.getObjectUnchecked(handle)
	require.NoError(t, err)
	require.NotEmpty(t, obj.KeyID,
		"C_CreateObject must have imported this key's material and given it a backend key id")
	require.NotEmpty(t, obj.BackendName, "an imported key must name the backend that holds it")

	return obj.KeyID
}
