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

// The key-management verbs -- C_UnwrapKey, C_UnwrapKeyAuthenticated and
// C_DecapsulateKey -- do not consult CKA_ALWAYS_AUTHENTICATE.
//
// PKCS#11 v3.2 §4.10 anchors re-authentication on an initiated operation:
// "calling C_Login with userType set to CKU_CONTEXT_SPECIFIC immediately after
// a cryptographic operation using the key has been initiated (e.g. after
// C_SignInit)". None of these three has an Init phase, so an application can
// never issue that login for them.
//
// They used to call requireContextAuthentication anyway, and the claim in the
// code was that the call could never fire. It could. Nothing stops an
// application from initiating a decryption with a key and then unwrapping or
// decapsulating with that same key, and in exactly that case the gate found the
// grant minted for the decryption and spent it -- leaving the decryption the
// application had just re-authenticated for unauthenticated. The tests below
// are the two halves of that: the theft must not happen, and the verbs must not
// start demanding a login no conforming application can supply.

// alwaysAuthenticateDecryptFixture builds a session holding one AES key that is
// usable for decryption, unwrapping and wrapping, carries
// CKA_ALWAYS_AUTHENTICATE, and has a blob C_UnwrapKeyAuthenticated can consume.
//
// The attribute is set after the wrap so the wrap that produces the blob is
// unencumbered and only the calls under test are governed by it.
func alwaysAuthenticateDecryptFixture(t *testing.T) (*Module, SessionHandle, ObjectHandle, []byte) {
	t.Helper()

	m := initializeTestModule(t)
	session := loginAsNormalUser(t, m)

	wrappingKey, targetKey := authWrapPublicKeyPair(t, m, session, []Attribute{
		NewBoolAttribute(CKA_DECRYPT, true),
		NewBoolAttribute(CKA_ENCRYPT, true),
	}, nil)
	bindObjectToBackend(t, m, wrappingKey, "context-auth-kek")

	wrapped, err := m.WrapKeyAuthenticated(session, NewMechanism(CKM_AES_GCM), wrappingKey, targetKey, nil)
	require.NoError(t, err)

	require.Equal(t, CKR_OK, m.SetAttributeValue(session, wrappingKey,
		[]Attribute{NewBoolAttribute(CKA_ALWAYS_AUTHENTICATE, true)}))

	return m, session, wrappingKey, wrapped
}

// TestKeyManagementVerbsDoNotConsumeADecryptContextAuthentication is the
// regression test for the theft.
//
// The application initiates a decryption, re-authenticates for it with
// C_Login(CKU_CONTEXT_SPECIFIC), then unwraps with the same key before calling
// C_Decrypt. The grant belongs to the decryption and must still be there when
// the decryption runs.
func TestKeyManagementVerbsDoNotConsumeADecryptContextAuthentication(t *testing.T) {
	m, session, key, wrapped := alwaysAuthenticateDecryptFixture(t)
	defer m.Finalize()

	require.Equal(t, CKR_OK, m.DecryptInit(session,
		NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(testGCMIV(), 128)), key))
	require.Equal(t, CKR_OK, m.Login(session, CKU_CONTEXT_SPECIFIC, []byte("user-pin-1234")))

	handle, err := m.UnwrapKeyAuthenticated(session, NewMechanism(CKM_AES_GCM), key, wrapped, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewBoolAttribute(CKA_PRIVATE, false),
		NewBoolAttribute(CKA_EXTRACTABLE, true),
	}, nil)
	require.NoError(t, err, "an unwrap must not be gated by CKA_ALWAYS_AUTHENTICATE")
	require.NotEqual(t, ObjectHandle(InvalidHandle), handle)

	// The decryption's own grant must have survived the unwrap. Before the fix
	// this returned CKR_USER_NOT_LOGGED_IN, indistinguishable from a wrong PIN.
	_, rv := m.Decrypt(session, []byte("0123456789ab-ciphertext-and-tag-0123456789abcdef"))
	assert.NotEqual(t, CKR_USER_NOT_LOGGED_IN, rv,
		"C_UnwrapKeyAuthenticated must not spend the grant C_Login minted for the active C_Decrypt")
}

// TestUnwrapVerbsIgnoreAlwaysAuthenticateWithADecryptionActive is the
// bad-input half: the same collision, but with no context-specific login at
// all.
//
// This is the state in which the deleted gate refused the call. A verb that has
// no Init phase must not demand a login the application cannot obtain, whatever
// unrelated operation happens to be active on the key.
func TestUnwrapVerbsIgnoreAlwaysAuthenticateWithADecryptionActive(t *testing.T) {
	t.Run("C_UnwrapKeyAuthenticated", func(t *testing.T) {
		m, session, key, wrapped := alwaysAuthenticateDecryptFixture(t)
		defer m.Finalize()

		require.Equal(t, CKR_OK, m.DecryptInit(session,
			NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(testGCMIV(), 128)), key))

		handle, err := m.UnwrapKeyAuthenticated(session, NewMechanism(CKM_AES_GCM), key, wrapped, []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
			NewBoolAttribute(CKA_PRIVATE, false),
			NewBoolAttribute(CKA_EXTRACTABLE, true),
		}, nil)
		require.NoError(t, err)
		assert.NotEqual(t, ObjectHandle(InvalidHandle), handle)
	})

	t.Run("C_UnwrapKey", func(t *testing.T) {
		m, session, key, wrapped := alwaysAuthenticateDecryptFixture(t)
		defer m.Finalize()

		require.Equal(t, CKR_OK, m.DecryptInit(session,
			NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(testGCMIV(), 128)), key))

		// The mock transport answers the unwrap, so what this asserts is the
		// return code: whatever C_UnwrapKey makes of the blob, it must not be
		// the CKR_USER_NOT_LOGGED_IN the gate produced.
		_, rv := m.UnwrapKey(session, NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(testGCMIV(), 128)),
			key, wrapped, unwrapTemplate())
		assert.NotEqual(t, CKR_USER_NOT_LOGGED_IN, rv,
			"C_UnwrapKey must not demand a re-authentication no conforming application can supply")
	})

	t.Run("C_DecapsulateKey", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()
		session := loginAsNormalUser(t, m)

		privKey, rv := m.CreateObject(session, []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_PRIVATE_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_ML_KEM)),
			NewStringAttribute(CKA_LABEL, "context-auth-kem-private-key"),
			NewBoolAttribute(CKA_DECAPSULATE, true),
			NewBoolAttribute(CKA_DECRYPT, true),
			NewBoolAttribute(CKA_TOKEN, false),
			NewAttribute(CKA_VALUE, make([]byte, 32)),
		})
		require.Equal(t, CKR_OK, rv)
		require.Equal(t, CKR_OK, m.SetAttributeValue(session, privKey,
			[]Attribute{NewBoolAttribute(CKA_ALWAYS_AUTHENTICATE, true)}))

		// An active decryption is the collision that made the deleted gate
		// reachable, so the session needs one -- but it cannot be on this key.
		// C_DecryptInit used to accept CKM_RSA_PKCS against this ML-KEM object,
		// which the test relied on while noting it was "not a claim that the key
		// can perform it". That pairing is now refused with
		// CKR_KEY_TYPE_INCONSISTENT, and correctly: CKM_ML_KEM is
		// encapsulate/decapsulate only, so no decryption mechanism accepts an
		// ML-KEM key and no decryption can ever be active on one.
		//
		// The precondition this test needs is a decryption active in the
		// session, which is what the doc comment above calls the "unrelated
		// operation". An AES key supplies it honestly.
		aesKey, rv := m.CreateObject(session, []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
			NewStringAttribute(CKA_LABEL, "context-auth-active-decrypt-key"),
			NewBoolAttribute(CKA_DECRYPT, true),
			NewBoolAttribute(CKA_TOKEN, false),
			NewBoolAttribute(CKA_SENSITIVE, false),
			NewBoolAttribute(CKA_EXTRACTABLE, true),
			NewAttribute(CKA_VALUE, make([]byte, 32)),
		})
		require.Equal(t, CKR_OK, rv)
		require.Equal(t, CKR_OK, m.DecryptInit(session,
			NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(testGCMIV(), 128)), aesKey))

		_, err := m.DecapsulateKey(session, NewMechanism(CKM_ML_KEM), privKey, []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		}, []byte("ciphertext"))
		if err != nil {
			var pkcsErr *PKCS11Error
			require.ErrorAs(t, err, &pkcsErr)
			assert.NotEqual(t, CKR_USER_NOT_LOGGED_IN, pkcsErr.Code,
				"C_DecapsulateKey must not demand a re-authentication no conforming application can supply")
		}
	})
}
