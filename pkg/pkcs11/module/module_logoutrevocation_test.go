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

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// privateSecretKeyTemplate is an AES key marked CKA_PRIVATE, so C_Logout's
// revocation sweep reaches every operation started under it.
//
// revokeLoginBoundOperations marks an operation exactly when its key is a
// private object, which PKCS#11 v3.2 §4.2 makes reachable only to an
// authenticated normal user. A public key would not be revoked, which is the
// negative case TestLogoutRevokesOperationsBoundToPrivateKeys already covers.
func revocablePrivateAESKeyTemplate(label string) []Attribute {
	return []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewStringAttribute(CKA_LABEL, label),
		NewBoolAttribute(CKA_PRIVATE, true),
		NewBoolAttribute(CKA_TOKEN, false),
		NewBoolAttribute(CKA_ENCRYPT, true),
		NewBoolAttribute(CKA_DECRYPT, true),
		NewAttribute(CKA_VALUE, []byte("0123456789ABCDEF")),
	}
}

// gcmMechanism returns a fresh CKM_AES_GCM mechanism with the given IV. Each
// operation needs its own: the module refuses a nonce already used under the
// same key.
func revocationGCMMechanism(iv string) *Mechanism {
	return NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams([]byte(iv), 128))
}

// loggedInWithPrivateKey initializes a module, logs in and creates a private
// key of the given template, returning both handles.
func loggedInWithPrivateKey(t *testing.T, template []Attribute) (*Module, SessionHandle, ObjectHandle) {
	t.Helper()

	m := initializeTestModule(t)
	session := loginAsNormalUser(t, m)

	keyHandle, rv := m.CreateObject(session, template)
	require.Equal(t, CKR_OK, rv)

	return m, session, keyHandle
}

// TestCachedResultCannotBeReplayedAfterLogout closes the hole the §5.2 two-call
// convention opened in C_Logout's revocation.
//
// A terminal operation computes its output on the length query and caches it,
// then hands it to the application on the second call. The output has been
// produced but NOT yet released, so a C_Logout in between must stop it: §5.6.10
// withdraws the authentication the operation was started under. While the
// cached replay ran before requireOperationAuthorization, the second call was a
// cache hit and the guard was never reached, so the sequence
//
//	C_Login, C_DecryptInit(private key), C_Decrypt(NULL_PTR), C_Logout, C_Decrypt(buf)
//
// returned recovered plaintext under CKR_OK to a session no longer entitled to
// it. The same shape applied to C_Sign, C_Encrypt and all their *Final forms.
func TestCachedResultCannotBeReplayedAfterLogout(t *testing.T) {
	t.Run("C_Decrypt", func(t *testing.T) {
		m, session, keyHandle := loggedInWithPrivateKey(t, revocablePrivateAESKeyTemplate("cache-replay-decrypt"))
		defer m.Finalize()

		require.Equal(t, CKR_OK, m.DecryptInit(session, revocationGCMMechanism("cache-dec-01"), keyHandle))

		// The length query: the plaintext is recovered and cached, and the
		// operation stays active for the collecting call.
		first, rv := m.Decrypt(session, []byte("ciphertext-and-tag-bytes--------"))
		require.Equal(t, CKR_OK, rv)
		require.NotEmpty(t, first)

		require.Equal(t, CKR_OK, m.Logout(session))

		replayed, rv := m.Decrypt(session, []byte("ciphertext-and-tag-bytes--------"))
		assert.Equal(t, CKR_USER_NOT_LOGGED_IN, rv,
			"a cached result must not be handed over after the authorization was withdrawn")
		assert.Nil(t, replayed, "no plaintext may be released without authentication")
	})

	t.Run("C_Sign", func(t *testing.T) {
		m, session, keyHandle := loggedInWithPrivateKey(t, signableKeyTemplate("cache-replay-sign"))
		defer m.Finalize()

		require.Equal(t, CKR_OK, m.SignInit(session, &Mechanism{Type: CKM_RSA_PKCS}, keyHandle))

		first, rv := m.Sign(session, []byte("data"))
		require.Equal(t, CKR_OK, rv)
		require.NotEmpty(t, first)

		require.Equal(t, CKR_OK, m.Logout(session))

		replayed, rv := m.Sign(session, []byte("data"))
		assert.Equal(t, CKR_USER_NOT_LOGGED_IN, rv)
		assert.Nil(t, replayed)
	})

	// The two message-based *Next verbs cache a final result the same way, so
	// the guard placed ahead of their replay is load-bearing for the same
	// reason.
	t.Run("C_EncryptMessageNext", func(t *testing.T) {
		m, session, keyHandle := loggedInWithPrivateKey(t, revocablePrivateAESKeyTemplate("cache-replay-encnext"))
		defer m.Finalize()

		client, ok := m.cryptoManager.client.(*mockClient)
		require.True(t, ok)
		client.encryptResponse = &transport.EncryptResponse{
			Ciphertext: []byte("plaintext"),
			Tag:        make([]byte, 16),
		}

		require.Equal(t, CKR_OK, m.MessageEncryptInit(session, revocationGCMMechanism("cache-enx-01"), keyHandle))
		require.Equal(t, CKR_OK, m.EncryptMessageBegin(session, nil, nil))

		params := &AESGCMMessageParams{IV: []byte("cache-enx-02"), IVGenerator: CKG_NO_GENERATE, TagBits: 128}
		first, rv := m.EncryptMessageNext(session, params, []byte("plaintext"), true)
		require.Equal(t, CKR_OK, rv)
		require.NotEmpty(t, first)

		require.Equal(t, CKR_OK, m.Logout(session))

		replayed, rv := m.EncryptMessageNext(session, params, []byte("plaintext"), true)
		assert.Equal(t, CKR_USER_NOT_LOGGED_IN, rv,
			"the guard must precede the cached-result replay")
		assert.Nil(t, replayed)
	})

	t.Run("C_DecryptMessageNext", func(t *testing.T) {
		m, session, keyHandle := loggedInWithPrivateKey(t, revocablePrivateAESKeyTemplate("cache-replay-decnext"))
		defer m.Finalize()

		require.Equal(t, CKR_OK, m.MessageDecryptInit(session, revocationGCMMechanism("cache-dnx-01"), keyHandle))
		require.Equal(t, CKR_OK, m.DecryptMessageBegin(session, nil, nil))

		params := &AESGCMMessageParams{IV: []byte("cache-dnx-02"), IVGenerator: CKG_NO_GENERATE, TagBits: 128, Tag: make([]byte, 16)}
		first, rv := m.DecryptMessageNext(session, params, []byte("ciphertext"), true)
		require.Equal(t, CKR_OK, rv)
		require.NotEmpty(t, first)

		require.Equal(t, CKR_OK, m.Logout(session))

		replayed, rv := m.DecryptMessageNext(session, params, []byte("ciphertext"), true)
		assert.Equal(t, CKR_USER_NOT_LOGGED_IN, rv,
			"the guard must precede the cached-result replay")
		assert.Nil(t, replayed)
	})

	t.Run("C_Encrypt", func(t *testing.T) {
		m, session, keyHandle := loggedInWithPrivateKey(t, revocablePrivateAESKeyTemplate("cache-replay-encrypt"))
		defer m.Finalize()

		require.Equal(t, CKR_OK, m.EncryptInit(session, revocationGCMMechanism("cache-enc-01"), keyHandle))

		first, rv := m.Encrypt(session, []byte("plaintext"))
		require.Equal(t, CKR_OK, rv)
		require.NotEmpty(t, first)

		require.Equal(t, CKR_OK, m.Logout(session))

		replayed, rv := m.Encrypt(session, []byte("plaintext"))
		assert.Equal(t, CKR_USER_NOT_LOGGED_IN, rv)
		assert.Nil(t, replayed)
	})
}

// TestCachedResultStillServesTheTwoCallConvention is the positive control the
// fix above must not break.
//
// PKCS#11 v3.2 §5.2 requires the second call to return the same bytes without
// re-running the operation: an AEAD encryption run twice would consume a second
// nonce, and a decryption run twice would be a second use of the key. Removing
// the cache would "fix" the replay hole and break this, so both are asserted.
func TestCachedResultStillServesTheTwoCallConvention(t *testing.T) {
	m, session, keyHandle := loggedInWithPrivateKey(t, revocablePrivateAESKeyTemplate("cache-two-call"))
	defer m.Finalize()

	oracle, ok := m.cryptoManager.client.(*mockClient)
	require.True(t, ok)

	require.Equal(t, CKR_OK, m.EncryptInit(session, revocationGCMMechanism("cache-two-01"), keyHandle))

	first, rv := m.Encrypt(session, []byte("plaintext"))
	require.Equal(t, CKR_OK, rv)
	require.NotEmpty(t, first)

	oracle.encryptCalled = false

	second, rv := m.Encrypt(session, []byte("plaintext"))
	require.Equal(t, CKR_OK, rv, "the collecting call must succeed with no intervening logout")
	assert.Equal(t, first, second, "the second call must return the identical bytes")
	assert.False(t, oracle.encryptCalled, "the operation must not be run a second time")
}

// TestLogoutRevokesMessageBasedAndDualFunctionOperations covers the eight verbs
// that consulted no authorization at all.
//
// Each drives a key or a buffered operation established before C_Logout, and
// each must refuse afterwards with the code §5.6.10's condition calls for.
// C_Sign, C_SignFinal and C_Decrypt were already covered; the message-based and
// dual-function verbs reach the same operation state by a different path, and
// nothing asked whether they honoured the revocation.
func TestLogoutRevokesMessageBasedAndDualFunctionOperations(t *testing.T) {
	t.Run("C_EncryptMessage", func(t *testing.T) {
		m, session, keyHandle := loggedInWithPrivateKey(t, revocablePrivateAESKeyTemplate("revoke-encrypt-message"))
		defer m.Finalize()

		require.Equal(t, CKR_OK, m.MessageEncryptInit(session, revocationGCMMechanism("revoke-em-01"), keyHandle))
		require.Equal(t, CKR_OK, m.Logout(session))

		out, rv := m.EncryptMessage(session, &AESGCMMessageParams{TagBits: 128}, nil, []byte("plaintext"))
		assert.Equal(t, CKR_USER_NOT_LOGGED_IN, rv)
		assert.Nil(t, out)
	})

	t.Run("C_EncryptMessageNext", func(t *testing.T) {
		m, session, keyHandle := loggedInWithPrivateKey(t, revocablePrivateAESKeyTemplate("revoke-encrypt-next"))
		defer m.Finalize()

		require.Equal(t, CKR_OK, m.MessageEncryptInit(session, revocationGCMMechanism("revoke-en-01"), keyHandle))
		require.Equal(t, CKR_OK, m.EncryptMessageBegin(session, nil, nil))
		require.Equal(t, CKR_OK, m.Logout(session))

		out, rv := m.EncryptMessageNext(session, &AESGCMMessageParams{TagBits: 128}, []byte("part"), false)
		assert.Equal(t, CKR_USER_NOT_LOGGED_IN, rv)
		assert.Nil(t, out)
	})

	t.Run("C_DecryptMessage", func(t *testing.T) {
		m, session, keyHandle := loggedInWithPrivateKey(t, revocablePrivateAESKeyTemplate("revoke-decrypt-message"))
		defer m.Finalize()

		require.Equal(t, CKR_OK, m.MessageDecryptInit(session, revocationGCMMechanism("revoke-dm-01"), keyHandle))
		require.Equal(t, CKR_OK, m.Logout(session))

		out, rv := m.DecryptMessage(session,
			&AESGCMMessageParams{IV: []byte("revoke-dm-01"), TagBits: 128, Tag: make([]byte, 16)},
			nil, []byte("ciphertext"))
		assert.Equal(t, CKR_USER_NOT_LOGGED_IN, rv)
		assert.Nil(t, out)
	})

	t.Run("C_DecryptMessageNext", func(t *testing.T) {
		m, session, keyHandle := loggedInWithPrivateKey(t, revocablePrivateAESKeyTemplate("revoke-decrypt-next"))
		defer m.Finalize()

		require.Equal(t, CKR_OK, m.MessageDecryptInit(session, revocationGCMMechanism("revoke-dn-01"), keyHandle))
		require.Equal(t, CKR_OK, m.DecryptMessageBegin(session, nil, nil))
		require.Equal(t, CKR_OK, m.Logout(session))

		out, rv := m.DecryptMessageNext(session, &AESGCMMessageParams{TagBits: 128}, []byte("part"), false)
		assert.Equal(t, CKR_USER_NOT_LOGGED_IN, rv)
		assert.Nil(t, out)
	})

	t.Run("C_DigestEncryptUpdate", func(t *testing.T) {
		m, session, keyHandle := loggedInWithPrivateKey(t, revocablePrivateAESKeyTemplate("revoke-digest-encrypt"))
		defer m.Finalize()

		require.Equal(t, CKR_OK, m.DigestInit(session, &Mechanism{Type: CKM_SHA256}))
		require.Equal(t, CKR_OK, m.EncryptInit(session, revocationGCMMechanism("revoke-de-01"), keyHandle))
		require.Equal(t, CKR_OK, m.Logout(session))

		out, rv := m.DigestEncryptUpdate(session, []byte("part"))
		assert.Equal(t, CKR_USER_NOT_LOGGED_IN, rv)
		assert.Nil(t, out)
	})

	t.Run("C_DecryptDigestUpdate", func(t *testing.T) {
		m, session, keyHandle := loggedInWithPrivateKey(t, revocablePrivateAESKeyTemplate("revoke-decrypt-digest"))
		defer m.Finalize()

		require.Equal(t, CKR_OK, m.DecryptInit(session, revocationGCMMechanism("revoke-dd-01"), keyHandle))
		require.Equal(t, CKR_OK, m.DigestInit(session, &Mechanism{Type: CKM_SHA256}))
		require.Equal(t, CKR_OK, m.Logout(session))

		out, rv := m.DecryptDigestUpdate(session, []byte("part"))
		assert.Equal(t, CKR_USER_NOT_LOGGED_IN, rv)
		assert.Nil(t, out)
	})

	t.Run("C_SignEncryptUpdate", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()
		session := loginAsNormalUser(t, m)

		signKey, rv := m.CreateObject(session, signableKeyTemplate("revoke-sign-encrypt-sign"))
		require.Equal(t, CKR_OK, rv)
		encKey, rv := m.CreateObject(session, revocablePrivateAESKeyTemplate("revoke-sign-encrypt-enc"))
		require.Equal(t, CKR_OK, rv)

		require.Equal(t, CKR_OK, m.SignInit(session, &Mechanism{Type: CKM_RSA_PKCS}, signKey))
		require.Equal(t, CKR_OK, m.EncryptInit(session, revocationGCMMechanism("revoke-se-01"), encKey))
		require.Equal(t, CKR_OK, m.Logout(session))

		out, rv := m.SignEncryptUpdate(session, []byte("part"))
		assert.Equal(t, CKR_USER_NOT_LOGGED_IN, rv)
		assert.Nil(t, out)
	})

	t.Run("C_DecryptVerifyUpdate", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()
		session := loginAsNormalUser(t, m)

		decKey, rv := m.CreateObject(session, revocablePrivateAESKeyTemplate("revoke-decrypt-verify-dec"))
		require.Equal(t, CKR_OK, rv)
		verifyKey, rv := m.CreateObject(session, []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_PUBLIC_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_RSA)),
			NewAttribute(CKA_MODULUS, make([]byte, 256)),
			NewAttribute(CKA_PUBLIC_EXPONENT, []byte{0x01, 0x00, 0x01}),
			NewStringAttribute(CKA_LABEL, "revoke-decrypt-verify-vfy"),
			NewBoolAttribute(CKA_VERIFY, true),
			NewBoolAttribute(CKA_TOKEN, false),
		})
		require.Equal(t, CKR_OK, rv)

		require.Equal(t, CKR_OK, m.DecryptInit(session, revocationGCMMechanism("revoke-dv-01"), decKey))
		require.Equal(t, CKR_OK, m.VerifyInit(session, &Mechanism{Type: CKM_RSA_PKCS}, verifyKey))
		require.Equal(t, CKR_OK, m.Logout(session))

		out, rv := m.DecryptVerifyUpdate(session, []byte("part"))
		assert.Equal(t, CKR_USER_NOT_LOGGED_IN, rv)
		assert.Nil(t, out)
	})
}

// TestMessageAndDualFunctionVerbsWorkWhileLoggedIn is the counterweight: the
// eight guards must refuse a revoked operation and nothing else. A guard that
// refused unconditionally would pass every assertion above.
func TestMessageAndDualFunctionVerbsWorkWhileLoggedIn(t *testing.T) {
	t.Run("C_EncryptMessage", func(t *testing.T) {
		m, session, keyHandle := loggedInWithPrivateKey(t, revocablePrivateAESKeyTemplate("allow-encrypt-message"))
		defer m.Finalize()

		// C_EncryptMessage returns the tag out of band in
		// CK_GCM_MESSAGE_PARAMS.pTag, so the transport must answer with a
		// full-length one for the split to have anything to take.
		client, ok := m.cryptoManager.client.(*mockClient)
		require.True(t, ok)
		client.encryptResponse = &transport.EncryptResponse{
			Ciphertext: []byte("plaintext"),
			Tag:        make([]byte, 16),
		}

		require.Equal(t, CKR_OK, m.MessageEncryptInit(session, revocationGCMMechanism("allow-em-001"), keyHandle))

		// CK_GCM_MESSAGE_PARAMS.ivGenerator CKG_NO_GENERATE means the caller
		// supplies the IV, so one is supplied (v3.2 §6.13.5).
		out, rv := m.EncryptMessage(session,
			&AESGCMMessageParams{IV: []byte("allow-em-002"), IVGenerator: CKG_NO_GENERATE, TagBits: 128},
			nil, []byte("plaintext"))
		assert.Equal(t, CKR_OK, rv)
		assert.NotNil(t, out)
	})

	t.Run("C_DigestEncryptUpdate", func(t *testing.T) {
		m, session, keyHandle := loggedInWithPrivateKey(t, revocablePrivateAESKeyTemplate("allow-digest-encrypt"))
		defer m.Finalize()

		require.Equal(t, CKR_OK, m.DigestInit(session, &Mechanism{Type: CKM_SHA256}))
		require.Equal(t, CKR_OK, m.EncryptInit(session, revocationGCMMechanism("allow-de-001"), keyHandle))

		_, rv := m.DigestEncryptUpdate(session, []byte("part"))
		assert.Equal(t, CKR_OK, rv)
	})

	t.Run("C_SignEncryptUpdate", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()
		session := loginAsNormalUser(t, m)

		signKey, rv := m.CreateObject(session, signableKeyTemplate("allow-sign-encrypt-sign"))
		require.Equal(t, CKR_OK, rv)
		encKey, rv := m.CreateObject(session, revocablePrivateAESKeyTemplate("allow-sign-encrypt-enc"))
		require.Equal(t, CKR_OK, rv)

		require.Equal(t, CKR_OK, m.SignInit(session, &Mechanism{Type: CKM_RSA_PKCS}, signKey))
		require.Equal(t, CKR_OK, m.EncryptInit(session, revocationGCMMechanism("allow-se-001"), encKey))

		_, rv = m.SignEncryptUpdate(session, []byte("part"))
		assert.Equal(t, CKR_OK, rv)
	})
}
