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

// Context-specific re-authentication, PKCS#11 v3.2 §4.10.
//
// The section defines one protocol and this file holds it to it. Re-authentication
// happens "immediately after a cryptographic operation using the key has been
// initiated (e.g. after C_SignInit)"; in that call "the actual user type is
// implicitly given by the usage requirements of the active key"; success "sets
// the active key in an authenticated state"; and "C_Login will return
// CKR_OPERATION_NOT_INITIALIZED ... if an attempt is made to re-authenticate when
// CKA_ALWAYS_AUTHENTICATE is set to CK_FALSE".
//
// Every clause names one key — the active one. The module used to grant for an
// operation category with no reference to any key, so a re-authentication
// obtained while an unrelated operation was active satisfied a different key's
// requirement, and a C_Login with nothing to authenticate returned CKR_OK and
// granted nothing at all.

// alwaysAuthenticateSigningKey is a private signing key that requires
// re-authentication before each use.
//
// §4.10 permits CKA_ALWAYS_AUTHENTICATE=CK_TRUE only "when CKA_PRIVATE is also
// CK_TRUE", which the private key class supplies.
func alwaysAuthenticateSigningKey(label string) []Attribute {
	return append(signableKeyTemplate(label),
		NewBoolAttribute(CKA_PRIVATE, true),
		NewBoolAttribute(CKA_ALWAYS_AUTHENTICATE, true))
}

// unauthenticatedDecryptionKey is a private decryption key that requires no
// re-authentication. It is the key the bypass was mounted from: a
// C_DecryptInit on it minted a decryption grant that any key could spend.
func unauthenticatedDecryptionKey(label string) []Attribute {
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

// TestContextSpecificLoginRefusesWhenNoActiveKeyRequiresIt is the regression
// test for the bypass.
//
// A C_DecryptInit on a key with no CKA_ALWAYS_AUTHENTICATE used to make
// C_Login(CKU_CONTEXT_SPECIFIC) return CKR_OK and mint a decryption grant, which
// any key carrying the attribute could then spend: one key's re-authentication
// satisfied another key's requirement. PKCS#11 v3.2 §4.10 requires the opposite
// answer — "C_Login will return CKR_OPERATION_NOT_INITIALIZED ... if an attempt
// is made to re-authenticate when CKA_ALWAYS_AUTHENTICATE is set to CK_FALSE" —
// and the grant that used to be minted here is what made the attribute
// meaningless.
func TestContextSpecificLoginRefusesWhenNoActiveKeyRequiresIt(t *testing.T) {
	m, session, decryptKey := loggedInWithPrivateKey(t, unauthenticatedDecryptionKey("context-no-requirement"))
	defer m.Finalize()

	require.Equal(t, CKR_OK, m.DecryptInit(session, revocationGCMMechanism("ctx-refuse-01"), decryptKey))

	assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED,
		m.Login(session, CKU_CONTEXT_SPECIFIC, []byte("user-pin-1234")),
		"a key that requires no re-authentication gives C_Login nothing to authenticate")

	// §4.10: "the active cryptographic operation will not be affected".
	plaintext, rv := m.Decrypt(session, []byte("ciphertext-and-tag-bytes--------"))
	assert.Equal(t, CKR_OK, rv, "the refused login must leave the operation it declined untouched")
	assert.NotEmpty(t, plaintext)
}

// TestContextSpecificLoginAdmitsAKeyThatRequiresIt is the positive control for
// the gate above: the same call on a key that does carry
// CKA_ALWAYS_AUTHENTICATE must succeed, or the refusal is merely a broken
// function rather than a correct one.
func TestContextSpecificLoginAdmitsAKeyThatRequiresIt(t *testing.T) {
	m, session, signingKey := loggedInWithPrivateKey(t, alwaysAuthenticateSigningKey("context-required"))
	defer m.Finalize()

	require.Equal(t, CKR_OK, m.SignInit(session, &Mechanism{Type: CKM_RSA_PKCS}, signingKey))

	assert.Equal(t, CKR_OK, m.Login(session, CKU_CONTEXT_SPECIFIC, []byte("user-pin-1234")))
}

// TestContextSpecificLoginValidatesThePIN keeps the authentication half honest.
// The operation precondition is checked first so a login that could not have
// authenticated anything does not spend a lockout attempt, but once past it the
// PIN still has to be right.
func TestContextSpecificLoginValidatesThePIN(t *testing.T) {
	m, session, signingKey := loggedInWithPrivateKey(t, alwaysAuthenticateSigningKey("context-wrong-pin"))
	defer m.Finalize()

	require.Equal(t, CKR_OK, m.SignInit(session, &Mechanism{Type: CKM_RSA_PKCS}, signingKey))

	assert.Equal(t, CKR_PIN_INCORRECT, m.Login(session, CKU_CONTEXT_SPECIFIC, []byte("not-the-user-pin")))

	// §4.10: "continuing the cryptographic operation will result in a behavior
	// as if C_Login had not been called."
	_, rv := m.Sign(session, []byte("data"))
	assert.Equal(t, CKR_USER_NOT_LOGGED_IN, rv,
		"a refused re-authentication must not leave a usable authorization behind")
}

// TestSignWithAlwaysAuthenticateRequiresReauthentication walks the whole §4.10
// sequence on the verb the section names, in both directions.
func TestSignWithAlwaysAuthenticateRequiresReauthentication(t *testing.T) {
	m, session, signingKey := loggedInWithPrivateKey(t, alwaysAuthenticateSigningKey("context-sign"))
	defer m.Finalize()

	require.Equal(t, CKR_OK, m.SignInit(session, &Mechanism{Type: CKM_RSA_PKCS}, signingKey))

	_, rv := m.Sign(session, []byte("data"))
	require.Equal(t, CKR_USER_NOT_LOGGED_IN, rv,
		"§4.10: failing or omitting to re-authenticate results in CKR_USER_NOT_LOGGED_IN from calls using the key")

	require.Equal(t, CKR_OK, m.Login(session, CKU_CONTEXT_SPECIFIC, []byte("user-pin-1234")))

	signature, rv := m.Sign(session, []byte("data"))
	assert.Equal(t, CKR_OK, rv, "the use the application re-authenticated for must be admitted")
	assert.NotEmpty(t, signature)

	// §4.10 ends the authenticated state when "the cryptographic operation has
	// successfully or unsuccessfully been completed", so the next signature
	// needs its own re-authentication. C_SignInit with a NULL mechanism
	// terminates the operation the signature above left active for the §5.2
	// two-call convention.
	require.Equal(t, CKR_OK, m.SignInit(session, nil, signingKey))
	require.Equal(t, CKR_OK, m.SignInit(session, &Mechanism{Type: CKM_RSA_PKCS}, signingKey))

	_, rv = m.Sign(session, []byte("data"))
	assert.Equal(t, CKR_USER_NOT_LOGGED_IN, rv,
		"an authorization must not outlive the operation it was granted for")
}

// TestContextSpecificLoginAgreesAcrossLoginAndLoginUser closes the divergence
// between the two entry points.
//
// C_Login and C_LoginUser name the same user type, and an application picks
// whichever its Cryptoki version offers. They used to answer differently for
// identical state: C_LoginUser demanded an active operation and returned
// CKR_OPERATION_NOT_INITIALIZED without one, while C_Login accepted anything and
// returned CKR_OK having granted nothing. C_Login is the function §4.10 names,
// so the specification-following application got the silent success and then an
// undiagnosable CKR_USER_NOT_LOGGED_IN from the key it thought it had
// authenticated.
func TestContextSpecificLoginAgreesAcrossLoginAndLoginUser(t *testing.T) {
	cases := []struct {
		name    string
		prepare func(t *testing.T, m *Module, session SessionHandle)
		want    CK_RV
	}{
		{
			name:    "no operation at all",
			prepare: func(t *testing.T, m *Module, session SessionHandle) {},
			want:    CKR_OPERATION_NOT_INITIALIZED,
		},
		{
			name: "an operation that names no key",
			prepare: func(t *testing.T, m *Module, session SessionHandle) {
				require.Equal(t, CKR_OK, m.DigestInit(session, &Mechanism{Type: CKM_SHA256}))
			},
			want: CKR_OPERATION_NOT_INITIALIZED,
		},
		{
			name: "an operation whose key requires nothing",
			prepare: func(t *testing.T, m *Module, session SessionHandle) {
				key, rv := m.CreateObject(session, unauthenticatedDecryptionKey("agree-no-requirement"))
				require.Equal(t, CKR_OK, rv)
				require.Equal(t, CKR_OK, m.DecryptInit(session, revocationGCMMechanism("ctx-agree-01"), key))
			},
			want: CKR_OPERATION_NOT_INITIALIZED,
		},
		{
			name: "an operation whose key requires re-authentication",
			prepare: func(t *testing.T, m *Module, session SessionHandle) {
				key, rv := m.CreateObject(session, alwaysAuthenticateSigningKey("agree-required"))
				require.Equal(t, CKR_OK, rv)
				require.Equal(t, CKR_OK, m.SignInit(session, &Mechanism{Type: CKM_RSA_PKCS}, key))
			},
			want: CKR_OK,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Run("C_Login", func(t *testing.T) {
				m := initializeTestModule(t)
				defer m.Finalize()
				session := loginAsNormalUser(t, m)

				tc.prepare(t, m, session)
				assert.Equal(t, tc.want, m.Login(session, CKU_CONTEXT_SPECIFIC, []byte("user-pin-1234")))
			})

			t.Run("C_LoginUser", func(t *testing.T) {
				m := initializeTestModule(t)
				defer m.Finalize()
				session := loginAsNormalUser(t, m)

				tc.prepare(t, m, session)
				assert.Equal(t, tc.want, m.LoginUser(session, CKU_CONTEXT_SPECIFIC, []byte("user-pin-1234"), "context"))
			})
		})
	}
}

// alwaysAuthenticateDecryptionKey is a private AES key that requires
// re-authentication before each use.
//
// It is the decryption counterpart of alwaysAuthenticateSigningKey. §4.10
// permits CKA_ALWAYS_AUTHENTICATE=CK_TRUE only "when CKA_PRIVATE is also
// CK_TRUE", which this template sets.
func alwaysAuthenticateDecryptionKey(label string) []Attribute {
	return append(unauthenticatedDecryptionKey(label),
		NewBoolAttribute(CKA_ALWAYS_AUTHENTICATE, true))
}

// TestMultiPartFinalRequiresReauthentication proves CKA_ALWAYS_AUTHENTICATE
// governs the multi-part paths, not only the single-part ones.
//
// The gate was applied to C_Sign, C_SignRecover and C_Decrypt and to none of
// the *Final verbs, which left it inert on the ordinary path for anything
// larger than one buffer: C_SignInit / C_SignUpdate / C_SignFinal produced a
// signature with no re-authentication requested and none required, and
// C_DecryptFinal did the same. An application could not even attempt the
// §4.10 protocol there, and nothing told it so.
//
// It is exactly the sidestep the gate on C_SignRecover was added to close --
// "the requirement could be sidestepped by driving the private key through
// C_SignRecover instead" -- through the more obvious door, so the two verbs are
// covered together here.
//
// §4.10 names C_SignFinal itself: the authenticated state "lasts until the
// cryptographic operation has successfully or unsuccessfully been completed
// (e.g. by C_Sign, C_SignFinal,..)". A state that ends at C_SignFinal is one
// C_SignFinal must have required.
func TestMultiPartFinalRequiresReauthentication(t *testing.T) {
	t.Run("C_SignFinal refuses without re-authentication", func(t *testing.T) {
		m, session, signingKey := loggedInWithPrivateKey(t, alwaysAuthenticateSigningKey("multipart-sign"))
		defer m.Finalize()

		require.Equal(t, CKR_OK, m.SignInit(session, &Mechanism{Type: CKM_RSA_PKCS}, signingKey))
		require.Equal(t, CKR_OK, m.SignUpdate(session, []byte("first part")))
		require.Equal(t, CKR_OK, m.SignUpdate(session, []byte("second part")))

		signature, rv := m.SignFinal(session)
		assert.Equal(t, CKR_USER_NOT_LOGGED_IN, rv,
			"a multi-part signature must require the same re-authentication C_Sign does")
		assert.Empty(t, signature, "a refused signature must return no bytes")
	})

	t.Run("C_SignFinal admits the use it was re-authenticated for", func(t *testing.T) {
		m, session, signingKey := loggedInWithPrivateKey(t, alwaysAuthenticateSigningKey("multipart-sign-ok"))
		defer m.Finalize()

		require.Equal(t, CKR_OK, m.SignInit(session, &Mechanism{Type: CKM_RSA_PKCS}, signingKey))
		require.Equal(t, CKR_OK, m.SignUpdate(session, []byte("first part")))
		require.Equal(t, CKR_OK, m.Login(session, CKU_CONTEXT_SPECIFIC, []byte("user-pin-1234")))

		signature, rv := m.SignFinal(session)
		assert.Equal(t, CKR_OK, rv,
			"the positive control: a gate that refuses unconditionally is not a fix")
		assert.NotEmpty(t, signature)
	})

	t.Run("C_DecryptFinal refuses without re-authentication", func(t *testing.T) {
		m, session, decryptKey := loggedInWithPrivateKey(t,
			alwaysAuthenticateDecryptionKey("multipart-decrypt"))
		defer m.Finalize()

		require.Equal(t, CKR_OK, m.DecryptInit(session, revocationGCMMechanism("ctx-mp-decr01"), decryptKey))
		_, rv := m.DecryptUpdate(session, []byte("ciphertext part"))
		require.Equal(t, CKR_OK, rv)

		plaintext, rv := m.DecryptFinal(session)
		assert.Equal(t, CKR_USER_NOT_LOGGED_IN, rv,
			"a multi-part decryption must require the same re-authentication C_Decrypt does")
		assert.Empty(t, plaintext, "a refused decryption must return no plaintext")
	})

	t.Run("C_DecryptFinal admits the use it was re-authenticated for", func(t *testing.T) {
		m, session, decryptKey := loggedInWithPrivateKey(t,
			alwaysAuthenticateDecryptionKey("multipart-decrypt-ok"))
		defer m.Finalize()

		require.Equal(t, CKR_OK, m.DecryptInit(session, revocationGCMMechanism("ctx-mp-decr02"), decryptKey))
		_, rv := m.DecryptUpdate(session, []byte("ciphertext part"))
		require.Equal(t, CKR_OK, rv)
		require.Equal(t, CKR_OK, m.Login(session, CKU_CONTEXT_SPECIFIC, []byte("user-pin-1234")))

		// The assertion is that the re-authentication gate let the call
		// through, not that the decryption succeeded. This fixture feeds
		// C_DecryptUpdate bytes that are not a valid AES-GCM blob, so the call
		// goes on to fail in the cipher with CKR_ENCRYPTED_DATA_LEN_RANGE --
		// which is the mock's business and not this test's. What matters is
		// that the refusal is no longer CKR_USER_NOT_LOGGED_IN: a gate that
		// refused unconditionally would still produce that here, and this is
		// what distinguishes it from the fix.
		_, rv = m.DecryptFinal(session)
		assert.NotEqual(t, CKR_USER_NOT_LOGGED_IN, rv,
			"the positive control: a gate that refuses unconditionally is not a fix")
	})
}

// TestMultiPartFinalReplayDoesNotConsumeTheGrantTwice proves the §5.2 two-call
// convention costs the caller only one re-authentication.
//
// A terminal call computes its output and caches it, and the application calls
// again to collect it. Both calls run C_SignFinal, so a gate placed before the
// cached-result check would consume the §4.10 grant on the first and refuse the
// second with CKR_USER_NOT_LOGGED_IN -- for a re-authentication the application
// performed correctly, and with no way to tell that apart from a wrong PIN. A
// length query followed by the real call is one use of the key, so the grant
// must cover both.
func TestMultiPartFinalReplayDoesNotConsumeTheGrantTwice(t *testing.T) {
	m, session, signingKey := loggedInWithPrivateKey(t, alwaysAuthenticateSigningKey("multipart-replay"))
	defer m.Finalize()

	require.Equal(t, CKR_OK, m.SignInit(session, &Mechanism{Type: CKM_RSA_PKCS}, signingKey))
	require.Equal(t, CKR_OK, m.SignUpdate(session, []byte("data to sign")))
	require.Equal(t, CKR_OK, m.Login(session, CKU_CONTEXT_SPECIFIC, []byte("user-pin-1234")))

	first, rv := m.SignFinal(session)
	require.Equal(t, CKR_OK, rv)
	require.NotEmpty(t, first)

	second, rv := m.SignFinal(session)
	assert.Equal(t, CKR_OK, rv,
		"the second call of the two-call convention must not need a second re-authentication")
	assert.Equal(t, first, second, "the replay must return the cached signature, not a new one")
}
