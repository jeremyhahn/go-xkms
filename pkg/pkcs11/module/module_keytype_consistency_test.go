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

// createKeyTypeTestObject builds a session key of the given class and type with
// every usage attribute enabled, so that a refusal in the tests below can only
// have come from the mechanism/key-type rule and not from CKA_SIGN, CKA_DECRYPT
// or any other usage gate.
func createKeyTypeTestObject(t *testing.T, m *Module, session SessionHandle, class ObjectClass, keyType KeyType, label string) ObjectHandle {
	t.Helper()

	handle, rv := m.CreateObject(session, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(class)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(keyType)),
		NewStringAttribute(CKA_LABEL, label),
		NewBoolAttribute(CKA_TOKEN, false),
		NewBoolAttribute(CKA_SIGN, true),
		NewBoolAttribute(CKA_VERIFY, true),
		NewBoolAttribute(CKA_ENCRYPT, true),
		NewBoolAttribute(CKA_DECRYPT, true),
		NewBoolAttribute(CKA_SENSITIVE, false),
		NewBoolAttribute(CKA_EXTRACTABLE, true),
		NewAttribute(CKA_VALUE, make([]byte, 32)),
	})
	require.Equal(t, CKR_OK, rv, "fixture object %s could not be created", label)
	return handle
}

// TestInitRefusesAMechanismTheKeyTypeCannotPerform covers PKCS#11 v3.2 §5.1.6's
// CKR_KEY_TYPE_INCONSISTENT: "the specified key is not the correct type of key
// to use with the specified mechanism".
//
// The module used to accept these pairings. resolveOperationKey enforced login,
// the handle, the usage attribute and CKA_ALLOWED_MECHANISMS, and
// validateInitMechanism only asked whether the token implements the mechanism at
// all -- so nothing compared the key's CKA_KEY_TYPE against the mechanism. An
// application that passed an RSA key to C_EncryptInit(CKM_AES_GCM) was told
// CKR_OK and then failed further down, at the backend or with a code describing
// the symptom rather than the caller's mistake. CKR_KEY_TYPE_INCONSISTENT is in
// the return table of every C_*Init function precisely so the refusal can name
// the real fault at the point it is made.
//
// Each case drives a real Module entry point rather than the table, so a
// regression that keeps the table but stops consulting it still fails.
func TestInitRefusesAMechanismTheKeyTypeCannotPerform(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()
	session := loginAsNormalUser(t, m)

	rsaKey := createKeyTypeTestObject(t, m, session, CKO_PRIVATE_KEY, CKK_RSA, "keytype-rsa")
	ecKey := createKeyTypeTestObject(t, m, session, CKO_PRIVATE_KEY, CKK_EC, "keytype-ec")
	edKey := createKeyTypeTestObject(t, m, session, CKO_PRIVATE_KEY, CKK_EC_EDWARDS, "keytype-ed")
	aesKey := createKeyTypeTestObject(t, m, session, CKO_SECRET_KEY, CKK_AES, "keytype-aes")

	t.Run("C_SignInit refuses an RSA mechanism on an EC key", func(t *testing.T) {
		rv := m.SignInit(session, NewMechanism(CKM_SHA256_RSA_PKCS), ecKey)
		assert.Equal(t, CKR_KEY_TYPE_INCONSISTENT, rv)
	})

	t.Run("C_SignInit refuses ECDSA on an RSA key", func(t *testing.T) {
		rv := m.SignInit(session, NewMechanism(CKM_ECDSA), rsaKey)
		assert.Equal(t, CKR_KEY_TYPE_INCONSISTENT, rv)
	})

	// EdDSA keys are CKK_EC_EDWARDS, a distinct type from CKK_EC. Confusing the
	// two is the mistake most likely to reach a token in practice, because both
	// are "elliptic curve" keys to an application author.
	t.Run("C_SignInit refuses EdDSA on an ECDSA key", func(t *testing.T) {
		rv := m.SignInit(session, NewMechanism(CKM_EDDSA), ecKey)
		assert.Equal(t, CKR_KEY_TYPE_INCONSISTENT, rv)
	})

	t.Run("C_SignInit refuses ECDSA on an Edwards key", func(t *testing.T) {
		rv := m.SignInit(session, NewMechanism(CKM_ECDSA), edKey)
		assert.Equal(t, CKR_KEY_TYPE_INCONSISTENT, rv)
	})

	t.Run("C_EncryptInit refuses AES-GCM on an RSA key", func(t *testing.T) {
		rv := m.EncryptInit(session,
			NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(testGCMIV(), 128)), rsaKey)
		assert.Equal(t, CKR_KEY_TYPE_INCONSISTENT, rv)
	})

	t.Run("C_EncryptInit refuses RSA-OAEP on an AES key", func(t *testing.T) {
		rv := m.EncryptInit(session,
			NewMechanismWithTypedParams(CKM_RSA_PKCS_OAEP, NewRSAOAEPParams(CKM_SHA256)), aesKey)
		assert.Equal(t, CKR_KEY_TYPE_INCONSISTENT, rv)
	})

	t.Run("C_DecryptInit refuses AES-CBC on an RSA key", func(t *testing.T) {
		rv := m.DecryptInit(session, NewMechanism(CKM_AES_CBC), rsaKey)
		assert.Equal(t, CKR_KEY_TYPE_INCONSISTENT, rv)
	})

	t.Run("C_VerifyInit refuses an RSA mechanism on an EC key", func(t *testing.T) {
		rv := m.VerifyInit(session, NewMechanism(CKM_RSA_PKCS_PSS), ecKey)
		assert.Equal(t, CKR_KEY_TYPE_INCONSISTENT, rv)
	})

	// HMAC takes a symmetric key. v3.2 says so per family in identical words --
	// for SHA-256, "the keys it uses are generic secret keys and
	// CKK_SHA256_HMAC" -- so an asymmetric key is a straightforward mismatch.
	//
	// This case matters more than it looks. The HMAC mechanisms are not
	// advertised, and the first version of the coverage test below only examined
	// advertised mechanisms, so every one of them was exempt from the rule while
	// the suite reported the table fully covered.
	t.Run("C_SignInit refuses HMAC on an RSA key", func(t *testing.T) {
		rv := m.SignInit(session, NewMechanism(CKM_SHA256_HMAC), rsaKey)
		assert.Equal(t, CKR_KEY_TYPE_INCONSISTENT, rv)
	})

	t.Run("C_SignInit refuses HMAC on an EC key", func(t *testing.T) {
		rv := m.SignInit(session, NewMechanism(CKM_SHA512_HMAC), ecKey)
		assert.Equal(t, CKR_KEY_TYPE_INCONSISTENT, rv)
	})

	// An AES key is symmetric but is still not one of the two types the spec
	// names for HMAC, so it is refused as well. This separates "symmetric" from
	// "the right symmetric type", which is the distinction the rule encodes.
	t.Run("C_SignInit refuses HMAC on an AES key", func(t *testing.T) {
		rv := m.SignInit(session, NewMechanism(CKM_SHA256_HMAC), aesKey)
		assert.Equal(t, CKR_KEY_TYPE_INCONSISTENT, rv)
	})
}

// TestInitAcceptsAMechanismTheKeyTypeCanPerform is the other half: the rule must
// refuse only genuine mismatches.
//
// Without this, a gate that refused everything -- or one that refused any key
// whose CKA_KEY_TYPE it did not recognise -- would pass the test above while
// making the token useless. The assertion is only that the call does not fail
// with CKR_KEY_TYPE_INCONSISTENT; these fixture objects carry no real key
// material, so a later failure from the backend is expected and irrelevant here.
func TestInitAcceptsAMechanismTheKeyTypeCanPerform(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()
	session := loginAsNormalUser(t, m)

	rsaKey := createKeyTypeTestObject(t, m, session, CKO_PRIVATE_KEY, CKK_RSA, "match-rsa")
	ecKey := createKeyTypeTestObject(t, m, session, CKO_PRIVATE_KEY, CKK_EC, "match-ec")
	edKey := createKeyTypeTestObject(t, m, session, CKO_PRIVATE_KEY, CKK_EC_EDWARDS, "match-ed")
	aesKey := createKeyTypeTestObject(t, m, session, CKO_SECRET_KEY, CKK_AES, "match-aes")

	t.Run("RSA signing on an RSA key", func(t *testing.T) {
		assert.NotEqual(t, CKR_KEY_TYPE_INCONSISTENT,
			m.SignInit(session, NewMechanism(CKM_SHA256_RSA_PKCS), rsaKey))
	})

	t.Run("ECDSA on an EC key", func(t *testing.T) {
		assert.NotEqual(t, CKR_KEY_TYPE_INCONSISTENT,
			m.SignInit(session, NewMechanism(CKM_ECDSA), ecKey))
	})

	t.Run("EdDSA on an Edwards key", func(t *testing.T) {
		assert.NotEqual(t, CKR_KEY_TYPE_INCONSISTENT,
			m.SignInit(session, NewMechanism(CKM_EDDSA), edKey))
	})

	t.Run("AES-GCM on an AES key", func(t *testing.T) {
		assert.NotEqual(t, CKR_KEY_TYPE_INCONSISTENT,
			m.EncryptInit(session,
				NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(testGCMIV(), 128)), aesKey))
	})

	// Both key types the spec names for HMAC must work: the generic secret key
	// and the digest's own HMAC key type. Accepting only one of them would make
	// the rule stricter than the standard.
	t.Run("HMAC on a generic secret key", func(t *testing.T) {
		genericKey := createKeyTypeTestObject(t, m, session, CKO_SECRET_KEY, CKK_GENERIC_SECRET, "match-generic")
		assert.NotEqual(t, CKR_KEY_TYPE_INCONSISTENT,
			m.SignInit(session, NewMechanism(CKM_SHA256_HMAC), genericKey))
	})

	t.Run("HMAC on its own HMAC key type", func(t *testing.T) {
		hmacKey := createKeyTypeTestObject(t, m, session, CKO_SECRET_KEY, CKK_SHA256_HMAC, "match-hmac")
		assert.NotEqual(t, CKR_KEY_TYPE_INCONSISTENT,
			m.SignInit(session, NewMechanism(CKM_SHA256_HMAC), hmacKey))
	})
}

// TestMechanismKeyTypeTableCoversEveryAdvertisedOperation keeps the table honest
// as the mechanism registry grows.
//
// mechanismAcceptsKeyType admits any mechanism it has no entry for, which is the
// right default -- inventing a rule for a mechanism whose key requirements were
// never established would refuse work the token can do. The cost of that default
// is that a new mechanism silently opts out of the check. This test makes that
// opt-out deliberate: adding an operational mechanism to the registry without
// deciding which key types it accepts fails here.
//
// Advertisement is deliberately not part of the filter. GetMechanismDescriptor
// resolves anything in the registry and filters only on FIPS, so an unadvertised
// mechanism still reaches every C_*Init -- that is what lets CKM_RSA_X_509 serve
// C_VerifyRecover without being offered in C_GetMechanismList. Scoping this test
// to advertised mechanisms, as it first did, exempted every HMAC mechanism in
// the registry from the check while reporting full coverage.
func TestMechanismKeyTypeTableCoversEveryOperationalMechanism(t *testing.T) {
	const operationFlags = CKF_SIGN | CKF_VERIFY | CKF_ENCRYPT | CKF_DECRYPT |
		CKF_SIGN_RECOVER | CKF_VERIFY_RECOVER

	for mechType, descriptor := range mechanismRegistry {
		if descriptor.Flags&operationFlags == 0 {
			continue
		}
		if _, ok := acceptedKeyTypes(mechType); !ok {
			t.Errorf("operational mechanism %s has no key-type rule: add it to "+
				"mechanismKeyTypes, or to v32KeyTypeMap if it uses exactly one key type",
				descriptor.Name)
		}
	}
}
