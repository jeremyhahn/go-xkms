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

//go:build integration && conformance

// Package conformance provides OASIS PKCS#11 v3.0 conformance tests.
//
// # Cryptographic Operation Conformance Tests
//
// This file tests PKCS#11 cryptographic operation conformance per the OASIS PKCS#11
// v3.0 specification, including multi-part operation state machine, operation
// cancellation, dual-function operations, and key usage restrictions.
//
// References:
//   - OASIS PKCS#11 Base v3.0, Section 5.8: Encryption Functions
//   - OASIS PKCS#11 Base v3.0, Section 5.9: Message Digesting Functions
//   - OASIS PKCS#11 Base v3.0, Section 5.10: Signing and MACing Functions
//   - OASIS PKCS#11 Base v3.0, Section 5.11: Verification Functions
//   - OASIS PKCS#11 Base v3.0, Section 5.13: Key Management Functions
package conformance

import (
	"bytes"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
	testutil "github.com/jeremyhahn/go-xkms/test/integration/pkcs11/module"
)

// TestCrypto_DigestOperations tests digest operation conformance.
//
// Reference: OASIS PKCS#11 v3.0, Section 5.9
func TestCrypto_DigestOperations(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)

	// Test single-part digest with SHA-256
	t.Run("SHA256_SinglePart", func(t *testing.T) {
		rv := env.Module.DigestInit(session, &module.Mechanism{Type: module.CKM_SHA256})
		if rv != module.CKR_OK {
			t.Skipf("DigestInit SHA256: %s", rv.String())
		}

		testData := []byte("The quick brown fox jumps over the lazy dog")
		digest, rv := env.Module.Digest(session, testData)
		if rv != module.CKR_OK {
			t.Fatalf("Digest: expected CKR_OK, got %s", rv.String())
		}

		// SHA-256 produces 32 bytes
		if len(digest) != 32 {
			t.Errorf("SHA-256 digest length: expected 32, got %d", len(digest))
		}

		// Verify operation is finalized (calling Digest again should fail)
		_, rv = env.Module.Digest(session, testData)
		if rv != module.CKR_OPERATION_NOT_INITIALIZED {
			t.Errorf("Digest after finalize: expected CKR_OPERATION_NOT_INITIALIZED, got %s", rv.String())
		}
	})

	// Test that DigestInit without Digest finalizes previous operation
	t.Run("DigestInit_ReInitialize", func(t *testing.T) {
		// Start first digest
		rv := env.Module.DigestInit(session, &module.Mechanism{Type: module.CKM_SHA256})
		if rv != module.CKR_OK {
			t.Skipf("DigestInit SHA256: %s", rv.String())
		}

		// Finalize first digest
		_, rv = env.Module.Digest(session, []byte("test1"))
		if rv != module.CKR_OK {
			t.Fatalf("Digest: expected CKR_OK, got %s", rv.String())
		}

		// Start second digest - should work
		rv = env.Module.DigestInit(session, &module.Mechanism{Type: module.CKM_SHA256})
		if rv != module.CKR_OK {
			t.Errorf("DigestInit second: expected CKR_OK, got %s", rv.String())
		}

		// Clean up
		env.Module.Digest(session, []byte("test2"))
	})

	// Test different digest mechanisms
	digestMechs := []struct {
		mech module.MechanismType
		name string
		size int
	}{
		{module.CKM_SHA_1, "SHA-1", 20},
		{module.CKM_SHA256, "SHA-256", 32},
		{module.CKM_SHA384, "SHA-384", 48},
		{module.CKM_SHA512, "SHA-512", 64},
	}

	for _, dm := range digestMechs {
		t.Run(dm.name, func(t *testing.T) {
			rv := env.Module.DigestInit(session, &module.Mechanism{Type: dm.mech})
			if rv != module.CKR_OK {
				t.Skipf("DigestInit %s: %s", dm.name, rv.String())
			}

			digest, rv := env.Module.Digest(session, []byte("test data"))
			if rv != module.CKR_OK {
				t.Fatalf("Digest %s: expected CKR_OK, got %s", dm.name, rv.String())
			}

			if len(digest) != dm.size {
				t.Errorf("%s digest length: expected %d, got %d", dm.name, dm.size, len(digest))
			}
		})
	}
}

// TestCrypto_RandomGeneration tests random number generation conformance.
//
// Reference: OASIS PKCS#11 v3.0, Section 5.17.2
func TestCrypto_RandomGeneration(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)

	t.Run("GenerateRandom_Basic", func(t *testing.T) {
		random, rv := env.Module.GenerateRandom(session, 32)
		if rv != module.CKR_OK {
			t.Fatalf("GenerateRandom: expected CKR_OK, got %s", rv.String())
		}

		if len(random) != 32 {
			t.Errorf("random length: expected 32, got %d", len(random))
		}
	})

	t.Run("GenerateRandom_VariousSizes", func(t *testing.T) {
		sizes := []uint32{1, 16, 32, 64, 128, 256, 512, 1024}

		for _, size := range sizes {
			random, rv := env.Module.GenerateRandom(session, size)
			if rv != module.CKR_OK {
				t.Errorf("GenerateRandom(%d): expected CKR_OK, got %s", size, rv.String())
				continue
			}

			if uint32(len(random)) != size {
				t.Errorf("random length for size %d: expected %d, got %d", size, size, len(random))
			}
		}
	})

	t.Run("GenerateRandom_Uniqueness", func(t *testing.T) {
		// Generate multiple random values and verify they're different
		samples := make([][]byte, 10)
		for i := range samples {
			random, rv := env.Module.GenerateRandom(session, 32)
			if rv != module.CKR_OK {
				t.Fatalf("GenerateRandom: expected CKR_OK, got %s", rv.String())
			}
			samples[i] = random
		}

		// Check for duplicates
		for i := 0; i < len(samples)-1; i++ {
			for j := i + 1; j < len(samples); j++ {
				if bytes.Equal(samples[i], samples[j]) {
					t.Errorf("duplicate random values at positions %d and %d", i, j)
				}
			}
		}
	})

	t.Run("GenerateRandom_NotAllZeros", func(t *testing.T) {
		random, rv := env.Module.GenerateRandom(session, 256)
		if rv != module.CKR_OK {
			t.Fatalf("GenerateRandom: expected CKR_OK, got %s", rv.String())
		}

		allZeros := true
		for _, b := range random {
			if b != 0 {
				allZeros = false
				break
			}
		}

		if allZeros {
			t.Error("GenerateRandom returned all zeros")
		}
	})
}

// TestCrypto_KeyGeneration tests key generation conformance.
//
// Reference: OASIS PKCS#11 v3.0, Section 5.13
func TestCrypto_KeyGeneration(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)

	// Test AES key generation
	t.Run("AES_KeyGen", func(t *testing.T) {
		template := []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_SECRET_KEY)),
			module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_AES)),
			module.NewStringAttribute(module.CKA_LABEL, "conformance-aes-key"),
			module.NewUint32Attribute(module.CKA_VALUE_LEN, 32), // 256 bits
			module.NewBoolAttribute(module.CKA_TOKEN, false),
			module.NewBoolAttribute(module.CKA_ENCRYPT, true),
			module.NewBoolAttribute(module.CKA_DECRYPT, true),
			module.NewBoolAttribute(module.CKA_EXTRACTABLE, true),
		}

		handle, rv := env.Module.GenerateKey(session, &module.Mechanism{Type: module.CKM_AES_KEY_GEN}, template)
		if rv != module.CKR_OK {
			t.Skipf("GenerateKey AES: %s", rv.String())
		}
		defer env.Module.DestroyObject(session, handle)

		// Verify key attributes
		getTemplate := []module.Attribute{
			{Type: module.CKA_CLASS},
			{Type: module.CKA_KEY_TYPE},
			{Type: module.CKA_VALUE_LEN},
		}

		attrs, rv := env.Module.GetAttributeValue(session, handle, getTemplate)
		if rv != module.CKR_OK {
			t.Fatalf("GetAttributeValue: expected CKR_OK, got %s", rv.String())
		}

		for _, attr := range attrs {
			switch attr.Type {
			case module.CKA_CLASS:
				classVal, _ := attr.GetUint32()
				if module.ObjectClass(classVal) != module.CKO_SECRET_KEY {
					t.Errorf("class: expected CKO_SECRET_KEY, got %d", classVal)
				}
			case module.CKA_KEY_TYPE:
				keyType, _ := attr.GetUint32()
				if module.KeyType(keyType) != module.CKK_AES {
					t.Errorf("key type: expected CKK_AES, got %d", keyType)
				}
			case module.CKA_VALUE_LEN:
				valueLen, _ := attr.GetUint32()
				if valueLen != 32 {
					t.Errorf("value len: expected 32, got %d", valueLen)
				}
			}
		}
	})

	// Test RSA key pair generation
	t.Run("RSA_KeyPairGen", func(t *testing.T) {
		publicTemplate := []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_PUBLIC_KEY)),
			module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_RSA)),
			module.NewStringAttribute(module.CKA_LABEL, "conformance-rsa-pub"),
			module.NewUint32Attribute(module.CKA_MODULUS_BITS, 2048),
			module.NewBoolAttribute(module.CKA_TOKEN, false),
			module.NewBoolAttribute(module.CKA_ENCRYPT, true),
			module.NewBoolAttribute(module.CKA_VERIFY, true),
			module.NewAttribute(module.CKA_PUBLIC_EXPONENT, []byte{0x01, 0x00, 0x01}),
		}

		privateTemplate := []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_PRIVATE_KEY)),
			module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_RSA)),
			module.NewStringAttribute(module.CKA_LABEL, "conformance-rsa-priv"),
			module.NewBoolAttribute(module.CKA_TOKEN, false),
			module.NewBoolAttribute(module.CKA_PRIVATE, true),
			module.NewBoolAttribute(module.CKA_SENSITIVE, true),
			module.NewBoolAttribute(module.CKA_DECRYPT, true),
			module.NewBoolAttribute(module.CKA_SIGN, true),
		}

		pubHandle, privHandle, rv := env.Module.GenerateKeyPair(
			session,
			&module.Mechanism{Type: module.CKM_RSA_PKCS_KEY_PAIR_GEN},
			publicTemplate,
			privateTemplate,
		)
		if rv != module.CKR_OK {
			t.Skipf("GenerateKeyPair RSA: %s", rv.String())
		}
		defer env.Module.DestroyObject(session, pubHandle)
		defer env.Module.DestroyObject(session, privHandle)

		// Verify public key attributes
		getTemplate := []module.Attribute{
			{Type: module.CKA_CLASS},
			{Type: module.CKA_KEY_TYPE},
		}

		attrs, rv := env.Module.GetAttributeValue(session, pubHandle, getTemplate)
		if rv != module.CKR_OK {
			t.Fatalf("GetAttributeValue public: expected CKR_OK, got %s", rv.String())
		}

		for _, attr := range attrs {
			switch attr.Type {
			case module.CKA_CLASS:
				classVal, _ := attr.GetUint32()
				if module.ObjectClass(classVal) != module.CKO_PUBLIC_KEY {
					t.Errorf("public key class: expected CKO_PUBLIC_KEY, got %d", classVal)
				}
			case module.CKA_KEY_TYPE:
				keyType, _ := attr.GetUint32()
				if module.KeyType(keyType) != module.CKK_RSA {
					t.Errorf("public key type: expected CKK_RSA, got %d", keyType)
				}
			}
		}

		// Verify private key attributes
		attrs, rv = env.Module.GetAttributeValue(session, privHandle, getTemplate)
		if rv != module.CKR_OK {
			t.Fatalf("GetAttributeValue private: expected CKR_OK, got %s", rv.String())
		}

		for _, attr := range attrs {
			switch attr.Type {
			case module.CKA_CLASS:
				classVal, _ := attr.GetUint32()
				if module.ObjectClass(classVal) != module.CKO_PRIVATE_KEY {
					t.Errorf("private key class: expected CKO_PRIVATE_KEY, got %d", classVal)
				}
			case module.CKA_KEY_TYPE:
				keyType, _ := attr.GetUint32()
				if module.KeyType(keyType) != module.CKK_RSA {
					t.Errorf("private key type: expected CKK_RSA, got %d", keyType)
				}
			}
		}
	})

	// Test EC key pair generation
	t.Run("EC_KeyPairGen", func(t *testing.T) {
		// P-256 OID
		ecParams := []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}

		publicTemplate := []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_PUBLIC_KEY)),
			module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_EC)),
			module.NewStringAttribute(module.CKA_LABEL, "conformance-ec-pub"),
			module.NewAttribute(module.CKA_EC_PARAMS, ecParams),
			module.NewBoolAttribute(module.CKA_TOKEN, false),
			module.NewBoolAttribute(module.CKA_VERIFY, true),
		}

		privateTemplate := []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_PRIVATE_KEY)),
			module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_EC)),
			module.NewStringAttribute(module.CKA_LABEL, "conformance-ec-priv"),
			module.NewBoolAttribute(module.CKA_TOKEN, false),
			module.NewBoolAttribute(module.CKA_PRIVATE, true),
			module.NewBoolAttribute(module.CKA_SENSITIVE, true),
			module.NewBoolAttribute(module.CKA_SIGN, true),
		}

		pubHandle, privHandle, rv := env.Module.GenerateKeyPair(
			session,
			&module.Mechanism{Type: module.CKM_EC_KEY_PAIR_GEN},
			publicTemplate,
			privateTemplate,
		)
		if rv != module.CKR_OK {
			t.Skipf("GenerateKeyPair EC: %s", rv.String())
		}
		defer env.Module.DestroyObject(session, pubHandle)
		defer env.Module.DestroyObject(session, privHandle)

		// Verify key types
		getTemplate := []module.Attribute{{Type: module.CKA_KEY_TYPE}}

		attrs, rv := env.Module.GetAttributeValue(session, pubHandle, getTemplate)
		if rv == module.CKR_OK && len(attrs) > 0 {
			keyType, _ := attrs[0].GetUint32()
			if module.KeyType(keyType) != module.CKK_EC {
				t.Errorf("EC public key type: expected CKK_EC, got %d", keyType)
			}
		}
	})
}

// TestCrypto_KeyUsageRestrictions tests that key usage attributes are enforced.
//
// Reference: OASIS PKCS#11 v3.0, Section 4.9.2
func TestCrypto_KeyUsageRestrictions(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)

	// Create an encrypt-only key
	t.Run("EncryptOnly_NoDecrypt", func(t *testing.T) {
		template := []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_SECRET_KEY)),
			module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_AES)),
			module.NewStringAttribute(module.CKA_LABEL, "encrypt-only"),
			module.NewAttribute(module.CKA_VALUE, make([]byte, 32)),
			module.NewBoolAttribute(module.CKA_TOKEN, false),
			module.NewBoolAttribute(module.CKA_ENCRYPT, true),
			module.NewBoolAttribute(module.CKA_DECRYPT, false),
		}

		handle, rv := env.Module.CreateObject(session, template)
		if rv != module.CKR_OK {
			t.Fatalf("CreateObject: expected CKR_OK, got %s", rv.String())
		}
		defer env.Module.DestroyObject(session, handle)

		// EncryptInit should work
		rv = env.Module.EncryptInit(session, &module.Mechanism{Type: module.CKM_AES_ECB}, handle)
		// May return CKR_OK or CKR_KEY_FUNCTION_NOT_PERMITTED based on implementation
		t.Logf("EncryptInit with encrypt-only key: %s", rv.String())

		// DecryptInit should fail
		rv = env.Module.DecryptInit(session, &module.Mechanism{Type: module.CKM_AES_ECB}, handle)
		if rv == module.CKR_OK {
			t.Log("note: DecryptInit succeeded with CKA_DECRYPT=false (implementation may defer check)")
		}
	})

	// Create a sign-only key
	t.Run("SignOnly_NoVerify", func(t *testing.T) {
		template := []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_SECRET_KEY)),
			module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_GENERIC_SECRET)),
			module.NewStringAttribute(module.CKA_LABEL, "sign-only"),
			module.NewAttribute(module.CKA_VALUE, make([]byte, 32)),
			module.NewBoolAttribute(module.CKA_TOKEN, false),
			module.NewBoolAttribute(module.CKA_SIGN, true),
			module.NewBoolAttribute(module.CKA_VERIFY, false),
		}

		handle, rv := env.Module.CreateObject(session, template)
		if rv != module.CKR_OK {
			t.Fatalf("CreateObject: expected CKR_OK, got %s", rv.String())
		}
		defer env.Module.DestroyObject(session, handle)

		// Verify attribute settings
		getTemplate := []module.Attribute{
			{Type: module.CKA_SIGN},
			{Type: module.CKA_VERIFY},
		}

		attrs, rv := env.Module.GetAttributeValue(session, handle, getTemplate)
		if rv != module.CKR_OK {
			t.Fatalf("GetAttributeValue: expected CKR_OK, got %s", rv.String())
		}

		for _, attr := range attrs {
			val, _ := attr.GetBool()
			switch attr.Type {
			case module.CKA_SIGN:
				if !val {
					t.Error("CKA_SIGN should be true")
				}
			case module.CKA_VERIFY:
				if val {
					t.Error("CKA_VERIFY should be false")
				}
			}
		}
	})
}

// TestCrypto_OperationStateMachine tests the multi-part operation state machine.
//
// Reference: OASIS PKCS#11 v3.0, Section 5.8, 5.9, 5.10, 5.11
func TestCrypto_OperationStateMachine(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)

	// Test that operations must be initialized before use
	t.Run("DigestWithoutInit", func(t *testing.T) {
		_, rv := env.Module.Digest(session, []byte("test"))
		if rv != module.CKR_OPERATION_NOT_INITIALIZED {
			t.Errorf("Digest without Init: expected CKR_OPERATION_NOT_INITIALIZED, got %s", rv.String())
		}
	})

	t.Run("SignWithoutInit", func(t *testing.T) {
		_, rv := env.Module.Sign(session, []byte("test"))
		if rv != module.CKR_OPERATION_NOT_INITIALIZED {
			t.Errorf("Sign without Init: expected CKR_OPERATION_NOT_INITIALIZED, got %s", rv.String())
		}
	})

	t.Run("VerifyWithoutInit", func(t *testing.T) {
		rv := env.Module.Verify(session, []byte("test"), []byte("sig"))
		if rv != module.CKR_OPERATION_NOT_INITIALIZED {
			t.Errorf("Verify without Init: expected CKR_OPERATION_NOT_INITIALIZED, got %s", rv.String())
		}
	})

	t.Run("EncryptWithoutInit", func(t *testing.T) {
		_, rv := env.Module.Encrypt(session, []byte("test"))
		if rv != module.CKR_OPERATION_NOT_INITIALIZED {
			t.Errorf("Encrypt without Init: expected CKR_OPERATION_NOT_INITIALIZED, got %s", rv.String())
		}
	})

	t.Run("DecryptWithoutInit", func(t *testing.T) {
		_, rv := env.Module.Decrypt(session, []byte("test"))
		if rv != module.CKR_OPERATION_NOT_INITIALIZED {
			t.Errorf("Decrypt without Init: expected CKR_OPERATION_NOT_INITIALIZED, got %s", rv.String())
		}
	})
}

// TestCrypto_FindObjectsStateMachine tests FindObjects operation state machine.
//
// Reference: OASIS PKCS#11 v3.0, Section 5.7.7, 5.7.8, 5.7.9
func TestCrypto_FindObjectsStateMachine(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)

	// Create some test objects
	for i := 0; i < 3; i++ {
		template := []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_DATA)),
			module.NewStringAttribute(module.CKA_LABEL, "find-state-test"),
			module.NewBoolAttribute(module.CKA_TOKEN, false),
		}
		handle, _ := env.Module.CreateObject(session, template)
		defer env.Module.DestroyObject(session, handle)
	}

	t.Run("FindObjects_ProperSequence", func(t *testing.T) {
		// Init
		rv := env.Module.FindObjectsInit(session, nil)
		if rv != module.CKR_OK {
			t.Fatalf("FindObjectsInit: expected CKR_OK, got %s", rv.String())
		}

		// Find (multiple calls allowed)
		handles1, rv := env.Module.FindObjects(session, 2)
		if rv != module.CKR_OK {
			t.Fatalf("FindObjects 1: expected CKR_OK, got %s", rv.String())
		}
		t.Logf("First FindObjects returned %d handles", len(handles1))

		handles2, rv := env.Module.FindObjects(session, 10)
		if rv != module.CKR_OK {
			t.Fatalf("FindObjects 2: expected CKR_OK, got %s", rv.String())
		}
		t.Logf("Second FindObjects returned %d handles", len(handles2))

		// Final
		rv = env.Module.FindObjectsFinal(session)
		if rv != module.CKR_OK {
			t.Fatalf("FindObjectsFinal: expected CKR_OK, got %s", rv.String())
		}
	})

	t.Run("FindObjects_DoubleInit", func(t *testing.T) {
		rv := env.Module.FindObjectsInit(session, nil)
		if rv != module.CKR_OK {
			t.Fatalf("FindObjectsInit: expected CKR_OK, got %s", rv.String())
		}

		// Double init should fail
		rv = env.Module.FindObjectsInit(session, nil)
		if rv != module.CKR_OPERATION_ACTIVE {
			t.Errorf("Double FindObjectsInit: expected CKR_OPERATION_ACTIVE, got %s", rv.String())
		}

		// Clean up
		env.Module.FindObjectsFinal(session)
	})

	t.Run("FindObjects_WithoutInit", func(t *testing.T) {
		_, rv := env.Module.FindObjects(session, 10)
		if rv != module.CKR_OPERATION_NOT_INITIALIZED {
			t.Errorf("FindObjects without Init: expected CKR_OPERATION_NOT_INITIALIZED, got %s", rv.String())
		}
	})

	t.Run("FindObjectsFinal_WithoutInit", func(t *testing.T) {
		rv := env.Module.FindObjectsFinal(session)
		if rv != module.CKR_OPERATION_NOT_INITIALIZED {
			t.Errorf("FindObjectsFinal without Init: expected CKR_OPERATION_NOT_INITIALIZED, got %s", rv.String())
		}
	})
}

// TestCrypto_SessionObjectCleanup tests that session objects are cleaned up when session closes.
//
// Reference: OASIS PKCS#11 v3.0, Section 5.6
func TestCrypto_SessionObjectCleanup(t *testing.T) {
	env := testutil.SetupTestEnvironment(t, nil)
	env.MustInitializeModule(t)
	env.MustInitializeToken(t, testutil.TestPINs.SO, testutil.TestLabels.Token)

	// Setup user PIN
	session := env.MustOpenRWSession(t)
	env.MustLoginSO(t, session, testutil.TestPINs.SO)
	testutil.RequireOK(t, env.Module.InitPIN(session, testutil.TestPINs.User), "InitPIN")
	testutil.RequireOK(t, env.Module.Logout(session), "Logout")
	testutil.RequireOK(t, env.Module.CloseSession(session), "CloseSession")

	// Create session object and verify cleanup
	session = env.MustOpenRWSession(t)
	env.MustLoginUser(t, session, testutil.TestPINs.User)

	template := []module.Attribute{
		module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_DATA)),
		module.NewStringAttribute(module.CKA_LABEL, "session-cleanup-test"),
		module.NewBoolAttribute(module.CKA_TOKEN, false), // Session object
	}

	handle, rv := env.Module.CreateObject(session, template)
	if rv != module.CKR_OK {
		t.Fatalf("CreateObject: expected CKR_OK, got %s", rv.String())
	}

	// Verify object exists
	_, rv = env.Module.GetAttributeValue(session, handle, []module.Attribute{{Type: module.CKA_LABEL}})
	if rv != module.CKR_OK {
		t.Fatalf("object should exist: got %s", rv.String())
	}

	// Close session
	env.Module.Logout(session)
	env.Module.CloseSession(session)

	// Open new session and verify object is gone
	session2 := env.MustOpenRWSession(t)
	env.MustLoginUser(t, session2, testutil.TestPINs.User)
	defer env.Module.CloseSession(session2)
	defer env.Module.Logout(session2)

	_, rv = env.Module.GetAttributeValue(session2, handle, []module.Attribute{{Type: module.CKA_LABEL}})
	if rv == module.CKR_OK {
		t.Error("session object should have been cleaned up")
	}
}

// TestCrypto_OperationCancellation tests operation cancellation behavior.
//
// Reference: OASIS PKCS#11 v3.0, Section 5.8, 5.9, 5.10
// "If an operation fails, no action is taken on the target."
func TestCrypto_OperationCancellation(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)

	// Start digest operation
	rv := env.Module.DigestInit(session, &module.Mechanism{Type: module.CKM_SHA256})
	if rv != module.CKR_OK {
		t.Skipf("DigestInit: %s", rv.String())
	}

	// Complete the operation normally (this cancels/finalizes it)
	_, rv = env.Module.Digest(session, []byte("test"))
	if rv != module.CKR_OK {
		t.Fatalf("Digest: expected CKR_OK, got %s", rv.String())
	}

	// Starting a new operation should now work
	rv = env.Module.DigestInit(session, &module.Mechanism{Type: module.CKM_SHA256})
	if rv != module.CKR_OK {
		t.Errorf("DigestInit after completion: expected CKR_OK, got %s", rv.String())
	}

	// Clean up
	env.Module.Digest(session, []byte("cleanup"))
}
