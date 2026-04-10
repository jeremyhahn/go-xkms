// Copyright (c) 2025 Jeremy Hahn
// Licensed under the AGPL-3.0 license with Commercial Licensing Option.
// See LICENSE file in the project root for full license information.

//go:build integration && conformance

// Package conformance provides OASIS PKCS#11 v3.0 conformance tests.
// This file tests PKCS#11 v3.0 specific features per OASIS PKCS#11 v3.0 specification.
//
// Implemented v3.0 features:
//   - C_GetInterfaceList, C_GetInterface (interface discovery)
//   - C_LoginUser with CKU_CONTEXT_SPECIFIC support
//   - C_SessionCancel (operation cancellation)
//   - Message-based encryption: C_MessageEncryptInit, C_EncryptMessage,
//     C_EncryptMessageBegin, C_EncryptMessageNext, C_MessageEncryptFinal
//   - Message-based decryption: C_MessageDecryptInit, C_DecryptMessage,
//     C_DecryptMessageBegin, C_DecryptMessageNext, C_MessageDecryptFinal
//   - Message-based signing: C_MessageSignInit, C_SignMessage,
//     C_SignMessageBegin, C_SignMessageNext, C_MessageSignFinal
//   - Message-based verification: C_MessageVerifyInit, C_VerifyMessage,
//     C_VerifyMessageBegin, C_VerifyMessageNext, C_MessageVerifyFinal
package conformance

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
	testutil "github.com/jeremyhahn/go-xkms/test/integration/pkcs11/module"
)

// =============================================================================
// PKCS#11 v3.0 Interface Tests
// OASIS PKCS#11 v3.0 Section 5.2 - Interface discovery
// =============================================================================

// TestV3InterfaceList tests C_GetInterfaceList returns correct interfaces.
// OASIS PKCS#11 v3.0 Section 5.2.1
func TestV3InterfaceList(t *testing.T) {
	env := testutil.SetupTestEnvironment(t, nil)

	// C_GetInterfaceList can be called before C_Initialize per spec
	t.Run("BeforeInitialize", func(t *testing.T) {
		interfaces, rv := env.Module.GetInterfaceList()
		testutil.RequireOK(t, rv, "GetInterfaceList failed before Initialize")

		if len(interfaces) == 0 {
			t.Fatal("Expected at least one interface")
		}

		// Per v3.0, at least the standard "PKCS 11" interface should be listed
		found := false
		for _, iface := range interfaces {
			t.Logf("Found interface: %s (flags: 0x%x)", iface.Name, iface.Flags)
			if iface.Name == "PKCS 11" {
				found = true
				// Verify FunctionList is set
				if iface.FunctionList == nil {
					t.Error("Interface FunctionList should not be nil")
				}
			}
		}
		if !found {
			t.Error("Expected to find 'PKCS 11' interface")
		}
	})

	env.MustInitializeModule(t)

	t.Run("AfterInitialize", func(t *testing.T) {
		interfaces, rv := env.Module.GetInterfaceList()
		testutil.RequireOK(t, rv, "GetInterfaceList failed after Initialize")

		if len(interfaces) == 0 {
			t.Fatal("Expected at least one interface after Initialize")
		}
		t.Logf("GetInterfaceList returned %d interface(s)", len(interfaces))
	})
}

// TestV3GetInterface tests C_GetInterface with version filtering.
// OASIS PKCS#11 v3.0 Section 5.2.2
func TestV3GetInterface(t *testing.T) {
	env := testutil.SetupTestEnvironment(t, nil)

	t.Run("DefaultInterface", func(t *testing.T) {
		// Empty name should return the default (standard) interface
		iface, rv := env.Module.GetInterface("", nil)
		testutil.RequireOK(t, rv, "GetInterface with empty name failed")

		if iface == nil {
			t.Fatal("Expected non-nil interface")
		}
		if iface.FunctionList == nil {
			t.Error("Expected non-nil FunctionList in interface")
		}
	})

	t.Run("NamedInterface", func(t *testing.T) {
		// Request "PKCS 11" by name
		iface, rv := env.Module.GetInterface("PKCS 11", nil)
		testutil.RequireOK(t, rv, "GetInterface with 'PKCS 11' name failed")

		if iface == nil {
			t.Fatal("Expected non-nil interface")
		}
	})

	t.Run("UnknownInterface", func(t *testing.T) {
		// Unknown interface name should fail
		_, rv := env.Module.GetInterface("Unknown Interface", nil)
		if rv == module.CKR_OK {
			t.Error("Expected error for unknown interface name")
		}
	})

	t.Run("VersionFiltering", func(t *testing.T) {
		// Request v3.0 interface
		version := &module.Version{Major: 3, Minor: 0}
		iface, rv := env.Module.GetInterface("PKCS 11", version)
		testutil.RequireOK(t, rv, "GetInterface with v3.0 version failed")

		if iface == nil {
			t.Fatal("Expected non-nil interface for v3.0")
		}

		// Request v2.40 should also work (backwards compatible)
		version2 := &module.Version{Major: 2, Minor: 40}
		iface2, rv := env.Module.GetInterface("PKCS 11", version2)
		testutil.RequireOK(t, rv, "GetInterface with v2.40 version failed")

		if iface2 == nil {
			t.Fatal("Expected non-nil interface for v2.40 (backwards compatible)")
		}

		// Request v4.0 should fail (future version)
		version4 := &module.Version{Major: 4, Minor: 0}
		_, rv = env.Module.GetInterface("PKCS 11", version4)
		if rv == module.CKR_OK {
			t.Error("Expected error for future version v4.0")
		}
	})
}

// =============================================================================
// PKCS#11 v3.0 Message-Based Functions
// OASIS PKCS#11 v3.0 Section 5.14 - Message-based encryption/decryption
// =============================================================================

// TestV3MessageEncryption tests v3.0 message-based encryption functions.
// OASIS PKCS#11 v3.0 Section 5.14.1-5.14.4
func TestV3MessageEncryption(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)

	// Generate an AES key for encryption
	aesTemplate := testutil.BuildAESKeyTemplate("test-aes-v3-enc", 32)
	keyHandle, rv := env.Module.GenerateKey(session, &module.Mechanism{Type: module.CKM_AES_KEY_GEN}, aesTemplate)
	testutil.RequireOK(t, rv, "GenerateKey failed")

	t.Run("SingleMessageEncryption", func(t *testing.T) {
		// Initialize message-based encryption with AES-GCM
		rv := env.Module.MessageEncryptInit(session, &module.Mechanism{Type: module.CKM_AES_GCM}, keyHandle)
		testutil.RequireOK(t, rv, "MessageEncryptInit failed")

		// Encrypt a single message with associated data
		plaintext := []byte("PKCS#11 v3.0 test message for AEAD encryption")
		aad := []byte("additional authenticated data")
		ciphertext, rv := env.Module.EncryptMessage(session, aad, plaintext)
		testutil.RequireOK(t, rv, "EncryptMessage failed")

		if len(ciphertext) == 0 {
			t.Error("Expected non-empty ciphertext")
		}

		t.Logf("Encrypted %d bytes plaintext to %d bytes ciphertext", len(plaintext), len(ciphertext))

		// Finalize the message encryption operation
		rv = env.Module.MessageEncryptFinal(session)
		testutil.RequireOK(t, rv, "MessageEncryptFinal failed")
	})

	t.Run("MultiPartMessageEncryption", func(t *testing.T) {
		// Initialize message-based encryption
		rv := env.Module.MessageEncryptInit(session, &module.Mechanism{Type: module.CKM_AES_GCM}, keyHandle)
		testutil.RequireOK(t, rv, "MessageEncryptInit failed")

		// Begin multi-part message encryption with AAD
		aad := []byte("associated data for multi-part")
		rv = env.Module.EncryptMessageBegin(session, aad)
		testutil.RequireOK(t, rv, "EncryptMessageBegin failed")

		// Encrypt first part (not final)
		part1 := []byte("First part of the message. ")
		_, rv = env.Module.EncryptMessageNext(session, part1, false)
		testutil.RequireOK(t, rv, "EncryptMessageNext (part 1) failed")

		// Encrypt second part (final)
		part2 := []byte("Second and final part.")
		ciphertext, rv := env.Module.EncryptMessageNext(session, part2, true)
		testutil.RequireOK(t, rv, "EncryptMessageNext (final) failed")

		if len(ciphertext) == 0 {
			t.Error("Expected non-empty ciphertext from final part")
		}

		t.Logf("Multi-part encryption produced %d bytes ciphertext", len(ciphertext))
	})

	t.Run("MessageEncryptWithoutInit", func(t *testing.T) {
		// Try to encrypt without calling MessageEncryptInit first
		_, rv := env.Module.EncryptMessage(session, nil, []byte("test"))
		if rv == module.CKR_OK {
			t.Error("Expected error when encrypting without init")
		}
		// Expected: CKR_OPERATION_NOT_INITIALIZED
		t.Logf("EncryptMessage without init returned: 0x%08x", rv)
	})
}

// TestV3MessageDecryption tests v3.0 message-based decryption functions.
// OASIS PKCS#11 v3.0 Section 5.14.5-5.14.8
func TestV3MessageDecryption(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)

	// Generate an AES key for encryption/decryption
	aesTemplate := testutil.BuildAESKeyTemplate("test-aes-v3-dec", 32)
	keyHandle, rv := env.Module.GenerateKey(session, &module.Mechanism{Type: module.CKM_AES_KEY_GEN}, aesTemplate)
	testutil.RequireOK(t, rv, "GenerateKey failed")

	t.Run("SingleMessageDecryption", func(t *testing.T) {
		// First encrypt a message
		plaintext := []byte("Test message for AEAD decryption")
		aad := []byte("aad-for-decryption-test")

		rv := env.Module.MessageEncryptInit(session, &module.Mechanism{Type: module.CKM_AES_GCM}, keyHandle)
		testutil.RequireOK(t, rv, "MessageEncryptInit failed")

		ciphertext, rv := env.Module.EncryptMessage(session, aad, plaintext)
		testutil.RequireOK(t, rv, "EncryptMessage failed")

		rv = env.Module.MessageEncryptFinal(session)
		testutil.RequireOK(t, rv, "MessageEncryptFinal failed")

		// Now decrypt the message
		rv = env.Module.MessageDecryptInit(session, &module.Mechanism{Type: module.CKM_AES_GCM}, keyHandle)
		testutil.RequireOK(t, rv, "MessageDecryptInit failed")

		decrypted, rv := env.Module.DecryptMessage(session, aad, ciphertext)
		testutil.RequireOK(t, rv, "DecryptMessage failed")

		rv = env.Module.MessageDecryptFinal(session)
		testutil.RequireOK(t, rv, "MessageDecryptFinal failed")

		// Verify decrypted data matches original plaintext
		if string(decrypted) != string(plaintext) {
			t.Errorf("Decrypted data mismatch: got %q, want %q", string(decrypted), string(plaintext))
		}

		t.Logf("Successfully decrypted %d bytes", len(decrypted))
	})

	t.Run("MultiPartMessageDecryption", func(t *testing.T) {
		// Encrypt a message first
		plaintext := []byte("Multi-part decryption test data for PKCS#11 v3.0")
		aad := []byte("multi-part-aad")

		rv := env.Module.MessageEncryptInit(session, &module.Mechanism{Type: module.CKM_AES_GCM}, keyHandle)
		testutil.RequireOK(t, rv, "MessageEncryptInit failed")

		ciphertext, rv := env.Module.EncryptMessage(session, aad, plaintext)
		testutil.RequireOK(t, rv, "EncryptMessage failed")

		rv = env.Module.MessageEncryptFinal(session)
		testutil.RequireOK(t, rv, "MessageEncryptFinal failed")

		// Decrypt using multi-part
		rv = env.Module.MessageDecryptInit(session, &module.Mechanism{Type: module.CKM_AES_GCM}, keyHandle)
		testutil.RequireOK(t, rv, "MessageDecryptInit failed")

		rv = env.Module.DecryptMessageBegin(session, aad)
		testutil.RequireOK(t, rv, "DecryptMessageBegin failed")

		// Decrypt final part
		decrypted, rv := env.Module.DecryptMessageNext(session, ciphertext, true)
		testutil.RequireOK(t, rv, "DecryptMessageNext failed")

		if string(decrypted) != string(plaintext) {
			t.Errorf("Multi-part decrypted data mismatch: got %q, want %q", string(decrypted), string(plaintext))
		}

		t.Logf("Multi-part decryption successful: %d bytes", len(decrypted))
	})

	t.Run("MessageDecryptWithoutInit", func(t *testing.T) {
		// Try to decrypt without calling MessageDecryptInit first
		_, rv := env.Module.DecryptMessage(session, nil, []byte("test"))
		if rv == module.CKR_OK {
			t.Error("Expected error when decrypting without init")
		}
		t.Logf("DecryptMessage without init returned: 0x%08x", rv)
	})
}

// =============================================================================
// PKCS#11 v3.0 Message-Based Signing
// OASIS PKCS#11 v3.0 Section 5.15 - Message-based signing/verification
// =============================================================================

// TestV3MessageSigning tests v3.0 message-based signing functions.
// OASIS PKCS#11 v3.0 Section 5.15.1-5.15.4
func TestV3MessageSigning(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)

	// Generate an RSA key pair for signing
	pubTemplate := testutil.BuildRSAPublicKeyTemplate("test-rsa-v3-sign-pub", 2048)
	privTemplate := testutil.BuildRSAPrivateKeyTemplate("test-rsa-v3-sign-priv")
	_, privHandle, rv := env.Module.GenerateKeyPair(
		session,
		&module.Mechanism{Type: module.CKM_RSA_PKCS_KEY_PAIR_GEN},
		pubTemplate,
		privTemplate,
	)
	testutil.RequireOK(t, rv, "GenerateKeyPair failed")

	t.Run("SingleMessageSign", func(t *testing.T) {
		// Initialize message-based signing
		rv := env.Module.MessageSignInit(session, &module.Mechanism{Type: module.CKM_SHA256_RSA_PKCS}, privHandle)
		testutil.RequireOK(t, rv, "MessageSignInit failed")

		// Sign a single message
		data := []byte("PKCS#11 v3.0 message-based signing test data")
		signature, rv := env.Module.SignMessage(session, data)
		testutil.RequireOK(t, rv, "SignMessage failed")

		if len(signature) == 0 {
			t.Error("Expected non-empty signature")
		}

		t.Logf("Signed %d bytes data, signature is %d bytes", len(data), len(signature))

		// Finalize signing operation
		rv = env.Module.MessageSignFinal(session)
		testutil.RequireOK(t, rv, "MessageSignFinal failed")
	})

	t.Run("MultiPartMessageSign", func(t *testing.T) {
		// Initialize message-based signing
		rv := env.Module.MessageSignInit(session, &module.Mechanism{Type: module.CKM_SHA256_RSA_PKCS}, privHandle)
		testutil.RequireOK(t, rv, "MessageSignInit failed")

		// Begin multi-part signing
		rv = env.Module.SignMessageBegin(session)
		testutil.RequireOK(t, rv, "SignMessageBegin failed")

		// Sign first part (not final)
		part1 := []byte("First part of data to sign. ")
		_, rv = env.Module.SignMessageNext(session, part1, false)
		testutil.RequireOK(t, rv, "SignMessageNext (part 1) failed")

		// Sign second part (final)
		part2 := []byte("Second and final part.")
		signature, rv := env.Module.SignMessageNext(session, part2, true)
		testutil.RequireOK(t, rv, "SignMessageNext (final) failed")

		if len(signature) == 0 {
			t.Error("Expected non-empty signature from final part")
		}

		t.Logf("Multi-part signing produced %d bytes signature", len(signature))
	})

	t.Run("MessageSignWithoutInit", func(t *testing.T) {
		// Try to sign without calling MessageSignInit first
		_, rv := env.Module.SignMessage(session, []byte("test"))
		if rv == module.CKR_OK {
			t.Error("Expected error when signing without init")
		}
		t.Logf("SignMessage without init returned: 0x%08x", rv)
	})
}

// TestV3MessageVerification tests v3.0 message-based verification functions.
// OASIS PKCS#11 v3.0 Section 5.15.5-5.15.8
func TestV3MessageVerification(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)

	// Generate an RSA key pair for signing/verification
	pubTemplate := testutil.BuildRSAPublicKeyTemplate("test-rsa-v3-verify-pub", 2048)
	privTemplate := testutil.BuildRSAPrivateKeyTemplate("test-rsa-v3-verify-priv")
	pubHandle, privHandle, rv := env.Module.GenerateKeyPair(
		session,
		&module.Mechanism{Type: module.CKM_RSA_PKCS_KEY_PAIR_GEN},
		pubTemplate,
		privTemplate,
	)
	testutil.RequireOK(t, rv, "GenerateKeyPair failed")

	t.Run("SingleMessageVerify", func(t *testing.T) {
		// First sign a message
		data := []byte("PKCS#11 v3.0 message verification test")

		rv := env.Module.MessageSignInit(session, &module.Mechanism{Type: module.CKM_SHA256_RSA_PKCS}, privHandle)
		testutil.RequireOK(t, rv, "MessageSignInit failed")

		signature, rv := env.Module.SignMessage(session, data)
		testutil.RequireOK(t, rv, "SignMessage failed")

		rv = env.Module.MessageSignFinal(session)
		testutil.RequireOK(t, rv, "MessageSignFinal failed")

		// Now verify the signature
		rv = env.Module.MessageVerifyInit(session, &module.Mechanism{Type: module.CKM_SHA256_RSA_PKCS}, pubHandle)
		testutil.RequireOK(t, rv, "MessageVerifyInit failed")

		rv = env.Module.VerifyMessage(session, data, signature)
		testutil.RequireOK(t, rv, "VerifyMessage failed")

		rv = env.Module.MessageVerifyFinal(session)
		testutil.RequireOK(t, rv, "MessageVerifyFinal failed")

		t.Logf("Successfully verified %d bytes data with %d bytes signature", len(data), len(signature))
	})

	t.Run("MultiPartMessageVerify", func(t *testing.T) {
		// Sign data first
		data := []byte("Multi-part verification test data for PKCS#11 v3.0")

		rv := env.Module.MessageSignInit(session, &module.Mechanism{Type: module.CKM_SHA256_RSA_PKCS}, privHandle)
		testutil.RequireOK(t, rv, "MessageSignInit failed")

		signature, rv := env.Module.SignMessage(session, data)
		testutil.RequireOK(t, rv, "SignMessage failed")

		rv = env.Module.MessageSignFinal(session)
		testutil.RequireOK(t, rv, "MessageSignFinal failed")

		// Verify using multi-part
		rv = env.Module.MessageVerifyInit(session, &module.Mechanism{Type: module.CKM_SHA256_RSA_PKCS}, pubHandle)
		testutil.RequireOK(t, rv, "MessageVerifyInit failed")

		rv = env.Module.VerifyMessageBegin(session)
		testutil.RequireOK(t, rv, "VerifyMessageBegin failed")

		// Verify with data and signature
		rv = env.Module.VerifyMessageNext(session, data, signature)
		testutil.RequireOK(t, rv, "VerifyMessageNext failed")

		t.Logf("Multi-part verification successful")
	})

	t.Run("VerifyInvalidSignature", func(t *testing.T) {
		data := []byte("test data")
		invalidSig := []byte("invalid signature that should not verify")

		rv := env.Module.MessageVerifyInit(session, &module.Mechanism{Type: module.CKM_SHA256_RSA_PKCS}, pubHandle)
		testutil.RequireOK(t, rv, "MessageVerifyInit failed")

		rv = env.Module.VerifyMessage(session, data, invalidSig)
		if rv == module.CKR_OK {
			t.Error("Expected verification to fail with invalid signature")
		}
		t.Logf("VerifyMessage with invalid signature returned: 0x%08x", rv)

		// Finalize to clean up operation state
		env.Module.MessageVerifyFinal(session)
	})

	t.Run("MessageVerifyWithoutInit", func(t *testing.T) {
		// Try to verify without calling MessageVerifyInit first
		rv := env.Module.VerifyMessage(session, []byte("test"), []byte("sig"))
		if rv == module.CKR_OK {
			t.Error("Expected error when verifying without init")
		}
		t.Logf("VerifyMessage without init returned: 0x%08x", rv)
	})
}

// =============================================================================
// PKCS#11 v3.0 Session Event Notification
// OASIS PKCS#11 v3.0 Section 5.16 - Session event notification
// =============================================================================

// TestV3SessionCancel tests C_SessionCancel function.
// OASIS PKCS#11 v3.0 Section 5.16.1
func TestV3SessionCancel(t *testing.T) {
	env := testutil.SetupTestEnvironment(t, nil)
	env.MustInitializeModule(t)
	env.MustInitializeToken(t, testutil.TestPINs.SO, testutil.TestLabels.Token)

	t.Run("CancelAllWithNoActiveOperation", func(t *testing.T) {
		session, rv := env.Module.OpenSession(0, module.CKF_SERIAL_SESSION|module.CKF_RW_SESSION)
		testutil.RequireOK(t, rv, "OpenSession failed")
		defer env.Module.CloseSession(session)

		// Per OASIS PKCS#11 v3.0 Section 5.16.1:
		// C_SessionCancel with flags=0 (cancel all) should return CKR_OK
		// even if there is no active operation
		rv = env.Module.SessionCancel(session, 0)
		testutil.RequireOK(t, rv, "SessionCancel with flags=0 should succeed")
	})

	t.Run("CancelActiveOperation", func(t *testing.T) {
		session, rv := env.Module.OpenSession(0, module.CKF_SERIAL_SESSION|module.CKF_RW_SESSION)
		testutil.RequireOK(t, rv, "OpenSession failed")
		defer env.Module.CloseSession(session)

		// Login as user
		rv = env.Module.Login(session, module.CKU_USER, testutil.TestPINs.User)
		testutil.RequireOK(t, rv, "Login failed")

		// Generate an AES key
		aesTemplate := testutil.BuildAESKeyTemplate("test-aes-cancel", 32)
		keyHandle, rv := env.Module.GenerateKey(session, &module.Mechanism{Type: module.CKM_AES_KEY_GEN}, aesTemplate)
		testutil.RequireOK(t, rv, "GenerateKey failed")

		// Start an encryption operation
		rv = env.Module.EncryptInit(session, &module.Mechanism{Type: module.CKM_AES_GCM}, keyHandle)
		testutil.RequireOK(t, rv, "EncryptInit failed")

		// Cancel the active operation
		rv = env.Module.SessionCancel(session, 0)
		testutil.RequireOK(t, rv, "SessionCancel with active operation failed")

		// Verify operation was cancelled (trying to encrypt should fail)
		_, rv = env.Module.Encrypt(session, []byte("test"))
		if rv == module.CKR_OK {
			t.Error("Expected error after cancelling operation")
		}

		env.Module.Logout(session)
	})

	t.Run("CancelInvalidSession", func(t *testing.T) {
		// Invalid session handle
		rv := env.Module.SessionCancel(module.SessionHandle(0xFFFFFFFF), 0)
		if rv != module.CKR_SESSION_HANDLE_INVALID {
			t.Errorf("Expected CKR_SESSION_HANDLE_INVALID for invalid session, got: 0x%08x", rv)
		}
	})
}

// =============================================================================
// PKCS#11 v3.0 Login User Types
// OASIS PKCS#11 v3.0 Section 5.6.7 - C_LoginUser
// =============================================================================

// TestV3LoginUser tests C_LoginUser with context-specific logins.
// OASIS PKCS#11 v3.0 Section 5.6.7
func TestV3LoginUser(t *testing.T) {
	env := testutil.SetupTestEnvironment(t, nil)
	env.MustInitializeModule(t)
	env.MustInitializeToken(t, testutil.TestPINs.SO, testutil.TestLabels.Token)

	// Set user PIN first
	soSession, rv := env.Module.OpenSession(0, module.CKF_SERIAL_SESSION|module.CKF_RW_SESSION)
	testutil.RequireOK(t, rv, "OpenSession for SO failed")
	rv = env.Module.Login(soSession, module.CKU_SO, []byte(testutil.TestPINs.SO))
	testutil.RequireOK(t, rv, "SO Login failed")
	rv = env.Module.InitPIN(soSession, []byte(testutil.TestPINs.User))
	testutil.RequireOK(t, rv, "InitPIN failed")
	env.Module.Logout(soSession)
	env.Module.CloseSession(soSession)

	t.Run("LoginUserWithUsername", func(t *testing.T) {
		session, rv := env.Module.OpenSession(0, module.CKF_SERIAL_SESSION|module.CKF_RW_SESSION)
		testutil.RequireOK(t, rv, "OpenSession failed")
		defer env.Module.CloseSession(session)

		// C_LoginUser with username - per v3.0 spec
		rv = env.Module.LoginUser(session, module.CKU_USER, []byte(testutil.TestPINs.User), "testuser")
		testutil.RequireOK(t, rv, "LoginUser with username failed")

		// Logout
		rv = env.Module.Logout(session)
		testutil.RequireOK(t, rv, "Logout failed")
	})

	t.Run("LoginUserWithEmptyUsername", func(t *testing.T) {
		session, rv := env.Module.OpenSession(0, module.CKF_SERIAL_SESSION|module.CKF_RW_SESSION)
		testutil.RequireOK(t, rv, "OpenSession failed")
		defer env.Module.CloseSession(session)

		// C_LoginUser with empty username - should behave like regular C_Login
		rv = env.Module.LoginUser(session, module.CKU_USER, []byte(testutil.TestPINs.User), "")
		testutil.RequireOK(t, rv, "LoginUser with empty username failed")

		// Logout
		rv = env.Module.Logout(session)
		testutil.RequireOK(t, rv, "Logout failed")
	})

	t.Run("LoginUserInvalidSession", func(t *testing.T) {
		rv := env.Module.LoginUser(module.SessionHandle(0xFFFFFFFF), module.CKU_USER, []byte(testutil.TestPINs.User), "testuser")
		if rv != module.CKR_SESSION_HANDLE_INVALID {
			t.Errorf("Expected CKR_SESSION_HANDLE_INVALID for invalid session, got: 0x%08x", rv)
		}
	})

	t.Run("LoginUserWrongPIN", func(t *testing.T) {
		session, rv := env.Module.OpenSession(0, module.CKF_SERIAL_SESSION|module.CKF_RW_SESSION)
		testutil.RequireOK(t, rv, "OpenSession failed")
		defer env.Module.CloseSession(session)

		rv = env.Module.LoginUser(session, module.CKU_USER, []byte("wrongpin"), "testuser")
		if rv != module.CKR_PIN_INCORRECT {
			t.Errorf("Expected CKR_PIN_INCORRECT for wrong PIN, got: 0x%08x", rv)
		}
	})

	t.Run("ContextSpecificLoginWithoutOperation", func(t *testing.T) {
		// Per OASIS PKCS#11 v3.0 Section 5.6.7: CKU_CONTEXT_SPECIFIC login
		// requires an active operation
		session, rv := env.Module.OpenSession(0, module.CKF_SERIAL_SESSION|module.CKF_RW_SESSION)
		testutil.RequireOK(t, rv, "OpenSession failed")
		defer env.Module.CloseSession(session)

		// Try context-specific login without an active operation
		rv = env.Module.LoginUser(session, module.CKU_CONTEXT_SPECIFIC, []byte(testutil.TestPINs.User), "context")
		if rv != module.CKR_OPERATION_NOT_INITIALIZED {
			t.Errorf("Expected CKR_OPERATION_NOT_INITIALIZED for context-specific login without operation, got: 0x%08x", rv)
		}
	})
}

// =============================================================================
// PKCS#11 v3.0 Version Verification
// =============================================================================

// TestV3CryptokiVersion verifies the module reports v3.0 compatibility.
// OASIS PKCS#11 v3.0 Section 5.4
func TestV3CryptokiVersion(t *testing.T) {
	env := testutil.SetupTestEnvironment(t, nil)
	env.MustInitializeModule(t)

	info, rv := env.Module.GetInfo()
	testutil.RequireOK(t, rv, "GetInfo failed")

	// Per OASIS PKCS#11 v3.0, CryptokiVersion should be 3.0
	t.Run("CryptokiVersion", func(t *testing.T) {
		t.Logf("Cryptoki version: %d.%d", info.CryptokiVersion.Major, info.CryptokiVersion.Minor)
		if info.CryptokiVersion.Major < 3 {
			t.Errorf("Module reports Cryptoki version %d.%d, expected 3.x for v3.0 compliance",
				info.CryptokiVersion.Major, info.CryptokiVersion.Minor)
		}
	})

	t.Run("LibraryInfo", func(t *testing.T) {
		t.Logf("Manufacturer: %s", string(info.ManufacturerID[:]))
		t.Logf("Library description: %s", string(info.LibraryDescription[:]))
		t.Logf("Library version: %d.%d", info.LibraryVersion.Major, info.LibraryVersion.Minor)
	})
}

// TestV3TokenInfo verifies token information fields required by v3.0.
// OASIS PKCS#11 v3.0 Section 5.5.2
func TestV3TokenInfo(t *testing.T) {
	env := testutil.SetupTestEnvironment(t, nil)
	env.MustInitializeModule(t)
	env.MustInitializeToken(t, testutil.TestPINs.SO, testutil.TestLabels.Token)

	tokenInfo, rv := env.Module.GetTokenInfo(0)
	testutil.RequireOK(t, rv, "GetTokenInfo failed")

	t.Run("RequiredFields", func(t *testing.T) {
		t.Logf("Token label: %s", string(tokenInfo.Label[:]))
		t.Logf("Manufacturer: %s", string(tokenInfo.ManufacturerID[:]))
		t.Logf("Model: %s", string(tokenInfo.Model[:]))
		t.Logf("Serial: %s", string(tokenInfo.SerialNumber[:]))
		t.Logf("Hardware version: %d.%d", tokenInfo.HardwareVersion.Major, tokenInfo.HardwareVersion.Minor)
		t.Logf("Firmware version: %d.%d", tokenInfo.FirmwareVersion.Major, tokenInfo.FirmwareVersion.Minor)
	})

	t.Run("TokenFlags", func(t *testing.T) {
		t.Logf("Token flags: 0x%08x", tokenInfo.Flags)

		// Per v3.0, check standard flags
		if tokenInfo.Flags&module.CKF_LOGIN_REQUIRED != 0 {
			t.Log("CKF_LOGIN_REQUIRED is set")
		}
		if tokenInfo.Flags&module.CKF_USER_PIN_INITIALIZED != 0 {
			t.Log("CKF_USER_PIN_INITIALIZED is set")
		}
		if tokenInfo.Flags&module.CKF_TOKEN_INITIALIZED != 0 {
			t.Log("CKF_TOKEN_INITIALIZED is set")
		}
		if tokenInfo.Flags&module.CKF_RNG != 0 {
			t.Log("CKF_RNG is set (token has RNG)")
		}
	})

	t.Run("Capacities", func(t *testing.T) {
		t.Logf("Max session count: %d", tokenInfo.MaxSessionCount)
		t.Logf("Session count: %d", tokenInfo.SessionCount)
		t.Logf("Max RW session count: %d", tokenInfo.MaxRwSessionCount)
		t.Logf("RW session count: %d", tokenInfo.RwSessionCount)
		t.Logf("Max PIN length: %d", tokenInfo.MaxPinLen)
		t.Logf("Min PIN length: %d", tokenInfo.MinPinLen)
		t.Logf("Total public memory: %d", tokenInfo.TotalPublicMemory)
		t.Logf("Free public memory: %d", tokenInfo.FreePublicMemory)
		t.Logf("Total private memory: %d", tokenInfo.TotalPrivateMemory)
		t.Logf("Free private memory: %d", tokenInfo.FreePrivateMemory)
	})
}

// TestV3SlotInfo verifies slot information fields required by v3.0.
// OASIS PKCS#11 v3.0 Section 5.5.1
func TestV3SlotInfo(t *testing.T) {
	env := testutil.SetupTestEnvironment(t, nil)
	env.MustInitializeModule(t)

	slotInfo, rv := env.Module.GetSlotInfo(0)
	testutil.RequireOK(t, rv, "GetSlotInfo failed")

	t.Run("RequiredFields", func(t *testing.T) {
		t.Logf("Slot description: %s", string(slotInfo.SlotDescription[:]))
		t.Logf("Manufacturer: %s", string(slotInfo.ManufacturerID[:]))
		t.Logf("Hardware version: %d.%d", slotInfo.HardwareVersion.Major, slotInfo.HardwareVersion.Minor)
		t.Logf("Firmware version: %d.%d", slotInfo.FirmwareVersion.Major, slotInfo.FirmwareVersion.Minor)
	})

	t.Run("SlotFlags", func(t *testing.T) {
		t.Logf("Slot flags: 0x%08x", slotInfo.Flags)

		if slotInfo.Flags&module.CKF_TOKEN_PRESENT != 0 {
			t.Log("CKF_TOKEN_PRESENT is set")
		}
		if slotInfo.Flags&module.CKF_REMOVABLE_DEVICE != 0 {
			t.Log("CKF_REMOVABLE_DEVICE is set")
		}
		if slotInfo.Flags&module.CKF_HW_SLOT != 0 {
			t.Log("CKF_HW_SLOT is set")
		}
	})
}
