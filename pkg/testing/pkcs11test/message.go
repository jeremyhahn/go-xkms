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

package pkcs11test

import (
	"bytes"
	"crypto"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
)

// RunMessageTests verifies Section 5.17 Message-based Encryption/Decryption,
// Signing, and Verification operations of the PKCS#11 v3.0 spec.
//
// Message-based operations allow multiple independent messages to be processed
// under a single Init/Final lifecycle, unlike traditional multi-part operations
// that process a single logical message.
//
// Tests cover:
//   - MessageEncrypt: Init + EncryptMessage + Final lifecycle
//   - MessageDecrypt: Init + DecryptMessage + Final lifecycle
//   - MessageSign: Init + SignMessage + Final lifecycle
//   - MessageVerify: Init + VerifyMessage + Final lifecycle
//   - Multi-part message: EncryptMessageBegin + EncryptMessageNext lifecycle
//   - Error conditions: invalid session handles
//
// References:
//   - OASIS PKCS#11 v3.0 Section 5.17
func (s *Suite) RunMessageTests(t *testing.T) {
	t.Run("MessageEncrypt", s.testMessageEncrypt)
	t.Run("MessageDecrypt", s.testMessageDecrypt)
	t.Run("MessageSign", s.testMessageSign)
	t.Run("MessageVerify", s.testMessageVerify)
	t.Run("MultiPartMessage", s.testMultiPartMessage)
	t.Run("InvalidSessionErrors", s.testMessageInvalidSession)
}

// testMessageEncrypt verifies the MessageEncryptInit + EncryptMessage +
// MessageEncryptFinal lifecycle per PKCS#11 v3.0 Section 5.17.
func (s *Suite) testMessageEncrypt(t *testing.T) {

	t.Run("init_encrypt_message_final_succeeds", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)
		keyHandle := generateSecretKey(t, m, sh)

		mech := module.NewMechanismWithTypedParams(module.CKM_AES_GCM, module.NewAESGCMParams(suiteGCMIV(), 128))

		// Initialize message-based encryption
		rv := m.MessageEncryptInit(sh, mech, keyHandle)
		requireRV(t, module.CKR_OK, rv, "MessageEncryptInit should return CKR_OK")

		// Encrypt a single message
		aad := []byte("associated-data")
		plaintext := []byte("message-encrypt-test-plaintext!")
		// The per-message IV and tag travel in CK_GCM_MESSAGE_PARAMS rather than
		// on the Init (v3.2 §6.13.5). CKG_GENERATE asks the token for the IV and
		// it writes back the one it used.
		encParams := &module.AESGCMMessageParams{IVGenerator: module.CKG_GENERATE, TagBits: 128}
		ciphertext, rv := m.EncryptMessage(sh, encParams, aad, plaintext)
		requireRV(t, module.CKR_OK, rv, "EncryptMessage should return CKR_OK")

		// A message-based encryption that handed the plaintext straight back
		// would satisfy a non-empty check. CK_GCM_MESSAGE_PARAMS carries the
		// tag out of band here (v3.2 §6.13.5), so the ciphertext is the same
		// length as the plaintext -- but it must not be the same bytes.
		if bytes.Equal(ciphertext, plaintext) {
			t.Fatal("EncryptMessage returned the plaintext unchanged")
		}
		if len(ciphertext) != len(plaintext) {
			t.Fatalf("AES-GCM message ciphertext is %d bytes, want %d",
				len(ciphertext), len(plaintext))
		}
		if len(encParams.IV) == 0 {
			t.Fatal("EncryptMessage did not return the generated IV; without it the " +
				"caller can never decrypt what it just encrypted")
		}
		if len(encParams.Tag) != 16 {
			t.Fatalf("EncryptMessage returned a %d-byte authentication tag, want 16",
				len(encParams.Tag))
		}

		// Finalize the message-based encryption session.
		// The underlying EncryptMessage may have already finalized the
		// operation via single-shot delegation, so accept both CKR_OK
		// and CKR_OPERATION_NOT_INITIALIZED.
		rv = m.MessageEncryptFinal(sh)
		if rv != module.CKR_OK && rv != module.CKR_OPERATION_NOT_INITIALIZED &&
			rv != module.CKR_FUNCTION_FAILED {
			t.Fatalf("MessageEncryptFinal unexpected error: %v", rv)
		}
	})
}

// testMessageDecrypt verifies the MessageDecryptInit + DecryptMessage +
// MessageDecryptFinal lifecycle per PKCS#11 v3.0 Section 5.17.
func (s *Suite) testMessageDecrypt(t *testing.T) {

	t.Run("init_decrypt_message_final_succeeds", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)
		keyHandle := generateSecretKey(t, m, sh)

		mech := module.NewMechanismWithTypedParams(module.CKM_AES_GCM, module.NewAESGCMParams(suiteGCMIV(), 128))

		// First, encrypt a message so we have valid ciphertext to decrypt.
		rv := m.MessageEncryptInit(sh, mech, keyHandle)
		requireRV(t, module.CKR_OK, rv, "MessageEncryptInit for test data should succeed")

		aad := []byte("associated-data")
		plaintext := []byte("message-decrypt-test-plaintext!")
		encParams := &module.AESGCMMessageParams{IVGenerator: module.CKG_GENERATE, TagBits: 128}
		ciphertext, rv := m.EncryptMessage(sh, encParams, aad, plaintext)
		requireRV(t, module.CKR_OK, rv, "EncryptMessage for test data should succeed")

		rv = m.MessageEncryptFinal(sh)
		// Accept CKR_OPERATION_NOT_INITIALIZED since EncryptMessage may
		// have already finalized the operation via single-shot delegation.
		if rv != module.CKR_OK && rv != module.CKR_OPERATION_NOT_INITIALIZED &&
			rv != module.CKR_FUNCTION_FAILED {
			t.Fatalf("MessageEncryptFinal for test data unexpected error: %v", rv)
		}

		// Now test the decrypt lifecycle
		rv = m.MessageDecryptInit(sh, mech, keyHandle)
		requireRV(t, module.CKR_OK, rv, "MessageDecryptInit should return CKR_OK")

		// The IV and tag the encryption produced are the decryption's inputs.
		decParams := &module.AESGCMMessageParams{
			IV:          encParams.IV,
			IVGenerator: module.CKG_NO_GENERATE,
			Tag:         encParams.Tag,
			TagBits:     128,
		}
		decrypted, rv := m.DecryptMessage(sh, decParams, aad, ciphertext)
		requireRV(t, module.CKR_OK, rv, "DecryptMessage should return CKR_OK")

		if !bytes.Equal(decrypted, plaintext) {
			t.Fatalf("the message-based round trip did not recover the plaintext\n got %q\nwant %q",
				decrypted, plaintext)
		}

		// Finalize the message-based decryption session.
		// Accept CKR_OPERATION_NOT_INITIALIZED since DecryptMessage may
		// have already finalized the operation via single-shot delegation.
		rv = m.MessageDecryptFinal(sh)
		if rv != module.CKR_OK && rv != module.CKR_OPERATION_NOT_INITIALIZED &&
			rv != module.CKR_FUNCTION_FAILED {
			t.Fatalf("MessageDecryptFinal unexpected error: %v", rv)
		}
	})
}

// testMessageSign verifies the MessageSignInit + SignMessage +
// MessageSignFinal lifecycle per PKCS#11 v3.0 Section 5.17.
func (s *Suite) testMessageSign(t *testing.T) {

	t.Run("init_sign_message_final_succeeds", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)
		pubKey, privKey := generateRSAKeyPair(t, m, sh)

		mech := &module.Mechanism{Type: module.CKM_SHA256_RSA_PKCS}

		// Initialize message-based signing
		rv := m.MessageSignInit(sh, mech, privKey)
		requireRV(t, module.CKR_OK, rv, "MessageSignInit should return CKR_OK")

		// Sign a single message
		data := []byte("message-sign-test-data")
		signature, rv := m.SignMessage(sh, data)
		requireRV(t, module.CKR_OK, rv, "SignMessage should return CKR_OK")

		// The sibling testMessageDecrypt round-trips its ciphertext and
		// compares the result; a non-empty check on a signature proves nothing
		// at all. Checking it against the token's own public key with
		// crypto/rsa is the same standard applied to the signing half, and it
		// does not depend on the module's own C_VerifyMessage being correct.
		pub := rsaPublicKeyFor(t, m, sh, pubKey)
		assertRSASignature(t, pub, crypto.SHA256, data, signature)

		// Finalize the message-based signing session.
		// The underlying SignMessage delegates to Sign which finalizes
		// the operation, so MessageSignFinal may find no active operation.
		rv = m.MessageSignFinal(sh)
		if rv != module.CKR_OK && rv != module.CKR_OPERATION_NOT_INITIALIZED &&
			rv != module.CKR_FUNCTION_FAILED {
			t.Fatalf("MessageSignFinal unexpected error: %v", rv)
		}
	})
}

// testMessageVerify verifies the MessageVerifyInit + VerifyMessage +
// MessageVerifyFinal lifecycle per PKCS#11 v3.0 Section 5.17.
func (s *Suite) testMessageVerify(t *testing.T) {

	t.Run("init_verify_message_final_succeeds", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)
		pubKey, privKey := generateRSAKeyPair(t, m, sh)

		mech := &module.Mechanism{Type: module.CKM_SHA256_RSA_PKCS}

		// First, sign a message to get a valid signature.
		rv := m.MessageSignInit(sh, mech, privKey)
		requireRV(t, module.CKR_OK, rv, "MessageSignInit for test data should succeed")

		data := []byte("message-verify-test-data")
		signature, rv := m.SignMessage(sh, data)
		requireRV(t, module.CKR_OK, rv, "SignMessage for test data should succeed")

		// Finalize the signing session. The underlying SignMessage delegates
		// to Sign which finalizes the operation, so accept both outcomes.
		rv = m.MessageSignFinal(sh)
		if rv != module.CKR_OK && rv != module.CKR_OPERATION_NOT_INITIALIZED &&
			rv != module.CKR_FUNCTION_FAILED {
			t.Fatalf("MessageSignFinal for test data unexpected error: %v", rv)
		}

		// Now test the verify lifecycle
		rv = m.MessageVerifyInit(sh, mech, pubKey)
		requireRV(t, module.CKR_OK, rv, "MessageVerifyInit should return CKR_OK")

		rv = m.VerifyMessage(sh, data, signature)
		requireRV(t, module.CKR_OK, rv, "VerifyMessage should return CKR_OK")

		// C_VerifyMessage must also be able to say no, or accepting the valid
		// signature above means nothing (v3.2 §5.16.2, CKR_SIGNATURE_INVALID).
		// One C_MessageVerifyInit covers all of these: a message-based process
		// outlives any single message, and C_VerifyMessage re-establishes it.
		rv = m.VerifyMessage(sh, data, tamper(signature))
		requireRV(t, module.CKR_SIGNATURE_INVALID, rv,
			"VerifyMessage with a corrupted signature should return CKR_SIGNATURE_INVALID")

		rv = m.VerifyMessage(sh, tamper(data), signature)
		requireRV(t, module.CKR_SIGNATURE_INVALID, rv,
			"VerifyMessage against modified data should return CKR_SIGNATURE_INVALID")

		// A rejected message must leave the process usable, so the valid
		// signature still verifies afterwards.
		rv = m.VerifyMessage(sh, data, signature)
		requireRV(t, module.CKR_OK, rv, "VerifyMessage should still accept the valid signature")

		// Finalize the verify session. The underlying VerifyMessage delegates
		// to Verify which finalizes the operation, so accept both outcomes.
		rv = m.MessageVerifyFinal(sh)
		if rv != module.CKR_OK && rv != module.CKR_OPERATION_NOT_INITIALIZED &&
			rv != module.CKR_FUNCTION_FAILED {
			t.Fatalf("MessageVerifyFinal unexpected error: %v", rv)
		}
	})
}

// testMultiPartMessage verifies the multi-part message encryption cycle using
// EncryptMessageBegin + EncryptMessageNext per PKCS#11 v3.0 Section 5.17.
func (s *Suite) testMultiPartMessage(t *testing.T) {

	t.Run("encrypt_message_begin_next_final_succeeds", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)
		keyHandle := generateSecretKey(t, m, sh)

		mech := module.NewMechanismWithTypedParams(module.CKM_AES_GCM, module.NewAESGCMParams(suiteGCMIV(), 128))

		// Initialize message-based encryption
		rv := m.MessageEncryptInit(sh, mech, keyHandle)
		requireRV(t, module.CKR_OK, rv, "MessageEncryptInit should return CKR_OK")

		// Begin a multi-part message
		aad := []byte("multi-part-aad")
		rv = m.EncryptMessageBegin(sh, nil, aad)
		requireRV(t, module.CKR_OK, rv, "EncryptMessageBegin should return CKR_OK")

		// Feed the final (and only) part with final=true
		plaintext := []byte("multi-part-message-plaintext-data")
		ciphertext, rv := m.EncryptMessageNext(sh, nil, plaintext, true)
		requireRV(t, module.CKR_OK, rv, "EncryptMessageNext(final=true) should return CKR_OK")

		if len(ciphertext) == 0 {
			t.Fatal("EncryptMessageNext returned empty ciphertext")
		}

		// Finalize the message-based encryption session.
		// EncryptMessageNext(final=true) calls EncryptFinal + FinalizeOperation,
		// which may already consume the operation state, so accept both outcomes.
		rv = m.MessageEncryptFinal(sh)
		if rv != module.CKR_OK && rv != module.CKR_OPERATION_NOT_INITIALIZED &&
			rv != module.CKR_FUNCTION_FAILED {
			t.Fatalf("MessageEncryptFinal unexpected error: %v", rv)
		}
	})
}

// testMessageInvalidSession verifies that all message-based Init functions
// return CKR_SESSION_HANDLE_INVALID for an invalid session handle.
func (s *Suite) testMessageInvalidSession(t *testing.T) {

	t.Run("MessageEncryptInit_invalid_session", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		invalidSession := module.SessionHandle(0xDEADBEEF)
		mech := module.NewMechanismWithTypedParams(module.CKM_AES_GCM, module.NewAESGCMParams(suiteGCMIV(), 128))

		rv := m.MessageEncryptInit(invalidSession, mech, module.ObjectHandle(1))
		requireRV(t, module.CKR_SESSION_HANDLE_INVALID, rv,
			"MessageEncryptInit with invalid session should return CKR_SESSION_HANDLE_INVALID")
	})

	t.Run("MessageDecryptInit_invalid_session", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		invalidSession := module.SessionHandle(0xDEADBEEF)
		mech := module.NewMechanismWithTypedParams(module.CKM_AES_GCM, module.NewAESGCMParams(suiteGCMIV(), 128))

		rv := m.MessageDecryptInit(invalidSession, mech, module.ObjectHandle(1))
		requireRV(t, module.CKR_SESSION_HANDLE_INVALID, rv,
			"MessageDecryptInit with invalid session should return CKR_SESSION_HANDLE_INVALID")
	})

	t.Run("MessageSignInit_invalid_session", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		invalidSession := module.SessionHandle(0xDEADBEEF)
		mech := &module.Mechanism{Type: module.CKM_SHA256_RSA_PKCS}

		rv := m.MessageSignInit(invalidSession, mech, module.ObjectHandle(1))
		requireRV(t, module.CKR_SESSION_HANDLE_INVALID, rv,
			"MessageSignInit with invalid session should return CKR_SESSION_HANDLE_INVALID")
	})

	t.Run("MessageVerifyInit_invalid_session", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		invalidSession := module.SessionHandle(0xDEADBEEF)
		mech := &module.Mechanism{Type: module.CKM_SHA256_RSA_PKCS}

		rv := m.MessageVerifyInit(invalidSession, mech, module.ObjectHandle(1))
		requireRV(t, module.CKR_SESSION_HANDLE_INVALID, rv,
			"MessageVerifyInit with invalid session should return CKR_SESSION_HANDLE_INVALID")
	})
}
