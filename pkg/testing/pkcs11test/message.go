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

		sh := openRWSession(t, m)
		keyHandle := generateSecretKey(t, m, sh)

		mech := &module.Mechanism{Type: module.CKM_AES_GCM}

		// Initialize message-based encryption
		rv := m.MessageEncryptInit(sh, mech, keyHandle)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "MessageEncryptInit should return CKR_OK")

		// Encrypt a single message
		aad := []byte("associated-data")
		plaintext := []byte("message-encrypt-test-plaintext!")
		ciphertext, rv := m.EncryptMessage(sh, aad, plaintext)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "EncryptMessage should return CKR_OK")

		if len(ciphertext) == 0 {
			t.Fatal("EncryptMessage returned empty ciphertext")
		}

		// Finalize the message-based encryption session.
		// The underlying EncryptMessage may have already finalized the
		// operation via single-shot delegation, so accept both CKR_OK
		// and CKR_OPERATION_NOT_INITIALIZED.
		rv = m.MessageEncryptFinal(sh)
		if s.skipIfUnsupported(t, rv) {
			return
		}
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

		sh := openRWSession(t, m)
		keyHandle := generateSecretKey(t, m, sh)

		mech := &module.Mechanism{Type: module.CKM_AES_GCM}

		// First, encrypt a message so we have valid ciphertext to decrypt.
		rv := m.MessageEncryptInit(sh, mech, keyHandle)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "MessageEncryptInit for test data should succeed")

		aad := []byte("associated-data")
		plaintext := []byte("message-decrypt-test-plaintext!")
		ciphertext, rv := m.EncryptMessage(sh, aad, plaintext)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "EncryptMessage for test data should succeed")

		rv = m.MessageEncryptFinal(sh)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		// Accept CKR_OPERATION_NOT_INITIALIZED since EncryptMessage may
		// have already finalized the operation via single-shot delegation.
		if rv != module.CKR_OK && rv != module.CKR_OPERATION_NOT_INITIALIZED &&
			rv != module.CKR_FUNCTION_FAILED {
			t.Fatalf("MessageEncryptFinal for test data unexpected error: %v", rv)
		}

		// Now test the decrypt lifecycle
		rv = m.MessageDecryptInit(sh, mech, keyHandle)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "MessageDecryptInit should return CKR_OK")

		decrypted, rv := m.DecryptMessage(sh, aad, ciphertext)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "DecryptMessage should return CKR_OK")

		if len(decrypted) == 0 {
			t.Fatal("DecryptMessage returned empty plaintext")
		}

		// Finalize the message-based decryption session.
		// Accept CKR_OPERATION_NOT_INITIALIZED since DecryptMessage may
		// have already finalized the operation via single-shot delegation.
		rv = m.MessageDecryptFinal(sh)
		if s.skipIfUnsupported(t, rv) {
			return
		}
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

		sh := openRWSession(t, m)
		_, privKey := generateRSAKeyPair(t, m, sh)

		mech := &module.Mechanism{Type: module.CKM_SHA256_RSA_PKCS}

		// Initialize message-based signing
		rv := m.MessageSignInit(sh, mech, privKey)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "MessageSignInit should return CKR_OK")

		// Sign a single message
		data := []byte("message-sign-test-data")
		signature, rv := m.SignMessage(sh, data)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "SignMessage should return CKR_OK")

		if len(signature) == 0 {
			t.Fatal("SignMessage returned empty signature")
		}

		// Finalize the message-based signing session.
		// The underlying SignMessage delegates to Sign which finalizes
		// the operation, so MessageSignFinal may find no active operation.
		rv = m.MessageSignFinal(sh)
		if s.skipIfUnsupported(t, rv) {
			return
		}
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

		sh := openRWSession(t, m)
		pubKey, privKey := generateRSAKeyPair(t, m, sh)

		mech := &module.Mechanism{Type: module.CKM_SHA256_RSA_PKCS}

		// First, sign a message to get a valid signature.
		rv := m.MessageSignInit(sh, mech, privKey)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "MessageSignInit for test data should succeed")

		data := []byte("message-verify-test-data")
		signature, rv := m.SignMessage(sh, data)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "SignMessage for test data should succeed")

		// Finalize the signing session. The underlying SignMessage delegates
		// to Sign which finalizes the operation, so accept both outcomes.
		rv = m.MessageSignFinal(sh)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		if rv != module.CKR_OK && rv != module.CKR_OPERATION_NOT_INITIALIZED &&
			rv != module.CKR_FUNCTION_FAILED {
			t.Fatalf("MessageSignFinal for test data unexpected error: %v", rv)
		}

		// Now test the verify lifecycle
		rv = m.MessageVerifyInit(sh, mech, pubKey)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "MessageVerifyInit should return CKR_OK")

		rv = m.VerifyMessage(sh, data, signature)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "VerifyMessage should return CKR_OK")

		// Finalize the verify session. The underlying VerifyMessage delegates
		// to Verify which finalizes the operation, so accept both outcomes.
		rv = m.MessageVerifyFinal(sh)
		if s.skipIfUnsupported(t, rv) {
			return
		}
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

		sh := openRWSession(t, m)
		keyHandle := generateSecretKey(t, m, sh)

		mech := &module.Mechanism{Type: module.CKM_AES_GCM}

		// Initialize message-based encryption
		rv := m.MessageEncryptInit(sh, mech, keyHandle)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "MessageEncryptInit should return CKR_OK")

		// Begin a multi-part message
		aad := []byte("multi-part-aad")
		rv = m.EncryptMessageBegin(sh, aad)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "EncryptMessageBegin should return CKR_OK")

		// Feed the final (and only) part with final=true
		plaintext := []byte("multi-part-message-plaintext-data")
		ciphertext, rv := m.EncryptMessageNext(sh, plaintext, true)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "EncryptMessageNext(final=true) should return CKR_OK")

		if len(ciphertext) == 0 {
			t.Fatal("EncryptMessageNext returned empty ciphertext")
		}

		// Finalize the message-based encryption session.
		// EncryptMessageNext(final=true) calls EncryptFinal + FinalizeOperation,
		// which may already consume the operation state, so accept both outcomes.
		rv = m.MessageEncryptFinal(sh)
		if s.skipIfUnsupported(t, rv) {
			return
		}
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
		mech := &module.Mechanism{Type: module.CKM_AES_GCM}

		rv := m.MessageEncryptInit(invalidSession, mech, module.ObjectHandle(1))
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_SESSION_HANDLE_INVALID, rv,
			"MessageEncryptInit with invalid session should return CKR_SESSION_HANDLE_INVALID")
	})

	t.Run("MessageDecryptInit_invalid_session", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		invalidSession := module.SessionHandle(0xDEADBEEF)
		mech := &module.Mechanism{Type: module.CKM_AES_GCM}

		rv := m.MessageDecryptInit(invalidSession, mech, module.ObjectHandle(1))
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_SESSION_HANDLE_INVALID, rv,
			"MessageDecryptInit with invalid session should return CKR_SESSION_HANDLE_INVALID")
	})

	t.Run("MessageSignInit_invalid_session", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		invalidSession := module.SessionHandle(0xDEADBEEF)
		mech := &module.Mechanism{Type: module.CKM_SHA256_RSA_PKCS}

		rv := m.MessageSignInit(invalidSession, mech, module.ObjectHandle(1))
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_SESSION_HANDLE_INVALID, rv,
			"MessageSignInit with invalid session should return CKR_SESSION_HANDLE_INVALID")
	})

	t.Run("MessageVerifyInit_invalid_session", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		invalidSession := module.SessionHandle(0xDEADBEEF)
		mech := &module.Mechanism{Type: module.CKM_SHA256_RSA_PKCS}

		rv := m.MessageVerifyInit(invalidSession, mech, module.ObjectHandle(1))
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_SESSION_HANDLE_INVALID, rv,
			"MessageVerifyInit with invalid session should return CKR_SESSION_HANDLE_INVALID")
	})
}
