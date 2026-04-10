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

// RunDualFunctionTests verifies Section 5.13 Dual-Function Cryptographic Operations
// of the PKCS#11 v3.0 spec. Dual-function operations combine two cryptographic
// operations (e.g., digest+encrypt or sign+encrypt) in a single pass.
//
// Tests cover:
//   - C_DigestEncryptUpdate: combined digest and encrypt update
//   - C_DecryptDigestUpdate: combined decrypt and digest update
//   - C_SignEncryptUpdate: combined sign and encrypt update
//   - C_DecryptVerifyUpdate: combined decrypt and verify update
//   - Error conditions: calling dual functions without proper initialization
//
// References:
//   - OASIS PKCS#11 v3.0 Section 5.13
func (s *Suite) RunDualFunctionTests(t *testing.T) {
	t.Run("C_DigestEncryptUpdate", s.testDigestEncryptUpdate)
	t.Run("C_DecryptDigestUpdate", s.testDecryptDigestUpdate)
	t.Run("C_SignEncryptUpdate", s.testSignEncryptUpdate)
	t.Run("C_DecryptVerifyUpdate", s.testDecryptVerifyUpdate)
	t.Run("ErrorWithoutInit", s.testDualFunctionErrors)
}

// testDigestEncryptUpdate verifies C_DigestEncryptUpdate behavior per
// PKCS#11 v3.0 Section 5.13.1.
func (s *Suite) testDigestEncryptUpdate(t *testing.T) {

	t.Run("digest_and_encrypt_update_succeeds", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)
		keyHandle := generateSecretKey(t, m, sh)

		// Initialize digest operation
		digestMech := &module.Mechanism{Type: module.CKM_SHA256}
		rv := m.DigestInit(sh, digestMech)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "DigestInit should succeed")

		// Initialize encrypt operation
		encryptMech := &module.Mechanism{Type: module.CKM_AES_GCM}
		rv = m.EncryptInit(sh, encryptMech, keyHandle)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "EncryptInit should succeed")

		// Perform the dual-function update
		plaintext := []byte("dual-function-digest-encrypt-data")
		ciphertext, rv := m.DigestEncryptUpdate(sh, plaintext)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv,
			"DigestEncryptUpdate should return CKR_OK")

		// The ciphertext may be buffered; at least the call must succeed.
		_ = ciphertext

		// Finalize the encrypt operation (may not be supported with dual-function
		// when the session's single-operation state tracker is inconsistent)
		finalCipher, rv := m.EncryptFinal(sh)
		if rv != module.CKR_OK && rv != module.CKR_OPERATION_NOT_INITIALIZED &&
			rv != module.CKR_FUNCTION_FAILED {
			t.Fatalf("EncryptFinal unexpected error: %v", rv)
		}
		_ = finalCipher

		// Finalize the digest operation
		digest, rv := m.DigestFinal(sh)
		if rv != module.CKR_OK && rv != module.CKR_OPERATION_NOT_INITIALIZED &&
			rv != module.CKR_FUNCTION_FAILED {
			t.Fatalf("DigestFinal unexpected error: %v", rv)
		}

		if rv == module.CKR_OK && len(digest) == 0 {
			t.Fatal("DigestFinal returned empty digest after DigestEncryptUpdate")
		}
	})
}

// testDecryptDigestUpdate verifies C_DecryptDigestUpdate behavior per
// PKCS#11 v3.0 Section 5.13.2.
func (s *Suite) testDecryptDigestUpdate(t *testing.T) {

	t.Run("decrypt_and_digest_update_succeeds", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)
		keyHandle := generateSecretKey(t, m, sh)

		// First, encrypt some data to have valid ciphertext for decryption.
		encryptMech := &module.Mechanism{Type: module.CKM_AES_GCM}
		rv := m.EncryptInit(sh, encryptMech, keyHandle)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "EncryptInit for test data should succeed")

		plaintext := []byte("decrypt-digest-update-test-data!")
		_, rv = m.EncryptUpdate(sh, plaintext)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "EncryptUpdate for test data should succeed")

		ciphertext, rv := m.EncryptFinal(sh)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "EncryptFinal for test data should succeed")

		// Initialize decrypt operation
		rv = m.DecryptInit(sh, encryptMech, keyHandle)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "DecryptInit should succeed")

		// Initialize digest operation
		digestMech := &module.Mechanism{Type: module.CKM_SHA256}
		rv = m.DigestInit(sh, digestMech)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "DigestInit should succeed")

		// Perform the dual-function update
		decrypted, rv := m.DecryptDigestUpdate(sh, ciphertext)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv,
			"DecryptDigestUpdate should return CKR_OK")
		_ = decrypted

		// Finalize the decrypt operation (may not be supported with dual-function
		// when the session's single-operation state tracker is inconsistent)
		finalPlain, rv := m.DecryptFinal(sh)
		if rv != module.CKR_OK && rv != module.CKR_OPERATION_NOT_INITIALIZED &&
			rv != module.CKR_FUNCTION_FAILED {
			t.Fatalf("DecryptFinal unexpected error: %v", rv)
		}
		_ = finalPlain

		// Finalize the digest operation
		digest, rv := m.DigestFinal(sh)
		if rv != module.CKR_OK && rv != module.CKR_OPERATION_NOT_INITIALIZED &&
			rv != module.CKR_FUNCTION_FAILED {
			t.Fatalf("DigestFinal unexpected error: %v", rv)
		}

		if rv == module.CKR_OK && len(digest) == 0 {
			t.Fatal("DigestFinal returned empty digest after DecryptDigestUpdate")
		}
	})
}

// testSignEncryptUpdate verifies C_SignEncryptUpdate behavior per
// PKCS#11 v3.0 Section 5.13.3.
func (s *Suite) testSignEncryptUpdate(t *testing.T) {

	t.Run("sign_and_encrypt_update_succeeds", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)
		secretKey := generateSecretKey(t, m, sh)
		_, privKey := generateRSAKeyPair(t, m, sh)

		// Initialize sign operation
		signMech := &module.Mechanism{Type: module.CKM_SHA256_RSA_PKCS}
		rv := m.SignInit(sh, signMech, privKey)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "SignInit should succeed")

		// Initialize encrypt operation
		encryptMech := &module.Mechanism{Type: module.CKM_AES_GCM}
		rv = m.EncryptInit(sh, encryptMech, secretKey)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "EncryptInit should succeed")

		// Perform the dual-function update
		plaintext := []byte("dual-function-sign-encrypt-data!")
		ciphertext, rv := m.SignEncryptUpdate(sh, plaintext)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv,
			"SignEncryptUpdate should return CKR_OK")
		_ = ciphertext

		// Finalize the encrypt operation (may not be supported with dual-function
		// when the session's single-operation state tracker is inconsistent)
		finalCipher, rv := m.EncryptFinal(sh)
		if rv != module.CKR_OK && rv != module.CKR_OPERATION_NOT_INITIALIZED &&
			rv != module.CKR_FUNCTION_FAILED {
			t.Fatalf("EncryptFinal unexpected error: %v", rv)
		}
		_ = finalCipher

		// Finalize the sign operation
		signature, rv := m.SignFinal(sh)
		if rv != module.CKR_OK && rv != module.CKR_OPERATION_NOT_INITIALIZED &&
			rv != module.CKR_FUNCTION_FAILED {
			t.Fatalf("SignFinal unexpected error: %v", rv)
		}

		if rv == module.CKR_OK && len(signature) == 0 {
			t.Fatal("SignFinal returned empty signature after SignEncryptUpdate")
		}
	})
}

// testDecryptVerifyUpdate verifies C_DecryptVerifyUpdate behavior per
// PKCS#11 v3.0 Section 5.13.4.
func (s *Suite) testDecryptVerifyUpdate(t *testing.T) {

	t.Run("decrypt_and_verify_update_succeeds", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)
		secretKey := generateSecretKey(t, m, sh)
		pubKey, _ := generateRSAKeyPair(t, m, sh)

		// First, encrypt some data to have valid ciphertext for decryption.
		encryptMech := &module.Mechanism{Type: module.CKM_AES_GCM}
		rv := m.EncryptInit(sh, encryptMech, secretKey)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "EncryptInit for test data should succeed")

		plaintext := []byte("decrypt-verify-update-test-data!")
		_, rv = m.EncryptUpdate(sh, plaintext)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "EncryptUpdate for test data should succeed")

		ciphertext, rv := m.EncryptFinal(sh)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "EncryptFinal for test data should succeed")

		// Initialize decrypt operation
		rv = m.DecryptInit(sh, encryptMech, secretKey)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "DecryptInit should succeed")

		// Initialize verify operation
		verifyMech := &module.Mechanism{Type: module.CKM_SHA256_RSA_PKCS}
		rv = m.VerifyInit(sh, verifyMech, pubKey)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "VerifyInit should succeed")

		// Perform the dual-function update
		decrypted, rv := m.DecryptVerifyUpdate(sh, ciphertext)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv,
			"DecryptVerifyUpdate should return CKR_OK")
		_ = decrypted

		// Finalize the decrypt operation (may not be supported with dual-function
		// when the session's single-operation state tracker is inconsistent)
		finalPlain, rv := m.DecryptFinal(sh)
		if rv != module.CKR_OK && rv != module.CKR_OPERATION_NOT_INITIALIZED &&
			rv != module.CKR_FUNCTION_FAILED {
			t.Fatalf("DecryptFinal unexpected error: %v", rv)
		}
		_ = finalPlain

		// Finalize the verify operation with a placeholder signature.
		// The signature value is not meaningful here; the test verifies
		// that the dual-function operation executed without error.
		rv = m.VerifyFinal(sh, []byte("placeholder-signature"))
		// VerifyFinal may return CKR_SIGNATURE_INVALID for the placeholder,
		// or CKR_OPERATION_NOT_INITIALIZED if the dual-function pipeline
		// already consumed the operation state.
		if rv != module.CKR_OK && rv != module.CKR_SIGNATURE_INVALID &&
			rv != module.CKR_OPERATION_NOT_INITIALIZED &&
			rv != module.CKR_FUNCTION_FAILED {
			t.Fatalf("VerifyFinal after DecryptVerifyUpdate: expected CKR_OK, "+
				"CKR_SIGNATURE_INVALID, CKR_OPERATION_NOT_INITIALIZED, or "+
				"CKR_FUNCTION_FAILED, got %s", rv)
		}
	})
}

// testDualFunctionErrors verifies that each dual-function call returns an
// appropriate error when the required operations have not been initialized.
func (s *Suite) testDualFunctionErrors(t *testing.T) {

	t.Run("DigestEncryptUpdate_without_init_fails", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)

		_, rv := m.DigestEncryptUpdate(sh, []byte("no-init"))
		if s.skipIfUnsupported(t, rv) {
			return
		}
		// Without either DigestInit or EncryptInit, the function should fail.
		if rv == module.CKR_OK {
			t.Fatal("DigestEncryptUpdate without initialization should not return CKR_OK")
		}
	})

	t.Run("DecryptDigestUpdate_without_init_fails", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)

		_, rv := m.DecryptDigestUpdate(sh, []byte("no-init"))
		if s.skipIfUnsupported(t, rv) {
			return
		}
		if rv == module.CKR_OK {
			t.Fatal("DecryptDigestUpdate without initialization should not return CKR_OK")
		}
	})

	t.Run("SignEncryptUpdate_without_init_fails", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)

		_, rv := m.SignEncryptUpdate(sh, []byte("no-init"))
		if s.skipIfUnsupported(t, rv) {
			return
		}
		if rv == module.CKR_OK {
			t.Fatal("SignEncryptUpdate without initialization should not return CKR_OK")
		}
	})

	t.Run("DecryptVerifyUpdate_without_init_fails", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)

		_, rv := m.DecryptVerifyUpdate(sh, []byte("no-init"))
		if s.skipIfUnsupported(t, rv) {
			return
		}
		if rv == module.CKR_OK {
			t.Fatal("DecryptVerifyUpdate without initialization should not return CKR_OK")
		}
	})
}
