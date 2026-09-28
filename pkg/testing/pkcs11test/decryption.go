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
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
)

// RunDecryptionTests runs PKCS#11 v3.0 Section 5.9 Decryption Functions conformance tests.
//
// Tests cover:
//   - C_DecryptInit: valid initialization, nil mechanism, invalid key, invalid session, double init
//   - C_Decrypt: single-part decrypt, no init, invalid session, operation state cleanup
//   - C_DecryptUpdate / C_DecryptFinal: multi-part decrypt, no init errors
//
// References:
//   - OASIS PKCS#11 v3.0 Section 5.9
func (s *Suite) RunDecryptionTests(t *testing.T) {
	t.Run("C_DecryptInit", s.testDecryptInit)
	t.Run("C_Decrypt", s.testDecrypt)
	t.Run("C_Decrypt_RSA_OAEP", s.testDecryptRSAOAEP)
	t.Run("C_DecryptUpdate_C_DecryptFinal", s.testDecryptMultiPart)
}

// encryptTestData encrypts plaintext using single-part EncryptInit + Encrypt
// so that the resulting ciphertext can be fed into decryption tests. Returns
// the ciphertext and true on success, or nil and false if the backend does
// not support the operation (in which case the calling test is skipped).
func (s *Suite) encryptTestData(t *testing.T, m *module.Module, sh module.SessionHandle, key module.ObjectHandle, plaintext []byte) ([]byte, bool) {
	t.Helper()

	mech := module.NewMechanismWithTypedParams(module.CKM_AES_GCM, module.NewAESGCMParams(suiteGCMIV(), 128))

	rv := m.EncryptInit(sh, mech, key)
	requireRV(t, module.CKR_OK, rv, "EncryptInit for test data failed")

	ciphertext, rv := m.Encrypt(sh, plaintext)
	requireRV(t, module.CKR_OK, rv, "Encrypt for test data failed")

	return ciphertext, true
}

// encryptTestDataMultiPart encrypts plaintext using multi-part EncryptInit +
// EncryptUpdate + EncryptFinal so that the resulting ciphertext can be fed
// into multi-part decryption tests. Returns the ciphertext and true on success,
// or nil and false if the backend does not support the operation (in which case
// the calling test is skipped).
func (s *Suite) encryptTestDataMultiPart(t *testing.T, m *module.Module, sh module.SessionHandle, key module.ObjectHandle, plaintext []byte) ([]byte, bool) {
	t.Helper()

	mech := module.NewMechanismWithTypedParams(module.CKM_AES_GCM, module.NewAESGCMParams(suiteGCMIV(), 128))

	rv := m.EncryptInit(sh, mech, key)
	requireRV(t, module.CKR_OK, rv, "EncryptInit for multi-part test data failed")

	_, rv = m.EncryptUpdate(sh, plaintext)
	requireRV(t, module.CKR_OK, rv, "EncryptUpdate for multi-part test data failed")

	ciphertext, rv := m.EncryptFinal(sh)
	requireRV(t, module.CKR_OK, rv, "EncryptFinal for multi-part test data failed")

	return ciphertext, true
}

// testDecryptInit verifies C_DecryptInit behavior per PKCS#11 v3.0 Section 5.9.
func (s *Suite) testDecryptInit(t *testing.T) {

	t.Run("valid_session_mechanism_key_succeeds", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)
		key := generateSecretKey(t, m, sh)
		mech := module.NewMechanismWithTypedParams(module.CKM_AES_GCM, module.NewAESGCMParams(suiteGCMIV(), 128))

		rv := m.DecryptInit(sh, mech, key)
		requireRV(t, module.CKR_OK, rv, "DecryptInit with valid session, mechanism, and key should succeed")
	})

	// PKCS#11 v3.2 §5.10.1: "C_DecryptInit can be called with pMechanism set to
	// NULL_PTR to terminate an active decryption operation." A NULL mechanism is
	// therefore a cancellation request, not a malformed argument, and the module
	// answers CKR_OK whether or not an operation was active -- §5.6.5 settles the
	// latter for C_SessionCancel, which ignores a flag naming an inactive
	// operation.
	t.Run("nil_mechanism_terminates_operation", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)
		key := generateSecretKey(t, m, sh)

		rv := m.DecryptInit(sh, nil, key)
		requireRV(t, module.CKR_OK, rv,
			"DecryptInit with nil mechanism terminates the operation and returns CKR_OK")
	})

	t.Run("invalid_key_handle_returns_key_handle_invalid", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)
		invalidKey := module.ObjectHandle(0xBADF00D)
		mech := module.NewMechanismWithTypedParams(module.CKM_AES_GCM, module.NewAESGCMParams(suiteGCMIV(), 128))

		rv := m.DecryptInit(sh, mech, invalidKey)
		requireRV(t, module.CKR_KEY_HANDLE_INVALID, rv,
			"DecryptInit with invalid key handle should return CKR_KEY_HANDLE_INVALID")
	})

	t.Run("invalid_session_returns_session_handle_invalid", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		invalidSession := module.SessionHandle(0xDEADBEEF)
		mech := module.NewMechanismWithTypedParams(module.CKM_AES_GCM, module.NewAESGCMParams(suiteGCMIV(), 128))

		rv := m.DecryptInit(invalidSession, mech, module.ObjectHandle(1))
		requireRV(t, module.CKR_SESSION_HANDLE_INVALID, rv,
			"DecryptInit with invalid session should return CKR_SESSION_HANDLE_INVALID")
	})

	t.Run("double_init_returns_operation_active", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)
		key := generateSecretKey(t, m, sh)
		mech := module.NewMechanismWithTypedParams(module.CKM_AES_GCM, module.NewAESGCMParams(suiteGCMIV(), 128))

		rv := m.DecryptInit(sh, mech, key)
		requireRV(t, module.CKR_OK, rv, "first DecryptInit should succeed")

		rv = m.DecryptInit(sh, mech, key)
		requireRV(t, module.CKR_OPERATION_ACTIVE, rv,
			"second DecryptInit without completing decrypt should return CKR_OPERATION_ACTIVE")
	})
}

// testDecrypt verifies C_Decrypt (single-part) behavior per PKCS#11 v3.0 Section 5.9.
func (s *Suite) testDecrypt(t *testing.T) {

	t.Run("init_then_decrypt_returns_ok_with_plaintext", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)
		key := generateSecretKey(t, m, sh)
		plaintext := []byte("conformance-test-plaintext-data")

		// Encrypt the plaintext so we have valid ciphertext to decrypt.
		ciphertext, ok := s.encryptTestData(t, m, sh, key, plaintext)
		if !ok {
			return
		}

		mech := module.NewMechanismWithTypedParams(module.CKM_AES_GCM, module.NewAESGCMParams(suiteGCMIV(), 128))
		rv := m.DecryptInit(sh, mech, key)
		requireRV(t, module.CKR_OK, rv, "DecryptInit should succeed")

		result, rv := m.Decrypt(sh, ciphertext)
		requireRV(t, module.CKR_OK, rv, "Decrypt should succeed")

		// Comparing against the plaintext is the whole point of the round
		// trip. Checking only that the result is non-empty accepts a decrypt
		// that hands back the ciphertext, a constant, or the plaintext of
		// some other message.
		if !bytes.Equal(result, plaintext) {
			t.Fatalf("Decrypt did not recover the plaintext\n got %q\nwant %q", result, plaintext)
		}
	})

	// The two negative tests below are the ones that make this file able to
	// fail. Everything else here checks return codes around an operation that
	// was handed well-formed input; a C_Decrypt that never looks at the
	// AES-GCM authentication tag satisfies all of it.
	//
	// PKCS#11 v3.2 §5.10.2 lists CKR_ENCRYPTED_DATA_INVALID as the code for a
	// ciphertext that cannot be decrypted, and also permits the generic
	// CKR_FUNCTION_FAILED, so these tests pin the security property -- the call
	// MUST NOT succeed and MUST NOT hand back data -- rather than one of the
	// two codes the spec allows.
	t.Run("decrypt_with_tampered_ciphertext_fails", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)
		key := generateSecretKey(t, m, sh)
		plaintext := []byte("authenticated-decryption-test-data")

		ciphertext, ok := s.encryptTestData(t, m, sh, key, plaintext)
		if !ok {
			return
		}

		// Flip a bit in the ciphertext body. AES-GCM authenticates every byte
		// it covers, so the tag check must fail; a decrypt that ignores the
		// tag would return CKR_OK and hand back corrupted plaintext.
		tampered := append([]byte(nil), ciphertext...)
		tampered[0] ^= 0x01

		mech := module.NewMechanismWithTypedParams(module.CKM_AES_GCM, module.NewAESGCMParams(suiteGCMIV(), 128))
		rv := m.DecryptInit(sh, mech, key)
		requireRV(t, module.CKR_OK, rv, "DecryptInit should succeed")

		result, rv := m.Decrypt(sh, tampered)
		if rv == module.CKR_OK {
			t.Fatalf("Decrypt accepted a ciphertext its authentication tag no longer "+
				"covers and returned %q", result)
		}
		if len(result) != 0 {
			t.Fatalf("Decrypt returned %d bytes of unauthenticated plaintext alongside %s",
				len(result), rv)
		}
	})

	t.Run("decrypt_under_a_different_key_fails", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)
		key := generateSecretKey(t, m, sh)
		other := generateSecretKey(t, m, sh)
		plaintext := []byte("wrong-key-decryption-test-data")

		ciphertext, ok := s.encryptTestData(t, m, sh, key, plaintext)
		if !ok {
			return
		}

		mech := module.NewMechanismWithTypedParams(module.CKM_AES_GCM, module.NewAESGCMParams(suiteGCMIV(), 128))
		rv := m.DecryptInit(sh, mech, other)
		requireRV(t, module.CKR_OK, rv, "DecryptInit with the other key should succeed")

		// A decrypt that ignores which key C_DecryptInit named would return
		// the plaintext here, which is silent key substitution.
		result, rv := m.Decrypt(sh, ciphertext)
		if rv == module.CKR_OK {
			t.Fatalf("Decrypt under a key the ciphertext was not encrypted with "+
				"returned %q instead of failing", result)
		}
		if len(result) != 0 {
			t.Fatalf("Decrypt returned %d bytes under the wrong key alongside %s",
				len(result), rv)
		}
	})

	t.Run("decrypt_without_init_returns_operation_not_initialized", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)

		_, rv := m.Decrypt(sh, []byte("dummy-ciphertext"))
		requireRV(t, module.CKR_OPERATION_NOT_INITIALIZED, rv,
			"Decrypt without DecryptInit should return CKR_OPERATION_NOT_INITIALIZED")
	})

	t.Run("decrypt_with_invalid_session_returns_session_handle_invalid", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		invalidSession := module.SessionHandle(0xDEADBEEF)

		_, rv := m.Decrypt(invalidSession, []byte("dummy-ciphertext"))
		requireRV(t, module.CKR_SESSION_HANDLE_INVALID, rv,
			"Decrypt with invalid session should return CKR_SESSION_HANDLE_INVALID")
	})

	t.Run("decrypt_clears_operation_state", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)
		key := generateSecretKey(t, m, sh)
		plaintext := []byte("state-cleanup-test-data")

		// Encrypt the plaintext so we have valid ciphertext to decrypt.
		ciphertext, ok := s.encryptTestData(t, m, sh, key, plaintext)
		if !ok {
			return
		}

		mech := module.NewMechanismWithTypedParams(module.CKM_AES_GCM, module.NewAESGCMParams(suiteGCMIV(), 128))
		rv := m.DecryptInit(sh, mech, key)
		requireRV(t, module.CKR_OK, rv, "DecryptInit should succeed")

		first, rv := m.Decrypt(sh, ciphertext)
		requireRV(t, module.CKR_OK, rv, "first Decrypt should succeed")
		if !bytes.Equal(first, plaintext) {
			t.Fatalf("Decrypt did not recover the plaintext\n got %q\nwant %q", first, plaintext)
		}

		// The operation stays active until the caller confirms it received the
		// plaintext, so the two-call buffer convention can retry it (v3.2 5.2).
		// Comparing the two outputs is what proves the retry served the cached
		// plaintext; discarding them would let a module that silently re-ran
		// the backend decryption -- consuming a second round trip and, for a
		// stateful mechanism, different state -- pass.
		second, rv := m.Decrypt(sh, ciphertext)
		requireRV(t, module.CKR_OK, rv, "repeated Decrypt should return the cached plaintext")
		if !bytes.Equal(first, second) {
			t.Fatalf("repeated Decrypt returned different bytes: %q vs %q", first, second)
		}

		requireRV(t, module.CKR_OK, m.FinishOperation(sh, module.OperationDecrypt),
			"FinishOperation should terminate the decryption operation")

		_, rv = m.Decrypt(sh, ciphertext)
		requireRV(t, module.CKR_OPERATION_NOT_INITIALIZED, rv,
			"Decrypt after FinishOperation should return CKR_OPERATION_NOT_INITIALIZED")
	})
}

// testDecryptRSAOAEP verifies CKM_RSA_PKCS_OAEP decryption per PKCS#11 v3.0
// Section 5.9.
//
// Unlike the CKM_AES_GCM cases in testDecrypt, OAEP encrypts under the public
// half of an RSA key pair and decrypts under the private half, so the fixture
// is generateRSAKeyPair rather than generateSecretKey. This is also the
// regression test for the CryptoMockClient bug where Decrypt always ran
// AES-GCM against getOrCreateSymKey regardless of the request's Padding: an
// OAEP decrypt against that backend silently created an unrelated AES key
// and failed, and neither this package nor cmd/pkcs11-module exercised the
// path that would have caught it.
func (s *Suite) testDecryptRSAOAEP(t *testing.T) {

	t.Run("round_trip_recovers_the_plaintext", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)
		pubKey, privKey := generateRSAKeyPair(t, m, sh)
		plaintext := []byte("RSA-OAEP conformance test plaintext")

		mech := module.NewMechanismWithTypedParams(module.CKM_RSA_PKCS_OAEP, module.NewRSAOAEPParams(module.CKM_SHA256))
		rv := m.EncryptInit(sh, mech, pubKey)
		requireRV(t, module.CKR_OK, rv, "EncryptInit (RSA-OAEP) should succeed")

		ciphertext, rv := m.Encrypt(sh, plaintext)
		requireRV(t, module.CKR_OK, rv, "Encrypt (RSA-OAEP) should succeed")
		if bytes.Equal(ciphertext, plaintext) {
			t.Fatal("Encrypt (RSA-OAEP) returned the plaintext unchanged")
		}

		rv = m.DecryptInit(sh, mech, privKey)
		requireRV(t, module.CKR_OK, rv, "DecryptInit (RSA-OAEP) should succeed")

		recovered, rv := m.Decrypt(sh, ciphertext)
		requireRV(t, module.CKR_OK, rv, "Decrypt (RSA-OAEP) should succeed")
		if !bytes.Equal(recovered, plaintext) {
			t.Fatalf("Decrypt (RSA-OAEP) did not recover the plaintext\n got %q\nwant %q", recovered, plaintext)
		}
	})

	// RFC 8017 §7.1.1 binds the OAEP label into the padding the decrypting
	// side reconstructs. Encrypting under one label and decrypting under
	// another must fail exactly as though the ciphertext were corrupt, or a
	// caller that mismatched a label recovers a decryption failure that looks
	// like ciphertext corruption instead of the parameter mistake it is.
	t.Run("wrong_label_fails_with_CKR_ENCRYPTED_DATA_INVALID", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)
		pubKey, privKey := generateRSAKeyPair(t, m, sh)
		plaintext := []byte("label-bound OAEP plaintext")

		encMech := module.NewMechanismWithTypedParams(module.CKM_RSA_PKCS_OAEP,
			module.NewRSAOAEPParamsWithLabel(module.CKM_SHA256, []byte("encrypt-label")))
		rv := m.EncryptInit(sh, encMech, pubKey)
		requireRV(t, module.CKR_OK, rv, "EncryptInit (RSA-OAEP, labeled) should succeed")

		ciphertext, rv := m.Encrypt(sh, plaintext)
		requireRV(t, module.CKR_OK, rv, "Encrypt (RSA-OAEP, labeled) should succeed")

		decMech := module.NewMechanismWithTypedParams(module.CKM_RSA_PKCS_OAEP,
			module.NewRSAOAEPParamsWithLabel(module.CKM_SHA256, []byte("decrypt-label")))
		rv = m.DecryptInit(sh, decMech, privKey)
		requireRV(t, module.CKR_OK, rv, "DecryptInit (RSA-OAEP, labeled) should succeed")

		result, rv := m.Decrypt(sh, ciphertext)
		requireRV(t, module.CKR_ENCRYPTED_DATA_INVALID, rv,
			"Decrypt under a mismatched OAEP label should return CKR_ENCRYPTED_DATA_INVALID")
		if len(result) != 0 {
			t.Fatalf("Decrypt returned %d bytes under a mismatched OAEP label alongside %s", len(result), rv)
		}
	})

	// PKCS#11 v3.2 §5.10.2 lists CKR_ENCRYPTED_DATA_INVALID as the code for a
	// ciphertext C_Decrypt has determined is invalid, mirroring the AES-GCM
	// tampered-ciphertext case in testDecrypt.
	t.Run("tampered_ciphertext_fails_with_CKR_ENCRYPTED_DATA_INVALID", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)
		pubKey, privKey := generateRSAKeyPair(t, m, sh)
		plaintext := []byte("tamper-resistant OAEP plaintext")

		mech := module.NewMechanismWithTypedParams(module.CKM_RSA_PKCS_OAEP, module.NewRSAOAEPParams(module.CKM_SHA256))
		rv := m.EncryptInit(sh, mech, pubKey)
		requireRV(t, module.CKR_OK, rv, "EncryptInit (RSA-OAEP) should succeed")

		ciphertext, rv := m.Encrypt(sh, plaintext)
		requireRV(t, module.CKR_OK, rv, "Encrypt (RSA-OAEP) should succeed")

		tampered := append([]byte(nil), ciphertext...)
		tampered[0] ^= 0x01

		rv = m.DecryptInit(sh, mech, privKey)
		requireRV(t, module.CKR_OK, rv, "DecryptInit (RSA-OAEP) should succeed")

		result, rv := m.Decrypt(sh, tampered)
		requireRV(t, module.CKR_ENCRYPTED_DATA_INVALID, rv,
			"Decrypt of a tampered RSA-OAEP ciphertext should return CKR_ENCRYPTED_DATA_INVALID")
		if len(result) != 0 {
			t.Fatalf("Decrypt returned %d bytes of unauthenticated plaintext alongside %s", len(result), rv)
		}
	})
}

// testDecryptMultiPart verifies C_DecryptUpdate and C_DecryptFinal (multi-part)
// behavior per PKCS#11 v3.0 Section 5.9.
func (s *Suite) testDecryptMultiPart(t *testing.T) {

	t.Run("init_update_final_returns_ok", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)
		key := generateSecretKey(t, m, sh)
		plaintext := []byte("multi-part-decryption-test-data")

		// Encrypt using multi-part to produce ciphertext compatible with multi-part decrypt.
		ciphertext, ok := s.encryptTestDataMultiPart(t, m, sh, key, plaintext)
		if !ok {
			return
		}

		mech := module.NewMechanismWithTypedParams(module.CKM_AES_GCM, module.NewAESGCMParams(suiteGCMIV(), 128))
		rv := m.DecryptInit(sh, mech, key)
		requireRV(t, module.CKR_OK, rv, "DecryptInit for multi-part should succeed")

		part, rv := m.DecryptUpdate(sh, ciphertext)
		requireRV(t, module.CKR_OK, rv, "DecryptUpdate should succeed")

		final, rv := m.DecryptFinal(sh)
		requireRV(t, module.CKR_OK, rv, "DecryptFinal should succeed")

		// The recovered data is whatever the update and the final call
		// produced, concatenated (v3.2 §5.10.3, §5.10.4). Checking only the
		// return codes accepts a chain that recovers nothing at all.
		recovered := make([]byte, 0, len(part)+len(final))
		recovered = append(recovered, part...)
		recovered = append(recovered, final...)
		if !bytes.Equal(recovered, plaintext) {
			t.Fatalf("the multi-part decryption did not recover the plaintext\n got %q\nwant %q",
				recovered, plaintext)
		}
	})

	t.Run("update_without_init_returns_operation_not_initialized", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)

		_, rv := m.DecryptUpdate(sh, []byte("dummy-ciphertext"))
		requireRV(t, module.CKR_OPERATION_NOT_INITIALIZED, rv,
			"DecryptUpdate without DecryptInit should return CKR_OPERATION_NOT_INITIALIZED")
	})

	t.Run("final_without_init_returns_operation_not_initialized", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)

		_, rv := m.DecryptFinal(sh)
		requireRV(t, module.CKR_OPERATION_NOT_INITIALIZED, rv,
			"DecryptFinal without DecryptInit should return CKR_OPERATION_NOT_INITIALIZED")
	})
}
