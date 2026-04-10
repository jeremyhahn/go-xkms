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
	t.Run("C_DecryptUpdate_C_DecryptFinal", s.testDecryptMultiPart)
}

// encryptTestData encrypts plaintext using single-part EncryptInit + Encrypt
// so that the resulting ciphertext can be fed into decryption tests. Returns
// the ciphertext and true on success, or nil and false if the backend does
// not support the operation (in which case the calling test is skipped).
func (s *Suite) encryptTestData(t *testing.T, m *module.Module, sh module.SessionHandle, key module.ObjectHandle, plaintext []byte) ([]byte, bool) {
	t.Helper()

	mech := &module.Mechanism{Type: module.CKM_AES_GCM}

	rv := m.EncryptInit(sh, mech, key)
	if s.skipIfUnsupported(t, rv) {
		return nil, false
	}
	requireRV(t, module.CKR_OK, rv, "EncryptInit for test data failed")

	ciphertext, rv := m.Encrypt(sh, plaintext)
	if s.skipIfUnsupported(t, rv) {
		return nil, false
	}
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

	mech := &module.Mechanism{Type: module.CKM_AES_GCM}

	rv := m.EncryptInit(sh, mech, key)
	if s.skipIfUnsupported(t, rv) {
		return nil, false
	}
	requireRV(t, module.CKR_OK, rv, "EncryptInit for multi-part test data failed")

	_, rv = m.EncryptUpdate(sh, plaintext)
	if s.skipIfUnsupported(t, rv) {
		return nil, false
	}
	requireRV(t, module.CKR_OK, rv, "EncryptUpdate for multi-part test data failed")

	ciphertext, rv := m.EncryptFinal(sh)
	if s.skipIfUnsupported(t, rv) {
		return nil, false
	}
	requireRV(t, module.CKR_OK, rv, "EncryptFinal for multi-part test data failed")

	return ciphertext, true
}

// testDecryptInit verifies C_DecryptInit behavior per PKCS#11 v3.0 Section 5.9.
func (s *Suite) testDecryptInit(t *testing.T) {

	t.Run("valid_session_mechanism_key_succeeds", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)
		key := generateSecretKey(t, m, sh)
		mech := &module.Mechanism{Type: module.CKM_AES_GCM}

		rv := m.DecryptInit(sh, mech, key)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "DecryptInit with valid session, mechanism, and key should succeed")
	})

	t.Run("nil_mechanism_returns_arguments_bad", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)
		key := generateSecretKey(t, m, sh)

		rv := m.DecryptInit(sh, nil, key)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_ARGUMENTS_BAD, rv,
			"DecryptInit with nil mechanism should return CKR_ARGUMENTS_BAD")
	})

	t.Run("invalid_key_handle_returns_key_handle_invalid", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)
		invalidKey := module.ObjectHandle(0xBADF00D)
		mech := &module.Mechanism{Type: module.CKM_AES_GCM}

		rv := m.DecryptInit(sh, mech, invalidKey)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_KEY_HANDLE_INVALID, rv,
			"DecryptInit with invalid key handle should return CKR_KEY_HANDLE_INVALID")
	})

	t.Run("invalid_session_returns_session_handle_invalid", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		invalidSession := module.SessionHandle(0xDEADBEEF)
		mech := &module.Mechanism{Type: module.CKM_AES_GCM}

		rv := m.DecryptInit(invalidSession, mech, module.ObjectHandle(1))
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_SESSION_HANDLE_INVALID, rv,
			"DecryptInit with invalid session should return CKR_SESSION_HANDLE_INVALID")
	})

	t.Run("double_init_returns_operation_active", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)
		key := generateSecretKey(t, m, sh)
		mech := &module.Mechanism{Type: module.CKM_AES_GCM}

		rv := m.DecryptInit(sh, mech, key)
		if s.skipIfUnsupported(t, rv) {
			return
		}
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

		sh := openRWSession(t, m)
		key := generateSecretKey(t, m, sh)
		plaintext := []byte("conformance-test-plaintext-data")

		// Encrypt the plaintext so we have valid ciphertext to decrypt.
		ciphertext, ok := s.encryptTestData(t, m, sh, key, plaintext)
		if !ok {
			return
		}

		mech := &module.Mechanism{Type: module.CKM_AES_GCM}
		rv := m.DecryptInit(sh, mech, key)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "DecryptInit should succeed")

		result, rv := m.Decrypt(sh, ciphertext)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "Decrypt should succeed")

		if len(result) == 0 {
			t.Fatal("Decrypt returned empty plaintext; expected non-empty result")
		}
	})

	t.Run("decrypt_without_init_returns_operation_not_initialized", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)

		_, rv := m.Decrypt(sh, []byte("dummy-ciphertext"))
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OPERATION_NOT_INITIALIZED, rv,
			"Decrypt without DecryptInit should return CKR_OPERATION_NOT_INITIALIZED")
	})

	t.Run("decrypt_with_invalid_session_returns_session_handle_invalid", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		invalidSession := module.SessionHandle(0xDEADBEEF)

		_, rv := m.Decrypt(invalidSession, []byte("dummy-ciphertext"))
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_SESSION_HANDLE_INVALID, rv,
			"Decrypt with invalid session should return CKR_SESSION_HANDLE_INVALID")
	})

	t.Run("decrypt_clears_operation_state", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)
		key := generateSecretKey(t, m, sh)
		plaintext := []byte("state-cleanup-test-data")

		// Encrypt the plaintext so we have valid ciphertext to decrypt.
		ciphertext, ok := s.encryptTestData(t, m, sh, key, plaintext)
		if !ok {
			return
		}

		mech := &module.Mechanism{Type: module.CKM_AES_GCM}
		rv := m.DecryptInit(sh, mech, key)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "DecryptInit should succeed")

		_, rv = m.Decrypt(sh, ciphertext)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "first Decrypt should succeed")

		// The operation has been consumed; a second Decrypt must fail.
		_, rv = m.Decrypt(sh, ciphertext)
		requireRV(t, module.CKR_OPERATION_NOT_INITIALIZED, rv,
			"second Decrypt after completed operation should return CKR_OPERATION_NOT_INITIALIZED")
	})
}

// testDecryptMultiPart verifies C_DecryptUpdate and C_DecryptFinal (multi-part)
// behavior per PKCS#11 v3.0 Section 5.9.
func (s *Suite) testDecryptMultiPart(t *testing.T) {

	t.Run("init_update_final_returns_ok", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)
		key := generateSecretKey(t, m, sh)
		plaintext := []byte("multi-part-decryption-test-data")

		// Encrypt using multi-part to produce ciphertext compatible with multi-part decrypt.
		ciphertext, ok := s.encryptTestDataMultiPart(t, m, sh, key, plaintext)
		if !ok {
			return
		}

		mech := &module.Mechanism{Type: module.CKM_AES_GCM}
		rv := m.DecryptInit(sh, mech, key)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "DecryptInit for multi-part should succeed")

		_, rv = m.DecryptUpdate(sh, ciphertext)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "DecryptUpdate should succeed")

		_, rv = m.DecryptFinal(sh)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "DecryptFinal should succeed")
	})

	t.Run("update_without_init_returns_operation_not_initialized", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)

		_, rv := m.DecryptUpdate(sh, []byte("dummy-ciphertext"))
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OPERATION_NOT_INITIALIZED, rv,
			"DecryptUpdate without DecryptInit should return CKR_OPERATION_NOT_INITIALIZED")
	})

	t.Run("final_without_init_returns_operation_not_initialized", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)

		_, rv := m.DecryptFinal(sh)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OPERATION_NOT_INITIALIZED, rv,
			"DecryptFinal without DecryptInit should return CKR_OPERATION_NOT_INITIALIZED")
	})
}
