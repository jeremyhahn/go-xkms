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

// RunEncryptionTests verifies Section 5.8 Encryption Functions of the PKCS#11 v3.0 spec.
// It exercises C_EncryptInit, C_Encrypt, C_EncryptUpdate, and C_EncryptFinal.
//
// References:
//   - OASIS PKCS#11 v3.0 Section 5.8
func (s *Suite) RunEncryptionTests(t *testing.T) {
	t.Run("C_EncryptInit", s.testEncryptInit)
	t.Run("C_Encrypt", s.testEncrypt)
	t.Run("C_EncryptUpdate_C_EncryptFinal", s.testEncryptMultiPart)
}

// testEncryptInit verifies C_EncryptInit behavior per PKCS#11 Section 5.8.1.
func (s *Suite) testEncryptInit(t *testing.T) {

	t.Run("valid_session_mechanism_key_succeeds", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)
		keyHandle := generateSecretKey(t, m, sh)

		mechanism := &module.Mechanism{Type: module.CKM_AES_GCM}
		rv := m.EncryptInit(sh, mechanism, keyHandle)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "EncryptInit with valid session, mechanism, and key should return CKR_OK")
	})

	t.Run("nil_mechanism_returns_arguments_bad", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)
		keyHandle := generateSecretKey(t, m, sh)

		rv := m.EncryptInit(sh, nil, keyHandle)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_ARGUMENTS_BAD, rv,
			"EncryptInit with nil mechanism should return CKR_ARGUMENTS_BAD")
	})

	t.Run("invalid_key_handle_fails", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)
		invalidKey := module.ObjectHandle(0xBADF00D)

		mechanism := &module.Mechanism{Type: module.CKM_AES_GCM}
		rv := m.EncryptInit(sh, mechanism, invalidKey)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_KEY_HANDLE_INVALID, rv,
			"EncryptInit with invalid key handle should return CKR_KEY_HANDLE_INVALID")
	})

	t.Run("invalid_session_handle_fails", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		invalidSession := module.SessionHandle(0xDEADBEEF)
		mechanism := &module.Mechanism{Type: module.CKM_AES_GCM}

		rv := m.EncryptInit(invalidSession, mechanism, module.ObjectHandle(1))
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_SESSION_HANDLE_INVALID, rv,
			"EncryptInit with invalid session should return CKR_SESSION_HANDLE_INVALID")
	})

	t.Run("double_encrypt_init_returns_operation_active", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)
		keyHandle := generateSecretKey(t, m, sh)

		mechanism := &module.Mechanism{Type: module.CKM_AES_GCM}
		rv := m.EncryptInit(sh, mechanism, keyHandle)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "first EncryptInit should succeed")

		rv = m.EncryptInit(sh, mechanism, keyHandle)
		requireRV(t, module.CKR_OPERATION_ACTIVE, rv,
			"second EncryptInit should return CKR_OPERATION_ACTIVE")
	})
}

// testEncrypt verifies C_Encrypt (single-part encryption) behavior per PKCS#11 Section 5.8.2.
func (s *Suite) testEncrypt(t *testing.T) {

	t.Run("encrypt_returns_non_empty_ciphertext", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)
		keyHandle := generateSecretKey(t, m, sh)

		mechanism := &module.Mechanism{Type: module.CKM_AES_GCM}
		rv := m.EncryptInit(sh, mechanism, keyHandle)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "EncryptInit should succeed")

		plaintext := []byte("conformance test plaintext data!")
		ciphertext, rv := m.Encrypt(sh, plaintext)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "Encrypt should return CKR_OK")

		if len(ciphertext) == 0 {
			t.Fatal("Encrypt returned empty ciphertext")
		}
	})

	t.Run("encrypt_without_init_returns_operation_not_initialized", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)

		plaintext := []byte("should fail without EncryptInit")
		_, rv := m.Encrypt(sh, plaintext)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OPERATION_NOT_INITIALIZED, rv,
			"Encrypt without EncryptInit should return CKR_OPERATION_NOT_INITIALIZED")
	})

	t.Run("encrypt_with_invalid_session_fails", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		invalidSession := module.SessionHandle(0xDEADBEEF)

		plaintext := []byte("should fail with invalid session")
		_, rv := m.Encrypt(invalidSession, plaintext)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_SESSION_HANDLE_INVALID, rv,
			"Encrypt with invalid session should return CKR_SESSION_HANDLE_INVALID")
	})

	t.Run("encrypt_clears_operation_state", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)
		keyHandle := generateSecretKey(t, m, sh)

		mechanism := &module.Mechanism{Type: module.CKM_AES_GCM}
		rv := m.EncryptInit(sh, mechanism, keyHandle)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "EncryptInit should succeed")

		plaintext := []byte("conformance test plaintext data!")
		_, rv = m.Encrypt(sh, plaintext)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "first Encrypt should succeed")

		// Per PKCS#11, a successful C_Encrypt completes the operation.
		// A second C_Encrypt without a new C_EncryptInit must fail.
		_, rv = m.Encrypt(sh, plaintext)
		requireRV(t, module.CKR_OPERATION_NOT_INITIALIZED, rv,
			"second Encrypt without new EncryptInit should return CKR_OPERATION_NOT_INITIALIZED")
	})
}

// testEncryptMultiPart verifies C_EncryptUpdate and C_EncryptFinal (multi-part encryption)
// behavior per PKCS#11 Section 5.8.3 and 5.8.4.
func (s *Suite) testEncryptMultiPart(t *testing.T) {

	t.Run("update_and_final_succeed", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)
		keyHandle := generateSecretKey(t, m, sh)

		mechanism := &module.Mechanism{Type: module.CKM_AES_GCM}
		rv := m.EncryptInit(sh, mechanism, keyHandle)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "EncryptInit should succeed")

		part1 := []byte("first part of pl")
		cipherPart1, rv := m.EncryptUpdate(sh, part1)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "EncryptUpdate (part 1) should return CKR_OK")

		part2 := []byte("aintext data!...")
		cipherPart2, rv := m.EncryptUpdate(sh, part2)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "EncryptUpdate (part 2) should return CKR_OK")

		finalPart, rv := m.EncryptFinal(sh)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "EncryptFinal should return CKR_OK")

		// At least one of the parts or the final block should contain ciphertext.
		totalLen := len(cipherPart1) + len(cipherPart2) + len(finalPart)
		if totalLen == 0 {
			t.Fatal("multi-part encryption produced zero total ciphertext bytes")
		}
	})

	t.Run("update_without_init_returns_operation_not_initialized", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)

		_, rv := m.EncryptUpdate(sh, []byte("should fail"))
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OPERATION_NOT_INITIALIZED, rv,
			"EncryptUpdate without EncryptInit should return CKR_OPERATION_NOT_INITIALIZED")
	})

	t.Run("final_without_init_returns_operation_not_initialized", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)

		_, rv := m.EncryptFinal(sh)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OPERATION_NOT_INITIALIZED, rv,
			"EncryptFinal without EncryptInit should return CKR_OPERATION_NOT_INITIALIZED")
	})
}
