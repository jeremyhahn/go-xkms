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

		sh := openAuthenticatedRWSession(t, m)
		keyHandle := generateSecretKey(t, m, sh)

		mechanism := module.NewMechanismWithTypedParams(module.CKM_AES_GCM, module.NewAESGCMParams(suiteGCMIV(), 128))
		rv := m.EncryptInit(sh, mechanism, keyHandle)
		requireRV(t, module.CKR_OK, rv, "EncryptInit with valid session, mechanism, and key should return CKR_OK")
	})

	// PKCS#11 v3.2 §5.8.1: "C_EncryptInit can be called with pMechanism set to
	// NULL_PTR to terminate an active encryption operation." A NULL mechanism is
	// therefore a cancellation request, not a malformed argument, and the module
	// answers CKR_OK whether or not an operation was active -- §5.6.5 settles the
	// latter for C_SessionCancel, which ignores a flag naming an inactive
	// operation.
	t.Run("nil_mechanism_terminates_operation", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)
		keyHandle := generateSecretKey(t, m, sh)

		rv := m.EncryptInit(sh, nil, keyHandle)
		requireRV(t, module.CKR_OK, rv,
			"EncryptInit with nil mechanism terminates the operation and returns CKR_OK")
	})

	t.Run("invalid_key_handle_fails", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)
		invalidKey := module.ObjectHandle(0xBADF00D)

		mechanism := module.NewMechanismWithTypedParams(module.CKM_AES_GCM, module.NewAESGCMParams(suiteGCMIV(), 128))
		rv := m.EncryptInit(sh, mechanism, invalidKey)
		requireRV(t, module.CKR_KEY_HANDLE_INVALID, rv,
			"EncryptInit with invalid key handle should return CKR_KEY_HANDLE_INVALID")
	})

	t.Run("invalid_session_handle_fails", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		invalidSession := module.SessionHandle(0xDEADBEEF)
		mechanism := module.NewMechanismWithTypedParams(module.CKM_AES_GCM, module.NewAESGCMParams(suiteGCMIV(), 128))

		rv := m.EncryptInit(invalidSession, mechanism, module.ObjectHandle(1))
		requireRV(t, module.CKR_SESSION_HANDLE_INVALID, rv,
			"EncryptInit with invalid session should return CKR_SESSION_HANDLE_INVALID")
	})

	t.Run("double_encrypt_init_returns_operation_active", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)
		keyHandle := generateSecretKey(t, m, sh)

		mechanism := module.NewMechanismWithTypedParams(module.CKM_AES_GCM, module.NewAESGCMParams(suiteGCMIV(), 128))
		rv := m.EncryptInit(sh, mechanism, keyHandle)
		requireRV(t, module.CKR_OK, rv, "first EncryptInit should succeed")

		rv = m.EncryptInit(sh, mechanism, keyHandle)
		requireRV(t, module.CKR_OPERATION_ACTIVE, rv,
			"second EncryptInit should return CKR_OPERATION_ACTIVE")
	})
}

// testEncrypt verifies C_Encrypt (single-part encryption) behavior per PKCS#11 Section 5.8.2.
func (s *Suite) testEncrypt(t *testing.T) {

	t.Run("encrypt_matches_the_AES_GCM_oracle", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)
		keyHandle := generateSecretKey(t, m, sh)

		mechanism := module.NewMechanismWithTypedParams(module.CKM_AES_GCM, module.NewAESGCMParams(suiteGCMIV(), 128))
		rv := m.EncryptInit(sh, mechanism, keyHandle)
		requireRV(t, module.CKR_OK, rv, "EncryptInit should succeed")

		plaintext := []byte("conformance test plaintext data!")
		ciphertext, rv := m.Encrypt(sh, plaintext)
		requireRV(t, module.CKR_OK, rv, "Encrypt should return CKR_OK")

		// A module that returned the plaintext untouched passed the previous
		// len != 0 assertion. These three checks close that hole: the output
		// must differ from the input, must carry the 128-bit tag
		// CK_GCM_PARAMS.ulTagBits asked for (v3.2 §6.13.7 fixes the wire
		// format as ciphertext || tag), and must equal what an independent
		// AES-GCM implementation produces under the same key and IV.
		if bytes.Equal(ciphertext, plaintext) {
			t.Fatal("Encrypt returned the plaintext unchanged")
		}
		if len(ciphertext) != len(plaintext)+gcmTagLen {
			t.Fatalf("AES-GCM ciphertext is %d bytes, want %d (plaintext + %d-byte tag)",
				len(ciphertext), len(plaintext)+gcmTagLen, gcmTagLen)
		}

		keyValue := attributeValue(t, m, sh, keyHandle, module.CKA_VALUE)
		expected := aesGCMSeal(t, keyValue, suiteGCMIV(), plaintext, nil)
		if !bytes.Equal(ciphertext, expected) {
			t.Fatalf("Encrypt disagrees with the AES-GCM oracle\n got %x\nwant %x",
				ciphertext, expected)
		}
	})

	t.Run("encrypt_without_init_returns_operation_not_initialized", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)

		plaintext := []byte("should fail without EncryptInit")
		_, rv := m.Encrypt(sh, plaintext)
		requireRV(t, module.CKR_OPERATION_NOT_INITIALIZED, rv,
			"Encrypt without EncryptInit should return CKR_OPERATION_NOT_INITIALIZED")
	})

	t.Run("encrypt_with_invalid_session_fails", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		invalidSession := module.SessionHandle(0xDEADBEEF)

		plaintext := []byte("should fail with invalid session")
		_, rv := m.Encrypt(invalidSession, plaintext)
		requireRV(t, module.CKR_SESSION_HANDLE_INVALID, rv,
			"Encrypt with invalid session should return CKR_SESSION_HANDLE_INVALID")
	})

	t.Run("encrypt_clears_operation_state", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)
		keyHandle := generateSecretKey(t, m, sh)

		mechanism := module.NewMechanismWithTypedParams(module.CKM_AES_GCM, module.NewAESGCMParams(suiteGCMIV(), 128))
		rv := m.EncryptInit(sh, mechanism, keyHandle)
		requireRV(t, module.CKR_OK, rv, "EncryptInit should succeed")

		plaintext := []byte("conformance test plaintext data!")
		first, rv := m.Encrypt(sh, plaintext)
		requireRV(t, module.CKR_OK, rv, "first Encrypt should succeed")

		// The operation stays active until the caller confirms it received
		// the ciphertext, so the two-call buffer convention can retry it
		// (v3.2 5.2). Re-running the encryption instead would consume a
		// second nonce for the same plaintext, so comparing the two outputs
		// is the check that matters: identical bytes prove the buffered
		// ciphertext was served rather than a fresh encryption performed.
		second, rv := m.Encrypt(sh, plaintext)
		requireRV(t, module.CKR_OK, rv, "repeated Encrypt should return the cached ciphertext")
		if !bytes.Equal(first, second) {
			t.Fatalf("the retry re-encrypted instead of returning the buffered ciphertext:\n"+
				" got %x\nwant %x", second, first)
		}

		requireRV(t, module.CKR_OK, m.FinishOperation(sh, module.OperationEncrypt),
			"FinishOperation should terminate the encryption operation")

		_, rv = m.Encrypt(sh, plaintext)
		requireRV(t, module.CKR_OPERATION_NOT_INITIALIZED, rv,
			"Encrypt after FinishOperation should return CKR_OPERATION_NOT_INITIALIZED")
	})
}

// testEncryptMultiPart verifies C_EncryptUpdate and C_EncryptFinal (multi-part encryption)
// behavior per PKCS#11 Section 5.8.3 and 5.8.4.
func (s *Suite) testEncryptMultiPart(t *testing.T) {

	t.Run("update_and_final_match_the_AES_GCM_oracle", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)
		keyHandle := generateSecretKey(t, m, sh)

		mechanism := module.NewMechanismWithTypedParams(module.CKM_AES_GCM, module.NewAESGCMParams(suiteGCMIV(), 128))
		rv := m.EncryptInit(sh, mechanism, keyHandle)
		requireRV(t, module.CKR_OK, rv, "EncryptInit should succeed")

		part1 := []byte("first part of pl")
		cipherPart1, rv := m.EncryptUpdate(sh, part1)
		requireRV(t, module.CKR_OK, rv, "EncryptUpdate (part 1) should return CKR_OK")

		part2 := []byte("aintext data!...")
		cipherPart2, rv := m.EncryptUpdate(sh, part2)
		requireRV(t, module.CKR_OK, rv, "EncryptUpdate (part 2) should return CKR_OK")

		finalPart, rv := m.EncryptFinal(sh)
		requireRV(t, module.CKR_OK, rv, "EncryptFinal should return CKR_OK")

		// The ciphertext is the concatenation of everything the chain emitted
		// (v3.2 §5.9.3, §5.9.4). Summing the lengths and checking the total is
		// non-zero, as this test used to, accepts a chain that drops part two
		// entirely.
		ciphertext := make([]byte, 0, len(cipherPart1)+len(cipherPart2)+len(finalPart))
		ciphertext = append(ciphertext, cipherPart1...)
		ciphertext = append(ciphertext, cipherPart2...)
		ciphertext = append(ciphertext, finalPart...)

		plaintext := make([]byte, 0, len(part1)+len(part2))
		plaintext = append(plaintext, part1...)
		plaintext = append(plaintext, part2...)

		// The multi-part chain must produce the same ciphertext a single-part
		// C_Encrypt produces for the same input, key and IV. That comparison
		// cannot be made by encrypting twice through the module -- reusing an
		// AES-GCM (key, IV) pair is refused, correctly -- so the reference is
		// an independent AES-GCM implementation instead, which is a stronger
		// oracle because it lives outside the module entirely.
		keyValue := attributeValue(t, m, sh, keyHandle, module.CKA_VALUE)
		expected := aesGCMSeal(t, keyValue, suiteGCMIV(), plaintext, nil)
		if !bytes.Equal(ciphertext, expected) {
			t.Fatalf("the multi-part ciphertext disagrees with the AES-GCM oracle\n got %x\nwant %x",
				ciphertext, expected)
		}

		// And it must decrypt back to exactly the parts that were fed in.
		requireRV(t, module.CKR_OK, m.FinishOperation(sh, module.OperationEncrypt),
			"FinishOperation should terminate the encryption operation")

		rv = m.DecryptInit(sh, mechanism, keyHandle)
		requireRV(t, module.CKR_OK, rv, "DecryptInit should succeed")

		recovered, rv := m.Decrypt(sh, ciphertext)
		requireRV(t, module.CKR_OK, rv, "Decrypt of the multi-part ciphertext should succeed")
		if !bytes.Equal(recovered, plaintext) {
			t.Fatalf("the multi-part ciphertext did not decrypt to the parts that were fed in\n"+
				" got %q\nwant %q", recovered, plaintext)
		}
	})

	t.Run("update_without_init_returns_operation_not_initialized", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)

		_, rv := m.EncryptUpdate(sh, []byte("should fail"))
		requireRV(t, module.CKR_OPERATION_NOT_INITIALIZED, rv,
			"EncryptUpdate without EncryptInit should return CKR_OPERATION_NOT_INITIALIZED")
	})

	t.Run("final_without_init_returns_operation_not_initialized", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)

		_, rv := m.EncryptFinal(sh)
		requireRV(t, module.CKR_OPERATION_NOT_INITIALIZED, rv,
			"EncryptFinal without EncryptInit should return CKR_OPERATION_NOT_INITIALIZED")
	})
}
