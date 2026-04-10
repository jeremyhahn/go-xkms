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

// RunDigestTests runs PKCS#11 v3.0 Section 5.10 Digest Functions conformance tests.
//
// Tests cover:
//   - C_DigestInit: mechanism validation, session handle validation, double-init detection
//   - C_Digest: single-part digest, operation state cleanup, pre-init error
//   - C_DigestUpdate / C_DigestFinal: multi-part digest pipeline, pre-init errors
//   - C_DigestKey: key material incorporation, pre-init error, invalid key handle
//
// References:
//   - OASIS PKCS#11 v3.0 Section 5.10
func (s *Suite) RunDigestTests(t *testing.T) {
	t.Run("C_DigestInit", s.testDigestInit)
	t.Run("C_Digest", s.testDigest)
	t.Run("C_DigestUpdate_C_DigestFinal", s.testDigestUpdateFinal)
	t.Run("C_DigestKey", s.testDigestKey)
}

// testDigestInit verifies C_DigestInit behavior per PKCS#11 v3.0 Section 5.10.1.
func (s *Suite) testDigestInit(t *testing.T) {

	t.Run("init_with_SHA256_succeeds", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)

		mech := &module.Mechanism{Type: module.CKM_SHA256}
		rv := m.DigestInit(sh, mech)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "DigestInit with CKM_SHA256 should succeed")

		// Consume the active operation so session state is clean
		_, rv = m.Digest(sh, []byte("cleanup"))
		requireRV(t, module.CKR_OK, rv, "Digest cleanup should succeed")
	})

	t.Run("nil_mechanism_returns_arguments_bad", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)

		rv := m.DigestInit(sh, nil)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_ARGUMENTS_BAD, rv,
			"DigestInit with nil mechanism should return CKR_ARGUMENTS_BAD")
	})

	t.Run("invalid_session_returns_session_handle_invalid", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		invalidSession := module.SessionHandle(0xDEADBEEF)
		mech := &module.Mechanism{Type: module.CKM_SHA256}

		rv := m.DigestInit(invalidSession, mech)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_SESSION_HANDLE_INVALID, rv,
			"DigestInit with invalid session should return CKR_SESSION_HANDLE_INVALID")
	})

	t.Run("double_init_returns_operation_active", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)

		mech := &module.Mechanism{Type: module.CKM_SHA256}
		rv := m.DigestInit(sh, mech)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "first DigestInit should succeed")

		rv = m.DigestInit(sh, mech)
		requireRV(t, module.CKR_OPERATION_ACTIVE, rv,
			"second DigestInit should return CKR_OPERATION_ACTIVE")

		// Consume the active operation so session state is clean
		_, rv = m.Digest(sh, []byte("cleanup"))
		requireRV(t, module.CKR_OK, rv, "Digest cleanup should succeed")
	})
}

// testDigest verifies single-part C_Digest behavior per PKCS#11 v3.0 Section 5.10.2.
func (s *Suite) testDigest(t *testing.T) {

	t.Run("digest_SHA256_returns_32_byte_hash", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)

		mech := &module.Mechanism{Type: module.CKM_SHA256}
		rv := m.DigestInit(sh, mech)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "DigestInit should succeed")

		data := []byte("The quick brown fox jumps over the lazy dog")
		digest, rv := m.Digest(sh, data)
		requireRV(t, module.CKR_OK, rv, "Digest should return CKR_OK")

		if len(digest) == 0 {
			t.Fatal("Digest returned empty result")
		}

		// SHA-256 always produces a 32-byte digest
		const sha256Len = 32
		if len(digest) != sha256Len {
			t.Fatalf("SHA-256 digest length: got %d, want %d", len(digest), sha256Len)
		}
	})

	t.Run("digest_without_init_returns_operation_not_initialized", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)

		_, rv := m.Digest(sh, []byte("no-init"))
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OPERATION_NOT_INITIALIZED, rv,
			"Digest without DigestInit should return CKR_OPERATION_NOT_INITIALIZED")
	})

	t.Run("digest_clears_operation_state", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)

		mech := &module.Mechanism{Type: module.CKM_SHA256}
		rv := m.DigestInit(sh, mech)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "DigestInit should succeed")

		_, rv = m.Digest(sh, []byte("first-digest"))
		requireRV(t, module.CKR_OK, rv, "first Digest should succeed")

		// The successful Digest call must have terminated the operation.
		// A second Digest without a new DigestInit must fail.
		_, rv = m.Digest(sh, []byte("second-digest"))
		requireRV(t, module.CKR_OPERATION_NOT_INITIALIZED, rv,
			"second Digest without new DigestInit should return CKR_OPERATION_NOT_INITIALIZED")
	})
}

// testDigestUpdateFinal verifies multi-part C_DigestUpdate and C_DigestFinal
// behavior per PKCS#11 v3.0 Section 5.10.3 and 5.10.5.
func (s *Suite) testDigestUpdateFinal(t *testing.T) {

	t.Run("multi_part_digest_succeeds", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)

		mech := &module.Mechanism{Type: module.CKM_SHA256}
		rv := m.DigestInit(sh, mech)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "DigestInit should succeed")

		rv = m.DigestUpdate(sh, []byte("part one "))
		requireRV(t, module.CKR_OK, rv, "first DigestUpdate should succeed")

		rv = m.DigestUpdate(sh, []byte("part two"))
		requireRV(t, module.CKR_OK, rv, "second DigestUpdate should succeed")

		digest, rv := m.DigestFinal(sh)
		requireRV(t, module.CKR_OK, rv, "DigestFinal should return CKR_OK")

		if len(digest) == 0 {
			t.Fatal("DigestFinal returned empty result")
		}

		// SHA-256 always produces a 32-byte digest
		const sha256Len = 32
		if len(digest) != sha256Len {
			t.Fatalf("SHA-256 multi-part digest length: got %d, want %d", len(digest), sha256Len)
		}
	})

	t.Run("digest_update_without_init_returns_operation_not_initialized", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)

		rv := m.DigestUpdate(sh, []byte("no-init"))
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OPERATION_NOT_INITIALIZED, rv,
			"DigestUpdate without DigestInit should return CKR_OPERATION_NOT_INITIALIZED")
	})

	t.Run("digest_final_without_init_returns_operation_not_initialized", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)

		_, rv := m.DigestFinal(sh)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OPERATION_NOT_INITIALIZED, rv,
			"DigestFinal without DigestInit should return CKR_OPERATION_NOT_INITIALIZED")
	})
}

// testDigestKey verifies C_DigestKey behavior per PKCS#11 v3.0 Section 5.10.4.
func (s *Suite) testDigestKey(t *testing.T) {

	t.Run("digest_key_with_valid_key_succeeds", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)
		// DigestKey needs CKA_VALUE populated on the object to digest key material
		keyHandle := createSecretKeyObject(t, m, sh)

		mech := &module.Mechanism{Type: module.CKM_SHA256}
		rv := m.DigestInit(sh, mech)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "DigestInit should succeed")

		rv = m.DigestKey(sh, keyHandle)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "DigestKey with valid key should succeed")

		digest, rv := m.DigestFinal(sh)
		requireRV(t, module.CKR_OK, rv, "DigestFinal after DigestKey should succeed")

		if len(digest) == 0 {
			t.Fatal("DigestFinal returned empty result after DigestKey")
		}
	})

	t.Run("digest_key_without_init_returns_operation_not_initialized", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)
		keyHandle := generateSecretKey(t, m, sh)

		rv := m.DigestKey(sh, keyHandle)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OPERATION_NOT_INITIALIZED, rv,
			"DigestKey without DigestInit should return CKR_OPERATION_NOT_INITIALIZED")
	})

	t.Run("digest_key_with_invalid_key_handle_fails", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)
		invalidKey := module.ObjectHandle(0xBADF00D)

		mech := &module.Mechanism{Type: module.CKM_SHA256}
		rv := m.DigestInit(sh, mech)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "DigestInit should succeed")

		rv = m.DigestKey(sh, invalidKey)
		if s.skipIfUnsupported(t, rv) {
			return
		}

		// Per PKCS#11, invalid key handle should return CKR_KEY_HANDLE_INVALID.
		// Some implementations may return CKR_OBJECT_HANDLE_INVALID instead.
		if rv != module.CKR_KEY_HANDLE_INVALID && rv != module.CKR_OBJECT_HANDLE_INVALID {
			t.Fatalf("DigestKey with invalid key handle: expected CKR_KEY_HANDLE_INVALID or "+
				"CKR_OBJECT_HANDLE_INVALID, got %s", rv)
		}
	})
}
