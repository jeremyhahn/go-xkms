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

// RunVerificationTests runs PKCS#11 v3.0 Section 5.12 Verification Functions
// conformance tests.
//
// Tests cover:
//   - C_VerifyInit: initialize a verification operation with mechanism and key
//   - C_Verify: single-part signature verification
//   - C_VerifyUpdate / C_VerifyFinal: multi-part signature verification
//   - C_VerifyRecoverInit / C_VerifyRecover: verification with data recovery
//
// References:
//   - OASIS PKCS#11 v3.0 Section 5.12
func (s *Suite) RunVerificationTests(t *testing.T) {
	t.Run("C_VerifyInit", s.testVerifyInit)
	t.Run("C_Verify", s.testVerify)
	t.Run("C_VerifyUpdate_C_VerifyFinal", s.testVerifyMultiPart)
	t.Run("C_VerifyRecoverInit_C_VerifyRecover", s.testVerifyRecover)
}

// testVerifyInit verifies C_VerifyInit behavior per PKCS#11 Section 5.12.1.
func (s *Suite) testVerifyInit(t *testing.T) {

	t.Run("valid_session_mechanism_key_succeeds", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)
		pubKey, _ := generateRSAKeyPair(t, m, sh)

		mech := &module.Mechanism{Type: module.CKM_RSA_PKCS}

		rv := m.VerifyInit(sh, mech, pubKey)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "VerifyInit with valid session/mechanism/key should succeed")
	})

	t.Run("nil_mechanism_returns_arguments_bad", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)
		pubKey, _ := generateRSAKeyPair(t, m, sh)

		rv := m.VerifyInit(sh, nil, pubKey)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_ARGUMENTS_BAD, rv,
			"VerifyInit with nil mechanism should return CKR_ARGUMENTS_BAD")
	})

	t.Run("invalid_key_handle_fails", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)
		invalidKey := module.ObjectHandle(0xBADF00D)

		mech := &module.Mechanism{Type: module.CKM_RSA_PKCS}

		rv := m.VerifyInit(sh, mech, invalidKey)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_KEY_HANDLE_INVALID, rv,
			"VerifyInit with invalid key handle should return CKR_KEY_HANDLE_INVALID")
	})

	t.Run("invalid_session_handle_fails", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		invalidSession := module.SessionHandle(0xDEADBEEF)
		mech := &module.Mechanism{Type: module.CKM_RSA_PKCS}

		rv := m.VerifyInit(invalidSession, mech, module.ObjectHandle(1))
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_SESSION_HANDLE_INVALID, rv,
			"VerifyInit with invalid session should return CKR_SESSION_HANDLE_INVALID")
	})

	t.Run("double_verify_init_returns_operation_active", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)
		pubKey, _ := generateRSAKeyPair(t, m, sh)

		mech := &module.Mechanism{Type: module.CKM_RSA_PKCS}

		rv := m.VerifyInit(sh, mech, pubKey)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "first VerifyInit should succeed")

		rv = m.VerifyInit(sh, mech, pubKey)
		requireRV(t, module.CKR_OPERATION_ACTIVE, rv,
			"second VerifyInit should return CKR_OPERATION_ACTIVE")
	})
}

// testVerify verifies C_Verify (single-part) behavior per PKCS#11 Section 5.12.2.
func (s *Suite) testVerify(t *testing.T) {

	t.Run("verify_after_init_succeeds", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)
		pubKey, privKey := generateRSAKeyPair(t, m, sh)

		data := []byte("test-data")
		mech := &module.Mechanism{Type: module.CKM_RSA_PKCS}

		// Sign the data first so we have a valid signature to verify
		rv := m.SignInit(sh, mech, privKey)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "SignInit should succeed")

		signature, rv := m.Sign(sh, data)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "Sign should succeed")

		// Verify the signature
		rv = m.VerifyInit(sh, mech, pubKey)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "VerifyInit should succeed")

		rv = m.Verify(sh, data, signature)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv,
			"Verify with valid signature should return CKR_OK")
	})

	t.Run("verify_without_init_returns_operation_not_initialized", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)

		rv := m.Verify(sh, []byte("test-data"), []byte("mock-signature"))
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OPERATION_NOT_INITIALIZED, rv,
			"Verify without VerifyInit should return CKR_OPERATION_NOT_INITIALIZED")
	})

	t.Run("verify_invalid_session_returns_session_handle_invalid", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		invalidSession := module.SessionHandle(0xDEADBEEF)

		rv := m.Verify(invalidSession, []byte("test-data"), []byte("mock-signature"))
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_SESSION_HANDLE_INVALID, rv,
			"Verify with invalid session should return CKR_SESSION_HANDLE_INVALID")
	})

	t.Run("verify_clears_operation_state", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)
		pubKey, privKey := generateRSAKeyPair(t, m, sh)

		data := []byte("test-data")
		mech := &module.Mechanism{Type: module.CKM_RSA_PKCS}

		// Sign to get a valid signature
		rv := m.SignInit(sh, mech, privKey)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "SignInit should succeed")

		signature, rv := m.Sign(sh, data)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "Sign should succeed")

		// First Verify should succeed and clear the operation
		rv = m.VerifyInit(sh, mech, pubKey)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "VerifyInit should succeed")

		rv = m.Verify(sh, data, signature)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "first Verify should succeed")

		// Second Verify without re-init must fail with CKR_OPERATION_NOT_INITIALIZED
		rv = m.Verify(sh, data, signature)
		requireRV(t, module.CKR_OPERATION_NOT_INITIALIZED, rv,
			"second Verify should return CKR_OPERATION_NOT_INITIALIZED after operation consumed")
	})
}

// testVerifyMultiPart verifies C_VerifyUpdate and C_VerifyFinal behavior
// per PKCS#11 Section 5.12.3 and 5.12.4.
func (s *Suite) testVerifyMultiPart(t *testing.T) {

	t.Run("multi_part_verify_succeeds", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)
		pubKey, privKey := generateRSAKeyPair(t, m, sh)

		mech := &module.Mechanism{Type: module.CKM_SHA256_RSA_PKCS}

		// Sign the full data first to get a valid signature
		rv := m.SignInit(sh, mech, privKey)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "SignInit should succeed")

		rv = m.SignUpdate(sh, []byte("test-"))
		requireRV(t, module.CKR_OK, rv, "first SignUpdate should succeed")

		rv = m.SignUpdate(sh, []byte("data"))
		requireRV(t, module.CKR_OK, rv, "second SignUpdate should succeed")

		signature, rv := m.SignFinal(sh)
		requireRV(t, module.CKR_OK, rv, "SignFinal should succeed")

		// Verify using multi-part VerifyUpdate/VerifyFinal with the real signature
		rv = m.VerifyInit(sh, mech, pubKey)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "VerifyInit for multi-part should succeed")

		rv = m.VerifyUpdate(sh, []byte("test-"))
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "first VerifyUpdate should succeed")

		rv = m.VerifyUpdate(sh, []byte("data"))
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "second VerifyUpdate should succeed")

		rv = m.VerifyFinal(sh, signature)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv,
			"VerifyFinal should succeed after VerifyUpdate calls")
	})

	t.Run("verify_update_without_init_returns_operation_not_initialized", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)

		rv := m.VerifyUpdate(sh, []byte("test-data"))
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OPERATION_NOT_INITIALIZED, rv,
			"VerifyUpdate without VerifyInit should return CKR_OPERATION_NOT_INITIALIZED")
	})

	t.Run("verify_final_without_init_returns_operation_not_initialized", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)

		rv := m.VerifyFinal(sh, []byte("mock-signature"))
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OPERATION_NOT_INITIALIZED, rv,
			"VerifyFinal without VerifyInit should return CKR_OPERATION_NOT_INITIALIZED")
	})
}

// testVerifyRecover verifies C_VerifyRecoverInit and C_VerifyRecover behavior
// per PKCS#11 Section 5.12.5 and 5.12.6.
func (s *Suite) testVerifyRecover(t *testing.T) {

	t.Run("verify_recover_init_and_recover_succeeds", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		initTokenAndPIN(t, m)
		sh := openRWSession(t, m)
		loginAsUser(t, m, sh)
		pubKey, privKey := generateRSAKeyPair(t, m, sh)

		mech := &module.Mechanism{Type: module.CKM_RSA_PKCS}

		// Sign recoverable data first so we have a real signature
		rv := m.SignRecoverInit(sh, mech, privKey)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "SignRecoverInit should succeed")

		data := []byte("recoverable data")
		signature, rv := m.SignRecover(sh, data)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "SignRecover should succeed")

		rv = m.VerifyRecoverInit(sh, mech, pubKey)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "VerifyRecoverInit should succeed")

		_, rv = m.VerifyRecover(sh, signature)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		if rv != module.CKR_OK && rv != module.CKR_KEY_FUNCTION_NOT_PERMITTED {
			t.Fatalf("VerifyRecover expected CKR_OK or CKR_KEY_FUNCTION_NOT_PERMITTED, got %v", rv)
		}
	})

	t.Run("verify_recover_without_init_returns_operation_not_initialized", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)

		_, rv := m.VerifyRecover(sh, []byte("mock-signature"))
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OPERATION_NOT_INITIALIZED, rv,
			"VerifyRecover without VerifyRecoverInit should return CKR_OPERATION_NOT_INITIALIZED")
	})
}
