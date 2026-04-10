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

// RunSigningTests verifies Section 5.11 Signing Functions of the PKCS#11 v3.0 spec.
// It exercises C_SignInit, C_Sign, C_SignUpdate, C_SignFinal, C_SignRecoverInit,
// and C_SignRecover.
//
// References:
//   - OASIS PKCS#11 v3.0 Section 5.11
func (s *Suite) RunSigningTests(t *testing.T) {
	t.Run("C_SignInit", s.testSignInit)
	t.Run("C_Sign", s.testSign)
	t.Run("C_SignUpdate_C_SignFinal", s.testSignUpdateFinal)
	t.Run("C_SignRecoverInit_C_SignRecover", s.testSignRecover)
}

// testSignInit verifies C_SignInit behavior per PKCS#11 v3.0 Section 5.11.1.
func (s *Suite) testSignInit(t *testing.T) {

	t.Run("Happy_SignInitWithValidParamsReturnsOK", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)
		_, keyHandle := generateRSAKeyPair(t, m, sh)

		mech := &module.Mechanism{Type: module.CKM_SHA256_RSA_PKCS}
		rv := m.SignInit(sh, mech, keyHandle)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "SignInit with valid session, mechanism, and key should return CKR_OK")
	})

	t.Run("Error_SignInitWithNilMechanismReturnsArgumentsBad", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)
		_, keyHandle := generateRSAKeyPair(t, m, sh)

		rv := m.SignInit(sh, nil, keyHandle)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_ARGUMENTS_BAD, rv,
			"SignInit with nil mechanism should return CKR_ARGUMENTS_BAD")
	})

	t.Run("Error_SignInitWithInvalidKeyReturnsKeyHandleInvalid", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)
		invalidKey := module.ObjectHandle(0xBADF00D)

		mech := &module.Mechanism{Type: module.CKM_SHA256_RSA_PKCS}
		rv := m.SignInit(sh, mech, invalidKey)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_KEY_HANDLE_INVALID, rv,
			"SignInit with invalid key handle should return CKR_KEY_HANDLE_INVALID")
	})

	t.Run("Error_SignInitWithInvalidSessionReturnsSessionHandleInvalid", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		invalidSession := module.SessionHandle(0xDEADBEEF)
		mech := &module.Mechanism{Type: module.CKM_SHA256_RSA_PKCS}

		rv := m.SignInit(invalidSession, mech, module.ObjectHandle(1))
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_SESSION_HANDLE_INVALID, rv,
			"SignInit with invalid session should return CKR_SESSION_HANDLE_INVALID")
	})

	t.Run("Error_DoubleSignInitReturnsOperationActive", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)
		_, keyHandle := generateRSAKeyPair(t, m, sh)

		mech := &module.Mechanism{Type: module.CKM_SHA256_RSA_PKCS}
		rv := m.SignInit(sh, mech, keyHandle)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "first SignInit should succeed")

		rv = m.SignInit(sh, mech, keyHandle)
		requireRV(t, module.CKR_OPERATION_ACTIVE, rv,
			"second SignInit on same session should return CKR_OPERATION_ACTIVE")
	})
}

// testSign verifies C_Sign (single-part signing) behavior per PKCS#11 v3.0 Section 5.11.2.
func (s *Suite) testSign(t *testing.T) {

	t.Run("Happy_SignInitThenSignReturnsSignature", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)
		_, keyHandle := generateRSAKeyPair(t, m, sh)

		mech := &module.Mechanism{Type: module.CKM_SHA256_RSA_PKCS}
		rv := m.SignInit(sh, mech, keyHandle)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "SignInit should succeed")

		data := []byte("test data to sign")
		signature, rv := m.Sign(sh, data)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "Sign should return CKR_OK")

		if len(signature) == 0 {
			t.Fatal("Sign should return a non-empty signature")
		}
	})

	t.Run("Error_SignWithoutSignInitReturnsOperationNotInitialized", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)

		data := []byte("test data to sign")
		_, rv := m.Sign(sh, data)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OPERATION_NOT_INITIALIZED, rv,
			"Sign without prior SignInit should return CKR_OPERATION_NOT_INITIALIZED")
	})

	t.Run("Error_SignWithInvalidSessionReturnsSessionHandleInvalid", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		invalidSession := module.SessionHandle(0xDEADBEEF)
		data := []byte("test data to sign")

		_, rv := m.Sign(invalidSession, data)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_SESSION_HANDLE_INVALID, rv,
			"Sign with invalid session should return CKR_SESSION_HANDLE_INVALID")
	})

	t.Run("Happy_SignClearsOperationState", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)
		_, keyHandle := generateRSAKeyPair(t, m, sh)

		mech := &module.Mechanism{Type: module.CKM_SHA256_RSA_PKCS}
		rv := m.SignInit(sh, mech, keyHandle)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "SignInit should succeed")

		data := []byte("test data to sign")
		_, rv = m.Sign(sh, data)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "first Sign should succeed")

		// A second Sign without a new SignInit must fail because the
		// operation state was cleared by the first Sign call.
		_, rv = m.Sign(sh, data)
		requireRV(t, module.CKR_OPERATION_NOT_INITIALIZED, rv,
			"second Sign without new SignInit should return CKR_OPERATION_NOT_INITIALIZED")
	})
}

// testSignUpdateFinal verifies C_SignUpdate and C_SignFinal (multi-part signing)
// behavior per PKCS#11 v3.0 Section 5.11.3 and 5.11.4.
func (s *Suite) testSignUpdateFinal(t *testing.T) {

	t.Run("Happy_MultiPartSignReturnsSignature", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)
		_, keyHandle := generateRSAKeyPair(t, m, sh)

		mech := &module.Mechanism{Type: module.CKM_SHA256_RSA_PKCS}
		rv := m.SignInit(sh, mech, keyHandle)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "SignInit should succeed")

		rv = m.SignUpdate(sh, []byte("first part "))
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "first SignUpdate should return CKR_OK")

		rv = m.SignUpdate(sh, []byte("second part"))
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "second SignUpdate should return CKR_OK")

		signature, rv := m.SignFinal(sh)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "SignFinal should return CKR_OK")

		if len(signature) == 0 {
			t.Fatal("SignFinal should return a non-empty signature")
		}
	})

	t.Run("Error_SignUpdateWithoutSignInitReturnsOperationNotInitialized", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)

		rv := m.SignUpdate(sh, []byte("data"))
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OPERATION_NOT_INITIALIZED, rv,
			"SignUpdate without prior SignInit should return CKR_OPERATION_NOT_INITIALIZED")
	})

	t.Run("Error_SignFinalWithoutSignInitReturnsOperationNotInitialized", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)

		_, rv := m.SignFinal(sh)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OPERATION_NOT_INITIALIZED, rv,
			"SignFinal without prior SignInit should return CKR_OPERATION_NOT_INITIALIZED")
	})
}

// testSignRecover verifies C_SignRecoverInit and C_SignRecover behavior
// per PKCS#11 v3.0 Section 5.11.5 and 5.11.6.
func (s *Suite) testSignRecover(t *testing.T) {

	t.Run("Happy_SignRecoverInitAndSignRecoverSucceeds", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		initTokenAndPIN(t, m)
		sh := openRWSession(t, m)
		loginAsUser(t, m, sh)
		_, keyHandle := generateRSAKeyPair(t, m, sh)

		mech := &module.Mechanism{Type: module.CKM_RSA_PKCS}
		rv := m.SignRecoverInit(sh, mech, keyHandle)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "SignRecoverInit should return CKR_OK")

		data := []byte("recoverable data")
		signature, rv := m.SignRecover(sh, data)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "SignRecover should return CKR_OK")

		if len(signature) == 0 {
			t.Fatal("SignRecover should return a non-empty signature")
		}
	})

	t.Run("Error_SignRecoverWithoutInitReturnsOperationNotInitialized", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)

		data := []byte("recoverable data")
		_, rv := m.SignRecover(sh, data)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OPERATION_NOT_INITIALIZED, rv,
			"SignRecover without prior SignRecoverInit should return CKR_OPERATION_NOT_INITIALIZED")
	})
}
