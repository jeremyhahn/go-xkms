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

		sh := openAuthenticatedRWSession(t, m)
		_, keyHandle := generateRSAKeyPair(t, m, sh)

		mech := &module.Mechanism{Type: module.CKM_SHA256_RSA_PKCS}
		rv := m.SignInit(sh, mech, keyHandle)
		requireRV(t, module.CKR_OK, rv, "SignInit with valid session, mechanism, and key should return CKR_OK")
	})

	// PKCS#11 v3.2 §5.13.1: "C_SignInit can be called with pMechanism set to
	// NULL_PTR to terminate an active signature operation." A NULL mechanism is
	// therefore a cancellation request, not a malformed argument, and the module
	// answers CKR_OK whether or not an operation was active -- §5.6.5 settles the
	// latter for C_SessionCancel, which ignores a flag naming an inactive
	// operation.
	t.Run("Error_SignInitWithNilMechanismTerminatesOperation", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)
		_, keyHandle := generateRSAKeyPair(t, m, sh)

		rv := m.SignInit(sh, nil, keyHandle)
		requireRV(t, module.CKR_OK, rv,
			"SignInit with nil mechanism terminates the operation and returns CKR_OK")
	})

	t.Run("Error_SignInitWithInvalidKeyReturnsKeyHandleInvalid", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)
		invalidKey := module.ObjectHandle(0xBADF00D)

		mech := &module.Mechanism{Type: module.CKM_SHA256_RSA_PKCS}
		rv := m.SignInit(sh, mech, invalidKey)
		requireRV(t, module.CKR_KEY_HANDLE_INVALID, rv,
			"SignInit with invalid key handle should return CKR_KEY_HANDLE_INVALID")
	})

	t.Run("Error_SignInitWithInvalidSessionReturnsSessionHandleInvalid", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		invalidSession := module.SessionHandle(0xDEADBEEF)
		mech := &module.Mechanism{Type: module.CKM_SHA256_RSA_PKCS}

		rv := m.SignInit(invalidSession, mech, module.ObjectHandle(1))
		requireRV(t, module.CKR_SESSION_HANDLE_INVALID, rv,
			"SignInit with invalid session should return CKR_SESSION_HANDLE_INVALID")
	})

	t.Run("Error_DoubleSignInitReturnsOperationActive", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)
		_, keyHandle := generateRSAKeyPair(t, m, sh)

		mech := &module.Mechanism{Type: module.CKM_SHA256_RSA_PKCS}
		rv := m.SignInit(sh, mech, keyHandle)
		requireRV(t, module.CKR_OK, rv, "first SignInit should succeed")

		rv = m.SignInit(sh, mech, keyHandle)
		requireRV(t, module.CKR_OPERATION_ACTIVE, rv,
			"second SignInit on same session should return CKR_OPERATION_ACTIVE")
	})
}

// testSign verifies C_Sign (single-part signing) behavior per PKCS#11 v3.0 Section 5.11.2.
func (s *Suite) testSign(t *testing.T) {

	t.Run("Happy_SignInitThenSignProducesAVerifiableSignature", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)
		// The public handle is kept, not discarded: without it there is no way
		// to check the signature outside the module, and a C_Sign returning a
		// constant 256 bytes satisfies every length-only assertion.
		pubHandle, keyHandle := generateRSAKeyPair(t, m, sh)

		mech := &module.Mechanism{Type: module.CKM_SHA256_RSA_PKCS}
		rv := m.SignInit(sh, mech, keyHandle)
		requireRV(t, module.CKR_OK, rv, "SignInit should succeed")

		data := []byte("test data to sign")
		signature, rv := m.Sign(sh, data)
		requireRV(t, module.CKR_OK, rv, "Sign should return CKR_OK")

		// CKM_SHA256_RSA_PKCS is RSASSA-PKCS1-v1_5 over a SHA-256 digest
		// (v3.2 §6.1.7), so crypto/rsa can check it against the modulus and
		// exponent the token published on the public key object.
		pub := rsaPublicKeyFor(t, m, sh, pubHandle)
		assertRSASignature(t, pub, crypto.SHA256, data, signature)
	})

	t.Run("Error_SignWithDataUnderADifferentKeyDoesNotVerify", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)
		_, keyHandle := generateRSAKeyPair(t, m, sh)
		otherPub, _ := generateRSAKeyPair(t, m, sh)

		mech := &module.Mechanism{Type: module.CKM_SHA256_RSA_PKCS}
		rv := m.SignInit(sh, mech, keyHandle)
		requireRV(t, module.CKR_OK, rv, "SignInit should succeed")

		data := []byte("test data to sign")
		signature, rv := m.Sign(sh, data)
		requireRV(t, module.CKR_OK, rv, "Sign should return CKR_OK")

		// The oracle must be able to say no, or "it verified" means nothing.
		// A C_SignInit that ignored its key handle would let this pass.
		pub := rsaPublicKeyFor(t, m, sh, otherPub)
		if err := verifyPKCS1v15(pub, crypto.SHA256, data, signature); err == nil {
			t.Fatal("the signature verified under an unrelated public key; " +
				"C_SignInit is not binding the operation to its key handle")
		}
	})

	t.Run("Error_SignWithoutSignInitReturnsOperationNotInitialized", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)

		data := []byte("test data to sign")
		_, rv := m.Sign(sh, data)
		requireRV(t, module.CKR_OPERATION_NOT_INITIALIZED, rv,
			"Sign without prior SignInit should return CKR_OPERATION_NOT_INITIALIZED")
	})

	t.Run("Error_SignWithInvalidSessionReturnsSessionHandleInvalid", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		invalidSession := module.SessionHandle(0xDEADBEEF)
		data := []byte("test data to sign")

		_, rv := m.Sign(invalidSession, data)
		requireRV(t, module.CKR_SESSION_HANDLE_INVALID, rv,
			"Sign with invalid session should return CKR_SESSION_HANDLE_INVALID")
	})

	t.Run("Happy_SignClearsOperationState", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)
		_, keyHandle := generateRSAKeyPair(t, m, sh)

		mech := &module.Mechanism{Type: module.CKM_SHA256_RSA_PKCS}
		rv := m.SignInit(sh, mech, keyHandle)
		requireRV(t, module.CKR_OK, rv, "SignInit should succeed")

		data := []byte("test data to sign")
		first, rv := m.Sign(sh, data)
		requireRV(t, module.CKR_OK, rv, "first Sign should succeed")

		// The operation stays active until the caller confirms it received
		// the signature, so the two-call buffer convention can retry it
		// (v3.2 5.2). A repeated Sign therefore returns the same bytes
		// without re-signing; only FinishOperation terminates it.
		second, rv := m.Sign(sh, data)
		requireRV(t, module.CKR_OK, rv, "repeated Sign should return the cached signature")
		if !bytes.Equal(first, second) {
			t.Fatalf("repeated Sign returned different bytes: %x vs %x", first, second)
		}

		requireRV(t, module.CKR_OK, m.FinishOperation(sh, module.OperationSign),
			"FinishOperation should terminate the signing operation")

		_, rv = m.Sign(sh, data)
		requireRV(t, module.CKR_OPERATION_NOT_INITIALIZED, rv,
			"Sign after FinishOperation should return CKR_OPERATION_NOT_INITIALIZED")
	})
}

// testSignUpdateFinal verifies C_SignUpdate and C_SignFinal (multi-part signing)
// behavior per PKCS#11 v3.0 Section 5.11.3 and 5.11.4.
func (s *Suite) testSignUpdateFinal(t *testing.T) {

	t.Run("Happy_MultiPartSignCoversEveryPart", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)
		pubHandle, keyHandle := generateRSAKeyPair(t, m, sh)

		mech := &module.Mechanism{Type: module.CKM_SHA256_RSA_PKCS}
		rv := m.SignInit(sh, mech, keyHandle)
		requireRV(t, module.CKR_OK, rv, "SignInit should succeed")

		partOne := []byte("first part ")
		partTwo := []byte("second part")

		rv = m.SignUpdate(sh, partOne)
		requireRV(t, module.CKR_OK, rv, "first SignUpdate should return CKR_OK")

		rv = m.SignUpdate(sh, partTwo)
		requireRV(t, module.CKR_OK, rv, "second SignUpdate should return CKR_OK")

		signature, rv := m.SignFinal(sh)
		requireRV(t, module.CKR_OK, rv, "SignFinal should return CKR_OK")

		// The signature must cover the concatenation of every part
		// (v3.2 §5.13.3). A non-empty check cannot see a dropped, duplicated
		// or reordered C_SignUpdate; verifying against "first part second
		// part" outside the module can.
		full := make([]byte, 0, len(partOne)+len(partTwo))
		full = append(full, partOne...)
		full = append(full, partTwo...)

		pub := rsaPublicKeyFor(t, m, sh, pubHandle)
		assertRSASignature(t, pub, crypto.SHA256, full, signature)
	})

	t.Run("Error_SignUpdateWithoutSignInitReturnsOperationNotInitialized", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)

		rv := m.SignUpdate(sh, []byte("data"))
		requireRV(t, module.CKR_OPERATION_NOT_INITIALIZED, rv,
			"SignUpdate without prior SignInit should return CKR_OPERATION_NOT_INITIALIZED")
	})

	t.Run("Error_SignFinalWithoutSignInitReturnsOperationNotInitialized", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)

		_, rv := m.SignFinal(sh)
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
		sh := openAuthenticatedRWSession(t, m)
		loginAsUser(t, m, sh)
		pubHandle, keyHandle := generateRSAKeyPair(t, m, sh)

		mech := &module.Mechanism{Type: module.CKM_RSA_PKCS}
		rv := m.SignRecoverInit(sh, mech, keyHandle)
		requireRV(t, module.CKR_OK, rv, "SignRecoverInit should return CKR_OK")

		data := []byte("recoverable data")
		signature, rv := m.SignRecover(sh, data)
		if !outsideFIPSAfterRefusal(t, module.CKR_MECHANISM_INVALID, rv,
			"fips140=only refuses raw PKCS#1 v1.5 over undigested data") {
			return
		}
		requireRV(t, module.CKR_OK, rv, "SignRecover should return CKR_OK")

		// CKM_RSA_PKCS carries the data itself inside the PKCS#1 v1.5 block
		// with no digest of its own (v3.2 §6.1.3), which is what makes the
		// data recoverable. Verifying with crypto.Hash(0) checks exactly that
		// encoding: if the token hashed the data first, the block holds a
		// DigestInfo instead and nothing can be recovered from it.
		pub := rsaPublicKeyFor(t, m, sh, pubHandle)
		assertRSASignature(t, pub, crypto.Hash(0), data, signature)
	})

	t.Run("Error_SignRecoverWithoutInitReturnsOperationNotInitialized", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)

		data := []byte("recoverable data")
		_, rv := m.SignRecover(sh, data)
		requireRV(t, module.CKR_OPERATION_NOT_INITIALIZED, rv,
			"SignRecover without prior SignRecoverInit should return CKR_OPERATION_NOT_INITIALIZED")
	})
}
