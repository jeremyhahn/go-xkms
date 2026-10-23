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
	"crypto/fips140"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
)

// tamper returns a copy of b with its first byte flipped.
//
// It is the smallest change that must make a signature or a ciphertext invalid,
// so it isolates "the token actually checked this input" from "the token
// returned CKR_OK".
func tamper(b []byte) []byte {
	out := append([]byte(nil), b...)
	out[0] ^= 0x01
	return out
}

// verifyRSAMechanism is the RSA signature mechanism the C_Verify tests sign
// and verify with. Their subject is C_Verify, not the signature encoding, so
// under fips140=only, where crypto/rsa refuses CKM_RSA_PKCS over undigested
// data (v3.2 §6.1.6), they use the approved CKM_SHA256_RSA_PKCS (§6.1.14).
// testSignRecover covers the refusal itself.
func verifyRSAMechanism() *module.Mechanism {
	if fips140.Enforced() {
		return &module.Mechanism{Type: module.CKM_SHA256_RSA_PKCS}
	}
	return &module.Mechanism{Type: module.CKM_RSA_PKCS}
}

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

		sh := openAuthenticatedRWSession(t, m)
		pubKey, _ := generateRSAKeyPair(t, m, sh)

		mech := &module.Mechanism{Type: module.CKM_RSA_PKCS}

		rv := m.VerifyInit(sh, mech, pubKey)
		requireRV(t, module.CKR_OK, rv, "VerifyInit with valid session/mechanism/key should succeed")
	})

	// PKCS#11 v3.2 §5.15.1: "C_VerifyInit can be called with pMechanism set to
	// NULL_PTR to terminate an active verification operation." A NULL mechanism is
	// therefore a cancellation request, not a malformed argument, and the module
	// answers CKR_OK whether or not an operation was active -- §5.6.5 settles the
	// latter for C_SessionCancel, which ignores a flag naming an inactive
	// operation.
	t.Run("nil_mechanism_terminates_operation", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)
		pubKey, _ := generateRSAKeyPair(t, m, sh)

		rv := m.VerifyInit(sh, nil, pubKey)
		requireRV(t, module.CKR_OK, rv,
			"VerifyInit with nil mechanism terminates the operation and returns CKR_OK")
	})

	t.Run("invalid_key_handle_fails", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)
		invalidKey := module.ObjectHandle(0xBADF00D)

		mech := &module.Mechanism{Type: module.CKM_RSA_PKCS}

		rv := m.VerifyInit(sh, mech, invalidKey)
		requireRV(t, module.CKR_KEY_HANDLE_INVALID, rv,
			"VerifyInit with invalid key handle should return CKR_KEY_HANDLE_INVALID")
	})

	t.Run("invalid_session_handle_fails", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		invalidSession := module.SessionHandle(0xDEADBEEF)
		mech := &module.Mechanism{Type: module.CKM_RSA_PKCS}

		rv := m.VerifyInit(invalidSession, mech, module.ObjectHandle(1))
		requireRV(t, module.CKR_SESSION_HANDLE_INVALID, rv,
			"VerifyInit with invalid session should return CKR_SESSION_HANDLE_INVALID")
	})

	t.Run("double_verify_init_returns_operation_active", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)
		pubKey, _ := generateRSAKeyPair(t, m, sh)

		mech := &module.Mechanism{Type: module.CKM_RSA_PKCS}

		rv := m.VerifyInit(sh, mech, pubKey)
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

		sh := openAuthenticatedRWSession(t, m)
		pubKey, privKey := generateRSAKeyPair(t, m, sh)

		data := []byte("test-data")
		mech := verifyRSAMechanism()

		// Sign the data first so we have a valid signature to verify
		rv := m.SignInit(sh, mech, privKey)
		requireRV(t, module.CKR_OK, rv, "SignInit should succeed")

		signature, rv := m.Sign(sh, data)
		requireRV(t, module.CKR_OK, rv, "Sign should succeed")

		// Verify the signature
		rv = m.VerifyInit(sh, mech, pubKey)
		requireRV(t, module.CKR_OK, rv, "VerifyInit should succeed")

		rv = m.Verify(sh, data, signature)
		requireRV(t, module.CKR_OK, rv,
			"Verify with valid signature should return CKR_OK")
	})

	// The three tests below are the ones that can fail. Without them a
	// C_Verify implemented as "return CKR_OK" passes every other test in this
	// file: they are the only place the suite ever asks the token to REJECT
	// something. PKCS#11 v3.2 §5.15.2 names CKR_SIGNATURE_INVALID as the code
	// for a signature that does not check out.

	t.Run("verify_with_tampered_signature_returns_signature_invalid", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)
		pubKey, privKey := generateRSAKeyPair(t, m, sh)

		data := []byte("test-data")
		mech := verifyRSAMechanism()

		rv := m.SignInit(sh, mech, privKey)
		requireRV(t, module.CKR_OK, rv, "SignInit should succeed")

		signature, rv := m.Sign(sh, data)
		requireRV(t, module.CKR_OK, rv, "Sign should succeed")
		requireRV(t, module.CKR_OK, m.FinishOperation(sh, module.OperationSign),
			"FinishOperation should terminate the signing operation")

		rv = m.VerifyInit(sh, mech, pubKey)
		requireRV(t, module.CKR_OK, rv, "VerifyInit should succeed")

		rv = m.Verify(sh, data, tamper(signature))
		requireRV(t, module.CKR_SIGNATURE_INVALID, rv,
			"Verify of a signature with one flipped bit should return CKR_SIGNATURE_INVALID")
	})

	t.Run("verify_with_tampered_data_returns_signature_invalid", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)
		pubKey, privKey := generateRSAKeyPair(t, m, sh)

		data := []byte("test-data")
		mech := verifyRSAMechanism()

		rv := m.SignInit(sh, mech, privKey)
		requireRV(t, module.CKR_OK, rv, "SignInit should succeed")

		signature, rv := m.Sign(sh, data)
		requireRV(t, module.CKR_OK, rv, "Sign should succeed")
		requireRV(t, module.CKR_OK, m.FinishOperation(sh, module.OperationSign),
			"FinishOperation should terminate the signing operation")

		rv = m.VerifyInit(sh, mech, pubKey)
		requireRV(t, module.CKR_OK, rv, "VerifyInit should succeed")

		// A signature binds the message. Verifying it against different data
		// must fail, or the signature proves nothing about what was signed.
		rv = m.Verify(sh, tamper(data), signature)
		requireRV(t, module.CKR_SIGNATURE_INVALID, rv,
			"Verify of a valid signature against modified data should return CKR_SIGNATURE_INVALID")
	})

	t.Run("verify_with_a_different_key_returns_signature_invalid", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)
		_, privKey := generateRSAKeyPair(t, m, sh)
		otherPub, _ := generateRSAKeyPair(t, m, sh)

		data := []byte("test-data")
		mech := verifyRSAMechanism()

		rv := m.SignInit(sh, mech, privKey)
		requireRV(t, module.CKR_OK, rv, "SignInit should succeed")

		signature, rv := m.Sign(sh, data)
		requireRV(t, module.CKR_OK, rv, "Sign should succeed")
		requireRV(t, module.CKR_OK, m.FinishOperation(sh, module.OperationSign),
			"FinishOperation should terminate the signing operation")

		// A signature must only check out under the key that produced it. If
		// it verifies under an unrelated key pair the token is not binding the
		// verification to the key C_VerifyInit named.
		rv = m.VerifyInit(sh, mech, otherPub)
		requireRV(t, module.CKR_OK, rv, "VerifyInit with the other public key should succeed")

		rv = m.Verify(sh, data, signature)
		requireRV(t, module.CKR_SIGNATURE_INVALID, rv,
			"Verify under an unrelated public key should return CKR_SIGNATURE_INVALID")
	})

	t.Run("verify_without_init_returns_operation_not_initialized", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)

		rv := m.Verify(sh, []byte("test-data"), []byte("mock-signature"))
		requireRV(t, module.CKR_OPERATION_NOT_INITIALIZED, rv,
			"Verify without VerifyInit should return CKR_OPERATION_NOT_INITIALIZED")
	})

	t.Run("verify_invalid_session_returns_session_handle_invalid", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		invalidSession := module.SessionHandle(0xDEADBEEF)

		rv := m.Verify(invalidSession, []byte("test-data"), []byte("mock-signature"))
		requireRV(t, module.CKR_SESSION_HANDLE_INVALID, rv,
			"Verify with invalid session should return CKR_SESSION_HANDLE_INVALID")
	})

	t.Run("verify_clears_operation_state", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)
		pubKey, privKey := generateRSAKeyPair(t, m, sh)

		data := []byte("test-data")
		mech := verifyRSAMechanism()

		// Sign to get a valid signature
		rv := m.SignInit(sh, mech, privKey)
		requireRV(t, module.CKR_OK, rv, "SignInit should succeed")

		signature, rv := m.Sign(sh, data)
		requireRV(t, module.CKR_OK, rv, "Sign should succeed")

		// First Verify should succeed and clear the operation
		rv = m.VerifyInit(sh, mech, pubKey)
		requireRV(t, module.CKR_OK, rv, "VerifyInit should succeed")

		rv = m.Verify(sh, data, signature)
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

		sh := openAuthenticatedRWSession(t, m)
		pubKey, privKey := generateRSAKeyPair(t, m, sh)

		mech := &module.Mechanism{Type: module.CKM_SHA256_RSA_PKCS}

		// Sign the full data first to get a valid signature
		rv := m.SignInit(sh, mech, privKey)
		requireRV(t, module.CKR_OK, rv, "SignInit should succeed")

		rv = m.SignUpdate(sh, []byte("test-"))
		requireRV(t, module.CKR_OK, rv, "first SignUpdate should succeed")

		rv = m.SignUpdate(sh, []byte("data"))
		requireRV(t, module.CKR_OK, rv, "second SignUpdate should succeed")

		signature, rv := m.SignFinal(sh)
		requireRV(t, module.CKR_OK, rv, "SignFinal should succeed")

		// Verify using multi-part VerifyUpdate/VerifyFinal with the real signature
		rv = m.VerifyInit(sh, mech, pubKey)
		requireRV(t, module.CKR_OK, rv, "VerifyInit for multi-part should succeed")

		rv = m.VerifyUpdate(sh, []byte("test-"))
		requireRV(t, module.CKR_OK, rv, "first VerifyUpdate should succeed")

		rv = m.VerifyUpdate(sh, []byte("data"))
		requireRV(t, module.CKR_OK, rv, "second VerifyUpdate should succeed")

		rv = m.VerifyFinal(sh, signature)
		requireRV(t, module.CKR_OK, rv,
			"VerifyFinal should succeed after VerifyUpdate calls")
	})

	t.Run("multi_part_verify_with_tampered_signature_returns_signature_invalid", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)
		pubKey, privKey := generateRSAKeyPair(t, m, sh)

		mech := &module.Mechanism{Type: module.CKM_SHA256_RSA_PKCS}

		rv := m.SignInit(sh, mech, privKey)
		requireRV(t, module.CKR_OK, rv, "SignInit should succeed")
		rv = m.SignUpdate(sh, []byte("test-"))
		requireRV(t, module.CKR_OK, rv, "first SignUpdate should succeed")
		rv = m.SignUpdate(sh, []byte("data"))
		requireRV(t, module.CKR_OK, rv, "second SignUpdate should succeed")
		signature, rv := m.SignFinal(sh)
		requireRV(t, module.CKR_OK, rv, "SignFinal should succeed")
		requireRV(t, module.CKR_OK, m.FinishOperation(sh, module.OperationSign),
			"FinishOperation should terminate the signing operation")

		rv = m.VerifyInit(sh, mech, pubKey)
		requireRV(t, module.CKR_OK, rv, "VerifyInit for multi-part should succeed")
		rv = m.VerifyUpdate(sh, []byte("test-"))
		requireRV(t, module.CKR_OK, rv, "first VerifyUpdate should succeed")
		rv = m.VerifyUpdate(sh, []byte("data"))
		requireRV(t, module.CKR_OK, rv, "second VerifyUpdate should succeed")

		rv = m.VerifyFinal(sh, tamper(signature))
		requireRV(t, module.CKR_SIGNATURE_INVALID, rv,
			"VerifyFinal with a corrupted signature should return CKR_SIGNATURE_INVALID")
	})

	t.Run("multi_part_verify_with_a_dropped_part_returns_signature_invalid", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)
		pubKey, privKey := generateRSAKeyPair(t, m, sh)

		mech := &module.Mechanism{Type: module.CKM_SHA256_RSA_PKCS}

		rv := m.SignInit(sh, mech, privKey)
		requireRV(t, module.CKR_OK, rv, "SignInit should succeed")
		rv = m.SignUpdate(sh, []byte("test-"))
		requireRV(t, module.CKR_OK, rv, "first SignUpdate should succeed")
		rv = m.SignUpdate(sh, []byte("data"))
		requireRV(t, module.CKR_OK, rv, "second SignUpdate should succeed")
		signature, rv := m.SignFinal(sh)
		requireRV(t, module.CKR_OK, rv, "SignFinal should succeed")
		requireRV(t, module.CKR_OK, m.FinishOperation(sh, module.OperationSign),
			"FinishOperation should terminate the signing operation")

		// Verify over only the first part. The signature covers both, so this
		// must be rejected; a C_VerifyUpdate chain that discards what it was
		// given and a C_VerifyFinal that ignores the buffer both accept it.
		rv = m.VerifyInit(sh, mech, pubKey)
		requireRV(t, module.CKR_OK, rv, "VerifyInit for multi-part should succeed")
		rv = m.VerifyUpdate(sh, []byte("test-"))
		requireRV(t, module.CKR_OK, rv, "VerifyUpdate should succeed")

		rv = m.VerifyFinal(sh, signature)
		requireRV(t, module.CKR_SIGNATURE_INVALID, rv,
			"VerifyFinal over a truncated message should return CKR_SIGNATURE_INVALID")
	})

	t.Run("verify_update_without_init_returns_operation_not_initialized", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)

		rv := m.VerifyUpdate(sh, []byte("test-data"))
		requireRV(t, module.CKR_OPERATION_NOT_INITIALIZED, rv,
			"VerifyUpdate without VerifyInit should return CKR_OPERATION_NOT_INITIALIZED")
	})

	t.Run("verify_final_without_init_returns_operation_not_initialized", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)

		rv := m.VerifyFinal(sh, []byte("mock-signature"))
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
		sh := openAuthenticatedRWSession(t, m)
		loginAsUser(t, m, sh)
		pubKey, privKey := generateRSAKeyPair(t, m, sh)

		mech := &module.Mechanism{Type: module.CKM_RSA_PKCS}

		// Sign recoverable data first so we have a real signature
		rv := m.SignRecoverInit(sh, mech, privKey)
		requireRV(t, module.CKR_OK, rv, "SignRecoverInit should succeed")

		data := []byte("recoverable data")
		signature, rv := m.SignRecover(sh, data)
		if !outsideFIPSAfterRefusal(t, module.CKR_MECHANISM_INVALID, rv,
			"fips140=only refuses raw PKCS#1 v1.5 over undigested data") {
			return
		}
		requireRV(t, module.CKR_OK, rv, "SignRecover should succeed")

		rv = m.VerifyRecoverInit(sh, mech, pubKey)
		requireRV(t, module.CKR_OK, rv, "VerifyRecoverInit should succeed")

		// Recovering the signed data is the entire purpose of C_VerifyRecover
		// (v3.2 §5.15.6): pData receives "the recovered data". Discarding it
		// left the one thing this function exists to do unchecked, and
		// tolerating CKR_KEY_FUNCTION_NOT_PERMITTED alongside CKR_OK meant a
		// token that simply refused the operation passed as well.
		recovered, rv := m.VerifyRecover(sh, signature)
		requireRV(t, module.CKR_OK, rv, "VerifyRecover should return CKR_OK")

		if !bytes.Equal(recovered, data) {
			t.Fatalf("VerifyRecover did not recover the signed data\n got %q\nwant %q",
				recovered, data)
		}
	})

	t.Run("verify_recover_with_tampered_signature_fails", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		initTokenAndPIN(t, m)
		sh := openAuthenticatedRWSession(t, m)
		loginAsUser(t, m, sh)
		pubKey, privKey := generateRSAKeyPair(t, m, sh)

		mech := &module.Mechanism{Type: module.CKM_RSA_PKCS}

		rv := m.SignRecoverInit(sh, mech, privKey)
		requireRV(t, module.CKR_OK, rv, "SignRecoverInit should succeed")

		data := []byte("recoverable data")
		signature, rv := m.SignRecover(sh, data)
		if !outsideFIPSAfterRefusal(t, module.CKR_MECHANISM_INVALID, rv,
			"fips140=only refuses raw PKCS#1 v1.5 over undigested data") {
			return
		}
		requireRV(t, module.CKR_OK, rv, "SignRecover should succeed")
		requireRV(t, module.CKR_OK, m.FinishOperation(sh, module.OperationSign),
			"FinishOperation should terminate the sign-recover operation")

		rv = m.VerifyRecoverInit(sh, mech, pubKey)
		requireRV(t, module.CKR_OK, rv, "VerifyRecoverInit should succeed")

		// Flipping a bit destroys the PKCS#1 v1.5 block structure, so the
		// recovery must fail rather than hand back whatever fell out of the
		// modular exponentiation.
		recovered, rv := m.VerifyRecover(sh, tamper(signature))
		if rv == module.CKR_OK {
			t.Fatalf("VerifyRecover accepted a corrupted signature and returned %q", recovered)
		}
		if len(recovered) != 0 {
			t.Fatalf("VerifyRecover returned %d bytes of unverified data alongside %s",
				len(recovered), rv)
		}
	})

	t.Run("verify_recover_without_init_returns_operation_not_initialized", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)

		_, rv := m.VerifyRecover(sh, []byte("mock-signature"))
		requireRV(t, module.CKR_OPERATION_NOT_INITIALIZED, rv,
			"VerifyRecover without VerifyRecoverInit should return CKR_OPERATION_NOT_INITIALIZED")
	})
}
