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
	"crypto/sha256"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
)

// suiteSecretKeyValue is the CKA_VALUE createSecretKeyObject plants on its test
// key. C_DigestKey digests exactly these bytes (v3.2 §5.12.4), which makes the
// expected digest computable outside the module.
var suiteSecretKeyValue = []byte("0123456789ABCDEF")

// assertSHA256 checks a digest against crypto/sha256.
//
// Length alone is not a check: a C_Digest that returns 32 zero bytes, or the
// digest of the previous message, satisfies it. Comparing against the standard
// library is what makes the digest tests able to fail.
func assertSHA256(t *testing.T, digest, data []byte, context string) {
	t.Helper()

	want := sha256.Sum256(data)
	if !bytes.Equal(digest, want[:]) {
		t.Fatalf("%s: SHA-256 digest is %x, want %x (the digest of %q)",
			context, digest, want[:], data)
	}
}

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

		sh := openAuthenticatedRWSession(t, m)

		mech := &module.Mechanism{Type: module.CKM_SHA256}
		rv := m.DigestInit(sh, mech)
		requireRV(t, module.CKR_OK, rv, "DigestInit with CKM_SHA256 should succeed")

		// Consume the active operation so session state is clean
		_, rv = m.Digest(sh, []byte("cleanup"))
		requireRV(t, module.CKR_OK, rv, "Digest cleanup should succeed")
	})

	// PKCS#11 v3.2 §5.12.1: "C_DigestInit can be called with pMechanism set to
	// NULL_PTR to terminate an active message digesting operation." A NULL mechanism is
	// therefore a cancellation request, not a malformed argument, and the module
	// answers CKR_OK whether or not an operation was active -- §5.6.5 settles the
	// latter for C_SessionCancel, which ignores a flag naming an inactive
	// operation.
	t.Run("nil_mechanism_terminates_operation", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)

		rv := m.DigestInit(sh, nil)
		requireRV(t, module.CKR_OK, rv,
			"DigestInit with nil mechanism terminates the operation and returns CKR_OK")
	})

	t.Run("invalid_session_returns_session_handle_invalid", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		invalidSession := module.SessionHandle(0xDEADBEEF)
		mech := &module.Mechanism{Type: module.CKM_SHA256}

		rv := m.DigestInit(invalidSession, mech)
		requireRV(t, module.CKR_SESSION_HANDLE_INVALID, rv,
			"DigestInit with invalid session should return CKR_SESSION_HANDLE_INVALID")
	})

	t.Run("double_init_returns_operation_active", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)

		mech := &module.Mechanism{Type: module.CKM_SHA256}
		rv := m.DigestInit(sh, mech)
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

	t.Run("digest_SHA256_matches_the_known_answer", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)

		mech := &module.Mechanism{Type: module.CKM_SHA256}
		rv := m.DigestInit(sh, mech)
		requireRV(t, module.CKR_OK, rv, "DigestInit should succeed")

		data := []byte("The quick brown fox jumps over the lazy dog")
		digest, rv := m.Digest(sh, data)
		requireRV(t, module.CKR_OK, rv, "Digest should return CKR_OK")

		assertSHA256(t, digest, data, "C_Digest with CKM_SHA256")
	})

	t.Run("digest_without_init_returns_operation_not_initialized", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)

		_, rv := m.Digest(sh, []byte("no-init"))
		requireRV(t, module.CKR_OPERATION_NOT_INITIALIZED, rv,
			"Digest without DigestInit should return CKR_OPERATION_NOT_INITIALIZED")
	})

	t.Run("digest_clears_operation_state", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)

		mech := &module.Mechanism{Type: module.CKM_SHA256}
		rv := m.DigestInit(sh, mech)
		requireRV(t, module.CKR_OK, rv, "DigestInit should succeed")

		firstData := []byte("first-digest")
		first, rv := m.Digest(sh, firstData)
		requireRV(t, module.CKR_OK, rv, "first Digest should succeed")
		assertSHA256(t, first, firstData, "first C_Digest")

		// The operation stays active until the caller confirms it received
		// the digest, so the two-call buffer convention can retry it
		// (v3.2 5.2). Feeding different data on the retry is what tells a
		// cache hit apart from a re-run: the second call must still return the
		// digest of the FIRST message. Discarding the output, as this test
		// used to, could not tell the two apart at all.
		second, rv := m.Digest(sh, []byte("second-digest"))
		requireRV(t, module.CKR_OK, rv, "repeated Digest should return the cached digest")
		if !bytes.Equal(first, second) {
			t.Fatalf("the retry re-ran the digest over the new data instead of returning "+
				"the buffered result: got %x, want %x", second, first)
		}

		requireRV(t, module.CKR_OK, m.FinishOperation(sh, module.OperationDigest),
			"FinishOperation should terminate the digest operation")

		_, rv = m.Digest(sh, []byte("second-digest"))
		requireRV(t, module.CKR_OPERATION_NOT_INITIALIZED, rv,
			"Digest after FinishOperation should return CKR_OPERATION_NOT_INITIALIZED")
	})
}

// testDigestUpdateFinal verifies multi-part C_DigestUpdate and C_DigestFinal
// behavior per PKCS#11 v3.0 Section 5.10.3 and 5.10.5.
func (s *Suite) testDigestUpdateFinal(t *testing.T) {

	t.Run("multi_part_digest_succeeds", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)

		mech := &module.Mechanism{Type: module.CKM_SHA256}
		rv := m.DigestInit(sh, mech)
		requireRV(t, module.CKR_OK, rv, "DigestInit should succeed")

		partOne := []byte("part one ")
		partTwo := []byte("part two")

		rv = m.DigestUpdate(sh, partOne)
		requireRV(t, module.CKR_OK, rv, "first DigestUpdate should succeed")

		rv = m.DigestUpdate(sh, partTwo)
		requireRV(t, module.CKR_OK, rv, "second DigestUpdate should succeed")

		digest, rv := m.DigestFinal(sh)
		requireRV(t, module.CKR_OK, rv, "DigestFinal should return CKR_OK")

		// The multi-part digest must equal the digest of the concatenation
		// (v3.2 §5.12.3). Asserting only the 32-byte length cannot see a
		// dropped, duplicated or reordered C_DigestUpdate.
		assertSHA256(t, digest, append(append([]byte{}, partOne...), partTwo...),
			"C_DigestUpdate x2 + C_DigestFinal")
	})

	t.Run("digest_update_without_init_returns_operation_not_initialized", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)

		rv := m.DigestUpdate(sh, []byte("no-init"))
		requireRV(t, module.CKR_OPERATION_NOT_INITIALIZED, rv,
			"DigestUpdate without DigestInit should return CKR_OPERATION_NOT_INITIALIZED")
	})

	t.Run("digest_final_without_init_returns_operation_not_initialized", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)

		_, rv := m.DigestFinal(sh)
		requireRV(t, module.CKR_OPERATION_NOT_INITIALIZED, rv,
			"DigestFinal without DigestInit should return CKR_OPERATION_NOT_INITIALIZED")
	})
}

// testDigestKey verifies C_DigestKey behavior per PKCS#11 v3.0 Section 5.10.4.
func (s *Suite) testDigestKey(t *testing.T) {

	t.Run("digest_key_with_valid_key_succeeds", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)
		// DigestKey needs CKA_VALUE populated on the object to digest key material
		keyHandle := createSecretKeyObject(t, m, sh)

		mech := &module.Mechanism{Type: module.CKM_SHA256}
		rv := m.DigestInit(sh, mech)
		requireRV(t, module.CKR_OK, rv, "DigestInit should succeed")

		rv = m.DigestKey(sh, keyHandle)
		requireRV(t, module.CKR_OK, rv, "DigestKey with valid key should succeed")

		digest, rv := m.DigestFinal(sh)
		requireRV(t, module.CKR_OK, rv, "DigestFinal after DigestKey should succeed")

		// C_DigestKey digests "the value of the secret key" (v3.2 §5.12.4),
		// and createSecretKeyObject planted exactly suiteSecretKeyValue as
		// CKA_VALUE. Anything else means the token digested the wrong bytes --
		// the key's label, its handle, or nothing at all -- which a non-empty
		// check cannot see.
		assertSHA256(t, digest, suiteSecretKeyValue, "C_DigestKey + C_DigestFinal")
	})

	t.Run("digest_key_incorporates_the_key_into_a_running_digest", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)
		keyHandle := createSecretKeyObject(t, m, sh)

		mech := &module.Mechanism{Type: module.CKM_SHA256}
		rv := m.DigestInit(sh, mech)
		requireRV(t, module.CKR_OK, rv, "DigestInit should succeed")

		prefix := []byte("prefix-")
		rv = m.DigestUpdate(sh, prefix)
		requireRV(t, module.CKR_OK, rv, "DigestUpdate before DigestKey should succeed")

		rv = m.DigestKey(sh, keyHandle)
		requireRV(t, module.CKR_OK, rv, "DigestKey should succeed")

		suffix := []byte("-suffix")
		rv = m.DigestUpdate(sh, suffix)
		requireRV(t, module.CKR_OK, rv, "DigestUpdate after DigestKey should succeed")

		digest, rv := m.DigestFinal(sh)
		requireRV(t, module.CKR_OK, rv, "DigestFinal should succeed")

		// C_DigestKey is an update, not a reset: the key's value must land in
		// the stream between the two data parts. A DigestKey that restarted
		// the digest, or that appended the key at the end, produces a
		// different answer here.
		expected := make([]byte, 0, len(prefix)+len(suiteSecretKeyValue)+len(suffix))
		expected = append(expected, prefix...)
		expected = append(expected, suiteSecretKeyValue...)
		expected = append(expected, suffix...)
		assertSHA256(t, digest, expected, "C_DigestUpdate + C_DigestKey + C_DigestUpdate")
	})

	t.Run("digest_key_without_init_returns_operation_not_initialized", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)
		keyHandle := generateSecretKey(t, m, sh)

		rv := m.DigestKey(sh, keyHandle)
		requireRV(t, module.CKR_OPERATION_NOT_INITIALIZED, rv,
			"DigestKey without DigestInit should return CKR_OPERATION_NOT_INITIALIZED")
	})

	t.Run("digest_key_with_invalid_key_handle_returns_key_handle_invalid", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)
		invalidKey := module.ObjectHandle(0xBADF00D)

		mech := &module.Mechanism{Type: module.CKM_SHA256}
		rv := m.DigestInit(sh, mech)
		requireRV(t, module.CKR_OK, rv, "DigestInit should succeed")

		// C_DigestKey's return-value list in v3.2 §5.12.4 contains
		// CKR_KEY_HANDLE_INVALID and does not contain
		// CKR_OBJECT_HANDLE_INVALID, so there is one correct answer here.
		// Accepting either let a token report the wrong one indefinitely.
		rv = m.DigestKey(sh, invalidKey)
		requireRV(t, module.CKR_KEY_HANDLE_INVALID, rv,
			"DigestKey with an invalid key handle should return CKR_KEY_HANDLE_INVALID")
	})
}
