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
	"crypto/sha256"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
)

// RunDualFunctionTests verifies Section 5.17 Dual-Function Cryptographic
// Operations of the PKCS#11 v3.2 spec.
//
// The point of these four functions is that TWO cryptographic operations run
// over the SAME data in one pass, so the data need not cross the token boundary
// twice. A test that only asserts CKR_OK cannot distinguish that from an
// implementation that quietly runs one of the two and drops the other, which is
// precisely the failure mode. Every test below therefore checks the output of
// each half against an oracle computed in the test with crypto/sha256,
// crypto/cipher and crypto/rsa -- never against the module's own inverse
// operation, which a module that consistently agrees with itself would pass.
//
// The contracts §5.17 states, and which the tests here pin:
//
//   - §5.17.1 C_DigestEncryptUpdate: "precisely the same input is passed to
//     both the active digesting operation and the active encryption operation".
//   - §5.17.2 C_DecryptDigestUpdate: "the input passed to the active digesting
//     operation is the output of the active decryption operation", and the
//     plaintext that emerges later from C_DecryptFinal is explicitly NOT
//     digested -- "these 2 bytes of plaintext are not passed on to be
//     digested". The application must feed them itself with C_DigestUpdate.
//   - §5.17.3 C_SignEncryptUpdate: same input to both the signing and the
//     encryption operation.
//   - §5.17.4 C_DecryptVerifyUpdate: the verifying operation is fed the output
//     of the decryption operation, under the same rule as §5.17.2.
//   - All four: both underlying operations "MUST both be active", and
//     CKR_OPERATION_NOT_INITIALIZED is the answer when either is missing.
//
// On empty output. §5.17.1 and §5.17.2 both provide for an update call that
// "does not produce" output, and CKM_AES_GCM -- the mechanism this suite
// encrypts with -- cannot release a byte before it has authenticated the tag,
// so its updates legitimately emit nothing and its final emits everything. That
// is a trap: an earlier version of this file took those zero bytes and fed them
// onward, then reported success over nothing at all. Every assertion here is
// therefore conditional on what the mechanism can actually produce, and where
// an update is legitimately empty the corresponding final call is required to
// produce the entire result instead (assertUpdateFinalAccounting). "Empty" is
// never accepted as "correct".
//
// On operation lifetime. This module's Go API has no NULL_PTR, so a terminal
// call cannot tell a length query from a real read; §5.2 requires the operation
// to survive a length query, so C_EncryptFinal and its peers cache their output
// and stay active until dualFinish confirms receipt. Every terminal call below
// is paired with one, or the next test in the suite fails with
// CKR_OPERATION_ACTIVE for reasons that have nothing to do with it.
//
// A dual function a token genuinely does not implement must refuse with
// CKR_FUNCTION_NOT_SUPPORTED rather than fail somewhere mid-stream. The happy
// paths below assert CKR_OK, which is the evidence that these four are
// implemented; CKR_FUNCTION_FAILED is tolerated nowhere.
//
// References:
//   - OASIS PKCS#11 v3.2 Section 5.17
func (s *Suite) RunDualFunctionTests(t *testing.T) {
	t.Run("C_DigestEncryptUpdate", s.testDigestEncryptUpdate)
	t.Run("C_DecryptDigestUpdate", s.testDecryptDigestUpdate)
	t.Run("C_SignEncryptUpdate", s.testSignEncryptUpdate)
	t.Run("C_DecryptVerifyUpdate", s.testDecryptVerifyUpdate)
	t.Run("RoundTripPairing", s.testDualRoundTripPairing)
	t.Run("OperationsNotInitialized", s.testDualFunctionErrors)
	t.Run("BothHalvesRequiredMidStream", s.testDualHalfFinalizedMidStream)
}

// ----------------------------------------------------------------
// Shared dual-function passes
// ----------------------------------------------------------------

// dualEncryptSideRun records everything one encryption-side dual pass
// (C_DigestEncryptUpdate or C_SignEncryptUpdate) emitted.
type dualEncryptSideRun struct {
	// updateOut is the concatenation of what the update calls emitted, which
	// for an AEAD mechanism is legitimately empty.
	updateOut []byte
	// finalOut is what C_EncryptFinal emitted.
	finalOut []byte
	// ciphertext is updateOut followed by finalOut: the only concatenation
	// PKCS#11 gives a contract for.
	ciphertext []byte
	// digestOrSignature is the output of the other half, C_DigestFinal or
	// C_SignFinal.
	digestOrSignature []byte
}

// runDigestEncrypt drives one complete C_DigestEncryptUpdate pass over
// plaintext, split into several unaligned parts, and returns both halves'
// output with both operations terminated. It returns false, and the caller
// stops, when fips140=only refused the caller-chosen IV (see dualEncryptFinal).
func runDigestEncrypt(t *testing.T, m *module.Module, sh module.SessionHandle,
	key module.ObjectHandle, iv, plaintext []byte) (dualEncryptSideRun, bool) {
	t.Helper()

	requireRV(t, module.CKR_OK, m.DigestInit(sh, dualDigestMechanism()),
		"DigestInit should succeed")
	requireRV(t, module.CKR_OK, m.EncryptInit(sh, dualGCMMechanismWithIV(iv), key),
		"EncryptInit should succeed")

	updateOut := dualFeed(t, plaintext, func(part []byte) ([]byte, module.CK_RV) {
		return m.DigestEncryptUpdate(sh, part)
	}, "C_DigestEncryptUpdate")

	finalOut, ok := dualEncryptFinal(t, m, sh,
		"EncryptFinal must complete the encryption half of the dual operation")
	if !ok {
		return dualEncryptSideRun{}, false
	}
	dualFinish(t, m, sh, module.OperationEncrypt, "FinishOperation after EncryptFinal")

	digest, rv := m.DigestFinal(sh)
	requireRV(t, module.CKR_OK, rv,
		"DigestFinal must complete the digest half of the dual operation")
	dualFinish(t, m, sh, module.OperationDigest, "FinishOperation after DigestFinal")

	return dualEncryptSideRun{
		updateOut:         updateOut,
		finalOut:          finalOut,
		ciphertext:        dualConcat(updateOut, finalOut),
		digestOrSignature: digest,
	}, true
}

// runSignEncrypt drives one complete C_SignEncryptUpdate pass over plaintext,
// split into several unaligned parts, and returns both halves' output with both
// operations terminated. It returns false, and the caller stops, when
// fips140=only refused the caller-chosen IV (see dualEncryptFinal).
func runSignEncrypt(t *testing.T, m *module.Module, sh module.SessionHandle,
	secretKey, privKey module.ObjectHandle, iv, plaintext []byte) (dualEncryptSideRun, bool) {
	t.Helper()

	requireRV(t, module.CKR_OK, m.SignInit(sh, dualSignMechanism(), privKey),
		"SignInit should succeed")
	requireRV(t, module.CKR_OK, m.EncryptInit(sh, dualGCMMechanismWithIV(iv), secretKey),
		"EncryptInit should succeed")

	updateOut := dualFeed(t, plaintext, func(part []byte) ([]byte, module.CK_RV) {
		return m.SignEncryptUpdate(sh, part)
	}, "C_SignEncryptUpdate")

	finalOut, ok := dualEncryptFinal(t, m, sh,
		"EncryptFinal must complete the encryption half of the dual operation")
	if !ok {
		return dualEncryptSideRun{}, false
	}
	dualFinish(t, m, sh, module.OperationEncrypt, "FinishOperation after EncryptFinal")

	signature, rv := m.SignFinal(sh)
	requireRV(t, module.CKR_OK, rv,
		"SignFinal must complete the signing half of the dual operation")
	dualFinish(t, m, sh, module.OperationSign, "FinishOperation after SignFinal")

	return dualEncryptSideRun{
		updateOut:         updateOut,
		finalOut:          finalOut,
		ciphertext:        dualConcat(updateOut, finalOut),
		digestOrSignature: signature,
	}, true
}

// dualDecryptSideRun records what one decryption-side dual pass
// (C_DecryptDigestUpdate or C_DecryptVerifyUpdate) emitted.
//
// updateOut and finalOut are kept apart because §5.17.2 and §5.17.4 give them
// different meanings: only updateOut reached the second operation, and finalOut
// is precisely the plaintext the application must feed on itself.
type dualDecryptSideRun struct {
	updateOut []byte
	finalOut  []byte
	plaintext []byte
}

// runDecryptSide drives the decryption half of a dual pass over ciphertext,
// split into several unaligned parts, and terminates the decryption operation.
// The caller supplies the dual update function and finishes the second half
// itself, because §5.17.2 and §5.17.4 leave that to the application.
func runDecryptSide(t *testing.T, m *module.Module, sh module.SessionHandle,
	ciphertext []byte, update func(part []byte) ([]byte, module.CK_RV),
	fn string) dualDecryptSideRun {
	t.Helper()

	updateOut := dualFeed(t, ciphertext, update, fn)

	finalOut, rv := m.DecryptFinal(sh)
	requireRV(t, module.CKR_OK, rv,
		"DecryptFinal must complete the decryption half of the dual operation")
	dualFinish(t, m, sh, module.OperationDecrypt, "FinishOperation after DecryptFinal")

	return dualDecryptSideRun{
		updateOut: updateOut,
		finalOut:  finalOut,
		plaintext: dualConcat(updateOut, finalOut),
	}
}

// ----------------------------------------------------------------
// §5.17.1 C_DigestEncryptUpdate
// ----------------------------------------------------------------

// testDigestEncryptUpdate verifies C_DigestEncryptUpdate per v3.2 §5.17.1.
func (s *Suite) testDigestEncryptUpdate(t *testing.T) {

	// This test catches a C_DigestEncryptUpdate that runs only one of its two
	// halves. The digest is checked against crypto/sha256 and the ciphertext
	// against crypto/cipher's AES-GCM, both computed here, so an implementation
	// that digests nothing, digests the ciphertext, returns the plaintext
	// unencrypted, or ignores the caller's IV all fail. It also catches a
	// multiple-part chain that drops the trailing partial block, because the
	// fixture is 37 bytes fed in parts of 20, 13 and 4.
	t.Run("digests_and_encrypts_precisely_the_same_input", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)
		key := generateSecretKey(t, m, sh)
		keyValue := attributeValue(t, m, sh, key, module.CKA_VALUE)

		plaintext := dualPlaintext()
		run, ok := runDigestEncrypt(t, m, sh, key, suiteGCMIV(), plaintext)
		if !ok {
			return
		}

		wantCiphertext := aesGCMSeal(t, keyValue, suiteGCMIV(), plaintext, nil)
		assertUpdateFinalAccounting(t, run.updateOut, run.finalOut, wantCiphertext,
			"C_DigestEncryptUpdate encryption half")

		// "Precisely the same input" (§5.17.1): the digest covers the plaintext
		// that was encrypted, not the ciphertext and not nothing.
		assertSHA256(t, run.digestOrSignature, plaintext, "C_DigestEncryptUpdate digest half")
	})

	// This test catches a module whose dual function is a thin alias for
	// C_EncryptUpdate, or for C_DigestUpdate, rather than a genuine pass over
	// both. Digesting separately over the same input must reproduce the dual
	// function's digest byte for byte -- the equivalence §5.17 exists to
	// provide.
	//
	// The ciphertexts cannot be compared to each other: AES-GCM may never reuse
	// a (key, IV) pair, and this module correctly refuses the attempt, so the
	// two paths must encrypt under different IVs. Each is therefore held to the
	// AES-GCM oracle for its own IV, which says the same thing -- both paths
	// compute the same function of the plaintext -- without asking the module
	// to do something unsafe.
	t.Run("is_equivalent_to_digesting_and_encrypting_separately", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)
		key := generateSecretKey(t, m, sh)
		keyValue := attributeValue(t, m, sh, key, module.CKA_VALUE)

		plaintext := dualPlaintext()
		dual, ok := runDigestEncrypt(t, m, sh, key, dualGCMIVFor(0), plaintext)
		if !ok {
			return
		}

		// The separate path: the same key, the same parts, but C_DigestUpdate
		// and C_EncryptUpdate driven independently, under a second IV.
		requireRV(t, module.CKR_OK, m.DigestInit(sh, dualDigestMechanism()),
			"DigestInit for the separate path should succeed")
		for _, part := range dualPartsOf(t, plaintext) {
			requireRV(t, module.CKR_OK, m.DigestUpdate(sh, part),
				"DigestUpdate for the separate path should succeed")
		}
		separateDigest, rv := m.DigestFinal(sh)
		requireRV(t, module.CKR_OK, rv, "DigestFinal for the separate path should succeed")
		dualFinish(t, m, sh, module.OperationDigest, "FinishOperation after the separate DigestFinal")

		requireRV(t, module.CKR_OK, m.EncryptInit(sh, dualGCMMechanismWithIV(dualGCMIVFor(1)), key),
			"EncryptInit for the separate path should succeed")
		var separateUpdateOut []byte
		for _, part := range dualPartsOf(t, plaintext) {
			out, rv := m.EncryptUpdate(sh, part)
			requireRV(t, module.CKR_OK, rv, "EncryptUpdate for the separate path should succeed")
			separateUpdateOut = append(separateUpdateOut, out...)
		}
		separateFinalOut, rv := m.EncryptFinal(sh)
		requireRV(t, module.CKR_OK, rv, "EncryptFinal for the separate path should succeed")
		dualFinish(t, m, sh, module.OperationEncrypt, "FinishOperation after the separate EncryptFinal")

		if !bytes.Equal(dual.digestOrSignature, separateDigest) {
			t.Fatalf("the dual-function digest differs from digesting separately\n"+
				" dual %x\nseparate %x", dual.digestOrSignature, separateDigest)
		}

		assertUpdateFinalAccounting(t, dual.updateOut, dual.finalOut,
			aesGCMSeal(t, keyValue, dualGCMIVFor(0), plaintext, nil),
			"C_DigestEncryptUpdate encryption half")
		assertUpdateFinalAccounting(t, separateUpdateOut, separateFinalOut,
			aesGCMSeal(t, keyValue, dualGCMIVFor(1), plaintext, nil),
			"the separate C_EncryptUpdate path")
	})

	// This test catches a half-implemented dual function that leaves one of its
	// two operations dead or already terminated. Both must survive the dual
	// call and remain terminable by their own final call, so the digest is
	// finalized FIRST here -- the reverse of the order runDigestEncrypt uses --
	// and a further C_DigestEncryptUpdate after two parts proves both were
	// still active mid-stream.
	t.Run("leaves_both_operations_active_and_separately_terminable", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)
		key := generateSecretKey(t, m, sh)
		keyValue := attributeValue(t, m, sh, key, module.CKA_VALUE)

		plaintext := dualPlaintext()
		parts := dualPartsOf(t, plaintext)

		requireRV(t, module.CKR_OK, m.DigestInit(sh, dualDigestMechanism()),
			"DigestInit should succeed")
		requireRV(t, module.CKR_OK, m.EncryptInit(sh, dualGCMMechanism(), key),
			"EncryptInit should succeed")

		var updateOut []byte
		for _, part := range parts {
			out, rv := m.DigestEncryptUpdate(sh, part)
			// A dual call that terminated either operation on the way through
			// would answer CKR_OPERATION_NOT_INITIALIZED here on the next part.
			requireRV(t, module.CKR_OK, rv,
				"C_DigestEncryptUpdate must leave both operations active for the following part")
			updateOut = append(updateOut, out...)
		}

		// Digest first, encryption second: the two halves must be independently
		// terminable, in either order.
		digest, rv := m.DigestFinal(sh)
		requireRV(t, module.CKR_OK, rv,
			"the digest operation must still be live after the dual updates")
		dualFinish(t, m, sh, module.OperationDigest, "FinishOperation after DigestFinal")
		assertSHA256(t, digest, plaintext, "C_DigestFinal after C_DigestEncryptUpdate")

		finalOut, ok := dualEncryptFinal(t, m, sh,
			"the encryption operation must still be live after the digest was finalized")
		if !ok {
			return
		}
		dualFinish(t, m, sh, module.OperationEncrypt, "FinishOperation after EncryptFinal")

		wantCiphertext := aesGCMSeal(t, keyValue, suiteGCMIV(), plaintext, nil)
		assertUpdateFinalAccounting(t, updateOut, finalOut, wantCiphertext,
			"C_DigestEncryptUpdate encryption half finalized second")
	})

	// This test catches the case where only ONE half really ran. Changing a
	// single input byte must move BOTH outputs: if the digest is unchanged the
	// digesting half is a no-op, and if the ciphertext does not track the
	// plaintext the encryption half is.
	//
	// The two runs must use different IVs, because AES-GCM may never reuse a
	// (key, IV) pair and this module correctly refuses. That makes "the two
	// ciphertexts differ" worthless -- differing IVs alone guarantee it -- so
	// the encryption half is pinned the sharper way instead: at a FIXED IV, the
	// ciphertext must equal the AES-GCM oracle over the input that was actually
	// supplied, and must NOT equal the oracle over the other input. Only an
	// encryption that saw the data can satisfy both.
	t.Run("one_changed_input_byte_moves_both_the_digest_and_the_ciphertext", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)
		key := generateSecretKey(t, m, sh)
		keyValue := attributeValue(t, m, sh, key, module.CKA_VALUE)

		original := dualPlaintext()
		mutated := dualMutatedPlaintext()
		if len(original) != len(mutated) {
			t.Fatalf("the fixtures must be the same length, got %d and %d",
				len(original), len(mutated))
		}
		if bytes.Equal(original, mutated) {
			t.Fatal("the mutated fixture is identical to the original")
		}

		first, ok := runDigestEncrypt(t, m, sh, key, dualGCMIVFor(0), original)
		if !ok {
			return
		}
		second, ok := runDigestEncrypt(t, m, sh, key, dualGCMIVFor(1), mutated)
		if !ok {
			return
		}

		if bytes.Equal(first.digestOrSignature, second.digestOrSignature) {
			t.Fatalf("the digest is %x for both inputs; the digesting half of "+
				"C_DigestEncryptUpdate did not see the data", first.digestOrSignature)
		}
		assertSHA256(t, first.digestOrSignature, original, "C_DigestEncryptUpdate original")
		assertSHA256(t, second.digestOrSignature, mutated, "C_DigestEncryptUpdate mutated")

		assertCiphertextTracksInput(t, keyValue, dualGCMIVFor(0), first.ciphertext,
			original, mutated, "C_DigestEncryptUpdate")
		assertCiphertextTracksInput(t, keyValue, dualGCMIVFor(1), second.ciphertext,
			mutated, original, "C_DigestEncryptUpdate")
	})
}

// ----------------------------------------------------------------
// §5.17.2 C_DecryptDigestUpdate
// ----------------------------------------------------------------

// testDecryptDigestUpdate verifies C_DecryptDigestUpdate per v3.2 §5.17.2.
//
// Every ciphertext here is produced by crypto/cipher inside the test, never by
// the module's own C_Encrypt. Decrypting the module's own output would prove
// only that it agrees with itself.
func (s *Suite) testDecryptDigestUpdate(t *testing.T) {

	// This test catches a digesting half fed the wrong bytes. §5.17.2 links the
	// two operations ONLY through the dual call: the digest gets exactly what
	// C_DecryptDigestUpdate itself returned, and the plaintext that emerges
	// later from C_DecryptFinal is explicitly not digested. So the digest must
	// equal the SHA-256 of the update output and nothing else -- which fails
	// for a token that digests the ciphertext, one that digests plaintext it
	// never returned, and one that digests the whole plaintext including the
	// final's share.
	t.Run("digests_exactly_the_plaintext_the_update_returned", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)
		key := generateSecretKey(t, m, sh)
		keyValue := attributeValue(t, m, sh, key, module.CKA_VALUE)

		plaintext := dualPlaintext()
		iv, ciphertext := aesGCMSealGeneratedIV(t, keyValue, plaintext, nil)

		requireRV(t, module.CKR_OK, m.DecryptInit(sh, dualGCMMechanismWithIV(iv), key),
			"DecryptInit should succeed")
		requireRV(t, module.CKR_OK, m.DigestInit(sh, dualDigestMechanism()),
			"DigestInit should succeed")

		run := runDecryptSide(t, m, sh, ciphertext, func(part []byte) ([]byte, module.CK_RV) {
			return m.DecryptDigestUpdate(sh, part)
		}, "C_DecryptDigestUpdate")

		assertUpdateFinalAccounting(t, run.updateOut, run.finalOut, plaintext,
			"C_DecryptDigestUpdate decryption half")

		digest, rv := m.DigestFinal(sh)
		requireRV(t, module.CKR_OK, rv,
			"the digest operation must still be live after the dual updates")
		dualFinish(t, m, sh, module.OperationDigest, "FinishOperation after DigestFinal")

		assertSHA256(t, digest, run.updateOut, "C_DecryptDigestUpdate digest half")
	})

	// This test is the one that proves the digesting half is a live, correctly
	// seeded SHA-256 rather than a stub, in the case where the update
	// legitimately hands it nothing.
	//
	// Under CKM_AES_GCM the whole plaintext arrives at C_DecryptFinal, so the
	// digest of the update output alone is the digest of the empty string --
	// true, but too weak to distinguish a working digest from a dead one. The
	// spec's own §5.17.2 example prescribes the remedy: "It is crucial that,
	// before C_DigestFinal is called, the last 2 bytes of plaintext get passed
	// into the active digesting operation via a C_DigestUpdate call." Feeding
	// exactly the bytes C_DecryptFinal returned must therefore yield the digest
	// of the ENTIRE plaintext. A digest operation that the dual call had killed,
	// reset, or never wired up cannot produce that value.
	t.Run("completes_to_the_whole_plaintext_when_the_final_bytes_are_fed", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)
		key := generateSecretKey(t, m, sh)
		keyValue := attributeValue(t, m, sh, key, module.CKA_VALUE)

		plaintext := dualPlaintext()
		iv, ciphertext := aesGCMSealGeneratedIV(t, keyValue, plaintext, nil)

		requireRV(t, module.CKR_OK, m.DecryptInit(sh, dualGCMMechanismWithIV(iv), key),
			"DecryptInit should succeed")
		requireRV(t, module.CKR_OK, m.DigestInit(sh, dualDigestMechanism()),
			"DigestInit should succeed")

		run := runDecryptSide(t, m, sh, ciphertext, func(part []byte) ([]byte, module.CK_RV) {
			return m.DecryptDigestUpdate(sh, part)
		}, "C_DecryptDigestUpdate")

		assertUpdateFinalAccounting(t, run.updateOut, run.finalOut, plaintext,
			"C_DecryptDigestUpdate decryption half")

		// Feed the digest exactly what the dual call did not: the bytes
		// C_DecryptFinal returned.
		requireRV(t, module.CKR_OK, m.DigestUpdate(sh, run.finalOut),
			"C_DigestUpdate must accept the plaintext C_DecryptFinal returned, per the §5.17.2 example")

		digest, rv := m.DigestFinal(sh)
		requireRV(t, module.CKR_OK, rv, "DigestFinal should succeed")
		dualFinish(t, m, sh, module.OperationDigest, "FinishOperation after DigestFinal")

		assertSHA256(t, digest, plaintext,
			"the digest completed per the §5.17.2 example must cover the whole plaintext")
	})

	// This test catches a decryption half that is not really decrypting: a
	// tampered ciphertext must be refused, not silently turned into plaintext.
	// CKR_ENCRYPTED_DATA_INVALID is among the return values §5.17.2 lists.
	t.Run("refuses_a_tampered_ciphertext", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)
		key := generateSecretKey(t, m, sh)
		keyValue := attributeValue(t, m, sh, key, module.CKA_VALUE)

		plaintext := dualPlaintext()
		iv, ciphertext := aesGCMSealGeneratedIV(t, keyValue, plaintext, nil)
		tampered := append([]byte(nil), ciphertext...)
		tampered[0] ^= 0x01

		requireRV(t, module.CKR_OK, m.DecryptInit(sh, dualGCMMechanismWithIV(iv), key),
			"DecryptInit should succeed")
		requireRV(t, module.CKR_OK, m.DigestInit(sh, dualDigestMechanism()),
			"DigestInit should succeed")

		for _, part := range dualPartsOf(t, tampered) {
			_, rv := m.DecryptDigestUpdate(sh, part)
			requireRV(t, module.CKR_OK, rv,
				"C_DecryptDigestUpdate buffers without authenticating, so it still returns CKR_OK")
		}

		_, rv := m.DecryptFinal(sh)
		if rv == module.CKR_OK {
			t.Fatal("DecryptFinal accepted a ciphertext with a flipped byte; the AES-GCM " +
				"tag is not being checked")
		}
		requireRV(t, module.CKR_ENCRYPTED_DATA_INVALID, rv,
			"a ciphertext that fails its AES-GCM tag check must be reported as "+
				"CKR_ENCRYPTED_DATA_INVALID, not as a generic failure")
	})

	// This test catches a decryption half or a digesting half that ignores its
	// input: two ciphertexts differing in one plaintext byte must recover
	// different plaintexts AND, once completed per §5.17.2, produce different
	// digests.
	t.Run("one_changed_input_byte_moves_both_the_plaintext_and_the_digest", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)
		key := generateSecretKey(t, m, sh)
		keyValue := attributeValue(t, m, sh, key, module.CKA_VALUE)

		recoverAndDigest := func(plaintext []byte) (recovered, digest []byte) {
			t.Helper()
			iv, ciphertext := aesGCMSealGeneratedIV(t, keyValue, plaintext, nil)

			requireRV(t, module.CKR_OK, m.DecryptInit(sh, dualGCMMechanismWithIV(iv), key),
				"DecryptInit should succeed")
			requireRV(t, module.CKR_OK, m.DigestInit(sh, dualDigestMechanism()),
				"DigestInit should succeed")

			run := runDecryptSide(t, m, sh, ciphertext, func(part []byte) ([]byte, module.CK_RV) {
				return m.DecryptDigestUpdate(sh, part)
			}, "C_DecryptDigestUpdate")
			assertUpdateFinalAccounting(t, run.updateOut, run.finalOut, plaintext,
				"C_DecryptDigestUpdate decryption half")

			requireRV(t, module.CKR_OK, m.DigestUpdate(sh, run.finalOut),
				"C_DigestUpdate for the §5.17.2 completion should succeed")
			d, rv := m.DigestFinal(sh)
			requireRV(t, module.CKR_OK, rv, "DigestFinal should succeed")
			dualFinish(t, m, sh, module.OperationDigest, "FinishOperation after DigestFinal")
			return run.plaintext, d
		}

		firstPlain, firstDigest := recoverAndDigest(dualPlaintext())
		secondPlain, secondDigest := recoverAndDigest(dualMutatedPlaintext())

		if bytes.Equal(firstPlain, secondPlain) {
			t.Fatalf("both ciphertexts decrypted to %q; the decryption half of "+
				"C_DecryptDigestUpdate did not see the data", firstPlain)
		}
		if bytes.Equal(firstDigest, secondDigest) {
			t.Fatalf("the digest is %x for both inputs; the digesting half of "+
				"C_DecryptDigestUpdate did not see the data", firstDigest)
		}
	})
}

// ----------------------------------------------------------------
// §5.17.3 C_SignEncryptUpdate
// ----------------------------------------------------------------

// testSignEncryptUpdate verifies C_SignEncryptUpdate per v3.2 §5.17.3.
func (s *Suite) testSignEncryptUpdate(t *testing.T) {

	// This test catches a C_SignEncryptUpdate that runs only one of its halves.
	// The signature is checked with crypto/rsa against the modulus and exponent
	// the token itself published, so a signature over the ciphertext, over
	// nothing, or over some other data all fail; the ciphertext is checked
	// against crypto/cipher's AES-GCM. Checking the signature by feeding it back
	// into C_Verify would prove only that the module agrees with itself.
	t.Run("signs_and_encrypts_precisely_the_same_input", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)
		secretKey := generateSecretKey(t, m, sh)
		keyValue := attributeValue(t, m, sh, secretKey, module.CKA_VALUE)
		pubKey, privKey := generateRSAKeyPair(t, m, sh)

		plaintext := dualPlaintext()
		run, ok := runSignEncrypt(t, m, sh, secretKey, privKey, suiteGCMIV(), plaintext)
		if !ok {
			return
		}

		wantCiphertext := aesGCMSeal(t, keyValue, suiteGCMIV(), plaintext, nil)
		assertUpdateFinalAccounting(t, run.updateOut, run.finalOut, wantCiphertext,
			"C_SignEncryptUpdate encryption half")

		// "Precisely the same input" (§5.17.3): the signature covers the
		// plaintext that was encrypted.
		pub := rsaPublicKeyFor(t, m, sh, pubKey)
		assertRSASignature(t, pub, crypto.SHA256, plaintext, run.digestOrSignature)
	})

	// This test catches a dual function that is a thin alias for one of its
	// halves. CKM_SHA256_RSA_PKCS is deterministic, so signing separately over
	// the same input must reproduce the dual function's signature byte for byte.
	//
	// The ciphertexts cannot be compared to each other: AES-GCM may never reuse
	// a (key, IV) pair, and this module correctly refuses the attempt, so the
	// two paths must encrypt under different IVs. Each is therefore held to the
	// AES-GCM oracle for its own IV, which says the same thing -- both paths
	// compute the same function of the plaintext -- without asking the module
	// to do something unsafe.
	t.Run("is_equivalent_to_signing_and_encrypting_separately", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)
		secretKey := generateSecretKey(t, m, sh)
		keyValue := attributeValue(t, m, sh, secretKey, module.CKA_VALUE)
		_, privKey := generateRSAKeyPair(t, m, sh)

		plaintext := dualPlaintext()
		dual, ok := runSignEncrypt(t, m, sh, secretKey, privKey, dualGCMIVFor(0), plaintext)
		if !ok {
			return
		}

		requireRV(t, module.CKR_OK, m.SignInit(sh, dualSignMechanism(), privKey),
			"SignInit for the separate path should succeed")
		for _, part := range dualPartsOf(t, plaintext) {
			requireRV(t, module.CKR_OK, m.SignUpdate(sh, part),
				"SignUpdate for the separate path should succeed")
		}
		separateSignature, rv := m.SignFinal(sh)
		requireRV(t, module.CKR_OK, rv, "SignFinal for the separate path should succeed")
		dualFinish(t, m, sh, module.OperationSign, "FinishOperation after the separate SignFinal")

		requireRV(t, module.CKR_OK, m.EncryptInit(sh, dualGCMMechanismWithIV(dualGCMIVFor(1)), secretKey),
			"EncryptInit for the separate path should succeed")
		var separateUpdateOut []byte
		for _, part := range dualPartsOf(t, plaintext) {
			out, rv := m.EncryptUpdate(sh, part)
			requireRV(t, module.CKR_OK, rv, "EncryptUpdate for the separate path should succeed")
			separateUpdateOut = append(separateUpdateOut, out...)
		}
		separateFinalOut, rv := m.EncryptFinal(sh)
		requireRV(t, module.CKR_OK, rv, "EncryptFinal for the separate path should succeed")
		dualFinish(t, m, sh, module.OperationEncrypt, "FinishOperation after the separate EncryptFinal")

		if !bytes.Equal(dual.digestOrSignature, separateSignature) {
			t.Fatalf("the dual-function signature differs from signing separately\n"+
				" dual %x\nseparate %x", dual.digestOrSignature, separateSignature)
		}

		assertUpdateFinalAccounting(t, dual.updateOut, dual.finalOut,
			aesGCMSeal(t, keyValue, dualGCMIVFor(0), plaintext, nil),
			"C_SignEncryptUpdate encryption half")
		assertUpdateFinalAccounting(t, separateUpdateOut, separateFinalOut,
			aesGCMSeal(t, keyValue, dualGCMIVFor(1), plaintext, nil),
			"the separate C_EncryptUpdate path")
	})

	// This test catches a half-implemented dual function that terminates one of
	// its operations on the way through. The signing half is finalized FIRST
	// here, the reverse of runSignEncrypt's order, and both finals must produce
	// correct output.
	t.Run("leaves_both_operations_active_and_separately_terminable", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)
		secretKey := generateSecretKey(t, m, sh)
		keyValue := attributeValue(t, m, sh, secretKey, module.CKA_VALUE)
		pubKey, privKey := generateRSAKeyPair(t, m, sh)

		plaintext := dualPlaintext()

		requireRV(t, module.CKR_OK, m.SignInit(sh, dualSignMechanism(), privKey),
			"SignInit should succeed")
		requireRV(t, module.CKR_OK, m.EncryptInit(sh, dualGCMMechanism(), secretKey),
			"EncryptInit should succeed")

		var updateOut []byte
		for _, part := range dualPartsOf(t, plaintext) {
			out, rv := m.SignEncryptUpdate(sh, part)
			requireRV(t, module.CKR_OK, rv,
				"C_SignEncryptUpdate must leave both operations active for the following part")
			updateOut = append(updateOut, out...)
		}

		signature, rv := m.SignFinal(sh)
		requireRV(t, module.CKR_OK, rv,
			"the signing operation must still be live after the dual updates")
		dualFinish(t, m, sh, module.OperationSign, "FinishOperation after SignFinal")
		pub := rsaPublicKeyFor(t, m, sh, pubKey)
		assertRSASignature(t, pub, crypto.SHA256, plaintext, signature)

		finalOut, ok := dualEncryptFinal(t, m, sh,
			"the encryption operation must still be live after the signature was finalized")
		if !ok {
			return
		}
		dualFinish(t, m, sh, module.OperationEncrypt, "FinishOperation after EncryptFinal")

		wantCiphertext := aesGCMSeal(t, keyValue, suiteGCMIV(), plaintext, nil)
		assertUpdateFinalAccounting(t, updateOut, finalOut, wantCiphertext,
			"C_SignEncryptUpdate encryption half finalized second")
	})

	// This test catches the case where only ONE half really ran: one changed
	// input byte must move both the signature and the ciphertext.
	//
	// As above, the two runs need different IVs because AES-GCM may never reuse
	// a (key, IV) pair, so the encryption half is pinned by requiring each
	// ciphertext to match the AES-GCM oracle over its own input and to differ
	// from the oracle over the other input at the same IV.
	t.Run("one_changed_input_byte_moves_both_the_signature_and_the_ciphertext", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)
		secretKey := generateSecretKey(t, m, sh)
		keyValue := attributeValue(t, m, sh, secretKey, module.CKA_VALUE)
		pubKey, privKey := generateRSAKeyPair(t, m, sh)

		original := dualPlaintext()
		mutated := dualMutatedPlaintext()

		first, ok := runSignEncrypt(t, m, sh, secretKey, privKey, dualGCMIVFor(0), original)
		if !ok {
			return
		}
		second, ok := runSignEncrypt(t, m, sh, secretKey, privKey, dualGCMIVFor(1), mutated)
		if !ok {
			return
		}

		if bytes.Equal(first.digestOrSignature, second.digestOrSignature) {
			t.Fatal("the signature is identical for both inputs; the signing half of " +
				"C_SignEncryptUpdate did not see the data")
		}

		pub := rsaPublicKeyFor(t, m, sh, pubKey)
		assertRSASignature(t, pub, crypto.SHA256, original, first.digestOrSignature)
		assertRSASignature(t, pub, crypto.SHA256, mutated, second.digestOrSignature)

		assertCiphertextTracksInput(t, keyValue, dualGCMIVFor(0), first.ciphertext,
			original, mutated, "C_SignEncryptUpdate")
		assertCiphertextTracksInput(t, keyValue, dualGCMIVFor(1), second.ciphertext,
			mutated, original, "C_SignEncryptUpdate")
	})
}

// ----------------------------------------------------------------
// §5.17.4 C_DecryptVerifyUpdate
// ----------------------------------------------------------------

// testDecryptVerifyUpdate verifies C_DecryptVerifyUpdate per v3.2 §5.17.4.
//
// The ciphertext is produced by crypto/cipher and the signature offered to
// C_VerifyFinal is checked with crypto/rsa before it is offered, so a failure
// here is the verifying half's, not a bad fixture's.
func (s *Suite) testDecryptVerifyUpdate(t *testing.T) {

	// This test catches a verifying half fed the wrong bytes. §5.17.4 links the
	// two operations only through the dual call, so after C_DecryptFinal the
	// application must feed the remaining plaintext with C_VerifyUpdate; the
	// verifier has then seen the whole plaintext exactly once and a signature
	// over that plaintext must be accepted. A token that fed the verifier the
	// ciphertext, or fed it the plaintext twice, or never fed it at all, ends up
	// with a different accumulator and fails.
	t.Run("verifies_a_signature_over_the_plaintext_it_recovered", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)
		secretKey := generateSecretKey(t, m, sh)
		keyValue := attributeValue(t, m, sh, secretKey, module.CKA_VALUE)
		pubKey, privKey := generateRSAKeyPair(t, m, sh)

		plaintext := dualPlaintext()
		iv, ciphertext := aesGCMSealGeneratedIV(t, keyValue, plaintext, nil)
		signature := dualSignatureOver(t, m, sh, privKey, pubKey, plaintext)

		requireRV(t, module.CKR_OK, m.DecryptInit(sh, dualGCMMechanismWithIV(iv), secretKey),
			"DecryptInit should succeed")
		requireRV(t, module.CKR_OK, m.VerifyInit(sh, dualSignMechanism(), pubKey),
			"VerifyInit should succeed")

		run := runDecryptSide(t, m, sh, ciphertext, func(part []byte) ([]byte, module.CK_RV) {
			return m.DecryptVerifyUpdate(sh, part)
		}, "C_DecryptVerifyUpdate")

		assertUpdateFinalAccounting(t, run.updateOut, run.finalOut, plaintext,
			"C_DecryptVerifyUpdate decryption half")

		// Feed the verifier exactly what the dual call did not, per §5.17.4.
		requireRV(t, module.CKR_OK, m.VerifyUpdate(sh, run.finalOut),
			"C_VerifyUpdate must accept the plaintext C_DecryptFinal returned, per §5.17.4")

		// C_VerifyFinal produces no output, so it terminates itself: no
		// FinishOperation here.
		requireRV(t, module.CKR_OK, m.VerifyFinal(sh, signature),
			"C_VerifyFinal must accept a signature over exactly the plaintext the "+
				"dual operation recovered")
	})

	// This test stops the positive case above from being satisfied by a
	// C_VerifyFinal that returns CKR_OK unconditionally. The signature covers
	// data the dual operation never processed, so it must be rejected, and
	// §5.17.4's verification failure is CKR_SIGNATURE_INVALID.
	t.Run("rejects_a_signature_over_different_data", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)
		secretKey := generateSecretKey(t, m, sh)
		keyValue := attributeValue(t, m, sh, secretKey, module.CKA_VALUE)
		pubKey, privKey := generateRSAKeyPair(t, m, sh)

		plaintext := dualPlaintext()
		iv, ciphertext := aesGCMSealGeneratedIV(t, keyValue, plaintext, nil)
		wrongSignature := dualSignatureOver(t, m, sh, privKey, pubKey,
			[]byte("data the dual operation never processed"))

		requireRV(t, module.CKR_OK, m.DecryptInit(sh, dualGCMMechanismWithIV(iv), secretKey),
			"DecryptInit should succeed")
		requireRV(t, module.CKR_OK, m.VerifyInit(sh, dualSignMechanism(), pubKey),
			"VerifyInit should succeed")

		run := runDecryptSide(t, m, sh, ciphertext, func(part []byte) ([]byte, module.CK_RV) {
			return m.DecryptVerifyUpdate(sh, part)
		}, "C_DecryptVerifyUpdate")

		assertUpdateFinalAccounting(t, run.updateOut, run.finalOut, plaintext,
			"C_DecryptVerifyUpdate decryption half")

		requireRV(t, module.CKR_OK, m.VerifyUpdate(sh, run.finalOut),
			"C_VerifyUpdate should succeed")

		rv := m.VerifyFinal(sh, wrongSignature)
		if rv == module.CKR_OK {
			t.Fatal("C_VerifyFinal accepted a signature over data the dual operation " +
				"never processed; the verifier is not being fed the plaintext")
		}
		requireRV(t, module.CKR_SIGNATURE_INVALID, rv,
			"a signature over other data must be reported as CKR_SIGNATURE_INVALID")
	})

	// This test catches a decryption half that ignores its input: two
	// ciphertexts differing in one plaintext byte must recover different
	// plaintexts, and the signature that fits one must not fit the other.
	t.Run("one_changed_input_byte_moves_both_the_plaintext_and_the_verdict", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)
		secretKey := generateSecretKey(t, m, sh)
		keyValue := attributeValue(t, m, sh, secretKey, module.CKA_VALUE)
		pubKey, privKey := generateRSAKeyPair(t, m, sh)

		original := dualPlaintext()
		mutated := dualMutatedPlaintext()
		signatureOverOriginal := dualSignatureOver(t, m, sh, privKey, pubKey, original)

		// The dual pass over the mutated ciphertext, checked against the
		// signature over the ORIGINAL plaintext.
		verdictFor := func(plaintext []byte) (recovered []byte, rv module.CK_RV) {
			t.Helper()
			iv, ciphertext := aesGCMSealGeneratedIV(t, keyValue, plaintext, nil)

			requireRV(t, module.CKR_OK, m.DecryptInit(sh, dualGCMMechanismWithIV(iv), secretKey),
				"DecryptInit should succeed")
			requireRV(t, module.CKR_OK, m.VerifyInit(sh, dualSignMechanism(), pubKey),
				"VerifyInit should succeed")

			run := runDecryptSide(t, m, sh, ciphertext, func(part []byte) ([]byte, module.CK_RV) {
				return m.DecryptVerifyUpdate(sh, part)
			}, "C_DecryptVerifyUpdate")
			assertUpdateFinalAccounting(t, run.updateOut, run.finalOut, plaintext,
				"C_DecryptVerifyUpdate decryption half")

			requireRV(t, module.CKR_OK, m.VerifyUpdate(sh, run.finalOut),
				"C_VerifyUpdate should succeed")
			return run.plaintext, m.VerifyFinal(sh, signatureOverOriginal)
		}

		originalPlain, originalVerdict := verdictFor(original)
		mutatedPlain, mutatedVerdict := verdictFor(mutated)

		if bytes.Equal(originalPlain, mutatedPlain) {
			t.Fatalf("both ciphertexts decrypted to %q; the decryption half of "+
				"C_DecryptVerifyUpdate did not see the data", originalPlain)
		}
		requireRV(t, module.CKR_OK, originalVerdict,
			"the signature over the original plaintext must verify against the "+
				"original plaintext")
		requireRV(t, module.CKR_SIGNATURE_INVALID, mutatedVerdict,
			"the signature over the original plaintext must not verify against a "+
				"plaintext differing by one byte")
	})
}

// dualSignatureOver produces a signature over data with the token's private key
// and checks it with crypto/rsa before handing it back.
//
// The verification tests need a signature that is known good independently of
// the module. Validating it here means that when C_VerifyFinal later rejects
// it, the fault is in the verifying half of the dual operation and not in a
// fixture nobody checked.
func dualSignatureOver(t *testing.T, m *module.Module, sh module.SessionHandle,
	privKey, pubKey module.ObjectHandle, data []byte) []byte {
	t.Helper()

	requireRV(t, module.CKR_OK, m.SignInit(sh, dualSignMechanism(), privKey),
		"SignInit for the fixture signature should succeed")

	signature, rv := m.Sign(sh, data)
	requireRV(t, module.CKR_OK, rv, "Sign for the fixture signature should succeed")
	dualFinish(t, m, sh, module.OperationSign, "FinishOperation after the fixture Sign")

	pub := rsaPublicKeyFor(t, m, sh, pubKey)
	assertRSASignature(t, pub, crypto.SHA256, data, signature)
	return signature
}

// ----------------------------------------------------------------
// Round-trip pairing
// ----------------------------------------------------------------

// testDualRoundTripPairing verifies that each encryption-side dual function
// pairs with its decryption-side inverse, which §5.17.2 and §5.17.4 name
// explicitly: C_DigestEncryptUpdate is the "inverse function" of
// C_DecryptDigestUpdate, and C_SignEncryptUpdate of C_DecryptVerifyUpdate.
//
// Both directions run through the module, so on its own a round trip proves
// only self-consistency. It is worth asserting anyway because it fails for a
// real and common defect the one-directional tests cannot see: a pair whose two
// halves disagree about how much data reached the second operation. Each round
// trip below is additionally anchored to an oracle -- the digest to
// crypto/sha256, the signature to crypto/rsa -- so neither direction can drift.
func (s *Suite) testDualRoundTripPairing(t *testing.T) {

	// This test catches a C_DecryptDigestUpdate that recovers the plaintext but
	// digests something other than what C_DigestEncryptUpdate digested. The two
	// digests must be the same value, and that value must be the SHA-256 of the
	// plaintext.
	t.Run("DigestEncryptUpdate_pairs_with_DecryptDigestUpdate", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)
		key := generateSecretKey(t, m, sh)

		plaintext := dualPlaintext()
		forward, ok := runDigestEncrypt(t, m, sh, key, suiteGCMIV(), plaintext)
		if !ok {
			return
		}
		assertSHA256(t, forward.digestOrSignature, plaintext, "C_DigestEncryptUpdate")

		requireRV(t, module.CKR_OK, m.DecryptInit(sh, dualGCMMechanism(), key),
			"DecryptInit should succeed")
		requireRV(t, module.CKR_OK, m.DigestInit(sh, dualDigestMechanism()),
			"DigestInit should succeed")

		back := runDecryptSide(t, m, sh, forward.ciphertext, func(part []byte) ([]byte, module.CK_RV) {
			return m.DecryptDigestUpdate(sh, part)
		}, "C_DecryptDigestUpdate")

		assertUpdateFinalAccounting(t, back.updateOut, back.finalOut, plaintext,
			"C_DecryptDigestUpdate decryption half")
		if !bytes.Equal(back.plaintext, plaintext) {
			t.Fatalf("the round trip did not recover the plaintext\n got %q\nwant %q",
				back.plaintext, plaintext)
		}

		// Complete the digest per the §5.17.2 example so it covers the same
		// bytes C_DigestEncryptUpdate saw.
		requireRV(t, module.CKR_OK, m.DigestUpdate(sh, back.finalOut),
			"C_DigestUpdate for the §5.17.2 completion should succeed")
		digest, rv := m.DigestFinal(sh)
		requireRV(t, module.CKR_OK, rv, "DigestFinal should succeed")
		dualFinish(t, m, sh, module.OperationDigest, "FinishOperation after DigestFinal")

		if !bytes.Equal(digest, forward.digestOrSignature) {
			t.Fatalf("the two halves of the round trip digested different data\n"+
				" C_DecryptDigestUpdate %x\nC_DigestEncryptUpdate %x",
				digest, forward.digestOrSignature)
		}
		assertSHA256(t, digest, plaintext, "the round-tripped digest")
	})

	// This test catches a C_DecryptVerifyUpdate that cannot accept the signature
	// its inverse produced -- the pairing defect that shows up when the two
	// sides disagree about how much data reached the signing and verifying
	// operations.
	t.Run("SignEncryptUpdate_pairs_with_DecryptVerifyUpdate", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)
		secretKey := generateSecretKey(t, m, sh)
		pubKey, privKey := generateRSAKeyPair(t, m, sh)

		plaintext := dualPlaintext()
		forward, ok := runSignEncrypt(t, m, sh, secretKey, privKey, suiteGCMIV(), plaintext)
		if !ok {
			return
		}

		pub := rsaPublicKeyFor(t, m, sh, pubKey)
		assertRSASignature(t, pub, crypto.SHA256, plaintext, forward.digestOrSignature)

		requireRV(t, module.CKR_OK, m.DecryptInit(sh, dualGCMMechanism(), secretKey),
			"DecryptInit should succeed")
		requireRV(t, module.CKR_OK, m.VerifyInit(sh, dualSignMechanism(), pubKey),
			"VerifyInit should succeed")

		back := runDecryptSide(t, m, sh, forward.ciphertext, func(part []byte) ([]byte, module.CK_RV) {
			return m.DecryptVerifyUpdate(sh, part)
		}, "C_DecryptVerifyUpdate")

		assertUpdateFinalAccounting(t, back.updateOut, back.finalOut, plaintext,
			"C_DecryptVerifyUpdate decryption half")
		if !bytes.Equal(back.plaintext, plaintext) {
			t.Fatalf("the round trip did not recover the plaintext\n got %q\nwant %q",
				back.plaintext, plaintext)
		}

		requireRV(t, module.CKR_OK, m.VerifyUpdate(sh, back.finalOut),
			"C_VerifyUpdate for the §5.17.4 completion should succeed")
		requireRV(t, module.CKR_OK, m.VerifyFinal(sh, forward.digestOrSignature),
			"C_DecryptVerifyUpdate must accept the signature C_SignEncryptUpdate produced "+
				"over the same plaintext")
	})
}

// ----------------------------------------------------------------
// State errors
// ----------------------------------------------------------------

// testDualFunctionErrors verifies that each dual-function call refuses to run
// unless BOTH of the operations it combines are active.
//
// §5.17 states for each of the four that the two operations "MUST both be
// active", and lists CKR_OPERATION_NOT_INITIALIZED among the return values.
// Half-initialized is not initialized, and it is the half-initialized case that
// matters: a module that only checks one of the two operations returns CKR_OK
// and then runs a single-function operation under a dual-function name, or
// fails somewhere downstream with CKR_FUNCTION_FAILED. Each of the four is
// therefore probed three ways -- neither half, and each half alone -- and
// CKR_FUNCTION_FAILED is accepted nowhere.
func (s *Suite) testDualFunctionErrors(t *testing.T) {

	// dualStateCase names one half-initialized (or wholly uninitialized) state
	// and the dual call that must refuse it.
	type dualStateCase struct {
		name string
		// arrange initializes whichever half the case leaves active, and
		// returns the dual call under test.
		arrange func(t *testing.T, m *module.Module, sh module.SessionHandle) func([]byte) ([]byte, module.CK_RV)
	}

	digestInit := func(t *testing.T, m *module.Module, sh module.SessionHandle) {
		t.Helper()
		requireRV(t, module.CKR_OK, m.DigestInit(sh, dualDigestMechanism()),
			"DigestInit should succeed")
	}
	encryptInit := func(t *testing.T, m *module.Module, sh module.SessionHandle) {
		t.Helper()
		requireRV(t, module.CKR_OK, m.EncryptInit(sh, dualGCMMechanism(),
			generateSecretKey(t, m, sh)), "EncryptInit should succeed")
	}
	decryptInit := func(t *testing.T, m *module.Module, sh module.SessionHandle) {
		t.Helper()
		requireRV(t, module.CKR_OK, m.DecryptInit(sh, dualGCMMechanism(),
			generateSecretKey(t, m, sh)), "DecryptInit should succeed")
	}
	signInit := func(t *testing.T, m *module.Module, sh module.SessionHandle) {
		t.Helper()
		_, privKey := generateRSAKeyPair(t, m, sh)
		requireRV(t, module.CKR_OK, m.SignInit(sh, dualSignMechanism(), privKey),
			"SignInit should succeed")
	}
	verifyInit := func(t *testing.T, m *module.Module, sh module.SessionHandle) {
		t.Helper()
		pubKey, _ := generateRSAKeyPair(t, m, sh)
		requireRV(t, module.CKR_OK, m.VerifyInit(sh, dualSignMechanism(), pubKey),
			"VerifyInit should succeed")
	}

	cases := []dualStateCase{
		{
			name: "DigestEncryptUpdate_with_neither_half_active",
			arrange: func(t *testing.T, m *module.Module, sh module.SessionHandle) func([]byte) ([]byte, module.CK_RV) {
				return func(b []byte) ([]byte, module.CK_RV) { return m.DigestEncryptUpdate(sh, b) }
			},
		},
		{
			name: "DigestEncryptUpdate_with_only_the_digest_active",
			arrange: func(t *testing.T, m *module.Module, sh module.SessionHandle) func([]byte) ([]byte, module.CK_RV) {
				digestInit(t, m, sh)
				return func(b []byte) ([]byte, module.CK_RV) { return m.DigestEncryptUpdate(sh, b) }
			},
		},
		{
			name: "DigestEncryptUpdate_with_only_the_encryption_active",
			arrange: func(t *testing.T, m *module.Module, sh module.SessionHandle) func([]byte) ([]byte, module.CK_RV) {
				encryptInit(t, m, sh)
				return func(b []byte) ([]byte, module.CK_RV) { return m.DigestEncryptUpdate(sh, b) }
			},
		},
		{
			name: "DecryptDigestUpdate_with_neither_half_active",
			arrange: func(t *testing.T, m *module.Module, sh module.SessionHandle) func([]byte) ([]byte, module.CK_RV) {
				return func(b []byte) ([]byte, module.CK_RV) { return m.DecryptDigestUpdate(sh, b) }
			},
		},
		{
			name: "DecryptDigestUpdate_with_only_the_decryption_active",
			arrange: func(t *testing.T, m *module.Module, sh module.SessionHandle) func([]byte) ([]byte, module.CK_RV) {
				decryptInit(t, m, sh)
				return func(b []byte) ([]byte, module.CK_RV) { return m.DecryptDigestUpdate(sh, b) }
			},
		},
		{
			name: "DecryptDigestUpdate_with_only_the_digest_active",
			arrange: func(t *testing.T, m *module.Module, sh module.SessionHandle) func([]byte) ([]byte, module.CK_RV) {
				digestInit(t, m, sh)
				return func(b []byte) ([]byte, module.CK_RV) { return m.DecryptDigestUpdate(sh, b) }
			},
		},
		{
			name: "SignEncryptUpdate_with_neither_half_active",
			arrange: func(t *testing.T, m *module.Module, sh module.SessionHandle) func([]byte) ([]byte, module.CK_RV) {
				return func(b []byte) ([]byte, module.CK_RV) { return m.SignEncryptUpdate(sh, b) }
			},
		},
		{
			name: "SignEncryptUpdate_with_only_the_signature_active",
			arrange: func(t *testing.T, m *module.Module, sh module.SessionHandle) func([]byte) ([]byte, module.CK_RV) {
				signInit(t, m, sh)
				return func(b []byte) ([]byte, module.CK_RV) { return m.SignEncryptUpdate(sh, b) }
			},
		},
		{
			name: "SignEncryptUpdate_with_only_the_encryption_active",
			arrange: func(t *testing.T, m *module.Module, sh module.SessionHandle) func([]byte) ([]byte, module.CK_RV) {
				encryptInit(t, m, sh)
				return func(b []byte) ([]byte, module.CK_RV) { return m.SignEncryptUpdate(sh, b) }
			},
		},
		{
			name: "DecryptVerifyUpdate_with_neither_half_active",
			arrange: func(t *testing.T, m *module.Module, sh module.SessionHandle) func([]byte) ([]byte, module.CK_RV) {
				return func(b []byte) ([]byte, module.CK_RV) { return m.DecryptVerifyUpdate(sh, b) }
			},
		},
		{
			name: "DecryptVerifyUpdate_with_only_the_decryption_active",
			arrange: func(t *testing.T, m *module.Module, sh module.SessionHandle) func([]byte) ([]byte, module.CK_RV) {
				decryptInit(t, m, sh)
				return func(b []byte) ([]byte, module.CK_RV) { return m.DecryptVerifyUpdate(sh, b) }
			},
		},
		{
			name: "DecryptVerifyUpdate_with_only_the_verification_active",
			arrange: func(t *testing.T, m *module.Module, sh module.SessionHandle) func([]byte) ([]byte, module.CK_RV) {
				verifyInit(t, m, sh)
				return func(b []byte) ([]byte, module.CK_RV) { return m.DecryptVerifyUpdate(sh, b) }
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, cleanup := s.createInitializedModule(t)
			defer cleanup()

			sh := openAuthenticatedRWSession(t, m)
			call := tc.arrange(t, m, sh)

			out, rv := call([]byte("input the token must not process"))
			if rv == module.CKR_FUNCTION_NOT_SUPPORTED {
				t.Fatal("the dual function reported CKR_FUNCTION_NOT_SUPPORTED here but " +
					"succeeds when both operations are active; a token either implements " +
					"a function or it does not")
			}
			requireRV(t, module.CKR_OPERATION_NOT_INITIALIZED, rv,
				"§5.17 requires both operations to be active; the missing one must be "+
					"reported as CKR_OPERATION_NOT_INITIALIZED, not as a generic failure")
			if len(out) != 0 {
				t.Fatalf("a refused dual-function call produced %d bytes of output", len(out))
			}
		})
	}

	// This test pins the guarantee the accounting helper relies on: SHA-256 of
	// the empty string is a specific, non-zero value, so an assertion that a
	// digest equals it is a real assertion and not an accident of a nil slice
	// comparing equal to another nil slice.
	t.Run("the_empty_digest_is_a_definite_value", func(t *testing.T) {
		empty := sha256.Sum256(nil)
		if bytes.Equal(empty[:], make([]byte, sha256.Size)) {
			t.Fatal("SHA-256 of the empty string is all zeroes, which would make the " +
				"§5.17.2 linkage assertion vacuous")
		}
	})
}

// ----------------------------------------------------------------
// Both halves required for the whole stream
// ----------------------------------------------------------------

// testDualHalfFinalizedMidStream verifies that a dual function stops working
// the moment either of its two operations ends, even mid-stream.
//
// §5.17 requires both operations to be active for every call, not merely for
// the first. This is the assertion that tells a dual function apart from the
// single-function call it wraps: C_EncryptUpdate does not care whether a digest
// is active and C_DecryptUpdate does not care whether a verification is, so a
// C_DigestEncryptUpdate aliased to C_EncryptUpdate, or a C_DecryptVerifyUpdate
// aliased to C_DecryptUpdate, would keep returning CKR_OK here. Each case below
// therefore terminates the half that ONLY the dual function is obliged to
// notice -- never the encryption or decryption half, which both functions need
// -- and requires the next call to be refused with
// CKR_OPERATION_NOT_INITIALIZED.
func (s *Suite) testDualHalfFinalizedMidStream(t *testing.T) {

	t.Run("DigestEncryptUpdate_stops_once_the_digest_is_finalized", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)
		key := generateSecretKey(t, m, sh)
		parts := dualPartsOf(t, dualPlaintext())

		requireRV(t, module.CKR_OK, m.DigestInit(sh, dualDigestMechanism()),
			"DigestInit should succeed")
		requireRV(t, module.CKR_OK, m.EncryptInit(sh, dualGCMMechanism(), key),
			"EncryptInit should succeed")

		_, rv := m.DigestEncryptUpdate(sh, parts[0])
		requireRV(t, module.CKR_OK, rv, "the first dual update should succeed")

		// End the digest half only. The encryption half is untouched.
		digest, rv := m.DigestFinal(sh)
		requireRV(t, module.CKR_OK, rv, "DigestFinal should succeed")
		dualFinish(t, m, sh, module.OperationDigest, "FinishOperation after DigestFinal")
		assertSHA256(t, digest, parts[0], "the digest of the first part alone")

		_, rv = m.DigestEncryptUpdate(sh, parts[1])
		requireRV(t, module.CKR_OPERATION_NOT_INITIALIZED, rv,
			"C_DigestEncryptUpdate must refuse once the digest operation has ended, "+
				"even though the encryption operation is still active")
	})

	t.Run("SignEncryptUpdate_stops_once_the_signature_is_finalized", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)
		secretKey := generateSecretKey(t, m, sh)
		pubKey, privKey := generateRSAKeyPair(t, m, sh)
		parts := dualPartsOf(t, dualPlaintext())

		requireRV(t, module.CKR_OK, m.SignInit(sh, dualSignMechanism(), privKey),
			"SignInit should succeed")
		requireRV(t, module.CKR_OK, m.EncryptInit(sh, dualGCMMechanism(), secretKey),
			"EncryptInit should succeed")

		_, rv := m.SignEncryptUpdate(sh, parts[0])
		requireRV(t, module.CKR_OK, rv, "the first dual update should succeed")

		// End the signing half only.
		signature, rv := m.SignFinal(sh)
		requireRV(t, module.CKR_OK, rv, "SignFinal should succeed")
		dualFinish(t, m, sh, module.OperationSign, "FinishOperation after SignFinal")
		pub := rsaPublicKeyFor(t, m, sh, pubKey)
		assertRSASignature(t, pub, crypto.SHA256, parts[0], signature)

		_, rv = m.SignEncryptUpdate(sh, parts[1])
		requireRV(t, module.CKR_OPERATION_NOT_INITIALIZED, rv,
			"C_SignEncryptUpdate must refuse once the signing operation has ended, "+
				"even though the encryption operation is still active")
	})

	t.Run("DecryptDigestUpdate_stops_once_the_digest_is_finalized", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)
		key := generateSecretKey(t, m, sh)
		keyValue := attributeValue(t, m, sh, key, module.CKA_VALUE)
		iv, ciphertext := aesGCMSealGeneratedIV(t, keyValue, dualPlaintext(), nil)
		parts := dualPartsOf(t, ciphertext)

		requireRV(t, module.CKR_OK, m.DecryptInit(sh, dualGCMMechanismWithIV(iv), key),
			"DecryptInit should succeed")
		requireRV(t, module.CKR_OK, m.DigestInit(sh, dualDigestMechanism()),
			"DigestInit should succeed")

		_, rv := m.DecryptDigestUpdate(sh, parts[0])
		requireRV(t, module.CKR_OK, rv, "the first dual update should succeed")

		// End the digest half only. The decryption half is untouched, so a
		// plain C_DecryptUpdate would still be accepted here -- the dual
		// function must not be.
		_, rv = m.DigestFinal(sh)
		requireRV(t, module.CKR_OK, rv, "DigestFinal should succeed")
		dualFinish(t, m, sh, module.OperationDigest, "FinishOperation after DigestFinal")

		_, rv = m.DecryptDigestUpdate(sh, parts[1])
		requireRV(t, module.CKR_OPERATION_NOT_INITIALIZED, rv,
			"C_DecryptDigestUpdate must refuse once the digest operation has ended, "+
				"even though the decryption operation is still active")
	})

	t.Run("DecryptVerifyUpdate_stops_once_the_verification_is_finalized", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)
		secretKey := generateSecretKey(t, m, sh)
		keyValue := attributeValue(t, m, sh, secretKey, module.CKA_VALUE)
		pubKey, privKey := generateRSAKeyPair(t, m, sh)
		iv, ciphertext := aesGCMSealGeneratedIV(t, keyValue, dualPlaintext(), nil)
		parts := dualPartsOf(t, ciphertext)

		// A signature over data the verifier will never accumulate, used only
		// to drive C_VerifyFinal so that the verification operation ends.
		unrelated := dualSignatureOver(t, m, sh, privKey, pubKey,
			[]byte("data the verifier never accumulates"))

		requireRV(t, module.CKR_OK, m.DecryptInit(sh, dualGCMMechanismWithIV(iv), secretKey),
			"DecryptInit should succeed")
		requireRV(t, module.CKR_OK, m.VerifyInit(sh, dualSignMechanism(), pubKey),
			"VerifyInit should succeed")

		_, rv := m.DecryptVerifyUpdate(sh, parts[0])
		requireRV(t, module.CKR_OK, rv, "the first dual update should succeed")

		// End the verification half only. C_VerifyFinal terminates its own
		// operation whether or not the signature checks out, and this one must
		// not: it covers data the verifier never saw.
		if rv := m.VerifyFinal(sh, unrelated); rv == module.CKR_OK {
			t.Fatal("C_VerifyFinal accepted a signature over data the verifier never " +
				"accumulated")
		}

		_, rv = m.DecryptVerifyUpdate(sh, parts[1])
		requireRV(t, module.CKR_OPERATION_NOT_INITIALIZED, rv,
			"C_DecryptVerifyUpdate must refuse once the verification operation has "+
				"ended, even though the decryption operation is still active")
	})
}
