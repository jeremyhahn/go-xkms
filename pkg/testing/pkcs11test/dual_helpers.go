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
	"fmt"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
)

// This file holds the fixtures and accounting helpers the Section 5.17
// dual-function tests are built from. They live apart from dual.go so that the
// assertions there read as statements about the spec rather than as plumbing.

// dualGCMMechanism builds the CKM_AES_GCM mechanism the dual-function tests
// encrypt and decrypt with, carrying the suite's fixed IV in CK_GCM_PARAMS and
// requesting the full 128-bit tag (PKCS#11 v3.2 §6.13.7).
//
// Both halves of a round trip must be initialized with the same IV: unlike
// encryption, decryption never generates one.
func dualGCMMechanism() *module.Mechanism {
	return dualGCMMechanismWithIV(suiteGCMIV())
}

// dualGCMMechanismWithIV is dualGCMMechanism with a caller-chosen IV, for the
// tests that encrypt more than once under one key.
func dualGCMMechanismWithIV(iv []byte) *module.Mechanism {
	return module.NewMechanismWithTypedParams(module.CKM_AES_GCM,
		module.NewAESGCMParams(iv, 128))
}

// dualGCMIVFor returns a distinct 12-byte AES-GCM IV for the seq'th encryption
// a single test performs under one key.
//
// AES-GCM loses both confidentiality and integrity if a (key, IV) pair ever
// repeats, and this module enforces that: a second C_EncryptInit with an IV
// already used under the same key is refused with CKR_MECHANISM_PARAM_INVALID
// (CryptoManager.checkGCMNonce). That is correct behaviour, so the tests that
// encrypt twice -- the equivalence tests and the one-changed-byte tests -- must
// vary the IV, and can no longer compare two module ciphertexts to each other.
// They compare each to the AES-GCM oracle for its own IV instead, which is the
// same evidence obtained without asking the module to do something unsafe.
//
// The generated IVs never collide with suiteGCMIV(), whose last byte is a
// letter, so a test may mix the two freely.
func dualGCMIVFor(seq int) []byte {
	if seq < 0 || seq > 9 {
		panic("dualGCMIVFor: sequence must be a single digit")
	}
	iv := append([]byte(nil), suiteGCMIV()...)
	iv[len(iv)-1] = byte('0' + seq)
	return iv
}

// dualDigestMechanism returns the digesting mechanism used throughout §5.17,
// chosen because crypto/sha256 can state its answer independently of the token.
func dualDigestMechanism() *module.Mechanism {
	return &module.Mechanism{Type: module.CKM_SHA256}
}

// dualSignMechanism returns the signing and verification mechanism used
// throughout §5.17. CKM_SHA256_RSA_PKCS is deterministic, which is what lets
// the equivalence tests compare a dual-function signature to a separately
// produced one byte for byte.
func dualSignMechanism() *module.Mechanism {
	return &module.Mechanism{Type: module.CKM_SHA256_RSA_PKCS}
}

// dualPlaintext returns the fixture every §5.17 test drives.
//
// It is 37 bytes: longer than the 16-byte AES block and deliberately not a
// multiple of it, so an implementation that only ever sees whole blocks, or
// that loses a trailing partial block between an update and its final, is
// caught. dualPartOffsets splits it into three unequal, individually
// unaligned parts so the same fixture also exercises the multiple-part path.
func dualPlaintext() []byte {
	return []byte("dual-function conformance fixture: 37")
}

// dualPartOffsets returns the split points dualPartsOf cuts the fixture at.
// The parts are 20, 13 and 4 bytes: three update calls, none of them block
// aligned, and none of them equal in length to another.
func dualPartOffsets() []int {
	return []int{20, 33}
}

// dualPartsOf splits data into the multiple-part fixture described by
// dualPartOffsets. Passing the whole buffer in one call would let a token that
// ignores everything after the first update still pass.
func dualPartsOf(t *testing.T, data []byte) [][]byte {
	t.Helper()

	offsets := dualPartOffsets()
	parts := make([][]byte, 0, len(offsets)+1)
	prev := 0
	for _, off := range offsets {
		if off <= prev || off >= len(data) {
			t.Fatalf("dual fixture split point %d is out of range for %d bytes", off, len(data))
		}
		parts = append(parts, data[prev:off])
		prev = off
	}
	parts = append(parts, data[prev:])
	return parts
}

// dualMutatedPlaintext returns dualPlaintext with exactly one byte changed.
//
// The mutated byte sits inside the first part, so a token that digests or signs
// only the tail of the input, or only the final part, still shows a difference
// here. Length is preserved so that a change in the ciphertext cannot be
// explained by a change in size.
func dualMutatedPlaintext() []byte {
	mutated := append([]byte(nil), dualPlaintext()...)
	mutated[7] ^= 0x01
	return mutated
}

// dualConcat joins the pieces an operation emitted across its updates and its
// final call. PKCS#11 lets a token split its output between those calls however
// it likes, so only the concatenation has a contract.
func dualConcat(parts ...[]byte) []byte {
	total := 0
	for _, p := range parts {
		total += len(p)
	}
	joined := make([]byte, 0, total)
	for _, p := range parts {
		joined = append(joined, p...)
	}
	return joined
}

// dualFinish confirms receipt of a terminal operation's output so the operation
// ends.
//
// This module's Go API has no NULL_PTR, so it cannot tell a length query from a
// real read and cannot decide on its own when to terminate; PKCS#11 v3.2 §5.2
// requires the operation to survive a length query, so C_EncryptFinal and its
// peers cache their result and leave the operation active until the caller says
// otherwise. Skipping this call leaves the session holding an active operation
// and the next C_*Init in the suite fails with CKR_OPERATION_ACTIVE, a failure
// that points at the wrong test.
//
// C_VerifyFinal is the exception: it returns no output, so it terminates itself
// and must not be passed here.
func dualFinish(t *testing.T, m *module.Module, sh module.SessionHandle,
	opType module.OperationType, what string) {
	t.Helper()
	requireRV(t, module.CKR_OK, m.FinishOperation(sh, opType), what)
}

// dualEncryptFinal completes the encryption half of a dual operation with
// C_EncryptFinal and requires CKR_OK, reporting msg otherwise. The suite's
// CKM_AES_GCM carries a caller-chosen IV, which fips140=only refuses at
// C_EncryptFinal with CKR_MECHANISM_PARAM_INVALID; there it returns false once
// the test has passed again with fips140=off, and the caller stops.
func dualEncryptFinal(t *testing.T, m *module.Module, sh module.SessionHandle, msg string) ([]byte, bool) {
	t.Helper()

	out, rv := m.EncryptFinal(sh)
	if !outsideFIPSAfterRefusal(t, module.CKR_MECHANISM_PARAM_INVALID, rv, fipsCallerIVRefusal) {
		return nil, false
	}
	requireRV(t, module.CKR_OK, rv, msg)
	return out, true
}

// dualFeed drives one of the four dual-function update calls over the parts of
// data and returns everything those calls emitted, concatenated.
//
// Every §5.17 test feeds its input in several pieces. A single update call
// would leave a token free to ignore all input after the first, and would never
// exercise the buffer that has to carry a partial AES block from one call to
// the next.
func dualFeed(t *testing.T, data []byte,
	update func(part []byte) ([]byte, module.CK_RV), fn string) []byte {
	t.Helper()

	var emitted []byte
	for i, part := range dualPartsOf(t, data) {
		out, rv := update(part)
		requireRV(t, module.CKR_OK, rv,
			fmt.Sprintf("%s part %d (%d bytes) should return CKR_OK", fn, i, len(part)))
		emitted = append(emitted, out...)
	}
	return emitted
}

// assertCiphertextTracksInput pins an encryption half to the input it was
// actually given, at a single fixed IV.
//
// It asserts two things about the same ciphertext: that it is exactly what
// crypto/cipher's AES-GCM produces for supplied, and that it is NOT what
// AES-GCM produces for other under the same key and IV. The first alone would
// pass for an encryption that ignores the mechanism parameters; the second
// alone would pass for an encryption that returns anything at all. Together
// they say the encryption half read the caller's data, which is the half of
// "both operations really ran" that a digest or a signature cannot speak for.
func assertCiphertextTracksInput(t *testing.T, key, iv, ciphertext, supplied, other []byte,
	fn string) {
	t.Helper()

	if bytes.Equal(supplied, other) {
		t.Fatalf("%s: the two inputs being compared are identical, so the check "+
			"cannot fail", fn)
	}

	want := aesGCMSeal(t, key, iv, supplied, nil)
	if !bytes.Equal(ciphertext, want) {
		t.Fatalf("%s: the ciphertext disagrees with the AES-GCM oracle over the input "+
			"that was supplied\n got %x\nwant %x", fn, ciphertext, want)
	}

	if notWant := aesGCMSeal(t, key, iv, other, nil); bytes.Equal(ciphertext, notWant) {
		t.Fatalf("%s: the ciphertext is what the oracle produces for a DIFFERENT input "+
			"under the same key and IV; the encryption half did not read the caller's data", fn)
	}
}

// assertUpdateFinalAccounting checks that the two calls of a multiple-part
// operation between them produced the whole expected output, and pins which
// call produced it.
//
// PKCS#11 permits an update to emit nothing: §5.17.1 and §5.17.2 both provide
// for a call that "does not produce" output, and an AEAD mechanism such as
// CKM_AES_GCM cannot release anything before it has authenticated the tag, so
// under AES-GCM the updates legitimately emit zero bytes and the final emits
// everything.
//
// What must never happen is for "empty" to be accepted as "correct". An earlier
// version of these tests took the zero bytes an AES-GCM update returned and fed
// them onward, then reported success over nothing at all. So when the updates
// emit nothing this insists the final produced the complete result, and when
// they do emit something it insists the pieces still add up. Either way some
// call has to have produced the full output.
func assertUpdateFinalAccounting(t *testing.T, updateOut, finalOut, want []byte, fn string) {
	t.Helper()

	got := dualConcat(updateOut, finalOut)
	if !bytes.Equal(got, want) {
		t.Fatalf("%s: the operation emitted %d bytes across its updates and %d at its "+
			"final, %d in total, but the expected output is %d bytes\n got %x\nwant %x",
			fn, len(updateOut), len(finalOut), len(got), len(want), got, want)
	}

	if len(want) == 0 {
		t.Fatalf("%s: the accounting check was given an empty expectation, which no "+
			"output can fail", fn)
	}

	if len(updateOut) == 0 && len(finalOut) != len(want) {
		t.Fatalf("%s: the updates produced no output, so the final call had to produce "+
			"the whole %d-byte result; it produced %d bytes",
			fn, len(want), len(finalOut))
	}
}
