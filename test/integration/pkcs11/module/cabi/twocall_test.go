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

//go:build integration && pkcs11_cabi

package cabi

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

// TestTwoCallSignProbeDoesNotTerminateTheOperation asserts the core rule of
// the two-call convention (PKCS#11 v3.2 section 5.2).
//
// A call with a NULL output buffer returns the required length and leaves the
// operation active, so the caller can immediately make the real call. A module
// that finalized the operation on the probe would force every conforming
// application, which always probes first, into CKR_OPERATION_NOT_INITIALIZED
// on the second call. CKM_RSA_PKCS is used because it is deterministic, so the
// probe and the real call are directly comparable.
func TestTwoCallSignProbeDoesNotTerminateTheOperation(t *testing.T) {
	f := NewFixture(t)
	pub, priv := generateRSAKeyPair(t, f, 2048)
	pubKey := readRSAPublicKey(t, f, pub)

	digest := sha256.Sum256([]byte("two-call sign probe"))

	if err := f.Session.SignInit(CKM_RSA_PKCS, nil, priv); err != nil {
		t.Fatalf("C_SignInit: %v", err)
	}

	required, err := f.Session.SignProbe(digest[:])
	if err != nil {
		t.Fatalf("C_Sign with a NULL pSignature must return CKR_OK and the required length, but it returned %s (0x%08X)",
			rvName(RV(err)), RV(err))
	}
	wantLen := uint(pubKey.Size())
	if required != wantLen {
		t.Fatalf("C_Sign with a NULL pSignature reported %d bytes, want %d for a %d-bit key",
			required, wantLen, pubKey.N.BitLen())
	}

	sig, reported, err := f.Session.SignInto(digest[:], required)
	if err != nil {
		t.Fatalf("the second C_Sign after a NULL-buffer probe failed with %s (0x%08X); the probe terminated the operation, which PKCS#11 v3.2 section 5.2 forbids",
			rvName(RV(err)), RV(err))
	}
	if reported != wantLen || uint(len(sig)) != wantLen {
		t.Fatalf("the second C_Sign reported %d bytes and returned %d, want %d", reported, len(sig), wantLen)
	}
}

// TestTwoCallSignBufferTooSmallDoesNotTerminateTheOperation asserts the other
// half of the convention.
//
// When the supplied buffer is too small the module returns
// CKR_BUFFER_TOO_SMALL, sets the required length, and leaves the operation
// active so the caller can retry with a larger buffer. Terminating instead
// turns a recoverable sizing mistake into a lost operation, and the caller has
// no way to distinguish the two without trying.
func TestTwoCallSignBufferTooSmallDoesNotTerminateTheOperation(t *testing.T) {
	f := NewFixture(t)
	pub, priv := generateRSAKeyPair(t, f, 2048)
	pubKey := readRSAPublicKey(t, f, pub)
	wantLen := uint(pubKey.Size())

	digest := sha256.Sum256([]byte("two-call buffer too small"))

	if err := f.Session.SignInit(CKM_RSA_PKCS, nil, priv); err != nil {
		t.Fatalf("C_SignInit: %v", err)
	}

	_, reported, err := f.Session.SignInto(digest[:], wantLen-1)
	if err == nil {
		t.Fatalf("C_Sign accepted a %d-byte buffer for a %d-byte signature", wantLen-1, wantLen)
	}
	if got := RV(err); got != CKR_BUFFER_TOO_SMALL {
		t.Fatalf("C_Sign with an undersized buffer returned %s (0x%08X), want CKR_BUFFER_TOO_SMALL", rvName(got), got)
	}
	if reported != wantLen {
		t.Fatalf("C_Sign returning CKR_BUFFER_TOO_SMALL reported %d bytes, want %d; the caller cannot size its retry",
			reported, wantLen)
	}

	sig, _, err := f.Session.SignInto(digest[:], wantLen)
	if err != nil {
		t.Fatalf("the retry after CKR_BUFFER_TOO_SMALL failed with %s (0x%08X); the failed call terminated the operation, which PKCS#11 v3.2 section 5.2 forbids",
			rvName(RV(err)), RV(err))
	}
	if uint(len(sig)) != wantLen {
		t.Fatalf("the retry returned %d bytes, want %d", len(sig), wantLen)
	}
}

// TestTwoCallSignProbeAndRealCallAgree proves the probe does not consume or
// alter the operation's input.
//
// CKM_RSA_PKCS is deterministic, so a probe followed by the real call must
// produce exactly the signature a single call would. A module that fed the
// input to the operation during the probe would sign the data twice over and
// return something else.
func TestTwoCallSignProbeAndRealCallAgree(t *testing.T) {
	f := NewFixture(t)
	pub, priv := generateRSAKeyPair(t, f, 2048)
	pubKey := readRSAPublicKey(t, f, pub)

	digest := sha256.Sum256([]byte("probe must not consume input"))

	if err := f.Session.SignInit(CKM_RSA_PKCS, nil, priv); err != nil {
		t.Fatalf("C_SignInit: %v", err)
	}
	if _, err := f.Session.SignProbe(digest[:]); err != nil {
		t.Fatalf("the NULL-buffer probe failed: %v", err)
	}
	probed, _, err := f.Session.SignInto(digest[:], uint(pubKey.Size()))
	if err != nil {
		t.Fatalf("the real call after a probe failed: %v", err)
	}

	if err := f.Session.SignInit(CKM_RSA_PKCS, nil, priv); err != nil {
		t.Fatalf("C_SignInit for the unprobed comparison: %v", err)
	}
	direct, _, err := f.Session.SignInto(digest[:], uint(pubKey.Size()))
	if err != nil {
		t.Fatalf("the unprobed call failed: %v", err)
	}

	if !bytes.Equal(probed, direct) {
		t.Fatalf("a probed CKM_RSA_PKCS signature differs from an unprobed one:\n  probed   %x\n  unprobed %x\nthe NULL-buffer call altered the operation's state",
			probed, direct)
	}
}

// TestTwoCallEncryptProbeDoesNotTerminateTheOperation applies the convention
// to C_Encrypt.
//
// The rule is stated once in section 5.2 and applies to every function that
// returns a variable-length result, so a module that honours it for C_Sign and
// not for C_Encrypt still breaks conforming callers. AES-GCM is used with a
// caller-supplied IV so the two calls are comparable.
func TestTwoCallEncryptProbeDoesNotTerminateTheOperation(t *testing.T) {
	f := NewFixture(t)
	key := generateAESKey(t, f, 32)

	plaintext := []byte("two-call encrypt probe")
	params := AESGCMParams{IV: []byte("twocall-iv12"), TagBits: 128}

	if err := f.Session.EncryptInit(CKM_AES_GCM, params, key); err != nil {
		t.Fatalf("C_EncryptInit: %v", err)
	}

	required, err := f.Session.EncryptProbe(plaintext)
	if err != nil {
		t.Fatalf("C_Encrypt with a NULL pEncryptedData must return CKR_OK and the required length, but it returned %s (0x%08X)",
			rvName(RV(err)), RV(err))
	}
	if required < uint(len(plaintext)) {
		t.Fatalf("C_Encrypt reported %d bytes for a %d-byte plaintext, which cannot hold the ciphertext and its tag",
			required, len(plaintext))
	}

	out, _, err := f.Session.EncryptInto(plaintext, required)
	if err != nil {
		t.Fatalf("the second C_Encrypt after a NULL-buffer probe failed with %s (0x%08X); the probe terminated the operation, which PKCS#11 v3.2 section 5.2 forbids",
			rvName(RV(err)), RV(err))
	}
	if uint(len(out)) != required {
		t.Fatalf("the second C_Encrypt returned %d bytes after reporting %d", len(out), required)
	}
}

// TestTwoCallEncryptBufferTooSmallDoesNotTerminateTheOperation asserts the
// undersized-buffer half of the convention for C_Encrypt.
func TestTwoCallEncryptBufferTooSmallDoesNotTerminateTheOperation(t *testing.T) {
	f := NewFixture(t)
	key := generateAESKey(t, f, 32)

	plaintext := []byte("two-call encrypt buffer too small")
	params := AESGCMParams{IV: []byte("twocall-iv34"), TagBits: 128}

	if err := f.Session.EncryptInit(CKM_AES_GCM, params, key); err != nil {
		t.Fatalf("C_EncryptInit: %v", err)
	}

	required, err := f.Session.EncryptProbe(plaintext)
	if err != nil {
		t.Fatalf("the NULL-buffer probe failed: %v", err)
	}

	_, reported, err := f.Session.EncryptInto(plaintext, required-1)
	if err == nil {
		t.Fatalf("C_Encrypt accepted a %d-byte buffer for %d bytes of ciphertext", required-1, required)
	}
	if got := RV(err); got != CKR_BUFFER_TOO_SMALL {
		t.Fatalf("C_Encrypt with an undersized buffer returned %s (0x%08X), want CKR_BUFFER_TOO_SMALL", rvName(got), got)
	}
	if reported != required {
		t.Fatalf("C_Encrypt returning CKR_BUFFER_TOO_SMALL reported %d bytes, want %d", reported, required)
	}

	if _, _, err := f.Session.EncryptInto(plaintext, required); err != nil {
		t.Fatalf("the retry after CKR_BUFFER_TOO_SMALL failed with %s (0x%08X); the failed call terminated the operation, which PKCS#11 v3.2 section 5.2 forbids",
			rvName(RV(err)), RV(err))
	}
}

// TestTwoCallGetAttributeValueReportsLength asserts the convention for
// C_GetAttributeValue, which is how every application reads a public key out
// of a token.
//
// A first call with a NULL pValue fills in ulValueLen; the second returns the
// bytes. The Attribute helper this suite uses everywhere depends on that
// behaviour, so proving it here makes the rest of the suite's oracles
// trustworthy.
func TestTwoCallGetAttributeValueReportsLength(t *testing.T) {
	f := NewFixture(t)
	pub, _ := generateRSAKeyPair(t, f, 2048)

	modulus, err := f.Session.Attribute(pub, CKA_MODULUS)
	if err != nil {
		t.Fatalf("reading CKA_MODULUS through the two-call convention: %v", err)
	}
	if len(modulus) != 256 {
		t.Fatalf("CKA_MODULUS of a 2048-bit key is %d bytes, want 256; the length reported by the NULL-pValue call was wrong",
			len(modulus))
	}
}

// TestTwoCallEncryptMessageProbeDoesNotTerminateTheOperation applies the
// convention to C_EncryptMessage.
//
// The message-based functions are covered by section 5.2 exactly as C_Encrypt
// is, and an application reaches them through the same shim that probes for a
// length before allocating. C_EncryptMessage runs the real encryption in order
// to report that length and caches nothing, so unless the probe releases the
// result the operation is left finalized and the second call — the one the
// convention exists to permit — is refused. Every message test in this suite
// used EncryptMessageOnce, which never probes, so nothing exercised this.
//
// The IV is token-generated on purpose: it makes the assertion the round trip
// rather than the return code, so a module that answered CKR_OK on both calls
// while writing back an IV belonging to the discarded first encryption would
// still fail here.
func TestTwoCallEncryptMessageProbeDoesNotTerminateTheOperation(t *testing.T) {
	f := NewFixture(t)
	if !f.Module.HasV3() {
		t.Fatalf("the module at %s returned a v2.40 function list, which has no message-based functions", f.Module.Path())
	}

	key := generateAESKey(t, f, 32)
	plaintext := []byte("two-call C_EncryptMessage probe")
	aad := []byte("two-call-message-aad")

	if err := f.Session.MessageEncryptInit(CKM_AES_GCM, nil, key); err != nil {
		t.Fatalf("C_MessageEncryptInit: %v", err)
	}

	params := &GCMMessageParams{
		IV:          make([]byte, 12),
		IVGenerator: CKG_GENERATE,
		Tag:         make([]byte, 16),
		TagBits:     128,
	}

	ciphertext, err := f.Session.EncryptMessage(params, aad, plaintext)
	if err != nil {
		t.Fatalf("C_EncryptMessage after a NULL-buffer probe failed with %s (0x%08X); the probe terminated the operation, which PKCS#11 v3.2 section 5.2 forbids",
			rvName(RV(err)), RV(err))
	}
	if len(ciphertext) != len(plaintext) {
		t.Fatalf("C_EncryptMessage returned %d ciphertext bytes for a %d-byte plaintext; the message form carries the tag in pTag",
			len(ciphertext), len(plaintext))
	}

	// A second message under the same initialization must still work: the
	// release must rearm the operation, not finalize it, because
	// C_MessageEncryptInit lives until C_MessageEncryptFinal.
	second := &GCMMessageParams{
		IV:          make([]byte, 12),
		IVGenerator: CKG_GENERATE,
		Tag:         make([]byte, 16),
		TagBits:     128,
	}
	if _, err := f.Session.EncryptMessage(second, aad, plaintext); err != nil {
		t.Fatalf("the second probed C_EncryptMessage under one C_MessageEncryptInit failed with %s (0x%08X)",
			rvName(RV(err)), RV(err))
	}
	if err := f.Session.MessageEncryptFinal(); err != nil {
		t.Fatalf("C_MessageEncryptFinal: %v", err)
	}

	// The IV and tag written back belong to the call that produced the
	// ciphertext, or this decryption cannot succeed.
	if err := f.Session.MessageDecryptInit(CKM_AES_GCM, nil, key); err != nil {
		t.Fatalf("C_MessageDecryptInit: %v", err)
	}
	recovered, err := f.Session.DecryptMessage(&GCMMessageParams{
		IV:          params.IV,
		IVGenerator: CKG_NO_GENERATE,
		Tag:         params.Tag,
		TagBits:     params.TagBits,
	}, aad, ciphertext, uint(len(plaintext)))
	if err != nil {
		t.Fatalf("C_DecryptMessage with the IV and tag the probed C_EncryptMessage wrote back failed with %s (0x%08X); the probe and the real call disagreed about which encryption the caller received",
			rvName(RV(err)), RV(err))
	}
	if err := f.Session.MessageDecryptFinal(); err != nil {
		t.Fatalf("C_MessageDecryptFinal: %v", err)
	}
	if !bytes.Equal(recovered, plaintext) {
		t.Fatalf("the round trip through a probed C_EncryptMessage returned %q, want %q", recovered, plaintext)
	}
}

// TestTwoCallEncryptMessageBufferTooSmallDoesNotTerminateTheOperation asserts
// the undersized-buffer half of the convention for C_EncryptMessage.
//
// Section 5.2 gives CKR_BUFFER_TOO_SMALL the same standing as the NULL-buffer
// probe: the operation survives so the caller can retry. The two legs share a
// cause here, because both return without copying and so both must release the
// result the encryption already produced.
func TestTwoCallEncryptMessageBufferTooSmallDoesNotTerminateTheOperation(t *testing.T) {
	f := NewFixture(t)
	if !f.Module.HasV3() {
		t.Fatalf("the module at %s returned a v2.40 function list, which has no message-based functions", f.Module.Path())
	}

	key := generateAESKey(t, f, 32)
	plaintext := []byte("two-call C_EncryptMessage buffer too small")
	aad := []byte("two-call-message-short-aad")

	if err := f.Session.MessageEncryptInit(CKM_AES_GCM, nil, key); err != nil {
		t.Fatalf("C_MessageEncryptInit: %v", err)
	}
	params := &GCMMessageParams{
		IV:          make([]byte, 12),
		IVGenerator: CKG_GENERATE,
		Tag:         make([]byte, 16),
		TagBits:     128,
	}

	_, err := f.Session.EncryptMessageOnce(params, aad, plaintext, uint(len(plaintext))-1)
	if err == nil {
		t.Fatalf("C_EncryptMessage accepted a %d-byte buffer for %d bytes of ciphertext", len(plaintext)-1, len(plaintext))
	}
	if got := RV(err); got != CKR_BUFFER_TOO_SMALL {
		t.Fatalf("C_EncryptMessage with an undersized buffer returned %s (0x%08X), want CKR_BUFFER_TOO_SMALL", rvName(got), got)
	}

	ciphertext, err := f.Session.EncryptMessageOnce(params, aad, plaintext, uint(len(plaintext)))
	if err != nil {
		t.Fatalf("the retry after CKR_BUFFER_TOO_SMALL failed with %s (0x%08X); the refused call terminated the operation, which PKCS#11 v3.2 section 5.2 forbids",
			rvName(RV(err)), RV(err))
	}
	if err := f.Session.MessageEncryptFinal(); err != nil {
		t.Fatalf("C_MessageEncryptFinal: %v", err)
	}

	if err := f.Session.MessageDecryptInit(CKM_AES_GCM, nil, key); err != nil {
		t.Fatalf("C_MessageDecryptInit: %v", err)
	}
	recovered, err := f.Session.DecryptMessage(&GCMMessageParams{
		IV:          params.IV,
		IVGenerator: CKG_NO_GENERATE,
		Tag:         params.Tag,
		TagBits:     params.TagBits,
	}, aad, ciphertext, uint(len(plaintext)))
	if err != nil {
		t.Fatalf("C_DecryptMessage with the IV and tag from the retried encryption: %v", err)
	}
	if err := f.Session.MessageDecryptFinal(); err != nil {
		t.Fatalf("C_MessageDecryptFinal: %v", err)
	}
	if !bytes.Equal(recovered, plaintext) {
		t.Fatalf("the retried encryption round-tripped to %q, want %q", recovered, plaintext)
	}
}

// TestTwoCallDecryptMessageProbeDoesNotTerminateTheOperation applies the
// convention to C_DecryptMessage, the other leg that ran its operation on the
// probe without caching or releasing the result.
//
// The failure this guards against is worse on the decrypt side: the second call
// returned CKR_OPERATION_NOT_INITIALIZED, and the module treats that as reason
// to finalize the operation type, so the whole message process established by
// C_MessageDecryptInit was torn down by a conforming caller doing nothing more
// than asking how large a buffer to allocate.
func TestTwoCallDecryptMessageProbeDoesNotTerminateTheOperation(t *testing.T) {
	f := NewFixture(t)
	if !f.Module.HasV3() {
		t.Fatalf("the module at %s returned a v2.40 function list, which has no message-based functions", f.Module.Path())
	}

	key := generateAESKey(t, f, 32)
	plaintext := []byte("two-call C_DecryptMessage probe")
	aad := []byte("two-call-decrypt-aad")

	if err := f.Session.MessageEncryptInit(CKM_AES_GCM, nil, key); err != nil {
		t.Fatalf("C_MessageEncryptInit: %v", err)
	}
	encryptParams := &GCMMessageParams{
		IV:          make([]byte, 12),
		IVGenerator: CKG_GENERATE,
		Tag:         make([]byte, 16),
		TagBits:     128,
	}
	ciphertext, err := f.Session.EncryptMessageOnce(encryptParams, aad, plaintext, uint(len(plaintext)))
	if err != nil {
		t.Fatalf("C_EncryptMessage: %v", err)
	}
	if err := f.Session.MessageEncryptFinal(); err != nil {
		t.Fatalf("C_MessageEncryptFinal: %v", err)
	}

	if err := f.Session.MessageDecryptInit(CKM_AES_GCM, nil, key); err != nil {
		t.Fatalf("C_MessageDecryptInit: %v", err)
	}
	decryptParams := &GCMMessageParams{
		IV:          encryptParams.IV,
		IVGenerator: CKG_NO_GENERATE,
		Tag:         encryptParams.Tag,
		TagBits:     encryptParams.TagBits,
	}

	required, err := f.Session.DecryptMessageProbe(decryptParams, aad, ciphertext)
	if err != nil {
		t.Fatalf("C_DecryptMessage with a NULL pPlaintext must return CKR_OK and the required length, but it returned %s (0x%08X)",
			rvName(RV(err)), RV(err))
	}
	if required != uint(len(plaintext)) {
		t.Fatalf("the probe reported %d plaintext bytes for a %d-byte message", required, len(plaintext))
	}

	recovered, err := f.Session.DecryptMessage(decryptParams, aad, ciphertext, required)
	if err != nil {
		t.Fatalf("the second C_DecryptMessage after a NULL-buffer probe failed with %s (0x%08X); the probe terminated the operation, which PKCS#11 v3.2 section 5.2 forbids",
			rvName(RV(err)), RV(err))
	}
	if !bytes.Equal(recovered, plaintext) {
		t.Fatalf("the probed C_DecryptMessage returned %q, want %q", recovered, plaintext)
	}

	// The message process must still be usable, which is what distinguishes
	// releasing the result from finalizing the operation.
	if err := f.Session.MessageDecryptFinal(); err != nil {
		t.Fatalf("C_MessageDecryptFinal after a probed decryption failed: %v; the probe tore down the message process", err)
	}
}

// TestTwoCallDecryptMessageBufferTooSmallDoesNotTerminateTheOperation asserts
// the undersized-buffer half of the convention for C_DecryptMessage.
func TestTwoCallDecryptMessageBufferTooSmallDoesNotTerminateTheOperation(t *testing.T) {
	f := NewFixture(t)
	if !f.Module.HasV3() {
		t.Fatalf("the module at %s returned a v2.40 function list, which has no message-based functions", f.Module.Path())
	}

	key := generateAESKey(t, f, 32)
	plaintext := []byte("two-call C_DecryptMessage buffer too small")
	aad := []byte("two-call-decrypt-short-aad")

	if err := f.Session.MessageEncryptInit(CKM_AES_GCM, nil, key); err != nil {
		t.Fatalf("C_MessageEncryptInit: %v", err)
	}
	encryptParams := &GCMMessageParams{
		IV:          make([]byte, 12),
		IVGenerator: CKG_GENERATE,
		Tag:         make([]byte, 16),
		TagBits:     128,
	}
	ciphertext, err := f.Session.EncryptMessageOnce(encryptParams, aad, plaintext, uint(len(plaintext)))
	if err != nil {
		t.Fatalf("C_EncryptMessage: %v", err)
	}
	if err := f.Session.MessageEncryptFinal(); err != nil {
		t.Fatalf("C_MessageEncryptFinal: %v", err)
	}

	if err := f.Session.MessageDecryptInit(CKM_AES_GCM, nil, key); err != nil {
		t.Fatalf("C_MessageDecryptInit: %v", err)
	}
	decryptParams := &GCMMessageParams{
		IV:          encryptParams.IV,
		IVGenerator: CKG_NO_GENERATE,
		Tag:         encryptParams.Tag,
		TagBits:     encryptParams.TagBits,
	}

	_, err = f.Session.DecryptMessage(decryptParams, aad, ciphertext, uint(len(plaintext))-1)
	if err == nil {
		t.Fatalf("C_DecryptMessage accepted a %d-byte buffer for %d bytes of plaintext", len(plaintext)-1, len(plaintext))
	}
	if got := RV(err); got != CKR_BUFFER_TOO_SMALL {
		t.Fatalf("C_DecryptMessage with an undersized buffer returned %s (0x%08X), want CKR_BUFFER_TOO_SMALL", rvName(got), got)
	}

	recovered, err := f.Session.DecryptMessage(decryptParams, aad, ciphertext, uint(len(plaintext)))
	if err != nil {
		t.Fatalf("the retry after CKR_BUFFER_TOO_SMALL failed with %s (0x%08X); the refused call terminated the operation, which PKCS#11 v3.2 section 5.2 forbids",
			rvName(RV(err)), RV(err))
	}
	if !bytes.Equal(recovered, plaintext) {
		t.Fatalf("the retried C_DecryptMessage returned %q, want %q", recovered, plaintext)
	}
	if err := f.Session.MessageDecryptFinal(); err != nil {
		t.Fatalf("C_MessageDecryptFinal: %v", err)
	}
}
