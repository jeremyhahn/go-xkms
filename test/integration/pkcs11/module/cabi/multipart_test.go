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
	"testing"
)

// multipartIV is the 12-byte GCM nonce the tests below encrypt under. Each test
// generates its own key, so the nonce can be fixed: the (key, IV) pair is still
// used exactly once, which is what CryptoManager's nonce-reuse guard requires
// and what makes an exact comparison against crypto/cipher possible.
var multipartIV = []byte{0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b}

// TestEncryptUpdate_LengthQueryDoesNotConsumeThePart proves that the NULL-output
// length query on C_EncryptUpdate leaves the operation's buffer untouched, so
// the caller's retry with a real buffer contributes its part exactly once.
//
// This is the C ABI's problem alone and cannot be reached from Go. Every other
// suite calls pkg/pkcs11/module directly, where there is no output pointer and
// therefore no length query to get wrong; the two-call convention only exists
// once the operation is expressed in C, in cmd/pkcs11-module/exports.go. The
// probe is not hypothetical either -- OpenSSL's pkcs11-provider issues exactly
// this sequence, so a module that mishandles it corrupts data for the most
// common real caller it has.
//
// The failure mode being guarded against is silent: C_EncryptUpdate answered
// CKR_OK for both calls, C_EncryptFinal answered CKR_OK, and the ciphertext was
// well-formed -- it just decrypted to the plaintext twice over. Nothing short of
// checking the recovered bytes catches it, which is why this test compares
// against an independent oracle rather than asserting return values.
func TestEncryptUpdate_LengthQueryDoesNotConsumeThePart(t *testing.T) {
	f := NewFixture(t)
	key := generateAESKey(t, f, 32)
	keyBytes := readSecretValue(t, f, key)

	part := []byte("one part, encrypted exactly once")

	if err := f.Session.EncryptInit(CKM_AES_GCM, AESGCMParams{IV: multipartIV, TagBits: 128}, key); err != nil {
		t.Fatalf("C_EncryptInit CKM_AES_GCM: %v", err)
	}

	// The length query. A buffering update emits nothing until C_EncryptFinal,
	// so the only conforming answer is zero.
	probed, err := f.Session.EncryptUpdateProbe(part)
	if err != nil {
		t.Fatalf("C_EncryptUpdate with a NULL output buffer: %v; PKCS#11 v3.2 section 5.2 requires a length query to succeed", err)
	}
	if probed != 0 {
		t.Fatalf("C_EncryptUpdate with a NULL output buffer reported %d bytes of output; a buffering update emits nothing until C_EncryptFinal, so it must report 0", probed)
	}

	// The retry the length query exists to inform.
	if _, written, err := f.Session.EncryptUpdateInto(part, probed); err != nil {
		t.Fatalf("C_EncryptUpdate with a real output buffer: %v", err)
	} else if written != 0 {
		t.Errorf("C_EncryptUpdate wrote %d bytes; it reported 0 on the length query, so writing anything contradicts the size the caller allocated to", written)
	}

	ciphertext, err := f.Session.EncryptFinal()
	if err != nil {
		t.Fatalf("C_EncryptFinal: %v", err)
	}

	oracle := gcmOracle(t, keyBytes, 16)
	want := oracle.Seal(nil, multipartIV, part, nil)
	if bytes.Equal(ciphertext, want) {
		return
	}

	// Name the specific defect when the output matches the doubled plaintext,
	// so a failure reads as the regression it is rather than as a generic
	// mismatch.
	if doubled := oracle.Seal(nil, multipartIV, append(append([]byte{}, part...), part...), nil); bytes.Equal(ciphertext, doubled) {
		t.Fatalf("C_EncryptFinal returned the encryption of the part TWICE (%d bytes for a %d-byte part): "+
			"the NULL-output length query on C_EncryptUpdate appended the caller's plaintext to the operation buffer, "+
			"and the caller's retry appended it again", len(ciphertext), len(part))
	}
	t.Fatalf("C_EncryptFinal produced\n  %x\ncrypto/cipher produced\n  %x\nunder the same key, IV and single part", ciphertext, want)
}

// TestEncryptUpdate_MultiPartRoundTripRecoversOnePart is the decrypting half of
// the proof above: the ciphertext the module produced must come back as exactly
// the bytes that went in, through the module's own decryption path.
//
// The oracle comparison already pins the ciphertext, but it does so against a
// key read out of the token. This one holds the module to its own output, so a
// module that encrypted and decrypted consistently-but-wrongly still fails on
// the length: a doubled part decrypts to twice as many bytes as were supplied.
func TestEncryptUpdate_MultiPartRoundTripRecoversOnePart(t *testing.T) {
	f := NewFixture(t)
	key := generateAESKey(t, f, 32)

	part := []byte("round trip must yield one part")

	if err := f.Session.EncryptInit(CKM_AES_GCM, AESGCMParams{IV: multipartIV, TagBits: 128}, key); err != nil {
		t.Fatalf("C_EncryptInit CKM_AES_GCM: %v", err)
	}
	probed, err := f.Session.EncryptUpdateProbe(part)
	if err != nil {
		t.Fatalf("C_EncryptUpdate with a NULL output buffer: %v", err)
	}
	if _, _, err := f.Session.EncryptUpdateInto(part, probed); err != nil {
		t.Fatalf("C_EncryptUpdate with a real output buffer: %v", err)
	}
	ciphertext, err := f.Session.EncryptFinal()
	if err != nil {
		t.Fatalf("C_EncryptFinal: %v", err)
	}

	if err := f.Session.DecryptInit(CKM_AES_GCM, AESGCMParams{IV: multipartIV, TagBits: 128}, key); err != nil {
		t.Fatalf("C_DecryptInit CKM_AES_GCM: %v", err)
	}
	recovered, err := f.Session.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("C_Decrypt of the multi-part ciphertext: %v", err)
	}

	if len(recovered) == 2*len(part) {
		t.Fatalf("the multi-part ciphertext decrypted to %d bytes for a %d-byte part: the part was encrypted twice, "+
			"which is what a NULL-output C_EncryptUpdate length query does when it forwards the caller's plaintext", len(recovered), len(part))
	}
	if !bytes.Equal(recovered, part) {
		t.Fatalf("the multi-part ciphertext decrypted to\n  %q\nwant\n  %q", recovered, part)
	}
}

// TestDecryptUpdate_LengthQueryDoesNotConsumeThePart is the decrypt-side
// counterpart of TestEncryptUpdate_LengthQueryDoesNotConsumeThePart.
//
// C_DecryptUpdate buffers identically, so the same probe would feed the token
// the ciphertext twice. Under GCM that is not silent -- the concatenation fails
// the tag check -- but it fails at C_DecryptFinal, several calls after the call
// that actually broke, which is exactly the kind of failure that gets
// misattributed. The ciphertext is sealed by crypto/cipher rather than by the
// module so that this test depends on nothing the encrypt path does.
func TestDecryptUpdate_LengthQueryDoesNotConsumeThePart(t *testing.T) {
	f := NewFixture(t)
	key := generateAESKey(t, f, 32)
	keyBytes := readSecretValue(t, f, key)

	plaintext := []byte("sealed outside, decrypted in parts")
	ciphertext := gcmOracle(t, keyBytes, 16).Seal(nil, multipartIV, plaintext, nil)

	if err := f.Session.DecryptInit(CKM_AES_GCM, AESGCMParams{IV: multipartIV, TagBits: 128}, key); err != nil {
		t.Fatalf("C_DecryptInit CKM_AES_GCM: %v", err)
	}

	probed, err := f.Session.DecryptUpdateProbe(ciphertext)
	if err != nil {
		t.Fatalf("C_DecryptUpdate with a NULL output buffer: %v; PKCS#11 v3.2 section 5.2 requires a length query to succeed", err)
	}
	if probed != 0 {
		t.Fatalf("C_DecryptUpdate with a NULL output buffer reported %d bytes of output; a buffering update emits nothing until C_DecryptFinal, so it must report 0", probed)
	}

	if _, written, err := f.Session.DecryptUpdateInto(ciphertext, probed); err != nil {
		t.Fatalf("C_DecryptUpdate with a real output buffer: %v", err)
	} else if written != 0 {
		t.Errorf("C_DecryptUpdate wrote %d bytes; it reported 0 on the length query", written)
	}

	recovered, err := f.Session.DecryptFinal()
	if err != nil {
		t.Fatalf("C_DecryptFinal: %v; the operation buffer most likely holds the ciphertext twice, because the "+
			"NULL-output length query on C_DecryptUpdate forwarded it before the caller's retry did", err)
	}
	if !bytes.Equal(recovered, plaintext) {
		t.Fatalf("C_DecryptFinal recovered\n  %q\nwant\n  %q", recovered, plaintext)
	}
}
