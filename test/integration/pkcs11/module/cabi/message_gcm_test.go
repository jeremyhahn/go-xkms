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

// TestMessageGCMWritesBackAGeneratedIV proves C_EncryptMessage returns the IV
// it generated through CK_GCM_MESSAGE_PARAMS.
//
// With ivGenerator set to CKG_GENERATE the token chooses the IV, and pIv is an
// output (PKCS#11 v3.2 section 6.13.5). A module that reads the struct but
// never writes to it makes the round trip impossible: the caller holds
// ciphertext it can never decrypt, because the IV that produced it was
// discarded inside the module. That is precisely why this defect stayed
// invisible, since a test that supplies its own IV never exercises the
// write-back at all.
func TestMessageGCMWritesBackAGeneratedIV(t *testing.T) {
	f := NewFixture(t)
	if !f.Module.HasV3() {
		t.Fatalf("the module at %s returned a v2.40 function list, which has no message-based functions", f.Module.Path())
	}

	key := generateAESKey(t, f, 32)
	plaintext := []byte("message-based AEAD must return its IV")
	aad := []byte("message-gcm-aad")

	if err := f.Session.MessageEncryptInit(CKM_AES_GCM, nil, key); err != nil {
		t.Fatalf("C_MessageEncryptInit: %v", err)
	}

	// The buffers are sized but zeroed: everything the caller learns about the
	// IV and tag has to come back through the struct.
	params := &GCMMessageParams{
		IV:          make([]byte, 12),
		IVGenerator: CKG_GENERATE,
		Tag:         make([]byte, 16),
		TagBits:     128,
	}

	ciphertext, err := f.Session.EncryptMessageOnce(params, aad, plaintext, uint(len(plaintext)))
	if err != nil {
		t.Fatalf("C_EncryptMessage with ivGenerator=CKG_GENERATE: %v", err)
	}
	if err := f.Session.MessageEncryptFinal(); err != nil {
		t.Fatalf("C_MessageEncryptFinal: %v", err)
	}

	if bytes.Equal(params.IV, make([]byte, 12)) {
		t.Fatal("C_EncryptMessage left pIv all zero after being asked to generate an IV. " +
			"The generated IV was never written back, so the caller cannot decrypt the ciphertext it just received " +
			"and cannot transmit the IV to a peer.")
	}
	if bytes.Equal(params.Tag, make([]byte, 16)) {
		t.Fatal("C_EncryptMessage left pTag all zero. The authentication tag is an output of the operation, " +
			"so without it the ciphertext can never be authenticated.")
	}
	if len(ciphertext) != len(plaintext) {
		t.Fatalf("C_EncryptMessage returned %d ciphertext bytes for a %d-byte plaintext; the message-based form carries the tag in pTag rather than appended to the ciphertext",
			len(ciphertext), len(plaintext))
	}
}

// TestMessageGCMRoundTripWithAGeneratedIV proves the written-back IV and tag
// are the ones that actually authenticate the ciphertext.
//
// Non-zero bytes in the struct are not enough: a module could write arbitrary
// values back. Feeding exactly those values to C_DecryptMessage and recovering
// the plaintext is what shows they are the real ones, and it is the round trip
// that was impossible before the write-back existed.
func TestMessageGCMRoundTripWithAGeneratedIV(t *testing.T) {
	f := NewFixture(t)
	if !f.Module.HasV3() {
		t.Fatalf("the module at %s returned a v2.40 function list, which has no message-based functions", f.Module.Path())
	}

	key := generateAESKey(t, f, 32)
	plaintext := []byte("round trip through a token-generated nonce")
	aad := []byte("round-trip-aad")

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
	recovered, err := f.Session.DecryptMessage(decryptParams, aad, ciphertext, uint(len(plaintext)))
	if err != nil {
		t.Fatalf("C_DecryptMessage with the IV and tag C_EncryptMessage wrote back: %v", err)
	}
	if err := f.Session.MessageDecryptFinal(); err != nil {
		t.Fatalf("C_MessageDecryptFinal: %v", err)
	}

	if !bytes.Equal(recovered, plaintext) {
		t.Fatalf("C_DecryptMessage returned %q, want %q", recovered, plaintext)
	}
}

// TestMessageGCMEncryptsSeveralMessagesPerInit proves the message-based
// interface accepts more than one message per initialization, and that each
// gets a distinct generated IV.
//
// Amortizing one C_MessageEncryptInit over many messages is the entire reason
// the message-based functions exist (PKCS#11 v3.2 section 5.9.1): the
// operation stays active until C_MessageEncryptFinal, and C_EncryptMessage may
// be called repeatedly in between. A module that ends the operation after the
// first message gives a caller no benefit over C_EncryptInit and breaks any
// application written to the documented shape.
//
// The second assertion is nonce uniqueness. A generated IV that repeats under
// one key is the worst outcome this interface can produce, because the caller
// has explicitly delegated nonce management to the token and has no way to
// notice.
func TestMessageGCMEncryptsSeveralMessagesPerInit(t *testing.T) {
	f := NewFixture(t)
	if !f.Module.HasV3() {
		t.Fatalf("the module at %s returned a v2.40 function list, which has no message-based functions", f.Module.Path())
	}

	key := generateAESKey(t, f, 32)
	plaintext := []byte("nonce uniqueness")

	if err := f.Session.MessageEncryptInit(CKM_AES_GCM, nil, key); err != nil {
		t.Fatalf("C_MessageEncryptInit: %v", err)
	}

	seen := make(map[string]bool)
	for i := 0; i < 4; i++ {
		params := &GCMMessageParams{
			IV:          make([]byte, 12),
			IVGenerator: CKG_GENERATE,
			Tag:         make([]byte, 16),
			TagBits:     128,
		}
		if _, err := f.Session.EncryptMessageOnce(params, nil, plaintext, uint(len(plaintext))); err != nil {
			if got := RV(err); got == CKR_OPERATION_NOT_INITIALIZED && i > 0 {
				t.Fatalf("C_EncryptMessage number %d returned CKR_OPERATION_NOT_INITIALIZED. "+
					"The message-based operation ended after the first message, but PKCS#11 v3.2 section 5.9.1 keeps it "+
					"active until C_MessageEncryptFinal so that one initialization can serve many messages, which is the "+
					"only reason to use these functions instead of C_EncryptInit.", i+1)
			}
			t.Fatalf("C_EncryptMessage number %d: %v", i+1, err)
		}
		if seen[string(params.IV)] {
			t.Fatalf("C_EncryptMessage generated the IV %x twice under one key; repeating a GCM nonce leaks the XOR of the plaintexts and the authentication subkey",
				params.IV)
		}
		seen[string(params.IV)] = true
	}

	if err := f.Session.MessageEncryptFinal(); err != nil {
		t.Fatalf("C_MessageEncryptFinal: %v", err)
	}
}

// TestMessageGCMRejectsTruncatedParameters proves the message functions honour
// ulParameterLen for CK_GCM_MESSAGE_PARAMS.
//
// The struct begins and ends with pointers that the module writes through.
// Trusting a length the caller declared shorter than the struct would mean
// writing the generated IV and tag past the end of caller memory, which is a
// corruption rather than merely a wrong answer.
func TestMessageGCMRejectsTruncatedParameters(t *testing.T) {
	f := NewFixture(t)
	if !f.Module.HasV3() {
		t.Fatalf("the module at %s returned a v2.40 function list, which has no message-based functions", f.Module.Path())
	}

	key := generateAESKey(t, f, 32)
	if err := f.Session.MessageEncryptInit(CKM_AES_GCM, nil, key); err != nil {
		t.Fatalf("C_MessageEncryptInit: %v", err)
	}

	params := &GCMMessageParams{
		IV:          make([]byte, 12),
		IVGenerator: CKG_GENERATE,
		Tag:         make([]byte, 16),
		TagBits:     128,
	}

	// SizeOfGCMMessageParams is read from the module's own header so the
	// truncation stays a truncation on any word size.
	_, err := f.Session.EncryptMessageTruncated(params, nil, []byte("x"), 1, SizeOfGCMMessageParams()-8)
	if err == nil {
		t.Fatal("C_EncryptMessage accepted a CK_GCM_MESSAGE_PARAMS declared shorter than the struct; the generated IV and tag would be written past the end of caller memory")
	}
	if got := RV(err); got != CKR_MECHANISM_PARAM_INVALID && got != CKR_ARGUMENTS_BAD {
		t.Fatalf("C_EncryptMessage with a truncated CK_GCM_MESSAGE_PARAMS returned %s (0x%08X), want CKR_MECHANISM_PARAM_INVALID or CKR_ARGUMENTS_BAD",
			rvName(got), got)
	}
}
