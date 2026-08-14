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
	"crypto/aes"
	"crypto/cipher"
	"testing"
)

// gcmOracle builds an independent AES-GCM instance from the key material the
// token holds, so the module's ciphertext can be compared against a value the
// module had no part in producing.
func gcmOracle(t *testing.T, key []byte, tagBytes int) cipher.AEAD {
	t.Helper()

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("building the AES oracle: %v", err)
	}
	aead, err := cipher.NewGCMWithTagSize(block, tagBytes)
	if err != nil {
		t.Fatalf("building the GCM oracle with a %d-byte tag: %v", tagBytes, err)
	}
	return aead
}

// gcmEncrypt runs one C_EncryptInit/C_Encrypt pair under CK_GCM_PARAMS.
func gcmEncrypt(t *testing.T, f *Fixture, key uint, params AESGCMParams, plaintext []byte) []byte {
	t.Helper()

	if err := f.Session.EncryptInit(CKM_AES_GCM, params, key); err != nil {
		t.Fatalf("C_EncryptInit with IV %x, AAD %q, ulTagBits %d: %v", params.IV, params.AAD, params.TagBits, err)
	}
	out, err := f.Session.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("C_Encrypt with IV %x, AAD %q, ulTagBits %d: %v", params.IV, params.AAD, params.TagBits, err)
	}
	return out
}

// TestAESGCMMatchesAnIndependentOracle proves the IV and the key reach the
// cipher, by comparing the module's output byte for byte against
// crypto/cipher.
//
// AES-GCM is deterministic given key, IV, AAD and plaintext, so this is an
// exact equality rather than a round trip: a round trip through one
// implementation agrees with itself no matter which parameters it dropped.
// The AAD is left empty here so that the check isolates the IV path; the AAD
// has its own test below.
func TestAESGCMMatchesAnIndependentOracle(t *testing.T) {
	f := NewFixture(t)
	key := generateAESKey(t, f, 32)
	keyBytes := readSecretValue(t, f, key)

	iv := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b}
	plaintext := []byte("AES-GCM parameters must survive the C ABI")

	got := gcmEncrypt(t, f, key, AESGCMParams{IV: iv, TagBits: 128}, plaintext)
	want := gcmOracle(t, keyBytes, 16).Seal(nil, iv, plaintext, nil)

	if !bytes.Equal(got, want) {
		t.Fatalf("C_Encrypt produced\n  %x\ncrypto/cipher produced\n  %x\nunder the same key and IV: a CK_GCM_PARAMS field did not cross the C ABI",
			got, want)
	}
}

// TestAESGCMIVCrossesTheABI proves pIv and ulIvLen reach the cipher.
//
// Reusing a GCM IV across two messages under one key is catastrophic, so a
// module that substituted its own IV for the caller's would silently break the
// caller's entire nonce discipline while still returning valid-looking
// ciphertext. Each encryption is checked against an oracle using that same IV,
// which pins the value rather than merely observing that two outputs differ.
func TestAESGCMIVCrossesTheABI(t *testing.T) {
	f := NewFixture(t)
	key := generateAESKey(t, f, 32)
	keyBytes := readSecretValue(t, f, key)

	plaintext := []byte("the caller chooses the nonce")
	ivA := []byte("iv-alpha--01")
	ivB := []byte("iv-bravo--02")

	first := gcmEncrypt(t, f, key, AESGCMParams{IV: ivA, TagBits: 128}, plaintext)
	second := gcmEncrypt(t, f, key, AESGCMParams{IV: ivB, TagBits: 128}, plaintext)

	if bytes.Equal(first, second) {
		t.Fatal("encrypting under two different IVs produced identical output: pIv did not cross the C ABI")
	}

	aead := gcmOracle(t, keyBytes, 16)
	if want := aead.Seal(nil, ivA, plaintext, nil); !bytes.Equal(first, want) {
		t.Fatalf("the ciphertext under IV %x does not match crypto/cipher:\n  got  %x\n  want %x", ivA, first, want)
	}
	if want := aead.Seal(nil, ivB, plaintext, nil); !bytes.Equal(second, want) {
		t.Fatalf("the ciphertext under IV %x does not match crypto/cipher:\n  got  %x\n  want %x", ivB, second, want)
	}
}

// TestAESGCMDecryptsAnExternallySealedMessage proves the decryption path reads
// the IV out of CK_GCM_PARAMS.
//
// The ciphertext comes from crypto/cipher, so the module cannot recover the
// plaintext unless the IV it parsed matches the one the oracle sealed with.
func TestAESGCMDecryptsAnExternallySealedMessage(t *testing.T) {
	f := NewFixture(t)
	key := generateAESKey(t, f, 32)
	keyBytes := readSecretValue(t, f, key)

	iv := []byte("dec-iv-12byt")
	plaintext := []byte("sealed outside the module")
	ciphertext := gcmOracle(t, keyBytes, 16).Seal(nil, iv, plaintext, nil)

	if err := f.Session.DecryptInit(CKM_AES_GCM, AESGCMParams{IV: iv, TagBits: 128}, key); err != nil {
		t.Fatalf("C_DecryptInit: %v", err)
	}
	recovered, err := f.Session.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("C_Decrypt of an externally sealed message: %v", err)
	}
	if !bytes.Equal(recovered, plaintext) {
		t.Fatalf("C_Decrypt returned %q, want %q", recovered, plaintext)
	}
}

// TestAESGCMDetectsATamperedCiphertext proves the tag really is verified.
//
// Flipping one bit of the ciphertext must make decryption fail. Without this,
// a module that returned the decrypted bytes without checking the tag would
// pass every other test in this file, and AES-GCM would provide confidentiality
// with no integrity at all.
func TestAESGCMDetectsATamperedCiphertext(t *testing.T) {
	f := NewFixture(t)
	key := generateAESKey(t, f, 32)
	keyBytes := readSecretValue(t, f, key)

	iv := []byte("tamper-iv-12")
	plaintext := []byte("integrity must be checked")
	ciphertext := gcmOracle(t, keyBytes, 16).Seal(nil, iv, plaintext, nil)

	tampered := bytes.Clone(ciphertext)
	tampered[0] ^= 0x01

	if err := f.Session.DecryptInit(CKM_AES_GCM, AESGCMParams{IV: iv, TagBits: 128}, key); err != nil {
		t.Fatalf("C_DecryptInit: %v", err)
	}
	recovered, err := f.Session.Decrypt(tampered)
	if err == nil {
		t.Fatalf("C_Decrypt returned %q for a ciphertext with a flipped bit: the GCM tag is not being verified", recovered)
	}
}

// TestAESGCMAADCrossesTheABI proves pAAD and ulAADLen reach the cipher.
//
// The additional authenticated data does not change the encrypted bytes, only
// the tag, so a module that accepted the AAD and discarded it still returns a
// plausible ciphertext of exactly the right length. Comparing against two
// oracles, one sealed with the caller's AAD and one sealed with none,
// distinguishes "the AAD was used" from "the AAD was dropped" and says which.
//
// An application that binds a ciphertext to a header, a key identifier or a
// tenant with the AAD gets none of that binding if the field is dropped, and
// its ciphertexts do not interoperate with any conforming peer.
func TestAESGCMAADCrossesTheABI(t *testing.T) {
	f := NewFixture(t)
	key := generateAESKey(t, f, 32)
	keyBytes := readSecretValue(t, f, key)

	iv := []byte("gcm-aad-iv12")
	aad := []byte("go-xkms/cabi/gcm/associated-data")
	plaintext := []byte("the AAD must reach the tag computation")

	got := gcmEncrypt(t, f, key, AESGCMParams{IV: iv, AAD: aad, TagBits: 128}, plaintext)

	aead := gcmOracle(t, keyBytes, 16)
	withAAD := aead.Seal(nil, iv, plaintext, aad)
	withoutAAD := aead.Seal(nil, iv, plaintext, nil)

	if bytes.Equal(got, withAAD) {
		return
	}
	if bytes.Equal(got, withoutAAD) {
		t.Fatalf("C_Encrypt sealed with an EMPTY AAD while %d bytes of pAAD were supplied. "+
			"The encrypted bytes match crypto/cipher but the tag is computed over no associated data, so the AAD "+
			"contributes nothing to integrity and the ciphertext does not interoperate with a conforming peer.\n"+
			"  module            %x\n  oracle with AAD   %x\n  oracle without    %x",
			len(aad), got, withAAD, withoutAAD)
	}
	t.Fatalf("C_Encrypt matched neither oracle:\n  module          %x\n  oracle with AAD %x\n  oracle no AAD   %x",
		got, withAAD, withoutAAD)
}

// TestAESGCMTagBitsCrossesTheABI proves ulTagBits reaches the cipher.
//
// A shortened tag is a deliberate, negotiated choice: a peer that agreed on a
// 96-bit tag rejects a 128-bit one. A module that ignores ulTagBits and always
// emits a full tag returns more bytes than the caller asked for, and the
// mismatch surfaces only at the far end of a protocol exchange.
func TestAESGCMTagBitsCrossesTheABI(t *testing.T) {
	f := NewFixture(t)
	key := generateAESKey(t, f, 32)
	keyBytes := readSecretValue(t, f, key)

	iv := []byte("gcm-tag-iv12")
	plaintext := []byte("shortened authentication tag")

	const tagBits = 96
	got := gcmEncrypt(t, f, key, AESGCMParams{IV: iv, TagBits: tagBits}, plaintext)

	wantLen := len(plaintext) + tagBits/8
	if len(got) != wantLen {
		t.Fatalf("C_Encrypt returned %d bytes for a %d-byte plaintext with ulTagBits=%d, want %d. "+
			"The tag is %d bytes rather than the requested %d, so ulTagBits did not cross the C ABI and a peer "+
			"expecting the negotiated tag length rejects the result.",
			len(got), len(plaintext), tagBits, wantLen, len(got)-len(plaintext), tagBits/8)
	}

	want := gcmOracle(t, keyBytes, tagBits/8).Seal(nil, iv, plaintext, nil)
	if !bytes.Equal(got, want) {
		t.Fatalf("the %d-bit-tag ciphertext does not match crypto/cipher:\n  got  %x\n  want %x", tagBits, got, want)
	}
}

// TestAESGCMRejectsIVReuse proves the module refuses to encrypt twice under
// the same key and IV.
//
// Repeating a GCM nonce under one key reveals the XOR of the two plaintexts
// and leaks the authentication subkey, so refusing is the right behaviour and
// worth locking down: it is exactly the kind of protection that a later
// refactor could remove without any other test noticing.
func TestAESGCMRejectsIVReuse(t *testing.T) {
	f := NewFixture(t)
	key := generateAESKey(t, f, 32)

	iv := []byte("reuse-iv-123")
	params := AESGCMParams{IV: iv, TagBits: 128}

	if err := f.Session.EncryptInit(CKM_AES_GCM, params, key); err != nil {
		t.Fatalf("the first C_EncryptInit failed: %v", err)
	}
	if _, err := f.Session.Encrypt([]byte("first message")); err != nil {
		t.Fatalf("the first C_Encrypt failed: %v", err)
	}

	err := f.Session.EncryptInit(CKM_AES_GCM, params, key)
	if err == nil {
		_, err = f.Session.Encrypt([]byte("second message"))
	}
	if err == nil {
		t.Fatal("the module encrypted twice under the same key and IV; repeating a GCM nonce leaks the XOR of the plaintexts and the authentication subkey")
	}
}

// TestAESGCMRejectsTruncatedParameters proves the boundary honours
// ulParameterLen for CK_GCM_PARAMS.
//
// CK_GCM_PARAMS begins with a pointer. A parser that read the whole struct out
// of a buffer the caller declared smaller would dereference whatever follows
// in caller memory. Accepting the call instead of refusing it is the same
// "accepted, then quietly defaulted" shape that hid the earlier parameter
// defects: the operation proceeds under values the caller never supplied.
func TestAESGCMRejectsTruncatedParameters(t *testing.T) {
	f := NewFixture(t)
	key := generateAESKey(t, f, 32)

	full := AESGCMParams{IV: []byte("trunc-iv-123"), AAD: []byte("a"), TagBits: 128}
	truncated := TruncatedParams{Params: full, Length: 8}

	err := f.Session.EncryptInit(CKM_AES_GCM, truncated, key)
	if err == nil {
		t.Fatal("C_EncryptInit accepted a CK_GCM_PARAMS declared as only 8 bytes; the operation proceeds under an IV and tag length the caller never supplied")
	}
	if got := RV(err); got != CKR_MECHANISM_PARAM_INVALID && got != CKR_ARGUMENTS_BAD {
		t.Fatalf("C_EncryptInit with a truncated CK_GCM_PARAMS returned %s (0x%08X), want CKR_MECHANISM_PARAM_INVALID or CKR_ARGUMENTS_BAD",
			rvName(got), got)
	}
}
