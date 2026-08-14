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

package wrapping

import (
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mustHex decodes a hex literal used in a known-answer test vector, failing
// the test immediately if the literal itself is malformed.
func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

// The RFC 3394 section 4 known-answer vectors below were independently
// re-derived for this task via the Python `cryptography` library's
// aes_key_wrap (not copied from this Go implementation), so a passing test
// is a genuine oracle check: WrapAESKW must reproduce a wrapping this code
// did not itself produce, under KEKs and key data of every size RFC 3394
// defines (128/192/256-bit KEK over 128/192/256-bit key data).

// TestWrapAESKW_RFC3394_128BitKEK is the RFC 3394 section 4.1 vector: a
// 128-bit KEK wrapping 128-bit key data.
func TestWrapAESKW_RFC3394_128BitKEK(t *testing.T) {
	kek := mustHex(t, "000102030405060708090A0B0C0D0E0F")
	keyData := mustHex(t, "00112233445566778899AABBCCDDEEFF")
	wantCiphertext := mustHex(t, "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5")

	got, err := WrapAESKW(keyData, kek)
	require.NoError(t, err)
	assert.Equal(t, wantCiphertext, got)

	// The oracle runs in both directions: the RFC ciphertext must unwrap
	// back to the original key data under the same KEK.
	recovered, err := UnwrapAESKW(wantCiphertext, kek)
	require.NoError(t, err)
	assert.Equal(t, keyData, recovered)
}

// TestWrapAESKW_RFC3394_192BitKEK is the RFC 3394 section 4.2 vector:
// 128-bit key data wrapped under a 192-bit KEK.
func TestWrapAESKW_RFC3394_192BitKEK(t *testing.T) {
	kek := mustHex(t, "000102030405060708090A0B0C0D0E0F1011121314151617")
	keyData := mustHex(t, "00112233445566778899AABBCCDDEEFF")
	wantCiphertext := mustHex(t, "96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D")

	got, err := WrapAESKW(keyData, kek)
	require.NoError(t, err)
	assert.Equal(t, wantCiphertext, got)
}

// TestWrapAESKW_RFC3394_256BitKEK is the RFC 3394 section 4.3 vector:
// 128-bit key data wrapped under a 256-bit KEK.
func TestWrapAESKW_RFC3394_256BitKEK(t *testing.T) {
	kek := mustHex(t, "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
	keyData := mustHex(t, "00112233445566778899AABBCCDDEEFF")
	wantCiphertext := mustHex(t, "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7")

	got, err := WrapAESKW(keyData, kek)
	require.NoError(t, err)
	assert.Equal(t, wantCiphertext, got)
}

// TestWrapAESKW_RFC3394_192BitKeyData is the RFC 3394 section 4.4 vector:
// 192-bit (24-byte, 3-block) key data wrapped under a 192-bit KEK, exercising
// n=3 unlike the n=2 vectors above.
func TestWrapAESKW_RFC3394_192BitKeyData(t *testing.T) {
	kek := mustHex(t, "000102030405060708090A0B0C0D0E0F1011121314151617")
	keyData := mustHex(t, "00112233445566778899AABBCCDDEEFF0001020304050607")
	wantCiphertext := mustHex(t, "031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2")

	got, err := WrapAESKW(keyData, kek)
	require.NoError(t, err)
	assert.Equal(t, wantCiphertext, got)

	recovered, err := UnwrapAESKW(wantCiphertext, kek)
	require.NoError(t, err)
	assert.Equal(t, keyData, recovered)
}

// TestWrapAESKW_RFC3394_256BitKeyData is the RFC 3394 section 4.6 vector:
// 256-bit (32-byte, 4-block) key data wrapped under a 256-bit KEK.
func TestWrapAESKW_RFC3394_256BitKeyData(t *testing.T) {
	kek := mustHex(t, "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
	keyData := mustHex(t, "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F")
	wantCiphertext := mustHex(t, "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21")

	got, err := WrapAESKW(keyData, kek)
	require.NoError(t, err)
	assert.Equal(t, wantCiphertext, got)
}

// TestWrapUnwrapAESKW_RoundTrip_MultiBlock proves round-trip correctness for
// key material that is not one of the fixed RFC vectors -- a randomly
// generated 5-block (40-byte) plaintext. The oracle here is the random
// plaintext itself: the unwrapped output must equal the exact bytes that
// were wrapped, not merely "no error".
func TestWrapUnwrapAESKW_RoundTrip_MultiBlock(t *testing.T) {
	kek := mustHex(t, "000102030405060708090A0B0C0D0E0F")
	plaintext := make([]byte, 40)
	_, err := rand.Read(plaintext)
	require.NoError(t, err)

	wrapped, err := WrapAESKW(plaintext, kek)
	require.NoError(t, err)
	// RFC 3394: ciphertext is (n+1) 8-byte blocks for n plaintext blocks.
	assert.Len(t, wrapped, len(plaintext)+8)

	recovered, err := UnwrapAESKW(wrapped, kek)
	require.NoError(t, err)
	assert.Equal(t, plaintext, recovered)
}

// TestUnwrapAESKW_TamperedCiphertextRejected proves the integrity check (the
// AIV comparison) actually rejects a modified wrapped blob rather than
// silently returning corrupted plaintext.
func TestUnwrapAESKW_TamperedCiphertextRejected(t *testing.T) {
	kek := mustHex(t, "000102030405060708090A0B0C0D0E0F")
	keyData := mustHex(t, "00112233445566778899AABBCCDDEEFF")

	wrapped, err := WrapAESKW(keyData, kek)
	require.NoError(t, err)

	tampered := make([]byte, len(wrapped))
	copy(tampered, wrapped)
	tampered[0] ^= 0xFF

	_, err = UnwrapAESKW(tampered, kek)
	require.Error(t, err)
	var malformed *MalformedWrappedKeyError
	assert.ErrorAs(t, err, &malformed)
}

// TestWrapAESKW_InvalidKeySize proves every unsupported KEK length is
// rejected with a typed error rather than silently truncating or padding
// the key, which would wrap under a different key than the caller named.
func TestWrapAESKW_InvalidKeySize(t *testing.T) {
	plaintext := mustHex(t, "00112233445566778899AABBCCDDEEFF")

	for _, size := range []int{0, 8, 15, 17, 20, 33} {
		_, err := WrapAESKW(plaintext, make([]byte, size))
		require.Errorf(t, err, "expected error for KEK size %d", size)
		var sizeErr *InvalidKeySizeError
		assert.ErrorAsf(t, err, &sizeErr, "expected InvalidKeySizeError for KEK size %d", size)
	}
}

// TestWrapAESKW_InvalidPlaintextLength proves plaintext that is empty, only
// one block, or not a multiple of 8 bytes is rejected rather than silently
// wrapped incorrectly.
func TestWrapAESKW_InvalidPlaintextLength(t *testing.T) {
	kek := mustHex(t, "000102030405060708090A0B0C0D0E0F")

	cases := map[string][]byte{
		"empty":            {},
		"one_block_only":   make([]byte, 8),
		"not_multiple_of8": make([]byte, 17),
	}
	for name, pt := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := WrapAESKW(pt, kek)
			require.Error(t, err)
		})
	}
}

// TestUnwrapAESKW_InvalidCiphertextLength proves a wrapped blob shorter than
// the minimum two ciphertext blocks, or not block-aligned, is rejected
// rather than read out of bounds.
func TestUnwrapAESKW_InvalidCiphertextLength(t *testing.T) {
	kek := mustHex(t, "000102030405060708090A0B0C0D0E0F")

	for _, size := range []int{0, 8, 16, 17, 23} {
		_, err := UnwrapAESKW(make([]byte, size), kek)
		require.Errorf(t, err, "expected error for ciphertext size %d", size)
	}
}
