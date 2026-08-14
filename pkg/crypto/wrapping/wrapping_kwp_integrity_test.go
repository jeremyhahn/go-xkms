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
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// forgeKWPCiphertext builds an RFC 5649 / RFC 3394 ciphertext from a chosen
// initial value and a chosen block-aligned plaintext, running the section 2.2.1
// wrapping rounds directly.
//
// It exists because the negative cases below need blobs WrapAESKWP can never
// emit: a correct AIV header paired with a message length indicator that
// contradicts the padding, or with padding that is not zero. WrapAESKWP always
// derives the AIV from the plaintext it was handed, so it cannot produce them,
// and driving UnwrapAESKWP with only self-consistent input is exactly how the
// missing section 4.2 checks stayed missing.
//
// The helper is validated against the published RFC 5649 section 6 ciphertexts
// by TestForgeKWPCiphertext_MatchesRFC5649Vectors before any negative case
// relies on it, so a forgery that is refused is refused on its content and not
// because the helper wrapped it wrongly.
func forgeKWPCiphertext(t *testing.T, kek []byte, iv [8]byte, padded []byte) []byte {
	t.Helper()
	require.NotEmpty(t, padded, "forged plaintext must be non-empty")
	require.Zero(t, len(padded)%8, "forged plaintext must be block aligned")

	block, err := aes.NewCipher(kek)
	require.NoError(t, err)

	// RFC 5649 section 4.1: a single padded block is wrapped with one AES-ECB
	// encryption of IV || P[1] rather than the 6n rounds.
	if len(padded) == 8 {
		in := make([]byte, 16)
		copy(in[0:8], iv[:])
		copy(in[8:16], padded)
		out := make([]byte, 16)
		block.Encrypt(out, in)
		return out
	}

	n := len(padded) / 8
	rb := make([]byte, (n+1)*8)
	copy(rb[0:8], iv[:])
	copy(rb[8:], padded)

	var b [16]byte
	for j := 0; j <= 5; j++ {
		for i := 1; i <= n; i++ {
			copy(b[0:8], rb[0:8])
			copy(b[8:16], rb[i*8:(i+1)*8])
			block.Encrypt(b[:], b[:])

			round := uint64(n*j + i)
			copy(rb[0:8], b[0:8])
			for k := 7; k >= 0; k-- {
				rb[7-k] ^= byte(round >> (uint(k) * 8))
			}
			copy(rb[i*8:(i+1)*8], b[8:16])
		}
	}
	return rb
}

// kwpAIV assembles an RFC 5649 section 3 Alternative Initial Value from a
// chosen message length indicator, keeping the A65959A6 header intact so that
// the MLI is the only field under test.
func kwpAIV(mli uint32) [8]byte {
	var iv [8]byte
	copy(iv[0:4], kwpAIVHeader[:])
	binary.BigEndian.PutUint32(iv[4:8], mli)
	return iv
}

// rfc5649KEK is the 192-bit key-encryption key both RFC 5649 section 6 worked
// examples use.
const rfc5649KEK = "5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8"

// TestForgeKWPCiphertext_MatchesRFC5649Vectors validates the attacker-side
// helper against the published section 6 ciphertexts, in the same two shapes
// the RFC gives: 20 octets padded to three blocks, and 7 octets padded to the
// single-block special case. Every negative test below depends on this.
func TestForgeKWPCiphertext_MatchesRFC5649Vectors(t *testing.T) {
	kek := mustHex(t, rfc5649KEK)

	t.Run("20 octets, three padded blocks", func(t *testing.T) {
		plaintext := mustHex(t, "c37b7e6492584340bed12207808941155068f738")
		padded := make([]byte, 24)
		copy(padded, plaintext)

		got := forgeKWPCiphertext(t, kek, kwpAIV(20), padded)
		want := mustHex(t, "138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a")
		assert.Equal(t, want, got)
	})

	t.Run("7 octets, single padded block", func(t *testing.T) {
		plaintext := mustHex(t, "466f7250617369")
		padded := make([]byte, 8)
		copy(padded, plaintext)

		got := forgeKWPCiphertext(t, kek, kwpAIV(7), padded)
		want := mustHex(t, "afbeb0f07dfbf5419200f2ccb50bb24f")
		assert.Equal(t, want, got)
	})
}

// TestUnwrapAESKWP_RejectsNonZeroPadding covers RFC 5649 section 4.2's third
// verification step: with b = 8n - MLI, the rightmost b octets of the recovered
// data must be zero.
//
// Every blob here carries the correct A65959A6 header and an in-range MLI, so
// the padding is the only thing wrong with it. Before this check existed all of
// them unwrapped successfully, which meant a forger only had to hit the 32-bit
// header rather than the header plus up to 56 bits of padding.
func TestUnwrapAESKWP_RejectsNonZeroPadding(t *testing.T) {
	kek := mustHex(t, rfc5649KEK)
	plaintext := mustHex(t, "c37b7e6492584340bed12207808941155068f738") // 20 octets

	// Three padded blocks (24 octets) with MLI=20 leaves four padding octets
	// at indices 20..23; each one must be rejected on its own.
	for offset := 20; offset < 24; offset++ {
		padded := make([]byte, 24)
		copy(padded, plaintext)
		padded[offset] = 0x01

		blob := forgeKWPCiphertext(t, kek, kwpAIV(20), padded)
		_, err := UnwrapAESKWP(blob, kek)
		require.Errorf(t, err, "non-zero padding at offset %d was accepted", offset)

		var malformed *MalformedWrappedKeyError
		require.ErrorAsf(t, err, &malformed, "offset %d", offset)
		assert.Equal(t, kwpIntegrityFailure, malformed.Reason)
	}

	// The same defect in the single-block special case, which RFC 5649
	// section 4.1 wraps with one AES call and which had no padding check at
	// all before this change.
	single := make([]byte, 8)
	copy(single, mustHex(t, "466f7250617369")) // 7 octets, one padding octet
	single[7] = 0xFF

	blob := forgeKWPCiphertext(t, kek, kwpAIV(7), single)
	_, err := UnwrapAESKWP(blob, kek)
	require.Error(t, err, "non-zero padding in the single-block case was accepted")
	var malformed *MalformedWrappedKeyError
	require.ErrorAs(t, err, &malformed)
	assert.Equal(t, kwpIntegrityFailure, malformed.Reason)
}

// TestUnwrapAESKWP_RejectsMLIBelowLowerBound covers the lower half of RFC 5649
// section 4.2's second verification step, 8*(n-1) < MLI. A blob carrying fewer
// blocks' worth of data than its block count implies is malformed: the wrapper
// would have emitted fewer blocks.
//
// The padding in each case is genuinely all zero, so the lower bound is the
// only check that can reject it. That is what makes this a test of the bound
// rather than of the padding rule: dropping the bound makes these blobs unwrap
// to a short "key" of the attacker's choosing.
func TestUnwrapAESKWP_RejectsMLIBelowLowerBound(t *testing.T) {
	kek := mustHex(t, rfc5649KEK)
	data := mustHex(t, "c37b7e6492584340bed12207808941155068f738") // 20 octets

	// n = 3 padded blocks, so the RFC requires 16 < MLI <= 24.
	for _, mli := range []uint32{0, 1, 8, 15, 16} {
		padded := make([]byte, 24)
		copy(padded, data[:min(int(mli), len(data))])

		blob := forgeKWPCiphertext(t, kek, kwpAIV(mli), padded)
		_, err := UnwrapAESKWP(blob, kek)
		require.Errorf(t, err, "MLI=%d (below 8*(n-1)=16) was accepted", mli)

		var malformed *MalformedWrappedKeyError
		require.ErrorAsf(t, err, &malformed, "MLI=%d", mli)
		assert.Equal(t, kwpIntegrityFailure, malformed.Reason)
	}

	// The single-block case bounds MLI at 0 < MLI <= 8; a zero length claims a
	// key with no bytes in it.
	blob := forgeKWPCiphertext(t, kek, kwpAIV(0), make([]byte, 8))
	_, err := UnwrapAESKWP(blob, kek)
	require.Error(t, err, "MLI=0 was accepted in the single-block case")
	var malformed *MalformedWrappedKeyError
	require.ErrorAs(t, err, &malformed)
	assert.Equal(t, kwpIntegrityFailure, malformed.Reason)
}

// TestUnwrapAESKWP_RejectsMLIAboveUpperBound covers the upper half of the same
// bound, MLI <= 8*n, including a value that would index far past the recovered
// buffer if it were trusted.
func TestUnwrapAESKWP_RejectsMLIAboveUpperBound(t *testing.T) {
	kek := mustHex(t, rfc5649KEK)
	padded := make([]byte, 24)
	copy(padded, mustHex(t, "c37b7e6492584340bed12207808941155068f738"))

	for _, mli := range []uint32{25, 32, 1 << 16, 0xFFFFFFFF} {
		blob := forgeKWPCiphertext(t, kek, kwpAIV(mli), padded)
		_, err := UnwrapAESKWP(blob, kek)
		require.Errorf(t, err, "MLI=%d (above 8*n=24) was accepted", mli)

		var malformed *MalformedWrappedKeyError
		require.ErrorAsf(t, err, &malformed, "MLI=%d", mli)
		assert.Equal(t, kwpIntegrityFailure, malformed.Reason)
	}
}

// TestUnwrapAESKWP_AcceptsMLIBounds pins the inclusive/exclusive ends of
// 8*(n-1) < MLI <= 8*n so the new checks cannot be tightened into rejecting
// legitimate blobs. MLI=17 is the smallest legal length for three blocks and
// MLI=24 the largest; both must unwrap, and to exactly the claimed bytes.
func TestUnwrapAESKWP_AcceptsMLIBounds(t *testing.T) {
	kek := mustHex(t, rfc5649KEK)
	data := bytes.Repeat([]byte{0x5a}, 24)

	for _, mli := range []uint32{17, 18, 23, 24} {
		padded := make([]byte, 24)
		copy(padded, data[:mli])

		blob := forgeKWPCiphertext(t, kek, kwpAIV(mli), padded)
		recovered, err := UnwrapAESKWP(blob, kek)
		require.NoErrorf(t, err, "MLI=%d is legal for n=3 but was rejected", mli)
		assert.Equalf(t, data[:mli], recovered, "MLI=%d recovered the wrong length", mli)
	}

	// Single-block bounds: 0 < MLI <= 8.
	for _, mli := range []uint32{1, 7, 8} {
		padded := make([]byte, 8)
		copy(padded, data[:mli])

		blob := forgeKWPCiphertext(t, kek, kwpAIV(mli), padded)
		recovered, err := UnwrapAESKWP(blob, kek)
		require.NoErrorf(t, err, "MLI=%d is legal for n=1 but was rejected", mli)
		assert.Equalf(t, data[:mli], recovered, "MLI=%d recovered the wrong length", mli)
	}
}

// TestUnwrapAESKWP_IntegrityFailuresAreIndistinguishable proves the three
// section 4.2 checks report one error value. An unwrap is reachable over the
// wire with attacker-chosen ciphertext; an error that named the failing check
// would tell the caller which field of the decrypted-but-unauthenticated block
// it had already got right, which is the distinguisher the single reason
// string exists to deny.
func TestUnwrapAESKWP_IntegrityFailuresAreIndistinguishable(t *testing.T) {
	kek := mustHex(t, rfc5649KEK)
	data := bytes.Repeat([]byte{0x31}, 20)

	badHeaderIV := kwpAIV(20)
	badHeaderIV[0] ^= 0xFF

	paddedClean := make([]byte, 24)
	copy(paddedClean, data)

	paddedDirty := make([]byte, 24)
	copy(paddedDirty, data)
	paddedDirty[23] = 0x01

	cases := map[string][]byte{
		"bad AIV header":   forgeKWPCiphertext(t, kek, badHeaderIV, paddedClean),
		"MLI too small":    forgeKWPCiphertext(t, kek, kwpAIV(4), make([]byte, 24)),
		"MLI too large":    forgeKWPCiphertext(t, kek, kwpAIV(25), paddedClean),
		"non-zero padding": forgeKWPCiphertext(t, kek, kwpAIV(20), paddedDirty),
	}

	messages := make(map[string]struct{}, len(cases))
	for name, blob := range cases {
		_, err := UnwrapAESKWP(blob, kek)
		require.Errorf(t, err, "%s was accepted", name)
		messages[err.Error()] = struct{}{}
	}
	assert.Lenf(t, messages, 1,
		"RFC 5649 section 4.2 failures must be indistinguishable, got %d distinct messages: %v",
		len(messages), messages)
}

// TestUnwrapAESKW_RejectsPartiallyMatchingICV drives the RFC 3394 section 2.2.2
// step 3 integrity check with forged blobs whose recovered A matches the
// default initial value in every octet but one, at the first position and at
// the last. Both must be refused identically: the check is now
// subtle.ConstantTimeCompare rather than a loop that returned on the first
// mismatched octet, which leaked through timing how many leading octets a
// forgery had already got right.
func TestUnwrapAESKW_RejectsPartiallyMatchingICV(t *testing.T) {
	kek := mustHex(t, "000102030405060708090A0B0C0D0E0F")
	keyData := mustHex(t, "00112233445566778899AABBCCDDEEFF")

	// The helper doubles as an RFC 3394 wrapper when handed the default IV,
	// so forging with A6A6A6A6A6A6A6A6 must reproduce the section 4.1 vector
	// and unwrap cleanly. That validates the forgeries below.
	good := forgeKWPCiphertext(t, kek, aesKWDefaultIV, keyData)
	assert.Equal(t, mustHex(t, "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5"), good)
	recovered, err := UnwrapAESKW(good, kek)
	require.NoError(t, err)
	assert.Equal(t, keyData, recovered)

	messages := make(map[string]struct{}, 8)
	for offset := 0; offset < 8; offset++ {
		iv := aesKWDefaultIV
		iv[offset] ^= 0x01

		_, err := UnwrapAESKW(forgeKWPCiphertext(t, kek, iv, keyData), kek)
		require.Errorf(t, err, "ICV differing only at octet %d was accepted", offset)

		var malformed *MalformedWrappedKeyError
		require.ErrorAsf(t, err, &malformed, "octet %d", offset)
		messages[err.Error()] = struct{}{}
	}
	assert.Len(t, messages, 1,
		"an ICV mismatch must report the same error regardless of which octet differs")
}

// TestUnwrapAESKWP_RejectsMLIWithoutPaddingRoom is the composite an attacker
// would actually try: a blob whose MLI is in range and whose header is correct,
// but whose padding carries the bytes it wants smuggled through. It must fail
// as a whole rather than returning a truncated key.
func TestUnwrapAESKWP_RejectsMLIWithoutPaddingRoom(t *testing.T) {
	kek := mustHex(t, rfc5649KEK)

	padded := bytes.Repeat([]byte{0xAA}, 24)
	blob := forgeKWPCiphertext(t, kek, kwpAIV(17), padded)

	out, err := UnwrapAESKWP(blob, kek)
	require.Error(t, err, "a blob claiming 17 octets but carrying 24 non-zero octets was accepted")
	assert.Nil(t, out)

	var malformed *MalformedWrappedKeyError
	require.ErrorAs(t, err, &malformed)
	assert.Equal(t, kwpIntegrityFailure, malformed.Reason)
	assert.True(t, errors.As(err, &malformed))
}

// TestCTGreaterU64 pins the branch-free comparison the MLI bound and the
// padding mask are both built on, including the boundary where the two
// arguments are equal and the largest value a 32-bit MLI can carry.
func TestCTGreaterU64(t *testing.T) {
	cases := []struct {
		x, y uint64
		want int
	}{
		{0, 0, 0},
		{1, 0, 1},
		{0, 1, 0},
		{16, 16, 0},
		{17, 16, 1},
		{24, 24, 0},
		{25, 24, 1},
		{0xFFFFFFFF, 24, 1},
		{24, 0xFFFFFFFF, 0},
	}
	for _, c := range cases {
		assert.Equalf(t, c.want, ctGreaterU64(c.x, c.y), "ctGreaterU64(%d, %d)", c.x, c.y)
	}
}
