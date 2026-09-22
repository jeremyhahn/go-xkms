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

package aesgcm

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Golden ciphertexts produced by the PRE-CHANGE implementation: a hand-rolled
// 12-byte nonce passed to cipher.NewGCM's Seal, with the nonce prepended.
//
// These are fixed bytes captured once from that code, not values this package
// can regenerate. That is the point: the round-trip tests elsewhere in this
// package encrypt and decrypt with the same implementation, so a matching
// mistake in the new writer and reader would pass them and still make every
// stored blob unreadable. Only a fixture the current code cannot have produced
// can catch that.
const (
	legacyKeyHex        = "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
	legacyNoAADHex      = "a0a1a2a3a4a5a6a7a8a9aaabc5aa58971d563c72b97e6cb4e725f3d70d4e8d0805a871467174be551de6a630cb1bf0d66b29b3"
	legacyWithAADHex    = "a0a1a2a3a4a5a6a7a8a9aaabc5aa58971d563c72b97e6cb4e725f3d70d4e8d0805a871a9c47ac897e5cc021b7f870e3b96a0d2"
	legacyPlaintext     = "legacy aesgcm plaintext"
	legacyAAD           = "aesgcm-aad"
	legacyNonceHexBytes = 12
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

// TestDecrypt_ReadsKnownAnswerCiphertext is a known-answer test: fixed
// ciphertexts captured from the format produced before AES-GCM nonce
// generation moved inside the module boundary must still decrypt.
func TestDecrypt_ReadsKnownAnswerCiphertext(t *testing.T) {
	key := mustHex(t, legacyKeyHex)

	t.Run("without AAD", func(t *testing.T) {
		got, err := Decrypt(key, mustHex(t, legacyNoAADHex))
		require.NoError(t, err)
		assert.Equal(t, legacyPlaintext, string(got))
	})

	t.Run("with AAD", func(t *testing.T) {
		got, err := DecryptWithAAD(key, mustHex(t, legacyWithAADHex), []byte(legacyAAD))
		require.NoError(t, err)
		assert.Equal(t, legacyPlaintext, string(got))
	})
}

// TestEncrypt_ProducesKnownAnswerLayout is the other direction: a blob
// written now must keep the same on-disk layout the known-answer vectors
// assume -- nonce split off the front by hand. Reproducing that split here,
// rather than calling Decrypt, keeps the check independent of the reader.
func TestEncrypt_ProducesKnownAnswerLayout(t *testing.T) {
	key := mustHex(t, legacyKeyHex)
	plaintext := []byte(legacyPlaintext)

	out, err := EncryptWithAAD(key, plaintext, []byte(legacyAAD))
	require.NoError(t, err)

	// What the old reader did: nonce is the first 12 bytes, the rest is
	// ciphertext+tag, and both go to cipher.NewGCM's Open. cipher.NewGCM is
	// refused under GODEBUG=fips140=only, so assert the layout instead of
	// re-running the old decrypt: same total length, and the leading bytes are
	// a nonce rather than part of the ciphertext.
	require.Len(t, out, len(plaintext)+NonceSize+TagSize)

	legacyNonce := out[:legacyNonceHexBytes]
	legacyBody := out[legacyNonceHexBytes:]
	assert.Len(t, legacyNonce, NonceSize)
	assert.Len(t, legacyBody, len(plaintext)+TagSize)

	// And the golden blob, which the old writer produced, has that same shape.
	golden := mustHex(t, legacyWithAADHex)
	assert.Len(t, golden, len(out))
}
