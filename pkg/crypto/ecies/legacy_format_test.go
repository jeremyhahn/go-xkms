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

package ecies

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Golden blob produced by the PRE-CHANGE Encrypt in this package's
// ephemeral_pub || nonce || tag || ciphertext layout, with a hand-rolled
// 12-byte nonce passed to cipher.NewGCM's Seal. Fixed bytes captured from that
// implementation against the fixed P-256 recipient scalar below. The current
// code cannot regenerate them, so this catches a layout mistake that the new
// writer and the new reader would otherwise make in agreement.
const (
	legacyECIESRecipientDHex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	legacyECIESBlobHex       = "04ecb6a2f86c7825ee71d022c29b9f8aa35971520ec3f9739855635765ead1bd14adad028bfba628ed75b72e3cbeb1ef192e60f52b3e2021497df3afb3006550dfa0a1a2a3a4a5a6a7a8a9aaab061b481579fa71bdc71ec0598b3d70c47ec7245683f539451c292673f1740aefb1d5ccf1df97"
	legacyECIESPlaintext     = "legacy ecies plaintext"
	legacyECIESAAD           = "ecies-aad"
)

// legacyECIESRecipientKey rebuilds the ECDSA private key the golden blob was
// encrypted to. A crypto/ecdh P-256 private key is the big-endian scalar, which
// is the same value as an ECDSA key's D, so deriving the ecdh public key and
// splitting its uncompressed encoding gives the same point.
//
// Derived through crypto/ecdh rather than elliptic.Curve.ScalarBaseMult, which
// is deprecated (staticcheck SA1019) and is the low-level unsafe API. The point
// is identical either way; ecdh additionally rejects a scalar outside [1, N-1]
// instead of returning a garbage point, so a corrupted fixture fails loudly.
func legacyECIESRecipientKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	d, err := hex.DecodeString(legacyECIESRecipientDHex)
	require.NoError(t, err)

	ecdhPriv, err := ecdh.P256().NewPrivateKey(d)
	require.NoError(t, err)

	// Uncompressed SEC 1 encoding: 0x04 || X (32 bytes) || Y (32 bytes).
	pub := ecdhPriv.PublicKey().Bytes()
	require.Len(t, pub, 65)

	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(pub[1:33]),
			Y:     new(big.Int).SetBytes(pub[33:65]),
		},
		D: new(big.Int).SetBytes(d),
	}
}

// TestDecrypt_ReadsLegacyCiphertext asserts an ECIES blob written before
// AES-GCM nonce generation moved inside the module boundary still decrypts.
func TestDecrypt_ReadsLegacyCiphertext(t *testing.T) {
	blob, err := hex.DecodeString(legacyECIESBlobHex)
	require.NoError(t, err)

	got, err := Decrypt(legacyECIESRecipientKey(t), blob, []byte(legacyECIESAAD))
	require.NoError(t, err)
	assert.Equal(t, legacyECIESPlaintext, string(got))
}

// TestEncrypt_KeepsLegacyFieldPositions asserts the other direction: a blob
// written now puts the nonce and tag where an older reader looks for them.
func TestEncrypt_KeepsLegacyFieldPositions(t *testing.T) {
	priv := legacyECIESRecipientKey(t)
	plaintext := []byte(legacyECIESPlaintext)

	out, err := Encrypt(rand.Reader, &priv.PublicKey, plaintext, []byte(legacyECIESAAD))
	require.NoError(t, err)

	golden, err := hex.DecodeString(legacyECIESBlobHex)
	require.NoError(t, err)

	// Same total length and same fixed-position layout as the blob the old
	// writer produced: ephemeral_pub(65) || nonce(12) || tag(16) || ciphertext.
	require.Len(t, out, len(golden))
	pubKeySize := getPublicKeySize(priv.Curve)
	assert.Equal(t, 65, pubKeySize)
	assert.Len(t, out[pubKeySize:pubKeySize+nonceSize], nonceSize)
	assert.Len(t, out[pubKeySize+nonceSize:pubKeySize+nonceSize+tagSize], tagSize)
	assert.Len(t, out[pubKeySize+nonceSize+tagSize:], len(plaintext))
}
