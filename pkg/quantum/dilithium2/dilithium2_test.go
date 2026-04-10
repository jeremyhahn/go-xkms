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

package dilithium2

import (
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	d, err := New()
	require.NoError(t, err)
	defer d.Clean()

	assert.Nil(t, d.privateKey)
	assert.Nil(t, d.publicKey)
	assert.False(t, d.hasSeed)
}

func TestGenerateKeyPair(t *testing.T) {
	d, err := New()
	require.NoError(t, err)
	defer d.Clean()

	pubKey, err := d.GenerateKeyPair()
	require.NoError(t, err)
	assert.NotEmpty(t, pubKey)
	assert.Equal(t, mldsa44.PublicKeySize, len(pubKey))

	secretKey := d.ExportSecretKey()
	assert.NotEmpty(t, secretKey)
	assert.Equal(t, mldsa44.SeedSize, len(secretKey))
	assert.True(t, d.hasSeed)
	assert.NotNil(t, d.privateKey)
	assert.NotNil(t, d.publicKey)
}

func TestSignAndVerify(t *testing.T) {
	d, err := New()
	require.NoError(t, err)
	defer d.Clean()

	pubKey, err := d.GenerateKeyPair()
	require.NoError(t, err)

	message := []byte("This is a test message for ML-DSA-44 signature")
	signature, err := d.Sign(message)
	require.NoError(t, err)
	assert.NotEmpty(t, signature)
	assert.Equal(t, mldsa44.SignatureSize, len(signature))

	valid, err := d.Verify(message, signature, pubKey)
	require.NoError(t, err)
	assert.True(t, valid)
}

func TestVerifyInvalidSignature(t *testing.T) {
	d, err := New()
	require.NoError(t, err)
	defer d.Clean()

	pubKey, err := d.GenerateKeyPair()
	require.NoError(t, err)

	message := []byte("Original message")
	signature, err := d.Sign(message)
	require.NoError(t, err)

	// Modify the signature to make it invalid
	signature[0] ^= 0xFF

	valid, err := d.Verify(message, signature, pubKey)
	require.NoError(t, err)
	assert.False(t, valid, "Modified signature should not verify")
}

func TestVerifyWrongMessage(t *testing.T) {
	d, err := New()
	require.NoError(t, err)
	defer d.Clean()

	pubKey, err := d.GenerateKeyPair()
	require.NoError(t, err)

	message := []byte("Original message")
	signature, err := d.Sign(message)
	require.NoError(t, err)

	wrongMessage := []byte("Different message")
	valid, err := d.Verify(wrongMessage, signature, pubKey)
	require.NoError(t, err)
	assert.False(t, valid, "Signature should not verify with wrong message")
}

func TestCreateWithExistingKey(t *testing.T) {
	// Generate a key pair first
	d1, err := New()
	require.NoError(t, err)

	pubKey, err := d1.GenerateKeyPair()
	require.NoError(t, err)

	// Export and copy the seed before cleaning
	seed := d1.ExportSecretKey()
	require.NotNil(t, seed)
	require.Equal(t, mldsa44.SeedSize, len(seed))
	d1.Clean()

	// Create new instance from the exported seed
	d2, err := Create(seed)
	require.NoError(t, err)
	defer d2.Clean()

	// Sign with the recreated key
	message := []byte("Test message for key reconstruction")
	signature, err := d2.Sign(message)
	require.NoError(t, err)

	// Verify with original public key
	valid, err := d2.Verify(message, signature, pubKey)
	require.NoError(t, err)
	assert.True(t, valid, "Signature from reconstructed key should verify with original public key")

	// Verify the reconstructed public key matches the original
	reconstructedPubKey := d2.publicKey.Bytes()
	assert.Equal(t, pubKey, reconstructedPubKey)
}

func TestCreateWithInvalidSeed(t *testing.T) {
	// Too short
	_, err := Create([]byte{0x01, 0x02, 0x03})
	assert.ErrorIs(t, err, ErrInvalidSecretKey)

	// Too long
	longSeed := make([]byte, 64)
	_, err = Create(longSeed)
	assert.ErrorIs(t, err, ErrInvalidSecretKey)

	// Empty
	_, err = Create([]byte{})
	assert.ErrorIs(t, err, ErrInvalidSecretKey)

	// Nil
	_, err = Create(nil)
	assert.ErrorIs(t, err, ErrInvalidSecretKey)
}

func TestSignNotInitialized(t *testing.T) {
	d, err := New()
	require.NoError(t, err)

	// Attempt to sign without generating keys
	_, err = d.Sign([]byte("test"))
	assert.ErrorIs(t, err, ErrNotInitialized)
}

func TestVerifyNotInitialized(t *testing.T) {
	d, err := New()
	require.NoError(t, err)

	// Attempt to verify without any public key (no generation, no external key)
	_, err = d.Verify([]byte("test"), make([]byte, mldsa44.SignatureSize), nil)
	assert.ErrorIs(t, err, ErrNotInitialized)
}

func TestVerifyWithInvalidPublicKey(t *testing.T) {
	d, err := New()
	require.NoError(t, err)
	defer d.Clean()

	// Provide garbage public key bytes
	_, err = d.Verify([]byte("test"), make([]byte, mldsa44.SignatureSize), []byte{0x01, 0x02})
	assert.ErrorIs(t, err, ErrVerificationFailed)
}

func TestExportSecretKeyNotInitialized(t *testing.T) {
	d, err := New()
	require.NoError(t, err)

	key := d.ExportSecretKey()
	assert.Nil(t, key)
}

func TestClean(t *testing.T) {
	d, err := New()
	require.NoError(t, err)

	_, err = d.GenerateKeyPair()
	require.NoError(t, err)
	assert.True(t, d.hasSeed)
	assert.NotNil(t, d.privateKey)

	d.Clean()

	assert.False(t, d.hasSeed)
	assert.Nil(t, d.privateKey)
	assert.Nil(t, d.publicKey)

	// Verify seed was zeroed
	for _, b := range d.seed {
		assert.Equal(t, byte(0), b)
	}
}

func TestCleanIdempotent(t *testing.T) {
	d, err := New()
	require.NoError(t, err)

	_, err = d.GenerateKeyPair()
	require.NoError(t, err)

	// Clean should be safe to call multiple times
	d.Clean()
	d.Clean()

	assert.False(t, d.hasSeed)
	assert.Nil(t, d.privateKey)
}

func TestDetails(t *testing.T) {
	d, err := New()
	require.NoError(t, err)
	defer d.Clean()

	details := d.Details()
	assert.Equal(t, AlgorithmName, details.Name)
	assert.Equal(t, mldsa44.PublicKeySize, details.LengthPublicKey)
	assert.Equal(t, mldsa44.SeedSize, details.LengthSecretKey)
	assert.Equal(t, mldsa44.SignatureSize, details.MaxLengthSignature)
}

func TestPublicKeyLength(t *testing.T) {
	d, err := New()
	require.NoError(t, err)
	assert.Equal(t, mldsa44.PublicKeySize, d.PublicKeyLength())
}

func TestSecretKeyLength(t *testing.T) {
	d, err := New()
	require.NoError(t, err)
	assert.Equal(t, mldsa44.SeedSize, d.SecretKeyLength())
}

func TestSignatureLength(t *testing.T) {
	d, err := New()
	require.NoError(t, err)
	assert.Equal(t, mldsa44.SignatureSize, d.SignatureLength())
}

func TestTypeStrings(t *testing.T) {
	var keyAlgo Dilithium2KeyAlgorithm
	assert.Equal(t, "Dilithium2", keyAlgo.String())

	var sigAlgo Dilithium2SignatureAlgorithm
	assert.Equal(t, "Dilithium2", sigAlgo.String())
}

func TestDeterministicKeyReconstruction(t *testing.T) {
	// Generate a key pair and capture the seed
	d1, err := New()
	require.NoError(t, err)

	pubKey1, err := d1.GenerateKeyPair()
	require.NoError(t, err)
	seed := d1.ExportSecretKey()
	d1.Clean()

	// Reconstruct twice from the same seed and verify determinism
	d2, err := Create(seed)
	require.NoError(t, err)
	pubKey2 := d2.publicKey.Bytes()
	d2.Clean()

	d3, err := Create(seed)
	require.NoError(t, err)
	pubKey3 := d3.publicKey.Bytes()
	d3.Clean()

	assert.Equal(t, pubKey1, pubKey2, "First reconstruction should match original")
	assert.Equal(t, pubKey2, pubKey3, "Second reconstruction should match first")
}

func TestCrossInstanceVerification(t *testing.T) {
	// Sign with one instance, verify with a separate instance using only the public key
	d1, err := New()
	require.NoError(t, err)
	defer d1.Clean()

	pubKey, err := d1.GenerateKeyPair()
	require.NoError(t, err)

	message := []byte("Cross-instance verification test")
	signature, err := d1.Sign(message)
	require.NoError(t, err)

	// Verify using a fresh instance (no keys loaded) with external public key
	d2, err := New()
	require.NoError(t, err)
	defer d2.Clean()

	valid, err := d2.Verify(message, signature, pubKey)
	require.NoError(t, err)
	assert.True(t, valid)
}
