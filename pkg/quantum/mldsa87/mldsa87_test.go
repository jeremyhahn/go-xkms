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

package mldsa87

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateKeyPair(t *testing.T) {
	m, err := New()
	require.NoError(t, err)
	defer m.Clean()

	pubKey, err := m.GenerateKeyPair()
	require.NoError(t, err)
	assert.NotEmpty(t, pubKey)
	assert.Equal(t, PublicKeySize, len(pubKey))

	secretKey := m.ExportSecretKey()
	assert.NotEmpty(t, secretKey)
	assert.Equal(t, SeedSize, len(secretKey))
	assert.True(t, m.hasSeed)
	assert.NotNil(t, m.privateKey)
	assert.NotNil(t, m.publicKey)
}

func TestSignAndVerify(t *testing.T) {
	m, err := New()
	require.NoError(t, err)
	defer m.Clean()

	pubKey, err := m.GenerateKeyPair()
	require.NoError(t, err)

	message := []byte("This is a test message for ML-DSA-87 signature")
	signature, err := m.Sign(message)
	require.NoError(t, err)
	assert.NotEmpty(t, signature)
	assert.Equal(t, SignatureSize, len(signature))

	valid, err := m.Verify(message, signature, pubKey)
	require.NoError(t, err)
	assert.True(t, valid)
}

func TestVerifyInvalidSignature(t *testing.T) {
	m, err := New()
	require.NoError(t, err)
	defer m.Clean()

	pubKey, err := m.GenerateKeyPair()
	require.NoError(t, err)

	message := []byte("Original message")
	signature, err := m.Sign(message)
	require.NoError(t, err)

	// Modify the signature to make it invalid
	signature[0] ^= 0xFF

	valid, err := m.Verify(message, signature, pubKey)
	require.NoError(t, err)
	assert.False(t, valid, "Modified signature should not verify")
}

func TestVerifyWrongMessage(t *testing.T) {
	m, err := New()
	require.NoError(t, err)
	defer m.Clean()

	pubKey, err := m.GenerateKeyPair()
	require.NoError(t, err)

	message := []byte("Original message")
	signature, err := m.Sign(message)
	require.NoError(t, err)

	wrongMessage := []byte("Different message")
	valid, err := m.Verify(wrongMessage, signature, pubKey)
	require.NoError(t, err)
	assert.False(t, valid, "Signature should not verify with wrong message")
}

func TestCreateWithExistingKey(t *testing.T) {
	// Generate a key pair first
	m1, err := New()
	require.NoError(t, err)

	pubKey, err := m1.GenerateKeyPair()
	require.NoError(t, err)

	// Export and copy the seed before cleaning
	seed := m1.ExportSecretKey()
	require.NotNil(t, seed)
	require.Equal(t, SeedSize, len(seed))
	m1.Clean()

	// Create new instance from the exported seed
	m2, err := Create(seed)
	require.NoError(t, err)
	defer m2.Clean()

	// Sign with the recreated key
	message := []byte("Test message for key reconstruction")
	signature, err := m2.Sign(message)
	require.NoError(t, err)

	// Verify with original public key
	valid, err := m2.Verify(message, signature, pubKey)
	require.NoError(t, err)
	assert.True(t, valid, "Signature from reconstructed key should verify with original public key")

	// Verify the reconstructed public key matches the original
	reconstructedPubKey := m2.publicKey.Bytes()
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
	m, err := New()
	require.NoError(t, err)

	// Attempt to sign without generating keys
	_, err = m.Sign([]byte("test"))
	assert.ErrorIs(t, err, ErrNotInitialized)
}

func TestVerifyNotInitialized(t *testing.T) {
	m, err := New()
	require.NoError(t, err)

	// Attempt to verify without any public key (no generation, no external key)
	_, err = m.Verify([]byte("test"), make([]byte, SignatureSize), nil)
	assert.ErrorIs(t, err, ErrNotInitialized)
}

func TestVerifyWithInvalidPublicKey(t *testing.T) {
	m, err := New()
	require.NoError(t, err)
	defer m.Clean()

	// Provide garbage public key bytes
	_, err = m.Verify([]byte("test"), make([]byte, SignatureSize), []byte{0x01, 0x02})
	assert.ErrorIs(t, err, ErrVerificationFailed)
}

func TestExportSecretKeyNotInitialized(t *testing.T) {
	m, err := New()
	require.NoError(t, err)

	key := m.ExportSecretKey()
	assert.Nil(t, key)
}

func TestClean(t *testing.T) {
	m, err := New()
	require.NoError(t, err)

	_, err = m.GenerateKeyPair()
	require.NoError(t, err)
	assert.True(t, m.hasSeed)
	assert.NotNil(t, m.privateKey)

	m.Clean()
	m.Clean() // a second Clean must be a no-op

	assert.False(t, m.hasSeed)
	assert.Nil(t, m.privateKey)
	assert.Nil(t, m.publicKey)

	// Verify seed was zeroed
	for _, b := range m.seed {
		assert.Equal(t, byte(0), b)
	}
}

func TestDetails(t *testing.T) {
	m, err := New()
	require.NoError(t, err)
	defer m.Clean()

	details := m.Details()
	assert.Equal(t, AlgorithmName, details.Name)
	assert.Equal(t, PublicKeySize, details.LengthPublicKey)
	assert.Equal(t, SeedSize, details.LengthSecretKey)
	assert.Equal(t, SignatureSize, details.MaxLengthSignature)

	assert.Equal(t, PublicKeySize, m.PublicKeyLength())
	assert.Equal(t, SeedSize, m.SecretKeyLength())
	assert.Equal(t, SignatureSize, m.SignatureLength())
}

func TestTypeStrings(t *testing.T) {
	var keyAlgo MLDSA87KeyAlgorithm
	assert.Equal(t, "ML-DSA-87", keyAlgo.String())

	var sigAlgo MLDSA87SignatureAlgorithm
	assert.Equal(t, "ML-DSA-87", sigAlgo.String())
}

func TestCrossInstanceVerification(t *testing.T) {
	// Sign with one instance, verify with a separate instance using only the public key
	m1, err := New()
	require.NoError(t, err)
	defer m1.Clean()

	pubKey, err := m1.GenerateKeyPair()
	require.NoError(t, err)

	message := []byte("Cross-instance verification test")
	signature, err := m1.Sign(message)
	require.NoError(t, err)

	// Verify using a fresh instance (no keys loaded) with external public key
	m2, err := New()
	require.NoError(t, err)
	defer m2.Clean()

	valid, err := m2.Verify(message, signature, pubKey)
	require.NoError(t, err)
	assert.True(t, valid)
}
