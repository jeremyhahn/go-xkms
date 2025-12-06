// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

//go:build quantum

package kyber768

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	k, err := New()
	require.NoError(t, err)
	defer k.Clean()
	assert.NotNil(t, k.kem)
}

func TestGenerateKeyPair(t *testing.T) {
	k, err := New()
	require.NoError(t, err)
	defer k.Clean()

	pubKey, err := k.GenerateKeyPair()
	require.NoError(t, err)
	assert.NotEmpty(t, pubKey)
	assert.Equal(t, k.PublicKeyLength(), len(pubKey))

	secretKey := k.ExportSecretKey()
	assert.NotEmpty(t, secretKey)
	assert.Equal(t, k.SecretKeyLength(), len(secretKey))
}

func TestEncapsulateDecapsulate(t *testing.T) {
	// Alice generates a key pair
	alice, err := New()
	require.NoError(t, err)
	defer alice.Clean()

	alicePubKey, err := alice.GenerateKeyPair()
	require.NoError(t, err)

	// Bob encapsulates a secret for Alice
	bob, err := New()
	require.NoError(t, err)
	defer bob.Clean()

	ciphertext, bobSharedSecret, err := bob.Encapsulate(alicePubKey)
	require.NoError(t, err)
	assert.NotEmpty(t, ciphertext)
	assert.NotEmpty(t, bobSharedSecret)
	assert.Equal(t, alice.CiphertextLength(), len(ciphertext))
	assert.Equal(t, alice.SharedSecretLength(), len(bobSharedSecret))

	// Alice decapsulates to recover the shared secret
	aliceSharedSecret, err := alice.Decapsulate(ciphertext)
	require.NoError(t, err)
	assert.Equal(t, bobSharedSecret, aliceSharedSecret)
}

func TestDecapsulateInvalidCiphertext(t *testing.T) {
	k, err := New()
	require.NoError(t, err)
	defer k.Clean()

	_, err = k.GenerateKeyPair()
	require.NoError(t, err)

	// Create an invalid ciphertext (wrong length)
	invalidCiphertext := make([]byte, 10)

	_, err = k.Decapsulate(invalidCiphertext)
	assert.Error(t, err)
}

func TestCreateWithExistingKey(t *testing.T) {
	// Generate a key pair first
	k1, err := New()
	require.NoError(t, err)

	pubKey, err := k1.GenerateKeyPair()
	require.NoError(t, err)

	// ExportSecretKey returns a reference to internal memory that gets zeroed
	// when Clean() is called, so we must copy it before cleaning
	exportedKey := k1.ExportSecretKey()
	secretKey := make([]byte, len(exportedKey))
	copy(secretKey, exportedKey)
	k1.Clean()

	// Create new instance with existing secret key
	k2, err := Create(secretKey)
	require.NoError(t, err)
	defer k2.Clean()

	// Bob encapsulates for our recreated key
	bob, err := New()
	require.NoError(t, err)
	defer bob.Clean()

	ciphertext, bobSecret, err := bob.Encapsulate(pubKey)
	require.NoError(t, err)

	// Decapsulate with recreated key
	aliceSecret, err := k2.Decapsulate(ciphertext)
	require.NoError(t, err)
	assert.Equal(t, bobSecret, aliceSecret)
}

func TestDetails(t *testing.T) {
	k, err := New()
	require.NoError(t, err)
	defer k.Clean()

	details := k.Details()
	assert.Equal(t, AlgorithmName, details.Name)
	assert.Greater(t, details.LengthPublicKey, 0)
	assert.Greater(t, details.LengthSecretKey, 0)
	assert.Greater(t, details.LengthCiphertext, 0)
	assert.Greater(t, details.LengthSharedSecret, 0)
}

func TestTypeStrings(t *testing.T) {
	var keyAlgo Kyber768KeyAlgorithm
	assert.Equal(t, "Kyber768", keyAlgo.String())

	var kemAlgo Kyber768KEMAlgorithm
	assert.Equal(t, "Kyber768", kemAlgo.String())
}
