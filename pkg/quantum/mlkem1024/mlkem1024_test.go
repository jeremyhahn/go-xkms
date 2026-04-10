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

package mlkem1024

import (
	"crypto/mlkem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	k, err := New()
	require.NoError(t, err)
	defer k.Clean()
	assert.NotNil(t, k.dk)
	assert.NotNil(t, k.seed)
	assert.Len(t, k.seed, SeedSize)
}

func TestGenerateKeyPair(t *testing.T) {
	k, err := New()
	require.NoError(t, err)
	defer k.Clean()

	pubKey, err := k.GenerateKeyPair()
	require.NoError(t, err)
	assert.NotEmpty(t, pubKey)
	assert.Len(t, pubKey, mlkem.EncapsulationKeySize1024)

	seed := k.ExportSecretKey()
	assert.NotEmpty(t, seed)
	assert.Len(t, seed, mlkem.SeedSize)
}

func TestGenerateKeyPair_NotInitialized(t *testing.T) {
	k := &MLKEM1024{}
	_, err := k.GenerateKeyPair()
	assert.ErrorIs(t, err, ErrNotInitialized)
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
	assert.Len(t, ciphertext, mlkem.CiphertextSize1024)
	assert.Len(t, bobSharedSecret, mlkem.SharedKeySize)

	// Alice decapsulates to recover the shared secret
	aliceSharedSecret, err := alice.Decapsulate(ciphertext)
	require.NoError(t, err)
	assert.Equal(t, bobSharedSecret, aliceSharedSecret)
}

func TestDecapsulateInvalidCiphertext(t *testing.T) {
	k, err := New()
	require.NoError(t, err)
	defer k.Clean()

	// Wrong length ciphertext should fail
	invalidCiphertext := make([]byte, 10)
	_, err = k.Decapsulate(invalidCiphertext)
	assert.ErrorIs(t, err, ErrDecapsulationFailed)
}

func TestDecapsulate_NotInitialized(t *testing.T) {
	k := &MLKEM1024{}
	_, err := k.Decapsulate(make([]byte, mlkem.CiphertextSize1024))
	assert.ErrorIs(t, err, ErrNotInitialized)
}

func TestCreateWithExistingKey(t *testing.T) {
	// Generate a key pair first
	k1, err := New()
	require.NoError(t, err)

	pubKey, err := k1.GenerateKeyPair()
	require.NoError(t, err)

	// Export the seed before cleaning
	seed := k1.ExportSecretKey()
	k1.Clean()

	// Recreate from seed
	k2, err := Create(seed)
	require.NoError(t, err)
	defer k2.Clean()

	// The recreated key should produce the same public key
	pubKey2, err := k2.GenerateKeyPair()
	require.NoError(t, err)
	assert.Equal(t, pubKey, pubKey2)

	// Bob encapsulates for the recreated key
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

func TestCreateWithInvalidSeed(t *testing.T) {
	// Too short
	_, err := Create(make([]byte, 32))
	assert.ErrorIs(t, err, ErrInvalidSeed)

	// Too long
	_, err = Create(make([]byte, 128))
	assert.ErrorIs(t, err, ErrInvalidSeed)

	// Empty
	_, err = Create(nil)
	assert.ErrorIs(t, err, ErrInvalidSeed)
}

func TestEncapsulateInvalidPublicKey(t *testing.T) {
	k, err := New()
	require.NoError(t, err)
	defer k.Clean()

	// Too short
	_, _, err = k.Encapsulate(make([]byte, 10))
	assert.ErrorIs(t, err, ErrInvalidPublicKey)

	// Empty
	_, _, err = k.Encapsulate(nil)
	assert.ErrorIs(t, err, ErrInvalidPublicKey)
}

func TestEncapsulate_NotInitialized(t *testing.T) {
	k := &MLKEM1024{}
	_, _, err := k.Encapsulate(make([]byte, mlkem.EncapsulationKeySize1024))
	assert.ErrorIs(t, err, ErrNotInitialized)
}

func TestDetails(t *testing.T) {
	k, err := New()
	require.NoError(t, err)
	defer k.Clean()

	details := k.Details()
	assert.Equal(t, AlgorithmName, details.Name)
	assert.Equal(t, mlkem.EncapsulationKeySize1024, details.LengthPublicKey)
	assert.Equal(t, mlkem.SeedSize, details.LengthSecretKey)
	assert.Equal(t, mlkem.CiphertextSize1024, details.LengthCiphertext)
	assert.Equal(t, mlkem.SharedKeySize, details.LengthSharedSecret)
}

func TestHelperMethods(t *testing.T) {
	k, err := New()
	require.NoError(t, err)
	defer k.Clean()

	assert.Equal(t, mlkem.EncapsulationKeySize1024, k.PublicKeyLength())
	assert.Equal(t, mlkem.SeedSize, k.SecretKeyLength())
	assert.Equal(t, mlkem.CiphertextSize1024, k.CiphertextLength())
	assert.Equal(t, mlkem.SharedKeySize, k.SharedSecretLength())
}

func TestTypeStrings(t *testing.T) {
	var keyAlgo MLKEM1024KeyAlgorithm
	assert.Equal(t, "MLKEM1024", keyAlgo.String())

	var kemAlgo MLKEM1024KEMAlgorithm
	assert.Equal(t, "MLKEM1024", kemAlgo.String())
}

func TestExportSecretKey_NotInitialized(t *testing.T) {
	k := &MLKEM1024{}
	assert.Nil(t, k.ExportSecretKey())
}

func TestExportSecretKey_ReturnsCopy(t *testing.T) {
	k, err := New()
	require.NoError(t, err)
	defer k.Clean()

	seed1 := k.ExportSecretKey()
	seed2 := k.ExportSecretKey()

	// Should be equal but not the same slice
	assert.Equal(t, seed1, seed2)

	// Modifying one should not affect the other
	seed1[0] ^= 0xFF
	assert.NotEqual(t, seed1, seed2)
}

func TestClean(t *testing.T) {
	k, err := New()
	require.NoError(t, err)

	// Verify key is functional
	_, err = k.GenerateKeyPair()
	require.NoError(t, err)

	k.Clean()

	// After clean, operations should fail
	assert.Nil(t, k.dk)
	assert.Nil(t, k.seed)
	assert.Nil(t, k.ExportSecretKey())

	_, err = k.GenerateKeyPair()
	assert.ErrorIs(t, err, ErrNotInitialized)

	// Clean on already-cleaned instance should not panic
	k.Clean()
}

func TestWrongKeyDecapsulation(t *testing.T) {
	// Alice generates a key pair
	alice, err := New()
	require.NoError(t, err)
	defer alice.Clean()

	alicePubKey, err := alice.GenerateKeyPair()
	require.NoError(t, err)

	// Bob generates a different key pair
	bob, err := New()
	require.NoError(t, err)
	defer bob.Clean()

	// Sender encapsulates for Alice
	sender, err := New()
	require.NoError(t, err)
	defer sender.Clean()

	ciphertext, senderSecret, err := sender.Encapsulate(alicePubKey)
	require.NoError(t, err)

	// Alice decapsulates correctly
	aliceSecret, err := alice.Decapsulate(ciphertext)
	require.NoError(t, err)
	assert.Equal(t, senderSecret, aliceSecret)

	// Bob decapsulates with wrong key - ML-KEM uses implicit rejection,
	// so decapsulation succeeds but produces a different shared secret
	bobSecret, err := bob.Decapsulate(ciphertext)
	require.NoError(t, err)
	assert.NotEqual(t, senderSecret, bobSecret,
		"Wrong key should produce different shared secret (implicit rejection)")
}
