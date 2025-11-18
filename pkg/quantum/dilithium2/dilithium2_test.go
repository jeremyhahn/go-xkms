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

package dilithium2

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	d, err := New()
	require.NoError(t, err)
	defer d.Clean()
	assert.NotNil(t, d.signer)
}

func TestGenerateKeyPair(t *testing.T) {
	d, err := New()
	require.NoError(t, err)
	defer d.Clean()

	pubKey, err := d.GenerateKeyPair()
	require.NoError(t, err)
	assert.NotEmpty(t, pubKey)
	assert.Equal(t, d.PublicKeyLength(), len(pubKey))

	secretKey := d.ExportSecretKey()
	assert.NotEmpty(t, secretKey)
	assert.Equal(t, d.SecretKeyLength(), len(secretKey))
}

func TestSignAndVerify(t *testing.T) {
	d, err := New()
	require.NoError(t, err)
	defer d.Clean()

	pubKey, err := d.GenerateKeyPair()
	require.NoError(t, err)

	message := []byte("This is a test message for Dilithium2 signature")
	signature, err := d.Sign(message)
	require.NoError(t, err)
	assert.NotEmpty(t, signature)

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
	// Verification should fail or return false
	if err == nil {
		assert.False(t, valid, "Modified signature should not verify")
	}
}

func TestCreateWithExistingKey(t *testing.T) {
	// Generate a key pair first
	d1, err := New()
	require.NoError(t, err)

	pubKey, err := d1.GenerateKeyPair()
	require.NoError(t, err)

	secretKey := d1.ExportSecretKey()
	d1.Clean()

	// Create new instance with existing secret key
	d2, err := Create(secretKey)
	require.NoError(t, err)
	defer d2.Clean()

	// Sign with the recreated key
	message := []byte("Test message")
	signature, err := d2.Sign(message)
	require.NoError(t, err)

	// Verify with original public key
	valid, err := d2.Verify(message, signature, pubKey)
	require.NoError(t, err)
	assert.True(t, valid)
}

func TestDetails(t *testing.T) {
	d, err := New()
	require.NoError(t, err)
	defer d.Clean()

	details := d.Details()
	assert.Equal(t, AlgorithmName, details.Name)
	assert.Greater(t, details.LengthPublicKey, 0)
	assert.Greater(t, details.LengthSecretKey, 0)
	assert.Greater(t, details.MaxLengthSignature, 0)
}

func TestTypeStrings(t *testing.T) {
	var keyAlgo Dilithium2KeyAlgorithm
	assert.Equal(t, "Dilithium2", keyAlgo.String())

	var sigAlgo Dilithium2SignatureAlgorithm
	assert.Equal(t, "Dilithium2", sigAlgo.String())
}
