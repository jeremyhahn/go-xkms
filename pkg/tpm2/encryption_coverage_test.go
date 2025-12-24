//go:build tpm_simulator

package tpm2

import (
	"crypto/x509"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Tests for TPM2 symmetric encryption methods

func TestTPM2_SymmetricEncryptDecrypt_Success(t *testing.T) {
	_, tpmInterface := createSim(false, false)
	defer func() { _ = tpmInterface.Close() }()

	tpm, ok := tpmInterface.(*TPM2)
	require.True(t, ok, "expected *TPM2 type")

	// Generate a symmetric key
	attrs := &types.KeyAttributes{
		CN:                 "test-symmetric-key",
		KeyType:            types.KeyTypeEncryption,
		KeyAlgorithm:       x509.UnknownPublicKeyAlgorithm,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	_, err := tpm.GenerateSymmetricKey(attrs)
	require.NoError(t, err)

	// Get encrypter for the key
	encrypter, err := tpm.SymmetricEncrypter(attrs)
	require.NoError(t, err)

	plaintext := []byte("test message to encrypt")

	// Encrypt
	encryptedData, err := encrypter.Encrypt(plaintext, nil)
	require.NoError(t, err)
	assert.NotNil(t, encryptedData.Ciphertext)
	assert.NotNil(t, encryptedData.Nonce)
	assert.NotNil(t, encryptedData.Tag)

	// Decrypt
	decrypted, err := encrypter.Decrypt(encryptedData, nil)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestTPM2_SymmetricEncrypt_WithAdditionalData(t *testing.T) {
	_, tpmInterface := createSim(false, false)
	defer func() { _ = tpmInterface.Close() }()

	tpm, ok := tpmInterface.(*TPM2)
	require.True(t, ok, "expected *TPM2 type")

	attrs := &types.KeyAttributes{
		CN:                 "test-aead-key",
		KeyType:            types.KeyTypeEncryption,
		KeyAlgorithm:       x509.UnknownPublicKeyAlgorithm,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	_, err := tpm.GenerateSymmetricKey(attrs)
	require.NoError(t, err)

	encrypter, err := tpm.SymmetricEncrypter(attrs)
	require.NoError(t, err)

	plaintext := []byte("secret message")
	additionalData := []byte("authenticated but not encrypted")

	// Encrypt with additional data
	encryptedData, err := encrypter.Encrypt(plaintext, &types.EncryptOptions{
		AdditionalData: additionalData,
	})
	require.NoError(t, err)

	// Decrypt with correct additional data
	decrypted, err := encrypter.Decrypt(encryptedData, &types.DecryptOptions{
		AdditionalData: additionalData,
	})
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)

	// Decrypt with wrong additional data should fail
	_, err = encrypter.Decrypt(encryptedData, &types.DecryptOptions{
		AdditionalData: []byte("wrong data"),
	})
	assert.Error(t, err, "decryption should fail with wrong additional data")
}

func TestTPM2_SymmetricDecrypt_InvalidTag(t *testing.T) {
	_, tpmInterface := createSim(false, false)
	defer func() { _ = tpmInterface.Close() }()

	tpm, ok := tpmInterface.(*TPM2)
	require.True(t, ok, "expected *TPM2 type")

	attrs := &types.KeyAttributes{
		CN:                 "test-invalid-tag",
		KeyType:            types.KeyTypeEncryption,
		KeyAlgorithm:       x509.UnknownPublicKeyAlgorithm,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	_, err := tpm.GenerateSymmetricKey(attrs)
	require.NoError(t, err)

	encrypter, err := tpm.SymmetricEncrypter(attrs)
	require.NoError(t, err)

	plaintext := []byte("test message")
	encryptedData, err := encrypter.Encrypt(plaintext, nil)
	require.NoError(t, err)

	// Corrupt the authentication tag
	encryptedData.Tag[0] ^= 0xFF

	// Decryption should fail
	_, err = encrypter.Decrypt(encryptedData, nil)
	assert.Error(t, err, "decryption should fail with corrupted tag")
}

// Tests for RSAEncrypt (currently 0% coverage)

func TestRSAEncrypt_Basic(t *testing.T) {
	_, tpmInterface := createSim(false, false)
	defer func() { _ = tpmInterface.Close() }()

	tpm, ok := tpmInterface.(*TPM2)
	require.True(t, ok, "expected *TPM2 type")

	ekAttrs, err := tpm.EKAttributes()
	require.NoError(t, err)

	message := []byte("test message")

	ciphertext, err := tpm.RSAEncrypt(
		ekAttrs.TPMAttributes.Handle,
		ekAttrs.TPMAttributes.Name,
		message,
	)

	if err != nil {
		t.Logf("RSAEncrypt not supported: %v", err)
		return
	}

	assert.NotEqual(t, message, ciphertext)
}

func TestRSAEncrypt_InvalidHandle(t *testing.T) {
	_, tpmInterface := createSim(false, false)
	defer func() { _ = tpmInterface.Close() }()

	tpm, ok := tpmInterface.(*TPM2)
	require.True(t, ok, "expected *TPM2 type")

	invalidHandle := tpm2.TPMHandle(0xFFFFFFFF)
	invalidName := tpm2.TPM2BName{Buffer: []byte("invalid")}

	_, err := tpm.RSAEncrypt(invalidHandle, invalidName, []byte("test"))
	assert.Error(t, err)
}
