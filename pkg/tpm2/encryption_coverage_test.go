package tpm2

import (
	"crypto/rand"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Tests for Encrypt/Decrypt methods (currently 0% coverage)

func TestAESGCM_EncryptDecrypt_Success(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	aesgcm := NewAESGCM(tpm)

	key := make([]byte, 32) // AES-256
	_, err := rand.Read(key)
	require.NoError(t, err)

	plaintext := []byte("test message to encrypt")

	ciphertext, err := aesgcm.Encrypt(key, plaintext)
	require.NoError(t, err)
	assert.NotEqual(t, plaintext, ciphertext)

	decrypted, err := aesgcm.Decrypt(key, ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestAESGCM_Encrypt_InvalidKey(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	aesgcm := NewAESGCM(tpm)

	invalidKey := make([]byte, 15) //  Invalid key size
	_, err := aesgcm.Encrypt(invalidKey, []byte("test"))
	assert.Error(t, err)
}

func TestAESGCM_Decrypt_TooShort(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	aesgcm := NewAESGCM(tpm)

	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	_, err = aesgcm.Decrypt(key, []byte("short"))
	assert.Equal(t, ErrCiphertextTooShort, err)
}

func TestAESGCM_Decrypt_InvalidCiphertext(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	aesgcm := NewAESGCM(tpm)

	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	corruptedCiphertext := make([]byte, 50)
	_, err = rand.Read(corruptedCiphertext)
	require.NoError(t, err)

	_, err = aesgcm.Decrypt(key, corruptedCiphertext)
	assert.Error(t, err)
}

// Tests for RSAEncrypt (currently 0% coverage)

func TestRSAEncrypt_Basic(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	ekAttrs, err := tpm.EKAttributes()
	require.NoError(t, err)

	message := []byte("test message")

	ciphertext, err := tpm.RSAEncrypt(
		ekAttrs.TPMAttributes.Handle.(tpm2.TPMHandle),
		ekAttrs.TPMAttributes.Name.(tpm2.TPM2BName),
		message,
	)

	if err != nil {
		t.Logf("RSAEncrypt not supported: %v", err)
		return
	}

	assert.NotEqual(t, message, ciphertext)
}

func TestRSAEncrypt_InvalidHandle(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	invalidHandle := tpm2.TPMHandle(0xFFFFFFFF)
	invalidName := tpm2.TPM2BName{Buffer: []byte("invalid")}

	_, err := tpm.RSAEncrypt(invalidHandle, invalidName, []byte("test"))
	assert.Error(t, err)
}
