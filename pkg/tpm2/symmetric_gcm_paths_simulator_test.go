//go:build tpm_simulator

package tpm2

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/x509"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/crypto/aead"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newGCMEncrypter returns the TPM-backed AES-256-GCM encrypter of a freshly
// generated key.
func newGCMEncrypter(t *testing.T, cn string) *tpm2AESEncrypter {
	t.Helper()
	_, tpm := createSim(t, false)
	t.Cleanup(func() { _ = tpm.Close() })
	tpm2Instance := tpm.(*TPM2)
	attrs := &types.KeyAttributes{
		CN:                 cn,
		StoreType:          types.StoreTPM2,
		KeyAlgorithm:       x509.PublicKeyAlgorithm(0),
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}
	_, err := tpm2Instance.GenerateSymmetricKey(attrs)
	require.NoError(t, err)
	encrypter, err := tpm2Instance.SymmetricEncrypter(attrs)
	require.NoError(t, err)
	return encrypter.(*tpm2AESEncrypter)
}

// sealRandomNonce seals plaintext the way a fips140=only process does, with
// the TPM key's own material, and returns it as Encrypt would have.
func sealRandomNonce(t *testing.T, e *tpm2AESEncrypter, plaintext []byte) *types.EncryptedData {
	t.Helper()
	key, err := e.loadKeyMaterial()
	require.NoError(t, err)
	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	gcm, err := cipher.NewGCMWithRandomNonce(block)
	require.NoError(t, err)
	nonce, ciphertext, tag, err := aead.SplitGCMWithRandomNonce(gcm.Seal(nil, nil, plaintext, nil))
	require.NoError(t, err)
	return &types.EncryptedData{
		Ciphertext:   ciphertext,
		Nonce:        nonce,
		Tag:          tag,
		GCMNonceMode: types.GCMNonceModeRandom,
	}
}

// TestSymmetricDecrypt_OpensRandomNonceCiphertext proves a ciphertext a
// fips140=only process wrote opens in any process, and that the
// random-nonce framing is still authenticated and length-checked.
func TestSymmetricDecrypt_OpensRandomNonceCiphertext(t *testing.T) {
	e := newGCMEncrypter(t, "gcm-random-nonce")
	plaintext := []byte("written under fips140=only")

	opened, err := e.Decrypt(sealRandomNonce(t, e, plaintext), nil)
	require.NoError(t, err)
	assert.Equal(t, plaintext, opened)

	tampered := sealRandomNonce(t, e, plaintext)
	tampered.Tag[0] ^= 0xff
	_, err = e.Decrypt(tampered, nil)
	assert.Error(t, err, "a forged tag must not open")

	short := sealRandomNonce(t, e, plaintext)
	short.Tag = short.Tag[:12]
	_, err = e.Decrypt(short, nil)
	assert.Error(t, err, "the random-nonce framing carries only the full tag")

	_, err = e.Decrypt(sealRandomNonce(t, e, plaintext), &types.DecryptOptions{TagSize: 12})
	assert.ErrorIs(t, err, aead.ErrInvalidGCMTagSize)
}

// TestSymmetricEncrypt_RefusesUnsafeNonces proves Encrypt never seals under
// a nonce it cannot vouch for: a wrong-length caller nonce, a caller nonce
// already used with this key, or a nonce the random source failed to fill.
func TestSymmetricEncrypt_RefusesUnsafeNonces(t *testing.T) {
	e := newGCMEncrypter(t, "gcm-nonce-safety")
	plaintext := []byte("payload")

	_, err := e.Encrypt(plaintext, &types.EncryptOptions{Nonce: make([]byte, 5)})
	assert.Error(t, err, "a wrong-length nonce is refused")

	if !aead.ArbitraryIVGCMUsable() {
		// fips140=only refuses every caller nonce and never reads the
		// random source; the refusal above is the whole contract there.
		return
	}
	nonce := []byte("unique-nonce")
	_, err = e.Encrypt(plaintext, &types.EncryptOptions{Nonce: nonce})
	require.NoError(t, err)
	_, err = e.Encrypt(plaintext, &types.EncryptOptions{Nonce: nonce})
	assert.Error(t, err, "a reused (key, nonce) pair must never seal")

	e.tpm.random = failingReader{}
	_, err = e.Encrypt(plaintext, nil)
	assert.ErrorIs(t, err, errShortRead)
}

// TestSymmetricEncryptDecrypt_InvalidTagSize proves an unsupported tag
// length is refused on both sides instead of silently using another.
func TestSymmetricEncryptDecrypt_InvalidTagSize(t *testing.T) {
	e := newGCMEncrypter(t, "gcm-bad-tag-size")

	_, err := e.Encrypt([]byte("payload"), &types.EncryptOptions{TagSize: 3})
	assert.Error(t, err)

	sealed, err := e.Encrypt([]byte("payload"), nil)
	require.NoError(t, err)
	_, err = e.Decrypt(sealed, &types.DecryptOptions{TagSize: 3})
	assert.Error(t, err)
}
