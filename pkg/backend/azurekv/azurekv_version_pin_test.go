// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

//go:build azurekv

package azurekv

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rsaVerify verifies a PKCS#1 v1.5 SHA-256 signature against pubKey,
// asserting that pubKey really is an *rsa.PublicKey.
func rsaVerify(t *testing.T, pubKey crypto.PublicKey, digest, sig []byte) error {
	t.Helper()
	rsaPub, ok := pubKey.(*rsa.PublicKey)
	require.True(t, ok, "public key must be an RSA public key")
	return rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, digest, sig)
}

// rsaEncryptOAEP encrypts plaintext with RSA-OAEP/SHA-256 against pubKey,
// asserting that pubKey really is an *rsa.PublicKey.
func rsaEncryptOAEP(t *testing.T, pubKey crypto.PublicKey, plaintext []byte) []byte {
	t.Helper()
	rsaPub, ok := pubKey.(*rsa.PublicKey)
	require.True(t, ok, "public key must be an RSA public key")
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPub, plaintext, nil)
	require.NoError(t, err)
	return ciphertext
}

// TestSigner_PinsVersionAcrossRotation verifies that a Signer built before a
// key rotation keeps signing with (and reporting the public key of) the
// version it was constructed against, instead of silently following the key
// to its latest version (H12).
func TestSigner_PinsVersionAcrossRotation(t *testing.T) {
	mockClient := NewMockKeyVaultClient()
	config := &Config{
		VaultURL:    "https://test-vault.vault.azure.net/",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}
	b, err := NewBackendWithClient(config, mockClient)
	require.NoError(t, err)

	attrs := &types.KeyAttributes{
		CN:           "test-signer-pin",
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_AZUREKV,
		KeyAlgorithm: x509.RSA,
	}
	_, err = b.CreateKey(attrs)
	require.NoError(t, err)

	ctx := context.Background()
	oldSigner, err := b.Signer(ctx, attrs)
	require.NoError(t, err)
	oldPublicKey := oldSigner.Public()

	// Rotate the key in Vault.
	require.NoError(t, b.RotateKey(ctx, attrs))

	newSigner, err := b.Signer(ctx, attrs)
	require.NoError(t, err)
	newPublicKey := newSigner.Public()

	// The two signers must report different public keys: the rotation
	// really did produce a new version.
	assert.NotEqual(t, oldPublicKey, newPublicKey)

	digest := sha256.Sum256([]byte("pin me to my version"))

	// The pre-rotation signer must still sign with its own (old) key, and
	// its signature must verify only under the old public key.
	oldSig, err := oldSigner.Sign(nil, digest[:], crypto.SHA256)
	require.NoError(t, err)
	require.NoError(t, rsaVerify(t, oldPublicKey, digest[:], oldSig))
	assert.Error(t, rsaVerify(t, newPublicKey, digest[:], oldSig))

	// The post-rotation signer must sign with the new key.
	newSig, err := newSigner.Sign(nil, digest[:], crypto.SHA256)
	require.NoError(t, err)
	require.NoError(t, rsaVerify(t, newPublicKey, digest[:], newSig))
}

// TestDecrypter_PinsVersionAcrossRotation verifies that a Decrypter built
// before a key rotation keeps decrypting with (and reporting the public key
// of) the version it was constructed against (H12).
func TestDecrypter_PinsVersionAcrossRotation(t *testing.T) {
	mockClient := NewMockKeyVaultClient()
	config := &Config{
		VaultURL:    "https://test-vault.vault.azure.net/",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}
	b, err := NewBackendWithClient(config, mockClient)
	require.NoError(t, err)

	attrs := &types.KeyAttributes{
		CN:           "test-decrypter-pin",
		KeyType:      backend.KEY_TYPE_ENCRYPTION,
		StoreType:    backend.STORE_AZUREKV,
		KeyAlgorithm: x509.RSA,
	}
	_, err = b.CreateKey(attrs)
	require.NoError(t, err)

	ctx := context.Background()
	oldDecrypter, err := b.Decrypter(ctx, attrs)
	require.NoError(t, err)

	require.NoError(t, b.RotateKey(ctx, attrs))

	newDecrypter, err := b.Decrypter(ctx, attrs)
	require.NoError(t, err)

	assert.NotEqual(t, oldDecrypter.Public(), newDecrypter.Public())

	// A ciphertext produced under the old public key must still decrypt
	// through the pre-rotation Decrypter, proving it stayed pinned to the
	// key whose public half it reports rather than following the key to
	// its new (post-rotation) version.
	plaintext := []byte("secret pinned to old version")
	ciphertext := rsaEncryptOAEP(t, oldDecrypter.Public(), plaintext)

	got, err := oldDecrypter.Decrypt(nil, ciphertext, &rsa.OAEPOptions{Hash: crypto.SHA256})
	require.NoError(t, err)
	assert.Equal(t, plaintext, got)
}
