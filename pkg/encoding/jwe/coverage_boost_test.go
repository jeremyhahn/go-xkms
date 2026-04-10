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

package jwe

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEncrypt_NilPlaintext verifies that Encrypt returns an error when
// provided nil plaintext.
func TestEncrypt_NilPlaintext(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	enc, err := NewEncrypter("RSA-OAEP-256", "A256GCM", &key.PublicKey)
	require.NoError(t, err)

	_, err = enc.Encrypt(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "plaintext cannot be nil")
}

// TestEncryptWithHeader_NilPlaintext verifies that EncryptWithHeader returns
// an error when provided nil plaintext.
func TestEncryptWithHeader_NilPlaintext(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	enc, err := NewEncrypter("RSA-OAEP-256", "A256GCM", &key.PublicKey)
	require.NoError(t, err)

	_, err = enc.EncryptWithHeader(nil, map[string]interface{}{"kid": "x"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "plaintext cannot be nil")
}

// TestEncryptWithHeader_EmptyHeaders verifies that an empty header map
// delegates to Encrypt.
func TestEncryptWithHeader_EmptyHeaders(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	enc, err := NewEncrypter("RSA-OAEP-256", "A256GCM", &key.PublicKey)
	require.NoError(t, err)

	jweStr, err := enc.EncryptWithHeader([]byte("test data"), map[string]interface{}{})
	require.NoError(t, err)
	assert.NotEmpty(t, jweStr)

	dec := NewDecrypter()
	plain, err := dec.Decrypt(jweStr, key)
	require.NoError(t, err)
	assert.Equal(t, []byte("test data"), plain)
}

// TestEncryptWithHeader_ECDSAKey verifies the ECDSA branch in
// EncryptWithHeader's switch statement.
func TestEncryptWithHeader_ECDSAKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	enc, err := NewEncrypter("ECDH-ES+A256KW", "A256GCM", &key.PublicKey)
	require.NoError(t, err)

	jweStr, err := enc.EncryptWithHeader([]byte("ecdh payload"), map[string]interface{}{
		"kid": "ec-key-1",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, jweStr)

	kid, err := ExtractKID(jweStr)
	require.NoError(t, err)
	assert.Equal(t, "ec-key-1", kid)

	dec := NewDecrypter()
	plain, err := dec.Decrypt(jweStr, key)
	require.NoError(t, err)
	assert.Equal(t, []byte("ecdh payload"), plain)
}

// TestEncryptWithHeader_SymmetricKey verifies the []byte key branch in
// EncryptWithHeader's switch statement.
func TestEncryptWithHeader_SymmetricKey(t *testing.T) {
	symKey := make([]byte, 32)
	_, err := rand.Read(symKey)
	require.NoError(t, err)

	enc, err := NewEncrypter("A256KW", "A256GCM", symKey)
	require.NoError(t, err)

	jweStr, err := enc.EncryptWithHeader([]byte("symmetric payload"), map[string]interface{}{
		"kid": "sym-key-1",
		"cty": "application/json",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, jweStr)

	kid, err := ExtractKID(jweStr)
	require.NoError(t, err)
	assert.Equal(t, "sym-key-1", kid)

	dec := NewDecrypter()
	plain, err := dec.Decrypt(jweStr, symKey)
	require.NoError(t, err)
	assert.Equal(t, []byte("symmetric payload"), plain)
}
