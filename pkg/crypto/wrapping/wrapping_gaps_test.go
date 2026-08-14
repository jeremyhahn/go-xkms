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

package wrapping

import (
	"crypto/aes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
)

func TestWrappingErrorMessages(t *testing.T) {
	t.Run("NilInputError", func(t *testing.T) {
		assert.Contains(t, (&NilInputError{Field: "publicKey"}).Error(), "publicKey")
	})
	t.Run("EmptyInputError", func(t *testing.T) {
		assert.Contains(t, (&EmptyInputError{Field: "keyMaterial"}).Error(), "keyMaterial")
	})
	t.Run("UnsupportedAlgorithmError", func(t *testing.T) {
		assert.Contains(t, (&UnsupportedAlgorithmError{Algorithm: "FOO"}).Error(), "FOO")
	})
	t.Run("InvalidKeySizeError", func(t *testing.T) {
		assert.Contains(t, (&InvalidKeySizeError{Algorithm: "aes-kwp", Size: 10}).Error(), "aes-kwp")
	})
	t.Run("MalformedWrappedKeyError", func(t *testing.T) {
		assert.Contains(t, (&MalformedWrappedKeyError{Reason: "too short"}).Error(), "too short")
	})
	t.Run("CryptoError", func(t *testing.T) {
		inner := errors.New("boom")
		err := &CryptoError{Op: "rsa.EncryptOAEP", Err: inner}
		assert.Contains(t, err.Error(), "rsa.EncryptOAEP")
		assert.Contains(t, err.Error(), "boom")
		assert.True(t, errors.Is(err, inner))
	})
}

// TestWrapRSAOAEP_MessageTooLarge exercises the rsa.EncryptOAEP failure branch:
// a 2048-bit key with SHA-256 OAEP caps the message at 190 bytes, so wrapping
// larger key material fails. (A sub-minimum RSA key would be rejected by Go's
// crypto/rsa, so an oversized message is the reachable trigger.)
func TestWrapRSAOAEP_MessageTooLarge(t *testing.T) {
	key, err := generateTestKeyPair(2048)
	require.NoError(t, err)
	oversized := make([]byte, 300) // > 190-byte OAEP capacity for a 2048-bit key

	_, err = WrapRSAOAEP(oversized, &key.PublicKey, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	require.Error(t, err)
	var cErr *CryptoError
	assert.True(t, errors.As(err, &cErr), "expected CryptoError, got %v", err)
}

// TestUnwrapRSAAES_EmptyAESKey crafts a payload whose "AES key" ciphertext
// decrypts to empty, exercising the "empty aes key after unwrap" branch.
func TestUnwrapRSAAES_EmptyAESKey(t *testing.T) {
	priv, err := generateTestKeyPair(2048)
	require.NoError(t, err)

	emptyWrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &priv.PublicKey, []byte{}, nil)
	require.NoError(t, err)
	material := make([]byte, 16)
	wrapped := make([]byte, 4+len(emptyWrapped)+len(material))
	binary.BigEndian.PutUint32(wrapped[0:4], uint32(len(emptyWrapped)))
	copy(wrapped[4:4+len(emptyWrapped)], emptyWrapped)
	copy(wrapped[4+len(emptyWrapped):], material)

	_, err = UnwrapRSAAES(wrapped, priv, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
	require.Error(t, err)
	var mErr *MalformedWrappedKeyError
	require.True(t, errors.As(err, &mErr), "expected MalformedWrappedKeyError, got %v", err)
	assert.Equal(t, "empty aes key after unwrap", mErr.Reason)
}

// TestUnwrapRSAAES_CorruptedMaterial corrupts the material portion (not the AES
// key), so RSA-OAEP succeeds but the AES-KWP unwrap fails.
func TestUnwrapRSAAES_CorruptedMaterial(t *testing.T) {
	priv, err := generateTestKeyPair(2048)
	require.NoError(t, err)
	material := []byte("more than one block of test key material for corrupting")
	wrapped, err := WrapRSAAES(material, &priv.PublicKey, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
	require.NoError(t, err)

	aesKeyLen := binary.BigEndian.Uint32(wrapped[0:4])
	materialStart := 4 + int(aesKeyLen)
	wrapped[materialStart+1] ^= 0xFF

	_, err = UnwrapRSAAES(wrapped, priv, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
	require.Error(t, err)
	var mErr *MalformedWrappedKeyError
	assert.True(t, errors.As(err, &mErr), "expected MalformedWrappedKeyError, got %v", err)
}

// TestAESKWP_SpecialCaseErrors exercises the single-block AIV/MLI validation
// branches of UnwrapAESKWP.
func TestAESKWP_SpecialCaseErrors(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	block, err := aes.NewCipher(key)
	require.NoError(t, err)

	t.Run("InvalidAIV", func(t *testing.T) {
		in := make([]byte, 16)
		_, err := rand.Read(in)
		require.NoError(t, err)
		out := make([]byte, 16)
		block.Encrypt(out, in)
		_, err = UnwrapAESKWP(out, key)
		require.Error(t, err)
		var mErr *MalformedWrappedKeyError
		assert.True(t, errors.As(err, &mErr), "expected MalformedWrappedKeyError, got %v", err)
	})

	t.Run("InvalidMLI", func(t *testing.T) {
		in := make([]byte, 16)
		binary.BigEndian.PutUint32(in[0:4], 0xA65959A6)
		binary.BigEndian.PutUint32(in[4:8], 9) // > 8, invalid for a single 8-byte block
		_, err := rand.Read(in[8:16])
		require.NoError(t, err)
		out := make([]byte, 16)
		block.Encrypt(out, in)
		_, err = UnwrapAESKWP(out, key)
		require.Error(t, err)
		var mErr *MalformedWrappedKeyError
		assert.True(t, errors.As(err, &mErr), "expected MalformedWrappedKeyError, got %v", err)
	})
}
