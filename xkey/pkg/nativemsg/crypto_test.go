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

package nativemsg

import (
	"bytes"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSessionCrypto_NewSessionCrypto(t *testing.T) {
	sc, pubKey, err := NewSessionCrypto()
	require.NoError(t, err)
	require.NotNil(t, sc)
	assert.Len(t, pubKey, X25519KeySize)
	assert.False(t, sc.Ready())
}

func TestSessionCrypto_NewSessionCrypto_UniqueKeys(t *testing.T) {
	_, pub1, err := NewSessionCrypto()
	require.NoError(t, err)

	_, pub2, err := NewSessionCrypto()
	require.NoError(t, err)

	assert.False(t, bytes.Equal(pub1, pub2),
		"two independent keypairs must produce different public keys")
}

func TestSessionCrypto_PublicKey_ReturnsCopy(t *testing.T) {
	sc, pubKey, err := NewSessionCrypto()
	require.NoError(t, err)

	got := sc.PublicKey()
	assert.Equal(t, pubKey, got)

	// Mutate the returned slice; original must be unaffected.
	got[0] ^= 0xFF
	assert.NotEqual(t, got, sc.PublicKey())
}

func TestSessionCrypto_CompleteHandshake_Success(t *testing.T) {
	host, hostPub, err := NewSessionCrypto()
	require.NoError(t, err)

	ext, extPub, err := NewSessionCrypto()
	require.NoError(t, err)

	require.NoError(t, host.CompleteHandshake(extPub))
	require.NoError(t, ext.CompleteHandshake(hostPub))

	assert.True(t, host.Ready())
	assert.True(t, ext.Ready())
}

func TestSessionCrypto_CompleteHandshake_InvalidPublicKeySize(t *testing.T) {
	sc, _, err := NewSessionCrypto()
	require.NoError(t, err)

	// Too short.
	err = sc.CompleteHandshake([]byte{0x01, 0x02, 0x03})
	assert.True(t, errors.Is(err, ErrInvalidPublicKey))

	// Too long.
	err = sc.CompleteHandshake(make([]byte, X25519KeySize+1))
	assert.True(t, errors.Is(err, ErrInvalidPublicKey))

	// Empty.
	err = sc.CompleteHandshake(nil)
	assert.True(t, errors.Is(err, ErrInvalidPublicKey))
}

func TestSessionCrypto_CompleteHandshake_DoubleHandshake(t *testing.T) {
	host, _, err := NewSessionCrypto()
	require.NoError(t, err)

	_, extPub, err := NewSessionCrypto()
	require.NoError(t, err)

	require.NoError(t, host.CompleteHandshake(extPub))
	assert.True(t, host.Ready())

	// Second handshake attempt must fail.
	err = host.CompleteHandshake(extPub)
	assert.True(t, errors.Is(err, ErrHandshakeFailed))
}

func TestSessionCrypto_EncryptDecrypt_RoundTrip(t *testing.T) {
	host, hostPub, err := NewSessionCrypto()
	require.NoError(t, err)

	ext, extPub, err := NewSessionCrypto()
	require.NoError(t, err)

	require.NoError(t, host.CompleteHandshake(extPub))
	require.NoError(t, ext.CompleteHandshake(hostPub))

	// Host -> Extension
	plaintext := []byte("hello from host")
	nonce, ciphertext, err := host.Encrypt(plaintext)
	require.NoError(t, err)
	assert.NotEmpty(t, ciphertext)
	assert.NotEqual(t, plaintext, ciphertext)

	decrypted, err := ext.Decrypt(nonce, ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)

	// Extension -> Host
	plaintext2 := []byte("hello from extension")
	nonce2, ciphertext2, err := ext.Encrypt(plaintext2)
	require.NoError(t, err)

	decrypted2, err := host.Decrypt(nonce2, ciphertext2)
	require.NoError(t, err)
	assert.Equal(t, plaintext2, decrypted2)
}

func TestSessionCrypto_EncryptDecrypt_EmptyMessage(t *testing.T) {
	host, hostPub, err := NewSessionCrypto()
	require.NoError(t, err)

	ext, extPub, err := NewSessionCrypto()
	require.NoError(t, err)

	require.NoError(t, host.CompleteHandshake(extPub))
	require.NoError(t, ext.CompleteHandshake(hostPub))

	nonce, ciphertext, err := host.Encrypt([]byte{})
	require.NoError(t, err)

	decrypted, err := ext.Decrypt(nonce, ciphertext)
	require.NoError(t, err)
	assert.Empty(t, decrypted)
}

func TestSessionCrypto_EncryptDecrypt_LargeMessage(t *testing.T) {
	host, hostPub, err := NewSessionCrypto()
	require.NoError(t, err)

	ext, extPub, err := NewSessionCrypto()
	require.NoError(t, err)

	require.NoError(t, host.CompleteHandshake(extPub))
	require.NoError(t, ext.CompleteHandshake(hostPub))

	// 64 KiB message.
	plaintext := make([]byte, 64*1024)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}

	nonce, ciphertext, err := host.Encrypt(plaintext)
	require.NoError(t, err)

	decrypted, err := ext.Decrypt(nonce, ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestSessionCrypto_Encrypt_BeforeHandshake(t *testing.T) {
	sc, _, err := NewSessionCrypto()
	require.NoError(t, err)

	_, _, err = sc.Encrypt([]byte("test"))
	assert.True(t, errors.Is(err, ErrHandshakeRequired))
}

func TestSessionCrypto_Decrypt_BeforeHandshake(t *testing.T) {
	sc, _, err := NewSessionCrypto()
	require.NoError(t, err)

	_, err = sc.Decrypt(1, []byte("test"))
	assert.True(t, errors.Is(err, ErrHandshakeRequired))
}

func TestSessionCrypto_ReplayProtection(t *testing.T) {
	host, hostPub, err := NewSessionCrypto()
	require.NoError(t, err)

	ext, extPub, err := NewSessionCrypto()
	require.NoError(t, err)

	require.NoError(t, host.CompleteHandshake(extPub))
	require.NoError(t, ext.CompleteHandshake(hostPub))

	nonce, ciphertext, err := host.Encrypt([]byte("message 1"))
	require.NoError(t, err)

	// First decryption succeeds.
	_, err = ext.Decrypt(nonce, ciphertext)
	require.NoError(t, err)

	// Replaying the same nonce must be rejected.
	_, err = ext.Decrypt(nonce, ciphertext)
	assert.True(t, errors.Is(err, ErrReplayDetected))
}

func TestSessionCrypto_ReplayProtection_OutOfOrderLowNonce(t *testing.T) {
	host, hostPub, err := NewSessionCrypto()
	require.NoError(t, err)

	ext, extPub, err := NewSessionCrypto()
	require.NoError(t, err)

	require.NoError(t, host.CompleteHandshake(extPub))
	require.NoError(t, ext.CompleteHandshake(hostPub))

	// Send two messages.
	nonce1, ct1, err := host.Encrypt([]byte("msg1"))
	require.NoError(t, err)

	nonce2, ct2, err := host.Encrypt([]byte("msg2"))
	require.NoError(t, err)

	// Receive msg2 first (out of order).
	_, err = ext.Decrypt(nonce2, ct2)
	require.NoError(t, err)

	// Attempting msg1 (lower nonce) must be rejected.
	_, err = ext.Decrypt(nonce1, ct1)
	assert.True(t, errors.Is(err, ErrReplayDetected))
}

func TestSessionCrypto_NonceMonotonicallyIncreases(t *testing.T) {
	host, hostPub, err := NewSessionCrypto()
	require.NoError(t, err)

	ext, extPub, err := NewSessionCrypto()
	require.NoError(t, err)

	require.NoError(t, host.CompleteHandshake(extPub))
	require.NoError(t, ext.CompleteHandshake(hostPub))

	var prevNonce uint64
	for i := 0; i < 100; i++ {
		nonce, _, err := host.Encrypt([]byte("tick"))
		require.NoError(t, err)
		assert.Greater(t, nonce, prevNonce,
			"nonce must strictly increase")
		prevNonce = nonce
	}
}

func TestSessionCrypto_NonceStartsAtOne(t *testing.T) {
	host, hostPub, err := NewSessionCrypto()
	require.NoError(t, err)

	_, extPub, err := NewSessionCrypto()
	require.NoError(t, err)

	require.NoError(t, host.CompleteHandshake(extPub))

	nonce, _, err := host.Encrypt([]byte("first"))
	require.NoError(t, err)
	assert.Equal(t, uint64(1), nonce, "first nonce must be 1")

	_ = hostPub // suppress unused
}

func TestSessionCrypto_TamperedCiphertext(t *testing.T) {
	host, hostPub, err := NewSessionCrypto()
	require.NoError(t, err)

	ext, extPub, err := NewSessionCrypto()
	require.NoError(t, err)

	require.NoError(t, host.CompleteHandshake(extPub))
	require.NoError(t, ext.CompleteHandshake(hostPub))

	nonce, ciphertext, err := host.Encrypt([]byte("sensitive data"))
	require.NoError(t, err)

	// Flip a byte in the ciphertext.
	tampered := make([]byte, len(ciphertext))
	copy(tampered, ciphertext)
	tampered[0] ^= 0xFF

	_, err = ext.Decrypt(nonce, tampered)
	assert.True(t, errors.Is(err, ErrDecryptionFailed))
}

func TestSessionCrypto_TruncatedCiphertext(t *testing.T) {
	host, hostPub, err := NewSessionCrypto()
	require.NoError(t, err)

	ext, extPub, err := NewSessionCrypto()
	require.NoError(t, err)

	require.NoError(t, host.CompleteHandshake(extPub))
	require.NoError(t, ext.CompleteHandshake(hostPub))

	nonce, ciphertext, err := host.Encrypt([]byte("test data"))
	require.NoError(t, err)

	// Truncate ciphertext to just a few bytes.
	_, err = ext.Decrypt(nonce, ciphertext[:4])
	assert.True(t, errors.Is(err, ErrDecryptionFailed))
}

func TestSessionCrypto_CrossDecryptFails(t *testing.T) {
	// Verify that the directional keys work correctly: a message encrypted
	// with the host's sendKey cannot be decrypted by the host itself using
	// its recvKey (which is the extension's sendKey).
	host, hostPub, err := NewSessionCrypto()
	require.NoError(t, err)

	ext, extPub, err := NewSessionCrypto()
	require.NoError(t, err)

	require.NoError(t, host.CompleteHandshake(extPub))
	require.NoError(t, ext.CompleteHandshake(hostPub))

	nonce, ciphertext, err := host.Encrypt([]byte("host message"))
	require.NoError(t, err)

	// Host should not be able to decrypt its own message (wrong key direction).
	_, err = host.Decrypt(nonce, ciphertext)
	assert.Error(t, err)
}

func TestSessionCrypto_DirectionalKeySymmetry(t *testing.T) {
	// Verify that regardless of which peer has the "lower" public key,
	// bidirectional communication works correctly.
	for i := 0; i < 10; i++ {
		a, aPub, err := NewSessionCrypto()
		require.NoError(t, err)

		b, bPub, err := NewSessionCrypto()
		require.NoError(t, err)

		require.NoError(t, a.CompleteHandshake(bPub))
		require.NoError(t, b.CompleteHandshake(aPub))

		// A -> B
		nonce, ct, err := a.Encrypt([]byte("from A"))
		require.NoError(t, err)
		pt, err := b.Decrypt(nonce, ct)
		require.NoError(t, err)
		assert.Equal(t, []byte("from A"), pt)

		// B -> A
		nonce, ct, err = b.Encrypt([]byte("from B"))
		require.NoError(t, err)
		pt, err = a.Decrypt(nonce, ct)
		require.NoError(t, err)
		assert.Equal(t, []byte("from B"), pt)
	}
}

func TestSessionCrypto_WrongPeerDecryptFails(t *testing.T) {
	// A message from host->ext should not be decryptable by a third party.
	host, _, err := NewSessionCrypto()
	require.NoError(t, err)

	ext, extPub, err := NewSessionCrypto()
	require.NoError(t, err)

	third, thirdPub, err := NewSessionCrypto()
	require.NoError(t, err)

	require.NoError(t, host.CompleteHandshake(extPub))
	require.NoError(t, ext.CompleteHandshake(host.PublicKey()))

	// Third party handshakes with ext (different shared secret).
	require.NoError(t, third.CompleteHandshake(extPub))

	nonce, ct, err := host.Encrypt([]byte("secret"))
	require.NoError(t, err)

	// Third party cannot decrypt host's message.
	_, err = third.Decrypt(nonce, ct)
	assert.Error(t, err)

	_ = thirdPub // suppress unused
}

func TestSessionCrypto_DecryptWithNonceZero(t *testing.T) {
	host, hostPub, err := NewSessionCrypto()
	require.NoError(t, err)

	ext, extPub, err := NewSessionCrypto()
	require.NoError(t, err)

	require.NoError(t, host.CompleteHandshake(extPub))
	require.NoError(t, ext.CompleteHandshake(hostPub))

	// Nonce 0 should be rejected (recvNonce starts at 0, 0 <= 0).
	_, err = ext.Decrypt(0, []byte("anything"))
	assert.True(t, errors.Is(err, ErrReplayDetected))
}
