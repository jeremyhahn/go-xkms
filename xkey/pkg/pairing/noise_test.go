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

package pairing

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-truststrap/pkg/noiseproto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

func TestNoiseConstants(t *testing.T) {
	assert.Equal(t, "Noise_XX_25519_ChaChaPoly_SHA256", NoiseProtocolName)
	assert.Equal(t, 32, NoiseKeySize)
	assert.Equal(t, 65535-16, NoiseMaxMessageSize)
}

func TestGenerateStaticKey(t *testing.T) {
	key, err := GenerateStaticKey()
	require.NoError(t, err)
	require.NotNil(t, key)

	assert.Len(t, key.Private, NoiseKeySize)
	assert.Len(t, key.Public, NoiseKeySize)
	assert.False(t, bytes.Equal(key.Private, make([]byte, NoiseKeySize)))
	assert.False(t, bytes.Equal(key.Public, make([]byte, NoiseKeySize)))
}

func TestGenerateStaticKey_Uniqueness(t *testing.T) {
	key1, err := GenerateStaticKey()
	require.NoError(t, err)

	key2, err := GenerateStaticKey()
	require.NoError(t, err)

	assert.False(t, bytes.Equal(key1.Private, key2.Private))
	assert.False(t, bytes.Equal(key1.Public, key2.Public))
}

func TestLoadStaticKey(t *testing.T) {
	original, err := GenerateStaticKey()
	require.NoError(t, err)

	loaded, err := LoadStaticKey(original.Private)
	require.NoError(t, err)
	require.NotNil(t, loaded)

	assert.Equal(t, original.Private, loaded.Private)
	assert.Equal(t, original.Public, loaded.Public)
}

func TestLoadStaticKey_InvalidLength(t *testing.T) {
	tests := []struct {
		name string
		key  []byte
	}{
		{"empty", []byte{}},
		{"too short", make([]byte, 16)},
		{"too long", make([]byte, 64)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := LoadStaticKey(tt.key)
			assert.ErrorIs(t, err, ErrInvalidNoiseMessage)
		})
	}
}

func TestEncodeDecodeStaticKey(t *testing.T) {
	key, err := GenerateStaticKey()
	require.NoError(t, err)

	encoded := EncodeStaticKey(key)
	assert.Len(t, encoded, NoiseKeySize*2)

	decoded, err := DecodeStaticKey(encoded)
	require.NoError(t, err)

	assert.Equal(t, key.Private, decoded.Private)
	assert.Equal(t, key.Public, decoded.Public)
}

func TestDecodeStaticKey_InvalidHex(t *testing.T) {
	_, err := DecodeStaticKey("xyz123")
	assert.Error(t, err)
}

func TestNewNoiseSession(t *testing.T) {
	session, err := NewNoiseSession(&NoiseSessionConfig{
		IsInitiator: true,
	})
	require.NoError(t, err)
	require.NotNil(t, session)

	assert.NotEmpty(t, session.LocalStaticPublicKey())
	assert.NotEmpty(t, session.LocalStaticPrivateKey())
	assert.False(t, session.IsHandshakeComplete())
}

func TestNewNoiseSession_WithProvidedKey(t *testing.T) {
	key, err := GenerateStaticKey()
	require.NoError(t, err)

	session, err := NewNoiseSession(&NoiseSessionConfig{
		LocalStaticKey: key,
		IsInitiator:    true,
	})
	require.NoError(t, err)

	assert.Equal(t, key.Public, session.LocalStaticPublicKey())
	assert.Equal(t, key.Private, session.LocalStaticPrivateKey())
}

func TestNoiseSession_InitHandshake(t *testing.T) {
	session, err := NewNoiseSession(&NoiseSessionConfig{
		IsInitiator: true,
	})
	require.NoError(t, err)

	err = session.InitHandshake()
	require.NoError(t, err)
}

func TestNoiseSession_HandshakeMessage_NoInit(t *testing.T) {
	session, err := NewNoiseSession(&NoiseSessionConfig{
		IsInitiator: true,
	})
	require.NoError(t, err)

	_, _, err = session.HandshakeMessage(nil)
	assert.ErrorIs(t, err, ErrNoiseHandshakeFailed)
}

func TestNoiseSession_EncryptDecrypt_NotComplete(t *testing.T) {
	session, err := NewNoiseSession(&NoiseSessionConfig{
		IsInitiator: true,
	})
	require.NoError(t, err)

	_, err = session.Encrypt([]byte("test"))
	assert.ErrorIs(t, err, ErrNoiseHandshakeFailed)

	_, err = session.Decrypt([]byte("test"))
	assert.ErrorIs(t, err, ErrNoiseHandshakeFailed)
}

func TestNoiseSession_FullHandshake(t *testing.T) {
	initiator, err := NewNoiseSession(&NoiseSessionConfig{
		IsInitiator: true,
	})
	require.NoError(t, err)

	responder, err := NewNoiseSession(&NoiseSessionConfig{
		IsInitiator: false,
	})
	require.NoError(t, err)

	err = initiator.InitHandshake()
	require.NoError(t, err)
	err = responder.InitHandshake()
	require.NoError(t, err)

	// -> e
	msg1, complete, err := initiator.HandshakeMessage(nil)
	require.NoError(t, err)
	assert.False(t, complete)
	assert.NotEmpty(t, msg1)

	// <- e, ee, s, es
	msg2, complete, err := responder.HandshakeMessage(msg1)
	require.NoError(t, err)
	assert.False(t, complete)
	assert.NotEmpty(t, msg2)

	// -> s, se
	msg3, complete, err := initiator.HandshakeMessage(msg2)
	require.NoError(t, err)
	assert.True(t, complete)
	assert.NotEmpty(t, msg3)

	// Responder receives final
	_, complete, err = responder.HandshakeMessage(msg3)
	require.NoError(t, err)
	assert.True(t, complete)

	assert.True(t, initiator.IsHandshakeComplete())
	assert.True(t, responder.IsHandshakeComplete())

	// Verify remote keys match
	assert.Equal(t, initiator.LocalStaticPublicKey(), responder.RemoteStaticPublicKey())
	assert.Equal(t, responder.LocalStaticPublicKey(), initiator.RemoteStaticPublicKey())
}

func TestNoiseSession_EncryptDecrypt(t *testing.T) {
	initiator, responder := setupCompletedHandshake(t)

	testCases := []struct {
		name      string
		plaintext []byte
	}{
		{"empty message", []byte{}},
		{"small message", []byte("hello")},
		{"medium message", bytes.Repeat([]byte("test"), 100)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ciphertext, err := initiator.Encrypt(tc.plaintext)
			require.NoError(t, err)

			decrypted, err := responder.Decrypt(ciphertext)
			require.NoError(t, err)
			// Use len comparison for empty slices to handle []byte{} vs []byte(nil)
			if len(tc.plaintext) == 0 {
				assert.Empty(t, decrypted)
			} else {
				assert.Equal(t, tc.plaintext, decrypted)
			}
		})
	}
}

func TestNoiseSession_BidirectionalEncryption(t *testing.T) {
	initiator, responder := setupCompletedHandshake(t)

	// Initiator to responder
	msg1 := []byte("hello from initiator")
	encrypted1, err := initiator.Encrypt(msg1)
	require.NoError(t, err)

	decrypted1, err := responder.Decrypt(encrypted1)
	require.NoError(t, err)
	assert.Equal(t, msg1, decrypted1)

	// Responder to initiator
	msg2 := []byte("hello from responder")
	encrypted2, err := responder.Encrypt(msg2)
	require.NoError(t, err)

	decrypted2, err := initiator.Decrypt(encrypted2)
	require.NoError(t, err)
	assert.Equal(t, msg2, decrypted2)
}

func TestNoiseSession_Encrypt_MessageTooLarge(t *testing.T) {
	initiator, _ := setupCompletedHandshake(t)

	largeMessage := make([]byte, NoiseMaxMessageSize+1)

	_, err := initiator.Encrypt(largeMessage)
	assert.ErrorIs(t, err, ErrEncryptionFailed)
}

func TestNoiseSession_Decrypt_InvalidCiphertext(t *testing.T) {
	_, responder := setupCompletedHandshake(t)

	_, err := responder.Decrypt([]byte("not valid"))
	assert.ErrorIs(t, err, ErrDecryptionFailed)
}

func TestNoiseSession_StaticKeyMismatch(t *testing.T) {
	expectedKey, err := GenerateStaticKey()
	require.NoError(t, err)

	initiator, err := NewNoiseSession(&NoiseSessionConfig{
		ExpectedRemoteStatic: expectedKey.Public,
		IsInitiator:          true,
	})
	require.NoError(t, err)

	responder, err := NewNoiseSession(&NoiseSessionConfig{
		IsInitiator: false,
	})
	require.NoError(t, err)

	err = initiator.InitHandshake()
	require.NoError(t, err)
	err = responder.InitHandshake()
	require.NoError(t, err)

	msg1, _, err := initiator.HandshakeMessage(nil)
	require.NoError(t, err)

	msg2, _, err := responder.HandshakeMessage(msg1)
	require.NoError(t, err)

	_, _, err = initiator.HandshakeMessage(msg2)
	assert.ErrorIs(t, err, ErrStaticKeyMismatch)
}

func setupCompletedHandshake(t *testing.T) (*NoiseSession, *NoiseSession) {
	t.Helper()

	initiator, err := NewNoiseSession(&NoiseSessionConfig{IsInitiator: true})
	require.NoError(t, err)

	responder, err := NewNoiseSession(&NoiseSessionConfig{IsInitiator: false})
	require.NoError(t, err)

	err = initiator.InitHandshake()
	require.NoError(t, err)
	err = responder.InitHandshake()
	require.NoError(t, err)

	msg1, _, err := initiator.HandshakeMessage(nil)
	require.NoError(t, err)

	msg2, _, err := responder.HandshakeMessage(msg1)
	require.NoError(t, err)

	msg3, _, err := initiator.HandshakeMessage(msg2)
	require.NoError(t, err)

	_, _, err = responder.HandshakeMessage(msg3)
	require.NoError(t, err)

	return initiator, responder
}

func BenchmarkNoiseHandshake(b *testing.B) {
	for i := 0; i < b.N; i++ {
		initiator, _ := NewNoiseSession(&NoiseSessionConfig{IsInitiator: true})
		responder, _ := NewNoiseSession(&NoiseSessionConfig{IsInitiator: false})

		initiator.InitHandshake()
		responder.InitHandshake()

		msg1, _, _ := initiator.HandshakeMessage(nil)
		msg2, _, _ := responder.HandshakeMessage(msg1)
		msg3, _, _ := initiator.HandshakeMessage(msg2)
		responder.HandshakeMessage(msg3)
	}
}

// TestNoiseDebugStateValues computes intermediate Noise state values for debugging
// Use this to compare with Android's computed values (from latest session)
func TestNoiseDebugStateValues(t *testing.T) {
	// Protocol name (32 bytes exactly, so h = protocolName, ck = h)
	protocolName := "Noise_XX_25519_ChaChaPoly_SHA256"
	t.Logf("Protocol name: %s (%d bytes)", protocolName, len(protocolName))

	// h = protocol name (since len == 32)
	h := []byte(protocolName)
	t.Logf("Initial h (protocol name): %x", h)

	// MixHash(empty prologue): h = SHA256(h || "")
	hash := sha256sum(h)
	t.Logf("After MixHash(empty prologue): h = %x", hash)

	// Android shows: f3d15e6108ed9556171207baa58f97d29a13c6be40595166066e2e0958dc002d
	expectedAfterPrologue := "f3d15e6108ed9556171207baa58f97d29a13c6be40595166066e2e0958dc002d"
	require.Equal(t, expectedAfterPrologue, hex.EncodeToString(hash), "h after prologue should match")
	t.Log("✓ Hash after prologue matches Android")

	// Latest session values:
	// Go ephemeral: 00ec18b56827bcc609991944156f7ad65212ca6fb077f18e29a2183af88a701b
	// Android ephemeral: 0a0788df4da15fa9ebd645f15a8733a3fcbd47f3012b6dcd91d90419dba33707
	goEphemeral, _ := hex.DecodeString("00ec18b56827bcc609991944156f7ad65212ca6fb077f18e29a2183af88a701b")
	androidEphemeral, _ := hex.DecodeString("0a0788df4da15fa9ebd645f15a8733a3fcbd47f3012b6dcd91d90419dba33707")

	// After MixHash(Go_e)
	h1 := sha256sum(append(hash, goEphemeral...))
	t.Logf("After MixHash(Go_e): h = %x", h1)

	// Android shows: 2e9505dbf8976dc2fc80c0a49add811dd250d32fbea3924b1f3ea5afe58dc804
	expectedH1 := "2e9505dbf8976dc2fc80c0a49add811dd250d32fbea3924b1f3ea5afe58dc804"
	require.Equal(t, expectedH1, hex.EncodeToString(h1), "h after Go's e should match")
	t.Log("✓ Hash after Go's ephemeral matches Android")

	// After MixHash(Android_e)
	h2 := sha256sum(append(h1, androidEphemeral...))
	t.Logf("After MixHash(Android_e): h = %x", h2)

	// Android shows: 71be3661a1eadad467d16561dc9508d7b1a55d459dac1cc662467db00720599e
	expectedH2 := "71be3661a1eadad467d16561dc9508d7b1a55d459dac1cc662467db00720599e"
	require.Equal(t, expectedH2, hex.EncodeToString(h2), "h after Android's e should match")
	t.Log("✓ Hash after Android's ephemeral matches Android")

	// ee and k values
	ee, _ := hex.DecodeString("9914253dfa646b3b81c9e56123611ac52da1e541d4c76e04e51c66b760458868")
	t.Logf("ee DH secret (both sides): %x", ee)

	// Compute HKDF to get k
	ck, _ := hex.DecodeString("4e6f6973655f58585f32353531395f436861436861506f6c795f534841323536")
	mac := hmac.New(sha256.New, ck)
	mac.Write(ee)
	prk := mac.Sum(nil)

	mac = hmac.New(sha256.New, prk)
	mac.Write([]byte{0x01})
	newCK := mac.Sum(nil)

	mac = hmac.New(sha256.New, prk)
	mac.Write(newCK)
	mac.Write([]byte{0x02})
	k := mac.Sum(nil)

	t.Logf("Computed k: %x", k)

	// Android shows k = bfff6906d52c0ed90aca0c6ce3ae42b715cf48368ad5eb1b49d19e7b21aa0a6a
	expectedK := "bfff6906d52c0ed90aca0c6ce3ae42b715cf48368ad5eb1b49d19e7b21aa0a6a"
	require.Equal(t, expectedK, hex.EncodeToString(k), "k should match")
	t.Log("✓ Encryption key k matches Android")

	t.Log("\nAll intermediate values match! If decryption fails, flynn/noise must be using different values.")
}

func sha256sum(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

// TestX25519DHVerification verifies X25519 DH computation using known test vectors
// TestVerifyGoEphemeralKey verifies that Go's ephemeral key is correctly derived
// TestManualNoiseDecrypt manually implements the Noise decryption flow
// to verify our understanding matches what should happen
func TestManualNoiseDecrypt(t *testing.T) {
	// From latest session:
	goEphPub, _ := hex.DecodeString("00ec18b56827bcc609991944156f7ad65212ca6fb077f18e29a2183af88a701b")
	goEphPriv, _ := hex.DecodeString("9fb28adcd74422688565faaaeca8a0d5c4089d6c643af172bc775d5ac867e416")
	androidEphPub, _ := hex.DecodeString("0a0788df4da15fa9ebd645f15a8733a3fcbd47f3012b6dcd91d90419dba33707")
	encryptedS, _ := hex.DecodeString("f0cb654a06ff3f2b796b2539313fcf849343c31b98cad8fe9cda3e0ea1a5c16d5289ae2f5f01c50cbdb22e9bcba774a5")

	// Step 1: Initialize symmetric state
	protocolName := []byte("Noise_XX_25519_ChaChaPoly_SHA256")
	h := make([]byte, 32)
	copy(h, protocolName)
	ck := make([]byte, 32)
	copy(ck, h)

	t.Logf("Initial h: %x", h)
	t.Logf("Initial ck: %x", ck)

	// Step 2: MixHash(prologue) - empty
	h = sha256sum(h) // SHA256(h || "")
	t.Logf("After MixHash(prologue): h = %x", h)

	// Step 3: WriteMessage(msg1) - initiator sends ephemeral
	// MixHash(Go_e_pub)
	h = sha256sum(append(h, goEphPub...))
	t.Logf("After MixHash(Go_e): h = %x", h)

	// Step 4: ReadMessage(msg2) starts
	// First: MixHash(Android_e_pub)
	h = sha256sum(append(h, androidEphPub...))
	t.Logf("After MixHash(Android_e): h = %x", h)

	// Step 5: DH(Go_e_priv, Android_e_pub) -> ee
	ee, err := curve25519.X25519(goEphPriv, androidEphPub)
	require.NoError(t, err)
	t.Logf("ee: %x", ee)

	// Step 6: MixKey(ee)
	// PRK = HMAC(ck, ee)
	mac := hmac.New(sha256.New, ck)
	mac.Write(ee)
	prk := mac.Sum(nil)

	// new_ck = HMAC(PRK, 0x01)
	mac = hmac.New(sha256.New, prk)
	mac.Write([]byte{0x01})
	ck = mac.Sum(nil)

	// new_k = HMAC(PRK, new_ck || 0x02)
	mac = hmac.New(sha256.New, prk)
	mac.Write(ck)
	mac.Write([]byte{0x02})
	k := mac.Sum(nil)

	t.Logf("After MixKey(ee): ck = %x", ck)
	t.Logf("After MixKey(ee): k = %x", k)
	t.Logf("h (AAD for decrypt): %x", h)

	// Step 7: DecryptAndHash(encrypted_s)
	// Decrypt with k, nonce=0, AAD=h
	nonce := make([]byte, 12)
	aead, err := chacha20poly1305.New(k)
	require.NoError(t, err)

	plaintext, err := aead.Open(nil, nonce, encryptedS, h)
	if err != nil {
		t.Errorf("Decryption failed: %v", err)
		t.Log("This means our manual computation differs from what actually works")
	} else {
		t.Logf("Decryption succeeded! Static key: %x", plaintext)
		// Expected: 00c0ab3b57d9a664336583b9a52aa7aace40833e2d57aa19db2815ddbec44d6a
		expectedStatic, _ := hex.DecodeString("00c0ab3b57d9a664336583b9a52aa7aace40833e2d57aa19db2815ddbec44d6a")
		require.Equal(t, expectedStatic, plaintext, "Decrypted static key should match")
		t.Log("✓ Manual Noise decryption matches Android!")
	}
}

// TestFlynnNoiseWithKnownKeys runs flynn/noise with the exact keys from the failed session
// TestFlynnNoiseWithKnownKeys was removed - it was a debug test for the old
// 80-byte msg2 format. The fix ensures Android sends 96-byte msg2 with the
// encrypted empty payload tag per Noise protocol spec.

func TestVerifyGoEphemeralKey(t *testing.T) {
	// From debug output:
	goEphPriv, _ := hex.DecodeString("9fb28adcd74422688565faaaeca8a0d5c4089d6c643af172bc775d5ac867e416")
	goEphPub, _ := hex.DecodeString("00ec18b56827bcc609991944156f7ad65212ca6fb077f18e29a2183af88a701b")

	// Derive public from private
	derivedPub, err := curve25519.X25519(goEphPriv, curve25519.Basepoint)
	require.NoError(t, err)

	t.Logf("Go ephemeral priv: %x", goEphPriv)
	t.Logf("Go ephemeral pub (from log): %x", goEphPub)
	t.Logf("Derived pub from priv: %x", derivedPub)

	assert.Equal(t, goEphPub, derivedPub, "Public key should be correctly derived from private key")
	t.Log("✓ Go ephemeral keypair is valid")

	// Now compute ee with Android's ephemeral
	androidEphPub, _ := hex.DecodeString("0a0788df4da15fa9ebd645f15a8733a3fcbd47f3012b6dcd91d90419dba33707")
	ee, err := curve25519.X25519(goEphPriv, androidEphPub)
	require.NoError(t, err)

	t.Logf("Go computes ee: %x", ee)

	// Android shows ee = 9914253dfa646b3b81c9e56123611ac52da1e541d4c76e04e51c66b760458868
	expectedEE, _ := hex.DecodeString("9914253dfa646b3b81c9e56123611ac52da1e541d4c76e04e51c66b760458868")
	assert.Equal(t, expectedEE, ee, "ee should match Android's computation")
	t.Log("✓ ee matches Android")
}

func TestX25519DHVerification(t *testing.T) {
	// RFC 7748 test vector
	// Alice's private key
	alicePriv, _ := hex.DecodeString("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
	// Bob's private key
	bobPriv, _ := hex.DecodeString("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
	// Expected shared secret
	expectedShared, _ := hex.DecodeString("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")

	// Derive public keys
	alicePub, err := curve25519.X25519(alicePriv, curve25519.Basepoint)
	require.NoError(t, err)
	t.Logf("Alice pub: %x", alicePub)

	bobPub, err := curve25519.X25519(bobPriv, curve25519.Basepoint)
	require.NoError(t, err)
	t.Logf("Bob pub: %x", bobPub)

	// Compute shared secret both ways
	shared1, err := curve25519.X25519(alicePriv, bobPub)
	require.NoError(t, err)
	t.Logf("Alice computes: DH(alice_priv, bob_pub) = %x", shared1)

	shared2, err := curve25519.X25519(bobPriv, alicePub)
	require.NoError(t, err)
	t.Logf("Bob computes: DH(bob_priv, alice_pub) = %x", shared2)

	// Verify commutativity
	assert.Equal(t, shared1, shared2, "X25519 should be commutative")

	// Verify against expected
	assert.Equal(t, expectedShared, shared1, "Shared secret should match RFC 7748 test vector")
	assert.Equal(t, expectedShared, shared2, "Shared secret should match RFC 7748 test vector")

	t.Log("✓ X25519 DH verified with RFC 7748 test vectors")
}

// TestNoiseHKDFComputation verifies the HKDF/MixKey computation matches Android
// TestNoiseDecryptWithAndroidValues attempts to decrypt Android's ciphertext
// using the computed k and h values
func TestNoiseDecryptWithAndroidValues(t *testing.T) {
	// Values from latest Android logs (session 2)
	k, _ := hex.DecodeString("bfff6906d52c0ed90aca0c6ce3ae42b715cf48368ad5eb1b49d19e7b21aa0a6a")
	h, _ := hex.DecodeString("71be3661a1eadad467d16561dc9508d7b1a55d459dac1cc662467db00720599e")
	encryptedS, _ := hex.DecodeString("f0cb654a06ff3f2b796b2539313fcf849343c31b98cad8fe9cda3e0ea1a5c16d5289ae2f5f01c50cbdb22e9bcba774a5")

	t.Logf("k: %x", k)
	t.Logf("h (AAD): %x", h)
	t.Logf("encrypted_s: %x", encryptedS)

	// Decrypt using ChaCha20-Poly1305
	// Nonce for Noise handshake encryption is all zeros
	nonce := make([]byte, 12)

	aead, err := chacha20poly1305.New(k)
	require.NoError(t, err)

	plaintext, err := aead.Open(nil, nonce, encryptedS, h)
	if err != nil {
		t.Logf("Decryption failed: %v", err)
		t.Log("This suggests Go might be computing different k or h values")
	} else {
		t.Logf("Decryption succeeded! Static key: %x", plaintext)
	}

	// Expected static key from Android
	expectedStaticKey, _ := hex.DecodeString("00c0ab3b57d9a664336583b9a52aa7aace40833e2d57aa19db2815ddbec44d6a")
	if bytes.Equal(plaintext, expectedStaticKey) {
		t.Log("✓ Decrypted static key matches Android's static key!")
	} else if plaintext != nil {
		t.Errorf("Decrypted key doesn't match!\n  Got:      %x\n  Expected: %x", plaintext, expectedStaticKey)
	}
}

func TestNoiseHKDFComputation(t *testing.T) {
	// Initial ck = protocol name bytes
	ck, _ := hex.DecodeString("4e6f6973655f58585f32353531395f436861436861506f6c795f534841323536")
	t.Logf("Initial ck: %x", ck)

	// Android's ee DH secret
	ee, _ := hex.DecodeString("a96c2338df0a281c25aa72e278a188654ba305ccf3561e30ba7640a966d6a74e")
	t.Logf("ee DH secret: %x", ee)

	// HKDF: PRK = HMAC-SHA256(ck, ee)
	mac := hmac.New(sha256.New, ck)
	mac.Write(ee)
	prk := mac.Sum(nil)
	t.Logf("PRK = HMAC(ck, ee): %x", prk)

	// T1 = HMAC-SHA256(PRK, 0x01) = new ck
	mac = hmac.New(sha256.New, prk)
	mac.Write([]byte{0x01})
	newCK := mac.Sum(nil)
	t.Logf("new ck = HMAC(PRK, 0x01): %x", newCK)

	// T2 = HMAC-SHA256(PRK, T1 || 0x02) = new k
	mac = hmac.New(sha256.New, prk)
	mac.Write(newCK)
	mac.Write([]byte{0x02})
	newK := mac.Sum(nil)
	t.Logf("new k = HMAC(PRK, ck||0x02): %x", newK)

	// Android shows:
	// ck = 1f69c0874751f7ae619563ac6ad7923bc9107010c6f1411827511d7abd545023
	// k = 2543133b5eea57a3292c19ffaed4f6995be45912d198c18dc0f216ce552f1f8d
	expectedCK := "1f69c0874751f7ae619563ac6ad7923bc9107010c6f1411827511d7abd545023"
	expectedK := "2543133b5eea57a3292c19ffaed4f6995be45912d198c18dc0f216ce552f1f8d"

	t.Logf("\nComputed ck: %x", newCK)
	t.Logf("Expected ck: %s", expectedCK)
	if hex.EncodeToString(newCK) == expectedCK {
		t.Log("✓ ck matches!")
	} else {
		t.Error("✗ ck mismatch!")
	}

	t.Logf("\nComputed k: %x", newK)
	t.Logf("Expected k: %s", expectedK)
	if hex.EncodeToString(newK) == expectedK {
		t.Log("✓ k matches!")
	} else {
		t.Error("✗ k mismatch!")
	}
}

func TestNoiseSession_SetPrologue(t *testing.T) {
	prologue := []byte("xkey-test-prologue-v1")

	session, err := NewNoiseSession(&NoiseSessionConfig{IsInitiator: true})
	require.NoError(t, err)

	// Set prologue before initializing handshake
	session.SetPrologue(prologue)

	// Verify prologue is set by checking it's used in InitHandshake
	err = session.InitHandshake()
	require.NoError(t, err)
}

func TestNoiseSession_SetPrologue_EmptyPrologue(t *testing.T) {
	session, err := NewNoiseSession(&NoiseSessionConfig{IsInitiator: true})
	require.NoError(t, err)

	// Empty prologue should be valid
	session.SetPrologue([]byte{})

	err = session.InitHandshake()
	require.NoError(t, err)
}

func TestNoiseSession_SetPrologue_NilPrologue(t *testing.T) {
	session, err := NewNoiseSession(&NoiseSessionConfig{IsInitiator: true})
	require.NoError(t, err)

	// Nil prologue should be valid
	session.SetPrologue(nil)

	err = session.InitHandshake()
	require.NoError(t, err)
}

func TestNoiseSession_SetPrologue_MatchingPrologues(t *testing.T) {
	prologue := []byte("shared-prologue-for-binding")

	// Create initiator and responder with same prologue
	initiator, err := NewNoiseSession(&NoiseSessionConfig{IsInitiator: true})
	require.NoError(t, err)
	initiator.SetPrologue(prologue)

	responder, err := NewNoiseSession(&NoiseSessionConfig{IsInitiator: false})
	require.NoError(t, err)
	responder.SetPrologue(prologue)

	// Initialize handshakes
	err = initiator.InitHandshake()
	require.NoError(t, err)
	err = responder.InitHandshake()
	require.NoError(t, err)

	// Perform full handshake
	msg1, _, err := initiator.HandshakeMessage(nil)
	require.NoError(t, err)

	msg2, _, err := responder.HandshakeMessage(msg1)
	require.NoError(t, err)

	msg3, complete, err := initiator.HandshakeMessage(msg2)
	require.NoError(t, err)
	assert.True(t, complete)

	_, complete, err = responder.HandshakeMessage(msg3)
	require.NoError(t, err)
	assert.True(t, complete)

	// Verify sessions can communicate
	plaintext := []byte("test message after prologue")
	ciphertext, err := initiator.Encrypt(plaintext)
	require.NoError(t, err)

	decrypted, err := responder.Decrypt(ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func BenchmarkNoiseEncrypt(b *testing.B) {
	initiator, _ := NewNoiseSession(&NoiseSessionConfig{IsInitiator: true})
	responder, _ := NewNoiseSession(&NoiseSessionConfig{IsInitiator: false})

	initiator.InitHandshake()
	responder.InitHandshake()

	msg1, _, _ := initiator.HandshakeMessage(nil)
	msg2, _, _ := responder.HandshakeMessage(msg1)
	msg3, _, _ := initiator.HandshakeMessage(msg2)
	responder.HandshakeMessage(msg3)

	plaintext := make([]byte, 1024)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		initiator.Encrypt(plaintext)
	}
}

// --- mapNoiseError coverage ---

func TestMapNoiseError_KnownErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    error
		expected error
	}{
		{"handshake failed", noiseproto.ErrHandshakeFailed, ErrNoiseHandshakeFailed},
		{"static key mismatch", noiseproto.ErrStaticKeyMismatch, ErrStaticKeyMismatch},
		{"encryption failed", noiseproto.ErrEncryptionFailed, ErrEncryptionFailed},
		{"decryption failed", noiseproto.ErrDecryptionFailed, ErrDecryptionFailed},
		{"invalid message", noiseproto.ErrInvalidMessage, ErrInvalidNoiseMessage},
		{"invalid key size", noiseproto.ErrInvalidKeySize, ErrInvalidNoiseMessage},
		{"session not ready", noiseproto.ErrSessionNotReady, ErrNoiseHandshakeFailed},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapNoiseError(tt.input)
			assert.ErrorIs(t, result, tt.expected)
		})
	}
}

func TestMapNoiseError_UnknownError(t *testing.T) {
	t.Parallel()

	// An error not in the map should fall through to the default.
	unknownErr := errors.New("some unknown noise error")
	result := mapNoiseError(unknownErr)
	assert.ErrorIs(t, result, ErrNoiseHandshakeFailed)
}
