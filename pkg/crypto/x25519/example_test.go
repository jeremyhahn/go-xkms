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

package x25519_test

import (
	"crypto/fips140"
	"crypto/rand"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/crypto/chacha20poly1305"
	"github.com/jeremyhahn/go-xkms/pkg/crypto/x25519"
	"github.com/jeremyhahn/go-xkms/pkg/types"

	"github.com/stretchr/testify/require"
)

// These were originally Example* functions (runnable godoc demonstrations
// that assert their result by matching a fixed "// Output:" comment). X25519
// and ChaCha20-Poly1305 are both deliberately unavailable under
// GODEBUG=fips140=only (go-xkms deliberately supports them and disables them
// in FIPS mode; see docs/fips/README.md), so every step here can return an
// error the demonstrations used to discard with `_`. An Example's output
// comment cannot vary by runtime mode, so there is no way to keep these as
// Example functions and still assert the FIPS-only refusal instead of
// silently deref'ing a nil result -- hence Test functions, which can branch
// on crypto/fips140 and assert the right outcome in both modes.

// TestKeyAgreementDemo demonstrates basic X25519 key agreement between two
// parties, and is the regression test for the nil-pointer panic
// ExampleKeyAgreement produced under GODEBUG=fips140=only (go-xkms#23):
// GenerateKey's discarded error left aliceKeyPair nil, and the next line
// dereferenced it.
func TestKeyAgreementDemo(t *testing.T) {
	ka := x25519.New()

	// Alice generates her key pair.
	aliceKeyPair, err := ka.GenerateKey()
	if fips140.Enforced() {
		require.Error(t, err, "X25519 must be refused under GODEBUG=fips140=only")
		require.Nil(t, aliceKeyPair)
		return
	}
	require.NoError(t, err)
	require.Len(t, aliceKeyPair.PublicKey.Bytes(), 32)

	// Bob generates his key pair.
	bobKeyPair, err := ka.GenerateKey()
	require.NoError(t, err)
	require.Len(t, bobKeyPair.PublicKey.Bytes(), 32)

	// Alice computes the shared secret with Bob's public key.
	aliceSharedSecret, err := ka.DeriveSharedSecret(aliceKeyPair.PrivateKey, bobKeyPair.PublicKey)
	require.NoError(t, err)
	require.Len(t, aliceSharedSecret, 32)

	// Bob computes the shared secret with Alice's public key.
	bobSharedSecret, err := ka.DeriveSharedSecret(bobKeyPair.PrivateKey, aliceKeyPair.PublicKey)
	require.NoError(t, err)
	require.Len(t, bobSharedSecret, 32)

	// Both derive the same symmetric encryption key.
	salt := []byte("example-salt")
	info := []byte("example-context")

	aliceKey, err := ka.DeriveKey(aliceSharedSecret, salt, info, 32)
	require.NoError(t, err)
	bobKey, err := ka.DeriveKey(bobSharedSecret, salt, info, 32)
	require.NoError(t, err)

	require.Equal(t, aliceKey, bobKey, "both parties must derive the same key")
}

// TestKeyAgreementDemo_WithEncryption demonstrates X25519 key agreement
// combined with ChaCha20-Poly1305 encryption, similar to the age protocol.
// Under GODEBUG=fips140=only both primitives are refused; the test asserts
// that refusal instead of running the round trip.
func TestKeyAgreementDemo_WithEncryption(t *testing.T) {
	ka := x25519.New()

	// Sender (Alice) generates an ephemeral key pair.
	senderKeyPair, err := ka.GenerateKey()
	if fips140.Enforced() {
		require.Error(t, err, "X25519 must be refused under GODEBUG=fips140=only")
		require.Nil(t, senderKeyPair)
		return
	}
	require.NoError(t, err)

	// Recipient (Bob) has a static key pair (published beforehand).
	recipientKeyPair, err := ka.GenerateKey()
	require.NoError(t, err)

	// Alice performs key agreement with Bob's public key.
	sharedSecret, err := ka.DeriveSharedSecret(senderKeyPair.PrivateKey, recipientKeyPair.PublicKey)
	require.NoError(t, err)

	// Derive an encryption key using HKDF.
	encryptionKey, err := ka.DeriveKey(
		sharedSecret,
		nil,                      // No salt for this example.
		[]byte("age-encryption"), // Context string.
		32,                       // ChaCha20-Poly1305 key size.
	)
	require.NoError(t, err)

	// Alice encrypts a message using ChaCha20-Poly1305. golang.org/x/crypto's
	// ChaCha20-Poly1305 is refused under fips140=only too (a second,
	// independent refusal from the X25519 one above), which is why this
	// assertion is not folded into the fips140.Enforced() branch above.
	message := []byte("Secret message for Bob")
	cipher, err := chacha20poly1305.New(encryptionKey)
	if fips140.Enforced() {
		require.Error(t, err, "ChaCha20-Poly1305 must be refused under GODEBUG=fips140=only")
		return
	}
	require.NoError(t, err)

	encrypted, err := cipher.Encrypt(message, &types.EncryptOptions{
		AdditionalData: senderKeyPair.PublicKey.Bytes(), // Include the sender's public key in the AAD.
	})
	require.NoError(t, err)
	require.Len(t, encrypted.Ciphertext, len(message))
	require.Len(t, encrypted.Nonce, 12)
	require.Len(t, encrypted.Tag, 16)

	// Bob receives the encrypted message and the sender's public key, and
	// performs key agreement with it.
	bobSharedSecret, err := ka.DeriveSharedSecret(recipientKeyPair.PrivateKey, senderKeyPair.PublicKey)
	require.NoError(t, err)

	// Bob derives the same encryption key.
	bobEncryptionKey, err := ka.DeriveKey(
		bobSharedSecret,
		nil,
		[]byte("age-encryption"),
		32,
	)
	require.NoError(t, err)

	// Bob decrypts the message.
	bobCipher, err := chacha20poly1305.New(bobEncryptionKey)
	require.NoError(t, err)
	decrypted, err := bobCipher.Decrypt(encrypted, &types.DecryptOptions{
		AdditionalData: senderKeyPair.PublicKey.Bytes(),
	})
	require.NoError(t, err)

	require.Equal(t, message, decrypted)
}

// TestKeyAgreementDemo_MultipleRecipients demonstrates encrypting a message
// for multiple recipients, similar to age encryption. Under
// GODEBUG=fips140=only, X25519 key generation is refused before any
// recipient stanza can be built; the test asserts that refusal instead.
func TestKeyAgreementDemo_MultipleRecipients(t *testing.T) {
	ka := x25519.New()

	// Generate a random file encryption key.
	fileKey := make([]byte, 32)
	_, err := rand.Read(fileKey)
	require.NoError(t, err)

	// Three recipients with their public keys.
	recipient1KeyPair, err := ka.GenerateKey()
	if fips140.Enforced() {
		require.Error(t, err, "X25519 must be refused under GODEBUG=fips140=only")
		require.Nil(t, recipient1KeyPair)
		return
	}
	require.NoError(t, err)
	recipient2KeyPair, err := ka.GenerateKey()
	require.NoError(t, err)
	recipient3KeyPair, err := ka.GenerateKey()
	require.NoError(t, err)

	// For each recipient, create an ephemeral key pair and wrap the file key.
	type recipientStanza struct {
		ephemeralPublic []byte
		wrappedKey      *types.EncryptedData
	}

	stanzas := make([]recipientStanza, 0, 3)
	recipients := []*x25519.KeyPair{recipient1KeyPair, recipient2KeyPair, recipient3KeyPair}

	for _, recipientKeyPair := range recipients {
		// Generate an ephemeral key for this recipient.
		ephemeralKeyPair, err := ka.GenerateKey()
		require.NoError(t, err)

		// Derive the wrapping key.
		sharedSecret, err := ka.DeriveSharedSecret(ephemeralKeyPair.PrivateKey, recipientKeyPair.PublicKey)
		require.NoError(t, err)
		wrappingKey, err := ka.DeriveKey(sharedSecret, nil, []byte("age-recipient"), 32)
		require.NoError(t, err)

		// Wrap the file key.
		wrappingCipher, err := chacha20poly1305.New(wrappingKey)
		require.NoError(t, err)
		wrappedKey, err := wrappingCipher.Encrypt(fileKey, nil)
		require.NoError(t, err)

		stanzas = append(stanzas, recipientStanza{
			ephemeralPublic: ephemeralKeyPair.PublicKey.Bytes(),
			wrappedKey:      wrappedKey,
		})
	}

	require.Len(t, stanzas, 3)

	// Any recipient can decrypt the file key using their private key. This
	// simulates recipient 2 decrypting.
	recipientIdx := 1
	stanza := stanzas[recipientIdx]
	recipientPrivateKey := recipients[recipientIdx].PrivateKey

	// Parse the ephemeral public key.
	ephemeralPublic, err := x25519.ParsePublicKey(stanza.ephemeralPublic)
	require.NoError(t, err)

	// Derive the unwrapping key.
	sharedSecret, err := ka.DeriveSharedSecret(recipientPrivateKey, ephemeralPublic)
	require.NoError(t, err)
	unwrappingKey, err := ka.DeriveKey(sharedSecret, nil, []byte("age-recipient"), 32)
	require.NoError(t, err)

	// Unwrap the file key.
	unwrappingCipher, err := chacha20poly1305.New(unwrappingKey)
	require.NoError(t, err)
	decryptedFileKey, err := unwrappingCipher.Decrypt(stanza.wrappedKey, nil)
	require.NoError(t, err)

	require.Len(t, decryptedFileKey, 32)
	require.Equal(t, fileKey, decryptedFileKey)
}
