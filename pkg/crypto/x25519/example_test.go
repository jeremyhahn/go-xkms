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

package x25519_test

import (
	"crypto/rand"
	"fmt"

	"github.com/jeremyhahn/go-keychain/pkg/crypto/chacha20poly1305"
	"github.com/jeremyhahn/go-keychain/pkg/crypto/x25519"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// ExampleKeyAgreement demonstrates basic X25519 key agreement between two parties.
func ExampleKeyAgreement() {
	// Create key agreement instance
	ka := x25519.New()

	// Alice generates her key pair
	aliceKeyPair, _ := ka.GenerateKey()
	fmt.Printf("Alice's public key: %d bytes\n", len(aliceKeyPair.PublicKey.Bytes()))

	// Bob generates his key pair
	bobKeyPair, _ := ka.GenerateKey()
	fmt.Printf("Bob's public key: %d bytes\n", len(bobKeyPair.PublicKey.Bytes()))

	// Alice computes shared secret with Bob's public key
	aliceSharedSecret, _ := ka.DeriveSharedSecret(aliceKeyPair.PrivateKey, bobKeyPair.PublicKey)
	fmt.Printf("Alice's shared secret: %d bytes\n", len(aliceSharedSecret))

	// Bob computes shared secret with Alice's public key
	bobSharedSecret, _ := ka.DeriveSharedSecret(bobKeyPair.PrivateKey, aliceKeyPair.PublicKey)
	fmt.Printf("Bob's shared secret: %d bytes\n", len(bobSharedSecret))

	// Both derive the same symmetric encryption key
	salt := []byte("example-salt")
	info := []byte("example-context")

	aliceKey, _ := ka.DeriveKey(aliceSharedSecret, salt, info, 32)
	bobKey, _ := ka.DeriveKey(bobSharedSecret, salt, info, 32)

	fmt.Printf("Keys match: %v\n", string(aliceKey) == string(bobKey))

	// Output:
	// Alice's public key: 32 bytes
	// Bob's public key: 32 bytes
	// Alice's shared secret: 32 bytes
	// Bob's shared secret: 32 bytes
	// Keys match: true
}

// ExampleKeyAgreement_withEncryption demonstrates X25519 key agreement
// combined with ChaCha20-Poly1305 encryption, similar to the age protocol.
func ExampleKeyAgreement_withEncryption() {
	// Create key agreement instance
	ka := x25519.New()

	// Sender (Alice) generates ephemeral key pair
	senderKeyPair, _ := ka.GenerateKey()

	// Recipient (Bob) has a static public key (published beforehand)
	recipientKeyPair, _ := ka.GenerateKey()

	// Alice performs key agreement with Bob's public key
	sharedSecret, _ := ka.DeriveSharedSecret(senderKeyPair.PrivateKey, recipientKeyPair.PublicKey)

	// Derive encryption key using HKDF
	encryptionKey, _ := ka.DeriveKey(
		sharedSecret,
		nil,                      // No salt for this example
		[]byte("age-encryption"), // Context string
		32,                       // ChaCha20-Poly1305 key size
	)

	// Alice encrypts a message using ChaCha20-Poly1305
	message := []byte("Secret message for Bob")
	cipher, _ := chacha20poly1305.New(encryptionKey)

	encrypted, _ := cipher.Encrypt(message, &types.EncryptOptions{
		AdditionalData: senderKeyPair.PublicKey.Bytes(), // Include sender's public key in AAD
	})

	fmt.Printf("Encrypted message: %d bytes\n", len(encrypted.Ciphertext))
	fmt.Printf("Nonce: %d bytes\n", len(encrypted.Nonce))
	fmt.Printf("Tag: %d bytes\n", len(encrypted.Tag))

	// Bob receives the encrypted message and sender's public key
	// Bob performs key agreement with sender's public key
	bobSharedSecret, _ := ka.DeriveSharedSecret(recipientKeyPair.PrivateKey, senderKeyPair.PublicKey)

	// Bob derives the same encryption key
	bobEncryptionKey, _ := ka.DeriveKey(
		bobSharedSecret,
		nil,
		[]byte("age-encryption"),
		32,
	)

	// Bob decrypts the message
	bobCipher, _ := chacha20poly1305.New(bobEncryptionKey)
	decrypted, _ := bobCipher.Decrypt(encrypted, &types.DecryptOptions{
		AdditionalData: senderKeyPair.PublicKey.Bytes(),
	})

	fmt.Printf("Decrypted message: %s\n", string(decrypted))

	// Output:
	// Encrypted message: 22 bytes
	// Nonce: 12 bytes
	// Tag: 16 bytes
	// Decrypted message: Secret message for Bob
}

// ExampleKeyAgreement_multipleRecipients demonstrates how to encrypt
// a message for multiple recipients, similar to age encryption.
func ExampleKeyAgreement_multipleRecipients() {
	// Create key agreement instance
	ka := x25519.New()

	// Generate a random file encryption key
	fileKey := make([]byte, 32)
	_, _ = rand.Read(fileKey)

	// Three recipients with their public keys
	recipient1KeyPair, _ := ka.GenerateKey()
	recipient2KeyPair, _ := ka.GenerateKey()
	recipient3KeyPair, _ := ka.GenerateKey()

	// For each recipient, create an ephemeral key pair and wrap the file key
	type RecipientStanza struct {
		ephemeralPublic []byte
		wrappedKey      *types.EncryptedData
	}

	stanzas := make([]RecipientStanza, 0, 3)
	recipients := []*x25519.KeyPair{recipient1KeyPair, recipient2KeyPair, recipient3KeyPair}

	for _, recipientKeyPair := range recipients {
		// Generate ephemeral key for this recipient
		ephemeralKeyPair, _ := ka.GenerateKey()

		// Derive wrapping key
		sharedSecret, _ := ka.DeriveSharedSecret(ephemeralKeyPair.PrivateKey, recipientKeyPair.PublicKey)
		wrappingKey, _ := ka.DeriveKey(sharedSecret, nil, []byte("age-recipient"), 32)

		// Wrap the file key
		wrappingCipher, _ := chacha20poly1305.New(wrappingKey)
		wrappedKey, _ := wrappingCipher.Encrypt(fileKey, nil)

		stanzas = append(stanzas, RecipientStanza{
			ephemeralPublic: ephemeralKeyPair.PublicKey.Bytes(),
			wrappedKey:      wrappedKey,
		})
	}

	fmt.Printf("Created %d recipient stanzas\n", len(stanzas))

	// Any recipient can decrypt the file key using their private key
	// Let's simulate recipient 2 decrypting
	recipientIdx := 1
	stanza := stanzas[recipientIdx]
	recipientPrivateKey := recipients[recipientIdx].PrivateKey

	// Parse ephemeral public key
	ephemeralPublic, _ := x25519.ParsePublicKey(stanza.ephemeralPublic)

	// Derive unwrapping key
	sharedSecret, _ := ka.DeriveSharedSecret(recipientPrivateKey, ephemeralPublic)
	unwrappingKey, _ := ka.DeriveKey(sharedSecret, nil, []byte("age-recipient"), 32)

	// Unwrap the file key
	unwrappingCipher, _ := chacha20poly1305.New(unwrappingKey)
	decryptedFileKey, _ := unwrappingCipher.Decrypt(stanza.wrappedKey, nil)

	fmt.Printf("Successfully unwrapped file key: %v\n", len(decryptedFileKey) == 32)
	fmt.Printf("File key matches: %v\n", string(decryptedFileKey) == string(fileKey))

	// Output:
	// Created 3 recipient stanzas
	// Successfully unwrapped file key: true
	// File key matches: true
}
