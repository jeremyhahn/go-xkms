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

package ecies_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"

	"github.com/jeremyhahn/go-keychain/pkg/crypto/ecies"
)

// Example demonstrates basic ECIES encryption and decryption
func Example() {
	// Bob generates his key pair
	bobPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	bobPublic := &bobPriv.PublicKey

	// Alice wants to send a secret message to Bob
	message := []byte("Secret message for Bob")

	// Alice encrypts using Bob's public key
	ciphertext, _ := ecies.Encrypt(rand.Reader, bobPublic, message, nil)

	// Bob decrypts using his private key
	plaintext, _ := ecies.Decrypt(bobPriv, ciphertext, nil)

	fmt.Printf("Message received: %s\n", plaintext)
	fmt.Printf("Ciphertext is larger: %v\n", len(ciphertext) > len(message))

	// Output:
	// Message received: Secret message for Bob
	// Ciphertext is larger: true
}

// ExampleEncrypt_withAAD demonstrates encryption with additional authenticated data
func ExampleEncrypt_withAAD() {
	// Generate recipient key pair
	recipientPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	message := []byte("Confidential data")
	context := []byte("transaction-id-12345")

	// Encrypt with AAD
	ciphertext, _ := ecies.Encrypt(rand.Reader, &recipientPriv.PublicKey, message, context)

	// Decrypt with same AAD succeeds
	plaintext, _ := ecies.Decrypt(recipientPriv, ciphertext, context)
	fmt.Printf("With correct AAD: %s\n", plaintext)

	// Decrypt with different AAD fails
	_, err := ecies.Decrypt(recipientPriv, ciphertext, []byte("wrong-context"))
	fmt.Printf("With wrong AAD: %v\n", err != nil)

	// Output:
	// With correct AAD: Confidential data
	// With wrong AAD: true
}

// ExampleEncrypt_p384 demonstrates ECIES with P-384 curve
func ExampleEncrypt_p384() {
	// Generate key pair using P-384 curve
	priv, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)

	message := []byte("Message for P-384")

	// Encrypt
	ciphertext, _ := ecies.Encrypt(rand.Reader, &priv.PublicKey, message, nil)

	// Decrypt
	plaintext, _ := ecies.Decrypt(priv, ciphertext, nil)

	fmt.Printf("Decrypted: %s\n", plaintext)

	// Output:
	// Decrypted: Message for P-384
}

// ExampleEncrypt_p521 demonstrates ECIES with P-521 curve
func ExampleEncrypt_p521() {
	// Generate key pair using P-521 curve
	priv, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)

	message := []byte("Message for P-521")

	// Encrypt
	ciphertext, _ := ecies.Encrypt(rand.Reader, &priv.PublicKey, message, nil)

	// Decrypt
	plaintext, _ := ecies.Decrypt(priv, ciphertext, nil)

	fmt.Printf("Decrypted: %s\n", plaintext)

	// Output:
	// Decrypted: Message for P-521
}

// ExampleEncrypt_emptyMessage demonstrates encrypting empty data
func ExampleEncrypt_emptyMessage() {
	// Generate key pair
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Encrypt empty message
	message := []byte{}
	ciphertext, _ := ecies.Encrypt(rand.Reader, &priv.PublicKey, message, nil)

	// Decrypt
	plaintext, _ := ecies.Decrypt(priv, ciphertext, nil)

	fmt.Printf("Empty message encrypted: %v\n", len(ciphertext) > 0)
	fmt.Printf("Decrypted empty: %v\n", len(plaintext) == 0)

	// Output:
	// Empty message encrypted: true
	// Decrypted empty: true
}

// ExampleEncrypt_largeMessage demonstrates encrypting larger data
func ExampleEncrypt_largeMessage() {
	// Generate key pair
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Create a 1KB message
	message := make([]byte, 1024)
	for i := range message {
		message[i] = byte(i % 256)
	}

	// Encrypt
	ciphertext, _ := ecies.Encrypt(rand.Reader, &priv.PublicKey, message, nil)

	// Decrypt
	plaintext, _ := ecies.Decrypt(priv, ciphertext, nil)

	fmt.Printf("Original size: %d\n", len(message))
	fmt.Printf("Ciphertext size: %d\n", len(ciphertext))
	fmt.Printf("Decrypted matches: %v\n", len(plaintext) == len(message))

	// Output:
	// Original size: 1024
	// Ciphertext size: 1117
	// Decrypted matches: true
}
