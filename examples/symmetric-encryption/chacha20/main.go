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

// Package main demonstrates ChaCha20-Poly1305 AEAD encryption with the AES backend.
//
// ChaCha20-Poly1305 is a modern AEAD cipher that provides:
//   - Fast encryption on systems without AES hardware acceleration (AES-NI)
//   - 256-bit key security
//   - 96-bit (12-byte) nonces for standard ChaCha20-Poly1305
//   - 192-bit (24-byte) nonces for XChaCha20-Poly1305 (better for random nonces)
//   - 128-bit (16-byte) authentication tags
//   - Constant-time implementation resistant to timing attacks
//
// This example demonstrates:
//  1. Generating a ChaCha20-Poly1305 symmetric key
//  2. Encrypting plaintext data
//  3. Decrypting and verifying the ciphertext
//  4. Handling authentication failures
//  5. Using additional authenticated data (AAD)
package main

import (
	"fmt"
	"log"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/backend/aes"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

func main() {
	// Create an in-memory storage backend
	storage := storage.New()

	// Create an AES backend (which supports both AES and ChaCha20)
	config := &aes.Config{
		KeyStorage: storage,
	}
	b, err := aes.NewBackend(config)
	if err != nil {
		log.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	symBackend := b

	// Example 1: ChaCha20-Poly1305 with standard 12-byte nonce
	fmt.Println("Example 1: ChaCha20-Poly1305 Encryption")
	fmt.Println("=========================================")
	basicChaCha20Example(symBackend)

	// Example 2: XChaCha20-Poly1305 with extended 24-byte nonce
	fmt.Println("\nExample 2: XChaCha20-Poly1305 Encryption")
	fmt.Println("==========================================")
	xChaCha20Example(symBackend)

	// Example 3: Encryption with Additional Authenticated Data (AAD)
	fmt.Println("\nExample 3: ChaCha20-Poly1305 with AAD")
	fmt.Println("======================================")
	chacha20WithAADExample(symBackend)

	// Example 4: Authentication failure detection
	fmt.Println("\nExample 4: Tampering Detection")
	fmt.Println("================================")
	chacha20TamperingExample(symBackend)
}

// basicChaCha20Example demonstrates basic ChaCha20-Poly1305 encryption and decryption
func basicChaCha20Example(symBackend types.SymmetricBackend) {
	// Create key attributes for ChaCha20-Poly1305
	attrs := &types.KeyAttributes{
		CN:                 "my-chacha20-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricChaCha20Poly1305,
	}

	// Generate a new ChaCha20-Poly1305 key
	// Note: No AESAttributes needed - ChaCha20 always uses 256-bit keys
	key, err := symBackend.GenerateSymmetricKey(attrs)
	if err != nil {
		log.Fatalf("Failed to generate ChaCha20 key: %v", err)
	}

	fmt.Printf("Generated key: %s\n", attrs.CN)
	fmt.Printf("Algorithm: %s\n", key.Algorithm())
	fmt.Printf("Key size: %d bits\n", key.KeySize())

	// Create an encrypter for the key
	encrypter, err := symBackend.SymmetricEncrypter(attrs)
	if err != nil {
		log.Fatalf("Failed to create encrypter: %v", err)
	}

	// Encrypt some plaintext
	plaintext := []byte("Hello, ChaCha20-Poly1305!")
	encrypted, err := encrypter.Encrypt(plaintext, &types.EncryptOptions{})
	if err != nil {
		log.Fatalf("Encryption failed: %v", err)
	}

	fmt.Printf("\nPlaintext: %s\n", plaintext)
	fmt.Printf("Ciphertext: %x\n", encrypted.Ciphertext)
	fmt.Printf("Nonce: %x (length: %d bytes)\n", encrypted.Nonce, len(encrypted.Nonce))
	fmt.Printf("Tag: %x (length: %d bytes)\n", encrypted.Tag, len(encrypted.Tag))

	// Decrypt the ciphertext
	decrypted, err := encrypter.Decrypt(encrypted, &types.DecryptOptions{})
	if err != nil {
		log.Fatalf("Decryption failed: %v", err)
	}

	fmt.Printf("Decrypted: %s\n", decrypted)
	fmt.Printf("Match: %v\n", string(decrypted) == string(plaintext))
}

// xChaCha20Example demonstrates XChaCha20-Poly1305 encryption
// XChaCha20 uses a 24-byte nonce, making it safer for random nonce generation
func xChaCha20Example(symBackend types.SymmetricBackend) {
	// Create key attributes for XChaCha20-Poly1305
	attrs := &types.KeyAttributes{
		CN:                 "my-xchacha20-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricXChaCha20Poly1305,
	}

	// Generate a new XChaCha20-Poly1305 key
	key, err := symBackend.GenerateSymmetricKey(attrs)
	if err != nil {
		log.Fatalf("Failed to generate XChaCha20 key: %v", err)
	}

	fmt.Printf("Generated key: %s\n", attrs.CN)
	fmt.Printf("Algorithm: %s\n", key.Algorithm())
	fmt.Printf("Key size: %d bits\n", key.KeySize())

	// Create an encrypter for the key
	encrypter, err := symBackend.SymmetricEncrypter(attrs)
	if err != nil {
		log.Fatalf("Failed to create encrypter: %v", err)
	}

	// Encrypt plaintext
	plaintext := []byte("XChaCha20 with extended nonce for safer random generation")
	encrypted, err := encrypter.Encrypt(plaintext, &types.EncryptOptions{})
	if err != nil {
		log.Fatalf("Encryption failed: %v", err)
	}

	fmt.Printf("\nPlaintext: %s\n", plaintext)
	fmt.Printf("Nonce: %x (length: %d bytes - extended for safer random generation)\n",
		encrypted.Nonce, len(encrypted.Nonce))
	fmt.Printf("Tag: %x\n", encrypted.Tag)

	// Decrypt
	decrypted, err := encrypter.Decrypt(encrypted, &types.DecryptOptions{})
	if err != nil {
		log.Fatalf("Decryption failed: %v", err)
	}

	fmt.Printf("Decrypted: %s\n", decrypted)
	fmt.Printf("Match: %v\n", string(decrypted) == string(plaintext))
}

// chacha20WithAADExample demonstrates ChaCha20-Poly1305 with Additional Authenticated Data
// AAD is authenticated but not encrypted, useful for metadata, headers, or protocol information
func chacha20WithAADExample(symBackend types.SymmetricBackend) {
	attrs := &types.KeyAttributes{
		CN:                 "my-aad-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricChaCha20Poly1305,
	}

	// Generate key
	_, err := symBackend.GenerateSymmetricKey(attrs)
	if err != nil {
		log.Fatalf("Failed to generate key: %v", err)
	}

	encrypter, err := symBackend.SymmetricEncrypter(attrs)
	if err != nil {
		log.Fatalf("Failed to create encrypter: %v", err)
	}

	// Plaintext to encrypt
	plaintext := []byte("Secret payment amount: $1000")

	// Additional data that will be authenticated but not encrypted
	// (e.g., header information, metadata, etc.)
	aad := []byte("PaymentID: 12345, Recipient: Alice")

	// Encrypt with AAD
	encrypted, err := encrypter.Encrypt(plaintext, &types.EncryptOptions{
		AdditionalData: aad,
	})
	if err != nil {
		log.Fatalf("Encryption failed: %v", err)
	}

	fmt.Printf("Plaintext: %s\n", plaintext)
	fmt.Printf("Additional Data (authenticated but not encrypted): %s\n", aad)
	fmt.Printf("Ciphertext: %x\n", encrypted.Ciphertext)

	// Decrypt with the same AAD
	decrypted, err := encrypter.Decrypt(encrypted, &types.DecryptOptions{
		AdditionalData: aad,
	})
	if err != nil {
		log.Fatalf("Decryption with correct AAD failed: %v", err)
	}

	fmt.Printf("Decrypted: %s\n", decrypted)

	// Attempt to decrypt with different AAD (should fail)
	fmt.Println("\nAttempting decryption with wrong AAD...")
	wrongAAD := []byte("PaymentID: 12345, Recipient: Bob")
	_, err = encrypter.Decrypt(encrypted, &types.DecryptOptions{
		AdditionalData: wrongAAD,
	})

	if err != nil {
		fmt.Printf("Decryption failed (as expected): authentication error detected\n")
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Println("ERROR: Decryption should have failed with wrong AAD!")
	}
}

// chacha20TamperingExample demonstrates that ChaCha20-Poly1305 detects tampering
func chacha20TamperingExample(symBackend types.SymmetricBackend) {
	attrs := &types.KeyAttributes{
		CN:                 "my-tamper-test-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricChaCha20Poly1305,
	}

	// Generate key
	_, err := symBackend.GenerateSymmetricKey(attrs)
	if err != nil {
		log.Fatalf("Failed to generate key: %v", err)
	}

	encrypter, err := symBackend.SymmetricEncrypter(attrs)
	if err != nil {
		log.Fatalf("Failed to create encrypter: %v", err)
	}

	// Encrypt message
	plaintext := []byte("Important: Do not modify this message")
	encrypted, err := encrypter.Encrypt(plaintext, &types.EncryptOptions{})
	if err != nil {
		log.Fatalf("Encryption failed: %v", err)
	}

	fmt.Printf("Original plaintext: %s\n", plaintext)
	fmt.Printf("Original ciphertext: %x\n", encrypted.Ciphertext)

	// Tamper with the ciphertext by flipping a bit
	fmt.Println("\nTampering with ciphertext (flipping a bit)...")
	encrypted.Ciphertext[0] ^= 0xFF

	// Attempt to decrypt tampered data
	decrypted, err := encrypter.Decrypt(encrypted, &types.DecryptOptions{})
	if err != nil {
		fmt.Printf("Decryption failed (as expected): %v\n", err)
		fmt.Println("ChaCha20-Poly1305 successfully detected tampering!")
	} else {
		fmt.Printf("ERROR: Decryption should have failed!\n")
		fmt.Printf("Got: %s\n", decrypted)
	}

	// Also test tampering with the authentication tag
	fmt.Println("\nTampering with authentication tag...")
	// Restore the ciphertext
	encrypted.Ciphertext[0] ^= 0xFF
	// Now tamper with the tag
	encrypted.Tag[0] ^= 0xFF

	decrypted, err = encrypter.Decrypt(encrypted, &types.DecryptOptions{})
	if err != nil {
		fmt.Printf("Decryption failed (as expected): %v\n", err)
		fmt.Println("ChaCha20-Poly1305 successfully detected tag tampering!")
	} else {
		fmt.Printf("ERROR: Decryption should have failed!\n")
		fmt.Printf("Got: %s\n", decrypted)
	}
}
