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

// Example demonstrating X25519 ECDH key agreement with the Software backend.
//
// X25519 is faster and simpler than NIST curves for ECDH (Elliptic Curve Diffie-Hellman).
// This example shows:
// - Generating X25519 key pairs
// - Performing ECDH key agreement
// - Deriving keys using HKDF
// - Encrypted communication using derived keys
package main

import (
	"crypto/sha256"
	"fmt"
	"log"

	"github.com/jeremyhahn/go-keychain/pkg/backend/software"
	"github.com/jeremyhahn/go-keychain/pkg/crypto/x25519"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"golang.org/x/crypto/hkdf"
)

func main() {
	// Create a software backend with in-memory storage
	storage := storage.New()
	config := &software.Config{KeyStorage: storage}
	backend, err := software.NewBackend(config)
	if err != nil {
		log.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = backend.Close() }()

	// Generate Alice's X25519 key pair
	fmt.Println("1. Generating Alice's X25519 key pair...")
	aliceAttrs := &types.KeyAttributes{
		CN:               "alice.x25519",
		KeyType:          types.KeyTypeEncryption,
		StoreType:        types.StoreSoftware,
		X25519Attributes: &types.X25519Attributes{},
	}
	aliceKeyInterface, err := backend.GenerateKey(aliceAttrs)
	if err != nil {
		log.Fatalf("Failed to generate Alice's key: %v", err)
	}
	aliceKey := aliceKeyInterface.(*x25519.PrivateKeyStorage)
	alicePublicKey := aliceKey.Public().(*x25519.PublicKeyStorage)
	fmt.Printf("   Alice's public key (32 bytes): %x\n", alicePublicKey.Bytes())

	// Generate Bob's X25519 key pair
	fmt.Println("\n2. Generating Bob's X25519 key pair...")
	bobAttrs := &types.KeyAttributes{
		CN:               "bob.x25519",
		KeyType:          types.KeyTypeEncryption,
		StoreType:        types.StoreSoftware,
		X25519Attributes: &types.X25519Attributes{},
	}
	bobKeyInterface, err := backend.GenerateKey(bobAttrs)
	if err != nil {
		log.Fatalf("Failed to generate Bob's key: %v", err)
	}
	bobKey := bobKeyInterface.(*x25519.PrivateKeyStorage)
	bobPublicKey := bobKey.Public().(*x25519.PublicKeyStorage)
	fmt.Printf("   Bob's public key (32 bytes): %x\n", bobPublicKey.Bytes())

	// Alice derives shared secret using Bob's public key
	fmt.Println("\n3. Alice performing ECDH with Bob's public key...")
	concreteBackend := backend.(*software.SoftwareBackend)
	aliceSharedSecret, err := concreteBackend.DeriveSharedSecret(aliceAttrs, bobPublicKey)
	if err != nil {
		log.Fatalf("Failed to derive shared secret: %v", err)
	}
	fmt.Printf("   Shared secret (32 bytes): %x\n", aliceSharedSecret)

	// Bob derives shared secret using Alice's public key
	fmt.Println("\n4. Bob performing ECDH with Alice's public key...")
	bobSharedSecret, err := concreteBackend.DeriveSharedSecret(bobAttrs, alicePublicKey)
	if err != nil {
		log.Fatalf("Failed to derive shared secret: %v", err)
	}
	fmt.Printf("   Shared secret (32 bytes): %x\n", bobSharedSecret)

	// Verify both secrets are identical
	fmt.Println("\n5. Verifying secrets match...")
	if len(aliceSharedSecret) != len(bobSharedSecret) {
		log.Fatal("Shared secrets have different lengths!")
	}

	match := true
	for i := range aliceSharedSecret {
		if aliceSharedSecret[i] != bobSharedSecret[i] {
			match = false
			break
		}
	}

	if match {
		fmt.Println("   ✓ Secrets match! Perfect synchronization achieved.")
	} else {
		log.Fatal("Secrets don't match!")
	}

	// Derive encryption key from shared secret using HKDF
	fmt.Println("\n6. Deriving AES-256 encryption key using HKDF-SHA256...")
	ka := x25519.New()
	encryptionKey, err := ka.DeriveKey(
		aliceSharedSecret,
		nil,                  // Optional salt
		[]byte("encryption"), // Context info
		32,                   // 256-bit AES key
	)
	if err != nil {
		log.Fatalf("Failed to derive encryption key: %v", err)
	}
	fmt.Printf("   Encryption key (32 bytes): %x\n", encryptionKey)

	// Also derive MAC key for authenticated encryption
	fmt.Println("\n7. Deriving MAC key for authentication...")
	macKey, err := ka.DeriveKey(
		aliceSharedSecret,
		nil,           // Optional salt
		[]byte("mac"), // Different context for MAC
		32,            // 256-bit HMAC key
	)
	if err != nil {
		log.Fatalf("Failed to derive MAC key: %v", err)
	}
	fmt.Printf("   MAC key (32 bytes): %x\n", macKey)

	// Demonstrate multiple key derivation from same shared secret
	fmt.Println("\n8. Deriving multiple keys from same shared secret...")
	keys := make(map[string][]byte)
	contexts := []string{"encryption", "mac", "authentication", "session"}

	for _, context := range contexts {
		key, err := ka.DeriveKey(aliceSharedSecret, nil, []byte(context), 32)
		if err != nil {
			log.Fatalf("Failed to derive %s key: %v", context, key)
		}
		keys[context] = key
	}

	for context, key := range keys {
		fmt.Printf("   %-15s: %x\n", context, key)
	}

	// Use HKDF directly for custom key derivation
	fmt.Println("\n9. Custom key derivation using HKDF directly...")
	const outputLength = 64 // Derive 64 bytes
	reader := hkdf.New(
		sha256.New,
		aliceSharedSecret,
		[]byte("salt"),   // Optional salt
		[]byte("custom"), // Application context
	)

	customKey := make([]byte, outputLength)
	if _, err := reader.Read(customKey); err != nil {
		log.Fatalf("Failed to derive custom key: %v", err)
	}
	fmt.Printf("   Custom key (64 bytes): %x\n", customKey)

	// Retrieve keys from backend storage
	fmt.Println("\n10. Retrieving generated keys from backend storage...")
	retrievedAlice, err := backend.GetKey(aliceAttrs)
	if err != nil {
		log.Fatalf("Failed to retrieve Alice's key: %v", err)
	}
	retrievedAliceKey := retrievedAlice.(*x25519.PrivateKeyStorage)
	fmt.Printf("   Retrieved Alice's key: %x\n", retrievedAliceKey.Bytes())

	// Verify the keys are the same
	if len(aliceKey.Bytes()) != len(retrievedAliceKey.Bytes()) {
		log.Fatal("Retrieved key has different length!")
	}

	keyMatch := true
	for i := range aliceKey.Bytes() {
		if aliceKey.Bytes()[i] != retrievedAliceKey.Bytes()[i] {
			keyMatch = false
			break
		}
	}

	if keyMatch {
		fmt.Println("   ✓ Key successfully persisted and retrieved!")
	} else {
		log.Fatal("Retrieved key doesn't match original!")
	}

	// Summary
	fmt.Println("\n" + string(rune(61)) + " Summary " + string(rune(61)))
	fmt.Println("X25519 ECDH Key Agreement Example:")
	fmt.Println("- Secure key exchange without transmitting secrets")
	fmt.Println("- Fast, constant-time Curve25519 implementation")
	fmt.Println("- HKDF-SHA256 for secure key derivation")
	fmt.Println("- Multiple keys from single shared secret")
	fmt.Println("- Perfect forward secrecy when ephemeral keys used")
	fmt.Println("- Compatible with modern protocols (age, WireGuard, etc)")
}
