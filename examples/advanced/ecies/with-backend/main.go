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

// Package main demonstrates ECIES encryption with backend-managed keys.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"log"

	"github.com/jeremyhahn/go-keychain/pkg/crypto/ecies"
)

func main() {
	fmt.Println("=== ECIES with Backend-Managed Keys ===")

	// Example: Direct backend key generation with ECIES
	directBackendExample()

	// Example: Key management and encryption workflow
	keyManagementExample()
}

// directBackendExample demonstrates generating ECDSA keys and using them with ECIES
func directBackendExample() {
	fmt.Println("Example 1: Direct ECDSA Key Generation for ECIES")
	fmt.Println("===============================================")

	// Generate ECDSA key pair directly for encryption
	fmt.Println("\n1. Generating ECDSA key pair (P-256)...")
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate key: %v", err)
	}
	pubKey := &privKey.PublicKey
	fmt.Printf("   Generated ECDSA key (P-256)\n")

	// Message to encrypt
	message := []byte("Sensitive data for ECIES encryption")

	// Encrypt using ECIES
	fmt.Println("\n2. Encrypting message with ECIES...")
	ciphertext, err := ecies.Encrypt(rand.Reader, pubKey, message, nil)
	if err != nil {
		log.Fatalf("Encryption failed: %v", err)
	}
	fmt.Printf("   Original: %s (%d bytes)\n", message, len(message))
	fmt.Printf("   Ciphertext size: %d bytes\n", len(ciphertext))

	// Decrypt using the private key
	fmt.Println("\n3. Decrypting with private key...")
	decrypted, err := ecies.Decrypt(privKey, ciphertext, nil)
	if err != nil {
		log.Fatalf("Decryption failed: %v", err)
	}
	fmt.Printf("   Decrypted: %s\n", decrypted)
	fmt.Printf("   Success: %v\n\n", string(decrypted) == string(message))
}

// keyManagementExample demonstrates multi-party encrypted communication with ECIES
func keyManagementExample() {
	fmt.Println("\nExample 2: Multi-Party Encrypted Communication")
	fmt.Println("==============================================")

	// Scenario: Multiple participants exchanging encrypted messages
	fmt.Println("\n1. Creating keys for participants...")

	// Alice generates her key
	alicePriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate Alice's key: %v", err)
	}
	fmt.Printf("   Alice's key generated\n")

	// Bob generates his key
	bobPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate Bob's key: %v", err)
	}
	fmt.Printf("   Bob's key generated\n")

	// Alice encrypts a message for Bob
	fmt.Println("\n2. Alice encrypts message for Bob...")
	aliceMessage := []byte("Bob, this is a secret message from Alice")

	ciphertext, err := ecies.Encrypt(rand.Reader, &bobPriv.PublicKey, aliceMessage, []byte("alice"))
	if err != nil {
		log.Fatalf("Encryption failed: %v", err)
	}
	fmt.Printf("   Message: %s\n", aliceMessage)
	fmt.Printf("   Ciphertext size: %d bytes\n", len(ciphertext))

	// Bob decrypts the message
	fmt.Println("\n3. Bob decrypts the message...")
	decrypted, err := ecies.Decrypt(bobPriv, ciphertext, []byte("alice"))
	if err != nil {
		log.Fatalf("Decryption failed: %v", err)
	}
	fmt.Printf("   Decrypted: %s\n", decrypted)

	// Bob encrypts a reply for Alice
	fmt.Println("\n4. Bob encrypts reply for Alice...")
	bobMessage := []byte("Alice, I received your message safely")

	replyCtxt, err := ecies.Encrypt(rand.Reader, &alicePriv.PublicKey, bobMessage, []byte("bob"))
	if err != nil {
		log.Fatalf("Encryption failed: %v", err)
	}
	fmt.Printf("   Reply: %s\n", bobMessage)
	fmt.Printf("   Ciphertext size: %d bytes\n", len(replyCtxt))

	// Alice decrypts the reply
	fmt.Println("\n5. Alice decrypts Bob's reply...")
	replyDecrypted, err := ecies.Decrypt(alicePriv, replyCtxt, []byte("bob"))
	if err != nil {
		log.Fatalf("Decryption failed: %v", err)
	}
	fmt.Printf("   Decrypted: %s\n\n", replyDecrypted)

	fmt.Println("Secure communication completed successfully!")
}
