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

//go:build quantum

// Package main demonstrates quantum-safe cryptography using ML-DSA and ML-KEM.
// This example shows how quantum algorithms integrate seamlessly with the keychain API.
package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/jeremyhahn/go-keychain/pkg/backend/quantum"
	"github.com/jeremyhahn/go-keychain/pkg/keychain"
	"github.com/jeremyhahn/go-keychain/pkg/storage/file"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

func main() {
	// Create a temporary directory for the keychain
	tmpDir := filepath.Join(os.TempDir(), "quantum-example")
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Initialize storage backend (same as any other backend)
	storage, err := file.New(tmpDir)
	if err != nil {
		log.Fatalf("Failed to create storage: %v", err)
	}

	// Create quantum backend (same pattern as PKCS8, TPM2, etc.)
	quantumBackend, err := quantum.New(storage)
	if err != nil {
		log.Fatalf("Failed to create quantum backend: %v", err)
	}
	defer func() { _ = quantumBackend.Close() }()

	// Create keystore instance (optional, provides high-level API)
	ks, err := keychain.New(&keychain.Config{
		Backend:     quantumBackend,
		CertStorage: storage,
	})
	if err != nil {
		log.Fatalf("Failed to create keystore: %v", err)
	}
	defer func() { _ = ks.Close() }()

	fmt.Println("=== Quantum Cryptography Examples ===\n")

	// Example 1: Generate ML-DSA-44 signing key (smallest, NIST Level 2)
	fmt.Println("1. Generating ML-DSA-44 key...")
	mldsaAttrs := &types.KeyAttributes{
		CN:        "mldsa44-signing-key",
		KeyType:   types.KeyTypeSigning,
		StoreType: types.StoreQuantum,
		QuantumAttributes: &types.QuantumAttributes{
			Algorithm: types.QuantumAlgorithmMLDSA44,
		},
	}

	mldsaKey, err := quantumBackend.GenerateKey(mldsaAttrs)
	if err != nil {
		log.Fatalf("Failed to generate ML-DSA-44 key: %v", err)
	}
	fmt.Printf("   ✓ ML-DSA-44 key generated: %s\n", mldsaAttrs.CN)
	fmt.Printf("   Public key: %d bytes, Signature: ~2420 bytes\n\n", 1312)

	// Example 2: Sign and verify with ML-DSA
	fmt.Println("2. Signing with ML-DSA-44...")
	message := []byte("Hello, quantum-safe world! This message is protected by NIST-standardized post-quantum cryptography.")

	// Get signer (implements standard crypto.Signer interface)
	signer, err := quantumBackend.Signer(mldsaAttrs)
	if err != nil {
		log.Fatalf("Failed to get signer: %v", err)
	}

	// Hash and sign (same pattern as RSA/ECDSA)
	hash := sha256.Sum256(message)
	signature, err := signer.Sign(rand.Reader, hash[:], crypto.SHA256)
	if err != nil {
		log.Fatalf("Failed to sign: %v", err)
	}
	fmt.Printf("   ✓ Message signed (%d bytes)\n", len(signature))

	// Verify signature
	mldsaPrivKey := mldsaKey.(*quantum.MLDSAPrivateKey)
	valid, err := mldsaPrivKey.Verify(message, signature)
	if err != nil {
		log.Fatalf("Verification error: %v", err)
	}
	if !valid {
		log.Fatal("Signature verification failed")
	}
	fmt.Printf("   ✓ Signature verified successfully\n\n")

	// Example 3: Generate ML-DSA-65 key (recommended, NIST Level 3)
	fmt.Println("3. Generating ML-DSA-65 key (recommended)...")
	mldsa65Attrs := &types.KeyAttributes{
		CN:        "mldsa65-signing-key",
		KeyType:   types.KeyTypeSigning,
		StoreType: types.StoreQuantum,
		QuantumAttributes: &types.QuantumAttributes{
			Algorithm: types.QuantumAlgorithmMLDSA65,
		},
	}

	_, err = quantumBackend.GenerateKey(mldsa65Attrs)
	if err != nil {
		log.Fatalf("Failed to generate ML-DSA-65 key: %v", err)
	}
	fmt.Printf("   ✓ ML-DSA-65 key generated: %s\n", mldsa65Attrs.CN)
	fmt.Printf("   Public key: %d bytes, Signature: ~3309 bytes\n\n", 1952)

	// Example 4: Generate ML-KEM-768 key (recommended, NIST Level 3)
	fmt.Println("4. Generating ML-KEM-768 key...")
	kemAttrs := &types.KeyAttributes{
		CN:        "mlkem768-encryption-key",
		KeyType:   types.KeyTypeEncryption,
		StoreType: types.StoreQuantum,
		QuantumAttributes: &types.QuantumAttributes{
			Algorithm: types.QuantumAlgorithmMLKEM768,
		},
	}

	kemKey, err := quantumBackend.GenerateKey(kemAttrs)
	if err != nil {
		log.Fatalf("Failed to generate ML-KEM-768 key: %v", err)
	}
	fmt.Printf("   ✓ ML-KEM-768 key generated: %s\n", kemAttrs.CN)
	fmt.Printf("   Public key: %d bytes, Ciphertext: %d bytes, Shared secret: %d bytes\n\n",
		1184, 1088, 32)

	// Example 5: Key encapsulation and decapsulation
	fmt.Println("5. Performing key encapsulation...")
	mlkemKey := kemKey.(*quantum.MLKEMPrivateKey)
	recipientPublicKey := mlkemKey.PublicKey.Bytes()

	// Sender: Encapsulate to recipient's public key
	ciphertext, sharedSecret1, err := mlkemKey.Encapsulate(recipientPublicKey)
	if err != nil {
		log.Fatalf("Encapsulation failed: %v", err)
	}
	fmt.Printf("   ✓ Encapsulation complete\n")
	fmt.Printf("   Ciphertext: %d bytes\n", len(ciphertext))
	fmt.Printf("   Shared secret: %d bytes (256-bit AES key)\n", len(sharedSecret1))

	// Recipient: Decapsulate using private key
	sharedSecret2, err := mlkemKey.Decapsulate(ciphertext)
	if err != nil {
		log.Fatalf("Decapsulation failed: %v", err)
	}
	fmt.Printf("   ✓ Decapsulation complete\n")

	// Verify shared secrets match
	if !bytes.Equal(sharedSecret1, sharedSecret2) {
		log.Fatal("Shared secrets don't match!")
	}
	fmt.Printf("   ✓ Shared secrets match - secure channel established\n\n")

	// Example 6: List all quantum keys
	fmt.Println("6. Listing all quantum keys...")
	keys, err := quantumBackend.ListKeys()
	if err != nil {
		log.Fatalf("Failed to list keys: %v", err)
	}

	fmt.Printf("   Total quantum keys: %d\n", len(keys))
	for i, key := range keys {
		fmt.Printf("   %d. %s (%s)\n", i+1, key.CN, key.QuantumAttributes.Algorithm)
	}
	fmt.Println()

	// Example 7: Key persistence - retrieve previously generated key
	fmt.Println("7. Demonstrating key persistence...")
	retrievedKey, err := quantumBackend.GetKey(mldsaAttrs)
	if err != nil {
		log.Fatalf("Failed to retrieve key: %v", err)
	}
	fmt.Printf("   ✓ Retrieved key: %s\n", mldsaAttrs.CN)

	// Use retrieved key to sign
	retrievedSigner, err := quantumBackend.Signer(mldsaAttrs)
	if err != nil {
		log.Fatalf("Failed to get signer from retrieved key: %v", err)
	}

	persistenceTestMsg := []byte("Testing key persistence")
	persistenceHash := sha256.Sum256(persistenceTestMsg)
	persistenceSig, err := retrievedSigner.Sign(rand.Reader, persistenceHash[:], crypto.SHA256)
	if err != nil {
		log.Fatalf("Failed to sign with retrieved key: %v", err)
	}
	fmt.Printf("   ✓ Signed with retrieved key (%d bytes)\n\n", len(persistenceSig))

	// Summary
	fmt.Println("=== Summary ===")
	fmt.Println("\nPost-Quantum Algorithms Used:")
	fmt.Println("  • ML-DSA-44 (Dilithium2) - NIST FIPS 204, Security Level 2")
	fmt.Println("  • ML-DSA-65 (Dilithium3) - NIST FIPS 204, Security Level 3 (recommended)")
	fmt.Println("  • ML-KEM-768 (Kyber768) - NIST FIPS 203, Security Level 3 (recommended)")
	fmt.Println("\nKey Features Demonstrated:")
	fmt.Println("  ✓ Seamless integration with keychain Backend interface")
	fmt.Println("  ✓ Standard crypto.Signer interface for ML-DSA")
	fmt.Println("  ✓ Key Encapsulation Mechanism (KEM) for ML-KEM")
	fmt.Println("  ✓ Key persistence and retrieval")
	fmt.Println("  ✓ Same API as PKCS8, TPM2, PKCS11 backends")
	fmt.Println("\nSecurity Benefits:")
	fmt.Println("  ✓ Resistant to quantum computer attacks")
	fmt.Println("  ✓ NIST-standardized algorithms (FIPS 203, FIPS 204)")
	fmt.Println("  ✓ Can be combined with classical algorithms for hybrid security")

	fmt.Printf("\n✓ All quantum cryptography examples completed successfully!\n")
	fmt.Printf("\nKeys stored in: %s\n", tmpDir)
	fmt.Println("\nNote: Build with -tags=\"quantum\" to enable quantum support")
}
