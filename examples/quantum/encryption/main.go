//go:build quantum

// Package main demonstrates quantum-safe encryption using ML-KEM + AES-256-GCM.
package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/jeremyhahn/go-keychain/pkg/backend/quantum"
	"github.com/jeremyhahn/go-keychain/pkg/storage/file"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

func main() {
	// Create a temporary directory for the keychain
	tmpDir := filepath.Join(os.TempDir(), "quantum-encryption")
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Initialize storage backend
	storage, err := file.New(tmpDir)
	if err != nil {
		log.Fatalf("Failed to create storage: %v", err)
	}

	// Create quantum backend
	backend, err := quantum.New(storage)
	if err != nil {
		log.Fatalf("Failed to create quantum backend: %v", err)
	}
	defer func() { _ = backend.Close() }()

	fmt.Println("=== Quantum-Safe Encryption Examples ===\n")
	fmt.Println("Using ML-KEM (Key Encapsulation) + AES-256-GCM (Symmetric Encryption)")
	fmt.Println()

	// Example 1: Generate ML-KEM-768 key
	fmt.Println("1. Generating ML-KEM-768 key...")
	attrs := &types.KeyAttributes{
		CN:        "encryption-key",
		KeyType:   types.KeyTypeEncryption,
		StoreType: types.StoreQuantum,
		QuantumAttributes: &types.QuantumAttributes{
			Algorithm: types.QuantumAlgorithmMLKEM768,
		},
	}

	privKey, err := backend.GenerateKey(attrs)
	if err != nil {
		log.Fatalf("Failed to generate key: %v", err)
	}

	mlkemKey := privKey.(*quantum.MLKEMPrivateKey)
	publicKey := mlkemKey.PublicKey.Bytes()

	fmt.Printf("   ✓ ML-KEM-768 key generated\n")
	fmt.Printf("   Public key: %d bytes\n\n", len(publicKey))

	// Example 2: Basic Encryption
	fmt.Println("2. Basic Encryption and Decryption...")
	plaintext := []byte("This is a secret message protected by quantum-safe cryptography!")

	// Encrypt: Returns KEM ciphertext + encrypted data
	kemCiphertext, encryptedData, err := mlkemKey.Encrypt(plaintext, publicKey)
	if err != nil {
		log.Fatalf("Encryption failed: %v", err)
	}

	fmt.Printf("   Original message: %d bytes\n", len(plaintext))
	fmt.Printf("   KEM ciphertext: %d bytes\n", len(kemCiphertext))
	fmt.Printf("   Encrypted data: %d bytes\n", len(encryptedData))
	fmt.Printf("   Total transmission: %d bytes\n", len(kemCiphertext)+len(encryptedData))
	fmt.Println()

	// Decrypt
	decrypted, err := mlkemKey.Decrypt(kemCiphertext, encryptedData)
	if err != nil {
		log.Fatalf("Decryption failed: %v", err)
	}

	if string(decrypted) == string(plaintext) {
		fmt.Printf("   ✓ Decryption successful!\n")
		fmt.Printf("   Message: %s\n\n", decrypted)
	}

	// Example 3: Encryption with Additional Authenticated Data (AAD)
	fmt.Println("3. Encryption with Additional Authenticated Data...")
	message := []byte("Transfer $1,000 to account 12345")
	aad := []byte("user-id:alice|timestamp:2025-01-15T10:30:00Z")

	kemCt, encData, err := mlkemKey.EncryptWithAAD(message, aad, publicKey)
	if err != nil {
		log.Fatalf("Encryption with AAD failed: %v", err)
	}

	fmt.Printf("   Message: %s\n", message)
	fmt.Printf("   AAD: %s\n", aad)
	fmt.Printf("   Encrypted: %d bytes\n", len(encData))

	// Decrypt with AAD verification
	decrypted, err = mlkemKey.DecryptWithAAD(kemCt, encData, aad)
	if err != nil {
		log.Fatalf("Decryption with AAD failed: %v", err)
	}

	fmt.Printf("   ✓ Decrypted and AAD verified: %s\n\n", decrypted)

	// Demonstrate AAD protection
	fmt.Println("   Testing AAD protection...")
	wrongAAD := []byte("user-id:mallory|timestamp:2025-01-15T10:30:00Z")
	_, err = mlkemKey.DecryptWithAAD(kemCt, encData, wrongAAD)
	if err != nil {
		fmt.Printf("   ✓ Decryption rejected with wrong AAD (as expected)\n\n")
	}

	// Example 4: Encrypting Multiple Messages
	fmt.Println("4. Encrypting Multiple Messages...")
	messages := []string{
		"Message 1: Status update",
		"Message 2: Configuration data",
		"Message 3: Long message with more content to demonstrate encryption efficiency",
	}

	for i, msg := range messages {
		kemCt, encData, err := mlkemKey.Encrypt([]byte(msg), publicKey)
		if err != nil {
			log.Fatalf("Failed to encrypt message %d: %v", i+1, err)
		}

		overhead := len(kemCt) + len(encData) - len(msg)
		fmt.Printf("   Message %d: %d bytes -> %d bytes (overhead: %d bytes)\n",
			i+1, len(msg), len(kemCt)+len(encData), overhead)
	}
	fmt.Println()

	// Example 5: Sender/Receiver Scenario
	fmt.Println("5. Sender/Receiver Scenario...")

	// Receiver generates key and publishes public key
	receiverAttrs := &types.KeyAttributes{
		CN:        "receiver-key",
		KeyType:   types.KeyTypeEncryption,
		StoreType: types.StoreQuantum,
		QuantumAttributes: &types.QuantumAttributes{
			Algorithm: types.QuantumAlgorithmMLKEM768,
		},
	}

	receiverKey, err := backend.GenerateKey(receiverAttrs)
	if err != nil {
		log.Fatalf("Failed to generate receiver key: %v", err)
	}

	receiverPrivKey := receiverKey.(*quantum.MLKEMPrivateKey)
	receiverPubKey := receiverPrivKey.PublicKey.Bytes()

	fmt.Printf("   Receiver published public key: %d bytes\n", len(receiverPubKey))

	// Sender encrypts to receiver's public key
	senderMessage := []byte("Confidential data for receiver")
	senderKemCt, senderEncData, err := receiverPrivKey.Encrypt(senderMessage, receiverPubKey)
	if err != nil {
		log.Fatalf("Sender encryption failed: %v", err)
	}

	fmt.Printf("   Sender encrypted message: %d bytes total\n", len(senderKemCt)+len(senderEncData))

	// Receiver decrypts
	receiverPlaintext, err := receiverPrivKey.Decrypt(senderKemCt, senderEncData)
	if err != nil {
		log.Fatalf("Receiver decryption failed: %v", err)
	}

	if string(receiverPlaintext) == string(senderMessage) {
		fmt.Printf("   ✓ Receiver decrypted: %s\n\n", receiverPlaintext)
	}

	// Example 6: Large Data Encryption
	fmt.Println("6. Large Data Encryption...")
	largeData := make([]byte, 1024*1024) // 1MB
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	kemCt, encData, err = mlkemKey.Encrypt(largeData, publicKey)
	if err != nil {
		log.Fatalf("Large data encryption failed: %v", err)
	}

	decryptedLarge, err := mlkemKey.Decrypt(kemCt, encData)
	if err != nil {
		log.Fatalf("Large data decryption failed: %v", err)
	}

	fmt.Printf("   Original size: %d bytes (1 MB)\n", len(largeData))
	fmt.Printf("   Encrypted size: %d bytes\n", len(kemCt)+len(encData))
	overhead := float64(len(kemCt)+len(encData)-len(largeData)) / float64(len(largeData)) * 100
	fmt.Printf("   Overhead: %.3f%%\n", overhead)

	// Verify
	match := true
	for i := range largeData {
		if largeData[i] != decryptedLarge[i] {
			match = false
			break
		}
	}

	if match {
		fmt.Printf("   ✓ Large data encrypted/decrypted successfully\n\n")
	}

	// Summary
	fmt.Println("=== Summary ===")
	fmt.Println("\nQuantum-Safe Encryption Solution:")
	fmt.Println("  • ML-KEM (Kyber) - Key Encapsulation Mechanism (NIST FIPS 203)")
	fmt.Println("  • AES-256-GCM - Authenticated Encryption")
	fmt.Println("  • Combined = Quantum-resistant encryption")
	fmt.Println("\nHow It Works:")
	fmt.Println("  1. ML-KEM establishes a shared secret (32-byte AES key)")
	fmt.Println("  2. Shared secret encrypts data with AES-256-GCM")
	fmt.Println("  3. Recipient uses ML-KEM to recover shared secret")
	fmt.Println("  4. Shared secret decrypts data")
	fmt.Println("\nSecurity Benefits:")
	fmt.Println("  ✓ Resistant to quantum computer attacks")
	fmt.Println("  ✓ NIST-standardized (FIPS 203)")
	fmt.Println("  ✓ Authenticated encryption (prevents tampering)")
	fmt.Println("  ✓ Efficient for large data (minimal overhead)")
	fmt.Println("\nAPI Features:")
	fmt.Println("  ✓ Simple Encrypt/Decrypt methods")
	fmt.Println("  ✓ Additional Authenticated Data (AAD) support")
	fmt.Println("  ✓ Seamless keychain integration")

	fmt.Printf("\n✓ All quantum encryption examples completed successfully!\n")
}
