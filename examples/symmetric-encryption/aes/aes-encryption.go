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

// Package main demonstrates symmetric encryption using AES-256-GCM
// with the AES backend. This example shows:
//   - Generating AES-256 symmetric keys
//   - Encrypting and decrypting data
//   - Using password-protected keys
//   - Proper error handling and cleanup
package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/backend/aes"
	"github.com/jeremyhahn/go-keychain/pkg/storage/file"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// simplePassword implements types.Password for examples
type simplePassword struct {
	password []byte
}

func newPassword(pwd []byte) types.Password {
	return &simplePassword{password: pwd}
}

func (p *simplePassword) Bytes() []byte {
	return p.password
}

func (p *simplePassword) String() (string, error) {
	return string(p.password), nil
}

func (p *simplePassword) Clear() {
	for i := range p.password {
		p.password[i] = 0
	}
}

func main() {
	fmt.Println("=== Symmetric Encryption Example (AES-256-GCM) ===")

	// Create a temporary directory for key storage
	// In production, use a secure, persistent location
	tmpDir := filepath.Join(os.TempDir(), "symmetric-encryption-example")
	if err := os.MkdirAll(tmpDir, 0700); err != nil {
		log.Fatalf("Failed to create directory: %v", err)
	}
	defer os.RemoveAll(tmpDir) // Clean up

	fmt.Printf("Key storage location: %s\n\n", tmpDir)

	// Initialize file-based storage
	storage, err := file.New(tmpDir)
	if err != nil {
		log.Fatalf("Failed to create storage: %v", err)
	}

	// Create AES backend (software-based symmetric encryption)
	symmetricBackend, err := aes.NewBackend(&aes.Config{
		KeyStorage: storage,
	})
	if err != nil {
		log.Fatalf("Failed to create AES backend: %v", err)
	}
	defer symmetricBackend.Close()

	// Example 1: Basic AES-256 encryption without password
	fmt.Println("--- Example 1: Basic AES-256 Encryption ---")
	if err := basicEncryption(symmetricBackend); err != nil {
		log.Fatalf("Basic encryption example failed: %v", err)
	}

	// Example 2: Password-protected AES-256 encryption
	fmt.Println("\n--- Example 2: Password-Protected AES-256 Encryption ---")
	if err := passwordProtectedEncryption(symmetricBackend); err != nil {
		log.Fatalf("Password-protected encryption example failed: %v", err)
	}

	// Example 3: Encryption with Additional Authenticated Data (AAD)
	fmt.Println("\n--- Example 3: Encryption with Additional Authenticated Data ---")
	if err := encryptionWithAAD(symmetricBackend); err != nil {
		log.Fatalf("AAD encryption example failed: %v", err)
	}

	fmt.Println("\n=== All examples completed successfully! ===")
}

// basicEncryption demonstrates basic AES-256-GCM encryption and decryption
// without password protection.
func basicEncryption(b types.SymmetricBackend) error {
	// Define key attributes for AES-256-GCM
	attrs := &types.KeyAttributes{
		CN:                 "basic-aes-key",
		KeyType:            backend.KEY_TYPE_ENCRYPTION,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		AESAttributes: &types.AESAttributes{
			KeySize: 256, // 256-bit key
		},
	}

	// Generate a new AES-256 symmetric key
	fmt.Println("1. Generating AES-256 key...")
	key, err := b.GenerateSymmetricKey(attrs)
	if err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}
	fmt.Printf("   ✓ Generated %s key (%d bits)\n", key.Algorithm(), key.KeySize())

	// Get an encrypter for the key
	fmt.Println("\n2. Creating symmetric encrypter...")
	encrypter, err := b.SymmetricEncrypter(attrs)
	if err != nil {
		return fmt.Errorf("failed to get encrypter: %w", err)
	}
	fmt.Println("   ✓ Encrypter created")

	// Encrypt some data
	plaintext := []byte("Hello, World! This is a secret message.")
	fmt.Printf("\n3. Encrypting plaintext: %q\n", plaintext)

	encrypted, err := encrypter.Encrypt(plaintext, nil)
	if err != nil {
		return fmt.Errorf("failed to encrypt: %w", err)
	}
	fmt.Printf("   ✓ Ciphertext: %s\n", base64.StdEncoding.EncodeToString(encrypted.Ciphertext))
	fmt.Printf("   ✓ Nonce: %s\n", base64.StdEncoding.EncodeToString(encrypted.Nonce))
	fmt.Printf("   ✓ Tag: %s\n", base64.StdEncoding.EncodeToString(encrypted.Tag))

	// Decrypt the data
	fmt.Println("\n4. Decrypting ciphertext...")
	decrypted, err := encrypter.Decrypt(encrypted, nil)
	if err != nil {
		return fmt.Errorf("failed to decrypt: %w", err)
	}
	fmt.Printf("   ✓ Decrypted: %q\n", decrypted)

	// Verify the decrypted data matches the original
	if string(decrypted) != string(plaintext) {
		return fmt.Errorf("decrypted data does not match original")
	}
	fmt.Println("   ✓ Verification successful!")

	return nil
}

// passwordProtectedEncryption demonstrates AES-256-GCM encryption
// with password-protected key storage.
func passwordProtectedEncryption(b types.SymmetricBackend) error {
	// Define a password for key encryption
	password := newPassword([]byte("my-secure-password"))

	// Define key attributes with password protection
	attrs := &types.KeyAttributes{
		CN:                 "password-protected-key",
		KeyType:            backend.KEY_TYPE_ENCRYPTION,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		AESAttributes: &types.AESAttributes{
			KeySize: 256,
		},
		Password: password, // Key will be encrypted with this password
	}

	// Generate a password-protected AES-256 key
	fmt.Println("1. Generating password-protected AES-256 key...")
	key, err := b.GenerateSymmetricKey(attrs)
	if err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}
	fmt.Printf("   ✓ Generated password-protected %s key (%d bits)\n", key.Algorithm(), key.KeySize())
	fmt.Println("   ✓ Key is encrypted at rest with password")

	// Get an encrypter (requires password to decrypt the stored key)
	fmt.Println("\n2. Retrieving key with password...")
	encrypter, err := b.SymmetricEncrypter(attrs)
	if err != nil {
		return fmt.Errorf("failed to get encrypter: %w", err)
	}
	fmt.Println("   ✓ Key decrypted successfully with password")

	// Encrypt sensitive data
	plaintext := []byte("This is highly sensitive data protected by a password!")
	fmt.Printf("\n3. Encrypting plaintext: %q\n", plaintext)

	encrypted, err := encrypter.Encrypt(plaintext, nil)
	if err != nil {
		return fmt.Errorf("failed to encrypt: %w", err)
	}
	fmt.Printf("   ✓ Data encrypted successfully\n")

	// Decrypt the data
	fmt.Println("\n4. Decrypting ciphertext...")
	decrypted, err := encrypter.Decrypt(encrypted, nil)
	if err != nil {
		return fmt.Errorf("failed to decrypt: %w", err)
	}
	fmt.Printf("   ✓ Decrypted: %q\n", decrypted)

	// Verify
	if string(decrypted) != string(plaintext) {
		return fmt.Errorf("decrypted data does not match original")
	}
	fmt.Println("   ✓ Verification successful!")

	// Demonstrate wrong password fails
	fmt.Println("\n5. Testing wrong password...")
	wrongAttrs := &types.KeyAttributes{
		CN:                 "password-protected-key",
		KeyType:            backend.KEY_TYPE_ENCRYPTION,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		AESAttributes: &types.AESAttributes{
			KeySize: 256,
		},
		Password: newPassword([]byte("wrong-password")),
	}

	_, err = b.SymmetricEncrypter(wrongAttrs)
	if err == nil {
		return fmt.Errorf("expected error with wrong password, got nil")
	}
	fmt.Printf("   ✓ Correctly rejected wrong password: %v\n", err)

	return nil
}

// encryptionWithAAD demonstrates authenticated encryption with
// Additional Authenticated Data (AAD). AAD is authenticated but not encrypted,
// useful for associating metadata with encrypted data.
func encryptionWithAAD(b types.SymmetricBackend) error {
	// Define key attributes
	attrs := &types.KeyAttributes{
		CN:                 "aad-example-key",
		KeyType:            backend.KEY_TYPE_ENCRYPTION,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		AESAttributes: &types.AESAttributes{
			KeySize: 256,
		},
	}

	// Generate the key
	fmt.Println("1. Generating AES-256 key...")
	_, err := b.GenerateSymmetricKey(attrs)
	if err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}
	fmt.Println("   ✓ Key generated")

	// Get encrypter
	encrypter, err := b.SymmetricEncrypter(attrs)
	if err != nil {
		return fmt.Errorf("failed to get encrypter: %w", err)
	}

	// Define plaintext and AAD
	// AAD is authenticated but NOT encrypted - useful for metadata
	plaintext := []byte("Confidential document content")
	aad := []byte("document-id:12345,user:alice,timestamp:2025-11-07")

	fmt.Printf("\n2. Encrypting with AAD:\n")
	fmt.Printf("   Plaintext: %q\n", plaintext)
	fmt.Printf("   AAD: %q\n", aad)

	// Encrypt with AAD
	encrypted, err := encrypter.Encrypt(plaintext, &types.EncryptOptions{
		AdditionalData: aad,
	})
	if err != nil {
		return fmt.Errorf("failed to encrypt: %w", err)
	}
	fmt.Printf("   ✓ Encrypted with AAD authentication\n")

	// Decrypt with matching AAD - should succeed
	fmt.Println("\n3. Decrypting with correct AAD...")
	decrypted, err := encrypter.Decrypt(encrypted, &types.DecryptOptions{
		AdditionalData: aad,
	})
	if err != nil {
		return fmt.Errorf("failed to decrypt: %w", err)
	}
	fmt.Printf("   ✓ Decrypted: %q\n", decrypted)

	// Try to decrypt with wrong AAD - should fail
	fmt.Println("\n4. Testing with wrong AAD (should fail)...")
	wrongAAD := []byte("document-id:99999,user:eve,timestamp:2025-11-07")
	_, err = encrypter.Decrypt(encrypted, &types.DecryptOptions{
		AdditionalData: wrongAAD,
	})
	if err == nil {
		return fmt.Errorf("expected error with wrong AAD, got nil")
	}
	fmt.Printf("   ✓ Correctly rejected wrong AAD: %v\n", err)

	// Try to decrypt with no AAD - should also fail
	fmt.Println("\n5. Testing with missing AAD (should fail)...")
	_, err = encrypter.Decrypt(encrypted, nil)
	if err == nil {
		return fmt.Errorf("expected error with missing AAD, got nil")
	}
	fmt.Printf("   ✓ Correctly rejected missing AAD: %v\n", err)

	return nil
}

/* Example Output:

=== Symmetric Encryption Example (AES-256-GCM) ===

Key storage location: /tmp/symmetric-encryption-example

--- Example 1: Basic AES-256 Encryption ---
1. Generating AES-256 key...
   ✓ Generated aes256-gcm key (256 bits)

2. Creating symmetric encrypter...
   ✓ Encrypter created

3. Encrypting plaintext: "Hello, World! This is a secret message."
   ✓ Ciphertext: 4Kj3m9F2xR8pQ7vN1cY6tH5sL0wE9aZ8
   ✓ Nonce: xY2wQ5mN8kR7pL1t
   ✓ Tag: 9aF3nM7kL2pR5tY8

4. Decrypting ciphertext...
   ✓ Decrypted: "Hello, World! This is a secret message."
   ✓ Verification successful!

--- Example 2: Password-Protected AES-256 Encryption ---
1. Generating password-protected AES-256 key...
   ✓ Generated password-protected aes256-gcm key (256 bits)
   ✓ Key is encrypted at rest with password

2. Retrieving key with password...
   ✓ Key decrypted successfully with password

3. Encrypting plaintext: "This is highly sensitive data protected by a password!"
   ✓ Data encrypted successfully

4. Decrypting ciphertext...
   ✓ Decrypted: "This is highly sensitive data protected by a password!"
   ✓ Verification successful!

5. Testing wrong password...
   ✓ Correctly rejected wrong password: failed to decrypt key: decryption failed (authentication error)

--- Example 3: Encryption with Additional Authenticated Data ---
1. Generating AES-256 key...
   ✓ Key generated

2. Encrypting with AAD:
   Plaintext: "Confidential document content"
   AAD: "document-id:12345,user:alice,timestamp:2025-11-07"
   ✓ Encrypted with AAD authentication

3. Decrypting with correct AAD...
   ✓ Decrypted: "Confidential document content"

4. Testing with wrong AAD (should fail)...
   ✓ Correctly rejected wrong AAD: decryption failed (authentication error)

5. Testing with missing AAD (should fail)...
   ✓ Correctly rejected missing AAD: decryption failed (authentication error)

=== All examples completed successfully! ===
*/
