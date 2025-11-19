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

//go:build gcpkms

// Package main demonstrates symmetric encryption using GCP KMS.
//
// Build with: go build -tags gcpkms
//
// Requirements:
//   - Set GOOGLE_APPLICATION_CREDENTIALS environment variable (path to service account JSON)
//   - Set GCP_PROJECT_ID environment variable
//   - Optionally set GCP_LOCATION (defaults to "global")
//   - Optionally set GCP_KEYRING (defaults to "go-keychain")
package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/backend/gcpkms"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/storage/file"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

func main() {
	fmt.Println("=== GCP KMS Symmetric Encryption Example ===\n")

	if err := gcpKMSExample(); err != nil {
		log.Fatalf("GCP KMS example failed: %v\n", err)
	}

	fmt.Println("\n=== Example completed successfully ===")
}

// gcpKMSExample demonstrates symmetric encryption using GCP KMS.
func gcpKMSExample() error {
	// Create GCP KMS backend
	b, err := createGCPKMSBackend()
	if err != nil {
		return fmt.Errorf("failed to create GCP KMS backend: %w", err)
	}
	defer func() { _ = b.Close() }()

	// GCP KMS supports AES-128, AES-192, and AES-256
	attrs := &types.KeyAttributes{
		CN:                 "gcp-symmetric-key",
		KeyType:            backend.KEY_TYPE_ENCRYPTION,
		StoreType:          backend.STORE_GCPKMS,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		AESAttributes: &types.AESAttributes{
			KeySize: 256,
		},
	}

	// Generate key in GCP KMS
	fmt.Println("1. Generating AES-256 key in GCP KMS...")
	key, err := b.GenerateSymmetricKey(attrs)
	if err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}
	fmt.Printf("   ✓ Generated %s key in GCP KMS\n", key.Algorithm())
	fmt.Println("   ✓ Key material never leaves GCP KMS")

	// Get encrypter
	fmt.Println("\n2. Creating encrypter...")
	encrypter, err := b.SymmetricEncrypter(attrs)
	if err != nil {
		return fmt.Errorf("failed to get encrypter: %w", err)
	}
	fmt.Println("   ✓ Encrypter created")

	// Encrypt data with AAD
	plaintext := []byte("Confidential data encrypted with GCP KMS")
	aad := []byte("project:my-project,environment:prod,app:backend")

	fmt.Printf("\n3. Encrypting data with AAD:\n")
	fmt.Printf("   Plaintext: %q\n", plaintext)
	fmt.Printf("   AAD: %q\n", aad)

	encrypted, err := encrypter.Encrypt(plaintext, &types.EncryptOptions{
		AdditionalData: aad,
	})
	if err != nil {
		return fmt.Errorf("failed to encrypt: %w", err)
	}
	fmt.Printf("   ✓ Ciphertext: %s...\n", base64.StdEncoding.EncodeToString(encrypted.Ciphertext[:min(32, len(encrypted.Ciphertext))]))
	fmt.Println("   ✓ Encryption performed in GCP KMS")

	// Decrypt data
	fmt.Println("\n4. Decrypting data...")
	decrypted, err := encrypter.Decrypt(encrypted, &types.DecryptOptions{
		AdditionalData: aad,
	})
	if err != nil {
		return fmt.Errorf("failed to decrypt: %w", err)
	}
	fmt.Printf("   ✓ Decrypted: %q\n", decrypted)
	fmt.Println("   ✓ Decryption performed in GCP KMS")

	// Verify
	if string(decrypted) != string(plaintext) {
		return fmt.Errorf("decrypted data does not match original")
	}
	fmt.Println("   ✓ Verification successful!")

	return nil
}

func createGCPKMSBackend() (types.SymmetricBackend, error) {
	// Load GCP configuration from environment
	// Requires: GOOGLE_APPLICATION_CREDENTIALS, GCP_PROJECT_ID, GCP_LOCATION, GCP_KEYRING
	projectID := os.Getenv("GCP_PROJECT_ID")
	if projectID == "" {
		return nil, fmt.Errorf("GCP_PROJECT_ID environment variable not set")
	}

	location := os.Getenv("GCP_LOCATION")
	if location == "" {
		location = "global" // Default location
	}

	keyring := os.Getenv("GCP_KEYRING")
	if keyring == "" {
		keyring = "go-keychain" // Default keyring name
	}

	// Create temporary storage for key metadata
	storage, err := createTempStorage()
	if err != nil {
		return nil, fmt.Errorf("failed to create storage: %w", err)
	}

	// Create GCP KMS backend configuration
	backendCfg := &gcpkms.Config{
		ProjectID:   projectID,
		LocationID:  location,
		KeyRingID:   keyring,
		KeyStorage:  storage,
		CertStorage: storage,
	}

	// Create and initialize the backend
	ctx := context.Background()
	b, err := gcpkms.NewBackend(ctx, backendCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCP KMS backend: %w", err)
	}

	return b, nil
}

// Helper function for temporary storage
func createTempStorage() (storage.Backend, error) {
	tmpDir := filepath.Join(os.TempDir(), "gcp-kms-example")
	return file.New(tmpDir)
}

// Helper function to get minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
