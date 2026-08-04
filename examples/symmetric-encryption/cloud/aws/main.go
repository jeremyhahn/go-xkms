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

//go:build awskms

// Package main demonstrates symmetric encryption using AWS KMS.
//
// Build with: go build -tags awskms
//
// Requirements:
//   - Configure AWS credentials (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
//   - Set AWS_REGION environment variable
package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/backend/awskms"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/file"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

func main() {
	fmt.Println("=== AWS KMS Symmetric Encryption Example ===")

	if err := awsKMSExample(); err != nil {
		log.Fatalf("AWS KMS example failed: %v\n", err)
	}

	fmt.Println("\n=== Example completed successfully ===")
}

// awsKMSExample demonstrates symmetric encryption using AWS KMS.
func awsKMSExample() error {
	// Create AWS KMS backend
	b, err := createAWSKMSBackend()
	if err != nil {
		return &errs.Wrapped{Msg: "failed to create AWS KMS backend", Err: err}
	}
	defer func() { _ = b.Close() }()

	// AWS KMS only supports AES-256 symmetric keys
	attrs := &types.KeyAttributes{
		CN:                 "aws-symmetric-key",
		KeyType:            backend.KEY_TYPE_ENCRYPTION,
		StoreType:          backend.STORE_AWSKMS,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	// Generate key in AWS KMS
	fmt.Println("1. Generating AES-256 key in AWS KMS...")
	key, err := b.GenerateSymmetricKey(context.Background(), attrs)
	if err != nil {
		return &errs.Wrapped{Msg: "failed to generate key", Err: err}
	}
	fmt.Printf("   ✓ Generated %s key in AWS KMS\n", key.Algorithm())
	fmt.Println("   ✓ Key material never leaves AWS KMS")

	// Get encrypter
	fmt.Println("\n2. Creating encrypter...")
	encrypter, err := b.SymmetricEncrypter(context.Background(), attrs)
	if err != nil {
		return &errs.Wrapped{Msg: "failed to get encrypter", Err: err}
	}
	fmt.Println("   ✓ Encrypter created")

	// Example with AAD (Additional Authenticated Data)
	plaintext := []byte("Sensitive data encrypted with AWS KMS")
	aad := []byte("context:production,service:api,version:1.0")

	fmt.Printf("\n3. Encrypting data with AAD:\n")
	fmt.Printf("   Plaintext: %q\n", plaintext)
	fmt.Printf("   AAD: %q\n", aad)

	// Encrypt with AWS KMS
	encrypted, err := encrypter.Encrypt(plaintext, &types.EncryptOptions{
		AdditionalData: aad,
	})
	if err != nil {
		return &errs.Wrapped{Msg: "failed to encrypt", Err: err}
	}
	fmt.Printf("   ✓ Ciphertext: %s...\n", base64.StdEncoding.EncodeToString(encrypted.Ciphertext[:min(32, len(encrypted.Ciphertext))]))
	fmt.Println("   ✓ Encryption performed in AWS KMS")

	// Decrypt with AWS KMS
	fmt.Println("\n4. Decrypting data...")
	decrypted, err := encrypter.Decrypt(encrypted, &types.DecryptOptions{
		AdditionalData: aad,
	})
	if err != nil {
		return &errs.Wrapped{Msg: "failed to decrypt", Err: err}
	}
	fmt.Printf("   ✓ Decrypted: %q\n", decrypted)
	fmt.Println("   ✓ Decryption performed in AWS KMS")

	// Verify
	if string(decrypted) != string(plaintext) {
		return &errs.Message{Msg: "decrypted data does not match original"}
	}
	fmt.Println("   ✓ Verification successful!")

	// Test AAD validation
	fmt.Println("\n5. Testing AAD validation (should fail)...")
	wrongAAD := []byte("context:development,service:api,version:1.0")
	_, err = encrypter.Decrypt(encrypted, &types.DecryptOptions{
		AdditionalData: wrongAAD,
	})
	if err == nil {
		return &errs.Message{Msg: "expected error with wrong AAD"}
	}
	fmt.Printf("   ✓ Correctly rejected wrong AAD: %v\n", err)

	return nil
}

func createAWSKMSBackend() (types.SymmetricKeyProvider, error) {
	// Load AWS configuration from environment
	// Requires: AWS_REGION, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY
	_ = context.Background()

	// Check required environment variables
	region := os.Getenv("AWS_REGION")
	if region == "" {
		return nil, &errs.Message{Msg: "AWS_REGION environment variable not set"}
	}

	// Create temporary storage for key metadata
	storage, err := createTempStorage()
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to create storage", Err: err}
	}

	// Create AWS KMS backend configuration
	backendCfg := &awskms.Config{
		Region:      region,
		KeyStorage:  storage,
		CertStorage: storage,
	}

	// Create and initialize the backend
	b, err := awskms.NewBackend(backendCfg)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to create AWS KMS backend", Err: err}
	}

	return b, nil
}

// Helper function for temporary storage
func createTempStorage() (storage.Backend, error) {
	tmpDir := filepath.Join(os.TempDir(), "aws-kms-example")
	return file.New(tmpDir)
}

// Helper function to get minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
