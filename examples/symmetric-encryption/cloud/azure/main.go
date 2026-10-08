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

//go:build azurekv

// Package main demonstrates symmetric encryption using Azure Key Vault.
//
// Build with: go build -tags azurekv
//
// Requirements:
//   - Set AZURE_TENANT_ID environment variable
//   - Set AZURE_CLIENT_ID environment variable
//   - Set AZURE_CLIENT_SECRET environment variable
//   - Set AZURE_VAULT_URL environment variable
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
	"github.com/jeremyhahn/go-xkms/pkg/backend/azurekv"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/file"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

func main() {
	fmt.Println("=== Azure Key Vault Symmetric Encryption Example ===")

	if err := azureKVExample(); err != nil {
		log.Fatalf("Azure Key Vault example failed: %v\n", err)
	}

	fmt.Println("\n=== Example completed successfully ===")
}

// azureKVExample demonstrates symmetric encryption using Azure Key Vault.
func azureKVExample() error {
	// Create Azure Key Vault backend
	b, err := createAzureKVBackend()
	if err != nil {
		return &errs.Wrapped{Msg: "failed to create Azure Key Vault backend", Err: err}
	}
	defer func() { _ = b.Close() }()

	// Azure Key Vault supports AES-128, AES-192, and AES-256
	attrs := &types.KeyAttributes{
		CN:                 "azure-symmetric-key",
		KeyType:            backend.KEY_TYPE_ENCRYPTION,
		StoreType:          backend.STORE_AZUREKV,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	// Generate key in Azure Key Vault
	fmt.Println("1. Generating AES-256 key in Azure Key Vault...")
	key, err := b.GenerateSymmetricKey(context.Background(), attrs)
	if err != nil {
		return &errs.Wrapped{Msg: "failed to generate key", Err: err}
	}
	fmt.Printf("   ✓ Generated %s key in Azure Key Vault\n", key.Algorithm())
	fmt.Println("   ✓ Key uses envelope encryption (local AES + key wrapping)")

	// Get encrypter
	fmt.Println("\n2. Creating encrypter...")
	encrypter, err := b.SymmetricEncrypter(context.Background(), attrs)
	if err != nil {
		return &errs.Wrapped{Msg: "failed to get encrypter", Err: err}
	}
	fmt.Println("   ✓ Encrypter created")

	// Encrypt data with AAD
	plaintext := []byte("Secret data protected by Azure Key Vault")
	aad := []byte("subscription:prod,resource:db,region:eastus")

	fmt.Printf("\n3. Encrypting data with AAD:\n")
	fmt.Printf("   Plaintext: %q\n", plaintext)
	fmt.Printf("   AAD: %q\n", aad)

	encrypted, err := encrypter.Encrypt(plaintext, &types.EncryptOptions{
		AdditionalData: aad,
	})
	if err != nil {
		return &errs.Wrapped{Msg: "failed to encrypt", Err: err}
	}
	fmt.Printf("   ✓ Ciphertext: %s...\n", base64.StdEncoding.EncodeToString(encrypted.Ciphertext[:min(32, len(encrypted.Ciphertext))]))
	fmt.Println("   ✓ Data encrypted locally, DEK wrapped in Azure KV")

	// Decrypt data
	fmt.Println("\n4. Decrypting data...")
	decrypted, err := encrypter.Decrypt(encrypted, &types.DecryptOptions{
		AdditionalData: aad,
	})
	if err != nil {
		return &errs.Wrapped{Msg: "failed to decrypt", Err: err}
	}
	fmt.Printf("   ✓ Decrypted: %q\n", decrypted)
	fmt.Println("   ✓ DEK unwrapped in Azure KV, data decrypted locally")

	// Verify
	if string(decrypted) != string(plaintext) {
		return &errs.Message{Msg: "decrypted data does not match original"}
	}
	fmt.Println("   ✓ Verification successful!")

	return nil
}

func createAzureKVBackend() (types.SymmetricKeyProvider, error) {
	// Load Azure configuration from environment
	// Requires: AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_VAULT_URL
	tenantID := os.Getenv("AZURE_TENANT_ID")
	if tenantID == "" {
		return nil, &errs.Message{Msg: "AZURE_TENANT_ID environment variable not set"}
	}

	clientID := os.Getenv("AZURE_CLIENT_ID")
	if clientID == "" {
		return nil, &errs.Message{Msg: "AZURE_CLIENT_ID environment variable not set"}
	}

	clientSecret := os.Getenv("AZURE_CLIENT_SECRET")
	if clientSecret == "" {
		return nil, &errs.Message{Msg: "AZURE_CLIENT_SECRET environment variable not set"}
	}

	vaultURL := os.Getenv("AZURE_VAULT_URL")
	if vaultURL == "" {
		return nil, &errs.Message{Msg: "AZURE_VAULT_URL environment variable not set"}
	}

	// Create temporary storage for key metadata
	storage, err := createTempStorage()
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to create storage", Err: err}
	}

	// Create Azure Key Vault backend configuration
	secret, err := types.NewLiteralSecretValue(context.Background(), []byte(clientSecret))
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to seal the client secret", Err: err}
	}
	backendCfg := &azurekv.Config{
		VaultURL:     vaultURL,
		TenantID:     tenantID,
		ClientID:     clientID,
		ClientSecret: secret,
		KeyStorage:   storage,
		CertStorage:  storage,
	}

	// Create and initialize the backend
	b, err := azurekv.NewBackend(backendCfg)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to create Azure Key Vault backend", Err: err}
	}

	return b, nil
}

// Helper function for temporary storage
func createTempStorage() (storage.Backend, error) {
	tmpDir := filepath.Join(os.TempDir(), "azure-kv-example")
	return file.New(tmpDir)
}

// Helper function to get minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
