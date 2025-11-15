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

//go:build azurekv

package azurekv

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/storage/memory"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// TestNewBackend tests the creation of a new Azure Key Vault backend.
func TestNewBackend(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
		errType error
	}{
		{
			name: "valid config",
			config: &Config{
				VaultURL:    "https://test-vault.vault.azure.net/",
				KeyStorage:  memory.New(),
				CertStorage: memory.New(),
			},
			wantErr: false,
		},
		{
			name:    "nil config",
			config:  nil,
			wantErr: true,
			errType: ErrInvalidConfig,
		},
		{
			name: "missing vault URL",
			config: &Config{
				VaultURL:    "",
				KeyStorage:  memory.New(),
				CertStorage: memory.New(),
			},
			wantErr: true,
			errType: ErrInvalidConfig,
		},
		{
			name: "invalid vault URL",
			config: &Config{
				VaultURL:    "http://invalid-url",
				KeyStorage:  memory.New(),
				CertStorage: memory.New(),
			},
			wantErr: true,
			errType: ErrInvalidVaultURL,
		},
		{
			name: "partial credentials",
			config: &Config{
				VaultURL:    "https://test-vault.vault.azure.net/",
				ClientID:    "client-id",
				KeyStorage:  memory.New(),
				CertStorage: memory.New(),
				// Missing ClientSecret and TenantID
			},
			wantErr: true,
			errType: ErrInvalidConfig,
		},
		{
			name: "complete credentials",
			config: &Config{
				VaultURL:     "https://test-vault.vault.azure.net/",
				TenantID:     "tenant-id",
				ClientID:     "client-id",
				ClientSecret: "client-secret",
				KeyStorage:   memory.New(),
				CertStorage:  memory.New(),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := NewBackend(tt.config)
			if tt.wantErr {
				if err == nil {
					t.Errorf("NewBackend() expected error but got nil")
					return
				}
				if tt.errType != nil && !errors.Is(err, tt.errType) {
					t.Errorf("NewBackend() error = %v, want error type %v", err, tt.errType)
				}
				return
			}
			if err != nil {
				t.Errorf("NewBackend() unexpected error = %v", err)
				return
			}
			if b == nil {
				t.Errorf("NewBackend() returned nil backend")
				return
			}
			if b.config != tt.config {
				t.Errorf("NewBackend() config mismatch")
			}
			if b.metadata == nil {
				t.Errorf("NewBackend() metadata map not initialized")
			}
		})
	}
}

// TestNewBackendWithClient tests creating a backend with a custom client.
func TestNewBackendWithClient(t *testing.T) {
	mockClient := NewMockKeyVaultClient()
	config := &Config{
		VaultURL:    "https://test-vault.vault.azure.net/",
		KeyStorage:  memory.New(),
		CertStorage: memory.New(),
	}

	b, err := NewBackendWithClient(config, mockClient)
	if err != nil {
		t.Fatalf("NewBackendWithClient() unexpected error = %v", err)
	}
	if b == nil {
		t.Fatal("NewBackendWithClient() returned nil backend")
	}
	if b.client == nil {
		t.Error("NewBackendWithClient() client is nil")
	}
}

// TestCreateKey tests key creation functionality.
func TestCreateKey(t *testing.T) {
	tests := []struct {
		name    string
		attrs   *types.KeyAttributes
		wantErr bool
	}{
		{
			name: "create RSA key",
			attrs: &types.KeyAttributes{
				CN:           "test-rsa-key",
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_AZUREKV,
				KeyAlgorithm: x509.RSA,
			},
			wantErr: false,
		},
		{
			name: "create ECDSA key",
			attrs: &types.KeyAttributes{
				CN:           "test-ecdsa-key",
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_AZUREKV,
				KeyAlgorithm: x509.ECDSA,
			},
			wantErr: false,
		},
		{
			name:    "nil attributes",
			attrs:   nil,
			wantErr: true,
		},
		{
			name: "unsupported algorithm",
			attrs: &types.KeyAttributes{
				CN:           "test-unsupported-key",
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_AZUREKV,
				KeyAlgorithm: x509.Ed25519, // Not supported by Azure KV
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := NewMockKeyVaultClient()
			config := &Config{
				VaultURL:    "https://test-vault.vault.azure.net/",
				KeyStorage:  memory.New(),
				CertStorage: memory.New(),
			}

			b, err := NewBackendWithClient(config, mockClient)
			if err != nil {
				t.Fatalf("NewBackendWithClient() error = %v", err)
			}

			keyID, err := b.CreateKey(tt.attrs)
			if tt.wantErr {
				if err == nil {
					t.Errorf("CreateKey() expected error but got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("CreateKey() unexpected error = %v", err)
				return
			}
			if keyID == "" {
				t.Error("CreateKey() returned empty key ID")
			}

			// Verify metadata was stored
			b.mu.RLock()
			_, exists := b.metadata[tt.attrs.CN]
			b.mu.RUnlock()
			if !exists {
				t.Error("CreateKey() metadata not stored")
			}
		})
	}
}

// TestCreateKeyIdempotent tests that CreateKey is idempotent.
func TestCreateKeyIdempotent(t *testing.T) {
	mockClient := NewMockKeyVaultClient()
	config := &Config{
		VaultURL:    "https://test-vault.vault.azure.net/",
		KeyStorage:  memory.New(),
		CertStorage: memory.New(),
	}

	b, err := NewBackendWithClient(config, mockClient)
	if err != nil {
		t.Fatalf("NewBackendWithClient() error = %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "test-idempotent-key",
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_AZUREKV,
		KeyAlgorithm: x509.RSA,
	}

	// Create key first time
	keyID1, err := b.CreateKey(attrs)
	if err != nil {
		t.Fatalf("CreateKey() first call error = %v", err)
	}

	// Create same key again (should be idempotent)
	keyID2, err := b.CreateKey(attrs)
	if err != nil {
		t.Fatalf("CreateKey() second call error = %v", err)
	}

	if keyID1 != keyID2 {
		t.Errorf("CreateKey() not idempotent: got different key IDs %s and %s", keyID1, keyID2)
	}
}

// TestSignAndVerify tests signing and verification operations.
func TestSignAndVerify(t *testing.T) {
	tests := []struct {
		name      string
		algorithm x509.PublicKeyAlgorithm
		wantErr   bool
	}{
		{
			name:      "RSA sign and verify",
			algorithm: x509.RSA,
			wantErr:   false,
		},
		{
			name:      "ECDSA sign and verify",
			algorithm: x509.ECDSA,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := NewMockKeyVaultClient()
			config := &Config{
				VaultURL:    "https://test-vault.vault.azure.net/",
				KeyStorage:  memory.New(),
				CertStorage: memory.New(),
			}

			b, err := NewBackendWithClient(config, mockClient)
			if err != nil {
				t.Fatalf("NewBackendWithClient() error = %v", err)
			}

			attrs := &types.KeyAttributes{
				CN:           "test-sign-verify-key",
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_AZUREKV,
				KeyAlgorithm: tt.algorithm,
			}

			// Create key
			_, err = b.CreateKey(attrs)
			if err != nil {
				t.Fatalf("CreateKey() error = %v", err)
			}

			// Create a test digest
			data := []byte("test data to sign")
			hash := sha256.Sum256(data)
			digest := hash[:]

			// Sign the digest
			signature, err := b.Sign(attrs, digest)
			if tt.wantErr {
				if err == nil {
					t.Errorf("Sign() expected error but got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("Sign() unexpected error = %v", err)
				return
			}
			if len(signature) == 0 {
				t.Error("Sign() returned empty signature")
				return
			}

			// Verify the signature
			err = b.Verify(attrs, digest, signature)
			if err != nil {
				t.Errorf("Verify() unexpected error = %v", err)
			}

			// Verify with wrong digest should fail
			wrongHash := sha256.Sum256([]byte("wrong data"))
			wrongDigest := wrongHash[:]
			err = b.Verify(attrs, wrongDigest, signature)
			if err == nil {
				t.Error("Verify() with wrong digest should fail")
			}
		})
	}
}

// TestGet tests retrieving key data.
func TestGet(t *testing.T) {
	mockClient := NewMockKeyVaultClient()
	config := &Config{
		VaultURL:    "https://test-vault.vault.azure.net/",
		KeyStorage:  memory.New(),
		CertStorage: memory.New(),
	}

	b, err := NewBackendWithClient(config, mockClient)
	if err != nil {
		t.Fatalf("NewBackendWithClient() error = %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "test-get-key",
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_AZUREKV,
		KeyAlgorithm: x509.RSA,
	}

	// Create key
	_, err = b.CreateKey(attrs)
	if err != nil {
		t.Fatalf("CreateKey() error = %v", err)
	}

	tests := []struct {
		name      string
		extension types.FSExtension
		wantErr   bool
	}{
		{
			name:      "get public key PEM",
			extension: backend.FSEXT_PUBLIC_PEM,
			wantErr:   false,
		},
		{
			name:      "get public key PKCS1",
			extension: backend.FSEXT_PUBLIC_PKCS1,
			wantErr:   false,
		},
		{
			name:      "get private blob (metadata)",
			extension: backend.FSEXT_PRIVATE_BLOB,
			wantErr:   false,
		},
		{
			name:      "get public blob (metadata)",
			extension: backend.FSEXT_PUBLIC_BLOB,
			wantErr:   false,
		},
		{
			name:      "unsupported extension",
			extension: backend.FSEXT_SIGNATURE,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := b.Get(attrs, tt.extension)
			if tt.wantErr {
				if err == nil {
					t.Errorf("Get() expected error but got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("Get() unexpected error = %v", err)
				return
			}
			if len(data) == 0 {
				t.Error("Get() returned empty data")
			}
		})
	}
}

// TestSave tests saving metadata.
func TestSave(t *testing.T) {
	mockClient := NewMockKeyVaultClient()
	config := &Config{
		VaultURL:    "https://test-vault.vault.azure.net/",
		KeyStorage:  memory.New(),
		CertStorage: memory.New(),
	}

	b, err := NewBackendWithClient(config, mockClient)
	if err != nil {
		t.Fatalf("NewBackendWithClient() error = %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "test-save-key",
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_AZUREKV,
		KeyAlgorithm: x509.RSA,
	}

	testData := []byte("test metadata")

	// Test saving new metadata
	err = b.Save(attrs, testData, backend.FSEXT_PRIVATE_BLOB, false)
	if err != nil {
		t.Errorf("Save() unexpected error = %v", err)
	}

	// Test overwrite protection
	err = b.Save(attrs, testData, backend.FSEXT_PRIVATE_BLOB, false)
	if err == nil {
		t.Error("Save() should fail when overwrite=false and data exists")
	}

	// Test overwrite allowed
	newData := []byte("new metadata")
	err = b.Save(attrs, newData, backend.FSEXT_PRIVATE_BLOB, true)
	if err != nil {
		t.Errorf("Save() with overwrite=true unexpected error = %v", err)
	}

	// Verify data was updated
	b.mu.RLock()
	savedData := b.metadata[attrs.CN]
	b.mu.RUnlock()

	if string(savedData) != string(newData) {
		t.Errorf("Save() data not updated: got %s, want %s", savedData, newData)
	}
}

// TestDelete tests deleting keys.
func TestDelete(t *testing.T) {
	mockClient := NewMockKeyVaultClient()
	config := &Config{
		VaultURL:    "https://test-vault.vault.azure.net/",
		KeyStorage:  memory.New(),
		CertStorage: memory.New(),
	}

	b, err := NewBackendWithClient(config, mockClient)
	if err != nil {
		t.Fatalf("NewBackendWithClient() error = %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "test-delete-key",
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_AZUREKV,
		KeyAlgorithm: x509.RSA,
	}

	// Create key
	_, err = b.CreateKey(attrs)
	if err != nil {
		t.Fatalf("CreateKey() error = %v", err)
	}

	// Verify metadata exists
	b.mu.RLock()
	_, exists := b.metadata[attrs.CN]
	b.mu.RUnlock()
	if !exists {
		t.Fatal("Metadata should exist before delete")
	}

	// Delete key
	err = b.Delete(attrs)
	if err != nil {
		t.Errorf("Delete() unexpected error = %v", err)
	}

	// Verify metadata was removed
	b.mu.RLock()
	_, exists = b.metadata[attrs.CN]
	b.mu.RUnlock()
	if exists {
		t.Error("Metadata should not exist after delete")
	}

	// Delete non-existent key should be idempotent
	err = b.Delete(attrs)
	if err != nil {
		t.Errorf("Delete() of non-existent key should not error: %v", err)
	}
}

// TestClose tests closing the backend.
func TestClose(t *testing.T) {
	mockClient := NewMockKeyVaultClient()
	config := &Config{
		VaultURL:    "https://test-vault.vault.azure.net/",
		KeyStorage:  memory.New(),
		CertStorage: memory.New(),
	}

	b, err := NewBackendWithClient(config, mockClient)
	if err != nil {
		t.Fatalf("NewBackendWithClient() error = %v", err)
	}

	// Add some metadata
	b.metadata["test-key"] = []byte("test data")

	err = b.Close()
	if err != nil {
		t.Errorf("Close() unexpected error = %v", err)
	}

	// Verify metadata was cleared
	if len(b.metadata) != 0 {
		t.Error("Close() should clear metadata")
	}

	// Verify client was cleared
	if b.client != nil {
		t.Error("Close() should clear client")
	}
}

// TestGetSigningAlgorithm tests the signing algorithm selection logic.
func TestGetSigningAlgorithm(t *testing.T) {
	mockClient := NewMockKeyVaultClient()
	config := &Config{
		VaultURL:    "https://test-vault.vault.azure.net/",
		KeyStorage:  memory.New(),
		CertStorage: memory.New(),
	}

	b, err := NewBackendWithClient(config, mockClient)
	if err != nil {
		t.Fatalf("NewBackendWithClient() error = %v", err)
	}

	tests := []struct {
		name      string
		algorithm x509.PublicKeyAlgorithm
		want      azkeys.SignatureAlgorithm
		wantErr   bool
	}{
		{
			name:      "RSA algorithm",
			algorithm: x509.RSA,
			want:      azkeys.SignatureAlgorithmRS256,
			wantErr:   false,
		},
		{
			name:      "ECDSA algorithm",
			algorithm: x509.ECDSA,
			want:      azkeys.SignatureAlgorithmES256,
			wantErr:   false,
		},
		{
			name:      "unsupported algorithm",
			algorithm: x509.Ed25519,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := &types.KeyAttributes{
				KeyAlgorithm: tt.algorithm,
				Hash:         crypto.SHA256, // Default hash for testing
			}

			got, err := b.getSigningAlgorithm(attrs, nil)
			if tt.wantErr {
				if err == nil {
					t.Errorf("getSigningAlgorithm() expected error but got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("getSigningAlgorithm() unexpected error = %v", err)
				return
			}
			if got != tt.want {
				t.Errorf("getSigningAlgorithm() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestConcurrentAccess tests thread-safety of the backend.
func TestConcurrentAccess(t *testing.T) {
	mockClient := NewMockKeyVaultClient()
	config := &Config{
		VaultURL:    "https://test-vault.vault.azure.net/",
		KeyStorage:  memory.New(),
		CertStorage: memory.New(),
	}

	b, err := NewBackendWithClient(config, mockClient)
	if err != nil {
		t.Fatalf("NewBackendWithClient() error = %v", err)
	}

	// Create multiple goroutines performing operations
	const numGoroutines = 10
	done := make(chan bool, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer func() { done <- true }()

			attrs := &types.KeyAttributes{
				CN:           fmt.Sprintf("concurrent-key-%d", id),
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_AZUREKV,
				KeyAlgorithm: x509.RSA,
			}

			// Create key (this also creates metadata)
			_, err := b.CreateKey(attrs)
			if err != nil {
				t.Errorf("Concurrent CreateKey() error = %v", err)
				return
			}

			// Get data (metadata was already created by CreateKey)
			_, err = b.Get(attrs, backend.FSEXT_PRIVATE_BLOB)
			if err != nil {
				t.Errorf("Concurrent Get() error = %v", err)
				return
			}

			// Delete key
			err = b.Delete(attrs)
			if err != nil {
				t.Errorf("Concurrent Delete() error = %v", err)
			}
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		<-done
	}
}
