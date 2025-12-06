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
	"context"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// TestCanSeal_NoConfig tests CanSeal returns false when config is nil
func TestCanSeal_NoConfig(t *testing.T) {
	b := &Backend{}

	if b.CanSeal() {
		t.Error("CanSeal() should return false when config is nil")
	}
}

// TestCanSeal_EmptyVaultURL tests CanSeal returns false when VaultURL is empty
func TestCanSeal_EmptyVaultURL(t *testing.T) {
	// Backend without VaultURL should fail during NewBackend
	config := &Config{
		VaultURL:    "",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}

	_, err := NewBackend(config)
	if err == nil {
		t.Error("NewBackend() should fail with empty VaultURL")
	}
}

// TestCanSeal_WithConfig tests CanSeal returns true when properly configured
func TestCanSeal_WithConfig(t *testing.T) {
	config := &Config{
		VaultURL:    "https://test-vault.vault.azure.net/",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() failed: %v", err)
	}

	if !b.CanSeal() {
		t.Error("CanSeal() should return true when VaultURL is set")
	}
}

// TestSeal_NilOptions tests Seal fails with nil options
func TestSeal_NilOptions(t *testing.T) {
	config := &Config{
		VaultURL:    "https://test-vault.vault.azure.net/",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() failed: %v", err)
	}

	ctx := context.Background()
	_, err = b.Seal(ctx, []byte("test"), nil)
	if err == nil {
		t.Error("Seal() should fail with nil options")
	}
}

// TestSeal_NilKeyAttributes tests Seal fails with nil KeyAttributes
func TestSeal_NilKeyAttributes(t *testing.T) {
	config := &Config{
		VaultURL:    "https://test-vault.vault.azure.net/",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() failed: %v", err)
	}

	ctx := context.Background()
	_, err = b.Seal(ctx, []byte("test"), &types.SealOptions{
		KeyAttributes: nil,
	})
	if err == nil {
		t.Error("Seal() should fail with nil KeyAttributes")
	}
}

// TestSeal_AsymmetricKeyRejected tests Seal fails with asymmetric key
func TestSeal_AsymmetricKeyRejected(t *testing.T) {
	config := &Config{
		VaultURL:    "https://test-vault.vault.azure.net/",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() failed: %v", err)
	}

	// Asymmetric key (no symmetric algorithm set)
	attrs := &types.KeyAttributes{
		CN:        "test-rsa-key",
		KeyType:   types.KeyTypeSigning,
		StoreType: types.StoreAzureKV,
	}

	ctx := context.Background()
	_, err = b.Seal(ctx, []byte("test"), &types.SealOptions{
		KeyAttributes: attrs,
	})
	if err == nil {
		t.Error("Seal() should fail with asymmetric key")
	}
}

// TestUnseal_NilSealedData tests Unseal fails with nil sealed data
func TestUnseal_NilSealedData(t *testing.T) {
	config := &Config{
		VaultURL:    "https://test-vault.vault.azure.net/",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() failed: %v", err)
	}

	ctx := context.Background()
	_, err = b.Unseal(ctx, nil, &types.UnsealOptions{
		KeyAttributes: &types.KeyAttributes{},
	})
	if err == nil {
		t.Error("Unseal() should fail with nil sealed data")
	}
}

// TestUnseal_WrongBackend tests Unseal fails with wrong backend type
func TestUnseal_WrongBackend(t *testing.T) {
	config := &Config{
		VaultURL:    "https://test-vault.vault.azure.net/",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() failed: %v", err)
	}

	sealed := &types.SealedData{
		Backend:    types.BackendTypePKCS8, // Wrong backend
		Ciphertext: []byte("test"),
		Nonce:      []byte("test-nonce"),
	}

	ctx := context.Background()
	_, err = b.Unseal(ctx, sealed, &types.UnsealOptions{
		KeyAttributes: &types.KeyAttributes{},
	})
	if err == nil {
		t.Error("Unseal() should fail with wrong backend type")
	}
}

// TestUnseal_NilOptions tests Unseal fails with nil options
func TestUnseal_NilOptions(t *testing.T) {
	config := &Config{
		VaultURL:    "https://test-vault.vault.azure.net/",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() failed: %v", err)
	}

	sealed := &types.SealedData{
		Backend:    types.BackendTypeAzureKV,
		Ciphertext: []byte("test"),
		Nonce:      []byte("test-nonce"),
	}

	ctx := context.Background()
	_, err = b.Unseal(ctx, sealed, nil)
	if err == nil {
		t.Error("Unseal() should fail with nil options")
	}
}

// TestUnseal_NilKeyAttributes tests Unseal fails with nil KeyAttributes
func TestUnseal_NilKeyAttributes(t *testing.T) {
	config := &Config{
		VaultURL:    "https://test-vault.vault.azure.net/",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() failed: %v", err)
	}

	sealed := &types.SealedData{
		Backend:    types.BackendTypeAzureKV,
		Ciphertext: []byte("test"),
		Nonce:      []byte("test-nonce"),
	}

	ctx := context.Background()
	_, err = b.Unseal(ctx, sealed, &types.UnsealOptions{
		KeyAttributes: nil,
	})
	if err == nil {
		t.Error("Unseal() should fail with nil KeyAttributes")
	}
}

// TestUnseal_KeyMismatch tests Unseal fails with mismatched key ID
func TestUnseal_KeyMismatch(t *testing.T) {
	config := &Config{
		VaultURL:    "https://test-vault.vault.azure.net/",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() failed: %v", err)
	}

	sealed := &types.SealedData{
		Backend:    types.BackendTypeAzureKV,
		Ciphertext: []byte("test"),
		Nonce:      []byte("test-nonce"),
		KeyID:      "original-key-id",
	}

	attrs := &types.KeyAttributes{
		CN:                 "different-key", // Different from KeyID
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		AESAttributes: &types.AESAttributes{
			KeySize: 256,
		},
	}

	ctx := context.Background()
	_, err = b.Unseal(ctx, sealed, &types.UnsealOptions{
		KeyAttributes: attrs,
	})
	if err == nil {
		t.Error("Unseal() should fail with mismatched key ID")
	}
}

// TestMarshalUnmarshalSealedData tests JSON serialization of SealedData
func TestMarshalUnmarshalSealedData(t *testing.T) {
	original := &types.SealedData{
		Backend:    types.BackendTypeAzureKV,
		Ciphertext: []byte("encrypted data"),
		Nonce:      []byte("test-nonce-12"),
		Tag:        []byte("test-tag-16-byte"),
		KeyID:      "test-key-id",
		Metadata: map[string][]byte{
			"azurekv:algorithm": []byte("AES-256-GCM"),
		},
	}

	// Marshal
	data, err := MarshalSealedData(original)
	if err != nil {
		t.Fatalf("MarshalSealedData() failed: %v", err)
	}

	// Unmarshal
	restored, err := UnmarshalSealedData(data)
	if err != nil {
		t.Fatalf("UnmarshalSealedData() failed: %v", err)
	}

	// Verify
	if restored.Backend != original.Backend {
		t.Errorf("Backend mismatch: got %s, want %s", restored.Backend, original.Backend)
	}
	if string(restored.Ciphertext) != string(original.Ciphertext) {
		t.Error("Ciphertext mismatch")
	}
	if string(restored.Nonce) != string(original.Nonce) {
		t.Error("Nonce mismatch")
	}
	if string(restored.Tag) != string(original.Tag) {
		t.Error("Tag mismatch")
	}
	if restored.KeyID != original.KeyID {
		t.Errorf("KeyID mismatch: got %s, want %s", restored.KeyID, original.KeyID)
	}
}
