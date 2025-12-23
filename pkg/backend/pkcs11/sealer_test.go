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

//go:build pkcs11

package pkcs11

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// TestCanSeal_NotInitialized tests CanSeal returns false when not initialized
func TestCanSeal_NotInitialized(t *testing.T) {
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	config := &Config{
		Library:     tempLib,
		TokenLabel:  "test",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() failed: %v", err)
	}

	if b.CanSeal() {
		t.Error("CanSeal() should return false when not initialized")
	}
}

// TestSeal_NilOptions tests Seal fails with nil options
func TestSeal_NilOptions(t *testing.T) {
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	config := &Config{
		Library:     tempLib,
		TokenLabel:  "test",
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
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	config := &Config{
		Library:     tempLib,
		TokenLabel:  "test",
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

// TestSeal_NotInitialized tests Seal fails when not initialized
func TestSeal_NotInitialized(t *testing.T) {
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	config := &Config{
		Library:     tempLib,
		TokenLabel:  "test",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() failed: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:                 "test-seal",
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		AESAttributes: &types.AESAttributes{
			KeySize: 256,
		},
	}

	ctx := context.Background()
	_, err = b.Seal(ctx, []byte("test data"), &types.SealOptions{
		KeyAttributes: attrs,
	})
	if !errors.Is(err, ErrNotInitialized) {
		t.Errorf("Seal() error = %v, want %v", err, ErrNotInitialized)
	}
}

// TestUnseal_NilSealedData tests Unseal fails with nil sealed data
func TestUnseal_NilSealedData(t *testing.T) {
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	config := &Config{
		Library:     tempLib,
		TokenLabel:  "test",
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
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	config := &Config{
		Library:     tempLib,
		TokenLabel:  "test",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() failed: %v", err)
	}

	sealed := &types.SealedData{
		Backend:    types.BackendTypeSoftware, // Wrong backend
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
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	config := &Config{
		Library:     tempLib,
		TokenLabel:  "test",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() failed: %v", err)
	}

	sealed := &types.SealedData{
		Backend:    types.BackendTypePKCS11,
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
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	config := &Config{
		Library:     tempLib,
		TokenLabel:  "test",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() failed: %v", err)
	}

	sealed := &types.SealedData{
		Backend:    types.BackendTypePKCS11,
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
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	config := &Config{
		Library:     tempLib,
		TokenLabel:  "test",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() failed: %v", err)
	}

	sealed := &types.SealedData{
		Backend:    types.BackendTypePKCS11,
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

// TestUnseal_NotInitialized tests Unseal fails when not initialized
func TestUnseal_NotInitialized(t *testing.T) {
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	config := &Config{
		Library:     tempLib,
		TokenLabel:  "test",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() failed: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:                 "test-unseal",
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		AESAttributes: &types.AESAttributes{
			KeySize: 256,
		},
	}

	sealed := &types.SealedData{
		Backend:    types.BackendTypePKCS11,
		Ciphertext: []byte("test"),
		Nonce:      make([]byte, 12),
		Tag:        make([]byte, 16),
		KeyID:      attrs.ID(),
	}

	ctx := context.Background()
	_, err = b.Unseal(ctx, sealed, &types.UnsealOptions{
		KeyAttributes: attrs,
	})
	if !errors.Is(err, ErrNotInitialized) {
		t.Errorf("Unseal() error = %v, want %v", err, ErrNotInitialized)
	}
}

// TestMarshalUnmarshalSealedData tests JSON serialization of SealedData
func TestMarshalUnmarshalSealedData(t *testing.T) {
	original := &types.SealedData{
		Backend:    types.BackendTypePKCS11,
		Ciphertext: []byte("encrypted data"),
		Nonce:      []byte("test-nonce-12"),
		Tag:        []byte("test-tag-16-byte"),
		KeyID:      "test-key-id",
		Metadata: map[string][]byte{
			"pkcs11:algorithm": []byte("AES-256-GCM"),
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
