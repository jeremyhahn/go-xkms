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

package symmetric

import (
	"bytes"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestExportKeyMaterial_Success tests successful raw key export
func TestExportKeyMaterial_Success(t *testing.T) {
	s := storage.New()
	config := &Config{KeyStorage: s}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	symmetricBackend := b.(*Backend)

	attrs := &types.KeyAttributes{
		CN:                 "exportable-material-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		Exportable:         true,
	}

	// Generate key
	key, err := symmetricBackend.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("GenerateSymmetricKey failed: %v", err)
	}

	// Get original key bytes
	originalKey, err := key.Raw()
	if err != nil {
		t.Fatalf("Failed to get raw key: %v", err)
	}

	// Export key material
	exported, err := symmetricBackend.ExportKeyMaterial(attrs)
	if err != nil {
		t.Fatalf("ExportKeyMaterial failed: %v", err)
	}

	// Verify exported matches original
	if !bytes.Equal(exported, originalKey) {
		t.Error("Exported key material does not match original")
	}
}

// TestExportKeyMaterial_NilAttributes tests error for nil attributes
func TestExportKeyMaterial_NilAttributes(t *testing.T) {
	s := storage.New()
	config := &Config{KeyStorage: s}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	symmetricBackend := b.(*Backend)

	// Test with nil attributes
	_, err = symmetricBackend.ExportKeyMaterial(nil)
	if err == nil {
		t.Error("Expected error for nil attributes")
	}
	if !errors.Is(err, backend.ErrInvalidAttributes) {
		t.Errorf("Expected ErrInvalidAttributes, got: %v", err)
	}
}

// TestExportKeyMaterial_NonExportable tests error for non-exportable key
func TestExportKeyMaterial_NonExportable(t *testing.T) {
	s := storage.New()
	config := &Config{KeyStorage: s}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	symmetricBackend := b.(*Backend)

	attrs := &types.KeyAttributes{
		CN:                 "non-exportable-material-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		Exportable:         false, // NOT exportable
	}

	// Generate key
	_, err = symmetricBackend.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("GenerateSymmetricKey failed: %v", err)
	}

	// Try to export - should fail
	_, err = symmetricBackend.ExportKeyMaterial(attrs)
	if err == nil {
		t.Error("Expected error for non-exportable key")
	}
	if !errors.Is(err, backend.ErrKeyNotExportable) {
		t.Errorf("Expected ErrKeyNotExportable, got: %v", err)
	}
}

// TestExportKeyMaterial_AsymmetricAlgorithm tests error for asymmetric algorithm
func TestExportKeyMaterial_AsymmetricAlgorithm(t *testing.T) {
	s := storage.New()
	config := &Config{KeyStorage: s}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	symmetricBackend := b.(*Backend)

	// Create attributes with asymmetric algorithm
	attrs := &types.KeyAttributes{
		CN:           "asymmetric-material-key",
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.RSA,
		Exportable:   true,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
	}

	// Try to export - should fail
	_, err = symmetricBackend.ExportKeyMaterial(attrs)
	if err == nil {
		t.Error("Expected error for asymmetric algorithm")
	}
	if !errors.Is(err, backend.ErrAsymmetricKeyExportNotAllowed) {
		t.Errorf("Expected ErrAsymmetricKeyExportNotAllowed, got: %v", err)
	}
}

// TestExportKeyMaterial_ClosedBackend tests error for closed backend
func TestExportKeyMaterial_ClosedBackend(t *testing.T) {
	s := storage.New()
	config := &Config{KeyStorage: s}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}

	symmetricBackend := b.(*Backend)

	attrs := &types.KeyAttributes{
		CN:                 "closed-material-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		Exportable:         true,
	}

	// Generate key before closing
	_, err = symmetricBackend.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("GenerateSymmetricKey failed: %v", err)
	}

	// Close backend
	_ = symmetricBackend.Close()

	// Try to export - should fail
	_, err = symmetricBackend.ExportKeyMaterial(attrs)
	if err == nil {
		t.Error("Expected error for closed backend")
	}
	if !errors.Is(err, ErrStorageClosed) {
		t.Errorf("Expected ErrStorageClosed, got: %v", err)
	}
}

// TestExportKeyMaterial_KeyNotFound tests error for non-existent key
func TestExportKeyMaterial_KeyNotFound(t *testing.T) {
	s := storage.New()
	config := &Config{KeyStorage: s}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	symmetricBackend := b.(*Backend)

	attrs := &types.KeyAttributes{
		CN:                 "nonexistent-material-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		Exportable:         true,
	}

	// Try to export non-existent key
	_, err = symmetricBackend.ExportKeyMaterial(attrs)
	if err == nil {
		t.Error("Expected error for non-existent key")
	}
	if !errors.Is(err, backend.ErrKeyNotFound) {
		t.Errorf("Expected ErrKeyNotFound, got: %v", err)
	}
}

// TestExportKeyMaterial_WithPassword tests export with password-protected key
func TestExportKeyMaterial_WithPassword(t *testing.T) {
	s := storage.New()
	config := &Config{KeyStorage: s}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	symmetricBackend := b.(*Backend)

	password := backend.StaticPassword([]byte("export-material-password"))

	attrs := &types.KeyAttributes{
		CN:                 "password-material-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		Exportable:         true,
		Password:           password,
	}

	// Generate key
	key, err := symmetricBackend.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("GenerateSymmetricKey failed: %v", err)
	}

	originalKey, err := key.Raw()
	if err != nil {
		t.Fatalf("Failed to get raw key: %v", err)
	}

	// Export key material
	exported, err := symmetricBackend.ExportKeyMaterial(attrs)
	if err != nil {
		t.Fatalf("ExportKeyMaterial failed: %v", err)
	}

	// Verify exported matches original
	if !bytes.Equal(exported, originalKey) {
		t.Error("Exported key material does not match original")
	}
}

// TestExportKeyMaterial_InvalidAttributes tests error for invalid attributes
func TestExportKeyMaterial_InvalidAttributes(t *testing.T) {
	s := storage.New()
	config := &Config{KeyStorage: s}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	symmetricBackend := b.(*Backend)

	// Create attributes with empty CN (invalid)
	attrs := &types.KeyAttributes{
		CN:                 "", // Invalid - empty CN
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		Exportable:         true,
	}

	// Try to export - should fail validation
	_, err = symmetricBackend.ExportKeyMaterial(attrs)
	if err == nil {
		t.Error("Expected error for invalid attributes")
	}
}

// TestExportKeyMaterial_AllAlgorithms tests export for all symmetric algorithms
func TestExportKeyMaterial_AllAlgorithms(t *testing.T) {
	algorithms := []types.SymmetricAlgorithm{
		types.SymmetricAES128GCM,
		types.SymmetricAES192GCM,
		types.SymmetricAES256GCM,
		types.SymmetricChaCha20Poly1305,
		types.SymmetricXChaCha20Poly1305,
	}

	for _, alg := range algorithms {
		t.Run(string(alg), func(t *testing.T) {
			s := storage.New()
			config := &Config{KeyStorage: s}
			b, err := NewBackend(config)
			if err != nil {
				t.Fatalf("Failed to create backend: %v", err)
			}
			defer func() { _ = b.Close() }()

			symmetricBackend := b.(*Backend)

			attrs := &types.KeyAttributes{
				CN:                 "test-material-" + string(alg),
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_SW,
				SymmetricAlgorithm: alg,
				Exportable:         true,
			}

			// Generate key
			key, err := symmetricBackend.GenerateSymmetricKey(attrs)
			if err != nil {
				t.Fatalf("GenerateSymmetricKey failed: %v", err)
			}

			originalKey, err := key.Raw()
			if err != nil {
				t.Fatalf("Failed to get raw key: %v", err)
			}

			// Export key material
			exported, err := symmetricBackend.ExportKeyMaterial(attrs)
			if err != nil {
				t.Fatalf("ExportKeyMaterial failed: %v", err)
			}

			// Verify
			if !bytes.Equal(exported, originalKey) {
				t.Error("Exported key material does not match original")
			}
		})
	}
}

// TestExportKeyMaterial_WrongPassword tests export with wrong password
func TestExportKeyMaterial_WrongPassword(t *testing.T) {
	s := storage.New()
	config := &Config{KeyStorage: s}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	symmetricBackend := b.(*Backend)

	correctPassword := backend.StaticPassword([]byte("correct-password"))
	wrongPassword := backend.StaticPassword([]byte("wrong-password"))

	attrsGenerate := &types.KeyAttributes{
		CN:                 "wrong-password-material-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		Exportable:         true,
		Password:           correctPassword,
	}

	// Generate key with correct password
	_, err = symmetricBackend.GenerateSymmetricKey(attrsGenerate)
	if err != nil {
		t.Fatalf("GenerateSymmetricKey failed: %v", err)
	}

	// Try to export with wrong password
	attrsExport := &types.KeyAttributes{
		CN:                 "wrong-password-material-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		Exportable:         true,
		Password:           wrongPassword,
	}

	_, err = symmetricBackend.ExportKeyMaterial(attrsExport)
	if err == nil {
		t.Error("Expected error for wrong password")
	}
}

// TestGetTracker tests GetTracker returns the AEAD safety tracker
func TestGetTracker_ReturnsTracker(t *testing.T) {
	s := storage.New()
	config := &Config{KeyStorage: s}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	symmetricBackend := b.(*Backend)
	tracker := symmetricBackend.GetTracker()
	if tracker == nil {
		t.Error("Expected non-nil tracker")
	}
}

// TestGetRNG tests GetRNG returns the RNG resolver
func TestGetRNG_ReturnsRNG(t *testing.T) {
	s := storage.New()
	config := &Config{KeyStorage: s}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	symmetricBackend := b.(*Backend)
	rng := symmetricBackend.GetRNG()
	if rng == nil {
		t.Error("Expected non-nil RNG resolver")
	}
}
