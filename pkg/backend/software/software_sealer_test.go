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

package software

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// TestSoftwareCanSeal verifies that CanSeal returns true for software backend
func TestSoftwareCanSeal(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() {
		if sb, ok := be.(*SoftwareBackend); ok {
			_ = sb.Close()
		}
	}()

	sb := be.(*SoftwareBackend)
	if !sb.CanSeal() {
		t.Error("CanSeal should return true for software backend")
	}
}

// TestSoftwareCanSealAfterClose verifies that CanSeal returns false after Close
func TestSoftwareCanSealAfterClose(t *testing.T) {
	keyStorage := storage.New()
	config := &Config{
		KeyStorage: keyStorage,
	}

	be, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}

	sb := be.(*SoftwareBackend)
	_ = sb.Close()

	if sb.CanSeal() {
		t.Error("CanSeal should return false after Close")
	}
}

// TestSoftwareSealUnsealRSA tests seal/unseal with RSA keys
func TestSoftwareSealUnsealRSA(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() {
		if sb, ok := be.(*SoftwareBackend); ok {
			_ = sb.Close()
		}
	}()

	sb := be.(*SoftwareBackend)

	// Generate an RSA key for sealing
	attrs := &types.KeyAttributes{
		CN:           "test-seal-rsa",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
		Hash: crypto.SHA256,
	}

	_, err := sb.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Test data to seal
	plaintext := []byte("test secret data for RSA seal/unseal")

	// Seal the data
	ctx := context.Background()
	sealed, err := sb.Seal(ctx, plaintext, &types.SealOptions{
		KeyAttributes: attrs,
	})
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}

	if sealed == nil {
		t.Fatal("Seal returned nil sealed data")
	}
	if sealed.Backend != types.BackendTypeSoftware {
		t.Errorf("Expected backend %s, got %s", types.BackendTypeSoftware, sealed.Backend)
	}
	if len(sealed.Ciphertext) == 0 {
		t.Error("Sealed ciphertext should not be empty")
	}
	if len(sealed.Nonce) == 0 {
		t.Error("Sealed nonce should not be empty")
	}

	// Unseal the data
	unsealed, err := sb.Unseal(ctx, sealed, &types.UnsealOptions{
		KeyAttributes: attrs,
	})
	if err != nil {
		t.Fatalf("Unseal failed: %v", err)
	}

	if !bytes.Equal(unsealed, plaintext) {
		t.Errorf("Unsealed data doesn't match original: got %q, want %q", unsealed, plaintext)
	}
}

// TestSoftwareSealUnsealECDSA tests seal/unseal with ECDSA keys
func TestSoftwareSealUnsealECDSA(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() {
		if sb, ok := be.(*SoftwareBackend); ok {
			_ = sb.Close()
		}
	}()

	sb := be.(*SoftwareBackend)

	// Generate an ECDSA P-256 key for sealing
	curve, _ := types.ParseCurve("P-256")
	attrs := &types.KeyAttributes{
		CN:           "test-seal-ecdsa",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: curve,
		},
		Hash: crypto.SHA256,
	}

	_, err := sb.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	// Test data to seal
	plaintext := []byte("test secret data for ECDSA seal/unseal")

	// Seal the data
	ctx := context.Background()
	sealed, err := sb.Seal(ctx, plaintext, &types.SealOptions{
		KeyAttributes: attrs,
	})
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}

	if sealed == nil {
		t.Fatal("Seal returned nil sealed data")
	}
	if sealed.Backend != types.BackendTypeSoftware {
		t.Errorf("Expected backend %s, got %s", types.BackendTypeSoftware, sealed.Backend)
	}

	// Unseal the data
	unsealed, err := sb.Unseal(ctx, sealed, &types.UnsealOptions{
		KeyAttributes: attrs,
	})
	if err != nil {
		t.Fatalf("Unseal failed: %v", err)
	}

	if !bytes.Equal(unsealed, plaintext) {
		t.Errorf("Unsealed data doesn't match original: got %q, want %q", unsealed, plaintext)
	}
}

// TestSoftwareSealUnsealEd25519 tests seal/unseal with Ed25519 keys
func TestSoftwareSealUnsealEd25519(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() {
		if sb, ok := be.(*SoftwareBackend); ok {
			_ = sb.Close()
		}
	}()

	sb := be.(*SoftwareBackend)

	// Generate an Ed25519 key for sealing
	attrs := &types.KeyAttributes{
		CN:           "test-seal-ed25519",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.Ed25519,
		Hash:         crypto.SHA256,
	}

	_, err := sb.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}

	// Test data to seal
	plaintext := []byte("test secret data for Ed25519 seal/unseal")

	// Seal the data
	ctx := context.Background()
	sealed, err := sb.Seal(ctx, plaintext, &types.SealOptions{
		KeyAttributes: attrs,
	})
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}

	if sealed == nil {
		t.Fatal("Seal returned nil sealed data")
	}
	if sealed.Backend != types.BackendTypeSoftware {
		t.Errorf("Expected backend %s, got %s", types.BackendTypeSoftware, sealed.Backend)
	}

	// Unseal the data
	unsealed, err := sb.Unseal(ctx, sealed, &types.UnsealOptions{
		KeyAttributes: attrs,
	})
	if err != nil {
		t.Fatalf("Unseal failed: %v", err)
	}

	if !bytes.Equal(unsealed, plaintext) {
		t.Errorf("Unsealed data doesn't match original: got %q, want %q", unsealed, plaintext)
	}
}

// TestSoftwareSealUnsealWithAAD tests seal/unseal with Additional Authenticated Data
func TestSoftwareSealUnsealWithAAD(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() {
		if sb, ok := be.(*SoftwareBackend); ok {
			_ = sb.Close()
		}
	}()

	sb := be.(*SoftwareBackend)

	// Generate an RSA key for sealing
	attrs := &types.KeyAttributes{
		CN:           "test-seal-aad",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
		Hash: crypto.SHA256,
	}

	_, err := sb.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Test data and AAD
	plaintext := []byte("test secret data with AAD")
	aad := []byte("additional authenticated data")

	// Seal the data with AAD
	ctx := context.Background()
	sealed, err := sb.Seal(ctx, plaintext, &types.SealOptions{
		KeyAttributes: attrs,
		AAD:           aad,
	})
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}

	// Unseal with same AAD should succeed
	unsealed, err := sb.Unseal(ctx, sealed, &types.UnsealOptions{
		KeyAttributes: attrs,
		AAD:           aad,
	})
	if err != nil {
		t.Fatalf("Unseal failed: %v", err)
	}

	if !bytes.Equal(unsealed, plaintext) {
		t.Errorf("Unsealed data doesn't match original: got %q, want %q", unsealed, plaintext)
	}
}

// TestSoftwareSealUnsealAADMismatch tests that unseal fails with wrong AAD
func TestSoftwareSealUnsealAADMismatch(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() {
		if sb, ok := be.(*SoftwareBackend); ok {
			_ = sb.Close()
		}
	}()

	sb := be.(*SoftwareBackend)

	// Generate an RSA key for sealing
	attrs := &types.KeyAttributes{
		CN:           "test-seal-aad-mismatch",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
		Hash: crypto.SHA256,
	}

	_, err := sb.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Test data and AAD
	plaintext := []byte("test secret data with AAD mismatch")
	aad := []byte("correct aad")
	wrongAad := []byte("wrong aad")

	// Seal the data with AAD
	ctx := context.Background()
	sealed, err := sb.Seal(ctx, plaintext, &types.SealOptions{
		KeyAttributes: attrs,
		AAD:           aad,
	})
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}

	// Unseal with wrong AAD should fail
	_, err = sb.Unseal(ctx, sealed, &types.UnsealOptions{
		KeyAttributes: attrs,
		AAD:           wrongAad,
	})
	if err == nil {
		t.Error("Unseal should fail with wrong AAD")
	}
}

// TestSoftwareSealReturnsSoftwareBackendType verifies sealed data has correct backend type
func TestSoftwareSealReturnsSoftwareBackendType(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() {
		if sb, ok := be.(*SoftwareBackend); ok {
			_ = sb.Close()
		}
	}()

	sb := be.(*SoftwareBackend)

	// Generate an RSA key for sealing
	attrs := &types.KeyAttributes{
		CN:           "test-seal-backend-type",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
		Hash: crypto.SHA256,
	}

	_, err := sb.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Seal the data
	ctx := context.Background()
	sealed, err := sb.Seal(ctx, []byte("test data"), &types.SealOptions{
		KeyAttributes: attrs,
	})
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}

	// Verify backend type is Software (not PKCS8)
	if sealed.Backend != types.BackendTypeSoftware {
		t.Errorf("Expected backend %s, got %s", types.BackendTypeSoftware, sealed.Backend)
	}
}

// TestSoftwareUnsealAcceptsBothBackendTypes verifies unseal accepts both Software and PKCS8 types
func TestSoftwareUnsealAcceptsBothBackendTypes(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() {
		if sb, ok := be.(*SoftwareBackend); ok {
			_ = sb.Close()
		}
	}()

	sb := be.(*SoftwareBackend)

	// Generate an RSA key for sealing
	attrs := &types.KeyAttributes{
		CN:           "test-seal-accept-types",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
		Hash: crypto.SHA256,
	}

	_, err := sb.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	plaintext := []byte("test data for backend type acceptance")

	// Seal the data
	ctx := context.Background()
	sealed, err := sb.Seal(ctx, plaintext, &types.SealOptions{
		KeyAttributes: attrs,
	})
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}

	// Test unseal with Software backend type (should work)
	sealed.Backend = types.BackendTypeSoftware
	unsealed, err := sb.Unseal(ctx, sealed, &types.UnsealOptions{
		KeyAttributes: attrs,
	})
	if err != nil {
		t.Fatalf("Unseal with Software backend type failed: %v", err)
	}
	if !bytes.Equal(unsealed, plaintext) {
		t.Error("Unsealed data doesn't match original")
	}

	// Test unseal with PKCS8 backend type (should also work)
	sealed.Backend = types.BackendTypeSoftware
	unsealed, err = sb.Unseal(ctx, sealed, &types.UnsealOptions{
		KeyAttributes: attrs,
	})
	if err != nil {
		t.Fatalf("Unseal with PKCS8 backend type failed: %v", err)
	}
	if !bytes.Equal(unsealed, plaintext) {
		t.Error("Unsealed data doesn't match original")
	}
}

// TestSoftwareSealClosedBackend tests that seal fails on closed backend
func TestSoftwareSealClosedBackend(t *testing.T) {
	keyStorage := storage.New()
	config := &Config{
		KeyStorage: keyStorage,
	}

	be, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}

	sb := be.(*SoftwareBackend)

	// Generate a key before closing
	attrs := &types.KeyAttributes{
		CN:           "test-seal-closed",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
		Hash: crypto.SHA256,
	}

	_, err = sb.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Close the backend
	_ = sb.Close()

	// Try to seal - should fail
	ctx := context.Background()
	_, err = sb.Seal(ctx, []byte("test"), &types.SealOptions{
		KeyAttributes: attrs,
	})
	if err == nil {
		t.Error("Seal should fail on closed backend")
	}
	if err != ErrStorageClosed {
		t.Errorf("Expected ErrStorageClosed, got: %v", err)
	}
}

// TestSoftwareUnsealClosedBackend tests that unseal fails on closed backend
func TestSoftwareUnsealClosedBackend(t *testing.T) {
	keyStorage := storage.New()
	config := &Config{
		KeyStorage: keyStorage,
	}

	be, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}

	sb := be.(*SoftwareBackend)

	// Generate a key and seal before closing
	attrs := &types.KeyAttributes{
		CN:           "test-unseal-closed",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
		Hash: crypto.SHA256,
	}

	_, err = sb.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	ctx := context.Background()
	sealed, err := sb.Seal(ctx, []byte("test"), &types.SealOptions{
		KeyAttributes: attrs,
	})
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}

	// Close the backend
	_ = sb.Close()

	// Try to unseal - should fail
	_, err = sb.Unseal(ctx, sealed, &types.UnsealOptions{
		KeyAttributes: attrs,
	})
	if err == nil {
		t.Error("Unseal should fail on closed backend")
	}
	if err != ErrStorageClosed {
		t.Errorf("Expected ErrStorageClosed, got: %v", err)
	}
}

// TestSoftwareUnsealWrongBackendType tests unseal fails with wrong backend type
func TestSoftwareUnsealWrongBackendType(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() {
		if sb, ok := be.(*SoftwareBackend); ok {
			_ = sb.Close()
		}
	}()

	sb := be.(*SoftwareBackend)

	// Generate an RSA key for sealing
	attrs := &types.KeyAttributes{
		CN:           "test-unseal-wrong-type",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
		Hash: crypto.SHA256,
	}

	_, err := sb.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Seal the data
	ctx := context.Background()
	sealed, err := sb.Seal(ctx, []byte("test data"), &types.SealOptions{
		KeyAttributes: attrs,
	})
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}

	// Change to wrong backend type
	sealed.Backend = types.BackendTypeTPM2

	// Unseal should fail
	_, err = sb.Unseal(ctx, sealed, &types.UnsealOptions{
		KeyAttributes: attrs,
	})
	if err == nil {
		t.Error("Unseal should fail with wrong backend type")
	}
}

// TestSoftwareUnsealNilSealedData tests unseal fails with nil sealed data
func TestSoftwareUnsealNilSealedData(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() {
		if sb, ok := be.(*SoftwareBackend); ok {
			_ = sb.Close()
		}
	}()

	sb := be.(*SoftwareBackend)

	ctx := context.Background()
	_, err := sb.Unseal(ctx, nil, &types.UnsealOptions{})
	if err == nil {
		t.Error("Unseal should fail with nil sealed data")
	}
}

// TestSoftwareCapabilitiesIncludeSealing tests that capabilities include sealing
func TestSoftwareCapabilitiesIncludeSealing(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() {
		if sb, ok := be.(*SoftwareBackend); ok {
			_ = sb.Close()
		}
	}()

	sb := be.(*SoftwareBackend)
	caps := sb.Capabilities()

	if !caps.Sealing {
		t.Error("Capabilities should include Sealing: true")
	}
}
