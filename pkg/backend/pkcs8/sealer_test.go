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

package pkcs8

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

// TestCanSeal verifies that CanSeal returns true for PKCS#8 backend
func TestCanSeal(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	if !be.CanSeal() {
		t.Error("CanSeal should return true for PKCS#8 backend")
	}
}

// TestCanSealAfterClose verifies that CanSeal returns false after Close
func TestCanSealAfterClose(t *testing.T) {
	keyStorage := storage.New()
	config := &Config{
		KeyStorage: keyStorage,
	}

	be, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}

	pkcs8Backend := be.(*PKCS8Backend)
	_ = pkcs8Backend.Close()

	if pkcs8Backend.CanSeal() {
		t.Error("CanSeal should return false after Close")
	}
}

// TestSealUnsealRSA tests seal/unseal with RSA keys
func TestSealUnsealRSA(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

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

	_, err := be.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Test data to seal
	plaintext := []byte("test secret data for RSA seal/unseal")

	// Seal the data
	ctx := context.Background()
	sealed, err := be.Seal(ctx, plaintext, &types.SealOptions{
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
	if sealed.KeyID != attrs.ID() {
		t.Errorf("Expected KeyID %s, got %s", attrs.ID(), sealed.KeyID)
	}

	// Unseal the data
	unsealed, err := be.Unseal(ctx, sealed, &types.UnsealOptions{
		KeyAttributes: attrs,
	})
	if err != nil {
		t.Fatalf("Unseal failed: %v", err)
	}

	if !bytes.Equal(plaintext, unsealed) {
		t.Errorf("Unsealed data does not match original: got %q, want %q", unsealed, plaintext)
	}
}

// TestSealUnsealECDSA tests seal/unseal with ECDSA keys
func TestSealUnsealECDSA(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

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

	_, err := be.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	plaintext := []byte("test secret data for ECDSA seal/unseal")

	ctx := context.Background()
	sealed, err := be.Seal(ctx, plaintext, &types.SealOptions{
		KeyAttributes: attrs,
	})
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}

	unsealed, err := be.Unseal(ctx, sealed, &types.UnsealOptions{
		KeyAttributes: attrs,
	})
	if err != nil {
		t.Fatalf("Unseal failed: %v", err)
	}

	if !bytes.Equal(plaintext, unsealed) {
		t.Errorf("Unsealed data does not match original")
	}
}

// TestSealUnsealEd25519 tests seal/unseal with Ed25519 keys
func TestSealUnsealEd25519(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "test-seal-ed25519",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.Ed25519,
	}

	_, err := be.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}

	plaintext := []byte("test secret data for Ed25519 seal/unseal")

	ctx := context.Background()
	sealed, err := be.Seal(ctx, plaintext, &types.SealOptions{
		KeyAttributes: attrs,
	})
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}

	unsealed, err := be.Unseal(ctx, sealed, &types.UnsealOptions{
		KeyAttributes: attrs,
	})
	if err != nil {
		t.Fatalf("Unseal failed: %v", err)
	}

	if !bytes.Equal(plaintext, unsealed) {
		t.Errorf("Unsealed data does not match original")
	}
}

// TestSealUnsealWithAAD tests seal/unseal with Additional Authenticated Data
func TestSealUnsealWithAAD(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

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

	_, err := be.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	plaintext := []byte("test secret data with AAD")
	aad := []byte("additional authenticated data")

	ctx := context.Background()
	sealed, err := be.Seal(ctx, plaintext, &types.SealOptions{
		KeyAttributes: attrs,
		AAD:           aad,
	})
	if err != nil {
		t.Fatalf("Seal with AAD failed: %v", err)
	}

	// Verify AAD hash was stored
	if _, ok := sealed.Metadata["pkcs8:aad_hash"]; !ok {
		t.Error("AAD hash should be stored in metadata")
	}

	// Unseal with correct AAD
	unsealed, err := be.Unseal(ctx, sealed, &types.UnsealOptions{
		KeyAttributes: attrs,
		AAD:           aad,
	})
	if err != nil {
		t.Fatalf("Unseal with AAD failed: %v", err)
	}

	if !bytes.Equal(plaintext, unsealed) {
		t.Errorf("Unsealed data does not match original")
	}

	// Unseal with wrong AAD should fail
	_, err = be.Unseal(ctx, sealed, &types.UnsealOptions{
		KeyAttributes: attrs,
		AAD:           []byte("wrong aad"),
	})
	if err == nil {
		t.Error("Unseal with wrong AAD should fail")
	}

	// Unseal without AAD should fail (if original had AAD)
	_, err = be.Unseal(ctx, sealed, &types.UnsealOptions{
		KeyAttributes: attrs,
	})
	if err == nil {
		t.Error("Unseal without AAD should fail when original had AAD")
	}
}

// TestSealNilOptions tests that Seal fails with nil options
func TestSealNilOptions(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	ctx := context.Background()
	_, err := be.Seal(ctx, []byte("test"), nil)
	if err == nil {
		t.Error("Seal should fail with nil options")
	}
}

// TestSealNilKeyAttributes tests that Seal fails with nil KeyAttributes
func TestSealNilKeyAttributes(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	ctx := context.Background()
	_, err := be.Seal(ctx, []byte("test"), &types.SealOptions{
		KeyAttributes: nil,
	})
	if err == nil {
		t.Error("Seal should fail with nil KeyAttributes")
	}
}

// TestSealNonExistentKey tests that Seal fails with non-existent key
func TestSealNonExistentKey(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "non-existent-key",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.RSA,
	}

	ctx := context.Background()
	_, err := be.Seal(ctx, []byte("test"), &types.SealOptions{
		KeyAttributes: attrs,
	})
	if err == nil {
		t.Error("Seal should fail with non-existent key")
	}
}

// TestUnsealNilSealedData tests that Unseal fails with nil sealed data
func TestUnsealNilSealedData(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	ctx := context.Background()
	_, err := be.Unseal(ctx, nil, &types.UnsealOptions{
		KeyAttributes: &types.KeyAttributes{},
	})
	if err == nil {
		t.Error("Unseal should fail with nil sealed data")
	}
}

// TestUnsealWrongBackend tests that Unseal fails with wrong backend type
func TestUnsealWrongBackend(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "test-wrong-backend",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
	}

	_, err := be.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	sealed := &types.SealedData{
		Backend:    types.BackendTypeTPM2, // Wrong backend
		Ciphertext: []byte("test"),
		Nonce:      []byte("test-nonce"),
		KeyID:      attrs.ID(),
	}

	ctx := context.Background()
	_, err = be.Unseal(ctx, sealed, &types.UnsealOptions{
		KeyAttributes: attrs,
	})
	if err == nil {
		t.Error("Unseal should fail with wrong backend type")
	}
}

// TestUnsealKeyMismatch tests that Unseal fails with mismatched key ID
func TestUnsealKeyMismatch(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	// Create two keys
	attrs1 := &types.KeyAttributes{
		CN:           "test-key1",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
		Hash: crypto.SHA256,
	}

	attrs2 := &types.KeyAttributes{
		CN:           "test-key2",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
		Hash: crypto.SHA256,
	}

	_, err := be.GenerateKey(attrs1)
	if err != nil {
		t.Fatalf("Failed to generate key1: %v", err)
	}

	_, err = be.GenerateKey(attrs2)
	if err != nil {
		t.Fatalf("Failed to generate key2: %v", err)
	}

	// Seal with key1
	ctx := context.Background()
	sealed, err := be.Seal(ctx, []byte("test"), &types.SealOptions{
		KeyAttributes: attrs1,
	})
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}

	// Try to unseal with key2 - should fail due to key ID mismatch
	_, err = be.Unseal(ctx, sealed, &types.UnsealOptions{
		KeyAttributes: attrs2,
	})
	if err == nil {
		t.Error("Unseal should fail with different key")
	}
}

// TestSealUnsealAfterClose tests that Seal/Unseal fail after Close
func TestSealUnsealAfterClose(t *testing.T) {
	keyStorage := storage.New()
	config := &Config{
		KeyStorage: keyStorage,
	}

	be, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}

	pkcs8Backend := be.(*PKCS8Backend)

	// Generate a key before closing
	attrs := &types.KeyAttributes{
		CN:           "test-close",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
	}

	_, err = pkcs8Backend.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Close the backend
	_ = pkcs8Backend.Close()

	ctx := context.Background()

	// Seal should fail
	_, err = pkcs8Backend.Seal(ctx, []byte("test"), &types.SealOptions{
		KeyAttributes: attrs,
	})
	if err == nil {
		t.Error("Seal should fail after Close")
	}

	// Unseal should fail
	_, err = pkcs8Backend.Unseal(ctx, &types.SealedData{
		Backend:    types.BackendTypeSoftware,
		Ciphertext: []byte("test"),
		Nonce:      make([]byte, 12),
		KeyID:      attrs.ID(),
	}, &types.UnsealOptions{
		KeyAttributes: attrs,
	})
	if err == nil {
		t.Error("Unseal should fail after Close")
	}
}

// TestSealUnsealEmptyData tests seal/unseal with empty data
func TestSealUnsealEmptyData(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "test-empty-data",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
		Hash: crypto.SHA256,
	}

	_, err := be.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Empty data should still work
	plaintext := []byte{}

	ctx := context.Background()
	sealed, err := be.Seal(ctx, plaintext, &types.SealOptions{
		KeyAttributes: attrs,
	})
	if err != nil {
		t.Fatalf("Seal of empty data failed: %v", err)
	}

	unsealed, err := be.Unseal(ctx, sealed, &types.UnsealOptions{
		KeyAttributes: attrs,
	})
	if err != nil {
		t.Fatalf("Unseal of empty data failed: %v", err)
	}

	if !bytes.Equal(plaintext, unsealed) {
		t.Errorf("Unsealed data does not match original empty data")
	}
}

// TestSealUnsealLargeData tests seal/unseal with large data
func TestSealUnsealLargeData(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "test-large-data",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
		Hash: crypto.SHA256,
	}

	_, err := be.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Large data (1MB)
	plaintext := make([]byte, 1<<20)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}

	ctx := context.Background()
	sealed, err := be.Seal(ctx, plaintext, &types.SealOptions{
		KeyAttributes: attrs,
	})
	if err != nil {
		t.Fatalf("Seal of large data failed: %v", err)
	}

	unsealed, err := be.Unseal(ctx, sealed, &types.UnsealOptions{
		KeyAttributes: attrs,
	})
	if err != nil {
		t.Fatalf("Unseal of large data failed: %v", err)
	}

	if !bytes.Equal(plaintext, unsealed) {
		t.Errorf("Unsealed data does not match original large data")
	}
}

// TestMarshalUnmarshalSealedData tests JSON serialization of SealedData
func TestMarshalUnmarshalSealedData(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "test-marshal",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
		Hash: crypto.SHA256,
	}

	_, err := be.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	plaintext := []byte("test data for marshaling")

	ctx := context.Background()
	sealed, err := be.Seal(ctx, plaintext, &types.SealOptions{
		KeyAttributes: attrs,
	})
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}

	// Marshal
	data, err := MarshalSealedData(sealed)
	if err != nil {
		t.Fatalf("MarshalSealedData failed: %v", err)
	}

	// Unmarshal
	restored, err := UnmarshalSealedData(data)
	if err != nil {
		t.Fatalf("UnmarshalSealedData failed: %v", err)
	}

	// Verify restored data
	if restored.Backend != sealed.Backend {
		t.Errorf("Backend mismatch: got %s, want %s", restored.Backend, sealed.Backend)
	}
	if !bytes.Equal(restored.Ciphertext, sealed.Ciphertext) {
		t.Error("Ciphertext mismatch")
	}
	if !bytes.Equal(restored.Nonce, sealed.Nonce) {
		t.Error("Nonce mismatch")
	}
	if restored.KeyID != sealed.KeyID {
		t.Errorf("KeyID mismatch: got %s, want %s", restored.KeyID, sealed.KeyID)
	}

	// Unseal from restored data
	unsealed, err := be.Unseal(ctx, restored, &types.UnsealOptions{
		KeyAttributes: attrs,
	})
	if err != nil {
		t.Fatalf("Unseal from restored data failed: %v", err)
	}

	if !bytes.Equal(plaintext, unsealed) {
		t.Errorf("Unsealed data does not match original")
	}
}

// TestDeriveSealingKeyDifferentKeyTypes verifies key derivation works for all key types
func TestDeriveSealingKeyDifferentKeyTypes(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	testCases := []struct {
		name  string
		attrs *types.KeyAttributes
	}{
		{
			name: "RSA-2048",
			attrs: &types.KeyAttributes{
				CN:           "derive-rsa",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_SW,
				KeyAlgorithm: x509.RSA,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 2048,
				},
				Hash: crypto.SHA256,
			},
		},
		{
			name: "ECDSA-P256",
			attrs: func() *types.KeyAttributes {
				curve, _ := types.ParseCurve("P-256")
				return &types.KeyAttributes{
					CN:           "derive-ecdsa-p256",
					KeyType:      backend.KEY_TYPE_TLS,
					StoreType:    backend.STORE_SW,
					KeyAlgorithm: x509.ECDSA,
					ECCAttributes: &types.ECCAttributes{
						Curve: curve,
					},
					Hash: crypto.SHA256,
				}
			}(),
		},
		{
			name: "ECDSA-P384",
			attrs: func() *types.KeyAttributes {
				curve, _ := types.ParseCurve("P-384")
				return &types.KeyAttributes{
					CN:           "derive-ecdsa-p384",
					KeyType:      backend.KEY_TYPE_TLS,
					StoreType:    backend.STORE_SW,
					KeyAlgorithm: x509.ECDSA,
					ECCAttributes: &types.ECCAttributes{
						Curve: curve,
					},
					Hash: crypto.SHA384,
				}
			}(),
		},
		{
			name: "Ed25519",
			attrs: &types.KeyAttributes{
				CN:           "derive-ed25519",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_SW,
				KeyAlgorithm: x509.Ed25519,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := be.GenerateKey(tc.attrs)
			if err != nil {
				t.Fatalf("Failed to generate key: %v", err)
			}

			plaintext := []byte("test data for " + tc.name)

			ctx := context.Background()
			sealed, err := be.Seal(ctx, plaintext, &types.SealOptions{
				KeyAttributes: tc.attrs,
			})
			if err != nil {
				t.Fatalf("Seal failed for %s: %v", tc.name, err)
			}

			unsealed, err := be.Unseal(ctx, sealed, &types.UnsealOptions{
				KeyAttributes: tc.attrs,
			})
			if err != nil {
				t.Fatalf("Unseal failed for %s: %v", tc.name, err)
			}

			if !bytes.Equal(plaintext, unsealed) {
				t.Errorf("Data mismatch for %s", tc.name)
			}
		})
	}
}
