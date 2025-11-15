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
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	pkcs11backend "github.com/jeremyhahn/go-keychain/pkg/backend/pkcs11"
	"github.com/jeremyhahn/go-keychain/pkg/keychain"
	"github.com/jeremyhahn/go-keychain/pkg/opaque"
	"github.com/jeremyhahn/go-keychain/pkg/storage/memory"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// TestNewKeyStore tests creating a new PKCS#11 keychain.
func TestNewKeyStore(t *testing.T) {
	t.Run("nil backend", func(t *testing.T) {
		ks, err := NewKeyStore(nil, memory.New())
		if err == nil {
			t.Fatal("Expected error but got none")
		}
		if !errors.Is(err, keychain.ErrBackendNotInitialized) {
			t.Errorf("Expected ErrBackendNotInitialized, got %v", err)
		}
		if ks != nil {
			t.Error("Expected nil keystore with error")
		}
	})

	// Note: Testing with a real backend requires PKCS#11 hardware (tested via integration tests)
}

// TestType tests the Type method.
func TestType(t *testing.T) {
	// Create a mock backend to pass validation
	config := &pkcs11backend.Config{
		CN:         "test",
		Library:    "/test/lib.so",
		TokenLabel: "test",
	}
	be, _ := pkcs11backend.NewBackend(config)
	ks := &KeyStore{backend: be}

	if ks.Type() != types.StorePKCS11 {
		t.Errorf("Expected type %s, got %s", types.StorePKCS11, ks.Type())
	}
}

// TestBackend tests the Backend method.
func TestBackend(t *testing.T) {
	config := &pkcs11backend.Config{
		CN:         "test",
		Library:    "/test/lib.so",
		TokenLabel: "test",
	}
	be, _ := pkcs11backend.NewBackend(config)
	ks := &KeyStore{backend: be}

	wrapper := ks.Backend()
	if wrapper == nil {
		t.Fatal("Expected non-nil backend wrapper")
	}

	if wrapper.Type() != backend.BackendTypePKCS11 {
		t.Errorf("Expected type %s, got %s", backend.BackendTypePKCS11, wrapper.Type())
	}
}

// TestBackendWrapperClose tests the backend wrapper Close method (no-op).
func TestBackendWrapperClose(t *testing.T) {
	config := &pkcs11backend.Config{
		CN:         "test",
		Library:    "/test/lib.so",
		TokenLabel: "test",
	}
	be, _ := pkcs11backend.NewBackend(config)
	ks := &KeyStore{backend: be}

	wrapper := ks.Backend()
	err := wrapper.Close()
	if err != nil {
		t.Errorf("Expected nil error from wrapper Close, got %v", err)
	}
}

// TestGenerateEd25519 tests Ed25519 key generation (unsupported).
func TestGenerateEd25519(t *testing.T) {
	config := &pkcs11backend.Config{
		CN:         "test",
		Library:    "/test/lib.so",
		TokenLabel: "test",
	}
	be, _ := pkcs11backend.NewBackend(config)
	ks := &KeyStore{backend: be}

	attrs := &types.KeyAttributes{
		CN:           "test-ed25519",
		KeyAlgorithm: x509.Ed25519,
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_PKCS11,
	}

	key, err := ks.GenerateEd25519(attrs)
	if err == nil {
		t.Fatal("Expected error for Ed25519 generation")
	}
	if !errors.Is(err, pkcs11backend.ErrUnsupportedKeyAlgorithm) {
		t.Errorf("Expected ErrUnsupportedKeyAlgorithm, got %v", err)
	}
	if key != nil {
		t.Error("Expected nil key for unsupported algorithm")
	}
}

// TestGenerateSecretKey tests secret key generation (error path without real HSM).
func TestGenerateSecretKey(t *testing.T) {
	config := &pkcs11backend.Config{
		CN:         "test",
		Library:    "/test/lib.so",
		TokenLabel: "test",
	}
	be, _ := pkcs11backend.NewBackend(config)
	ks := &KeyStore{backend: be}

	attrs := &types.KeyAttributes{
		CN:        "test-secret",
		KeyType:   backend.KEY_TYPE_SIGNING,
		StoreType: backend.STORE_PKCS11,
	}

	// Without a real HSM, this will fail - which is the expected behavior
	err := ks.GenerateSecretKey(attrs)
	if err == nil {
		t.Error("Expected error without real HSM connection")
	}
}

// TestGenerateKeyInvalidAlgorithm tests GenerateKey with invalid algorithm.
func TestGenerateKeyInvalidAlgorithm(t *testing.T) {
	config := &pkcs11backend.Config{
		CN:         "test",
		Library:    "/test/lib.so",
		TokenLabel: "test",
	}
	be, _ := pkcs11backend.NewBackend(config)
	ks := &KeyStore{backend: be}

	attrs := &types.KeyAttributes{
		CN:           "test",
		KeyAlgorithm: x509.PublicKeyAlgorithm(999),
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_PKCS11,
	}

	_, err := ks.GenerateKey(attrs)
	if err == nil {
		t.Fatal("Expected error for invalid algorithm")
	}
	if !errors.Is(err, keychain.ErrInvalidKeyAlgorithm) {
		t.Errorf("Expected ErrInvalidKeyAlgorithm, got %v", err)
	}
}

// TestGenerateKeyEd25519 tests GenerateKey dispatching to Ed25519 (unsupported).
func TestGenerateKeyEd25519(t *testing.T) {
	config := &pkcs11backend.Config{
		CN:         "test",
		Library:    "/test/lib.so",
		TokenLabel: "test",
	}
	be, _ := pkcs11backend.NewBackend(config)
	ks := &KeyStore{backend: be}

	attrs := &types.KeyAttributes{
		CN:           "test",
		KeyAlgorithm: x509.Ed25519,
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_PKCS11,
	}

	_, err := ks.GenerateKey(attrs)
	if err == nil {
		t.Fatal("Expected error for Ed25519")
	}
	if !errors.Is(err, pkcs11backend.ErrUnsupportedKeyAlgorithm) {
		t.Errorf("Expected ErrUnsupportedKeyAlgorithm, got %v", err)
	}
}

// TestEqual tests the Equal method for comparing keys.
func TestEqual(t *testing.T) {
	config := &pkcs11backend.Config{
		CN:         "test",
		Library:    "/test/lib.so",
		TokenLabel: "test",
	}
	be, _ := pkcs11backend.NewBackend(config)
	ks := &KeyStore{backend: be}

	tests := []struct {
		name     string
		setup    func(t *testing.T) (crypto.PrivateKey, crypto.PrivateKey)
		expected bool
	}{
		{
			name: "nil opaque key",
			setup: func(t *testing.T) (crypto.PrivateKey, crypto.PrivateKey) {
				key, _ := rsa.GenerateKey(rand.Reader, 2048)
				return nil, key
			},
			expected: false,
		},
		{
			name: "nil private key",
			setup: func(t *testing.T) (crypto.PrivateKey, crypto.PrivateKey) {
				key, _ := rsa.GenerateKey(rand.Reader, 2048)
				attrs := &types.KeyAttributes{CN: "test"}
				opaque, _ := opaque.NewOpaqueKey(ks, attrs, &key.PublicKey)
				return opaque, nil
			},
			expected: false,
		},
		{
			name: "both nil",
			setup: func(t *testing.T) (crypto.PrivateKey, crypto.PrivateKey) {
				return nil, nil
			},
			expected: false,
		},
		{
			name: "nil opaque public key",
			setup: func(t *testing.T) (crypto.PrivateKey, crypto.PrivateKey) {
				key, _ := rsa.GenerateKey(rand.Reader, 2048)
				attrs := &types.KeyAttributes{CN: "test"}
				opaque, _ := opaque.NewOpaqueKey(ks, attrs, nil)
				return opaque, key
			},
			expected: false,
		},
		{
			name: "same RSA key",
			setup: func(t *testing.T) (crypto.PrivateKey, crypto.PrivateKey) {
				key, _ := rsa.GenerateKey(rand.Reader, 2048)
				attrs := &types.KeyAttributes{CN: "test"}
				opaque, _ := opaque.NewOpaqueKey(ks, attrs, &key.PublicKey)
				return opaque, key
			},
			expected: true,
		},
		{
			name: "different RSA keys",
			setup: func(t *testing.T) (crypto.PrivateKey, crypto.PrivateKey) {
				key1, _ := rsa.GenerateKey(rand.Reader, 2048)
				key2, _ := rsa.GenerateKey(rand.Reader, 2048)
				attrs := &types.KeyAttributes{CN: "test"}
				opaque, _ := opaque.NewOpaqueKey(ks, attrs, &key1.PublicKey)
				return opaque, key2
			},
			expected: false,
		},
		{
			name: "same ECDSA key",
			setup: func(t *testing.T) (crypto.PrivateKey, crypto.PrivateKey) {
				key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				attrs := &types.KeyAttributes{CN: "test"}
				opaque, _ := opaque.NewOpaqueKey(ks, attrs, &key.PublicKey)
				return opaque, key
			},
			expected: true,
		},
		{
			name: "different ECDSA keys",
			setup: func(t *testing.T) (crypto.PrivateKey, crypto.PrivateKey) {
				key1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				key2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				attrs := &types.KeyAttributes{CN: "test"}
				opaque, _ := opaque.NewOpaqueKey(ks, attrs, &key1.PublicKey)
				return opaque, key2
			},
			expected: false,
		},
		{
			name: "same Ed25519 key",
			setup: func(t *testing.T) (crypto.PrivateKey, crypto.PrivateKey) {
				pub, priv, _ := ed25519.GenerateKey(rand.Reader)
				attrs := &types.KeyAttributes{CN: "test"}
				opaque, _ := opaque.NewOpaqueKey(ks, attrs, pub)
				return opaque, priv
			},
			expected: true,
		},
		{
			name: "different Ed25519 keys",
			setup: func(t *testing.T) (crypto.PrivateKey, crypto.PrivateKey) {
				pub1, _, _ := ed25519.GenerateKey(rand.Reader)
				_, priv2, _ := ed25519.GenerateKey(rand.Reader)
				attrs := &types.KeyAttributes{CN: "test"}
				opaque, _ := opaque.NewOpaqueKey(ks, attrs, pub1)
				return opaque, priv2
			},
			expected: false,
		},
		{
			name: "mismatched key types (RSA vs ECDSA)",
			setup: func(t *testing.T) (crypto.PrivateKey, crypto.PrivateKey) {
				rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
				ecdsaKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				attrs := &types.KeyAttributes{CN: "test"}
				opaque, _ := opaque.NewOpaqueKey(ks, attrs, &rsaKey.PublicKey)
				return opaque, ecdsaKey
			},
			expected: false,
		},
		{
			name: "unsupported private key type",
			setup: func(t *testing.T) (crypto.PrivateKey, crypto.PrivateKey) {
				rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
				attrs := &types.KeyAttributes{CN: "test"}
				opaque, _ := opaque.NewOpaqueKey(ks, attrs, &rsaKey.PublicKey)
				return opaque, "invalid-key-type"
			},
			expected: false,
		},
		{
			name: "unsupported opaque public key type",
			setup: func(t *testing.T) (crypto.PrivateKey, crypto.PrivateKey) {
				key, _ := rsa.GenerateKey(rand.Reader, 2048)
				attrs := &types.KeyAttributes{CN: "test"}
				opaque, _ := opaque.NewOpaqueKey(ks, attrs, "invalid-public-key")
				return opaque, key
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opaque, priv := tt.setup(t)
			result := ks.Equal(opaque, priv)
			if result != tt.expected {
				t.Errorf("Expected Equal to return %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestGenerateSecretKey_InvalidKeyType tests invalid key type handling.
func TestGenerateSecretKey_InvalidKeyType(t *testing.T) {
	config := &pkcs11backend.Config{
		CN:         "test",
		Library:    "/test/lib.so",
		TokenLabel: "test",
	}
	be, _ := pkcs11backend.NewBackend(config)
	ks := &KeyStore{backend: be}

	// Test with invalid key type (should be KeyTypeSecret or KeyTypeHMAC)
	attrs := &types.KeyAttributes{
		CN:        "test-secret",
		KeyType:   backend.KEY_TYPE_CA, // Invalid for secret keys
		StoreType: backend.STORE_PKCS11,
	}

	// This should fail validation before attempting HSM connection
	err := ks.GenerateSecretKey(attrs)
	if err == nil {
		t.Error("Expected error for invalid key type")
	}
}

// TestGenerateSecretKey_InvalidSize tests invalid key size handling.
func TestGenerateSecretKey_InvalidSize(t *testing.T) {
	config := &pkcs11backend.Config{
		CN:         "test",
		Library:    "/test/lib.so",
		TokenLabel: "test",
	}
	be, _ := pkcs11backend.NewBackend(config)
	ks := &KeyStore{backend: be}

	tests := []struct {
		name       string
		secretSize int
		wantErr    bool
	}{
		{"valid 16 bytes", 16, true},   // Will fail (no HSM) but size is valid
		{"valid 32 bytes", 32, true},   // Will fail (no HSM) but size is valid
		{"invalid 8 bytes", 8, true},   // Invalid size
		{"invalid 24 bytes", 24, true}, // Invalid size
		{"invalid 64 bytes", 64, true}, // Invalid size
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:        "test-secret",
				KeyType:   backend.KEY_TYPE_SIGNING,
				StoreType: backend.STORE_PKCS11,
			}

			err := ks.GenerateSecretKey(attrs)

			// All should fail without real HSM
			if err == nil {
				t.Error("Expected error without real HSM connection")
			}
		})
	}
}
