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

//go:build integration
// +build integration

package pkcs8

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/backend/pkcs8"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// Helper function to create a test backend
func createTestBackend(t *testing.T) (*pkcs8.PKCS8Backend, storage.Backend) {
	t.Helper()

	keyStorage := storage.New()
	config := &pkcs8.Config{
		KeyStorage: keyStorage,
	}

	be, err := pkcs8.NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}

	return be.(*pkcs8.PKCS8Backend), keyStorage
}

// Helper function to create RSA attributes
func createRSAAttrs(cn string, keySize int) *types.KeyAttributes {
	return &types.KeyAttributes{
		CN:           cn,
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: keySize,
		},
		Hash: crypto.SHA256,
	}
}

// Helper function to create ECDSA attributes
func createECDSAAttrs(cn, curve string) *types.KeyAttributes {
	parsedCurve, _ := types.ParseCurve(curve)
	return &types.KeyAttributes{
		CN:           cn,
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: parsedCurve,
		},
		Hash: crypto.SHA256,
	}
}

// Helper function to create Ed25519 attributes
func createEd25519Attrs(cn string) *types.KeyAttributes {
	return &types.KeyAttributes{
		CN:           cn,
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.Ed25519,
	}
}

// TestGenerateRSAKey_MaximumSize tests RSA key generation with maximum valid key size
// func TestGenerateRSAKey_MaximumSize(t *testing.T) {
// 	be, _ := createTestBackend(t)
// 	defer be.Close()

// 	// Test with 8192 bit RSA key (maximum commonly supported)
// 	attrs := createRSAAttrs("test-rsa-max.com", 8192)

// 	key, err := be.GenerateKey(attrs)
// 	if err != nil {
// 		t.Fatalf("GenerateKey with 8192 bits failed: %v", err)
// 	}

// 	rsaKey, ok := key.(*rsa.PrivateKey)
// 	if !ok {
// 		t.Fatal("Generated key is not *rsa.PrivateKey")
// 	}

// 	if rsaKey.N.BitLen() != 8192 {
// 		t.Errorf("Expected key size 8192, got %d", rsaKey.N.BitLen())
// 	}
// }

// TestGenerateKey_AllCombinations tests various key generation combinations
func TestGenerateKey_AllCombinations(t *testing.T) {
	be, _ := createTestBackend(t)
	defer be.Close()

	// Test RSA with different sizes
	rsaSizes := []int{2048, 3072, 4096}
	for _, size := range rsaSizes {
		t.Run(fmt.Sprintf("RSA-%d", size), func(t *testing.T) {
			attrs := createRSAAttrs(fmt.Sprintf("test-combo-rsa-%d.com", size), size)
			key, err := be.GenerateKey(attrs)
			if err != nil {
				t.Fatalf("GenerateKey RSA-%d failed: %v", size, err)
			}
			if key == nil {
				t.Fatal("Generated key is nil")
			}
		})
	}

	// Test ECDSA with all curves
	curves := []string{"P-256", "P-384", "P-521"}
	for _, curve := range curves {
		t.Run(fmt.Sprintf("ECDSA-%s", curve), func(t *testing.T) {
			attrs := createECDSAAttrs(fmt.Sprintf("test-combo-%s.com", curve), curve)
			key, err := be.GenerateKey(attrs)
			if err != nil {
				t.Fatalf("GenerateKey ECDSA-%s failed: %v", curve, err)
			}
			if key == nil {
				t.Fatal("Generated key is nil")
			}
		})
	}

	// Test Ed25519
	t.Run("Ed25519", func(t *testing.T) {
		attrs := createEd25519Attrs("test-combo-ed25519.com")
		key, err := be.GenerateKey(attrs)
		if err != nil {
			t.Fatalf("GenerateKey Ed25519 failed: %v", err)
		}
		if key == nil {
			t.Fatal("Generated key is nil")
		}
	})
}

// TestGenerateKey_CommonRSA tests RSA generation for common key sizes
func TestGenerateKey_CommonRSA(t *testing.T) {
	be, _ := createTestBackend(t)
	defer be.Close()

	// Test multiple key sizes to ensure generateRSAKey is well-tested
	sizes := []int{2048, 3072, 4096}

	for _, size := range sizes {
		t.Run(fmt.Sprintf("Size%d", size), func(t *testing.T) {
			attrs := createRSAAttrs(fmt.Sprintf("test-common-rsa-%d.com", size), size)

			key, err := be.GenerateKey(attrs)
			if err != nil {
				t.Fatalf("GenerateKey RSA-%d failed: %v", size, err)
			}

			rsaKey, ok := key.(*rsa.PrivateKey)
			if !ok {
				t.Fatal("Generated key is not *rsa.PrivateKey")
			}

			// Verify the key can be used
			if rsaKey.N.BitLen() < 2048 {
				t.Errorf("Key size too small: %d", rsaKey.N.BitLen())
			}

			// Verify key is stored
			retrieved, err := be.GetKey(attrs)
			if err != nil {
				t.Fatalf("GetKey failed: %v", err)
			}

			retrievedRSA := retrieved.(*rsa.PrivateKey)
			if retrievedRSA.N.Cmp(rsaKey.N) != 0 {
				t.Error("Retrieved key doesn't match")
			}
		})
	}
}
