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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	azurekvbackend "github.com/jeremyhahn/go-keychain/pkg/backend/azurekv"
	"github.com/jeremyhahn/go-keychain/pkg/keychain"
	"github.com/jeremyhahn/go-keychain/pkg/opaque"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// Helper function to create a test backend with mock client
func newTestBackend(t *testing.T) *azurekvbackend.Backend {
	config := &azurekvbackend.Config{
		VaultURL:    "https://test-vault.vault.azure.net",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}

	mockClient := azurekvbackend.NewMockKeyVaultClient()
	backend, err := azurekvbackend.NewBackendWithClient(config, mockClient)
	if err != nil {
		t.Fatalf("Failed to create test backend: %v", err)
	}

	return backend
}

func TestNewKeyStore(t *testing.T) {
	t.Run("ValidBackend", func(t *testing.T) {
		be := newTestBackend(t)
		defer func() { _ = be.Close() }()

		ks, err := NewKeyStore(be, storage.NewCertAdapter(storage.New()))
		if err != nil {
			t.Fatalf("NewKeyStore failed: %v", err)
		}
		if ks == nil {
			t.Fatal("NewKeyStore returned nil keystore")
		}

		// Verify keystore can be closed
		if err := ks.Close(); err != nil {
			t.Errorf("Close failed: %v", err)
		}
	})

	t.Run("NilBackend", func(t *testing.T) {
		_, err := NewKeyStore(nil, storage.NewCertAdapter(storage.New()))
		if err == nil {
			t.Fatal("Expected error for nil backend")
		}
		if !errors.Is(err, keychain.ErrBackendNotInitialized) {
			t.Errorf("Expected ErrBackendNotInitialized, got: %v", err)
		}
	})
}

func TestKeyStore_Backend(t *testing.T) {
	be := newTestBackend(t)
	defer func() { _ = be.Close() }()

	ks, err := NewKeyStore(be, storage.NewCertAdapter(storage.New()))
	if err != nil {
		t.Fatalf("NewKeyStore failed: %v", err)
	}
	defer func() { _ = ks.Close() }()

	b := ks.Backend()
	if b == nil {
		t.Fatal("Backend returned nil")
	}
	if b.Type() != backend.BackendTypeAzureKV {
		t.Errorf("Expected type %s, got %s", backend.BackendTypeAzureKV, b.Type())
	}
}

func TestKeyStore_GenerateRSA(t *testing.T) {
	be := newTestBackend(t)
	defer func() { _ = be.Close() }()

	ks, err := NewKeyStore(be, storage.NewCertAdapter(storage.New()))
	if err != nil {
		t.Fatalf("NewKeyStore failed: %v", err)
	}
	defer func() { _ = ks.Close() }()

	t.Run("Success", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test-rsa-key",
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}

		key, err := ks.GenerateRSA(attrs)
		if err != nil {
			t.Fatalf("GenerateRSA failed: %v", err)
		}
		if key == nil {
			t.Fatal("GenerateRSA returned nil key")
		}

		// Verify public key
		signer, ok := key.(crypto.Signer)
		if !ok {
			t.Fatal("Expected key to implement crypto.Signer")
		}
		pub := signer.Public()
		if pub == nil {
			t.Fatal("Public key is nil")
		}
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			t.Fatalf("Expected RSA public key, got %T", pub)
		}
		if rsaPub.N.BitLen() != 2048 {
			t.Errorf("Expected 2048-bit key, got %d bits", rsaPub.N.BitLen())
		}
	})

	t.Run("DefaultKeySize", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test-rsa-default",
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
		}

		key, err := ks.GenerateRSA(attrs)
		if err != nil {
			t.Fatalf("GenerateRSA failed: %v", err)
		}

		signer, ok := key.(crypto.Signer)
		if !ok {
			t.Fatal("Expected key to implement crypto.Signer")
		}
		pub := signer.Public().(*rsa.PublicKey)
		if pub.N.BitLen() != 2048 {
			t.Errorf("Expected default 2048-bit key, got %d bits", pub.N.BitLen())
		}
	})

	t.Run("SmallKeySizeDefaults", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test-rsa-small",
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 256, // Too small, should default to 2048
			},
		}

		key, err := ks.GenerateRSA(attrs)
		if err != nil {
			t.Fatalf("GenerateRSA failed: %v", err)
		}

		signer, ok := key.(crypto.Signer)
		if !ok {
			t.Fatal("Expected key to implement crypto.Signer")
		}
		pub := signer.Public().(*rsa.PublicKey)
		if pub.N.BitLen() != 2048 {
			t.Errorf("Expected default 2048-bit key for small size, got %d bits", pub.N.BitLen())
		}
	})
}

func TestKeyStore_GenerateECDSA(t *testing.T) {
	be := newTestBackend(t)
	defer func() { _ = be.Close() }()

	ks, err := NewKeyStore(be, storage.NewCertAdapter(storage.New()))
	if err != nil {
		t.Fatalf("NewKeyStore failed: %v", err)
	}
	defer func() { _ = ks.Close() }()

	t.Run("Success", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test-ecdsa-key",
			KeyAlgorithm: x509.ECDSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			ECCAttributes: &types.ECCAttributes{
				Curve: elliptic.P256(),
			},
		}

		key, err := ks.GenerateECDSA(attrs)
		if err != nil {
			t.Fatalf("GenerateECDSA failed: %v", err)
		}
		if key == nil {
			t.Fatal("GenerateECDSA returned nil key")
		}

		// Verify public key
		signer, ok := key.(crypto.Signer)
		if !ok {
			t.Fatal("Expected key to implement crypto.Signer")
		}
		pub := signer.Public()
		if pub == nil {
			t.Fatal("Public key is nil")
		}
		ecdsaPub, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			t.Fatalf("Expected ECDSA public key, got %T", pub)
		}
		if ecdsaPub.Curve != elliptic.P256() {
			t.Errorf("Expected P-256 curve, got %v", ecdsaPub.Curve)
		}
	})

	t.Run("DefaultCurve", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test-ecdsa-default",
			KeyAlgorithm: x509.ECDSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
		}

		key, err := ks.GenerateECDSA(attrs)
		if err != nil {
			t.Fatalf("GenerateECDSA failed: %v", err)
		}

		signer, ok := key.(crypto.Signer)
		if !ok {
			t.Fatal("Expected key to implement crypto.Signer")
		}
		pub := signer.Public().(*ecdsa.PublicKey)
		if pub.Curve != elliptic.P256() {
			t.Errorf("Expected default P-256 curve, got %v", pub.Curve)
		}
	})

	t.Run("NilCurveDefaults", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test-ecdsa-nil",
			KeyAlgorithm: x509.ECDSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			ECCAttributes: &types.ECCAttributes{
				Curve: nil,
			},
		}

		key, err := ks.GenerateECDSA(attrs)
		if err != nil {
			t.Fatalf("GenerateECDSA failed: %v", err)
		}

		signer, ok := key.(crypto.Signer)
		if !ok {
			t.Fatal("Expected key to implement crypto.Signer")
		}
		pub := signer.Public().(*ecdsa.PublicKey)
		if pub.Curve != elliptic.P256() {
			t.Errorf("Expected default P-256 curve for nil curve, got %v", pub.Curve)
		}
	})
}

func TestKeyStore_GenerateEd25519(t *testing.T) {
	be := newTestBackend(t)
	defer func() { _ = be.Close() }()

	ks, err := NewKeyStore(be, storage.NewCertAdapter(storage.New()))
	if err != nil {
		t.Fatalf("NewKeyStore failed: %v", err)
	}
	defer func() { _ = ks.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "test-ed25519-key",
		KeyAlgorithm: x509.Ed25519,
		KeyType:      backend.KEY_TYPE_SIGNING,
	}

	_, err = ks.GenerateEd25519(attrs)
	if err == nil {
		t.Fatal("Expected error for Ed25519 generation")
	}
	if !errors.Is(err, azurekvbackend.ErrUnsupportedKeyType) {
		t.Errorf("Expected ErrUnsupportedKeyType, got: %v", err)
	}
}

func TestKeyStore_GenerateKey(t *testing.T) {
	be := newTestBackend(t)
	defer func() { _ = be.Close() }()

	ks, err := NewKeyStore(be, storage.NewCertAdapter(storage.New()))
	if err != nil {
		t.Fatalf("NewKeyStore failed: %v", err)
	}
	defer func() { _ = ks.Close() }()

	// Type assert to concrete type to access GenerateKey method
	azureKS, ok := ks.(*KeyStore)
	if !ok {
		t.Fatal("Failed to type assert to *KeyStore")
	}

	t.Run("RSA", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test-key-rsa",
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}

		key, err := azureKS.GenerateKey(attrs)
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}
		signer, ok := key.(crypto.Signer)
		if !ok {
			t.Fatal("Expected key to implement crypto.Signer")
		}
		if _, ok := signer.Public().(*rsa.PublicKey); !ok {
			t.Error("Expected RSA public key")
		}
	})

	t.Run("ECDSA", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test-key-ecdsa",
			KeyAlgorithm: x509.ECDSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			ECCAttributes: &types.ECCAttributes{
				Curve: elliptic.P256(),
			},
		}

		key, err := azureKS.GenerateKey(attrs)
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}
		signer, ok := key.(crypto.Signer)
		if !ok {
			t.Fatal("Expected key to implement crypto.Signer")
		}
		if _, ok := signer.Public().(*ecdsa.PublicKey); !ok {
			t.Error("Expected ECDSA public key")
		}
	})

	t.Run("Ed25519", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test-key-ed25519",
			KeyAlgorithm: x509.Ed25519,
			KeyType:      backend.KEY_TYPE_SIGNING,
		}

		_, err := azureKS.GenerateKey(attrs)
		if err == nil {
			t.Fatal("Expected error for Ed25519")
		}
	})

	t.Run("InvalidAlgorithm", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test-key-invalid",
			KeyAlgorithm: x509.PublicKeyAlgorithm(999), // Invalid algorithm
			KeyType:      backend.KEY_TYPE_SIGNING,
		}

		_, err := azureKS.GenerateKey(attrs)
		if err == nil {
			t.Fatal("Expected error for invalid algorithm")
		}
		if !errors.Is(err, keychain.ErrInvalidKeyAlgorithm) {
			t.Errorf("Expected ErrInvalidKeyAlgorithm, got: %v", err)
		}
	})
}

func TestKeyStore_GenerateSecretKey(t *testing.T) {
	be := newTestBackend(t)
	defer func() { _ = be.Close() }()

	ks, err := NewKeyStore(be, storage.NewCertAdapter(storage.New()))
	if err != nil {
		t.Fatalf("NewKeyStore failed: %v", err)
	}
	defer func() { _ = ks.Close() }()

	// Type assert to concrete type to access GenerateSecretKey method
	azureKS, ok := ks.(*KeyStore)
	if !ok {
		t.Fatal("Failed to type assert to *KeyStore")
	}

	t.Run("AES256_Success", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:      "test-aes256-key",
			KeyType: backend.KEY_TYPE_ENCRYPTION,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 256,
			},
		}

		err := azureKS.GenerateSecretKey(attrs)
		if err != nil {
			t.Fatalf("GenerateSecretKey failed: %v", err)
		}
	})

	t.Run("AES128_Success", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:      "test-aes128-key",
			KeyType: backend.KEY_TYPE_ENCRYPTION,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 128,
			},
		}

		err := azureKS.GenerateSecretKey(attrs)
		if err != nil {
			t.Fatalf("GenerateSecretKey failed: %v", err)
		}
	})

	t.Run("EncryptionKeyType", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:      "test-encryption-key",
			KeyType: backend.KEY_TYPE_ENCRYPTION,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 256,
			},
		}

		err := azureKS.GenerateSecretKey(attrs)
		if err != nil {
			t.Fatalf("GenerateSecretKey failed for encryption key type: %v", err)
		}
	})

	t.Run("DefaultKeySize", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:      "test-default-size-key",
			KeyType: backend.KEY_TYPE_ENCRYPTION,
		}

		err := azureKS.GenerateSecretKey(attrs)
		if err != nil {
			t.Fatalf("GenerateSecretKey failed with default key size: %v", err)
		}
	})

	t.Run("InvalidKeyType", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:      "test-invalid-type",
			KeyType: backend.KEY_TYPE_SIGNING,
		}

		err := azureKS.GenerateSecretKey(attrs)
		if err == nil {
			t.Fatal("Expected error for invalid key type")
		}
	})

	t.Run("InvalidKeySize", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:      "test-invalid-size",
			KeyType: backend.KEY_TYPE_ENCRYPTION,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 512,
			},
		}

		err := azureKS.GenerateSecretKey(attrs)
		if err == nil {
			t.Fatal("Expected error for invalid key size")
		}
	})
}

func TestKeyStore_Find(t *testing.T) {
	be := newTestBackend(t)
	defer func() { _ = be.Close() }()

	ks, err := NewKeyStore(be, storage.NewCertAdapter(storage.New()))
	if err != nil {
		t.Fatalf("NewKeyStore failed: %v", err)
	}
	defer func() { _ = ks.Close() }()

	t.Run("ExistingKey", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test-find-key",
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}

		// Generate key first
		_, err := ks.GenerateRSA(attrs)
		if err != nil {
			t.Fatalf("GenerateRSA failed: %v", err)
		}

		// Find the key
		key, err := ks.GetKey(attrs)
		if err != nil {
			t.Fatalf("Find failed: %v", err)
		}
		if key == nil {
			t.Fatal("Find returned nil key")
		}
	})

	t.Run("NonExistentKey", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "non-existent-key",
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
		}

		_, err := ks.GetKey(attrs)
		if err == nil {
			t.Fatal("Expected error for non-existent key")
		}
	})
}

func TestKeyStore_Key(t *testing.T) {
	be := newTestBackend(t)
	defer func() { _ = be.Close() }()

	ks, err := NewKeyStore(be, storage.NewCertAdapter(storage.New()))
	if err != nil {
		t.Fatalf("NewKeyStore failed: %v", err)
	}
	defer func() { _ = ks.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "test-key-lookup",
		KeyAlgorithm: x509.RSA,
		KeyType:      backend.KEY_TYPE_SIGNING,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
	}

	// Generate key first
	_, err = ks.GenerateRSA(attrs)
	if err != nil {
		t.Fatalf("GenerateRSA failed: %v", err)
	}

	// Retrieve the key
	key, err := ks.GetKey(attrs)
	if err != nil {
		t.Fatalf("Key failed: %v", err)
	}
	if key == nil {
		t.Fatal("Key returned nil")
	}
}

func TestKeyStore_Delete(t *testing.T) {
	be := newTestBackend(t)
	defer func() { _ = be.Close() }()

	ks, err := NewKeyStore(be, storage.NewCertAdapter(storage.New()))
	if err != nil {
		t.Fatalf("NewKeyStore failed: %v", err)
	}
	defer func() { _ = ks.Close() }()

	t.Run("Success", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test-delete-key",
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}

		// Generate key
		_, err := ks.GenerateRSA(attrs)
		if err != nil {
			t.Fatalf("GenerateRSA failed: %v", err)
		}

		// Delete key
		err = ks.DeleteKey(attrs)
		if err != nil {
			t.Fatalf("Delete failed: %v", err)
		}

		// Verify key is deleted
		_, err = ks.GetKey(attrs)
		if err == nil {
			t.Fatal("Expected error after deletion")
		}
	})

	t.Run("NonExistentKey", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "non-existent-delete-key",
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
		}

		// Delete should be idempotent
		err := ks.DeleteKey(attrs)
		if err != nil {
			t.Errorf("Delete should be idempotent: %v", err)
		}
	})
}

func TestKeyStore_RotateKey(t *testing.T) {
	be := newTestBackend(t)
	defer func() { _ = be.Close() }()

	ks, err := NewKeyStore(be, storage.NewCertAdapter(storage.New()))
	if err != nil {
		t.Fatalf("NewKeyStore failed: %v", err)
	}
	defer func() { _ = ks.Close() }()

	t.Run("Success", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test-rotate-key",
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}

		// Generate initial key
		key1, err := ks.GenerateRSA(attrs)
		if err != nil {
			t.Fatalf("GenerateRSA failed: %v", err)
		}
		signer1, ok := key1.(crypto.Signer)
		if !ok {
			t.Fatal("Expected key1 to implement crypto.Signer")
		}
		pub1 := signer1.Public().(*rsa.PublicKey)

		// Rotate the key
		key2, err := ks.RotateKey(attrs)
		if err != nil {
			t.Fatalf("RotateKey failed: %v", err)
		}
		signer2, ok := key2.(crypto.Signer)
		if !ok {
			t.Fatal("Expected key2 to implement crypto.Signer")
		}
		pub2 := signer2.Public().(*rsa.PublicKey)

		// Verify keys are different
		if pub1.N.Cmp(pub2.N) == 0 {
			t.Error("Expected different keys after rotation")
		}
	})

	t.Run("NonExistentKey", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "non-existent-rotate-key",
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
		}

		_, err := ks.RotateKey(attrs)
		if err == nil {
			t.Fatal("Expected error rotating non-existent key")
		}
	})

	t.Run("Ed25519NotSupported", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test-rotate-ed25519",
			KeyAlgorithm: x509.Ed25519,
			KeyType:      backend.KEY_TYPE_SIGNING,
		}

		// Mock the key exists (even though we can't create it)
		// This tests the rotation logic for unsupported algorithms
		_, err := ks.RotateKey(attrs)
		if err == nil {
			t.Fatal("Expected error for Ed25519 rotation")
		}
	})
}

func TestKeyStore_Equal(t *testing.T) {
	be := newTestBackend(t)
	defer func() { _ = be.Close() }()

	ks, err := NewKeyStore(be, storage.NewCertAdapter(storage.New()))
	if err != nil {
		t.Fatalf("NewKeyStore failed: %v", err)
	}
	defer func() { _ = ks.Close() }()

	// Type assert to concrete type to access Equal method
	azureKS, ok := ks.(*KeyStore)
	if !ok {
		t.Fatal("Failed to type assert to *KeyStore")
	}

	t.Run("RSAEqual", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test-equal-rsa",
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}

		key, err := ks.GenerateRSA(attrs)
		if err != nil {
			t.Fatalf("GenerateRSA failed: %v", err)
		}

		// Generate an RSA key with the same public key
		signer, ok := key.(crypto.Signer)
		if !ok {
			t.Fatal("Expected key to implement crypto.Signer")
		}
		rsaPub := signer.Public().(*rsa.PublicKey)
		rsaPriv := &rsa.PrivateKey{
			PublicKey: *rsaPub,
			D:         big.NewInt(1), // Dummy value
			Primes:    []*big.Int{big.NewInt(2), big.NewInt(3)},
		}

		if !azureKS.Equal(key, rsaPriv) {
			t.Error("Expected keys to be equal")
		}
	})

	t.Run("RSANotEqual", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test-not-equal-rsa",
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}

		key, err := ks.GenerateRSA(attrs)
		if err != nil {
			t.Fatalf("GenerateRSA failed: %v", err)
		}

		// Generate a different RSA key
		otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)

		if azureKS.Equal(key, otherKey) {
			t.Error("Expected keys to not be equal")
		}
	})

	t.Run("ECDSAEqual", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test-equal-ecdsa",
			KeyAlgorithm: x509.ECDSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			ECCAttributes: &types.ECCAttributes{
				Curve: elliptic.P256(),
			},
		}

		key, err := ks.GenerateECDSA(attrs)
		if err != nil {
			t.Fatalf("GenerateECDSA failed: %v", err)
		}

		// Generate an ECDSA key with the same public key
		signer, ok := key.(crypto.Signer)
		if !ok {
			t.Fatal("Expected key to implement crypto.Signer")
		}
		ecdsaPub := signer.Public().(*ecdsa.PublicKey)
		ecdsaPriv := &ecdsa.PrivateKey{
			PublicKey: *ecdsaPub,
			D:         big.NewInt(1), // Dummy value
		}

		if !azureKS.Equal(key, ecdsaPriv) {
			t.Error("Expected keys to be equal")
		}
	})

	t.Run("NilOpaqueKey", func(t *testing.T) {
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		if azureKS.Equal(nil, key) {
			t.Error("Expected false for nil opaque key")
		}
	})

	t.Run("NilPrivateKey", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test-nil-private",
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}

		key, err := ks.GenerateRSA(attrs)
		if err != nil {
			t.Fatalf("GenerateRSA failed: %v", err)
		}

		if azureKS.Equal(key, nil) {
			t.Error("Expected false for nil private key")
		}
	})

	t.Run("DifferentKeyTypes", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test-different-types",
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}

		key, err := ks.GenerateRSA(attrs)
		if err != nil {
			t.Fatalf("GenerateRSA failed: %v", err)
		}

		// Try to compare with ECDSA key
		ecdsaKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

		if azureKS.Equal(key, ecdsaKey) {
			t.Error("Expected false for different key types")
		}
	})

	t.Run("Ed25519Equal", func(t *testing.T) {
		// Test Ed25519 comparison logic even though we can't generate them
		pub1, priv1, _ := ed25519.GenerateKey(rand.Reader)
		pub2, priv2, _ := ed25519.GenerateKey(rand.Reader)

		// Create opaque keys manually for testing
		opaqueKey1, err := opaque.NewOpaqueKey(ks, &types.KeyAttributes{
			CN:           "ed25519-1",
			KeyAlgorithm: x509.Ed25519,
		}, pub1)
		if err != nil {
			t.Fatalf("NewOpaqueKey failed: %v", err)
		}

		opaqueKey2, err := opaque.NewOpaqueKey(ks, &types.KeyAttributes{
			CN:           "ed25519-2",
			KeyAlgorithm: x509.Ed25519,
		}, pub2)
		if err != nil {
			t.Fatalf("NewOpaqueKey failed: %v", err)
		}

		// Test equal keys
		if !azureKS.Equal(opaqueKey1, priv1) {
			t.Error("Expected Ed25519 keys to be equal")
		}

		// Test not equal keys
		if azureKS.Equal(opaqueKey1, priv2) {
			t.Error("Expected Ed25519 keys to not be equal")
		}

		// Test with different public key
		if azureKS.Equal(opaqueKey1, opaqueKey2) {
			t.Error("Expected different Ed25519 keys to not be equal")
		}
	})
}

func TestKeyStore_Signer(t *testing.T) {
	be := newTestBackend(t)
	defer func() { _ = be.Close() }()

	ks, err := NewKeyStore(be, storage.NewCertAdapter(storage.New()))
	if err != nil {
		t.Fatalf("NewKeyStore failed: %v", err)
	}
	defer func() { _ = ks.Close() }()

	t.Run("RSASigner", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test-signer-rsa",
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}

		// Generate key
		_, err := ks.GenerateRSA(attrs)
		if err != nil {
			t.Fatalf("GenerateRSA failed: %v", err)
		}

		// Get signer
		signer, err := ks.Signer(attrs)
		if err != nil {
			t.Fatalf("Signer failed: %v", err)
		}
		if signer == nil {
			t.Fatal("Signer returned nil")
		}

		// Test signing
		digest := make([]byte, 32)
		_, err = rand.Read(digest)
		if err != nil {
			t.Fatalf("Failed to generate digest: %v", err)
		}

		signature, err := signer.Sign(rand.Reader, digest, crypto.SHA256)
		if err != nil {
			t.Fatalf("Sign failed: %v", err)
		}
		if len(signature) == 0 {
			t.Error("Signature is empty")
		}
	})

	t.Run("ECDSASigner", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test-signer-ecdsa",
			KeyAlgorithm: x509.ECDSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			ECCAttributes: &types.ECCAttributes{
				Curve: elliptic.P256(),
			},
		}

		// Generate key
		_, err := ks.GenerateECDSA(attrs)
		if err != nil {
			t.Fatalf("GenerateECDSA failed: %v", err)
		}

		// Get signer
		signer, err := ks.Signer(attrs)
		if err != nil {
			t.Fatalf("Signer failed: %v", err)
		}

		// Test signing
		digest := make([]byte, 32)
		_, err = rand.Read(digest)
		if err != nil {
			t.Fatalf("Failed to generate digest: %v", err)
		}

		signature, err := signer.Sign(rand.Reader, digest, crypto.SHA256)
		if err != nil {
			t.Fatalf("Sign failed: %v", err)
		}
		if len(signature) == 0 {
			t.Error("Signature is empty")
		}
	})

	t.Run("NonExistentKey", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "non-existent-signer",
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
		}

		_, err := ks.Signer(attrs)
		if err == nil {
			t.Fatal("Expected error for non-existent key")
		}
	})
}

func TestKeyStore_Decrypter(t *testing.T) {
	be := newTestBackend(t)
	defer func() { _ = be.Close() }()

	ks, err := NewKeyStore(be, storage.NewCertAdapter(storage.New()))
	if err != nil {
		t.Fatalf("NewKeyStore failed: %v", err)
	}
	defer func() { _ = ks.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "test-decrypter",
		KeyAlgorithm: x509.RSA,
		KeyType:      backend.KEY_TYPE_ENCRYPTION,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
	}

	_, err = ks.Decrypter(attrs)
	if err == nil {
		t.Fatal("Expected error for Decrypter (not supported)")
	}
}

// TestKeyStore_Verifier is disabled - Verifier method doesn't exist on KeyStore interface
// Verification can be done using the Signer's Public() method
// func TestKeyStore_Verifier(t *testing.T) {
// 	be := newTestBackend(t)
// 	defer be.Close()
//
// 	ks, err := NewKeyStore(be, storage.NewCertAdapter(storage.New()))
// 	if err != nil {
// 		t.Fatalf("NewKeyStore failed: %v", err)
// 	}
// 	defer ks.Close()
//
// 	attrs := &types.KeyAttributes{
// 		CN:           "test-verifier",
// 		KeyAlgorithm: x509.RSA,
// 		KeyType:      backend.KEY_TYPE_SIGNING,
// 	}
//
// 	verifier := ks.Verifier(attrs)
// 	if verifier == nil {
// 		t.Fatal("Verifier returned nil")
// 	}
// }

func TestBackendWrapper(t *testing.T) {
	be := newTestBackend(t)
	defer func() { _ = be.Close() }()

	ks, err := NewKeyStore(be, storage.NewCertAdapter(storage.New()))
	if err != nil {
		t.Fatalf("NewKeyStore failed: %v", err)
	}
	defer func() { _ = ks.Close() }()

	wrapper := ks.Backend()

	t.Run("Type", func(t *testing.T) {
		if wrapper.Type() != backend.BackendTypeAzureKV {
			t.Errorf("Expected type %s, got %s", backend.BackendTypeAzureKV, wrapper.Type())
		}
	})

	t.Run("Capabilities", func(t *testing.T) {
		caps := wrapper.Capabilities()
		if !caps.Keys {
			t.Error("Expected Keys capability to be true")
		}
		if !caps.HardwareBacked {
			t.Error("Expected HardwareBacked capability to be true")
		}
		if !caps.Signing {
			t.Error("Expected Signing capability to be true")
		}
	})

	t.Run("ListKeys", func(t *testing.T) {
		keys, err := wrapper.ListKeys()
		if err != nil {
			t.Fatalf("ListKeys failed: %v", err)
		}
		// Empty list is expected since we haven't created any keys yet
		if keys == nil {
			t.Error("Expected non-nil keys slice")
		}
	})

	t.Run("Close", func(t *testing.T) {
		// Close should be a no-op
		err := wrapper.Close()
		if err != nil {
			t.Errorf("Close failed: %v", err)
		}
	})
}

func TestKVSigner(t *testing.T) {
	be := newTestBackend(t)
	defer func() { _ = be.Close() }()

	ks, err := NewKeyStore(be, storage.NewCertAdapter(storage.New()))
	if err != nil {
		t.Fatalf("NewKeyStore failed: %v", err)
	}
	defer func() { _ = ks.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "test-kv-signer",
		KeyAlgorithm: x509.RSA,
		KeyType:      backend.KEY_TYPE_SIGNING,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
	}

	// Generate key
	_, err = ks.GenerateRSA(attrs)
	if err != nil {
		t.Fatalf("GenerateRSA failed: %v", err)
	}

	// Get signer
	signer, err := ks.Signer(attrs)
	if err != nil {
		t.Fatalf("Signer failed: %v", err)
	}

	t.Run("Public", func(t *testing.T) {
		pub := signer.Public()
		if pub == nil {
			t.Fatal("Public returned nil")
		}
		if _, ok := pub.(*rsa.PublicKey); !ok {
			t.Errorf("Expected RSA public key, got %T", pub)
		}
	})

	t.Run("Sign", func(t *testing.T) {
		digest := make([]byte, 32)
		_, err := rand.Read(digest)
		if err != nil {
			t.Fatalf("Failed to generate digest: %v", err)
		}

		signature, err := signer.Sign(rand.Reader, digest, crypto.SHA256)
		if err != nil {
			t.Fatalf("Sign failed: %v", err)
		}
		if len(signature) == 0 {
			t.Error("Signature is empty")
		}
	})
}

// Test concurrent access
func TestKeyStore_ConcurrentAccess(t *testing.T) {
	be := newTestBackend(t)
	defer func() { _ = be.Close() }()

	ks, err := NewKeyStore(be, storage.NewCertAdapter(storage.New()))
	if err != nil {
		t.Fatalf("NewKeyStore failed: %v", err)
	}
	defer func() { _ = ks.Close() }()

	// Generate a key first
	attrs := &types.KeyAttributes{
		CN:           "test-concurrent",
		KeyAlgorithm: x509.RSA,
		KeyType:      backend.KEY_TYPE_SIGNING,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
	}
	_, err = ks.GenerateRSA(attrs)
	if err != nil {
		t.Fatalf("GenerateRSA failed: %v", err)
	}

	// Test concurrent reads
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			defer func() { done <- true }()
			_, err := ks.GetKey(attrs)
			if err != nil {
				t.Errorf("Concurrent Find failed: %v", err)
			}
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

// Test error handling in kvSigner
func TestKVSigner_ErrorHandling(t *testing.T) {
	// Create a backend with a mock client that returns errors
	config := &azurekvbackend.Config{
		VaultURL:    "https://test-vault.vault.azure.net",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}

	mockClient := azurekvbackend.NewMockKeyVaultClient()
	mockClient.SetSignError(fmt.Errorf("mock sign error"))

	b, err := azurekvbackend.NewBackendWithClient(config, mockClient)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	// Create a signer directly
	signer := &kvSigner{
		backend: b,
		attrs: &types.KeyAttributes{
			CN:           "test-error",
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
		},
		pub: &rsa.PublicKey{N: big.NewInt(123), E: 65537},
	}

	digest := make([]byte, 32)
	_, err = signer.Sign(rand.Reader, digest, crypto.SHA256)
	if err == nil {
		t.Fatal("Expected error from Sign")
	}
}
