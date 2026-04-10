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

package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

func TestNewLocalBackend(t *testing.T) {
	t.Run("success with valid config", func(t *testing.T) {
		backend := storage.NewMemory()
		defer backend.Close()

		lb, err := NewLocalBackend(&LocalBackendConfig{
			Backend: backend,
		})
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		defer lb.Close()

		if lb == nil {
			t.Fatal("expected non-nil backend")
		}
	})

	t.Run("error with nil config", func(t *testing.T) {
		_, err := NewLocalBackend(nil)
		if err == nil {
			t.Fatal("expected error for nil config")
		}
		if !errors.Is(err, ErrLocalBackendNilConfig) {
			t.Errorf("expected ErrLocalBackendNilConfig, got %v", err)
		}
	})

	t.Run("error with nil storage backend", func(t *testing.T) {
		_, err := NewLocalBackend(&LocalBackendConfig{
			Backend: nil,
		})
		if err == nil {
			t.Fatal("expected error for nil storage backend")
		}
		if !errors.Is(err, ErrLocalBackendNilStorage) {
			t.Errorf("expected ErrLocalBackendNilStorage, got %v", err)
		}
	})
}

func TestLocalBackend_GenerateKey_Ed25519(t *testing.T) {
	ctx := context.Background()

	t.Run("success default ed25519", func(t *testing.T) {
		lb := newTestLocalBackend(t)
		defer lb.Close()

		keyInfo, err := lb.GenerateKey(ctx, "test-ed25519", KeyTypeEd25519, nil)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if keyInfo.KeyID != "test-ed25519" {
			t.Errorf("expected ID 'test-ed25519', got %s", keyInfo.KeyID)
		}
		if keyInfo.KeyType != KeyTypeEd25519 {
			t.Errorf("expected KeyType Ed25519, got %s", keyInfo.KeyType)
		}
		if keyInfo.PublicKey == nil {
			t.Error("expected non-nil public key")
		}
	})

	t.Run("success explicit ed25519 with options", func(t *testing.T) {
		lb := newTestLocalBackend(t)
		defer lb.Close()

		keyInfo, err := lb.GenerateKey(ctx, "test-ed25519-opts", KeyTypeEd25519, &GenerateOptions{
			Comment: "test key",
		})
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if keyInfo.KeyType != KeyTypeEd25519 {
			t.Errorf("expected KeyType Ed25519, got %s", keyInfo.KeyType)
		}
	})
}

func TestLocalBackend_GenerateKey_RSA(t *testing.T) {
	ctx := context.Background()

	t.Run("success with default bits", func(t *testing.T) {
		lb := newTestLocalBackend(t)
		defer lb.Close()

		keyInfo, err := lb.GenerateKey(ctx, "test-rsa", KeyTypeRSA, nil)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if keyInfo.KeyID != "test-rsa" {
			t.Errorf("expected ID 'test-rsa', got %s", keyInfo.KeyID)
		}
		if keyInfo.KeyType != KeyTypeRSA {
			t.Errorf("expected KeyType RSA, got %s", keyInfo.KeyType)
		}
	})

	t.Run("success with 2048 bits", func(t *testing.T) {
		lb := newTestLocalBackend(t)
		defer lb.Close()

		keyInfo, err := lb.GenerateKey(ctx, "test-rsa-2048", KeyTypeRSA, &GenerateOptions{
			Bits: types.RSAKeySize2048,
		})
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if keyInfo.KeyType != KeyTypeRSA {
			t.Errorf("expected KeyType RSA, got %s", keyInfo.KeyType)
		}
	})

	t.Run("error with invalid key size", func(t *testing.T) {
		lb := newTestLocalBackend(t)
		defer lb.Close()

		_, err := lb.GenerateKey(ctx, "test-rsa-small", KeyTypeRSA, &GenerateOptions{
			Bits: 1024,
		})
		if err == nil {
			t.Fatal("expected error for invalid RSA key size")
		}
	})
}

func TestLocalBackend_GenerateKey_ECDSA(t *testing.T) {
	ctx := context.Background()

	testCases := []struct {
		name  string
		curve string
	}{
		{"P-256", types.CurveP256.String()},
		{"P-384", types.CurveP384.String()},
		{"P-521", types.CurveP521.String()},
	}

	for _, tc := range testCases {
		t.Run("success with "+tc.name, func(t *testing.T) {
			lb := newTestLocalBackend(t)
			defer lb.Close()

			keyInfo, err := lb.GenerateKey(ctx, "test-ecdsa-"+tc.name, KeyTypeECDSA, &GenerateOptions{
				Curve: tc.curve,
			})
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}

			if keyInfo.KeyType != KeyTypeECDSA {
				t.Errorf("expected KeyType ECDSA, got %s", keyInfo.KeyType)
			}
		})
	}

	t.Run("error with invalid curve", func(t *testing.T) {
		lb := newTestLocalBackend(t)
		defer lb.Close()

		_, err := lb.GenerateKey(ctx, "test-ecdsa-bad", KeyTypeECDSA, &GenerateOptions{
			Curve: "invalid-curve",
		})
		if err == nil {
			t.Fatal("expected error for invalid curve")
		}
	})
}

func TestLocalBackend_GenerateKey_Errors(t *testing.T) {
	ctx := context.Background()

	t.Run("error with empty key ID", func(t *testing.T) {
		lb := newTestLocalBackend(t)
		defer lb.Close()

		_, err := lb.GenerateKey(ctx, "", KeyTypeEd25519, nil)
		if err == nil {
			t.Fatal("expected error for empty key ID")
		}
		if !errors.Is(err, ErrBackendEmptyKeyID) {
			t.Errorf("expected ErrBackendEmptyKeyID, got %v", err)
		}
	})

	t.Run("error with invalid key type", func(t *testing.T) {
		lb := newTestLocalBackend(t)
		defer lb.Close()

		_, err := lb.GenerateKey(ctx, "test-unsupported", "unsupported", nil)
		if err == nil {
			t.Fatal("expected error for unsupported key type")
		}
		if !errors.Is(err, ErrBackendInvalidKeyType) {
			t.Errorf("expected ErrBackendInvalidKeyType, got %v", err)
		}
	})

	t.Run("error with duplicate key ID", func(t *testing.T) {
		lb := newTestLocalBackend(t)
		defer lb.Close()

		_, err := lb.GenerateKey(ctx, "duplicate", KeyTypeEd25519, nil)
		if err != nil {
			t.Fatalf("expected no error on first generate, got %v", err)
		}

		_, err = lb.GenerateKey(ctx, "duplicate", KeyTypeEd25519, nil)
		if err == nil {
			t.Fatal("expected error for duplicate key ID")
		}
		if !errors.Is(err, ErrBackendKeyExists) {
			t.Errorf("expected ErrBackendKeyExists, got %v", err)
		}
	})

	t.Run("error after close", func(t *testing.T) {
		lb := newTestLocalBackend(t)
		lb.Close()

		_, err := lb.GenerateKey(ctx, "test", KeyTypeEd25519, nil)
		if err == nil {
			t.Fatal("expected error after close")
		}
		if !errors.Is(err, ErrBackendClosed) {
			t.Errorf("expected ErrBackendClosed, got %v", err)
		}
	})
}

func TestLocalBackend_ImportKey(t *testing.T) {
	ctx := context.Background()

	t.Run("success import ed25519", func(t *testing.T) {
		lb := newTestLocalBackend(t)
		defer lb.Close()

		// Generate an ed25519 key to import
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate ed25519 key: %v", err)
		}

		privPEM := encodeTestEd25519PrivateKey(t, priv)

		keyInfo, err := lb.ImportKey(ctx, "imported-ed25519", privPEM)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if keyInfo.KeyID != "imported-ed25519" {
			t.Errorf("expected ID 'imported-ed25519', got %s", keyInfo.KeyID)
		}
		if keyInfo.KeyType != KeyTypeEd25519 {
			t.Errorf("expected KeyType Ed25519, got %s", keyInfo.KeyType)
		}
	})

	t.Run("success import rsa", func(t *testing.T) {
		lb := newTestLocalBackend(t)
		defer lb.Close()

		// Generate an RSA key to import
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("failed to generate RSA key: %v", err)
		}

		privPEM := encodeTestRSAPrivateKey(t, priv)

		keyInfo, err := lb.ImportKey(ctx, "imported-rsa", privPEM)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if keyInfo.KeyType != KeyTypeRSA {
			t.Errorf("expected KeyType RSA, got %s", keyInfo.KeyType)
		}
	})

	t.Run("success import ecdsa", func(t *testing.T) {
		lb := newTestLocalBackend(t)
		defer lb.Close()

		// Generate an ECDSA key to import
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate ECDSA key: %v", err)
		}

		privPEM := encodeTestECDSAPrivateKey(t, priv)

		keyInfo, err := lb.ImportKey(ctx, "imported-ecdsa", privPEM)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if keyInfo.KeyType != KeyTypeECDSA {
			t.Errorf("expected KeyType ECDSA, got %s", keyInfo.KeyType)
		}
	})

	t.Run("error with empty key ID", func(t *testing.T) {
		lb := newTestLocalBackend(t)
		defer lb.Close()

		_, err := lb.ImportKey(ctx, "", []byte("dummy"))
		if err == nil {
			t.Fatal("expected error for empty key ID")
		}
	})

	t.Run("error with invalid PEM", func(t *testing.T) {
		lb := newTestLocalBackend(t)
		defer lb.Close()

		_, err := lb.ImportKey(ctx, "invalid", []byte("not valid pem"))
		if err == nil {
			t.Fatal("expected error for invalid PEM")
		}
	})

	t.Run("error with duplicate key ID", func(t *testing.T) {
		lb := newTestLocalBackend(t)
		defer lb.Close()

		_, priv, _ := ed25519.GenerateKey(rand.Reader)
		privPEM := encodeTestEd25519PrivateKey(t, priv)

		_, err := lb.ImportKey(ctx, "dup-import", privPEM)
		if err != nil {
			t.Fatalf("expected no error on first import, got %v", err)
		}

		_, err = lb.ImportKey(ctx, "dup-import", privPEM)
		if err == nil {
			t.Fatal("expected error for duplicate key ID")
		}
		if !errors.Is(err, ErrBackendKeyExists) {
			t.Errorf("expected ErrBackendKeyExists, got %v", err)
		}
	})
}

func TestLocalBackend_Sign(t *testing.T) {
	ctx := context.Background()

	t.Run("success sign with ed25519", func(t *testing.T) {
		lb := newTestLocalBackend(t)
		defer lb.Close()

		keyInfo, err := lb.GenerateKey(ctx, "sign-ed25519", KeyTypeEd25519, nil)
		if err != nil {
			t.Fatalf("failed to generate key: %v", err)
		}

		data := []byte("test data to sign")
		sig, err := lb.Sign(ctx, keyInfo.KeyID, data, "")
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if len(sig) == 0 {
			t.Error("expected non-empty signature")
		}

		// Verify the signature using the public key
		pubKey, ok := keyInfo.PublicKey.(ssh.CryptoPublicKey)
		if !ok {
			t.Fatal("public key does not implement ssh.CryptoPublicKey")
		}
		ed25519Pub, ok := pubKey.CryptoPublicKey().(ed25519.PublicKey)
		if !ok {
			t.Fatal("expected ed25519 public key")
		}

		if !ed25519.Verify(ed25519Pub, data, sig) {
			t.Error("signature verification failed")
		}
	})

	t.Run("success sign with rsa sha256", func(t *testing.T) {
		lb := newTestLocalBackend(t)
		defer lb.Close()

		keyInfo, err := lb.GenerateKey(ctx, "sign-rsa", KeyTypeRSA, &GenerateOptions{
			Bits: types.RSAKeySize2048,
		})
		if err != nil {
			t.Fatalf("failed to generate key: %v", err)
		}

		data := []byte("test data to sign")
		sig, err := lb.Sign(ctx, keyInfo.KeyID, data, "rsa-sha256")
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if len(sig) == 0 {
			t.Error("expected non-empty signature")
		}
	})

	t.Run("success sign with rsa sha512", func(t *testing.T) {
		lb := newTestLocalBackend(t)
		defer lb.Close()

		keyInfo, err := lb.GenerateKey(ctx, "sign-rsa-512", KeyTypeRSA, &GenerateOptions{
			Bits: types.RSAKeySize2048,
		})
		if err != nil {
			t.Fatalf("failed to generate key: %v", err)
		}

		data := []byte("test data to sign")
		sig, err := lb.Sign(ctx, keyInfo.KeyID, data, "rsa-sha512")
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if len(sig) == 0 {
			t.Error("expected non-empty signature")
		}
	})

	t.Run("success sign with ecdsa p256", func(t *testing.T) {
		lb := newTestLocalBackend(t)
		defer lb.Close()

		keyInfo, err := lb.GenerateKey(ctx, "sign-ecdsa-p256", KeyTypeECDSA, &GenerateOptions{
			Curve: types.CurveP256.String(),
		})
		if err != nil {
			t.Fatalf("failed to generate key: %v", err)
		}

		data := []byte("test data to sign")
		sig, err := lb.Sign(ctx, keyInfo.KeyID, data, "ecdsa-sha256")
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if len(sig) == 0 {
			t.Error("expected non-empty signature")
		}
	})

	t.Run("success sign with ecdsa p384", func(t *testing.T) {
		lb := newTestLocalBackend(t)
		defer lb.Close()

		keyInfo, err := lb.GenerateKey(ctx, "sign-ecdsa-p384", KeyTypeECDSA, &GenerateOptions{
			Curve: types.CurveP384.String(),
		})
		if err != nil {
			t.Fatalf("failed to generate key: %v", err)
		}

		data := []byte("test data to sign")
		sig, err := lb.Sign(ctx, keyInfo.KeyID, data, "ecdsa-sha384")
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if len(sig) == 0 {
			t.Error("expected non-empty signature")
		}
	})

	t.Run("success sign with ecdsa p521", func(t *testing.T) {
		lb := newTestLocalBackend(t)
		defer lb.Close()

		keyInfo, err := lb.GenerateKey(ctx, "sign-ecdsa-p521", KeyTypeECDSA, &GenerateOptions{
			Curve: types.CurveP521.String(),
		})
		if err != nil {
			t.Fatalf("failed to generate key: %v", err)
		}

		data := []byte("test data to sign")
		sig, err := lb.Sign(ctx, keyInfo.KeyID, data, "ecdsa-sha512")
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if len(sig) == 0 {
			t.Error("expected non-empty signature")
		}
	})

	t.Run("error with nonexistent key", func(t *testing.T) {
		lb := newTestLocalBackend(t)
		defer lb.Close()

		_, err := lb.Sign(ctx, "nonexistent", []byte("data"), "")
		if err == nil {
			t.Fatal("expected error for nonexistent key")
		}
		if !errors.Is(err, ErrBackendKeyNotFound) {
			t.Errorf("expected ErrBackendKeyNotFound, got %v", err)
		}
	})

	t.Run("error with invalid hash algorithm for rsa", func(t *testing.T) {
		lb := newTestLocalBackend(t)
		defer lb.Close()

		keyInfo, err := lb.GenerateKey(ctx, "sign-rsa-bad-hash", KeyTypeRSA, &GenerateOptions{
			Bits: types.RSAKeySize2048,
		})
		if err != nil {
			t.Fatalf("failed to generate key: %v", err)
		}

		_, err = lb.Sign(ctx, keyInfo.KeyID, []byte("data"), "invalid-hash")
		if err == nil {
			t.Fatal("expected error for invalid hash algorithm")
		}
	})

	t.Run("error after close", func(t *testing.T) {
		lb := newTestLocalBackend(t)

		keyInfo, err := lb.GenerateKey(ctx, "sign-closed", KeyTypeEd25519, nil)
		if err != nil {
			t.Fatalf("failed to generate key: %v", err)
		}

		lb.Close()

		_, err = lb.Sign(ctx, keyInfo.KeyID, []byte("data"), "")
		if err == nil {
			t.Fatal("expected error after close")
		}
		if !errors.Is(err, ErrBackendClosed) {
			t.Errorf("expected ErrBackendClosed, got %v", err)
		}
	})
}

func TestLocalBackend_GetPublicKey(t *testing.T) {
	ctx := context.Background()

	t.Run("success get existing key", func(t *testing.T) {
		lb := newTestLocalBackend(t)
		defer lb.Close()

		generated, err := lb.GenerateKey(ctx, "get-test", KeyTypeEd25519, nil)
		if err != nil {
			t.Fatalf("failed to generate key: %v", err)
		}

		pubKey, err := lb.GetPublicKey(ctx, "get-test")
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if ssh.FingerprintSHA256(pubKey) != ssh.FingerprintSHA256(generated.PublicKey) {
			t.Error("public key fingerprints do not match")
		}
	})

	t.Run("error get nonexistent key", func(t *testing.T) {
		lb := newTestLocalBackend(t)
		defer lb.Close()

		_, err := lb.GetPublicKey(ctx, "nonexistent")
		if err == nil {
			t.Fatal("expected error for nonexistent key")
		}
		if !errors.Is(err, ErrBackendKeyNotFound) {
			t.Errorf("expected ErrBackendKeyNotFound, got %v", err)
		}
	})

	t.Run("error after close", func(t *testing.T) {
		lb := newTestLocalBackend(t)
		lb.Close()

		_, err := lb.GetPublicKey(ctx, "test")
		if err == nil {
			t.Fatal("expected error after close")
		}
		if !errors.Is(err, ErrBackendClosed) {
			t.Errorf("expected ErrBackendClosed, got %v", err)
		}
	})
}

func TestLocalBackend_ListKeys(t *testing.T) {
	ctx := context.Background()

	t.Run("success list empty", func(t *testing.T) {
		lb := newTestLocalBackend(t)
		defer lb.Close()

		keys, err := lb.ListKeys(ctx)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if len(keys) != 0 {
			t.Errorf("expected 0 keys, got %d", len(keys))
		}
	})

	t.Run("success list multiple keys", func(t *testing.T) {
		lb := newTestLocalBackend(t)
		defer lb.Close()

		// Generate multiple keys
		_, err := lb.GenerateKey(ctx, "list-key-1", KeyTypeEd25519, nil)
		if err != nil {
			t.Fatalf("failed to generate key: %v", err)
		}
		_, err = lb.GenerateKey(ctx, "list-key-2", KeyTypeRSA, &GenerateOptions{Bits: types.RSAKeySize2048})
		if err != nil {
			t.Fatalf("failed to generate key: %v", err)
		}
		_, err = lb.GenerateKey(ctx, "list-key-3", KeyTypeECDSA, nil)
		if err != nil {
			t.Fatalf("failed to generate key: %v", err)
		}

		keys, err := lb.ListKeys(ctx)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if len(keys) != 3 {
			t.Errorf("expected 3 keys, got %d", len(keys))
		}

		// Verify sorted order
		for i := 1; i < len(keys); i++ {
			if keys[i-1].KeyID >= keys[i].KeyID {
				t.Errorf("keys not sorted: %s >= %s", keys[i-1].KeyID, keys[i].KeyID)
			}
		}
	})

	t.Run("error after close", func(t *testing.T) {
		lb := newTestLocalBackend(t)
		lb.Close()

		_, err := lb.ListKeys(ctx)
		if err == nil {
			t.Fatal("expected error after close")
		}
		if !errors.Is(err, ErrBackendClosed) {
			t.Errorf("expected ErrBackendClosed, got %v", err)
		}
	})
}

func TestLocalBackend_DeleteKey(t *testing.T) {
	ctx := context.Background()

	t.Run("success delete key", func(t *testing.T) {
		lb := newTestLocalBackend(t)
		defer lb.Close()

		_, err := lb.GenerateKey(ctx, "delete-test", KeyTypeEd25519, nil)
		if err != nil {
			t.Fatalf("failed to generate key: %v", err)
		}

		err = lb.DeleteKey(ctx, "delete-test")
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		// Verify key is deleted
		_, err = lb.GetPublicKey(ctx, "delete-test")
		if err == nil {
			t.Fatal("expected error after delete")
		}
	})

	t.Run("error delete nonexistent key", func(t *testing.T) {
		lb := newTestLocalBackend(t)
		defer lb.Close()

		err := lb.DeleteKey(ctx, "nonexistent")
		if err == nil {
			t.Fatal("expected error for nonexistent key")
		}
		if !errors.Is(err, ErrBackendKeyNotFound) {
			t.Errorf("expected ErrBackendKeyNotFound, got %v", err)
		}
	})

	t.Run("error after close", func(t *testing.T) {
		lb := newTestLocalBackend(t)
		lb.Close()

		err := lb.DeleteKey(ctx, "test")
		if err == nil {
			t.Fatal("expected error after close")
		}
		if !errors.Is(err, ErrBackendClosed) {
			t.Errorf("expected ErrBackendClosed, got %v", err)
		}
	})
}

func TestLocalBackend_Close(t *testing.T) {
	t.Run("success close", func(t *testing.T) {
		lb := newTestLocalBackend(t)

		err := lb.Close()
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	})

	t.Run("success close idempotent", func(t *testing.T) {
		lb := newTestLocalBackend(t)

		err := lb.Close()
		if err != nil {
			t.Fatalf("expected no error on first close, got %v", err)
		}

		err = lb.Close()
		if err != nil {
			t.Fatalf("expected no error on second close, got %v", err)
		}
	})
}

func TestLocalBackend_SignatureVerification(t *testing.T) {
	ctx := context.Background()

	t.Run("verify ed25519 signature", func(t *testing.T) {
		lb := newTestLocalBackend(t)
		defer lb.Close()

		keyInfo, err := lb.GenerateKey(ctx, "verify-ed25519", KeyTypeEd25519, nil)
		if err != nil {
			t.Fatalf("failed to generate key: %v", err)
		}

		data := []byte("message to sign and verify")
		sig, err := lb.Sign(ctx, keyInfo.KeyID, data, "")
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		// Extract the ed25519 public key
		cryptoPub := keyInfo.PublicKey.(ssh.CryptoPublicKey).CryptoPublicKey()
		ed25519Pub := cryptoPub.(ed25519.PublicKey)

		if !ed25519.Verify(ed25519Pub, data, sig) {
			t.Error("ed25519 signature verification failed")
		}
	})

	t.Run("verify ecdsa signature", func(t *testing.T) {
		lb := newTestLocalBackend(t)
		defer lb.Close()

		keyInfo, err := lb.GenerateKey(ctx, "verify-ecdsa", KeyTypeECDSA, &GenerateOptions{
			Curve: types.CurveP256.String(),
		})
		if err != nil {
			t.Fatalf("failed to generate key: %v", err)
		}

		data := []byte("message to sign and verify")
		sig, err := lb.Sign(ctx, keyInfo.KeyID, data, "")
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		// Extract the ECDSA public key
		cryptoPub := keyInfo.PublicKey.(ssh.CryptoPublicKey).CryptoPublicKey()
		ecdsaPub := cryptoPub.(*ecdsa.PublicKey)

		// Hash the data
		h := computeTestSHA256Hash(data)

		if !ecdsa.VerifyASN1(ecdsaPub, h, sig) {
			t.Error("ecdsa signature verification failed")
		}
	})
}

func TestLocalBackend_KeyPersistence(t *testing.T) {
	ctx := context.Background()

	t.Run("keys persist across operations", func(t *testing.T) {
		backend := storage.NewMemory()
		defer backend.Close()

		// Create backend and generate key
		lb1, err := NewLocalBackend(&LocalBackendConfig{Backend: backend})
		if err != nil {
			t.Fatalf("failed to create backend: %v", err)
		}

		keyInfo1, err := lb1.GenerateKey(ctx, "persist-test", KeyTypeEd25519, nil)
		if err != nil {
			t.Fatalf("failed to generate key: %v", err)
		}

		// Note: In production, you'd use a file backend that persists across
		// backend instances. For this test, we verify the key is stored
		// correctly by creating a new LocalBackend with the same storage.

		// Create new LocalBackend with same storage (simulating restart)
		lb2, err := NewLocalBackend(&LocalBackendConfig{Backend: backend})
		if err != nil {
			t.Fatalf("failed to create second backend: %v", err)
		}
		defer lb2.Close()

		pubKey2, err := lb2.GetPublicKey(ctx, "persist-test")
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if ssh.FingerprintSHA256(pubKey2) != ssh.FingerprintSHA256(keyInfo1.PublicKey) {
			t.Error("public keys do not match after persistence")
		}
	})
}

func TestLocalBackend_InterfaceCompliance(t *testing.T) {
	t.Run("implements KeyBackend interface", func(t *testing.T) {
		lb := newTestLocalBackend(t)
		defer lb.Close()

		// Verify the LocalBackend can be assigned to the KeyBackend interface
		var _ KeyBackend = lb
	})
}

// Helper functions

func newTestLocalBackend(t *testing.T) *LocalBackend {
	t.Helper()

	backend := storage.NewMemory()
	lb, err := NewLocalBackend(&LocalBackendConfig{
		Backend: backend,
	})
	if err != nil {
		t.Fatalf("failed to create local backend: %v", err)
	}

	return lb
}

func encodeTestEd25519PrivateKey(t *testing.T, priv ed25519.PrivateKey) []byte {
	t.Helper()

	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("failed to marshal ed25519 private key: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	})
}

func encodeTestRSAPrivateKey(t *testing.T, priv *rsa.PrivateKey) []byte {
	t.Helper()

	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})
}

func encodeTestECDSAPrivateKey(t *testing.T, priv *ecdsa.PrivateKey) []byte {
	t.Helper()

	der, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("failed to marshal ECDSA private key: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: der,
	})
}

func computeTestSHA256Hash(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}
