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
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

func TestNewXKMSdBackend(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		client := NewMockClient()
		backend, err := NewXKMSdBackend(client, "software")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if backend == nil {
			t.Fatal("expected non-nil backend")
		}
		if backend.Backend() != "software" {
			t.Errorf("expected backend 'software', got '%s'", backend.Backend())
		}
		if backend.Client() != client {
			t.Error("expected client to match")
		}
	})

	t.Run("nil_client", func(t *testing.T) {
		_, err := NewXKMSdBackend(nil, "software")
		if !errors.Is(err, ErrBackendNilClient) {
			t.Errorf("expected ErrBackendNilClient, got %v", err)
		}
	})

	t.Run("empty_backend_name", func(t *testing.T) {
		client := NewMockClient()
		_, err := NewXKMSdBackend(client, "")
		if !errors.Is(err, ErrBackendEmptyName) {
			t.Errorf("expected ErrBackendEmptyName, got %v", err)
		}
	})
}

func TestXKMSdBackend_ListKeys(t *testing.T) {
	t.Run("success_with_ssh_compatible_keys", func(t *testing.T) {
		client := NewMockClient()
		if err := client.AddEd25519Key("software", "key1"); err != nil {
			t.Fatalf("failed to add key: %v", err)
		}
		if err := client.AddRSAKey("software", "key2", 2048); err != nil {
			t.Fatalf("failed to add key: %v", err)
		}
		if err := client.AddECDSAKey("software", "key3", elliptic.P256()); err != nil {
			t.Fatalf("failed to add key: %v", err)
		}

		backend, err := NewXKMSdBackend(client, "software")
		if err != nil {
			t.Fatalf("failed to create backend: %v", err)
		}

		ctx := context.Background()
		keys, err := backend.ListKeys(ctx)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(keys) != 3 {
			t.Errorf("expected 3 keys, got %d", len(keys))
		}

		// Verify each key has a public key and fingerprint
		for _, key := range keys {
			if key.PublicKey == nil {
				t.Errorf("key %s has nil public key", key.KeyID)
			}
			if key.Fingerprint == "" {
				t.Errorf("key %s has empty fingerprint", key.KeyID)
			}
		}
	})

	t.Run("filters_non_ssh_keys", func(t *testing.T) {
		client := NewMockClient()
		if err := client.AddEd25519Key("software", "ssh-key"); err != nil {
			t.Fatalf("failed to add key: %v", err)
		}
		// Add a non-SSH key type (symmetric)
		client.AddKeyWithType("software", "aes-key", "aes-256")

		backend, err := NewXKMSdBackend(client, "software")
		if err != nil {
			t.Fatalf("failed to create backend: %v", err)
		}

		ctx := context.Background()
		keys, err := backend.ListKeys(ctx)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Should only return SSH-compatible key
		if len(keys) != 1 {
			t.Errorf("expected 1 key, got %d", len(keys))
		}
	})

	t.Run("list_error", func(t *testing.T) {
		client := NewMockClient()
		client.SetListError(errors.New("list failed"))

		backend, err := NewXKMSdBackend(client, "software")
		if err != nil {
			t.Fatalf("failed to create backend: %v", err)
		}

		ctx := context.Background()
		_, err = backend.ListKeys(ctx)
		if err == nil {
			t.Fatal("expected error")
		}
		if !errors.Is(err, ErrBackendListFailed) {
			t.Errorf("expected ErrBackendListFailed, got %v", err)
		}
	})

	t.Run("empty_list", func(t *testing.T) {
		client := NewMockClient()
		backend, err := NewXKMSdBackend(client, "software")
		if err != nil {
			t.Fatalf("failed to create backend: %v", err)
		}

		ctx := context.Background()
		keys, err := backend.ListKeys(ctx)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(keys) != 0 {
			t.Errorf("expected 0 keys, got %d", len(keys))
		}
	})
}

func TestXKMSdBackend_GetPublicKey(t *testing.T) {
	t.Run("success_ed25519", func(t *testing.T) {
		client := NewMockClient()
		if err := client.AddEd25519Key("software", "test-key"); err != nil {
			t.Fatalf("failed to add key: %v", err)
		}

		backend, err := NewXKMSdBackend(client, "software")
		if err != nil {
			t.Fatalf("failed to create backend: %v", err)
		}

		ctx := context.Background()
		pubKey, err := backend.GetPublicKey(ctx, "test-key")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if pubKey == nil {
			t.Fatal("expected non-nil public key")
		}
		if pubKey.Type() != "ssh-ed25519" {
			t.Errorf("expected ssh-ed25519, got %s", pubKey.Type())
		}
	})

	t.Run("success_rsa", func(t *testing.T) {
		client := NewMockClient()
		if err := client.AddRSAKey("software", "rsa-key", 2048); err != nil {
			t.Fatalf("failed to add key: %v", err)
		}

		backend, err := NewXKMSdBackend(client, "software")
		if err != nil {
			t.Fatalf("failed to create backend: %v", err)
		}

		ctx := context.Background()
		pubKey, err := backend.GetPublicKey(ctx, "rsa-key")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if pubKey == nil {
			t.Fatal("expected non-nil public key")
		}
		if pubKey.Type() != "ssh-rsa" {
			t.Errorf("expected ssh-rsa, got %s", pubKey.Type())
		}
	})

	t.Run("success_ecdsa", func(t *testing.T) {
		client := NewMockClient()
		if err := client.AddECDSAKey("software", "ecdsa-key", elliptic.P256()); err != nil {
			t.Fatalf("failed to add key: %v", err)
		}

		backend, err := NewXKMSdBackend(client, "software")
		if err != nil {
			t.Fatalf("failed to create backend: %v", err)
		}

		ctx := context.Background()
		pubKey, err := backend.GetPublicKey(ctx, "ecdsa-key")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if pubKey == nil {
			t.Fatal("expected non-nil public key")
		}
		if pubKey.Type() != "ecdsa-sha2-nistp256" {
			t.Errorf("expected ecdsa-sha2-nistp256, got %s", pubKey.Type())
		}
	})

	t.Run("key_not_found", func(t *testing.T) {
		client := NewMockClient()
		backend, err := NewXKMSdBackend(client, "software")
		if err != nil {
			t.Fatalf("failed to create backend: %v", err)
		}

		ctx := context.Background()
		_, err = backend.GetPublicKey(ctx, "nonexistent")
		if err == nil {
			t.Fatal("expected error")
		}
		if !errors.Is(err, ErrBackendGetKeyFailed) {
			t.Errorf("expected ErrBackendGetKeyFailed, got %v", err)
		}
	})

	t.Run("empty_pem", func(t *testing.T) {
		client := NewMockClient()
		client.AddKeyWithEmptyPEM("software", "bad-key", "Ed25519")

		backend, err := NewXKMSdBackend(client, "software")
		if err != nil {
			t.Fatalf("failed to create backend: %v", err)
		}

		ctx := context.Background()
		_, err = backend.GetPublicKey(ctx, "bad-key")
		if err == nil {
			t.Fatal("expected error")
		}
		if !errors.Is(err, ErrBackendNoPublicKey) {
			t.Errorf("expected ErrBackendNoPublicKey, got %v", err)
		}
	})

	t.Run("invalid_pem", func(t *testing.T) {
		client := NewMockClient()
		client.AddKeyWithInvalidPEM("software", "bad-key", "Ed25519")

		backend, err := NewXKMSdBackend(client, "software")
		if err != nil {
			t.Fatalf("failed to create backend: %v", err)
		}

		ctx := context.Background()
		_, err = backend.GetPublicKey(ctx, "bad-key")
		if err == nil {
			t.Fatal("expected error")
		}
		if !errors.Is(err, ErrBackendInvalidPEM) {
			t.Errorf("expected ErrBackendInvalidPEM, got %v", err)
		}
	})

	t.Run("invalid_der", func(t *testing.T) {
		client := NewMockClient()
		client.AddKeyWithInvalidDER("software", "bad-key", "Ed25519")

		backend, err := NewXKMSdBackend(client, "software")
		if err != nil {
			t.Fatalf("failed to create backend: %v", err)
		}

		ctx := context.Background()
		_, err = backend.GetPublicKey(ctx, "bad-key")
		if err == nil {
			t.Fatal("expected error")
		}
		if !errors.Is(err, ErrBackendParseFailed) {
			t.Errorf("expected ErrBackendParseFailed, got %v", err)
		}
	})
}

func TestXKMSdBackend_Sign(t *testing.T) {
	t.Run("success_ed25519", func(t *testing.T) {
		client := NewMockClient()
		if err := client.AddEd25519Key("software", "sign-key"); err != nil {
			t.Fatalf("failed to add key: %v", err)
		}

		backend, err := NewXKMSdBackend(client, "software")
		if err != nil {
			t.Fatalf("failed to create backend: %v", err)
		}

		ctx := context.Background()
		data := []byte("test data to sign")
		sig, err := backend.Sign(ctx, "sign-key", data, "ed25519")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(sig) == 0 {
			t.Error("expected non-empty signature")
		}
	})

	t.Run("success_rsa", func(t *testing.T) {
		client := NewMockClient()
		if err := client.AddRSAKey("software", "rsa-sign-key", 2048); err != nil {
			t.Fatalf("failed to add key: %v", err)
		}

		backend, err := NewXKMSdBackend(client, "software")
		if err != nil {
			t.Fatalf("failed to create backend: %v", err)
		}

		ctx := context.Background()
		data := []byte("test data to sign")
		sig, err := backend.Sign(ctx, "rsa-sign-key", data, "rsa-sha256")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(sig) == 0 {
			t.Error("expected non-empty signature")
		}
	})

	t.Run("sign_error", func(t *testing.T) {
		client := NewMockClient()
		if err := client.AddEd25519Key("software", "sign-key"); err != nil {
			t.Fatalf("failed to add key: %v", err)
		}
		client.SetSignError(errors.New("signing failed"))

		backend, err := NewXKMSdBackend(client, "software")
		if err != nil {
			t.Fatalf("failed to create backend: %v", err)
		}

		ctx := context.Background()
		_, err = backend.Sign(ctx, "sign-key", []byte("data"), "ed25519")
		if err == nil {
			t.Fatal("expected error")
		}
		if !errors.Is(err, ErrBackendSignFailed) {
			t.Errorf("expected ErrBackendSignFailed, got %v", err)
		}
	})
}

func TestXKMSdBackend_GenerateKey(t *testing.T) {
	t.Run("success_ed25519", func(t *testing.T) {
		client := NewMockClient()
		backend, err := NewXKMSdBackend(client, "software")
		if err != nil {
			t.Fatalf("failed to create backend: %v", err)
		}

		ctx := context.Background()
		keyInfo, err := backend.GenerateKey(ctx, "new-ed25519-key", KeyTypeEd25519, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if keyInfo == nil {
			t.Fatal("expected non-nil key info")
		}
		if keyInfo.KeyID != "new-ed25519-key" {
			t.Errorf("expected key ID 'new-ed25519-key', got '%s'", keyInfo.KeyID)
		}
		if keyInfo.PublicKey == nil {
			t.Error("expected non-nil public key")
		}
		if keyInfo.Fingerprint == "" {
			t.Error("expected non-empty fingerprint")
		}
	})

	t.Run("success_rsa", func(t *testing.T) {
		client := NewMockClient()
		backend, err := NewXKMSdBackend(client, "software")
		if err != nil {
			t.Fatalf("failed to create backend: %v", err)
		}

		ctx := context.Background()
		opts := &GenerateOptions{Bits: 2048}
		keyInfo, err := backend.GenerateKey(ctx, "new-rsa-key", KeyTypeRSA, opts)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if keyInfo == nil {
			t.Fatal("expected non-nil key info")
		}
		if keyInfo.KeyID != "new-rsa-key" {
			t.Errorf("expected key ID 'new-rsa-key', got '%s'", keyInfo.KeyID)
		}
	})

	t.Run("success_ecdsa", func(t *testing.T) {
		client := NewMockClient()
		backend, err := NewXKMSdBackend(client, "software")
		if err != nil {
			t.Fatalf("failed to create backend: %v", err)
		}

		ctx := context.Background()
		opts := &GenerateOptions{Curve: "P-256"}
		keyInfo, err := backend.GenerateKey(ctx, "new-ecdsa-key", KeyTypeECDSA, opts)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if keyInfo == nil {
			t.Fatal("expected non-nil key info")
		}
	})

	t.Run("empty_key_id", func(t *testing.T) {
		client := NewMockClient()
		backend, err := NewXKMSdBackend(client, "software")
		if err != nil {
			t.Fatalf("failed to create backend: %v", err)
		}

		ctx := context.Background()
		_, err = backend.GenerateKey(ctx, "", KeyTypeEd25519, nil)
		if err == nil {
			t.Fatal("expected error")
		}
		if !errors.Is(err, ErrBackendEmptyKeyID) {
			t.Errorf("expected ErrBackendEmptyKeyID, got %v", err)
		}
	})

	t.Run("unsupported_key_type", func(t *testing.T) {
		client := NewMockClient()
		backend, err := NewXKMSdBackend(client, "software")
		if err != nil {
			t.Fatalf("failed to create backend: %v", err)
		}

		ctx := context.Background()
		_, err = backend.GenerateKey(ctx, "bad-key", "unknown", nil)
		if err == nil {
			t.Fatal("expected error")
		}
		if !errors.Is(err, ErrBackendUnsupportedKeyType) {
			t.Errorf("expected ErrBackendUnsupportedKeyType, got %v", err)
		}
	})

	t.Run("generate_error", func(t *testing.T) {
		client := NewMockClient()
		client.SetGenerateError(errors.New("generation failed"))

		backend, err := NewXKMSdBackend(client, "software")
		if err != nil {
			t.Fatalf("failed to create backend: %v", err)
		}

		ctx := context.Background()
		_, err = backend.GenerateKey(ctx, "fail-key", KeyTypeEd25519, nil)
		if err == nil {
			t.Fatal("expected error")
		}
		if !errors.Is(err, ErrBackendGenerateFailed) {
			t.Errorf("expected ErrBackendGenerateFailed, got %v", err)
		}
	})

	t.Run("with_comment", func(t *testing.T) {
		client := NewMockClient()
		backend, err := NewXKMSdBackend(client, "software")
		if err != nil {
			t.Fatalf("failed to create backend: %v", err)
		}

		ctx := context.Background()
		opts := &GenerateOptions{Comment: "test key comment"}
		keyInfo, err := backend.GenerateKey(ctx, "commented-key", KeyTypeEd25519, opts)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if keyInfo.Comment != "test key comment" {
			t.Errorf("expected comment 'test key comment', got '%s'", keyInfo.Comment)
		}
	})
}

func TestXKMSdBackend_ImportKey(t *testing.T) {
	t.Run("success_rsa_private_key", func(t *testing.T) {
		client := NewMockClient()
		backend, err := NewXKMSdBackend(client, "software")
		if err != nil {
			t.Fatalf("failed to create backend: %v", err)
		}

		ctx := context.Background()
		// Generate a real RSA private key for testing
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("failed to generate RSA key: %v", err)
		}
		rsaPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(rsaKey),
		})

		keyInfo, err := backend.ImportKey(ctx, "imported-rsa", rsaPEM)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if keyInfo == nil {
			t.Fatal("expected non-nil key info")
		}
		if keyInfo.KeyID != "imported-rsa" {
			t.Errorf("expected key ID 'imported-rsa', got '%s'", keyInfo.KeyID)
		}
	})

	t.Run("success_ec_private_key", func(t *testing.T) {
		client := NewMockClient()
		backend, err := NewXKMSdBackend(client, "software")
		if err != nil {
			t.Fatalf("failed to create backend: %v", err)
		}

		ctx := context.Background()
		// Generate a real EC private key for testing
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate EC key: %v", err)
		}
		ecBytes, err := x509.MarshalECPrivateKey(ecKey)
		if err != nil {
			t.Fatalf("failed to marshal EC key: %v", err)
		}
		ecPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: ecBytes,
		})

		keyInfo, err := backend.ImportKey(ctx, "imported-ec", ecPEM)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if keyInfo == nil {
			t.Fatal("expected non-nil key info")
		}
	})

	t.Run("success_pkcs8_private_key", func(t *testing.T) {
		client := NewMockClient()
		backend, err := NewXKMSdBackend(client, "software")
		if err != nil {
			t.Fatalf("failed to create backend: %v", err)
		}

		ctx := context.Background()
		// Generate an Ed25519 key and encode as PKCS#8
		_, privKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate Ed25519 key: %v", err)
		}
		pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(privKey)
		if err != nil {
			t.Fatalf("failed to marshal PKCS#8: %v", err)
		}
		pkcs8PEM := pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: pkcs8Bytes,
		})

		keyInfo, err := backend.ImportKey(ctx, "imported-pkcs8", pkcs8PEM)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if keyInfo == nil {
			t.Fatal("expected non-nil key info")
		}
	})

	t.Run("empty_key_id", func(t *testing.T) {
		client := NewMockClient()
		backend, err := NewXKMSdBackend(client, "software")
		if err != nil {
			t.Fatalf("failed to create backend: %v", err)
		}

		ctx := context.Background()
		_, err = backend.ImportKey(ctx, "", []byte("key"))
		if err == nil {
			t.Fatal("expected error")
		}
		if !errors.Is(err, ErrBackendEmptyKeyID) {
			t.Errorf("expected ErrBackendEmptyKeyID, got %v", err)
		}
	})

	t.Run("invalid_pem", func(t *testing.T) {
		client := NewMockClient()
		backend, err := NewXKMSdBackend(client, "software")
		if err != nil {
			t.Fatalf("failed to create backend: %v", err)
		}

		ctx := context.Background()
		_, err = backend.ImportKey(ctx, "bad-import", []byte("not-valid-pem"))
		if err == nil {
			t.Fatal("expected error")
		}
		if !errors.Is(err, ErrBackendInvalidKeyData) {
			t.Errorf("expected ErrBackendInvalidKeyData, got %v", err)
		}
	})

	t.Run("import_error", func(t *testing.T) {
		client := NewMockClient()
		client.SetImportError(errors.New("import failed"))

		backend, err := NewXKMSdBackend(client, "software")
		if err != nil {
			t.Fatalf("failed to create backend: %v", err)
		}

		ctx := context.Background()
		// Generate a real RSA private key for testing
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("failed to generate RSA key: %v", err)
		}
		rsaPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(rsaKey),
		})
		_, err = backend.ImportKey(ctx, "fail-import", rsaPEM)
		if err == nil {
			t.Fatal("expected error")
		}
		if !errors.Is(err, ErrBackendImportFailed) {
			t.Errorf("expected ErrBackendImportFailed, got %v", err)
		}
	})
}

func TestXKMSdBackend_DeleteKey(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		client := NewMockClient()
		if err := client.AddEd25519Key("software", "delete-me"); err != nil {
			t.Fatalf("failed to add key: %v", err)
		}

		backend, err := NewXKMSdBackend(client, "software")
		if err != nil {
			t.Fatalf("failed to create backend: %v", err)
		}

		ctx := context.Background()

		// Verify key exists
		keys, err := backend.ListKeys(ctx)
		if err != nil {
			t.Fatalf("failed to list keys: %v", err)
		}
		if len(keys) != 1 {
			t.Fatalf("expected 1 key, got %d", len(keys))
		}

		// Delete the key
		err = backend.DeleteKey(ctx, "delete-me")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Verify key is gone
		keys, err = backend.ListKeys(ctx)
		if err != nil {
			t.Fatalf("failed to list keys: %v", err)
		}
		if len(keys) != 0 {
			t.Errorf("expected 0 keys, got %d", len(keys))
		}
	})

	t.Run("empty_key_id", func(t *testing.T) {
		client := NewMockClient()
		backend, err := NewXKMSdBackend(client, "software")
		if err != nil {
			t.Fatalf("failed to create backend: %v", err)
		}

		ctx := context.Background()
		err = backend.DeleteKey(ctx, "")
		if err == nil {
			t.Fatal("expected error")
		}
		if !errors.Is(err, ErrBackendEmptyKeyID) {
			t.Errorf("expected ErrBackendEmptyKeyID, got %v", err)
		}
	})

	t.Run("delete_error", func(t *testing.T) {
		client := NewMockClient()
		client.SetDeleteError(errors.New("delete failed"))

		backend, err := NewXKMSdBackend(client, "software")
		if err != nil {
			t.Fatalf("failed to create backend: %v", err)
		}

		ctx := context.Background()
		err = backend.DeleteKey(ctx, "some-key")
		if err == nil {
			t.Fatal("expected error")
		}
		if !errors.Is(err, ErrBackendDeleteFailed) {
			t.Errorf("expected ErrBackendDeleteFailed, got %v", err)
		}
	})
}

func TestXKMSdBackend_Close(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		client := NewMockClient()
		backend, err := NewXKMSdBackend(client, "software")
		if err != nil {
			t.Fatalf("failed to create backend: %v", err)
		}

		err = backend.Close()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("close_error", func(t *testing.T) {
		client := NewMockClient()
		client.SetCloseError(errors.New("close failed"))

		backend, err := NewXKMSdBackend(client, "software")
		if err != nil {
			t.Fatalf("failed to create backend: %v", err)
		}

		err = backend.Close()
		if err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestIsSSHCompatibleKeyType(t *testing.T) {
	tests := []struct {
		keyType    string
		compatible bool
	}{
		{"ed25519", true},
		{"Ed25519", true},
		{"ED25519", true},
		{"rsa", true},
		{"RSA", true},
		{"ecdsa", true},
		{"ECDSA", true},
		{"ecdsa-p256", true},
		{"ecdsa-p384", true},
		{"ecdsa-p521", true},
		{"ECDSA-P256", true},
		{"aes-256", false},
		{"AES", false},
		{"hmac-sha256", false},
		{"x25519", false},
		{"", false},
		{"unknown", false},
	}

	for _, tt := range tests {
		t.Run(tt.keyType, func(t *testing.T) {
			result := isSSHCompatibleKeyType(tt.keyType)
			if result != tt.compatible {
				t.Errorf("isSSHCompatibleKeyType(%q) = %v, want %v", tt.keyType, result, tt.compatible)
			}
		})
	}
}

func TestParsePublicKeyFromDER(t *testing.T) {
	t.Run("unsupported_key_type", func(t *testing.T) {
		_, err := parsePublicKeyFromDER([]byte("data"), "unsupported-type")
		if err == nil {
			t.Fatal("expected error for unsupported key type")
		}
	})
}

func TestDetectKeyTypeFromPEM(t *testing.T) {
	tests := []struct {
		name     string
		pemType  string
		expected string
	}{
		{"rsa_private_key", "RSA PRIVATE KEY", string(types.AlgorithmRSA)},
		{"ec_private_key", "EC PRIVATE KEY", string(types.AlgorithmECDSA)},
		{"openssh_private_key", "OPENSSH PRIVATE KEY", string(types.AlgorithmEd25519)},
		{"generic_private_key", "PRIVATE KEY", string(types.AlgorithmEd25519)},
		{"unknown", "UNKNOWN TYPE", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			block := &pem.Block{Type: tt.pemType}
			result := detectKeyTypeFromPEM(block)
			if result != tt.expected {
				t.Errorf("detectKeyTypeFromPEM(%q) = %q, want %q", tt.pemType, result, tt.expected)
			}
		})
	}
}

func TestXKMSdBackendImplementsInterface(t *testing.T) {
	// This test verifies that XKMSdBackend implements KeyBackend at compile time
	var _ KeyBackend = (*XKMSdBackend)(nil)
}
