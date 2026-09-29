// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

//go:build vault

package vault

import (
	"context"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestVaultSymmetricKey_Raw proves vaultSymmetricKey.Raw refuses to expose
// key material, since it never leaves Vault Transit's engine.
func TestVaultSymmetricKey_Raw(t *testing.T) {
	k := &vaultSymmetricKey{algorithm: "aes256-gcm", keySize: 256, keyName: "test-key"}
	if _, err := k.Raw(); !errors.Is(err, backend.ErrNotSupported) {
		t.Errorf("Raw() error = %v, want ErrNotSupported", err)
	}
}

// TestGenerateSymmetricKey_ValidationErrors proves GenerateSymmetricKey's
// guards: empty CN, a Validate() failure, an asymmetric algorithm, and an
// unsupported (non-256-bit) symmetric key size, none of which should reach
// Vault.
func TestGenerateSymmetricKey_ValidationErrors(t *testing.T) {
	b, double := newVaultTestBackend(t)
	_ = double

	t.Run("empty CN", func(t *testing.T) {
		attrs := &types.KeyAttributes{SymmetricAlgorithm: types.SymmetricAES256GCM}
		if _, err := b.GenerateSymmetricKey(context.Background(), attrs); !errors.Is(err, backend.ErrInvalidAttributes) {
			t.Errorf("GenerateSymmetricKey() error = %v, want ErrInvalidAttributes", err)
		}
	})

	t.Run("asymmetric algorithm", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "generate-symmetric-asymmetric-attrs",
			StoreType:    backend.STORE_VAULT,
			KeyType:      backend.KEY_TYPE_SIGNING,
			KeyAlgorithm: x509.RSA,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}
		if _, err := b.GenerateSymmetricKey(context.Background(), attrs); !errors.Is(err, backend.ErrInvalidKeyType) {
			t.Errorf("GenerateSymmetricKey() error = %v, want ErrInvalidKeyType", err)
		}
	})

	t.Run("unsupported key size", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:                 "generate-symmetric-wrong-size",
			StoreType:          backend.STORE_VAULT,
			KeyType:            backend.KEY_TYPE_SECRET,
			SymmetricAlgorithm: types.SymmetricAES128GCM,
		}
		if _, err := b.GenerateSymmetricKey(context.Background(), attrs); !errors.Is(err, backend.ErrInvalidAlgorithm) {
			t.Errorf("GenerateSymmetricKey() error = %v, want ErrInvalidAlgorithm", err)
		}
	})
}

// TestGetSymmetricKey_ValidationErrors proves GetSymmetricKey's guards:
// empty CN and an asymmetric algorithm, before any storage or Vault lookup.
func TestGetSymmetricKey_ValidationErrors(t *testing.T) {
	b, double := newVaultTestBackend(t)
	_ = double

	t.Run("empty CN", func(t *testing.T) {
		attrs := &types.KeyAttributes{SymmetricAlgorithm: types.SymmetricAES256GCM}
		if _, err := b.GetSymmetricKey(context.Background(), attrs); !errors.Is(err, backend.ErrInvalidAttributes) {
			t.Errorf("GetSymmetricKey() error = %v, want ErrInvalidAttributes", err)
		}
	})

	t.Run("asymmetric algorithm", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "get-symmetric-asymmetric-attrs",
			StoreType:    backend.STORE_VAULT,
			KeyType:      backend.KEY_TYPE_SIGNING,
			KeyAlgorithm: x509.RSA,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}
		if _, err := b.GetSymmetricKey(context.Background(), attrs); !errors.Is(err, backend.ErrInvalidKeyType) {
			t.Errorf("GetSymmetricKey() error = %v, want ErrInvalidKeyType", err)
		}
	})
}

// TestGetSymmetricKey_CorruptMetadata proves a metadata record that is not
// valid JSON is reported as an unmarshal failure rather than a silent zero
// value.
func TestGetSymmetricKey_CorruptMetadata(t *testing.T) {
	b, double := newVaultTestBackend(t)
	_ = double

	attrs := &types.KeyAttributes{CN: "get-symmetric-corrupt-metadata", SymmetricAlgorithm: types.SymmetricAES256GCM}
	if err := storage.SaveKey(context.Background(), b.config.KeyStorage, attrs.CN, []byte("not json")); err != nil {
		t.Fatalf("SaveKey() error = %v", err)
	}
	if _, err := b.GetSymmetricKey(context.Background(), attrs); err == nil {
		t.Error("GetSymmetricKey() expected an unmarshal error for corrupt metadata, got nil")
	}
}

// TestGetSymmetricKey_NotMarkedSymmetric proves metadata whose "symmetric"
// flag is false or absent is refused instead of treated as a symmetric key.
func TestGetSymmetricKey_NotMarkedSymmetric(t *testing.T) {
	b, double := newVaultTestBackend(t)
	_ = double

	attrs := &types.KeyAttributes{CN: "get-symmetric-not-marked", StoreType: backend.STORE_VAULT, KeyType: backend.KEY_TYPE_SECRET, SymmetricAlgorithm: types.SymmetricAES256GCM}
	if err := storage.SaveKey(context.Background(), b.config.KeyStorage, attrs.CN, []byte(`{"cn":"get-symmetric-not-marked"}`)); err != nil {
		t.Fatalf("SaveKey() error = %v", err)
	}
	if _, err := b.GetSymmetricKey(context.Background(), attrs); !errors.Is(err, backend.ErrInvalidKeyType) {
		t.Errorf("GetSymmetricKey() error = %v, want ErrInvalidKeyType", err)
	}
}

// TestGetSymmetricKey_MissingVaultName proves metadata marked symmetric but
// missing vault_name is reported rather than passed on as an empty Transit
// key name.
func TestGetSymmetricKey_MissingVaultName(t *testing.T) {
	b, double := newVaultTestBackend(t)
	_ = double

	attrs := &types.KeyAttributes{CN: "get-symmetric-missing-vaultname", SymmetricAlgorithm: types.SymmetricAES256GCM}
	if err := storage.SaveKey(context.Background(), b.config.KeyStorage, attrs.CN, []byte(`{"symmetric":true}`)); err != nil {
		t.Fatalf("SaveKey() error = %v", err)
	}
	if _, err := b.GetSymmetricKey(context.Background(), attrs); !errors.Is(err, backend.ErrInvalidAttributes) {
		t.Errorf("GetSymmetricKey() error = %v, want ErrInvalidAttributes", err)
	}
}

// TestSymmetricEncrypter_ValidationErrors mirrors
// TestGetSymmetricKey_ValidationErrors for SymmetricEncrypter.
func TestSymmetricEncrypter_ValidationErrors(t *testing.T) {
	b, double := newVaultTestBackend(t)
	_ = double

	t.Run("empty CN", func(t *testing.T) {
		attrs := &types.KeyAttributes{SymmetricAlgorithm: types.SymmetricAES256GCM}
		if _, err := b.SymmetricEncrypter(context.Background(), attrs); !errors.Is(err, backend.ErrInvalidAttributes) {
			t.Errorf("SymmetricEncrypter() error = %v, want ErrInvalidAttributes", err)
		}
	})

	t.Run("asymmetric algorithm", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "symmetric-encrypter-asymmetric-attrs",
			StoreType:    backend.STORE_VAULT,
			KeyType:      backend.KEY_TYPE_SIGNING,
			KeyAlgorithm: x509.RSA,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}
		if _, err := b.SymmetricEncrypter(context.Background(), attrs); !errors.Is(err, backend.ErrInvalidKeyType) {
			t.Errorf("SymmetricEncrypter() error = %v, want ErrInvalidKeyType", err)
		}
	})
}

// TestSymmetricEncrypter_CorruptMetadata mirrors
// TestGetSymmetricKey_CorruptMetadata for SymmetricEncrypter.
func TestSymmetricEncrypter_CorruptMetadata(t *testing.T) {
	b, double := newVaultTestBackend(t)
	_ = double

	attrs := &types.KeyAttributes{CN: "symmetric-encrypter-corrupt-metadata", SymmetricAlgorithm: types.SymmetricAES256GCM}
	if err := storage.SaveKey(context.Background(), b.config.KeyStorage, attrs.CN, []byte("not json")); err != nil {
		t.Fatalf("SaveKey() error = %v", err)
	}
	if _, err := b.SymmetricEncrypter(context.Background(), attrs); err == nil {
		t.Error("SymmetricEncrypter() expected an unmarshal error for corrupt metadata, got nil")
	}
}

// TestSymmetricEncrypter_MissingVaultName mirrors
// TestGetSymmetricKey_MissingVaultName for SymmetricEncrypter.
func TestSymmetricEncrypter_MissingVaultName(t *testing.T) {
	b, double := newVaultTestBackend(t)
	_ = double

	attrs := &types.KeyAttributes{CN: "symmetric-encrypter-missing-vaultname", SymmetricAlgorithm: types.SymmetricAES256GCM}
	if err := storage.SaveKey(context.Background(), b.config.KeyStorage, attrs.CN, []byte(`{"symmetric":true}`)); err != nil {
		t.Fatalf("SaveKey() error = %v", err)
	}
	if _, err := b.SymmetricEncrypter(context.Background(), attrs); !errors.Is(err, backend.ErrInvalidAttributes) {
		t.Errorf("SymmetricEncrypter() error = %v, want ErrInvalidAttributes", err)
	}
}

// TestVaultSymmetricEncrypterEncrypt_RejectsNonDefaultTagSize proves Encrypt
// refuses a caller-specified tag size, since Vault Transit's ciphertext
// string is self-describing and does not allow choosing the tag length.
func TestVaultSymmetricEncrypterEncrypt_RejectsNonDefaultTagSize(t *testing.T) {
	b, double := newVaultTestBackend(t)
	_ = double
	e := &vaultSymmetricEncrypter{
		backend: b,
		keyName: "tagsize-test",
		attrs:   &types.KeyAttributes{CN: "tagsize-test", SymmetricAlgorithm: types.SymmetricAES256GCM},
	}
	if _, err := e.Encrypt([]byte("plaintext"), &types.EncryptOptions{TagSize: 8}); err == nil {
		t.Error("Encrypt() expected error for non-default TagSize, got nil")
	}
}

// TestVaultSymmetricEncrypterEncrypt_RejectsCallerNonce proves Encrypt
// refuses a caller-supplied nonce rather than silently dropping it: Vault
// Transit's encrypt endpoint manages nonce generation server-side and
// exposes no parameter to override it (go-xkms#1223).
func TestVaultSymmetricEncrypterEncrypt_RejectsCallerNonce(t *testing.T) {
	b, double := newVaultTestBackend(t)
	_ = double
	e := &vaultSymmetricEncrypter{
		backend: b,
		keyName: "nonce-test",
		attrs:   &types.KeyAttributes{CN: "nonce-test", SymmetricAlgorithm: types.SymmetricAES256GCM},
	}
	_, err := e.Encrypt([]byte("plaintext"), &types.EncryptOptions{Nonce: []byte("123456789012")})
	if !errors.Is(err, backend.ErrCallerNonceNotSupported) {
		t.Errorf("Encrypt() error = %v, want backend.ErrCallerNonceNotSupported", err)
	}
}

// TestVaultSymmetricEncrypterDecrypt_RejectsNonDefaultTagSize mirrors
// TestVaultSymmetricEncrypterEncrypt_RejectsNonDefaultTagSize for Decrypt.
func TestVaultSymmetricEncrypterDecrypt_RejectsNonDefaultTagSize(t *testing.T) {
	b, double := newVaultTestBackend(t)
	_ = double
	e := &vaultSymmetricEncrypter{
		backend: b,
		keyName: "tagsize-test",
		attrs:   &types.KeyAttributes{CN: "tagsize-test", SymmetricAlgorithm: types.SymmetricAES256GCM},
	}
	if _, err := e.Decrypt(&types.EncryptedData{Ciphertext: []byte("vault:v1:ciphertext")}, &types.DecryptOptions{TagSize: 8}); err == nil {
		t.Error("Decrypt() expected error for non-default TagSize, got nil")
	}
}
