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

//go:build awskms

package awskms

import (
	"context"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestSymmetricKey_Raw proves awsKMSSymmetricKey.Raw refuses to expose key
// material, since it never leaves AWS KMS's HSM boundary.
func TestSymmetricKey_Raw(t *testing.T) {
	k := &awsKMSSymmetricKey{algorithm: "aes256-gcm", keySize: 256, keyID: "test-key-id"}
	if _, err := k.Raw(); !errors.Is(err, backend.ErrNotSupported) {
		t.Errorf("Raw() error = %v, want ErrNotSupported", err)
	}
}

// TestGenerateSymmetricKey_InvalidAttributes proves GenerateSymmetricKey
// rejects attributes that fail types.KeyAttributes.Validate (an empty CN)
// before ever calling KMS.
func TestGenerateSymmetricKey_InvalidAttributes(t *testing.T) {
	b, err := NewBackendWithClient(&Config{
		Region:      "us-east-1",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}, &MockKMSClient{})
	if err != nil {
		t.Fatalf("NewBackendWithClient() error = %v", err)
	}
	attrs := &types.KeyAttributes{
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_AWSKMS,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}
	if _, err := b.GenerateSymmetricKey(context.Background(), attrs); !errors.Is(err, backend.ErrInvalidAttributes) {
		t.Errorf("GenerateSymmetricKey() error = %v, want ErrInvalidAttributes", err)
	}
}

// TestGetSymmetricKey_InvalidAttributes proves GetSymmetricKey rejects
// attributes that fail Validate (an empty CN).
func TestGetSymmetricKey_InvalidAttributes(t *testing.T) {
	b, err := NewBackendWithClient(&Config{
		Region:      "us-east-1",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}, &MockKMSClient{})
	if err != nil {
		t.Fatalf("NewBackendWithClient() error = %v", err)
	}
	attrs := &types.KeyAttributes{
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_AWSKMS,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}
	if _, err := b.GetSymmetricKey(context.Background(), attrs); !errors.Is(err, backend.ErrInvalidAttributes) {
		t.Errorf("GetSymmetricKey() error = %v, want ErrInvalidAttributes", err)
	}
}

// TestGetSymmetricKey_AsymmetricRejected proves GetSymmetricKey refuses a
// well-formed asymmetric key's attributes instead of treating them as a
// symmetric key.
func TestGetSymmetricKey_AsymmetricRejected(t *testing.T) {
	b, err := NewBackendWithClient(&Config{
		Region:      "us-east-1",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}, &MockKMSClient{})
	if err != nil {
		t.Fatalf("NewBackendWithClient() error = %v", err)
	}
	attrs := &types.KeyAttributes{
		CN:           "get-symmetric-asymmetric-attrs",
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_AWSKMS,
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
	}
	if _, err := b.GetSymmetricKey(context.Background(), attrs); !errors.Is(err, backend.ErrInvalidKeyType) {
		t.Errorf("GetSymmetricKey() error = %v, want ErrInvalidKeyType", err)
	}
}

// TestGetSymmetricKey_CorruptMetadata proves a metadata record that isn't
// valid JSON is reported as an unmarshal failure, not treated as missing.
func TestGetSymmetricKey_CorruptMetadata(t *testing.T) {
	mem := storage.New()
	b, err := NewBackendWithClient(&Config{
		Region:      "us-east-1",
		KeyStorage:  mem,
		CertStorage: storage.New(),
	}, &MockKMSClient{})
	if err != nil {
		t.Fatalf("NewBackendWithClient() error = %v", err)
	}
	attrs := &types.KeyAttributes{
		CN:                 "corrupt-symmetric-metadata",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_AWSKMS,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}
	if err := storage.SaveKey(context.Background(), mem, attrs.CN, []byte("not json")); err != nil {
		t.Fatalf("SaveKey() error = %v", err)
	}
	if _, err := b.GetSymmetricKey(context.Background(), attrs); err == nil {
		t.Error("GetSymmetricKey() expected an unmarshal error for corrupt metadata, got nil")
	}
}

// TestGetSymmetricKey_MissingKeyID proves metadata that unmarshals but lacks
// key_id is reported rather than passed on as an empty KMS key ID.
func TestGetSymmetricKey_MissingKeyID(t *testing.T) {
	mem := storage.New()
	b, err := NewBackendWithClient(&Config{
		Region:      "us-east-1",
		KeyStorage:  mem,
		CertStorage: storage.New(),
	}, &MockKMSClient{})
	if err != nil {
		t.Fatalf("NewBackendWithClient() error = %v", err)
	}
	attrs := &types.KeyAttributes{
		CN:                 "missing-keyid-symmetric",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_AWSKMS,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}
	if err := storage.SaveKey(context.Background(), mem, attrs.CN, []byte(`{"alias":"alias/missing-keyid-symmetric"}`)); err != nil {
		t.Fatalf("SaveKey() error = %v", err)
	}
	if _, err := b.GetSymmetricKey(context.Background(), attrs); err == nil {
		t.Error("GetSymmetricKey() expected an error for metadata missing key_id, got nil")
	}
}

// TestSymmetricEncrypter_InvalidAttributes proves SymmetricEncrypter rejects
// attributes that fail Validate.
func TestSymmetricEncrypter_InvalidAttributes(t *testing.T) {
	b, err := NewBackendWithClient(&Config{
		Region:      "us-east-1",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}, &MockKMSClient{})
	if err != nil {
		t.Fatalf("NewBackendWithClient() error = %v", err)
	}
	attrs := &types.KeyAttributes{
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_AWSKMS,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}
	if _, err := b.SymmetricEncrypter(context.Background(), attrs); !errors.Is(err, backend.ErrInvalidAttributes) {
		t.Errorf("SymmetricEncrypter() error = %v, want ErrInvalidAttributes", err)
	}
}

// TestSymmetricEncrypter_AsymmetricRejected proves SymmetricEncrypter
// refuses well-formed asymmetric key attributes.
func TestSymmetricEncrypter_AsymmetricRejected(t *testing.T) {
	b, err := NewBackendWithClient(&Config{
		Region:      "us-east-1",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}, &MockKMSClient{})
	if err != nil {
		t.Fatalf("NewBackendWithClient() error = %v", err)
	}
	attrs := &types.KeyAttributes{
		CN:           "symmetric-encrypter-asymmetric-attrs",
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_AWSKMS,
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
	}
	if _, err := b.SymmetricEncrypter(context.Background(), attrs); !errors.Is(err, backend.ErrInvalidKeyType) {
		t.Errorf("SymmetricEncrypter() error = %v, want ErrInvalidKeyType", err)
	}
}

// TestSymmetricEncrypter_GetKeyIDError proves a corrupt metadata record
// causes SymmetricEncrypter to surface getKeyID's error rather than
// building an encrypter for a key ID it could not resolve.
func TestSymmetricEncrypter_GetKeyIDError(t *testing.T) {
	mem := storage.New()
	b, err := NewBackendWithClient(&Config{
		Region:      "us-east-1",
		KeyStorage:  mem,
		CertStorage: storage.New(),
	}, &MockKMSClient{})
	if err != nil {
		t.Fatalf("NewBackendWithClient() error = %v", err)
	}
	attrs := &types.KeyAttributes{
		CN:                 "symmetric-encrypter-getkeyid-error",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_AWSKMS,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}
	if err := storage.SaveKey(context.Background(), mem, attrs.CN, []byte("not json")); err != nil {
		t.Fatalf("SaveKey() error = %v", err)
	}
	if _, err := b.SymmetricEncrypter(context.Background(), attrs); err == nil {
		t.Error("SymmetricEncrypter() expected an error when getKeyID fails, got nil")
	}
}

// TestSymmetricEncrypterEncrypt_RejectsNonDefaultTagSize proves Encrypt
// refuses a caller-specified tag size: AWS KMS produces a fixed-length tag
// baked into its opaque ciphertext blob, so a non-zero TagSize can never be
// honored.
func TestSymmetricEncrypterEncrypt_RejectsNonDefaultTagSize(t *testing.T) {
	e := &awsKMSSymmetricEncrypter{
		backend: mustBackendWithClient(t, &MockKMSClient{}),
		keyID:   "test-key-id",
		attrs:   &types.KeyAttributes{CN: "tagsize-test", SymmetricAlgorithm: types.SymmetricAES256GCM},
	}
	_, err := e.Encrypt([]byte("plaintext"), &types.EncryptOptions{TagSize: 8})
	if err == nil {
		t.Error("Encrypt() expected error for non-default TagSize, got nil")
	}
}

// TestSymmetricEncrypterDecrypt_RejectsNonDefaultTagSize mirrors
// TestSymmetricEncrypterEncrypt_RejectsNonDefaultTagSize for Decrypt.
func TestSymmetricEncrypterDecrypt_RejectsNonDefaultTagSize(t *testing.T) {
	e := &awsKMSSymmetricEncrypter{
		backend: mustBackendWithClient(t, &MockKMSClient{}),
		keyID:   "test-key-id",
		attrs:   &types.KeyAttributes{CN: "tagsize-test", SymmetricAlgorithm: types.SymmetricAES256GCM},
	}
	_, err := e.Decrypt(&types.EncryptedData{Ciphertext: []byte("ciphertext")}, &types.DecryptOptions{TagSize: 8})
	if err == nil {
		t.Error("Decrypt() expected error for non-default TagSize, got nil")
	}
}

// mustBackendWithClient is a small helper for tests that construct an
// awsKMSSymmetricEncrypter directly (bypassing Backend.SymmetricEncrypter)
// to isolate Encrypt/Decrypt's own validation from key-resolution concerns.
func mustBackendWithClient(t *testing.T, client KMSClient) *Backend {
	t.Helper()
	b, err := NewBackendWithClient(&Config{
		Region:      "us-east-1",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}, client)
	if err != nil {
		t.Fatalf("NewBackendWithClient() error = %v", err)
	}
	return b
}
