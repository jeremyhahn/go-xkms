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

//go:build gcpkms

package gcpkms

import (
	"context"
	"crypto/x509"
	"errors"
	"testing"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

func newImportExportGapsBackend(t *testing.T) (*Backend, *MockKMSClient) {
	t.Helper()
	config := &Config{
		ProjectID:   "test-project",
		LocationID:  "us-central1",
		KeyRingID:   "test-keyring",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}
	mockClient := &MockKMSClient{}
	b, err := NewBackendWithClient(config, mockClient)
	if err != nil {
		t.Fatalf("NewBackendWithClient() error = %v", err)
	}
	return b, mockClient
}

// TestWrapKey_ValidationErrors proves WrapKey's guards against empty key
// material, nil parameters, and a wrapping public key of the wrong
// concrete type, none of which should reach the wrapping ceremony.
func TestWrapKey_ValidationErrors(t *testing.T) {
	b, _ := newImportExportGapsBackend(t)

	t.Run("empty key material", func(t *testing.T) {
		_, err := b.WrapKey(context.Background(), nil, &backend.ImportParameters{Algorithm: backend.WrappingAlgorithmRSAES_OAEP_SHA_256})
		if !errors.Is(err, backend.ErrInvalidAttributes) {
			t.Errorf("WrapKey() error = %v, want ErrInvalidAttributes", err)
		}
	})

	t.Run("nil params", func(t *testing.T) {
		_, err := b.WrapKey(context.Background(), []byte("key-material"), nil)
		if !errors.Is(err, backend.ErrInvalidAttributes) {
			t.Errorf("WrapKey() error = %v, want ErrInvalidAttributes", err)
		}
	})

	t.Run("wrapping key not RSA", func(t *testing.T) {
		_, err := b.WrapKey(context.Background(), []byte("key-material"), &backend.ImportParameters{
			Algorithm:         backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
			WrappingPublicKey: "not-an-rsa-key",
		})
		if !errors.Is(err, backend.ErrInvalidKeyType) {
			t.Errorf("WrapKey() error = %v, want ErrInvalidKeyType", err)
		}
	})

	t.Run("unsupported algorithm", func(t *testing.T) {
		wrappingKey, err := generateTestRSAKey(3072)
		if err != nil {
			t.Fatalf("generateTestRSAKey() error = %v", err)
		}
		_, err = b.WrapKey(context.Background(), []byte("key-material"), &backend.ImportParameters{
			Algorithm:         backend.WrappingAlgorithmRSAES_OAEP_SHA_1,
			WrappingPublicKey: &wrappingKey.PublicKey,
		})
		if !errors.Is(err, backend.ErrInvalidAlgorithm) {
			t.Errorf("WrapKey() error = %v, want ErrInvalidAlgorithm", err)
		}
	})
}

// TestWrapKey_DirectOAEP proves WrapKey's direct RSA-OAEP branch (used for
// small key material such as symmetric keys), which
// TestWrapKey only exercises through the hybrid RSA+AES branch.
func TestWrapKey_DirectOAEP(t *testing.T) {
	b, _ := newImportExportGapsBackend(t)

	wrappingKey, err := generateTestRSAKey(3072)
	if err != nil {
		t.Fatalf("generateTestRSAKey() error = %v", err)
	}

	wrapped, err := b.WrapKey(context.Background(), []byte("short-key-material"), &backend.ImportParameters{
		Algorithm:         backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
		WrappingPublicKey: &wrappingKey.PublicKey,
	})
	if err != nil {
		t.Fatalf("WrapKey() error = %v", err)
	}
	if len(wrapped.WrappedKey) == 0 {
		t.Error("WrapKey() returned empty wrapped key")
	}
}

// TestImportKey_ValidationErrors proves ImportKey's guards against nil
// attributes and nil wrapped material, before reaching GCP KMS.
func TestImportKey_ValidationErrors(t *testing.T) {
	b, _ := newImportExportGapsBackend(t)

	t.Run("nil attrs", func(t *testing.T) {
		err := b.ImportKey(context.Background(), nil, &backend.WrappedKeyMaterial{WrappedKey: []byte("wrapped")})
		if !errors.Is(err, backend.ErrInvalidAttributes) {
			t.Errorf("ImportKey() error = %v, want ErrInvalidAttributes", err)
		}
	})

	t.Run("nil wrapped", func(t *testing.T) {
		attrs := &types.KeyAttributes{CN: "import-key-nil-wrapped", KeyAlgorithm: x509.RSA}
		err := b.ImportKey(context.Background(), attrs, nil)
		if !errors.Is(err, backend.ErrInvalidAttributes) {
			t.Errorf("ImportKey() error = %v, want ErrInvalidAttributes", err)
		}
	})
}

// TestImportKey_UnsupportedWrappingAlgorithm proves ImportKey rejects a
// wrapped-key algorithm it does not recognize instead of sending a
// malformed request to GCP KMS.
func TestImportKey_UnsupportedWrappingAlgorithm(t *testing.T) {
	b, _ := newImportExportGapsBackend(t)

	attrs := &types.KeyAttributes{CN: "import-key-bad-algorithm", KeyAlgorithm: x509.RSA}
	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey:  []byte("wrapped-key-material"),
		Algorithm:   backend.WrappingAlgorithmRSAES_OAEP_SHA_1,
		ImportToken: []byte("test-import-job"),
	}
	if err := b.ImportKey(context.Background(), attrs, wrapped); !errors.Is(err, backend.ErrInvalidAlgorithm) {
		t.Errorf("ImportKey() error = %v, want ErrInvalidAlgorithm", err)
	}
}

// TestImportKey_DirectOAEPAlgorithm proves ImportKey's direct RSA-OAEP
// branch (WrappingAlgorithmRSAES_OAEP_SHA_256 / RSA_OAEP_4096_SHA256),
// which TestImportKey only exercises through the hybrid branch.
func TestImportKey_DirectOAEPAlgorithm(t *testing.T) {
	mockClient := &MockKMSClient{
		ImportCryptoKeyVersionFunc: func(ctx context.Context, req *kmspb.ImportCryptoKeyVersionRequest, opts ...interface{}) (*kmspb.CryptoKeyVersion, error) {
			return &kmspb.CryptoKeyVersion{
				Name:      req.Parent + "/cryptoKeyVersions/1",
				State:     kmspb.CryptoKeyVersion_ENABLED,
				Algorithm: kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256,
			}, nil
		},
	}
	config := &Config{
		ProjectID:   "test-project",
		LocationID:  "us-central1",
		KeyRingID:   "test-keyring",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}
	b, err := NewBackendWithClient(config, mockClient)
	if err != nil {
		t.Fatalf("NewBackendWithClient() error = %v", err)
	}

	attrs := &types.KeyAttributes{CN: "import-key-direct-oaep", KeyAlgorithm: x509.RSA}
	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey:  []byte("wrapped-key-material"),
		Algorithm:   backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
		ImportToken: []byte("test-import-job"),
	}
	if err := b.ImportKey(context.Background(), attrs, wrapped); err != nil {
		t.Fatalf("ImportKey() error = %v", err)
	}
}

// TestImportKey_RPCError proves a ImportCryptoKeyVersion RPC failure
// surfaces from ImportKey wrapped rather than being swallowed.
func TestImportKey_RPCError(t *testing.T) {
	mockClient := &MockKMSClient{
		ImportCryptoKeyVersionFunc: func(ctx context.Context, req *kmspb.ImportCryptoKeyVersionRequest, opts ...interface{}) (*kmspb.CryptoKeyVersion, error) {
			return nil, errors.New("kms: import denied")
		},
	}
	config := &Config{
		ProjectID:   "test-project",
		LocationID:  "us-central1",
		KeyRingID:   "test-keyring",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}
	b, err := NewBackendWithClient(config, mockClient)
	if err != nil {
		t.Fatalf("NewBackendWithClient() error = %v", err)
	}

	attrs := &types.KeyAttributes{CN: "import-key-rpc-error", KeyAlgorithm: x509.RSA}
	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey:  []byte("wrapped-key-material"),
		Algorithm:   backend.WrappingAlgorithmRSA_OAEP_3072_SHA256_AES_256,
		ImportToken: []byte("test-import-job"),
	}
	if err := b.ImportKey(context.Background(), attrs, wrapped); err == nil {
		t.Error("ImportKey() expected error when ImportCryptoKeyVersion fails, got nil")
	}
}
