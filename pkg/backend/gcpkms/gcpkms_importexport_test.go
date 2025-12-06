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

//go:build gcpkms

package gcpkms

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// generateTestRSAKey generates an RSA key for testing
func generateTestRSAKey(bits int) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, bits)
}

// rsaPublicKeyToPEM converts an RSA public key to PEM format
func rsaPublicKeyToPEM(pubKey *rsa.PublicKey) (string, error) {
	pubASN1, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", err
	}

	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubASN1,
	})

	return string(pubPEM), nil
}

func TestGetImportParameters(t *testing.T) {
	tests := []struct {
		name        string
		attrs       *types.KeyAttributes
		algorithm   backend.WrappingAlgorithm
		mockFunc    func(ctx context.Context, req *kmspb.CreateImportJobRequest, opts ...interface{}) (*kmspb.ImportJob, error)
		wantErr     bool
		errContains string
	}{
		{
			name: "successful import job creation with RSA_OAEP_3072",
			attrs: &types.KeyAttributes{
				CN:           "test-key",
				KeyAlgorithm: x509.RSA,
				KeyType:      backend.KEY_TYPE_SIGNING,
			},
			algorithm: backend.WrappingAlgorithmRSA_OAEP_3072_SHA256_AES_256,
			mockFunc: func(ctx context.Context, req *kmspb.CreateImportJobRequest, opts ...interface{}) (*kmspb.ImportJob, error) {
				testKey, _ := generateTestRSAKey(3072)
				pubPEM, _ := rsaPublicKeyToPEM(&testKey.PublicKey)

				return &kmspb.ImportJob{
					Name:            req.Parent + "/importJobs/" + req.ImportJobId,
					ImportMethod:    kmspb.ImportJob_RSA_OAEP_3072_SHA256_AES_256,
					ProtectionLevel: kmspb.ProtectionLevel_HSM,
					State:           kmspb.ImportJob_ACTIVE,
					PublicKey: &kmspb.ImportJob_WrappingPublicKey{
						Pem: pubPEM,
					},
				}, nil
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				ProjectID:   "test-project",
				LocationID:  "us-central1",
				KeyRingID:   "test-keyring",
				KeyStorage:  storage.New(),
				CertStorage: storage.New(),
			}

			mockClient := &MockKMSClient{
				CreateImportJobFunc: tt.mockFunc,
			}

			b, err := NewBackendWithClient(config, mockClient)
			if err != nil {
				t.Fatalf("Failed to create backend: %v", err)
			}

			params, err := b.GetImportParameters(tt.attrs, tt.algorithm)

			if tt.wantErr {
				if err == nil {
					t.Errorf("GetImportParameters() expected error, got nil")
					return
				}
				return
			}

			if err != nil {
				t.Errorf("GetImportParameters() unexpected error: %v", err)
				return
			}

			if params == nil {
				t.Error("GetImportParameters() returned nil parameters")
			}
		})
	}
}

func TestWrapKey(t *testing.T) {
	wrappingKey, _ := generateTestRSAKey(3072)

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
		t.Fatalf("Failed to create backend: %v", err)
	}

	params := &backend.ImportParameters{
		WrappingPublicKey: &wrappingKey.PublicKey,
		ImportToken:       []byte("test-import-job"),
		Algorithm:         backend.WrappingAlgorithmRSA_OAEP_3072_SHA256_AES_256,
	}

	wrapped, err := b.WrapKey([]byte("test-key-material"), params)
	if err != nil {
		t.Fatalf("WrapKey() failed: %v", err)
	}

	if wrapped == nil {
		t.Fatal("WrapKey() returned nil")
	}

	if len(wrapped.WrappedKey) == 0 {
		t.Error("WrapKey() returned empty wrapped key")
	}
}

func TestUnwrapKey(t *testing.T) {
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
		t.Fatalf("Failed to create backend: %v", err)
	}

	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey:  []byte("test-wrapped-key"),
		Algorithm:   backend.WrappingAlgorithmRSA_OAEP_3072_SHA256_AES_256,
		ImportToken: []byte("test-import-job"),
	}

	params := &backend.ImportParameters{
		Algorithm: backend.WrappingAlgorithmRSA_OAEP_3072_SHA256_AES_256,
	}

	_, err = b.UnwrapKey(wrapped, params)
	if err == nil {
		t.Error("UnwrapKey() expected error, got nil")
	}
}

func TestImportKey(t *testing.T) {
	config := &Config{
		ProjectID:   "test-project",
		LocationID:  "us-central1",
		KeyRingID:   "test-keyring",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}

	mockClient := &MockKMSClient{
		ImportCryptoKeyVersionFunc: func(ctx context.Context, req *kmspb.ImportCryptoKeyVersionRequest, opts ...interface{}) (*kmspb.CryptoKeyVersion, error) {
			return &kmspb.CryptoKeyVersion{
				Name:      req.Parent + "/cryptoKeyVersions/1",
				State:     kmspb.CryptoKeyVersion_ENABLED,
				Algorithm: kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256,
			}, nil
		},
	}

	b, err := NewBackendWithClient(config, mockClient)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "imported-key",
		KeyAlgorithm: x509.RSA,
		KeyType:      backend.KEY_TYPE_SIGNING,
	}

	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey:  []byte("wrapped-key-material"),
		Algorithm:   backend.WrappingAlgorithmRSA_OAEP_3072_SHA256_AES_256,
		ImportToken: []byte("test-import-job"),
	}

	err = b.ImportKey(attrs, wrapped)
	if err != nil {
		t.Fatalf("ImportKey() failed: %v", err)
	}
}

func TestExportKey(t *testing.T) {
	config := &Config{
		ProjectID:   "test-project",
		LocationID:  "us-central1",
		KeyRingID:   "test-keyring",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}

	mockClient := &MockKMSClient{
		GetCryptoKeyFunc: func(ctx context.Context, req *kmspb.GetCryptoKeyRequest, opts ...interface{}) (*kmspb.CryptoKey, error) {
			return &kmspb.CryptoKey{
				Name:    req.Name,
				Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN,
				Primary: &kmspb.CryptoKeyVersion{
					Name:      req.Name + "/cryptoKeyVersions/1",
					State:     kmspb.CryptoKeyVersion_ENABLED,
					Algorithm: kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256,
				},
			}, nil
		},
	}

	b, err := NewBackendWithClient(config, mockClient)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "test-key",
		KeyAlgorithm: x509.RSA,
	}

	_, err = b.ExportKey(attrs, backend.WrappingAlgorithmRSA_OAEP_3072_SHA256_AES_256)
	if err == nil {
		t.Error("ExportKey() expected error, got nil")
	}
}
