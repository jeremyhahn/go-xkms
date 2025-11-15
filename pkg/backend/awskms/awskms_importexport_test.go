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

//go:build awskms

package awskms

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/storage/memory"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// TestGetImportParameters tests retrieving import parameters from AWS KMS.
func TestGetImportParameters(t *testing.T) {
	// Generate a test RSA key pair for the wrapping key
	wrappingPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	wrappingPubKeyDER, err := x509.MarshalPKIXPublicKey(&wrappingPrivKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}

	validTo := time.Now().Add(24 * time.Hour)

	tests := []struct {
		name      string
		attrs     *types.KeyAttributes
		algorithm backend.WrappingAlgorithm
		mockFunc  func(ctx context.Context, params *kms.GetParametersForImportInput, optFns ...func(*kms.Options)) (*kms.GetParametersForImportOutput, error)
		wantErr   bool
		validate  func(t *testing.T, params *backend.ImportParameters)
	}{
		{
			name: "success - RSA OAEP SHA-256",
			attrs: &types.KeyAttributes{
				CN:           "test-key",
				KeyAlgorithm: x509.RSA,
			},
			algorithm: backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
			mockFunc: func(ctx context.Context, params *kms.GetParametersForImportInput, optFns ...func(*kms.Options)) (*kms.GetParametersForImportOutput, error) {
				return &kms.GetParametersForImportOutput{
					PublicKey:         wrappingPubKeyDER,
					ImportToken:       []byte("test-import-token"),
					ParametersValidTo: &validTo,
					KeyId:             aws.String("test-key-id"),
				}, nil
			},
			wantErr: false,
			validate: func(t *testing.T, params *backend.ImportParameters) {
				if params == nil {
					t.Fatal("ImportParameters is nil")
				}
				if params.WrappingPublicKey == nil {
					t.Error("WrappingPublicKey is nil")
				}
				if len(params.ImportToken) == 0 {
					t.Error("ImportToken is empty")
				}
				if params.Algorithm != backend.WrappingAlgorithmRSAES_OAEP_SHA_256 {
					t.Errorf("Algorithm = %v, want %v", params.Algorithm, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
				}
				if params.ExpiresAt == nil {
					t.Error("ExpiresAt is nil")
				}
			},
		},
		{
			name: "success - RSA AES KEY WRAP SHA-256",
			attrs: &types.KeyAttributes{
				CN:           "test-key",
				KeyAlgorithm: x509.RSA,
			},
			algorithm: backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256,
			mockFunc: func(ctx context.Context, params *kms.GetParametersForImportInput, optFns ...func(*kms.Options)) (*kms.GetParametersForImportOutput, error) {
				return &kms.GetParametersForImportOutput{
					PublicKey:         wrappingPubKeyDER,
					ImportToken:       []byte("test-import-token"),
					ParametersValidTo: &validTo,
					KeyId:             aws.String("test-key-id"),
				}, nil
			},
			wantErr: false,
		},
		{
			name:      "error - nil attributes",
			attrs:     nil,
			algorithm: backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
			wantErr:   true,
		},
		{
			name: "error - KMS API failure",
			attrs: &types.KeyAttributes{
				CN:           "test-key",
				KeyAlgorithm: x509.RSA,
			},
			algorithm: backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
			mockFunc: func(ctx context.Context, params *kms.GetParametersForImportInput, optFns ...func(*kms.Options)) (*kms.GetParametersForImportOutput, error) {
				return nil, errors.New("KMS API error")
			},
			wantErr: true,
		},
		{
			name: "error - invalid public key",
			attrs: &types.KeyAttributes{
				CN:           "test-key",
				KeyAlgorithm: x509.RSA,
			},
			algorithm: backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
			mockFunc: func(ctx context.Context, params *kms.GetParametersForImportInput, optFns ...func(*kms.Options)) (*kms.GetParametersForImportOutput, error) {
				return &kms.GetParametersForImportOutput{
					PublicKey:   []byte("invalid-public-key"),
					ImportToken: []byte("test-import-token"),
				}, nil
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &MockKMSClient{
				GetParametersForImportFunc: tt.mockFunc,
			}

			config := &Config{
				Region:      "us-east-1",
				KeyStorage:  memory.New(),
				CertStorage: memory.New(),
			}

			b, err := NewBackendWithClient(config, mockClient)
			if err != nil {
				t.Fatalf("NewBackendWithClient() error = %v", err)
			}

			params, err := b.GetImportParameters(tt.attrs, tt.algorithm)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetImportParameters() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && tt.validate != nil {
				tt.validate(t, params)
			}
		})
	}
}

// TestWrapKey tests wrapping key material for import.
func TestWrapKey(t *testing.T) {
	// Generate a test RSA key pair
	wrappingPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	keyMaterial := make([]byte, 32) // 256-bit key
	if _, err := rand.Read(keyMaterial); err != nil {
		t.Fatalf("Failed to generate key material: %v", err)
	}

	tests := []struct {
		name        string
		keyMaterial []byte
		params      *backend.ImportParameters
		wantErr     bool
		validate    func(t *testing.T, wrapped *backend.WrappedKeyMaterial)
	}{
		{
			name:        "success - RSA OAEP SHA-256",
			keyMaterial: keyMaterial,
			params: &backend.ImportParameters{
				WrappingPublicKey: &wrappingPrivKey.PublicKey,
				ImportToken:       []byte("test-token"),
				Algorithm:         backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
			},
			wantErr: false,
			validate: func(t *testing.T, wrapped *backend.WrappedKeyMaterial) {
				if len(wrapped.WrappedKey) == 0 {
					t.Error("WrappedKey is empty")
				}
				if wrapped.Algorithm != backend.WrappingAlgorithmRSAES_OAEP_SHA_256 {
					t.Errorf("Algorithm = %v, want %v", wrapped.Algorithm, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
				}
				if len(wrapped.ImportToken) == 0 {
					t.Error("ImportToken is empty")
				}
			},
		},
		{
			name:        "success - RSA AES KEY WRAP SHA-256",
			keyMaterial: keyMaterial,
			params: &backend.ImportParameters{
				WrappingPublicKey: &wrappingPrivKey.PublicKey,
				ImportToken:       []byte("test-token"),
				Algorithm:         backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256,
			},
			wantErr: false,
		},
		{
			name:        "error - empty key material",
			keyMaterial: []byte{},
			params: &backend.ImportParameters{
				WrappingPublicKey: &wrappingPrivKey.PublicKey,
				ImportToken:       []byte("test-token"),
				Algorithm:         backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
			},
			wantErr: true,
		},
		{
			name:        "error - nil params",
			keyMaterial: keyMaterial,
			params:      nil,
			wantErr:     true,
		},
		{
			name:        "error - nil wrapping public key",
			keyMaterial: keyMaterial,
			params: &backend.ImportParameters{
				WrappingPublicKey: nil,
				ImportToken:       []byte("test-token"),
				Algorithm:         backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				Region:      "us-east-1",
				KeyStorage:  memory.New(),
				CertStorage: memory.New(),
			}

			b, err := NewBackend(config)
			if err != nil {
				t.Fatalf("NewBackend() error = %v", err)
			}

			wrapped, err := b.WrapKey(tt.keyMaterial, tt.params)
			if (err != nil) != tt.wantErr {
				t.Errorf("WrapKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && tt.validate != nil {
				tt.validate(t, wrapped)
			}
		})
	}
}

// TestUnwrapKey tests that UnwrapKey returns ErrNotSupported.
func TestUnwrapKey(t *testing.T) {
	config := &Config{
		Region:      "us-east-1",
		KeyStorage:  memory.New(),
		CertStorage: memory.New(),
	}

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() error = %v", err)
	}

	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey:  []byte("test-wrapped-key"),
		Algorithm:   backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
		ImportToken: []byte("test-token"),
	}

	params := &backend.ImportParameters{
		Algorithm: backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	_, err = b.UnwrapKey(wrapped, params)
	if !errors.Is(err, backend.ErrNotSupported) {
		t.Errorf("UnwrapKey() error = %v, want ErrNotSupported", err)
	}
}

// TestImportKey tests importing key material into AWS KMS.
func TestImportKey(t *testing.T) {
	tests := []struct {
		name     string
		attrs    *types.KeyAttributes
		wrapped  *backend.WrappedKeyMaterial
		mockFunc func(ctx context.Context, params *kms.ImportKeyMaterialInput, optFns ...func(*kms.Options)) (*kms.ImportKeyMaterialOutput, error)
		wantErr  bool
	}{
		{
			name: "success",
			attrs: &types.KeyAttributes{
				CN:           "test-key",
				KeyAlgorithm: x509.RSA,
			},
			wrapped: &backend.WrappedKeyMaterial{
				WrappedKey:  []byte("test-wrapped-key"),
				Algorithm:   backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
				ImportToken: []byte("test-token"),
			},
			mockFunc: func(ctx context.Context, params *kms.ImportKeyMaterialInput, optFns ...func(*kms.Options)) (*kms.ImportKeyMaterialOutput, error) {
				// Validate input
				if params.KeyId == nil {
					return nil, errors.New("KeyId is nil")
				}
				if len(params.ImportToken) == 0 {
					return nil, errors.New("ImportToken is empty")
				}
				if len(params.EncryptedKeyMaterial) == 0 {
					return nil, errors.New("EncryptedKeyMaterial is empty")
				}
				return &kms.ImportKeyMaterialOutput{}, nil
			},
			wantErr: false,
		},
		{
			name:  "error - nil attributes",
			attrs: nil,
			wrapped: &backend.WrappedKeyMaterial{
				WrappedKey:  []byte("test-wrapped-key"),
				Algorithm:   backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
				ImportToken: []byte("test-token"),
			},
			wantErr: true,
		},
		{
			name: "error - nil wrapped material",
			attrs: &types.KeyAttributes{
				CN:           "test-key",
				KeyAlgorithm: x509.RSA,
			},
			wrapped: nil,
			wantErr: true,
		},
		{
			name: "error - empty import token",
			attrs: &types.KeyAttributes{
				CN:           "test-key",
				KeyAlgorithm: x509.RSA,
			},
			wrapped: &backend.WrappedKeyMaterial{
				WrappedKey:  []byte("test-wrapped-key"),
				Algorithm:   backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
				ImportToken: []byte{},
			},
			wantErr: true,
		},
		{
			name: "error - empty wrapped key",
			attrs: &types.KeyAttributes{
				CN:           "test-key",
				KeyAlgorithm: x509.RSA,
			},
			wrapped: &backend.WrappedKeyMaterial{
				WrappedKey:  []byte{},
				Algorithm:   backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
				ImportToken: []byte("test-token"),
			},
			wantErr: true,
		},
		{
			name: "error - KMS API failure",
			attrs: &types.KeyAttributes{
				CN:           "test-key",
				KeyAlgorithm: x509.RSA,
			},
			wrapped: &backend.WrappedKeyMaterial{
				WrappedKey:  []byte("test-wrapped-key"),
				Algorithm:   backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
				ImportToken: []byte("test-token"),
			},
			mockFunc: func(ctx context.Context, params *kms.ImportKeyMaterialInput, optFns ...func(*kms.Options)) (*kms.ImportKeyMaterialOutput, error) {
				return nil, errors.New("KMS API error")
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &MockKMSClient{
				ImportKeyMaterialFunc: tt.mockFunc,
			}

			config := &Config{
				Region:      "us-east-1",
				KeyStorage:  memory.New(),
				CertStorage: memory.New(),
			}

			b, err := NewBackendWithClient(config, mockClient)
			if err != nil {
				t.Fatalf("NewBackendWithClient() error = %v", err)
			}

			err = b.ImportKey(tt.attrs, tt.wrapped)
			if (err != nil) != tt.wantErr {
				t.Errorf("ImportKey() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestExportKey tests that ExportKey returns ErrNotSupported.
func TestExportKey(t *testing.T) {
	config := &Config{
		Region:      "us-east-1",
		KeyStorage:  memory.New(),
		CertStorage: memory.New(),
	}

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() error = %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "test-key",
		KeyAlgorithm: x509.RSA,
	}

	_, err = b.ExportKey(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	if !errors.Is(err, backend.ErrExportNotSupported) {
		t.Errorf("ExportKey() error = %v, want ErrExportNotSupported", err)
	}
}

// TestImportKeyRoundTrip tests the complete import flow with real wrapping/unwrapping.
func TestImportKeyRoundTrip(t *testing.T) {
	// Generate a test RSA key pair for wrapping
	wrappingPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	wrappingPubKeyDER, err := x509.MarshalPKIXPublicKey(&wrappingPrivKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}

	// Generate key material to import
	keyMaterial := make([]byte, 32) // 256-bit AES key
	if _, err := rand.Read(keyMaterial); err != nil {
		t.Fatalf("Failed to generate key material: %v", err)
	}

	validTo := time.Now().Add(24 * time.Hour)
	importToken := []byte("test-import-token-12345")

	// Mock the KMS client
	mockClient := &MockKMSClient{
		GetParametersForImportFunc: func(ctx context.Context, params *kms.GetParametersForImportInput, optFns ...func(*kms.Options)) (*kms.GetParametersForImportOutput, error) {
			return &kms.GetParametersForImportOutput{
				PublicKey:         wrappingPubKeyDER,
				ImportToken:       importToken,
				ParametersValidTo: &validTo,
				KeyId:             params.KeyId,
			}, nil
		},
		ImportKeyMaterialFunc: func(ctx context.Context, params *kms.ImportKeyMaterialInput, optFns ...func(*kms.Options)) (*kms.ImportKeyMaterialOutput, error) {
			// Validate the import token matches
			if string(params.ImportToken) != string(importToken) {
				return nil, errors.New("import token mismatch")
			}
			// Validate we received encrypted key material
			if len(params.EncryptedKeyMaterial) == 0 {
				return nil, errors.New("encrypted key material is empty")
			}
			return &kms.ImportKeyMaterialOutput{}, nil
		},
	}

	config := &Config{
		Region:      "us-east-1",
		KeyStorage:  memory.New(),
		CertStorage: memory.New(),
	}

	b, err := NewBackendWithClient(config, mockClient)
	if err != nil {
		t.Fatalf("NewBackendWithClient() error = %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "test-import-key",
		KeyAlgorithm: x509.RSA,
	}

	// Test both wrapping algorithms
	algorithms := []backend.WrappingAlgorithm{
		backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
		backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256,
	}

	for _, algorithm := range algorithms {
		t.Run(string(algorithm), func(t *testing.T) {
			// Step 1: Get import parameters
			params, err := b.GetImportParameters(attrs, algorithm)
			if err != nil {
				t.Fatalf("GetImportParameters() error = %v", err)
			}

			// Step 2: Wrap the key material
			wrapped, err := b.WrapKey(keyMaterial, params)
			if err != nil {
				t.Fatalf("WrapKey() error = %v", err)
			}

			// Verify wrapped key is not empty
			if len(wrapped.WrappedKey) == 0 {
				t.Error("WrappedKey is empty")
			}

			// Verify import token is preserved
			if string(wrapped.ImportToken) != string(importToken) {
				t.Error("ImportToken was not preserved")
			}

			// Step 3: Import the wrapped key
			err = b.ImportKey(attrs, wrapped)
			if err != nil {
				t.Fatalf("ImportKey() error = %v", err)
			}
		})
	}
}

// TestMapWrappingAlgorithm tests the algorithm mapping function.
func TestMapWrappingAlgorithm(t *testing.T) {
	config := &Config{
		Region:      "us-east-1",
		KeyStorage:  memory.New(),
		CertStorage: memory.New(),
	}

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() error = %v", err)
	}

	tests := []struct {
		name      string
		algorithm backend.WrappingAlgorithm
		want      kmstypes.AlgorithmSpec
		wantErr   bool
	}{
		{
			name:      "RSAES_OAEP_SHA_1",
			algorithm: backend.WrappingAlgorithmRSAES_OAEP_SHA_1,
			want:      kmstypes.AlgorithmSpecRsaesOaepSha1,
			wantErr:   false,
		},
		{
			name:      "RSAES_OAEP_SHA_256",
			algorithm: backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
			want:      kmstypes.AlgorithmSpecRsaesOaepSha256,
			wantErr:   false,
		},
		{
			name:      "RSA_AES_KEY_WRAP_SHA_1",
			algorithm: backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_1,
			want:      kmstypes.AlgorithmSpecRsaAesKeyWrapSha1,
			wantErr:   false,
		},
		{
			name:      "RSA_AES_KEY_WRAP_SHA_256",
			algorithm: backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256,
			want:      kmstypes.AlgorithmSpecRsaAesKeyWrapSha256,
			wantErr:   false,
		},
		{
			name:      "unsupported algorithm",
			algorithm: "UNSUPPORTED_ALGORITHM",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := b.mapWrappingAlgorithm(tt.algorithm)
			if (err != nil) != tt.wantErr {
				t.Errorf("mapWrappingAlgorithm() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("mapWrappingAlgorithm() = %v, want %v", got, tt.want)
			}
		})
	}
}
