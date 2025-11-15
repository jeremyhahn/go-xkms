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
	"crypto"
	"crypto/x509"
	"errors"
	"testing"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/storage/memory"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

func TestNewBackend(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
		errType error
	}{
		{
			name: "valid config",
			config: &Config{
				ProjectID:   "test-project",
				LocationID:  "us-central1",
				KeyRingID:   "test-keyring",
				KeyStorage:  memory.New(),
				CertStorage: memory.New(),
			},
			wantErr: false,
		},
		{
			name: "missing project ID",
			config: &Config{
				LocationID:  "us-central1",
				KeyRingID:   "test-keyring",
				KeyStorage:  memory.New(),
				CertStorage: memory.New(),
			},
			wantErr: true,
			errType: ErrInvalidProjectID,
		},
		{
			name: "missing location ID",
			config: &Config{
				ProjectID:   "test-project",
				KeyRingID:   "test-keyring",
				KeyStorage:  memory.New(),
				CertStorage: memory.New(),
			},
			wantErr: true,
			errType: ErrInvalidLocationID,
		},
		{
			name: "missing key ring ID",
			config: &Config{
				ProjectID:   "test-project",
				LocationID:  "us-central1",
				KeyStorage:  memory.New(),
				CertStorage: memory.New(),
			},
			wantErr: true,
			errType: ErrInvalidKeyRingID,
		},
		{
			name:    "nil config",
			config:  nil,
			wantErr: true,
			errType: ErrInvalidConfig,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.config == nil {
				_, err := NewBackend(context.Background(), tt.config)
				if !tt.wantErr {
					t.Errorf("NewBackend() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				if !errors.Is(err, tt.errType) {
					t.Errorf("NewBackend() error type = %v, want %v", err, tt.errType)
				}
				return
			}

			// Use mock client for testing
			mockClient := &MockKMSClient{}
			b, err := NewBackendWithClient(tt.config, mockClient)

			if tt.wantErr {
				if err == nil {
					t.Errorf("NewBackendWithClient() expected error, got nil")
					return
				}
				if tt.errType != nil && !errors.Is(err, tt.errType) {
					t.Errorf("NewBackendWithClient() error type = %v, want %v", err, tt.errType)
				}
				return
			}

			if err != nil {
				t.Errorf("NewBackendWithClient() unexpected error: %v", err)
				return
			}

			if b == nil {
				t.Error("NewBackendWithClient() returned nil backend")
				return
			}

			if b.config != tt.config {
				t.Error("Backend config mismatch")
			}

			if b.client == nil {
				t.Error("Backend client is nil")
			}
		})
	}
}

func TestBackend_Type(t *testing.T) {
	config := &Config{
		ProjectID:   "test-project",
		LocationID:  "us-central1",
		KeyRingID:   "test-keyring",
		KeyStorage:  memory.New(),
		CertStorage: memory.New(),
	}

	mockClient := &MockKMSClient{}
	b, err := NewBackendWithClient(config, mockClient)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}

	backendType := b.Type()
	expected := backend.BackendTypeGCPKMS

	if backendType != expected {
		t.Errorf("Type() = %v, want %v", backendType, expected)
	}
}

func TestBackend_GenerateRSA(t *testing.T) {
	tests := []struct {
		name     string
		attrs    *types.KeyAttributes
		mockFunc func(*MockKMSClient)
		wantErr  bool
		errType  error
	}{
		{
			name: "successful RSA 2048 key generation",
			attrs: &types.KeyAttributes{
				CN:           "test-rsa-key",
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_GCPKMS,
				KeyAlgorithm: x509.RSA,
			},
			mockFunc: func(m *MockKMSClient) {
				m.CreateCryptoKeyFunc = func(ctx context.Context, req *kmspb.CreateCryptoKeyRequest, opts ...interface{}) (*kmspb.CryptoKey, error) {
					if req.CryptoKeyId != "test-rsa-key" {
						t.Errorf("CreateCryptoKey() key ID = %v, want test-rsa-key", req.CryptoKeyId)
					}
					if req.CryptoKey.Purpose != kmspb.CryptoKey_ASYMMETRIC_SIGN {
						t.Errorf("CreateCryptoKey() purpose = %v, want ASYMMETRIC_SIGN", req.CryptoKey.Purpose)
					}
					return &kmspb.CryptoKey{
						Name:    req.Parent + "/cryptoKeys/" + req.CryptoKeyId,
						Purpose: req.CryptoKey.Purpose,
						Primary: &kmspb.CryptoKeyVersion{
							Name:      req.Parent + "/cryptoKeys/" + req.CryptoKeyId + "/cryptoKeyVersions/1",
							State:     kmspb.CryptoKeyVersion_ENABLED,
							Algorithm: kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256,
						},
					}, nil
				}
			},
			wantErr: false,
		},
		{
			name:    "nil attributes",
			attrs:   nil,
			wantErr: true,
			errType: backend.ErrInvalidAttributes,
		},
		{
			name: "wrong algorithm",
			attrs: &types.KeyAttributes{
				CN:           "test-key",
				KeyAlgorithm: x509.ECDSA,
			},
			wantErr: true,
			errType: backend.ErrInvalidAttributes,
		},
		{
			name: "KMS API error",
			attrs: &types.KeyAttributes{
				CN:           "test-key",
				KeyAlgorithm: x509.RSA,
			},
			mockFunc: func(m *MockKMSClient) {
				m.CreateCryptoKeyFunc = func(ctx context.Context, req *kmspb.CreateCryptoKeyRequest, opts ...interface{}) (*kmspb.CryptoKey, error) {
					return nil, errors.New("KMS API error")
				}
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				ProjectID:   "test-project",
				LocationID:  "us-central1",
				KeyRingID:   "test-keyring",
				KeyStorage:  memory.New(),
				CertStorage: memory.New(),
			}

			mockClient := &MockKMSClient{}
			if tt.mockFunc != nil {
				tt.mockFunc(mockClient)
			}

			b, err := NewBackendWithClient(config, mockClient)
			if err != nil {
				t.Fatalf("Failed to create backend: %v", err)
			}

			signer, err := b.GenerateRSA(tt.attrs)

			if tt.wantErr {
				if err == nil {
					t.Error("GenerateRSA() expected error, got nil")
					return
				}
				if tt.errType != nil && !errors.Is(err, tt.errType) {
					t.Errorf("GenerateRSA() error type = %v, want %v", err, tt.errType)
				}
				return
			}

			if err != nil {
				t.Errorf("GenerateRSA() unexpected error: %v", err)
				return
			}

			if signer == nil {
				t.Error("GenerateRSA() returned nil signer")
			}
		})
	}
}

func TestBackend_GenerateECDSA(t *testing.T) {
	tests := []struct {
		name     string
		attrs    *types.KeyAttributes
		mockFunc func(*MockKMSClient)
		wantErr  bool
		errType  error
	}{
		{
			name: "successful ECDSA P-256 key generation",
			attrs: &types.KeyAttributes{
				CN:           "test-ecdsa-key",
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_GCPKMS,
				KeyAlgorithm: x509.ECDSA,
			},
			mockFunc: func(m *MockKMSClient) {
				m.CreateCryptoKeyFunc = func(ctx context.Context, req *kmspb.CreateCryptoKeyRequest, opts ...interface{}) (*kmspb.CryptoKey, error) {
					if req.CryptoKey.VersionTemplate.Algorithm != kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256 {
						t.Errorf("CreateCryptoKey() algorithm = %v, want EC_SIGN_P256_SHA256", req.CryptoKey.VersionTemplate.Algorithm)
					}
					return &kmspb.CryptoKey{
						Name:    req.Parent + "/cryptoKeys/" + req.CryptoKeyId,
						Purpose: req.CryptoKey.Purpose,
						Primary: &kmspb.CryptoKeyVersion{
							Name:      req.Parent + "/cryptoKeys/" + req.CryptoKeyId + "/cryptoKeyVersions/1",
							State:     kmspb.CryptoKeyVersion_ENABLED,
							Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
						},
					}, nil
				}
				m.GetPublicKeyFunc = func(ctx context.Context, req *kmspb.GetPublicKeyRequest, opts ...interface{}) (*kmspb.PublicKey, error) {
					ecdsaPubKeyPEM := `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2adMrdG7aUfZH57aeKFFM01dPnkx
C18ScRb4Z6poMBgJtYlVtd9ly63URv57ZW0Ncs1LiZB7WATb3svu+1c7HQ==
-----END PUBLIC KEY-----`
					return &kmspb.PublicKey{
						Pem:       ecdsaPubKeyPEM,
						Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
					}, nil
				}
			},
			wantErr: false,
		},
		{
			name:    "nil attributes",
			attrs:   nil,
			wantErr: true,
			errType: backend.ErrInvalidAttributes,
		},
		{
			name: "wrong algorithm",
			attrs: &types.KeyAttributes{
				CN:           "test-key",
				KeyAlgorithm: x509.RSA,
			},
			wantErr: true,
			errType: backend.ErrInvalidAttributes,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				ProjectID:   "test-project",
				LocationID:  "us-central1",
				KeyRingID:   "test-keyring",
				KeyStorage:  memory.New(),
				CertStorage: memory.New(),
			}

			mockClient := &MockKMSClient{}
			if tt.mockFunc != nil {
				tt.mockFunc(mockClient)
			}

			b, err := NewBackendWithClient(config, mockClient)
			if err != nil {
				t.Fatalf("Failed to create backend: %v", err)
			}

			signer, err := b.GenerateECDSA(tt.attrs)

			if tt.wantErr {
				if err == nil {
					t.Error("GenerateECDSA() expected error, got nil")
					return
				}
				if tt.errType != nil && !errors.Is(err, tt.errType) {
					t.Errorf("GenerateECDSA() error type = %v, want %v", err, tt.errType)
				}
				return
			}

			if err != nil {
				t.Errorf("GenerateECDSA() unexpected error: %v", err)
				return
			}

			if signer == nil {
				t.Error("GenerateECDSA() returned nil signer")
			}
		})
	}
}

func TestBackend_GenerateKey(t *testing.T) {
	tests := []struct {
		name    string
		attrs   *types.KeyAttributes
		wantErr bool
		errType error
	}{
		{
			name: "RSA key",
			attrs: &types.KeyAttributes{
				CN:           "test-key",
				KeyAlgorithm: x509.RSA,
			},
			wantErr: false,
		},
		{
			name: "ECDSA key",
			attrs: &types.KeyAttributes{
				CN:           "test-key",
				KeyAlgorithm: x509.ECDSA,
			},
			wantErr: false,
		},
		{
			name: "unsupported algorithm",
			attrs: &types.KeyAttributes{
				CN:           "test-key",
				KeyAlgorithm: x509.Ed25519,
			},
			wantErr: true,
			errType: backend.ErrInvalidKeyType,
		},
		{
			name:    "nil attributes",
			attrs:   nil,
			wantErr: true,
			errType: backend.ErrInvalidAttributes,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				ProjectID:   "test-project",
				LocationID:  "us-central1",
				KeyRingID:   "test-keyring",
				KeyStorage:  memory.New(),
				CertStorage: memory.New(),
			}

			mockClient := &MockKMSClient{}
			b, err := NewBackendWithClient(config, mockClient)
			if err != nil {
				t.Fatalf("Failed to create backend: %v", err)
			}

			_, err = b.GenerateKey(tt.attrs)

			if tt.wantErr {
				if err == nil {
					t.Error("GenerateKey() expected error, got nil")
					return
				}
				if tt.errType != nil && !errors.Is(err, tt.errType) {
					t.Errorf("GenerateKey() error type = %v, want %v", err, tt.errType)
				}
				return
			}

			if err != nil {
				t.Errorf("GenerateKey() unexpected error: %v", err)
			}
		})
	}
}

func TestBackend_Get(t *testing.T) {
	tests := []struct {
		name     string
		attrs    *types.KeyAttributes
		mockFunc func(*MockKMSClient)
		wantErr  bool
		errType  error
	}{
		{
			name: "successful get",
			attrs: &types.KeyAttributes{
				CN: "test-key",
			},
			wantErr: false,
		},
		{
			name: "key not found",
			attrs: &types.KeyAttributes{
				CN: "nonexistent-key",
			},
			mockFunc: func(m *MockKMSClient) {
				m.GetPublicKeyFunc = func(ctx context.Context, req *kmspb.GetPublicKeyRequest, opts ...interface{}) (*kmspb.PublicKey, error) {
					return nil, errors.New("not found")
				}
			},
			wantErr: true,
			errType: backend.ErrKeyNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				ProjectID:   "test-project",
				LocationID:  "us-central1",
				KeyRingID:   "test-keyring",
				KeyStorage:  memory.New(),
				CertStorage: memory.New(),
			}

			mockClient := &MockKMSClient{}
			if tt.mockFunc != nil {
				tt.mockFunc(mockClient)
			}

			b, err := NewBackendWithClient(config, mockClient)
			if err != nil {
				t.Fatalf("Failed to create backend: %v", err)
			}

			data, err := b.Get(tt.attrs, backend.FSEXT_PUBLIC_PEM)

			if tt.wantErr {
				if err == nil {
					t.Error("Get() expected error, got nil")
					return
				}
				if tt.errType != nil && !errors.Is(err, tt.errType) {
					t.Errorf("Get() error type = %v, want %v", err, tt.errType)
				}
				return
			}

			if err != nil {
				t.Errorf("Get() unexpected error: %v", err)
				return
			}

			if len(data) == 0 {
				t.Error("Get() returned empty data")
			}
		})
	}
}

func TestBackend_Save(t *testing.T) {
	config := &Config{
		ProjectID:   "test-project",
		LocationID:  "us-central1",
		KeyRingID:   "test-keyring",
		KeyStorage:  memory.New(),
		CertStorage: memory.New(),
	}

	mockClient := &MockKMSClient{}
	b, err := NewBackendWithClient(config, mockClient)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}

	attrs := &types.KeyAttributes{CN: "test-key"}
	err = b.Save(attrs, []byte("test data"), backend.FSEXT_PUBLIC_PEM, false)

	if err == nil {
		t.Error("Save() expected error for unsupported operation, got nil")
	}

	if !errors.Is(err, backend.ErrOperationNotSupported) {
		t.Errorf("Save() error = %v, want %v", err, backend.ErrOperationNotSupported)
	}
}

func TestBackend_Delete(t *testing.T) {
	tests := []struct {
		name     string
		attrs    *types.KeyAttributes
		mockFunc func(*MockKMSClient)
		wantErr  bool
	}{
		{
			name: "successful delete",
			attrs: &types.KeyAttributes{
				CN: "test-key",
			},
			wantErr: false,
		},
		{
			name: "delete error",
			attrs: &types.KeyAttributes{
				CN: "test-key",
			},
			mockFunc: func(m *MockKMSClient) {
				m.DestroyCryptoKeyVersionFunc = func(ctx context.Context, req *kmspb.DestroyCryptoKeyVersionRequest, opts ...interface{}) (*kmspb.CryptoKeyVersion, error) {
					return nil, errors.New("delete failed")
				}
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				ProjectID:   "test-project",
				LocationID:  "us-central1",
				KeyRingID:   "test-keyring",
				KeyStorage:  memory.New(),
				CertStorage: memory.New(),
			}

			mockClient := &MockKMSClient{}
			if tt.mockFunc != nil {
				tt.mockFunc(mockClient)
			}

			b, err := NewBackendWithClient(config, mockClient)
			if err != nil {
				t.Fatalf("Failed to create backend: %v", err)
			}

			err = b.Delete(tt.attrs)

			if tt.wantErr && err == nil {
				t.Error("Delete() expected error, got nil")
				return
			}

			if !tt.wantErr && err != nil {
				t.Errorf("Delete() unexpected error: %v", err)
			}
		})
	}
}

func TestBackend_Close(t *testing.T) {
	tests := []struct {
		name     string
		mockFunc func(*MockKMSClient)
		wantErr  bool
	}{
		{
			name:    "successful close",
			wantErr: false,
		},
		{
			name: "close with error",
			mockFunc: func(m *MockKMSClient) {
				m.CloseFunc = func() error {
					return errors.New("close error")
				}
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				ProjectID:   "test-project",
				LocationID:  "us-central1",
				KeyRingID:   "test-keyring",
				KeyStorage:  memory.New(),
				CertStorage: memory.New(),
			}

			mockClient := &MockKMSClient{}
			if tt.mockFunc != nil {
				tt.mockFunc(mockClient)
			}

			b, err := NewBackendWithClient(config, mockClient)
			if err != nil {
				t.Fatalf("Failed to create backend: %v", err)
			}

			err = b.Close()

			if tt.wantErr && err == nil {
				t.Error("Close() expected error, got nil")
				return
			}

			if !tt.wantErr && err != nil {
				t.Errorf("Close() unexpected error: %v", err)
			}
		})
	}
}

func TestBackend_Sign(t *testing.T) {
	tests := []struct {
		name     string
		attrs    *types.KeyAttributes
		digest   []byte
		opts     crypto.SignerOpts
		mockFunc func(*MockKMSClient)
		wantErr  bool
		errType  error
	}{
		{
			name: "successful sign with SHA256",
			attrs: &types.KeyAttributes{
				CN: "test-key",
			},
			digest:  make([]byte, 32),
			opts:    crypto.SHA256,
			wantErr: false,
		},
		{
			name: "successful sign with SHA384",
			attrs: &types.KeyAttributes{
				CN: "test-key",
			},
			digest:  make([]byte, 48),
			opts:    crypto.SHA384,
			wantErr: false,
		},
		{
			name: "successful sign with SHA512",
			attrs: &types.KeyAttributes{
				CN: "test-key",
			},
			digest:  make([]byte, 64),
			opts:    crypto.SHA512,
			wantErr: false,
		},
		{
			name: "empty digest",
			attrs: &types.KeyAttributes{
				CN: "test-key",
			},
			digest:  []byte{},
			opts:    crypto.SHA256,
			wantErr: true,
			errType: backend.ErrInvalidAttributes,
		},
		{
			name: "KMS API error",
			attrs: &types.KeyAttributes{
				CN: "test-key",
			},
			digest: make([]byte, 32),
			opts:   crypto.SHA256,
			mockFunc: func(m *MockKMSClient) {
				m.AsymmetricSignFunc = func(ctx context.Context, req *kmspb.AsymmetricSignRequest, opts ...interface{}) (*kmspb.AsymmetricSignResponse, error) {
					return nil, errors.New("sign failed")
				}
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				ProjectID:   "test-project",
				LocationID:  "us-central1",
				KeyRingID:   "test-keyring",
				KeyStorage:  memory.New(),
				CertStorage: memory.New(),
			}

			mockClient := &MockKMSClient{}
			if tt.mockFunc != nil {
				tt.mockFunc(mockClient)
			}

			b, err := NewBackendWithClient(config, mockClient)
			if err != nil {
				t.Fatalf("Failed to create backend: %v", err)
			}

			signature, err := b.Sign(tt.attrs, tt.digest, tt.opts)

			if tt.wantErr {
				if err == nil {
					t.Error("Sign() expected error, got nil")
					return
				}
				if tt.errType != nil && !errors.Is(err, tt.errType) {
					t.Errorf("Sign() error type = %v, want %v", err, tt.errType)
				}
				return
			}

			if err != nil {
				t.Errorf("Sign() unexpected error: %v", err)
				return
			}

			if len(signature) == 0 {
				t.Error("Sign() returned empty signature")
			}
		})
	}
}

func TestBackend_Verify(t *testing.T) {
	tests := []struct {
		name      string
		attrs     *types.KeyAttributes
		digest    []byte
		signature []byte
		mockFunc  func(*MockKMSClient)
		wantErr   bool
		errType   error
	}{
		{
			name: "empty digest",
			attrs: &types.KeyAttributes{
				CN: "test-key",
			},
			digest:    []byte{},
			signature: make([]byte, 256),
			wantErr:   true,
			errType:   backend.ErrInvalidAttributes,
		},
		{
			name: "empty signature",
			attrs: &types.KeyAttributes{
				CN: "test-key",
			},
			digest:    make([]byte, 32),
			signature: []byte{},
			wantErr:   true,
			errType:   backend.ErrInvalidAttributes,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				ProjectID:   "test-project",
				LocationID:  "us-central1",
				KeyRingID:   "test-keyring",
				KeyStorage:  memory.New(),
				CertStorage: memory.New(),
			}

			mockClient := &MockKMSClient{}
			if tt.mockFunc != nil {
				tt.mockFunc(mockClient)
			}

			b, err := NewBackendWithClient(config, mockClient)
			if err != nil {
				t.Fatalf("Failed to create backend: %v", err)
			}

			err = b.Verify(tt.attrs, tt.digest, tt.signature)

			if tt.wantErr {
				if err == nil {
					t.Error("Verify() expected error, got nil")
					return
				}
				if tt.errType != nil && !errors.Is(err, tt.errType) {
					t.Errorf("Verify() error type = %v, want %v", err, tt.errType)
				}
				return
			}

			if err != nil {
				t.Errorf("Verify() unexpected error: %v", err)
			}
		})
	}
}

func TestBackend_Signer(t *testing.T) {
	tests := []struct {
		name     string
		attrs    *types.KeyAttributes
		mockFunc func(*MockKMSClient)
		wantErr  bool
		errType  error
	}{
		{
			name: "successful signer creation",
			attrs: &types.KeyAttributes{
				CN: "test-key",
			},
			wantErr: false,
		},
		{
			name: "key not found",
			attrs: &types.KeyAttributes{
				CN: "nonexistent-key",
			},
			mockFunc: func(m *MockKMSClient) {
				m.GetPublicKeyFunc = func(ctx context.Context, req *kmspb.GetPublicKeyRequest, opts ...interface{}) (*kmspb.PublicKey, error) {
					return nil, errors.New("not found")
				}
			},
			wantErr: true,
			errType: backend.ErrKeyNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				ProjectID:   "test-project",
				LocationID:  "us-central1",
				KeyRingID:   "test-keyring",
				KeyStorage:  memory.New(),
				CertStorage: memory.New(),
			}

			mockClient := &MockKMSClient{}
			if tt.mockFunc != nil {
				tt.mockFunc(mockClient)
			}

			b, err := NewBackendWithClient(config, mockClient)
			if err != nil {
				t.Fatalf("Failed to create backend: %v", err)
			}

			signer, err := b.Signer(tt.attrs)

			if tt.wantErr {
				if err == nil {
					t.Error("Signer() expected error, got nil")
					return
				}
				if tt.errType != nil && !errors.Is(err, tt.errType) {
					t.Errorf("Signer() error type = %v, want %v", err, tt.errType)
				}
				return
			}

			if err != nil {
				t.Errorf("Signer() unexpected error: %v", err)
				return
			}

			if signer == nil {
				t.Error("Signer() returned nil")
				return
			}

			// Test the signer interface
			pubKey := signer.Public()
			if pubKey == nil {
				t.Error("Signer.Public() returned nil")
			}
		})
	}
}

func TestBackend_Client(t *testing.T) {
	config := &Config{
		ProjectID:   "test-project",
		LocationID:  "us-central1",
		KeyRingID:   "test-keyring",
		KeyStorage:  memory.New(),
		CertStorage: memory.New(),
	}

	mockClient := &MockKMSClient{}
	b, err := NewBackendWithClient(config, mockClient)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}

	client := b.Client()
	if client == nil {
		t.Error("Client() returned nil")
	}

	if client != mockClient {
		t.Error("Client() returned different client")
	}
}

func TestBackend_NotInitialized(t *testing.T) {
	config := &Config{
		ProjectID:   "test-project",
		LocationID:  "us-central1",
		KeyRingID:   "test-keyring",
		KeyStorage:  memory.New(),
		CertStorage: memory.New(),
	}

	b := &Backend{
		config: config,
		client: nil, // Not initialized
	}

	attrs := &types.KeyAttributes{CN: "test-key"}

	// Test Get with uninitialized client
	_, err := b.Get(attrs, backend.FSEXT_PUBLIC_PEM)
	if !errors.Is(err, ErrNotInitialized) {
		t.Errorf("Get() with nil client error = %v, want %v", err, ErrNotInitialized)
	}

	// Test Delete with uninitialized client
	err = b.Delete(attrs)
	if !errors.Is(err, ErrNotInitialized) {
		t.Errorf("Delete() with nil client error = %v, want %v", err, ErrNotInitialized)
	}

	// Test Sign with uninitialized client
	_, err = b.Sign(attrs, make([]byte, 32), crypto.SHA256)
	if !errors.Is(err, ErrNotInitialized) {
		t.Errorf("Sign() with nil client error = %v, want %v", err, ErrNotInitialized)
	}

	// Test Signer with uninitialized client
	_, err = b.Signer(attrs)
	if !errors.Is(err, ErrNotInitialized) {
		t.Errorf("Signer() with nil client error = %v, want %v", err, ErrNotInitialized)
	}

	// Test GenerateRSA with uninitialized client
	rsaAttrs := &types.KeyAttributes{
		CN:           "test-key",
		KeyAlgorithm: x509.RSA,
	}
	_, err = b.GenerateRSA(rsaAttrs)
	if !errors.Is(err, ErrNotInitialized) {
		t.Errorf("GenerateRSA() with nil client error = %v, want %v", err, ErrNotInitialized)
	}

	// Test GenerateECDSA with uninitialized client
	ecdsaAttrs := &types.KeyAttributes{
		CN:           "test-key",
		KeyAlgorithm: x509.ECDSA,
	}
	_, err = b.GenerateECDSA(ecdsaAttrs)
	if !errors.Is(err, ErrNotInitialized) {
		t.Errorf("GenerateECDSA() with nil client error = %v, want %v", err, ErrNotInitialized)
	}
}

func TestBackend_ConcurrentAccess(t *testing.T) {
	config := &Config{
		ProjectID:   "test-project",
		LocationID:  "us-central1",
		KeyRingID:   "test-keyring",
		KeyStorage:  memory.New(),
		CertStorage: memory.New(),
	}

	mockClient := &MockKMSClient{}
	b, err := NewBackendWithClient(config, mockClient)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}

	// Test concurrent Get operations
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(id int) {
			attrs := &types.KeyAttributes{
				CN: "test-key",
			}
			_, _ = b.Get(attrs, backend.FSEXT_PUBLIC_PEM)
			done <- true
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	// Test concurrent Sign operations
	for i := 0; i < 10; i++ {
		go func(id int) {
			attrs := &types.KeyAttributes{
				CN: "test-key",
			}
			digest := make([]byte, 32)
			_, _ = b.Sign(attrs, digest, crypto.SHA256)
			done <- true
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestKMSSigner(t *testing.T) {
	config := &Config{
		ProjectID:   "test-project",
		LocationID:  "us-central1",
		KeyRingID:   "test-keyring",
		KeyStorage:  memory.New(),
		CertStorage: memory.New(),
	}

	mockClient := &MockKMSClient{}
	b, err := NewBackendWithClient(config, mockClient)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "test-key",
		KeyAlgorithm: x509.RSA,
	}

	signer, err := b.Signer(attrs)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	// Test Public() method
	pubKey := signer.Public()
	if pubKey == nil {
		t.Error("Public() returned nil")
	}

	// Test Sign() method
	digest := make([]byte, 32)
	signature, err := signer.Sign(nil, digest, crypto.SHA256)
	if err != nil {
		t.Errorf("Sign() unexpected error: %v", err)
	}

	if len(signature) == 0 {
		t.Error("Sign() returned empty signature")
	}
}

func TestCRC32C(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "empty data",
			data: []byte{},
		},
		{
			name: "small data",
			data: []byte("hello"),
		},
		{
			name: "large data",
			data: make([]byte, 1024),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checksum := crc32c(tt.data)
			// Just verify it doesn't panic and returns a value
			_ = checksum
		})
	}
}

func TestParsePublicKey(t *testing.T) {
	tests := []struct {
		name    string
		pemData string
		wantErr bool
	}{
		{
			name: "valid RSA public key",
			pemData: `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo
4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u
+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh
kd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ
0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg
cKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc
mwIDAQAB
-----END PUBLIC KEY-----`,
			wantErr: false,
		},
		{
			name: "valid ECDSA public key",
			pemData: `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2adMrdG7aUfZH57aeKFFM01dPnkx
C18ScRb4Z6poMBgJtYlVtd9ly63URv57ZW0Ncs1LiZB7WATb3svu+1c7HQ==
-----END PUBLIC KEY-----`,
			wantErr: false,
		},
		{
			name:    "invalid PEM",
			pemData: "not a valid PEM",
			wantErr: true,
		},
		{
			name:    "empty PEM",
			pemData: "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pubKey, err := parsePublicKey(tt.pemData)

			if tt.wantErr {
				if err == nil {
					t.Error("parsePublicKey() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("parsePublicKey() unexpected error: %v", err)
				return
			}

			if pubKey == nil {
				t.Error("parsePublicKey() returned nil key")
			}
		})
	}
}

func TestBackend_CryptoKeyNames(t *testing.T) {
	config := &Config{
		ProjectID:   "test-project",
		LocationID:  "us-central1",
		KeyRingID:   "test-keyring",
		KeyStorage:  memory.New(),
		CertStorage: memory.New(),
	}

	mockClient := &MockKMSClient{}
	b, err := NewBackendWithClient(config, mockClient)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}

	// Test cryptoKeyName
	keyName := b.cryptoKeyName("my-key")
	expected := "projects/test-project/locations/us-central1/keyRings/test-keyring/cryptoKeys/my-key"
	if keyName != expected {
		t.Errorf("cryptoKeyName() = %v, want %v", keyName, expected)
	}

	// Test cryptoKeyVersionName
	versionName := b.cryptoKeyVersionName("my-key")
	expected = "projects/test-project/locations/us-central1/keyRings/test-keyring/cryptoKeys/my-key/cryptoKeyVersions/1"
	if versionName != expected {
		t.Errorf("cryptoKeyVersionName() = %v, want %v", versionName, expected)
	}
}
