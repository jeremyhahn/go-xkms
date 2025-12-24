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
	"crypto/x509"
	"errors"
	"testing"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestBackend_GenerateSymmetricKey(t *testing.T) {
	tests := []struct {
		name     string
		attrs    *types.KeyAttributes
		mockFunc func(*MockKMSClient)
		wantErr  bool
		errType  error
	}{
		{
			name: "successful AES-256 key generation",
			attrs: &types.KeyAttributes{
				CN:                 "test-symmetric-key",
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_GCPKMS,
				SymmetricAlgorithm: types.SymmetricAES256GCM,
			},
			mockFunc: func(m *MockKMSClient) {
				m.CreateCryptoKeyFunc = func(ctx context.Context, req *kmspb.CreateCryptoKeyRequest, opts ...interface{}) (*kmspb.CryptoKey, error) {
					if req.CryptoKeyId != "test-symmetric-key" {
						t.Errorf("CreateCryptoKey() key ID = %v, want test-symmetric-key", req.CryptoKeyId)
					}
					if req.CryptoKey.Purpose != kmspb.CryptoKey_ENCRYPT_DECRYPT {
						t.Errorf("CreateCryptoKey() purpose = %v, want ENCRYPT_DECRYPT", req.CryptoKey.Purpose)
					}
					if req.CryptoKey.VersionTemplate.Algorithm != kmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION {
						t.Errorf("CreateCryptoKey() algorithm = %v, want GOOGLE_SYMMETRIC_ENCRYPTION", req.CryptoKey.VersionTemplate.Algorithm)
					}
					return &kmspb.CryptoKey{
						Name:    req.Parent + "/cryptoKeys/" + req.CryptoKeyId,
						Purpose: req.CryptoKey.Purpose,
						Primary: &kmspb.CryptoKeyVersion{
							Name:      req.Parent + "/cryptoKeys/" + req.CryptoKeyId + "/cryptoKeyVersions/1",
							State:     kmspb.CryptoKeyVersion_ENABLED,
							Algorithm: kmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION,
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
			name: "asymmetric algorithm",
			attrs: &types.KeyAttributes{
				CN:           "test-key",
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_GCPKMS,
				KeyAlgorithm: x509.RSA,
			},
			wantErr: true,
		},
		{
			name: "unsupported AES key size",
			attrs: &types.KeyAttributes{
				CN:                 "test-key",
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_GCPKMS,
				SymmetricAlgorithm: types.SymmetricAES128GCM,
			},
			wantErr: true,
		},
		{
			name: "KMS API error",
			attrs: &types.KeyAttributes{
				CN:                 "test-key",
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_GCPKMS,
				SymmetricAlgorithm: types.SymmetricAES256GCM,
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
				KeyStorage:  storage.New(),
				CertStorage: storage.New(),
			}

			mockClient := &MockKMSClient{}
			if tt.mockFunc != nil {
				tt.mockFunc(mockClient)
			}

			b, err := NewBackendWithClient(config, mockClient)
			if err != nil {
				t.Fatalf("Failed to create backend: %v", err)
			}

			key, err := b.GenerateSymmetricKey(tt.attrs)

			if tt.wantErr {
				if err == nil {
					t.Error("GenerateSymmetricKey() expected error, got nil")
					return
				}
				if tt.errType != nil && !errors.Is(err, tt.errType) {
					t.Errorf("GenerateSymmetricKey() error type = %v, want %v", err, tt.errType)
				}
				return
			}

			if err != nil {
				t.Errorf("GenerateSymmetricKey() unexpected error: %v", err)
				return
			}

			if key == nil {
				t.Error("GenerateSymmetricKey() returned nil key")
				return
			}

			// Verify key properties
			if key.Algorithm() != string(types.SymmetricAES256GCM) {
				t.Errorf("Key algorithm = %v, want %v", key.Algorithm(), types.SymmetricAES256GCM)
			}

			if key.KeySize() != 256 {
				t.Errorf("Key size = %v, want 256", key.KeySize())
			}
		})
	}
}

func TestBackend_GetSymmetricKey(t *testing.T) {
	tests := []struct {
		name     string
		attrs    *types.KeyAttributes
		mockFunc func(*MockKMSClient)
		wantErr  bool
		errType  error
	}{
		{
			name: "successful key retrieval",
			attrs: &types.KeyAttributes{
				CN:                 "test-symmetric-key",
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_GCPKMS,
				SymmetricAlgorithm: types.SymmetricAES256GCM,
			},
			mockFunc: func(m *MockKMSClient) {
				m.GetCryptoKeyFunc = func(ctx context.Context, req *kmspb.GetCryptoKeyRequest, opts ...interface{}) (*kmspb.CryptoKey, error) {
					return &kmspb.CryptoKey{
						Name:    req.Name,
						Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT,
						Primary: &kmspb.CryptoKeyVersion{
							Name:      req.Name + "/cryptoKeyVersions/1",
							State:     kmspb.CryptoKeyVersion_ENABLED,
							Algorithm: kmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION,
						},
					}, nil
				}
			},
			wantErr: false,
		},
		{
			name: "key not found",
			attrs: &types.KeyAttributes{
				CN:                 "nonexistent-key",
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_GCPKMS,
				SymmetricAlgorithm: types.SymmetricAES256GCM,
			},
			mockFunc: func(m *MockKMSClient) {
				m.GetCryptoKeyFunc = func(ctx context.Context, req *kmspb.GetCryptoKeyRequest, opts ...interface{}) (*kmspb.CryptoKey, error) {
					return nil, errors.New("not found")
				}
			},
			wantErr: true,
			errType: backend.ErrKeyNotFound,
		},
		{
			name: "wrong key purpose",
			attrs: &types.KeyAttributes{
				CN:                 "test-key",
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_GCPKMS,
				SymmetricAlgorithm: types.SymmetricAES256GCM,
			},
			mockFunc: func(m *MockKMSClient) {
				m.GetCryptoKeyFunc = func(ctx context.Context, req *kmspb.GetCryptoKeyRequest, opts ...interface{}) (*kmspb.CryptoKey, error) {
					return &kmspb.CryptoKey{
						Name:    req.Name,
						Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN,
						Primary: &kmspb.CryptoKeyVersion{
							Name:      req.Name + "/cryptoKeyVersions/1",
							State:     kmspb.CryptoKeyVersion_ENABLED,
							Algorithm: kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256,
						},
					}, nil
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
				KeyStorage:  storage.New(),
				CertStorage: storage.New(),
			}

			mockClient := &MockKMSClient{}
			if tt.mockFunc != nil {
				tt.mockFunc(mockClient)
			}

			b, err := NewBackendWithClient(config, mockClient)
			if err != nil {
				t.Fatalf("Failed to create backend: %v", err)
			}

			key, err := b.GetSymmetricKey(tt.attrs)

			if tt.wantErr {
				if err == nil {
					t.Error("GetSymmetricKey() expected error, got nil")
					return
				}
				if tt.errType != nil && !errors.Is(err, tt.errType) {
					t.Errorf("GetSymmetricKey() error type = %v, want %v", err, tt.errType)
				}
				return
			}

			if err != nil {
				t.Errorf("GetSymmetricKey() unexpected error: %v", err)
				return
			}

			if key == nil {
				t.Error("GetSymmetricKey() returned nil key")
			}
		})
	}
}

func TestBackend_SymmetricEncrypter(t *testing.T) {
	tests := []struct {
		name     string
		attrs    *types.KeyAttributes
		mockFunc func(*MockKMSClient)
		wantErr  bool
	}{
		{
			name: "successful encrypter creation",
			attrs: &types.KeyAttributes{
				CN:                 "test-symmetric-key",
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_GCPKMS,
				SymmetricAlgorithm: types.SymmetricAES256GCM,
			},
			mockFunc: func(m *MockKMSClient) {
				m.GetCryptoKeyFunc = func(ctx context.Context, req *kmspb.GetCryptoKeyRequest, opts ...interface{}) (*kmspb.CryptoKey, error) {
					return &kmspb.CryptoKey{
						Name:    req.Name,
						Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT,
						Primary: &kmspb.CryptoKeyVersion{
							Name:      req.Name + "/cryptoKeyVersions/1",
							State:     kmspb.CryptoKeyVersion_ENABLED,
							Algorithm: kmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION,
						},
					}, nil
				}
			},
			wantErr: false,
		},
		{
			name: "key not found",
			attrs: &types.KeyAttributes{
				CN:                 "nonexistent-key",
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_GCPKMS,
				SymmetricAlgorithm: types.SymmetricAES256GCM,
			},
			mockFunc: func(m *MockKMSClient) {
				m.GetCryptoKeyFunc = func(ctx context.Context, req *kmspb.GetCryptoKeyRequest, opts ...interface{}) (*kmspb.CryptoKey, error) {
					return nil, errors.New("not found")
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
				KeyStorage:  storage.New(),
				CertStorage: storage.New(),
			}

			mockClient := &MockKMSClient{}
			if tt.mockFunc != nil {
				tt.mockFunc(mockClient)
			}

			b, err := NewBackendWithClient(config, mockClient)
			if err != nil {
				t.Fatalf("Failed to create backend: %v", err)
			}

			encrypter, err := b.SymmetricEncrypter(tt.attrs)

			if tt.wantErr {
				if err == nil {
					t.Error("SymmetricEncrypter() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("SymmetricEncrypter() unexpected error: %v", err)
				return
			}

			if encrypter == nil {
				t.Error("SymmetricEncrypter() returned nil encrypter")
			}
		})
	}
}

func TestSymmetricEncrypter_Encrypt(t *testing.T) {
	tests := []struct {
		name      string
		plaintext []byte
		opts      *types.EncryptOptions
		mockFunc  func(*MockKMSClient)
		wantErr   bool
	}{
		{
			name:      "successful encryption without AAD",
			plaintext: []byte("sensitive data to encrypt"),
			opts:      nil,
			mockFunc: func(m *MockKMSClient) {
				m.EncryptFunc = func(ctx context.Context, req *kmspb.EncryptRequest, opts ...interface{}) (*kmspb.EncryptResponse, error) {
					if len(req.Plaintext) == 0 {
						t.Error("EncryptFunc() received empty plaintext")
					}
					ciphertext := []byte("encrypted-data")
					return &kmspb.EncryptResponse{
						Ciphertext: ciphertext,
						CiphertextCrc32C: &wrapperspb.Int64Value{
							Value: int64(crc32c(ciphertext)),
						},
					}, nil
				}
			},
			wantErr: false,
		},
		{
			name:      "successful encryption with AAD",
			plaintext: []byte("sensitive data"),
			opts: &types.EncryptOptions{
				AdditionalData: []byte("context information"),
			},
			mockFunc: func(m *MockKMSClient) {
				m.EncryptFunc = func(ctx context.Context, req *kmspb.EncryptRequest, opts ...interface{}) (*kmspb.EncryptResponse, error) {
					if len(req.AdditionalAuthenticatedData) == 0 {
						t.Error("EncryptFunc() AAD not provided")
					}
					ciphertext := []byte("encrypted-with-aad")
					return &kmspb.EncryptResponse{
						Ciphertext: ciphertext,
						CiphertextCrc32C: &wrapperspb.Int64Value{
							Value: int64(crc32c(ciphertext)),
						},
					}, nil
				}
			},
			wantErr: false,
		},
		{
			name:      "checksum mismatch",
			plaintext: []byte("test data"),
			opts:      nil,
			mockFunc: func(m *MockKMSClient) {
				m.EncryptFunc = func(ctx context.Context, req *kmspb.EncryptRequest, opts ...interface{}) (*kmspb.EncryptResponse, error) {
					return &kmspb.EncryptResponse{
						Ciphertext: []byte("encrypted"),
						CiphertextCrc32C: &wrapperspb.Int64Value{
							Value: 99999, // Invalid checksum
						},
					}, nil
				}
			},
			wantErr: true,
		},
		{
			name:      "KMS API error",
			plaintext: []byte("test data"),
			opts:      nil,
			mockFunc: func(m *MockKMSClient) {
				m.EncryptFunc = func(ctx context.Context, req *kmspb.EncryptRequest, opts ...interface{}) (*kmspb.EncryptResponse, error) {
					return nil, errors.New("KMS encryption failed")
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
				KeyStorage:  storage.New(),
				CertStorage: storage.New(),
			}

			mockClient := &MockKMSClient{}
			if tt.mockFunc != nil {
				tt.mockFunc(mockClient)
			}

			// Setup mock for GetCryptoKey
			mockClient.GetCryptoKeyFunc = func(ctx context.Context, req *kmspb.GetCryptoKeyRequest, opts ...interface{}) (*kmspb.CryptoKey, error) {
				return &kmspb.CryptoKey{
					Name:    req.Name,
					Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT,
					Primary: &kmspb.CryptoKeyVersion{
						Name:      req.Name + "/cryptoKeyVersions/1",
						State:     kmspb.CryptoKeyVersion_ENABLED,
						Algorithm: kmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION,
					},
				}, nil
			}

			b, err := NewBackendWithClient(config, mockClient)
			if err != nil {
				t.Fatalf("Failed to create backend: %v", err)
			}

			attrs := &types.KeyAttributes{
				CN:                 "test-key",
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_GCPKMS,
				SymmetricAlgorithm: types.SymmetricAES256GCM,
			}

			encrypter, err := b.SymmetricEncrypter(attrs)
			if err != nil {
				t.Fatalf("Failed to create encrypter: %v", err)
			}

			encrypted, err := encrypter.Encrypt(tt.plaintext, tt.opts)

			if tt.wantErr {
				if err == nil {
					t.Error("Encrypt() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Encrypt() unexpected error: %v", err)
				return
			}

			if encrypted == nil {
				t.Error("Encrypt() returned nil encrypted data")
				return
			}

			if len(encrypted.Ciphertext) == 0 {
				t.Error("Encrypt() returned empty ciphertext")
			}

			if encrypted.Algorithm != string(types.SymmetricAES256GCM) {
				t.Errorf("Algorithm = %v, want %v", encrypted.Algorithm, backend.ALG_AES256_GCM)
			}
		})
	}
}

func TestSymmetricEncrypter_Decrypt(t *testing.T) {
	tests := []struct {
		name     string
		data     *types.EncryptedData
		opts     *types.DecryptOptions
		mockFunc func(*MockKMSClient)
		wantErr  bool
	}{
		{
			name: "successful decryption without AAD",
			data: &types.EncryptedData{
				Ciphertext: []byte("encrypted-data"),
				Algorithm:  string(types.SymmetricAES256GCM),
			},
			opts: nil,
			mockFunc: func(m *MockKMSClient) {
				m.DecryptFunc = func(ctx context.Context, req *kmspb.DecryptRequest, opts ...interface{}) (*kmspb.DecryptResponse, error) {
					plaintext := []byte("decrypted data")
					return &kmspb.DecryptResponse{
						Plaintext: plaintext,
						PlaintextCrc32C: &wrapperspb.Int64Value{
							Value: int64(crc32c(plaintext)),
						},
					}, nil
				}
			},
			wantErr: false,
		},
		{
			name: "successful decryption with AAD",
			data: &types.EncryptedData{
				Ciphertext: []byte("encrypted-with-aad"),
				Algorithm:  string(types.SymmetricAES256GCM),
			},
			opts: &types.DecryptOptions{
				AdditionalData: []byte("context information"),
			},
			mockFunc: func(m *MockKMSClient) {
				m.DecryptFunc = func(ctx context.Context, req *kmspb.DecryptRequest, opts ...interface{}) (*kmspb.DecryptResponse, error) {
					if len(req.AdditionalAuthenticatedData) == 0 {
						t.Error("DecryptFunc() AAD not provided")
					}
					plaintext := []byte("decrypted with aad")
					return &kmspb.DecryptResponse{
						Plaintext: plaintext,
						PlaintextCrc32C: &wrapperspb.Int64Value{
							Value: int64(crc32c(plaintext)),
						},
					}, nil
				}
			},
			wantErr: false,
		},
		{
			name: "checksum mismatch",
			data: &types.EncryptedData{
				Ciphertext: []byte("encrypted"),
				Algorithm:  string(types.SymmetricAES256GCM),
			},
			opts: nil,
			mockFunc: func(m *MockKMSClient) {
				m.DecryptFunc = func(ctx context.Context, req *kmspb.DecryptRequest, opts ...interface{}) (*kmspb.DecryptResponse, error) {
					return &kmspb.DecryptResponse{
						Plaintext: []byte("decrypted"),
						PlaintextCrc32C: &wrapperspb.Int64Value{
							Value: 88888, // Invalid checksum
						},
					}, nil
				}
			},
			wantErr: true,
		},
		{
			name: "KMS API error",
			data: &types.EncryptedData{
				Ciphertext: []byte("encrypted"),
				Algorithm:  string(types.SymmetricAES256GCM),
			},
			opts: nil,
			mockFunc: func(m *MockKMSClient) {
				m.DecryptFunc = func(ctx context.Context, req *kmspb.DecryptRequest, opts ...interface{}) (*kmspb.DecryptResponse, error) {
					return nil, errors.New("KMS decryption failed")
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
				KeyStorage:  storage.New(),
				CertStorage: storage.New(),
			}

			mockClient := &MockKMSClient{}
			if tt.mockFunc != nil {
				tt.mockFunc(mockClient)
			}

			// Setup mock for GetCryptoKey
			mockClient.GetCryptoKeyFunc = func(ctx context.Context, req *kmspb.GetCryptoKeyRequest, opts ...interface{}) (*kmspb.CryptoKey, error) {
				return &kmspb.CryptoKey{
					Name:    req.Name,
					Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT,
					Primary: &kmspb.CryptoKeyVersion{
						Name:      req.Name + "/cryptoKeyVersions/1",
						State:     kmspb.CryptoKeyVersion_ENABLED,
						Algorithm: kmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION,
					},
				}, nil
			}

			b, err := NewBackendWithClient(config, mockClient)
			if err != nil {
				t.Fatalf("Failed to create backend: %v", err)
			}

			attrs := &types.KeyAttributes{
				CN:                 "test-key",
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_GCPKMS,
				SymmetricAlgorithm: types.SymmetricAES256GCM,
			}

			encrypter, err := b.SymmetricEncrypter(attrs)
			if err != nil {
				t.Fatalf("Failed to create encrypter: %v", err)
			}

			plaintext, err := encrypter.Decrypt(tt.data, tt.opts)

			if tt.wantErr {
				if err == nil {
					t.Error("Decrypt() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Decrypt() unexpected error: %v", err)
				return
			}

			if plaintext == nil {
				t.Error("Decrypt() returned nil plaintext")
				return
			}

			if len(plaintext) == 0 {
				t.Error("Decrypt() returned empty plaintext")
			}
		})
	}
}

func TestSymmetricEncrypter_RoundTrip(t *testing.T) {
	config := &Config{
		ProjectID:   "test-project",
		LocationID:  "us-central1",
		KeyRingID:   "test-keyring",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}

	mockClient := &MockKMSClient{}

	// Setup mock for GetCryptoKey
	mockClient.GetCryptoKeyFunc = func(ctx context.Context, req *kmspb.GetCryptoKeyRequest, opts ...interface{}) (*kmspb.CryptoKey, error) {
		return &kmspb.CryptoKey{
			Name:    req.Name,
			Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT,
			Primary: &kmspb.CryptoKeyVersion{
				Name:      req.Name + "/cryptoKeyVersions/1",
				State:     kmspb.CryptoKeyVersion_ENABLED,
				Algorithm: kmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION,
			},
		}, nil
	}

	b, err := NewBackendWithClient(config, mockClient)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:                 "test-roundtrip-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_GCPKMS,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	encrypter, err := b.SymmetricEncrypter(attrs)
	if err != nil {
		t.Fatalf("Failed to create encrypter: %v", err)
	}

	// Test data
	originalPlaintext := []byte("This is a test message for encryption round-trip")
	aad := []byte("additional authenticated data")

	// Encrypt
	encrypted, err := encrypter.Encrypt(originalPlaintext, &types.EncryptOptions{
		AdditionalData: aad,
	})
	if err != nil {
		t.Fatalf("Encrypt() failed: %v", err)
	}

	// Decrypt
	decrypted, err := encrypter.Decrypt(encrypted, &types.DecryptOptions{
		AdditionalData: aad,
	})
	if err != nil {
		t.Fatalf("Decrypt() failed: %v", err)
	}

	// Verify round-trip
	if string(decrypted) != string(originalPlaintext) {
		t.Errorf("Round-trip failed: got %q, want %q", string(decrypted), string(originalPlaintext))
	}
}

func TestBackend_Capabilities_SymmetricEncryption(t *testing.T) {
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

	caps := b.Capabilities()

	if !caps.SupportsSymmetricEncryption() {
		t.Error("Backend should support symmetric encryption")
	}

	if !caps.SymmetricEncryption {
		t.Error("SymmetricEncryption capability should be true")
	}
}

// TestGCPKMSBackend_BytesLimit tests AEAD bytes limit enforcement.
// GCP KMS manages nonces server-side, so only bytes tracking is tested.
func TestGCPKMSBackend_BytesLimit(t *testing.T) {
	config := &Config{
		ProjectID:   "test-project",
		LocationID:  "us-central1",
		KeyRingID:   "test-keyring",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}

	mockClient := &MockKMSClient{}

	// Setup mock for GetCryptoKey
	mockClient.GetCryptoKeyFunc = func(ctx context.Context, req *kmspb.GetCryptoKeyRequest, opts ...interface{}) (*kmspb.CryptoKey, error) {
		return &kmspb.CryptoKey{
			Name:    req.Name,
			Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT,
			Primary: &kmspb.CryptoKeyVersion{
				Name:      req.Name + "/cryptoKeyVersions/1",
				State:     kmspb.CryptoKeyVersion_ENABLED,
				Algorithm: kmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION,
			},
		}, nil
	}

	// Setup mock for CreateCryptoKey
	mockClient.CreateCryptoKeyFunc = func(ctx context.Context, req *kmspb.CreateCryptoKeyRequest, opts ...interface{}) (*kmspb.CryptoKey, error) {
		return &kmspb.CryptoKey{
			Name:    req.Parent + "/cryptoKeys/" + req.CryptoKeyId,
			Purpose: req.CryptoKey.Purpose,
			Primary: &kmspb.CryptoKeyVersion{
				Name:      req.Parent + "/cryptoKeys/" + req.CryptoKeyId + "/cryptoKeyVersions/1",
				State:     kmspb.CryptoKeyVersion_ENABLED,
				Algorithm: kmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION,
			},
		}, nil
	}

	// Setup mock for Encrypt
	mockClient.EncryptFunc = func(ctx context.Context, req *kmspb.EncryptRequest, opts ...interface{}) (*kmspb.EncryptResponse, error) {
		ciphertext := []byte("mock-encrypted-data")
		return &kmspb.EncryptResponse{
			Ciphertext: ciphertext,
			CiphertextCrc32C: &wrapperspb.Int64Value{
				Value: int64(crc32c(ciphertext)),
			},
		}, nil
	}

	b, err := NewBackendWithClient(config, mockClient)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}

	// Generate a key with small bytes limit for testing
	smallLimit := int64(100) // 100 bytes
	attrs := &types.KeyAttributes{
		CN:                 "test-bytes-limit",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_GCPKMS,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		AEADOptions: &types.AEADOptions{
			NonceTracking:      false, // GCP KMS manages nonces
			BytesTracking:      true,
			BytesTrackingLimit: smallLimit,
		},
	}

	// Generate key
	_, err = b.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Get encrypter
	encrypter, err := b.SymmetricEncrypter(attrs)
	if err != nil {
		t.Fatalf("Failed to get encrypter: %v", err)
	}

	// Encrypt up to the limit
	plaintext := make([]byte, 50)

	// First 50 bytes - should succeed
	_, err = encrypter.Encrypt(plaintext, nil)
	if err != nil {
		t.Fatalf("First encryption failed: %v", err)
	}

	// Second 50 bytes - should succeed (total 100)
	_, err = encrypter.Encrypt(plaintext, nil)
	if err != nil {
		t.Fatalf("Second encryption failed: %v", err)
	}

	// Third 50 bytes - should fail (would exceed 100 byte limit)
	_, err = encrypter.Encrypt(plaintext, nil)
	if err == nil {
		t.Fatal("Expected bytes limit to be enforced")
	}

	// Verify error is ErrBytesLimitExceeded
	if !errors.Is(err, backend.ErrBytesLimitExceeded) {
		t.Errorf("Expected ErrBytesLimitExceeded, got: %v", err)
	}
}
