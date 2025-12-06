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
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// mockKMSClientSymmetric extends MockKMSClient with convenient defaults.
type mockKMSClientSymmetric struct {
	MockKMSClient
}

// TestGenerateSymmetricKey tests symmetric key generation.
func TestGenerateSymmetricKey(t *testing.T) {
	tests := []struct {
		name        string
		attrs       *types.KeyAttributes
		setupMock   func(*mockKMSClientSymmetric)
		wantErr     bool
		errContains string
	}{
		{
			name: "successful AES-256 key generation",
			attrs: &types.KeyAttributes{
				CN:                 "test-symmetric-key",
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_AWSKMS,
				SymmetricAlgorithm: types.SymmetricAES256GCM,
				AESAttributes: &types.AESAttributes{
					KeySize: 256,
				},
			},
			setupMock: func(m *mockKMSClientSymmetric) {
				m.CreateKeyFunc = func(ctx context.Context, params *kms.CreateKeyInput, optFns ...func(*kms.Options)) (*kms.CreateKeyOutput, error) {
					if params.KeySpec != kmstypes.KeySpecSymmetricDefault {
						return nil, errors.New("expected SYMMETRIC_DEFAULT key spec")
					}
					if params.KeyUsage != kmstypes.KeyUsageTypeEncryptDecrypt {
						return nil, errors.New("expected ENCRYPT_DECRYPT key usage")
					}
					return &kms.CreateKeyOutput{
						KeyMetadata: &kmstypes.KeyMetadata{
							KeyId: aws.String("test-key-id-123"),
						},
					}, nil
				}
				m.CreateAliasFunc = func(ctx context.Context, params *kms.CreateAliasInput, optFns ...func(*kms.Options)) (*kms.CreateAliasOutput, error) {
					return &kms.CreateAliasOutput{}, nil
				}
			},
			wantErr: false,
		},
		{
			name: "error - AES-128 not supported",
			attrs: &types.KeyAttributes{
				CN:                 "test-aes128-key",
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_AWSKMS,
				SymmetricAlgorithm: types.SymmetricAES128GCM,
				AESAttributes: &types.AESAttributes{
					KeySize: 128,
				},
			},
			setupMock:   func(m *mockKMSClientSymmetric) {},
			wantErr:     true,
			errContains: "only supports AES-256",
		},
		{
			name: "error - asymmetric algorithm",
			attrs: &types.KeyAttributes{
				CN:           "test-rsa-key",
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_AWSKMS,
				KeyAlgorithm: x509.RSA,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 2048,
				},
			},
			setupMock:   func(m *mockKMSClientSymmetric) {},
			wantErr:     true,
			errContains: "asymmetric algorithm",
		},
		{
			name: "error - key already exists",
			attrs: &types.KeyAttributes{
				CN:                 "existing-key",
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_AWSKMS,
				SymmetricAlgorithm: types.SymmetricAES256GCM,
				AESAttributes: &types.AESAttributes{
					KeySize: 256,
				},
			},
			setupMock: func(m *mockKMSClientSymmetric) {
				// Pre-populate metadata to simulate existing key
			},
			wantErr:     true,
			errContains: "already exists",
		},
		{
			name: "error - KMS create key fails",
			attrs: &types.KeyAttributes{
				CN:                 "test-error-key",
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_AWSKMS,
				SymmetricAlgorithm: types.SymmetricAES256GCM,
				AESAttributes: &types.AESAttributes{
					KeySize: 256,
				},
			},
			setupMock: func(m *mockKMSClientSymmetric) {
				m.CreateKeyFunc = func(ctx context.Context, params *kms.CreateKeyInput, optFns ...func(*kms.Options)) (*kms.CreateKeyOutput, error) {
					return nil, errors.New("KMS service error")
				}
			},
			wantErr:     true,
			errContains: "KMS service error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &mockKMSClientSymmetric{}
			tt.setupMock(mockClient)

			config := &Config{
				Region:      "us-east-1",
				KeyStorage:  storage.New(),
				CertStorage: storage.New(),
			}

			b, err := NewBackendWithClient(config, mockClient)
			if err != nil {
				t.Fatalf("Failed to create backend: %v", err)
			}

			// Pre-populate metadata if testing existing key
			if tt.name == "error - key already exists" {
				metadata := map[string]interface{}{
					"key_id": "existing-key-id",
				}
				metadataBytes, _ := json.Marshal(metadata)
				b.metadata[tt.attrs.CN] = metadataBytes
			}

			key, err := b.GenerateSymmetricKey(tt.attrs)

			if tt.wantErr {
				if err == nil {
					t.Errorf("GenerateSymmetricKey() expected error containing %q, got nil", tt.errContains)
					return
				}
				if tt.errContains != "" && !contains(err.Error(), tt.errContains) {
					t.Errorf("GenerateSymmetricKey() error = %v, want error containing %q", err, tt.errContains)
				}
				return
			}

			if err != nil {
				t.Errorf("GenerateSymmetricKey() unexpected error = %v", err)
				return
			}

			if key == nil {
				t.Error("GenerateSymmetricKey() returned nil key")
				return
			}

			// Verify key properties
			if key.Algorithm() != string(tt.attrs.SymmetricAlgorithm) {
				t.Errorf("Key algorithm = %v, want %v", key.Algorithm(), tt.attrs.SymmetricAlgorithm)
			}

			if key.KeySize() != 256 {
				t.Errorf("Key size = %v, want 256", key.KeySize())
			}

			// Verify metadata was stored
			if _, exists := b.metadata[tt.attrs.CN]; !exists {
				t.Error("Metadata not stored for generated key")
			}
		})
	}
}

// TestGetSymmetricKey tests retrieving existing symmetric keys.
func TestGetSymmetricKey(t *testing.T) {
	tests := []struct {
		name        string
		attrs       *types.KeyAttributes
		setupMock   func(*mockKMSClientSymmetric, *Backend)
		wantErr     bool
		errContains string
	}{
		{
			name: "successful key retrieval",
			attrs: &types.KeyAttributes{
				CN:                 "existing-key",
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_AWSKMS,
				SymmetricAlgorithm: types.SymmetricAES256GCM,
				AESAttributes: &types.AESAttributes{
					KeySize: 256,
				},
			},
			setupMock: func(m *mockKMSClientSymmetric, b *Backend) {
				// Setup metadata
				metadata := map[string]interface{}{
					"key_id":    "test-key-id-456",
					"algorithm": string(backend.ALG_AES256_GCM),
				}
				metadataBytes, _ := json.Marshal(metadata)
				b.metadata["existing-key"] = metadataBytes

				m.DescribeKeyFunc = func(ctx context.Context, params *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
					return &kms.DescribeKeyOutput{
						KeyMetadata: &kmstypes.KeyMetadata{
							KeyId: aws.String("test-key-id-456"),
						},
					}, nil
				}
			},
			wantErr: false,
		},
		{
			name: "error - key not found in metadata",
			attrs: &types.KeyAttributes{
				CN:                 "non-existent-key",
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_AWSKMS,
				SymmetricAlgorithm: types.SymmetricAES256GCM,
				AESAttributes: &types.AESAttributes{
					KeySize: 256,
				},
			},
			setupMock:   func(m *mockKMSClientSymmetric, b *Backend) {},
			wantErr:     true,
			errContains: "not found",
		},
		{
			name: "error - key not found in KMS",
			attrs: &types.KeyAttributes{
				CN:                 "deleted-key",
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_AWSKMS,
				SymmetricAlgorithm: types.SymmetricAES256GCM,
				AESAttributes: &types.AESAttributes{
					KeySize: 256,
				},
			},
			setupMock: func(m *mockKMSClientSymmetric, b *Backend) {
				metadata := map[string]interface{}{
					"key_id": "deleted-key-id",
				}
				metadataBytes, _ := json.Marshal(metadata)
				b.metadata["deleted-key"] = metadataBytes

				m.DescribeKeyFunc = func(ctx context.Context, params *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
					return nil, errors.New("NotFoundException: Key not found")
				}
			},
			wantErr:     true,
			errContains: "not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &mockKMSClientSymmetric{}

			config := &Config{
				Region:      "us-east-1",
				KeyStorage:  storage.New(),
				CertStorage: storage.New(),
			}

			b, err := NewBackendWithClient(config, mockClient)
			if err != nil {
				t.Fatalf("Failed to create backend: %v", err)
			}

			tt.setupMock(mockClient, b)

			key, err := b.GetSymmetricKey(tt.attrs)

			if tt.wantErr {
				if err == nil {
					t.Errorf("GetSymmetricKey() expected error containing %q, got nil", tt.errContains)
					return
				}
				if tt.errContains != "" && !contains(err.Error(), tt.errContains) {
					t.Errorf("GetSymmetricKey() error = %v, want error containing %q", err, tt.errContains)
				}
				return
			}

			if err != nil {
				t.Errorf("GetSymmetricKey() unexpected error = %v", err)
				return
			}

			if key == nil {
				t.Error("GetSymmetricKey() returned nil key")
				return
			}

			if key.Algorithm() != string(tt.attrs.SymmetricAlgorithm) {
				t.Errorf("Key algorithm = %v, want %v", key.Algorithm(), tt.attrs.SymmetricAlgorithm)
			}
		})
	}
}

// TestSymmetricEncrypter tests getting a symmetric encrypter.
func TestSymmetricEncrypter(t *testing.T) {
	tests := []struct {
		name        string
		attrs       *types.KeyAttributes
		setupMock   func(*mockKMSClientSymmetric, *Backend)
		wantErr     bool
		errContains string
	}{
		{
			name: "successful encrypter creation",
			attrs: &types.KeyAttributes{
				CN:                 "encryption-key",
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_AWSKMS,
				SymmetricAlgorithm: types.SymmetricAES256GCM,
				AESAttributes: &types.AESAttributes{
					KeySize: 256,
				},
			},
			setupMock: func(m *mockKMSClientSymmetric, b *Backend) {
				metadata := map[string]interface{}{
					"key_id": "encryption-key-id",
				}
				metadataBytes, _ := json.Marshal(metadata)
				b.metadata["encryption-key"] = metadataBytes
			},
			wantErr: false,
		},
		{
			name: "error - key not found",
			attrs: &types.KeyAttributes{
				CN:                 "missing-key",
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_AWSKMS,
				SymmetricAlgorithm: types.SymmetricAES256GCM,
				AESAttributes: &types.AESAttributes{
					KeySize: 256,
				},
			},
			setupMock:   func(m *mockKMSClientSymmetric, b *Backend) {},
			wantErr:     true,
			errContains: "not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &mockKMSClientSymmetric{}

			config := &Config{
				Region:      "us-east-1",
				KeyStorage:  storage.New(),
				CertStorage: storage.New(),
			}

			b, err := NewBackendWithClient(config, mockClient)
			if err != nil {
				t.Fatalf("Failed to create backend: %v", err)
			}

			tt.setupMock(mockClient, b)

			encrypter, err := b.SymmetricEncrypter(tt.attrs)

			if tt.wantErr {
				if err == nil {
					t.Errorf("SymmetricEncrypter() expected error containing %q, got nil", tt.errContains)
					return
				}
				if tt.errContains != "" && !contains(err.Error(), tt.errContains) {
					t.Errorf("SymmetricEncrypter() error = %v, want error containing %q", err, tt.errContains)
				}
				return
			}

			if err != nil {
				t.Errorf("SymmetricEncrypter() unexpected error = %v", err)
				return
			}

			if encrypter == nil {
				t.Error("SymmetricEncrypter() returned nil encrypter")
			}
		})
	}
}

// TestSymmetricEncrypt tests symmetric encryption.
func TestSymmetricEncrypt(t *testing.T) {
	tests := []struct {
		name        string
		plaintext   []byte
		opts        *types.EncryptOptions
		setupMock   func(*mockKMSClientSymmetric)
		wantErr     bool
		errContains string
	}{
		{
			name:      "successful encryption without AAD",
			plaintext: []byte("sensitive data to encrypt"),
			opts:      nil,
			setupMock: func(m *mockKMSClientSymmetric) {
				m.EncryptFunc = func(ctx context.Context, params *kms.EncryptInput, optFns ...func(*kms.Options)) (*kms.EncryptOutput, error) {
					if params.EncryptionContext != nil {
						return nil, errors.New("unexpected encryption context")
					}
					return &kms.EncryptOutput{
						CiphertextBlob: []byte("encrypted-ciphertext"),
						KeyId:          params.KeyId,
					}, nil
				}
			},
			wantErr: false,
		},
		{
			name:      "successful encryption with AAD",
			plaintext: []byte("data with context"),
			opts: &types.EncryptOptions{
				AdditionalData: []byte("context information"),
			},
			setupMock: func(m *mockKMSClientSymmetric) {
				m.EncryptFunc = func(ctx context.Context, params *kms.EncryptInput, optFns ...func(*kms.Options)) (*kms.EncryptOutput, error) {
					if params.EncryptionContext == nil {
						return nil, errors.New("expected encryption context")
					}
					if aad, ok := params.EncryptionContext["aad"]; !ok || aad != "context information" {
						return nil, fmt.Errorf("unexpected AAD: %v", params.EncryptionContext)
					}
					return &kms.EncryptOutput{
						CiphertextBlob: []byte("encrypted-with-aad"),
						KeyId:          params.KeyId,
					}, nil
				}
			},
			wantErr: false,
		},
		{
			name:      "error - KMS encryption fails",
			plaintext: []byte("data"),
			opts:      nil,
			setupMock: func(m *mockKMSClientSymmetric) {
				m.EncryptFunc = func(ctx context.Context, params *kms.EncryptInput, optFns ...func(*kms.Options)) (*kms.EncryptOutput, error) {
					return nil, errors.New("KMS encryption error")
				}
			},
			wantErr:     true,
			errContains: "KMS encryption error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &mockKMSClientSymmetric{}
			tt.setupMock(mockClient)

			config := &Config{
				Region:      "us-east-1",
				KeyStorage:  storage.New(),
				CertStorage: storage.New(),
			}

			b, err := NewBackendWithClient(config, mockClient)
			if err != nil {
				t.Fatalf("Failed to create backend: %v", err)
			}

			// Setup metadata
			metadata := map[string]interface{}{
				"key_id": "test-encryption-key",
			}
			metadataBytes, _ := json.Marshal(metadata)
			b.metadata["test-key"] = metadataBytes

			attrs := &types.KeyAttributes{
				CN:                 "test-key",
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_AWSKMS,
				SymmetricAlgorithm: types.SymmetricAES256GCM,
				AESAttributes: &types.AESAttributes{
					KeySize: 256,
				},
			}

			encrypter, err := b.SymmetricEncrypter(attrs)
			if err != nil {
				t.Fatalf("Failed to get encrypter: %v", err)
			}

			encrypted, err := encrypter.Encrypt(tt.plaintext, tt.opts)

			if tt.wantErr {
				if err == nil {
					t.Errorf("Encrypt() expected error containing %q, got nil", tt.errContains)
					return
				}
				if tt.errContains != "" && !contains(err.Error(), tt.errContains) {
					t.Errorf("Encrypt() error = %v, want error containing %q", err, tt.errContains)
				}
				return
			}

			if err != nil {
				t.Errorf("Encrypt() unexpected error = %v", err)
				return
			}

			if encrypted == nil {
				t.Error("Encrypt() returned nil encrypted data")
				return
			}

			if len(encrypted.Ciphertext) == 0 {
				t.Error("Encrypt() returned empty ciphertext")
			}

			if encrypted.Algorithm != string(backend.ALG_AES256_GCM) {
				t.Errorf("Encrypted data algorithm = %v, want %v", encrypted.Algorithm, backend.ALG_AES256_GCM)
			}
		})
	}
}

// TestSymmetricDecrypt tests symmetric decryption.
func TestSymmetricDecrypt(t *testing.T) {
	tests := []struct {
		name        string
		encrypted   *types.EncryptedData
		opts        *types.DecryptOptions
		setupMock   func(*mockKMSClientSymmetric)
		wantErr     bool
		errContains string
	}{
		{
			name: "successful decryption without AAD",
			encrypted: &types.EncryptedData{
				Ciphertext: []byte("encrypted-data"),
				Algorithm:  string(backend.ALG_AES256_GCM),
			},
			opts: nil,
			setupMock: func(m *mockKMSClientSymmetric) {
				m.DecryptFunc = func(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error) {
					return &kms.DecryptOutput{
						Plaintext: []byte("decrypted plaintext"),
						KeyId:     params.KeyId,
					}, nil
				}
			},
			wantErr: false,
		},
		{
			name: "successful decryption with AAD",
			encrypted: &types.EncryptedData{
				Ciphertext: []byte("encrypted-with-aad"),
				Algorithm:  string(backend.ALG_AES256_GCM),
			},
			opts: &types.DecryptOptions{
				AdditionalData: []byte("matching context"),
			},
			setupMock: func(m *mockKMSClientSymmetric) {
				m.DecryptFunc = func(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error) {
					if params.EncryptionContext == nil {
						return nil, errors.New("expected encryption context")
					}
					if aad, ok := params.EncryptionContext["aad"]; !ok || aad != "matching context" {
						return nil, errors.New("AAD mismatch")
					}
					return &kms.DecryptOutput{
						Plaintext: []byte("decrypted with aad"),
						KeyId:     params.KeyId,
					}, nil
				}
			},
			wantErr: false,
		},
		{
			name: "error - KMS decryption fails (authentication error)",
			encrypted: &types.EncryptedData{
				Ciphertext: []byte("tampered-data"),
				Algorithm:  string(backend.ALG_AES256_GCM),
			},
			opts: nil,
			setupMock: func(m *mockKMSClientSymmetric) {
				m.DecryptFunc = func(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error) {
					return nil, errors.New("InvalidCiphertextException: authentication failed")
				}
			},
			wantErr:     true,
			errContains: "authentication failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &mockKMSClientSymmetric{}
			tt.setupMock(mockClient)

			config := &Config{
				Region:      "us-east-1",
				KeyStorage:  storage.New(),
				CertStorage: storage.New(),
			}

			b, err := NewBackendWithClient(config, mockClient)
			if err != nil {
				t.Fatalf("Failed to create backend: %v", err)
			}

			// Setup metadata
			metadata := map[string]interface{}{
				"key_id": "test-decryption-key",
			}
			metadataBytes, _ := json.Marshal(metadata)
			b.metadata["test-key"] = metadataBytes

			attrs := &types.KeyAttributes{
				CN:                 "test-key",
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_AWSKMS,
				SymmetricAlgorithm: types.SymmetricAES256GCM,
				AESAttributes: &types.AESAttributes{
					KeySize: 256,
				},
			}

			encrypter, err := b.SymmetricEncrypter(attrs)
			if err != nil {
				t.Fatalf("Failed to get encrypter: %v", err)
			}

			plaintext, err := encrypter.Decrypt(tt.encrypted, tt.opts)

			if tt.wantErr {
				if err == nil {
					t.Errorf("Decrypt() expected error containing %q, got nil", tt.errContains)
					return
				}
				if tt.errContains != "" && !contains(err.Error(), tt.errContains) {
					t.Errorf("Decrypt() error = %v, want error containing %q", err, tt.errContains)
				}
				return
			}

			if err != nil {
				t.Errorf("Decrypt() unexpected error = %v", err)
				return
			}

			if len(plaintext) == 0 {
				t.Error("Decrypt() returned empty plaintext")
			}
		})
	}
}

// TestSymmetricEncryptDecryptRoundTrip tests full encrypt/decrypt round trip.
func TestSymmetricEncryptDecryptRoundTrip(t *testing.T) {
	mockClient := &mockKMSClientSymmetric{}

	// Setup mock to store and retrieve encrypted data
	var storedContext map[string]string

	mockClient.EncryptFunc = func(ctx context.Context, params *kms.EncryptInput, optFns ...func(*kms.Options)) (*kms.EncryptOutput, error) {
		// Store encryption context for testing
		storedContext = params.EncryptionContext
		return &kms.EncryptOutput{
			CiphertextBlob: params.Plaintext, // Return plaintext as ciphertext for mock
			KeyId:          params.KeyId,
		}, nil
	}

	mockClient.DecryptFunc = func(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error) {
		// Verify context matches
		if storedContext != nil {
			if params.EncryptionContext == nil {
				return nil, errors.New("missing encryption context")
			}
			for k, v := range storedContext {
				if params.EncryptionContext[k] != v {
					return nil, errors.New("encryption context mismatch")
				}
			}
		}
		return &kms.DecryptOutput{
			Plaintext: params.CiphertextBlob, // Return ciphertext as plaintext for mock
			KeyId:     params.KeyId,
		}, nil
	}

	config := &Config{
		Region:      "us-east-1",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}

	b, err := NewBackendWithClient(config, mockClient)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}

	// Setup metadata
	metadata := map[string]interface{}{
		"key_id": "test-round-trip-key",
	}
	metadataBytes, _ := json.Marshal(metadata)
	b.metadata["round-trip-key"] = metadataBytes

	attrs := &types.KeyAttributes{
		CN:                 "round-trip-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_AWSKMS,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		AESAttributes: &types.AESAttributes{
			KeySize: 256,
		},
	}

	encrypter, err := b.SymmetricEncrypter(attrs)
	if err != nil {
		t.Fatalf("Failed to get encrypter: %v", err)
	}

	// Test without AAD
	t.Run("round trip without AAD", func(t *testing.T) {
		originalPlaintext := []byte("test data without context")

		encrypted, err := encrypter.Encrypt(originalPlaintext, nil)
		if err != nil {
			t.Fatalf("Encrypt() failed: %v", err)
		}

		decrypted, err := encrypter.Decrypt(encrypted, nil)
		if err != nil {
			t.Fatalf("Decrypt() failed: %v", err)
		}

		if string(decrypted) != string(originalPlaintext) {
			t.Errorf("Round trip failed: got %q, want %q", decrypted, originalPlaintext)
		}
	})

	// Test with AAD
	t.Run("round trip with AAD", func(t *testing.T) {
		originalPlaintext := []byte("test data with context")
		aad := []byte("important context")

		encrypted, err := encrypter.Encrypt(originalPlaintext, &types.EncryptOptions{
			AdditionalData: aad,
		})
		if err != nil {
			t.Fatalf("Encrypt() failed: %v", err)
		}

		decrypted, err := encrypter.Decrypt(encrypted, &types.DecryptOptions{
			AdditionalData: aad,
		})
		if err != nil {
			t.Fatalf("Decrypt() failed: %v", err)
		}

		if string(decrypted) != string(originalPlaintext) {
			t.Errorf("Round trip failed: got %q, want %q", decrypted, originalPlaintext)
		}
	})
}

// TestBackendImplementsSymmetricBackend verifies the Backend type implements SymmetricBackend.
func TestBackendImplementsSymmetricBackend(t *testing.T) {
	mockClient := &mockKMSClientSymmetric{}

	config := &Config{
		Region:      "us-east-1",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}

	b, err := NewBackendWithClient(config, mockClient)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}

	// Type assertion to verify interface implementation
	_, ok := interface{}(b).(types.SymmetricBackend)
	if !ok {
		t.Error("Backend does not implement SymmetricBackend interface")
	}
}

// TestCapabilitiesSupportsSymmetricEncryption tests the Capabilities method.
func TestCapabilitiesSupportsSymmetricEncryption(t *testing.T) {
	mockClient := &mockKMSClientSymmetric{}

	config := &Config{
		Region:      "us-east-1",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}

	b, err := NewBackendWithClient(config, mockClient)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}

	caps := b.Capabilities()

	if !caps.SupportsSymmetricEncryption() {
		t.Error("Capabilities.SupportsSymmetricEncryption() returned false, want true")
	}

	if !caps.SymmetricEncryption {
		t.Error("Capabilities.SymmetricEncryption is false, want true")
	}
}

// TestAWSKMSBackend_BytesLimit tests AEAD bytes limit enforcement.
// AWS KMS manages nonces server-side, so only bytes tracking is tested.
func TestAWSKMSBackend_BytesLimit(t *testing.T) {
	mockClient := &mockKMSClientSymmetric{}

	// Setup mock for encryption operations
	mockClient.EncryptFunc = func(ctx context.Context, params *kms.EncryptInput, optFns ...func(*kms.Options)) (*kms.EncryptOutput, error) {
		return &kms.EncryptOutput{
			CiphertextBlob: []byte("mock-encrypted-data"),
			KeyId:          params.KeyId,
		}, nil
	}

	config := &Config{
		Region:      "us-east-1",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
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
		StoreType:          backend.STORE_AWSKMS,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		AESAttributes: &types.AESAttributes{
			KeySize: 256,
		},
		AEADOptions: &types.AEADOptions{
			NonceTracking:      false, // AWS KMS manages nonces
			BytesTracking:      true,
			BytesTrackingLimit: smallLimit,
		},
	}

	// Setup mock for key creation
	mockClient.CreateKeyFunc = func(ctx context.Context, params *kms.CreateKeyInput, optFns ...func(*kms.Options)) (*kms.CreateKeyOutput, error) {
		return &kms.CreateKeyOutput{
			KeyMetadata: &kmstypes.KeyMetadata{
				KeyId: aws.String("test-key-id-bytes-limit"),
			},
		}, nil
	}
	mockClient.CreateAliasFunc = func(ctx context.Context, params *kms.CreateAliasInput, optFns ...func(*kms.Options)) (*kms.CreateAliasOutput, error) {
		return &kms.CreateAliasOutput{}, nil
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

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(substr) == 0 || (len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
