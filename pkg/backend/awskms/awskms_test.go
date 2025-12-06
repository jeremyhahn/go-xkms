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
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// TestNewBackend tests the NewBackend constructor.
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
				Region:      "us-east-1",
				KeyStorage:  storage.New(),
				CertStorage: storage.New(),
			},
			wantErr: false,
		},
		{
			name: "valid config with credentials",
			config: &Config{
				Region:          "us-west-2",
				AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
				SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				KeyStorage:      storage.New(),
				CertStorage:     storage.New(),
			},
			wantErr: false,
		},
		{
			name: "invalid config - missing region",
			config: &Config{
				AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
				SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			},
			wantErr: true,
			errType: ErrInvalidConfig,
		},
		{
			name:    "invalid config - nil",
			config:  nil,
			wantErr: true,
			errType: ErrInvalidConfig,
		},
		{
			name: "invalid region format",
			config: &Config{
				Region:      "invalid_region",
				KeyStorage:  storage.New(),
				CertStorage: storage.New(),
			},
			wantErr: true,
			errType: ErrInvalidConfig,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := NewBackend(tt.config)
			if tt.wantErr {
				if err == nil {
					t.Errorf("NewBackend() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("NewBackend() unexpected error: %v", err)
				return
			}
			if b == nil {
				t.Errorf("NewBackend() returned nil backend")
			}
		})
	}
}

// TestNewBackendWithClient tests the NewBackendWithClient constructor.
func TestNewBackendWithClient(t *testing.T) {
	mockClient := &MockKMSClient{}
	config := &Config{
		Region:      "us-east-1",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}

	b, err := NewBackendWithClient(config, mockClient)
	if err != nil {
		t.Errorf("NewBackendWithClient() unexpected error: %v", err)
	}
	if b == nil {
		t.Errorf("NewBackendWithClient() returned nil backend")
	}
	if b.client != mockClient {
		t.Errorf("NewBackendWithClient() client not set correctly")
	}
}

// TestSave tests the Save method.
func TestSave(t *testing.T) {
	mockClient := &MockKMSClient{}
	config := &Config{
		Region:      "us-east-1",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}
	b, _ := NewBackendWithClient(config, mockClient)

	attrs := &types.KeyAttributes{
		CN:           "test-key",
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_AWSKMS,
		KeyAlgorithm: x509.RSA,
	}

	tests := []struct {
		name      string
		attrs     *types.KeyAttributes
		data      []byte
		extension types.FSExtension
		overwrite bool
		wantErr   bool
	}{
		{
			name:      "save new metadata",
			attrs:     attrs,
			data:      []byte("test-data"),
			extension: backend.FSEXT_PRIVATE_BLOB,
			overwrite: false,
			wantErr:   false,
		},
		{
			name:      "save existing without overwrite",
			attrs:     attrs,
			data:      []byte("new-data"),
			extension: backend.FSEXT_PRIVATE_BLOB,
			overwrite: false,
			wantErr:   true,
		},
		{
			name:      "save existing with overwrite",
			attrs:     attrs,
			data:      []byte("overwritten-data"),
			extension: backend.FSEXT_PRIVATE_BLOB,
			overwrite: true,
			wantErr:   false,
		},
		{
			name:      "nil attributes",
			attrs:     nil,
			data:      []byte("test-data"),
			extension: backend.FSEXT_PRIVATE_BLOB,
			overwrite: false,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := b.Save(tt.attrs, tt.data, tt.extension, tt.overwrite)
			if (err != nil) != tt.wantErr {
				t.Errorf("Save() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestGet tests the Get method.
func TestGet(t *testing.T) {
	mockClient := &MockKMSClient{
		GetPublicKeyFunc: func(ctx context.Context, params *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
			return &kms.GetPublicKeyOutput{
				PublicKey: []byte("mock-public-key"),
			}, nil
		},
	}

	config := &Config{
		Region:      "us-east-1",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}
	b, _ := NewBackendWithClient(config, mockClient)

	attrs := &types.KeyAttributes{
		CN:           "test-key",
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_AWSKMS,
		KeyAlgorithm: x509.RSA,
	}

	// Save some metadata first
	testData := []byte("test-metadata")
	_ = b.Save(attrs, testData, backend.FSEXT_PRIVATE_BLOB, false)

	tests := []struct {
		name      string
		attrs     *types.KeyAttributes
		extension types.FSExtension
		wantErr   bool
	}{
		{
			name:      "get existing metadata",
			attrs:     attrs,
			extension: backend.FSEXT_PRIVATE_BLOB,
			wantErr:   false,
		},
		{
			name:      "get public key",
			attrs:     attrs,
			extension: backend.FSEXT_PUBLIC_PKCS1,
			wantErr:   false,
		},
		{
			name: "get non-existent metadata",
			attrs: &types.KeyAttributes{
				CN:           "non-existent",
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_AWSKMS,
				KeyAlgorithm: x509.RSA,
			},
			extension: backend.FSEXT_PRIVATE_BLOB,
			wantErr:   true,
		},
		{
			name:      "nil attributes",
			attrs:     nil,
			extension: backend.FSEXT_PRIVATE_BLOB,
			wantErr:   true,
		},
		{
			name:      "unsupported extension",
			attrs:     attrs,
			extension: backend.FSEXT_DIGEST,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := b.Get(tt.attrs, tt.extension)
			if (err != nil) != tt.wantErr {
				t.Errorf("Get() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && data == nil {
				t.Errorf("Get() returned nil data when expecting data")
			}
		})
	}
}

// TestGetPublicKeyError tests Get with KMS error.
func TestGetPublicKeyError(t *testing.T) {
	mockClient := &MockKMSClient{
		GetPublicKeyFunc: func(ctx context.Context, params *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
			return nil, errors.New("KMS error")
		},
	}

	config := &Config{
		Region:      "us-east-1",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}
	b, _ := NewBackendWithClient(config, mockClient)

	attrs := &types.KeyAttributes{
		CN:           "test-key",
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_AWSKMS,
		KeyAlgorithm: x509.RSA,
	}

	_, err := b.Get(attrs, backend.FSEXT_PUBLIC_PEM)
	if err == nil {
		t.Errorf("Get() expected error for KMS failure")
	}
}

// TestDelete tests the Delete method.
func TestDelete(t *testing.T) {
	deleteCalled := false
	mockClient := &MockKMSClient{
		ScheduleKeyDeletionFunc: func(ctx context.Context, params *kms.ScheduleKeyDeletionInput, optFns ...func(*kms.Options)) (*kms.ScheduleKeyDeletionOutput, error) {
			deleteCalled = true
			return &kms.ScheduleKeyDeletionOutput{}, nil
		},
	}

	config := &Config{
		Region:      "us-east-1",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}
	b, _ := NewBackendWithClient(config, mockClient)

	attrs := &types.KeyAttributes{
		CN:           "test-key",
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_AWSKMS,
		KeyAlgorithm: x509.RSA,
	}

	// Save metadata first
	_ = b.Save(attrs, []byte("test-data"), backend.FSEXT_PRIVATE_BLOB, false)

	err := b.Delete(attrs)
	if err != nil {
		t.Errorf("Delete() unexpected error: %v", err)
	}

	if !deleteCalled {
		t.Errorf("Delete() did not call ScheduleKeyDeletion")
	}

	// Verify metadata was deleted
	_, err = b.Get(attrs, backend.FSEXT_PRIVATE_BLOB)
	if err == nil {
		t.Errorf("Delete() metadata still exists after deletion")
	}
}

// TestDeleteNilAttributes tests Delete with nil attributes.
func TestDeleteNilAttributes(t *testing.T) {
	mockClient := &MockKMSClient{}
	config := &Config{
		Region:      "us-east-1",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}
	b, _ := NewBackendWithClient(config, mockClient)

	err := b.Delete(nil)
	if err == nil {
		t.Errorf("Delete() expected error for nil attributes")
	}
}

// TestDeleteKMSError tests Delete with KMS error (should still succeed for idempotency).
func TestDeleteKMSError(t *testing.T) {
	mockClient := &MockKMSClient{
		ScheduleKeyDeletionFunc: func(ctx context.Context, params *kms.ScheduleKeyDeletionInput, optFns ...func(*kms.Options)) (*kms.ScheduleKeyDeletionOutput, error) {
			return nil, errors.New("key not found")
		},
	}

	config := &Config{
		Region:      "us-east-1",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}
	b, _ := NewBackendWithClient(config, mockClient)

	attrs := &types.KeyAttributes{
		CN:           "test-key",
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_AWSKMS,
		KeyAlgorithm: x509.RSA,
	}

	err := b.Delete(attrs)
	if err != nil {
		t.Errorf("Delete() should succeed even with KMS error (idempotent), got: %v", err)
	}
}

// TestClose tests the Close method.
func TestClose(t *testing.T) {
	mockClient := &MockKMSClient{}
	config := &Config{
		Region:      "us-east-1",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}
	b, _ := NewBackendWithClient(config, mockClient)

	attrs := &types.KeyAttributes{
		CN:           "test-key",
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_AWSKMS,
		KeyAlgorithm: x509.RSA,
	}

	// Save some metadata
	_ = b.Save(attrs, []byte("test-data"), backend.FSEXT_PRIVATE_BLOB, false)

	err := b.Close()
	if err != nil {
		t.Errorf("Close() unexpected error: %v", err)
	}

	// Verify metadata was cleared
	if len(b.metadata) != 0 {
		t.Errorf("Close() did not clear metadata")
	}

	if b.client != nil {
		t.Errorf("Close() did not clear client")
	}
}

// TestCreateKey tests the CreateKey method.
func TestCreateKey(t *testing.T) {
	tests := []struct {
		name        string
		attrs       *types.KeyAttributes
		mockSetup   func(*MockKMSClient)
		wantErr     bool
		wantKeyID   string
		aliasExists bool
	}{
		{
			name: "create RSA signing key",
			attrs: &types.KeyAttributes{
				CN:           "rsa-test-key",
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_AWSKMS,
				KeyAlgorithm: x509.RSA,
			},
			mockSetup: func(m *MockKMSClient) {
				m.CreateKeyFunc = func(ctx context.Context, params *kms.CreateKeyInput, optFns ...func(*kms.Options)) (*kms.CreateKeyOutput, error) {
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
			wantErr:     false,
			wantKeyID:   "test-key-id-123",
			aliasExists: true,
		},
		{
			name: "create ECDSA encryption key",
			attrs: &types.KeyAttributes{
				CN:           "ecdsa-test-key",
				KeyType:      backend.KEY_TYPE_ENCRYPTION,
				StoreType:    backend.STORE_AWSKMS,
				KeyAlgorithm: x509.ECDSA,
			},
			mockSetup: func(m *MockKMSClient) {
				m.CreateKeyFunc = func(ctx context.Context, params *kms.CreateKeyInput, optFns ...func(*kms.Options)) (*kms.CreateKeyOutput, error) {
					return &kms.CreateKeyOutput{
						KeyMetadata: &kmstypes.KeyMetadata{
							KeyId: aws.String("test-key-id-456"),
						},
					}, nil
				}
				m.CreateAliasFunc = func(ctx context.Context, params *kms.CreateAliasInput, optFns ...func(*kms.Options)) (*kms.CreateAliasOutput, error) {
					return &kms.CreateAliasOutput{}, nil
				}
			},
			wantErr:     false,
			wantKeyID:   "test-key-id-456",
			aliasExists: true,
		},
		{
			name: "create key with alias failure",
			attrs: &types.KeyAttributes{
				CN:           "alias-fail-key",
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_AWSKMS,
				KeyAlgorithm: x509.RSA,
			},
			mockSetup: func(m *MockKMSClient) {
				m.CreateKeyFunc = func(ctx context.Context, params *kms.CreateKeyInput, optFns ...func(*kms.Options)) (*kms.CreateKeyOutput, error) {
					return &kms.CreateKeyOutput{
						KeyMetadata: &kmstypes.KeyMetadata{
							KeyId: aws.String("test-key-id-789"),
						},
					}, nil
				}
				m.CreateAliasFunc = func(ctx context.Context, params *kms.CreateAliasInput, optFns ...func(*kms.Options)) (*kms.CreateAliasOutput, error) {
					return nil, errors.New("alias already exists")
				}
			},
			wantErr:     false,
			wantKeyID:   "test-key-id-789",
			aliasExists: false,
		},
		{
			name: "create key KMS error",
			attrs: &types.KeyAttributes{
				CN:           "error-key",
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_AWSKMS,
				KeyAlgorithm: x509.RSA,
			},
			mockSetup: func(m *MockKMSClient) {
				m.CreateKeyFunc = func(ctx context.Context, params *kms.CreateKeyInput, optFns ...func(*kms.Options)) (*kms.CreateKeyOutput, error) {
					return nil, errors.New("KMS service error")
				}
			},
			wantErr: true,
		},
		{
			name:    "nil attributes",
			attrs:   nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &MockKMSClient{}
			if tt.mockSetup != nil {
				tt.mockSetup(mockClient)
			}

			config := &Config{
				Region:      "us-east-1",
				KeyStorage:  storage.New(),
				CertStorage: storage.New(),
			}
			b, _ := NewBackendWithClient(config, mockClient)

			keyID, err := b.CreateKey(tt.attrs)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if keyID != tt.wantKeyID {
					t.Errorf("CreateKey() keyID = %v, want %v", keyID, tt.wantKeyID)
				}

				// Verify metadata was stored
				b.mu.RLock()
				metadataBytes, ok := b.metadata[tt.attrs.CN]
				b.mu.RUnlock()

				if !ok {
					t.Errorf("CreateKey() metadata not stored")
				} else {
					var metadata map[string]interface{}
					if err := json.Unmarshal(metadataBytes, &metadata); err != nil {
						t.Errorf("CreateKey() invalid metadata JSON: %v", err)
					}
					if metadata["key_id"] != tt.wantKeyID {
						t.Errorf("CreateKey() metadata key_id = %v, want %v", metadata["key_id"], tt.wantKeyID)
					}
				}
			}
		})
	}
}

// TestSign tests the Sign method.
func TestSign(t *testing.T) {
	tests := []struct {
		name      string
		attrs     *types.KeyAttributes
		digest    []byte
		mockSetup func(*MockKMSClient)
		wantErr   bool
	}{
		{
			name: "sign with RSA",
			attrs: &types.KeyAttributes{
				CN:           "rsa-key",
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_AWSKMS,
				KeyAlgorithm: x509.RSA,
			},
			digest: []byte("test-digest"),
			mockSetup: func(m *MockKMSClient) {
				m.SignFunc = func(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error) {
					return &kms.SignOutput{
						Signature: []byte("mock-signature"),
					}, nil
				}
			},
			wantErr: false,
		},
		{
			name: "sign with ECDSA",
			attrs: &types.KeyAttributes{
				CN:           "ecdsa-key",
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_AWSKMS,
				KeyAlgorithm: x509.ECDSA,
			},
			digest: []byte("test-digest"),
			mockSetup: func(m *MockKMSClient) {
				m.SignFunc = func(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error) {
					return &kms.SignOutput{
						Signature: []byte("mock-ecdsa-signature"),
					}, nil
				}
			},
			wantErr: false,
		},
		{
			name: "sign KMS error",
			attrs: &types.KeyAttributes{
				CN:           "error-key",
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_AWSKMS,
				KeyAlgorithm: x509.RSA,
			},
			digest: []byte("test-digest"),
			mockSetup: func(m *MockKMSClient) {
				m.SignFunc = func(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error) {
					return nil, errors.New("KMS sign error")
				}
			},
			wantErr: true,
		},
		{
			name:    "nil attributes",
			attrs:   nil,
			digest:  []byte("test-digest"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &MockKMSClient{}
			if tt.mockSetup != nil {
				tt.mockSetup(mockClient)
			}

			config := &Config{
				Region:      "us-east-1",
				KeyStorage:  storage.New(),
				CertStorage: storage.New(),
			}
			b, _ := NewBackendWithClient(config, mockClient)

			signature, err := b.Sign(tt.attrs, tt.digest)
			if (err != nil) != tt.wantErr {
				t.Errorf("Sign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && signature == nil {
				t.Errorf("Sign() returned nil signature")
			}
		})
	}
}

// TestVerify tests the Verify method.
func TestVerify(t *testing.T) {
	tests := []struct {
		name      string
		attrs     *types.KeyAttributes
		digest    []byte
		signature []byte
		mockSetup func(*MockKMSClient)
		wantErr   bool
	}{
		{
			name: "verify valid signature",
			attrs: &types.KeyAttributes{
				CN:           "test-key",
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_AWSKMS,
				KeyAlgorithm: x509.RSA,
			},
			digest:    []byte("test-digest"),
			signature: []byte("valid-signature"),
			mockSetup: func(m *MockKMSClient) {
				m.VerifyFunc = func(ctx context.Context, params *kms.VerifyInput, optFns ...func(*kms.Options)) (*kms.VerifyOutput, error) {
					return &kms.VerifyOutput{
						SignatureValid: true,
					}, nil
				}
			},
			wantErr: false,
		},
		{
			name: "verify invalid signature",
			attrs: &types.KeyAttributes{
				CN:           "test-key",
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_AWSKMS,
				KeyAlgorithm: x509.RSA,
			},
			digest:    []byte("test-digest"),
			signature: []byte("invalid-signature"),
			mockSetup: func(m *MockKMSClient) {
				m.VerifyFunc = func(ctx context.Context, params *kms.VerifyInput, optFns ...func(*kms.Options)) (*kms.VerifyOutput, error) {
					return &kms.VerifyOutput{
						SignatureValid: false,
					}, nil
				}
			},
			wantErr: true,
		},
		{
			name: "verify KMS error",
			attrs: &types.KeyAttributes{
				CN:           "test-key",
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_AWSKMS,
				KeyAlgorithm: x509.RSA,
			},
			digest:    []byte("test-digest"),
			signature: []byte("signature"),
			mockSetup: func(m *MockKMSClient) {
				m.VerifyFunc = func(ctx context.Context, params *kms.VerifyInput, optFns ...func(*kms.Options)) (*kms.VerifyOutput, error) {
					return nil, errors.New("KMS verify error")
				}
			},
			wantErr: true,
		},
		{
			name:      "nil attributes",
			attrs:     nil,
			digest:    []byte("test-digest"),
			signature: []byte("signature"),
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &MockKMSClient{}
			if tt.mockSetup != nil {
				tt.mockSetup(mockClient)
			}

			config := &Config{
				Region:      "us-east-1",
				KeyStorage:  storage.New(),
				CertStorage: storage.New(),
			}
			b, _ := NewBackendWithClient(config, mockClient)

			err := b.Verify(tt.attrs, tt.digest, tt.signature)
			if (err != nil) != tt.wantErr {
				t.Errorf("Verify() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestConcurrentAccess tests concurrent access to the backend.
func TestConcurrentAccess(t *testing.T) {
	mockClient := &MockKMSClient{
		GetPublicKeyFunc: func(ctx context.Context, params *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
			return &kms.GetPublicKeyOutput{
				PublicKey: []byte("mock-public-key"),
			}, nil
		},
		ScheduleKeyDeletionFunc: func(ctx context.Context, params *kms.ScheduleKeyDeletionInput, optFns ...func(*kms.Options)) (*kms.ScheduleKeyDeletionOutput, error) {
			return &kms.ScheduleKeyDeletionOutput{}, nil
		},
	}

	config := &Config{
		Region:      "us-east-1",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}
	b, _ := NewBackendWithClient(config, mockClient)

	var wg sync.WaitGroup
	numGoroutines := 10

	// Concurrent saves
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			attrs := &types.KeyAttributes{
				CN:           fmt.Sprintf("concurrent-key-%d", n),
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_AWSKMS,
				KeyAlgorithm: x509.RSA,
			}
			_ = b.Save(attrs, []byte("test-data"), backend.FSEXT_PRIVATE_BLOB, false)
		}(i)
	}

	// Concurrent reads
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			attrs := &types.KeyAttributes{
				CN:           fmt.Sprintf("concurrent-key-%d", n),
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_AWSKMS,
				KeyAlgorithm: x509.RSA,
			}
			_, _ = b.Get(attrs, backend.FSEXT_PRIVATE_BLOB)
		}(i)
	}

	// Concurrent deletes
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			attrs := &types.KeyAttributes{
				CN:           fmt.Sprintf("concurrent-key-%d", n),
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_AWSKMS,
				KeyAlgorithm: x509.RSA,
			}
			_ = b.Delete(attrs)
		}(i)
	}

	wg.Wait()
}

// TestGetKeyID tests the getKeyID helper method.
func TestGetKeyID(t *testing.T) {
	mockClient := &MockKMSClient{}
	config := &Config{
		Region:      "us-east-1",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}
	b, _ := NewBackendWithClient(config, mockClient)

	// Test with metadata
	metadata := map[string]interface{}{
		"key_id": "stored-key-id-123",
		"alias":  "alias/test-key",
	}
	metadataBytes, _ := json.Marshal(metadata)
	b.metadata["test-key-with-metadata"] = metadataBytes

	keyID := b.getKeyID("test-key-with-metadata")
	if keyID != "stored-key-id-123" {
		t.Errorf("getKeyID() with metadata = %v, want stored-key-id-123", keyID)
	}

	// Test without metadata (should return alias)
	keyID = b.getKeyID("test-key-no-metadata")
	if keyID != "alias/test-key-no-metadata" {
		t.Errorf("getKeyID() without metadata = %v, want alias/test-key-no-metadata", keyID)
	}
}

// TestGetKeySpec tests the getKeySpec helper method.
func TestGetKeySpec(t *testing.T) {
	mockClient := &MockKMSClient{}
	config := &Config{
		Region:      "us-east-1",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}
	b, _ := NewBackendWithClient(config, mockClient)

	tests := []struct {
		name     string
		attrs    *types.KeyAttributes
		wantSpec kmstypes.KeySpec
		wantErr  bool
	}{
		{
			name: "RSA algorithm",
			attrs: &types.KeyAttributes{
				KeyAlgorithm: x509.RSA,
			},
			wantSpec: kmstypes.KeySpecRsa2048,
			wantErr:  false,
		},
		{
			name: "ECDSA algorithm",
			attrs: &types.KeyAttributes{
				KeyAlgorithm: x509.ECDSA,
			},
			wantSpec: kmstypes.KeySpecEccNistP256,
			wantErr:  false,
		},
		{
			name: "unsupported algorithm",
			attrs: &types.KeyAttributes{
				KeyAlgorithm: x509.Ed25519,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec, err := b.getKeySpec(tt.attrs)
			if (err != nil) != tt.wantErr {
				t.Errorf("getKeySpec() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && spec != tt.wantSpec {
				t.Errorf("getKeySpec() = %v, want %v", spec, tt.wantSpec)
			}
		})
	}
}

// TestGetKeyUsage tests the getKeyUsage helper method.
func TestGetKeyUsage(t *testing.T) {
	mockClient := &MockKMSClient{}
	config := &Config{
		Region:      "us-east-1",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}
	b, _ := NewBackendWithClient(config, mockClient)

	tests := []struct {
		name      string
		keyType   types.KeyType
		wantUsage kmstypes.KeyUsageType
	}{
		{
			name:      "encryption key",
			keyType:   backend.KEY_TYPE_ENCRYPTION,
			wantUsage: kmstypes.KeyUsageTypeEncryptDecrypt,
		},
		{
			name:      "signing key",
			keyType:   backend.KEY_TYPE_SIGNING,
			wantUsage: kmstypes.KeyUsageTypeSignVerify,
		},
		{
			name:      "TLS key",
			keyType:   backend.KEY_TYPE_TLS,
			wantUsage: kmstypes.KeyUsageTypeSignVerify,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			usage := b.getKeyUsage(tt.keyType)
			if usage != tt.wantUsage {
				t.Errorf("getKeyUsage() = %v, want %v", usage, tt.wantUsage)
			}
		})
	}
}

// TestGetSigningAlgorithm tests the getSigningAlgorithm helper method.
func TestGetSigningAlgorithm(t *testing.T) {
	mockClient := &MockKMSClient{}
	config := &Config{
		Region:      "us-east-1",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}
	b, _ := NewBackendWithClient(config, mockClient)

	tests := []struct {
		name     string
		attrs    *types.KeyAttributes
		wantAlgo kmstypes.SigningAlgorithmSpec
		wantErr  bool
	}{
		{
			name: "RSA algorithm",
			attrs: &types.KeyAttributes{
				KeyAlgorithm: x509.RSA,
			},
			wantAlgo: kmstypes.SigningAlgorithmSpecRsassaPssSha256,
			wantErr:  false,
		},
		{
			name: "ECDSA algorithm",
			attrs: &types.KeyAttributes{
				KeyAlgorithm: x509.ECDSA,
			},
			wantAlgo: kmstypes.SigningAlgorithmSpecEcdsaSha256,
			wantErr:  false,
		},
		{
			name: "unsupported algorithm",
			attrs: &types.KeyAttributes{
				KeyAlgorithm: x509.Ed25519,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			algo, err := b.getSigningAlgorithm(tt.attrs)
			if (err != nil) != tt.wantErr {
				t.Errorf("getSigningAlgorithm() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && algo != tt.wantAlgo {
				t.Errorf("getSigningAlgorithm() = %v, want %v", algo, tt.wantAlgo)
			}
		})
	}
}
