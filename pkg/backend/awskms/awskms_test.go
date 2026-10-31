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

//go:build awskms

package awskms

import (
	"context"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
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
		wantErrIs error
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
			wantErrIs: backend.ErrKeyAlreadyExists,
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
			if tt.wantErrIs != nil && !errors.Is(err, tt.wantErrIs) {
				t.Errorf("Save() error = %v, want errors.Is %v (go-xkms#1599)", err, tt.wantErrIs)
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

	// Save some metadata first. It must be a valid JSON record with key_id,
	// like CreateKey/GenerateSymmetricKey actually write: getKeyID (used by
	// the "get public key" subtest below) now returns a typed error for a
	// record it cannot parse, rather than silently falling back to an alias
	// (go-xkms#839).
	testData := []byte(`{"key_id":"mock-public-key-id"}`)
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

	// Save metadata first. Must be a valid JSON record with key_id, like
	// CreateKey/GenerateSymmetricKey actually write: Delete resolves the key
	// ID via getKeyID before deleting, which now returns a typed error for
	// an unparseable record instead of silently falling back to an alias
	// (go-xkms#839).
	_ = b.Save(attrs, []byte(`{"key_id":"test-key-id"}`), backend.FSEXT_PRIVATE_BLOB, false)

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

// TestClose tests the Close method. Close must NOT clear persisted key
// metadata: Config.KeyStorage's lifecycle belongs to the caller, and a
// second Backend built over the same storage (a restart) must still resolve
// keys this one persisted (go-xkms#839) -- only the AWS client handle is
// backend-owned and reset.
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

	// Verify metadata was NOT cleared: it is persisted in config.KeyStorage,
	// which Close does not own.
	exists, err := storage.KeyExists(context.Background(), config.KeyStorage, attrs.CN)
	if err != nil {
		t.Fatalf("failed to check metadata existence: %v", err)
	}
	if !exists {
		t.Errorf("Close() must not clear persisted key metadata")
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
				metadataBytes, err := storage.GetKey(context.Background(), config.KeyStorage, tt.attrs.CN)
				if err != nil {
					t.Errorf("CreateKey() metadata not stored: %v", err)
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
	if err := storage.SaveKey(context.Background(), config.KeyStorage, "test-key-with-metadata", metadataBytes); err != nil {
		t.Fatalf("failed to seed metadata: %v", err)
	}

	keyID, err := b.getKeyID(context.Background(), "test-key-with-metadata")
	if err != nil {
		t.Fatalf("getKeyID() with metadata: unexpected error: %v", err)
	}
	if keyID != "stored-key-id-123" {
		t.Errorf("getKeyID() with metadata = %v, want stored-key-id-123", keyID)
	}

	// Test without metadata (should return alias): storage.ErrNotFound is
	// the one failure getKeyID resolves silently, since both CreateKey and
	// GenerateSymmetricKey attempt to create this exact alias alongside
	// every key they provision -- see persistence_test.go for the storage
	// errors and corrupt records that must NOT resolve silently.
	keyID, err = b.getKeyID(context.Background(), "test-key-no-metadata")
	if err != nil {
		t.Fatalf("getKeyID() without metadata: unexpected error: %v", err)
	}
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
	b, err := NewBackendWithClient(config, mockClient)
	if err != nil {
		t.Fatalf("NewBackendWithClient() error = %v", err)
	}

	tests := []struct {
		name     string
		attrs    *types.KeyAttributes
		wantSpec kmstypes.KeySpec
		wantErr  error
	}{
		{
			name: "RSA algorithm",
			attrs: &types.KeyAttributes{
				KeyAlgorithm: x509.RSA,
			},
			wantSpec: kmstypes.KeySpecRsa2048,
		},
		{
			name: "RSA 3072",
			attrs: &types.KeyAttributes{
				KeyAlgorithm:  x509.RSA,
				RSAAttributes: &types.RSAAttributes{KeySize: 3072},
			},
			wantSpec: kmstypes.KeySpecRsa3072,
		},
		{
			name: "RSA 4096",
			attrs: &types.KeyAttributes{
				KeyAlgorithm:  x509.RSA,
				RSAAttributes: &types.RSAAttributes{KeySize: 4096},
			},
			wantSpec: kmstypes.KeySpecRsa4096,
		},
		{
			name: "RSA 1024 is not offered by AWS KMS",
			attrs: &types.KeyAttributes{
				KeyAlgorithm:  x509.RSA,
				RSAAttributes: &types.RSAAttributes{KeySize: 1024},
			},
			wantErr: ErrInvalidKeySpec,
		},
		{
			name: "ECDSA algorithm",
			attrs: &types.KeyAttributes{
				KeyAlgorithm: x509.ECDSA,
			},
			wantSpec: kmstypes.KeySpecEccNistP256,
		},
		{
			name: "ECDSA P-384",
			attrs: &types.KeyAttributes{
				KeyAlgorithm:  x509.ECDSA,
				ECCAttributes: &types.ECCAttributes{Curve: elliptic.P384()},
			},
			wantSpec: kmstypes.KeySpecEccNistP384,
		},
		{
			name: "ECDSA P-521",
			attrs: &types.KeyAttributes{
				KeyAlgorithm:  x509.ECDSA,
				ECCAttributes: &types.ECCAttributes{Curve: elliptic.P521()},
			},
			wantSpec: kmstypes.KeySpecEccNistP521,
		},
		{
			name: "ECDSA P-224 is not offered by AWS KMS",
			attrs: &types.KeyAttributes{
				KeyAlgorithm:  x509.ECDSA,
				ECCAttributes: &types.ECCAttributes{Curve: elliptic.P224()},
			},
			wantErr: ErrInvalidKeySpec,
		},
		{
			name: "unsupported algorithm",
			attrs: &types.KeyAttributes{
				KeyAlgorithm: x509.Ed25519,
			},
			wantErr: backend.ErrInvalidKeyType,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec, err := b.getKeySpec(tt.attrs)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("getKeySpec() error = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("getKeySpec() error = %v", err)
			}
			if spec != tt.wantSpec {
				t.Errorf("getKeySpec() = %v, want %v", spec, tt.wantSpec)
			}
		})
	}
}

// TestCreateKeySendsRequestedCurve checks that CreateKey asks AWS KMS for the
// curve in ECCAttributes, so an ECDSA_SHA_384 or ECDSA_SHA_512 Sign later
// matches the key spec instead of being rejected against ECC_NIST_P256.
func TestCreateKeySendsRequestedCurve(t *testing.T) {
	tests := []struct {
		name     string
		curve    elliptic.Curve
		wantSpec kmstypes.KeySpec
	}{
		{name: "P-256", curve: elliptic.P256(), wantSpec: kmstypes.KeySpecEccNistP256},
		{name: "P-384", curve: elliptic.P384(), wantSpec: kmstypes.KeySpecEccNistP384},
		{name: "P-521", curve: elliptic.P521(), wantSpec: kmstypes.KeySpecEccNistP521},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var sentSpec kmstypes.KeySpec
			mockClient := &MockKMSClient{
				CreateKeyFunc: func(ctx context.Context, params *kms.CreateKeyInput, optFns ...func(*kms.Options)) (*kms.CreateKeyOutput, error) {
					sentSpec = params.KeySpec
					return &kms.CreateKeyOutput{KeyMetadata: &kmstypes.KeyMetadata{KeyId: aws.String("key-" + tt.name)}}, nil
				},
				CreateAliasFunc: func(ctx context.Context, params *kms.CreateAliasInput, optFns ...func(*kms.Options)) (*kms.CreateAliasOutput, error) {
					return &kms.CreateAliasOutput{}, nil
				},
			}
			b, err := NewBackendWithClient(&Config{
				Region:      "us-east-1",
				KeyStorage:  storage.New(),
				CertStorage: storage.New(),
			}, mockClient)
			if err != nil {
				t.Fatalf("NewBackendWithClient() error = %v", err)
			}

			attrs := &types.KeyAttributes{
				CN:            "curve-" + tt.name,
				KeyAlgorithm:  x509.ECDSA,
				KeyType:       backend.KEY_TYPE_SIGNING,
				ECCAttributes: &types.ECCAttributes{Curve: tt.curve},
			}
			if _, err := b.CreateKey(attrs); err != nil {
				t.Fatalf("CreateKey() error = %v", err)
			}
			if sentSpec != tt.wantSpec {
				t.Errorf("CreateKey sent KeySpec %q, want %q", sentSpec, tt.wantSpec)
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
