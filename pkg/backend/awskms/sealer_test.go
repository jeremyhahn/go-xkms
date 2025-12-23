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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// TestCanSeal_NoClient tests CanSeal returns false when client is not initialized
func TestCanSeal_NoClient(t *testing.T) {
	config := &Config{
		Region:      "us-east-1",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() failed: %v", err)
	}

	if b.CanSeal() {
		t.Error("CanSeal() should return false when client is not initialized")
	}
}

// TestCanSeal_WithClient tests CanSeal returns true when client is initialized
func TestCanSeal_WithClient(t *testing.T) {
	mockClient := &MockKMSClient{}

	config := &Config{
		Region:      "us-east-1",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}

	b, err := NewBackendWithClient(config, mockClient)
	if err != nil {
		t.Fatalf("NewBackendWithClient() failed: %v", err)
	}

	if !b.CanSeal() {
		t.Error("CanSeal() should return true when client is initialized")
	}
}

// TestSeal_NilOptions tests Seal fails with nil options
func TestSeal_NilOptions(t *testing.T) {
	mockClient := &MockKMSClient{}

	config := &Config{
		Region:      "us-east-1",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}

	b, err := NewBackendWithClient(config, mockClient)
	if err != nil {
		t.Fatalf("NewBackendWithClient() failed: %v", err)
	}

	ctx := context.Background()
	_, err = b.Seal(ctx, []byte("test"), nil)
	if err == nil {
		t.Error("Seal() should fail with nil options")
	}
}

// TestSeal_NilKeyAttributes tests Seal fails with nil KeyAttributes
func TestSeal_NilKeyAttributes(t *testing.T) {
	mockClient := &MockKMSClient{}

	config := &Config{
		Region:      "us-east-1",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}

	b, err := NewBackendWithClient(config, mockClient)
	if err != nil {
		t.Fatalf("NewBackendWithClient() failed: %v", err)
	}

	ctx := context.Background()
	_, err = b.Seal(ctx, []byte("test"), &types.SealOptions{
		KeyAttributes: nil,
	})
	if err == nil {
		t.Error("Seal() should fail with nil KeyAttributes")
	}
}

// TestSeal_AsymmetricKeyRejected tests Seal fails with asymmetric key
func TestSeal_AsymmetricKeyRejected(t *testing.T) {
	mockClient := &MockKMSClient{}

	config := &Config{
		Region:      "us-east-1",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}

	b, err := NewBackendWithClient(config, mockClient)
	if err != nil {
		t.Fatalf("NewBackendWithClient() failed: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:        "test-rsa-key",
		KeyType:   backend.KEY_TYPE_SIGNING,
		StoreType: backend.STORE_AWSKMS,
	}

	ctx := context.Background()
	_, err = b.Seal(ctx, []byte("test"), &types.SealOptions{
		KeyAttributes: attrs,
	})
	if err == nil {
		t.Error("Seal() should fail with asymmetric key")
	}
}

// TestSealUnseal_Success tests successful seal/unseal roundtrip
func TestSealUnseal_Success(t *testing.T) {
	plaintext := []byte("secret data for sealing")
	ciphertext := []byte("encrypted-blob")

	mockClient := &MockKMSClient{
		EncryptFunc: func(ctx context.Context, params *kms.EncryptInput, optFns ...func(*kms.Options)) (*kms.EncryptOutput, error) {
			return &kms.EncryptOutput{
				CiphertextBlob: ciphertext,
				KeyId:          aws.String("test-key-id"),
			}, nil
		},
		DecryptFunc: func(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error) {
			if !bytes.Equal(params.CiphertextBlob, ciphertext) {
				return nil, errors.New("wrong ciphertext")
			}
			return &kms.DecryptOutput{
				Plaintext: plaintext,
				KeyId:     aws.String("test-key-id"),
			}, nil
		},
		DescribeKeyFunc: func(ctx context.Context, params *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
			return &kms.DescribeKeyOutput{
				KeyMetadata: &kmstypes.KeyMetadata{
					KeyId: aws.String("test-key-id"),
				},
			}, nil
		},
	}

	config := &Config{
		Region:      "us-east-1",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}

	b, err := NewBackendWithClient(config, mockClient)
	if err != nil {
		t.Fatalf("NewBackendWithClient() failed: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:                 "test-seal-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_AWSKMS,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		AESAttributes: &types.AESAttributes{
			KeySize: 256,
		},
	}

	// Pre-populate metadata
	metadata := map[string]interface{}{
		"key_id":    "test-key-id",
		"alias":     "alias/test-seal-key",
		"algorithm": string(types.SymmetricAES256GCM),
	}
	metadataBytes, _ := json.Marshal(metadata)
	b.metadata[attrs.CN] = metadataBytes

	ctx := context.Background()

	// Seal
	sealed, err := b.Seal(ctx, plaintext, &types.SealOptions{
		KeyAttributes: attrs,
	})
	if err != nil {
		t.Fatalf("Seal() failed: %v", err)
	}

	if sealed == nil {
		t.Fatal("Seal() returned nil sealed data")
	}
	if sealed.Backend != types.BackendTypeAWSKMS {
		t.Errorf("Expected backend %s, got %s", types.BackendTypeAWSKMS, sealed.Backend)
	}
	if !bytes.Equal(sealed.Ciphertext, ciphertext) {
		t.Error("Ciphertext mismatch")
	}

	// Unseal
	unsealed, err := b.Unseal(ctx, sealed, &types.UnsealOptions{
		KeyAttributes: attrs,
	})
	if err != nil {
		t.Fatalf("Unseal() failed: %v", err)
	}

	if !bytes.Equal(plaintext, unsealed) {
		t.Errorf("Unsealed data does not match original")
	}
}

// TestUnseal_NilSealedData tests Unseal fails with nil sealed data
func TestUnseal_NilSealedData(t *testing.T) {
	mockClient := &MockKMSClient{}

	config := &Config{
		Region:      "us-east-1",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}

	b, err := NewBackendWithClient(config, mockClient)
	if err != nil {
		t.Fatalf("NewBackendWithClient() failed: %v", err)
	}

	ctx := context.Background()
	_, err = b.Unseal(ctx, nil, &types.UnsealOptions{
		KeyAttributes: &types.KeyAttributes{},
	})
	if err == nil {
		t.Error("Unseal() should fail with nil sealed data")
	}
}

// TestUnseal_WrongBackend tests Unseal fails with wrong backend type
func TestUnseal_WrongBackend(t *testing.T) {
	mockClient := &MockKMSClient{}

	config := &Config{
		Region:      "us-east-1",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}

	b, err := NewBackendWithClient(config, mockClient)
	if err != nil {
		t.Fatalf("NewBackendWithClient() failed: %v", err)
	}

	sealed := &types.SealedData{
		Backend:    types.BackendTypeSoftware, // Wrong backend
		Ciphertext: []byte("test"),
	}

	ctx := context.Background()
	_, err = b.Unseal(ctx, sealed, &types.UnsealOptions{
		KeyAttributes: &types.KeyAttributes{},
	})
	if err == nil {
		t.Error("Unseal() should fail with wrong backend type")
	}
}

// TestUnseal_NilOptions tests Unseal fails with nil options
func TestUnseal_NilOptions(t *testing.T) {
	mockClient := &MockKMSClient{}

	config := &Config{
		Region:      "us-east-1",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}

	b, err := NewBackendWithClient(config, mockClient)
	if err != nil {
		t.Fatalf("NewBackendWithClient() failed: %v", err)
	}

	sealed := &types.SealedData{
		Backend:    types.BackendTypeAWSKMS,
		Ciphertext: []byte("test"),
	}

	ctx := context.Background()
	_, err = b.Unseal(ctx, sealed, nil)
	if err == nil {
		t.Error("Unseal() should fail with nil options")
	}
}

// TestUnseal_NilKeyAttributes tests Unseal fails with nil KeyAttributes
func TestUnseal_NilKeyAttributes(t *testing.T) {
	mockClient := &MockKMSClient{}

	config := &Config{
		Region:      "us-east-1",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}

	b, err := NewBackendWithClient(config, mockClient)
	if err != nil {
		t.Fatalf("NewBackendWithClient() failed: %v", err)
	}

	sealed := &types.SealedData{
		Backend:    types.BackendTypeAWSKMS,
		Ciphertext: []byte("test"),
	}

	ctx := context.Background()
	_, err = b.Unseal(ctx, sealed, &types.UnsealOptions{
		KeyAttributes: nil,
	})
	if err == nil {
		t.Error("Unseal() should fail with nil KeyAttributes")
	}
}

// TestUnseal_KeyMismatch tests Unseal fails with mismatched key ID
func TestUnseal_KeyMismatch(t *testing.T) {
	mockClient := &MockKMSClient{}

	config := &Config{
		Region:      "us-east-1",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}

	b, err := NewBackendWithClient(config, mockClient)
	if err != nil {
		t.Fatalf("NewBackendWithClient() failed: %v", err)
	}

	sealed := &types.SealedData{
		Backend:    types.BackendTypeAWSKMS,
		Ciphertext: []byte("test"),
		KeyID:      "original-key-id",
	}

	attrs := &types.KeyAttributes{
		CN:                 "different-key", // Different from KeyID
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_AWSKMS,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		AESAttributes: &types.AESAttributes{
			KeySize: 256,
		},
	}

	ctx := context.Background()
	_, err = b.Unseal(ctx, sealed, &types.UnsealOptions{
		KeyAttributes: attrs,
	})
	if err == nil {
		t.Error("Unseal() should fail with mismatched key ID")
	}
}

// TestSealUnseal_WithAAD tests seal/unseal with Additional Authenticated Data
func TestSealUnseal_WithAAD(t *testing.T) {
	plaintext := []byte("secret data with AAD")
	ciphertext := []byte("encrypted-blob-with-aad")
	aad := []byte("additional context")

	mockClient := &MockKMSClient{
		EncryptFunc: func(ctx context.Context, params *kms.EncryptInput, optFns ...func(*kms.Options)) (*kms.EncryptOutput, error) {
			// Verify AAD was passed
			if params.EncryptionContext == nil {
				return nil, errors.New("expected encryption context")
			}
			if params.EncryptionContext["aad"] != string(aad) {
				return nil, errors.New("wrong AAD value")
			}
			return &kms.EncryptOutput{
				CiphertextBlob: ciphertext,
				KeyId:          aws.String("test-key-id"),
			}, nil
		},
		DecryptFunc: func(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error) {
			// Verify AAD matches
			if params.EncryptionContext == nil {
				return nil, errors.New("expected encryption context")
			}
			if params.EncryptionContext["aad"] != string(aad) {
				return nil, errors.New("AAD mismatch")
			}
			return &kms.DecryptOutput{
				Plaintext: plaintext,
				KeyId:     aws.String("test-key-id"),
			}, nil
		},
		DescribeKeyFunc: func(ctx context.Context, params *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
			return &kms.DescribeKeyOutput{
				KeyMetadata: &kmstypes.KeyMetadata{
					KeyId: aws.String("test-key-id"),
				},
			}, nil
		},
	}

	config := &Config{
		Region:      "us-east-1",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}

	b, err := NewBackendWithClient(config, mockClient)
	if err != nil {
		t.Fatalf("NewBackendWithClient() failed: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:                 "test-aad-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_AWSKMS,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		AESAttributes: &types.AESAttributes{
			KeySize: 256,
		},
	}

	// Pre-populate metadata
	metadata := map[string]interface{}{
		"key_id":    "test-key-id",
		"alias":     "alias/test-aad-key",
		"algorithm": string(types.SymmetricAES256GCM),
	}
	metadataBytes, _ := json.Marshal(metadata)
	b.metadata[attrs.CN] = metadataBytes

	ctx := context.Background()

	// Seal with AAD
	sealed, err := b.Seal(ctx, plaintext, &types.SealOptions{
		KeyAttributes: attrs,
		AAD:           aad,
	})
	if err != nil {
		t.Fatalf("Seal() with AAD failed: %v", err)
	}

	// Verify AAD indicator in metadata
	if _, ok := sealed.Metadata["awskms:has_aad"]; !ok {
		t.Error("Expected AAD indicator in metadata")
	}

	// Unseal with correct AAD
	unsealed, err := b.Unseal(ctx, sealed, &types.UnsealOptions{
		KeyAttributes: attrs,
		AAD:           aad,
	})
	if err != nil {
		t.Fatalf("Unseal() with AAD failed: %v", err)
	}

	if !bytes.Equal(plaintext, unsealed) {
		t.Error("Unsealed data does not match original")
	}
}

// TestMarshalUnmarshalSealedData tests JSON serialization of SealedData
func TestMarshalUnmarshalSealedData(t *testing.T) {
	original := &types.SealedData{
		Backend:    types.BackendTypeAWSKMS,
		Ciphertext: []byte("encrypted data"),
		KeyID:      "test-key-id",
		Metadata: map[string][]byte{
			"awskms:algorithm": []byte("AES-256-GCM"),
		},
	}

	// Marshal
	data, err := MarshalSealedData(original)
	if err != nil {
		t.Fatalf("MarshalSealedData() failed: %v", err)
	}

	// Unmarshal
	restored, err := UnmarshalSealedData(data)
	if err != nil {
		t.Fatalf("UnmarshalSealedData() failed: %v", err)
	}

	// Verify
	if restored.Backend != original.Backend {
		t.Errorf("Backend mismatch: got %s, want %s", restored.Backend, original.Backend)
	}
	if string(restored.Ciphertext) != string(original.Ciphertext) {
		t.Error("Ciphertext mismatch")
	}
	if restored.KeyID != original.KeyID {
		t.Errorf("KeyID mismatch: got %s, want %s", restored.KeyID, original.KeyID)
	}
}
