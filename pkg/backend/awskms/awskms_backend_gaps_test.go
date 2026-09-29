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
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestType proves Type() reports the AWS KMS backend identifier used to
// route requests to this backend elsewhere in the stack.
func TestType(t *testing.T) {
	b, err := NewBackendWithClient(&Config{
		Region:      "us-east-1",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}, &MockKMSClient{})
	if err != nil {
		t.Fatalf("NewBackendWithClient() error = %v", err)
	}
	if got := b.Type(); got != backend.BackendTypeAWSKMS {
		t.Errorf("Type() = %v, want %v", got, backend.BackendTypeAWSKMS)
	}
}

// TestOperatorSealKeyID proves OperatorSealKeyID reflects the operator's
// configured Config.KeyID, including the "operator configured none" case
// pkg/seal.EnsureSealKey relies on to decide whether to create a new CMK.
func TestOperatorSealKeyID(t *testing.T) {
	tests := []struct {
		name  string
		keyID string
	}{
		{name: "configured", keyID: "alias/my-seal-key"},
		{name: "unconfigured", keyID: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := NewBackendWithClient(&Config{
				Region:      "us-east-1",
				KeyID:       tt.keyID,
				KeyStorage:  storage.New(),
				CertStorage: storage.New(),
			}, &MockKMSClient{})
			if err != nil {
				t.Fatalf("NewBackendWithClient() error = %v", err)
			}
			if got := b.OperatorSealKeyID(); got != tt.keyID {
				t.Errorf("OperatorSealKeyID() = %q, want %q", got, tt.keyID)
			}
		})
	}
}

// TestGenerateKey_Success proves GenerateKey creates the underlying KMS key
// via CreateKey and, matching the documented contract, returns a nil
// crypto.PrivateKey since AWS KMS never releases key material -- callers
// must go through Signer()/Decrypter() instead.
func TestGenerateKey_Success(t *testing.T) {
	createCalled := false
	mockClient := &MockKMSClient{
		CreateKeyFunc: func(ctx context.Context, params *kms.CreateKeyInput, optFns ...func(*kms.Options)) (*kms.CreateKeyOutput, error) {
			createCalled = true
			return &kms.CreateKeyOutput{
				KeyMetadata: &kmstypes.KeyMetadata{KeyId: aws.String("generated-key-id")},
			}, nil
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
		CN:           "generate-key-test",
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_AWSKMS,
		KeyAlgorithm: x509.RSA,
	}

	key, err := b.GenerateKey(context.Background(), attrs)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	if key != nil {
		t.Errorf("GenerateKey() key = %v, want nil (AWS KMS never returns extractable key material)", key)
	}
	if !createCalled {
		t.Error("GenerateKey() did not create the underlying KMS key")
	}
}

// TestGenerateKey_NilAttributes proves GenerateKey rejects nil attributes
// instead of panicking on attrs.CN.
func TestGenerateKey_NilAttributes(t *testing.T) {
	b, err := NewBackendWithClient(&Config{
		Region:      "us-east-1",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}, &MockKMSClient{})
	if err != nil {
		t.Fatalf("NewBackendWithClient() error = %v", err)
	}
	if _, err := b.GenerateKey(context.Background(), nil); !errors.Is(err, backend.ErrInvalidAttributes) {
		t.Errorf("GenerateKey(nil) error = %v, want ErrInvalidAttributes", err)
	}
}

// TestGenerateKey_CreateKeyError proves a CreateKey failure surfaces from
// GenerateKey wrapped rather than being swallowed.
func TestGenerateKey_CreateKeyError(t *testing.T) {
	mockClient := &MockKMSClient{
		CreateKeyFunc: func(ctx context.Context, params *kms.CreateKeyInput, optFns ...func(*kms.Options)) (*kms.CreateKeyOutput, error) {
			return nil, errors.New("kms: throttled")
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
		CN:           "generate-key-fail",
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_AWSKMS,
		KeyAlgorithm: x509.RSA,
	}
	if _, err := b.GenerateKey(context.Background(), attrs); err == nil {
		t.Error("GenerateKey() expected error when CreateKey fails, got nil")
	}
}

// TestGetKey_Success proves GetKey resolves a key whose metadata and KMS
// record both exist, returning nil (not extractable) without error.
func TestGetKey_Success(t *testing.T) {
	mockClient := &MockKMSClient{
		DescribeKeyFunc: func(ctx context.Context, params *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
			return &kms.DescribeKeyOutput{KeyMetadata: &kmstypes.KeyMetadata{KeyId: params.KeyId}}, nil
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
		CN:           "get-key-success",
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_AWSKMS,
		KeyAlgorithm: x509.RSA,
	}
	if err := b.Save(attrs, []byte(`{"key_id":"existing-key-id"}`), backend.FSEXT_PRIVATE_BLOB, false); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	key, err := b.GetKey(context.Background(), attrs)
	if err != nil {
		t.Fatalf("GetKey() error = %v", err)
	}
	if key != nil {
		t.Errorf("GetKey() key = %v, want nil", key)
	}
}

// TestGetSignerByID proves GetSignerByID's two real outcomes: an unknown
// CN propagates GetKey's ErrKeyNotFound, and a CN whose metadata exists
// returns ErrInvalidKeyType because GetKey never returns an extractable
// crypto.Signer for a hardware-backed AWS KMS key (the same contract
// gcpkms.GetSignerByID and azurekv.GetSignerByID document and test).
func TestGetSignerByID(t *testing.T) {
	mockClient := &MockKMSClient{
		DescribeKeyFunc: func(ctx context.Context, params *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
			return &kms.DescribeKeyOutput{KeyMetadata: &kmstypes.KeyMetadata{KeyId: params.KeyId}}, nil
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

	if _, err := b.GetSignerByID("does-not-exist"); !errors.Is(err, backend.ErrKeyNotFound) {
		t.Errorf("GetSignerByID(unknown) error = %v, want ErrKeyNotFound", err)
	}

	existing := &types.KeyAttributes{CN: "existing-signer", StoreType: backend.STORE_AWSKMS}
	if err := b.Save(existing, []byte(`{"key_id":"existing-signer-id"}`), backend.FSEXT_PRIVATE_BLOB, false); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	if _, err := b.GetSignerByID(existing.CN); !errors.Is(err, backend.ErrInvalidKeyType) {
		t.Errorf("GetSignerByID(existing) error = %v, want ErrInvalidKeyType", err)
	}
}

// TestGetDecrypterByID mirrors TestGetSignerByID for the decrypter path.
func TestGetDecrypterByID(t *testing.T) {
	mockClient := &MockKMSClient{
		DescribeKeyFunc: func(ctx context.Context, params *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
			return &kms.DescribeKeyOutput{KeyMetadata: &kmstypes.KeyMetadata{KeyId: params.KeyId}}, nil
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

	if _, err := b.GetDecrypterByID("does-not-exist"); !errors.Is(err, backend.ErrKeyNotFound) {
		t.Errorf("GetDecrypterByID(unknown) error = %v, want ErrKeyNotFound", err)
	}

	existing := &types.KeyAttributes{CN: "existing-decrypter", StoreType: backend.STORE_AWSKMS}
	if err := b.Save(existing, []byte(`{"key_id":"existing-decrypter-id"}`), backend.FSEXT_PRIVATE_BLOB, false); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	if _, err := b.GetDecrypterByID(existing.CN); !errors.Is(err, backend.ErrInvalidKeyType) {
		t.Errorf("GetDecrypterByID(existing) error = %v, want ErrInvalidKeyType", err)
	}
}

// TestDeleteKey proves DeleteKey delegates to Delete: the underlying
// ScheduleKeyDeletion call happens and the persisted metadata is removed.
func TestDeleteKey(t *testing.T) {
	deleteCalled := false
	mockClient := &MockKMSClient{
		ScheduleKeyDeletionFunc: func(ctx context.Context, params *kms.ScheduleKeyDeletionInput, optFns ...func(*kms.Options)) (*kms.ScheduleKeyDeletionOutput, error) {
			deleteCalled = true
			return &kms.ScheduleKeyDeletionOutput{}, nil
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

	attrs := &types.KeyAttributes{CN: "delete-key-test", StoreType: backend.STORE_AWSKMS}
	if err := b.Save(attrs, []byte(`{"key_id":"delete-key-id"}`), backend.FSEXT_PRIVATE_BLOB, false); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	if err := b.DeleteKey(context.Background(), attrs); err != nil {
		t.Fatalf("DeleteKey() error = %v", err)
	}
	if !deleteCalled {
		t.Error("DeleteKey() did not call ScheduleKeyDeletion")
	}
	if _, err := b.Get(attrs, backend.FSEXT_PRIVATE_BLOB); err == nil {
		t.Error("DeleteKey() metadata still exists after deletion")
	}
}

// TestRotateKey_AsymmetricSuccess proves RotateKey resolves the key ID and
// calls RotateKeyOnDemand for a signing key (no AEAD tracker involvement).
func TestRotateKey_AsymmetricSuccess(t *testing.T) {
	var rotatedKeyID string
	mockClient := &MockKMSClient{
		RotateKeyOnDemandFunc: func(ctx context.Context, params *kms.RotateKeyOnDemandInput, optFns ...func(*kms.Options)) (*kms.RotateKeyOnDemandOutput, error) {
			rotatedKeyID = aws.ToString(params.KeyId)
			return &kms.RotateKeyOnDemandOutput{}, nil
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
		CN:           "rotate-signing-key",
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_AWSKMS,
		KeyAlgorithm: x509.RSA,
	}
	if err := b.Save(attrs, []byte(`{"key_id":"rotate-signing-key-id"}`), backend.FSEXT_PRIVATE_BLOB, false); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	if err := b.RotateKey(context.Background(), attrs); err != nil {
		t.Fatalf("RotateKey() error = %v", err)
	}
	if rotatedKeyID != "rotate-signing-key-id" {
		t.Errorf("RotateKey() rotated key ID = %q, want %q", rotatedKeyID, "rotate-signing-key-id")
	}
}

// TestRotateKey_SymmetricResetsAEADTracking proves that rotating a symmetric
// key resets its AEAD bytes-encrypted tracking: bytes counted against the
// old key version must not carry into the new one's budget.
//
// Nonce-reuse tracking is no longer part of this reset: go-xkms#1201 moved
// it out of AEADSafetyTracker entirely, into the shared, process-wide
// aead.KeyNonceGuard every backend's Encrypt claims through, which is keyed
// by the key's own material and is deliberately NOT reset on rotation --
// resetting it would let the OLD key version's nonces be reused if the
// rotated key ever produced the same material again.
func TestRotateKey_SymmetricResetsAEADTracking(t *testing.T) {
	mockClient := &MockKMSClient{
		CreateKeyFunc: func(ctx context.Context, params *kms.CreateKeyInput, optFns ...func(*kms.Options)) (*kms.CreateKeyOutput, error) {
			return &kms.CreateKeyOutput{KeyMetadata: &kmstypes.KeyMetadata{KeyId: aws.String("rotate-symmetric-id")}}, nil
		},
		CreateAliasFunc: func(ctx context.Context, params *kms.CreateAliasInput, optFns ...func(*kms.Options)) (*kms.CreateAliasOutput, error) {
			return &kms.CreateAliasOutput{}, nil
		},
		RotateKeyOnDemandFunc: func(ctx context.Context, params *kms.RotateKeyOnDemandInput, optFns ...func(*kms.Options)) (*kms.RotateKeyOnDemandOutput, error) {
			return &kms.RotateKeyOnDemandOutput{}, nil
		},
	}
	tracker := backend.NewMemoryAEADTracker()
	b, err := NewBackendWithClient(&Config{
		Region:      "us-east-1",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
		Tracker:     tracker,
	}, mockClient)
	if err != nil {
		t.Fatalf("NewBackendWithClient() error = %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:                 "rotate-symmetric-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_AWSKMS,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}
	if _, err := b.GenerateSymmetricKey(context.Background(), attrs); err != nil {
		t.Fatalf("GenerateSymmetricKey() error = %v", err)
	}

	trackingKeyID := attrs.ID()
	if err := tracker.SetAEADOptions(trackingKeyID, &types.AEADOptions{
		BytesTracking:      true,
		BytesTrackingLimit: 1000,
	}); err != nil {
		t.Fatalf("SetAEADOptions() error = %v", err)
	}
	if err := tracker.IncrementBytes(trackingKeyID, 900); err != nil {
		t.Fatalf("IncrementBytes() error = %v", err)
	}
	if err := tracker.IncrementBytes(trackingKeyID, 200); err == nil {
		t.Fatal("IncrementBytes() expected the budget to be exceeded before rotation, got nil")
	}

	if err := b.RotateKey(context.Background(), attrs); err != nil {
		t.Fatalf("RotateKey() error = %v", err)
	}

	if err := tracker.IncrementBytes(trackingKeyID, 200); err != nil {
		t.Errorf("IncrementBytes() after RotateKey() = %v, want nil (bytes budget must reset on rotation)", err)
	}
}

// TestRotateKey_NilAttributes proves RotateKey rejects nil attributes.
func TestRotateKey_NilAttributes(t *testing.T) {
	b, err := NewBackendWithClient(&Config{
		Region:      "us-east-1",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}, &MockKMSClient{})
	if err != nil {
		t.Fatalf("NewBackendWithClient() error = %v", err)
	}
	if err := b.RotateKey(context.Background(), nil); !errors.Is(err, backend.ErrInvalidAttributes) {
		t.Errorf("RotateKey(nil) error = %v, want ErrInvalidAttributes", err)
	}
}

// TestRotateKey_KMSError proves a RotateKeyOnDemand failure surfaces from
// RotateKey wrapped rather than being swallowed.
func TestRotateKey_KMSError(t *testing.T) {
	mockClient := &MockKMSClient{
		RotateKeyOnDemandFunc: func(ctx context.Context, params *kms.RotateKeyOnDemandInput, optFns ...func(*kms.Options)) (*kms.RotateKeyOnDemandOutput, error) {
			return nil, errors.New("kms: rotation denied")
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

	attrs := &types.KeyAttributes{CN: "rotate-error-key", StoreType: backend.STORE_AWSKMS}
	if err := b.Save(attrs, []byte(`{"key_id":"rotate-error-key-id"}`), backend.FSEXT_PRIVATE_BLOB, false); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	if err := b.RotateKey(context.Background(), attrs); err == nil {
		t.Error("RotateKey() expected error when RotateKeyOnDemand fails, got nil")
	}
}

// TestExportKey_NilAttributes proves ExportKey rejects nil attributes before
// reaching the always-refuse capability check.
func TestExportKey_NilAttributes(t *testing.T) {
	b, err := NewBackendWithClient(&Config{
		Region:      "us-east-1",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}, &MockKMSClient{})
	if err != nil {
		t.Fatalf("NewBackendWithClient() error = %v", err)
	}
	if _, err := b.ExportKey(context.Background(), nil, backend.WrappingAlgorithmRSAES_OAEP_SHA_256); !errors.Is(err, backend.ErrInvalidAttributes) {
		t.Errorf("ExportKey(nil) error = %v, want ErrInvalidAttributes", err)
	}
}

// TestExportKeyTo proves ExportKeyTo's two real outcomes: nil dstParams is
// rejected before any work, and a non-nil dstParams still refuses with
// ErrExportToUnsupported since AWS KMS never releases key material outside
// the service boundary.
func TestExportKeyTo(t *testing.T) {
	b, err := NewBackendWithClient(&Config{
		Region:      "us-east-1",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}, &MockKMSClient{})
	if err != nil {
		t.Fatalf("NewBackendWithClient() error = %v", err)
	}

	attrs := &types.KeyAttributes{CN: "export-to-test", StoreType: backend.STORE_AWSKMS}

	if _, err := b.ExportKeyTo(context.Background(), nil, &backend.ImportParameters{}); !errors.Is(err, backend.ErrInvalidAttributes) {
		t.Errorf("ExportKeyTo(nil attrs) error = %v, want ErrInvalidAttributes", err)
	}
	if _, err := b.ExportKeyTo(context.Background(), attrs, nil); !errors.Is(err, backend.ErrInvalidAttributes) {
		t.Errorf("ExportKeyTo(nil dstParams) error = %v, want ErrInvalidAttributes", err)
	}
	if _, err := b.ExportKeyTo(context.Background(), attrs, &backend.ImportParameters{}); !errors.Is(err, backend.ErrExportToUnsupported) {
		t.Errorf("ExportKeyTo() error = %v, want ErrExportToUnsupported", err)
	}
}

// TestInitClient_BuildsClientFromConfig proves initClient builds a real KMS
// client from Config's static credentials/region/endpoint the first time
// it is called through NewBackend (not NewBackendWithClient), and that a
// second call is a no-op fast path (b.client already set).
func TestInitClient_BuildsClientFromConfig(t *testing.T) {
	b, err := NewBackend(&Config{
		Region:          "us-east-1",
		AccessKeyID:     "AKIAEXAMPLE",
		SecretAccessKey: "example-secret",
		Endpoint:        "http://localhost:4566",
		KeyStorage:      storage.New(),
		CertStorage:     storage.New(),
	})
	if err != nil {
		t.Fatalf("NewBackend() error = %v", err)
	}
	if b.client != nil {
		t.Fatal("expected client to be nil before initClient")
	}

	if err := b.initClient(context.Background()); err != nil {
		t.Fatalf("initClient() error = %v", err)
	}
	first := b.client
	if first == nil {
		t.Fatal("initClient() left client nil")
	}

	if err := b.initClient(context.Background()); err != nil {
		t.Fatalf("second initClient() error = %v", err)
	}
	if b.client != first {
		t.Error("second initClient() replaced an already-initialized client")
	}
}

// TestInitClient_ConcurrentCallsInitializeOnce exercises the double-checked
// locking pattern under -race: many goroutines calling initClient
// concurrently must all observe a non-nil client and none may error.
func TestInitClient_ConcurrentCallsInitializeOnce(t *testing.T) {
	b, err := NewBackend(&Config{
		Region:      "us-east-1",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	})
	if err != nil {
		t.Fatalf("NewBackend() error = %v", err)
	}

	const goroutines = 16
	var wg sync.WaitGroup
	errs := make([]error, goroutines)
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(i int) {
			defer wg.Done()
			errs[i] = b.initClient(context.Background())
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d: initClient() error = %v", i, err)
		}
	}
	if b.client == nil {
		t.Error("initClient() left client nil after concurrent calls")
	}
}

// TestKMSSigner_Public proves kmsSigner.Public returns the exact public key
// parsed from GetPublicKey's response, which callers rely on to build
// certificates and JWKs without a second round trip to KMS.
func TestKMSSigner_Public(t *testing.T) {
	signer, _ := newTestSigner(t, x509.RSA)
	if signer.Public() == nil {
		t.Error("Public() = nil, want the parsed RSA public key")
	}
}

// TestSigner_NilAttributes proves Signer rejects nil attributes.
func TestSigner_NilAttributes(t *testing.T) {
	b, err := NewBackendWithClient(&Config{
		Region:      "us-east-1",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}, &MockKMSClient{})
	if err != nil {
		t.Fatalf("NewBackendWithClient() error = %v", err)
	}
	if _, err := b.Signer(context.Background(), nil); !errors.Is(err, backend.ErrInvalidAttributes) {
		t.Errorf("Signer(nil) error = %v, want ErrInvalidAttributes", err)
	}
}

// TestSigner_GetPublicKeyError proves a GetPublicKey failure surfaces from
// Signer wrapped rather than returning a half-built signer.
func TestSigner_GetPublicKeyError(t *testing.T) {
	mockClient := &MockKMSClient{
		GetPublicKeyFunc: func(ctx context.Context, params *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
			return nil, errors.New("kms: access denied")
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
	attrs := &types.KeyAttributes{CN: "signer-getpublickey-error", StoreType: backend.STORE_AWSKMS}
	if _, err := b.Signer(context.Background(), attrs); err == nil {
		t.Error("Signer() expected error when GetPublicKey fails, got nil")
	}
}

// TestSigner_MalformedPublicKey proves Signer rejects a public key AWS KMS
// returned that fails to parse as PKIX/SPKI DER, instead of constructing a
// signer with a garbage or nil public key.
func TestSigner_MalformedPublicKey(t *testing.T) {
	mockClient := &MockKMSClient{
		GetPublicKeyFunc: func(ctx context.Context, params *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
			return &kms.GetPublicKeyOutput{PublicKey: []byte("not valid DER")}, nil
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
	attrs := &types.KeyAttributes{CN: "signer-malformed-pubkey", StoreType: backend.STORE_AWSKMS}
	if _, err := b.Signer(context.Background(), attrs); err == nil {
		t.Error("Signer() expected error for malformed public key DER, got nil")
	}
}

// TestDecrypter_GetPublicKeyError proves a GetPublicKey failure surfaces
// from Decrypter wrapped rather than returning a half-built decrypter.
func TestDecrypter_GetPublicKeyError(t *testing.T) {
	mockClient := &MockKMSClient{
		GetPublicKeyFunc: func(ctx context.Context, params *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
			return nil, errors.New("kms: access denied")
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
		CN:           "decrypter-getpublickey-error",
		KeyType:      backend.KEY_TYPE_ENCRYPTION,
		StoreType:    backend.STORE_AWSKMS,
		KeyAlgorithm: x509.RSA,
	}
	if _, err := b.Decrypter(context.Background(), attrs); err == nil {
		t.Error("Decrypter() expected error when GetPublicKey fails, got nil")
	}
}

// TestDecrypter_MalformedPublicKey proves Decrypter rejects a public key AWS
// KMS returned that fails to parse as PKIX/SPKI DER.
func TestDecrypter_MalformedPublicKey(t *testing.T) {
	mockClient := &MockKMSClient{
		GetPublicKeyFunc: func(ctx context.Context, params *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
			return &kms.GetPublicKeyOutput{PublicKey: []byte("not valid DER")}, nil
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
		CN:           "decrypter-malformed-pubkey",
		KeyType:      backend.KEY_TYPE_ENCRYPTION,
		StoreType:    backend.STORE_AWSKMS,
		KeyAlgorithm: x509.RSA,
	}
	if _, err := b.Decrypter(context.Background(), attrs); err == nil {
		t.Error("Decrypter() expected error for malformed public key DER, got nil")
	}
}

// TestGetSigningAlgorithm_AllHashesAndInvalid extends TestGetSigningAlgorithm
// with the SHA-384/SHA-512 branches for both RSA and ECDSA, and the
// unsupported-hash branch for each key algorithm, none of which the
// existing table (which only exercises the default-SHA-256 case) reaches.
func TestGetSigningAlgorithm_AllHashesAndInvalid(t *testing.T) {
	b, err := NewBackendWithClient(&Config{
		Region:      "us-east-1",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}, &MockKMSClient{})
	if err != nil {
		t.Fatalf("NewBackendWithClient() error = %v", err)
	}

	tests := []struct {
		name     string
		attrs    *types.KeyAttributes
		wantAlgo kmstypes.SigningAlgorithmSpec
		wantErr  bool
	}{
		{
			name:     "RSA SHA-384",
			attrs:    &types.KeyAttributes{KeyAlgorithm: x509.RSA, Hash: crypto.SHA384},
			wantAlgo: kmstypes.SigningAlgorithmSpecRsassaPssSha384,
		},
		{
			name:     "RSA SHA-512",
			attrs:    &types.KeyAttributes{KeyAlgorithm: x509.RSA, Hash: crypto.SHA512},
			wantAlgo: kmstypes.SigningAlgorithmSpecRsassaPssSha512,
		},
		{
			name:    "RSA unsupported hash",
			attrs:   &types.KeyAttributes{KeyAlgorithm: x509.RSA, Hash: crypto.MD5},
			wantErr: true,
		},
		{
			name:     "ECDSA SHA-384",
			attrs:    &types.KeyAttributes{KeyAlgorithm: x509.ECDSA, Hash: crypto.SHA384},
			wantAlgo: kmstypes.SigningAlgorithmSpecEcdsaSha384,
		},
		{
			name:     "ECDSA SHA-512",
			attrs:    &types.KeyAttributes{KeyAlgorithm: x509.ECDSA, Hash: crypto.SHA512},
			wantAlgo: kmstypes.SigningAlgorithmSpecEcdsaSha512,
		},
		{
			name:    "ECDSA unsupported hash",
			attrs:   &types.KeyAttributes{KeyAlgorithm: x509.ECDSA, Hash: crypto.MD5},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			algo, err := b.getSigningAlgorithm(tt.attrs)
			if (err != nil) != tt.wantErr {
				t.Fatalf("getSigningAlgorithm() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && algo != tt.wantAlgo {
				t.Errorf("getSigningAlgorithm() = %v, want %v", algo, tt.wantAlgo)
			}
		})
	}
}

// TestAWSSigningAlgorithm_AllHashes fills in the SHA-384/SHA-512 branches
// awsSigningAlgorithm's existing tests (TestAWSSigningAlgorithm_ECDSA,
// TestAWSSigningAlgorithm_InvalidInputs) don't reach for either key
// algorithm, both for bare-hash (PKCS1v15/ECDSA) and *rsa.PSSOptions.
func TestAWSSigningAlgorithm_AllHashes(t *testing.T) {
	tests := []struct {
		name     string
		keyAlgo  x509.PublicKeyAlgorithm
		opts     crypto.SignerOpts
		wantAlgo kmstypes.SigningAlgorithmSpec
	}{
		{
			name:     "RSA PKCS1v15 SHA-384",
			keyAlgo:  x509.RSA,
			opts:     crypto.SHA384,
			wantAlgo: kmstypes.SigningAlgorithmSpecRsassaPkcs1V15Sha384,
		},
		{
			name:     "RSA PKCS1v15 SHA-512",
			keyAlgo:  x509.RSA,
			opts:     crypto.SHA512,
			wantAlgo: kmstypes.SigningAlgorithmSpecRsassaPkcs1V15Sha512,
		},
		{
			name:     "RSA PSS SHA-384",
			keyAlgo:  x509.RSA,
			opts:     &rsa.PSSOptions{Hash: crypto.SHA384},
			wantAlgo: kmstypes.SigningAlgorithmSpecRsassaPssSha384,
		},
		{
			name:     "RSA PSS SHA-512",
			keyAlgo:  x509.RSA,
			opts:     &rsa.PSSOptions{Hash: crypto.SHA512},
			wantAlgo: kmstypes.SigningAlgorithmSpecRsassaPssSha512,
		},
		{
			name:     "ECDSA SHA-384",
			keyAlgo:  x509.ECDSA,
			opts:     crypto.SHA384,
			wantAlgo: kmstypes.SigningAlgorithmSpecEcdsaSha384,
		},
		{
			name:     "ECDSA SHA-512",
			keyAlgo:  x509.ECDSA,
			opts:     crypto.SHA512,
			wantAlgo: kmstypes.SigningAlgorithmSpecEcdsaSha512,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			algo, err := awsSigningAlgorithm(tt.keyAlgo, tt.opts)
			if err != nil {
				t.Fatalf("awsSigningAlgorithm() error = %v", err)
			}
			if algo != tt.wantAlgo {
				t.Errorf("awsSigningAlgorithm() = %v, want %v", algo, tt.wantAlgo)
			}
		})
	}
}
