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
	"crypto/x509"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// This file covers go-xkms#839's persistence fix directly: Backend keeps no
// in-process key-metadata cache, so every path that used to read/write the
// old `b.metadata` map now goes through Config.KeyStorage and can fail the
// way any storage.Backend call can fail. failingStorage below injects those
// failures; the restart-reuse test lives in
// pkg/seal/cloud_provision_awskms_test.go, alongside EnsureSealKey/
// BuildCloudKMSStrategy, since it exercises that composition rather than the
// backend alone.

// failingStorage wraps a real storage.Backend and injects a configurable
// error from one method at a time, so a test can prove a specific
// storage.Backend failure surfaces as a typed error from the awskms.Backend
// method under test rather than being silently swallowed or panicking.
// Every method it does not override is promoted from the embedded Backend.
type failingStorage struct {
	storage.Backend
	getErr    error
	putErr    error
	existsErr error
	deleteErr error
	listErr   error
}

func (f *failingStorage) Get(ctx context.Context, key string) ([]byte, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	return f.Backend.Get(ctx, key)
}

func (f *failingStorage) Put(ctx context.Context, key string, value []byte) error {
	if f.putErr != nil {
		return f.putErr
	}
	return f.Backend.Put(ctx, key, value)
}

func (f *failingStorage) Exists(ctx context.Context, key string) (bool, error) {
	if f.existsErr != nil {
		return false, f.existsErr
	}
	return f.Backend.Exists(ctx, key)
}

func (f *failingStorage) Delete(ctx context.Context, key string) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	return f.Backend.Delete(ctx, key)
}

func (f *failingStorage) List(ctx context.Context, prefix string) ([]string, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.Backend.List(ctx, prefix)
}

var _ storage.Backend = (*failingStorage)(nil)

// newFailingStorage builds a failingStorage backed by a real in-memory
// engine, so every non-injected method behaves exactly like production
// storage.
func newFailingStorage(t *testing.T) *failingStorage {
	t.Helper()
	mem, err := storage.NewMemoryBackend()
	if err != nil {
		t.Fatalf("failed to create memory backend: %v", err)
	}
	return &failingStorage{Backend: mem}
}

var errStorageUnavailable = errors.New("storage: backend unavailable")

// TestGenerateSymmetricKey_StorageExistsCheckError proves that a
// storage.KeyExists failure while checking for a pre-existing key
// propagates instead of silently falling through to CreateKey (which would
// generate a duplicate, orphaned CMK).
func TestGenerateSymmetricKey_StorageExistsCheckError(t *testing.T) {
	fs := newFailingStorage(t)
	fs.existsErr = errStorageUnavailable

	b, err := NewBackendWithClient(&Config{
		Region:      "us-east-1",
		KeyStorage:  fs,
		CertStorage: storage.New(),
	}, &MockKMSClient{})
	if err != nil {
		t.Fatalf("NewBackendWithClient() failed: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:                 "seal-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_AWSKMS,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	if _, err := b.GenerateSymmetricKey(context.Background(), attrs); err == nil {
		t.Fatal("GenerateSymmetricKey() with a failing existence check must return an error")
	}
}

// TestGenerateSymmetricKey_StorageSaveError proves that a storage.SaveKey
// failure AFTER AWS KMS's CreateKey already succeeded surfaces as an error:
// the caller must not believe the key is fully provisioned when its
// metadata never reached durable storage.
func TestGenerateSymmetricKey_StorageSaveError(t *testing.T) {
	fs := newFailingStorage(t)
	fs.putErr = errStorageUnavailable

	createKeyCalled := false
	mock := &MockKMSClient{
		CreateKeyFunc: func(_ context.Context, _ *kms.CreateKeyInput, _ ...func(*kms.Options)) (*kms.CreateKeyOutput, error) {
			createKeyCalled = true
			return &kms.CreateKeyOutput{KeyMetadata: &kmstypes.KeyMetadata{KeyId: aws.String("new-key-id")}}, nil
		},
		CreateAliasFunc: func(_ context.Context, _ *kms.CreateAliasInput, _ ...func(*kms.Options)) (*kms.CreateAliasOutput, error) {
			return &kms.CreateAliasOutput{}, nil
		},
	}

	b, err := NewBackendWithClient(&Config{
		Region:      "us-east-1",
		KeyStorage:  fs,
		CertStorage: storage.New(),
	}, mock)
	if err != nil {
		t.Fatalf("NewBackendWithClient() failed: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:                 "seal-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_AWSKMS,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	if _, err := b.GenerateSymmetricKey(context.Background(), attrs); err == nil {
		t.Fatal("GenerateSymmetricKey() with a failing metadata save must return an error")
	}
	if !createKeyCalled {
		t.Fatal("test invariant broken: CreateKey should have been reached before the metadata save")
	}
}

// TestSymmetricEncrypter_StorageExistsCheckError proves that a
// storage.KeyExists failure while confirming the key is provisioned
// propagates rather than being treated as "not found" or silently ignored.
func TestSymmetricEncrypter_StorageExistsCheckError(t *testing.T) {
	fs := newFailingStorage(t)
	fs.existsErr = errStorageUnavailable

	b, err := NewBackendWithClient(&Config{
		Region:      "us-east-1",
		KeyStorage:  fs,
		CertStorage: storage.New(),
	}, &MockKMSClient{})
	if err != nil {
		t.Fatalf("NewBackendWithClient() failed: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:                 "seal-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_AWSKMS,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	if _, err := b.SymmetricEncrypter(context.Background(), attrs); err == nil {
		t.Fatal("SymmetricEncrypter() with a failing existence check must return an error")
	}
}

// TestCreateKey_StorageSaveError proves that, for the asymmetric path too, a
// storage.SaveKey failure after AWS KMS's CreateKey already succeeded
// surfaces as an error (still carrying the AWS-assigned key ID, since the
// key genuinely exists in AWS -- only its local metadata record failed).
func TestCreateKey_StorageSaveError(t *testing.T) {
	fs := newFailingStorage(t)
	fs.putErr = errStorageUnavailable

	mock := &MockKMSClient{
		CreateKeyFunc: func(_ context.Context, _ *kms.CreateKeyInput, _ ...func(*kms.Options)) (*kms.CreateKeyOutput, error) {
			return &kms.CreateKeyOutput{KeyMetadata: &kmstypes.KeyMetadata{KeyId: aws.String("new-key-id")}}, nil
		},
		CreateAliasFunc: func(_ context.Context, _ *kms.CreateAliasInput, _ ...func(*kms.Options)) (*kms.CreateAliasOutput, error) {
			return &kms.CreateAliasOutput{}, nil
		},
	}

	b, err := NewBackendWithClient(&Config{
		Region:      "us-east-1",
		KeyStorage:  fs,
		CertStorage: storage.New(),
	}, mock)
	if err != nil {
		t.Fatalf("NewBackendWithClient() failed: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "asym-key",
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_AWSKMS,
		KeyAlgorithm: x509.RSA,
	}

	keyID, err := b.CreateKey(attrs)
	if err == nil {
		t.Fatal("CreateKey() with a failing metadata save must return an error")
	}
	if keyID != "new-key-id" {
		t.Errorf("CreateKey() keyID = %q, want the AWS-assigned id even though the local save failed", keyID)
	}
}

// TestGetKey_StorageExistsCheckError proves that a storage.KeyExists
// failure while resolving an asymmetric key propagates.
func TestGetKey_StorageExistsCheckError(t *testing.T) {
	fs := newFailingStorage(t)
	fs.existsErr = errStorageUnavailable

	b, err := NewBackendWithClient(&Config{
		Region:      "us-east-1",
		KeyStorage:  fs,
		CertStorage: storage.New(),
	}, &MockKMSClient{})
	if err != nil {
		t.Fatalf("NewBackendWithClient() failed: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "asym-key",
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_AWSKMS,
		KeyAlgorithm: x509.RSA,
	}

	if _, err := b.GetKey(context.Background(), attrs); err == nil {
		t.Fatal("GetKey() with a failing existence check must return an error")
	}
}

// TestSave_StorageExistsCheckError proves that Save's overwrite=false guard
// propagates a storage.KeyExists failure instead of assuming the key is
// absent and overwriting silently.
func TestSave_StorageExistsCheckError(t *testing.T) {
	fs := newFailingStorage(t)
	fs.existsErr = errStorageUnavailable

	b, err := NewBackendWithClient(&Config{
		Region:      "us-east-1",
		KeyStorage:  fs,
		CertStorage: storage.New(),
	}, &MockKMSClient{})
	if err != nil {
		t.Fatalf("NewBackendWithClient() failed: %v", err)
	}

	attrs := &types.KeyAttributes{CN: "some-key", StoreType: backend.STORE_AWSKMS}

	if err := b.Save(attrs, []byte("data"), backend.FSEXT_PRIVATE_BLOB, false); err == nil {
		t.Fatal("Save() with a failing existence check must return an error")
	}
}

// TestSave_StorageSaveError proves that a storage.Put failure from the
// underlying backend surfaces as an error from Save.
func TestSave_StorageSaveError(t *testing.T) {
	fs := newFailingStorage(t)
	fs.putErr = errStorageUnavailable

	b, err := NewBackendWithClient(&Config{
		Region:      "us-east-1",
		KeyStorage:  fs,
		CertStorage: storage.New(),
	}, &MockKMSClient{})
	if err != nil {
		t.Fatalf("NewBackendWithClient() failed: %v", err)
	}

	attrs := &types.KeyAttributes{CN: "some-key", StoreType: backend.STORE_AWSKMS}

	if err := b.Save(attrs, []byte("data"), backend.FSEXT_PRIVATE_BLOB, true); err == nil {
		t.Fatal("Save() with a failing underlying store must return an error")
	}
}

// TestDelete_StorageDeleteError proves that a storage.Delete failure other
// than "not found" surfaces as an error, rather than being swallowed the
// same way ScheduleKeyDeletion's idempotent not-found case is.
func TestDelete_StorageDeleteError(t *testing.T) {
	fs := newFailingStorage(t)
	fs.deleteErr = errStorageUnavailable

	b, err := NewBackendWithClient(&Config{
		Region:      "us-east-1",
		KeyStorage:  fs,
		CertStorage: storage.New(),
	}, &MockKMSClient{
		ScheduleKeyDeletionFunc: func(_ context.Context, _ *kms.ScheduleKeyDeletionInput, _ ...func(*kms.Options)) (*kms.ScheduleKeyDeletionOutput, error) {
			return &kms.ScheduleKeyDeletionOutput{}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewBackendWithClient() failed: %v", err)
	}

	attrs := &types.KeyAttributes{CN: "some-key", StoreType: backend.STORE_AWSKMS}

	if err := b.Delete(attrs); err == nil {
		t.Fatal("Delete() with a failing underlying store (not a not-found) must return an error")
	}
}

// TestListKeys_StorageListError proves that a storage.List failure
// propagates instead of silently returning an empty (and misleading) list.
func TestListKeys_StorageListError(t *testing.T) {
	fs := newFailingStorage(t)
	fs.listErr = errStorageUnavailable

	b, err := NewBackendWithClient(&Config{
		Region:      "us-east-1",
		KeyStorage:  fs,
		CertStorage: storage.New(),
	}, &MockKMSClient{})
	if err != nil {
		t.Fatalf("NewBackendWithClient() failed: %v", err)
	}

	if _, err := b.ListKeys(context.Background()); err == nil {
		t.Fatal("ListKeys() with a failing underlying store must return an error")
	}
}

// TestGet_StorageGetError proves that Get's metadata/blob path surfaces
// backend.ErrFileNotFound for a genuine storage failure exactly as it does
// for a missing key -- both are "the caller cannot read this blob", which
// matches storage.GetKey's own contract of not distinguishing the two.
func TestGet_StorageGetError(t *testing.T) {
	fs := newFailingStorage(t)
	fs.getErr = errStorageUnavailable

	b, err := NewBackendWithClient(&Config{
		Region:      "us-east-1",
		KeyStorage:  fs,
		CertStorage: storage.New(),
	}, &MockKMSClient{})
	if err != nil {
		t.Fatalf("NewBackendWithClient() failed: %v", err)
	}

	attrs := &types.KeyAttributes{CN: "some-key", StoreType: backend.STORE_AWSKMS}

	if _, err := b.Get(attrs, backend.FSEXT_PRIVATE_BLOB); err == nil {
		t.Fatal("Get() with a failing underlying store must return an error")
	} else if !errors.Is(err, backend.ErrFileNotFound) {
		t.Errorf("Get() error = %v, want errors.Is(err, backend.ErrFileNotFound)", err)
	}
}

// The tests below exercise getKeyID directly and through its callers.
// getKeyID has exactly ONE silent fallback (storage.ErrNotFound resolves to
// the "alias/{cn}" alias, verified safe because both CreateKey and
// GenerateSymmetricKey attempt to create that exact alias alongside every
// key they provision -- see TestGetKeyID in awskms_test.go for that case).
// Every other failure -- a genuine storage error, a corrupt record, or a
// record missing key_id -- must return a typed error instead, since
// KeyStorage is now this backend's sole source of truth for which AWS key a
// CN maps to and a silent wrong answer would address a different key with
// nothing surfaced to say so.

// TestGetKeyID_StorageErrorPropagatesThroughSign proves that a
// Config.KeyStorage failure (not "not found") during Sign's key resolution
// surfaces as a typed error, and that Sign never reaches AWS KMS with a
// guessed key ID.
func TestGetKeyID_StorageErrorPropagatesThroughSign(t *testing.T) {
	fs := newFailingStorage(t)
	fs.getErr = errStorageUnavailable

	b, err := NewBackendWithClient(&Config{
		Region:      "us-east-1",
		KeyStorage:  fs,
		CertStorage: storage.New(),
	}, &MockKMSClient{
		SignFunc: func(_ context.Context, _ *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
			t.Fatal("Sign must not reach AWS KMS when key resolution fails")
			return nil, nil
		},
	})
	if err != nil {
		t.Fatalf("NewBackendWithClient() failed: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "some-key",
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_AWSKMS,
		KeyAlgorithm: x509.RSA,
	}

	_, gotErr := b.Sign(attrs, []byte("digest"))
	if gotErr == nil {
		t.Fatal("Sign() with a failing key-metadata read must return an error")
	}
	if !errors.Is(gotErr, ErrMetadataStorage) {
		t.Errorf("Sign() error = %v, want errors.Is(err, ErrMetadataStorage)", gotErr)
	}
}

// TestGetKeyID_StorageErrorPropagatesThroughDecrypter mirrors the Sign case
// for Decrypter, the second representative caller: it also resolves the key
// ID via getKeyID before making any AWS KMS call.
func TestGetKeyID_StorageErrorPropagatesThroughDecrypter(t *testing.T) {
	fs := newFailingStorage(t)
	fs.getErr = errStorageUnavailable

	b, err := NewBackendWithClient(&Config{
		Region:      "us-east-1",
		KeyStorage:  fs,
		CertStorage: storage.New(),
	}, &MockKMSClient{
		GetPublicKeyFunc: func(_ context.Context, _ *kms.GetPublicKeyInput, _ ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
			t.Fatal("Decrypter must not reach AWS KMS when key resolution fails")
			return nil, nil
		},
	})
	if err != nil {
		t.Fatalf("NewBackendWithClient() failed: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "some-key",
		KeyType:      backend.KEY_TYPE_ENCRYPTION,
		StoreType:    backend.STORE_AWSKMS,
		KeyAlgorithm: x509.RSA,
	}

	_, gotErr := b.Decrypter(context.Background(), attrs)
	if gotErr == nil {
		t.Fatal("Decrypter() with a failing key-metadata read must return an error")
	}
	if !errors.Is(gotErr, ErrMetadataStorage) {
		t.Errorf("Decrypter() error = %v, want errors.Is(err, ErrMetadataStorage)", gotErr)
	}
}

// TestGetKeyID_CorruptMetadataRecord proves that a metadata record which
// exists but fails to parse as JSON returns a typed error rather than
// silently falling back to an alias that might address a different key.
func TestGetKeyID_CorruptMetadataRecord(t *testing.T) {
	ks := storage.New()
	if err := storage.SaveKey(context.Background(), ks, "corrupt-key", []byte("not valid json")); err != nil {
		t.Fatalf("failed to seed corrupt metadata: %v", err)
	}

	b, err := NewBackendWithClient(&Config{
		Region:      "us-east-1",
		KeyStorage:  ks,
		CertStorage: storage.New(),
	}, &MockKMSClient{})
	if err != nil {
		t.Fatalf("NewBackendWithClient() failed: %v", err)
	}

	_, gotErr := b.getKeyID(context.Background(), "corrupt-key")
	if gotErr == nil {
		t.Fatal("getKeyID() with a corrupt (non-JSON) record must return an error")
	}
	if !errors.Is(gotErr, ErrMetadataStorage) {
		t.Errorf("getKeyID() error = %v, want errors.Is(err, ErrMetadataStorage)", gotErr)
	}
}

// TestGetKeyID_MissingKeyIDField proves that a metadata record which parses
// as valid JSON but carries no key_id field returns a typed error, the same
// as a record that fails to parse at all.
func TestGetKeyID_MissingKeyIDField(t *testing.T) {
	ks := storage.New()
	if err := storage.SaveKey(context.Background(), ks, "no-key-id", []byte(`{"alias":"alias/no-key-id"}`)); err != nil {
		t.Fatalf("failed to seed metadata: %v", err)
	}

	b, err := NewBackendWithClient(&Config{
		Region:      "us-east-1",
		KeyStorage:  ks,
		CertStorage: storage.New(),
	}, &MockKMSClient{})
	if err != nil {
		t.Fatalf("NewBackendWithClient() failed: %v", err)
	}

	_, gotErr := b.getKeyID(context.Background(), "no-key-id")
	if gotErr == nil {
		t.Fatal("getKeyID() with a record missing key_id must return an error")
	}
	if !errors.Is(gotErr, ErrMetadataStorage) {
		t.Errorf("getKeyID() error = %v, want errors.Is(err, ErrMetadataStorage)", gotErr)
	}
}
