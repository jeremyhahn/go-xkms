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

//go:build azurekv

package azurekv

import (
	"context"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// This file covers go-xkms#1098's persistence fix directly: Backend keeps no
// in-process key-metadata cache, so every path that used to read/write the
// old `b.metadata` map now goes through Config.KeyStorage and can fail the
// way any storage.Backend call can fail. failingStorage below injects those
// failures, mirroring pkg/backend/awskms/persistence_test.go's go-xkms#839
// fix exactly. The restart-reuse test that exercises this through the seal
// composition (EnsureSealKey/BuildCloudKMSStrategy) lives in
// pkg/seal/cloud_provision_azurekv_test.go, alongside its awskms and gcpkms
// equivalents.

// failingStorage wraps a real storage.Backend and injects a configurable
// error from one method at a time, so a test can prove a specific
// storage.Backend failure surfaces as a typed error from the azurekv.Backend
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

// TestBackend_MetadataSurvivesNewBackendOverSameStorage proves the
// go-xkms#1098 fix at the backend level: a second *Backend built over the
// SAME Config.KeyStorage/CertStorage as the first -- simulating a process
// restart -- resolves the CN -> key metadata record the first Backend's
// CreateKey wrote, through Get and ListKeys, without ever touching the
// in-process state of the first Backend (which is discarded here by simply
// never referencing it again).
func TestBackend_MetadataSurvivesNewBackendOverSameStorage(t *testing.T) {
	keyStorage := storage.New()
	certStorage := storage.New()

	attrs := &types.KeyAttributes{
		CN:           "restart-survives-key",
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_AZUREKV,
		KeyAlgorithm: x509.RSA,
	}

	b1, err := NewBackendWithClient(&Config{
		VaultURL:    "https://mock-vault.vault.azure.net",
		KeyStorage:  keyStorage,
		CertStorage: certStorage,
	}, NewMockKeyVaultClient())
	if err != nil {
		t.Fatalf("NewBackendWithClient() error = %v", err)
	}
	if _, err := b1.CreateKey(attrs); err != nil {
		t.Fatalf("CreateKey() error = %v", err)
	}

	// "Restart": a brand-new Backend and a brand-new Key Vault client share
	// only keyStorage/certStorage -- no other in-process state survives.
	b2, err := NewBackendWithClient(&Config{
		VaultURL:    "https://mock-vault.vault.azure.net",
		KeyStorage:  keyStorage,
		CertStorage: certStorage,
	}, NewMockKeyVaultClient())
	if err != nil {
		t.Fatalf("NewBackendWithClient() error = %v", err)
	}

	data, err := b2.Get(attrs, backend.FSEXT_PRIVATE_BLOB)
	if err != nil {
		t.Fatalf("Get() on the restarted backend error = %v, want the metadata CreateKey persisted", err)
	}
	if len(data) == 0 {
		t.Error("Get() on the restarted backend returned no metadata")
	}

	keys, err := b2.ListKeys(context.Background())
	if err != nil {
		t.Fatalf("ListKeys() on the restarted backend error = %v", err)
	}
	found := false
	for _, k := range keys {
		if k.CN == attrs.CN {
			found = true
			if k.KeyAlgorithm != x509.RSA {
				t.Errorf("ListKeys() reconstructed KeyAlgorithm = %v, want %v", k.KeyAlgorithm, x509.RSA)
			}
		}
	}
	if !found {
		t.Errorf("ListKeys() on the restarted backend did not include %q", attrs.CN)
	}
}

// TestBackend_DeleteKey_RemovesMetadataAcrossRestart proves that a delete
// through one Backend is visible to a second Backend built over the same
// storage: the persisted record does not linger because it happened to be
// deleted from a different Backend instance.
func TestBackend_DeleteKey_RemovesMetadataAcrossRestart(t *testing.T) {
	keyStorage := storage.New()
	certStorage := storage.New()

	attrs := &types.KeyAttributes{
		CN:           "restart-delete-key",
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_AZUREKV,
		KeyAlgorithm: x509.RSA,
	}

	b1, err := NewBackendWithClient(&Config{
		VaultURL:    "https://mock-vault.vault.azure.net",
		KeyStorage:  keyStorage,
		CertStorage: certStorage,
	}, NewMockKeyVaultClient())
	if err != nil {
		t.Fatalf("NewBackendWithClient() error = %v", err)
	}
	if _, err := b1.CreateKey(attrs); err != nil {
		t.Fatalf("CreateKey() error = %v", err)
	}
	if err := b1.DeleteKey(context.Background(), attrs); err != nil {
		t.Fatalf("DeleteKey() error = %v", err)
	}

	b2, err := NewBackendWithClient(&Config{
		VaultURL:    "https://mock-vault.vault.azure.net",
		KeyStorage:  keyStorage,
		CertStorage: certStorage,
	}, NewMockKeyVaultClient())
	if err != nil {
		t.Fatalf("NewBackendWithClient() error = %v", err)
	}

	if _, err := b2.Get(attrs, backend.FSEXT_PRIVATE_BLOB); err == nil {
		t.Error("Get() on the restarted backend unexpectedly found metadata Delete already removed")
	}
}

// TestCreateKey_StorageSaveError proves that a storage.Put failure AFTER
// Azure Key Vault's CreateKey already succeeded surfaces as an error: the
// caller must not believe the key is fully provisioned when its metadata
// never reached durable storage.
func TestCreateKey_StorageSaveError(t *testing.T) {
	fs := newFailingStorage(t)
	fs.putErr = errStorageUnavailable

	b, err := NewBackendWithClient(&Config{
		VaultURL:    "https://mock-vault.vault.azure.net",
		KeyStorage:  fs,
		CertStorage: storage.New(),
	}, NewMockKeyVaultClient())
	if err != nil {
		t.Fatalf("NewBackendWithClient() failed: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "unsaved-key",
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_AZUREKV,
		KeyAlgorithm: x509.RSA,
	}

	if _, err := b.CreateKey(attrs); err == nil {
		t.Fatal("CreateKey() with a failing metadata save must return an error")
	}
}

// TestGenerateSymmetricKey_StorageSaveError proves that a storage.Put
// failure AFTER the symmetric key material is already stored as an Azure
// Key Vault secret surfaces as an error, exactly like CreateKey's
// equivalent asymmetric-key case above.
func TestGenerateSymmetricKey_StorageSaveError(t *testing.T) {
	fs := newFailingStorage(t)
	fs.putErr = errStorageUnavailable

	config := &Config{
		VaultURL:    "https://mock-vault.vault.azure.net",
		KeyStorage:  fs,
		CertStorage: storage.New(),
	}
	b, err := NewBackendWithClients(config, NewMockKeyVaultClient(), NewMockSecretsClient())
	if err != nil {
		t.Fatalf("NewBackendWithClients() failed: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:                 "seal-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_AZUREKV,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	if _, err := b.GenerateSymmetricKey(context.Background(), attrs); err == nil {
		t.Fatal("GenerateSymmetricKey() with a failing metadata save must return an error")
	}
}

// TestGetKey_StorageExistsCheckError proves that a storage.Exists failure
// while resolving an asymmetric key propagates instead of silently
// reporting the key as not found.
func TestGetKey_StorageExistsCheckError(t *testing.T) {
	fs := newFailingStorage(t)
	fs.existsErr = errStorageUnavailable

	b, err := NewBackendWithClient(&Config{
		VaultURL:    "https://mock-vault.vault.azure.net",
		KeyStorage:  fs,
		CertStorage: storage.New(),
	}, NewMockKeyVaultClient())
	if err != nil {
		t.Fatalf("NewBackendWithClient() failed: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "asym-key",
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_AZUREKV,
		KeyAlgorithm: x509.RSA,
	}

	if _, err := b.GetKey(context.Background(), attrs); err == nil {
		t.Fatal("GetKey() with a failing existence check must return an error")
	}
}

// TestSave_StorageExistsCheckError proves that Save's overwrite=false guard
// propagates a storage.Exists failure instead of assuming the key is absent
// and overwriting silently.
func TestSave_StorageExistsCheckError(t *testing.T) {
	fs := newFailingStorage(t)
	fs.existsErr = errStorageUnavailable

	b, err := NewBackendWithClient(&Config{
		VaultURL:    "https://mock-vault.vault.azure.net",
		KeyStorage:  fs,
		CertStorage: storage.New(),
	}, NewMockKeyVaultClient())
	if err != nil {
		t.Fatalf("NewBackendWithClient() failed: %v", err)
	}

	attrs := &types.KeyAttributes{CN: "some-key", StoreType: backend.STORE_AZUREKV}

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
		VaultURL:    "https://mock-vault.vault.azure.net",
		KeyStorage:  fs,
		CertStorage: storage.New(),
	}, NewMockKeyVaultClient())
	if err != nil {
		t.Fatalf("NewBackendWithClient() failed: %v", err)
	}

	attrs := &types.KeyAttributes{CN: "some-key", StoreType: backend.STORE_AZUREKV}

	if err := b.Save(attrs, []byte("data"), backend.FSEXT_PRIVATE_BLOB, true); err == nil {
		t.Fatal("Save() with a failing underlying store must return an error")
	}
}

// TestDelete_StorageDeleteError proves that a storage.Delete failure other
// than "not found" surfaces as an error, rather than being swallowed the
// same way the Key Vault client's own DeleteKey error is.
func TestDelete_StorageDeleteError(t *testing.T) {
	fs := newFailingStorage(t)
	fs.deleteErr = errStorageUnavailable

	b, err := NewBackendWithClient(&Config{
		VaultURL:    "https://mock-vault.vault.azure.net",
		KeyStorage:  fs,
		CertStorage: storage.New(),
	}, NewMockKeyVaultClient())
	if err != nil {
		t.Fatalf("NewBackendWithClient() failed: %v", err)
	}

	attrs := &types.KeyAttributes{CN: "some-key", StoreType: backend.STORE_AZUREKV}

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
		VaultURL:    "https://mock-vault.vault.azure.net",
		KeyStorage:  fs,
		CertStorage: storage.New(),
	}, NewMockKeyVaultClient())
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
		VaultURL:    "https://mock-vault.vault.azure.net",
		KeyStorage:  fs,
		CertStorage: storage.New(),
	}, NewMockKeyVaultClient())
	if err != nil {
		t.Fatalf("NewBackendWithClient() failed: %v", err)
	}

	attrs := &types.KeyAttributes{CN: "some-key", StoreType: backend.STORE_AZUREKV}

	if _, err := b.Get(attrs, backend.FSEXT_PRIVATE_BLOB); err == nil {
		t.Fatal("Get() with a failing underlying store must return an error")
	} else if !errors.Is(err, backend.ErrFileNotFound) {
		t.Errorf("Get() error = %v, want errors.Is(err, backend.ErrFileNotFound)", err)
	}
}
