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

package pkcs8

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// interruptingStorage fails the first metadata Delete and the first metadata
// Put it sees, standing in for a process stop or a transient storage failure
// part-way through a two-record operation. Every later call delegates.
type interruptingStorage struct {
	storage.Backend
	failMetaDelete bool
	failMetaPut    bool
	failBlobDelete bool
}

func (s *interruptingStorage) Delete(ctx context.Context, key string) error {
	if s.failMetaDelete && strings.HasPrefix(key, "meta/") {
		s.failMetaDelete = false
		return errors.New("injected interruption on metadata delete")
	}
	if s.failBlobDelete && !strings.HasPrefix(key, "meta/") {
		s.failBlobDelete = false
		return errors.New("injected interruption on key delete")
	}
	return s.Backend.Delete(ctx, key)
}

func (s *interruptingStorage) Put(ctx context.Context, key string, value []byte) error {
	if s.failMetaPut && strings.HasPrefix(key, "meta/") {
		s.failMetaPut = false
		return errors.New("injected interruption on metadata put")
	}
	return s.Backend.Put(ctx, key, value)
}

func newOrphanTestBackend(t *testing.T) (*PKCS8Backend, storage.Backend) {
	t.Helper()
	keyStorage := storage.New()
	real, err := NewBackend(&Config{KeyStorage: keyStorage, AllowPlaintextKeys: true})
	if err != nil {
		t.Fatalf("NewBackend failed: %v", err)
	}
	be := real.(*PKCS8Backend)
	t.Cleanup(func() { _ = be.Close() })
	return be, keyStorage
}

// placeBlobOnly stores key material under keyID with no metadata record, the
// way an import that carries no attributes does, so the listed attributes come
// only from whatever metadata record the identifier already has.
func placeBlobOnly(t *testing.T, be *PKCS8Backend, keyStorage storage.Backend, keyID string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey failed: %v", err)
	}
	data, err := be.encodeKey(priv, nil)
	if err != nil {
		t.Fatalf("encodeKey failed: %v", err)
	}
	if err := storage.SaveKey(context.Background(), keyStorage, keyID, data); err != nil {
		t.Fatalf("SaveKey failed: %v", err)
	}
}

// TestDeleteKey_InterruptedDeleteLeavesNoInheritedMetadata pins #2231: a
// DeleteKey interrupted between its two storage calls must be recoverable by
// a retry, and a later key of the same identifier must not inherit the
// deleted key's tenant record or Exportable flag.
func TestDeleteKey_InterruptedDeleteLeavesNoInheritedMetadata(t *testing.T) {
	be, keyStorage := newOrphanTestBackend(t)
	ctx := context.Background()

	attrs := tenantRSAAttrs("tenant-a", "interrupted.com")
	attrs.Exportable = true
	if _, err := be.GenerateKey(ctx, attrs); err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	keyID := attrs.ID()

	be.storage = &interruptingStorage{Backend: keyStorage, failMetaDelete: true}
	if err := be.DeleteKey(ctx, attrs); err == nil {
		t.Fatal("the interrupted DeleteKey must report its failure")
	}

	// (a) The retry completes the delete whatever the first call reached.
	if err := be.DeleteKey(ctx, attrs); err != nil && !errors.Is(err, backend.ErrKeyNotFound) {
		t.Fatalf("retried DeleteKey failed: %v", err)
	}
	if _, err := keyStorage.Get(ctx, metadataPath(keyID)); err == nil {
		t.Fatal("a retried DeleteKey left the metadata record behind")
	}
	if _, err := storage.GetKey(ctx, keyStorage, keyID); err == nil {
		t.Fatal("a retried DeleteKey left the key blob behind")
	}

	// (b) A new key under the same identifier starts from the defaults.
	placeBlobOnly(t, be, keyStorage, keyID)
	listed, err := be.ListKeys(ctx)
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}
	if findByCN(t, listed, "interrupted.com").Exportable {
		t.Error("the new key inherited the deleted key's Exportable flag")
	}
}

// TestGenerateKey_RollbackRemovesStaleMetadata pins the creation half of
// #2231: a metadata record whose blob is missing must not survive a key
// creation of the same identifier, even one whose own metadata write fails
// and rolls the blob back.
func TestGenerateKey_RollbackRemovesStaleMetadata(t *testing.T) {
	be, keyStorage := newOrphanTestBackend(t)
	ctx := context.Background()

	stale := tenantRSAAttrs("tenant-a", "stale.com")
	stale.Exportable = true
	keyID := stale.ID()
	if err := WriteKeyMetadata(ctx, keyStorage, keyID, stale); err != nil {
		t.Fatalf("WriteKeyMetadata failed: %v", err)
	}

	be.storage = &interruptingStorage{Backend: keyStorage, failMetaPut: true}
	if _, err := be.GenerateKey(ctx, tenantRSAAttrs("tenant-a", "stale.com")); err == nil {
		t.Fatal("GenerateKey must report the failed metadata write")
	}
	if _, err := keyStorage.Get(ctx, metadataPath(keyID)); err == nil {
		t.Fatal("a stale metadata record of a missing blob survived key creation")
	}

	placeBlobOnly(t, be, keyStorage, keyID)
	listed, err := be.ListKeys(ctx)
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}
	if findByCN(t, listed, "stale.com").Exportable {
		t.Error("the new key inherited the stale record's Exportable flag")
	}
}

// A failed blob delete keeps the ownership record, and a retry removes both.
func TestDeleteKey_FailedBlobDeleteKeepsOwnership(t *testing.T) {
	be, keyStorage := newOrphanTestBackend(t)
	ctx := context.Background()

	attrs := tenantRSAAttrs("tenant-a", "blobfail.com")
	if _, err := be.GenerateKey(ctx, attrs); err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	keyID := attrs.ID()

	be.storage = &interruptingStorage{Backend: keyStorage, failBlobDelete: true}
	if err := be.DeleteKey(ctx, attrs); err == nil {
		t.Fatal("DeleteKey must report the failed key delete")
	}

	listed, err := be.ListKeys(ctx)
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}
	if got := findByCN(t, listed, "blobfail.com").TenantID; got != "tenant-a" {
		t.Fatalf("key listed with tenant %q after a failed delete, want tenant-a", got)
	}

	if err := be.DeleteKey(ctx, attrs); err != nil {
		t.Fatalf("retried DeleteKey failed: %v", err)
	}
	if _, err := keyStorage.Get(ctx, metadataPath(keyID)); err == nil {
		t.Fatal("a retried DeleteKey left the metadata record behind")
	}
	if _, err := storage.GetKey(ctx, keyStorage, keyID); err == nil {
		t.Fatal("a retried DeleteKey left the key blob behind")
	}
}

// A rollback whose metadata cleanup fails keeps the blob and reports both errors.
func TestGenerateKey_RollbackStopsWhenMetadataCleanupFails(t *testing.T) {
	be, keyStorage := newOrphanTestBackend(t)
	ctx := context.Background()

	stale := tenantRSAAttrs("tenant-a", "stuck.com")
	keyID := stale.ID()
	if err := WriteKeyMetadata(ctx, keyStorage, keyID, stale); err != nil {
		t.Fatalf("WriteKeyMetadata failed: %v", err)
	}

	be.storage = &interruptingStorage{Backend: keyStorage, failMetaPut: true, failMetaDelete: true}
	_, err := be.GenerateKey(ctx, tenantRSAAttrs("tenant-a", "stuck.com"))
	if err == nil {
		t.Fatal("GenerateKey must report the failed metadata write")
	}
	if !strings.Contains(err.Error(), "metadata delete") {
		t.Errorf("GenerateKey error %q does not carry the metadata cleanup failure", err)
	}
	if _, err := keyStorage.Get(ctx, metadataPath(keyID)); err != nil {
		t.Fatalf("stale metadata record unexpectedly gone: %v", err)
	}
	if _, err := storage.GetKey(ctx, keyStorage, keyID); err != nil {
		t.Fatal("the rollback deleted the blob while its metadata record remained")
	}
}
