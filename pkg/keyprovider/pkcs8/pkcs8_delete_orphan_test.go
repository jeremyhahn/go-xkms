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
	"errors"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// metaDeleteFailOnceStorage fails the first Delete of one metadata record and
// passes every other call through, modelling a DeleteKey interrupted between
// removing the key blob and removing its metadata record.
type metaDeleteFailOnceStorage struct {
	storage.Backend
	metaKey string
	once    sync.Once
}

// Delete fails once for the configured metadata record.
func (s *metaDeleteFailOnceStorage) Delete(ctx context.Context, key string) error {
	if key == s.metaKey {
		failed := false
		s.once.Do(func() { failed = true })
		if failed {
			return &errs.Message{Msg: "injected interrupted metadata delete"}
		}
	}
	return s.Backend.Delete(ctx, key)
}

// TestDeleteKey_InterruptedDeleteLeavesNoOrphanedMetadata proves an
// interrupted DeleteKey is recoverable (#2231): retrying it removes the
// metadata record the first attempt left behind, and a new key under the same
// identifier never inherits that record's Exportable flag.
func TestDeleteKey_InterruptedDeleteLeavesNoOrphanedMetadata(t *testing.T) {
	be, keyStorage := createTestBackend(t)
	defer func() { _ = be.Close() }()

	ctx := context.Background()
	attrs := tenantRSAAttrs("tenant-a", "interrupted-delete.com")
	attrs.Exportable = true
	if _, err := be.GenerateKey(ctx, attrs); err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	keyID := attrs.ID()
	be.storage = &metaDeleteFailOnceStorage{Backend: keyStorage, metaKey: metadataPath(keyID)}

	if err := be.DeleteKey(ctx, attrs); err == nil {
		t.Fatal("DeleteKey must report the interrupted metadata delete")
	}
	if _, err := keyStorage.Get(ctx, metadataPath(keyID)); err != nil {
		t.Fatalf("precondition: the interrupted delete should leave the record, got %v", err)
	}

	// (a) A retry completes the delete: the orphaned record is removed.
	if err := be.DeleteKey(ctx, attrs); err != nil {
		t.Fatalf("retried DeleteKey failed: %v", err)
	}
	if _, err := keyStorage.Get(ctx, metadataPath(keyID)); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("the retried delete left the metadata record behind (err=%v)", err)
	}

	// A further delete of a key that is entirely gone reports not found.
	if err := be.DeleteKey(ctx, attrs); err == nil {
		t.Fatal("DeleteKey of an absent key must report not found")
	}
}

// TestGenerateKey_OrphanedMetadataIsNotInherited proves a key created under
// an identifier whose metadata record outlived its blob starts from its own
// attributes, not from the orphaned record (#2231).
func TestGenerateKey_OrphanedMetadataIsNotInherited(t *testing.T) {
	be, keyStorage := createTestBackend(t)
	defer func() { _ = be.Close() }()

	ctx := context.Background()
	attrs := tenantRSAAttrs("tenant-a", "orphaned-meta.com")
	attrs.Exportable = true
	if _, err := be.GenerateKey(ctx, attrs); err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	keyID := attrs.ID()
	// Orphan the record: remove only the key blob.
	if err := storage.DeleteKey(ctx, keyStorage, keyID); err != nil {
		t.Fatalf("removing the key blob failed: %v", err)
	}

	replacement := tenantRSAAttrs("tenant-a", "orphaned-meta.com")
	if _, err := be.GenerateKey(ctx, replacement); err != nil {
		t.Fatalf("GenerateKey (replacement) failed: %v", err)
	}
	listed, err := be.ListKeys(ctx)
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}
	got := findByCN(t, listed, "orphaned-meta.com")
	if got.Exportable {
		t.Error("the replacement key inherited the orphaned record's exportable flag")
	}
	if got.TenantID != "tenant-a" {
		t.Errorf("replacement tenant = %q, want %q", got.TenantID, "tenant-a")
	}
}
