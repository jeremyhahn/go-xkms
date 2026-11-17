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

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
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

// pauseStorage pauses the first generator call that publishes, or checks for,
// one key blob: after an Exists on the blob path that reports it absent, or
// before a PutIfAbsent of it (afterPublish false), or after a PutIfAbsent
// that stored it (afterPublish true). paused is closed when the pause starts;
// the call then blocks until resume is closed.
type pauseStorage struct {
	storage.Backend
	blobKey      string
	afterPublish bool
	once         sync.Once
	paused       chan struct{}
	resume       chan struct{}
}

func newPauseStorage(inner storage.Backend, keyID string, afterPublish bool) *pauseStorage {
	return &pauseStorage{
		Backend:      inner,
		blobKey:      storage.KeyPath(keyID),
		afterPublish: afterPublish,
		paused:       make(chan struct{}),
		resume:       make(chan struct{}),
	}
}

func (s *pauseStorage) pause() {
	s.once.Do(func() {
		close(s.paused)
		<-s.resume
	})
}

// Exists pauses after an absence check of the blob.
func (s *pauseStorage) Exists(ctx context.Context, key string) (bool, error) {
	exists, err := s.Backend.Exists(ctx, key)
	if key == s.blobKey && !s.afterPublish && err == nil && !exists {
		s.pause()
	}
	return exists, err
}

// PutIfAbsent pauses before (or, with afterPublish, after) publishing the blob.
func (s *pauseStorage) PutIfAbsent(ctx context.Context, key string, value []byte) (bool, error) {
	if key == s.blobKey && !s.afterPublish {
		s.pause()
	}
	stored, err := s.Backend.PutIfAbsent(ctx, key, value)
	if key == s.blobKey && s.afterPublish && err == nil && stored {
		s.pause()
	}
	return stored, err
}

// newSharedBackend opens a second backend on store, the way a second process
// shares one storage. It does not close store.
func newSharedBackend(t *testing.T, store storage.Backend) *PKCS8Backend {
	t.Helper()
	be, err := NewBackend(&Config{KeyStorage: store, AllowPlaintextKeys: true})
	if err != nil {
		t.Fatalf("NewBackend failed: %v", err)
	}
	return be.(*PKCS8Backend)
}

// TestGenerateKey_LosingGeneratorKeepsWinnersMetadata proves a generator that
// loses the race for an identifier never touches the winner's metadata
// record: generator A checks the identifier while it is free, generator B (a
// second backend on the same storage) then creates the key, and A must fail
// with ErrKeyAlreadyExists leaving B's tenant, Exportable flag and origin
// intact (#2231, Codex finding 1).
func TestGenerateKey_LosingGeneratorKeepsWinnersMetadata(t *testing.T) {
	winner, keyStorage := createTestBackend(t)
	defer func() { _ = winner.Close() }()

	ctx := context.Background()
	attrs := tenantRSAAttrs("tenant-a", "raced-generate.com")
	attrs.Exportable = true
	attrs.KeyOrigin = types.KeyOriginGenerated

	hook := newPauseStorage(keyStorage, attrs.ID(), false)
	loser := newSharedBackend(t, hook)

	loserErr := make(chan error, 1)
	go func() {
		_, err := loser.GenerateKey(ctx, tenantRSAAttrs("tenant-a", "raced-generate.com"))
		loserErr <- err
	}()
	<-hook.paused
	if _, err := winner.GenerateKey(ctx, attrs); err != nil {
		close(hook.resume)
		t.Fatalf("GenerateKey (winner) failed: %v", err)
	}
	close(hook.resume)
	if err := <-loserErr; !errors.Is(err, backend.ErrKeyAlreadyExists) {
		t.Fatalf("losing GenerateKey = %v, want ErrKeyAlreadyExists", err)
	}

	listed, err := winner.ListKeys(ctx)
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}
	got := findByCN(t, listed, "raced-generate.com")
	if got.TenantID != "tenant-a" || !got.Exportable || got.KeyOrigin != types.KeyOriginGenerated {
		t.Errorf("winner's record lost: tenant=%q exportable=%v origin=%q, want tenant-a/true/%q",
			got.TenantID, got.Exportable, got.KeyOrigin, types.KeyOriginGenerated)
	}
}

// TestGenerateKey_OrphanedMetadataIsNotInherited proves a key created under
// an identifier whose metadata record outlived its blob never reads as
// carrying that record, not even between publishing its blob and writing its
// own record: a second backend listing the key in that window must not see
// the orphan's tenant or Exportable flag (#2231, Codex finding 4).
func TestGenerateKey_OrphanedMetadataIsNotInherited(t *testing.T) {
	reader, keyStorage := createTestBackend(t)
	defer func() { _ = reader.Close() }()

	ctx := context.Background()
	attrs := tenantRSAAttrs("tenant-a", "orphaned-meta.com")
	if _, err := reader.GenerateKey(ctx, attrs); err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	keyID := attrs.ID()
	// Plant a record that differs from the replacement on every attribute the
	// identifier cannot carry, then orphan it by removing only the blob.
	forged := tenantRSAAttrs("tenant-a", "orphaned-meta.com")
	forged.TenantID = "tenant-orphan"
	forged.Exportable = true
	forged.KeyOrigin = types.KeyOriginImported
	if err := WriteKeyMetadata(ctx, keyStorage, keyID, forged); err != nil {
		t.Fatalf("WriteKeyMetadata failed: %v", err)
	}
	if err := storage.DeleteKey(ctx, keyStorage, keyID); err != nil {
		t.Fatalf("removing the key blob failed: %v", err)
	}

	hook := newPauseStorage(keyStorage, keyID, true)
	generator := newSharedBackend(t, hook)
	genErr := make(chan error, 1)
	go func() {
		_, err := generator.GenerateKey(ctx, tenantRSAAttrs("tenant-a", "orphaned-meta.com"))
		genErr <- err
	}()
	<-hook.paused

	// The blob is published and its own record not yet written.
	listed, err := reader.ListKeys(ctx)
	close(hook.resume)
	if gerr := <-genErr; gerr != nil {
		t.Fatalf("GenerateKey (replacement) failed: %v", gerr)
	}
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}
	mid := findByCN(t, listed, "orphaned-meta.com")
	if mid.Exportable || mid.TenantID == "tenant-orphan" || mid.KeyOrigin == types.KeyOriginImported {
		t.Errorf("the new key read as the orphan's record: tenant=%q exportable=%v origin=%q",
			mid.TenantID, mid.Exportable, mid.KeyOrigin)
	}

	listed, err = reader.ListKeys(ctx)
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}
	got := findByCN(t, listed, "orphaned-meta.com")
	if got.Exportable || got.TenantID != "tenant-a" {
		t.Errorf("replacement = tenant %q exportable %v, want tenant-a/false", got.TenantID, got.Exportable)
	}
}
