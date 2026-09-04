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

package software

import (
	"context"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// metadataFailStorage fails the metadata Put and, optionally, the Delete the
// rollback then attempts. Selecting by path prefix rather than by call order
// keeps the injection aimed at the second of the import's two writes however
// many records the path writes alongside the key.
type metadataFailStorage struct {
	storage.Backend

	failMetaPut bool
	failDelete  bool

	deletes []string
}

func (s *metadataFailStorage) Put(ctx context.Context, key string, value []byte) error {
	if s.failMetaPut && strings.HasPrefix(key, "meta/") {
		return &errs.Message{Msg: "injected metadata put failure"}
	}
	return s.Backend.Put(ctx, key, value)
}

func (s *metadataFailStorage) Delete(ctx context.Context, key string) error {
	s.deletes = append(s.deletes, key)
	if s.failDelete {
		return &errs.Message{Msg: "injected delete failure"}
	}
	return s.Backend.Delete(ctx, key)
}

// newMetadataFailBackend builds a software backend over a storage layer that
// fails the metadata write, so the import's second write can be made to fail
// without a bespoke storage implementation.
func newMetadataFailBackend(t *testing.T, failDelete bool) (types.SymmetricKeyProvider, *metadataFailStorage) {
	t.Helper()

	store := &metadataFailStorage{Backend: storage.New(), failMetaPut: true, failDelete: failDelete}
	be, err := NewBackend(&Config{KeyStorage: store})
	if err != nil {
		t.Fatalf("NewBackend failed: %v", err)
	}
	t.Cleanup(func() { _ = be.Close() })
	return be, store
}

// importSymmetricWithFailingMetadata runs a symmetric import against a backend
// whose metadata write fails, returning the attributes used and the error.
func importSymmetricWithFailingMetadata(t *testing.T, be types.SymmetricKeyProvider,
	cn string) (*types.KeyAttributes, error) {

	t.Helper()

	attrs := createAESAttrs(cn, 256, types.SymmetricAES256GCM)
	// Exportable and Sensitive are the two attributes that live only in the
	// metadata record, so an import that loses the record loses exactly these.
	attrs.Exportable = true
	attrs.Sensitive = false

	keyMaterial := make([]byte, 32)
	if _, err := rand.Read(keyMaterial); err != nil {
		t.Fatalf("generating key material failed: %v", err)
	}

	wrapped := wrapForImport(t, be, attrs,
		backend.WrappingAlgorithmRSAES_OAEP_SHA_256, keyMaterial)

	return attrs, be.(backend.ImportExportBackend).ImportKey(context.Background(), attrs, wrapped)
}

// TestImportSymmetricKey_MetadataFailureRollsBackTheKey is the regression for
// go-xkms#150. importSymmetricKey commits the key bytes and then, as a
// separate write, the metadata record. Without a compensating delete a failed
// second write returns an error to a caller who believes nothing changed,
// while the bytes stay durably stored.
//
// The orphan is not merely untidy. loadKeyMetadata reads a missing record as
// Exportable=false, Sensitive=true, so the key exists under a policy the
// caller never asked for; and because the collision check refuses a second
// import at the same identifier, the orphan blocks its own recovery.
func TestImportSymmetricKey_MetadataFailureRollsBackTheKey(t *testing.T) {
	be, store := newMetadataFailBackend(t, false)
	ctx := context.Background()

	attrs, err := importSymmetricWithFailingMetadata(t, be, "rollback-aes")
	if err == nil {
		t.Fatal("ImportKey succeeded despite the injected metadata failure")
	}

	exists, existsErr := storage.KeyExists(ctx, store, attrs.ID())
	if existsErr != nil {
		t.Fatalf("checking for the key after the failed import failed: %v", existsErr)
	}
	if exists {
		t.Error("the key is still stored after a failed import: the metadata failure must roll the key blob back")
	}
}

// TestImportSymmetricKey_MetadataFailureLeavesTheIDReusable is the consequence
// the rollback exists to produce, asserted end to end rather than through
// storage state: after a failed import the same identifier must import again.
//
// Without the rollback this fails with backend.ErrKeyAlreadyExists -- the
// orphaned blob from the first attempt makes the retry look like a collision,
// so the caller can neither use the key nor replace it.
func TestImportSymmetricKey_MetadataFailureLeavesTheIDReusable(t *testing.T) {
	store := &metadataFailStorage{Backend: storage.New(), failMetaPut: true}
	be, err := NewBackend(&Config{KeyStorage: store})
	if err != nil {
		t.Fatalf("NewBackend failed: %v", err)
	}
	defer func() { _ = be.Close() }()

	attrs, importErr := importSymmetricWithFailingMetadata(t, be, "retry-aes")
	if importErr == nil {
		t.Fatal("ImportKey succeeded despite the injected metadata failure")
	}

	// Let the metadata write through and retry the identical import.
	store.failMetaPut = false

	keyMaterial := make([]byte, 32)
	if _, randErr := rand.Read(keyMaterial); randErr != nil {
		t.Fatalf("generating key material failed: %v", randErr)
	}
	wrapped := wrapForImport(t, be, attrs,
		backend.WrappingAlgorithmRSAES_OAEP_SHA_256, keyMaterial)

	if retryErr := be.(backend.ImportExportBackend).ImportKey(context.Background(), attrs, wrapped); retryErr != nil {
		if errors.Is(retryErr, backend.ErrKeyAlreadyExists) {
			t.Fatalf("retrying the import hit a collision with the orphan left by the failed attempt: %v", retryErr)
		}
		t.Fatalf("retrying the import after a rolled-back failure failed: %v", retryErr)
	}
}

// TestImportSymmetricKey_MetadataFailureReportsAFailedRollback covers the
// branch where the compensating delete itself fails. The key really is
// orphaned then and nothing this process can do will remove it, so the error
// must say so rather than reporting the metadata failure alone -- an operator
// reading it needs to know an identifier was left occupied.
func TestImportSymmetricKey_MetadataFailureReportsAFailedRollback(t *testing.T) {
	be, store := newMetadataFailBackend(t, true)

	attrs, err := importSymmetricWithFailingMetadata(t, be, "rollback-fails-aes")
	if err == nil {
		t.Fatal("ImportKey succeeded despite the injected metadata failure")
	}

	msg := err.Error()
	if !strings.Contains(msg, "rollback of key") {
		t.Errorf("error = %q, want it to report that the rollback also failed", msg)
	}
	if !strings.Contains(msg, attrs.ID()) {
		t.Errorf("error = %q, want it to name the orphaned key %q", msg, attrs.ID())
	}

	// The rollback was attempted against the key path, not some other record.
	wantPath := storage.KeyPath(attrs.ID())
	found := false
	for _, k := range store.deletes {
		if k == wantPath {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("deletes = %v, want the rollback to target %q", store.deletes, wantPath)
	}
}

// TestImportSymmetricKey_CollisionIsRefusedBeforeAnyWrite pins the property the
// rollback's safety rests on: the compensating delete may only ever remove a
// blob this import wrote. If a collision were accepted and overwrote an
// existing key, rolling back would destroy the previous key rather than
// restore it.
//
// This one passes without the rollback too, by design -- it guards the
// pre-existing collision check (go-xkms#165) that the rollback depends on, so
// a later change that relaxes that check fails here rather than silently
// turning the rollback into a destructive operation.
func TestImportSymmetricKey_CollisionIsRefusedBeforeAnyWrite(t *testing.T) {
	store := &metadataFailStorage{Backend: storage.New()}
	be, err := NewBackend(&Config{KeyStorage: store})
	if err != nil {
		t.Fatalf("NewBackend failed: %v", err)
	}
	defer func() { _ = be.Close() }()

	ctx := context.Background()
	attrs := createAESAttrs("collision-before-write", 256, types.SymmetricAES256GCM)
	if _, genErr := be.GenerateSymmetricKey(ctx, attrs); genErr != nil {
		t.Fatalf("GenerateSymmetricKey failed: %v", genErr)
	}

	// Fail the metadata write for the import that follows. If the collision
	// were not refused first, the import would write the key and then roll it
	// back -- destroying the key generated above.
	store.failMetaPut = true

	replacement := make([]byte, 32)
	if _, randErr := rand.Read(replacement); randErr != nil {
		t.Fatalf("generating replacement material failed: %v", randErr)
	}
	wrapped := wrapForImport(t, be, attrs,
		backend.WrappingAlgorithmRSAES_OAEP_SHA_256, replacement)

	importErr := be.(backend.ImportExportBackend).ImportKey(ctx, attrs, wrapped)
	if !errors.Is(importErr, backend.ErrKeyAlreadyExists) {
		t.Fatalf("ImportKey error = %v, want backend.ErrKeyAlreadyExists", importErr)
	}

	if len(store.deletes) != 0 {
		t.Errorf("deletes = %v, want none: a refused collision must not reach the rollback", store.deletes)
	}
	exists, existsErr := storage.KeyExists(ctx, store, attrs.ID())
	if existsErr != nil {
		t.Fatalf("checking for the pre-existing key failed: %v", existsErr)
	}
	if !exists {
		t.Error("the pre-existing key was removed by a refused import")
	}
}
