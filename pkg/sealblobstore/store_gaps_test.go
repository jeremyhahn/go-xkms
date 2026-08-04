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

package sealblobstore

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/kvadapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errFaultInjected is a sentinel error returned by faultyBackend to simulate
// a storage fault that is unrelated to "not found" conditions.
var errFaultInjected = errors.New("sealblobstore: injected storage fault")

// faultyBackend wraps a real storage.Backend and injects failures on
// selected operations, letting tests exercise the non-ErrNotFound error
// propagation paths in Store without a mock framework.
type faultyBackend struct {
	storage.Backend
	failGet  bool
	failScan bool
}

func (f *faultyBackend) Get(ctx context.Context, key string) ([]byte, error) {
	if f.failGet {
		return nil, errFaultInjected
	}
	return f.Backend.Get(ctx, key)
}

func (f *faultyBackend) Scan(ctx context.Context, prefix string, fn func(key string, value []byte) error) error {
	if f.failScan {
		return errFaultInjected
	}
	return f.Backend.Scan(ctx, prefix, fn)
}

// newFaultyStore creates a Store backed by a faultyBackend so tests can
// force non-not-found errors out of the underlying DAO.
func newFaultyStore(t *testing.T, faulty *faultyBackend) *Store {
	t.Helper()
	kvStore, err := kvadapter.New(faulty)
	require.NoError(t, err)

	store, err := NewStore(kvStore)
	require.NoError(t, err)
	t.Cleanup(func() { store.Close() })

	return store
}

// TestErrCreation_Error verifies the wrapped-cause error message format.
func TestErrCreation_Error(t *testing.T) {
	cause := errors.New("boom")
	err := ErrCreation{Cause: cause}
	assert.Equal(t, "sealblobstore: failed to create DAO: boom", err.Error())
}

// TestErrCreation_Unwrap verifies errors.Is/As can reach the wrapped cause.
func TestErrCreation_Unwrap(t *testing.T) {
	cause := errors.New("root cause")
	err := ErrCreation{Cause: cause}
	assert.Equal(t, cause, err.Unwrap())
	assert.True(t, errors.Is(err, cause))
}

// TestStore_Load_NonNotFoundError verifies Load propagates a raw storage
// error, rather than translating it to ErrNotFound, when the underlying
// fault is unrelated to a missing entity.
func TestStore_Load_NonNotFoundError(t *testing.T) {
	backend := &faultyBackend{Backend: storage.NewMemory()}
	store := newFaultyStore(t, backend)

	// Save succeeds first (Get is not yet faulted).
	require.NoError(t, store.Save(context.Background(), testEntity("faulty-label")))

	backend.failGet = true
	loaded, err := store.Load(context.Background(), "faulty-label")
	require.Error(t, err)
	assert.False(t, errors.Is(err, ErrNotFound))
	assert.Nil(t, loaded)
}

// TestStore_Delete_NonNotFoundError verifies Delete propagates a raw storage
// error from the existence-check Get, rather than translating it to
// ErrNotFound.
func TestStore_Delete_NonNotFoundError(t *testing.T) {
	backend := &faultyBackend{Backend: storage.NewMemory()}
	store := newFaultyStore(t, backend)

	require.NoError(t, store.Save(context.Background(), testEntity("faulty-delete")))

	backend.failGet = true
	err := store.Delete(context.Background(), "faulty-delete")
	require.Error(t, err)
	assert.False(t, errors.Is(err, ErrNotFound))
}

// TestStore_List_ScanError verifies List propagates a raw storage error
// encountered while paging through entities.
func TestStore_List_ScanError(t *testing.T) {
	backend := &faultyBackend{Backend: storage.NewMemory()}
	store := newFaultyStore(t, backend)

	require.NoError(t, store.Save(context.Background(), testEntity("scan-fault")))

	backend.failScan = true
	entities, err := store.List(context.Background())
	require.Error(t, err)
	assert.Nil(t, entities)
}
