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
	"fmt"
	"sync"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/kvadapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestStore creates a Store backed by in-memory storage.
func newTestStore(t *testing.T) *Store {
	t.Helper()
	backend := storage.NewMemory()
	t.Cleanup(func() { backend.Close() })

	kvStore, err := kvadapter.New(backend)
	require.NoError(t, err)

	store, err := NewStore(kvStore)
	require.NoError(t, err)
	t.Cleanup(func() { store.Close() })

	return store
}

// testEntity creates a test Entity with the given label.
func testEntity(label string) *Entity {
	return &Entity{
		Label:       label,
		BackendID:   "tpm2",
		PolicyType:  "none",
		PolicyName:  "",
		StorageType: "disk",
		Category:    "user",
		SizeBytes:   256,
		PCRBound:    false,
		SealedData:  []byte(`{"ciphertext":"dGVzdA=="}`),
		CreatedAt:   time.Now().UTC().Truncate(time.Second),
	}
}

func TestStore_NewStore_NilKVStore(t *testing.T) {
	store, err := NewStore(nil)
	require.ErrorIs(t, err, ErrNilKVStore)
	assert.Nil(t, store)
}

func TestStore_SaveLoad(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	entity := testEntity("my-secret")
	require.NoError(t, store.Save(ctx, entity))

	loaded, err := store.Load(ctx, "my-secret")
	require.NoError(t, err)
	require.NotNil(t, loaded)

	assert.Equal(t, "my-secret", loaded.Label)
	assert.Equal(t, "tpm2", loaded.BackendID)
	assert.Equal(t, "none", loaded.PolicyType)
	assert.Equal(t, "disk", loaded.StorageType)
	assert.Equal(t, "user", loaded.Category)
	assert.Equal(t, 256, loaded.SizeBytes)
	assert.False(t, loaded.PCRBound)
	assert.Equal(t, entity.SealedData, loaded.SealedData)
}

func TestStore_Save_NilEntity(t *testing.T) {
	store := newTestStore(t)
	err := store.Save(context.Background(), nil)
	require.ErrorIs(t, err, ErrNilEntity)
}

func TestStore_Save_EmptyLabel(t *testing.T) {
	store := newTestStore(t)
	entity := testEntity("")
	err := store.Save(context.Background(), entity)
	require.ErrorIs(t, err, ErrInvalidLabel)
}

func TestStore_Save_Closed(t *testing.T) {
	store := newTestStore(t)
	require.NoError(t, store.Close())

	err := store.Save(context.Background(), testEntity("test"))
	require.ErrorIs(t, err, ErrStoreClosed)
}

func TestStore_Save_SetsTimestamps(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	entity := &Entity{
		Label:      "timestamp-test",
		BackendID:  "software",
		SealedData: []byte("test"),
	}
	require.NoError(t, store.Save(ctx, entity))

	loaded, err := store.Load(ctx, "timestamp-test")
	require.NoError(t, err)
	assert.False(t, loaded.CreatedAt.IsZero())
	assert.False(t, loaded.UpdatedAt.IsZero())
}

func TestStore_Delete(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	require.NoError(t, store.Save(ctx, testEntity("to-delete")))

	err := store.Delete(ctx, "to-delete")
	require.NoError(t, err)

	// Verify the blob is gone.
	loaded, err := store.Load(ctx, "to-delete")
	require.ErrorIs(t, err, ErrNotFound)
	assert.Nil(t, loaded)
}

func TestStore_Delete_NotFound(t *testing.T) {
	store := newTestStore(t)
	err := store.Delete(context.Background(), "nonexistent")
	require.ErrorIs(t, err, ErrNotFound)
}

func TestStore_Delete_EmptyLabel(t *testing.T) {
	store := newTestStore(t)
	err := store.Delete(context.Background(), "")
	require.ErrorIs(t, err, ErrInvalidLabel)
}

func TestStore_Delete_Closed(t *testing.T) {
	store := newTestStore(t)
	require.NoError(t, store.Close())

	err := store.Delete(context.Background(), "test")
	require.ErrorIs(t, err, ErrStoreClosed)
}

func TestStore_List(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	e1 := testEntity("z-secret")
	e1.BackendID = "software"
	require.NoError(t, store.Save(ctx, e1))

	e2 := testEntity("a-secret")
	e2.BackendID = "tpm2"
	require.NoError(t, store.Save(ctx, e2))

	e3 := testEntity("m-secret")
	e3.BackendID = "tpm2"
	require.NoError(t, store.Save(ctx, e3))

	entities, err := store.List(ctx)
	require.NoError(t, err)
	require.Len(t, entities, 3)

	// Entities should be sorted by label.
	assert.Equal(t, "a-secret", entities[0].Label)
	assert.Equal(t, "m-secret", entities[1].Label)
	assert.Equal(t, "z-secret", entities[2].Label)
}

func TestStore_List_Empty(t *testing.T) {
	store := newTestStore(t)

	entities, err := store.List(context.Background())
	require.NoError(t, err)
	assert.Empty(t, entities)
}

func TestStore_List_Closed(t *testing.T) {
	store := newTestStore(t)
	require.NoError(t, store.Close())

	entities, err := store.List(context.Background())
	require.ErrorIs(t, err, ErrStoreClosed)
	assert.Nil(t, entities)
}

func TestStore_Page(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	// Save 5 entries.
	for i := 0; i < 5; i++ {
		entity := testEntity(fmt.Sprintf("blob-%02d", i))
		require.NoError(t, store.Save(ctx, entity))
	}

	// Page with size 2.
	result, err := store.Page(ctx, qrdbsdk.PageQuery{Page: 1, PageSize: 2})
	require.NoError(t, err)
	assert.Len(t, result.Entities, 2)
	assert.Equal(t, 5, result.Total)
	assert.True(t, result.HasMore)
	assert.Equal(t, 1, result.Page)
	assert.Equal(t, 2, result.PageSize)

	// Page 2.
	result2, err := store.Page(ctx, qrdbsdk.PageQuery{Page: 2, PageSize: 2})
	require.NoError(t, err)
	assert.Len(t, result2.Entities, 2)
	assert.True(t, result2.HasMore)

	// Page 3 (last page with 1 entry).
	result3, err := store.Page(ctx, qrdbsdk.PageQuery{Page: 3, PageSize: 2})
	require.NoError(t, err)
	assert.Len(t, result3.Entities, 1)
	assert.False(t, result3.HasMore)
}

func TestStore_Page_Closed(t *testing.T) {
	store := newTestStore(t)
	require.NoError(t, store.Close())

	_, err := store.Page(context.Background(), qrdbsdk.PageQuery{Page: 1, PageSize: 10})
	require.ErrorIs(t, err, ErrStoreClosed)
}

func TestStore_DuplicateLabel(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	// Save initial entity.
	e1 := testEntity("my-secret")
	e1.SealedData = []byte("first-data")
	require.NoError(t, store.Save(ctx, e1))

	// Save again with the same label (should overwrite).
	e2 := testEntity("my-secret")
	e2.SealedData = []byte("second-data")
	require.NoError(t, store.Save(ctx, e2))

	// Load should return the latest.
	loaded, err := store.Load(ctx, "my-secret")
	require.NoError(t, err)
	assert.Equal(t, []byte("second-data"), loaded.SealedData)

	// List should show only one entry.
	entities, err := store.List(ctx)
	require.NoError(t, err)
	assert.Len(t, entities, 1)
}

func TestStore_NotFound(t *testing.T) {
	store := newTestStore(t)

	loaded, err := store.Load(context.Background(), "nonexistent")
	require.ErrorIs(t, err, ErrNotFound)
	assert.Nil(t, loaded)
}

func TestStore_Load_EmptyLabel(t *testing.T) {
	store := newTestStore(t)

	loaded, err := store.Load(context.Background(), "")
	require.ErrorIs(t, err, ErrInvalidLabel)
	assert.Nil(t, loaded)
}

func TestStore_Load_Closed(t *testing.T) {
	store := newTestStore(t)
	require.NoError(t, store.Close())

	loaded, err := store.Load(context.Background(), "test")
	require.ErrorIs(t, err, ErrStoreClosed)
	assert.Nil(t, loaded)
}

func TestStore_Close_Idempotent(t *testing.T) {
	store := newTestStore(t)
	require.NoError(t, store.Close())
	require.NoError(t, store.Close())
	require.NoError(t, store.Close())
}

func TestStore_Concurrency(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines * 3)

	// Concurrent saves.
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			_ = store.Save(ctx, testEntity("concurrent-blob"))
		}()
	}

	// Concurrent loads.
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			_, _ = store.Load(ctx, "concurrent-blob")
		}()
	}

	// Concurrent lists.
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			_, _ = store.List(ctx)
		}()
	}

	wg.Wait()

	// After all goroutines complete, the store should be consistent.
	loaded, err := store.Load(ctx, "concurrent-blob")
	require.NoError(t, err)
	assert.NotEmpty(t, loaded.SealedData)
}

func TestStore_PCRBoundBlob(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	entity := testEntity("pcr-bound-secret")
	entity.PCRBound = true
	entity.PolicyType = "platform_policy"
	entity.BackendID = "tpm2"
	require.NoError(t, store.Save(ctx, entity))

	loaded, err := store.Load(ctx, "pcr-bound-secret")
	require.NoError(t, err)
	assert.True(t, loaded.PCRBound)
	assert.Equal(t, "platform_policy", loaded.PolicyType)
	assert.Equal(t, "tpm2", loaded.BackendID)
}

func TestStore_TimestampPreservation(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Second)
	entity := &Entity{
		Label:      "ts-test",
		BackendID:  "software",
		SealedData: []byte("data"),
		CreatedAt:  now,
	}
	require.NoError(t, store.Save(ctx, entity))

	loaded, err := store.Load(ctx, "ts-test")
	require.NoError(t, err)

	// CreatedAt should be preserved through serialization.
	assert.WithinDuration(t, now, loaded.CreatedAt, time.Second)
	// UpdatedAt should be set automatically.
	assert.False(t, loaded.UpdatedAt.IsZero())
}
