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

package services

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-qrdb/pkg/dao"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/kvadapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestSealedBlobDAOStore creates a SealedBlobDAOStore backed by in-memory storage.
func newTestSealedBlobDAOStore(t *testing.T) *SealedBlobDAOStore {
	t.Helper()
	backend := storage.NewMemory()
	t.Cleanup(func() { backend.Close() })

	kvStore, err := kvadapter.New(backend)
	require.NoError(t, err)

	store, err := NewSealedBlobDAOStore(kvStore)
	require.NoError(t, err)
	t.Cleanup(func() { store.Close() })

	return store
}

// testSealedBlobEntity creates a test SealedBlobEntity with the given label.
func testSealedBlobEntity(label string) *SealedBlobEntity {
	return &SealedBlobEntity{
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

func TestSealedBlobDAOStore_NewSealedBlobDAOStore_NilKVStore(t *testing.T) {
	store, err := NewSealedBlobDAOStore(nil)
	require.ErrorIs(t, err, ErrSealDAONilKVStore)
	assert.Nil(t, store)
}

func TestSealedBlobDAOStore_SaveLoad(t *testing.T) {
	store := newTestSealedBlobDAOStore(t)
	ctx := context.Background()

	entity := testSealedBlobEntity("my-secret")
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

func TestSealedBlobDAOStore_Save_NilEntity(t *testing.T) {
	store := newTestSealedBlobDAOStore(t)
	err := store.Save(context.Background(), nil)
	require.ErrorIs(t, err, ErrSealDAONilEntity)
}

func TestSealedBlobDAOStore_Save_EmptyLabel(t *testing.T) {
	store := newTestSealedBlobDAOStore(t)
	entity := testSealedBlobEntity("")
	err := store.Save(context.Background(), entity)
	require.ErrorIs(t, err, ErrSealDAOInvalidLabel)
}

func TestSealedBlobDAOStore_Save_Closed(t *testing.T) {
	store := newTestSealedBlobDAOStore(t)
	require.NoError(t, store.Close())

	err := store.Save(context.Background(), testSealedBlobEntity("test"))
	require.ErrorIs(t, err, ErrSealDAOStoreClosed)
}

func TestSealedBlobDAOStore_Save_SetsTimestamps(t *testing.T) {
	store := newTestSealedBlobDAOStore(t)
	ctx := context.Background()

	entity := &SealedBlobEntity{
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

func TestSealedBlobDAOStore_Delete(t *testing.T) {
	store := newTestSealedBlobDAOStore(t)
	ctx := context.Background()

	require.NoError(t, store.Save(ctx, testSealedBlobEntity("to-delete")))

	err := store.Delete(ctx, "to-delete")
	require.NoError(t, err)

	// Verify the blob is gone.
	loaded, err := store.Load(ctx, "to-delete")
	require.ErrorIs(t, err, ErrSealDAONotFound)
	assert.Nil(t, loaded)
}

func TestSealedBlobDAOStore_Delete_NotFound(t *testing.T) {
	store := newTestSealedBlobDAOStore(t)
	err := store.Delete(context.Background(), "nonexistent")
	require.ErrorIs(t, err, ErrSealDAONotFound)
}

func TestSealedBlobDAOStore_Delete_EmptyLabel(t *testing.T) {
	store := newTestSealedBlobDAOStore(t)
	err := store.Delete(context.Background(), "")
	require.ErrorIs(t, err, ErrSealDAOInvalidLabel)
}

func TestSealedBlobDAOStore_Delete_Closed(t *testing.T) {
	store := newTestSealedBlobDAOStore(t)
	require.NoError(t, store.Close())

	err := store.Delete(context.Background(), "test")
	require.ErrorIs(t, err, ErrSealDAOStoreClosed)
}

func TestSealedBlobDAOStore_List(t *testing.T) {
	store := newTestSealedBlobDAOStore(t)
	ctx := context.Background()

	e1 := testSealedBlobEntity("z-secret")
	e1.BackendID = "software"
	require.NoError(t, store.Save(ctx, e1))

	e2 := testSealedBlobEntity("a-secret")
	e2.BackendID = "tpm2"
	require.NoError(t, store.Save(ctx, e2))

	e3 := testSealedBlobEntity("m-secret")
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

func TestSealedBlobDAOStore_List_Empty(t *testing.T) {
	store := newTestSealedBlobDAOStore(t)

	entities, err := store.List(context.Background())
	require.NoError(t, err)
	assert.Empty(t, entities)
}

func TestSealedBlobDAOStore_List_Closed(t *testing.T) {
	store := newTestSealedBlobDAOStore(t)
	require.NoError(t, store.Close())

	entities, err := store.List(context.Background())
	require.ErrorIs(t, err, ErrSealDAOStoreClosed)
	assert.Nil(t, entities)
}

func TestSealedBlobDAOStore_Page(t *testing.T) {
	store := newTestSealedBlobDAOStore(t)
	ctx := context.Background()

	// Save 5 entries.
	for i := 0; i < 5; i++ {
		entity := testSealedBlobEntity(fmt.Sprintf("blob-%02d", i))
		require.NoError(t, store.Save(ctx, entity))
	}

	// Page with size 2.
	result, err := store.Page(ctx, dao.PageQuery{Page: 1, PageSize: 2})
	require.NoError(t, err)
	assert.Len(t, result.Entities, 2)
	assert.Equal(t, 5, result.Total)
	assert.True(t, result.HasMore)
	assert.Equal(t, 1, result.Page)
	assert.Equal(t, 2, result.PageSize)

	// Page 2.
	result2, err := store.Page(ctx, dao.PageQuery{Page: 2, PageSize: 2})
	require.NoError(t, err)
	assert.Len(t, result2.Entities, 2)
	assert.True(t, result2.HasMore)

	// Page 3 (last page with 1 entry).
	result3, err := store.Page(ctx, dao.PageQuery{Page: 3, PageSize: 2})
	require.NoError(t, err)
	assert.Len(t, result3.Entities, 1)
	assert.False(t, result3.HasMore)
}

func TestSealedBlobDAOStore_Page_Closed(t *testing.T) {
	store := newTestSealedBlobDAOStore(t)
	require.NoError(t, store.Close())

	_, err := store.Page(context.Background(), dao.PageQuery{Page: 1, PageSize: 10})
	require.ErrorIs(t, err, ErrSealDAOStoreClosed)
}

func TestSealedBlobDAOStore_DuplicateLabel(t *testing.T) {
	store := newTestSealedBlobDAOStore(t)
	ctx := context.Background()

	// Save initial entity.
	e1 := testSealedBlobEntity("my-secret")
	e1.SealedData = []byte("first-data")
	require.NoError(t, store.Save(ctx, e1))

	// Save again with the same label (should overwrite).
	e2 := testSealedBlobEntity("my-secret")
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

func TestSealedBlobDAOStore_NotFound(t *testing.T) {
	store := newTestSealedBlobDAOStore(t)

	loaded, err := store.Load(context.Background(), "nonexistent")
	require.ErrorIs(t, err, ErrSealDAONotFound)
	assert.Nil(t, loaded)
}

func TestSealedBlobDAOStore_Load_EmptyLabel(t *testing.T) {
	store := newTestSealedBlobDAOStore(t)

	loaded, err := store.Load(context.Background(), "")
	require.ErrorIs(t, err, ErrSealDAOInvalidLabel)
	assert.Nil(t, loaded)
}

func TestSealedBlobDAOStore_Load_Closed(t *testing.T) {
	store := newTestSealedBlobDAOStore(t)
	require.NoError(t, store.Close())

	loaded, err := store.Load(context.Background(), "test")
	require.ErrorIs(t, err, ErrSealDAOStoreClosed)
	assert.Nil(t, loaded)
}

func TestSealedBlobDAOStore_Close_Idempotent(t *testing.T) {
	store := newTestSealedBlobDAOStore(t)
	require.NoError(t, store.Close())
	require.NoError(t, store.Close())
	require.NoError(t, store.Close())
}

func TestSealedBlobDAOStore_Concurrency(t *testing.T) {
	store := newTestSealedBlobDAOStore(t)
	ctx := context.Background()

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines * 3)

	// Concurrent saves.
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			_ = store.Save(ctx, testSealedBlobEntity("concurrent-blob"))
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

func TestSealedBlobDAOStore_PCRBoundBlob(t *testing.T) {
	store := newTestSealedBlobDAOStore(t)
	ctx := context.Background()

	entity := testSealedBlobEntity("pcr-bound-secret")
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

func TestSealedBlobDAOStore_TimestampPreservation(t *testing.T) {
	store := newTestSealedBlobDAOStore(t)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Second)
	entity := &SealedBlobEntity{
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
