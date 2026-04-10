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

package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewBackendStore(t *testing.T) {

	t.Run("with explicit max size", func(t *testing.T) {
		backend := storage.NewMemory()
		store, err := NewBackendStore(backend, 500, nil)
		require.NoError(t, err)
		require.NotNil(t, store)
		assert.Equal(t, 500, store.maxSize)
		assert.Equal(t, 0, store.Count())
	})

	t.Run("zero max size defaults to 10000", func(t *testing.T) {
		backend := storage.NewMemory()
		store, err := NewBackendStore(backend, 0, nil)
		require.NoError(t, err)
		require.NotNil(t, store)
		assert.Equal(t, defaultMaxSize, store.maxSize)
	})

	t.Run("negative max size defaults to 10000", func(t *testing.T) {
		backend := storage.NewMemory()
		store, err := NewBackendStore(backend, -5, nil)
		require.NoError(t, err)
		require.NotNil(t, store)
		assert.Equal(t, defaultMaxSize, store.maxSize)
	})

	t.Run("cache slice is initialized", func(t *testing.T) {
		backend := storage.NewMemory()
		store, err := NewBackendStore(backend, 100, nil)
		require.NoError(t, err)
		require.NotNil(t, store)
		assert.NotNil(t, store.cache)
		assert.Equal(t, 0, len(store.cache))
		assert.Equal(t, 100, cap(store.cache))
	})

	t.Run("prefix is set correctly", func(t *testing.T) {
		backend := storage.NewMemory()
		store, err := NewBackendStore(backend, 100, nil)
		require.NoError(t, err)
		assert.Equal(t, "audit/", store.prefix)
	})
}

func TestNewBackendStore_NilBackend(t *testing.T) {

	t.Run("returns error for nil backend", func(t *testing.T) {
		store, err := NewBackendStore(nil, 100, nil)
		require.Error(t, err)
		assert.Nil(t, store)
		assert.ErrorIs(t, err, ErrNilBackend)
	})

	t.Run("returns error for nil backend with logger", func(t *testing.T) {
		var buf bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&buf, nil))
		store, err := NewBackendStore(nil, 100, logger)
		require.Error(t, err)
		assert.Nil(t, store)
		assert.ErrorIs(t, err, ErrNilBackend)
	})
}

func TestBackendStore_Log(t *testing.T) {

	t.Run("entries are stored in cache and backend", func(t *testing.T) {
		backend := storage.NewMemory()
		store, err := NewBackendStore(backend, 100, nil)
		require.NoError(t, err)

		entry := Entry{
			Timestamp: time.Now(),
			Operation: OpKeyCreated,
			Backend:   "tpm2",
			KeyID:     "key-1",
			Success:   true,
		}
		store.Log(entry)

		assert.Equal(t, 1, store.Count())

		results := store.Query(QueryFilter{})
		require.Len(t, results, 1)
		assert.Equal(t, OpKeyCreated, results[0].Operation)
		assert.Equal(t, "tpm2", results[0].Backend)
		assert.Equal(t, "key-1", results[0].KeyID)
		assert.True(t, results[0].Success)

		// Verify the entry was persisted to the backend.
		keys, listErr := backend.List(context.Background(), "audit/")
		require.NoError(t, listErr)
		require.Len(t, keys, 1)

		data, getErr := backend.Get(context.Background(), keys[0])
		require.NoError(t, getErr)

		var persisted Entry
		require.NoError(t, json.Unmarshal(data, &persisted))
		assert.Equal(t, OpKeyCreated, persisted.Operation)
		assert.Equal(t, "key-1", persisted.KeyID)
	})

	t.Run("multiple entries are stored in order", func(t *testing.T) {
		backend := storage.NewMemory()
		store, err := NewBackendStore(backend, 100, nil)
		require.NoError(t, err)

		for i := 0; i < 5; i++ {
			store.Log(Entry{
				Timestamp: time.Now(),
				Operation: OpKeyCreated,
				KeyID:     fmt.Sprintf("key-%d", i),
				Success:   true,
			})
		}

		assert.Equal(t, 5, store.Count())
		results := store.Query(QueryFilter{})
		require.Len(t, results, 5)
		for i := 0; i < 5; i++ {
			assert.Equal(t, fmt.Sprintf("key-%d", i), results[i].KeyID)
		}

		// Verify all 5 entries are in the backend.
		keys, listErr := backend.List(context.Background(), "audit/")
		require.NoError(t, listErr)
		assert.Len(t, keys, 5)
	})
}

func TestBackendStore_LogPersistence(t *testing.T) {

	t.Run("entries survive store recreation", func(t *testing.T) {
		backend := storage.NewMemory()

		// Create first store and log entries.
		store1, err := NewBackendStore(backend, 100, nil)
		require.NoError(t, err)

		store1.Log(Entry{
			Timestamp: time.Date(2025, 3, 8, 10, 0, 0, 0, time.UTC),
			Operation: OpKeyCreated,
			Backend:   "tpm2",
			KeyID:     "persistent-key-1",
			Success:   true,
		})
		store1.Log(Entry{
			Timestamp: time.Date(2025, 3, 8, 11, 0, 0, 0, time.UTC),
			Operation: OpSignRequest,
			Backend:   "software",
			KeyID:     "persistent-key-2",
			Success:   true,
		})

		assert.Equal(t, 2, store1.Count())

		// Create second store with the same backend.
		store2, err := NewBackendStore(backend, 100, nil)
		require.NoError(t, err)

		assert.Equal(t, 2, store2.Count())

		results := store2.Query(QueryFilter{})
		require.Len(t, results, 2)
		assert.Equal(t, "persistent-key-1", results[0].KeyID)
		assert.Equal(t, "persistent-key-2", results[1].KeyID)
	})

	t.Run("loaded entries maintain correct operations", func(t *testing.T) {
		backend := storage.NewMemory()

		store1, err := NewBackendStore(backend, 100, nil)
		require.NoError(t, err)

		store1.Log(Entry{
			Timestamp:  time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
			Operation:  OpSignRequest,
			Backend:    "tpm2",
			KeyID:      "sign-key",
			Success:    false,
			Error:      "device locked",
			DurationMs: 42,
		})

		store2, err := NewBackendStore(backend, 100, nil)
		require.NoError(t, err)

		results := store2.Query(QueryFilter{})
		require.Len(t, results, 1)
		assert.Equal(t, OpSignRequest, results[0].Operation)
		assert.Equal(t, "tpm2", results[0].Backend)
		assert.Equal(t, "sign-key", results[0].KeyID)
		assert.False(t, results[0].Success)
		assert.Equal(t, "device locked", results[0].Error)
		assert.Equal(t, int64(42), results[0].DurationMs)
	})
}

func TestBackendStore_Query_ByOperation(t *testing.T) {

	backend := storage.NewMemory()
	store, err := NewBackendStore(backend, 100, nil)
	require.NoError(t, err)

	store.Log(Entry{Timestamp: time.Now(), Operation: OpKeyCreated, KeyID: "k1", Success: true})
	store.Log(Entry{Timestamp: time.Now(), Operation: OpSignRequest, KeyID: "k2", Success: true})
	store.Log(Entry{Timestamp: time.Now(), Operation: OpKeyCreated, KeyID: "k3", Success: true})
	store.Log(Entry{Timestamp: time.Now(), Operation: OpDecryptRequest, KeyID: "k4", Success: false})

	t.Run("filter key_created returns 2", func(t *testing.T) {
		results := store.Query(QueryFilter{Operation: OpKeyCreated})
		require.Len(t, results, 2)
		assert.Equal(t, "k1", results[0].KeyID)
		assert.Equal(t, "k3", results[1].KeyID)
	})

	t.Run("filter sign_request returns 1", func(t *testing.T) {
		results := store.Query(QueryFilter{Operation: OpSignRequest})
		require.Len(t, results, 1)
		assert.Equal(t, "k2", results[0].KeyID)
	})

	t.Run("filter decrypt_request returns 1", func(t *testing.T) {
		results := store.Query(QueryFilter{Operation: OpDecryptRequest})
		require.Len(t, results, 1)
		assert.Equal(t, "k4", results[0].KeyID)
	})
}

func TestBackendStore_Query_ByBackend(t *testing.T) {

	backend := storage.NewMemory()
	store, err := NewBackendStore(backend, 100, nil)
	require.NoError(t, err)

	store.Log(Entry{Timestamp: time.Now(), Operation: OpKeyCreated, Backend: "tpm2", KeyID: "k1", Success: true})
	store.Log(Entry{Timestamp: time.Now(), Operation: OpSignRequest, Backend: "software", KeyID: "k2", Success: true})
	store.Log(Entry{Timestamp: time.Now(), Operation: OpKeyDeleted, Backend: "tpm2", KeyID: "k3", Success: true})
	store.Log(Entry{Timestamp: time.Now(), Operation: OpEncryptRequest, Backend: "phone", KeyID: "k4", Success: true})

	t.Run("filter tpm2 returns 2", func(t *testing.T) {
		results := store.Query(QueryFilter{Backend: "tpm2"})
		require.Len(t, results, 2)
		assert.Equal(t, "k1", results[0].KeyID)
		assert.Equal(t, "k3", results[1].KeyID)
	})

	t.Run("filter software returns 1", func(t *testing.T) {
		results := store.Query(QueryFilter{Backend: "software"})
		require.Len(t, results, 1)
		assert.Equal(t, "k2", results[0].KeyID)
	})

	t.Run("filter phone returns 1", func(t *testing.T) {
		results := store.Query(QueryFilter{Backend: "phone"})
		require.Len(t, results, 1)
		assert.Equal(t, "k4", results[0].KeyID)
	})
}

func TestBackendStore_Query_BySuccess(t *testing.T) {

	backend := storage.NewMemory()
	store, err := NewBackendStore(backend, 100, nil)
	require.NoError(t, err)

	store.Log(Entry{Timestamp: time.Now(), Operation: OpSignRequest, KeyID: "k1", Success: true})
	store.Log(Entry{Timestamp: time.Now(), Operation: OpSignRequest, KeyID: "k2", Success: false})
	store.Log(Entry{Timestamp: time.Now(), Operation: OpDecryptRequest, KeyID: "k3", Success: true})
	store.Log(Entry{Timestamp: time.Now(), Operation: OpEncryptRequest, KeyID: "k4", Success: false})

	t.Run("filter success=true returns 2", func(t *testing.T) {
		trueVal := true
		results := store.Query(QueryFilter{Success: &trueVal})
		require.Len(t, results, 2)
		assert.Equal(t, "k1", results[0].KeyID)
		assert.Equal(t, "k3", results[1].KeyID)
	})

	t.Run("filter success=false returns 2", func(t *testing.T) {
		falseVal := false
		results := store.Query(QueryFilter{Success: &falseVal})
		require.Len(t, results, 2)
		assert.Equal(t, "k2", results[0].KeyID)
		assert.Equal(t, "k4", results[1].KeyID)
	})

	t.Run("filter success=nil returns all", func(t *testing.T) {
		results := store.Query(QueryFilter{})
		require.Len(t, results, 4)
	})
}

func TestBackendStore_Query_TimeRange(t *testing.T) {

	backend := storage.NewMemory()
	store, err := NewBackendStore(backend, 100, nil)
	require.NoError(t, err)

	now := time.Now()

	store.Log(Entry{Timestamp: now.Add(-3 * time.Hour), Operation: OpKeyCreated, KeyID: "old", Success: true})
	store.Log(Entry{Timestamp: now.Add(-1 * time.Hour), Operation: OpSignRequest, KeyID: "mid", Success: true})
	store.Log(Entry{Timestamp: now, Operation: OpKeyDeleted, KeyID: "new", Success: true})

	t.Run("since filters out older entries", func(t *testing.T) {
		results := store.Query(QueryFilter{Since: now.Add(-2 * time.Hour)})
		require.Len(t, results, 2)
		assert.Equal(t, "mid", results[0].KeyID)
		assert.Equal(t, "new", results[1].KeyID)
	})

	t.Run("until filters out newer entries", func(t *testing.T) {
		results := store.Query(QueryFilter{Until: now.Add(-30 * time.Minute)})
		require.Len(t, results, 2)
		assert.Equal(t, "old", results[0].KeyID)
		assert.Equal(t, "mid", results[1].KeyID)
	})

	t.Run("since and until together define a window", func(t *testing.T) {
		results := store.Query(QueryFilter{
			Since: now.Add(-2 * time.Hour),
			Until: now.Add(-30 * time.Minute),
		})
		require.Len(t, results, 1)
		assert.Equal(t, "mid", results[0].KeyID)
	})

	t.Run("zero time values are ignored", func(t *testing.T) {
		results := store.Query(QueryFilter{})
		require.Len(t, results, 3)
	})
}

func TestBackendStore_Query_LimitOffset(t *testing.T) {

	backend := storage.NewMemory()
	store, err := NewBackendStore(backend, 100, nil)
	require.NoError(t, err)

	for i := 0; i < 10; i++ {
		store.Log(Entry{
			Timestamp: time.Now(),
			Operation: OpKeyCreated,
			KeyID:     fmt.Sprintf("key-%d", i),
			Success:   true,
		})
	}

	t.Run("limit restricts result count", func(t *testing.T) {
		results := store.Query(QueryFilter{Limit: 3})
		require.Len(t, results, 3)
		assert.Equal(t, "key-0", results[0].KeyID)
		assert.Equal(t, "key-1", results[1].KeyID)
		assert.Equal(t, "key-2", results[2].KeyID)
	})

	t.Run("offset skips entries", func(t *testing.T) {
		results := store.Query(QueryFilter{Offset: 7})
		require.Len(t, results, 3)
		assert.Equal(t, "key-7", results[0].KeyID)
		assert.Equal(t, "key-8", results[1].KeyID)
		assert.Equal(t, "key-9", results[2].KeyID)
	})

	t.Run("limit and offset together paginate", func(t *testing.T) {
		results := store.Query(QueryFilter{Offset: 2, Limit: 3})
		require.Len(t, results, 3)
		assert.Equal(t, "key-2", results[0].KeyID)
		assert.Equal(t, "key-3", results[1].KeyID)
		assert.Equal(t, "key-4", results[2].KeyID)
	})

	t.Run("offset beyond count returns empty", func(t *testing.T) {
		results := store.Query(QueryFilter{Offset: 20})
		assert.Empty(t, results)
	})

	t.Run("limit larger than available returns all available", func(t *testing.T) {
		results := store.Query(QueryFilter{Limit: 50})
		require.Len(t, results, 10)
	})

	t.Run("limit zero means unlimited", func(t *testing.T) {
		results := store.Query(QueryFilter{Limit: 0})
		require.Len(t, results, 10)
	})
}

func TestBackendStore_Query_NoMatch(t *testing.T) {

	backend := storage.NewMemory()
	store, err := NewBackendStore(backend, 100, nil)
	require.NoError(t, err)

	store.Log(Entry{Timestamp: time.Now(), Operation: OpKeyCreated, Backend: "tpm2", KeyID: "k1", Success: true})
	store.Log(Entry{Timestamp: time.Now(), Operation: OpSignRequest, Backend: "software", KeyID: "k2", Success: true})

	t.Run("non-existent operation returns empty", func(t *testing.T) {
		results := store.Query(QueryFilter{Operation: OpPolicyDenied})
		assert.Empty(t, results)
	})

	t.Run("non-existent backend returns empty", func(t *testing.T) {
		results := store.Query(QueryFilter{Backend: "nonexistent"})
		assert.Empty(t, results)
	})

	t.Run("non-existent key ID returns empty", func(t *testing.T) {
		results := store.Query(QueryFilter{KeyID: "no-such-key"})
		assert.Empty(t, results)
	})

	t.Run("non-existent device ID returns empty", func(t *testing.T) {
		results := store.Query(QueryFilter{DeviceID: "no-such-device"})
		assert.Empty(t, results)
	})

	t.Run("empty store returns empty", func(t *testing.T) {
		emptyBackend := storage.NewMemory()
		emptyStore, storeErr := NewBackendStore(emptyBackend, 100, nil)
		require.NoError(t, storeErr)
		results := emptyStore.Query(QueryFilter{})
		assert.Empty(t, results)
	})
}

func TestBackendStore_Query_CombinedFilters(t *testing.T) {

	backend := storage.NewMemory()
	store, err := NewBackendStore(backend, 100, nil)
	require.NoError(t, err)

	store.LogKeyOperation(OpKeyCreated, "tpm2", "k1", true, nil, 100)
	store.LogKeyOperation(OpKeyCreated, "software", "k2", true, nil, 50)
	store.LogKeyOperation(OpKeyDeleted, "tpm2", "k3", false, errors.New("not found"), 10)
	store.LogCryptoOperation(OpSignRequest, "tpm2", "k4", "d1", "Phone", true, nil, 200)

	t.Run("operation and backend", func(t *testing.T) {
		results := store.Query(QueryFilter{
			Operation: OpKeyCreated,
			Backend:   "tpm2",
		})
		require.Len(t, results, 1)
		assert.Equal(t, "k1", results[0].KeyID)
	})

	t.Run("backend and success", func(t *testing.T) {
		falseVal := false
		results := store.Query(QueryFilter{
			Backend: "tpm2",
			Success: &falseVal,
		})
		require.Len(t, results, 1)
		assert.Equal(t, "k3", results[0].KeyID)
	})
}

func TestBackendStore_RingBufferEviction(t *testing.T) {

	t.Run("evicts oldest entries when full", func(t *testing.T) {
		backend := storage.NewMemory()
		store, err := NewBackendStore(backend, 3, nil)
		require.NoError(t, err)

		for i := 0; i < 5; i++ {
			store.Log(Entry{
				Timestamp: time.Now(),
				Operation: OpKeyCreated,
				KeyID:     fmt.Sprintf("key-%d", i),
				Success:   true,
			})
		}

		assert.Equal(t, 3, store.Count())

		results := store.Query(QueryFilter{})
		require.Len(t, results, 3)
		assert.Equal(t, "key-2", results[0].KeyID)
		assert.Equal(t, "key-3", results[1].KeyID)
		assert.Equal(t, "key-4", results[2].KeyID)

		// Backend still has all 5 entries persisted.
		keys, listErr := backend.List(context.Background(), "audit/")
		require.NoError(t, listErr)
		assert.Len(t, keys, 5)
	})

	t.Run("max size of 1 keeps only latest in cache", func(t *testing.T) {
		backend := storage.NewMemory()
		store, err := NewBackendStore(backend, 1, nil)
		require.NoError(t, err)

		store.Log(Entry{Timestamp: time.Now(), Operation: OpKeyCreated, KeyID: "first", Success: true})
		store.Log(Entry{Timestamp: time.Now(), Operation: OpKeyDeleted, KeyID: "second", Success: true})

		assert.Equal(t, 1, store.Count())
		results := store.Query(QueryFilter{})
		require.Len(t, results, 1)
		assert.Equal(t, "second", results[0].KeyID)
	})

	t.Run("loadFromBackend respects maxSize", func(t *testing.T) {
		backend := storage.NewMemory()

		// Create a store with large buffer and log 10 entries.
		store1, err := NewBackendStore(backend, 100, nil)
		require.NoError(t, err)

		for i := 0; i < 10; i++ {
			store1.Log(Entry{
				Timestamp: time.Date(2025, 1, 1, i, 0, 0, 0, time.UTC),
				Operation: OpKeyCreated,
				KeyID:     fmt.Sprintf("key-%d", i),
				Success:   true,
			})
		}

		// Create a new store with maxSize=3, loading from same backend.
		store2, err := NewBackendStore(backend, 3, nil)
		require.NoError(t, err)

		assert.Equal(t, 3, store2.Count())
		results := store2.Query(QueryFilter{})
		require.Len(t, results, 3)
		// Should have the 3 most recent entries.
		assert.Equal(t, "key-7", results[0].KeyID)
		assert.Equal(t, "key-8", results[1].KeyID)
		assert.Equal(t, "key-9", results[2].KeyID)
	})
}

func TestBackendStore_MigrateBackend(t *testing.T) {

	t.Run("migrates all entries to new backend", func(t *testing.T) {
		oldBackend := storage.NewMemory()
		store, err := NewBackendStore(oldBackend, 100, nil)
		require.NoError(t, err)

		store.Log(Entry{
			Timestamp: time.Date(2025, 3, 8, 10, 0, 0, 0, time.UTC),
			Operation: OpKeyCreated,
			Backend:   "tpm2",
			KeyID:     "migrate-key-1",
			Success:   true,
		})
		store.Log(Entry{
			Timestamp: time.Date(2025, 3, 8, 11, 0, 0, 0, time.UTC),
			Operation: OpSignRequest,
			Backend:   "software",
			KeyID:     "migrate-key-2",
			Success:   true,
		})

		newBackend := storage.NewMemory()
		require.NoError(t, store.MigrateBackend(newBackend))

		// Verify entries exist in the new backend.
		keys, listErr := newBackend.List(context.Background(), "audit/")
		require.NoError(t, listErr)
		assert.Len(t, keys, 2)

		// Verify the cache is still intact.
		assert.Equal(t, 2, store.Count())
		results := store.Query(QueryFilter{})
		require.Len(t, results, 2)
		assert.Equal(t, "migrate-key-1", results[0].KeyID)
		assert.Equal(t, "migrate-key-2", results[1].KeyID)

		// Verify new entries go to the new backend.
		store.Log(Entry{
			Timestamp: time.Date(2025, 3, 8, 12, 0, 0, 0, time.UTC),
			Operation: OpKeyDeleted,
			KeyID:     "migrate-key-3",
			Success:   true,
		})

		newKeys, newListErr := newBackend.List(context.Background(), "audit/")
		require.NoError(t, newListErr)
		assert.Len(t, newKeys, 3)
	})

	t.Run("old backend is no longer written to after migration", func(t *testing.T) {
		oldBackend := storage.NewMemory()
		store, err := NewBackendStore(oldBackend, 100, nil)
		require.NoError(t, err)

		store.Log(Entry{
			Timestamp: time.Now(),
			Operation: OpKeyCreated,
			KeyID:     "pre-migrate",
			Success:   true,
		})

		oldKeys, listErr := oldBackend.List(context.Background(), "audit/")
		require.NoError(t, listErr)
		oldCount := len(oldKeys)

		newBackend := storage.NewMemory()
		require.NoError(t, store.MigrateBackend(newBackend))

		// Log after migration.
		store.Log(Entry{
			Timestamp: time.Now(),
			Operation: OpSignRequest,
			KeyID:     "post-migrate",
			Success:   true,
		})

		// Old backend should not have the new entry.
		oldKeysAfter, listErr2 := oldBackend.List(context.Background(), "audit/")
		require.NoError(t, listErr2)
		assert.Equal(t, oldCount, len(oldKeysAfter))
	})
}

func TestBackendStore_MigrateBackend_NilBackend(t *testing.T) {

	t.Run("returns error for nil new backend", func(t *testing.T) {
		backend := storage.NewMemory()
		store, err := NewBackendStore(backend, 100, nil)
		require.NoError(t, err)

		migrateErr := store.MigrateBackend(nil)
		require.Error(t, migrateErr)
		assert.ErrorIs(t, migrateErr, ErrNilBackend)
	})

	t.Run("store remains usable after nil migration attempt", func(t *testing.T) {
		backend := storage.NewMemory()
		store, err := NewBackendStore(backend, 100, nil)
		require.NoError(t, err)

		store.Log(Entry{Timestamp: time.Now(), Operation: OpKeyCreated, KeyID: "before", Success: true})

		migrateErr := store.MigrateBackend(nil)
		require.Error(t, migrateErr)

		// Store should still work.
		store.Log(Entry{Timestamp: time.Now(), Operation: OpSignRequest, KeyID: "after", Success: true})
		assert.Equal(t, 2, store.Count())
	})
}

func TestBackendStore_Count(t *testing.T) {

	t.Run("empty store returns 0", func(t *testing.T) {
		backend := storage.NewMemory()
		store, err := NewBackendStore(backend, 100, nil)
		require.NoError(t, err)
		assert.Equal(t, 0, store.Count())
	})

	t.Run("count increments with each log", func(t *testing.T) {
		backend := storage.NewMemory()
		store, err := NewBackendStore(backend, 100, nil)
		require.NoError(t, err)

		for i := 1; i <= 5; i++ {
			store.Log(Entry{Timestamp: time.Now(), Operation: OpKeyCreated, Success: true})
			assert.Equal(t, i, store.Count())
		}
	})

	t.Run("count does not exceed max size", func(t *testing.T) {
		backend := storage.NewMemory()
		store, err := NewBackendStore(backend, 3, nil)
		require.NoError(t, err)

		for i := 0; i < 10; i++ {
			store.Log(Entry{Timestamp: time.Now(), Operation: OpKeyCreated, Success: true})
		}
		assert.Equal(t, 3, store.Count())
	})
}

func TestBackendStore_AllLogMethods(t *testing.T) {

	t.Run("LogKeyOperation", func(t *testing.T) {
		backend := storage.NewMemory()
		store, err := NewBackendStore(backend, 100, nil)
		require.NoError(t, err)

		store.LogKeyOperation(OpKeyCreated, "tpm2", "key-abc", true, nil, 250)

		require.Equal(t, 1, store.Count())
		results := store.Query(QueryFilter{})
		require.Len(t, results, 1)

		entry := results[0]
		assert.Equal(t, OpKeyCreated, entry.Operation)
		assert.Equal(t, "tpm2", entry.Backend)
		assert.Equal(t, "key-abc", entry.KeyID)
		assert.True(t, entry.Success)
		assert.Empty(t, entry.Error)
		assert.Equal(t, int64(250), entry.DurationMs)
		assert.False(t, entry.Timestamp.IsZero())
	})

	t.Run("LogKeyOperation with error", func(t *testing.T) {
		backend := storage.NewMemory()
		store, err := NewBackendStore(backend, 100, nil)
		require.NoError(t, err)

		testErr := errors.New("key not found")
		store.LogKeyOperation(OpKeyDeleted, "software", "key-xyz", false, testErr, 10)

		results := store.Query(QueryFilter{})
		require.Len(t, results, 1)
		assert.Equal(t, "key not found", results[0].Error)
		assert.False(t, results[0].Success)
	})

	t.Run("LogCryptoOperation", func(t *testing.T) {
		backend := storage.NewMemory()
		store, err := NewBackendStore(backend, 100, nil)
		require.NoError(t, err)

		store.LogCryptoOperation(OpSignRequest, "tpm2", "sign-key", "device-1", "Pixel 8", true, nil, 120)

		results := store.Query(QueryFilter{})
		require.Len(t, results, 1)

		entry := results[0]
		assert.Equal(t, OpSignRequest, entry.Operation)
		assert.Equal(t, "device-1", entry.DeviceID)
		assert.Equal(t, "Pixel 8", entry.DeviceName)
		assert.True(t, entry.Success)
		assert.Equal(t, int64(120), entry.DurationMs)
	})

	t.Run("LogCryptoOperation with error", func(t *testing.T) {
		backend := storage.NewMemory()
		store, err := NewBackendStore(backend, 100, nil)
		require.NoError(t, err)

		testErr := errors.New("invalid ciphertext")
		store.LogCryptoOperation(OpDecryptRequest, "software", "dec-key", "device-2", "Galaxy S24", false, testErr, 50)

		results := store.Query(QueryFilter{})
		require.Len(t, results, 1)
		assert.Equal(t, "invalid ciphertext", results[0].Error)
		assert.False(t, results[0].Success)
	})

	t.Run("LogConnectionEvent with details", func(t *testing.T) {
		backend := storage.NewMemory()
		store, err := NewBackendStore(backend, 100, nil)
		require.NoError(t, err)

		details := map[string]any{"protocol": "BLE", "mtu": 247}
		store.LogConnectionEvent(OpConnectionEstablished, "device-abc", "Pixel 8 Pro", details)

		results := store.Query(QueryFilter{})
		require.Len(t, results, 1)

		entry := results[0]
		assert.Equal(t, OpConnectionEstablished, entry.Operation)
		assert.Equal(t, "device-abc", entry.DeviceID)
		assert.Equal(t, "Pixel 8 Pro", entry.DeviceName)
		assert.True(t, entry.Success)
	})

	t.Run("LogConnectionEvent without details", func(t *testing.T) {
		backend := storage.NewMemory()
		store, err := NewBackendStore(backend, 100, nil)
		require.NoError(t, err)

		store.LogConnectionEvent(OpConnectionClosed, "device-xyz", "Galaxy S24", nil)

		results := store.Query(QueryFilter{})
		require.Len(t, results, 1)
		assert.Equal(t, OpConnectionClosed, results[0].Operation)
		assert.True(t, results[0].Success)
		assert.Nil(t, results[0].Details)
	})

	t.Run("LogServiceEvent with details", func(t *testing.T) {
		backend := storage.NewMemory()
		store, err := NewBackendStore(backend, 100, nil)
		require.NoError(t, err)

		details := map[string]any{"version": "1.0.0", "pid": 12345}
		store.LogServiceEvent(OpServiceStarted, details)

		results := store.Query(QueryFilter{})
		require.Len(t, results, 1)
		assert.Equal(t, OpServiceStarted, results[0].Operation)
		assert.True(t, results[0].Success)
	})

	t.Run("LogServiceEvent without details", func(t *testing.T) {
		backend := storage.NewMemory()
		store, err := NewBackendStore(backend, 100, nil)
		require.NoError(t, err)

		store.LogServiceEvent(OpServiceStopped, nil)

		results := store.Query(QueryFilter{})
		require.Len(t, results, 1)
		assert.Equal(t, OpServiceStopped, results[0].Operation)
		assert.Nil(t, results[0].Details)
	})

	t.Run("LogPINOperation", func(t *testing.T) {
		backend := storage.NewMemory()
		store, err := NewBackendStore(backend, 100, nil)
		require.NoError(t, err)

		details := map[string]any{"retries": 2}
		store.LogPINOperation(OpPINVerified, "tpm2", true, nil, details)

		results := store.Query(QueryFilter{})
		require.Len(t, results, 1)
		assert.Equal(t, OpPINVerified, results[0].Operation)
		assert.Equal(t, "tpm2", results[0].Backend)
		assert.True(t, results[0].Success)
	})

	t.Run("LogPINOperation with error", func(t *testing.T) {
		backend := storage.NewMemory()
		store, err := NewBackendStore(backend, 100, nil)
		require.NoError(t, err)

		testErr := errors.New("pin locked")
		store.LogPINOperation(OpPINLocked, "pkcs11", false, testErr, nil)

		results := store.Query(QueryFilter{})
		require.Len(t, results, 1)
		assert.Equal(t, "pin locked", results[0].Error)
		assert.False(t, results[0].Success)
	})

	t.Run("LogTPMOperation", func(t *testing.T) {
		backend := storage.NewMemory()
		store, err := NewBackendStore(backend, 100, nil)
		require.NoError(t, err)

		details := map[string]any{"hierarchy": "owner"}
		store.LogTPMOperation(OpTPMProvisioned, true, nil, details)

		results := store.Query(QueryFilter{})
		require.Len(t, results, 1)
		assert.Equal(t, OpTPMProvisioned, results[0].Operation)
		assert.Equal(t, "tpm2", results[0].Backend)
		assert.True(t, results[0].Success)
	})

	t.Run("LogTPMOperation with error", func(t *testing.T) {
		backend := storage.NewMemory()
		store, err := NewBackendStore(backend, 100, nil)
		require.NoError(t, err)

		testErr := errors.New("auth failed")
		store.LogTPMOperation(OpTPMAuthFailed, false, testErr, nil)

		results := store.Query(QueryFilter{})
		require.Len(t, results, 1)
		assert.Equal(t, "auth failed", results[0].Error)
		assert.Equal(t, "tpm2", results[0].Backend)
	})

	t.Run("LogPasswordStoreOperation", func(t *testing.T) {
		backend := storage.NewMemory()
		store, err := NewBackendStore(backend, 100, nil)
		require.NoError(t, err)

		details := map[string]any{"site": "example.com"}
		store.LogPasswordStoreOperation(OpPasswordAccessed, "browser-ext", true, nil, details)

		results := store.Query(QueryFilter{})
		require.Len(t, results, 1)
		assert.Equal(t, OpPasswordAccessed, results[0].Operation)
		assert.True(t, results[0].Success)
	})

	t.Run("LogPasswordStoreOperation nil details initializes map", func(t *testing.T) {
		backend := storage.NewMemory()
		store, err := NewBackendStore(backend, 100, nil)
		require.NoError(t, err)

		store.LogPasswordStoreOperation(OpAutofillDenied, "autofill", false, errors.New("denied"), nil)

		results := store.Query(QueryFilter{})
		require.Len(t, results, 1)
		assert.Equal(t, "denied", results[0].Error)
	})

	t.Run("LogUserPresenceEvent", func(t *testing.T) {
		backend := storage.NewMemory()
		store, err := NewBackendStore(backend, 100, nil)
		require.NoError(t, err)

		details := map[string]any{"timeout_ms": 30000}
		store.LogUserPresenceEvent(OpUserPresenceConfirmed, "touch-sensor", true, details)

		results := store.Query(QueryFilter{})
		require.Len(t, results, 1)
		assert.Equal(t, OpUserPresenceConfirmed, results[0].Operation)
		assert.True(t, results[0].Success)
	})

	t.Run("LogUserPresenceEvent nil details initializes map", func(t *testing.T) {
		backend := storage.NewMemory()
		store, err := NewBackendStore(backend, 100, nil)
		require.NoError(t, err)

		store.LogUserPresenceEvent(OpUserPresenceTimedOut, "button", false, nil)

		results := store.Query(QueryFilter{})
		require.Len(t, results, 1)
		assert.Equal(t, OpUserPresenceTimedOut, results[0].Operation)
	})
}

func TestBackendStore_Concurrency(t *testing.T) {

	backend := storage.NewMemory()
	store, err := NewBackendStore(backend, 1000, nil)
	require.NoError(t, err)

	writerCount := 100
	readerCount := 100

	var wg sync.WaitGroup
	wg.Add(writerCount + readerCount)

	// Spawn writers.
	for i := 0; i < writerCount; i++ {
		go func(id int) {
			defer wg.Done()
			store.Log(Entry{
				Timestamp: time.Now(),
				Operation: OpSignRequest,
				Backend:   "tpm2",
				KeyID:     fmt.Sprintf("concurrent-key-%d", id),
				Success:   true,
			})
		}(i)
	}

	// Spawn readers.
	for i := 0; i < readerCount; i++ {
		go func() {
			defer wg.Done()
			_ = store.Query(QueryFilter{})
			_ = store.Count()
		}()
	}

	wg.Wait()

	count := store.Count()
	assert.True(t, count > 0, "expected entries to be logged, got 0")
	assert.True(t, count <= writerCount,
		"expected count <= %d, got %d", writerCount, count)

	// Verify backend has entries.
	keys, listErr := backend.List(context.Background(), "audit/")
	require.NoError(t, listErr)
	assert.Equal(t, writerCount, len(keys))
}

func TestBackendStore_WithSlogLogger(t *testing.T) {

	t.Run("slog receives logged entries", func(t *testing.T) {
		var buf bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&buf, nil))

		backend := storage.NewMemory()
		store, err := NewBackendStore(backend, 100, logger)
		require.NoError(t, err)
		require.NotNil(t, store.slog)

		store.Log(Entry{
			Timestamp: time.Now(),
			Operation: OpKeyCreated,
			Backend:   "tpm2",
			KeyID:     "slog-key",
			Success:   true,
		})

		// Verify entry is in the store.
		assert.Equal(t, 1, store.Count())
		results := store.Query(QueryFilter{})
		require.Len(t, results, 1)
		assert.Equal(t, "slog-key", results[0].KeyID)

		// Verify the slog logger also received the entry.
		output := buf.String()
		assert.Contains(t, output, "key_created")
		assert.Contains(t, output, "tpm2")
		assert.Contains(t, output, "slog-key")
		assert.Contains(t, output, "audit")
		assert.Contains(t, output, "INFO")
	})

	t.Run("nil slog logger does not panic", func(t *testing.T) {
		backend := storage.NewMemory()
		store, err := NewBackendStore(backend, 100, nil)
		require.NoError(t, err)
		assert.Nil(t, store.slog)

		// Verify logging works without panic when slog is nil.
		store.Log(Entry{
			Timestamp: time.Now(),
			Operation: OpKeyCreated,
			Backend:   "software",
			KeyID:     "no-slog-key",
			Success:   true,
		})

		assert.Equal(t, 1, store.Count())
		results := store.Query(QueryFilter{})
		require.Len(t, results, 1)
		assert.Equal(t, "no-slog-key", results[0].KeyID)
	})

	t.Run("all helper methods work without slog", func(t *testing.T) {
		backend := storage.NewMemory()
		store, err := NewBackendStore(backend, 100, nil)
		require.NoError(t, err)

		store.LogKeyOperation(OpKeyDeleted, "tpm2", "key-2", true, nil, 100)
		store.LogCryptoOperation(OpSignRequest, "tpm2", "key-3", "dev-1", "Phone", true, nil, 50)
		store.LogConnectionEvent(OpConnectionEstablished, "dev-1", "Phone", nil)
		store.LogServiceEvent(OpServiceStarted, nil)
		store.LogPINOperation(OpPINVerified, "tpm2", true, nil, nil)
		store.LogTPMOperation(OpTPMProvisioned, true, nil, nil)
		store.LogPasswordStoreOperation(OpPasswordAccessed, "browser", true, nil, nil)
		store.LogUserPresenceEvent(OpUserPresenceConfirmed, "touch", true, nil)

		assert.Equal(t, 8, store.Count())
	})
}

func TestBackendStore_StoreInterface(t *testing.T) {
	// Compile-time interface check.
	var _ Store = (*BackendStore)(nil)
}

func TestBackendStore_EntryKey(t *testing.T) {

	t.Run("keys are deterministic and sorted chronologically", func(t *testing.T) {
		backend := storage.NewMemory()
		store, err := NewBackendStore(backend, 100, nil)
		require.NoError(t, err)

		ts1 := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
		ts2 := time.Date(2025, 1, 1, 1, 0, 0, 0, time.UTC)

		key1 := store.entryKey(Entry{Timestamp: ts1})
		key2 := store.entryKey(Entry{Timestamp: ts2})

		// key2 should sort after key1 because ts2 > ts1.
		assert.True(t, key1 < key2, "expected key1 < key2, got key1=%s key2=%s", key1, key2)
	})

	t.Run("keys have correct prefix", func(t *testing.T) {
		backend := storage.NewMemory()
		store, err := NewBackendStore(backend, 100, nil)
		require.NoError(t, err)

		key := store.entryKey(Entry{Timestamp: time.Now()})
		assert.Contains(t, key, "audit/")
		assert.Contains(t, key, ".json")
	})

	t.Run("concurrent keys are unique", func(t *testing.T) {
		backend := storage.NewMemory()
		store, err := NewBackendStore(backend, 100, nil)
		require.NoError(t, err)

		ts := time.Now()
		keys := make(map[string]bool)
		for i := 0; i < 100; i++ {
			key := store.entryKey(Entry{Timestamp: ts})
			assert.False(t, keys[key], "duplicate key: %s", key)
			keys[key] = true
		}
	})
}
