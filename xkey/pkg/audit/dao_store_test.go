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

//go:build codec_json

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

	"github.com/jeremyhahn/go-qrdb/pkg/dao"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/kvadapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestDAOStore creates a DAOAuditStore backed by in-memory storage for testing.
func newTestDAOStore(t *testing.T, opts ...Option) *DAOAuditStore {
	t.Helper()
	backend := storage.NewMemory()
	t.Cleanup(func() { backend.Close() })

	kvStore, err := kvadapter.New(backend)
	require.NoError(t, err)

	store, err := NewDAOAuditStore(kvStore, opts...)
	require.NoError(t, err)
	t.Cleanup(func() { store.Close() })

	return store
}

func TestDAOAuditStore_NewDAOAuditStore_NilKVStore(t *testing.T) {
	store, err := NewDAOAuditStore(nil)
	require.ErrorIs(t, err, ErrNilKVStore)
	assert.Nil(t, store)
}

func TestDAOAuditStore_NewDAOAuditStore_DefaultMaxSize(t *testing.T) {
	store := newTestDAOStore(t)
	assert.Equal(t, defaultMaxSize, store.maxSize)
	assert.Equal(t, 0, store.Count())
}

func TestDAOAuditStore_NewDAOAuditStore_CustomMaxSize(t *testing.T) {
	store := newTestDAOStore(t, WithMaxEntries(500))
	assert.Equal(t, 500, store.maxSize)
}

func TestDAOAuditStore_NewDAOAuditStore_NegativeMaxSizeIgnored(t *testing.T) {
	store := newTestDAOStore(t, WithMaxEntries(-5))
	assert.Equal(t, defaultMaxSize, store.maxSize)
}

func TestDAOAuditStore_LogKeyOperation(t *testing.T) {

	t.Run("successful key operation", func(t *testing.T) {
		store := newTestDAOStore(t)

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

	t.Run("failed key operation with error", func(t *testing.T) {
		store := newTestDAOStore(t)

		testErr := errors.New("key not found")
		store.LogKeyOperation(OpKeyDeleted, "software", "key-xyz", false, testErr, 10)

		results := store.Query(QueryFilter{})
		require.Len(t, results, 1)
		assert.Equal(t, "key not found", results[0].Error)
		assert.False(t, results[0].Success)
	})
}

func TestDAOAuditStore_LogCryptoOperation(t *testing.T) {

	t.Run("successful crypto operation", func(t *testing.T) {
		store := newTestDAOStore(t)

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

	t.Run("failed crypto operation with error", func(t *testing.T) {
		store := newTestDAOStore(t)

		testErr := errors.New("invalid ciphertext")
		store.LogCryptoOperation(OpDecryptRequest, "software", "dec-key", "device-2", "Galaxy S24", false, testErr, 50)

		results := store.Query(QueryFilter{})
		require.Len(t, results, 1)
		assert.Equal(t, "invalid ciphertext", results[0].Error)
		assert.False(t, results[0].Success)
	})
}

func TestDAOAuditStore_LogConnectionEvent(t *testing.T) {

	t.Run("with details", func(t *testing.T) {
		store := newTestDAOStore(t)

		details := map[string]any{"protocol": "BLE", "mtu": 247}
		store.LogConnectionEvent(OpConnectionEstablished, "device-abc", "Pixel 8 Pro", details)

		results := store.Query(QueryFilter{})
		require.Len(t, results, 1)
		assert.Equal(t, OpConnectionEstablished, results[0].Operation)
		assert.Equal(t, "device-abc", results[0].DeviceID)
		assert.True(t, results[0].Success)
	})

	t.Run("without details", func(t *testing.T) {
		store := newTestDAOStore(t)

		store.LogConnectionEvent(OpConnectionClosed, "device-xyz", "Galaxy S24", nil)

		results := store.Query(QueryFilter{})
		require.Len(t, results, 1)
		assert.Equal(t, OpConnectionClosed, results[0].Operation)
		assert.Nil(t, results[0].Details)
	})
}

func TestDAOAuditStore_LogServiceEvent(t *testing.T) {
	store := newTestDAOStore(t)

	details := map[string]any{"version": "1.0.0"}
	store.LogServiceEvent(OpServiceStarted, details)

	results := store.Query(QueryFilter{})
	require.Len(t, results, 1)
	assert.Equal(t, OpServiceStarted, results[0].Operation)
	assert.True(t, results[0].Success)
}

func TestDAOAuditStore_LogPINOperation(t *testing.T) {

	t.Run("successful PIN operation", func(t *testing.T) {
		store := newTestDAOStore(t)

		details := map[string]any{"retries": 2}
		store.LogPINOperation(OpPINVerified, "tpm2", true, nil, details)

		results := store.Query(QueryFilter{})
		require.Len(t, results, 1)
		assert.Equal(t, OpPINVerified, results[0].Operation)
		assert.Equal(t, "tpm2", results[0].Backend)
		assert.True(t, results[0].Success)
	})

	t.Run("failed PIN operation with error", func(t *testing.T) {
		store := newTestDAOStore(t)

		testErr := errors.New("pin locked")
		store.LogPINOperation(OpPINLocked, "pkcs11", false, testErr, nil)

		results := store.Query(QueryFilter{})
		require.Len(t, results, 1)
		assert.Equal(t, "pin locked", results[0].Error)
		assert.False(t, results[0].Success)
	})
}

func TestDAOAuditStore_LogTPMOperation(t *testing.T) {

	t.Run("successful TPM operation", func(t *testing.T) {
		store := newTestDAOStore(t)

		details := map[string]any{"hierarchy": "owner"}
		store.LogTPMOperation(OpTPMProvisioned, true, nil, details)

		results := store.Query(QueryFilter{})
		require.Len(t, results, 1)
		assert.Equal(t, OpTPMProvisioned, results[0].Operation)
		assert.Equal(t, "tpm2", results[0].Backend)
	})

	t.Run("failed TPM operation with error", func(t *testing.T) {
		store := newTestDAOStore(t)

		testErr := errors.New("auth failed")
		store.LogTPMOperation(OpTPMAuthFailed, false, testErr, nil)

		results := store.Query(QueryFilter{})
		require.Len(t, results, 1)
		assert.Equal(t, "auth failed", results[0].Error)
		assert.Equal(t, "tpm2", results[0].Backend)
	})
}

func TestDAOAuditStore_LogPasswordStoreOperation(t *testing.T) {

	t.Run("with existing details", func(t *testing.T) {
		store := newTestDAOStore(t)

		details := map[string]any{"site": "example.com"}
		store.LogPasswordStoreOperation(OpPasswordAccessed, "browser-ext", true, nil, details)

		results := store.Query(QueryFilter{})
		require.Len(t, results, 1)
		assert.Equal(t, OpPasswordAccessed, results[0].Operation)
	})

	t.Run("nil details initializes map", func(t *testing.T) {
		store := newTestDAOStore(t)

		store.LogPasswordStoreOperation(OpAutofillDenied, "autofill", false, errors.New("denied"), nil)

		results := store.Query(QueryFilter{})
		require.Len(t, results, 1)
		assert.Equal(t, "denied", results[0].Error)
	})
}

func TestDAOAuditStore_LogUserPresenceEvent(t *testing.T) {

	t.Run("with details", func(t *testing.T) {
		store := newTestDAOStore(t)

		details := map[string]any{"timeout_ms": 30000}
		store.LogUserPresenceEvent(OpUserPresenceConfirmed, "touch-sensor", true, details)

		results := store.Query(QueryFilter{})
		require.Len(t, results, 1)
		assert.Equal(t, OpUserPresenceConfirmed, results[0].Operation)
	})

	t.Run("nil details initializes map", func(t *testing.T) {
		store := newTestDAOStore(t)

		store.LogUserPresenceEvent(OpUserPresenceTimedOut, "button", false, nil)

		results := store.Query(QueryFilter{})
		require.Len(t, results, 1)
		assert.Equal(t, OpUserPresenceTimedOut, results[0].Operation)
	})
}

func TestDAOAuditStore_QueryByOperation(t *testing.T) {
	store := newTestDAOStore(t)

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
}

func TestDAOAuditStore_QueryByBackend(t *testing.T) {
	store := newTestDAOStore(t)

	store.Log(Entry{Timestamp: time.Now(), Operation: OpKeyCreated, Backend: "tpm2", KeyID: "k1", Success: true})
	store.Log(Entry{Timestamp: time.Now(), Operation: OpSignRequest, Backend: "software", KeyID: "k2", Success: true})
	store.Log(Entry{Timestamp: time.Now(), Operation: OpKeyDeleted, Backend: "tpm2", KeyID: "k3", Success: true})

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
}

func TestDAOAuditStore_QueryBySuccess(t *testing.T) {
	store := newTestDAOStore(t)

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
}

func TestDAOAuditStore_QueryTimeRange(t *testing.T) {
	store := newTestDAOStore(t)

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
}

func TestDAOAuditStore_QueryLimitOffset(t *testing.T) {
	store := newTestDAOStore(t)

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
	})

	t.Run("offset skips entries", func(t *testing.T) {
		results := store.Query(QueryFilter{Offset: 7})
		require.Len(t, results, 3)
		assert.Equal(t, "key-7", results[0].KeyID)
	})

	t.Run("limit and offset together paginate", func(t *testing.T) {
		results := store.Query(QueryFilter{Offset: 2, Limit: 3})
		require.Len(t, results, 3)
		assert.Equal(t, "key-2", results[0].KeyID)
		assert.Equal(t, "key-4", results[2].KeyID)
	})

	t.Run("offset beyond count returns empty", func(t *testing.T) {
		results := store.Query(QueryFilter{Offset: 20})
		assert.Empty(t, results)
	})
}

func TestDAOAuditStore_RingBufferEviction(t *testing.T) {

	t.Run("evicts oldest entries when full", func(t *testing.T) {
		store := newTestDAOStore(t, WithMaxEntries(3))

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
	})

	t.Run("max size of 1 keeps only latest in cache", func(t *testing.T) {
		store := newTestDAOStore(t, WithMaxEntries(1))

		store.Log(Entry{Timestamp: time.Now(), Operation: OpKeyCreated, KeyID: "first", Success: true})
		store.Log(Entry{Timestamp: time.Now(), Operation: OpKeyDeleted, KeyID: "second", Success: true})

		assert.Equal(t, 1, store.Count())
		results := store.Query(QueryFilter{})
		require.Len(t, results, 1)
		assert.Equal(t, "second", results[0].KeyID)
	})
}

func TestDAOAuditStore_RingBufferLoadRespectMaxSize(t *testing.T) {
	// Create a store with large buffer, log 10 entries, then create a new
	// store with maxSize=3 from the same backend and verify only 3 most
	// recent are loaded.
	backend := storage.NewMemory()
	t.Cleanup(func() { backend.Close() })

	kvStore, err := kvadapter.New(backend)
	require.NoError(t, err)

	store1, err := NewDAOAuditStore(kvStore, WithMaxEntries(100))
	require.NoError(t, err)

	for i := 0; i < 10; i++ {
		store1.Log(Entry{
			Timestamp: time.Date(2025, 1, 1, i, 0, 0, 0, time.UTC),
			Operation: OpKeyCreated,
			KeyID:     fmt.Sprintf("key-%d", i),
			Success:   true,
		})
	}
	store1.Close()

	store2, err := NewDAOAuditStore(kvStore, WithMaxEntries(3))
	require.NoError(t, err)
	defer store2.Close()

	assert.Equal(t, 3, store2.Count())
	results := store2.Query(QueryFilter{})
	require.Len(t, results, 3)
	assert.Equal(t, "key-7", results[0].KeyID)
	assert.Equal(t, "key-8", results[1].KeyID)
	assert.Equal(t, "key-9", results[2].KeyID)
}

func TestDAOAuditStore_Persistence(t *testing.T) {
	// Entries survive store recreation from the same kvstore.
	backend := storage.NewMemory()
	t.Cleanup(func() { backend.Close() })

	kvStore, err := kvadapter.New(backend)
	require.NoError(t, err)

	store1, err := NewDAOAuditStore(kvStore)
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
	store1.Close()

	store2, err := NewDAOAuditStore(kvStore)
	require.NoError(t, err)
	defer store2.Close()

	assert.Equal(t, 2, store2.Count())
	results := store2.Query(QueryFilter{})
	require.Len(t, results, 2)
	assert.Equal(t, "persistent-key-1", results[0].KeyID)
	assert.Equal(t, "persistent-key-2", results[1].KeyID)
}

func TestDAOAuditStore_Page(t *testing.T) {

	t.Run("returns paginated entities", func(t *testing.T) {
		store := newTestDAOStore(t)

		for i := 0; i < 10; i++ {
			store.Log(Entry{
				Timestamp: time.Now(),
				Operation: OpKeyCreated,
				KeyID:     fmt.Sprintf("page-key-%d", i),
				Success:   true,
			})
		}

		ctx := context.Background()
		result, err := store.Page(ctx, dao.PageQuery{Page: 1, PageSize: 3})
		require.NoError(t, err)
		assert.Len(t, result.Entities, 3)
		assert.Equal(t, 10, result.Total)
		assert.True(t, result.HasMore)
	})

	t.Run("returns empty for empty store", func(t *testing.T) {
		store := newTestDAOStore(t)

		ctx := context.Background()
		result, err := store.Page(ctx, dao.PageQuery{Page: 1, PageSize: 10})
		require.NoError(t, err)
		assert.Empty(t, result.Entities)
		assert.Equal(t, 0, result.Total)
	})

	t.Run("returns error when closed", func(t *testing.T) {
		store := newTestDAOStore(t)
		store.Close()

		ctx := context.Background()
		_, err := store.Page(ctx, dao.PageQuery{Page: 1, PageSize: 10})
		require.ErrorIs(t, err, ErrStoreClosed)
	})
}

func TestDAOAuditStore_Count(t *testing.T) {

	t.Run("empty store returns 0", func(t *testing.T) {
		store := newTestDAOStore(t)
		assert.Equal(t, 0, store.Count())
	})

	t.Run("count increments with each log", func(t *testing.T) {
		store := newTestDAOStore(t)

		for i := 1; i <= 5; i++ {
			store.Log(Entry{Timestamp: time.Now(), Operation: OpKeyCreated, Success: true})
			assert.Equal(t, i, store.Count())
		}
	})

	t.Run("count does not exceed max size", func(t *testing.T) {
		store := newTestDAOStore(t, WithMaxEntries(3))

		for i := 0; i < 10; i++ {
			store.Log(Entry{Timestamp: time.Now(), Operation: OpKeyCreated, Success: true})
		}
		assert.Equal(t, 3, store.Count())
	})
}

func TestDAOAuditStore_EmptyStoreBehavior(t *testing.T) {
	store := newTestDAOStore(t)

	t.Run("query returns empty", func(t *testing.T) {
		results := store.Query(QueryFilter{})
		assert.Empty(t, results)
	})

	t.Run("count returns 0", func(t *testing.T) {
		assert.Equal(t, 0, store.Count())
	})

	t.Run("query with filter returns empty", func(t *testing.T) {
		results := store.Query(QueryFilter{Operation: OpKeyCreated, Backend: "tpm2"})
		assert.Empty(t, results)
	})
}

func TestDAOAuditStore_WithSlogLogger(t *testing.T) {

	t.Run("slog receives logged entries", func(t *testing.T) {
		var buf bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&buf, nil))

		store := newTestDAOStore(t, WithLogger(logger))

		store.Log(Entry{
			Timestamp: time.Now(),
			Operation: OpKeyCreated,
			Backend:   "tpm2",
			KeyID:     "slog-key",
			Success:   true,
		})

		assert.Equal(t, 1, store.Count())
		output := buf.String()
		assert.Contains(t, output, "key_created")
		assert.Contains(t, output, "tpm2")
		assert.Contains(t, output, "slog-key")
	})

	t.Run("nil logger does not panic", func(t *testing.T) {
		store := newTestDAOStore(t)

		store.Log(Entry{
			Timestamp: time.Now(),
			Operation: OpKeyCreated,
			KeyID:     "no-slog-key",
			Success:   true,
		})

		assert.Equal(t, 1, store.Count())
	})
}

func TestDAOAuditStore_ClosedStoreDropsLogs(t *testing.T) {
	store := newTestDAOStore(t)

	store.Log(Entry{Timestamp: time.Now(), Operation: OpKeyCreated, KeyID: "before-close", Success: true})
	assert.Equal(t, 1, store.Count())

	store.Close()

	// Log after close is silently dropped.
	store.LogKeyOperation(OpKeyDeleted, "tpm2", "after-close", true, nil, 0)
	assert.Equal(t, 1, store.Count())
}

func TestDAOAuditStore_Concurrency(t *testing.T) {
	store := newTestDAOStore(t, WithMaxEntries(1000))

	writerCount := 100
	readerCount := 100

	var wg sync.WaitGroup
	wg.Add(writerCount + readerCount)

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
}

func TestDAOAuditStore_InterfaceSatisfaction(t *testing.T) {
	var _ Store = (*DAOAuditStore)(nil)
	var _ Logger = (*DAOAuditStore)(nil)
}

func TestDAOAuditStore_EntryEntityConversion(t *testing.T) {
	now := time.Now().Truncate(time.Millisecond)
	entry := Entry{
		Timestamp:  now,
		Operation:  OpSignRequest,
		Backend:    "tpm2",
		KeyID:      "key-123",
		DeviceID:   "dev-456",
		DeviceName: "Test Device",
		Success:    true,
		Error:      "some error",
		DurationMs: 42,
		Details:    map[string]any{"algo": "ES256"},
	}

	entity := entryToEntity(entry)
	assert.Equal(t, entry.Timestamp, entity.Timestamp)
	assert.Equal(t, entry.Operation, entity.Operation)
	assert.Equal(t, entry.Backend, entity.Backend)
	assert.Equal(t, entry.KeyID, entity.KeyID)
	assert.Equal(t, entry.DeviceID, entity.DeviceID)
	assert.Equal(t, entry.DeviceName, entity.DeviceName)
	assert.Equal(t, entry.Success, entity.Success)
	assert.Equal(t, entry.Error, entity.Error)
	assert.Equal(t, entry.DurationMs, entity.DurationMs)

	roundTripped := entityToEntry(entity)
	assert.Equal(t, entry.Timestamp, roundTripped.Timestamp)
	assert.Equal(t, entry.Operation, roundTripped.Operation)
	assert.Equal(t, entry.Backend, roundTripped.Backend)
	assert.Equal(t, entry.KeyID, roundTripped.KeyID)
	assert.Equal(t, entry.DeviceID, roundTripped.DeviceID)
	assert.Equal(t, entry.DeviceName, roundTripped.DeviceName)
	assert.Equal(t, entry.Success, roundTripped.Success)
	assert.Equal(t, entry.Error, roundTripped.Error)
	assert.Equal(t, entry.DurationMs, roundTripped.DurationMs)
}

func TestDAOMigrateFromBackend(t *testing.T) {

	t.Run("migrates entries from old backend to DAO store", func(t *testing.T) {
		// Create old backend with entries in the old format.
		oldBackend := storage.NewMemory()
		t.Cleanup(func() { oldBackend.Close() })

		ctx := context.Background()

		entry1 := Entry{
			Timestamp: time.Date(2025, 3, 8, 10, 0, 0, 0, time.UTC),
			Operation: OpKeyCreated,
			Backend:   "tpm2",
			KeyID:     "migrate-key-1",
			Success:   true,
		}
		entry2 := Entry{
			Timestamp: time.Date(2025, 3, 8, 11, 0, 0, 0, time.UTC),
			Operation: OpSignRequest,
			Backend:   "software",
			KeyID:     "migrate-key-2",
			Success:   true,
		}

		data1, _ := json.Marshal(entry1)
		data2, _ := json.Marshal(entry2)
		require.NoError(t, oldBackend.Put(ctx, "audit/1000-000000000000.json", data1))
		require.NoError(t, oldBackend.Put(ctx, "audit/2000-000000000001.json", data2))

		store := newTestDAOStore(t)

		errs := MigrateFromBackend(ctx, oldBackend, store)
		assert.Empty(t, errs)

		assert.Equal(t, 2, store.Count())
		results := store.Query(QueryFilter{})
		require.Len(t, results, 2)

		// Old keys should be deleted.
		keys, listErr := oldBackend.List(ctx, "audit/")
		require.NoError(t, listErr)
		assert.Empty(t, keys)
	})

	t.Run("nil backend returns nil errors", func(t *testing.T) {
		store := newTestDAOStore(t)
		errs := MigrateFromBackend(context.Background(), nil, store)
		assert.Nil(t, errs)
	})

	t.Run("nil store returns nil errors", func(t *testing.T) {
		backend := storage.NewMemory()
		t.Cleanup(func() { backend.Close() })
		errs := MigrateFromBackend(context.Background(), backend, nil)
		assert.Nil(t, errs)
	})

	t.Run("invalid JSON entries are reported as errors", func(t *testing.T) {
		oldBackend := storage.NewMemory()
		t.Cleanup(func() { oldBackend.Close() })

		ctx := context.Background()
		require.NoError(t, oldBackend.Put(ctx, "audit/1000-000000000000.json", []byte("not-json")))

		store := newTestDAOStore(t)

		errs := MigrateFromBackend(ctx, oldBackend, store)
		require.Len(t, errs, 1)

		var migErr ErrMigration
		require.True(t, errors.As(errs[0], &migErr))
		assert.Contains(t, migErr.Key, "audit/")
	})
}
