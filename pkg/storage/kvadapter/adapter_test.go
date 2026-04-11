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

package kvadapter

import (
	"context"
	"errors"
	"testing"

	dberrors "github.com/jeremyhahn/go-qrdb/pkg/errors"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errorBackend is a configurable mock backend for testing error paths.
type errorBackend struct {
	getErr    error
	putErr    error
	deleteErr error
	listErr   error
	scanErr   error
	existsErr error
}

func (e *errorBackend) Get(_ context.Context, _ string) ([]byte, error) {
	return nil, e.getErr
}
func (e *errorBackend) Put(_ context.Context, _ string, _ []byte) error {
	return e.putErr
}
func (e *errorBackend) Delete(_ context.Context, _ string) error {
	return e.deleteErr
}
func (e *errorBackend) List(_ context.Context, _ string) ([]string, error) {
	return nil, e.listErr
}
func (e *errorBackend) Scan(_ context.Context, _ string, _ func(key string, value []byte) error) error {
	return e.scanErr
}
func (e *errorBackend) Exists(_ context.Context, _ string) (bool, error) {
	return false, e.existsErr
}
func (e *errorBackend) Close() error { return nil }

// =============================================================================
// Constructor Tests
// =============================================================================

func TestNew_Success(t *testing.T) {
	backend := storage.NewMemory()
	adapter, err := New(backend)
	require.NoError(t, err)
	assert.NotNil(t, adapter)
}

func TestNew_NilBackend(t *testing.T) {
	adapter, err := New(nil)
	assert.Nil(t, adapter)
	assert.Error(t, err)

	var nilErr NilBackendError
	assert.True(t, errors.As(err, &nilErr))
	assert.Contains(t, err.Error(), "backend cannot be nil")
}

// =============================================================================
// Put Tests
// =============================================================================

func TestPut_Success(t *testing.T) {
	backend := storage.NewMemory()
	adapter, err := New(backend)
	require.NoError(t, err)
	ctx := context.Background()

	err = adapter.Put(ctx, "key1", []byte("value1"))
	assert.NoError(t, err)

	// Verify via direct backend access
	data, getErr := backend.Get(ctx, "key1")
	require.NoError(t, getErr)
	assert.Equal(t, []byte("value1"), data)
}

func TestPut_BackendError(t *testing.T) {
	backendErr := errors.New("disk full")
	backend := &errorBackend{putErr: backendErr}
	adapter, err := New(backend)
	require.NoError(t, err)
	ctx := context.Background()

	err = adapter.Put(ctx, "key1", []byte("value1"))
	assert.Error(t, err)

	var putErr *PutError
	assert.True(t, errors.As(err, &putErr))
	assert.Equal(t, "key1", putErr.Key)
	assert.True(t, errors.Is(err, backendErr))
	assert.Contains(t, err.Error(), "kvadapter: put key1")
}

// =============================================================================
// Get Tests
// =============================================================================

func TestGet_Success(t *testing.T) {
	backend := storage.NewMemory()
	adapter, err := New(backend)
	require.NoError(t, err)
	ctx := context.Background()

	err = adapter.Put(ctx, "key1", []byte("value1"))
	require.NoError(t, err)

	data, getErr := adapter.Get(ctx, "key1")
	assert.NoError(t, getErr)
	assert.Equal(t, []byte("value1"), data)
}

func TestGet_NotFound_ReturnsQRDBError(t *testing.T) {
	backend := storage.NewMemory()
	adapter, err := New(backend)
	require.NoError(t, err)
	ctx := context.Background()

	data, getErr := adapter.Get(ctx, "nonexistent")
	assert.Error(t, getErr)
	assert.Nil(t, data)

	// Verify it's a QRDB NotFound error (required by DAO layer).
	assert.True(t, dberrors.IsNotFound(getErr))
}

func TestGet_BackendError(t *testing.T) {
	backendErr := errors.New("io error")
	backend := &errorBackend{getErr: backendErr}
	adapter, err := New(backend)
	require.NoError(t, err)
	ctx := context.Background()

	data, getErr := adapter.Get(ctx, "key1")
	assert.Error(t, getErr)
	assert.Nil(t, data)

	var typedErr *GetError
	assert.True(t, errors.As(getErr, &typedErr))
	assert.Equal(t, "key1", typedErr.Key)
	assert.True(t, errors.Is(getErr, backendErr))
	assert.Contains(t, getErr.Error(), "kvadapter: get key1")
}

// =============================================================================
// Delete Tests
// =============================================================================

func TestDelete_Success(t *testing.T) {
	backend := storage.NewMemory()
	adapter, err := New(backend)
	require.NoError(t, err)
	ctx := context.Background()

	err = adapter.Put(ctx, "key1", []byte("value1"))
	require.NoError(t, err)

	err = adapter.Delete(ctx, "key1")
	assert.NoError(t, err)

	// Verify key is gone via Get returning QRDB NotFound error.
	data, getErr := adapter.Get(ctx, "key1")
	assert.Error(t, getErr)
	assert.Nil(t, data)
	assert.True(t, dberrors.IsNotFound(getErr))
}

func TestDelete_NotFound_Idempotent(t *testing.T) {
	backend := storage.NewMemory()
	adapter, err := New(backend)
	require.NoError(t, err)
	ctx := context.Background()

	err = adapter.Delete(ctx, "nonexistent")
	assert.NoError(t, err)
}

func TestDelete_BackendError(t *testing.T) {
	backendErr := errors.New("permission denied")
	backend := &errorBackend{deleteErr: backendErr}
	adapter, err := New(backend)
	require.NoError(t, err)
	ctx := context.Background()

	err = adapter.Delete(ctx, "key1")
	assert.Error(t, err)

	var typedErr *DeleteError
	assert.True(t, errors.As(err, &typedErr))
	assert.Equal(t, "key1", typedErr.Key)
	assert.True(t, errors.Is(err, backendErr))
	assert.Contains(t, err.Error(), "kvadapter: delete key1")
}

// =============================================================================
// Scan Tests
// =============================================================================

func TestScan_Success(t *testing.T) {
	backend := storage.NewMemory()
	adapter, err := New(backend)
	require.NoError(t, err)
	ctx := context.Background()

	require.NoError(t, adapter.Put(ctx, "prefix/a", []byte("va")))
	require.NoError(t, adapter.Put(ctx, "prefix/b", []byte("vb")))
	require.NoError(t, adapter.Put(ctx, "other/c", []byte("vc")))

	var keys []string
	var values []string
	err = adapter.Scan(ctx, "prefix/", func(key string, value []byte) error {
		keys = append(keys, key)
		values = append(values, string(value))
		return nil
	})
	assert.NoError(t, err)
	assert.Equal(t, 2, len(keys))
	assert.Equal(t, "prefix/a", keys[0])
	assert.Equal(t, "prefix/b", keys[1])
	assert.Equal(t, "va", values[0])
	assert.Equal(t, "vb", values[1])
}

func TestScan_EmptyPrefix(t *testing.T) {
	backend := storage.NewMemory()
	adapter, err := New(backend)
	require.NoError(t, err)
	ctx := context.Background()

	require.NoError(t, adapter.Put(ctx, "a", []byte("va")))
	require.NoError(t, adapter.Put(ctx, "b", []byte("vb")))

	count := 0
	err = adapter.Scan(ctx, "", func(_ string, _ []byte) error {
		count++
		return nil
	})
	assert.NoError(t, err)
	assert.Equal(t, 2, count)
}

func TestScan_CallbackError(t *testing.T) {
	backend := storage.NewMemory()
	adapter, err := New(backend)
	require.NoError(t, err)
	ctx := context.Background()

	require.NoError(t, adapter.Put(ctx, "k1", []byte("v1")))

	callbackErr := errors.New("callback error")
	err = adapter.Scan(ctx, "", func(_ string, _ []byte) error {
		return callbackErr
	})
	assert.True(t, errors.Is(err, callbackErr))
}

func TestScan_BackendError(t *testing.T) {
	backendErr := errors.New("scan failed")
	backend := &errorBackend{scanErr: backendErr}
	adapter, err := New(backend)
	require.NoError(t, err)
	ctx := context.Background()

	err = adapter.Scan(ctx, "prefix/", func(_ string, _ []byte) error {
		return nil
	})
	assert.Error(t, err)

	var typedErr *ScanError
	assert.True(t, errors.As(err, &typedErr))
	assert.Equal(t, "prefix/", typedErr.Prefix)
	assert.True(t, errors.Is(err, backendErr))
	assert.Contains(t, err.Error(), "kvadapter: scan prefix/")
}

func TestScan_NoMatches(t *testing.T) {
	backend := storage.NewMemory()
	adapter, err := New(backend)
	require.NoError(t, err)
	ctx := context.Background()

	require.NoError(t, adapter.Put(ctx, "other/a", []byte("va")))

	count := 0
	err = adapter.Scan(ctx, "prefix/", func(_ string, _ []byte) error {
		count++
		return nil
	})
	assert.NoError(t, err)
	assert.Equal(t, 0, count)
}

// =============================================================================
// List Tests
// =============================================================================

func TestList_Success(t *testing.T) {
	backend := storage.NewMemory()
	adapter, err := New(backend)
	require.NoError(t, err)
	ctx := context.Background()

	require.NoError(t, adapter.Put(ctx, "ns/a", []byte("va")))
	require.NoError(t, adapter.Put(ctx, "ns/b", []byte("vb")))
	require.NoError(t, adapter.Put(ctx, "other/c", []byte("vc")))

	keys, listErr := adapter.List(ctx, "ns/")
	assert.NoError(t, listErr)
	assert.Equal(t, 2, len(keys))
}

func TestList_Empty(t *testing.T) {
	backend := storage.NewMemory()
	adapter, err := New(backend)
	require.NoError(t, err)
	ctx := context.Background()

	keys, listErr := adapter.List(ctx, "nonexistent/")
	assert.NoError(t, listErr)
	assert.Empty(t, keys)
}

func TestList_BackendError(t *testing.T) {
	backendErr := errors.New("list failed")
	backend := &errorBackend{listErr: backendErr}
	adapter, err := New(backend)
	require.NoError(t, err)
	ctx := context.Background()

	keys, listErr := adapter.List(ctx, "prefix/")
	assert.Error(t, listErr)
	assert.Nil(t, keys)

	var typedErr *ListError
	assert.True(t, errors.As(listErr, &typedErr))
	assert.Equal(t, "prefix/", typedErr.Prefix)
	assert.True(t, errors.Is(listErr, backendErr))
}

// =============================================================================
// Exists Tests
// =============================================================================

func TestExists_True(t *testing.T) {
	backend := storage.NewMemory()
	adapter, err := New(backend)
	require.NoError(t, err)
	ctx := context.Background()

	require.NoError(t, adapter.Put(ctx, "key1", []byte("value1")))

	exists, existsErr := adapter.Exists(ctx, "key1")
	assert.NoError(t, existsErr)
	assert.True(t, exists)
}

func TestExists_False(t *testing.T) {
	backend := storage.NewMemory()
	adapter, err := New(backend)
	require.NoError(t, err)
	ctx := context.Background()

	exists, existsErr := adapter.Exists(ctx, "nonexistent")
	assert.NoError(t, existsErr)
	assert.False(t, exists)
}

func TestExists_BackendError(t *testing.T) {
	backendErr := errors.New("exists failed")
	backend := &errorBackend{existsErr: backendErr}
	adapter, err := New(backend)
	require.NoError(t, err)
	ctx := context.Background()

	exists, existsErr := adapter.Exists(ctx, "key1")
	assert.Error(t, existsErr)
	assert.False(t, exists)

	var typedErr *ExistsError
	assert.True(t, errors.As(existsErr, &typedErr))
	assert.Equal(t, "key1", typedErr.Key)
	assert.True(t, errors.Is(existsErr, backendErr))
}

// =============================================================================
// Index No-Op Tests
// =============================================================================

func TestRegisterEntityIndexes_NoOp(t *testing.T) {
	backend := storage.NewMemory()
	adapter, err := New(backend)
	require.NoError(t, err)

	indexes := []qrdbsdk.EntityIndex{
		{FieldName: "name", JSONFieldName: "name"},
	}
	err = adapter.RegisterEntityIndexes("users", indexes)
	assert.NoError(t, err)
}

func TestRegisterEntityIndexes_EmptyIndexes(t *testing.T) {
	backend := storage.NewMemory()
	adapter, err := New(backend)
	require.NoError(t, err)

	err = adapter.RegisterEntityIndexes("users", nil)
	assert.NoError(t, err)
}

func TestQueryIndex_ReturnsNil(t *testing.T) {
	backend := storage.NewMemory()
	adapter, err := New(backend)
	require.NoError(t, err)
	ctx := context.Background()

	results, queryErr := adapter.QueryIndex(ctx, "idx_name", []byte("alice"))
	assert.NoError(t, queryErr)
	assert.Nil(t, results)
}

func TestQueryIndex_EmptyValue(t *testing.T) {
	backend := storage.NewMemory()
	adapter, err := New(backend)
	require.NoError(t, err)
	ctx := context.Background()

	results, queryErr := adapter.QueryIndex(ctx, "idx_name", nil)
	assert.NoError(t, queryErr)
	assert.Nil(t, results)
}

func TestScanIndex_ReturnsNil(t *testing.T) {
	backend := storage.NewMemory()
	adapter, err := New(backend)
	require.NoError(t, err)
	ctx := context.Background()

	results, scanErr := adapter.ScanIndex(ctx, "idx_name", []byte("a"), []byte("z"))
	assert.NoError(t, scanErr)
	assert.Nil(t, results)
}

func TestScanIndex_NilBounds(t *testing.T) {
	backend := storage.NewMemory()
	adapter, err := New(backend)
	require.NoError(t, err)
	ctx := context.Background()

	results, scanErr := adapter.ScanIndex(ctx, "idx_name", nil, nil)
	assert.NoError(t, scanErr)
	assert.Nil(t, results)
}

// =============================================================================
// Compound Index No-Op Tests
// =============================================================================

func TestQueryCompoundIndex_ReturnsNil(t *testing.T) {
	backend := storage.NewMemory()
	adapter, err := New(backend)
	require.NoError(t, err)
	ctx := context.Background()

	values := [][]byte{[]byte("tenant-1"), []byte("alice")}
	results, queryErr := adapter.QueryCompoundIndex(ctx, "idx_tenant_name", values)
	assert.NoError(t, queryErr)
	assert.Nil(t, results)
}

func TestQueryCompoundIndex_NilValues(t *testing.T) {
	backend := storage.NewMemory()
	adapter, err := New(backend)
	require.NoError(t, err)
	ctx := context.Background()

	results, queryErr := adapter.QueryCompoundIndex(ctx, "idx_tenant_name", nil)
	assert.NoError(t, queryErr)
	assert.Nil(t, results)
}

func TestScanCompoundIndex_ReturnsNil(t *testing.T) {
	backend := storage.NewMemory()
	adapter, err := New(backend)
	require.NoError(t, err)
	ctx := context.Background()

	prefixValues := [][]byte{[]byte("tenant-1")}
	results, scanErr := adapter.ScanCompoundIndex(ctx, "idx_compound", prefixValues, []byte("a"), []byte("z"))
	assert.NoError(t, scanErr)
	assert.Nil(t, results)
}

func TestScanCompoundIndex_NilArgs(t *testing.T) {
	backend := storage.NewMemory()
	adapter, err := New(backend)
	require.NoError(t, err)
	ctx := context.Background()

	results, scanErr := adapter.ScanCompoundIndex(ctx, "idx_compound", nil, nil, nil)
	assert.NoError(t, scanErr)
	assert.Nil(t, results)
}

// =============================================================================
// Error Type Tests
// =============================================================================

func TestErrorTypes_Messages(t *testing.T) {
	baseErr := errors.New("base error")

	t.Run("NilBackendError", func(t *testing.T) {
		err := NilBackendError{}
		assert.Equal(t, "kvadapter: backend cannot be nil", err.Error())
	})

	t.Run("PutError", func(t *testing.T) {
		err := &PutError{Key: "k1", Err: baseErr}
		assert.Equal(t, "kvadapter: put k1: base error", err.Error())
		assert.Equal(t, baseErr, err.Unwrap())
	})

	t.Run("GetError", func(t *testing.T) {
		err := &GetError{Key: "k1", Err: baseErr}
		assert.Equal(t, "kvadapter: get k1: base error", err.Error())
		assert.Equal(t, baseErr, err.Unwrap())
	})

	t.Run("DeleteError", func(t *testing.T) {
		err := &DeleteError{Key: "k1", Err: baseErr}
		assert.Equal(t, "kvadapter: delete k1: base error", err.Error())
		assert.Equal(t, baseErr, err.Unwrap())
	})

	t.Run("ScanError", func(t *testing.T) {
		err := &ScanError{Prefix: "pfx/", Err: baseErr}
		assert.Equal(t, "kvadapter: scan pfx/: base error", err.Error())
		assert.Equal(t, baseErr, err.Unwrap())
	})

	t.Run("ScanCallbackError", func(t *testing.T) {
		err := &ScanCallbackError{Key: "k1", Err: baseErr}
		assert.Equal(t, "kvadapter: scan callback k1: base error", err.Error())
		assert.Equal(t, baseErr, err.Unwrap())
	})

	t.Run("ListError", func(t *testing.T) {
		err := &ListError{Prefix: "pfx/", Err: baseErr}
		assert.Equal(t, "kvadapter: list pfx/: base error", err.Error())
		assert.Equal(t, baseErr, err.Unwrap())
	})

	t.Run("ExistsError", func(t *testing.T) {
		err := &ExistsError{Key: "k1", Err: baseErr}
		assert.Equal(t, "kvadapter: exists k1: base error", err.Error())
		assert.Equal(t, baseErr, err.Unwrap())
	})
}

// =============================================================================
// Integration Round-Trip
// =============================================================================

func TestKVStoreAdapter_RoundTrip(t *testing.T) {
	backend := storage.NewMemory()
	adapter, err := New(backend)
	require.NoError(t, err)
	ctx := context.Background()

	// Full CRUD cycle
	err = adapter.Put(ctx, "entity/1", []byte(`{"id":1,"name":"alice"}`))
	require.NoError(t, err)

	err = adapter.Put(ctx, "entity/2", []byte(`{"id":2,"name":"bob"}`))
	require.NoError(t, err)

	// Get
	data, getErr := adapter.Get(ctx, "entity/1")
	assert.NoError(t, getErr)
	assert.Contains(t, string(data), "alice")

	// Exists
	exists, existsErr := adapter.Exists(ctx, "entity/1")
	assert.NoError(t, existsErr)
	assert.True(t, exists)

	// List
	keys, listErr := adapter.List(ctx, "entity/")
	assert.NoError(t, listErr)
	assert.Equal(t, 2, len(keys))

	// Scan
	count := 0
	scanErr := adapter.Scan(ctx, "entity/", func(_ string, _ []byte) error {
		count++
		return nil
	})
	assert.NoError(t, scanErr)
	assert.Equal(t, 2, count)

	// Delete
	err = adapter.Delete(ctx, "entity/1")
	assert.NoError(t, err)

	// Verify deleted - Get should return QRDB NotFound error.
	data, getErr = adapter.Get(ctx, "entity/1")
	assert.Error(t, getErr)
	assert.Nil(t, data)
	assert.True(t, dberrors.IsNotFound(getErr))

	exists, existsErr = adapter.Exists(ctx, "entity/1")
	assert.NoError(t, existsErr)
	assert.False(t, exists)
}

func TestKVStoreAdapter_ClosedBackend(t *testing.T) {
	backend := storage.NewMemory()
	adapter, err := New(backend)
	require.NoError(t, err)
	ctx := context.Background()

	// Close the backend
	require.NoError(t, backend.Close())

	// All operations should return wrapped errors
	_, getErr := adapter.Get(ctx, "key1")
	assert.Error(t, getErr)

	putErr := adapter.Put(ctx, "key1", []byte("v"))
	assert.Error(t, putErr)

	deleteErr := adapter.Delete(ctx, "key1")
	assert.Error(t, deleteErr)
}
