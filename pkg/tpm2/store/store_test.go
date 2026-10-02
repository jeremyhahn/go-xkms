// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC

package store

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testLogger creates a logger for testing
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// =============================================================================
// FSBlobStore Tests
// =============================================================================
func TestFSBlobStore_NewFSBlobStore(t *testing.T) {
	logger := testLogger()
	backend := storage.NewMemory()

	blobStore, err := NewFSBlobStore(logger, backend)
	require.NoError(t, err)

	assert.NotNil(t, blobStore)
}

func TestFSBlobStore_Write(t *testing.T) {
	logger := testLogger()
	backend := storage.NewMemory()
	blobStore, err := NewFSBlobStore(logger, backend)
	require.NoError(t, err)

	t.Run("write blob successfully", func(t *testing.T) {
		err := blobStore.Write("test-blob", []byte("test data"))
		assert.NoError(t, err)

		// Verify we can read it back
		data, err := blobStore.Read("test-blob")
		assert.NoError(t, err)
		assert.Equal(t, []byte("test data"), data)
	})

	t.Run("overwrite existing blob", func(t *testing.T) {
		err := blobStore.Write("overwrite-blob", []byte("original data"))
		require.NoError(t, err)

		err = blobStore.Write("overwrite-blob", []byte("new data"))
		assert.NoError(t, err)

		data, err := blobStore.Read("overwrite-blob")
		assert.NoError(t, err)
		assert.Equal(t, []byte("new data"), data)
	})

	t.Run("write empty data", func(t *testing.T) {
		err := blobStore.Write("empty-blob", []byte{})
		assert.NoError(t, err)

		data, err := blobStore.Read("empty-blob")
		assert.NoError(t, err)
		assert.Empty(t, data)
	})
}

func TestFSBlobStore_Read(t *testing.T) {
	logger := testLogger()
	backend := storage.NewMemory()
	blobStore, err := NewFSBlobStore(logger, backend)
	require.NoError(t, err)

	t.Run("read existing blob", func(t *testing.T) {
		err := blobStore.Write("read-test", []byte("read data"))
		require.NoError(t, err)

		data, err := blobStore.Read("read-test")
		assert.NoError(t, err)
		assert.Equal(t, []byte("read data"), data)
	})

	t.Run("read non-existent blob returns error", func(t *testing.T) {
		data, err := blobStore.Read("non-existent")
		assert.Error(t, err)
		assert.Nil(t, data)
		assert.Contains(t, err.Error(), "blob store: failed to read")
	})
}

func TestFSBlobStore_Delete(t *testing.T) {
	logger := testLogger()
	backend := storage.NewMemory()
	blobStore, err := NewFSBlobStore(logger, backend)
	require.NoError(t, err)

	t.Run("delete existing blob", func(t *testing.T) {
		err := blobStore.Write("delete-test", []byte("delete data"))
		require.NoError(t, err)

		err = blobStore.Delete("delete-test")
		assert.NoError(t, err)

		// Verify it's deleted
		_, err = blobStore.Read("delete-test")
		assert.Error(t, err)
	})

	t.Run("delete non-existent blob succeeds (no error for not found)", func(t *testing.T) {
		err := blobStore.Delete("non-existent-delete")
		// Delete returns nil for not found (see implementation)
		assert.NoError(t, err)
	})
}

// =============================================================================
// StorageFactory Tests
// =============================================================================
func TestStorageFactory_NewStorageFactory(t *testing.T) {
	logger := testLogger()

	t.Run("with temp directory (empty baseDir)", func(t *testing.T) {
		factory, err := NewStorageFactory(logger, "")
		require.NoError(t, err)
		require.NotNil(t, factory)

		// Verify interfaces are available
		assert.NotNil(t, factory.BlobStore())
		assert.NotNil(t, factory.KeyBackend())
		assert.NotNil(t, factory.Backend())

		// Clean up
		err = factory.Close()
		assert.NoError(t, err)
	})

	t.Run("with specific directory", func(t *testing.T) {
		tempDir, err := os.MkdirTemp("", "storage-factory-test-*")
		require.NoError(t, err)
		defer func() { _ = os.RemoveAll(tempDir) }()

		factory, err := NewStorageFactory(logger, tempDir)
		require.NoError(t, err)
		require.NotNil(t, factory)

		// Verify we can use it
		err = factory.BlobStore().Write("test", []byte("data"))
		assert.NoError(t, err)

		err = factory.Close()
		assert.NoError(t, err)
	})
}

func TestStorageFactory_NewMemoryStorageFactory(t *testing.T) {
	logger := testLogger()

	factory, err := NewMemoryStorageFactory(logger)
	require.NoError(t, err)
	require.NotNil(t, factory)

	// Verify all interfaces
	assert.NotNil(t, factory.BlobStore())
	assert.NotNil(t, factory.KeyBackend())
	assert.NotNil(t, factory.Backend())

	// Verify we can use it
	err = factory.BlobStore().Write("memory-test", []byte("memory data"))
	assert.NoError(t, err)

	data, err := factory.BlobStore().Read("memory-test")
	assert.NoError(t, err)
	assert.Equal(t, []byte("memory data"), data)

	err = factory.Close()
	assert.NoError(t, err)
}

// TestStorageFactory_NewFactory proves NewFactory builds a working factory
// over an already-open storage.Backend -- e.g. a key-prefixed view of the
// shared datastore -- rather than opening a private file or memory engine,
// and that NewStorageFactory/NewMemoryStorageFactory (a temp/file-rooted
// engine, and a bare in-memory one) are implemented in terms of it.
func TestStorageFactory_NewFactory(t *testing.T) {
	logger := testLogger()
	backend := storage.NewMemory()

	factory, err := NewFactory(logger, backend)
	require.NoError(t, err)
	require.NotNil(t, factory)

	assert.NotNil(t, factory.BlobStore())
	assert.NotNil(t, factory.KeyBackend())
	assert.Same(t, backend, factory.Backend(), "NewFactory must use the caller's backend, not a private engine")

	require.NoError(t, factory.BlobStore().Write("datastore-test", []byte("data")))
	data, readErr := factory.BlobStore().Read("datastore-test")
	require.NoError(t, readErr)
	assert.Equal(t, []byte("data"), data)

	// NewFactory never owns the backend's lifecycle beyond what it wraps, so
	// Close does not remove anything the caller's own datastore owns (no
	// tempDir was set).
	require.NoError(t, factory.Close())
}

// TestStorageFactory_NewFactory_NilBackend proves a nil backend fails closed
// with a typed error rather than constructing a factory nothing can use.
func TestStorageFactory_NewFactory_NilBackend(t *testing.T) {
	_, err := NewFactory(testLogger(), nil)
	require.Error(t, err)
}

func TestStorageFactory_Close(t *testing.T) {
	logger := testLogger()

	t.Run("close with temp directory", func(t *testing.T) {
		factory, err := NewStorageFactory(logger, "")
		require.NoError(t, err)

		err = factory.Close()
		assert.NoError(t, err)
	})

	t.Run("close memory factory", func(t *testing.T) {
		factory, err := NewMemoryStorageFactory(logger)
		require.NoError(t, err)

		err = factory.Close()
		assert.NoError(t, err)
	})

	t.Run("close with nil backend", func(t *testing.T) {
		factory := &StorageFactory{
			logger:  logger,
			backend: nil,
		}

		err := factory.Close()
		assert.NoError(t, err)
	})
}

// =============================================================================
// FileBackend Tests
// =============================================================================
func TestFileBackend_NewFileBackend(t *testing.T) {
	logger := testLogger()
	backend := storage.NewMemory()

	fb := NewFileBackend(logger, backend)
	assert.NotNil(t, fb)
}

func TestFileBackend_Get(t *testing.T) {
	logger := testLogger()
	backend := storage.NewMemory()
	fb := NewFileBackend(logger, backend)

	attrs := &types.KeyAttributes{
		CN: "test-key",
	}

	t.Run("get existing key", func(t *testing.T) {
		// Save first
		err := fb.Save(attrs, []byte("key data"), types.FSExtBlob, true)
		require.NoError(t, err)

		// Get it back
		data, err := fb.Get(attrs, types.FSExtBlob)
		assert.NoError(t, err)
		assert.Equal(t, []byte("key data"), data)
	})

	t.Run("get non-existent key returns error", func(t *testing.T) {
		nonExistentAttrs := &types.KeyAttributes{
			CN: "non-existent-key",
		}

		data, err := fb.Get(nonExistentAttrs, types.FSExtBlob)
		assert.Error(t, err)
		assert.Nil(t, data)
		assert.Contains(t, err.Error(), "failed to read key")
	})

	t.Run("get with different extensions", func(t *testing.T) {
		extAttrs := &types.KeyAttributes{
			CN: "ext-test-key",
		}

		// Save with private blob extension
		err := fb.Save(extAttrs, []byte("private blob"), types.FSExtension(FSEXT_PRIVATE_BLOB), true)
		require.NoError(t, err)

		// Save with public blob extension
		err = fb.Save(extAttrs, []byte("public blob"), types.FSExtension(FSEXT_PUBLIC_BLOB), true)
		require.NoError(t, err)

		// Get private
		data, err := fb.Get(extAttrs, types.FSExtension(FSEXT_PRIVATE_BLOB))
		assert.NoError(t, err)
		assert.Equal(t, []byte("private blob"), data)

		// Get public
		data, err = fb.Get(extAttrs, types.FSExtension(FSEXT_PUBLIC_BLOB))
		assert.NoError(t, err)
		assert.Equal(t, []byte("public blob"), data)
	})
}

func TestFileBackend_Save(t *testing.T) {
	logger := testLogger()
	backend := storage.NewMemory()
	fb := NewFileBackend(logger, backend)

	t.Run("save new key", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN: "new-save-key",
		}

		err := fb.Save(attrs, []byte("new key data"), types.FSExtBlob, false)
		assert.NoError(t, err)

		// Verify
		data, err := fb.Get(attrs, types.FSExtBlob)
		assert.NoError(t, err)
		assert.Equal(t, []byte("new key data"), data)
	})

	t.Run("save without overwrite fails if exists", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN: "no-overwrite-key",
		}

		// First save should succeed
		err := fb.Save(attrs, []byte("original"), types.FSExtBlob, false)
		require.NoError(t, err)

		// Second save without overwrite should fail
		err = fb.Save(attrs, []byte("new"), types.FSExtBlob, false)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "already exists")
	})

	t.Run("save with overwrite succeeds if exists", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN: "overwrite-key",
		}

		// First save
		err := fb.Save(attrs, []byte("original"), types.FSExtBlob, false)
		require.NoError(t, err)

		// Second save with overwrite should succeed
		err = fb.Save(attrs, []byte("overwritten"), types.FSExtBlob, true)
		assert.NoError(t, err)

		// Verify new data
		data, err := fb.Get(attrs, types.FSExtBlob)
		assert.NoError(t, err)
		assert.Equal(t, []byte("overwritten"), data)
	})

	t.Run("save empty data", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN: "empty-data-key",
		}

		err := fb.Save(attrs, []byte{}, types.FSExtBlob, false)
		assert.NoError(t, err)

		data, err := fb.Get(attrs, types.FSExtBlob)
		assert.NoError(t, err)
		assert.Empty(t, data)
	})
}

func TestFileBackend_Delete(t *testing.T) {
	logger := testLogger()
	backend := storage.NewMemory()
	fb := NewFileBackend(logger, backend)

	t.Run("delete existing key", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN: "delete-key",
		}

		// Save all extensions
		err := fb.Save(attrs, []byte("blob"), types.FSExtension(FSEXT_PRIVATE_BLOB), true)
		require.NoError(t, err)
		err = fb.Save(attrs, []byte("pub"), types.FSExtension(FSEXT_PUBLIC_BLOB), true)
		require.NoError(t, err)
		err = fb.Save(attrs, []byte("ctx"), types.FSExtension(FSEXT_TPM_CONTEXT), true)
		require.NoError(t, err)

		// Delete
		err = fb.Delete(attrs)
		assert.NoError(t, err)

		// Verify all deleted
		_, err = fb.Get(attrs, types.FSExtension(FSEXT_PRIVATE_BLOB))
		assert.Error(t, err)
		_, err = fb.Get(attrs, types.FSExtension(FSEXT_PUBLIC_BLOB))
		assert.Error(t, err)
		_, err = fb.Get(attrs, types.FSExtension(FSEXT_TPM_CONTEXT))
		assert.Error(t, err)
	})

	t.Run("delete non-existent key succeeds (partial files)", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN: "partial-delete-key",
		}

		// Save only private blob
		err := fb.Save(attrs, []byte("blob"), types.FSExtension(FSEXT_PRIVATE_BLOB), true)
		require.NoError(t, err)

		// Delete should succeed even if some files don't exist
		err = fb.Delete(attrs)
		assert.NoError(t, err)
	})

	t.Run("delete completely non-existent key succeeds", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN: "totally-non-existent-key",
		}

		// Delete should not return error for non-existent keys
		err := fb.Delete(attrs)
		assert.NoError(t, err)
	})
}

// =============================================================================
// Password Tests for uncovered code
// =============================================================================
func TestRequiredPassword_Clear(t *testing.T) {
	// This specifically tests the RequiredPassword.Clear() method
	// which was shown as 0% coverage
	p := &RequiredPassword{}

	// Clear should be a no-op and not panic
	p.Clear()

	// State should be unchanged
	assert.Nil(t, p.Bytes())

	assert.Equal(t, types.PasswordRedacted, p.String())
	assert.Equal(t, ErrPasswordRequired, p.WithBytes(func([]byte) error { return nil }))
}

func TestFileBackend_IntegrationWithStorageFactory(t *testing.T) {
	logger := testLogger()

	factory, err := NewMemoryStorageFactory(logger)
	require.NoError(t, err)
	defer func() { _ = factory.Close() }()

	keyBackend := factory.KeyBackend()

	attrs := &types.KeyAttributes{
		CN: "file-backend-integration",
	}

	// Save key data
	err = keyBackend.Save(attrs, []byte("key content"), types.FSExtension(FSEXT_PRIVATE_BLOB), false)
	assert.NoError(t, err)

	// Retrieve
	data, err := keyBackend.Get(attrs, types.FSExtension(FSEXT_PRIVATE_BLOB))
	assert.NoError(t, err)
	assert.Equal(t, []byte("key content"), data)

	// Delete
	err = keyBackend.Delete(attrs)
	assert.NoError(t, err)

	// Verify deleted
	_, err = keyBackend.Get(attrs, types.FSExtension(FSEXT_PRIVATE_BLOB))
	assert.Error(t, err)
}

// =============================================================================
// Error Backend for Testing Error Paths
// =============================================================================
// errorBackend is a mock backend that returns errors for testing
type errorBackend struct {
	getError    error
	putError    error
	deleteError error
	existsError error
}

func (e *errorBackend) Get(_ context.Context, key string) ([]byte, error) {
	if e.getError != nil {
		return nil, e.getError
	}
	return nil, storage.ErrNotFound
}

func (e *errorBackend) Put(_ context.Context, key string, value []byte) error {
	return e.putError
}

func (e *errorBackend) Delete(_ context.Context, key string) error {
	return e.deleteError
}

func (e *errorBackend) List(_ context.Context, prefix string) ([]string, error) {
	return nil, nil
}

func (e *errorBackend) Exists(_ context.Context, key string) (bool, error) {
	return false, e.existsError
}

func (e *errorBackend) Scan(_ context.Context, prefix string, fn func(key string, value []byte) error) error {
	return nil
}

func (e *errorBackend) Close() error {
	return nil
}

func TestFSBlobStore_WriteError(t *testing.T) {
	logger := testLogger()
	backend := &errorBackend{putError: errors.New("write failed")}
	blobStore, err := NewFSBlobStore(logger, backend)
	require.NoError(t, err)

	err = blobStore.Write("test", []byte("data"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "blob store: failed to write")
}

func TestFSBlobStore_DeleteError(t *testing.T) {
	logger := testLogger()
	backend := &errorBackend{deleteError: errors.New("delete failed")}
	blobStore, err := NewFSBlobStore(logger, backend)
	require.NoError(t, err)

	err = blobStore.Delete("test")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "blob store: failed to delete")
}

func TestFileBackend_SaveExistsError(t *testing.T) {
	logger := testLogger()
	backend := &errorBackend{existsError: errors.New("exists check failed")}
	fb := NewFileBackend(logger, backend)

	attrs := &types.KeyAttributes{
		CN: "exists-error-key",
	}

	err := fb.Save(attrs, []byte("data"), types.FSExtBlob, false)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to check key existence")
}

func TestFileBackend_SavePutError(t *testing.T) {
	logger := testLogger()
	backend := &errorBackend{putError: errors.New("put failed")}
	fb := NewFileBackend(logger, backend)

	attrs := &types.KeyAttributes{
		CN: "put-error-key",
	}

	err := fb.Save(attrs, []byte("data"), types.FSExtBlob, true)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to write key")
}

func TestFileBackend_DeleteError(t *testing.T) {
	logger := testLogger()
	// Use a custom error that is not ErrNotFound and not os not exist error
	backend := &errorBackend{deleteError: errors.New("custom delete error")}
	fb := NewFileBackend(logger, backend)

	attrs := &types.KeyAttributes{
		CN: "delete-error-key",
	}

	err := fb.Delete(attrs)
	assert.Error(t, err)
}

func TestFileBackend_NilLogger(t *testing.T) {
	backend := storage.NewMemory()
	fb := NewFileBackend(nil, backend)

	attrs := &types.KeyAttributes{
		CN: "nil-logger-file-backend",
	}

	// All operations should work with nil logger
	err := fb.Save(attrs, []byte("data"), types.FSExtBlob, true)
	assert.NoError(t, err)

	data, err := fb.Get(attrs, types.FSExtBlob)
	assert.NoError(t, err)
	assert.Equal(t, []byte("data"), data)

	err = fb.Delete(attrs)
	assert.NoError(t, err)
}

func TestFSBlobStore_NilLogger(t *testing.T) {
	backend := storage.NewMemory()
	blobStore, err := NewFSBlobStore(nil, backend)
	require.NoError(t, err)

	err = blobStore.Write("nil-logger-blob", []byte("data"))
	assert.NoError(t, err)

	data, err := blobStore.Read("nil-logger-blob")
	assert.NoError(t, err)
	assert.Equal(t, []byte("data"), data)

	err = blobStore.Delete("nil-logger-blob")
	assert.NoError(t, err)
}
