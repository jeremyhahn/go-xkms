// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC

package store

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

func TestNewStorageFactory(t *testing.T) {
	attrs := &types.KeyAttributes{CN: "persisted"}

	t.Run("blobs persist in the directory across reopen", func(t *testing.T) {
		dir := t.TempDir()
		factory, err := NewStorageFactory(testLogger(), dir)
		require.NoError(t, err)
		require.NoError(t, factory.KeyBackend().Save(attrs, []byte("blob"), FSEXT_PRIVATE_BLOB, false))
		require.NoError(t, factory.Close())

		reopened, err := NewStorageFactory(testLogger(), dir)
		require.NoError(t, err)
		t.Cleanup(func() { assert.NoError(t, reopened.Close()) })
		got, err := reopened.KeyBackend().Get(attrs, FSEXT_PRIVATE_BLOB)
		require.NoError(t, err)
		assert.Equal(t, []byte("blob"), got)
	})

	t.Run("an empty directory is a temporary one removed on close", func(t *testing.T) {
		factory, err := NewStorageFactory(nil, "")
		require.NoError(t, err)
		tempDir := factory.tempDir
		require.DirExists(t, tempDir)
		require.NoError(t, factory.KeyBackend().Save(attrs, []byte("blob"), FSEXT_PRIVATE_BLOB, false))

		require.NoError(t, factory.Close())
		assert.NoDirExists(t, tempDir)
	})

	t.Run("a directory that cannot be opened is refused", func(t *testing.T) {
		notDir := filepath.Join(t.TempDir(), "file")
		require.NoError(t, os.WriteFile(notDir, []byte("x"), 0o600))

		_, err := NewStorageFactory(testLogger(), filepath.Join(notDir, "tpm"))
		var createErr *BlobStoreCreateError
		assert.ErrorAs(t, err, &createErr)
	})
}

func TestNewBackendBlobStore(t *testing.T) {
	t.Run("blobs are stored in the backend", func(t *testing.T) {
		backend := storage.New()
		blobs, err := NewBackendBlobStore(testLogger(), backend)
		require.NoError(t, err)
		attrs := &types.KeyAttributes{CN: "backend"}
		require.NoError(t, blobs.Save(attrs, []byte("blob"), FSEXT_PRIVATE_BLOB, false))

		reopened, err := NewBackendBlobStore(testLogger(), backend)
		require.NoError(t, err)
		got, err := reopened.Get(attrs, FSEXT_PRIVATE_BLOB)
		require.NoError(t, err)
		assert.Equal(t, []byte("blob"), got)
	})

	t.Run("a nil backend is refused", func(t *testing.T) {
		_, err := NewBackendBlobStore(testLogger(), nil)
		var createErr *BlobStoreCreateError
		assert.ErrorAs(t, err, &createErr)
	})
}

func TestNewMemoryStorageFactory(t *testing.T) {
	factory, err := NewMemoryStorageFactory(testLogger())
	require.NoError(t, err)
	attrs := &types.KeyAttributes{CN: "memory"}

	require.NoError(t, factory.KeyBackend().Save(attrs, []byte("blob"), FSEXT_PUBLIC_BLOB, false))
	got, err := factory.KeyBackend().Get(attrs, FSEXT_PUBLIC_BLOB)
	require.NoError(t, err)
	assert.Equal(t, []byte("blob"), got)

	assert.NoError(t, factory.Close())
	assert.NoError(t, factory.Close(), "closing a memory factory twice is harmless")
}
