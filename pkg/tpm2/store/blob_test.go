// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC

package store

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/dao"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

var errInjected = errors.New("injected store failure")

// testLogger returns a logger that discards its output.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// newTestBlobStore returns a system-tenant BlobStore over a fresh memory
// store.
func newTestBlobStore(t *testing.T) *BlobStore {
	t.Helper()
	blobs, err := NewBlobStore(testLogger(), dao.NewStoreFactory(qrdbsdk.NewMemoryKVStore()))
	require.NoError(t, err)
	return blobs
}

// failingKV is an atomic KVStore whose reads, writes and scans fail with
// errInjected once broken is set.
type failingKV struct {
	qrdbsdk.AtomicKVStore
	broken bool
}

func (f *failingKV) Get(ctx context.Context, key string) ([]byte, error) {
	if f.broken {
		return nil, errInjected
	}
	return f.AtomicKVStore.Get(ctx, key)
}

func (f *failingKV) Put(ctx context.Context, key string, value []byte) error {
	if f.broken {
		return errInjected
	}
	return f.AtomicKVStore.Put(ctx, key, value)
}

func (f *failingKV) PutIfAbsent(ctx context.Context, key string, value []byte) (bool, error) {
	if f.broken {
		return false, errInjected
	}
	return f.AtomicKVStore.PutIfAbsent(ctx, key, value)
}

func (f *failingKV) CompareAndSwap(ctx context.Context, key string, expected, next []byte) (bool, error) {
	if f.broken {
		return false, errInjected
	}
	return f.AtomicKVStore.CompareAndSwap(ctx, key, expected, next)
}

func (f *failingKV) Scan(ctx context.Context, prefix string, fn func(string, []byte) error) error {
	if f.broken {
		return errInjected
	}
	return f.AtomicKVStore.Scan(ctx, prefix, fn)
}

func (f *failingKV) List(ctx context.Context, prefix string) ([]string, error) {
	if f.broken {
		return nil, errInjected
	}
	return f.AtomicKVStore.List(ctx, prefix)
}

// nonAtomicKV hides the atomic writes of the store it wraps.
type nonAtomicKV struct {
	qrdbsdk.KVStore
}

// newFailingBlobStore returns a BlobStore over a failingKV.
func newFailingBlobStore(t *testing.T) (*BlobStore, *failingKV) {
	t.Helper()
	kv := &failingKV{AtomicKVStore: qrdbsdk.NewMemoryKVStore()}
	blobs, err := NewBlobStore(testLogger(), dao.NewStoreFactory(kv))
	require.NoError(t, err)
	return blobs, kv
}

func TestNewBlobStore(t *testing.T) {
	t.Run("serves the system tenant", func(t *testing.T) {
		blobs := newTestBlobStore(t)
		assert.Equal(t, SystemTenant, blobs.TenantID())
	})

	t.Run("nil logger falls back to the default logger", func(t *testing.T) {
		blobs, err := NewBlobStore(nil, dao.NewStoreFactory(qrdbsdk.NewMemoryKVStore()))
		require.NoError(t, err)
		assert.NotNil(t, blobs.logger)
	})

	t.Run("nil factory is refused", func(t *testing.T) {
		_, err := NewBlobStore(testLogger(), nil)
		assert.ErrorIs(t, err, ErrNilDAOFactory)
	})

	t.Run("factory without the tpm2 database is refused", func(t *testing.T) {
		kv := qrdbsdk.NewMemoryKVStore()
		daos := qrdbsdk.NewDAOFactoryWithConfig(&qrdbsdk.DAOFactoryConfig{
			KVStoreProvider: func(uint64) qrdbsdk.KVStore { return kv },
		})
		_, err := NewBlobStore(testLogger(), daos)
		var createErr *BlobStoreCreateError
		require.ErrorAs(t, err, &createErr)
		var unavailable *dao.DatabaseUnavailableError
		require.ErrorAs(t, err, &unavailable)
		assert.Equal(t, DatabaseName, unavailable.Database)
	})
}

func TestBlobStore_Tenant(t *testing.T) {
	blobs := newTestBlobStore(t)
	attrs := &types.KeyAttributes{CN: "shared-cn"}

	acme, err := blobs.Tenant("acme")
	require.NoError(t, err)
	assert.Equal(t, "acme", acme.TenantID())

	t.Run("tenants with the same CN do not collide", func(t *testing.T) {
		require.NoError(t, blobs.Save(attrs, []byte("system"), FSEXT_PRIVATE_BLOB, false))
		require.NoError(t, acme.Save(attrs, []byte("acme"), FSEXT_PRIVATE_BLOB, false))

		got, err := blobs.Get(attrs, FSEXT_PRIVATE_BLOB)
		require.NoError(t, err)
		assert.Equal(t, []byte("system"), got)
		got, err = acme.Get(attrs, FSEXT_PRIVATE_BLOB)
		require.NoError(t, err)
		assert.Equal(t, []byte("acme"), got)
	})

	t.Run("the empty tenant is the system tenant", func(t *testing.T) {
		system, err := acme.Tenant("")
		require.NoError(t, err)
		got, err := system.Get(attrs, FSEXT_PRIVATE_BLOB)
		require.NoError(t, err)
		assert.Equal(t, []byte("system"), got)
	})

	t.Run("an invalid tenant is refused", func(t *testing.T) {
		for _, tenant := range []string{"a/b", "..", "bad\x00tenant"} {
			_, err := blobs.Tenant(tenant)
			var keyErr *InvalidBlobKeyError
			require.ErrorAs(t, err, &keyErr, tenant)
			assert.Equal(t, "tenant", keyErr.Field)
		}
	})
}

func TestBlobStore_GetSave(t *testing.T) {
	blobs := newTestBlobStore(t)
	attrs := &types.KeyAttributes{CN: "edge-001"}

	t.Run("a blob that was never stored is not found", func(t *testing.T) {
		_, err := blobs.Get(attrs, FSEXT_PUBLIC_BLOB)
		var readErr *BlobReadError
		require.ErrorAs(t, err, &readErr)
		assert.ErrorIs(t, err, ErrBlobNotFound)
		assert.Equal(t, "system/edge-001/.pub", readErr.Name)
	})

	t.Run("save then get round-trips", func(t *testing.T) {
		require.NoError(t, blobs.Save(attrs, []byte("public"), FSEXT_PUBLIC_BLOB, false))
		got, err := blobs.Get(attrs, FSEXT_PUBLIC_BLOB)
		require.NoError(t, err)
		assert.Equal(t, []byte("public"), got)
	})

	t.Run("save without overwrite keeps the stored blob", func(t *testing.T) {
		err := blobs.Save(attrs, []byte("replacement"), FSEXT_PUBLIC_BLOB, false)
		var writeErr *BlobWriteError
		require.ErrorAs(t, err, &writeErr)
		assert.ErrorIs(t, err, ErrBlobExists)

		got, err := blobs.Get(attrs, FSEXT_PUBLIC_BLOB)
		require.NoError(t, err)
		assert.Equal(t, []byte("public"), got)
	})

	t.Run("save with overwrite replaces the stored blob", func(t *testing.T) {
		require.NoError(t, blobs.Save(attrs, []byte("replacement"), FSEXT_PUBLIC_BLOB, true))
		got, err := blobs.Get(attrs, FSEXT_PUBLIC_BLOB)
		require.NoError(t, err)
		assert.Equal(t, []byte("replacement"), got)
	})

	t.Run("extensions of one key are distinct blobs", func(t *testing.T) {
		require.NoError(t, blobs.Save(attrs, []byte("private"), FSEXT_PRIVATE_BLOB, false))
		got, err := blobs.Get(attrs, FSEXT_PRIVATE_BLOB)
		require.NoError(t, err)
		assert.Equal(t, []byte("private"), got)
	})

	t.Run("a CN holding a path separator is one name", func(t *testing.T) {
		nested := &types.KeyAttributes{CN: "parent/child"}
		require.NoError(t, blobs.Save(nested, []byte("nested"), FSEXT_PRIVATE_BLOB, false))
		got, err := blobs.Get(nested, FSEXT_PRIVATE_BLOB)
		require.NoError(t, err)
		assert.Equal(t, []byte("nested"), got)
	})
}

func TestBlobStore_InvalidKeys(t *testing.T) {
	blobs := newTestBlobStore(t)

	t.Run("nil attributes and an empty CN are refused on every path", func(t *testing.T) {
		for _, attrs := range []*types.KeyAttributes{nil, {}} {
			_, err := blobs.Get(attrs, FSEXT_PRIVATE_BLOB)
			assert.ErrorIs(t, err, ErrEmptyKeyCN)
			assert.ErrorIs(t, blobs.Save(attrs, []byte("x"), FSEXT_PRIVATE_BLOB, true), ErrEmptyKeyCN)
			assert.ErrorIs(t, blobs.Delete(attrs), ErrEmptyKeyCN)
		}
	})

	t.Run("a CN holding NUL is refused", func(t *testing.T) {
		err := blobs.Save(&types.KeyAttributes{CN: "bad\x00cn"}, []byte("x"), FSEXT_PRIVATE_BLOB, true)
		var keyErr *InvalidBlobKeyError
		require.ErrorAs(t, err, &keyErr)
		assert.Equal(t, "name", keyErr.Field)
	})

	t.Run("an empty or nested extension is refused", func(t *testing.T) {
		attrs := &types.KeyAttributes{CN: "key"}
		for _, ext := range []types.FSExtension{"", "a/.blob", ".bl\x00b"} {
			_, err := blobs.Get(attrs, ext)
			var keyErr *InvalidBlobKeyError
			require.ErrorAs(t, err, &keyErr, ext)
			assert.Equal(t, "extension", keyErr.Field)
		}
	})
}

func TestBlobStore_Delete(t *testing.T) {
	t.Run("removes every key blob and keeps the certificate", func(t *testing.T) {
		blobs := newTestBlobStore(t)
		attrs := &types.KeyAttributes{CN: "doomed"}
		for _, ext := range blobExtensions {
			require.NoError(t, blobs.Save(attrs, []byte(ext), types.FSExtension(ext), false))
		}
		require.NoError(t, blobs.Save(attrs, []byte("cert"), FSEXT_CERTIFICATE, false))
		other := &types.KeyAttributes{CN: "survivor"}
		require.NoError(t, blobs.Save(other, []byte("kept"), FSEXT_PRIVATE_BLOB, false))

		require.NoError(t, blobs.Delete(attrs))

		for _, ext := range blobExtensions {
			_, err := blobs.Get(attrs, types.FSExtension(ext))
			assert.ErrorIs(t, err, ErrBlobNotFound, ext)
		}
		_, err := blobs.Get(attrs, FSEXT_CERTIFICATE)
		assert.NoError(t, err)
		_, err = blobs.Get(other, FSEXT_PRIVATE_BLOB)
		assert.NoError(t, err)
	})

	t.Run("a key with no blobs deletes cleanly", func(t *testing.T) {
		assert.NoError(t, newTestBlobStore(t).Delete(&types.KeyAttributes{CN: "never-stored"}))
	})

	t.Run("a store failure is reported", func(t *testing.T) {
		blobs, kv := newFailingBlobStore(t)
		kv.broken = true
		err := blobs.Delete(&types.KeyAttributes{CN: "key"})
		var deleteErr *BlobDeleteError
		require.ErrorAs(t, err, &deleteErr)
		assert.ErrorIs(t, err, errInjected)
	})
}

func TestBlobStore_KeyNames(t *testing.T) {
	t.Run("lists the tenant's objects with the extension, sorted", func(t *testing.T) {
		blobs := newTestBlobStore(t)
		acme, err := blobs.Tenant("acme")
		require.NoError(t, err)
		for _, cn := range []string{"zeta", "alpha", "parent/child"} {
			require.NoError(t, blobs.Save(&types.KeyAttributes{CN: cn}, []byte(cn), FSEXT_PRIVATE_BLOB, false))
		}
		require.NoError(t, blobs.Save(&types.KeyAttributes{CN: "public-only"}, []byte("p"), FSEXT_PUBLIC_BLOB, false))
		require.NoError(t, acme.Save(&types.KeyAttributes{CN: "tenant-key"}, []byte("t"), FSEXT_PRIVATE_BLOB, false))

		names, err := blobs.KeyNames(t.Context(), FSEXT_PRIVATE_BLOB)
		require.NoError(t, err)
		assert.Equal(t, []string{"alpha", "parent/child", "zeta"}, names)

		names, err = acme.KeyNames(t.Context(), FSEXT_PRIVATE_BLOB)
		require.NoError(t, err)
		assert.Equal(t, []string{"tenant-key"}, names)
	})

	t.Run("an empty store lists nothing", func(t *testing.T) {
		names, err := newTestBlobStore(t).KeyNames(t.Context(), FSEXT_PRIVATE_BLOB)
		require.NoError(t, err)
		assert.Empty(t, names)
	})

	t.Run("a store failure is reported", func(t *testing.T) {
		blobs, kv := newFailingBlobStore(t)
		require.NoError(t, blobs.Save(&types.KeyAttributes{CN: "key"}, []byte("x"), FSEXT_PRIVATE_BLOB, true))
		kv.broken = true
		_, err := blobs.KeyNames(t.Context(), FSEXT_PRIVATE_BLOB)
		var listErr *BlobListError
		require.ErrorAs(t, err, &listErr)
		assert.ErrorIs(t, err, errInjected)
	})
}

func TestBlobStore_StoreFailures(t *testing.T) {
	attrs := &types.KeyAttributes{CN: "key"}

	t.Run("a read failure is not reported as not found", func(t *testing.T) {
		blobs, kv := newFailingBlobStore(t)
		kv.broken = true
		_, err := blobs.Get(attrs, FSEXT_PRIVATE_BLOB)
		var readErr *BlobReadError
		require.ErrorAs(t, err, &readErr)
		assert.ErrorIs(t, err, errInjected)
		assert.NotErrorIs(t, err, ErrBlobNotFound)
	})

	t.Run("a write failure is reported", func(t *testing.T) {
		blobs, kv := newFailingBlobStore(t)
		kv.broken = true
		for _, overwrite := range []bool{true, false} {
			err := blobs.Save(attrs, []byte("x"), FSEXT_PRIVATE_BLOB, overwrite)
			var writeErr *BlobWriteError
			require.ErrorAs(t, err, &writeErr, "overwrite=%v", overwrite)
			assert.ErrorIs(t, err, errInjected, "overwrite=%v", overwrite)
		}
	})

	t.Run("a store without atomic writes refuses a save that may not overwrite", func(t *testing.T) {
		blobs, err := NewBlobStore(testLogger(), dao.NewStoreFactory(&nonAtomicKV{KVStore: qrdbsdk.NewMemoryKVStore()}))
		require.NoError(t, err)
		err = blobs.Save(attrs, []byte("x"), FSEXT_PRIVATE_BLOB, false)
		var writeErr *BlobWriteError
		require.ErrorAs(t, err, &writeErr)
		assert.ErrorIs(t, err, qrdbsdk.ErrKVAtomicWriteUnsupported)
	})
}
