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

package seal

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// newTestPlatformStore creates a SealedPlatformStore backed by an in-memory
// storage backend for unit testing. Uses a plain MemoryBackend so no sealer
// is required; values are stored and retrieved as-is.
func newTestPlatformStore(t *testing.T) *SealedPlatformStore {
	t.Helper()
	backend, err := storage.NewMemoryBackend()
	require.NoError(t, err)
	store, err := NewPlatformStore(backend, nil)
	require.NoError(t, err)
	return store
}

func TestNewPlatformStore_Success(t *testing.T) {
	backend, err := storage.NewMemoryBackend()
	require.NoError(t, err)

	store, err := NewPlatformStore(backend, nil)
	require.NoError(t, err)
	assert.NotNil(t, store)
	assert.NotNil(t, store.logger)
	assert.Equal(t, backend, store.backend)
}

func TestNewPlatformStore_NilBackend(t *testing.T) {
	store, err := NewPlatformStore(nil, nil)
	require.ErrorIs(t, err, ErrNilSealedBackend)
	assert.Nil(t, store)
}

func TestPlatformStore_PutGet_Roundtrip(t *testing.T) {
	store := newTestPlatformStore(t)
	ctx := context.Background()
	secret := []byte("super-secret-value")

	err := store.Put(ctx, "test/roundtrip", secret)
	require.NoError(t, err)

	got, err := store.Get(ctx, "test/roundtrip")
	require.NoError(t, err)
	assert.Equal(t, secret, got)
}

func TestPlatformStore_PutGet_WellKnownSecrets(t *testing.T) {
	store := newTestPlatformStore(t)
	ctx := context.Background()

	secrets := map[string][]byte{
		SecretUserPIN:        []byte("1234"),
		SecretLUKSPassphrase: []byte("correct-horse-battery-staple"),
		SecretPKCS11PIN:      []byte("pkcs11-user-pin"),
		SecretTPM2Auth:       []byte("tpm2-owner-auth"),
	}

	for name, value := range secrets {
		err := store.Put(ctx, name, value)
		require.NoError(t, err, "put %s", name)
	}

	for name, expected := range secrets {
		got, err := store.Get(ctx, name)
		require.NoError(t, err, "get %s", name)
		assert.Equal(t, expected, got, "value mismatch for %s", name)
	}
}

func TestPlatformStore_Put_InvalidName(t *testing.T) {
	store := newTestPlatformStore(t)
	ctx := context.Background()

	tests := []struct {
		name string
		desc string
	}{
		{name: "", desc: "empty string"},
		{name: "   ", desc: "whitespace only"},
		{name: "\t\n", desc: "tab and newline"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			err := store.Put(ctx, tt.name, []byte("value"))
			require.ErrorIs(t, err, ErrInvalidSecretName)
		})
	}
}

func TestPlatformStore_Get_NotFound(t *testing.T) {
	store := newTestPlatformStore(t)
	ctx := context.Background()

	got, err := store.Get(ctx, "does-not-exist")
	require.ErrorIs(t, err, ErrSecretNotFound)
	assert.Nil(t, got)
}

func TestPlatformStore_Get_InvalidName(t *testing.T) {
	store := newTestPlatformStore(t)
	ctx := context.Background()

	tests := []struct {
		name string
		desc string
	}{
		{name: "", desc: "empty string"},
		{name: "   ", desc: "whitespace only"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			got, err := store.Get(ctx, tt.name)
			require.ErrorIs(t, err, ErrInvalidSecretName)
			assert.Nil(t, got)
		})
	}
}

func TestPlatformStore_Delete_Success(t *testing.T) {
	store := newTestPlatformStore(t)
	ctx := context.Background()

	err := store.Put(ctx, "to-delete", []byte("ephemeral"))
	require.NoError(t, err)

	err = store.Delete(ctx, "to-delete")
	require.NoError(t, err)

	exists, err := store.Exists(ctx, "to-delete")
	require.NoError(t, err)
	assert.False(t, exists)
}

func TestPlatformStore_Delete_NotFound(t *testing.T) {
	store := newTestPlatformStore(t)
	ctx := context.Background()

	err := store.Delete(ctx, "nonexistent")
	require.ErrorIs(t, err, ErrSecretNotFound)
}

func TestPlatformStore_Delete_InvalidName(t *testing.T) {
	store := newTestPlatformStore(t)
	ctx := context.Background()

	err := store.Delete(ctx, "")
	require.ErrorIs(t, err, ErrInvalidSecretName)
}

func TestPlatformStore_Exists_True(t *testing.T) {
	store := newTestPlatformStore(t)
	ctx := context.Background()

	err := store.Put(ctx, "check-exists", []byte("present"))
	require.NoError(t, err)

	exists, err := store.Exists(ctx, "check-exists")
	require.NoError(t, err)
	assert.True(t, exists)
}

func TestPlatformStore_Exists_False(t *testing.T) {
	store := newTestPlatformStore(t)
	ctx := context.Background()

	exists, err := store.Exists(ctx, "never-stored")
	require.NoError(t, err)
	assert.False(t, exists)
}

func TestPlatformStore_Exists_InvalidName(t *testing.T) {
	store := newTestPlatformStore(t)
	ctx := context.Background()

	exists, err := store.Exists(ctx, "")
	require.ErrorIs(t, err, ErrInvalidSecretName)
	assert.False(t, exists)
}

func TestPlatformStore_List_Empty(t *testing.T) {
	store := newTestPlatformStore(t)
	ctx := context.Background()

	names, err := store.List(ctx)
	require.NoError(t, err)
	assert.Empty(t, names)
}

func TestPlatformStore_List_Multiple(t *testing.T) {
	store := newTestPlatformStore(t)
	ctx := context.Background()

	keys := []string{"alpha", "beta", "gamma"}
	for _, k := range keys {
		err := store.Put(ctx, k, []byte("val-"+k))
		require.NoError(t, err)
	}

	names, err := store.List(ctx)
	require.NoError(t, err)
	assert.Len(t, names, 3)
	// MemoryBackend returns sorted keys; prefix is stripped.
	assert.Equal(t, []string{"alpha", "beta", "gamma"}, names)
}

func TestPlatformStore_List_PrefixIsolation(t *testing.T) {
	// Verify that secrets stored via PlatformStore are namespace-isolated
	// from other data written directly to the same backend.
	backend, err := storage.NewMemoryBackend()
	require.NoError(t, err)

	store, err := NewPlatformStore(backend, nil)
	require.NoError(t, err)

	ctx := context.Background()

	// Store a secret via PlatformStore.
	err = store.Put(ctx, "my-secret", []byte("hidden"))
	require.NoError(t, err)

	// Store a value directly in the backend without the prefix.
	err = backend.Put(ctx, "unrelated-key", []byte("visible"))
	require.NoError(t, err)

	// List should only return the platform store secret.
	names, err := store.List(ctx)
	require.NoError(t, err)
	assert.Equal(t, []string{"my-secret"}, names)
}

func TestPlatformStore_Reseal_Success(t *testing.T) {
	store := newTestPlatformStore(t)
	ctx := context.Background()
	secret := []byte("resealable-secret")

	err := store.Put(ctx, "reseal-me", secret)
	require.NoError(t, err)

	err = store.Reseal(ctx, "reseal-me")
	require.NoError(t, err)

	// Verify the secret is still retrievable after reseal.
	got, err := store.Get(ctx, "reseal-me")
	require.NoError(t, err)
	assert.Equal(t, secret, got)
}

func TestPlatformStore_Reseal_NotFound(t *testing.T) {
	store := newTestPlatformStore(t)
	ctx := context.Background()

	err := store.Reseal(ctx, "ghost")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrResealFailed))
	assert.True(t, errors.Is(err, ErrSecretNotFound))
}

func TestPlatformStore_Reseal_InvalidName(t *testing.T) {
	store := newTestPlatformStore(t)
	ctx := context.Background()

	err := store.Reseal(ctx, "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrResealFailed))
	assert.True(t, errors.Is(err, ErrInvalidSecretName))
}

func TestPlatformStore_Put_Overwrite(t *testing.T) {
	store := newTestPlatformStore(t)
	ctx := context.Background()

	err := store.Put(ctx, "overwrite-key", []byte("first"))
	require.NoError(t, err)

	err = store.Put(ctx, "overwrite-key", []byte("second"))
	require.NoError(t, err)

	got, err := store.Get(ctx, "overwrite-key")
	require.NoError(t, err)
	assert.Equal(t, []byte("second"), got)
}

func TestPlatformStoreInterface(t *testing.T) {
	// Compile-time check that SealedPlatformStore satisfies PlatformStore.
	var _ PlatformStore = (*SealedPlatformStore)(nil)
}

// --- Backend error path tests ---

// TestPlatformStore_Put_BackendError verifies that Put propagates the
// underlying backend error when the storage Put call fails.
func TestPlatformStore_Put_BackendError(t *testing.T) {
	putErr := errors.New("disk full")
	backend := &errBackend{putErr: putErr}
	store, err := NewPlatformStore(backend, nil)
	require.NoError(t, err)

	err = store.Put(context.Background(), "valid-name", []byte("data"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "disk full")
}

// TestPlatformStore_Get_BackendError verifies that Get propagates a
// non-ErrNotFound backend error as a wrapped seal error.
func TestPlatformStore_Get_BackendError(t *testing.T) {
	getErr := errors.New("connection refused")
	backend := &errBackend{getErr: getErr}
	store, err := NewPlatformStore(backend, nil)
	require.NoError(t, err)

	got, err := store.Get(context.Background(), "valid-name")
	require.Error(t, err)
	assert.Nil(t, got)
	assert.Contains(t, err.Error(), "connection refused")
	// Should NOT be ErrSecretNotFound since this is a different error.
	assert.False(t, errors.Is(err, ErrSecretNotFound))
}

// TestPlatformStore_Delete_BackendError verifies that Delete propagates a
// non-ErrNotFound backend error as a wrapped seal error.
func TestPlatformStore_Delete_BackendError(t *testing.T) {
	deleteErr := errors.New("permission denied")
	backend := &errBackend{deleteErr: deleteErr}
	store, err := NewPlatformStore(backend, nil)
	require.NoError(t, err)

	err = store.Delete(context.Background(), "valid-name")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "permission denied")
	assert.False(t, errors.Is(err, ErrSecretNotFound))
}

// TestPlatformStore_Exists_BackendError verifies that Exists propagates
// the underlying backend error when the storage Exists call fails.
func TestPlatformStore_Exists_BackendError(t *testing.T) {
	existsErr := errors.New("I/O timeout")
	backend := &errBackend{existsErr: existsErr}
	store, err := NewPlatformStore(backend, nil)
	require.NoError(t, err)

	exists, err := store.Exists(context.Background(), "valid-name")
	require.Error(t, err)
	assert.False(t, exists)
	assert.Contains(t, err.Error(), "I/O timeout")
}

// TestPlatformStore_List_BackendError verifies that List propagates
// the underlying backend error when the storage List call fails.
func TestPlatformStore_List_BackendError(t *testing.T) {
	listErr := errors.New("storage unavailable")
	backend := &errBackend{listErr: listErr}
	store, err := NewPlatformStore(backend, nil)
	require.NoError(t, err)

	names, err := store.List(context.Background())
	require.Error(t, err)
	assert.Nil(t, names)
	assert.Contains(t, err.Error(), "storage unavailable")
}

// TestPlatformStore_Reseal_DeleteFailure verifies that Reseal returns
// ErrResealFailed wrapping the delete error when the Delete step fails
// during a reseal operation (after Get succeeds).
func TestPlatformStore_Reseal_DeleteFailure(t *testing.T) {
	// Use a memoryBackend so Get succeeds, then swap to errBackend for Delete.
	// Actually, we can simulate this by putting data in the backend that
	// allows Get to succeed but Delete to fail. We'll use a custom approach.
	backend := newMemoryBackend()
	store, err := NewPlatformStore(backend, nil)
	require.NoError(t, err)

	ctx := context.Background()
	err = store.Put(ctx, "reseal-target", []byte("value"))
	require.NoError(t, err)

	// Close the backend between Get and Delete to cause Delete to fail.
	// Reseal calls Get, then Delete, then Put sequentially. We need to
	// make Delete fail but Get succeed. Since memoryBackend returns ErrClosed
	// on Delete when closed, and Reseal calls self.Get (which acquires RLock)
	// then self.Delete (which acquires Lock), closing after Get is not
	// straightforward. Instead, use a wrapper that fails on the second
	// delete call (the Reseal one).
	//
	// Simpler approach: create a store with errBackend that has getVal set
	// (so Get succeeds) and deleteErr set (so Delete fails).
	deleteErr := errors.New("delete failed during reseal")
	errBe := &errBackend{
		getVal:    []byte("plaintext-value"),
		deleteErr: deleteErr,
	}
	store2, err := NewPlatformStore(errBe, nil)
	require.NoError(t, err)

	err = store2.Reseal(ctx, "reseal-target")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrResealFailed))
	assert.Contains(t, err.Error(), "delete")
}

// TestPlatformStore_Reseal_PutFailure verifies that Reseal returns
// ErrResealFailed wrapping the put error when the Put step fails
// during a reseal operation (after Get and Delete succeed).
func TestPlatformStore_Reseal_PutFailure(t *testing.T) {
	// We need Get to succeed, Delete to succeed, and Put to fail.
	// Use a custom backend for this scenario.
	putErr := errors.New("disk full during reseal put")
	resealBackend := &resealErrBackend{
		data:   map[string][]byte{platformStorePrefix + "reseal-target": []byte("value")},
		putErr: putErr,
	}
	store, err := NewPlatformStore(resealBackend, nil)
	require.NoError(t, err)

	err = store.Reseal(context.Background(), "reseal-target")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrResealFailed))
	assert.Contains(t, err.Error(), "disk full during reseal put")
}

// resealErrBackend is a test backend that allows Get and Delete to succeed
// but returns an error from Put. Used to test the Reseal Put failure path.
type resealErrBackend struct {
	data   map[string][]byte
	putErr error
}

func (r *resealErrBackend) Get(_ context.Context, key string) ([]byte, error) {
	v, ok := r.data[key]
	if !ok {
		return nil, storage.ErrNotFound
	}
	out := make([]byte, len(v))
	copy(out, v)
	return out, nil
}

func (r *resealErrBackend) Put(_ context.Context, key string, value []byte) error {
	return r.putErr
}

func (r *resealErrBackend) Delete(_ context.Context, key string) error {
	if _, ok := r.data[key]; !ok {
		return storage.ErrNotFound
	}
	delete(r.data, key)
	return nil
}

func (r *resealErrBackend) List(_ context.Context, prefix string) ([]string, error) {
	return nil, nil
}

func (r *resealErrBackend) Exists(_ context.Context, key string) (bool, error) {
	_, ok := r.data[key]
	return ok, nil
}

func (r *resealErrBackend) Scan(_ context.Context, prefix string, fn func(key string, value []byte) error) error {
	for k, v := range r.data {
		if len(prefix) == 0 || (len(k) >= len(prefix) && k[:len(prefix)] == prefix) {
			if err := fn(k, v); err != nil {
				return err
			}
		}
	}
	return nil
}
func (r *resealErrBackend) Close() error { return nil }

var _ storage.Backend = (*resealErrBackend)(nil)
