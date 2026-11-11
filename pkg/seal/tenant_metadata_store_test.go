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

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// fakeBackendGet is a StorageBackend whose Get returns canned values; all other
// methods are nil (unused by these tests, satisfied via interface embedding).
type fakeBackendGet struct {
	qrdbsdk.StorageBackend
	val []byte
	err error
}

func (f fakeBackendGet) Get(context.Context, string) ([]byte, error) { return f.val, f.err }

func TestTenantMetadataStore_TranslatesNotFound(t *testing.T) {
	store := tenantMetadataStore{fakeBackendGet{err: storage.ErrNotFound}}

	_, err := store.Get(context.Background(), "missing")
	assert.ErrorIs(t, err, qrdbsdk.ErrSecretNotFound,
		"xkms storage.ErrNotFound must surface as go-qrdb ErrSecretNotFound")
}

func TestTenantMetadataStore_PassesThroughValueAndOtherErrors(t *testing.T) {
	// A present value is returned unchanged.
	ok := tenantMetadataStore{fakeBackendGet{val: []byte("record")}}
	v, err := ok.Get(context.Background(), "present")
	require.NoError(t, err)
	assert.Equal(t, []byte("record"), v)

	// An unrelated error is not rewritten to ErrSecretNotFound.
	sentinel := errors.New("disk exploded")
	bad := tenantMetadataStore{fakeBackendGet{err: sentinel}}
	_, err = bad.Get(context.Background(), "boom")
	assert.ErrorIs(t, err, sentinel)
	assert.NotErrorIs(t, err, qrdbsdk.ErrSecretNotFound)
}

// fakeSwapBackend records the guarded swap it is handed and answers with a
// fixed outcome.
type fakeSwapBackend struct {
	qrdbsdk.StorageBackend
	swapped  bool
	err      error
	key      string
	expected []byte
	next     []byte
}

func (f *fakeSwapBackend) CompareAndSwap(_ context.Context, key string, expected, next []byte) (bool, error) {
	f.key, f.expected, f.next = key, expected, next
	return f.swapped, f.err
}

func TestTenantMetadataStore_CompareAndSwapForwards(t *testing.T) {
	backend := &fakeSwapBackend{swapped: true}
	store := tenantMetadataStore{backend}
	swapped, err := store.CompareAndSwap(context.Background(), "tenants/t-1", []byte("old"), []byte("new"))
	require.NoError(t, err)
	assert.True(t, swapped)
	assert.Equal(t, "tenants/t-1", backend.key)
	assert.Equal(t, []byte("old"), backend.expected)
	assert.Equal(t, []byte("new"), backend.next)

	// A lost swap and a store failure reach the caller unchanged.
	sentinel := errors.New("disk exploded")
	lost := tenantMetadataStore{&fakeSwapBackend{err: sentinel}}
	swapped, err = lost.CompareAndSwap(context.Background(), "tenants/t-1", []byte("old"), []byte("new"))
	assert.ErrorIs(t, err, sentinel)
	assert.False(t, swapped)
}

func TestTenantMetadataStore_CompareAndSwapRefusesStoreWithoutSwap(t *testing.T) {
	store := tenantMetadataStore{fakeBackendGet{}}
	swapped, err := store.CompareAndSwap(context.Background(), "tenants/t-1", []byte("old"), []byte("new"))
	assert.ErrorIs(t, err, storage.ErrCompareAndSwapUnsupported)
	assert.False(t, swapped)
}
