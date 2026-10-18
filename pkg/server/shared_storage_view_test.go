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

package server

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSharedStorageView_RefusesBeforeTheDatastoreOpens proves a store built
// before the qrdb node never writes anywhere but the shared datastore: every
// call is refused with ErrSharedStorageUnbound until it is open.
func TestSharedStorageView_RefusesBeforeTheDatastoreOpens(t *testing.T) {
	ctx := context.Background()
	view := sharedStorageView{s: &Server{}}
	noop := func(string, []byte) error { return nil }

	_, err := view.Get(ctx, "k")
	assert.ErrorIs(t, err, ErrSharedStorageUnbound)
	assert.ErrorIs(t, view.Put(ctx, "k", []byte("v")), ErrSharedStorageUnbound)
	_, err = view.PutIfAbsent(ctx, "k", []byte("v"))
	assert.ErrorIs(t, err, ErrSharedStorageUnbound)
	assert.ErrorIs(t, view.Delete(ctx, "k"), ErrSharedStorageUnbound)
	_, err = view.List(ctx, "")
	assert.ErrorIs(t, err, ErrSharedStorageUnbound)
	assert.ErrorIs(t, view.Scan(ctx, "", noop), ErrSharedStorageUnbound)
	_, err = view.Exists(ctx, "k")
	assert.ErrorIs(t, err, ErrSharedStorageUnbound)
}

// TestSharedStorageView_ServesTheDatastoreOnceOpen proves a view built
// before the datastore opens serves it afterwards, so a backend opened
// before the node keeps its metadata in the shared datastore.
func TestSharedStorageView_ServesTheDatastoreOnceOpen(t *testing.T) {
	ctx := context.Background()
	s := &Server{}
	view := sharedStorageView{s: s}
	s.setSharedStorage(storage.NewMemory())

	require.NoError(t, view.Put(ctx, "keys/a", []byte("1")))
	stored, err := view.PutIfAbsent(ctx, "keys/a", []byte("2"))
	require.NoError(t, err)
	assert.False(t, stored, "an existing key must not be overwritten")
	got, err := view.Get(ctx, "keys/a")
	require.NoError(t, err)
	assert.Equal(t, []byte("1"), got)
	exists, err := view.Exists(ctx, "keys/a")
	require.NoError(t, err)
	assert.True(t, exists)
	keys, err := view.List(ctx, "keys/")
	require.NoError(t, err)
	assert.Equal(t, []string{"keys/a"}, keys)
	scanned := 0
	require.NoError(t, view.Scan(ctx, "keys/", func(string, []byte) error { scanned++; return nil }))
	assert.Equal(t, 1, scanned)
	require.NoError(t, view.Delete(ctx, "keys/a"))
	require.NoError(t, view.Close())
	got, err = s.sharedStorage().Get(ctx, "keys/a")
	assert.Error(t, err, "the delete must reach the shared datastore")
	assert.Nil(t, got)
}
