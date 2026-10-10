// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package testutil

import (
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var _ qrdbsdk.TenantStoreResolver = (*TenantStores)(nil)

func TestTenantStores_EachTenantHasItsOwnStore(t *testing.T) {
	stores := NewTenantStores()
	acme, err := stores.Resolve(t.Context(), "acme")
	require.NoError(t, err)
	require.NoError(t, acme.Put(t.Context(), "k", []byte("acme")))

	globex, err := stores.Resolve(t.Context(), "globex")
	require.NoError(t, err)
	exists, err := globex.Exists(t.Context(), "k")
	require.NoError(t, err)
	assert.False(t, exists, "a tenant never sees another tenant's keys")

	again, err := stores.Resolve(t.Context(), "acme")
	require.NoError(t, err)
	got, err := again.Get(t.Context(), "k")
	require.NoError(t, err)
	assert.Equal(t, "acme", string(got))
	assert.Same(t, stores.Store("acme"), again)
}

func TestTenantStores_SealedTenantFailsClosed(t *testing.T) {
	stores := NewTenantStores()
	require.NoError(t, stores.Store("acme").Put(t.Context(), "k", []byte("v")))

	stores.Seal("acme")
	store, err := stores.Resolve(t.Context(), "acme")
	assert.ErrorIs(t, err, qrdbsdk.ErrTenantStoreSealed)
	assert.Nil(t, store)
	_, err = stores.Resolve(t.Context(), "globex")
	assert.NoError(t, err, "sealing one tenant leaves the others open")

	stores.Unseal("acme")
	store, err = stores.Resolve(t.Context(), "acme")
	require.NoError(t, err)
	got, err := store.Get(t.Context(), "k")
	require.NoError(t, err)
	assert.Equal(t, "v", string(got), "the data survives the seal")
}
