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
	"testing"

	"github.com/jeremyhahn/go-qrdb/pkg/kvstore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// go-qrdb v0.58 refuses tenant updates unless the tenant metadata store has
// the atomic writes of kvstore.AtomicKVStore. The full interface also embeds
// kvstore.KVStore (QueryCompoundIndex, ...), which a StorageBackend is not,
// so the assertion names the three atomic methods.
var _ interface {
	PutIfAbsent(ctx context.Context, key string, value []byte) (bool, error)
	CompareAndDelete(ctx context.Context, key string, expected []byte) (bool, error)
	CompareAndSwap(ctx context.Context, key string, expected, next []byte) (bool, error)
} = tenantMetadataStore{}

var _ = kvstore.AtomicKVStore(nil)

func TestTenantMetadataStore_CompareAndSwapStaleExpectedIsRefused(t *testing.T) {
	ctx := context.Background()
	base := storage.NewMemory()
	t.Cleanup(func() { _ = base.Close() })
	barrier, err := NewBarrier(testLogger(), base, BarrierConfig{
		RootKeyPath: "core/seal",
	}, NewSoftwareStrategy())
	require.NoError(t, err)
	creds, err := CredentialsFor(ctx, []byte("system-pass"))
	require.NoError(t, err)
	t.Cleanup(func() { creds.Secret.Destroy() })
	require.NoError(t, barrier.Initialize(ctx, creds))
	if barrier.IsSealed() {
		require.NoError(t, barrier.Unseal(ctx, creds))
	}

	store := tenantMetadataStore{barrier}
	require.NoError(t, store.Put(ctx, "tenants/a", []byte("v2")))

	swapped, err := store.CompareAndSwap(ctx, "tenants/a", []byte("v1"), []byte("v3"))
	require.NoError(t, err)
	assert.False(t, swapped, "a stale expected value must not swap")
	got, err := store.Get(ctx, "tenants/a")
	require.NoError(t, err)
	assert.Equal(t, []byte("v2"), got, "a refused swap must leave the value")

	swapped, err = store.CompareAndSwap(ctx, "tenants/a", []byte("v2"), []byte("v3"))
	require.NoError(t, err)
	assert.True(t, swapped)
	got, err = store.Get(ctx, "tenants/a")
	require.NoError(t, err)
	assert.Equal(t, []byte("v3"), got)
}
