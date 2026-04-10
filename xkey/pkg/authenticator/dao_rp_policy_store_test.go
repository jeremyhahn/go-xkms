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

package authenticator

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-qrdb/pkg/dao"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/kvadapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestDAORPPolicyStore creates a DAORPPolicyStore backed by in-memory storage.
func newTestDAORPPolicyStore(t *testing.T) *DAORPPolicyStore {
	t.Helper()
	backend := storage.NewMemory()
	t.Cleanup(func() { backend.Close() })

	kvStore, err := kvadapter.New(backend)
	require.NoError(t, err)

	store, err := NewDAORPPolicyStore(kvStore)
	require.NoError(t, err)
	t.Cleanup(func() { store.Close() })

	return store
}

func TestDAORPPolicyStore_NewNilKVStore(t *testing.T) {
	store, err := NewDAORPPolicyStore(nil)
	require.ErrorIs(t, err, ErrNilStorage)
	assert.Nil(t, store)
}

func TestDAORPPolicyStore_SaveGet_RoundTrip(t *testing.T) {
	store := newTestDAORPPolicyStore(t)

	upTrue := true
	policy := &RPPolicy{
		RPID:                "example.com",
		UVOverride:          "required",
		UPOverride:          &upTrue,
		AttestationOverride: "direct",
		Enterprise:          true,
		Blocked:             false,
	}

	require.NoError(t, store.SetPolicy(policy))

	loaded, err := store.GetPolicy("example.com")
	require.NoError(t, err)
	require.NotNil(t, loaded)

	assert.Equal(t, "example.com", loaded.RPID)
	assert.Equal(t, "required", loaded.UVOverride)
	require.NotNil(t, loaded.UPOverride)
	assert.True(t, *loaded.UPOverride)
	assert.Equal(t, "direct", loaded.AttestationOverride)
	assert.True(t, loaded.Enterprise)
	assert.False(t, loaded.Blocked)
}

func TestDAORPPolicyStore_SetPolicy_NilPolicy(t *testing.T) {
	store := newTestDAORPPolicyStore(t)

	err := store.SetPolicy(nil)
	require.ErrorIs(t, err, ErrRPPolicyNil)
}

func TestDAORPPolicyStore_SetPolicy_EmptyRPID(t *testing.T) {
	store := newTestDAORPPolicyStore(t)

	err := store.SetPolicy(&RPPolicy{RPID: ""})
	require.ErrorIs(t, err, ErrRPPolicyInvalidRPID)
}

func TestDAORPPolicyStore_SetPolicy_InvalidUVOverride(t *testing.T) {
	store := newTestDAORPPolicyStore(t)

	err := store.SetPolicy(&RPPolicy{RPID: "example.com", UVOverride: "bogus"})
	require.ErrorIs(t, err, ErrInvalidParameter)
}

func TestDAORPPolicyStore_SetPolicy_Closed(t *testing.T) {
	store := newTestDAORPPolicyStore(t)
	require.NoError(t, store.Close())

	err := store.SetPolicy(&RPPolicy{RPID: "example.com"})
	require.ErrorIs(t, err, ErrRPPolicyStoreClosed)
}

func TestDAORPPolicyStore_SetPolicy_Upsert(t *testing.T) {
	store := newTestDAORPPolicyStore(t)

	// Initial save.
	require.NoError(t, store.SetPolicy(&RPPolicy{
		RPID:       "example.com",
		UVOverride: "required",
	}))

	// Update.
	require.NoError(t, store.SetPolicy(&RPPolicy{
		RPID:       "example.com",
		UVOverride: "discouraged",
		Blocked:    true,
	}))

	loaded, err := store.GetPolicy("example.com")
	require.NoError(t, err)
	assert.Equal(t, "discouraged", loaded.UVOverride)
	assert.True(t, loaded.Blocked)

	// List should show only one entry.
	policies, err := store.ListPolicies()
	require.NoError(t, err)
	assert.Len(t, policies, 1)
}

func TestDAORPPolicyStore_GetPolicy_NotFound(t *testing.T) {
	store := newTestDAORPPolicyStore(t)

	loaded, err := store.GetPolicy("nonexistent.com")
	require.ErrorIs(t, err, ErrRPPolicyNotFound)
	assert.Nil(t, loaded)
}

func TestDAORPPolicyStore_GetPolicy_EmptyRPID(t *testing.T) {
	store := newTestDAORPPolicyStore(t)

	loaded, err := store.GetPolicy("")
	require.ErrorIs(t, err, ErrRPPolicyInvalidRPID)
	assert.Nil(t, loaded)
}

func TestDAORPPolicyStore_GetPolicy_Closed(t *testing.T) {
	store := newTestDAORPPolicyStore(t)
	require.NoError(t, store.Close())

	loaded, err := store.GetPolicy("example.com")
	require.ErrorIs(t, err, ErrRPPolicyStoreClosed)
	assert.Nil(t, loaded)
}

func TestDAORPPolicyStore_Delete(t *testing.T) {
	store := newTestDAORPPolicyStore(t)

	require.NoError(t, store.SetPolicy(&RPPolicy{RPID: "example.com"}))

	err := store.DeletePolicy("example.com")
	require.NoError(t, err)

	// Verify gone.
	loaded, err := store.GetPolicy("example.com")
	require.ErrorIs(t, err, ErrRPPolicyNotFound)
	assert.Nil(t, loaded)
}

func TestDAORPPolicyStore_Delete_NotFound(t *testing.T) {
	store := newTestDAORPPolicyStore(t)

	err := store.DeletePolicy("nonexistent.com")
	require.ErrorIs(t, err, ErrRPPolicyNotFound)
}

func TestDAORPPolicyStore_Delete_EmptyRPID(t *testing.T) {
	store := newTestDAORPPolicyStore(t)

	err := store.DeletePolicy("")
	require.ErrorIs(t, err, ErrRPPolicyInvalidRPID)
}

func TestDAORPPolicyStore_Delete_Closed(t *testing.T) {
	store := newTestDAORPPolicyStore(t)
	require.NoError(t, store.Close())

	err := store.DeletePolicy("example.com")
	require.ErrorIs(t, err, ErrRPPolicyStoreClosed)
}

func TestDAORPPolicyStore_List(t *testing.T) {
	store := newTestDAORPPolicyStore(t)

	require.NoError(t, store.SetPolicy(&RPPolicy{RPID: "z-corp.com"}))
	require.NoError(t, store.SetPolicy(&RPPolicy{RPID: "a-corp.com"}))
	require.NoError(t, store.SetPolicy(&RPPolicy{RPID: "m-corp.com"}))

	policies, err := store.ListPolicies()
	require.NoError(t, err)
	require.Len(t, policies, 3)

	// Should be sorted by RPID.
	assert.Equal(t, "a-corp.com", policies[0].RPID)
	assert.Equal(t, "m-corp.com", policies[1].RPID)
	assert.Equal(t, "z-corp.com", policies[2].RPID)
}

func TestDAORPPolicyStore_List_Empty(t *testing.T) {
	store := newTestDAORPPolicyStore(t)

	policies, err := store.ListPolicies()
	require.NoError(t, err)
	assert.Empty(t, policies)
}

func TestDAORPPolicyStore_List_Closed(t *testing.T) {
	store := newTestDAORPPolicyStore(t)
	require.NoError(t, store.Close())

	policies, err := store.ListPolicies()
	require.ErrorIs(t, err, ErrRPPolicyStoreClosed)
	assert.Nil(t, policies)
}

func TestDAORPPolicyStore_Page(t *testing.T) {
	store := newTestDAORPPolicyStore(t)

	// Store 5 policies.
	for i := 0; i < 5; i++ {
		require.NoError(t, store.SetPolicy(&RPPolicy{
			RPID: fmt.Sprintf("rp-%02d.com", i),
		}))
	}

	// Page with size 2.
	result, err := store.Page(context.Background(), dao.PageQuery{Page: 1, PageSize: 2})
	require.NoError(t, err)
	assert.Len(t, result.Entities, 2)
	assert.Equal(t, 5, result.Total)
	assert.True(t, result.HasMore)

	// Last page.
	result3, err := store.Page(context.Background(), dao.PageQuery{Page: 3, PageSize: 2})
	require.NoError(t, err)
	assert.Len(t, result3.Entities, 1)
	assert.False(t, result3.HasMore)
}

func TestDAORPPolicyStore_Page_Closed(t *testing.T) {
	store := newTestDAORPPolicyStore(t)
	require.NoError(t, store.Close())

	_, err := store.Page(context.Background(), dao.PageQuery{Page: 1, PageSize: 10})
	require.ErrorIs(t, err, ErrRPPolicyStoreClosed)
}

func TestDAORPPolicyStore_Close_Idempotent(t *testing.T) {
	store := newTestDAORPPolicyStore(t)
	require.NoError(t, store.Close())
	require.NoError(t, store.Close())
	require.NoError(t, store.Close())
}

func TestDAORPPolicyStore_ImplementsInterface(t *testing.T) {
	store := newTestDAORPPolicyStore(t)
	var _ RPPolicyStore = store
}

func TestDAORPPolicyStore_NilUPOverride(t *testing.T) {
	store := newTestDAORPPolicyStore(t)

	// Policy with nil UPOverride.
	require.NoError(t, store.SetPolicy(&RPPolicy{
		RPID:       "example.com",
		UVOverride: "preferred",
	}))

	loaded, err := store.GetPolicy("example.com")
	require.NoError(t, err)
	assert.Nil(t, loaded.UPOverride)
}

func TestDAORPPolicyStore_Concurrency(t *testing.T) {
	store := newTestDAORPPolicyStore(t)

	const goroutines = 20
	var wg sync.WaitGroup
	wg.Add(goroutines * 3)

	// Concurrent saves.
	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			_ = store.SetPolicy(&RPPolicy{
				RPID: fmt.Sprintf("rp-%d.com", idx),
			})
		}(i)
	}

	// Concurrent gets.
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			_, _ = store.GetPolicy("rp-0.com")
		}()
	}

	// Concurrent lists.
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			_, _ = store.ListPolicies()
		}()
	}

	wg.Wait()

	policies, err := store.ListPolicies()
	require.NoError(t, err)
	assert.Equal(t, goroutines, len(policies))
}
