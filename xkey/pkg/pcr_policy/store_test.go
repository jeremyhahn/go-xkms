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

package pcrpolicy

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

// newTestStore creates a DAOStore backed by in-memory storage for testing.
func newTestStore(t *testing.T) *DAOStore {
	t.Helper()
	backend := storage.NewMemory()
	t.Cleanup(func() { backend.Close() })

	kvStore, err := kvadapter.New(backend)
	require.NoError(t, err)

	store, err := NewDAOStore(kvStore)
	require.NoError(t, err)
	t.Cleanup(func() { store.Close() })

	return store
}

// testPCRs returns a simple PCR digest map for testing.
func testPCRs() map[uint][]byte {
	return map[uint][]byte{
		0: {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
			0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
			0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F},
		7: {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
			0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
			0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
			0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99},
	}
}

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

func TestNewDAOStore_NilKVStore(t *testing.T) {
	store, err := NewDAOStore(nil)
	require.ErrorIs(t, err, ErrNilKVStore)
	assert.Nil(t, store)
}

func TestNewDAOStore_Success(t *testing.T) {
	store := newTestStore(t)
	assert.NotNil(t, store)
}

func TestDAOStore_ImplementsInterface(t *testing.T) {
	store := newTestStore(t)
	var _ PolicyStore = store
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

func TestDAOStore_Create_Success(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	entity, err := store.Create(ctx, "boot-policy", "SHA256", testPCRs())
	require.NoError(t, err)
	require.NotNil(t, entity)

	assert.Equal(t, "boot-policy", entity.Name)
	assert.Equal(t, "SHA256", entity.Bank)
	assert.Len(t, entity.PCRs, 2)
	assert.False(t, entity.AutoUnseal)
	assert.False(t, entity.CreatedAt.IsZero())
	assert.False(t, entity.UpdatedAt.IsZero())
	assert.NotZero(t, entity.EntityID())
}

func TestDAOStore_Create_EmptyName(t *testing.T) {
	store := newTestStore(t)
	entity, err := store.Create(context.Background(), "", "SHA256", testPCRs())
	require.ErrorIs(t, err, ErrInvalidName)
	assert.Nil(t, entity)
}

func TestDAOStore_Create_InvalidBank(t *testing.T) {
	store := newTestStore(t)
	entity, err := store.Create(context.Background(), "test", "MD5", testPCRs())
	require.ErrorIs(t, err, ErrInvalidBank)
	assert.Nil(t, entity)
}

func TestDAOStore_Create_EmptyBank(t *testing.T) {
	store := newTestStore(t)
	entity, err := store.Create(context.Background(), "test", "", testPCRs())
	require.ErrorIs(t, err, ErrInvalidBank)
	assert.Nil(t, entity)
}

func TestDAOStore_Create_NilPCRs(t *testing.T) {
	store := newTestStore(t)
	entity, err := store.Create(context.Background(), "test", "SHA256", nil)
	require.ErrorIs(t, err, ErrNoPCRs)
	assert.Nil(t, entity)
}

func TestDAOStore_Create_EmptyPCRs(t *testing.T) {
	store := newTestStore(t)
	entity, err := store.Create(context.Background(), "test", "SHA256", map[uint][]byte{})
	require.ErrorIs(t, err, ErrNoPCRs)
	assert.Nil(t, entity)
}

func TestDAOStore_Create_Closed(t *testing.T) {
	store := newTestStore(t)
	require.NoError(t, store.Close())

	entity, err := store.Create(context.Background(), "test", "SHA256", testPCRs())
	require.ErrorIs(t, err, ErrStoreClosed)
	assert.Nil(t, entity)
}

func TestDAOStore_Create_DuplicateName(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	pcrs1 := map[uint][]byte{0: {0x01}}
	pcrs2 := map[uint][]byte{7: {0xFF}}

	_, err := store.Create(ctx, "dupe", "SHA256", pcrs1)
	require.NoError(t, err)

	// Second create with same name overwrites (upsert).
	entity, err := store.Create(ctx, "dupe", "SHA384", pcrs2)
	require.NoError(t, err)
	assert.Equal(t, "SHA384", entity.Bank)

	// List should have exactly one entry.
	list, err := store.List(ctx)
	require.NoError(t, err)
	assert.Len(t, list, 1)
	assert.Equal(t, "SHA384", list[0].Bank)
}

func TestDAOStore_Create_AllBanks(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	for _, bank := range []string{"SHA1", "SHA256", "SHA384"} {
		entity, err := store.Create(ctx, "policy-"+bank, bank, testPCRs())
		require.NoError(t, err)
		assert.Equal(t, bank, entity.Bank)
	}
}

// ---------------------------------------------------------------------------
// Get
// ---------------------------------------------------------------------------

func TestDAOStore_Get_Success(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	created, err := store.Create(ctx, "secure-boot", "SHA256", testPCRs())
	require.NoError(t, err)

	got, err := store.Get(ctx, "secure-boot")
	require.NoError(t, err)
	require.NotNil(t, got)

	assert.Equal(t, created.EntityID(), got.EntityID())
	assert.Equal(t, "secure-boot", got.Name)
	assert.Equal(t, "SHA256", got.Bank)
	assert.Len(t, got.PCRs, 2)
}

func TestDAOStore_Get_NotFound(t *testing.T) {
	store := newTestStore(t)
	got, err := store.Get(context.Background(), "nonexistent")
	require.ErrorIs(t, err, ErrPolicyNotFound)
	assert.Nil(t, got)
}

func TestDAOStore_Get_EmptyName(t *testing.T) {
	store := newTestStore(t)
	got, err := store.Get(context.Background(), "")
	require.ErrorIs(t, err, ErrInvalidName)
	assert.Nil(t, got)
}

func TestDAOStore_Get_Closed(t *testing.T) {
	store := newTestStore(t)
	require.NoError(t, store.Close())

	got, err := store.Get(context.Background(), "test")
	require.ErrorIs(t, err, ErrStoreClosed)
	assert.Nil(t, got)
}

// ---------------------------------------------------------------------------
// List
// ---------------------------------------------------------------------------

func TestDAOStore_List_Success(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	_, err := store.Create(ctx, "z-policy", "SHA256", testPCRs())
	require.NoError(t, err)
	_, err = store.Create(ctx, "a-policy", "SHA384", testPCRs())
	require.NoError(t, err)
	_, err = store.Create(ctx, "m-policy", "SHA1", testPCRs())
	require.NoError(t, err)

	list, err := store.List(ctx)
	require.NoError(t, err)
	require.Len(t, list, 3)

	// Should be sorted by name.
	assert.Equal(t, "a-policy", list[0].Name)
	assert.Equal(t, "m-policy", list[1].Name)
	assert.Equal(t, "z-policy", list[2].Name)
}

func TestDAOStore_List_Empty(t *testing.T) {
	store := newTestStore(t)
	list, err := store.List(context.Background())
	require.NoError(t, err)
	assert.Empty(t, list)
}

func TestDAOStore_List_Closed(t *testing.T) {
	store := newTestStore(t)
	require.NoError(t, store.Close())

	list, err := store.List(context.Background())
	require.ErrorIs(t, err, ErrStoreClosed)
	assert.Nil(t, list)
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

func TestDAOStore_Page_Success(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		_, err := store.Create(ctx, fmt.Sprintf("policy-%02d", i), "SHA256", testPCRs())
		require.NoError(t, err)
	}

	// Page 1 with size 2.
	result, err := store.Page(ctx, dao.PageQuery{Page: 1, PageSize: 2})
	require.NoError(t, err)
	assert.Len(t, result.Entities, 2)
	assert.Equal(t, 5, result.Total)
	assert.True(t, result.HasMore)

	// Page 3 (last page with 1 entry).
	result3, err := store.Page(ctx, dao.PageQuery{Page: 3, PageSize: 2})
	require.NoError(t, err)
	assert.Len(t, result3.Entities, 1)
	assert.False(t, result3.HasMore)
}

func TestDAOStore_Page_Closed(t *testing.T) {
	store := newTestStore(t)
	require.NoError(t, store.Close())

	_, err := store.Page(context.Background(), dao.PageQuery{Page: 1, PageSize: 10})
	require.ErrorIs(t, err, ErrStoreClosed)
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

func TestDAOStore_Delete_Success(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	_, err := store.Create(ctx, "to-delete", "SHA256", testPCRs())
	require.NoError(t, err)

	require.NoError(t, store.Delete(ctx, "to-delete"))

	got, err := store.Get(ctx, "to-delete")
	require.ErrorIs(t, err, ErrPolicyNotFound)
	assert.Nil(t, got)
}

func TestDAOStore_Delete_NotFound(t *testing.T) {
	store := newTestStore(t)
	err := store.Delete(context.Background(), "nonexistent")
	require.ErrorIs(t, err, ErrPolicyNotFound)
}

func TestDAOStore_Delete_EmptyName(t *testing.T) {
	store := newTestStore(t)
	err := store.Delete(context.Background(), "")
	require.ErrorIs(t, err, ErrInvalidName)
}

func TestDAOStore_Delete_Closed(t *testing.T) {
	store := newTestStore(t)
	require.NoError(t, store.Close())

	err := store.Delete(context.Background(), "test")
	require.ErrorIs(t, err, ErrStoreClosed)
}

func TestDAOStore_Delete_AutoUnsealPolicy(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	_, err := store.Create(ctx, "auto-policy", "SHA256", testPCRs())
	require.NoError(t, err)

	require.NoError(t, store.SetAutoUnseal(ctx, "auto-policy"))

	// Deleting the auto-unseal policy should fail.
	err = store.Delete(ctx, "auto-policy")
	require.ErrorIs(t, err, ErrDeleteAutoUnseal)

	// Verify the policy is still present.
	got, err := store.Get(ctx, "auto-policy")
	require.NoError(t, err)
	assert.True(t, got.AutoUnseal)
}

// ---------------------------------------------------------------------------
// SetAutoUnseal
// ---------------------------------------------------------------------------

func TestDAOStore_SetAutoUnseal_Success(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	_, err := store.Create(ctx, "policy-a", "SHA256", testPCRs())
	require.NoError(t, err)

	require.NoError(t, store.SetAutoUnseal(ctx, "policy-a"))

	got, err := store.Get(ctx, "policy-a")
	require.NoError(t, err)
	assert.True(t, got.AutoUnseal)
}

func TestDAOStore_SetAutoUnseal_ClearsOld(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	_, err := store.Create(ctx, "old-auto", "SHA256", testPCRs())
	require.NoError(t, err)
	_, err = store.Create(ctx, "new-auto", "SHA384", testPCRs())
	require.NoError(t, err)

	require.NoError(t, store.SetAutoUnseal(ctx, "old-auto"))

	// Verify old has it.
	old, err := store.Get(ctx, "old-auto")
	require.NoError(t, err)
	assert.True(t, old.AutoUnseal)

	// Switch to new.
	require.NoError(t, store.SetAutoUnseal(ctx, "new-auto"))

	// Old should be cleared.
	old, err = store.Get(ctx, "old-auto")
	require.NoError(t, err)
	assert.False(t, old.AutoUnseal)

	// New should be set.
	newPolicy, err := store.Get(ctx, "new-auto")
	require.NoError(t, err)
	assert.True(t, newPolicy.AutoUnseal)
}

func TestDAOStore_SetAutoUnseal_NotFound(t *testing.T) {
	store := newTestStore(t)
	err := store.SetAutoUnseal(context.Background(), "nonexistent")
	require.ErrorIs(t, err, ErrPolicyNotFound)
}

func TestDAOStore_SetAutoUnseal_EmptyName(t *testing.T) {
	store := newTestStore(t)
	err := store.SetAutoUnseal(context.Background(), "")
	require.ErrorIs(t, err, ErrInvalidName)
}

func TestDAOStore_SetAutoUnseal_Closed(t *testing.T) {
	store := newTestStore(t)
	require.NoError(t, store.Close())

	err := store.SetAutoUnseal(context.Background(), "test")
	require.ErrorIs(t, err, ErrStoreClosed)
}

func TestDAOStore_SetAutoUnseal_Idempotent(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	_, err := store.Create(ctx, "idem-policy", "SHA256", testPCRs())
	require.NoError(t, err)

	// Set auto-unseal twice on the same policy.
	require.NoError(t, store.SetAutoUnseal(ctx, "idem-policy"))
	require.NoError(t, store.SetAutoUnseal(ctx, "idem-policy"))

	got, err := store.Get(ctx, "idem-policy")
	require.NoError(t, err)
	assert.True(t, got.AutoUnseal)
}

// ---------------------------------------------------------------------------
// ClearAutoUnseal
// ---------------------------------------------------------------------------

func TestDAOStore_ClearAutoUnseal_Success(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	_, err := store.Create(ctx, "auto-policy", "SHA256", testPCRs())
	require.NoError(t, err)

	require.NoError(t, store.SetAutoUnseal(ctx, "auto-policy"))

	// Verify it is set.
	got, err := store.Get(ctx, "auto-policy")
	require.NoError(t, err)
	assert.True(t, got.AutoUnseal)

	// Clear it.
	require.NoError(t, store.ClearAutoUnseal(ctx))

	// Verify it is cleared.
	got, err = store.Get(ctx, "auto-policy")
	require.NoError(t, err)
	assert.False(t, got.AutoUnseal)

	// GetAutoUnsealPolicy should return not found.
	_, err = store.GetAutoUnsealPolicy(ctx)
	require.ErrorIs(t, err, ErrPolicyNotFound)
}

func TestDAOStore_ClearAutoUnseal_NoneSet(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	_, err := store.Create(ctx, "normal-policy", "SHA256", testPCRs())
	require.NoError(t, err)

	// Clearing when nothing is set is a no-op.
	require.NoError(t, store.ClearAutoUnseal(ctx))
}

func TestDAOStore_ClearAutoUnseal_EmptyStore(t *testing.T) {
	store := newTestStore(t)
	require.NoError(t, store.ClearAutoUnseal(context.Background()))
}

func TestDAOStore_ClearAutoUnseal_Closed(t *testing.T) {
	store := newTestStore(t)
	require.NoError(t, store.Close())

	err := store.ClearAutoUnseal(context.Background())
	require.ErrorIs(t, err, ErrStoreClosed)
}

func TestDAOStore_ClearAutoUnseal_ThenDelete(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	_, err := store.Create(ctx, "locked-policy", "SHA256", testPCRs())
	require.NoError(t, err)

	require.NoError(t, store.SetAutoUnseal(ctx, "locked-policy"))

	// Cannot delete while auto-unseal is set.
	err = store.Delete(ctx, "locked-policy")
	require.ErrorIs(t, err, ErrDeleteAutoUnseal)

	// Clear auto-unseal, then delete should succeed.
	require.NoError(t, store.ClearAutoUnseal(ctx))
	require.NoError(t, store.Delete(ctx, "locked-policy"))
}

// ---------------------------------------------------------------------------
// GetAutoUnsealPolicy
// ---------------------------------------------------------------------------

func TestDAOStore_GetAutoUnsealPolicy_Success(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	_, err := store.Create(ctx, "auto-target", "SHA256", testPCRs())
	require.NoError(t, err)

	require.NoError(t, store.SetAutoUnseal(ctx, "auto-target"))

	got, err := store.GetAutoUnsealPolicy(ctx)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "auto-target", got.Name)
	assert.True(t, got.AutoUnseal)
}

func TestDAOStore_GetAutoUnsealPolicy_NoneSet(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	_, err := store.Create(ctx, "no-auto", "SHA256", testPCRs())
	require.NoError(t, err)

	got, err := store.GetAutoUnsealPolicy(ctx)
	require.ErrorIs(t, err, ErrPolicyNotFound)
	assert.Nil(t, got)
}

func TestDAOStore_GetAutoUnsealPolicy_Empty(t *testing.T) {
	store := newTestStore(t)
	got, err := store.GetAutoUnsealPolicy(context.Background())
	require.ErrorIs(t, err, ErrPolicyNotFound)
	assert.Nil(t, got)
}

func TestDAOStore_GetAutoUnsealPolicy_Closed(t *testing.T) {
	store := newTestStore(t)
	require.NoError(t, store.Close())

	got, err := store.GetAutoUnsealPolicy(context.Background())
	require.ErrorIs(t, err, ErrStoreClosed)
	assert.Nil(t, got)
}

// ---------------------------------------------------------------------------
// Close
// ---------------------------------------------------------------------------

func TestDAOStore_Close_Idempotent(t *testing.T) {
	store := newTestStore(t)
	require.NoError(t, store.Close())
	require.NoError(t, store.Close())
	require.NoError(t, store.Close())
}

// ---------------------------------------------------------------------------
// Concurrency
// ---------------------------------------------------------------------------

func TestDAOStore_Concurrency(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines * 3)

	// Concurrent creates.
	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			_, _ = store.Create(ctx, fmt.Sprintf("policy-%03d", idx), "SHA256", testPCRs())
		}(i)
	}

	// Concurrent gets.
	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			_, _ = store.Get(ctx, fmt.Sprintf("policy-%03d", idx))
		}(i)
	}

	// Concurrent lists.
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			_, _ = store.List(ctx)
		}()
	}

	wg.Wait()

	// Store should be consistent after all goroutines complete.
	list, err := store.List(ctx)
	require.NoError(t, err)
	assert.NotEmpty(t, list)
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

func TestErrDAOCreation_ErrorAndUnwrap(t *testing.T) {
	cause := fmt.Errorf("underlying issue")
	err := ErrDAOCreation{Cause: cause}

	assert.Contains(t, err.Error(), "failed to create DAO")
	assert.Contains(t, err.Error(), "underlying issue")
	assert.Equal(t, cause, err.Unwrap())
}
