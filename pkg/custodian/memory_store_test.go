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

package custodian

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestGroup(id string) *CustodianGroup {
	now := time.Now().UTC()
	return &CustodianGroup{
		ID:        id,
		TenantID:  "tenant-1",
		Name:      "Test Group " + id,
		Purpose:   PurposeBarrier,
		Threshold: 2,
		Total:     3,
		Members: []CustodianMember{
			{
				ShareIndex: 1,
				UserID:     "user-1",
				Username:   "alice",
				AssignedAt: now,
				Method:     MethodFIDO2,
			},
		},
		CreatedAt: now,
		UpdatedAt: now,
	}
}

func TestMemoryStore_Create(t *testing.T) {
	t.Run("creates group successfully", func(t *testing.T) {
		store := NewMemoryStore()
		ctx := context.Background()
		group := newTestGroup("group-1")

		err := store.Create(ctx, group)
		require.NoError(t, err)

		got, err := store.Get(ctx, "group-1")
		require.NoError(t, err)
		assert.Equal(t, "group-1", got.ID)
		assert.Equal(t, "Test Group group-1", got.Name)
		assert.Len(t, got.Members, 1)
	})

	t.Run("returns error for duplicate ID", func(t *testing.T) {
		store := NewMemoryStore()
		ctx := context.Background()
		group := newTestGroup("group-1")

		err := store.Create(ctx, group)
		require.NoError(t, err)

		err = store.Create(ctx, group)
		assert.ErrorIs(t, err, ErrGroupAlreadyExists)
	})
}

func TestMemoryStore_Get(t *testing.T) {
	t.Run("returns group by ID", func(t *testing.T) {
		store := NewMemoryStore()
		ctx := context.Background()
		group := newTestGroup("group-1")

		err := store.Create(ctx, group)
		require.NoError(t, err)

		got, err := store.Get(ctx, "group-1")
		require.NoError(t, err)
		assert.Equal(t, group.ID, got.ID)
		assert.Equal(t, group.Name, got.Name)
		assert.Equal(t, group.Purpose, got.Purpose)
		assert.Equal(t, group.Threshold, got.Threshold)
		assert.Equal(t, group.Total, got.Total)
	})

	t.Run("returns error for non-existing group", func(t *testing.T) {
		store := NewMemoryStore()
		ctx := context.Background()

		_, err := store.Get(ctx, "nonexistent")
		assert.ErrorIs(t, err, ErrGroupNotFound)
	})
}

func TestMemoryStore_Update(t *testing.T) {
	t.Run("updates group successfully", func(t *testing.T) {
		store := NewMemoryStore()
		ctx := context.Background()
		group := newTestGroup("group-1")

		err := store.Create(ctx, group)
		require.NoError(t, err)

		group.Name = "Updated Name"
		group.Members = append(group.Members, CustodianMember{
			ShareIndex: 2,
			UserID:     "user-2",
			Username:   "bob",
			AssignedAt: time.Now().UTC(),
			Method:     MethodManual,
		})

		err = store.Update(ctx, group)
		require.NoError(t, err)

		got, err := store.Get(ctx, "group-1")
		require.NoError(t, err)
		assert.Equal(t, "Updated Name", got.Name)
		assert.Len(t, got.Members, 2)
	})

	t.Run("returns error for non-existing group", func(t *testing.T) {
		store := NewMemoryStore()
		ctx := context.Background()
		group := newTestGroup("nonexistent")

		err := store.Update(ctx, group)
		assert.ErrorIs(t, err, ErrGroupNotFound)
	})
}

func TestMemoryStore_Delete(t *testing.T) {
	t.Run("deletes group successfully", func(t *testing.T) {
		store := NewMemoryStore()
		ctx := context.Background()
		group := newTestGroup("group-1")

		err := store.Create(ctx, group)
		require.NoError(t, err)

		err = store.Delete(ctx, "group-1")
		require.NoError(t, err)

		_, err = store.Get(ctx, "group-1")
		assert.ErrorIs(t, err, ErrGroupNotFound)
	})

	t.Run("returns error for non-existing group", func(t *testing.T) {
		store := NewMemoryStore()
		ctx := context.Background()

		err := store.Delete(ctx, "nonexistent")
		assert.ErrorIs(t, err, ErrGroupNotFound)
	})
}

func TestMemoryStore_List(t *testing.T) {
	t.Run("returns all groups", func(t *testing.T) {
		store := NewMemoryStore()
		ctx := context.Background()

		err := store.Create(ctx, newTestGroup("group-1"))
		require.NoError(t, err)
		err = store.Create(ctx, newTestGroup("group-2"))
		require.NoError(t, err)

		groups, err := store.List(ctx)
		require.NoError(t, err)
		assert.Len(t, groups, 2)
	})

	t.Run("returns empty slice when no groups", func(t *testing.T) {
		store := NewMemoryStore()
		ctx := context.Background()

		groups, err := store.List(ctx)
		require.NoError(t, err)
		assert.Empty(t, groups)
	})
}

func TestMemoryStore_ListByTenant(t *testing.T) {
	t.Run("filters by tenant ID", func(t *testing.T) {
		store := NewMemoryStore()
		ctx := context.Background()

		g1 := newTestGroup("group-1")
		g1.TenantID = "tenant-a"
		g2 := newTestGroup("group-2")
		g2.TenantID = "tenant-b"
		g3 := newTestGroup("group-3")
		g3.TenantID = "tenant-a"

		require.NoError(t, store.Create(ctx, g1))
		require.NoError(t, store.Create(ctx, g2))
		require.NoError(t, store.Create(ctx, g3))

		groups, err := store.ListByTenant(ctx, "tenant-a")
		require.NoError(t, err)
		assert.Len(t, groups, 2)

		groups, err = store.ListByTenant(ctx, "tenant-b")
		require.NoError(t, err)
		assert.Len(t, groups, 1)
	})

	t.Run("returns system-level groups with empty tenant ID", func(t *testing.T) {
		store := NewMemoryStore()
		ctx := context.Background()

		g1 := newTestGroup("group-1")
		g1.TenantID = ""
		g2 := newTestGroup("group-2")
		g2.TenantID = "tenant-a"

		require.NoError(t, store.Create(ctx, g1))
		require.NoError(t, store.Create(ctx, g2))

		groups, err := store.ListByTenant(ctx, "")
		require.NoError(t, err)
		assert.Len(t, groups, 1)
		assert.Equal(t, "group-1", groups[0].ID)
	})

	t.Run("returns empty when no groups match", func(t *testing.T) {
		store := NewMemoryStore()
		ctx := context.Background()

		groups, err := store.ListByTenant(ctx, "nonexistent")
		require.NoError(t, err)
		assert.Empty(t, groups)
	})
}

func TestMemoryStore_ListByPurpose(t *testing.T) {
	t.Run("filters by purpose", func(t *testing.T) {
		store := NewMemoryStore()
		ctx := context.Background()

		g1 := newTestGroup("group-1")
		g1.Purpose = PurposeBarrier
		g2 := newTestGroup("group-2")
		g2.Purpose = PurposeBackup
		g3 := newTestGroup("group-3")
		g3.Purpose = PurposeBarrier

		require.NoError(t, store.Create(ctx, g1))
		require.NoError(t, store.Create(ctx, g2))
		require.NoError(t, store.Create(ctx, g3))

		groups, err := store.ListByPurpose(ctx, PurposeBarrier)
		require.NoError(t, err)
		assert.Len(t, groups, 2)

		groups, err = store.ListByPurpose(ctx, PurposeBackup)
		require.NoError(t, err)
		assert.Len(t, groups, 1)
	})

	t.Run("returns empty when no groups match purpose", func(t *testing.T) {
		store := NewMemoryStore()
		ctx := context.Background()

		groups, err := store.ListByPurpose(ctx, PurposeSigningKey)
		require.NoError(t, err)
		assert.Empty(t, groups)
	})
}

func TestMemoryStore_DeepCopy(t *testing.T) {
	t.Run("mutating returned value does not affect store", func(t *testing.T) {
		store := NewMemoryStore()
		ctx := context.Background()
		group := newTestGroup("group-1")

		err := store.Create(ctx, group)
		require.NoError(t, err)

		got, err := store.Get(ctx, "group-1")
		require.NoError(t, err)

		// Mutate the returned value
		got.Name = "Mutated"
		got.Members = append(got.Members, CustodianMember{
			UserID: "mutated-user",
		})

		// Verify the store is unaffected
		original, err := store.Get(ctx, "group-1")
		require.NoError(t, err)
		assert.Equal(t, "Test Group group-1", original.Name)
		assert.Len(t, original.Members, 1)
	})

	t.Run("mutating input after create does not affect store", func(t *testing.T) {
		store := NewMemoryStore()
		ctx := context.Background()
		group := newTestGroup("group-1")

		err := store.Create(ctx, group)
		require.NoError(t, err)

		// Mutate the original input
		group.Name = "Mutated After Create"
		group.Members[0].Username = "mutated"

		// Verify the store is unaffected
		got, err := store.Get(ctx, "group-1")
		require.NoError(t, err)
		assert.Equal(t, "Test Group group-1", got.Name)
		assert.Equal(t, "alice", got.Members[0].Username)
	})

	t.Run("deep copy preserves ReceivedAt pointer independence", func(t *testing.T) {
		store := NewMemoryStore()
		ctx := context.Background()

		now := time.Now().UTC()
		group := newTestGroup("group-1")
		group.Members[0].ReceivedAt = &now

		err := store.Create(ctx, group)
		require.NoError(t, err)

		got, err := store.Get(ctx, "group-1")
		require.NoError(t, err)
		require.NotNil(t, got.Members[0].ReceivedAt)

		// Mutate the pointer value
		modified := got.Members[0].ReceivedAt.Add(24 * time.Hour)
		got.Members[0].ReceivedAt = &modified

		// Verify store value is unchanged
		original, err := store.Get(ctx, "group-1")
		require.NoError(t, err)
		assert.Equal(t, now, *original.Members[0].ReceivedAt)
	})
}

func TestMemoryStore_ThreadSafety(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	numGoroutines := 50

	// Create base groups
	for i := 0; i < numGoroutines; i++ {
		g := newTestGroup(fmt.Sprintf("group-%d", i))
		require.NoError(t, store.Create(ctx, g))
	}

	var wg sync.WaitGroup

	// Concurrent reads
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			_, err := store.Get(ctx, fmt.Sprintf("group-%d", id))
			assert.NoError(t, err)
		}(i)
	}
	wg.Wait()

	// Concurrent list operations
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			_, err := store.List(ctx)
			assert.NoError(t, err)
		}()
	}
	wg.Wait()
}
