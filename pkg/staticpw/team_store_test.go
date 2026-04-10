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

package staticpw

import (
	"context"
	"testing"
	"time"

	"github.com/jeremyhahn/go-qrdb/pkg/dao"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/kvadapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestTeamStore creates a DAOTeamStore backed by in-memory storage for testing.
func newTestTeamStore(t *testing.T) *DAOTeamStore {
	t.Helper()
	backend := storage.NewMemory()
	t.Cleanup(func() { require.NoError(t, backend.Close()) })

	kvStore, err := kvadapter.New(backend)
	require.NoError(t, err)

	store, err := NewDAOTeamStore(kvStore)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.Close()) })

	return store
}

func TestTeamStore_Create(t *testing.T) {
	store := newTestTeamStore(t)
	ctx := context.Background()

	team := &TeamEntity{
		Name:     "engineering",
		TenantID: "tenant1",
		OwnerID:  "alice",
		Members:  []string{"bob", "charlie"},
	}

	err := store.Create(ctx, team)
	require.NoError(t, err)
	assert.False(t, team.CreatedAt.IsZero())
	assert.False(t, team.UpdatedAt.IsZero())

	// Verify it was persisted.
	got, err := store.Get(ctx, "engineering")
	require.NoError(t, err)
	assert.Equal(t, "engineering", got.Name)
	assert.Equal(t, "tenant1", got.TenantID)
	assert.Equal(t, "alice", got.OwnerID)
	assert.Equal(t, []string{"bob", "charlie"}, got.Members)
}

func TestTeamStore_Create_EmptyName(t *testing.T) {
	store := newTestTeamStore(t)
	ctx := context.Background()

	team := &TeamEntity{Name: "", OwnerID: "alice"}
	err := store.Create(ctx, team)
	assert.ErrorIs(t, err, ErrTeamNameEmpty)
}

func TestTeamStore_Create_WhitespaceName(t *testing.T) {
	store := newTestTeamStore(t)
	ctx := context.Background()

	team := &TeamEntity{Name: "   ", OwnerID: "alice"}
	err := store.Create(ctx, team)
	assert.ErrorIs(t, err, ErrTeamNameEmpty)
}

func TestTeamStore_Create_Duplicate(t *testing.T) {
	store := newTestTeamStore(t)
	ctx := context.Background()

	team := &TeamEntity{Name: "devops", OwnerID: "alice"}
	require.NoError(t, store.Create(ctx, team))

	dup := &TeamEntity{Name: "devops", OwnerID: "bob"}
	err := store.Create(ctx, dup)
	assert.ErrorIs(t, err, ErrTeamExists)
}

func TestTeamStore_Create_DuplicateCaseInsensitive(t *testing.T) {
	store := newTestTeamStore(t)
	ctx := context.Background()

	team := &TeamEntity{Name: "DevOps", OwnerID: "alice"}
	require.NoError(t, store.Create(ctx, team))

	dup := &TeamEntity{Name: "devops", OwnerID: "bob"}
	err := store.Create(ctx, dup)
	assert.ErrorIs(t, err, ErrTeamExists)
}

func TestTeamStore_Create_NilMembers(t *testing.T) {
	store := newTestTeamStore(t)
	ctx := context.Background()

	team := &TeamEntity{Name: "solo", OwnerID: "alice"}
	require.NoError(t, store.Create(ctx, team))

	got, err := store.Get(ctx, "solo")
	require.NoError(t, err)
	assert.NotNil(t, got.Members)
	assert.Empty(t, got.Members)
}

func TestTeamStore_Create_StoreClosed(t *testing.T) {
	store := newTestTeamStore(t)
	require.NoError(t, store.Close())

	team := &TeamEntity{Name: "test", OwnerID: "alice"}
	err := store.Create(context.Background(), team)
	assert.ErrorIs(t, err, ErrStoreClosed)
}

func TestTeamStore_Get_NotFound(t *testing.T) {
	store := newTestTeamStore(t)
	ctx := context.Background()

	_, err := store.Get(ctx, "nonexistent")
	assert.ErrorIs(t, err, ErrTeamNotFound)
}

func TestTeamStore_Get_EmptyName(t *testing.T) {
	store := newTestTeamStore(t)
	ctx := context.Background()

	_, err := store.Get(ctx, "")
	assert.ErrorIs(t, err, ErrTeamNameEmpty)
}

func TestTeamStore_Get_StoreClosed(t *testing.T) {
	store := newTestTeamStore(t)
	require.NoError(t, store.Close())

	_, err := store.Get(context.Background(), "test")
	assert.ErrorIs(t, err, ErrStoreClosed)
}

func TestTeamStore_List(t *testing.T) {
	store := newTestTeamStore(t)
	ctx := context.Background()

	require.NoError(t, store.Create(ctx, &TeamEntity{Name: "Zulu", OwnerID: "alice"}))
	require.NoError(t, store.Create(ctx, &TeamEntity{Name: "Alpha", OwnerID: "bob"}))
	require.NoError(t, store.Create(ctx, &TeamEntity{Name: "bravo", OwnerID: "charlie"}))

	teams, err := store.List(ctx)
	require.NoError(t, err)
	require.Len(t, teams, 3)
	assert.Equal(t, "Alpha", teams[0].Name)
	assert.Equal(t, "bravo", teams[1].Name)
	assert.Equal(t, "Zulu", teams[2].Name)
}

func TestTeamStore_List_Empty(t *testing.T) {
	store := newTestTeamStore(t)
	ctx := context.Background()

	teams, err := store.List(ctx)
	require.NoError(t, err)
	assert.Empty(t, teams)
}

func TestTeamStore_List_StoreClosed(t *testing.T) {
	store := newTestTeamStore(t)
	require.NoError(t, store.Close())

	_, err := store.List(context.Background())
	assert.ErrorIs(t, err, ErrStoreClosed)
}

func TestTeamStore_ListByTenant(t *testing.T) {
	store := newTestTeamStore(t)
	ctx := context.Background()

	require.NoError(t, store.Create(ctx, &TeamEntity{Name: "team-a", TenantID: "t1", OwnerID: "alice"}))
	require.NoError(t, store.Create(ctx, &TeamEntity{Name: "team-b", TenantID: "t2", OwnerID: "bob"}))
	require.NoError(t, store.Create(ctx, &TeamEntity{Name: "team-c", TenantID: "t1", OwnerID: "charlie"}))

	teams, err := store.ListByTenant(ctx, "t1")
	require.NoError(t, err)
	require.Len(t, teams, 2)
	assert.Equal(t, "team-a", teams[0].Name)
	assert.Equal(t, "team-c", teams[1].Name)
}

func TestTeamStore_ListByTenant_NoMatches(t *testing.T) {
	store := newTestTeamStore(t)
	ctx := context.Background()

	require.NoError(t, store.Create(ctx, &TeamEntity{Name: "team-a", TenantID: "t1", OwnerID: "alice"}))

	teams, err := store.ListByTenant(ctx, "t99")
	require.NoError(t, err)
	assert.Empty(t, teams)
}

func TestTeamStore_ListByTenant_EmptyTenantID(t *testing.T) {
	store := newTestTeamStore(t)
	ctx := context.Background()

	_, err := store.ListByTenant(ctx, "")
	assert.ErrorIs(t, err, ErrInvalidTenantID)
}

func TestTeamStore_ListByTenant_StoreClosed(t *testing.T) {
	store := newTestTeamStore(t)
	require.NoError(t, store.Close())

	_, err := store.ListByTenant(context.Background(), "t1")
	assert.ErrorIs(t, err, ErrStoreClosed)
}

func TestTeamStore_Update(t *testing.T) {
	store := newTestTeamStore(t)
	ctx := context.Background()

	team := &TeamEntity{Name: "ops", OwnerID: "alice", TenantID: "t1"}
	require.NoError(t, store.Create(ctx, team))

	// Update the team.
	updated := &TeamEntity{
		Name:     "ops",
		OwnerID:  "bob",
		TenantID: "t1",
		Members:  []string{"dave"},
	}
	err := store.Update(ctx, updated)
	require.NoError(t, err)

	got, err := store.Get(ctx, "ops")
	require.NoError(t, err)
	assert.Equal(t, "bob", got.OwnerID)
	assert.Equal(t, []string{"dave"}, got.Members)
	// CreatedAt is preserved (monotonic component stripped by JSON round-trip).
	assert.WithinDuration(t, team.CreatedAt, got.CreatedAt, time.Millisecond)
	assert.False(t, got.UpdatedAt.Before(team.UpdatedAt))
}

func TestTeamStore_Update_NotFound(t *testing.T) {
	store := newTestTeamStore(t)
	ctx := context.Background()

	team := &TeamEntity{Name: "ghost", OwnerID: "alice"}
	err := store.Update(ctx, team)
	assert.ErrorIs(t, err, ErrTeamNotFound)
}

func TestTeamStore_Update_EmptyName(t *testing.T) {
	store := newTestTeamStore(t)
	ctx := context.Background()

	team := &TeamEntity{Name: "", OwnerID: "alice"}
	err := store.Update(ctx, team)
	assert.ErrorIs(t, err, ErrTeamNameEmpty)
}

func TestTeamStore_Update_StoreClosed(t *testing.T) {
	store := newTestTeamStore(t)
	require.NoError(t, store.Close())

	team := &TeamEntity{Name: "test", OwnerID: "alice"}
	err := store.Update(context.Background(), team)
	assert.ErrorIs(t, err, ErrStoreClosed)
}

func TestTeamStore_Delete(t *testing.T) {
	store := newTestTeamStore(t)
	ctx := context.Background()

	require.NoError(t, store.Create(ctx, &TeamEntity{Name: "temp", OwnerID: "alice"}))

	err := store.Delete(ctx, "temp")
	require.NoError(t, err)

	_, err = store.Get(ctx, "temp")
	assert.ErrorIs(t, err, ErrTeamNotFound)
}

func TestTeamStore_Delete_NotFound(t *testing.T) {
	store := newTestTeamStore(t)
	ctx := context.Background()

	err := store.Delete(ctx, "nonexistent")
	assert.ErrorIs(t, err, ErrTeamNotFound)
}

func TestTeamStore_Delete_EmptyName(t *testing.T) {
	store := newTestTeamStore(t)
	ctx := context.Background()

	err := store.Delete(ctx, "")
	assert.ErrorIs(t, err, ErrTeamNameEmpty)
}

func TestTeamStore_Delete_StoreClosed(t *testing.T) {
	store := newTestTeamStore(t)
	require.NoError(t, store.Close())

	err := store.Delete(context.Background(), "test")
	assert.ErrorIs(t, err, ErrStoreClosed)
}

func TestTeamStore_AddMember(t *testing.T) {
	store := newTestTeamStore(t)
	ctx := context.Background()

	require.NoError(t, store.Create(ctx, &TeamEntity{Name: "dev", OwnerID: "alice"}))

	err := store.AddMember(ctx, "dev", "bob")
	require.NoError(t, err)

	team, err := store.Get(ctx, "dev")
	require.NoError(t, err)
	assert.Contains(t, team.Members, "bob")
}

func TestTeamStore_AddMember_Idempotent(t *testing.T) {
	store := newTestTeamStore(t)
	ctx := context.Background()

	require.NoError(t, store.Create(ctx, &TeamEntity{
		Name:    "dev",
		OwnerID: "alice",
		Members: []string{"bob"},
	}))

	// Adding same member again should be a no-op.
	err := store.AddMember(ctx, "dev", "bob")
	require.NoError(t, err)

	team, err := store.Get(ctx, "dev")
	require.NoError(t, err)
	assert.Equal(t, []string{"bob"}, team.Members)
}

func TestTeamStore_AddMember_TeamNotFound(t *testing.T) {
	store := newTestTeamStore(t)
	ctx := context.Background()

	err := store.AddMember(ctx, "nonexistent", "bob")
	assert.ErrorIs(t, err, ErrTeamNotFound)
}

func TestTeamStore_AddMember_InvalidUserID(t *testing.T) {
	store := newTestTeamStore(t)
	ctx := context.Background()

	require.NoError(t, store.Create(ctx, &TeamEntity{Name: "dev", OwnerID: "alice"}))

	err := store.AddMember(ctx, "dev", "")
	assert.ErrorIs(t, err, ErrInvalidUserID)
}

func TestTeamStore_AddMember_StoreClosed(t *testing.T) {
	store := newTestTeamStore(t)
	require.NoError(t, store.Close())

	err := store.AddMember(context.Background(), "dev", "bob")
	assert.ErrorIs(t, err, ErrStoreClosed)
}

func TestTeamStore_RemoveMember(t *testing.T) {
	store := newTestTeamStore(t)
	ctx := context.Background()

	require.NoError(t, store.Create(ctx, &TeamEntity{
		Name:    "dev",
		OwnerID: "alice",
		Members: []string{"bob", "charlie"},
	}))

	err := store.RemoveMember(ctx, "dev", "bob")
	require.NoError(t, err)

	team, err := store.Get(ctx, "dev")
	require.NoError(t, err)
	assert.Equal(t, []string{"charlie"}, team.Members)
}

func TestTeamStore_RemoveMember_NotPresent(t *testing.T) {
	store := newTestTeamStore(t)
	ctx := context.Background()

	require.NoError(t, store.Create(ctx, &TeamEntity{
		Name:    "dev",
		OwnerID: "alice",
		Members: []string{"bob"},
	}))

	// Removing a non-member should be a no-op.
	err := store.RemoveMember(ctx, "dev", "dave")
	require.NoError(t, err)

	team, err := store.Get(ctx, "dev")
	require.NoError(t, err)
	assert.Equal(t, []string{"bob"}, team.Members)
}

func TestTeamStore_RemoveMember_TeamNotFound(t *testing.T) {
	store := newTestTeamStore(t)
	ctx := context.Background()

	err := store.RemoveMember(ctx, "nonexistent", "bob")
	assert.ErrorIs(t, err, ErrTeamNotFound)
}

func TestTeamStore_RemoveMember_EmptyMemberID(t *testing.T) {
	store := newTestTeamStore(t)
	ctx := context.Background()

	require.NoError(t, store.Create(ctx, &TeamEntity{Name: "dev", OwnerID: "alice"}))

	err := store.RemoveMember(ctx, "dev", "")
	assert.ErrorIs(t, err, ErrInvalidUserID)
}

func TestTeamStore_RemoveMember_StoreClosed(t *testing.T) {
	store := newTestTeamStore(t)
	require.NoError(t, store.Close())

	err := store.RemoveMember(context.Background(), "dev", "bob")
	assert.ErrorIs(t, err, ErrStoreClosed)
}

func TestTeamStore_IsMember_True(t *testing.T) {
	store := newTestTeamStore(t)
	ctx := context.Background()

	require.NoError(t, store.Create(ctx, &TeamEntity{
		Name:    "dev",
		OwnerID: "alice",
		Members: []string{"bob"},
	}))

	assert.True(t, store.IsMember(ctx, "dev", "bob"))
}

func TestTeamStore_IsMember_False(t *testing.T) {
	store := newTestTeamStore(t)
	ctx := context.Background()

	require.NoError(t, store.Create(ctx, &TeamEntity{
		Name:    "dev",
		OwnerID: "alice",
		Members: []string{"bob"},
	}))

	assert.False(t, store.IsMember(ctx, "dev", "charlie"))
}

func TestTeamStore_IsMember_TeamNotFound(t *testing.T) {
	store := newTestTeamStore(t)
	ctx := context.Background()

	assert.False(t, store.IsMember(ctx, "nonexistent", "bob"))
}

func TestTeamStore_IsMember_StoreClosed(t *testing.T) {
	store := newTestTeamStore(t)
	require.NoError(t, store.Close())

	assert.False(t, store.IsMember(context.Background(), "dev", "bob"))
}

func TestTeamStore_Page(t *testing.T) {
	store := newTestTeamStore(t)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		name := string(rune('A'+i)) + "-team"
		require.NoError(t, store.Create(ctx, &TeamEntity{
			Name:    name,
			OwnerID: "alice",
		}))
	}

	result, err := store.Page(ctx, dao.PageQuery{Page: 1, PageSize: 2})
	require.NoError(t, err)
	assert.Len(t, result.Entities, 2)
	assert.Equal(t, 5, result.Total)
	assert.True(t, result.HasMore)
}

func TestTeamStore_Page_SecondPage(t *testing.T) {
	store := newTestTeamStore(t)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		name := string(rune('A'+i)) + "-team"
		require.NoError(t, store.Create(ctx, &TeamEntity{
			Name:    name,
			OwnerID: "alice",
		}))
	}

	result, err := store.Page(ctx, dao.PageQuery{Page: 3, PageSize: 2})
	require.NoError(t, err)
	assert.Len(t, result.Entities, 1)
	assert.False(t, result.HasMore)
}

func TestTeamStore_Page_StoreClosed(t *testing.T) {
	store := newTestTeamStore(t)
	require.NoError(t, store.Close())

	_, err := store.Page(context.Background(), dao.PageQuery{Page: 1, PageSize: 10})
	assert.ErrorIs(t, err, ErrStoreClosed)
}

func TestTeamStore_Close_Idempotent(t *testing.T) {
	store := newTestTeamStore(t)

	require.NoError(t, store.Close())
	require.NoError(t, store.Close())
}

func TestTeamStore_NilKVStore(t *testing.T) {
	_, err := NewDAOTeamStore(nil)
	assert.ErrorAs(t, err, &ErrNilKVStore{})
}
