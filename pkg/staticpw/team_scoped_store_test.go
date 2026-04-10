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

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/kvadapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestTeamScopedSetup creates a TeamScopedStore along with the
// underlying password store, team store, and a pre-created team.
// The team "engineering" is owned by "alice" with member "bob".
func newTestTeamScopedSetup(t *testing.T, userID string) (*TeamScopedStore, Store, *DAOTeamStore) {
	t.Helper()

	backend := storage.NewMemory()
	t.Cleanup(func() { require.NoError(t, backend.Close()) })

	// Password store.
	pwStore := NewStore(backend)
	t.Cleanup(func() { require.NoError(t, pwStore.Close()) })

	// Team store (needs its own kvstore for DAO).
	kvStore, err := kvadapter.New(backend)
	require.NoError(t, err)

	teamStore, err := NewDAOTeamStore(kvStore)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, teamStore.Close()) })

	// Create a team.
	ctx := context.Background()
	require.NoError(t, teamStore.Create(ctx, &TeamEntity{
		Name:    "engineering",
		OwnerID: "alice",
		Members: []string{"bob"},
	}))

	scopedStore, err := NewTeamScopedStore(pwStore, teamStore, userID)
	require.NoError(t, err)

	return scopedStore, pwStore, teamStore
}

func TestTeamScopedStore_ListTeamPasswords_AsMember(t *testing.T) {
	scopedStore, pwStore, _ := newTestTeamScopedSetup(t, "bob")
	ctx := context.Background()

	// Add passwords owned by the team.
	require.NoError(t, pwStore.Add(&StaticPassword{
		Name:     "deploy-key",
		Password: "s3cret",
		OwnerID:  "engineering",
		Shared:   true,
	}))
	require.NoError(t, pwStore.Add(&StaticPassword{
		Name:     "api-token",
		Password: "tok3n",
		OwnerID:  "engineering",
		Shared:   true,
	}))
	// Add a non-team password that should be excluded.
	require.NoError(t, pwStore.Add(&StaticPassword{
		Name:     "personal-key",
		Password: "mine",
		OwnerID:  "bob",
		Shared:   false,
	}))

	passwords, err := scopedStore.ListTeamPasswords(ctx, "engineering")
	require.NoError(t, err)
	require.Len(t, passwords, 2)
	assert.Equal(t, "api-token", passwords[0].Name) // Sorted.
	assert.Equal(t, "deploy-key", passwords[1].Name)
}

func TestTeamScopedStore_ListTeamPasswords_AsOwner(t *testing.T) {
	scopedStore, pwStore, _ := newTestTeamScopedSetup(t, "alice")
	ctx := context.Background()

	require.NoError(t, pwStore.Add(&StaticPassword{
		Name:     "root-pw",
		Password: "r00t",
		OwnerID:  "engineering",
		Shared:   true,
	}))

	passwords, err := scopedStore.ListTeamPasswords(ctx, "engineering")
	require.NoError(t, err)
	require.Len(t, passwords, 1)
	assert.Equal(t, "root-pw", passwords[0].Name)
}

func TestTeamScopedStore_ListTeamPasswords_NonMemberDenied(t *testing.T) {
	scopedStore, _, _ := newTestTeamScopedSetup(t, "eve")
	ctx := context.Background()

	_, err := scopedStore.ListTeamPasswords(ctx, "engineering")
	assert.ErrorIs(t, err, ErrNotTeamMember)
}

func TestTeamScopedStore_ListTeamPasswords_TeamNotFound(t *testing.T) {
	scopedStore, _, _ := newTestTeamScopedSetup(t, "alice")
	ctx := context.Background()

	_, err := scopedStore.ListTeamPasswords(ctx, "nonexistent")
	assert.ErrorIs(t, err, ErrTeamNotFound)
}

func TestTeamScopedStore_ListTeamPasswords_Empty(t *testing.T) {
	scopedStore, _, _ := newTestTeamScopedSetup(t, "alice")
	ctx := context.Background()

	passwords, err := scopedStore.ListTeamPasswords(ctx, "engineering")
	require.NoError(t, err)
	assert.Empty(t, passwords)
}

func TestTeamScopedStore_AddTeamPassword_AsOwner(t *testing.T) {
	scopedStore, pwStore, _ := newTestTeamScopedSetup(t, "alice")
	ctx := context.Background()

	pw := &StaticPassword{
		Name:     "shared-key",
		Password: "key123",
	}

	err := scopedStore.AddTeamPassword(ctx, "engineering", pw)
	require.NoError(t, err)
	assert.Equal(t, "engineering", pw.OwnerID)
	assert.True(t, pw.Shared)

	// Verify it was persisted.
	got, err := pwStore.Get("shared-key")
	require.NoError(t, err)
	assert.Equal(t, "engineering", got.OwnerID)
	assert.True(t, got.Shared)
}

func TestTeamScopedStore_AddTeamPassword_AsMemberDenied(t *testing.T) {
	scopedStore, _, _ := newTestTeamScopedSetup(t, "bob")
	ctx := context.Background()

	pw := &StaticPassword{
		Name:     "hack-attempt",
		Password: "nope",
	}

	err := scopedStore.AddTeamPassword(ctx, "engineering", pw)
	assert.ErrorIs(t, err, ErrNotTeamOwner)
}

func TestTeamScopedStore_AddTeamPassword_NonMemberDenied(t *testing.T) {
	scopedStore, _, _ := newTestTeamScopedSetup(t, "eve")
	ctx := context.Background()

	pw := &StaticPassword{
		Name:     "intruder",
		Password: "nope",
	}

	// Eve is not a member but can find the team; denied because she is not the owner.
	err := scopedStore.AddTeamPassword(ctx, "engineering", pw)
	assert.ErrorIs(t, err, ErrNotTeamOwner)
}

func TestTeamScopedStore_AddTeamPassword_TeamNotFound(t *testing.T) {
	scopedStore, _, _ := newTestTeamScopedSetup(t, "alice")
	ctx := context.Background()

	pw := &StaticPassword{
		Name:     "orphan",
		Password: "nope",
	}

	err := scopedStore.AddTeamPassword(ctx, "nonexistent", pw)
	assert.ErrorIs(t, err, ErrTeamNotFound)
}

func TestTeamScopedStore_GetTeamPassword_AsMember(t *testing.T) {
	scopedStore, pwStore, _ := newTestTeamScopedSetup(t, "bob")
	ctx := context.Background()

	require.NoError(t, pwStore.Add(&StaticPassword{
		Name:     "the-key",
		Password: "val",
		OwnerID:  "engineering",
		Shared:   true,
	}))

	pw, err := scopedStore.GetTeamPassword(ctx, "engineering", "the-key")
	require.NoError(t, err)
	assert.Equal(t, "the-key", pw.Name)
}

func TestTeamScopedStore_GetTeamPassword_NonMemberDenied(t *testing.T) {
	scopedStore, pwStore, _ := newTestTeamScopedSetup(t, "eve")
	ctx := context.Background()

	require.NoError(t, pwStore.Add(&StaticPassword{
		Name:     "the-key",
		Password: "val",
		OwnerID:  "engineering",
		Shared:   true,
	}))

	_, err := scopedStore.GetTeamPassword(ctx, "engineering", "the-key")
	assert.ErrorIs(t, err, ErrNotTeamMember)
}

func TestTeamScopedStore_GetTeamPassword_WrongTeam(t *testing.T) {
	scopedStore, pwStore, _ := newTestTeamScopedSetup(t, "alice")
	ctx := context.Background()

	// Add a password owned by a different team.
	require.NoError(t, pwStore.Add(&StaticPassword{
		Name:     "other-pw",
		Password: "val",
		OwnerID:  "other-team",
		Shared:   true,
	}))

	_, err := scopedStore.GetTeamPassword(ctx, "engineering", "other-pw")
	assert.ErrorIs(t, err, ErrPasswordNotFound)
}

func TestTeamScopedStore_DeleteTeamPassword_AsOwner(t *testing.T) {
	scopedStore, pwStore, _ := newTestTeamScopedSetup(t, "alice")
	ctx := context.Background()

	require.NoError(t, pwStore.Add(&StaticPassword{
		Name:     "deleteme",
		Password: "bye",
		OwnerID:  "engineering",
		Shared:   true,
	}))

	err := scopedStore.DeleteTeamPassword(ctx, "engineering", "deleteme")
	require.NoError(t, err)

	_, err = pwStore.Get("deleteme")
	assert.ErrorIs(t, err, ErrPasswordNotFound)
}

func TestTeamScopedStore_DeleteTeamPassword_AsMemberDenied(t *testing.T) {
	scopedStore, pwStore, _ := newTestTeamScopedSetup(t, "bob")
	ctx := context.Background()

	require.NoError(t, pwStore.Add(&StaticPassword{
		Name:     "nodelete",
		Password: "stay",
		OwnerID:  "engineering",
		Shared:   true,
	}))

	err := scopedStore.DeleteTeamPassword(ctx, "engineering", "nodelete")
	assert.ErrorIs(t, err, ErrNotTeamOwner)
}

func TestTeamScopedStore_DeleteTeamPassword_WrongTeam(t *testing.T) {
	scopedStore, pwStore, _ := newTestTeamScopedSetup(t, "alice")
	ctx := context.Background()

	require.NoError(t, pwStore.Add(&StaticPassword{
		Name:     "foreign",
		Password: "val",
		OwnerID:  "other-team",
		Shared:   true,
	}))

	err := scopedStore.DeleteTeamPassword(ctx, "engineering", "foreign")
	assert.ErrorIs(t, err, ErrPasswordNotFound)
}

func TestTeamScopedStore_Constructor_NilPasswordStore(t *testing.T) {
	backend := storage.NewMemory()
	defer func() { require.NoError(t, backend.Close()) }()

	kvStore, err := kvadapter.New(backend)
	require.NoError(t, err)

	teamStore, err := NewDAOTeamStore(kvStore)
	require.NoError(t, err)
	defer func() { require.NoError(t, teamStore.Close()) }()

	_, err = NewTeamScopedStore(nil, teamStore, "alice")
	assert.ErrorIs(t, err, ErrNilPasswordStore)
}

func TestTeamScopedStore_Constructor_NilTeamStore(t *testing.T) {
	backend := storage.NewMemory()
	defer func() { require.NoError(t, backend.Close()) }()

	pwStore := NewStore(backend)
	defer func() { require.NoError(t, pwStore.Close()) }()

	_, err := NewTeamScopedStore(pwStore, nil, "alice")
	assert.ErrorIs(t, err, ErrNilTeamStore)
}

func TestTeamScopedStore_Constructor_InvalidUserID(t *testing.T) {
	backend := storage.NewMemory()
	defer func() { require.NoError(t, backend.Close()) }()

	kvStore, err := kvadapter.New(backend)
	require.NoError(t, err)

	pwStore := NewStore(backend)
	defer func() { require.NoError(t, pwStore.Close()) }()

	teamStore, err := NewDAOTeamStore(kvStore)
	require.NoError(t, err)
	defer func() { require.NoError(t, teamStore.Close()) }()

	_, err = NewTeamScopedStore(pwStore, teamStore, "")
	assert.ErrorIs(t, err, ErrInvalidUserID)
}
