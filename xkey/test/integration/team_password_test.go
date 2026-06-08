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

//go:build integration && linux

package xkey

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/services"
)

// newFileBackedTeamService creates a TeamService backed by file-based storage
// in a temporary directory. The directory and all resources are cleaned up
// when the test completes.
func newFileBackedTeamService(t *testing.T) *services.TeamService {
	t.Helper()

	tmpDir := t.TempDir()

	backend, err := xkms.NewFileStorageBackend(tmpDir)
	require.NoError(t, err)
	t.Cleanup(func() { backend.Close() })

	kvStore, err := xkms.NewKVStoreAdapter(backend)
	require.NoError(t, err)

	teamStore, err := xkms.NewStaticPasswordDAOTeamStore(kvStore)
	require.NoError(t, err)
	t.Cleanup(func() { teamStore.Close() })

	svc := services.NewTeamService()
	svc.SetStore(teamStore)
	return svc
}

// newFileBackedPasswordStore creates a xkms.StaticPasswordStore backed by file storage
// in the given directory.
func newFileBackedPasswordStore(t *testing.T, dir string) xkms.StaticPasswordStore {
	t.Helper()

	backend, err := xkms.NewFileStorageBackend(dir)
	require.NoError(t, err)
	t.Cleanup(func() { backend.Close() })

	store := xkms.NewStaticPasswordStore(backend)
	t.Cleanup(func() { store.Close() })
	return store
}

// newFileBackedTeamStore creates a xkms.StaticPasswordTeamStore backed by file storage
// in the given directory.
func newFileBackedTeamStore(t *testing.T, dir string) xkms.StaticPasswordTeamStore {
	t.Helper()

	backend, err := xkms.NewFileStorageBackend(dir)
	require.NoError(t, err)
	t.Cleanup(func() { backend.Close() })

	kvStore, err := xkms.NewKVStoreAdapter(backend)
	require.NoError(t, err)

	teamStore, err := xkms.NewStaticPasswordDAOTeamStore(kvStore)
	require.NoError(t, err)
	t.Cleanup(func() { teamStore.Close() })
	return teamStore
}

func TestTeamLifecycle(t *testing.T) {
	svc := newFileBackedTeamService(t)

	// Create a team and verify the returned info.
	info, err := svc.CreateTeam("engineering")
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.Equal(t, "engineering", info.Name)
	assert.NotZero(t, info.ID)
	assert.NotEmpty(t, info.CreatedAt)
	assert.NotEmpty(t, info.UpdatedAt)
	assert.Empty(t, info.Members)

	// List teams and verify the team appears.
	teams, err := svc.ListTeams()
	require.NoError(t, err)
	require.Len(t, teams, 1)
	assert.Equal(t, "engineering", teams[0].Name)

	// Add two members.
	require.NoError(t, svc.AddMember("engineering", "user-alice"))
	require.NoError(t, svc.AddMember("engineering", "user-bob"))

	// Verify both members are present.
	info, err = svc.GetTeam("engineering")
	require.NoError(t, err)
	assert.Len(t, info.Members, 2)
	assert.Contains(t, info.Members, "user-alice")
	assert.Contains(t, info.Members, "user-bob")

	// Remove bob and verify alice remains.
	require.NoError(t, svc.RemoveMember("engineering", "user-bob"))

	info, err = svc.GetTeam("engineering")
	require.NoError(t, err)
	assert.Len(t, info.Members, 1)
	assert.Contains(t, info.Members, "user-alice")
	assert.NotContains(t, info.Members, "user-bob")

	// Delete the team.
	require.NoError(t, svc.DeleteTeam("engineering"))

	// Verify the team list is empty.
	teams, err = svc.ListTeams()
	require.NoError(t, err)
	assert.Empty(t, teams)
}

func TestTeamScopedPasswordAccess(t *testing.T) {
	tmpDir := t.TempDir()

	teamStore := newFileBackedTeamStore(t, tmpDir)
	passwordStore := newFileBackedPasswordStore(t, tmpDir)

	// Create a team with an owner and a member.
	ctx := context.Background()
	team := &xkms.StaticPasswordTeamEntity{
		Name:    "devops",
		OwnerID: "admin",
		Members: []string{"alice"},
	}
	require.NoError(t, teamStore.Create(ctx, team))

	// Owner adds a password under team scope.
	ownerScoped, err := xkms.NewStaticPasswordTeamScopedStore(passwordStore, teamStore, "admin")
	require.NoError(t, err)

	pw := &xkms.StaticPassword{
		Name:     "prod-db",
		Password: "s3cret-db-pass",
	}
	require.NoError(t, ownerScoped.AddTeamPassword(ctx, "devops", pw))

	// Member can read team passwords.
	memberScoped, err := xkms.NewStaticPasswordTeamScopedStore(passwordStore, teamStore, "alice")
	require.NoError(t, err)

	passwords, err := memberScoped.ListTeamPasswords(ctx, "devops")
	require.NoError(t, err)
	require.Len(t, passwords, 1)
	assert.Equal(t, "prod-db", passwords[0].Name)
	assert.True(t, passwords[0].Shared)
	assert.Equal(t, "devops", passwords[0].OwnerID)

	// Member can get a specific team password.
	fetched, err := memberScoped.GetTeamPassword(ctx, "devops", "prod-db")
	require.NoError(t, err)
	assert.Equal(t, "prod-db", fetched.Name)

	// Non-member is denied access.
	outsiderScoped, err := xkms.NewStaticPasswordTeamScopedStore(passwordStore, teamStore, "outsider")
	require.NoError(t, err)

	_, err = outsiderScoped.ListTeamPasswords(ctx, "devops")
	require.Error(t, err)
	assert.True(t, errors.Is(err, xkms.ErrStaticPasswordNotTeamMember))

	_, err = outsiderScoped.GetTeamPassword(ctx, "devops", "prod-db")
	require.Error(t, err)
	assert.True(t, errors.Is(err, xkms.ErrStaticPasswordNotTeamMember))

	// Member cannot add passwords (only owner can).
	memberPW := &xkms.StaticPassword{
		Name:     "staging-db",
		Password: "staging-pass",
	}
	err = memberScoped.AddTeamPassword(ctx, "devops", memberPW)
	require.Error(t, err)
	assert.True(t, errors.Is(err, xkms.ErrStaticPasswordNotTeamOwner))

	// Member cannot delete team passwords (only owner can).
	err = memberScoped.DeleteTeamPassword(ctx, "devops", "prod-db")
	require.Error(t, err)
	assert.True(t, errors.Is(err, xkms.ErrStaticPasswordNotTeamOwner))

	// Owner can delete team passwords.
	require.NoError(t, ownerScoped.DeleteTeamPassword(ctx, "devops", "prod-db"))

	passwords, err = ownerScoped.ListTeamPasswords(ctx, "devops")
	require.NoError(t, err)
	assert.Empty(t, passwords)
}

func TestMultipleTeamsIsolation(t *testing.T) {
	tmpDir := t.TempDir()

	teamStore := newFileBackedTeamStore(t, tmpDir)
	passwordStore := newFileBackedPasswordStore(t, tmpDir)

	ctx := context.Background()

	// Create two teams with the same owner.
	frontendTeam := &xkms.StaticPasswordTeamEntity{
		Name:    "frontend",
		OwnerID: "admin",
		Members: []string{"user-fe1"},
	}
	backendTeam := &xkms.StaticPasswordTeamEntity{
		Name:    "backend",
		OwnerID: "admin",
		Members: []string{"user-be1"},
	}
	require.NoError(t, teamStore.Create(ctx, frontendTeam))
	require.NoError(t, teamStore.Create(ctx, backendTeam))

	// Owner adds passwords to each team.
	ownerScoped, err := xkms.NewStaticPasswordTeamScopedStore(passwordStore, teamStore, "admin")
	require.NoError(t, err)

	require.NoError(t, ownerScoped.AddTeamPassword(ctx, "frontend", &xkms.StaticPassword{
		Name:     "cdn-key",
		Password: "cdn-secret-123",
	}))
	require.NoError(t, ownerScoped.AddTeamPassword(ctx, "frontend", &xkms.StaticPassword{
		Name:     "analytics-token",
		Password: "analytics-abc",
	}))
	require.NoError(t, ownerScoped.AddTeamPassword(ctx, "backend", &xkms.StaticPassword{
		Name:     "database-root",
		Password: "db-root-pass",
	}))

	// Frontend team sees only its passwords.
	fePws, err := ownerScoped.ListTeamPasswords(ctx, "frontend")
	require.NoError(t, err)
	assert.Len(t, fePws, 2)

	feNames := make([]string, len(fePws))
	for i, p := range fePws {
		feNames[i] = p.Name
	}
	assert.Contains(t, feNames, "cdn-key")
	assert.Contains(t, feNames, "analytics-token")
	assert.NotContains(t, feNames, "database-root")

	// Backend team sees only its passwords.
	bePws, err := ownerScoped.ListTeamPasswords(ctx, "backend")
	require.NoError(t, err)
	assert.Len(t, bePws, 1)
	assert.Equal(t, "database-root", bePws[0].Name)

	// Frontend member cannot see backend passwords.
	feScoped, err := xkms.NewStaticPasswordTeamScopedStore(passwordStore, teamStore, "user-fe1")
	require.NoError(t, err)

	_, err = feScoped.ListTeamPasswords(ctx, "backend")
	require.Error(t, err)
	assert.True(t, errors.Is(err, xkms.ErrStaticPasswordNotTeamMember))

	// Backend member cannot see frontend passwords.
	beScoped, err := xkms.NewStaticPasswordTeamScopedStore(passwordStore, teamStore, "user-be1")
	require.NoError(t, err)

	_, err = beScoped.ListTeamPasswords(ctx, "frontend")
	require.Error(t, err)
	assert.True(t, errors.Is(err, xkms.ErrStaticPasswordNotTeamMember))
}

func TestTeamServiceErrorCases(t *testing.T) {
	t.Run("duplicate team name", func(t *testing.T) {
		svc := newFileBackedTeamService(t)

		_, err := svc.CreateTeam("devops")
		require.NoError(t, err)

		_, err = svc.CreateTeam("devops")
		require.Error(t, err)
		assert.True(t, errors.Is(err, xkms.ErrStaticPasswordTeamExists))
	})

	t.Run("delete non-existent team", func(t *testing.T) {
		svc := newFileBackedTeamService(t)

		err := svc.DeleteTeam("phantom")
		require.Error(t, err)
		assert.True(t, errors.Is(err, services.ErrTeamNotFound))
	})

	t.Run("add member to non-existent team", func(t *testing.T) {
		svc := newFileBackedTeamService(t)

		err := svc.AddMember("phantom", "user-1")
		require.Error(t, err)
		assert.True(t, errors.Is(err, services.ErrTeamNotFound))
	})

	t.Run("create team with empty name", func(t *testing.T) {
		svc := newFileBackedTeamService(t)

		_, err := svc.CreateTeam("")
		require.Error(t, err)
		assert.True(t, errors.Is(err, services.ErrTeamNameRequired))
	})

	t.Run("get non-existent team", func(t *testing.T) {
		svc := newFileBackedTeamService(t)

		_, err := svc.GetTeam("ghost")
		require.Error(t, err)
		assert.True(t, errors.Is(err, services.ErrTeamNotFound))
	})

	t.Run("add member with empty team name", func(t *testing.T) {
		svc := newFileBackedTeamService(t)

		err := svc.AddMember("", "user-1")
		require.Error(t, err)
		assert.True(t, errors.Is(err, services.ErrTeamNameRequired))
	})

	t.Run("add member with empty member ID", func(t *testing.T) {
		svc := newFileBackedTeamService(t)

		_, err := svc.CreateTeam("ops")
		require.NoError(t, err)

		err = svc.AddMember("ops", "")
		require.Error(t, err)
		assert.True(t, errors.Is(err, services.ErrTeamMemberRequired))
	})

	t.Run("remove member with empty team name", func(t *testing.T) {
		svc := newFileBackedTeamService(t)

		err := svc.RemoveMember("", "user-1")
		require.Error(t, err)
		assert.True(t, errors.Is(err, services.ErrTeamNameRequired))
	})

	t.Run("remove member with empty member ID", func(t *testing.T) {
		svc := newFileBackedTeamService(t)

		_, err := svc.CreateTeam("ops")
		require.NoError(t, err)

		err = svc.RemoveMember("ops", "")
		require.Error(t, err)
		assert.True(t, errors.Is(err, services.ErrTeamMemberRequired))
	})

	t.Run("remove member from non-existent team", func(t *testing.T) {
		svc := newFileBackedTeamService(t)

		err := svc.RemoveMember("phantom", "user-1")
		require.Error(t, err)
		assert.True(t, errors.Is(err, services.ErrTeamNotFound))
	})

	t.Run("get team with empty name", func(t *testing.T) {
		svc := newFileBackedTeamService(t)

		_, err := svc.GetTeam("")
		require.Error(t, err)
		assert.True(t, errors.Is(err, services.ErrTeamNameRequired))
	})

	t.Run("delete team with empty name", func(t *testing.T) {
		svc := newFileBackedTeamService(t)

		err := svc.DeleteTeam("")
		require.Error(t, err)
		assert.True(t, errors.Is(err, services.ErrTeamNameRequired))
	})

	t.Run("operations with store not set", func(t *testing.T) {
		svc := services.NewTeamService()

		_, err := svc.CreateTeam("ops")
		require.Error(t, err)
		assert.True(t, errors.Is(err, services.ErrTeamStoreNotSet))

		_, err = svc.ListTeams()
		require.Error(t, err)
		assert.True(t, errors.Is(err, services.ErrTeamStoreNotSet))

		_, err = svc.GetTeam("ops")
		require.Error(t, err)
		assert.True(t, errors.Is(err, services.ErrTeamStoreNotSet))

		err = svc.DeleteTeam("ops")
		require.Error(t, err)
		assert.True(t, errors.Is(err, services.ErrTeamStoreNotSet))

		err = svc.AddMember("ops", "user-1")
		require.Error(t, err)
		assert.True(t, errors.Is(err, services.ErrTeamStoreNotSet))

		err = svc.RemoveMember("ops", "user-1")
		require.Error(t, err)
		assert.True(t, errors.Is(err, services.ErrTeamStoreNotSet))
	})
}

func TestTeamScopedStoreConstructorErrors(t *testing.T) {
	tmpDir := t.TempDir()
	passwordStore := newFileBackedPasswordStore(t, tmpDir)
	teamStore := newFileBackedTeamStore(t, tmpDir)

	t.Run("nil password store", func(t *testing.T) {
		_, err := xkms.NewStaticPasswordTeamScopedStore(nil, teamStore, "user-1")
		require.Error(t, err)
		assert.True(t, errors.Is(err, xkms.ErrStaticPasswordNilPasswordStore))
	})

	t.Run("nil team store", func(t *testing.T) {
		_, err := xkms.NewStaticPasswordTeamScopedStore(passwordStore, nil, "user-1")
		require.Error(t, err)
		assert.True(t, errors.Is(err, xkms.ErrStaticPasswordNilTeamStore))
	})

	t.Run("empty user ID", func(t *testing.T) {
		_, err := xkms.NewStaticPasswordTeamScopedStore(passwordStore, teamStore, "")
		require.Error(t, err)
		assert.True(t, errors.Is(err, xkms.ErrStaticPasswordInvalidUserID))
	})
}

func TestTeamMemberIdempotency(t *testing.T) {
	svc := newFileBackedTeamService(t)

	_, err := svc.CreateTeam("platform")
	require.NoError(t, err)

	// Adding the same member twice should be idempotent.
	require.NoError(t, svc.AddMember("platform", "user-alice"))
	require.NoError(t, svc.AddMember("platform", "user-alice"))

	info, err := svc.GetTeam("platform")
	require.NoError(t, err)

	count := 0
	for _, m := range info.Members {
		if m == "user-alice" {
			count++
		}
	}
	assert.Equal(t, 1, count, "duplicate member should not be added")

	// Removing a non-existent member should be idempotent.
	require.NoError(t, svc.RemoveMember("platform", "user-nonexistent"))
}

func TestTeamPersistenceAcrossServiceInstances(t *testing.T) {
	tmpDir := t.TempDir()

	// First service instance: create a team and add members.
	func() {
		backend, err := xkms.NewFileStorageBackend(tmpDir)
		require.NoError(t, err)
		defer backend.Close()

		kvStore, err := xkms.NewKVStoreAdapter(backend)
		require.NoError(t, err)

		teamStore, err := xkms.NewStaticPasswordDAOTeamStore(kvStore)
		require.NoError(t, err)
		defer teamStore.Close()

		svc := services.NewTeamService()
		svc.SetStore(teamStore)

		_, err = svc.CreateTeam("persistent-team")
		require.NoError(t, err)
		require.NoError(t, svc.AddMember("persistent-team", "user-alice"))
		require.NoError(t, svc.AddMember("persistent-team", "user-bob"))
	}()

	// Second service instance: verify the team and members persist.
	backend, err := xkms.NewFileStorageBackend(tmpDir)
	require.NoError(t, err)
	defer backend.Close()

	kvStore, err := xkms.NewKVStoreAdapter(backend)
	require.NoError(t, err)

	teamStore, err := xkms.NewStaticPasswordDAOTeamStore(kvStore)
	require.NoError(t, err)
	defer teamStore.Close()

	svc := services.NewTeamService()
	svc.SetStore(teamStore)

	teams, err := svc.ListTeams()
	require.NoError(t, err)
	require.Len(t, teams, 1)
	assert.Equal(t, "persistent-team", teams[0].Name)

	info, err := svc.GetTeam("persistent-team")
	require.NoError(t, err)
	assert.Len(t, info.Members, 2)
	assert.Contains(t, info.Members, "user-alice")
	assert.Contains(t, info.Members, "user-bob")
}
