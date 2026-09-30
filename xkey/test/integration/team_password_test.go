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
