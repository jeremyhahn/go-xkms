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

package services

import (
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/staticpw"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/kvadapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestTeamService creates a TeamService backed by an in-memory store.
func newTestTeamService(t *testing.T) *TeamService {
	t.Helper()

	backend := storage.NewMemory()
	t.Cleanup(func() { backend.Close() })

	kvStore, err := kvadapter.New(backend)
	require.NoError(t, err)

	store, err := staticpw.NewDAOTeamStore(kvStore)
	require.NoError(t, err)
	t.Cleanup(func() { store.Close() })

	svc := NewTeamService()
	svc.SetStore(store)
	return svc
}

func TestTeamServiceCreateTeam(t *testing.T) {
	svc := newTestTeamService(t)

	info, err := svc.CreateTeam("engineering")
	require.NoError(t, err)
	require.NotNil(t, info)

	assert.Equal(t, "engineering", info.Name)
	assert.NotEmpty(t, info.CreatedAt)
	assert.NotEmpty(t, info.UpdatedAt)
	assert.Empty(t, info.Members)
	assert.NotZero(t, info.ID)
}

func TestTeamServiceCreateTeamStoreNotSet(t *testing.T) {
	svc := NewTeamService()

	_, err := svc.CreateTeam("ops")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrTeamStoreNotSet))
}

func TestTeamServiceCreateTeamEmptyName(t *testing.T) {
	svc := newTestTeamService(t)

	_, err := svc.CreateTeam("")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrTeamNameRequired))
}

func TestTeamServiceCreateTeamDuplicate(t *testing.T) {
	svc := newTestTeamService(t)

	_, err := svc.CreateTeam("devops")
	require.NoError(t, err)

	_, err = svc.CreateTeam("devops")
	require.Error(t, err)
}

func TestTeamServiceListTeams(t *testing.T) {
	svc := newTestTeamService(t)

	// Create multiple teams.
	_, err := svc.CreateTeam("alpha")
	require.NoError(t, err)
	_, err = svc.CreateTeam("bravo")
	require.NoError(t, err)
	_, err = svc.CreateTeam("charlie")
	require.NoError(t, err)

	teams, err := svc.ListTeams()
	require.NoError(t, err)
	assert.Len(t, teams, 3)

	// Verify sorted order (the store sorts by name).
	assert.Equal(t, "alpha", teams[0].Name)
	assert.Equal(t, "bravo", teams[1].Name)
	assert.Equal(t, "charlie", teams[2].Name)
}

func TestTeamServiceListTeamsEmpty(t *testing.T) {
	svc := newTestTeamService(t)

	teams, err := svc.ListTeams()
	require.NoError(t, err)
	assert.Empty(t, teams)
}

func TestTeamServiceListTeamsStoreNotSet(t *testing.T) {
	svc := NewTeamService()

	_, err := svc.ListTeams()
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrTeamStoreNotSet))
}

func TestTeamServiceGetTeam(t *testing.T) {
	svc := newTestTeamService(t)

	_, err := svc.CreateTeam("platform")
	require.NoError(t, err)

	info, err := svc.GetTeam("platform")
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.Equal(t, "platform", info.Name)
}

func TestTeamServiceGetTeamNotFound(t *testing.T) {
	svc := newTestTeamService(t)

	_, err := svc.GetTeam("nonexistent")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrTeamNotFound))
}

func TestTeamServiceGetTeamEmptyName(t *testing.T) {
	svc := newTestTeamService(t)

	_, err := svc.GetTeam("")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrTeamNameRequired))
}

func TestTeamServiceGetTeamStoreNotSet(t *testing.T) {
	svc := NewTeamService()

	_, err := svc.GetTeam("team1")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrTeamStoreNotSet))
}

func TestTeamServiceDeleteTeam(t *testing.T) {
	svc := newTestTeamService(t)

	_, err := svc.CreateTeam("temp-team")
	require.NoError(t, err)

	err = svc.DeleteTeam("temp-team")
	require.NoError(t, err)

	// Verify it is gone.
	_, err = svc.GetTeam("temp-team")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrTeamNotFound))
}

func TestTeamServiceDeleteTeamNotFound(t *testing.T) {
	svc := newTestTeamService(t)

	err := svc.DeleteTeam("ghost")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrTeamNotFound))
}

func TestTeamServiceDeleteTeamEmptyName(t *testing.T) {
	svc := newTestTeamService(t)

	err := svc.DeleteTeam("")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrTeamNameRequired))
}

func TestTeamServiceDeleteTeamStoreNotSet(t *testing.T) {
	svc := NewTeamService()

	err := svc.DeleteTeam("team1")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrTeamStoreNotSet))
}

func TestTeamServiceAddMember(t *testing.T) {
	svc := newTestTeamService(t)

	_, err := svc.CreateTeam("dev")
	require.NoError(t, err)

	err = svc.AddMember("dev", "user-123")
	require.NoError(t, err)

	// Verify the member appears.
	info, err := svc.GetTeam("dev")
	require.NoError(t, err)
	assert.Contains(t, info.Members, "user-123")
}

func TestTeamServiceAddMemberDuplicate(t *testing.T) {
	svc := newTestTeamService(t)

	_, err := svc.CreateTeam("dev")
	require.NoError(t, err)

	err = svc.AddMember("dev", "user-456")
	require.NoError(t, err)

	// Adding the same member again should not error (idempotent).
	err = svc.AddMember("dev", "user-456")
	require.NoError(t, err)

	// Verify member appears only once.
	info, err := svc.GetTeam("dev")
	require.NoError(t, err)
	count := 0
	for _, m := range info.Members {
		if m == "user-456" {
			count++
		}
	}
	assert.Equal(t, 1, count)
}

func TestTeamServiceAddMemberTeamNotFound(t *testing.T) {
	svc := newTestTeamService(t)

	err := svc.AddMember("nonexistent", "user-789")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrTeamNotFound))
}

func TestTeamServiceAddMemberEmptyTeamName(t *testing.T) {
	svc := newTestTeamService(t)

	err := svc.AddMember("", "user-123")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrTeamNameRequired))
}

func TestTeamServiceAddMemberEmptyMemberID(t *testing.T) {
	svc := newTestTeamService(t)

	_, err := svc.CreateTeam("dev")
	require.NoError(t, err)

	err = svc.AddMember("dev", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrTeamMemberRequired))
}

func TestTeamServiceAddMemberStoreNotSet(t *testing.T) {
	svc := NewTeamService()

	err := svc.AddMember("team1", "user-1")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrTeamStoreNotSet))
}

func TestTeamServiceRemoveMember(t *testing.T) {
	svc := newTestTeamService(t)

	_, err := svc.CreateTeam("qa")
	require.NoError(t, err)

	err = svc.AddMember("qa", "user-aaa")
	require.NoError(t, err)
	err = svc.AddMember("qa", "user-bbb")
	require.NoError(t, err)

	err = svc.RemoveMember("qa", "user-aaa")
	require.NoError(t, err)

	// Verify only user-bbb remains.
	info, err := svc.GetTeam("qa")
	require.NoError(t, err)
	assert.NotContains(t, info.Members, "user-aaa")
	assert.Contains(t, info.Members, "user-bbb")
}

func TestTeamServiceRemoveMemberNotPresent(t *testing.T) {
	svc := newTestTeamService(t)

	_, err := svc.CreateTeam("qa")
	require.NoError(t, err)

	// Removing a member who is not present should not error.
	err = svc.RemoveMember("qa", "user-ghost")
	require.NoError(t, err)
}

func TestTeamServiceRemoveMemberTeamNotFound(t *testing.T) {
	svc := newTestTeamService(t)

	err := svc.RemoveMember("nonexistent", "user-123")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrTeamNotFound))
}

func TestTeamServiceRemoveMemberEmptyTeamName(t *testing.T) {
	svc := newTestTeamService(t)

	err := svc.RemoveMember("", "user-123")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrTeamNameRequired))
}

func TestTeamServiceRemoveMemberEmptyMemberID(t *testing.T) {
	svc := newTestTeamService(t)

	_, err := svc.CreateTeam("qa")
	require.NoError(t, err)

	err = svc.RemoveMember("qa", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrTeamMemberRequired))
}

func TestTeamServiceRemoveMemberStoreNotSet(t *testing.T) {
	svc := NewTeamService()

	err := svc.RemoveMember("team1", "user-1")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrTeamStoreNotSet))
}

func TestTeamServiceFullLifecycle(t *testing.T) {
	svc := newTestTeamService(t)

	// Create a team.
	info, err := svc.CreateTeam("lifecycle-team")
	require.NoError(t, err)
	assert.Equal(t, "lifecycle-team", info.Name)
	assert.Empty(t, info.Members)

	// Add members.
	require.NoError(t, svc.AddMember("lifecycle-team", "alice"))
	require.NoError(t, svc.AddMember("lifecycle-team", "bob"))

	// Verify members.
	info, err = svc.GetTeam("lifecycle-team")
	require.NoError(t, err)
	assert.Len(t, info.Members, 2)
	assert.Contains(t, info.Members, "alice")
	assert.Contains(t, info.Members, "bob")

	// Remove one member.
	require.NoError(t, svc.RemoveMember("lifecycle-team", "alice"))
	info, err = svc.GetTeam("lifecycle-team")
	require.NoError(t, err)
	assert.Len(t, info.Members, 1)
	assert.Contains(t, info.Members, "bob")

	// List should show exactly one team.
	teams, err := svc.ListTeams()
	require.NoError(t, err)
	assert.Len(t, teams, 1)

	// Delete the team.
	require.NoError(t, svc.DeleteTeam("lifecycle-team"))

	// Verify it is gone.
	teams, err = svc.ListTeams()
	require.NoError(t, err)
	assert.Empty(t, teams)
}
