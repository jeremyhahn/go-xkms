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
	"sort"
	"strings"
)

// TeamScopedStore extends password access with team-based sharing.
// It wraps an underlying password Store and a TeamStore to enforce
// team membership and ownership rules when reading and writing
// team-scoped passwords.
//
// Ownership rules:
//   - Team owners (TeamEntity.OwnerID) can read and write team passwords.
//   - Team members (TeamEntity.Members) can only read team passwords.
//   - Non-members are denied access entirely.
type TeamScopedStore struct {
	passwordStore Store
	teamStore     TeamStore
	userID        string
}

// NewTeamScopedStore creates a TeamScopedStore for the specified user.
// The passwordStore is the underlying storage for password entries. The
// teamStore manages team entities and membership. The userID identifies
// the current user for permission checks.
func NewTeamScopedStore(passwordStore Store, teamStore TeamStore, userID string) (*TeamScopedStore, error) {
	if passwordStore == nil {
		return nil, ErrNilPasswordStore
	}
	if teamStore == nil {
		return nil, ErrNilTeamStore
	}
	if !isValidUserID(userID) {
		return nil, ErrInvalidUserID
	}
	return &TeamScopedStore{
		passwordStore: passwordStore,
		teamStore:     teamStore,
		userID:        userID,
	}, nil
}

// ListTeamPasswords returns all passwords belonging to the specified team.
// The calling user must be a member or owner of the team. Passwords are
// identified by OwnerID matching the team name and Shared being true.
func (s *TeamScopedStore) ListTeamPasswords(ctx context.Context, teamName string) ([]*StaticPassword, error) {
	team, err := s.teamStore.Get(ctx, teamName)
	if err != nil {
		return nil, err
	}

	if !s.hasAccess(team) {
		return nil, ErrNotTeamMember
	}

	all, err := s.passwordStore.List()
	if err != nil {
		return nil, err
	}

	teamPws := make([]*StaticPassword, 0)
	for _, pw := range all {
		if pw.OwnerID == teamName && pw.Shared {
			teamPws = append(teamPws, pw)
		}
	}

	sort.Slice(teamPws, func(i, j int) bool {
		return strings.ToLower(teamPws[i].Name) < strings.ToLower(teamPws[j].Name)
	})

	return teamPws, nil
}

// AddTeamPassword adds a password to the team's shared collection.
// Only the team owner may add passwords. The password's OwnerID is set
// to the team name and Shared is set to true.
func (s *TeamScopedStore) AddTeamPassword(ctx context.Context, teamName string, pw *StaticPassword) error {
	team, err := s.teamStore.Get(ctx, teamName)
	if err != nil {
		return err
	}

	if team.OwnerID != s.userID {
		return ErrNotTeamOwner
	}

	pw.OwnerID = teamName
	pw.Shared = true

	return s.passwordStore.Add(pw)
}

// GetTeamPassword retrieves a specific password from a team. The calling
// user must be a member or owner of the team.
func (s *TeamScopedStore) GetTeamPassword(ctx context.Context, teamName, idOrName string) (*StaticPassword, error) {
	team, err := s.teamStore.Get(ctx, teamName)
	if err != nil {
		return nil, err
	}

	if !s.hasAccess(team) {
		return nil, ErrNotTeamMember
	}

	pw, err := s.passwordStore.Get(idOrName)
	if err != nil {
		return nil, err
	}

	// Verify the password belongs to this team.
	if pw.OwnerID != teamName || !pw.Shared {
		return nil, ErrPasswordNotFound
	}

	return pw, nil
}

// DeleteTeamPassword removes a password from the team's collection.
// Only the team owner may delete team passwords.
func (s *TeamScopedStore) DeleteTeamPassword(ctx context.Context, teamName, idOrName string) error {
	team, err := s.teamStore.Get(ctx, teamName)
	if err != nil {
		return err
	}

	if team.OwnerID != s.userID {
		return ErrNotTeamOwner
	}

	// Verify the password belongs to this team before deleting.
	pw, err := s.passwordStore.Get(idOrName)
	if err != nil {
		return err
	}

	if pw.OwnerID != teamName || !pw.Shared {
		return ErrPasswordNotFound
	}

	return s.passwordStore.Delete(idOrName)
}

// hasAccess reports whether the current user is either the owner or a
// member of the team.
func (s *TeamScopedStore) hasAccess(team *TeamEntity) bool {
	if team.OwnerID == s.userID {
		return true
	}
	for _, m := range team.Members {
		if m == s.userID {
			return true
		}
	}
	return false
}
