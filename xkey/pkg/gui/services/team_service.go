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
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/staticpw"
)

// Team service errors.
var (
	// ErrTeamStoreNotSet indicates the team store has not been configured.
	ErrTeamStoreNotSet = errors.New("team_service: store not configured")

	// ErrTeamNameRequired indicates the team name is required but was empty.
	ErrTeamNameRequired = errors.New("team_service: team name is required")

	// ErrTeamMemberRequired indicates a member ID is required but was empty.
	ErrTeamMemberRequired = errors.New("team_service: member ID is required")

	// ErrTeamNotFound indicates the requested team was not found.
	ErrTeamNotFound = errors.New("team_service: team not found")
)

// TeamInfo is the frontend-facing representation of a team entity.
type TeamInfo struct {
	ID        uint64   `json:"id"`
	Name      string   `json:"name"`
	TenantID  string   `json:"tenant_id"`
	OwnerID   string   `json:"owner_id"`
	Members   []string `json:"members"`
	CreatedAt string   `json:"created_at"`
	UpdatedAt string   `json:"updated_at"`
}

// TeamService exposes team management operations to the Wails frontend.
type TeamService struct {
	store staticpw.TeamStore
	log   *slog.Logger
}

// NewTeamService creates a new TeamService. The store may be nil and set
// later via SetStore for deferred initialization.
func NewTeamService() *TeamService {
	return &TeamService{
		log: slog.Default().With("service", "team"),
	}
}

// SetStore replaces the team store. This is used for deferred initialization
// when the data directory is created after construction.
func (s *TeamService) SetStore(store staticpw.TeamStore) {
	s.store = store
}

// CreateTeam creates a new team with the given name and empty membership list.
func (s *TeamService) CreateTeam(name string) (*TeamInfo, error) {
	if s.store == nil {
		return nil, ErrTeamStoreNotSet
	}
	if name == "" {
		return nil, ErrTeamNameRequired
	}

	now := time.Now()
	entity := &staticpw.TeamEntity{
		Name:      name,
		Members:   []string{},
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := s.store.Create(context.Background(), entity); err != nil {
		s.log.Error("failed to create team", "name", name, "error", err)
		return nil, err
	}

	info := entityToTeamInfo(entity)
	return &info, nil
}

// ListTeams returns all teams in the store.
func (s *TeamService) ListTeams() ([]*TeamInfo, error) {
	if s.store == nil {
		return nil, ErrTeamStoreNotSet
	}

	entities, err := s.store.List(context.Background())
	if err != nil {
		s.log.Error("failed to list teams", "error", err)
		return nil, err
	}

	teams := make([]*TeamInfo, 0, len(entities))
	for _, e := range entities {
		info := entityToTeamInfo(e)
		teams = append(teams, &info)
	}
	return teams, nil
}

// GetTeam retrieves a team by name.
func (s *TeamService) GetTeam(name string) (*TeamInfo, error) {
	if s.store == nil {
		return nil, ErrTeamStoreNotSet
	}
	if name == "" {
		return nil, ErrTeamNameRequired
	}

	entity, err := s.store.Get(context.Background(), name)
	if err != nil {
		if errors.Is(err, staticpw.ErrTeamNotFound) {
			return nil, ErrTeamNotFound
		}
		s.log.Error("failed to get team", "name", name, "error", err)
		return nil, err
	}

	info := entityToTeamInfo(entity)
	return &info, nil
}

// DeleteTeam removes a team by name.
func (s *TeamService) DeleteTeam(name string) error {
	if s.store == nil {
		return ErrTeamStoreNotSet
	}
	if name == "" {
		return ErrTeamNameRequired
	}

	if err := s.store.Delete(context.Background(), name); err != nil {
		if errors.Is(err, staticpw.ErrTeamNotFound) {
			return ErrTeamNotFound
		}
		s.log.Error("failed to delete team", "name", name, "error", err)
		return err
	}
	return nil
}

// AddMember adds a member to a team. Adding a member who is already present
// is a no-op and does not return an error.
func (s *TeamService) AddMember(teamName, memberID string) error {
	if s.store == nil {
		return ErrTeamStoreNotSet
	}
	if teamName == "" {
		return ErrTeamNameRequired
	}
	if memberID == "" {
		return ErrTeamMemberRequired
	}

	if err := s.store.AddMember(context.Background(), teamName, memberID); err != nil {
		if errors.Is(err, staticpw.ErrTeamNotFound) {
			return ErrTeamNotFound
		}
		s.log.Error("failed to add member", "team", teamName, "member", memberID, "error", err)
		return err
	}
	return nil
}

// RemoveMember removes a member from a team. Removing a member who is not
// present is a no-op and does not return an error.
func (s *TeamService) RemoveMember(teamName, memberID string) error {
	if s.store == nil {
		return ErrTeamStoreNotSet
	}
	if teamName == "" {
		return ErrTeamNameRequired
	}
	if memberID == "" {
		return ErrTeamMemberRequired
	}

	if err := s.store.RemoveMember(context.Background(), teamName, memberID); err != nil {
		if errors.Is(err, staticpw.ErrTeamNotFound) {
			return ErrTeamNotFound
		}
		s.log.Error("failed to remove member", "team", teamName, "member", memberID, "error", err)
		return err
	}
	return nil
}

// entityToTeamInfo maps a staticpw.TeamEntity to the frontend TeamInfo type.
func entityToTeamInfo(e *staticpw.TeamEntity) TeamInfo {
	members := e.Members
	if members == nil {
		members = []string{}
	}
	return TeamInfo{
		ID:        e.ID,
		Name:      e.Name,
		TenantID:  e.TenantID,
		OwnerID:   e.OwnerID,
		Members:   members,
		CreatedAt: e.CreatedAt.Format(time.RFC3339),
		UpdatedAt: e.UpdatedAt.Format(time.RFC3339),
	}
}
