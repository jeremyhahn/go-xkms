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
	"sync/atomic"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// TeamStore defines the interface for team persistence and membership management.
type TeamStore interface {
	// Create persists a new team. The team Name must be unique.
	Create(ctx context.Context, team *TeamEntity) error

	// Get retrieves a team by name.
	Get(ctx context.Context, name string) (*TeamEntity, error)

	// List returns all teams sorted by name.
	List(ctx context.Context) ([]*TeamEntity, error)

	// ListByTenant returns all teams belonging to the specified tenant,
	// sorted by name.
	ListByTenant(ctx context.Context, tenantID string) ([]*TeamEntity, error)

	// Update modifies an existing team. The team must already exist.
	Update(ctx context.Context, team *TeamEntity) error

	// Delete removes a team by name.
	Delete(ctx context.Context, name string) error

	// AddMember adds a member to a team. The member is appended to the
	// team's Members slice if not already present.
	AddMember(ctx context.Context, teamName, memberID string) error

	// RemoveMember removes a member from a team. It is not an error if
	// the member is not present.
	RemoveMember(ctx context.Context, teamName, memberID string) error

	// IsMember reports whether the given member belongs to the team.
	IsMember(ctx context.Context, teamName, memberID string) bool

	// Page retrieves a paginated set of team entities.
	Page(ctx context.Context, q qrdbsdk.PageQuery) (qrdbsdk.PageResult[*TeamEntity], error)

	// Close marks the store as closed.
	Close() error
}

// DAOTeamStore implements TeamStore using a go-qrdb GenericDAO backed by
// a kvstore.KVStore.
type DAOTeamStore struct {
	closed atomic.Bool
	dao    qrdbsdk.GenericDAO[*TeamEntity]
	idGen  *qrdbsdk.FieldHashGenerator
}

// Compile-time interface compliance check.
var _ TeamStore = (*DAOTeamStore)(nil)

// NewDAOTeamStore creates a new DAOTeamStore using the given kvstore.KVStore.
// The entity type namespace is "teams".
func NewDAOTeamStore(kvStore qrdbsdk.KVStore) (*DAOTeamStore, error) {
	if kvStore == nil {
		return nil, ErrNilKVStore{}
	}

	idGen := qrdbsdk.NewFieldHashGenerator("Name")

	teamDAO, err := qrdbsdk.NewDAO[*TeamEntity](
		kvStore,
		"teams",
		func() *TeamEntity { return &TeamEntity{} },
		qrdbsdk.WithIDGenerator(idGen),
	)
	if err != nil {
		return nil, ErrDAOCreation{Cause: err}
	}

	return &DAOTeamStore{
		dao:   teamDAO,
		idGen: idGen,
	}, nil
}

// Create persists a new team entity. It validates the team name, checks for
// duplicates, and sets timestamps.
func (s *DAOTeamStore) Create(ctx context.Context, team *TeamEntity) error {
	if s.closed.Load() {
		return ErrStoreClosed
	}

	if strings.TrimSpace(team.Name) == "" {
		return ErrTeamNameEmpty
	}

	// Check for duplicate name.
	existing, _ := s.findByName(ctx, team.Name)
	if existing != nil {
		return ErrTeamExists
	}

	now := time.Now()
	team.CreatedAt = now
	team.UpdatedAt = now

	if team.Members == nil {
		team.Members = []string{}
	}

	return s.dao.Save(ctx, team)
}

// Get retrieves a team by name. Returns ErrTeamNotFound if the team does
// not exist.
func (s *DAOTeamStore) Get(ctx context.Context, name string) (*TeamEntity, error) {
	if s.closed.Load() {
		return nil, ErrStoreClosed
	}

	if strings.TrimSpace(name) == "" {
		return nil, ErrTeamNameEmpty
	}

	team, err := s.findByName(ctx, name)
	if err != nil {
		return nil, err
	}
	return team, nil
}

// List returns all teams sorted by name (case-insensitive).
func (s *DAOTeamStore) List(ctx context.Context) ([]*TeamEntity, error) {
	if s.closed.Load() {
		return nil, ErrStoreClosed
	}

	teams, err := s.allTeams(ctx)
	if err != nil {
		return nil, err
	}

	sort.Slice(teams, func(i, j int) bool {
		return strings.ToLower(teams[i].Name) < strings.ToLower(teams[j].Name)
	})

	return teams, nil
}

// ListByTenant returns all teams belonging to the specified tenant,
// sorted by name (case-insensitive).
func (s *DAOTeamStore) ListByTenant(ctx context.Context, tenantID string) ([]*TeamEntity, error) {
	if s.closed.Load() {
		return nil, ErrStoreClosed
	}

	if strings.TrimSpace(tenantID) == "" {
		return nil, ErrInvalidTenantID
	}

	all, err := s.allTeams(ctx)
	if err != nil {
		return nil, err
	}

	filtered := make([]*TeamEntity, 0, len(all))
	for _, t := range all {
		if t.TenantID == tenantID {
			filtered = append(filtered, t)
		}
	}

	sort.Slice(filtered, func(i, j int) bool {
		return strings.ToLower(filtered[i].Name) < strings.ToLower(filtered[j].Name)
	})

	return filtered, nil
}

// Update modifies an existing team. The team is looked up by Name. Returns
// ErrTeamNotFound if the team does not exist.
func (s *DAOTeamStore) Update(ctx context.Context, team *TeamEntity) error {
	if s.closed.Load() {
		return ErrStoreClosed
	}

	if strings.TrimSpace(team.Name) == "" {
		return ErrTeamNameEmpty
	}

	existing, err := s.findByName(ctx, team.Name)
	if err != nil {
		return err
	}

	// Preserve immutable fields.
	team.ID = existing.ID
	team.CreatedAt = existing.CreatedAt
	team.UpdatedAt = time.Now()

	return s.dao.Save(ctx, team)
}

// Delete removes a team by name. Returns ErrTeamNotFound if the team does
// not exist.
func (s *DAOTeamStore) Delete(ctx context.Context, name string) error {
	if s.closed.Load() {
		return ErrStoreClosed
	}

	if strings.TrimSpace(name) == "" {
		return ErrTeamNameEmpty
	}

	existing, err := s.findByName(ctx, name)
	if err != nil {
		return err
	}

	return s.dao.Delete(ctx, existing)
}

// AddMember adds a member to a team. If the member is already present,
// the operation is a no-op. Returns ErrTeamNotFound if the team does not
// exist, or ErrInvalidUserID if the memberID is empty.
func (s *DAOTeamStore) AddMember(ctx context.Context, teamName, memberID string) error {
	if s.closed.Load() {
		return ErrStoreClosed
	}

	if !isValidUserID(memberID) {
		return ErrInvalidUserID
	}

	team, err := s.findByName(ctx, teamName)
	if err != nil {
		return err
	}

	// Check if already a member.
	for _, m := range team.Members {
		if m == memberID {
			return nil // Idempotent.
		}
	}

	team.Members = append(team.Members, memberID)
	team.UpdatedAt = time.Now()

	return s.dao.Save(ctx, team)
}

// RemoveMember removes a member from a team. If the member is not present,
// the operation is a no-op. Returns ErrTeamNotFound if the team does not exist.
func (s *DAOTeamStore) RemoveMember(ctx context.Context, teamName, memberID string) error {
	if s.closed.Load() {
		return ErrStoreClosed
	}

	if strings.TrimSpace(memberID) == "" {
		return ErrInvalidUserID
	}

	team, err := s.findByName(ctx, teamName)
	if err != nil {
		return err
	}

	filtered := make([]string, 0, len(team.Members))
	for _, m := range team.Members {
		if m != memberID {
			filtered = append(filtered, m)
		}
	}

	team.Members = filtered
	team.UpdatedAt = time.Now()

	return s.dao.Save(ctx, team)
}

// IsMember reports whether the given member belongs to the team. Returns
// false if the team does not exist or any error occurs.
func (s *DAOTeamStore) IsMember(ctx context.Context, teamName, memberID string) bool {
	if s.closed.Load() {
		return false
	}

	team, err := s.findByName(ctx, teamName)
	if err != nil {
		return false
	}

	for _, m := range team.Members {
		if m == memberID {
			return true
		}
	}
	return false
}

// Page retrieves a paginated set of team entities.
func (s *DAOTeamStore) Page(ctx context.Context, q qrdbsdk.PageQuery) (qrdbsdk.PageResult[*TeamEntity], error) {
	if s.closed.Load() {
		return qrdbsdk.PageResult[*TeamEntity]{}, ErrStoreClosed
	}
	return s.dao.Page(ctx, q)
}

// Close marks the store as closed.
func (s *DAOTeamStore) Close() error {
	s.closed.Store(true)
	return nil
}

// findByName scans all teams for a case-insensitive name match.
func (s *DAOTeamStore) findByName(ctx context.Context, name string) (*TeamEntity, error) {
	lower := strings.ToLower(name)

	var found *TeamEntity
	err := s.dao.ForEachPage(ctx, qrdbsdk.PageQuery{Page: 1, PageSize: 500}, func(result qrdbsdk.PageResult[*TeamEntity]) error {
		for _, entity := range result.Entities {
			if strings.ToLower(entity.Name) == lower {
				found = entity
				return nil
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if found == nil {
		return nil, ErrTeamNotFound
	}
	return found, nil
}

// allTeams retrieves all team entities using pagination.
func (s *DAOTeamStore) allTeams(ctx context.Context) ([]*TeamEntity, error) {
	var entities []*TeamEntity
	err := s.dao.ForEachPage(ctx, qrdbsdk.PageQuery{Page: 1, PageSize: 1000}, func(result qrdbsdk.PageResult[*TeamEntity]) error {
		entities = append(entities, result.Entities...)
		return nil
	})
	return entities, err
}
