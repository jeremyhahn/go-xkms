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
	"time"
)

// Service provides business logic for custodian group management.
type Service struct {
	store CustodianGroupStore
}

// NewService creates a new custodian Service backed by the given store.
// Returns ErrNilStore if store is nil.
func NewService(store CustodianGroupStore) (*Service, error) {
	if store == nil {
		return nil, ErrNilStore
	}
	return &Service{store: store}, nil
}

// CreateGroup creates a new custodian group with the given parameters.
// It validates all inputs, sets timestamps, and persists the group.
func (s *Service) CreateGroup(
	ctx context.Context,
	id, tenantID, name, purpose string,
	threshold, total int,
) (*CustodianGroup, error) {
	now := time.Now().UTC()

	group := &CustodianGroup{
		ID:        id,
		TenantID:  tenantID,
		Name:      name,
		Purpose:   purpose,
		Threshold: threshold,
		Total:     total,
		Members:   make([]CustodianMember, 0),
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := group.Validate(); err != nil {
		return nil, err
	}

	if err := s.store.Create(ctx, group); err != nil {
		return nil, err
	}

	return group, nil
}

// GetGroup retrieves a custodian group by ID.
func (s *Service) GetGroup(ctx context.Context, id string) (*CustodianGroup, error) {
	return s.store.Get(ctx, id)
}

// DeleteGroup deletes a custodian group by ID.
func (s *Service) DeleteGroup(ctx context.Context, id string) error {
	return s.store.Delete(ctx, id)
}

// AddMember adds a member to a custodian group. Returns ErrGroupFull if the
// group has reached its maximum number of members, and ErrMemberAlreadyExists
// if the user is already a member.
func (s *Service) AddMember(
	ctx context.Context,
	groupID, userID, username, method string,
) (*CustodianMember, error) {
	if userID == "" {
		return nil, ErrEmptyUserID
	}

	group, err := s.store.Get(ctx, groupID)
	if err != nil {
		return nil, err
	}

	if group.IsFull() {
		return nil, ErrGroupFull
	}

	if group.HasMember(userID) {
		return nil, ErrMemberAlreadyExists
	}

	member := CustodianMember{
		ShareIndex: len(group.Members) + 1,
		UserID:     userID,
		Username:   username,
		AssignedAt: time.Now().UTC(),
		Method:     method,
	}

	group.Members = append(group.Members, member)
	group.UpdatedAt = time.Now().UTC()

	if err := s.store.Update(ctx, group); err != nil {
		return nil, err
	}

	return &member, nil
}

// RemoveMember removes a member from a custodian group.
func (s *Service) RemoveMember(ctx context.Context, groupID, userID string) error {
	if userID == "" {
		return ErrEmptyUserID
	}

	group, err := s.store.Get(ctx, groupID)
	if err != nil {
		return err
	}

	found := false
	for i, m := range group.Members {
		if m.UserID == userID {
			group.Members = append(group.Members[:i], group.Members[i+1:]...)
			found = true
			break
		}
	}

	if !found {
		return ErrMemberNotFound
	}

	group.UpdatedAt = time.Now().UTC()

	return s.store.Update(ctx, group)
}

// MarkShareReceived marks a member's share as received. Returns
// ErrShareAlreadyReceived if the share was already marked.
func (s *Service) MarkShareReceived(ctx context.Context, groupID, userID string) error {
	if userID == "" {
		return ErrEmptyUserID
	}

	group, err := s.store.Get(ctx, groupID)
	if err != nil {
		return err
	}

	member := group.GetMember(userID)
	if member == nil {
		return ErrMemberNotFound
	}

	if member.HasReceived() {
		return ErrShareAlreadyReceived
	}

	now := time.Now().UTC()
	member.ReceivedAt = &now
	group.UpdatedAt = now

	return s.store.Update(ctx, group)
}

// ListGroups returns all custodian groups.
func (s *Service) ListGroups(ctx context.Context) ([]*CustodianGroup, error) {
	return s.store.List(ctx)
}

// ListGroupsByTenant returns custodian groups scoped to a specific tenant.
func (s *Service) ListGroupsByTenant(ctx context.Context, tenantID string) ([]*CustodianGroup, error) {
	return s.store.ListByTenant(ctx, tenantID)
}

// DistributeShares triggers share distribution for a custodian group.
// It validates the group exists and has members, returning the count of
// members to receive shares.
func (s *Service) DistributeShares(ctx context.Context, groupID string) (int, error) {
	if groupID == "" {
		return 0, ErrEmptyGroupID
	}

	group, err := s.store.Get(ctx, groupID)
	if err != nil {
		return 0, err
	}

	if len(group.Members) == 0 {
		return 0, ErrGroupEmpty
	}

	return len(group.Members), nil
}
