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
	"sync"
)

// MemoryStore is an in-memory implementation of CustodianGroupStore.
// All returned values are deep copies to prevent external mutation.
type MemoryStore struct {
	groups map[string]*CustodianGroup
	mu     sync.RWMutex
}

var _ CustodianGroupStore = (*MemoryStore)(nil)

// NewMemoryStore creates a new in-memory custodian group store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		groups: make(map[string]*CustodianGroup),
	}
}

// Create persists a new custodian group.
func (s *MemoryStore) Create(_ context.Context, group *CustodianGroup) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.groups[group.ID]; exists {
		return ErrGroupAlreadyExists
	}

	s.groups[group.ID] = deepCopyGroup(group)
	return nil
}

// Get retrieves a custodian group by ID.
func (s *MemoryStore) Get(_ context.Context, id string) (*CustodianGroup, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	group, exists := s.groups[id]
	if !exists {
		return nil, ErrGroupNotFound
	}

	return deepCopyGroup(group), nil
}

// Update replaces an existing custodian group.
func (s *MemoryStore) Update(_ context.Context, group *CustodianGroup) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.groups[group.ID]; !exists {
		return ErrGroupNotFound
	}

	s.groups[group.ID] = deepCopyGroup(group)
	return nil
}

// Delete removes a custodian group by ID.
func (s *MemoryStore) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.groups[id]; !exists {
		return ErrGroupNotFound
	}

	delete(s.groups, id)
	return nil
}

// List returns all custodian groups.
func (s *MemoryStore) List(_ context.Context) ([]*CustodianGroup, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*CustodianGroup, 0, len(s.groups))
	for _, group := range s.groups {
		result = append(result, deepCopyGroup(group))
	}
	return result, nil
}

// ListByTenant returns custodian groups scoped to a specific tenant.
func (s *MemoryStore) ListByTenant(_ context.Context, tenantID string) ([]*CustodianGroup, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*CustodianGroup, 0)
	for _, group := range s.groups {
		if group.TenantID == tenantID {
			result = append(result, deepCopyGroup(group))
		}
	}
	return result, nil
}

// ListByPurpose returns custodian groups filtered by purpose.
func (s *MemoryStore) ListByPurpose(_ context.Context, purpose string) ([]*CustodianGroup, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*CustodianGroup, 0)
	for _, group := range s.groups {
		if group.Purpose == purpose {
			result = append(result, deepCopyGroup(group))
		}
	}
	return result, nil
}

// deepCopyGroup creates a deep copy of a CustodianGroup to prevent external mutation.
func deepCopyGroup(src *CustodianGroup) *CustodianGroup {
	dst := &CustodianGroup{
		ID:        src.ID,
		TenantID:  src.TenantID,
		Name:      src.Name,
		Purpose:   src.Purpose,
		Threshold: src.Threshold,
		Total:     src.Total,
		CreatedAt: src.CreatedAt,
		UpdatedAt: src.UpdatedAt,
		Members:   make([]CustodianMember, len(src.Members)),
	}
	for i, m := range src.Members {
		dst.Members[i] = CustodianMember{
			ShareIndex: m.ShareIndex,
			UserID:     m.UserID,
			Username:   m.Username,
			AssignedAt: m.AssignedAt,
			Method:     m.Method,
		}
		if m.ReceivedAt != nil {
			t := *m.ReceivedAt
			dst.Members[i].ReceivedAt = &t
		}
	}
	return dst
}
