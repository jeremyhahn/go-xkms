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

package policy

import "sync"

// Compile-time interface check.
var _ PolicyStore = (*MemoryPolicyStore)(nil)

// MemoryPolicyStore is an in-memory PolicyStore implementation. It is
// thread-safe and suitable for testing or as a default when no persistent
// store is configured.
type MemoryPolicyStore struct {
	mu       sync.RWMutex
	policies map[string]*PolicyDefinition
}

// NewMemoryPolicyStore returns a ready-to-use in-memory policy store.
func NewMemoryPolicyStore() *MemoryPolicyStore {
	return &MemoryPolicyStore{
		policies: make(map[string]*PolicyDefinition),
	}
}

// SavePolicy persists a policy definition under the given name, overwriting
// any existing policy with the same name.
func (s *MemoryPolicyStore) SavePolicy(name string, def *PolicyDefinition) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policies[name] = def
	return nil
}

// LoadPolicy retrieves a policy definition by name. Returns ErrPolicyNotFound
// if no policy with the given name exists.
func (s *MemoryPolicyStore) LoadPolicy(name string) (*PolicyDefinition, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	def, ok := s.policies[name]
	if !ok {
		return nil, ErrPolicyNotFound
	}
	return def, nil
}

// DeletePolicy removes a policy definition by name. Returns ErrPolicyNotFound
// if no policy with the given name exists.
func (s *MemoryPolicyStore) DeletePolicy(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.policies[name]; !ok {
		return ErrPolicyNotFound
	}
	delete(s.policies, name)
	return nil
}

// ListPolicies returns all stored policy definitions. The returned slice is
// safe to mutate without affecting the store.
func (s *MemoryPolicyStore) ListPolicies() ([]*PolicyDefinition, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*PolicyDefinition, 0, len(s.policies))
	for _, def := range s.policies {
		result = append(result, def)
	}
	return result, nil
}
