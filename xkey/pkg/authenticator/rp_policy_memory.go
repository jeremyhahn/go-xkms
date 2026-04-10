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

package authenticator

import "sync"

// MemoryRPPolicyStore implements RPPolicyStore using an in-memory map.
// This implementation is used exclusively by authenticator unit tests.
// Thread-safe using a read-write mutex.
type MemoryRPPolicyStore struct {
	policies map[string]*RPPolicy // keyed by RPID
	mu       sync.RWMutex
	closed   bool
}

// NewMemoryRPPolicyStore creates a new in-memory RP policy store.
func NewMemoryRPPolicyStore() *MemoryRPPolicyStore {
	return &MemoryRPPolicyStore{
		policies: make(map[string]*RPPolicy),
	}
}

// SetPolicy creates or updates a per-RP policy.
func (m *MemoryRPPolicyStore) SetPolicy(policy *RPPolicy) error {
	if err := policy.Validate(); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return ErrRPPolicyStoreClosed
	}

	// Deep copy to prevent external mutation
	stored := copyRPPolicy(policy)
	m.policies[policy.RPID] = stored

	return nil
}

// GetPolicy retrieves the policy for a specific RPID.
func (m *MemoryRPPolicyStore) GetPolicy(rpID string) (*RPPolicy, error) {
	if rpID == "" {
		return nil, ErrRPPolicyInvalidRPID
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, ErrRPPolicyStoreClosed
	}

	policy, ok := m.policies[rpID]
	if !ok {
		return nil, ErrRPPolicyNotFound
	}

	return copyRPPolicy(policy), nil
}

// DeletePolicy removes the policy for a specific RPID.
func (m *MemoryRPPolicyStore) DeletePolicy(rpID string) error {
	if rpID == "" {
		return ErrRPPolicyInvalidRPID
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return ErrRPPolicyStoreClosed
	}

	if _, ok := m.policies[rpID]; !ok {
		return ErrRPPolicyNotFound
	}

	delete(m.policies, rpID)
	return nil
}

// ListPolicies returns all stored RP policies.
func (m *MemoryRPPolicyStore) ListPolicies() ([]*RPPolicy, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, ErrRPPolicyStoreClosed
	}

	result := make([]*RPPolicy, 0, len(m.policies))
	for _, policy := range m.policies {
		result = append(result, copyRPPolicy(policy))
	}

	return result, nil
}

// Close marks the store as closed.
func (m *MemoryRPPolicyStore) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil
	}

	m.closed = true
	m.policies = nil
	return nil
}

// copyRPPolicy creates a deep copy of an RPPolicy.
func copyRPPolicy(p *RPPolicy) *RPPolicy {
	if p == nil {
		return nil
	}
	copied := *p
	if p.UPOverride != nil {
		v := *p.UPOverride
		copied.UPOverride = &v
	}
	return &copied
}

// Compile-time interface check.
var _ RPPolicyStore = (*MemoryRPPolicyStore)(nil)
