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

package pairing

import (
	"encoding/json"
	"os"
	"sync"
)

// SharingPolicy controls what can be shared for a specific key.
// The default policy is deny: AllowShare must be explicitly set to true.
type SharingPolicy struct {
	KeyID          string   `json:"key_id" yaml:"key_id"`
	Backend        string   `json:"backend" yaml:"backend"`
	AllowShare     bool     `json:"allow_share" yaml:"allow_share"`
	SharePublic    bool     `json:"share_public" yaml:"share_public"`
	SharePrivate   bool     `json:"share_private" yaml:"share_private"`
	ShareSymmetric bool     `json:"share_symmetric" yaml:"share_symmetric"`
	AllowedDevices []string `json:"allowed_devices,omitempty" yaml:"allowed_devices,omitempty"`
}

// SharingPolicyStore manages sharing policies for keys.
type SharingPolicyStore interface {
	GetPolicy(backend, keyID string) (*SharingPolicy, error)
	SetPolicy(policy *SharingPolicy) error
	DeletePolicy(backend, keyID string) error
	ListPolicies() ([]*SharingPolicy, error)
	IsShareAllowed(backend, keyID, deviceFingerprint string) (bool, error)
}

// FileSharingPolicyStore implements SharingPolicyStore with JSON file persistence.
type FileSharingPolicyStore struct {
	path     string
	policies map[string]*SharingPolicy
	mu       sync.RWMutex
}

// NewFileSharingPolicyStore creates a new FileSharingPolicyStore backed by the
// given file path. If the file exists, policies are loaded from it. If the file
// does not exist, an empty store is created and the file will be written on the
// first mutation.
func NewFileSharingPolicyStore(path string) (*FileSharingPolicyStore, error) {
	store := &FileSharingPolicyStore{
		path:     path,
		policies: make(map[string]*SharingPolicy),
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return store, nil
		}
		return nil, err
	}

	// Empty file is valid, treat as empty store.
	if len(data) == 0 {
		return store, nil
	}

	var policies []*SharingPolicy
	if err := json.Unmarshal(data, &policies); err != nil {
		return nil, err
	}

	for _, p := range policies {
		key := policyKey(p.Backend, p.KeyID)
		store.policies[key] = p
	}

	return store, nil
}

// GetPolicy retrieves the sharing policy for a given backend and key ID.
// Returns ErrSharePolicyNotFound if no policy exists.
func (s *FileSharingPolicyStore) GetPolicy(backend, keyID string) (*SharingPolicy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key := policyKey(backend, keyID)
	policy, ok := s.policies[key]
	if !ok {
		return nil, ErrSharePolicyNotFound
	}

	// Return a copy to prevent mutation of the stored policy.
	cp := *policy
	if policy.AllowedDevices != nil {
		cp.AllowedDevices = make([]string, len(policy.AllowedDevices))
		copy(cp.AllowedDevices, policy.AllowedDevices)
	}
	return &cp, nil
}

// SetPolicy creates or updates a sharing policy and persists to disk.
// The policy must have non-empty Backend and KeyID fields.
func (s *FileSharingPolicyStore) SetPolicy(policy *SharingPolicy) error {
	if policy == nil {
		return ErrBridgeInvalidParams
	}
	if policy.Backend == "" || policy.KeyID == "" {
		return ErrBridgeInvalidParams
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Store a copy to prevent caller mutation.
	cp := *policy
	if policy.AllowedDevices != nil {
		cp.AllowedDevices = make([]string, len(policy.AllowedDevices))
		copy(cp.AllowedDevices, policy.AllowedDevices)
	}

	key := policyKey(policy.Backend, policy.KeyID)
	s.policies[key] = &cp

	return s.save()
}

// DeletePolicy removes a sharing policy and persists the change.
// Returns ErrSharePolicyNotFound if the policy does not exist.
func (s *FileSharingPolicyStore) DeletePolicy(backend, keyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := policyKey(backend, keyID)
	if _, ok := s.policies[key]; !ok {
		return ErrSharePolicyNotFound
	}

	delete(s.policies, key)
	return s.save()
}

// ListPolicies returns all stored sharing policies.
func (s *FileSharingPolicyStore) ListPolicies() ([]*SharingPolicy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*SharingPolicy, 0, len(s.policies))
	for _, p := range s.policies {
		cp := *p
		if p.AllowedDevices != nil {
			cp.AllowedDevices = make([]string, len(p.AllowedDevices))
			copy(cp.AllowedDevices, p.AllowedDevices)
		}
		result = append(result, &cp)
	}
	return result, nil
}

// IsShareAllowed checks whether sharing is permitted for a given backend,
// key ID, and device fingerprint. Returns false when no policy exists
// (default deny) or when the policy denies sharing. When AllowedDevices
// is non-empty, the device fingerprint must be in the list.
func (s *FileSharingPolicyStore) IsShareAllowed(backend, keyID, deviceFingerprint string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key := policyKey(backend, keyID)
	policy, ok := s.policies[key]
	if !ok {
		return false, nil
	}

	if !policy.AllowShare {
		return false, nil
	}

	// If an allowed devices list is configured, enforce it.
	if len(policy.AllowedDevices) > 0 {
		for _, allowed := range policy.AllowedDevices {
			if allowed == deviceFingerprint {
				return true, nil
			}
		}
		return false, nil
	}

	return true, nil
}

// save persists all policies to the backing JSON file. The caller must
// hold the write lock.
func (s *FileSharingPolicyStore) save() error {
	policies := make([]*SharingPolicy, 0, len(s.policies))
	for _, p := range s.policies {
		policies = append(policies, p)
	}

	data, err := json.MarshalIndent(policies, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(s.path, data, 0600)
}

// policyKey builds the map key for a backend and key ID pair.
func policyKey(backend, keyID string) string {
	return backend + ":" + keyID
}
