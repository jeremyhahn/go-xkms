// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package policy

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// MemoryPolicyEngine is an in-memory implementation of PolicyAdapter.
// It provides thread-safe policy storage and evaluation with support for:
// - Wildcard matching in actions and resources
// - Policy precedence (deny overrides allow)
// - Priority-based policy ordering
type MemoryPolicyEngine struct {
	mu       sync.RWMutex
	policies map[string]*Policy
}

// NewMemoryPolicyEngine creates a new in-memory policy engine.
func NewMemoryPolicyEngine() *MemoryPolicyEngine {
	return &MemoryPolicyEngine{
		policies: make(map[string]*Policy),
	}
}

// EvaluatePolicy evaluates a request against all policies.
// Evaluation rules:
// 1. Policies are evaluated in priority order (highest first)
// 2. If any Deny policy matches, access is denied immediately
// 3. If any Allow policy matches and no Deny matches, access is allowed
// 4. If no policies match, access is denied by default (fail-safe)
func (m *MemoryPolicyEngine) EvaluatePolicy(ctx context.Context, req *EvaluationRequest) (*EvaluationResult, error) {
	if err := ValidateEvaluationRequest(req); err != nil {
		return nil, fmt.Errorf("invalid evaluation request: %w", err)
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	// Get all policies sorted by priority (highest first)
	policies := m.getSortedPolicies()

	var matchedDeny []string
	var matchedAllow []string

	// Evaluate each policy
	for _, policy := range policies {
		if m.policyMatches(policy, req) {
			if policy.Effect == Deny {
				matchedDeny = append(matchedDeny, policy.ID)
			} else {
				matchedAllow = append(matchedAllow, policy.ID)
			}
		}
	}

	// Deny overrides allow
	if len(matchedDeny) > 0 {
		return &EvaluationResult{
			Effect:          Deny,
			MatchedPolicies: matchedDeny,
			Reason:          fmt.Sprintf("denied by policy: %s", strings.Join(matchedDeny, ", ")),
		}, nil
	}

	// Allow if at least one allow policy matched
	if len(matchedAllow) > 0 {
		return &EvaluationResult{
			Effect:          Allow,
			MatchedPolicies: matchedAllow,
			Reason:          fmt.Sprintf("allowed by policy: %s", strings.Join(matchedAllow, ", ")),
		}, nil
	}

	// Default deny (fail-safe)
	return &EvaluationResult{
		Effect:          Deny,
		MatchedPolicies: nil,
		Reason:          "no matching policies (default deny)",
	}, nil
}

// AddPolicy adds a new policy to the engine.
func (m *MemoryPolicyEngine) AddPolicy(ctx context.Context, policy *Policy) error {
	if err := ValidatePolicy(policy); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.policies[policy.ID]; exists {
		return fmt.Errorf("%w: policy %s", ErrPolicyExists, policy.ID)
	}

	// Set timestamps
	now := time.Now()
	policy.CreatedAt = now
	policy.UpdatedAt = now

	m.policies[policy.ID] = policy
	return nil
}

// UpdatePolicy updates an existing policy.
func (m *MemoryPolicyEngine) UpdatePolicy(ctx context.Context, policy *Policy) error {
	if err := ValidatePolicy(policy); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	existing, exists := m.policies[policy.ID]
	if !exists {
		return fmt.Errorf("%w: policy %s", ErrPolicyNotFound, policy.ID)
	}

	// Preserve creation time
	policy.CreatedAt = existing.CreatedAt
	policy.UpdatedAt = time.Now()

	m.policies[policy.ID] = policy
	return nil
}

// DeletePolicy removes a policy by ID.
func (m *MemoryPolicyEngine) DeletePolicy(ctx context.Context, policyID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.policies[policyID]; !exists {
		return fmt.Errorf("%w: policy %s", ErrPolicyNotFound, policyID)
	}

	delete(m.policies, policyID)
	return nil
}

// GetPolicy retrieves a policy by ID.
func (m *MemoryPolicyEngine) GetPolicy(ctx context.Context, policyID string) (*Policy, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	policy, exists := m.policies[policyID]
	if !exists {
		return nil, fmt.Errorf("%w: policy %s", ErrPolicyNotFound, policyID)
	}

	return policy, nil
}

// ListPolicies returns all policies in the engine.
func (m *MemoryPolicyEngine) ListPolicies(ctx context.Context) ([]*Policy, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	policies := make([]*Policy, 0, len(m.policies))
	for _, policy := range m.policies {
		policies = append(policies, policy)
	}

	// Sort by priority (highest first), then by ID for stable ordering
	sort.Slice(policies, func(i, j int) bool {
		if policies[i].Priority != policies[j].Priority {
			return policies[i].Priority > policies[j].Priority
		}
		return policies[i].ID < policies[j].ID
	})

	return policies, nil
}

// getSortedPolicies returns all policies sorted by priority (highest first).
// Must be called with read lock held.
func (m *MemoryPolicyEngine) getSortedPolicies() []*Policy {
	policies := make([]*Policy, 0, len(m.policies))
	for _, policy := range m.policies {
		policies = append(policies, policy)
	}

	// Sort by priority (highest first), then by ID for stable ordering
	sort.Slice(policies, func(i, j int) bool {
		if policies[i].Priority != policies[j].Priority {
			return policies[i].Priority > policies[j].Priority
		}
		return policies[i].ID < policies[j].ID
	})

	return policies
}

// policyMatches checks if a policy matches the evaluation request.
func (m *MemoryPolicyEngine) policyMatches(policy *Policy, req *EvaluationRequest) bool {
	// Check each rule in the policy
	for _, rule := range policy.Rules {
		if m.ruleMatches(rule, req) {
			return true
		}
	}
	return false
}

// ruleMatches checks if a rule matches the evaluation request.
func (m *MemoryPolicyEngine) ruleMatches(rule PolicyRule, req *EvaluationRequest) bool {
	// Check if action matches
	if !m.matchesPattern(req.Action, rule.Actions) {
		return false
	}

	// Check if resource matches
	if !m.matchesPattern(req.Resource, rule.Resources) {
		return false
	}

	// Check if conditions match
	if len(rule.Conditions) > 0 {
		if !m.conditionsMatch(rule.Conditions, req.Context) {
			return false
		}
	}

	return true
}

// matchesPattern checks if a value matches any pattern in the list.
// Supports wildcards (*) for matching.
func (m *MemoryPolicyEngine) matchesPattern(value string, patterns []string) bool {
	for _, pattern := range patterns {
		if m.wildcardMatch(pattern, value) {
			return true
		}
	}
	return false
}

// wildcardMatch performs wildcard matching similar to filepath.Match.
// Supports * for matching any sequence of characters.
func (m *MemoryPolicyEngine) wildcardMatch(pattern, value string) bool {
	// Exact match
	if pattern == value {
		return true
	}

	// Wildcard match all
	if pattern == "*" {
		return true
	}

	// Use filepath.Match for wildcard matching
	matched, err := filepath.Match(pattern, value)
	if err != nil {
		// If pattern is invalid, treat as literal match
		return pattern == value
	}

	return matched
}

// conditionsMatch checks if all rule conditions match the request context.
func (m *MemoryPolicyEngine) conditionsMatch(ruleConditions, requestContext map[string]string) bool {
	if requestContext == nil {
		requestContext = make(map[string]string)
	}

	for key, expectedValue := range ruleConditions {
		actualValue, exists := requestContext[key]
		if !exists {
			return false
		}

		// Support wildcard matching in condition values
		if !m.wildcardMatch(expectedValue, actualValue) {
			return false
		}
	}

	return true
}
