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

// Package policy provides a policy engine adapter for enforcing access control
// and authorization policies on key operations.
package policy

import (
	"context"
	"fmt"
	"time"
)

// PolicyEffect represents the effect of a policy evaluation (Allow or Deny).
type PolicyEffect string

const (
	// Allow indicates the policy permits the requested action.
	Allow PolicyEffect = "Allow"
	// Deny indicates the policy prohibits the requested action.
	Deny PolicyEffect = "Deny"
)

// String returns the string representation of the PolicyEffect.
func (e PolicyEffect) String() string {
	return string(e)
}

// PolicyRule defines a rule with conditions, actions, and resources.
type PolicyRule struct {
	// Conditions are key-value pairs that must match for the rule to apply.
	// Supports wildcards (*) for matching.
	Conditions map[string]string
	// Actions are the operations this rule applies to (e.g., "GenerateKey", "Sign").
	// Supports wildcards (*) for matching all actions.
	Actions []string
	// Resources are the key identifiers or resource patterns this rule applies to.
	// Supports wildcards (*) for matching all resources.
	Resources []string
}

// Policy represents a security policy with rules and an effect.
type Policy struct {
	// ID is the unique identifier for the policy.
	ID string
	// Name is a human-readable name for the policy.
	Name string
	// Description provides additional context about the policy.
	Description string
	// Effect determines whether this policy allows or denies access.
	Effect PolicyEffect
	// Rules are the conditions that must be met for this policy to apply.
	Rules []PolicyRule
	// Priority determines policy precedence. Higher values take precedence.
	// When multiple policies match, the highest priority is evaluated first.
	Priority int
	// CreatedAt is the timestamp when the policy was created.
	CreatedAt time.Time
	// UpdatedAt is the timestamp when the policy was last updated.
	UpdatedAt time.Time
}

// EvaluationRequest contains the context for policy evaluation.
type EvaluationRequest struct {
	// Action is the operation being requested (e.g., "GenerateKey", "Sign").
	Action string
	// Resource is the key identifier or resource being accessed.
	Resource string
	// Context contains additional attributes for condition evaluation.
	Context map[string]string
}

// EvaluationResult contains the outcome of policy evaluation.
type EvaluationResult struct {
	// Effect is the final decision (Allow or Deny).
	Effect PolicyEffect
	// MatchedPolicies are the policies that matched the request.
	MatchedPolicies []string
	// Reason provides an explanation for the decision.
	Reason string
}

// PolicyAdapter defines the interface for policy engine implementations.
type PolicyAdapter interface {
	// EvaluatePolicy evaluates a request against all policies and returns the decision.
	// The evaluation follows these rules:
	// 1. If any Deny policy matches, the request is denied.
	// 2. If any Allow policy matches and no Deny policy matches, the request is allowed.
	// 3. If no policies match, the default behavior is to deny (fail-safe).
	EvaluatePolicy(ctx context.Context, req *EvaluationRequest) (*EvaluationResult, error)

	// AddPolicy adds a new policy to the engine.
	// Returns an error if a policy with the same ID already exists.
	AddPolicy(ctx context.Context, policy *Policy) error

	// UpdatePolicy updates an existing policy.
	// Returns an error if the policy does not exist.
	UpdatePolicy(ctx context.Context, policy *Policy) error

	// DeletePolicy removes a policy by ID.
	// Returns an error if the policy does not exist.
	DeletePolicy(ctx context.Context, policyID string) error

	// GetPolicy retrieves a policy by ID.
	// Returns an error if the policy does not exist.
	GetPolicy(ctx context.Context, policyID string) (*Policy, error)

	// ListPolicies returns all policies in the engine.
	ListPolicies(ctx context.Context) ([]*Policy, error)
}

// Common errors for policy operations.
var (
	// ErrPolicyNotFound indicates the requested policy does not exist.
	ErrPolicyNotFound = fmt.Errorf("policy not found")
	// ErrPolicyExists indicates a policy with the same ID already exists.
	ErrPolicyExists = fmt.Errorf("policy already exists")
	// ErrInvalidPolicy indicates the policy is invalid or incomplete.
	ErrInvalidPolicy = fmt.Errorf("invalid policy")
	// ErrAccessDenied indicates the request was denied by policy evaluation.
	ErrAccessDenied = fmt.Errorf("access denied by policy")
)

// ValidatePolicy checks if a policy is valid and complete.
func ValidatePolicy(policy *Policy) error {
	if policy == nil {
		return fmt.Errorf("%w: policy is nil", ErrInvalidPolicy)
	}
	if policy.ID == "" {
		return fmt.Errorf("%w: policy ID is required", ErrInvalidPolicy)
	}
	if policy.Name == "" {
		return fmt.Errorf("%w: policy name is required", ErrInvalidPolicy)
	}
	if policy.Effect != Allow && policy.Effect != Deny {
		return fmt.Errorf("%w: policy effect must be Allow or Deny", ErrInvalidPolicy)
	}
	if len(policy.Rules) == 0 {
		return fmt.Errorf("%w: policy must have at least one rule", ErrInvalidPolicy)
	}
	for i, rule := range policy.Rules {
		if len(rule.Actions) == 0 {
			return fmt.Errorf("%w: rule %d must specify at least one action", ErrInvalidPolicy, i)
		}
		if len(rule.Resources) == 0 {
			return fmt.Errorf("%w: rule %d must specify at least one resource", ErrInvalidPolicy, i)
		}
	}
	return nil
}

// ValidateEvaluationRequest checks if an evaluation request is valid.
func ValidateEvaluationRequest(req *EvaluationRequest) error {
	if req == nil {
		return fmt.Errorf("evaluation request is nil")
	}
	if req.Action == "" {
		return fmt.Errorf("action is required")
	}
	if req.Resource == "" {
		return fmt.Errorf("resource is required")
	}
	return nil
}
