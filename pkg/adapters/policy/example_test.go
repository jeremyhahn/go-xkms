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

package policy_test

import (
	"context"
	"fmt"

	"github.com/jeremyhahn/go-keychain/pkg/adapters/policy"
)

// Example demonstrates basic policy engine usage.
func Example() {
	// Create a new in-memory policy engine
	engine := policy.NewMemoryPolicyEngine()

	// Define a policy that allows signing with production keys for admins
	allowPolicy := &policy.Policy{
		ID:          "allow-prod-signing",
		Name:        "Allow Production Signing",
		Description: "Allows admins to sign with production keys",
		Effect:      policy.Allow,
		Priority:    10,
		Rules: []policy.PolicyRule{
			{
				Actions:   []string{"Sign"},
				Resources: []string{"prod-*"},
				Conditions: map[string]string{
					"user": "admin",
					"env":  "production",
				},
			},
		},
	}

	// Add the policy to the engine
	err := engine.AddPolicy(context.Background(), allowPolicy)
	if err != nil {
		fmt.Printf("Error adding policy: %v\n", err)
		return
	}

	// Evaluate a request that should be allowed
	result, err := engine.EvaluatePolicy(context.Background(), &policy.EvaluationRequest{
		Action:   "Sign",
		Resource: "prod-key-1",
		Context: map[string]string{
			"user": "admin",
			"env":  "production",
		},
	})
	if err != nil {
		fmt.Printf("Error evaluating policy: %v\n", err)
		return
	}

	fmt.Printf("Effect: %s\n", result.Effect)
	fmt.Printf("Reason: %s\n", result.Reason)

	// Output:
	// Effect: Allow
	// Reason: allowed by policy: allow-prod-signing
}

// Example_denyOverridesAllow demonstrates that deny policies take precedence over allow policies.
func Example_denyOverridesAllow() {
	engine := policy.NewMemoryPolicyEngine()

	// Allow all signing operations
	allowPolicy := &policy.Policy{
		ID:       "allow-all-signing",
		Name:     "Allow All Signing",
		Effect:   policy.Allow,
		Priority: 5,
		Rules: []policy.PolicyRule{
			{
				Actions:   []string{"Sign"},
				Resources: []string{"*"},
			},
		},
	}

	// Deny signing with sensitive keys
	denyPolicy := &policy.Policy{
		ID:       "deny-sensitive-keys",
		Name:     "Deny Sensitive Keys",
		Effect:   policy.Deny,
		Priority: 10,
		Rules: []policy.PolicyRule{
			{
				Actions:   []string{"Sign"},
				Resources: []string{"sensitive-*"},
			},
		},
	}

	_ = engine.AddPolicy(context.Background(), allowPolicy)
	_ = engine.AddPolicy(context.Background(), denyPolicy)

	// Try to sign with a sensitive key
	req := &policy.EvaluationRequest{
		Action:   "Sign",
		Resource: "sensitive-key-1",
	}
	result, err := engine.EvaluatePolicy(context.Background(), req)
	if err != nil {
		fmt.Printf("Error evaluating policy: %v\n", err)
		return
	}

	fmt.Printf("Effect: %s\n", result.Effect)
	fmt.Printf("Matched Policies: %v\n", result.MatchedPolicies)

	// Output:
	// Effect: Deny
	// Matched Policies: [deny-sensitive-keys]
}

// Example_wildcardMatching demonstrates wildcard pattern matching in policies.
func Example_wildcardMatching() {
	engine := policy.NewMemoryPolicyEngine()

	// Allow all sign operations on development keys
	p := &policy.Policy{
		ID:       "allow-dev-signing",
		Name:     "Allow Development Signing",
		Effect:   policy.Allow,
		Priority: 10,
		Rules: []policy.PolicyRule{
			{
				Actions:   []string{"Sign*"}, // Matches Sign, SignData, SignHash, etc.
				Resources: []string{"dev-*"}, // Matches dev-key-1, dev-key-2, etc.
			},
		},
	}

	_ = engine.AddPolicy(context.Background(), p)

	// Test with a development key
	req := &policy.EvaluationRequest{
		Action:   "SignData",
		Resource: "dev-key-123",
	}
	result, err := engine.EvaluatePolicy(context.Background(), req)
	if err != nil {
		fmt.Printf("Error evaluating policy: %v\n", err)
		return
	}

	fmt.Printf("Effect: %s\n", result.Effect)

	// Output:
	// Effect: Allow
}

// Example_conditionalPolicy demonstrates conditional policy evaluation.
func Example_conditionalPolicy() {
	engine := policy.NewMemoryPolicyEngine()

	// Allow encryption only for authorized users in the production environment
	p := &policy.Policy{
		ID:       "allow-prod-encryption",
		Name:     "Allow Production Encryption",
		Effect:   policy.Allow,
		Priority: 10,
		Rules: []policy.PolicyRule{
			{
				Actions:   []string{"Encrypt"},
				Resources: []string{"*"},
				Conditions: map[string]string{
					"user":   "authorized",
					"env":    "production",
					"region": "us-*", // Wildcard in condition value
				},
			},
		},
	}

	_ = engine.AddPolicy(context.Background(), p)

	// Request with matching conditions
	req := &policy.EvaluationRequest{
		Action:   "Encrypt",
		Resource: "data-key-1",
		Context: map[string]string{
			"user":   "authorized",
			"env":    "production",
			"region": "us-west-2",
		},
	}
	result, err := engine.EvaluatePolicy(context.Background(), req)
	if err != nil {
		fmt.Printf("Error evaluating policy: %v\n", err)
		return
	}

	fmt.Printf("Effect: %s\n", result.Effect)

	// Output:
	// Effect: Allow
}

// Example_defaultDeny demonstrates the default deny behavior when no policies match.
func Example_defaultDeny() {
	engine := policy.NewMemoryPolicyEngine()

	// Engine has no policies

	// Try to perform an operation
	req := &policy.EvaluationRequest{
		Action:   "Sign",
		Resource: "key-1",
	}
	result, err := engine.EvaluatePolicy(context.Background(), req)
	if err != nil {
		fmt.Printf("Error evaluating policy: %v\n", err)
		return
	}

	fmt.Printf("Effect: %s\n", result.Effect)
	fmt.Printf("Reason: %s\n", result.Reason)

	// Output:
	// Effect: Deny
	// Reason: no matching policies (default deny)
}

// Example_policyManagement demonstrates adding, updating, and deleting policies.
func Example_policyManagement() {
	engine := policy.NewMemoryPolicyEngine()
	ctx := context.Background()

	// Add a policy
	policy := &policy.Policy{
		ID:       "policy-1",
		Name:     "Test Policy",
		Effect:   policy.Allow,
		Priority: 10,
		Rules: []policy.PolicyRule{
			{
				Actions:   []string{"Sign"},
				Resources: []string{"key-1"},
			},
		},
	}
	_ = engine.AddPolicy(ctx, policy)

	// List policies
	policies, _ := engine.ListPolicies(ctx)
	fmt.Printf("Policies: %d\n", len(policies))

	// Update the policy
	policy.Name = "Updated Test Policy"
	_ = engine.UpdatePolicy(ctx, policy)

	// Get the updated policy
	updated, _ := engine.GetPolicy(ctx, "policy-1")
	fmt.Printf("Updated name: %s\n", updated.Name)

	// Delete the policy
	_ = engine.DeletePolicy(ctx, "policy-1")

	// Verify deletion
	policies, _ = engine.ListPolicies(ctx)
	fmt.Printf("Policies after deletion: %d\n", len(policies))

	// Output:
	// Policies: 1
	// Updated name: Updated Test Policy
	// Policies after deletion: 0
}
