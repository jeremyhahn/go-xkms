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

// Package policy provides a flexible policy engine adapter for enforcing
// access control and authorization policies on cryptographic key operations.
//
// The policy engine supports:
//   - Allow and Deny policy effects
//   - Wildcard matching for actions and resources (using filepath.Match syntax)
//   - Conditional policy evaluation based on context attributes
//   - Policy precedence (deny always overrides allow)
//   - Priority-based policy ordering
//   - Thread-safe in-memory storage
//
// Example Usage:
//
//	// Create a policy engine
//	engine := policy.NewMemoryPolicyEngine()
//
//	// Define a policy that allows signing with production keys for admins
//	allowPolicy := &policy.Policy{
//	    ID:       "allow-prod-signing",
//	    Name:     "Allow Production Signing",
//	    Effect:   policy.Allow,
//	    Priority: 10,
//	    Rules: []policy.PolicyRule{
//	        {
//	            Actions:   []string{"Sign"},
//	            Resources: []string{"prod-*"},
//	            Conditions: map[string]string{
//	                "user": "admin",
//	                "env":  "production",
//	            },
//	        },
//	    },
//	}
//
//	// Add the policy
//	err := engine.AddPolicy(context.Background(), allowPolicy)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Evaluate a request
//	result, err := engine.EvaluatePolicy(context.Background(), &policy.EvaluationRequest{
//	    Action:   "Sign",
//	    Resource: "prod-key-1",
//	    Context: map[string]string{
//	        "user": "admin",
//	        "env":  "production",
//	    },
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	if result.Effect == policy.Allow {
//	    // Proceed with the operation
//	    fmt.Println("Access granted:", result.Reason)
//	} else {
//	    // Deny the operation
//	    fmt.Println("Access denied:", result.Reason)
//	}
//
// Policy Evaluation Rules:
//
// 1. Policies are evaluated in priority order (highest priority first)
// 2. If any Deny policy matches, access is denied immediately
// 3. If any Allow policy matches and no Deny policy matches, access is allowed
// 4. If no policies match, access is denied by default (fail-safe)
//
// Wildcard Patterns:
//
// The policy engine supports wildcards in actions, resources, and condition values:
//   - "*" matches any sequence of characters
//   - "prod-*" matches "prod-key-1", "prod-key-2", etc.
//   - "Sign*" matches "Sign", "SignData", "SignHash", etc.
//
// Integration with go-keychain:
//
// The policy adapter can be integrated with go-keychain's backend operations
// to enforce fine-grained access control on cryptographic operations:
//
//	// Wrap backend operations with policy enforcement
//	type PolicyEnforcedBackend struct {
//	    backend backend.Backend
//	    engine  policy.PolicyAdapter
//	}
//
//	func (b *PolicyEnforcedBackend) Sign(ctx context.Context, keyID string, data []byte) ([]byte, error) {
//	    // Evaluate policy before performing the operation
//	    result, err := b.engine.EvaluatePolicy(ctx, &policy.EvaluationRequest{
//	        Action:   "Sign",
//	        Resource: keyID,
//	        Context:  extractContextFromRequest(ctx),
//	    })
//	    if err != nil {
//	        return nil, err
//	    }
//	    if result.Effect != policy.Allow {
//	        return nil, fmt.Errorf("operation denied: %s", result.Reason)
//	    }
//
//	    // Proceed with the operation
//	    return b.backend.Sign(ctx, keyID, data)
//	}
package policy
