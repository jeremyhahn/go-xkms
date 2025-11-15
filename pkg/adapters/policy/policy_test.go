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
	"testing"
	"time"
)

func TestPolicyEffect_String(t *testing.T) {
	tests := []struct {
		name   string
		effect PolicyEffect
		want   string
	}{
		{
			name:   "allow effect",
			effect: Allow,
			want:   "Allow",
		},
		{
			name:   "deny effect",
			effect: Deny,
			want:   "Deny",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.effect.String(); got != tt.want {
				t.Errorf("PolicyEffect.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidatePolicy(t *testing.T) {
	tests := []struct {
		name    string
		policy  *Policy
		wantErr bool
	}{
		{
			name:    "nil policy",
			policy:  nil,
			wantErr: true,
		},
		{
			name: "missing ID",
			policy: &Policy{
				Name:   "test",
				Effect: Allow,
				Rules: []PolicyRule{
					{
						Actions:   []string{"Sign"},
						Resources: []string{"key-1"},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "missing name",
			policy: &Policy{
				ID:     "policy-1",
				Effect: Allow,
				Rules: []PolicyRule{
					{
						Actions:   []string{"Sign"},
						Resources: []string{"key-1"},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid effect",
			policy: &Policy{
				ID:     "policy-1",
				Name:   "test",
				Effect: PolicyEffect("Invalid"),
				Rules: []PolicyRule{
					{
						Actions:   []string{"Sign"},
						Resources: []string{"key-1"},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "no rules",
			policy: &Policy{
				ID:     "policy-1",
				Name:   "test",
				Effect: Allow,
				Rules:  []PolicyRule{},
			},
			wantErr: true,
		},
		{
			name: "rule with no actions",
			policy: &Policy{
				ID:     "policy-1",
				Name:   "test",
				Effect: Allow,
				Rules: []PolicyRule{
					{
						Actions:   []string{},
						Resources: []string{"key-1"},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "rule with no resources",
			policy: &Policy{
				ID:     "policy-1",
				Name:   "test",
				Effect: Allow,
				Rules: []PolicyRule{
					{
						Actions:   []string{"Sign"},
						Resources: []string{},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "valid policy",
			policy: &Policy{
				ID:     "policy-1",
				Name:   "test",
				Effect: Allow,
				Rules: []PolicyRule{
					{
						Actions:   []string{"Sign"},
						Resources: []string{"key-1"},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid policy with conditions",
			policy: &Policy{
				ID:     "policy-1",
				Name:   "test",
				Effect: Allow,
				Rules: []PolicyRule{
					{
						Actions:   []string{"Sign"},
						Resources: []string{"key-1"},
						Conditions: map[string]string{
							"user": "admin",
						},
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePolicy(tt.policy)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePolicy() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateEvaluationRequest(t *testing.T) {
	tests := []struct {
		name    string
		req     *EvaluationRequest
		wantErr bool
	}{
		{
			name:    "nil request",
			req:     nil,
			wantErr: true,
		},
		{
			name: "missing action",
			req: &EvaluationRequest{
				Resource: "key-1",
			},
			wantErr: true,
		},
		{
			name: "missing resource",
			req: &EvaluationRequest{
				Action: "Sign",
			},
			wantErr: true,
		},
		{
			name: "valid request",
			req: &EvaluationRequest{
				Action:   "Sign",
				Resource: "key-1",
			},
			wantErr: false,
		},
		{
			name: "valid request with context",
			req: &EvaluationRequest{
				Action:   "Sign",
				Resource: "key-1",
				Context: map[string]string{
					"user": "admin",
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateEvaluationRequest(tt.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateEvaluationRequest() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestMemoryPolicyEngine_AddPolicy(t *testing.T) {
	ctx := context.Background()
	engine := NewMemoryPolicyEngine()

	policy := &Policy{
		ID:     "policy-1",
		Name:   "test policy",
		Effect: Allow,
		Rules: []PolicyRule{
			{
				Actions:   []string{"Sign"},
				Resources: []string{"key-1"},
			},
		},
	}

	// Add policy
	err := engine.AddPolicy(ctx, policy)
	if err != nil {
		t.Fatalf("AddPolicy() error = %v", err)
	}

	// Verify timestamps were set
	if policy.CreatedAt.IsZero() {
		t.Error("CreatedAt was not set")
	}
	if policy.UpdatedAt.IsZero() {
		t.Error("UpdatedAt was not set")
	}

	// Verify policy was added
	retrieved, err := engine.GetPolicy(ctx, "policy-1")
	if err != nil {
		t.Fatalf("GetPolicy() error = %v", err)
	}
	if retrieved.ID != policy.ID {
		t.Errorf("GetPolicy() ID = %v, want %v", retrieved.ID, policy.ID)
	}

	// Try to add duplicate
	err = engine.AddPolicy(ctx, policy)
	if err == nil {
		t.Error("AddPolicy() expected error for duplicate, got nil")
	}
}

func TestMemoryPolicyEngine_AddPolicy_Invalid(t *testing.T) {
	ctx := context.Background()
	engine := NewMemoryPolicyEngine()

	invalidPolicy := &Policy{
		ID:   "policy-1",
		Name: "test",
		// Missing effect and rules
	}

	err := engine.AddPolicy(ctx, invalidPolicy)
	if err == nil {
		t.Error("AddPolicy() expected error for invalid policy, got nil")
	}
}

func TestMemoryPolicyEngine_UpdatePolicy(t *testing.T) {
	ctx := context.Background()
	engine := NewMemoryPolicyEngine()

	policy := &Policy{
		ID:     "policy-1",
		Name:   "test policy",
		Effect: Allow,
		Rules: []PolicyRule{
			{
				Actions:   []string{"Sign"},
				Resources: []string{"key-1"},
			},
		},
	}

	// Add policy
	err := engine.AddPolicy(ctx, policy)
	if err != nil {
		t.Fatalf("AddPolicy() error = %v", err)
	}

	createdAt := policy.CreatedAt
	time.Sleep(time.Millisecond) // Ensure time difference

	// Update policy
	policy.Name = "updated policy"
	err = engine.UpdatePolicy(ctx, policy)
	if err != nil {
		t.Fatalf("UpdatePolicy() error = %v", err)
	}

	// Verify update
	retrieved, err := engine.GetPolicy(ctx, "policy-1")
	if err != nil {
		t.Fatalf("GetPolicy() error = %v", err)
	}
	if retrieved.Name != "updated policy" {
		t.Errorf("UpdatePolicy() Name = %v, want %v", retrieved.Name, "updated policy")
	}
	if !retrieved.CreatedAt.Equal(createdAt) {
		t.Error("UpdatePolicy() modified CreatedAt")
	}
	if !retrieved.UpdatedAt.After(createdAt) {
		t.Error("UpdatePolicy() did not update UpdatedAt")
	}
}

func TestMemoryPolicyEngine_UpdatePolicy_NotFound(t *testing.T) {
	ctx := context.Background()
	engine := NewMemoryPolicyEngine()

	policy := &Policy{
		ID:     "nonexistent",
		Name:   "test policy",
		Effect: Allow,
		Rules: []PolicyRule{
			{
				Actions:   []string{"Sign"},
				Resources: []string{"key-1"},
			},
		},
	}

	err := engine.UpdatePolicy(ctx, policy)
	if err == nil {
		t.Error("UpdatePolicy() expected error for nonexistent policy, got nil")
	}
}

func TestMemoryPolicyEngine_DeletePolicy(t *testing.T) {
	ctx := context.Background()
	engine := NewMemoryPolicyEngine()

	policy := &Policy{
		ID:     "policy-1",
		Name:   "test policy",
		Effect: Allow,
		Rules: []PolicyRule{
			{
				Actions:   []string{"Sign"},
				Resources: []string{"key-1"},
			},
		},
	}

	// Add policy
	err := engine.AddPolicy(ctx, policy)
	if err != nil {
		t.Fatalf("AddPolicy() error = %v", err)
	}

	// Delete policy
	err = engine.DeletePolicy(ctx, "policy-1")
	if err != nil {
		t.Fatalf("DeletePolicy() error = %v", err)
	}

	// Verify deletion
	_, err = engine.GetPolicy(ctx, "policy-1")
	if err == nil {
		t.Error("GetPolicy() expected error for deleted policy, got nil")
	}
}

func TestMemoryPolicyEngine_DeletePolicy_NotFound(t *testing.T) {
	ctx := context.Background()
	engine := NewMemoryPolicyEngine()

	err := engine.DeletePolicy(ctx, "nonexistent")
	if err == nil {
		t.Error("DeletePolicy() expected error for nonexistent policy, got nil")
	}
}

func TestMemoryPolicyEngine_GetPolicy_NotFound(t *testing.T) {
	ctx := context.Background()
	engine := NewMemoryPolicyEngine()

	_, err := engine.GetPolicy(ctx, "nonexistent")
	if err == nil {
		t.Error("GetPolicy() expected error for nonexistent policy, got nil")
	}
}

func TestMemoryPolicyEngine_ListPolicies(t *testing.T) {
	ctx := context.Background()
	engine := NewMemoryPolicyEngine()

	// Add multiple policies with different priorities
	policies := []*Policy{
		{
			ID:       "policy-1",
			Name:     "low priority",
			Effect:   Allow,
			Priority: 1,
			Rules: []PolicyRule{
				{
					Actions:   []string{"Sign"},
					Resources: []string{"key-1"},
				},
			},
		},
		{
			ID:       "policy-2",
			Name:     "high priority",
			Effect:   Deny,
			Priority: 10,
			Rules: []PolicyRule{
				{
					Actions:   []string{"Sign"},
					Resources: []string{"key-1"},
				},
			},
		},
		{
			ID:       "policy-3",
			Name:     "medium priority",
			Effect:   Allow,
			Priority: 5,
			Rules: []PolicyRule{
				{
					Actions:   []string{"Sign"},
					Resources: []string{"key-1"},
				},
			},
		},
	}

	for _, p := range policies {
		err := engine.AddPolicy(ctx, p)
		if err != nil {
			t.Fatalf("AddPolicy() error = %v", err)
		}
	}

	// List policies
	retrieved, err := engine.ListPolicies(ctx)
	if err != nil {
		t.Fatalf("ListPolicies() error = %v", err)
	}

	if len(retrieved) != 3 {
		t.Errorf("ListPolicies() count = %v, want 3", len(retrieved))
	}

	// Verify sorted by priority (highest first)
	if retrieved[0].ID != "policy-2" {
		t.Errorf("ListPolicies() first policy = %v, want policy-2", retrieved[0].ID)
	}
	if retrieved[1].ID != "policy-3" {
		t.Errorf("ListPolicies() second policy = %v, want policy-3", retrieved[1].ID)
	}
	if retrieved[2].ID != "policy-1" {
		t.Errorf("ListPolicies() third policy = %v, want policy-1", retrieved[2].ID)
	}
}

func TestMemoryPolicyEngine_ListPolicies_Empty(t *testing.T) {
	ctx := context.Background()
	engine := NewMemoryPolicyEngine()

	policies, err := engine.ListPolicies(ctx)
	if err != nil {
		t.Fatalf("ListPolicies() error = %v", err)
	}

	if len(policies) != 0 {
		t.Errorf("ListPolicies() count = %v, want 0", len(policies))
	}
}

func TestMemoryPolicyEngine_EvaluatePolicy_Allow(t *testing.T) {
	ctx := context.Background()
	engine := NewMemoryPolicyEngine()

	policy := &Policy{
		ID:     "policy-1",
		Name:   "allow policy",
		Effect: Allow,
		Rules: []PolicyRule{
			{
				Actions:   []string{"Sign"},
				Resources: []string{"key-1"},
			},
		},
	}

	err := engine.AddPolicy(ctx, policy)
	if err != nil {
		t.Fatalf("AddPolicy() error = %v", err)
	}

	req := &EvaluationRequest{
		Action:   "Sign",
		Resource: "key-1",
	}

	result, err := engine.EvaluatePolicy(ctx, req)
	if err != nil {
		t.Fatalf("EvaluatePolicy() error = %v", err)
	}

	if result.Effect != Allow {
		t.Errorf("EvaluatePolicy() Effect = %v, want Allow", result.Effect)
	}
	if len(result.MatchedPolicies) != 1 || result.MatchedPolicies[0] != "policy-1" {
		t.Errorf("EvaluatePolicy() MatchedPolicies = %v, want [policy-1]", result.MatchedPolicies)
	}
}

func TestMemoryPolicyEngine_EvaluatePolicy_Deny(t *testing.T) {
	ctx := context.Background()
	engine := NewMemoryPolicyEngine()

	policy := &Policy{
		ID:     "policy-1",
		Name:   "deny policy",
		Effect: Deny,
		Rules: []PolicyRule{
			{
				Actions:   []string{"Sign"},
				Resources: []string{"key-1"},
			},
		},
	}

	err := engine.AddPolicy(ctx, policy)
	if err != nil {
		t.Fatalf("AddPolicy() error = %v", err)
	}

	req := &EvaluationRequest{
		Action:   "Sign",
		Resource: "key-1",
	}

	result, err := engine.EvaluatePolicy(ctx, req)
	if err != nil {
		t.Fatalf("EvaluatePolicy() error = %v", err)
	}

	if result.Effect != Deny {
		t.Errorf("EvaluatePolicy() Effect = %v, want Deny", result.Effect)
	}
	if len(result.MatchedPolicies) != 1 || result.MatchedPolicies[0] != "policy-1" {
		t.Errorf("EvaluatePolicy() MatchedPolicies = %v, want [policy-1]", result.MatchedPolicies)
	}
}

func TestMemoryPolicyEngine_EvaluatePolicy_DenyOverridesAllow(t *testing.T) {
	ctx := context.Background()
	engine := NewMemoryPolicyEngine()

	allowPolicy := &Policy{
		ID:       "allow-policy",
		Name:     "allow policy",
		Effect:   Allow,
		Priority: 1,
		Rules: []PolicyRule{
			{
				Actions:   []string{"Sign"},
				Resources: []string{"*"},
			},
		},
	}

	denyPolicy := &Policy{
		ID:       "deny-policy",
		Name:     "deny policy",
		Effect:   Deny,
		Priority: 10,
		Rules: []PolicyRule{
			{
				Actions:   []string{"Sign"},
				Resources: []string{"key-1"},
			},
		},
	}

	err := engine.AddPolicy(ctx, allowPolicy)
	if err != nil {
		t.Fatalf("AddPolicy() error = %v", err)
	}
	err = engine.AddPolicy(ctx, denyPolicy)
	if err != nil {
		t.Fatalf("AddPolicy() error = %v", err)
	}

	req := &EvaluationRequest{
		Action:   "Sign",
		Resource: "key-1",
	}

	result, err := engine.EvaluatePolicy(ctx, req)
	if err != nil {
		t.Fatalf("EvaluatePolicy() error = %v", err)
	}

	if result.Effect != Deny {
		t.Errorf("EvaluatePolicy() Effect = %v, want Deny (deny should override allow)", result.Effect)
	}
}

func TestMemoryPolicyEngine_EvaluatePolicy_DefaultDeny(t *testing.T) {
	ctx := context.Background()
	engine := NewMemoryPolicyEngine()

	req := &EvaluationRequest{
		Action:   "Sign",
		Resource: "key-1",
	}

	result, err := engine.EvaluatePolicy(ctx, req)
	if err != nil {
		t.Fatalf("EvaluatePolicy() error = %v", err)
	}

	if result.Effect != Deny {
		t.Errorf("EvaluatePolicy() Effect = %v, want Deny (default deny)", result.Effect)
	}
}

func TestMemoryPolicyEngine_EvaluatePolicy_WildcardAction(t *testing.T) {
	ctx := context.Background()
	engine := NewMemoryPolicyEngine()

	policy := &Policy{
		ID:     "policy-1",
		Name:   "wildcard action policy",
		Effect: Allow,
		Rules: []PolicyRule{
			{
				Actions:   []string{"*"},
				Resources: []string{"key-1"},
			},
		},
	}

	err := engine.AddPolicy(ctx, policy)
	if err != nil {
		t.Fatalf("AddPolicy() error = %v", err)
	}

	req := &EvaluationRequest{
		Action:   "Sign",
		Resource: "key-1",
	}

	result, err := engine.EvaluatePolicy(ctx, req)
	if err != nil {
		t.Fatalf("EvaluatePolicy() error = %v", err)
	}

	if result.Effect != Allow {
		t.Errorf("EvaluatePolicy() Effect = %v, want Allow", result.Effect)
	}
}

func TestMemoryPolicyEngine_EvaluatePolicy_WildcardResource(t *testing.T) {
	ctx := context.Background()
	engine := NewMemoryPolicyEngine()

	policy := &Policy{
		ID:     "policy-1",
		Name:   "wildcard resource policy",
		Effect: Allow,
		Rules: []PolicyRule{
			{
				Actions:   []string{"Sign"},
				Resources: []string{"*"},
			},
		},
	}

	err := engine.AddPolicy(ctx, policy)
	if err != nil {
		t.Fatalf("AddPolicy() error = %v", err)
	}

	req := &EvaluationRequest{
		Action:   "Sign",
		Resource: "any-key",
	}

	result, err := engine.EvaluatePolicy(ctx, req)
	if err != nil {
		t.Fatalf("EvaluatePolicy() error = %v", err)
	}

	if result.Effect != Allow {
		t.Errorf("EvaluatePolicy() Effect = %v, want Allow", result.Effect)
	}
}

func TestMemoryPolicyEngine_EvaluatePolicy_PatternMatching(t *testing.T) {
	ctx := context.Background()
	engine := NewMemoryPolicyEngine()

	policy := &Policy{
		ID:     "policy-1",
		Name:   "pattern matching policy",
		Effect: Allow,
		Rules: []PolicyRule{
			{
				Actions:   []string{"Sign*"},
				Resources: []string{"prod-*"},
			},
		},
	}

	err := engine.AddPolicy(ctx, policy)
	if err != nil {
		t.Fatalf("AddPolicy() error = %v", err)
	}

	tests := []struct {
		name     string
		action   string
		resource string
		want     PolicyEffect
	}{
		{
			name:     "matching pattern",
			action:   "SignData",
			resource: "prod-key-1",
			want:     Allow,
		},
		{
			name:     "non-matching action",
			action:   "Encrypt",
			resource: "prod-key-1",
			want:     Deny,
		},
		{
			name:     "non-matching resource",
			action:   "SignData",
			resource: "dev-key-1",
			want:     Deny,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &EvaluationRequest{
				Action:   tt.action,
				Resource: tt.resource,
			}

			result, err := engine.EvaluatePolicy(ctx, req)
			if err != nil {
				t.Fatalf("EvaluatePolicy() error = %v", err)
			}

			if result.Effect != tt.want {
				t.Errorf("EvaluatePolicy() Effect = %v, want %v", result.Effect, tt.want)
			}
		})
	}
}

func TestMemoryPolicyEngine_EvaluatePolicy_Conditions(t *testing.T) {
	ctx := context.Background()
	engine := NewMemoryPolicyEngine()

	policy := &Policy{
		ID:     "policy-1",
		Name:   "conditional policy",
		Effect: Allow,
		Rules: []PolicyRule{
			{
				Actions:   []string{"Sign"},
				Resources: []string{"key-1"},
				Conditions: map[string]string{
					"user": "admin",
					"env":  "prod",
				},
			},
		},
	}

	err := engine.AddPolicy(ctx, policy)
	if err != nil {
		t.Fatalf("AddPolicy() error = %v", err)
	}

	tests := []struct {
		name    string
		context map[string]string
		want    PolicyEffect
	}{
		{
			name: "matching conditions",
			context: map[string]string{
				"user": "admin",
				"env":  "prod",
			},
			want: Allow,
		},
		{
			name: "missing condition",
			context: map[string]string{
				"user": "admin",
			},
			want: Deny,
		},
		{
			name: "wrong condition value",
			context: map[string]string{
				"user": "user",
				"env":  "prod",
			},
			want: Deny,
		},
		{
			name:    "no context",
			context: nil,
			want:    Deny,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &EvaluationRequest{
				Action:   "Sign",
				Resource: "key-1",
				Context:  tt.context,
			}

			result, err := engine.EvaluatePolicy(ctx, req)
			if err != nil {
				t.Fatalf("EvaluatePolicy() error = %v", err)
			}

			if result.Effect != tt.want {
				t.Errorf("EvaluatePolicy() Effect = %v, want %v", result.Effect, tt.want)
			}
		})
	}
}

func TestMemoryPolicyEngine_EvaluatePolicy_ConditionWildcard(t *testing.T) {
	ctx := context.Background()
	engine := NewMemoryPolicyEngine()

	policy := &Policy{
		ID:     "policy-1",
		Name:   "wildcard condition policy",
		Effect: Allow,
		Rules: []PolicyRule{
			{
				Actions:   []string{"Sign"},
				Resources: []string{"key-1"},
				Conditions: map[string]string{
					"user": "admin-*",
				},
			},
		},
	}

	err := engine.AddPolicy(ctx, policy)
	if err != nil {
		t.Fatalf("AddPolicy() error = %v", err)
	}

	req := &EvaluationRequest{
		Action:   "Sign",
		Resource: "key-1",
		Context: map[string]string{
			"user": "admin-john",
		},
	}

	result, err := engine.EvaluatePolicy(ctx, req)
	if err != nil {
		t.Fatalf("EvaluatePolicy() error = %v", err)
	}

	if result.Effect != Allow {
		t.Errorf("EvaluatePolicy() Effect = %v, want Allow", result.Effect)
	}
}

func TestMemoryPolicyEngine_EvaluatePolicy_InvalidRequest(t *testing.T) {
	ctx := context.Background()
	engine := NewMemoryPolicyEngine()

	tests := []struct {
		name string
		req  *EvaluationRequest
	}{
		{
			name: "nil request",
			req:  nil,
		},
		{
			name: "missing action",
			req: &EvaluationRequest{
				Resource: "key-1",
			},
		},
		{
			name: "missing resource",
			req: &EvaluationRequest{
				Action: "Sign",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := engine.EvaluatePolicy(ctx, tt.req)
			if err == nil {
				t.Error("EvaluatePolicy() expected error for invalid request, got nil")
			}
		})
	}
}

func TestMemoryPolicyEngine_EvaluatePolicy_MultipleRules(t *testing.T) {
	ctx := context.Background()
	engine := NewMemoryPolicyEngine()

	policy := &Policy{
		ID:     "policy-1",
		Name:   "multi-rule policy",
		Effect: Allow,
		Rules: []PolicyRule{
			{
				Actions:   []string{"Sign"},
				Resources: []string{"key-1"},
			},
			{
				Actions:   []string{"Encrypt"},
				Resources: []string{"key-2"},
			},
		},
	}

	err := engine.AddPolicy(ctx, policy)
	if err != nil {
		t.Fatalf("AddPolicy() error = %v", err)
	}

	tests := []struct {
		name     string
		action   string
		resource string
		want     PolicyEffect
	}{
		{
			name:     "matches first rule",
			action:   "Sign",
			resource: "key-1",
			want:     Allow,
		},
		{
			name:     "matches second rule",
			action:   "Encrypt",
			resource: "key-2",
			want:     Allow,
		},
		{
			name:     "matches no rule",
			action:   "Decrypt",
			resource: "key-3",
			want:     Deny,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &EvaluationRequest{
				Action:   tt.action,
				Resource: tt.resource,
			}

			result, err := engine.EvaluatePolicy(ctx, req)
			if err != nil {
				t.Fatalf("EvaluatePolicy() error = %v", err)
			}

			if result.Effect != tt.want {
				t.Errorf("EvaluatePolicy() Effect = %v, want %v", result.Effect, tt.want)
			}
		})
	}
}

func TestMemoryPolicyEngine_ThreadSafety(t *testing.T) {
	ctx := context.Background()
	engine := NewMemoryPolicyEngine()

	// Add initial policy
	policy := &Policy{
		ID:     "policy-1",
		Name:   "test policy",
		Effect: Allow,
		Rules: []PolicyRule{
			{
				Actions:   []string{"Sign"},
				Resources: []string{"key-1"},
			},
		},
	}

	err := engine.AddPolicy(ctx, policy)
	if err != nil {
		t.Fatalf("AddPolicy() error = %v", err)
	}

	// Run concurrent operations
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			// Read operations
			_, _ = engine.GetPolicy(ctx, "policy-1")
			_, _ = engine.ListPolicies(ctx)
			_, _ = engine.EvaluatePolicy(ctx, &EvaluationRequest{
				Action:   "Sign",
				Resource: "key-1",
			})
			done <- true
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}
}
