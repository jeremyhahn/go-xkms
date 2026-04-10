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

package authz

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/rbac"
)

func TestNoOpAuthorizer_AlwaysAllows(t *testing.T) {
	authorizer := &NoOpAuthorizer{}
	ctx := context.Background()

	req := &AuthorizationRequest{
		Subject:  "alice",
		Role:     rbac.RoleUser,
		Resource: rbac.ResourceKeys,
		Action:   rbac.ActionDelete,
	}

	decision, err := authorizer.Authorize(ctx, req)
	if err != nil {
		t.Fatalf("Authorize() unexpected error: %v", err)
	}
	if !decision.Allowed {
		t.Error("Authorize() Allowed = false, want true for NoOpAuthorizer")
	}
	if decision.Reason != "no-op authorizer" {
		t.Errorf("Authorize() Reason = %q, want %q", decision.Reason, "no-op authorizer")
	}
}

func TestNoOpAuthorizer_NilRequest(t *testing.T) {
	authorizer := &NoOpAuthorizer{}
	ctx := context.Background()

	decision, err := authorizer.Authorize(ctx, nil)
	if err != nil {
		t.Fatalf("Authorize() unexpected error: %v", err)
	}
	if !decision.Allowed {
		t.Error("Authorize() Allowed = false, want true for NoOpAuthorizer with nil request")
	}
}

func TestRBACAuthorizer_AdminAllowed(t *testing.T) {
	adapter := rbac.NewMemoryRBACAdapter(true)
	ctx := context.Background()

	err := adapter.AssignRole(ctx, "admin-user", rbac.RoleAdmin)
	if err != nil {
		t.Fatalf("AssignRole() error: %v", err)
	}

	authorizer := NewRBACAuthorizer(adapter)

	req := &AuthorizationRequest{
		Subject:  "admin-user",
		Role:     rbac.RoleAdmin,
		Resource: rbac.ResourceKeys,
		Action:   rbac.ActionDelete,
	}

	decision, err := authorizer.Authorize(ctx, req)
	if err != nil {
		t.Fatalf("Authorize() unexpected error: %v", err)
	}
	if !decision.Allowed {
		t.Errorf("Authorize() Allowed = false, want true for admin; Reason = %q", decision.Reason)
	}
	if decision.Reason != "permitted" {
		t.Errorf("Authorize() Reason = %q, want %q", decision.Reason, "permitted")
	}
}

func TestRBACAuthorizer_UserDeniedDeleteKeys(t *testing.T) {
	adapter := rbac.NewMemoryRBACAdapter(true)
	ctx := context.Background()

	err := adapter.AssignRole(ctx, "regular-user", rbac.RoleUser)
	if err != nil {
		t.Fatalf("AssignRole() error: %v", err)
	}

	authorizer := NewRBACAuthorizer(adapter)

	req := &AuthorizationRequest{
		Subject:  "regular-user",
		Role:     rbac.RoleUser,
		Resource: rbac.ResourceKeys,
		Action:   rbac.ActionDelete,
	}

	decision, err := authorizer.Authorize(ctx, req)
	if err != nil {
		t.Fatalf("Authorize() unexpected error: %v", err)
	}
	if decision.Allowed {
		t.Error("Authorize() Allowed = true, want false for user deleting keys")
	}
	if decision.Reason == "" {
		t.Error("Authorize() Reason should not be empty for denied request")
	}
}

func TestRBACAuthorizer_UserAllowedSign(t *testing.T) {
	adapter := rbac.NewMemoryRBACAdapter(true)
	ctx := context.Background()

	err := adapter.AssignRole(ctx, "signer", rbac.RoleUser)
	if err != nil {
		t.Fatalf("AssignRole() error: %v", err)
	}

	authorizer := NewRBACAuthorizer(adapter)

	req := &AuthorizationRequest{
		Subject:  "signer",
		Role:     rbac.RoleUser,
		Resource: rbac.ResourceKeys,
		Action:   rbac.ActionSign,
	}

	decision, err := authorizer.Authorize(ctx, req)
	if err != nil {
		t.Fatalf("Authorize() unexpected error: %v", err)
	}
	if !decision.Allowed {
		t.Errorf("Authorize() Allowed = false, want true for user signing; Reason = %q", decision.Reason)
	}
}

func TestRBACAuthorizer_EmptySubject(t *testing.T) {
	adapter := rbac.NewMemoryRBACAdapter(true)
	authorizer := NewRBACAuthorizer(adapter)
	ctx := context.Background()

	req := &AuthorizationRequest{
		Subject:  "",
		Role:     rbac.RoleUser,
		Resource: rbac.ResourceKeys,
		Action:   rbac.ActionRead,
	}

	decision, err := authorizer.Authorize(ctx, req)
	if err != nil {
		t.Fatalf("Authorize() unexpected error: %v", err)
	}
	if decision.Allowed {
		t.Error("Authorize() Allowed = true, want false for empty subject")
	}
	if decision.Reason != "empty subject" {
		t.Errorf("Authorize() Reason = %q, want %q", decision.Reason, "empty subject")
	}
}

func TestRBACAuthorizer_NilRequest(t *testing.T) {
	adapter := rbac.NewMemoryRBACAdapter(true)
	authorizer := NewRBACAuthorizer(adapter)
	ctx := context.Background()

	decision, err := authorizer.Authorize(ctx, nil)
	if err == nil {
		t.Fatal("Authorize() expected error for nil request, got nil")
	}
	if decision != nil {
		t.Error("Authorize() decision should be nil when error is returned")
	}
	if err != ErrInvalidRequest {
		t.Errorf("Authorize() error = %v, want %v", err, ErrInvalidRequest)
	}
}

func TestRBACAuthorizer_OperatorPermissions(t *testing.T) {
	adapter := rbac.NewMemoryRBACAdapter(true)
	ctx := context.Background()

	err := adapter.AssignRole(ctx, "ops-user", rbac.RoleOperator)
	if err != nil {
		t.Fatalf("AssignRole() error: %v", err)
	}

	authorizer := NewRBACAuthorizer(adapter)

	tests := []struct {
		name     string
		resource string
		action   string
		allowed  bool
	}{
		{
			name:     "operator can create keys",
			resource: rbac.ResourceKeys,
			action:   rbac.ActionCreate,
			allowed:  true,
		},
		{
			name:     "operator can delete keys",
			resource: rbac.ResourceKeys,
			action:   rbac.ActionDelete,
			allowed:  true,
		},
		{
			name:     "operator can create secrets",
			resource: rbac.ResourceSecrets,
			action:   rbac.ActionCreate,
			allowed:  true,
		},
		{
			name:     "operator cannot manage users",
			resource: rbac.ResourceUsers,
			action:   rbac.ActionManage,
			allowed:  false,
		},
		{
			name:     "operator cannot manage system",
			resource: rbac.ResourceSystem,
			action:   rbac.ActionManage,
			allowed:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &AuthorizationRequest{
				Subject:  "ops-user",
				Role:     rbac.RoleOperator,
				Resource: tt.resource,
				Action:   tt.action,
			}

			decision, err := authorizer.Authorize(ctx, req)
			if err != nil {
				t.Fatalf("Authorize() unexpected error: %v", err)
			}
			if decision.Allowed != tt.allowed {
				t.Errorf("Authorize() Allowed = %v, want %v; Reason = %q",
					decision.Allowed, tt.allowed, decision.Reason)
			}
		})
	}
}

func TestRBACAuthorizer_AuditorPermissions(t *testing.T) {
	adapter := rbac.NewMemoryRBACAdapter(true)
	ctx := context.Background()

	err := adapter.AssignRole(ctx, "auditor-user", rbac.RoleAuditor)
	if err != nil {
		t.Fatalf("AssignRole() error: %v", err)
	}

	authorizer := NewRBACAuthorizer(adapter)

	tests := []struct {
		name     string
		resource string
		action   string
		allowed  bool
	}{
		{
			name:     "auditor can read audit logs",
			resource: rbac.ResourceAudit,
			action:   rbac.ActionRead,
			allowed:  true,
		},
		{
			name:     "auditor can list audit logs",
			resource: rbac.ResourceAudit,
			action:   rbac.ActionList,
			allowed:  true,
		},
		{
			name:     "auditor can list keys",
			resource: rbac.ResourceKeys,
			action:   rbac.ActionList,
			allowed:  true,
		},
		{
			name:     "auditor can list certificates",
			resource: rbac.ResourceCertificates,
			action:   rbac.ActionList,
			allowed:  true,
		},
		{
			name:     "auditor can list users",
			resource: rbac.ResourceUsers,
			action:   rbac.ActionList,
			allowed:  true,
		},
		{
			name:     "auditor cannot delete keys",
			resource: rbac.ResourceKeys,
			action:   rbac.ActionDelete,
			allowed:  false,
		},
		{
			name:     "auditor cannot sign with keys",
			resource: rbac.ResourceKeys,
			action:   rbac.ActionSign,
			allowed:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &AuthorizationRequest{
				Subject:  "auditor-user",
				Role:     rbac.RoleAuditor,
				Resource: tt.resource,
				Action:   tt.action,
			}

			decision, err := authorizer.Authorize(ctx, req)
			if err != nil {
				t.Fatalf("Authorize() unexpected error: %v", err)
			}
			if decision.Allowed != tt.allowed {
				t.Errorf("Authorize() Allowed = %v, want %v; Reason = %q",
					decision.Allowed, tt.allowed, decision.Reason)
			}
		})
	}
}

func TestRBACAuthorizer_InterfaceCompliance(t *testing.T) {
	// Verify compile-time interface satisfaction.
	var _ Authorizer = (*RBACAuthorizer)(nil)
	var _ Authorizer = (*NoOpAuthorizer)(nil)

	// Ensure concrete types can be assigned to the interface
	// and exercised (concrete constructors never return nil).
	adapter := rbac.NewMemoryRBACAdapter(false)
	authorizer := NewRBACAuthorizer(adapter)
	_, _ = authorizer.Authorize(context.Background(), &AuthorizationRequest{})

	noop := &NoOpAuthorizer{}
	_, _ = noop.Authorize(context.Background(), &AuthorizationRequest{})
}

func TestAuthorizationDecision_Fields(t *testing.T) {
	tests := []struct {
		name     string
		decision AuthorizationDecision
		allowed  bool
		reason   string
	}{
		{
			name:     "allowed decision",
			decision: AuthorizationDecision{Allowed: true, Reason: "permitted"},
			allowed:  true,
			reason:   "permitted",
		},
		{
			name:     "denied decision",
			decision: AuthorizationDecision{Allowed: false, Reason: "insufficient permissions"},
			allowed:  false,
			reason:   "insufficient permissions",
		},
		{
			name:     "zero value decision",
			decision: AuthorizationDecision{},
			allowed:  false,
			reason:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.decision.Allowed != tt.allowed {
				t.Errorf("Allowed = %v, want %v", tt.decision.Allowed, tt.allowed)
			}
			if tt.decision.Reason != tt.reason {
				t.Errorf("Reason = %q, want %q", tt.decision.Reason, tt.reason)
			}
		})
	}
}
