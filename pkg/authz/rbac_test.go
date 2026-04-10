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

func TestRBACAuthorizer_WildcardPermissions(t *testing.T) {
	adapter := rbac.NewMemoryRBACAdapter(true)
	ctx := context.Background()

	// Create a custom superadmin role with a global wildcard (*:*) permission
	// that grants access to every resource and action. The built-in admin role
	// is intentionally scoped per FIPS 140-2/3 separation of duties.
	superadminRole := &rbac.Role{
		Name:        "superadmin",
		Description: "Unrestricted access via global wildcard",
		Permissions: []rbac.Permission{
			{Resource: rbac.ResourceAll, Action: rbac.ActionAll},
		},
	}
	if err := adapter.CreateRole(ctx, superadminRole); err != nil {
		t.Fatalf("CreateRole() error: %v", err)
	}

	err := adapter.AssignRole(ctx, "superadmin-user", "superadmin")
	if err != nil {
		t.Fatalf("AssignRole() error: %v", err)
	}

	authorizer := NewRBACAuthorizer(adapter)

	tests := []struct {
		name     string
		resource string
		action   string
	}{
		{"wildcard allows keys:delete", rbac.ResourceKeys, rbac.ActionDelete},
		{"wildcard allows system:manage", rbac.ResourceSystem, rbac.ActionManage},
		{"wildcard allows users:create", rbac.ResourceUsers, rbac.ActionCreate},
		{"wildcard allows audit:list", rbac.ResourceAudit, rbac.ActionList},
		{"wildcard allows secrets:export", rbac.ResourceSecrets, rbac.ActionExport},
		{"wildcard allows certs:rotate", rbac.ResourceCertificates, rbac.ActionRotate},
		{"wildcard allows arbitrary resource", "custom-resource", "custom-action"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &AuthorizationRequest{
				Subject:  "superadmin-user",
				Role:     "superadmin",
				Resource: tt.resource,
				Action:   tt.action,
			}

			decision, err := authorizer.Authorize(ctx, req)
			if err != nil {
				t.Fatalf("Authorize() unexpected error: %v", err)
			}
			if !decision.Allowed {
				t.Errorf("Authorize() Allowed = false, want true for superadmin wildcard on %s:%s; Reason = %q",
					tt.resource, tt.action, decision.Reason)
			}
		})
	}
}

func TestRBACAuthorizer_ResourceSpecificDenial(t *testing.T) {
	adapter := rbac.NewMemoryRBACAdapter(true)
	ctx := context.Background()

	// The default "user" role only has sign, verify, encrypt, decrypt on keys
	// and read on secrets.
	err := adapter.AssignRole(ctx, "limited-user", rbac.RoleUser)
	if err != nil {
		t.Fatalf("AssignRole() error: %v", err)
	}

	authorizer := NewRBACAuthorizer(adapter)

	tests := []struct {
		name     string
		resource string
		action   string
	}{
		{"user denied keys:create", rbac.ResourceKeys, rbac.ActionCreate},
		{"user denied keys:delete", rbac.ResourceKeys, rbac.ActionDelete},
		{"user denied keys:list", rbac.ResourceKeys, rbac.ActionList},
		{"user denied keys:import", rbac.ResourceKeys, rbac.ActionImport},
		{"user denied keys:export", rbac.ResourceKeys, rbac.ActionExport},
		{"user denied keys:rotate", rbac.ResourceKeys, rbac.ActionRotate},
		{"user denied secrets:delete", rbac.ResourceSecrets, rbac.ActionDelete},
		{"user denied secrets:create", rbac.ResourceSecrets, rbac.ActionCreate},
		{"user denied users:read", rbac.ResourceUsers, rbac.ActionRead},
		{"user denied backends:manage", rbac.ResourceBackends, rbac.ActionManage},
		{"user denied system:manage", rbac.ResourceSystem, rbac.ActionManage},
		{"user denied audit:read", rbac.ResourceAudit, rbac.ActionRead},
		{"user denied roles:create", rbac.ResourceRoles, rbac.ActionCreate},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &AuthorizationRequest{
				Subject:  "limited-user",
				Role:     rbac.RoleUser,
				Resource: tt.resource,
				Action:   tt.action,
			}

			decision, err := authorizer.Authorize(ctx, req)
			if err != nil {
				t.Fatalf("Authorize() unexpected error: %v", err)
			}
			if decision.Allowed {
				t.Errorf("Authorize() Allowed = true, want false for user on %s:%s",
					tt.resource, tt.action)
			}
		})
	}
}

func TestRBACAuthorizer_AllActions(t *testing.T) {
	adapter := rbac.NewMemoryRBACAdapter(true)
	ctx := context.Background()

	// Operator has wildcard action on keys (keys:*) and certs (certificates:*).
	err := adapter.AssignRole(ctx, "operator", rbac.RoleOperator)
	if err != nil {
		t.Fatalf("AssignRole() error: %v", err)
	}

	authorizer := NewRBACAuthorizer(adapter)

	// All standard actions should be allowed on keys for operator (keys:*).
	keyActions := []string{
		rbac.ActionCreate,
		rbac.ActionRead,
		rbac.ActionUpdate,
		rbac.ActionDelete,
		rbac.ActionList,
		rbac.ActionSign,
		rbac.ActionVerify,
		rbac.ActionEncrypt,
		rbac.ActionDecrypt,
		rbac.ActionImport,
		rbac.ActionExport,
		rbac.ActionRotate,
		rbac.ActionManage,
	}

	for _, action := range keyActions {
		t.Run("operator keys:"+action, func(t *testing.T) {
			req := &AuthorizationRequest{
				Subject:  "operator",
				Role:     rbac.RoleOperator,
				Resource: rbac.ResourceKeys,
				Action:   action,
			}

			decision, err := authorizer.Authorize(ctx, req)
			if err != nil {
				t.Fatalf("Authorize() unexpected error: %v", err)
			}
			if !decision.Allowed {
				t.Errorf("Authorize() Allowed = false, want true for operator on keys:%s; Reason = %q",
					action, decision.Reason)
			}
		})
	}

	// All standard actions should be allowed on certificates for operator.
	for _, action := range keyActions {
		t.Run("operator certificates:"+action, func(t *testing.T) {
			req := &AuthorizationRequest{
				Subject:  "operator",
				Role:     rbac.RoleOperator,
				Resource: rbac.ResourceCertificates,
				Action:   action,
			}

			decision, err := authorizer.Authorize(ctx, req)
			if err != nil {
				t.Fatalf("Authorize() unexpected error: %v", err)
			}
			if !decision.Allowed {
				t.Errorf("Authorize() Allowed = false, want true for operator on certificates:%s; Reason = %q",
					action, decision.Reason)
			}
		})
	}
}

func TestRBACAuthorizer_SubjectWithNoRoles(t *testing.T) {
	adapter := rbac.NewMemoryRBACAdapter(true)
	authorizer := NewRBACAuthorizer(adapter)
	ctx := context.Background()

	// Subject exists but has no assigned roles.
	req := &AuthorizationRequest{
		Subject:  "unknown-user",
		Role:     "",
		Resource: rbac.ResourceKeys,
		Action:   rbac.ActionRead,
	}

	decision, err := authorizer.Authorize(ctx, req)
	if err != nil {
		t.Fatalf("Authorize() unexpected error: %v", err)
	}
	if decision.Allowed {
		t.Error("Authorize() Allowed = true, want false for subject with no roles")
	}
}

func TestRBACAuthorizer_ContextPassthrough(t *testing.T) {
	adapter := rbac.NewMemoryRBACAdapter(true)
	ctx := context.Background()

	err := adapter.AssignRole(ctx, "ctx-user", rbac.RoleUser)
	if err != nil {
		t.Fatalf("AssignRole() error: %v", err)
	}

	authorizer := NewRBACAuthorizer(adapter)

	// Verify that additional context fields do not interfere with authorization.
	req := &AuthorizationRequest{
		Subject:  "ctx-user",
		Role:     rbac.RoleUser,
		Resource: rbac.ResourceKeys,
		Action:   rbac.ActionSign,
		Context: map[string]string{
			"key_id":  "rsa-4096-prod",
			"backend": "tpm2",
			"tenant":  "acme-corp",
		},
	}

	decision, err := authorizer.Authorize(ctx, req)
	if err != nil {
		t.Fatalf("Authorize() unexpected error: %v", err)
	}
	if !decision.Allowed {
		t.Errorf("Authorize() Allowed = false, want true; context should not affect RBAC decision; Reason = %q",
			decision.Reason)
	}
}

func TestRBACAuthorizer_MultipleRoles(t *testing.T) {
	adapter := rbac.NewMemoryRBACAdapter(true)
	ctx := context.Background()

	// Assign both auditor and user roles to the same subject.
	err := adapter.AssignRole(ctx, "multi-role", rbac.RoleAuditor)
	if err != nil {
		t.Fatalf("AssignRole(auditor) error: %v", err)
	}
	err = adapter.AssignRole(ctx, "multi-role", rbac.RoleUser)
	if err != nil {
		t.Fatalf("AssignRole(user) error: %v", err)
	}

	authorizer := NewRBACAuthorizer(adapter)

	tests := []struct {
		name     string
		resource string
		action   string
		allowed  bool
	}{
		// From auditor role.
		{"audit read from auditor", rbac.ResourceAudit, rbac.ActionRead, true},
		{"users list from auditor", rbac.ResourceUsers, rbac.ActionList, true},
		// From user role.
		{"keys sign from user", rbac.ResourceKeys, rbac.ActionSign, true},
		{"keys verify from user", rbac.ResourceKeys, rbac.ActionVerify, true},
		// Neither role grants this.
		{"system manage denied", rbac.ResourceSystem, rbac.ActionManage, false},
		{"keys delete denied", rbac.ResourceKeys, rbac.ActionDelete, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &AuthorizationRequest{
				Subject:  "multi-role",
				Role:     rbac.RoleUser, // Claimed role, but we check all assigned roles.
				Resource: tt.resource,
				Action:   tt.action,
			}

			decision, err := authorizer.Authorize(ctx, req)
			if err != nil {
				t.Fatalf("Authorize() unexpected error: %v", err)
			}
			if decision.Allowed != tt.allowed {
				t.Errorf("Authorize() Allowed = %v, want %v for %s:%s; Reason = %q",
					decision.Allowed, tt.allowed, tt.resource, tt.action, decision.Reason)
			}
		})
	}
}
