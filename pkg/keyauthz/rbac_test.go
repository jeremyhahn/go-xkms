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

package keyauthz

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/keyrbac"
)

func TestRBACAuthorizer_WildcardPermissions(t *testing.T) {
	adapter := keyrbac.NewMemoryRBACAdapter(true)
	ctx := context.Background()

	// Create a custom wildcard-admin role with a global wildcard (*:*)
	// permission that grants access to every resource and action. The
	// built-in admin role is intentionally scoped per FIPS 140-2/3
	// separation of duties — this test exercises only the wildcard
	// matching behaviour of the authorizer, not a recommended role design.
	wildcardRole := &keyrbac.Role{
		Name:        "wildcard-admin",
		Description: "Unrestricted access via global wildcard",
		Permissions: []keyrbac.Permission{
			{Resource: keyrbac.ResourceAll, Action: keyrbac.ActionAll},
		},
	}
	if err := adapter.CreateRole(ctx, wildcardRole); err != nil {
		t.Fatalf("CreateRole() error: %v", err)
	}

	err := adapter.AssignRole(ctx, "wildcard-user", "wildcard-admin")
	if err != nil {
		t.Fatalf("AssignRole() error: %v", err)
	}

	authorizer := NewRBACAuthorizer(adapter)

	tests := []struct {
		name     string
		resource string
		action   string
	}{
		{"wildcard allows keys:delete", keyrbac.ResourceKeys, keyrbac.ActionDelete},
		{"wildcard allows system:manage", keyrbac.ResourceSystem, keyrbac.ActionManage},
		{"wildcard allows users:create", keyrbac.ResourceUsers, keyrbac.ActionCreate},
		{"wildcard allows audit:list", keyrbac.ResourceAudit, keyrbac.ActionList},
		{"wildcard allows secrets:export", keyrbac.ResourceSecrets, keyrbac.ActionExport},
		{"wildcard allows certs:rotate", keyrbac.ResourceCertificates, keyrbac.ActionRotate},
		{"wildcard allows arbitrary resource", "custom-resource", "custom-action"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &AuthorizationRequest{
				Subject:  "wildcard-user",
				Role:     "wildcard-admin",
				Resource: tt.resource,
				Action:   tt.action,
			}

			decision, err := authorizer.Authorize(ctx, req)
			if err != nil {
				t.Fatalf("Authorize() unexpected error: %v", err)
			}
			if !decision.Allowed {
				t.Errorf("Authorize() Allowed = false, want true for wildcard-admin on %s:%s; Reason = %q",
					tt.resource, tt.action, decision.Reason)
			}
		})
	}
}

func TestRBACAuthorizer_ResourceSpecificDenial(t *testing.T) {
	adapter := keyrbac.NewMemoryRBACAdapter(true)
	ctx := context.Background()

	// The default "user" role only has sign, verify, encrypt, decrypt on keys
	// and read on secrets.
	err := adapter.AssignRole(ctx, "limited-user", keyrbac.RoleUser)
	if err != nil {
		t.Fatalf("AssignRole() error: %v", err)
	}

	authorizer := NewRBACAuthorizer(adapter)

	tests := []struct {
		name     string
		resource string
		action   string
	}{
		{"user denied keys:create", keyrbac.ResourceKeys, keyrbac.ActionCreate},
		{"user denied keys:delete", keyrbac.ResourceKeys, keyrbac.ActionDelete},
		{"user denied keys:list", keyrbac.ResourceKeys, keyrbac.ActionList},
		{"user denied keys:import", keyrbac.ResourceKeys, keyrbac.ActionImport},
		{"user denied keys:export", keyrbac.ResourceKeys, keyrbac.ActionExport},
		{"user denied keys:rotate", keyrbac.ResourceKeys, keyrbac.ActionRotate},
		{"user denied secrets:delete", keyrbac.ResourceSecrets, keyrbac.ActionDelete},
		{"user denied secrets:create", keyrbac.ResourceSecrets, keyrbac.ActionCreate},
		{"user denied users:read", keyrbac.ResourceUsers, keyrbac.ActionRead},
		{"user denied backends:manage", keyrbac.ResourceBackends, keyrbac.ActionManage},
		{"user denied system:manage", keyrbac.ResourceSystem, keyrbac.ActionManage},
		{"user denied audit:read", keyrbac.ResourceAudit, keyrbac.ActionRead},
		{"user denied roles:create", keyrbac.ResourceRoles, keyrbac.ActionCreate},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &AuthorizationRequest{
				Subject:  "limited-user",
				Role:     keyrbac.RoleUser,
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
	adapter := keyrbac.NewMemoryRBACAdapter(true)
	ctx := context.Background()

	// Operator has wildcard action on keys (keys:*) and certs (certificates:*).
	err := adapter.AssignRole(ctx, "operator", keyrbac.RoleOperator)
	if err != nil {
		t.Fatalf("AssignRole() error: %v", err)
	}

	authorizer := NewRBACAuthorizer(adapter)

	// All standard actions should be allowed on keys for operator (keys:*).
	keyActions := []string{
		keyrbac.ActionCreate,
		keyrbac.ActionRead,
		keyrbac.ActionUpdate,
		keyrbac.ActionDelete,
		keyrbac.ActionList,
		keyrbac.ActionSign,
		keyrbac.ActionVerify,
		keyrbac.ActionEncrypt,
		keyrbac.ActionDecrypt,
		keyrbac.ActionImport,
		keyrbac.ActionExport,
		keyrbac.ActionRotate,
		keyrbac.ActionManage,
	}

	for _, action := range keyActions {
		t.Run("operator keys:"+action, func(t *testing.T) {
			req := &AuthorizationRequest{
				Subject:  "operator",
				Role:     keyrbac.RoleOperator,
				Resource: keyrbac.ResourceKeys,
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
				Role:     keyrbac.RoleOperator,
				Resource: keyrbac.ResourceCertificates,
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
	adapter := keyrbac.NewMemoryRBACAdapter(true)
	authorizer := NewRBACAuthorizer(adapter)
	ctx := context.Background()

	// Subject exists but has no assigned roles.
	req := &AuthorizationRequest{
		Subject:  "unknown-user",
		Role:     "",
		Resource: keyrbac.ResourceKeys,
		Action:   keyrbac.ActionRead,
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
	adapter := keyrbac.NewMemoryRBACAdapter(true)
	ctx := context.Background()

	err := adapter.AssignRole(ctx, "ctx-user", keyrbac.RoleUser)
	if err != nil {
		t.Fatalf("AssignRole() error: %v", err)
	}

	authorizer := NewRBACAuthorizer(adapter)

	// Verify that additional context fields do not interfere with authorization.
	req := &AuthorizationRequest{
		Subject:  "ctx-user",
		Role:     keyrbac.RoleUser,
		Resource: keyrbac.ResourceKeys,
		Action:   keyrbac.ActionSign,
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
	adapter := keyrbac.NewMemoryRBACAdapter(true)
	ctx := context.Background()

	// Assign both auditor and user roles to the same subject.
	err := adapter.AssignRole(ctx, "multi-role", keyrbac.RoleAuditor)
	if err != nil {
		t.Fatalf("AssignRole(auditor) error: %v", err)
	}
	err = adapter.AssignRole(ctx, "multi-role", keyrbac.RoleUser)
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
		{"audit read from auditor", keyrbac.ResourceAudit, keyrbac.ActionRead, true},
		{"users list from auditor", keyrbac.ResourceUsers, keyrbac.ActionList, true},
		// From user role.
		{"keys sign from user", keyrbac.ResourceKeys, keyrbac.ActionSign, true},
		{"keys verify from user", keyrbac.ResourceKeys, keyrbac.ActionVerify, true},
		// Neither role grants this.
		{"system manage denied", keyrbac.ResourceSystem, keyrbac.ActionManage, false},
		{"keys delete denied", keyrbac.ResourceKeys, keyrbac.ActionDelete, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &AuthorizationRequest{
				Subject:  "multi-role",
				Role:     keyrbac.RoleUser, // Claimed role, but we check all assigned roles.
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
