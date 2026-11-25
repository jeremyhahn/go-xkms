//go:build codec_json

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

package admin

import (
	"context"
	"errors"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	db "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/assert"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

var errGrantDenied = errors.New("permission denied")

// grantTableRBAC grants each role exactly the permissions listed for it.
type grantTableRBAC struct {
	grants map[string][]string
}

func (g *grantTableRBAC) Authorize(_ context.Context, id *db.Identity, resource, action string) error {
	if id == nil {
		return errGrantDenied
	}
	want := resource + ":" + action
	for _, r := range id.Roles {
		for _, p := range g.grants[r] {
			if p == want {
				return nil
			}
		}
	}
	return errGrantDenied
}

func (g *grantTableRBAC) ListPermissions(_ context.Context, _ *db.Identity) ([]db.PermissionInfo, error) {
	return nil, nil
}

func (g *grantTableRBAC) ListOwnPermissions(ctx context.Context) ([]db.PermissionInfo, error) {
	return g.ListPermissions(ctx, nil)
}

func TestPermissionGate_AdminRoleCannotCreateOrUpdateRoles(t *testing.T) {
	rbac := &grantTableRBAC{grants: map[string][]string{
		qrdbsdk.RoleNameAdmin: {"roles:create", "roles:update", "roles:delete"},
		qrdbsdk.RoleNameSO:    {"roles:create", "roles:update"},
		"role-editor":         {"roles:update"},
	}}
	gate := NewPermissionGate(auth.NewAuthorizer(rbac), discardLogger())

	cases := []struct {
		name    string
		roles   []string
		action  string
		allowed bool
	}{
		{"admin create", []string{qrdbsdk.RoleNameAdmin}, auth.ActionCreate, false},
		{"admin update", []string{qrdbsdk.RoleNameAdmin}, auth.ActionUpdate, false},
		{"admin delete keeps its grant", []string{qrdbsdk.RoleNameAdmin}, auth.ActionDelete, true},
		{"so create", []string{qrdbsdk.RoleNameSO}, auth.ActionCreate, true},
		{"admin and so create", []string{qrdbsdk.RoleNameAdmin, qrdbsdk.RoleNameSO}, auth.ActionCreate, true},
		{"admin and editor update", []string{qrdbsdk.RoleNameAdmin, "role-editor"}, auth.ActionUpdate, true},
		{"admin and editor create", []string{qrdbsdk.RoleNameAdmin, "role-editor"}, auth.ActionCreate, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := auth.WithIdentity(context.Background(), &auth.Identity{
				Subject: "tester", TenantID: "t1", Roles: tc.roles,
			})
			err := gate.Authorize(ctx, auth.ResourceRoles, tc.action)
			if tc.allowed {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}
