// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package qrdb

import (
	"context"
	"sort"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	db "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
)

// storedRoleNames returns the client's role names, sorted.
func storedRoleNames(c *memoryRoleClient, tenantID string) []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var names []string
	for _, r := range c.roles {
		if r.TenantID == tenantID {
			names = append(names, r.Name)
		}
	}
	sort.Strings(names)
	return names
}

func TestMemoryRoleClientReconcileSeedsBuiltInsAndIsIdempotent(t *testing.T) {
	const tenantID = "acme-tenant"
	c := newMemoryRoleClient()

	report, err := c.ReconcileBuiltInRoles(context.Background(), &db.ReconcileRolesRequest{TenantID: tenantID})
	if err != nil {
		t.Fatalf("ReconcileBuiltInRoles: %v", err)
	}
	if report.TenantID != tenantID {
		t.Errorf("TenantID = %q, want %q", report.TenantID, tenantID)
	}

	want := qrdbsdk.BuiltInRoles(tenantID)
	if len(report.Roles) != len(want) {
		t.Fatalf("reported %d roles, want %d", len(report.Roles), len(want))
	}
	for _, r := range report.Roles {
		if !r.Created {
			t.Errorf("role %q: Created = false, want true", r.Name)
		}
		if len(r.Added) == 0 && r.Name != qrdbsdk.RoleNameCustodian {
			t.Errorf("role %q: Added is empty on a seeded role", r.Name)
		}
	}

	var wantNames []string
	for _, r := range want {
		wantNames = append(wantNames, r.Name)
	}
	sort.Strings(wantNames)
	got := storedRoleNames(c, tenantID)
	if len(got) != len(wantNames) {
		t.Fatalf("stored roles = %v, want %v", got, wantNames)
	}
	for i := range got {
		if got[i] != wantNames[i] {
			t.Fatalf("stored roles = %v, want %v", got, wantNames)
		}
	}

	// A converged tenant reports nothing and writes nothing.
	second, err := c.ReconcileBuiltInRoles(context.Background(), &db.ReconcileRolesRequest{TenantID: tenantID})
	if err != nil {
		t.Fatalf("second ReconcileBuiltInRoles: %v", err)
	}
	if len(second.Roles) != 0 {
		t.Errorf("second call reported %d roles, want 0", len(second.Roles))
	}
	if names := storedRoleNames(c, tenantID); len(names) != len(wantNames) {
		t.Errorf("second call changed the stored set: %v", names)
	}
}

func TestMemoryRoleClientReconcileRepairsDriftAndSparesCustomRoles(t *testing.T) {
	const tenantID = "acme-tenant"
	ctx := context.Background()
	c := newMemoryRoleClient()

	custom, err := c.CreateRole(ctx, &db.CreateRoleRequest{
		Name:        "acme-issuer",
		TenantID:    tenantID,
		Permissions: []string{"retired:verb"},
	})
	if err != nil {
		t.Fatalf("CreateRole(custom): %v", err)
	}
	admin, err := c.CreateRole(ctx, &db.CreateRoleRequest{
		Name:        qrdbsdk.RoleNameAdmin,
		TenantID:    tenantID,
		Permissions: []string{"retired:verb"},
	})
	if err != nil {
		t.Fatalf("CreateRole(admin): %v", err)
	}

	report, err := c.ReconcileBuiltInRoles(ctx, &db.ReconcileRolesRequest{TenantID: tenantID})
	if err != nil {
		t.Fatalf("ReconcileBuiltInRoles: %v", err)
	}

	var repaired *db.RoleReconcileResult
	for i := range report.Roles {
		if report.Roles[i].Name == qrdbsdk.RoleNameAdmin {
			repaired = &report.Roles[i]
		}
	}
	if repaired == nil {
		t.Fatal("admin is absent from the report")
	}
	if repaired.Created {
		t.Error("admin reported as Created; it already existed")
	}
	if repaired.RoleID != admin.ID {
		t.Errorf("RoleID = %q, want the stored %q", repaired.RoleID, admin.ID)
	}
	if len(repaired.Removed) != 1 || repaired.Removed[0] != "retired:verb" {
		t.Errorf("Removed = %v, want [retired:verb]", repaired.Removed)
	}
	if len(admin.Permissions) == 0 || admin.Permissions[0] == "retired:verb" {
		t.Errorf("stored admin permissions were not replaced: %v", admin.Permissions)
	}

	if len(custom.Permissions) != 1 || custom.Permissions[0] != "retired:verb" {
		t.Errorf("the custom role was rewritten: %v", custom.Permissions)
	}
	for _, r := range report.Roles {
		if r.Name == "acme-issuer" {
			t.Error("the custom role appears in the reconciliation report")
		}
	}
}

// TestMemoryRoleClientReconcileEmptyRequest covers the degenerate inputs. None
// of this client's operations can fail, so the "bad input" surface is the
// request itself: a nil or empty request names no tenant and must resolve to
// the system tenant rather than seeding roles into an unnamed one.
func TestMemoryRoleClientReconcileEmptyRequest(t *testing.T) {
	ctx := context.Background()

	for _, tc := range []struct {
		name string
		req  *db.ReconcileRolesRequest
	}{
		{"nil request", nil},
		{"empty tenant", &db.ReconcileRolesRequest{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newMemoryRoleClient()
			report, err := c.ReconcileBuiltInRoles(ctx, tc.req)
			if err != nil {
				t.Fatalf("ReconcileBuiltInRoles: %v", err)
			}
			if report.TenantID != qrdbsdk.SystemTenantID {
				t.Errorf("TenantID = %q, want %q", report.TenantID, qrdbsdk.SystemTenantID)
			}
			if len(report.Roles) == 0 {
				t.Fatal("nothing was seeded")
			}
			for _, r := range storedRoleNames(c, "") {
				t.Errorf("role %q was seeded into an unnamed tenant", r)
			}
			if names := storedRoleNames(c, qrdbsdk.SystemTenantID); len(names) != len(report.Roles) {
				t.Errorf("stored %d roles in the system tenant, reported %d", len(names), len(report.Roles))
			}
		})
	}
}
