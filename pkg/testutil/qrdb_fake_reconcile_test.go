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

package testutil

import (
	"context"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
)

func TestQRDBFakeReconcileBuiltInRolesSeedsAndIsIdempotent(t *testing.T) {
	const tenantID = "tenant-a"
	ctx := context.Background()
	f := NewQRDBFakeTransport()

	report, err := f.ReconcileBuiltInRoles(ctx, &qrdbtransport.ReconcileRolesRequest{TenantID: tenantID})
	if err != nil {
		t.Fatalf("ReconcileBuiltInRoles: %v", err)
	}
	want := qrdbsdk.BuiltInRoles(tenantID)
	if len(report.Roles) != len(want) {
		t.Fatalf("reported %d roles, want %d", len(report.Roles), len(want))
	}
	for i, got := range report.Roles {
		if !got.Created {
			t.Errorf("role %q: Created = false, want true", got.Name)
		}
		if got.RoleID != want[i].ID {
			t.Errorf("role %q: RoleID = %q, want the deterministic %q", got.Name, got.RoleID, want[i].ID)
		}
		stored, err := f.GetRole(ctx, got.RoleID)
		if err != nil {
			t.Fatalf("GetRole(%q): %v", got.RoleID, err)
		}
		if stored.TenantID != tenantID {
			t.Errorf("role %q landed in tenant %q, want %q", got.Name, stored.TenantID, tenantID)
		}
	}

	second, err := f.ReconcileBuiltInRoles(ctx, &qrdbtransport.ReconcileRolesRequest{TenantID: tenantID})
	if err != nil {
		t.Fatalf("second ReconcileBuiltInRoles: %v", err)
	}
	if len(second.Roles) != 0 {
		t.Errorf("second call reported %d roles, want 0", len(second.Roles))
	}
}

func TestQRDBFakeReconcileBuiltInRolesRepairsDrift(t *testing.T) {
	const tenantID = "tenant-b"
	ctx := context.Background()
	f := NewQRDBFakeTransport()

	admin, err := f.CreateRole(ctx, &qrdbtransport.CreateRoleRequest{
		Name:        qrdbsdk.RoleNameAdmin,
		TenantID:    tenantID,
		Permissions: []string{"retired:verb"},
	})
	if err != nil {
		t.Fatalf("CreateRole: %v", err)
	}

	report, err := f.ReconcileBuiltInRoles(ctx, &qrdbtransport.ReconcileRolesRequest{TenantID: tenantID})
	if err != nil {
		t.Fatalf("ReconcileBuiltInRoles: %v", err)
	}
	var repaired *qrdbtransport.RoleReconcileResult
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
}

// TestQRDBFakeReconcileBuiltInRolesIgnoresOtherTenants pins the guard that
// matters for this fake specifically: its ListRoles returns every role
// regardless of the requested tenant, so reconciliation must do the tenant
// filtering itself rather than converge one tenant onto another's records.
func TestQRDBFakeReconcileBuiltInRolesIgnoresOtherTenants(t *testing.T) {
	ctx := context.Background()
	f := NewQRDBFakeTransport()

	foreign, err := f.CreateRole(ctx, &qrdbtransport.CreateRoleRequest{
		Name:        qrdbsdk.RoleNameAdmin,
		TenantID:    "someone-else",
		Permissions: []string{"retired:verb"},
	})
	if err != nil {
		t.Fatalf("CreateRole: %v", err)
	}

	report, err := f.ReconcileBuiltInRoles(ctx, &qrdbtransport.ReconcileRolesRequest{TenantID: "tenant-c"})
	if err != nil {
		t.Fatalf("ReconcileBuiltInRoles: %v", err)
	}
	if len(foreign.Permissions) != 1 || foreign.Permissions[0] != "retired:verb" {
		t.Errorf("the other tenant's admin was rewritten: %v", foreign.Permissions)
	}
	var seeded bool
	for _, r := range report.Roles {
		if r.Name == qrdbsdk.RoleNameAdmin && r.Created {
			seeded = true
		}
	}
	if !seeded {
		t.Error("admin was not seeded into the requested tenant")
	}
}

// TestQRDBFakeReconcileBuiltInRolesEmptyRequest covers the degenerate input:
// no operation of this fake can fail, so the bad-input surface is the request,
// which must resolve to the system tenant rather than an unnamed one.
func TestQRDBFakeReconcileBuiltInRolesEmptyRequest(t *testing.T) {
	ctx := context.Background()

	for _, tc := range []struct {
		name string
		req  *qrdbtransport.ReconcileRolesRequest
	}{
		{"nil request", nil},
		{"empty tenant", &qrdbtransport.ReconcileRolesRequest{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := NewQRDBFakeTransport()
			report, err := f.ReconcileBuiltInRoles(ctx, tc.req)
			if err != nil {
				t.Fatalf("ReconcileBuiltInRoles: %v", err)
			}
			if report.TenantID != qrdbsdk.SystemTenantID {
				t.Errorf("TenantID = %q, want %q", report.TenantID, qrdbsdk.SystemTenantID)
			}
			if len(report.Roles) == 0 {
				t.Fatal("nothing was seeded")
			}
			for _, r := range report.Roles {
				stored, err := f.GetRole(ctx, r.RoleID)
				if err != nil {
					t.Fatalf("GetRole(%q): %v", r.RoleID, err)
				}
				if stored.TenantID != qrdbsdk.SystemTenantID {
					t.Errorf("role %q landed in tenant %q, want the system tenant", r.Name, stored.TenantID)
				}
			}
		})
	}
}
