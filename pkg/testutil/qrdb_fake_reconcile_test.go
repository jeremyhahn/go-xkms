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
	"errors"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
)

// TestQRDBFakeRefusesRoleReconcile proves the fake reports built-in role
// reconciliation as unsupported -- go-qrdb owns that rule -- and leaves the
// stored roles exactly as they were instead of converging them itself.
func TestQRDBFakeRefusesRoleReconcile(t *testing.T) {
	ctx := context.Background()
	ft := NewQRDBFakeTransport()
	drifted, err := ft.CreateRole(ctx, &qrdbtransport.CreateRoleRequest{
		Name:        qrdbsdk.RoleNameAdmin,
		TenantID:    "tenant-a",
		Permissions: []string{"custom:drifted"},
	})
	if err != nil {
		t.Fatalf("CreateRole: %v", err)
	}

	report, err := ft.ReconcileBuiltInRoles(ctx, &qrdbtransport.ReconcileRolesRequest{TenantID: "tenant-a"})
	var unsupported *qrdbtransport.CapabilityUnsupportedError
	if !errors.As(err, &unsupported) {
		t.Fatalf("ReconcileBuiltInRoles error = %v, want CapabilityUnsupportedError", err)
	}
	if report != nil {
		t.Fatalf("ReconcileBuiltInRoles report = %+v, want nil", report)
	}

	roles, err := ft.ListRoles(ctx, &qrdbtransport.ListRolesRequest{})
	if err != nil {
		t.Fatalf("ListRoles: %v", err)
	}
	if roles.Total != 1 {
		t.Fatalf("fake holds %d roles after reconcile, want 1", roles.Total)
	}
	stored, err := ft.GetRole(ctx, drifted.ID)
	if err != nil {
		t.Fatalf("GetRole: %v", err)
	}
	if len(stored.Permissions) != 1 || stored.Permissions[0] != "custom:drifted" {
		t.Fatalf("role permissions = %v, want [custom:drifted] untouched", stored.Permissions)
	}
}

// TestQRDBFakeRefusesRoleReconcileNilRequest covers the degenerate input: a
// nil request gets the same typed refusal, not a panic.
func TestQRDBFakeRefusesRoleReconcileNilRequest(t *testing.T) {
	ft := NewQRDBFakeTransport()
	_, err := ft.ReconcileBuiltInRoles(context.Background(), nil)
	var unsupported *qrdbtransport.CapabilityUnsupportedError
	if !errors.As(err, &unsupported) {
		t.Fatalf("ReconcileBuiltInRoles(nil) error = %v, want CapabilityUnsupportedError", err)
	}
}
