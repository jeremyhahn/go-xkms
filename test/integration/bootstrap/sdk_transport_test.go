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

//go:build integration

package bootstrap

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// uniqueID produces a test-unique identifier to avoid collisions between
// parallel test runs.
func uniqueID(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
}

// ---------------------------------------------------------------------------
// TenantService — CRUD lifecycle
// ---------------------------------------------------------------------------

func TestSDK_Tenant_CreateGetListDelete(t *testing.T) {
	tr := newSDKTransport(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tenantID := uniqueID("tenant")
	tenantName := "Integration Test Tenant"

	// --- Create ---
	createResp, err := tr.CreateTenant(ctx, &transport.CreateTenantRequest{
		ID:   tenantID,
		Name: tenantName,
	})
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	if createResp.Tenant.ID != tenantID {
		t.Errorf("expected tenant ID %q, got %q", tenantID, createResp.Tenant.ID)
	}
	if createResp.Tenant.Name != tenantName {
		t.Errorf("expected tenant name %q, got %q", tenantName, createResp.Tenant.Name)
	}
	t.Logf("Created tenant: %s (%s)", createResp.Tenant.ID, createResp.Tenant.Name)

	// --- Get ---
	getResp, err := tr.GetTenant(ctx, tenantID)
	if err != nil {
		t.Fatalf("GetTenant: %v", err)
	}
	if getResp.Tenant.ID != tenantID {
		t.Errorf("GetTenant: expected ID %q, got %q", tenantID, getResp.Tenant.ID)
	}
	t.Logf("Got tenant: %s", getResp.Tenant.ID)

	// --- List ---
	listResp, err := tr.ListTenants(ctx)
	if err != nil {
		t.Fatalf("ListTenants: %v", err)
	}
	found := false
	for _, ten := range listResp.Tenants {
		if ten.ID == tenantID {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("ListTenants: tenant %q not found in %d tenants", tenantID, len(listResp.Tenants))
	}
	t.Logf("Listed %d tenants, found test tenant: %v", len(listResp.Tenants), found)

	// --- Delete ---
	if err := tr.DeleteTenant(ctx, tenantID); err != nil {
		t.Fatalf("DeleteTenant: %v", err)
	}
	t.Logf("Deleted tenant: %s", tenantID)

	// --- Verify deletion ---
	_, err = tr.GetTenant(ctx, tenantID)
	if err == nil {
		t.Error("expected error when getting deleted tenant, but got nil")
	}
	t.Logf("Verified tenant deletion — get returned error: %v", err)
}

func TestSDK_Tenant_CreateDuplicate(t *testing.T) {
	tr := newSDKTransport(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	tenantID := uniqueID("dup-tenant")

	_, err := tr.CreateTenant(ctx, &transport.CreateTenantRequest{
		ID:   tenantID,
		Name: "First",
	})
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	defer tr.DeleteTenant(ctx, tenantID)

	_, err = tr.CreateTenant(ctx, &transport.CreateTenantRequest{
		ID:   tenantID,
		Name: "Duplicate",
	})
	if err == nil {
		t.Error("expected error for duplicate tenant, got nil")
	}
	t.Logf("Correctly returned error for duplicate tenant: %v", err)
}

func TestSDK_Tenant_GetNonExistent(t *testing.T) {
	tr := newSDKTransport(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := tr.GetTenant(ctx, "nonexistent-tenant-id")
	if err == nil {
		t.Error("expected error for non-existent tenant, got nil")
	}
	t.Logf("Correctly returned error for non-existent tenant: %v", err)
}

func TestSDK_Tenant_DeleteNonExistent(t *testing.T) {
	tr := newSDKTransport(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := tr.DeleteTenant(ctx, "nonexistent-tenant-id")
	if err == nil {
		t.Error("expected error for deleting non-existent tenant, got nil")
	}
	t.Logf("Correctly returned error for deleting non-existent tenant: %v", err)
}
