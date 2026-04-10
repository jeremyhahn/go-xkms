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
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport/rest"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// newSDKTransport creates a connected REST transport pointing at the
// integration-test xkms-server.  The caller is responsible for closing it.
func newSDKTransport(t *testing.T) *rest.Transport {
	t.Helper()

	serverURL := requiredEnv(t, EnvServerURL)
	caFile := requiredEnv(t, EnvTLSCA)

	tr, err := rest.New(
		transport.WithAddress(serverURL),
		transport.WithTLS(caFile),
	)
	if err != nil {
		t.Fatalf("create REST transport: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := tr.Connect(ctx); err != nil {
		t.Fatalf("connect to server: %v", err)
	}

	t.Cleanup(func() { tr.Close() })
	return tr
}

// uniqueID produces a test-unique identifier to avoid collisions between
// parallel test runs.
func uniqueID(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
}

// ---------------------------------------------------------------------------
// CustodianGroupService — full lifecycle
// ---------------------------------------------------------------------------

func TestSDK_CustodianGroup_CreateGetListDelete(t *testing.T) {
	tr := newSDKTransport(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	groupID := uniqueID("grp")
	groupName := "Integration Test Group"

	// --- Create ---
	createResp, err := tr.CreateCustodianGroup(ctx, &transport.CreateCustodianGroupRequest{
		ID:        groupID,
		Name:      groupName,
		Purpose:   "integration-test",
		Threshold: 2,
		Total:     3,
	})
	if err != nil {
		t.Fatalf("CreateCustodianGroup: %v", err)
	}
	if createResp.Group.ID != groupID {
		t.Errorf("expected group ID %q, got %q", groupID, createResp.Group.ID)
	}
	if createResp.Group.Name != groupName {
		t.Errorf("expected group name %q, got %q", groupName, createResp.Group.Name)
	}
	if createResp.Group.Threshold != 2 {
		t.Errorf("expected threshold 2, got %d", createResp.Group.Threshold)
	}
	if createResp.Group.Total != 3 {
		t.Errorf("expected total 3, got %d", createResp.Group.Total)
	}
	t.Logf("Created group: %s (%s)", createResp.Group.ID, createResp.Group.Name)

	// --- Get ---
	getResp, err := tr.GetCustodianGroup(ctx, groupID)
	if err != nil {
		t.Fatalf("GetCustodianGroup: %v", err)
	}
	if getResp.Group.ID != groupID {
		t.Errorf("GetCustodianGroup: expected ID %q, got %q", groupID, getResp.Group.ID)
	}
	if getResp.Group.Purpose != "integration-test" {
		t.Errorf("expected purpose %q, got %q", "integration-test", getResp.Group.Purpose)
	}
	t.Logf("Got group: %s", getResp.Group.ID)

	// --- List ---
	listResp, err := tr.ListCustodianGroups(ctx)
	if err != nil {
		t.Fatalf("ListCustodianGroups: %v", err)
	}
	found := false
	for _, g := range listResp.Groups {
		if g.ID == groupID {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("ListCustodianGroups: group %q not found in %d groups", groupID, len(listResp.Groups))
	}
	t.Logf("Listed %d groups, found test group: %v", len(listResp.Groups), found)

	// --- Delete ---
	if err := tr.DeleteCustodianGroup(ctx, groupID); err != nil {
		t.Fatalf("DeleteCustodianGroup: %v", err)
	}
	t.Logf("Deleted group: %s", groupID)

	// --- Verify deletion ---
	_, err = tr.GetCustodianGroup(ctx, groupID)
	if err == nil {
		t.Error("expected error when getting deleted group, but got nil")
	}
	t.Logf("Verified group deletion — get returned error: %v", err)
}

func TestSDK_CustodianGroup_GetNonExistent(t *testing.T) {
	tr := newSDKTransport(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := tr.GetCustodianGroup(ctx, "nonexistent-group-id")
	if err == nil {
		t.Error("expected error for non-existent group, got nil")
	}
	t.Logf("Correctly returned error for non-existent group: %v", err)
}

func TestSDK_CustodianGroup_DeleteNonExistent(t *testing.T) {
	tr := newSDKTransport(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := tr.DeleteCustodianGroup(ctx, "nonexistent-group-id")
	if err == nil {
		t.Error("expected error for deleting non-existent group, got nil")
	}
	t.Logf("Correctly returned error for deleting non-existent group: %v", err)
}

// ---------------------------------------------------------------------------
// CustodianGroupService — member management
// ---------------------------------------------------------------------------

func TestSDK_CustodianGroup_MemberLifecycle(t *testing.T) {
	tr := newSDKTransport(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	groupID := uniqueID("member-grp")

	// Create group
	_, err := tr.CreateCustodianGroup(ctx, &transport.CreateCustodianGroupRequest{
		ID:        groupID,
		Name:      "Member Test Group",
		Purpose:   "member-test",
		Threshold: 2,
		Total:     3,
	})
	if err != nil {
		t.Fatalf("CreateCustodianGroup: %v", err)
	}
	defer tr.DeleteCustodianGroup(ctx, groupID)

	// --- Add first member ---
	addResp, err := tr.AddCustodianMember(ctx, &transport.AddCustodianMemberRequest{
		GroupID:  groupID,
		UserID:   "user-alice",
		Username: "alice",
		Method:   "manual",
	})
	if err != nil {
		t.Fatalf("AddCustodianMember (alice): %v", err)
	}
	if addResp.Member.UserID != "user-alice" {
		t.Errorf("expected member user_id %q, got %q", "user-alice", addResp.Member.UserID)
	}
	if addResp.Member.Username != "alice" {
		t.Errorf("expected member username %q, got %q", "alice", addResp.Member.Username)
	}
	t.Logf("Added member: %s (%s)", addResp.Member.UserID, addResp.Member.Username)

	// --- Add second member ---
	addResp2, err := tr.AddCustodianMember(ctx, &transport.AddCustodianMemberRequest{
		GroupID:  groupID,
		UserID:   "user-bob",
		Username: "bob",
		Method:   "manual",
	})
	if err != nil {
		t.Fatalf("AddCustodianMember (bob): %v", err)
	}
	if addResp2.Member.UserID != "user-bob" {
		t.Errorf("expected member user_id %q, got %q", "user-bob", addResp2.Member.UserID)
	}
	t.Logf("Added member: %s (%s)", addResp2.Member.UserID, addResp2.Member.Username)

	// --- Verify members via GetGroup ---
	getResp, err := tr.GetCustodianGroup(ctx, groupID)
	if err != nil {
		t.Fatalf("GetCustodianGroup: %v", err)
	}
	if len(getResp.Group.Members) != 2 {
		t.Errorf("expected 2 members, got %d", len(getResp.Group.Members))
	}
	t.Logf("Group has %d members", len(getResp.Group.Members))

	// --- Remove first member ---
	if err := tr.RemoveCustodianMember(ctx, &transport.RemoveCustodianMemberRequest{
		GroupID: groupID,
		UserID:  "user-alice",
	}); err != nil {
		t.Fatalf("RemoveCustodianMember (alice): %v", err)
	}
	t.Logf("Removed member: user-alice")

	// --- Verify member count after removal ---
	getResp2, err := tr.GetCustodianGroup(ctx, groupID)
	if err != nil {
		t.Fatalf("GetCustodianGroup after removal: %v", err)
	}
	if len(getResp2.Group.Members) != 1 {
		t.Errorf("expected 1 member after removal, got %d", len(getResp2.Group.Members))
	}
	if getResp2.Group.Members[0].UserID != "user-bob" {
		t.Errorf("expected remaining member %q, got %q", "user-bob", getResp2.Group.Members[0].UserID)
	}
	t.Logf("Verified member removal — 1 member remaining: %s", getResp2.Group.Members[0].UserID)
}

// ---------------------------------------------------------------------------
// CustodianGroupService — DistributeShares
// ---------------------------------------------------------------------------

func TestSDK_CustodianGroup_DistributeShares(t *testing.T) {
	tr := newSDKTransport(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	groupID := uniqueID("dist-grp")

	// Create group and add members
	_, err := tr.CreateCustodianGroup(ctx, &transport.CreateCustodianGroupRequest{
		ID:        groupID,
		Name:      "Distribution Test Group",
		Purpose:   "dist-test",
		Threshold: 2,
		Total:     3,
	})
	if err != nil {
		t.Fatalf("CreateCustodianGroup: %v", err)
	}
	defer tr.DeleteCustodianGroup(ctx, groupID)

	for _, user := range []struct{ id, name string }{
		{"user-1", "custodian-1"},
		{"user-2", "custodian-2"},
		{"user-3", "custodian-3"},
	} {
		_, err := tr.AddCustodianMember(ctx, &transport.AddCustodianMemberRequest{
			GroupID:  groupID,
			UserID:   user.id,
			Username: user.name,
			Method:   "manual",
		})
		if err != nil {
			t.Fatalf("AddCustodianMember (%s): %v", user.name, err)
		}
	}

	// --- Distribute ---
	distResp, err := tr.DistributeShares(ctx, &transport.DistributeSharesRequest{
		GroupID: groupID,
	})
	if err != nil {
		t.Fatalf("DistributeShares: %v", err)
	}
	if distResp.Distributed != 3 {
		t.Errorf("expected 3 distributed, got %d", distResp.Distributed)
	}
	t.Logf("Distributed shares to %d members", distResp.Distributed)
}

func TestSDK_CustodianGroup_DistributeShares_EmptyGroup(t *testing.T) {
	tr := newSDKTransport(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	groupID := uniqueID("empty-grp")

	_, err := tr.CreateCustodianGroup(ctx, &transport.CreateCustodianGroupRequest{
		ID:        groupID,
		Name:      "Empty Group",
		Purpose:   "empty-test",
		Threshold: 2,
		Total:     3,
	})
	if err != nil {
		t.Fatalf("CreateCustodianGroup: %v", err)
	}
	defer tr.DeleteCustodianGroup(ctx, groupID)

	// Distribute on empty group should fail
	_, err = tr.DistributeShares(ctx, &transport.DistributeSharesRequest{
		GroupID: groupID,
	})
	if err == nil {
		t.Error("expected error when distributing to empty group, got nil")
	}
	t.Logf("Correctly returned error for empty group distribution: %v", err)
}

func TestSDK_CustodianGroup_DistributeShares_NonExistent(t *testing.T) {
	tr := newSDKTransport(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := tr.DistributeShares(ctx, &transport.DistributeSharesRequest{
		GroupID: "nonexistent-group",
	})
	if err == nil {
		t.Error("expected error for non-existent group, got nil")
	}
	t.Logf("Correctly returned error for non-existent group: %v", err)
}

// ---------------------------------------------------------------------------
// ShareService — submit, list, collection status
// ---------------------------------------------------------------------------

func TestSDK_Share_SubmitAndList(t *testing.T) {
	tr := newSDKTransport(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	serverURL := requiredEnv(t, EnvServerURL)
	groupID := uniqueID("share-grp")

	// --- Submit share ---
	submitResp, err := tr.SubmitShare(ctx, &transport.SubmitShareRequest{
		ServerURL:  serverURL,
		GroupID:    groupID,
		GroupName:  "Share Test Group",
		ShareIndex: 1,
		ShareData:  []byte("test-share-data-1"),
		Purpose:    "integration-test",
	})
	if err != nil {
		t.Fatalf("SubmitShare: %v", err)
	}
	// The server returns a share status response (without the sensitive data).
	// SubmitShareResponse maps to the accepted field; check we got a valid response.
	t.Logf("SubmitShare response: %+v", submitResp)

	// --- Submit second share for same group ---
	_, err = tr.SubmitShare(ctx, &transport.SubmitShareRequest{
		ServerURL:  serverURL,
		GroupID:    groupID,
		GroupName:  "Share Test Group",
		ShareIndex: 2,
		ShareData:  []byte("test-share-data-2"),
		Purpose:    "integration-test",
	})
	if err != nil {
		t.Fatalf("SubmitShare (2): %v", err)
	}

	// --- List shares ---
	listResp, err := tr.ListShares(ctx)
	if err != nil {
		t.Fatalf("ListShares: %v", err)
	}
	found := 0
	for _, s := range listResp.Shares {
		if s.GroupID == groupID {
			found++
		}
	}
	if found < 2 {
		t.Errorf("expected at least 2 shares for group %q, found %d in %d total shares",
			groupID, found, len(listResp.Shares))
	}
	t.Logf("Listed %d total shares, %d for group %s", len(listResp.Shares), found, groupID)
}

func TestSDK_Share_SubmitValidation(t *testing.T) {
	tr := newSDKTransport(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Missing server_url
	_, err := tr.SubmitShare(ctx, &transport.SubmitShareRequest{
		GroupID:   "grp-1",
		ShareData: []byte("data"),
	})
	if err == nil {
		t.Error("expected error for missing server_url, got nil")
	}
	t.Logf("Correctly rejected missing server_url: %v", err)

	// Missing group_id
	_, err = tr.SubmitShare(ctx, &transport.SubmitShareRequest{
		ServerURL: "https://example.com",
		ShareData: []byte("data"),
	})
	if err == nil {
		t.Error("expected error for missing group_id, got nil")
	}
	t.Logf("Correctly rejected missing group_id: %v", err)

	// Missing share_data
	_, err = tr.SubmitShare(ctx, &transport.SubmitShareRequest{
		ServerURL: "https://example.com",
		GroupID:   "grp-1",
	})
	if err == nil {
		t.Error("expected error for missing share_data, got nil")
	}
	t.Logf("Correctly rejected missing share_data: %v", err)
}

func TestSDK_Share_CollectionStatus(t *testing.T) {
	tr := newSDKTransport(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	serverURL := requiredEnv(t, EnvServerURL)
	groupID := uniqueID("status-grp")

	// Submit 3 shares from different "servers" for the same group
	for i := 1; i <= 3; i++ {
		_, err := tr.SubmitShare(ctx, &transport.SubmitShareRequest{
			ServerURL:  fmt.Sprintf("%s/instance-%d", serverURL, i),
			GroupID:    groupID,
			GroupName:  "Status Test Group",
			ShareIndex: i,
			ShareData:  []byte(fmt.Sprintf("share-data-%d", i)),
			Purpose:    "collection-status-test",
		})
		if err != nil {
			t.Fatalf("SubmitShare (%d): %v", i, err)
		}
	}

	// --- Check collection status ---
	status, err := tr.GetShareCollectionStatus(ctx, groupID)
	if err != nil {
		t.Fatalf("GetShareCollectionStatus: %v", err)
	}
	if status.GroupID != groupID {
		t.Errorf("expected group_id %q, got %q", groupID, status.GroupID)
	}
	if status.Collected != 3 {
		t.Errorf("expected 3 collected shares, got %d", status.Collected)
	}
	t.Logf("Share collection status: group=%s, collected=%d", status.GroupID, status.Collected)
}

func TestSDK_Share_CollectionStatus_Empty(t *testing.T) {
	tr := newSDKTransport(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Query status for a group with no shares — should return 0
	status, err := tr.GetShareCollectionStatus(ctx, "no-shares-group")
	if err != nil {
		t.Fatalf("GetShareCollectionStatus: %v", err)
	}
	if status.Collected != 0 {
		t.Errorf("expected 0 collected for empty group, got %d", status.Collected)
	}
	t.Logf("Empty group collection status: collected=%d", status.Collected)
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

// ---------------------------------------------------------------------------
// TenantService — barrier operations
// ---------------------------------------------------------------------------

func TestSDK_Tenant_BarrierInit(t *testing.T) {
	tr := newSDKTransport(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tenantID := uniqueID("barrier-tenant")

	_, err := tr.CreateTenant(ctx, &transport.CreateTenantRequest{
		ID:   tenantID,
		Name: "Barrier Init Tenant",
	})
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	defer tr.DeleteTenant(ctx, tenantID)

	// --- Init barrier ---
	err = tr.TenantBarrierInit(ctx, &transport.TenantBarrierInitRequest{
		TenantID:  tenantID,
		Threshold: 2,
		Shares:    3,
	})
	if err != nil {
		t.Fatalf("TenantBarrierInit: %v", err)
	}
	t.Logf("Initialized barrier for tenant: %s", tenantID)
}

func TestSDK_Tenant_BarrierInit_NonExistent(t *testing.T) {
	tr := newSDKTransport(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := tr.TenantBarrierInit(ctx, &transport.TenantBarrierInitRequest{
		TenantID:  "nonexistent-tenant",
		Threshold: 2,
		Shares:    3,
	})
	if err == nil {
		t.Error("expected error for non-existent tenant barrier init, got nil")
	}
	t.Logf("Correctly returned error for non-existent tenant: %v", err)
}

func TestSDK_Tenant_BarrierUnseal(t *testing.T) {
	tr := newSDKTransport(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tenantID := uniqueID("unseal-tenant")

	_, err := tr.CreateTenant(ctx, &transport.CreateTenantRequest{
		ID:   tenantID,
		Name: "Barrier Unseal Tenant",
	})
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	defer tr.DeleteTenant(ctx, tenantID)

	// --- Unseal without init should fail ---
	err = tr.TenantBarrierUnseal(ctx, &transport.TenantBarrierUnsealRequest{
		TenantID: tenantID,
		Key:      []byte("test-unseal-key"),
	})
	if err == nil {
		t.Fatal("expected error for unseal without init, got nil")
	}
	t.Logf("Correctly returned error for unseal without init: %v", err)

	// --- Initialize barrier ---
	err = tr.TenantBarrierInit(ctx, &transport.TenantBarrierInitRequest{
		TenantID: tenantID,
	})
	if err != nil {
		t.Fatalf("TenantBarrierInit: %v", err)
	}
	t.Logf("Initialized barrier for tenant: %s", tenantID)

	// --- Unseal after init returns already-unsealed (barrier is unsealed after init) ---
	err = tr.TenantBarrierUnseal(ctx, &transport.TenantBarrierUnsealRequest{
		TenantID: tenantID,
		Key:      []byte("test-unseal-key"),
	})
	if err == nil {
		t.Fatal("expected already-unsealed error after init, got nil")
	}
	if !strings.Contains(err.Error(), "already unsealed") {
		t.Fatalf("expected 'already unsealed' error, got: %v", err)
	}
	t.Logf("Correctly returned already-unsealed error: %v", err)
}

func TestSDK_Tenant_BarrierUnseal_NonExistent(t *testing.T) {
	tr := newSDKTransport(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := tr.TenantBarrierUnseal(ctx, &transport.TenantBarrierUnsealRequest{
		TenantID: "nonexistent-tenant",
		Key:      []byte("test-key"),
	})
	if err == nil {
		t.Error("expected error for non-existent tenant barrier unseal, got nil")
	}
	t.Logf("Correctly returned error for non-existent tenant: %v", err)
}

// ---------------------------------------------------------------------------
// Full end-to-end bootstrap flow
// ---------------------------------------------------------------------------

func TestSDK_FullBootstrapFlow(t *testing.T) {
	tr := newSDKTransport(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	serverURL := requiredEnv(t, EnvServerURL)
	groupID := uniqueID("e2e-grp")
	tenantID := uniqueID("e2e-tenant")

	// 1. Create custodian group
	createGrpResp, err := tr.CreateCustodianGroup(ctx, &transport.CreateCustodianGroupRequest{
		ID:        groupID,
		Name:      "E2E Bootstrap Group",
		Purpose:   "e2e-test",
		Threshold: 2,
		Total:     3,
	})
	if err != nil {
		t.Fatalf("Step 1 - CreateCustodianGroup: %v", err)
	}
	t.Logf("Step 1: Created group %s", createGrpResp.Group.ID)

	// 2. Add 3 custodian members
	members := []struct{ id, name string }{
		{"e2e-user-1", "custodian-alpha"},
		{"e2e-user-2", "custodian-beta"},
		{"e2e-user-3", "custodian-gamma"},
	}
	for _, m := range members {
		_, err := tr.AddCustodianMember(ctx, &transport.AddCustodianMemberRequest{
			GroupID:  groupID,
			UserID:   m.id,
			Username: m.name,
			Method:   "manual",
		})
		if err != nil {
			t.Fatalf("Step 2 - AddCustodianMember (%s): %v", m.name, err)
		}
	}
	t.Logf("Step 2: Added %d members", len(members))

	// 3. Verify group has 3 members
	grp, err := tr.GetCustodianGroup(ctx, groupID)
	if err != nil {
		t.Fatalf("Step 3 - GetCustodianGroup: %v", err)
	}
	if len(grp.Group.Members) != 3 {
		t.Fatalf("Step 3: expected 3 members, got %d", len(grp.Group.Members))
	}
	t.Logf("Step 3: Verified %d members in group", len(grp.Group.Members))

	// 4. Distribute shares
	distResp, err := tr.DistributeShares(ctx, &transport.DistributeSharesRequest{GroupID: groupID})
	if err != nil {
		t.Fatalf("Step 4 - DistributeShares: %v", err)
	}
	if distResp.Distributed != 3 {
		t.Errorf("Step 4: expected 3 distributed, got %d", distResp.Distributed)
	}
	t.Logf("Step 4: Distributed to %d members", distResp.Distributed)

	// 5. Create tenant
	tenantResp, err := tr.CreateTenant(ctx, &transport.CreateTenantRequest{
		ID:   tenantID,
		Name: "E2E Test Tenant",
	})
	if err != nil {
		t.Fatalf("Step 5 - CreateTenant: %v", err)
	}
	t.Logf("Step 5: Created tenant %s", tenantResp.Tenant.ID)

	// 6. Each custodian submits their share
	for i := 1; i <= 3; i++ {
		_, err := tr.SubmitShare(ctx, &transport.SubmitShareRequest{
			ServerURL:  serverURL,
			GroupID:    groupID,
			GroupName:  "E2E Bootstrap Group",
			ShareIndex: i,
			ShareData:  []byte(fmt.Sprintf("e2e-share-data-%d", i)),
			Purpose:    "e2e-test",
			TenantID:   tenantID,
		})
		if err != nil {
			t.Fatalf("Step 6 - SubmitShare (%d): %v", i, err)
		}
	}
	t.Logf("Step 6: Submitted 3 shares")

	// 7. Verify share collection status
	status, err := tr.GetShareCollectionStatus(ctx, groupID)
	if err != nil {
		t.Fatalf("Step 7 - GetShareCollectionStatus: %v", err)
	}
	if status.Collected != 3 {
		t.Errorf("Step 7: expected 3 collected, got %d", status.Collected)
	}
	t.Logf("Step 7: Collection status — collected=%d", status.Collected)

	// 8. List shares and verify
	shareList, err := tr.ListShares(ctx)
	if err != nil {
		t.Fatalf("Step 8 - ListShares: %v", err)
	}
	groupShares := 0
	for _, s := range shareList.Shares {
		if s.GroupID == groupID {
			groupShares++
		}
	}
	if groupShares < 3 {
		t.Errorf("Step 8: expected at least 3 shares for group, found %d", groupShares)
	}
	t.Logf("Step 8: Found %d shares for group in %d total", groupShares, len(shareList.Shares))

	// 9. List tenants and verify
	tenantList, err := tr.ListTenants(ctx)
	if err != nil {
		t.Fatalf("Step 9 - ListTenants: %v", err)
	}
	foundTenant := false
	for _, ten := range tenantList.Tenants {
		if ten.ID == tenantID {
			foundTenant = true
			break
		}
	}
	if !foundTenant {
		t.Errorf("Step 9: tenant %q not found in list", tenantID)
	}
	t.Logf("Step 9: Found tenant in list of %d tenants", len(tenantList.Tenants))

	// 10. Cleanup
	if err := tr.DeleteTenant(ctx, tenantID); err != nil {
		t.Errorf("Cleanup - DeleteTenant: %v", err)
	}
	if err := tr.DeleteCustodianGroup(ctx, groupID); err != nil {
		t.Errorf("Cleanup - DeleteCustodianGroup: %v", err)
	}
	t.Log("Step 10: Cleanup complete")
}
