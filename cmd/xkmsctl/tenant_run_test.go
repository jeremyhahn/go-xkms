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

// tenant_run_test.go exercises the "xkmsctl tenant" command tree's Run
// closures (create, list, show, delete, barrier-init, barrier-unseal,
// barrier-status, update-entitlements, update-quotas), plus the previously
// 0%-covered tenantUpdateEntitlements / tenantUpdateQuotas named functions.
// mockTenantClient (defined in tenant_test.go) provides the client.Client
// surface.
package main

import (
	"bytes"
	"errors"
	"testing"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

var errTenantRunBoom = errors.New("boom")

func newTenantRunConfig(mock *mockTenantClient) *Config {
	return &Config{
		OutputFormat: "text",
		ClientFactory: func(*Config) (client.Client, error) {
			return mock, nil
		},
	}
}

func resetTenantCreateFlags(t *testing.T) {
	t.Helper()
	_ = tenantCreateCmd.Flags().Set("id", "")
	_ = tenantCreateCmd.Flags().Set("name", "")
	_ = tenantCreateCmd.Flags().Set("isolation", "")
	_ = tenantCreateCmd.Flags().Set("barrier-auto-unseal", "false")
}

func TestTenantCreateCmd_MissingID(t *testing.T) {
	resetTenantCreateFlags(t)
	t.Cleanup(func() { resetTenantCreateFlags(t) })
	withGlobalConfig(t, newTenantRunConfig(&mockTenantClient{}))

	code := captureExit(t, func() {
		tenantCreateCmd.Run(tenantCreateCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestTenantCreateCmd_MissingName(t *testing.T) {
	resetTenantCreateFlags(t)
	t.Cleanup(func() { resetTenantCreateFlags(t) })
	withGlobalConfig(t, newTenantRunConfig(&mockTenantClient{}))
	_ = tenantCreateCmd.Flags().Set("id", "acme")

	code := captureExit(t, func() {
		tenantCreateCmd.Run(tenantCreateCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestTenantCreateCmd_Success(t *testing.T) {
	resetTenantCreateFlags(t)
	t.Cleanup(func() { resetTenantCreateFlags(t) })
	mock := &mockTenantClient{createTenantResp: &transport.CreateTenantResponse{
		Tenant: transport.TenantInfo{ID: "acme", Name: "Acme"},
	}}
	withGlobalConfig(t, newTenantRunConfig(mock))
	_ = tenantCreateCmd.Flags().Set("id", "acme")
	_ = tenantCreateCmd.Flags().Set("name", "Acme")
	_ = tenantCreateCmd.Flags().Set("isolation", "volume")
	_ = tenantCreateCmd.Flags().Set("barrier-auto-unseal", "true")

	captureStdout(t, func() {
		tenantCreateCmd.Run(tenantCreateCmd, nil)
	})
	if mock.gotCreateReq == nil || mock.gotCreateReq.ID != "acme" {
		t.Error("expected CreateTenant to be called with id=acme")
	}
}

func TestTenantListCmd_Run(t *testing.T) {
	mock := &mockTenantClient{listTenantsResp: &transport.ListTenantsResponse{
		Tenants: []transport.TenantInfo{{ID: "acme", Name: "Acme"}},
	}}
	withGlobalConfig(t, newTenantRunConfig(mock))

	captureStdout(t, func() {
		tenantListCmd.Run(tenantListCmd, nil)
	})
}

func TestTenantListCmd_Error(t *testing.T) {
	mock := &mockTenantClient{listTenantsErr: errTenantRunBoom}
	withGlobalConfig(t, newTenantRunConfig(mock))

	code := captureExit(t, func() {
		tenantListCmd.Run(tenantListCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestTenantShowCmd_MissingID(t *testing.T) {
	_ = tenantShowCmd.Flags().Set("id", "")
	withGlobalConfig(t, newTenantRunConfig(&mockTenantClient{}))

	code := captureExit(t, func() {
		tenantShowCmd.Run(tenantShowCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestTenantShowCmd_Success(t *testing.T) {
	mock := &mockTenantClient{getTenantResp: &transport.GetTenantResponse{
		Tenant: transport.TenantInfo{ID: "acme", Name: "Acme"},
	}}
	withGlobalConfig(t, newTenantRunConfig(mock))
	_ = tenantShowCmd.Flags().Set("id", "acme")
	t.Cleanup(func() { _ = tenantShowCmd.Flags().Set("id", "") })

	captureStdout(t, func() {
		tenantShowCmd.Run(tenantShowCmd, nil)
	})
}

func TestTenantDeleteCmd_MissingID(t *testing.T) {
	_ = tenantDeleteCmd.Flags().Set("id", "")
	withGlobalConfig(t, newTenantRunConfig(&mockTenantClient{}))

	code := captureExit(t, func() {
		tenantDeleteCmd.Run(tenantDeleteCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestTenantDeleteCmd_Success(t *testing.T) {
	mock := &mockTenantClient{}
	withGlobalConfig(t, newTenantRunConfig(mock))
	_ = tenantDeleteCmd.Flags().Set("id", "acme")
	t.Cleanup(func() { _ = tenantDeleteCmd.Flags().Set("id", "") })

	captureStdout(t, func() {
		tenantDeleteCmd.Run(tenantDeleteCmd, nil)
	})
}

func TestTenantBarrierInitCmd_MissingID(t *testing.T) {
	_ = tenantBarrierInitCmd.Flags().Set("id", "")
	withGlobalConfig(t, newTenantRunConfig(&mockTenantClient{}))

	code := captureExit(t, func() {
		tenantBarrierInitCmd.Run(tenantBarrierInitCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestTenantBarrierInitCmd_Success(t *testing.T) {
	mock := &mockTenantClient{}
	withGlobalConfig(t, newTenantRunConfig(mock))
	_ = tenantBarrierInitCmd.Flags().Set("id", "acme")
	_ = tenantBarrierInitCmd.Flags().Set("passphrase", "s3cret")
	_ = tenantBarrierInitCmd.Flags().Set("strategy", "passphrase")
	_ = tenantBarrierInitCmd.Flags().Set("threshold", "2")
	_ = tenantBarrierInitCmd.Flags().Set("shares", "3")
	t.Cleanup(func() {
		_ = tenantBarrierInitCmd.Flags().Set("id", "")
		_ = tenantBarrierInitCmd.Flags().Set("passphrase", "")
		_ = tenantBarrierInitCmd.Flags().Set("strategy", "")
		_ = tenantBarrierInitCmd.Flags().Set("threshold", "0")
		_ = tenantBarrierInitCmd.Flags().Set("shares", "0")
	})

	captureStdout(t, func() {
		tenantBarrierInitCmd.Run(tenantBarrierInitCmd, nil)
	})
	if mock.gotBarrierInitReq == nil || mock.gotBarrierInitReq.TenantID != "acme" {
		t.Error("expected TenantBarrierInit to be called with tenant acme")
	}
}

func TestTenantBarrierUnsealCmd_MissingID(t *testing.T) {
	_ = tenantBarrierUnsealCmd.Flags().Set("id", "")
	withGlobalConfig(t, newTenantRunConfig(&mockTenantClient{}))

	code := captureExit(t, func() {
		tenantBarrierUnsealCmd.Run(tenantBarrierUnsealCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestTenantBarrierUnsealCmd_Success(t *testing.T) {
	mock := &mockTenantClient{}
	withGlobalConfig(t, newTenantRunConfig(mock))
	_ = tenantBarrierUnsealCmd.Flags().Set("id", "acme")
	_ = tenantBarrierUnsealCmd.Flags().Set("share", "c2hhcmU=")
	t.Cleanup(func() {
		_ = tenantBarrierUnsealCmd.Flags().Set("id", "")
		_ = tenantBarrierUnsealCmd.Flags().Set("share", "")
	})

	captureStdout(t, func() {
		tenantBarrierUnsealCmd.Run(tenantBarrierUnsealCmd, nil)
	})
}

func TestTenantBarrierStatusCmd_MissingID(t *testing.T) {
	_ = tenantBarrierStatusCmd.Flags().Set("id", "")
	withGlobalConfig(t, newTenantRunConfig(&mockTenantClient{}))

	code := captureExit(t, func() {
		tenantBarrierStatusCmd.Run(tenantBarrierStatusCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestTenantBarrierStatusCmd_Success(t *testing.T) {
	mock := &mockTenantClient{tenantBarrierStatusResp: &transport.TenantBarrierStatusResponse{
		TenantID: "acme", Sealed: false, Strategy: "passphrase",
	}}
	withGlobalConfig(t, newTenantRunConfig(mock))
	_ = tenantBarrierStatusCmd.Flags().Set("id", "acme")
	t.Cleanup(func() { _ = tenantBarrierStatusCmd.Flags().Set("id", "") })

	captureStdout(t, func() {
		tenantBarrierStatusCmd.Run(tenantBarrierStatusCmd, nil)
	})
}

// ---------------------------------------------------------------------------
// tenantUpdateEntitlementsCmd / tenantUpdateEntitlements (0% -> covered)
// ---------------------------------------------------------------------------

func TestTenantUpdateEntitlementsCmd_MissingID(t *testing.T) {
	_ = tenantUpdateEntitlementsCmd.Flags().Set("id", "")
	withGlobalConfig(t, newTenantRunConfig(&mockTenantClient{}))

	code := captureExit(t, func() {
		tenantUpdateEntitlementsCmd.Run(tenantUpdateEntitlementsCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestTenantUpdateEntitlementsCmd_Success(t *testing.T) {
	mock := &mockTenantClient{updateEntitlementsResp: &transport.UpdateTenantEntitlementsResponse{
		Tenant: transport.TenantInfo{ID: "acme", Name: "Acme"},
	}}
	withGlobalConfig(t, newTenantRunConfig(mock))
	_ = tenantUpdateEntitlementsCmd.Flags().Set("id", "acme")
	_ = tenantUpdateEntitlementsCmd.Flags().Set("isolation-modes", "prefix,barrier,volume")
	_ = tenantUpdateEntitlementsCmd.Flags().Set("allow-raft", "true")
	_ = tenantUpdateEntitlementsCmd.Flags().Set("allow-volume", "true")
	_ = tenantUpdateEntitlementsCmd.Flags().Set("allow-system-managed", "true")
	t.Cleanup(func() {
		_ = tenantUpdateEntitlementsCmd.Flags().Set("id", "")
		_ = tenantUpdateEntitlementsCmd.Flags().Set("isolation-modes", "")
		_ = tenantUpdateEntitlementsCmd.Flags().Set("allow-raft", "false")
		_ = tenantUpdateEntitlementsCmd.Flags().Set("allow-volume", "false")
		_ = tenantUpdateEntitlementsCmd.Flags().Set("allow-system-managed", "false")
	})

	captureStdout(t, func() {
		tenantUpdateEntitlementsCmd.Run(tenantUpdateEntitlementsCmd, nil)
	})
}

func TestTenantUpdateEntitlements_ClientError(t *testing.T) {
	withGlobalConfig(t, newUserErrorConfig("text"))
	code := captureExit(t, func() {
		tenantUpdateEntitlements(getConfig(), NewPrinter("text", new(bytes.Buffer)), "acme", nil, false, false, false)
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestTenantUpdateEntitlements_RPCError(t *testing.T) {
	mock := &mockTenantClient{updateEntitlementsErr: errTenantRunBoom}
	cfg := newTenantRunConfig(mock)
	withGlobalConfig(t, cfg)
	code := captureExit(t, func() {
		tenantUpdateEntitlements(cfg, NewPrinter("text", new(bytes.Buffer)), "acme", nil, false, false, false)
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

// ---------------------------------------------------------------------------
// tenantUpdateQuotasCmd / tenantUpdateQuotas (0% -> covered)
// ---------------------------------------------------------------------------

func TestTenantUpdateQuotasCmd_MissingID(t *testing.T) {
	_ = tenantUpdateQuotasCmd.Flags().Set("id", "")
	withGlobalConfig(t, newTenantRunConfig(&mockTenantClient{}))

	code := captureExit(t, func() {
		tenantUpdateQuotasCmd.Run(tenantUpdateQuotasCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestTenantUpdateQuotasCmd_Success(t *testing.T) {
	mock := &mockTenantClient{updateQuotasResp: &transport.UpdateTenantQuotasResponse{
		Tenant: transport.TenantInfo{ID: "acme", Name: "Acme"},
	}}
	withGlobalConfig(t, newTenantRunConfig(mock))
	_ = tenantUpdateQuotasCmd.Flags().Set("id", "acme")
	_ = tenantUpdateQuotasCmd.Flags().Set("max-databases", "10")
	_ = tenantUpdateQuotasCmd.Flags().Set("max-keys", "1000")
	_ = tenantUpdateQuotasCmd.Flags().Set("max-collections", "5")
	_ = tenantUpdateQuotasCmd.Flags().Set("max-storage-bytes", "1073741824")
	_ = tenantUpdateQuotasCmd.Flags().Set("max-users", "50")
	_ = tenantUpdateQuotasCmd.Flags().Set("max-roles", "10")
	_ = tenantUpdateQuotasCmd.Flags().Set("max-certificates", "100")
	t.Cleanup(func() {
		_ = tenantUpdateQuotasCmd.Flags().Set("id", "")
		_ = tenantUpdateQuotasCmd.Flags().Set("max-databases", "0")
		_ = tenantUpdateQuotasCmd.Flags().Set("max-keys", "0")
		_ = tenantUpdateQuotasCmd.Flags().Set("max-collections", "0")
		_ = tenantUpdateQuotasCmd.Flags().Set("max-storage-bytes", "0")
		_ = tenantUpdateQuotasCmd.Flags().Set("max-users", "0")
		_ = tenantUpdateQuotasCmd.Flags().Set("max-roles", "0")
		_ = tenantUpdateQuotasCmd.Flags().Set("max-certificates", "0")
	})

	captureStdout(t, func() {
		tenantUpdateQuotasCmd.Run(tenantUpdateQuotasCmd, nil)
	})
}

func TestTenantUpdateQuotas_ClientError(t *testing.T) {
	withGlobalConfig(t, newUserErrorConfig("text"))
	code := captureExit(t, func() {
		tenantUpdateQuotas(getConfig(), NewPrinter("text", new(bytes.Buffer)), "acme", transport.TenantQuotas{})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestTenantUpdateQuotas_RPCError(t *testing.T) {
	mock := &mockTenantClient{updateQuotasErr: errTenantRunBoom}
	cfg := newTenantRunConfig(mock)
	withGlobalConfig(t, cfg)
	code := captureExit(t, func() {
		tenantUpdateQuotas(cfg, NewPrinter("text", new(bytes.Buffer)), "acme", transport.TenantQuotas{MaxKeys: 5})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}
