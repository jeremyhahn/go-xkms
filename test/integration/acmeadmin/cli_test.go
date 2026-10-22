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

package acmeadmin

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	db "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/pkg/acme/admin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// parseJSON parses JSON output into the given interface.
func parseJSON(t *testing.T, output string, v interface{}) {
	t.Helper()
	err := json.Unmarshal([]byte(output), v)
	require.NoError(t, err, "output should be valid JSON: %s", output)
}

// TestXkmsctlAdminCLI drives the real xkmsctl binary against a running
// xkmsd, covering what test/integration/cactl's TestCactlCLI covered
// through the (now-removed) cactl binary. See harness.go's package doc for
// why tenant lifecycle runs through "xkmsctl tenant" rather than "xkmsctl
// acme".
func TestXkmsctlAdminCLI(t *testing.T) {
	cfg := newXkmsctlConfig()
	if err := findXkmsctlBinary(cfg); err != nil {
		t.Fatalf("xkmsctl binary not found: %v", err)
	}

	t.Run("Version", func(t *testing.T) { testCLIVersion(t, cfg) })
	t.Run("Help", func(t *testing.T) { testCLIHelp(t, cfg) })
	t.Run("Status", func(t *testing.T) { testCLIStatus(t, cfg) })
	t.Run("Stats", func(t *testing.T) { testCLIStats(t, cfg) })
	t.Run("CertificateList", func(t *testing.T) { testCLICertList(t, cfg) })
	t.Run("TenantLifecycle", func(t *testing.T) { testCLITenantLifecycle(t, cfg) })
	t.Run("EABLifecycle", func(t *testing.T) { testCLIEABLifecycle(t, cfg) })
	t.Run("InvalidCommands", func(t *testing.T) { testCLIInvalidCommands(t, cfg) })
	t.Run("OutputFormats", func(t *testing.T) { testCLIOutputFormats(t, cfg) })
}

// testCLIVersion tests "xkmsctl version".
func testCLIVersion(t *testing.T, cfg *xkmsctlConfig) {
	cmd := exec.Command(cfg.Binary, "version")
	output, err := cmd.Output()
	require.NoError(t, err, "version command should succeed")
	require.Contains(t, string(output), "xkmsctl", "output should contain xkmsctl")
}

// testCLIHelp tests "xkmsctl --help".
func testCLIHelp(t *testing.T, cfg *xkmsctlConfig) {
	cmd := exec.Command(cfg.Binary, "--help")
	output, err := cmd.Output()
	require.NoError(t, err, "help command should succeed")

	helpText := string(output)
	require.Contains(t, helpText, "xkmsctl", "help should contain tool name")
	require.Contains(t, helpText, "tenant", "help should mention the tenant command")
}

// testCLIStatus tests "xkmsctl acme status".
func testCLIStatus(t *testing.T, cfg *xkmsctlConfig) {
	output := requireSuccess(t, cfg, "acme", "status", "-o", "json")

	var status admin.CAStatus
	parseJSON(t, output, &status)

	assert.NotEmpty(t, status.Identity, "status should have identity")
	assert.NotEmpty(t, status.Version, "status should have version")
}

// testCLIStats tests "xkmsctl acme stats".
func testCLIStats(t *testing.T, cfg *xkmsctlConfig) {
	output := requireSuccess(t, cfg, "acme", "stats", "-o", "json")

	var stats admin.CAStats
	parseJSON(t, output, &stats)

	assert.GreaterOrEqual(t, stats.TotalCertificates, 0, "total certificates should be >= 0")
	assert.GreaterOrEqual(t, stats.TotalAccounts, 0, "total accounts should be >= 0")
}

// testCLICertList tests "xkmsctl acme cert list". Unlike cactl, the CLI
// wraps the list in {"certificates": [...], "pagination": {...}}
// (cmd/xkmsctl/acme_cert.go:188) rather than returning a bare array.
func testCLICertList(t *testing.T, cfg *xkmsctlConfig) {
	output := requireSuccess(t, cfg, "acme", "cert", "list", "-o", "json")

	var result struct {
		Certificates []*admin.CertificateInfo `json:"certificates"`
	}
	parseJSON(t, output, &result)

	// A fresh server may have zero certificates - that's valid.
	assert.GreaterOrEqual(t, len(result.Certificates), 0, "certificates should be a valid list")
}

// testCLITenantLifecycle tests tenant create, show, list, and delete via
// "xkmsctl tenant". There is no "tenant update" verb
// (cmd/xkmsctl/tenant.go has create/list/show/delete/barrier-*, no rename),
// so the rename assertion cactl's TenantCRUD test made has no equivalent
// and is dropped rather than invented.
//
// This test first caught "xkmsctl tenant create"/"list" requesting the
// collection root without the trailing slash pkg/api/rest/routes.go
// registers ("/api/v1/tenants" vs "/api/v1/tenants/"), while the ACME admin
// plane still mounted its own tenant surface at the bare path and answered
// with an all-zero body. The client now sends the slash
// (pkg/api/transport/rest/transport.go's CreateTenant, regression tests in
// transport_tenant_test.go), and core is the one owner of the tenant
// collection: the admin plane keeps only the tenant sub-resources.
func testCLITenantLifecycle(t *testing.T, cfg *xkmsctlConfig) {
	tenantID := fmt.Sprintf("%stenant-%d", testTenantPrefix, time.Now().UnixNano())
	tenantName := tenantID

	// Create tenant. "xkmsctl tenant create" requires --id explicitly
	// (cmd/xkmsctl/tenant.go: ErrTenantIDRequired).
	createOutput := requireSuccess(t, cfg, "tenant", "create",
		"--id", tenantID, "--name", tenantName, "-o", "json")

	var created db.TenantInfo
	parseJSON(t, createOutput, &created)
	require.Equal(t, tenantID, created.ID, "created tenant ID should match")
	assert.Equal(t, tenantName, created.Name, "created tenant name should match")

	// Cleanup at end, registered immediately after a successful create so
	// it still runs even if a later assertion in this test fails.
	defer func() {
		_, _ = runTenant(cfg, "delete", "--id", tenantID)
	}()

	// Show tenant.
	showOutput := requireSuccess(t, cfg, "tenant", "show", "--id", tenantID, "-o", "json")

	var shown db.TenantInfo
	parseJSON(t, showOutput, &shown)
	assert.Equal(t, tenantID, shown.ID, "shown tenant ID should match")
	assert.Equal(t, tenantName, shown.Name, "shown tenant name should match")

	// List tenants and confirm the new one is present.
	listOutput := requireSuccess(t, cfg, "tenant", "list", "-o", "json")

	var listResult struct {
		Tenants []db.TenantInfo `json:"tenants"`
		Total   int             `json:"total"`
	}
	parseJSON(t, listOutput, &listResult)

	found := false
	for _, tenant := range listResult.Tenants {
		if tenant.ID == tenantID {
			found = true
			break
		}
	}
	assert.True(t, found, "created tenant should be in list")

	// Delete tenant.
	deleteOutput := requireSuccess(t, cfg, "tenant", "delete", "--id", tenantID, "-o", "json")
	assert.Contains(t, deleteOutput, "success", "delete should report success")

	// Verify tenant is deleted.
	xerr := requireFail(t, cfg, "tenant", "show", "--id", tenantID)
	assert.Contains(t, strings.ToLower(xerr.Stderr+xerr.Stdout), "failed to get tenant",
		"should report failure getting the deleted tenant")
}

// testCLIEABLifecycle tests EAB create, get, list, and delete under a
// tenant created via "xkmsctl tenant" (EAB is scoped to a tenant in
// go-xkms's ACME server, cmd/xkmsctl/acme_eab.go:18).
func testCLIEABLifecycle(t *testing.T, cfg *xkmsctlConfig) {
	tenantID := fmt.Sprintf("%seab-%d", testTenantPrefix, time.Now().UnixNano())
	requireSuccess(t, cfg, "tenant", "create", "--id", tenantID, "--name", tenantID, "-o", "json")
	defer func() {
		_, _ = runTenant(cfg, "delete", "--id", tenantID)
	}()

	// Create EAB.
	createEABOutput := requireSuccess(t, cfg, "acme", "eab", "create", "--tenant", tenantID, "-o", "json")

	var createdEAB admin.CreateEABResponse
	parseJSON(t, createEABOutput, &createdEAB)
	require.NotEmpty(t, createdEAB.ID, "created EAB should have ID")
	require.NotEmpty(t, createdEAB.MACKey, "created EAB should have MAC key")
	kid := createdEAB.ID

	defer func() {
		_, _ = runAcme(cfg, "eab", "delete", "--tenant", tenantID, kid)
	}()

	// Get EAB.
	getEABOutput := requireSuccess(t, cfg, "acme", "eab", "get", "--tenant", tenantID, kid, "-o", "json")

	var retrievedEAB admin.EABInfo
	parseJSON(t, getEABOutput, &retrievedEAB)
	assert.Equal(t, kid, retrievedEAB.ID, "retrieved EAB ID should match")

	// List EABs. The CLI wraps the list in {"eabs": [...], "pagination":
	// {...}} (cmd/xkmsctl/acme_eab.go:314).
	listEABOutput := requireSuccess(t, cfg, "acme", "eab", "list", "--tenant", tenantID, "--per-page", "100", "-o", "json")

	var eabList struct {
		EABs []*admin.EABInfo `json:"eabs"`
	}
	parseJSON(t, listEABOutput, &eabList)

	found := false
	for _, eab := range eabList.EABs {
		if eab.ID == kid {
			found = true
			break
		}
	}
	assert.True(t, found, "created EAB should be in list")

	// Delete EAB.
	deleteEABOutput := requireSuccess(t, cfg, "acme", "eab", "delete", "--tenant", tenantID, kid, "-o", "json")
	assert.Contains(t, deleteEABOutput, "success", "EAB delete should report success")
}

// testCLIInvalidCommands tests error handling for invalid commands and inputs.
func testCLIInvalidCommands(t *testing.T, cfg *xkmsctlConfig) {
	t.Run("UnknownCommand", func(t *testing.T) {
		cmd := exec.Command(cfg.Binary, "nonexistent-command")
		err := cmd.Run()
		assert.Error(t, err, "unknown command should fail")
	})

	t.Run("MissingRequiredArg", func(t *testing.T) {
		// tenant show without --id should fail.
		xerr := requireFail(t, cfg, "tenant", "show")
		assert.True(t, len(xerr.Stderr) > 0 || len(xerr.Stdout) > 0, "should have error output")
	})

	t.Run("InvalidTenantID", func(t *testing.T) {
		xerr := requireFail(t, cfg, "tenant", "show", "--id", "nonexistent-tenant-id-12345")
		combined := strings.ToLower(xerr.Stderr + xerr.Stdout)
		assert.Contains(t, combined, "failed to get tenant",
			"should report error for nonexistent tenant, got: %s", combined)
	})

	t.Run("InvalidACMETransport", func(t *testing.T) {
		badCfg := &xkmsctlConfig{
			Binary:        cfg.Binary,
			ACMEServer:    cfg.ACMEServer,
			ACMETransport: "invalid-transport",
			Timeout:       cfg.Timeout,
		}
		xerr := requireFail(t, badCfg, "acme", "status")
		assert.True(t, len(xerr.Stderr) > 0 || len(xerr.Stdout) > 0,
			"should have error output for invalid transport")
	})
}

// testCLIOutputFormats tests different output format options.
func testCLIOutputFormats(t *testing.T, cfg *xkmsctlConfig) {
	t.Run("JSON", func(t *testing.T) {
		output := requireSuccess(t, cfg, "acme", "status", "-o", "json")
		var status admin.CAStatus
		err := json.Unmarshal([]byte(output), &status)
		assert.NoError(t, err, "JSON output should be valid")
	})

	t.Run("Table", func(t *testing.T) {
		output := requireSuccess(t, cfg, "acme", "status", "-o", "table")
		assert.NotEmpty(t, output, "table output should not be empty")
	})

	t.Run("Text", func(t *testing.T) {
		output := requireSuccess(t, cfg, "acme", "status", "-o", "text")
		assert.Contains(t, output, ":", "text output should contain key/value pairs")
	})
}
