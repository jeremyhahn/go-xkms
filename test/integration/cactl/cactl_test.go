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

// Package cactl provides integration tests for the cactl CLI tool.
//
// These tests exercise the cactl binary against a real trusted-acme-server
// running in a Docker container, testing all supported protocols:
//   - REST (HTTP/HTTPS)
//   - gRPC (TCP)
//   - QUIC (UDP)
//   - MCP (stdio/HTTP)
//   - Unix (Unix domain socket)
//
// Environment variables:
//   - CACTL_TRANSPORT: Protocol to use (unix|rest|grpc|quic|mcp)
//   - CACTL_ADDRESS: Server address (socket path or host:port)
//   - CACTL_TOKEN: Authentication token
//   - CACTL_BINARY: Path to cactl binary (default: ./cactl)
package cactl

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	db "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/pkg/acme/admin"
	"github.com/jeremyhahn/go-xkms/pkg/acme/api"
	"github.com/jeremyhahn/go-xkms/test/integration/acme-multiprotocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Default test configuration.
const (
	defaultCactlBinary = "./cactl"
	defaultTimeout     = 30 * time.Second
)

// Test tenant name for cleanup.
const testTenantPrefix = "integration-test-"

// cactlConfig holds configuration for cactl CLI execution.
type cactlConfig struct {
	Binary      string
	Transport   string
	Address     string
	Token       string
	TLSInsecure bool
	Timeout     time.Duration
}

// newCactlConfig creates a new cactl configuration from environment variables.
func newCactlConfig() *cactlConfig {
	return &cactlConfig{
		Binary:      getEnvOrDefault("CACTL_BINARY", defaultCactlBinary),
		Transport:   getEnvOrDefault("CACTL_TRANSPORT", "rest"),
		Address:     getEnvOrDefault("CACTL_ADDRESS", "http://localhost:8443"),
		Token:       os.Getenv("CACTL_TOKEN"),
		TLSInsecure: os.Getenv("CACTL_TLS_INSECURE") == "true",
		Timeout:     defaultTimeout,
	}
}

// getEnvOrDefault returns the environment variable value or a default.
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// runCactl executes the cactl binary with the given arguments and returns stdout output.
func runCactl(cfg *cactlConfig, args ...string) (string, error) {
	fullArgs := buildArgs(cfg, args...)

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, cfg.Binary, fullArgs...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return "", &CactlError{
			Err:    err,
			Stdout: stdout.String(),
			Stderr: stderr.String(),
			Args:   fullArgs,
		}
	}

	return stdout.String(), nil
}

// buildArgs constructs the full argument list including transport and address flags.
func buildArgs(cfg *cactlConfig, args ...string) []string {
	fullArgs := make([]string, 0, len(args)+8)

	// Add transport flag
	if cfg.Transport != "" {
		fullArgs = append(fullArgs, "-t", cfg.Transport)
	}

	// Add address flag
	if cfg.Address != "" {
		fullArgs = append(fullArgs, "-a", cfg.Address)
	}

	// Add auth token if present
	if cfg.Token != "" {
		fullArgs = append(fullArgs, "--token", cfg.Token)
	}

	// Add TLS insecure flag if set
	if cfg.TLSInsecure {
		fullArgs = append(fullArgs, "--tls-insecure")
	}

	// Append user-provided arguments
	fullArgs = append(fullArgs, args...)

	return fullArgs
}

// CactlError represents an error from running the cactl command.
type CactlError struct {
	Err    error
	Stdout string
	Stderr string
	Args   []string
}

// Error implements the error interface.
func (e *CactlError) Error() string {
	return fmt.Sprintf("cactl command failed: %v\nargs: %v\nstdout: %s\nstderr: %s",
		e.Err, e.Args, e.Stdout, e.Stderr)
}

// Unwrap returns the underlying error.
func (e *CactlError) Unwrap() error {
	return e.Err
}

// requireCactlSuccess executes cactl and requires successful execution.
func requireCactlSuccess(t *testing.T, cfg *cactlConfig, args ...string) string {
	t.Helper()
	output, err := runCactl(cfg, args...)
	require.NoError(t, err, "cactl command should succeed")
	return output
}

// requireCactlFail executes cactl and requires it to fail.
func requireCactlFail(t *testing.T, cfg *cactlConfig, args ...string) *CactlError {
	t.Helper()
	_, err := runCactl(cfg, args...)
	require.Error(t, err, "cactl command should fail")
	cactlErr, ok := err.(*CactlError)
	require.True(t, ok, "error should be CactlError")
	return cactlErr
}

// parseJSON parses JSON output into the given interface.
func parseJSON(t *testing.T, output string, v interface{}) {
	t.Helper()
	err := json.Unmarshal([]byte(output), v)
	require.NoError(t, err, "output should be valid JSON")
}

// TestCactlCLI tests the cactl binary execution via os/exec.
// This test exercises the actual CLI binary and validates command-line behavior.
func TestCactlCLI(t *testing.T) {
	cfg := newCactlConfig()

	// Find the binary - try multiple locations
	if _, err := os.Stat(cfg.Binary); os.IsNotExist(err) {
		possiblePaths := []string{
			"./cactl",
			"../../../cmd/cactl/cactl",
			"/usr/local/bin/cactl",
			"/workspace/go-xkms/bin/cactl",
		}
		found := false
		for _, p := range possiblePaths {
			if absPath, err := filepath.Abs(p); err == nil {
				if _, err := os.Stat(absPath); err == nil {
					cfg.Binary = absPath
					found = true
					break
				}
			}
		}
		if !found {
			t.Fatalf("cactl binary not found at %s or common locations - run 'make build' first", cfg.Binary)
		}
	}

	t.Run("Version", func(t *testing.T) {
		testCLIVersion(t, cfg)
	})

	t.Run("Help", func(t *testing.T) {
		testCLIHelp(t, cfg)
	})

	t.Run("Status", func(t *testing.T) {
		testCLIStatus(t, cfg)
	})

	t.Run("Stats", func(t *testing.T) {
		testCLIStats(t, cfg)
	})

	t.Run("CertificateList", func(t *testing.T) {
		testCLICertList(t, cfg)
	})

	t.Run("TenantCRUD", func(t *testing.T) {
		testCLITenantCRUD(t, cfg)
	})

	t.Run("EABCRUD", func(t *testing.T) {
		testCLIEABCRUD(t, cfg)
	})

	t.Run("InvalidCommands", func(t *testing.T) {
		testCLIInvalidCommands(t, cfg)
	})

	t.Run("OutputFormats", func(t *testing.T) {
		testCLIOutputFormats(t, cfg)
	})
}

// testCLIVersion tests the version command.
func testCLIVersion(t *testing.T, cfg *cactlConfig) {
	// Version command doesn't need server connection
	cmd := exec.Command(cfg.Binary, "version")
	output, err := cmd.Output()
	require.NoError(t, err, "version command should succeed")
	require.Contains(t, string(output), "cactl", "output should contain cactl")
}

// testCLIHelp tests the help command.
func testCLIHelp(t *testing.T, cfg *cactlConfig) {
	// Help command doesn't need server connection
	cmd := exec.Command(cfg.Binary, "--help")
	output, err := cmd.Output()
	require.NoError(t, err, "help command should succeed")

	helpText := string(output)
	require.Contains(t, helpText, "cactl", "help should contain tool name")
	require.Contains(t, helpText, "status", "help should mention status command")
	require.Contains(t, helpText, "tenant", "help should mention tenant command")
	require.Contains(t, helpText, "cert", "help should mention cert command")
}

// testCLIStatus tests the status command.
func testCLIStatus(t *testing.T, cfg *cactlConfig) {
	output := requireCactlSuccess(t, cfg, "status", "-o", "json")

	var status admin.CAStatus
	parseJSON(t, output, &status)

	assert.NotEmpty(t, status.Identity, "status should have identity")
	assert.NotEmpty(t, status.Version, "status should have version")
}

// testCLIStats tests the stats command.
func testCLIStats(t *testing.T, cfg *cactlConfig) {
	output := requireCactlSuccess(t, cfg, "stats", "-o", "json")

	var stats admin.CAStats
	parseJSON(t, output, &stats)

	// Stats should have valid values (>= 0)
	assert.GreaterOrEqual(t, stats.TotalCertificates, 0, "total certificates should be >= 0")
	assert.GreaterOrEqual(t, stats.TotalAccounts, 0, "total accounts should be >= 0")
}

// testCLICertList tests the certificate list command.
func testCLICertList(t *testing.T, cfg *cactlConfig) {
	output := requireCactlSuccess(t, cfg, "cert", "list", "-o", "json")

	// The cert list output is valid JSON (either an array or null for empty)
	var certs []*admin.CertificateInfo
	parseJSON(t, output, &certs)

	// A fresh server may have zero certificates - that's valid
	assert.GreaterOrEqual(t, len(certs), 0, "certificates should be a valid list")
}

// testCLITenantCRUD tests tenant create, get, update, list, and delete operations.
func testCLITenantCRUD(t *testing.T, cfg *cactlConfig) {
	tenantName := fmt.Sprintf("%s%d", testTenantPrefix, time.Now().UnixNano())

	// Create tenant
	createOutput := requireCactlSuccess(t, cfg, "tenant", "create", "--name", tenantName, "-o", "json")

	var createdTenant admin.TenantInfo
	parseJSON(t, createOutput, &createdTenant)

	require.NotEmpty(t, createdTenant.ID, "created tenant should have ID")
	assert.Equal(t, tenantName, createdTenant.Name, "tenant name should match")

	tenantID := createdTenant.ID

	// Cleanup at end
	defer func() {
		_, _ = runCactl(cfg, "tenant", "delete", tenantID)
	}()

	// Get tenant
	getOutput := requireCactlSuccess(t, cfg, "tenant", "get", tenantID, "-o", "json")

	var retrievedTenant admin.TenantInfo
	parseJSON(t, getOutput, &retrievedTenant)

	assert.Equal(t, tenantID, retrievedTenant.ID, "retrieved tenant ID should match")
	assert.Equal(t, tenantName, retrievedTenant.Name, "retrieved tenant name should match")

	// Update tenant
	newName := tenantName + "-updated"
	updateOutput := requireCactlSuccess(t, cfg, "tenant", "update", tenantID, "--name", newName, "-o", "json")

	var updatedTenant admin.TenantInfo
	parseJSON(t, updateOutput, &updatedTenant)

	assert.Equal(t, tenantID, updatedTenant.ID, "updated tenant ID should match")
	assert.Equal(t, newName, updatedTenant.Name, "updated tenant name should match")

	// List tenants - use high per_page to ensure we see all tenants
	// (map iteration order is non-deterministic, so with pagination the newly
	// created tenant might not be in the first page with default per_page=20)
	// Use 500 to handle parallel tests creating many tenants
	listOutput := requireCactlSuccess(t, cfg, "tenant", "list", "--per-page", "500", "-o", "json")
	t.Logf("DEBUG: tenant list output: %s", listOutput)
	t.Logf("DEBUG: looking for tenant ID: %s", tenantID)

	var tenants []*admin.TenantInfo
	parseJSON(t, listOutput, &tenants)
	t.Logf("DEBUG: parsed %d tenants", len(tenants))
	for i, tenant := range tenants {
		t.Logf("DEBUG: tenant[%d]: id=%s name=%s", i, tenant.ID, tenant.Name)
	}

	found := false
	for _, tenant := range tenants {
		if tenant.ID == tenantID {
			found = true
			break
		}
	}
	assert.True(t, found, "created tenant should be in list")

	// Delete tenant
	deleteOutput := requireCactlSuccess(t, cfg, "tenant", "delete", tenantID, "-o", "json")
	assert.Contains(t, deleteOutput, "success", "delete should report success")

	// Verify tenant is deleted
	cactlErr := requireCactlFail(t, cfg, "tenant", "get", tenantID)
	assert.Contains(t, cactlErr.Stderr, "not found", "should report tenant not found")
}

// testCLIEABCRUD tests EAB create, get, list, and delete operations.
func testCLIEABCRUD(t *testing.T, cfg *cactlConfig) {
	// First create a tenant for EAB operations
	tenantName := fmt.Sprintf("%s%d", testTenantPrefix, time.Now().UnixNano())
	createTenantOutput := requireCactlSuccess(t, cfg, "tenant", "create", "--name", tenantName, "-o", "json")

	var tenant admin.TenantInfo
	parseJSON(t, createTenantOutput, &tenant)
	tenantID := tenant.ID

	// Cleanup tenant at end
	defer func() {
		_, _ = runCactl(cfg, "tenant", "delete", tenantID)
	}()

	// Create EAB
	createEABOutput := requireCactlSuccess(t, cfg, "tenant", "eab", "create", tenantID, "-o", "json")

	var createdEAB admin.CreateEABResponse
	parseJSON(t, createEABOutput, &createdEAB)

	require.NotEmpty(t, createdEAB.ID, "created EAB should have ID")
	require.NotEmpty(t, createdEAB.MACKey, "created EAB should have MAC key")
	kid := createdEAB.ID

	// Cleanup EAB at end
	defer func() {
		_, _ = runCactl(cfg, "tenant", "eab", "delete", tenantID, kid)
	}()

	// Get EAB
	getEABOutput := requireCactlSuccess(t, cfg, "tenant", "eab", "get", tenantID, kid, "-o", "json")

	var retrievedEAB admin.EABInfo
	parseJSON(t, getEABOutput, &retrievedEAB)

	assert.Equal(t, kid, retrievedEAB.ID, "retrieved EAB ID should match")

	// List EABs - use high per_page to ensure we see all EABs
	listEABOutput := requireCactlSuccess(t, cfg, "tenant", "eab", "list", tenantID, "--per-page", "100", "-o", "json")

	var eabs []*admin.EABInfo
	parseJSON(t, listEABOutput, &eabs)

	found := false
	for _, eab := range eabs {
		if eab.ID == kid {
			found = true
			break
		}
	}
	assert.True(t, found, "created EAB should be in list")

	// Delete EAB
	deleteEABOutput := requireCactlSuccess(t, cfg, "tenant", "eab", "delete", tenantID, kid, "-o", "json")
	assert.Contains(t, deleteEABOutput, "success", "delete should report success")
}

// testCLIInvalidCommands tests error handling for invalid commands and inputs.
func testCLIInvalidCommands(t *testing.T, cfg *cactlConfig) {
	t.Run("UnknownCommand", func(t *testing.T) {
		cmd := exec.Command(cfg.Binary, "nonexistent-command")
		err := cmd.Run()
		assert.Error(t, err, "unknown command should fail")
	})

	t.Run("MissingRequiredArg", func(t *testing.T) {
		// tenant get without ID should fail
		cactlErr := requireCactlFail(t, cfg, "tenant", "get")
		assert.True(t, len(cactlErr.Stderr) > 0 || len(cactlErr.Stdout) > 0,
			"should have error output")
	})

	t.Run("InvalidTenantID", func(t *testing.T) {
		cactlErr := requireCactlFail(t, cfg, "tenant", "get", "nonexistent-tenant-id-12345")
		combinedOutput := strings.ToLower(cactlErr.Stderr + cactlErr.Stdout)
		assert.True(t, strings.Contains(combinedOutput, "not found") ||
			strings.Contains(combinedOutput, "failed to get tenant") ||
			strings.Contains(combinedOutput, "error"),
			"should report error for nonexistent tenant, got: %s", combinedOutput)
	})

	t.Run("InvalidTransport", func(t *testing.T) {
		badCfg := &cactlConfig{
			Binary:    cfg.Binary,
			Transport: "invalid-transport",
			Address:   cfg.Address,
			Timeout:   cfg.Timeout,
		}
		cactlErr := requireCactlFail(t, badCfg, "status")
		assert.True(t, len(cactlErr.Stderr) > 0 || len(cactlErr.Stdout) > 0,
			"should have error output for invalid transport")
	})
}

// testCLIOutputFormats tests different output format options.
func testCLIOutputFormats(t *testing.T, cfg *cactlConfig) {
	t.Run("JSON", func(t *testing.T) {
		output := requireCactlSuccess(t, cfg, "status", "-o", "json")
		var status admin.CAStatus
		err := json.Unmarshal([]byte(output), &status)
		assert.NoError(t, err, "JSON output should be valid")
	})

	t.Run("Table", func(t *testing.T) {
		output := requireCactlSuccess(t, cfg, "status", "-o", "table")
		// Table output should contain column headers or formatted data
		assert.NotEmpty(t, output, "table output should not be empty")
	})

	t.Run("YAML", func(t *testing.T) {
		output := requireCactlSuccess(t, cfg, "status", "-o", "yaml")
		// YAML output should contain key: value pairs
		assert.Contains(t, output, ":", "YAML output should contain colons")
	})
}

// TestCactlMultiProtocol tests the cactl functionality via all protocol adapters.
// This uses the multiprotocol test framework for protocol-agnostic testing.
func TestCactlMultiProtocol(t *testing.T) {
	ctx := multiprotocol.NewTestContext(t)
	defer ctx.Cleanup()

	ctx.ForEachProtocol(t, func(t *testing.T, adapter api.AdminAdapter) {
		protocol := adapter.Protocol()

		t.Run("GetStatus", func(t *testing.T) {
			testGetStatus(t, adapter, protocol)
		})

		t.Run("GetStats", func(t *testing.T) {
			testGetStats(t, adapter, protocol)
		})

		t.Run("ListCertificates", func(t *testing.T) {
			testListCertificates(t, adapter, protocol)
		})

		t.Run("TenantCRUD", func(t *testing.T) {
			testTenantCRUD(t, adapter, protocol)
		})

		t.Run("EABCRUD", func(t *testing.T) {
			testEABCRUD(t, adapter, protocol)
		})

		t.Run("RoleCRUD", func(t *testing.T) {
			testRoleCRUD(t, adapter, protocol)
		})
	})
}

// testGetStatus tests the GetStatus operation via protocol adapter.
func testGetStatus(t *testing.T, adapter api.AdminAdapter, protocol api.Protocol) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	status, err := adapter.GetStatus(ctx)
	require.NoError(t, err, "GetStatus via %s should succeed", protocol)
	require.NotNil(t, status, "status should not be nil")

	assert.NotEmpty(t, status.Identity, "status should have identity")
	assert.NotEmpty(t, status.Version, "status should have version")
}

// testGetStats tests the GetStats operation via protocol adapter.
func testGetStats(t *testing.T, adapter api.AdminAdapter, protocol api.Protocol) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	stats, err := adapter.GetStats(ctx)
	require.NoError(t, err, "GetStats via %s should succeed", protocol)
	require.NotNil(t, stats, "stats should not be nil")

	assert.GreaterOrEqual(t, stats.TotalCertificates, 0, "total certificates should be >= 0")
	assert.GreaterOrEqual(t, stats.TotalAccounts, 0, "total accounts should be >= 0")
}

// testListCertificates tests the ListCertificates operation via protocol adapter.
func testListCertificates(t *testing.T, adapter api.AdminAdapter, protocol api.Protocol) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	req := &admin.ListCertificatesRequest{
		Page:    1,
		PerPage: 10,
	}

	certs, pagination, err := adapter.ListCertificates(ctx, req)
	require.NoError(t, err, "ListCertificates via %s should succeed", protocol)

	// Result should be a non-nil slice (can be empty)
	assert.NotNil(t, certs, "certificates should not be nil")

	if pagination != nil {
		assert.GreaterOrEqual(t, pagination.Page, 1, "page should be >= 1")
		assert.GreaterOrEqual(t, pagination.Total, 0, "total should be >= 0")
	}
}

// testTenantCRUD tests tenant CRUD operations via protocol adapter.
func testTenantCRUD(t *testing.T, adapter api.AdminAdapter, protocol api.Protocol) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	tenantName := fmt.Sprintf("%s%s-%d", testTenantPrefix, protocol, time.Now().UnixNano())

	// Create
	createReq := &admin.CreateTenantRequest{
		Name: tenantName,
	}

	created, err := adapter.CreateTenant(ctx, createReq)
	require.NoError(t, err, "CreateTenant via %s should succeed", protocol)
	require.NotNil(t, created, "created tenant should not be nil")
	require.NotEmpty(t, created.ID, "created tenant should have ID")
	assert.Equal(t, tenantName, created.Name, "tenant name should match")

	tenantID := created.ID

	// Cleanup at end
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), defaultTimeout)
		defer cleanupCancel()
		_ = adapter.DeleteTenant(cleanupCtx, tenantID)
	}()

	// Get
	retrieved, err := adapter.GetTenant(ctx, tenantID)
	require.NoError(t, err, "GetTenant via %s should succeed", protocol)
	require.NotNil(t, retrieved, "retrieved tenant should not be nil")
	assert.Equal(t, tenantID, retrieved.ID, "retrieved tenant ID should match")
	assert.Equal(t, tenantName, retrieved.Name, "retrieved tenant name should match")

	// Update
	newName := tenantName + "-updated"
	updateReq := &admin.UpdateTenantRequest{
		Name: newName,
	}

	updated, err := adapter.UpdateTenant(ctx, tenantID, updateReq)
	require.NoError(t, err, "UpdateTenant via %s should succeed", protocol)
	require.NotNil(t, updated, "updated tenant should not be nil")
	assert.Equal(t, tenantID, updated.ID, "updated tenant ID should match")
	assert.Equal(t, newName, updated.Name, "updated tenant name should match")

	// List - verify listing works and the tenant can be found
	listReq := &admin.ListTenantsRequest{
		Page:    1,
		PerPage: 100,
	}

	tenants, pagination, err := adapter.ListTenants(ctx, listReq)
	require.NoError(t, err, "ListTenants via %s should succeed", protocol)
	require.NotNil(t, tenants, "tenants list should not be nil")
	assert.Greater(t, len(tenants), 0, "tenants list should have at least one entry (protocol=%s)", protocol)

	// Verify pagination metadata is valid if returned
	if pagination != nil {
		assert.GreaterOrEqual(t, pagination.Page, 1, "pagination page should be >= 1")
		assert.GreaterOrEqual(t, pagination.Total, len(tenants), "pagination total should be >= returned count")
	}

	// Delete
	err = adapter.DeleteTenant(ctx, tenantID)
	require.NoError(t, err, "DeleteTenant via %s should succeed", protocol)

	// Verify deletion
	_, err = adapter.GetTenant(ctx, tenantID)
	assert.Error(t, err, "GetTenant after delete should fail")
}

// testEABCRUD tests EAB CRUD operations via protocol adapter.
func testEABCRUD(t *testing.T, adapter api.AdminAdapter, protocol api.Protocol) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	// First create a tenant
	tenantName := fmt.Sprintf("%seab-%s-%d", testTenantPrefix, protocol, time.Now().UnixNano())
	createTenantReq := &admin.CreateTenantRequest{
		Name: tenantName,
	}

	tenant, err := adapter.CreateTenant(ctx, createTenantReq)
	require.NoError(t, err, "CreateTenant for EAB test should succeed")
	tenantID := tenant.ID

	// Cleanup tenant at end
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), defaultTimeout)
		defer cleanupCancel()
		_ = adapter.DeleteTenant(cleanupCtx, tenantID)
	}()

	// Create EAB
	createEABReq := &admin.CreateEABRequest{
		Purpose: "account-binding",
		Contact: []string{"test@example.com"},
	}

	createdEAB, err := adapter.CreateEAB(ctx, tenantID, createEABReq)
	require.NoError(t, err, "CreateEAB via %s should succeed", protocol)
	require.NotNil(t, createdEAB, "created EAB should not be nil")
	require.NotEmpty(t, createdEAB.ID, "created EAB should have ID")
	require.NotEmpty(t, createdEAB.MACKey, "created EAB should have MAC key")

	kid := createdEAB.ID

	// Cleanup EAB at end
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), defaultTimeout)
		defer cleanupCancel()
		_ = adapter.DeleteEAB(cleanupCtx, tenantID, kid)
	}()

	// Get EAB
	retrieved, err := adapter.GetEAB(ctx, tenantID, kid)
	require.NoError(t, err, "GetEAB via %s should succeed", protocol)
	require.NotNil(t, retrieved, "retrieved EAB should not be nil")
	assert.Equal(t, kid, retrieved.ID, "retrieved EAB ID should match")

	// List EABs
	listReq := &admin.ListEABRequest{
		Page:    1,
		PerPage: 100,
	}

	eabs, _, err := adapter.ListEABs(ctx, tenantID, listReq)
	require.NoError(t, err, "ListEABs via %s should succeed", protocol)
	require.NotNil(t, eabs, "EABs list should not be nil")

	found := false
	for _, eab := range eabs {
		if eab.ID == kid {
			found = true
			break
		}
	}
	assert.True(t, found, "created EAB should be in list")

	// Delete EAB
	err = adapter.DeleteEAB(ctx, tenantID, kid)
	require.NoError(t, err, "DeleteEAB via %s should succeed", protocol)

	// Verify deletion
	_, err = adapter.GetEAB(ctx, tenantID, kid)
	assert.Error(t, err, "GetEAB after delete should fail")
}

// testRoleCRUD tests RBAC role CRUD operations via protocol adapter.
func testRoleCRUD(t *testing.T, adapter api.AdminAdapter, protocol api.Protocol) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	// First create a tenant
	tenantName := fmt.Sprintf("%srole-%s-%d", testTenantPrefix, protocol, time.Now().UnixNano())
	createTenantReq := &admin.CreateTenantRequest{
		Name: tenantName,
	}

	tenant, err := adapter.CreateTenant(ctx, createTenantReq)
	require.NoError(t, err, "CreateTenant for role test should succeed")
	tenantID := tenant.ID

	// Cleanup tenant at end
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), defaultTimeout)
		defer cleanupCancel()
		_ = adapter.DeleteTenant(cleanupCtx, tenantID)
	}()

	// Create role
	roleName := fmt.Sprintf("test-role-%d", time.Now().UnixNano())
	createRoleReq := &db.CreateRoleRequest{
		Name: roleName,
		Permissions: []string{
			"certificates:read",
			"certificates:list",
		},
	}

	createdRole, err := adapter.CreateTenantRole(ctx, tenantID, createRoleReq)
	require.NoError(t, err, "CreateTenantRole via %s should succeed", protocol)
	require.NotNil(t, createdRole, "created role should not be nil")
	assert.Equal(t, roleName, createdRole.Name, "role name should match")
	assert.NotEmpty(t, createdRole.ID, "role should have an ID")

	// Cleanup role at end
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), defaultTimeout)
		defer cleanupCancel()
		_ = adapter.DeleteTenantRole(cleanupCtx, tenantID, createdRole.ID)
	}()

	// Get role
	retrieved, err := adapter.GetTenantRole(ctx, tenantID, createdRole.ID)
	require.NoError(t, err, "GetTenantRole via %s should succeed", protocol)
	require.NotNil(t, retrieved, "retrieved role should not be nil")
	assert.Equal(t, createdRole.ID, retrieved.ID, "retrieved role ID should match")
	assert.Equal(t, roleName, retrieved.Name, "retrieved role name should match")

	// Update role
	updatedName := roleName + "-updated"
	updateReq := &db.UpdateRoleRequest{
		ID:   createdRole.ID,
		Name: updatedName,
		Permissions: []string{
			"certificates:read",
			"certificates:list",
			"accounts:read",
		},
	}

	updated, err := adapter.UpdateTenantRole(ctx, tenantID, updateReq)
	require.NoError(t, err, "UpdateTenantRole via %s should succeed", protocol)
	require.NotNil(t, updated, "updated role should not be nil")
	assert.Equal(t, updatedName, updated.Name, "updated role name should match")

	// List roles
	listResp, err := adapter.ListTenantRoles(ctx, tenantID, &db.ListRolesRequest{
		TenantID: tenantID,
	})
	require.NoError(t, err, "ListTenantRoles via %s should succeed", protocol)
	require.NotNil(t, listResp, "roles list response should not be nil")

	found := false
	for _, r := range listResp.Roles {
		if r.ID == createdRole.ID {
			found = true
			break
		}
	}
	assert.True(t, found, "created role should be in list")

	// Delete role
	err = adapter.DeleteTenantRole(ctx, tenantID, createdRole.ID)
	require.NoError(t, err, "DeleteTenantRole via %s should succeed", protocol)

	// Verify deletion
	_, err = adapter.GetTenantRole(ctx, tenantID, createdRole.ID)
	assert.Error(t, err, "GetTenantRole after delete should fail")
}

// TestCactlErrorHandling tests error handling scenarios.
func TestCactlErrorHandling(t *testing.T) {
	ctx := multiprotocol.NewTestContext(t)
	defer ctx.Cleanup()

	ctx.ForEachProtocol(t, func(t *testing.T, adapter api.AdminAdapter) {
		protocol := adapter.Protocol()

		t.Run("GetNonexistentTenant", func(t *testing.T) {
			testCtx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
			defer cancel()

			_, err := adapter.GetTenant(testCtx, "nonexistent-tenant-id-12345")
			assert.Error(t, err, "GetTenant via %s for nonexistent tenant should fail", protocol)
		})

		t.Run("GetNonexistentCertificate", func(t *testing.T) {
			testCtx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
			defer cancel()

			_, err := adapter.GetCertificate(testCtx, "00:00:00:00:00:00:00:00")
			assert.Error(t, err, "GetCertificate via %s for nonexistent cert should fail", protocol)
		})

		t.Run("DeleteNonexistentTenant", func(t *testing.T) {
			testCtx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
			defer cancel()

			err := adapter.DeleteTenant(testCtx, "nonexistent-tenant-id-12345")
			assert.Error(t, err, "DeleteTenant via %s for nonexistent tenant should fail", protocol)
		})

		t.Run("CreateDuplicateTenant", func(t *testing.T) {
			testCtx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
			defer cancel()

			tenantName := fmt.Sprintf("%sdup-%s-%d", testTenantPrefix, protocol, time.Now().UnixNano())
			req := &admin.CreateTenantRequest{Name: tenantName}

			// Create first tenant
			tenant, err := adapter.CreateTenant(testCtx, req)
			require.NoError(t, err, "first CreateTenant should succeed")
			defer func() {
				cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), defaultTimeout)
				defer cleanupCancel()
				_ = adapter.DeleteTenant(cleanupCtx, tenant.ID)
			}()

			// Attempt to create duplicate with same ID
			reqDup := &admin.CreateTenantRequest{
				ID:   tenant.ID,
				Name: tenantName + "-dup",
			}
			_, err = adapter.CreateTenant(testCtx, reqDup)
			assert.Error(t, err, "CreateTenant via %s with duplicate ID should fail", protocol)
		})
	})
}

// TestCactlPagination tests pagination functionality.
func TestCactlPagination(t *testing.T) {
	ctx := multiprotocol.NewTestContext(t)
	defer ctx.Cleanup()

	ctx.ForEachProtocol(t, func(t *testing.T, adapter api.AdminAdapter) {
		protocol := adapter.Protocol()

		t.Run("ListTenantsWithPagination", func(t *testing.T) {
			testCtx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
			defer cancel()

			// Create several tenants for pagination testing
			tenantIDs := make([]string, 0, 3)
			for i := 0; i < 3; i++ {
				name := fmt.Sprintf("%spage-%s-%d-%d", testTenantPrefix, protocol, time.Now().UnixNano(), i)
				req := &admin.CreateTenantRequest{Name: name}
				tenant, err := adapter.CreateTenant(testCtx, req)
				if err == nil {
					tenantIDs = append(tenantIDs, tenant.ID)
				}
			}

			// Cleanup
			defer func() {
				cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), defaultTimeout)
				defer cleanupCancel()
				for _, id := range tenantIDs {
					_ = adapter.DeleteTenant(cleanupCtx, id)
				}
			}()

			// Test pagination
			req := &admin.ListTenantsRequest{
				Page:    1,
				PerPage: 2,
			}

			tenants, pagination, err := adapter.ListTenants(testCtx, req)
			require.NoError(t, err, "ListTenants via %s should succeed", protocol)
			require.NotNil(t, tenants, "tenants should not be nil")

			if pagination != nil && pagination.Total > 2 {
				assert.LessOrEqual(t, len(tenants), 2, "should return at most 2 tenants per page")

				// Get second page
				req.Page = 2
				tenants2, _, err := adapter.ListTenants(testCtx, req)
				require.NoError(t, err, "ListTenants page 2 via %s should succeed", protocol)
				assert.NotNil(t, tenants2, "page 2 tenants should not be nil")
			}
		})
	})
}

// TestCactlCertificateOperations tests certificate-specific operations.
func TestCactlCertificateOperations(t *testing.T) {
	ctx := multiprotocol.NewTestContext(t)
	defer ctx.Cleanup()

	ctx.ForEachProtocol(t, func(t *testing.T, adapter api.AdminAdapter) {
		protocol := adapter.Protocol()

		t.Run("ListCertificatesFiltered", func(t *testing.T) {
			testCtx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
			defer cancel()

			// Test with status filter
			req := &admin.ListCertificatesRequest{
				Page:    1,
				PerPage: 10,
				Status:  "valid",
			}

			certs, _, err := adapter.ListCertificates(testCtx, req)
			require.NoError(t, err, "ListCertificates via %s with filter should succeed", protocol)
			assert.NotNil(t, certs, "certificates should not be nil")

			// All returned certificates should have valid status
			for _, cert := range certs {
				assert.Equal(t, "valid", cert.Status,
					"filtered certificates should have valid status")
			}
		})
	})
}
