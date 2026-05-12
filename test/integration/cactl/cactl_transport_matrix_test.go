// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

//go:build integration

// Package cactl provides full transport matrix integration tests for the cactl CLI.
//
// These tests exercise every cactl subcommand across ALL 5 supported protocols
// (REST, gRPC, QUIC, MCP, Unix) via subprocess execution of the cactl binary.
// Each test creates a fresh subprocess with the appropriate transport flags,
// ensuring the CLI binary works end-to-end over each protocol.
//
// Environment variables:
//   - CACTL_BINARY: Path to cactl binary (default: ./cactl)
//   - CACTL_REST_ADDR: REST server address (default: https://localhost:8443)
//   - CACTL_GRPC_ADDR: gRPC server address (default: localhost:9443)
//   - CACTL_QUIC_ADDR: QUIC server address (default: localhost:9444)
//   - CACTL_MCP_ADDR: MCP server address (default: localhost:9445)
//   - CACTL_UNIX_PATH: Unix socket path (default: /run/trusted-ca-grpc.sock)
//   - CACTL_TLS_CA: TLS CA certificate file
//   - CACTL_AUTH_TOKEN: Authentication token
//   - CACTL_TLS_INSECURE: Skip TLS verification (default: false)
package cactl

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/acme/admin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// transportProtocol defines a protocol transport configuration for CLI tests.
type transportProtocol struct {
	Name      string
	Transport string
	Address   string
}

// configuredProtocols returns the list of protocols configured via environment.
// Only protocols with configured addresses are included.
func configuredProtocols() []transportProtocol {
	type protocolDef struct {
		name      string
		transport string
		envKey    string
		fallback  string
	}

	defs := []protocolDef{
		{"REST", "rest", "CACTL_REST_ADDR", ""},
		{"gRPC", "grpc", "CACTL_GRPC_ADDR", ""},
		{"QUIC", "quic", "CACTL_QUIC_ADDR", ""},
		{"MCP", "mcp", "CACTL_MCP_ADDR", ""},
		{"Unix", "unix", "CACTL_UNIX_PATH", ""},
	}

	var protos []transportProtocol
	for _, d := range defs {
		addr := os.Getenv(d.envKey)
		if addr == "" {
			addr = d.fallback
		}
		if addr == "" {
			continue
		}
		protos = append(protos, transportProtocol{
			Name:      d.name,
			Transport: d.transport,
			Address:   addr,
		})
	}
	return protos
}

// matrixConfig creates a cactlConfig for a specific transport protocol.
func matrixConfig(proto transportProtocol) *cactlConfig {
	cfg := newCactlConfig()
	cfg.Transport = proto.Transport
	cfg.Address = proto.Address
	return cfg
}

// requireMatrixBinary locates the cactl binary or fatals.
func requireMatrixBinary(t *testing.T) {
	t.Helper()
	cfg := newCactlConfig()
	if err := findCactlBinary(cfg); err != nil {
		t.Fatalf("cactl binary not found: %v", err)
	}
}

// TestTransportMatrixStatus tests the status command across all protocols.
func TestTransportMatrixStatus(t *testing.T) {
	requireMatrixBinary(t)
	protos := configuredProtocols()
	if len(protos) == 0 {
		t.Fatal("no protocols configured for transport matrix tests")
	}

	for _, proto := range protos {
		t.Run(proto.Name, func(t *testing.T) {
			cfg := matrixConfig(proto)
			if err := findCactlBinary(cfg); err != nil {
				t.Fatalf("cactl binary not found: %v", err)
			}

			output := requireCactlSuccess(t, cfg, "status", "-o", "json")

			var status admin.CAStatus
			parseJSON(t, output, &status)

			assert.NotEmpty(t, status.Identity, "status should have identity via %s", proto.Name)
			assert.NotEmpty(t, status.Version, "status should have version via %s", proto.Name)
		})
	}
}

// TestTransportMatrixStats tests the stats command across all protocols.
func TestTransportMatrixStats(t *testing.T) {
	requireMatrixBinary(t)
	protos := configuredProtocols()
	if len(protos) == 0 {
		t.Fatal("no protocols configured for transport matrix tests")
	}

	for _, proto := range protos {
		t.Run(proto.Name, func(t *testing.T) {
			cfg := matrixConfig(proto)
			if err := findCactlBinary(cfg); err != nil {
				t.Fatalf("cactl binary not found: %v", err)
			}

			output := requireCactlSuccess(t, cfg, "stats", "-o", "json")

			var stats admin.CAStats
			parseJSON(t, output, &stats)

			assert.GreaterOrEqual(t, stats.TotalCertificates, 0,
				"total certificates should be >= 0 via %s", proto.Name)
			assert.GreaterOrEqual(t, stats.TotalAccounts, 0,
				"total accounts should be >= 0 via %s", proto.Name)
		})
	}
}

// TestTransportMatrixTenantLifecycle tests tenant CRUD across all protocols.
func TestTransportMatrixTenantLifecycle(t *testing.T) {
	requireMatrixBinary(t)
	protos := configuredProtocols()
	if len(protos) == 0 {
		t.Fatal("no protocols configured for transport matrix tests")
	}

	for _, proto := range protos {
		t.Run(proto.Name, func(t *testing.T) {
			cfg := matrixConfig(proto)
			if err := findCactlBinary(cfg); err != nil {
				t.Fatalf("cactl binary not found: %v", err)
			}

			tenantName := fmt.Sprintf("matrix-%s-%d", proto.Transport, time.Now().UnixNano())

			// Create tenant
			createOutput := requireCactlSuccess(t, cfg,
				"tenant", "create", "--name", tenantName, "-o", "json")

			var created admin.TenantInfo
			parseJSON(t, createOutput, &created)

			require.NotEmpty(t, created.ID, "created tenant should have ID via %s", proto.Name)
			assert.Equal(t, tenantName, created.Name, "tenant name should match via %s", proto.Name)

			tenantID := created.ID
			t.Cleanup(func() {
				cleanCfg := matrixConfig(proto)
				_ = findCactlBinary(cleanCfg)
				_, _ = runCactl(cleanCfg, "tenant", "delete", tenantID)
			})

			// Get tenant
			getOutput := requireCactlSuccess(t, cfg,
				"tenant", "get", tenantID, "-o", "json")

			var retrieved admin.TenantInfo
			parseJSON(t, getOutput, &retrieved)

			assert.Equal(t, tenantID, retrieved.ID, "retrieved tenant ID should match via %s", proto.Name)
			assert.Equal(t, tenantName, retrieved.Name, "retrieved tenant name should match via %s", proto.Name)

			// Update tenant
			updatedName := tenantName + "-updated"
			updateOutput := requireCactlSuccess(t, cfg,
				"tenant", "update", tenantID, "--name", updatedName, "-o", "json")

			var updated admin.TenantInfo
			parseJSON(t, updateOutput, &updated)

			assert.Equal(t, tenantID, updated.ID, "updated tenant ID should match via %s", proto.Name)
			assert.Equal(t, updatedName, updated.Name, "updated tenant name should match via %s", proto.Name)

			// List tenants
			listOutput := requireCactlSuccess(t, cfg,
				"tenant", "list", "--per-page", "500", "-o", "json")

			var tenants []*admin.TenantInfo
			parseJSON(t, listOutput, &tenants)

			found := false
			for _, tenant := range tenants {
				if tenant.ID == tenantID {
					found = true
					break
				}
			}
			assert.True(t, found, "created tenant should be in list via %s", proto.Name)

			// Delete tenant
			deleteOutput := requireCactlSuccess(t, cfg,
				"tenant", "delete", tenantID, "-o", "json")
			assert.Contains(t, deleteOutput, "success",
				"delete should report success via %s", proto.Name)

			// Verify deletion
			cactlErr := requireCactlFail(t, cfg, "tenant", "get", tenantID)
			combinedOutput := strings.ToLower(cactlErr.Stderr + cactlErr.Stdout)
			assert.True(t,
				strings.Contains(combinedOutput, "not found") ||
					strings.Contains(combinedOutput, "error"),
				"should report tenant not found via %s", proto.Name)
		})
	}
}

// TestTransportMatrixEABLifecycle tests EAB CRUD across all protocols.
func TestTransportMatrixEABLifecycle(t *testing.T) {
	requireMatrixBinary(t)
	protos := configuredProtocols()
	if len(protos) == 0 {
		t.Fatal("no protocols configured for transport matrix tests")
	}

	for _, proto := range protos {
		t.Run(proto.Name, func(t *testing.T) {
			cfg := matrixConfig(proto)
			if err := findCactlBinary(cfg); err != nil {
				t.Fatalf("cactl binary not found: %v", err)
			}

			// Create a tenant for EAB operations
			tenantName := fmt.Sprintf("matrix-eab-%s-%d", proto.Transport, time.Now().UnixNano())
			createTenantOut := requireCactlSuccess(t, cfg,
				"tenant", "create", "--name", tenantName, "-o", "json")

			var tenant admin.TenantInfo
			parseJSON(t, createTenantOut, &tenant)
			tenantID := tenant.ID

			t.Cleanup(func() {
				cleanCfg := matrixConfig(proto)
				_ = findCactlBinary(cleanCfg)
				_, _ = runCactl(cleanCfg, "tenant", "delete", tenantID)
			})

			// Create EAB
			createEABOut := requireCactlSuccess(t, cfg,
				"tenant", "eab", "create", tenantID, "-o", "json")

			var createdEAB admin.CreateEABResponse
			parseJSON(t, createEABOut, &createdEAB)

			require.NotEmpty(t, createdEAB.ID, "created EAB should have ID via %s", proto.Name)
			require.NotEmpty(t, createdEAB.MACKey, "created EAB should have MAC key via %s", proto.Name)
			kid := createdEAB.ID

			t.Cleanup(func() {
				cleanCfg := matrixConfig(proto)
				_ = findCactlBinary(cleanCfg)
				_, _ = runCactl(cleanCfg, "tenant", "eab", "delete", tenantID, "--", kid)
			})

			// Get EAB (put -o before positional args to prevent KIDs starting with - from being parsed as flags)
			getEABOut := requireCactlSuccess(t, cfg,
				"tenant", "eab", "get", "-o", "json", tenantID, kid)

			var retrievedEAB admin.EABInfo
			parseJSON(t, getEABOut, &retrievedEAB)

			assert.Equal(t, kid, retrievedEAB.ID, "retrieved EAB ID should match via %s", proto.Name)

			// List EABs
			listEABOut := requireCactlSuccess(t, cfg,
				"tenant", "eab", "list", tenantID, "--per-page", "100", "-o", "json")

			var eabs []*admin.EABInfo
			parseJSON(t, listEABOut, &eabs)

			found := false
			for _, eab := range eabs {
				if eab.ID == kid {
					found = true
					break
				}
			}
			assert.True(t, found, "created EAB should be in list via %s", proto.Name)

			// Delete EAB
			deleteEABOut := requireCactlSuccess(t, cfg,
				"tenant", "eab", "delete", tenantID, kid, "-o", "json")
			assert.Contains(t, deleteEABOut, "success",
				"EAB delete should report success via %s", proto.Name)
		})
	}
}

// TestTransportMatrixCertificateList tests certificate listing across all protocols.
func TestTransportMatrixCertificateList(t *testing.T) {
	requireMatrixBinary(t)
	protos := configuredProtocols()
	if len(protos) == 0 {
		t.Fatal("no protocols configured for transport matrix tests")
	}

	for _, proto := range protos {
		t.Run(proto.Name, func(t *testing.T) {
			cfg := matrixConfig(proto)
			if err := findCactlBinary(cfg); err != nil {
				t.Fatalf("cactl binary not found: %v", err)
			}

			output := requireCactlSuccess(t, cfg, "cert", "list", "-o", "json")

			var certs []*admin.CertificateInfo
			parseJSON(t, output, &certs)

			// A fresh server may have zero certificates - that's valid
			for _, cert := range certs {
				assert.NotEmpty(t, cert.SerialNumber, "cert should have serial via %s", proto.Name)
			}
		})
	}
}

// TestTransportMatrixCertificateListFiltered tests filtered certificate listing.
func TestTransportMatrixCertificateListFiltered(t *testing.T) {
	requireMatrixBinary(t)
	protos := configuredProtocols()
	if len(protos) == 0 {
		t.Fatal("no protocols configured for transport matrix tests")
	}

	for _, proto := range protos {
		t.Run(proto.Name+"/status-valid", func(t *testing.T) {
			cfg := matrixConfig(proto)
			if err := findCactlBinary(cfg); err != nil {
				t.Fatalf("cactl binary not found: %v", err)
			}

			output, err := runCactl(cfg,
				"cert", "list", "--status", "valid", "-o", "json")
			if err != nil {
				if cactlErr, ok := err.(*CactlError); ok {
					combined := cactlErr.Stderr + cactlErr.Stdout
					if strings.Contains(combined, "QueryIndex") || strings.Contains(combined, "not support") {
						t.Logf("filtered queries not supported via %s (expected for remote transports)", proto.Name)
						return
					}
				}
				t.Fatalf("cert list --status valid failed via %s: %v", proto.Name, err)
			}

			var certs []*admin.CertificateInfo
			parseJSON(t, output, &certs)

			for _, cert := range certs {
				assert.Equal(t, "valid", cert.Status,
					"filtered certs should have valid status via %s", proto.Name)
			}
		})

		t.Run(proto.Name+"/status-revoked", func(t *testing.T) {
			cfg := matrixConfig(proto)
			if err := findCactlBinary(cfg); err != nil {
				t.Fatalf("cactl binary not found: %v", err)
			}

			output, err := runCactl(cfg,
				"cert", "list", "--status", "revoked", "-o", "json")
			if err != nil {
				if cactlErr, ok := err.(*CactlError); ok {
					combined := cactlErr.Stderr + cactlErr.Stdout
					if strings.Contains(combined, "QueryIndex") || strings.Contains(combined, "not support") {
						t.Logf("filtered queries not supported via %s (expected for remote transports)", proto.Name)
						return
					}
				}
				t.Fatalf("cert list --status revoked failed via %s: %v", proto.Name, err)
			}

			var certs []*admin.CertificateInfo
			parseJSON(t, output, &certs)

			for _, cert := range certs {
				assert.Equal(t, "revoked", cert.Status,
					"filtered certs should have revoked status via %s", proto.Name)
			}
		})
	}
}

// TestTransportMatrixAccountList tests account listing across all protocols.
func TestTransportMatrixAccountList(t *testing.T) {
	requireMatrixBinary(t)
	protos := configuredProtocols()
	if len(protos) == 0 {
		t.Fatal("no protocols configured for transport matrix tests")
	}

	for _, proto := range protos {
		t.Run(proto.Name, func(t *testing.T) {
			cfg := matrixConfig(proto)
			if err := findCactlBinary(cfg); err != nil {
				t.Fatalf("cactl binary not found: %v", err)
			}

			output, err := runCactl(cfg, "account", "list", "-o", "json")
			if err != nil {
				if cactlErr, ok := err.(*CactlError); ok {
					if strings.Contains(cactlErr.Stderr, "not yet implemented") {
						t.Fatalf("account list not implemented for %s", proto.Name)
					}
				}
				t.Fatalf("account list failed via %s: %v", proto.Name, err)
			}

			assert.NotEmpty(t, output, "account list should return output via %s", proto.Name)
			assert.True(t, output[0] == '[' || output[0] == 'n',
				"output should be JSON array or null via %s", proto.Name)
		})
	}
}

// TestTransportMatrixAccountGetNonexistent tests getting nonexistent accounts.
func TestTransportMatrixAccountGetNonexistent(t *testing.T) {
	requireMatrixBinary(t)
	protos := configuredProtocols()
	if len(protos) == 0 {
		t.Fatal("no protocols configured for transport matrix tests")
	}

	for _, proto := range protos {
		t.Run(proto.Name, func(t *testing.T) {
			cfg := matrixConfig(proto)
			if err := findCactlBinary(cfg); err != nil {
				t.Fatalf("cactl binary not found: %v", err)
			}

			cactlErr := requireCactlFail(t, cfg, "account", "get", "9999999999")
			assert.True(t, len(cactlErr.Stderr) > 0 || len(cactlErr.Stdout) > 0,
				"should have error output for nonexistent account via %s", proto.Name)
		})
	}
}

// TestTransportMatrixOutputFormats tests all output formats across all protocols.
func TestTransportMatrixOutputFormats(t *testing.T) {
	requireMatrixBinary(t)
	protos := configuredProtocols()
	if len(protos) == 0 {
		t.Fatal("no protocols configured for transport matrix tests")
	}

	formats := []struct {
		name     string
		flag     string
		validate func(t *testing.T, output, proto string)
	}{
		{
			name: "JSON",
			flag: "json",
			validate: func(t *testing.T, output, proto string) {
				t.Helper()
				var result map[string]interface{}
				err := json.Unmarshal([]byte(output), &result)
				assert.NoError(t, err, "JSON output should be valid via %s", proto)
			},
		},
		{
			name: "Table",
			flag: "table",
			validate: func(t *testing.T, output, proto string) {
				t.Helper()
				assert.NotEmpty(t, output, "table output should not be empty via %s", proto)
			},
		},
		{
			name: "YAML",
			flag: "yaml",
			validate: func(t *testing.T, output, proto string) {
				t.Helper()
				assert.Contains(t, output, ":", "YAML output should contain colons via %s", proto)
			},
		},
	}

	for _, proto := range protos {
		for _, format := range formats {
			testName := fmt.Sprintf("%s/%s", proto.Name, format.name)
			t.Run(testName, func(t *testing.T) {
				cfg := matrixConfig(proto)
				if err := findCactlBinary(cfg); err != nil {
					t.Fatalf("cactl binary not found: %v", err)
				}

				output := requireCactlSuccess(t, cfg, "status", "-o", format.flag)
				format.validate(t, output, proto.Name)
			})
		}
	}
}

// TestTransportMatrixInvalidTransport tests error handling for invalid transport.
func TestTransportMatrixInvalidTransport(t *testing.T) {
	cfg := newCactlConfig()
	if err := findCactlBinary(cfg); err != nil {
		t.Fatalf("cactl binary not found: %v", err)
	}

	badCfg := &cactlConfig{
		Binary:    cfg.Binary,
		Transport: "bogus-transport",
		Address:   "localhost:1234",
		Timeout:   10 * time.Second,
	}

	cactlErr := requireCactlFail(t, badCfg, "status")
	assert.True(t, len(cactlErr.Stderr) > 0 || len(cactlErr.Stdout) > 0,
		"should have error output for invalid transport")
}

// TestTransportMatrixTenantGetNonexistent tests getting nonexistent tenants.
func TestTransportMatrixTenantGetNonexistent(t *testing.T) {
	requireMatrixBinary(t)
	protos := configuredProtocols()
	if len(protos) == 0 {
		t.Fatal("no protocols configured for transport matrix tests")
	}

	for _, proto := range protos {
		t.Run(proto.Name, func(t *testing.T) {
			cfg := matrixConfig(proto)
			if err := findCactlBinary(cfg); err != nil {
				t.Fatalf("cactl binary not found: %v", err)
			}

			cactlErr := requireCactlFail(t, cfg, "tenant", "get", "nonexistent-id-99999")
			combinedOutput := strings.ToLower(cactlErr.Stderr + cactlErr.Stdout)
			assert.True(t,
				strings.Contains(combinedOutput, "not found") ||
					strings.Contains(combinedOutput, "error") ||
					strings.Contains(combinedOutput, "failed"),
				"should report error for nonexistent tenant via %s, got: %s",
				proto.Name, combinedOutput)
		})
	}
}

// TestTransportMatrixTenantCreateMissingName tests creating tenant without name.
func TestTransportMatrixTenantCreateMissingName(t *testing.T) {
	requireMatrixBinary(t)
	protos := configuredProtocols()
	if len(protos) == 0 {
		t.Fatal("no protocols configured for transport matrix tests")
	}

	for _, proto := range protos {
		t.Run(proto.Name, func(t *testing.T) {
			cfg := matrixConfig(proto)
			if err := findCactlBinary(cfg); err != nil {
				t.Fatalf("cactl binary not found: %v", err)
			}

			// Creating tenant without --name should fail
			cactlErr := requireCactlFail(t, cfg, "tenant", "create")
			assert.True(t, len(cactlErr.Stderr) > 0 || len(cactlErr.Stdout) > 0,
				"should have error output for missing tenant name via %s", proto.Name)
		})
	}
}

// TestTransportMatrixOutputFormatConsistency verifies that the same data is
// returned regardless of protocol. Creates a tenant on one protocol,
// reads it on all others.
func TestTransportMatrixOutputFormatConsistency(t *testing.T) {
	requireMatrixBinary(t)
	protos := configuredProtocols()
	if len(protos) < 2 {
		t.Skip("need at least 2 protocols to test cross-protocol consistency")
	}

	// Create tenant on first protocol
	firstCfg := matrixConfig(protos[0])
	if err := findCactlBinary(firstCfg); err != nil {
		t.Fatalf("cactl binary not found: %v", err)
	}

	tenantName := fmt.Sprintf("matrix-consistency-%d", time.Now().UnixNano())
	createOut := requireCactlSuccess(t, firstCfg,
		"tenant", "create", "--name", tenantName, "-o", "json")

	var created admin.TenantInfo
	parseJSON(t, createOut, &created)
	tenantID := created.ID

	t.Cleanup(func() {
		cleanCfg := matrixConfig(protos[0])
		_ = findCactlBinary(cleanCfg)
		_, _ = runCactl(cleanCfg, "tenant", "delete", tenantID)
	})

	// Verify all protocols can read the same tenant
	for _, proto := range protos {
		t.Run(proto.Name, func(t *testing.T) {
			cfg := matrixConfig(proto)
			if err := findCactlBinary(cfg); err != nil {
				t.Fatalf("cactl binary not found: %v", err)
			}

			getOut := requireCactlSuccess(t, cfg,
				"tenant", "get", tenantID, "-o", "json")

			var retrieved admin.TenantInfo
			parseJSON(t, getOut, &retrieved)

			assert.Equal(t, tenantID, retrieved.ID,
				"tenant ID should match via %s", proto.Name)
			assert.Equal(t, tenantName, retrieved.Name,
				"tenant name should match via %s", proto.Name)
		})
	}
}
