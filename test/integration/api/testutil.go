// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

//go:build integration

package integration

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestConfig holds configuration for integration tests
type TestConfig struct {
	// CLI configuration
	CLIBinPath string

	// REST API configuration
	RESTBaseURL string

	// gRPC configuration
	GRPCAddr string

	// QUIC/HTTP3 configuration
	QUICBaseURL string

	// MCP configuration
	MCPAddr string
}

// LoadTestConfig loads test configuration from environment or defaults
func LoadTestConfig() *TestConfig {
	cfg := &TestConfig{
		CLIBinPath:  getEnv("KEYSTORE_CLI_BIN", "./bin/keychain"),
		RESTBaseURL: getEnv("KEYSTORE_REST_URL", "http://localhost:8443"),
		GRPCAddr:    getEnv("KEYSTORE_GRPC_ADDR", "localhost:9443"),
		QUICBaseURL: getEnv("KEYSTORE_QUIC_URL", "https://localhost:9445"),
		MCPAddr:     getEnv("KEYSTORE_MCP_ADDR", "localhost:9444"),
	}
	return cfg
}

// getEnv gets environment variable with fallback default
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// isCLIAvailable checks if the CLI binary is available
func isCLIAvailable(t *testing.T, cfg *TestConfig) bool {
	t.Helper()

	// Check if binary exists
	if _, err := os.Stat(cfg.CLIBinPath); os.IsNotExist(err) {
		return false
	}

	// Try to execute version command
	cmd := exec.Command(cfg.CLIBinPath, "version")
	if err := cmd.Run(); err != nil {
		return false
	}

	return true
}

// isServerAvailable checks if the REST server is available
func isServerAvailable(t *testing.T, cfg *TestConfig) bool {
	t.Helper()

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(cfg.RESTBaseURL + "/health")
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}

// isGRPCServerAvailable checks if the gRPC server is available
func isGRPCServerAvailable(t *testing.T, cfg *TestConfig) bool {
	t.Helper()

	conn, err := net.DialTimeout("tcp", cfg.GRPCAddr, 2*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()

	return true
}

// generateUniqueID generates a unique identifier for test resources
func generateUniqueID(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
}

// assertNoError fails the test if err is not nil
func assertNoError(t *testing.T, err error, msg string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", msg, err)
	}
}

// assertError fails the test if err is nil
func assertError(t *testing.T, err error, msg string) {
	t.Helper()
	if err == nil {
		t.Fatal(msg)
	}
}

// assertContains fails the test if s does not contain substr
func assertContains(t *testing.T, s, substr, msg string) {
	t.Helper()
	if !strings.Contains(s, substr) {
		t.Fatalf("%s: '%s' does not contain '%s'", msg, s, substr)
	}
}

// assertEqual fails the test if expected != actual
func assertEqual(t *testing.T, expected, actual interface{}, msg string) {
	t.Helper()
	if expected != actual {
		t.Fatalf("%s: expected %v, got %v", msg, expected, actual)
	}
}

// assertNotEmpty fails the test if s is empty
func assertNotEmpty(t *testing.T, s string, msg string) {
	t.Helper()
	if s == "" {
		t.Fatal(msg)
	}
}

// assertNotNil fails the test if v is nil
func assertNotNil(t *testing.T, v interface{}, msg string) {
	t.Helper()
	if v == nil {
		t.Fatal(msg)
	}
}
