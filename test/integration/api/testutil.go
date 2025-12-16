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
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestConfig holds configuration for integration tests
type TestConfig struct {
	// CLI configuration
	CLIBinPath string

	// Unix socket configuration
	UnixSocketPath string

	// REST API configuration
	RESTBaseURL string

	// gRPC configuration
	GRPCAddr string

	// QUIC/HTTP3 configuration
	QUICBaseURL string

	// MCP configuration
	MCPAddr string
}

// getProjectRoot returns the project root directory by walking up from the test file location
func getProjectRoot() string {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		return ""
	}
	// This file is in test/integration/api/, so go up 3 levels
	return filepath.Join(filepath.Dir(filename), "..", "..", "..")
}

// LoadTestConfig loads test configuration from environment or defaults
func LoadTestConfig() *TestConfig {
	projectRoot := getProjectRoot()
	defaultCLIPath := filepath.Join(projectRoot, "build", "bin", "keychain")

	cfg := &TestConfig{
		CLIBinPath:     getEnv("KEYSTORE_CLI_BIN", defaultCLIPath),
		UnixSocketPath: getEnv("KEYSTORE_UNIX_SOCKET", "/var/run/keychain/keychain.sock"),
		RESTBaseURL:    getEnv("KEYSTORE_REST_URL", "http://localhost:8443"),
		GRPCAddr:       getEnv("KEYSTORE_GRPC_ADDR", "localhost:9443"),
		QUICBaseURL:    getEnv("KEYSTORE_QUIC_URL", "https://localhost:9445"),
		MCPAddr:        getEnv("KEYSTORE_MCP_ADDR", "localhost:9444"),
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

// assertErrorIs fails the test if err does not wrap the target error
func assertErrorIs(t *testing.T, err, target error, msg string) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("%s: expected error %v, got %v", msg, target, err)
	}
}

// assertLen fails the test if the length of v does not match expected
func assertLen(t *testing.T, v interface{}, expected int, msg string) {
	t.Helper()
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Slice && rv.Kind() != reflect.Array && rv.Kind() != reflect.Map && rv.Kind() != reflect.String {
		t.Fatalf("%s: cannot determine length of %T", msg, v)
	}
	actual := rv.Len()
	if actual != expected {
		t.Fatalf("%s: expected length %d, got %d", msg, expected, actual)
	}
}

// assertGreaterThan fails the test if actual <= expected
func assertGreaterThan(t *testing.T, actual, expected int, msg string) {
	t.Helper()
	if actual <= expected {
		t.Fatalf("%s: expected > %d, got %d", msg, expected, actual)
	}
}

// assertTrue fails the test if condition is false
func assertTrue(t *testing.T, condition bool, msg string) {
	t.Helper()
	if !condition {
		t.Fatal(msg)
	}
}

// assertFalse fails the test if condition is true
func assertFalse(t *testing.T, condition bool, msg string) {
	t.Helper()
	if condition {
		t.Fatal(msg)
	}
}

// isUnixSocketAvailable checks if the Unix socket server is available
func isUnixSocketAvailable(t *testing.T, cfg *TestConfig) bool {
	t.Helper()

	// Check if socket file exists
	if _, err := os.Stat(cfg.UnixSocketPath); os.IsNotExist(err) {
		return false
	}

	// Try to connect
	conn, err := net.DialTimeout("unix", cfg.UnixSocketPath, 2*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()

	return true
}

// ProtocolType represents the communication protocol for tests
type ProtocolType string

const (
	// ProtocolUnix uses Unix domain socket
	ProtocolUnix ProtocolType = "unix"
	// ProtocolREST uses HTTP/HTTPS
	ProtocolREST ProtocolType = "rest"
	// ProtocolGRPC uses gRPC
	ProtocolGRPC ProtocolType = "grpc"
	// ProtocolQUIC uses HTTP/3 over QUIC
	ProtocolQUIC ProtocolType = "quic"
)

// GetServerURL returns the server URL for the specified protocol
func (cfg *TestConfig) GetServerURL(protocol ProtocolType) string {
	switch protocol {
	case ProtocolUnix:
		return "unix://" + cfg.UnixSocketPath
	case ProtocolREST:
		return cfg.RESTBaseURL
	case ProtocolGRPC:
		return "grpc://" + cfg.GRPCAddr
	case ProtocolQUIC:
		return "quic://" + strings.TrimPrefix(strings.TrimPrefix(cfg.QUICBaseURL, "https://"), "http://")
	default:
		return ""
	}
}

// IsProtocolAvailable checks if the specified protocol server is available
func (cfg *TestConfig) IsProtocolAvailable(t *testing.T, protocol ProtocolType) bool {
	t.Helper()

	switch protocol {
	case ProtocolUnix:
		return isUnixSocketAvailable(t, cfg)
	case ProtocolREST:
		return isServerAvailable(t, cfg)
	case ProtocolGRPC:
		return isGRPCServerAvailable(t, cfg)
	case ProtocolQUIC:
		// QUIC is known to fail in Docker due to UDP buffer size limitations
		// Skip QUIC tests when running in Docker (detected by DOCKER_ENV or container detection)
		if os.Getenv("DOCKER_ENV") != "" || isRunningInDocker() {
			t.Log("Skipping QUIC: Docker environment detected (UDP buffer limitations)")
			return false
		}
		// QUIC availability check - use HTTP client to check QUIC health endpoint
		// UDP dial alone is insufficient since UDP is connectionless
		// We use insecure TLS for testing as the server may use self-signed certs
		client := &http.Client{
			Timeout: 2 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}
		resp, err := client.Get(cfg.QUICBaseURL + "/health")
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	default:
		return false
	}
}

// isRunningInDocker detects if the current process is running inside a Docker container
func isRunningInDocker() bool {
	// Check for /.dockerenv file
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	// Check for docker in /proc/1/cgroup
	if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		if strings.Contains(string(data), "docker") || strings.Contains(string(data), "kubepods") {
			return true
		}
	}
	// Check for container hostname pattern
	if hostname, err := os.Hostname(); err == nil {
		// Docker containers often have 12-char hex hostnames
		if len(hostname) == 12 && isHexString(hostname) {
			return true
		}
	}
	return false
}

// isHexString checks if a string contains only hexadecimal characters
func isHexString(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
