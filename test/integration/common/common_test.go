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
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"
)

// TestConfig holds configuration for integration tests
type TestConfig struct {
	RESTBaseURL  string
	GRPCAddr     string
	QUICBaseURL  string
	CLIBinPath   string
	MCPAddr      string
	Timeout      time.Duration
	SkipSetup    bool
	SkipTeardown bool
}

// LoadTestConfig loads test configuration from environment variables
func LoadTestConfig() *TestConfig {
	timeout := 30 * time.Second
	if t := os.Getenv("INTEGRATION_TIMEOUT"); t != "" {
		if d, err := time.ParseDuration(t); err == nil {
			timeout = d
		}
	}

	return &TestConfig{
		RESTBaseURL:  getEnvOrDefault("KEYSTORE_REST_URL", "http://localhost:8443"),
		GRPCAddr:     getEnvOrDefault("KEYSTORE_GRPC_ADDR", "localhost:9443"),
		QUICBaseURL:  getEnvOrDefault("KEYSTORE_QUIC_URL", "https://localhost:8444"),
		CLIBinPath:   getEnvOrDefault("KEYSTORE_CLI_BIN", "../../build/bin/keystore"),
		MCPAddr:      getEnvOrDefault("KEYSTORE_MCP_ADDR", "localhost:9444"),
		Timeout:      timeout,
		SkipSetup:    os.Getenv("SKIP_SETUP") == "true",
		SkipTeardown: os.Getenv("SKIP_TEARDOWN") == "true",
	}
}

// getEnvOrDefault returns environment variable value or default
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// waitForServer waits for the server to become available
func waitForServer(t *testing.T, cfg *TestConfig) bool {
	t.Helper()

	deadline := time.Now().Add(cfg.Timeout)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for time.Now().Before(deadline) {
		// Try REST endpoint
		client := &http.Client{Timeout: 2 * time.Second}
		resp, err := client.Get(cfg.RESTBaseURL + "/health")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				t.Logf("Server is ready (REST)")
				return true
			}
		}

		<-ticker.C
	}

	return false
}

// waitForGRPCServer waits for gRPC server to become available
func waitForGRPCServer(t *testing.T, cfg *TestConfig) bool {
	t.Helper()

	deadline := time.Now().Add(cfg.Timeout)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for time.Now().Before(deadline) {
		conn, err := grpc.NewClient(cfg.GRPCAddr,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
		if err == nil {
			defer conn.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			healthClient := grpc_health_v1.NewHealthClient(conn)
			_, err := healthClient.Check(ctx, &grpc_health_v1.HealthCheckRequest{})
			if err == nil {
				t.Logf("gRPC server is ready")
				return true
			}
		}

		<-ticker.C
	}

	return false
}

// isServerAvailable checks if the keychain server is available
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

// isGRPCServerAvailable checks if gRPC server is available
func isGRPCServerAvailable(t *testing.T, cfg *TestConfig) bool {
	t.Helper()

	conn, err := grpc.NewClient(cfg.GRPCAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return false
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	healthClient := grpc_health_v1.NewHealthClient(conn)
	_, err = healthClient.Check(ctx, &grpc_health_v1.HealthCheckRequest{})

	return err == nil
}

// isCLIAvailable checks if CLI binary is available
func isCLIAvailable(t *testing.T, cfg *TestConfig) bool {
	t.Helper()

	_, err := os.Stat(cfg.CLIBinPath)
	return err == nil
}

// generateUniqueID generates a unique identifier for test resources
func generateUniqueID(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
}

// assertNoError fails the test if error is not nil
func assertNoError(t *testing.T, err error, format string, args ...interface{}) {
	t.Helper()
	if err != nil {
		t.Fatalf(format+": %v", append(args, err)...)
	}
}

// assertError fails the test if error is nil
func assertError(t *testing.T, err error, format string, args ...interface{}) {
	t.Helper()
	if err == nil {
		t.Fatalf(format, args...)
	}
}

// assertEqual fails the test if expected != actual
func assertEqual(t *testing.T, expected, actual interface{}, format string, args ...interface{}) {
	t.Helper()
	if expected != actual {
		t.Fatalf(format+": expected %v, got %v", append(args, expected, actual)...)
	}
}

// assertNotEmpty fails the test if value is empty string
func assertNotEmpty(t *testing.T, value string, format string, args ...interface{}) {
	t.Helper()
	if value == "" {
		t.Fatalf(format, args...)
	}
}

// assertContains fails the test if haystack doesn't contain needle
func assertContains(t *testing.T, haystack, needle string, format string, args ...interface{}) {
	t.Helper()
	if haystack == "" || needle == "" {
		t.Fatalf(format+": empty string", args...)
	}
	// Simple contains check
	found := false
	for i := 0; i <= len(haystack)-len(needle); i++ {
		if haystack[i:i+len(needle)] == needle {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf(format+": %q not found in %q", append(args, needle, haystack)...)
	}
}

// getAvailablePort finds an available TCP port
func getAvailablePort() (int, error) {
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		return 0, err
	}

	listener, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return 0, err
	}
	defer listener.Close()

	return listener.Addr().(*net.TCPAddr).Port, nil
}

// retryOperation retries an operation with exponential backoff
func retryOperation(maxRetries int, operation func() error) error {
	var err error
	for i := 0; i < maxRetries; i++ {
		err = operation()
		if err == nil {
			return nil
		}
		time.Sleep(time.Duration(1<<uint(i)) * 100 * time.Millisecond)
	}
	return err
}

// cleanupKeys removes test keys created during tests
type cleanupFunc func()

// testCleanup stores cleanup functions
var testCleanups []cleanupFunc

// registerCleanup registers a cleanup function to be called after tests
func registerCleanup(fn cleanupFunc) {
	testCleanups = append(testCleanups, fn)
}

// runCleanups executes all registered cleanup functions
func runCleanups() {
	for _, fn := range testCleanups {
		fn()
	}
	testCleanups = nil
}
