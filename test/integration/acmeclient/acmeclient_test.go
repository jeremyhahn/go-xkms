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

// Package acmeclient_test provides integration tests for the trusted-acme-client CLI.
//
// These tests exercise the ACME client binary via subprocess execution against
// a real ACME server running in Docker. They cover:
//   - Account management (add, list, show, remove)
//   - Certificate request with various challenge types
//   - Certificate renewal
//   - Certificate revocation
//   - Certificate listing, showing, and deployment
//   - Auto-renewal service startup/shutdown
//   - Error handling and edge cases
//
// Environment variables:
//   - ACME_CLIENT_BIN: Path to trusted-acme-client binary
//   - ACME_SERVER_URL: ACME directory URL
//   - ACME_TEST_EMAIL: Test email for account registration
//   - ACME_TEST_DOMAIN: Test domain for certificate requests
package acmeclient_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const (
	defaultACMEClientBin = "trusted-acme-client"
	defaultServerURL     = "https://localhost:8443/directory"
	defaultTestEmail     = "integration-test@example.com"
	defaultTestDomain    = "test.example.com"
	defaultTimeout       = 60 * time.Second

	defaultAccountName = "test-ca"
	defaultCertName    = "test-cert"
)

// acmeClientConfig holds configuration for the ACME client binary execution.
type acmeClientConfig struct {
	Binary     string
	ServerURL  string
	Email      string
	Domain     string
	ConfigPath string
	Timeout    time.Duration
}

// newACMEClientConfig creates a new ACME client configuration from environment variables.
func newACMEClientConfig() *acmeClientConfig {
	return &acmeClientConfig{
		Binary:    envOr("ACME_CLIENT_BIN", defaultACMEClientBin),
		ServerURL: envOr("ACME_SERVER_URL", defaultServerURL),
		Email:     envOr("ACME_TEST_EMAIL", defaultTestEmail),
		Domain:    envOr("ACME_TEST_DOMAIN", defaultTestDomain),
		Timeout:   defaultTimeout,
	}
}

// envOr returns the environment variable value or a default.
func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// createTestConfigEmpty creates a temporary config YAML file with no accounts or certificates.
// Use this for "account add" tests where the test itself adds the account.
func createTestConfigEmpty(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	configPath := filepath.Join(dir, "test-config.yaml")
	config := fmt.Sprintf(`
storage:
  backend: filesystem
  options:
    path: %s/storage
xkms:
  backend: software
  options:
    path: %s/keys
logging:
  level: debug
  format: text
  output: stdout
`, dir, dir)
	err := os.WriteFile(configPath, []byte(config), 0644)
	require.NoError(t, err)
	return configPath
}

// createTestConfig creates a temporary config YAML file for CLI tests and returns the path.
// The config includes a pre-defined "test-ca" account and "test-cert" certificate spec.
func createTestConfig(t *testing.T, serverURL, email string) string {
	t.Helper()
	dir := t.TempDir()
	configPath := filepath.Join(dir, "test-config.yaml")
	config := fmt.Sprintf(`
storage:
  backend: filesystem
  options:
    path: %s/storage
xkms:
  backend: software
  options:
    path: %s/keys
logging:
  level: debug
  format: text
  output: stdout
accounts:
  test-ca:
    directory: %s
    email: %s
    request_server_bundle: true
    key:
      algorithm: ECDSA
      store: software
      ecc:
        curve: P-256
certificates:
  test-cert:
    account: test-ca
    subject:
      cn: %s
    key:
      algorithm: ECDSA
      store: software
      ecc:
        curve: P-256
    challenge: http-01
`, dir, dir, serverURL, email, envOr("ACME_TEST_DOMAIN", defaultTestDomain))
	err := os.WriteFile(configPath, []byte(config), 0644)
	require.NoError(t, err)
	return configPath
}

// createTestConfigWithCert creates a config with a custom certificate spec.
func createTestConfigWithCert(t *testing.T, serverURL, email, certName, domain, challenge string) string {
	t.Helper()
	dir := t.TempDir()
	configPath := filepath.Join(dir, "test-config.yaml")
	config := fmt.Sprintf(`
storage:
  backend: filesystem
  options:
    path: %s/storage
xkms:
  backend: software
  options:
    path: %s/keys
logging:
  level: debug
  format: text
  output: stdout
accounts:
  test-ca:
    directory: %s
    email: %s
    request_server_bundle: true
    key:
      algorithm: ECDSA
      store: software
      ecc:
        curve: P-256
certificates:
  %s:
    account: test-ca
    subject:
      cn: %s
    key:
      algorithm: ECDSA
      store: software
      ecc:
        curve: P-256
    challenge: %s
`, dir, dir, serverURL, email, certName, domain, challenge)
	err := os.WriteFile(configPath, []byte(config), 0644)
	require.NoError(t, err)
	return configPath
}

// createTestConfigWithKeySpec creates a config with a custom key specification for a certificate.
func createTestConfigWithKeySpec(t *testing.T, serverURL, email, certName, domain, keyAlgo, keyCurve string, keySize int) string {
	t.Helper()
	dir := t.TempDir()
	configPath := filepath.Join(dir, "test-config.yaml")

	var keyBlock string
	if keyAlgo == "RSA" {
		keyBlock = fmt.Sprintf(`    key:
      algorithm: RSA
      store: software
      rsa:
        size: %d`, keySize)
	} else {
		keyBlock = fmt.Sprintf(`    key:
      algorithm: ECDSA
      store: software
      ecc:
        curve: %s`, keyCurve)
	}

	config := fmt.Sprintf(`
storage:
  backend: filesystem
  options:
    path: %s/storage
xkms:
  backend: software
  options:
    path: %s/keys
logging:
  level: debug
  format: text
  output: stdout
accounts:
  test-ca:
    directory: %s
    email: %s
    key:
      algorithm: ECDSA
      store: software
      ecc:
        curve: P-256
certificates:
  %s:
    account: test-ca
    subject:
      cn: %s
%s
    challenge: http-01
`, dir, dir, serverURL, email, certName, domain, keyBlock)
	err := os.WriteFile(configPath, []byte(config), 0644)
	require.NoError(t, err)
	return configPath
}

// runACMEClient executes the trusted-acme-client binary and returns stdout, stderr, error.
func runACMEClient(t *testing.T, cfg *acmeClientConfig, args ...string) (string, string, error) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	fullArgs := buildACMEClientArgs(cfg, args...)
	cmd := exec.CommandContext(ctx, cfg.Binary, fullArgs...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Inherit environment
	cmd.Env = os.Environ()

	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

// buildACMEClientArgs constructs the full argument list for the ACME client.
func buildACMEClientArgs(cfg *acmeClientConfig, args ...string) []string {
	var fullArgs []string

	// Add config file path
	if cfg.ConfigPath != "" {
		fullArgs = append(fullArgs, "--config", cfg.ConfigPath)
	}

	// Append command-specific arguments
	fullArgs = append(fullArgs, args...)

	return fullArgs
}

// requireACMEClientSuccess executes the ACME client and requires success.
func requireACMEClientSuccess(t *testing.T, cfg *acmeClientConfig, args ...string) string {
	t.Helper()
	stdout, stderr, err := runACMEClient(t, cfg, args...)
	if err != nil {
		t.Fatalf("trusted-acme-client failed: %v\nstdout: %s\nstderr: %s\nargs: %v",
			err, stdout, stderr, args)
	}
	return stdout
}

// requireACMEClientFail executes the ACME client and requires failure.
func requireACMEClientFail(t *testing.T, cfg *acmeClientConfig, args ...string) (string, string) {
	t.Helper()
	stdout, stderr, err := runACMEClient(t, cfg, args...)
	if err == nil {
		t.Fatalf("expected trusted-acme-client to fail, but it succeeded\nstdout: %s\nstderr: %s",
			stdout, stderr)
	}
	return stdout, stderr
}

// findACMEClientBinary locates the trusted-acme-client binary.
func findACMEClientBinary(cfg *acmeClientConfig) error {
	possiblePaths := []string{
		cfg.Binary,
		"./trusted-acme-client",
		"../../../bin/trusted-acme-client",
		"/usr/local/bin/trusted-acme-client",
		"/workspace/go-xkms/bin/trusted-acme-client",
	}

	for _, p := range possiblePaths {
		absPath, err := filepath.Abs(p)
		if err != nil {
			continue
		}
		if _, err := os.Stat(absPath); err == nil {
			cfg.Binary = absPath
			return nil
		}
	}

	return &binaryNotFoundError{binary: "trusted-acme-client"}
}

// binaryNotFoundError indicates the CLI binary was not found.
type binaryNotFoundError struct {
	binary string
}

// Error implements the error interface.
func (e *binaryNotFoundError) Error() string {
	return e.binary + " binary not found in common locations"
}

// requireBinary locates the ACME client binary or fatals.
func requireBinary(t *testing.T, cfg *acmeClientConfig) {
	t.Helper()
	if err := findACMEClientBinary(cfg); err != nil {
		t.Fatalf("trusted-acme-client binary not found: %v - run 'make build' first", err)
	}
}
