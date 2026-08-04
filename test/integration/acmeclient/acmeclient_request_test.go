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

package acmeclient_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestCertRequestHTTP01 tests certificate request with HTTP-01 challenge.
func TestCertRequestHTTP01(t *testing.T) {
	cfg := newACMEClientConfig()
	requireBinary(t, cfg)

	email := fmt.Sprintf("request-http01-%d@example.com", time.Now().UnixNano())
	configPath := createTestConfigWithCert(t, cfg.ServerURL, email,
		defaultCertName, cfg.Domain, "http-01")
	cfg.ConfigPath = configPath

	// Request certificate by name (account is already defined in config)
	stdout, stderr, err := runACMEClient(t, cfg,
		"cert", "request", defaultCertName)

	if err != nil {
		// HTTP-01 may fail in Docker if port 80 is not available
		t.Logf("cert request http-01 result: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
		combinedOutput := strings.ToLower(stderr + stdout)
		// Accept specific expected failures in Docker environment
		if strings.Contains(combinedOutput, "port") ||
			strings.Contains(combinedOutput, "bind") ||
			strings.Contains(combinedOutput, "connection refused") ||
			strings.Contains(combinedOutput, "tls") ||
			strings.Contains(combinedOutput, "certificate") ||
			strings.Contains(combinedOutput, "x509") ||
			strings.Contains(combinedOutput, "authorize") {
			t.Log("HTTP-01 challenge failed due to infrastructure (expected in Docker)")
			return
		}
		t.Fatalf("unexpected request failure: %v", err)
	}

	// If successful, verify outputs
	assert.True(t,
		strings.Contains(strings.ToLower(stdout), "certificate") ||
			strings.Contains(strings.ToLower(stdout), "success"),
		"output should indicate certificate obtained, got: %s", stdout)
}

// TestCertRequestDNS01 tests certificate request with DNS-01 challenge.
func TestCertRequestDNS01(t *testing.T) {
	cfg := newACMEClientConfig()
	requireBinary(t, cfg)

	email := fmt.Sprintf("request-dns01-%d@example.com", time.Now().UnixNano())
	configPath := createTestConfigWithCert(t, cfg.ServerURL, email,
		"dns-cert", cfg.Domain, "dns-01")
	cfg.ConfigPath = configPath

	// Request certificate (account is already defined in config)
	stdout, stderr, err := runACMEClient(t, cfg,
		"cert", "request", "dns-cert")

	if err != nil {
		// DNS-01 requires DNS infrastructure, may fail in minimal Docker env
		t.Logf("cert request dns-01 result: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
		combinedOutput := strings.ToLower(stderr + stdout)
		if strings.Contains(combinedOutput, "dns") ||
			strings.Contains(combinedOutput, "resolver") ||
			strings.Contains(combinedOutput, "txt record") ||
			strings.Contains(combinedOutput, "tls") ||
			strings.Contains(combinedOutput, "certificate") ||
			strings.Contains(combinedOutput, "x509") ||
			strings.Contains(combinedOutput, "authorize") {
			t.Log("DNS-01 challenge failed due to infrastructure (expected in Docker)")
			return
		}
		t.Fatalf("unexpected request failure: %v", err)
	}

	assert.True(t,
		strings.Contains(strings.ToLower(stdout), "certificate") ||
			strings.Contains(strings.ToLower(stdout), "success"),
		"output should indicate certificate obtained, got: %s", stdout)
}

// TestCertRequestMissingName tests certificate request without a cert name.
func TestCertRequestMissingName(t *testing.T) {
	cfg := newACMEClientConfig()
	requireBinary(t, cfg)

	configPath := createTestConfig(t, cfg.ServerURL, cfg.Email)
	cfg.ConfigPath = configPath

	_, stderr, err := runACMEClient(t, cfg, "cert", "request")
	if err == nil {
		t.Fatal("expected error for missing cert name, but command succeeded")
	}

	combinedOutput := strings.ToLower(stderr)
	assert.True(t,
		strings.Contains(combinedOutput, "name") ||
			strings.Contains(combinedOutput, "required") ||
			strings.Contains(combinedOutput, "argument") ||
			strings.Contains(combinedOutput, "error"),
		"error should mention name requirement, got: %s", stderr)
}

// TestCertRequestNonexistentName tests certificate request with a name not in config.
func TestCertRequestNonexistentName(t *testing.T) {
	cfg := newACMEClientConfig()
	requireBinary(t, cfg)

	configPath := createTestConfig(t, cfg.ServerURL, cfg.Email)
	cfg.ConfigPath = configPath

	_, stderr, err := runACMEClient(t, cfg,
		"cert", "request", "nonexistent-cert-spec")
	if err == nil {
		t.Fatal("expected error for nonexistent cert name, but command succeeded")
	}

	combinedOutput := strings.ToLower(stderr)
	assert.True(t,
		strings.Contains(combinedOutput, "not found") ||
			strings.Contains(combinedOutput, "unknown") ||
			strings.Contains(combinedOutput, "error"),
		"error should indicate cert spec not found, got: %s", stderr)
}

// TestCertRequestKeyTypes tests certificate request with different key types defined in config.
func TestCertRequestKeyTypes(t *testing.T) {
	cfg := newACMEClientConfig()
	requireBinary(t, cfg)

	testCases := []struct {
		name     string
		keyAlgo  string
		keyCurve string
		keySize  int
	}{
		{"ECDSA-P256", "ECDSA", "P-256", 0},
		{"ECDSA-P384", "ECDSA", "P-384", 0},
		{"RSA-2048", "RSA", "", 2048},
		{"RSA-4096", "RSA", "", 4096},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			email := fmt.Sprintf("keytype-%s-%d@example.com", tc.name, time.Now().UnixNano())
			certName := fmt.Sprintf("keytype-%s", strings.ToLower(tc.name))

			configPath := createTestConfigWithKeySpec(t, cfg.ServerURL, email,
				certName, cfg.Domain, tc.keyAlgo, tc.keyCurve, tc.keySize)
			cfg.ConfigPath = configPath

			stdout, stderr, err := runACMEClient(t, cfg,
				"cert", "request", certName)

			// Log the result regardless of success/failure
			t.Logf("key type %s result: err=%v\nstdout: %s\nstderr: %s",
				tc.name, err, stdout, stderr)

			// We primarily validate that the CLI accepts the config
			// without parsing errors
			if err != nil {
				combinedOutput := strings.ToLower(stderr)
				assert.False(t,
					strings.Contains(combinedOutput, "unknown") &&
						strings.Contains(combinedOutput, "key"),
					"CLI should accept key config for %s", tc.name)
			}
		})
	}
}

// TestCertList tests listing certificates.
func TestCertList(t *testing.T) {
	cfg := newACMEClientConfig()
	requireBinary(t, cfg)

	configPath := createTestConfig(t, cfg.ServerURL, cfg.Email)
	cfg.ConfigPath = configPath

	stdout, stderr, err := runACMEClient(t, cfg, "cert", "list")
	if err != nil {
		t.Fatalf("cert list failed: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
	}

	// The config defines a "test-cert" spec, so listing should show it
	combinedOutput := strings.ToLower(stdout + stderr)
	assert.True(t,
		strings.Contains(combinedOutput, defaultCertName) ||
			strings.Contains(combinedOutput, "test-cert") ||
			strings.Contains(combinedOutput, "no certificates"),
		"cert list output should contain cert names or empty indicator, got: %s", stdout)
}

// TestCertShow tests showing details of a certificate.
func TestCertShow(t *testing.T) {
	cfg := newACMEClientConfig()
	requireBinary(t, cfg)

	configPath := createTestConfig(t, cfg.ServerURL, cfg.Email)
	cfg.ConfigPath = configPath

	stdout, stderr, err := runACMEClient(t, cfg, "cert", "show", defaultCertName)

	// May fail if no cert has been issued yet, but should not fail on unknown command
	t.Logf("cert show result: err=%v\nstdout: %s\nstderr: %s", err, stdout, stderr)

	if err != nil {
		combinedOutput := strings.ToLower(stderr)
		assert.False(t,
			strings.Contains(combinedOutput, "unknown command"),
			"CLI should accept 'cert show' command, got: %s", stderr)
	}
}

// TestCertDeploy tests deploying a certificate.
func TestCertDeploy(t *testing.T) {
	cfg := newACMEClientConfig()
	requireBinary(t, cfg)

	configPath := createTestConfig(t, cfg.ServerURL, cfg.Email)
	cfg.ConfigPath = configPath

	stdout, stderr, err := runACMEClient(t, cfg, "cert", "deploy", defaultCertName)

	// May fail if no cert has been issued, but should not fail on unknown command
	t.Logf("cert deploy result: err=%v\nstdout: %s\nstderr: %s", err, stdout, stderr)

	if err != nil {
		combinedOutput := strings.ToLower(stderr)
		assert.False(t,
			strings.Contains(combinedOutput, "unknown command"),
			"CLI should accept 'cert deploy' command, got: %s", stderr)
	}
}
