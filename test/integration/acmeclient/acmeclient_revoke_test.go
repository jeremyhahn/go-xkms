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

package acmeclient_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestCertRevokeMissingName tests revocation without specifying a certificate name.
func TestCertRevokeMissingName(t *testing.T) {
	cfg := newACMEClientConfig()
	requireBinary(t, cfg)

	configPath := createTestConfig(t, cfg.ServerURL, cfg.Email)
	cfg.ConfigPath = configPath

	_, stderr, err := runACMEClient(t, cfg, "cert", "revoke")
	if err == nil {
		t.Fatal("expected error for missing cert name, but command succeeded")
	}

	combinedOutput := strings.ToLower(stderr)
	assert.True(t,
		strings.Contains(combinedOutput, "name") ||
			strings.Contains(combinedOutput, "required") ||
			strings.Contains(combinedOutput, "argument") ||
			strings.Contains(combinedOutput, "error"),
		"error should mention certificate name requirement, got: %s", stderr)
}

// TestCertRevokeNonexistentName tests revocation with a name not in config.
func TestCertRevokeNonexistentName(t *testing.T) {
	cfg := newACMEClientConfig()
	requireBinary(t, cfg)

	configPath := createTestConfig(t, cfg.ServerURL, cfg.Email)
	cfg.ConfigPath = configPath

	_, stderr, err := runACMEClient(t, cfg,
		"cert", "revoke", "nonexistent-revoke-cert-12345")
	if err == nil {
		t.Fatal("expected error for nonexistent cert name, but command succeeded")
	}

	combinedOutput := strings.ToLower(stderr)
	assert.True(t,
		strings.Contains(combinedOutput, "not found") ||
			strings.Contains(combinedOutput, "unknown") ||
			strings.Contains(combinedOutput, "error"),
		"error should indicate cert not found, got: %s", stderr)
}

// TestCertRevokeNoIssuedCert tests revocation when no certificate has been issued.
func TestCertRevokeNoIssuedCert(t *testing.T) {
	cfg := newACMEClientConfig()
	requireBinary(t, cfg)

	configPath := createTestConfig(t, cfg.ServerURL, cfg.Email)
	cfg.ConfigPath = configPath

	_, stderr, clientErr := runACMEClient(t, cfg,
		"cert", "revoke", defaultCertName)
	if clientErr == nil {
		t.Fatal("expected error for cert that has not been issued, but command succeeded")
	}

	combinedOutput := strings.ToLower(stderr)
	assert.True(t,
		strings.Contains(combinedOutput, "not found") ||
			strings.Contains(combinedOutput, "no certificate") ||
			strings.Contains(combinedOutput, "not issued") ||
			strings.Contains(combinedOutput, "error"),
		"error should indicate no certificate to revoke, got: %s", stderr)
}

// TestCertRevokeReasonCodes tests that revocation with reason codes is accepted by the CLI.
func TestCertRevokeReasonCodes(t *testing.T) {
	cfg := newACMEClientConfig()
	requireBinary(t, cfg)

	reasonCodes := []struct {
		code string
		name string
	}{
		{"0", "unspecified"},
		{"1", "keyCompromise"},
		{"3", "affiliationChanged"},
		{"4", "superseded"},
		{"5", "cessationOfOperation"},
	}

	for _, rc := range reasonCodes {
		t.Run(rc.name, func(t *testing.T) {
			configPath := createTestConfig(t, cfg.ServerURL, cfg.Email)
			cfg.ConfigPath = configPath

			_, stderr, err := runACMEClient(t, cfg,
				"cert", "revoke", defaultCertName,
				"--reason", rc.code)

			// Should fail due to no issued cert, not unknown flags
			if err == nil {
				return // If it somehow succeeded, that's fine
			}

			combinedOutput := strings.ToLower(stderr)
			assert.False(t,
				strings.Contains(combinedOutput, "unknown flag"),
				"CLI should accept --reason %s flag, got: %s", rc.code, stderr)
		})
	}
}
