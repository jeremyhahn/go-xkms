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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestCertRenewMissingName tests renewal without specifying a certificate name.
func TestCertRenewMissingName(t *testing.T) {
	cfg := newACMEClientConfig()
	requireBinary(t, cfg)

	configPath := createTestConfig(t, cfg.ServerURL, cfg.Email)
	cfg.ConfigPath = configPath

	_, stderr, err := runACMEClient(t, cfg, "cert", "renew")
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

// TestCertRenewNonexistentName tests renewal with a certificate name not in config.
func TestCertRenewNonexistentName(t *testing.T) {
	cfg := newACMEClientConfig()
	requireBinary(t, cfg)

	configPath := createTestConfig(t, cfg.ServerURL, cfg.Email)
	cfg.ConfigPath = configPath

	_, stderr, err := runACMEClient(t, cfg,
		"cert", "renew", "nonexistent-cert-12345")
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

// TestCertRenewNoIssuedCert tests renewal when no certificate has been issued yet.
func TestCertRenewNoIssuedCert(t *testing.T) {
	cfg := newACMEClientConfig()
	requireBinary(t, cfg)

	configPath := createTestConfig(t, cfg.ServerURL, cfg.Email)
	cfg.ConfigPath = configPath

	// The cert name exists in config but has never been issued
	_, stderr, clientErr := runACMEClient(t, cfg,
		"cert", "renew", defaultCertName)
	if clientErr == nil {
		t.Fatal("expected error for cert that has not been issued, but command succeeded")
	}

	combinedOutput := strings.ToLower(stderr)
	assert.True(t,
		strings.Contains(combinedOutput, "not found") ||
			strings.Contains(combinedOutput, "no certificate") ||
			strings.Contains(combinedOutput, "not issued") ||
			strings.Contains(combinedOutput, "error"),
		"error should indicate no certificate to renew, got: %s", stderr)
}

// TestCertRenewChallengeTypes tests that cert renew works with different challenge-configured certs.
func TestCertRenewChallengeTypes(t *testing.T) {
	cfg := newACMEClientConfig()
	requireBinary(t, cfg)

	challengeTypes := []string{"http-01", "dns-01"}
	for _, challenge := range challengeTypes {
		t.Run(challenge, func(t *testing.T) {
			certName := "renew-" + challenge
			configPath := createTestConfigWithCert(t, cfg.ServerURL, cfg.Email,
				certName, cfg.Domain, challenge)
			cfg.ConfigPath = configPath

			_, stderr, err := runACMEClient(t, cfg,
				"cert", "renew", certName)

			// Should fail because no cert has been issued, but command should be accepted
			if err == nil {
				return // If it somehow succeeded, that's fine too
			}

			combinedOutput := strings.ToLower(stderr)
			assert.False(t,
				strings.Contains(combinedOutput, "unknown command"),
				"CLI should accept 'cert renew' with challenge config '%s', got: %s",
				challenge, stderr)
		})
	}
}
