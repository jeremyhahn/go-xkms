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

// TestAccountAddSuccess tests successful account registration via "account add".
func TestAccountAddSuccess(t *testing.T) {
	cfg := newACMEClientConfig()
	requireBinary(t, cfg)

	email := fmt.Sprintf("register-success-%d@example.com", time.Now().UnixNano())
	configPath := createTestConfigEmpty(t)
	cfg.ConfigPath = configPath

	stdout, stderr, err := runACMEClient(t, cfg,
		"account", "add", "new-account",
		"--directory", cfg.ServerURL,
		"--email", email)
	if err != nil {
		t.Fatalf("account add failed: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
	}

	combinedOutput := strings.ToLower(stdout + stderr)
	assert.True(t,
		strings.Contains(combinedOutput, "added") ||
			strings.Contains(combinedOutput, "success") ||
			strings.Contains(combinedOutput, "new-account"),
		"output should indicate successful addition, got: %s", stdout)
}

// TestAccountAddDuplicateAccount tests adding an account that already exists in config.
func TestAccountAddDuplicateAccount(t *testing.T) {
	cfg := newACMEClientConfig()
	requireBinary(t, cfg)

	email := fmt.Sprintf("register-dup-%d@example.com", time.Now().UnixNano())
	// Use a config that already has test-ca defined
	configPath := createTestConfig(t, cfg.ServerURL, email)
	cfg.ConfigPath = configPath

	// Try to add test-ca which already exists in the config file
	_, stderr, err := runACMEClient(t, cfg,
		"account", "add", defaultAccountName,
		"--directory", cfg.ServerURL,
		"--email", email)
	assert.Error(t, err, "adding existing account should fail")
	assert.Contains(t, strings.ToLower(stderr), "already exists",
		"error should indicate account already exists, got: %s", stderr)
}

// TestAccountAddMissingEmail tests account add without an email address.
func TestAccountAddMissingEmail(t *testing.T) {
	cfg := newACMEClientConfig()
	requireBinary(t, cfg)

	configPath := createTestConfigEmpty(t)
	cfg.ConfigPath = configPath

	_, stderr, err := runACMEClient(t, cfg,
		"account", "add", "no-email-account",
		"--directory", cfg.ServerURL)
	assert.Error(t, err, "account add without email should fail")

	combinedOutput := strings.ToLower(stderr)
	assert.True(t,
		strings.Contains(combinedOutput, "email") ||
			strings.Contains(combinedOutput, "required"),
		"error should mention email requirement, got: %s", stderr)
}

// TestAccountAddMissingDirectory tests account add without a directory URL.
func TestAccountAddMissingDirectory(t *testing.T) {
	cfg := newACMEClientConfig()
	requireBinary(t, cfg)

	configPath := createTestConfigEmpty(t)
	cfg.ConfigPath = configPath

	_, stderr, err := runACMEClient(t, cfg,
		"account", "add", "no-dir-account",
		"--email", "test@example.com")
	assert.Error(t, err, "account add without directory should fail")
	combinedOutput := strings.ToLower(stderr)
	assert.True(t,
		strings.Contains(combinedOutput, "directory") ||
			strings.Contains(combinedOutput, "required"),
		"error should mention directory requirement, got: %s", stderr)
}

// TestAccountList tests listing accounts defined in config.
func TestAccountList(t *testing.T) {
	cfg := newACMEClientConfig()
	requireBinary(t, cfg)

	email := fmt.Sprintf("account-list-%d@example.com", time.Now().UnixNano())
	configPath := createTestConfig(t, cfg.ServerURL, email)
	cfg.ConfigPath = configPath

	// The config already has test-ca account, just list it
	stdout, stderr, err := runACMEClient(t, cfg, "account", "list")
	if err != nil {
		t.Fatalf("account list failed: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
	}

	combinedOutput := strings.ToLower(stdout + stderr)
	assert.Contains(t, combinedOutput, "test-ca",
		"account list should contain test-ca, got: %s", stdout)
}

// TestAccountShow tests showing details of a configured account.
func TestAccountShow(t *testing.T) {
	cfg := newACMEClientConfig()
	requireBinary(t, cfg)

	email := fmt.Sprintf("account-show-%d@example.com", time.Now().UnixNano())
	configPath := createTestConfig(t, cfg.ServerURL, email)
	cfg.ConfigPath = configPath

	// Account is already in config, just show it
	stdout, stderr, err := runACMEClient(t, cfg, "account", "show", defaultAccountName)
	if err != nil {
		t.Fatalf("account show failed: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
	}

	combinedOutput := strings.ToLower(stdout + stderr)
	assert.True(t,
		strings.Contains(combinedOutput, defaultAccountName) ||
			strings.Contains(combinedOutput, email) ||
			strings.Contains(combinedOutput, "directory"),
		"account show should contain account details, got: %s", stdout)
}

// TestAccountShowNonexistent tests showing a nonexistent account.
func TestAccountShowNonexistent(t *testing.T) {
	cfg := newACMEClientConfig()
	requireBinary(t, cfg)

	configPath := createTestConfig(t, cfg.ServerURL, cfg.Email)
	cfg.ConfigPath = configPath

	_, stderr, err := runACMEClient(t, cfg, "account", "show", "nonexistent-account")
	assert.Error(t, err, "account show for nonexistent should fail")

	combinedOutput := strings.ToLower(stderr)
	assert.True(t,
		strings.Contains(combinedOutput, "not found") ||
			strings.Contains(combinedOutput, "error"),
		"error should indicate account not found, got: %s", stderr)
}

// TestAccountRemove tests removing an account that is referenced by certificates.
// Since each CLI invocation is stateless, we test that removing an account referenced
// by cert specs is correctly rejected.
func TestAccountRemove(t *testing.T) {
	cfg := newACMEClientConfig()
	requireBinary(t, cfg)

	email := fmt.Sprintf("account-remove-%d@example.com", time.Now().UnixNano())
	// Config has test-ca referenced by test-cert → can't remove
	configPath := createTestConfig(t, cfg.ServerURL, email)
	cfg.ConfigPath = configPath

	// Try to remove test-ca which is referenced by cert specs
	_, stderr, err := runACMEClient(t, cfg, "account", "remove", defaultAccountName)
	assert.Error(t, err, "removing account referenced by certs should fail")
	assert.True(t,
		strings.Contains(strings.ToLower(stderr), "referenced") ||
			strings.Contains(strings.ToLower(stderr), "certificate"),
		"error should mention cert references, got: %s", stderr)
}

// TestAccountRemoveNonexistent tests removing a nonexistent account.
func TestAccountRemoveNonexistent(t *testing.T) {
	cfg := newACMEClientConfig()
	requireBinary(t, cfg)

	configPath := createTestConfig(t, cfg.ServerURL, cfg.Email)
	cfg.ConfigPath = configPath

	_, stderr, err := runACMEClient(t, cfg, "account", "remove", "nonexistent-account")
	assert.Error(t, err, "account remove for nonexistent should fail")

	combinedOutput := strings.ToLower(stderr)
	assert.True(t,
		strings.Contains(combinedOutput, "not found") ||
			strings.Contains(combinedOutput, "error"),
		"error should indicate account not found, got: %s", stderr)
}
