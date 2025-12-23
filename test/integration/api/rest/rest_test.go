//go:build integration

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

// Package rest provides REST API integration tests for go-keychain.
// These tests verify that all CLI commands work correctly when using the REST protocol.
package rest

import (
	"strings"
	"testing"

	"github.com/jeremyhahn/go-keychain/test/integration/api/commands"
)

// TestRESTAPI_Health tests the REST health endpoint
func TestRESTAPI_Health(t *testing.T) {
	runner := commands.NewTestRunner()
	if !runner.IsCLIAvailable(t) {
		t.Fatal("CLI binary required. Run: make build")
	}

	stdout, stderr, err := runner.RunCommandWithProtocol(t, commands.ProtocolREST, "backends", "list")
	if err != nil {
		t.Logf("stdout: %s", stdout)
		t.Logf("stderr: %s", stderr)
		t.Fatalf("REST server not available - server must be running: %v", err)
	}

	output := stdout + stderr
	if output == "" {
		t.Fatal("No output from REST server")
	}
	t.Logf("REST health check passed")
}

// TestRESTAPI_KeyOperations tests key operations via REST
func TestRESTAPI_KeyOperations(t *testing.T) {
	runner := commands.NewTestRunner()
	if !runner.IsCLIAvailable(t) {
		t.Fatal("CLI binary required. Run: make build")
	}

	keyDir := commands.CreateTempKeyDir(t)
	runner = runner.WithKeyDir(keyDir).WithBackend("software")
	keyID := commands.GenerateUniqueKeyID("rest-test")

	// Generate key
	t.Run("Generate", func(t *testing.T) {
		args := []string{
			"key", "generate", keyID,
			"--backend", "software",
			"--key-dir", keyDir,
			"--key-type", "ecdsa",
			"--key-algorithm", "ecdsa",
			"--curve", "P-256",
		}
		stdout, stderr, err := runner.RunCommandWithProtocol(t, commands.ProtocolREST, args...)
		if err != nil {
			t.Logf("stdout: %s", stdout)
			t.Logf("stderr: %s", stderr)
			t.Fatalf("REST key generation failed: %v", err)
		}
	})

	// List keys
	t.Run("List", func(t *testing.T) {
		args := []string{
			"key", "list",
			"--backend", "software",
			"--key-dir", keyDir,
		}
		stdout, stderr, err := runner.RunCommandWithProtocol(t, commands.ProtocolREST, args...)
		if err != nil {
			t.Logf("stdout: %s", stdout)
			t.Logf("stderr: %s", stderr)
			t.Fatalf("List keys failed: %v", err)
		}
		if !strings.Contains(stdout+stderr, keyID) {
			t.Fatalf("Key %s not in list", keyID)
		}
	})

	// Sign
	t.Run("Sign", func(t *testing.T) {
		args := []string{
			"key", "sign", keyID, "test data",
			"--backend", "software",
			"--key-dir", keyDir,
			"--key-type", "ecdsa",
			"--key-algorithm", "ecdsa",
			"--hash", "SHA-256",
		}
		stdout, stderr, err := runner.RunCommandWithProtocol(t, commands.ProtocolREST, args...)
		if err != nil {
			t.Logf("stdout: %s", stdout)
			t.Logf("stderr: %s", stderr)
			t.Fatalf("Sign failed: %v", err)
		}
		if strings.TrimSpace(stdout) == "" {
			t.Fatal("No signature returned")
		}
	})

	// Delete
	t.Run("Delete", func(t *testing.T) {
		args := []string{
			"key", "delete", keyID,
			"--backend", "software",
			"--key-dir", keyDir,
			"--key-type", "ecdsa",
			"--key-algorithm", "ecdsa",
		}
		_, stderr, err := runner.RunCommandWithProtocol(t, commands.ProtocolREST, args...)
		if err != nil {
			t.Logf("stderr: %s", stderr)
			t.Fatalf("Delete failed: %v", err)
		}
	})
}

// TestRESTAPI_AllCommands runs all CLI commands via REST protocol
func TestRESTAPI_AllCommands(t *testing.T) {
	runner := commands.NewTestRunner()
	if !runner.IsCLIAvailable(t) {
		t.Fatal("CLI binary required. Run: make build")
	}

	keyDir := commands.CreateTempKeyDir(t)
	runner = runner.WithKeyDir(keyDir).WithBackend("software")

	// Get enabled build tags
	enabledTags := []string{"integration", "frost"}

	// Run all commands for REST protocol
	results := runner.RunAllCommandsForProtocol(t, commands.ProtocolREST, enabledTags)

	passed := 0
	failed := 0
	for _, r := range results {
		if r.Passed {
			passed++
		} else {
			failed++
			t.Logf("FAILED: %s - %s", r.Command.Name, r.Message)
		}
	}

	t.Logf("REST Protocol: %d passed, %d failed", passed, failed)
}
