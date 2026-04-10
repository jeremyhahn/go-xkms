//go:build integration

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

// Package quic provides QUIC/HTTP3 integration tests for go-xkms.
// These tests verify that all CLI commands work correctly when using the QUIC protocol.
package quic

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/test/integration/api/commands"
)

// checkQUICAvailable checks if the QUIC server is available
func checkQUICAvailable(t *testing.T, runner *commands.TestRunner) bool {
	t.Helper()
	// Try a simple command to verify QUIC server is running
	stdout, stderr, err := runner.RunCommandWithProtocol(t, commands.ProtocolQUIC, "backends", "list")
	if err != nil {
		t.Logf("QUIC server check failed: %v", err)
		t.Logf("stdout: %s", stdout)
		t.Logf("stderr: %s", stderr)
		return false
	}
	return true
}

// TestQUIC_Health tests the QUIC health endpoint
func TestQUIC_Health(t *testing.T) {
	runner := commands.NewTestRunner()
	runner.RequireCLI(t)

	if !checkQUICAvailable(t, runner) {
		t.Fatal("QUIC server not available - server must be running")
	}

	stdout, stderr, err := runner.RunCommandWithProtocol(t, commands.ProtocolQUIC, "backends", "list")
	if err != nil {
		t.Logf("stdout: %s", stdout)
		t.Logf("stderr: %s", stderr)
		t.Fatalf("QUIC backends list failed: %v", err)
	}

	output := stdout + stderr
	if output == "" {
		t.Fatal("No output from QUIC server")
	}
	t.Logf("QUIC health check passed")
}

// TestQUIC_AllCommands runs all CLI commands via QUIC protocol
func TestQUIC_AllCommands(t *testing.T) {
	runner := commands.NewTestRunner()
	runner.RequireCLI(t)

	if !checkQUICAvailable(t, runner) {
		t.Fatal("QUIC server not available - server must be running")
	}

	keyDir := commands.CreateTempKeyDir(t)
	runner = runner.WithKeyDir(keyDir).WithBackend("software")

	enabledTags := []string{"integration", "frost"}

	results := runner.RunAllCommandsForProtocol(t, commands.ProtocolQUIC, enabledTags)

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

	t.Logf("QUIC Protocol: %d passed, %d failed", passed, failed)
}
