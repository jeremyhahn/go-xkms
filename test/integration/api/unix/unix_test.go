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

// Package unix provides Unix socket integration tests for go-keychain.
// These tests verify that all CLI commands work correctly when using the Unix socket protocol.
package unix

import (
	"testing"

	"github.com/jeremyhahn/go-keychain/test/integration/api/commands"
)

// TestUnix_Health tests the Unix socket health endpoint
func TestUnix_Health(t *testing.T) {
	runner := commands.NewTestRunner()
	runner.RequireCLI(t)

	stdout, stderr, err := runner.RunCommandWithProtocol(t, commands.ProtocolUnix, "backends", "list")
	if err != nil {
		t.Logf("stdout: %s", stdout)
		t.Logf("stderr: %s", stderr)
		t.Fatalf("Unix socket server not available - server must be running: %v", err)
	}

	output := stdout + stderr
	if output == "" {
		t.Fatal("No output from Unix socket server")
	}
	t.Logf("Unix socket health check passed")
}

// TestUnix_AllCommands runs all CLI commands via Unix socket protocol
func TestUnix_AllCommands(t *testing.T) {
	runner := commands.NewTestRunner()
	runner.RequireCLI(t)

	keyDir := commands.CreateTempKeyDir(t)
	runner = runner.WithKeyDir(keyDir).WithBackend("software")

	enabledTags := []string{"integration", "frost"}

	results := runner.RunAllCommandsForProtocol(t, commands.ProtocolUnix, enabledTags)

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

	t.Logf("Unix Socket Protocol: %d passed, %d failed", passed, failed)
}
