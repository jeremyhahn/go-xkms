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

// Package grpc provides gRPC integration tests for go-xkms.
// These tests verify that all CLI commands work correctly when using the gRPC protocol.
package grpc

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/test/integration/api/commands"
)

// TestGRPC_Health tests the gRPC health endpoint
func TestGRPC_Health(t *testing.T) {
	runner := commands.NewTestRunner()
	runner.RequireCLI(t)

	stdout, stderr, err := runner.RunCommandWithProtocol(t, commands.ProtocolGRPC, "backends", "list")
	if err != nil {
		t.Logf("stdout: %s", stdout)
		t.Logf("stderr: %s", stderr)
		t.Fatalf("gRPC server not available - server must be running: %v", err)
	}

	output := stdout + stderr
	if output == "" {
		t.Fatal("No output from gRPC server")
	}
	t.Logf("gRPC health check passed")
}

// TestGRPC_AllCommands runs all CLI commands via gRPC protocol
func TestGRPC_AllCommands(t *testing.T) {
	runner := commands.NewTestRunner()
	runner.RequireCLI(t)

	keyDir := commands.CreateTempKeyDir(t)
	runner = runner.WithKeyDir(keyDir).WithBackend("software")

	enabledTags := []string{"integration", "frost"}

	results := runner.RunAllCommandsForProtocol(t, commands.ProtocolGRPC, enabledTags)

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

	t.Logf("gRPC Protocol: %d passed, %d failed", passed, failed)
}
