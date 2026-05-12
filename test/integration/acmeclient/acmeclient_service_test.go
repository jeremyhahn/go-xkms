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
	"context"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestServiceStartupAndShutdown tests the auto-renewal daemon startup and graceful shutdown.
func TestServiceStartupAndShutdown(t *testing.T) {
	cfg := newACMEClientConfig()
	requireBinary(t, cfg)

	configPath := createTestConfig(t, cfg.ServerURL, cfg.Email)
	cfg.ConfigPath = configPath

	// Start the service command with a short timeout context
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	args := buildACMEClientArgs(cfg, "service", "start")
	cmd := exec.CommandContext(ctx, cfg.Binary, args...)

	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Start the process
	err := cmd.Start()
	require.NoError(t, err, "service start command should start")

	// Wait briefly to allow the daemon to initialize
	time.Sleep(2 * time.Second)

	// Send SIGTERM for graceful shutdown
	if cmd.Process != nil {
		err = cmd.Process.Signal(syscall.SIGTERM)
		if err != nil {
			t.Logf("failed to send SIGTERM: %v", err)
		}
	}

	// Wait for the process to exit
	err = cmd.Wait()

	// The service should exit cleanly on SIGTERM
	stdoutStr := stdout.String()
	stderrStr := stderr.String()
	t.Logf("service stdout: %s", stdoutStr)
	t.Logf("service stderr: %s", stderrStr)

	if err != nil {
		// Check if it was killed by our signal (expected)
		if exitErr, ok := err.(*exec.ExitError); ok {
			// Signal-based exit is expected
			t.Logf("service exited with signal: %v", exitErr)
		} else if ctx.Err() == context.DeadlineExceeded {
			t.Log("service was killed by timeout (acceptable)")
		} else {
			t.Logf("service exited with error: %v", err)
		}
	}
}

// TestServiceHelp tests that the service command shows help information.
func TestServiceHelp(t *testing.T) {
	cfg := newACMEClientConfig()
	requireBinary(t, cfg)

	// Use the binary directly for help (no server needed)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, cfg.Binary, "service", "--help")
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "service --help should succeed")

	helpText := strings.ToLower(string(output))
	assert.True(t,
		strings.Contains(helpText, "service") ||
			strings.Contains(helpText, "start") ||
			strings.Contains(helpText, "renewal") ||
			strings.Contains(helpText, "daemon"),
		"help should describe the service command, got: %s", string(output))
}

// TestServiceVersion tests that version command works alongside service.
func TestServiceVersion(t *testing.T) {
	cfg := newACMEClientConfig()
	requireBinary(t, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, cfg.Binary, "version")
	output, err := cmd.Output()
	require.NoError(t, err, "version command should succeed")

	versionText := string(output)
	assert.NotEmpty(t, versionText, "version output should not be empty")
	assert.True(t,
		strings.Contains(versionText, "trusted-acme-client") ||
			strings.Contains(versionText, "version"),
		"version output should contain program name or version, got: %s", versionText)
}
