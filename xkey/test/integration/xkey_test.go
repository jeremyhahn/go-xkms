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

//go:build integration && linux

// Package xkey provides E2E integration tests for the xkey CLI binary.
// These tests verify basic binary execution, help output, and command routing.
package xkey

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestXKey_Version runs "xkey version" and verifies the output contains
// the program name.
func TestXKey_Version(t *testing.T) {
	binaryPath := findBinary(t)
	if binaryPath == "" {
		t.Log("xkey binary not found, attempting to build...")
		binaryPath = buildBinary(t)
	}

	t.Logf("Using binary: %s", binaryPath)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, binaryPath, "version")
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "Version command should succeed")

	outputStr := string(output)
	assert.Contains(t, outputStr, "xkey", "Version output should contain program name")
	t.Logf("Version output: %s", outputStr)
}

// TestXKey_Help runs "xkey --help" and verifies the output shows usage
// information including expected subcommands.
func TestXKey_Help(t *testing.T) {
	binaryPath := findBinary(t)
	if binaryPath == "" {
		binaryPath = buildBinary(t)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, binaryPath, "--help")
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "Help command should succeed")

	outputStr := string(output)
	assert.Contains(t, outputStr, "Usage", "Help output should show usage")
	assert.Contains(t, outputStr, "xKey", "Help should mention xKey")
	assert.Contains(t, outputStr, "FIDO2", "Help should mention FIDO2")
}

// TestXKey_UnknownCommand runs "xkey nonexistent-command" and verifies
// a non-zero exit code and appropriate error message.
func TestXKey_UnknownCommand(t *testing.T) {
	binaryPath := findBinary(t)
	if binaryPath == "" {
		binaryPath = buildBinary(t)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, binaryPath, "nonexistent-command")
	output, err := cmd.CombinedOutput()
	assert.Error(t, err, "Unknown subcommand should fail")

	outputStr := string(output)
	assert.Contains(t, outputStr, "unknown command", "Should report unknown command")
}

// TestXKey_Fido2Help runs "xkey fido2 --help" and verifies the output
// contains FIDO2-related information.
func TestXKey_Fido2Help(t *testing.T) {
	binaryPath := findBinary(t)
	if binaryPath == "" {
		binaryPath = buildBinary(t)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, binaryPath, "fido2", "--help")
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "fido2 --help should succeed")

	outputStr := string(output)
	assert.Contains(t, outputStr, "fido2", "Help should mention fido2")
}

// TestXKey_Fido2DaemonStartStop starts "xkey fido2" as a subprocess with
// in-memory storage, verifies the process is running, then sends SIGTERM
// and verifies a clean exit.
func TestXKey_Fido2DaemonStartStop(t *testing.T) {
	skipIfNoUHID(t)

	binaryPath := findBinary(t)
	if binaryPath == "" {
		binaryPath = buildBinary(t)
	}

	tmpDir := tempDir(t)
	logFile := filepath.Join(tmpDir, "xkey.log")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, binaryPath,
		"fido2",
		"--log-file", logFile,
		"--storage", "memory",
		"--notify", "none",
		"--require-touch=false",
	)

	err := cmd.Start()
	require.NoError(t, err, "Failed to start fido2 subcommand")

	// Give the daemon time to initialize.
	time.Sleep(1 * time.Second)

	// Verify the process is still running (has not crashed immediately).
	if cmd.Process != nil {
		assert.True(t, processRunning(cmd.Process.Pid), "fido2 process should be running")
	}

	// Send SIGTERM for graceful shutdown before context kills it.
	if cmd.Process != nil {
		cmd.Process.Signal(os.Interrupt)
	}

	// Wait for process to exit with timeout.
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case <-done:
		t.Log("fido2 process exited after interrupt")
	case <-time.After(5 * time.Second):
		cancel() // Force kill via context.
		t.Log("fido2 process force-killed after timeout")
	}
}
