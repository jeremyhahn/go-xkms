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

package xkey

// Helpers for CLI integration tests.

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
)

// binaryBuild holds the compiled xkey binary path and any build error.
// It is populated once per test run via sync.Once for efficiency.
var (
	cliBinaryPath     string
	cliBinaryBuildErr error
	cliBinaryOnce     sync.Once
)

// getOrBuildBinary returns the path to the xkey binary, building it once
// if it has not already been compiled during this test run.
func getOrBuildBinary(t *testing.T) string {
	t.Helper()

	cliBinaryOnce.Do(func() {
		// Try to find an existing binary first.
		existing := findBinary(t)
		if existing != "" {
			cliBinaryPath = existing
			return
		}
		// Build from source.
		cliBinaryPath = buildBinary(t)
	})

	if cliBinaryBuildErr != nil {
		t.Fatalf("Failed to build xkey binary: %v", cliBinaryBuildErr)
	}

	return cliBinaryPath
}

// RunXKey executes the xkey CLI binary with args and optional stdin input.
// Returns stdout, stderr, and exit code.
func RunXKey(t *testing.T, binary string, stdinInput string, args ...string) (string, string, int) {
	t.Helper()

	cmd := exec.Command(binary, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if stdinInput != "" {
		cmd.Stdin = strings.NewReader(stdinInput)
	}

	err := cmd.Run()

	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}

	return stdout.String(), stderr.String(), exitCode
}

// RunXKeyExpectSuccess runs xkey and fails the test if exit code != 0.
// Returns the combined stdout output.
func RunXKeyExpectSuccess(t *testing.T, binary string, stdinInput string, args ...string) string {
	t.Helper()

	stdout, stderr, exitCode := RunXKey(t, binary, stdinInput, args...)
	if exitCode != 0 {
		t.Fatalf("Expected success (exit 0) but got exit %d\nArgs: %v\nStdout: %s\nStderr: %s",
			exitCode, args, stdout, stderr)
	}

	return stdout
}

// RunXKeyExpectFailure runs xkey and fails the test if exit code == 0.
// Returns the combined stderr output.
func RunXKeyExpectFailure(t *testing.T, binary string, stdinInput string, args ...string) string {
	t.Helper()

	stdout, stderr, exitCode := RunXKey(t, binary, stdinInput, args...)
	if exitCode == 0 {
		t.Fatalf("Expected failure (exit != 0) but got exit 0\nArgs: %v\nStdout: %s\nStderr: %s",
			args, stdout, stderr)
	}

	// Return stderr, falling back to stdout if stderr is empty.
	if stderr != "" {
		return stderr
	}
	return stdout
}

// SetupCleanEnvironment creates a temporary directory with clean xkey state.
// Returns the data directory path. Cleanup is automatic via t.Cleanup.
func SetupCleanEnvironment(t *testing.T) string {
	t.Helper()

	dir, err := os.MkdirTemp("", "xkey-cli-integration-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}

	t.Cleanup(func() {
		os.RemoveAll(dir)
	})

	return dir
}
