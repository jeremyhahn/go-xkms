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

// Package touch provides integration tests for the xkey touch and
// password type CLI commands. These tests execute the real xkey binary
// and verify actual CLI behavior when communicating with the daemon over IPC.
package touch

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// binaryPath holds the path to the built xkey binary.
// It is built once per test run using sync.Once.
var (
	binaryPath     string
	binaryBuildErr error
	binaryOnce     sync.Once
)

// getBinary builds the xkey binary once and returns its path.
// This ensures we only compile once per test run for efficiency.
func getBinary(t *testing.T) string {
	t.Helper()

	binaryOnce.Do(func() {
		binaryPath, binaryBuildErr = buildXkeyBinary()
	})

	if binaryBuildErr != nil {
		t.Fatalf("Failed to build xkey binary: %v", binaryBuildErr)
	}

	return binaryPath
}

// buildXkeyBinary compiles the xkey binary and returns its path.
func buildXkeyBinary() (string, error) {
	tmpDir, err := os.MkdirTemp("", "xkey-touch-integration-*")
	if err != nil {
		return "", err
	}

	binaryPath := filepath.Join(tmpDir, "xkey")

	projectRoot, err := findProjectRoot()
	if err != nil {
		return "", err
	}

	// Use full path to go since tests may run with sudo where PATH is reset
	goBinary := "go"
	if _, err := exec.LookPath("go"); err != nil {
		// Try common installation paths
		for _, path := range []string{"/usr/local/go/bin/go", "/usr/bin/go"} {
			if _, err := os.Stat(path); err == nil {
				goBinary = path
				break
			}
		}
	}
	cmd := exec.Command(goBinary, "build", "-o", binaryPath, "./cmd/xkey")
	cmd.Dir = projectRoot

	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", &BuildError{Output: string(output), Err: err}
	}

	return binaryPath, nil
}

// BuildError represents a binary build failure.
type BuildError struct {
	Output string
	Err    error
}

func (e *BuildError) Error() string {
	return "build failed: " + e.Err.Error() + "\nOutput: " + e.Output
}

func (e *BuildError) Unwrap() error {
	return e.Err
}

// findProjectRoot locates the project root by searching for go.mod.
func findProjectRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	for {
		goModPath := filepath.Join(dir, "go.mod")
		if _, err := os.Stat(goModPath); err == nil {
			return dir, nil
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	// Fallback: try relative paths from typical test locations.
	candidates := []string{
		"../../../..",
		"../../..",
		"../..",
		"..",
	}

	for _, candidate := range candidates {
		absPath, err := filepath.Abs(candidate)
		if err != nil {
			continue
		}
		goModPath := filepath.Join(absPath, "go.mod")
		if _, err := os.Stat(goModPath); err == nil {
			return absPath, nil
		}
	}

	return "", os.ErrNotExist
}

// CommandResult holds the result of a CLI command execution.
type CommandResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Err      error
}

// Success returns true if the command succeeded (exit code 0).
func (r *CommandResult) Success() bool {
	return r.ExitCode == 0 && r.Err == nil
}

// Combined returns stdout and stderr combined.
func (r *CommandResult) Combined() string {
	if r.Stderr == "" {
		return r.Stdout
	}
	if r.Stdout == "" {
		return r.Stderr
	}
	return r.Stdout + "\n" + r.Stderr
}

// OutputContains checks if the command output contains a substring.
func (r *CommandResult) OutputContains(substr string) bool {
	return strings.Contains(r.Stdout, substr) || strings.Contains(r.Stderr, substr)
}

// OutputContainsAll checks if the command output contains all substrings.
func (r *CommandResult) OutputContainsAll(substrs ...string) bool {
	combined := r.Combined()
	for _, substr := range substrs {
		if !strings.Contains(combined, substr) {
			return false
		}
	}
	return true
}

// TouchTestHelper provides helper methods for touch and password type CLI
// integration tests. It manages a temporary socket path for IPC communication.
type TouchTestHelper struct {
	t          *testing.T
	binaryPath string
	socketPath string
}

// NewTouchTestHelper creates a new test helper with a temporary socket directory.
// The socket path points to a non-existent file, simulating a daemon that is
// not running -- the most common testable scenario without hardware.
func NewTouchTestHelper(t *testing.T) *TouchTestHelper {
	t.Helper()

	socketDir, err := os.MkdirTemp("", "xkey-touch-socket-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}

	t.Cleanup(func() {
		os.RemoveAll(socketDir)
	})

	return &TouchTestHelper{
		t:          t,
		binaryPath: getBinary(t),
		socketPath: filepath.Join(socketDir, "xkey.sock"),
	}
}

// SocketPath returns the path to the IPC socket.
func (h *TouchTestHelper) SocketPath() string {
	return h.socketPath
}

// RunTouch executes an xkey touch command with the test socket path.
func (h *TouchTestHelper) RunTouch(args ...string) *CommandResult {
	h.t.Helper()

	fullArgs := []string{"touch", "--socket", h.socketPath}
	fullArgs = append(fullArgs, args...)

	return h.RunCommand(fullArgs...)
}

// RunPasswordType executes an xkey password type command with the test
// socket path. The name argument is the password name to type.
func (h *TouchTestHelper) RunPasswordType(name string, extraArgs ...string) *CommandResult {
	h.t.Helper()

	fullArgs := []string{"password", "type", name, "--socket", h.socketPath}
	fullArgs = append(fullArgs, extraArgs...)

	return h.RunCommand(fullArgs...)
}

// RunCommand executes the xkey binary with the given arguments.
func (h *TouchTestHelper) RunCommand(args ...string) *CommandResult {
	h.t.Helper()

	cmd := exec.Command(h.binaryPath, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}

	return &CommandResult{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		ExitCode: exitCode,
		Err:      err,
	}
}

// intToString converts an integer to a string.
func intToString(n int) string {
	return fmt.Sprintf("%d", n)
}
