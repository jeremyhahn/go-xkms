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

// Package password provides integration tests for the xkey password CLI commands.
// These tests execute the real xkey binary and verify actual CLI behavior
// for static password management including add, list, get, and remove operations.
package password

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
	tmpDir, err := os.MkdirTemp("", "xkey-password-integration-*")
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

// PasswordTestHelper provides helper methods for password CLI integration tests.
type PasswordTestHelper struct {
	t          *testing.T
	binaryPath string
	storePath  string
}

// NewPasswordTestHelper creates a new test helper with a temp password store directory.
func NewPasswordTestHelper(t *testing.T) *PasswordTestHelper {
	t.Helper()

	storePath, err := os.MkdirTemp("", "password-cli-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}

	t.Cleanup(func() {
		os.RemoveAll(storePath)
	})

	return &PasswordTestHelper{
		t:          t,
		binaryPath: getBinary(t),
		storePath:  storePath,
	}
}

// StorePath returns the path to the password store directory.
func (h *PasswordTestHelper) StorePath() string {
	return h.storePath
}

// RunPassword executes an xkey password command with the test store path.
// The --store flag is defined on each subcommand (not as a PersistentFlag
// on the password parent), so it must be placed after the subcommand name.
func (h *PasswordTestHelper) RunPassword(args ...string) *CommandResult {
	h.t.Helper()

	if len(args) == 0 {
		return h.RunCommand("password")
	}

	// First arg is the subcommand (add, list, get, remove, etc.)
	// Insert --store after the subcommand name.
	fullArgs := []string{"password", args[0], "--store", h.storePath}
	if len(args) > 1 {
		fullArgs = append(fullArgs, args[1:]...)
	}

	return h.RunCommand(fullArgs...)
}

// RunCommand executes the xkey binary with the given arguments.
func (h *PasswordTestHelper) RunCommand(args ...string) *CommandResult {
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

// AddPassword adds a static password with the given name and value.
func (h *PasswordTestHelper) AddPassword(name, password string) *CommandResult {
	h.t.Helper()

	return h.RunPassword("add",
		"--name", name,
		"--password", password)
}

// AddGeneratedPassword adds a static password with a generated random value.
func (h *PasswordTestHelper) AddGeneratedPassword(name string) *CommandResult {
	h.t.Helper()

	return h.RunPassword("add",
		"--name", name,
		"--generate")
}

// intToString converts an integer to a string.
func intToString(n int) string {
	return fmt.Sprintf("%d", n)
}
