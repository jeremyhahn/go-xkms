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

package oidc

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// binaryPath holds the path to the built xkey binary.
// It is built once per test run using sync.Once.
var (
	binaryPath     string
	binaryBuildErr error
	binaryOnce     sync.Once
)

// getBinary returns the xkey binary path, using XKEY_BINARY env var if set,
// otherwise building the binary once per test run.
func getBinary(t *testing.T) string {
	t.Helper()

	binaryOnce.Do(func() {
		// Check for pre-built binary (e.g., in Docker containers)
		if envBinary := os.Getenv("XKEY_BINARY"); envBinary != "" {
			if _, err := os.Stat(envBinary); err == nil {
				binaryPath = envBinary
				return
			}
		}
		binaryPath, binaryBuildErr = buildXkeyBinary()
	})

	if binaryBuildErr != nil {
		t.Fatalf("Failed to build xkey binary: %v", binaryBuildErr)
	}

	return binaryPath
}

// buildXkeyBinary compiles the xkey binary and returns its path.
func buildXkeyBinary() (string, error) {
	tmpDir, err := os.MkdirTemp("", "xkey-oidc-integration-*")
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

	// Fallback: try relative paths from typical test locations
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

// OIDCTestHelper provides helper methods for OIDC CLI integration tests.
type OIDCTestHelper struct {
	t                   *testing.T
	binaryPath          string
	tokenStorePath      string
	providersConfigPath string
}

// NewOIDCTestHelper creates a new test helper with temp directories for
// the token store and providers config. The --token-store flag is defined
// on each OIDC subcommand and controls both the token store file location
// and the derived providers config location (same directory, different file).
func NewOIDCTestHelper(t *testing.T) *OIDCTestHelper {
	t.Helper()

	tmpDir, err := os.MkdirTemp("", "oidc-cli-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}

	tokenStorePath := filepath.Join(tmpDir, "tokens.json")
	providersConfigPath := filepath.Join(tmpDir, "oidc-providers.json")

	t.Cleanup(func() {
		os.RemoveAll(tmpDir)
	})

	return &OIDCTestHelper{
		t:                   t,
		binaryPath:          getBinary(t),
		tokenStorePath:      tokenStorePath,
		providersConfigPath: providersConfigPath,
	}
}

// TokenStorePath returns the path to the OIDC token store file.
func (h *OIDCTestHelper) TokenStorePath() string {
	return h.tokenStorePath
}

// ProvidersConfigPath returns the path to the OIDC providers config file.
func (h *OIDCTestHelper) ProvidersConfigPath() string {
	return h.providersConfigPath
}

// RunCommand executes the xkey binary with the given arguments.
func (h *OIDCTestHelper) RunCommand(args ...string) *CommandResult {
	h.t.Helper()
	return h.RunCommandWithTimeout(0, args...)
}

// RunCommandWithTimeout executes the xkey binary with a timeout.
// If timeout is 0, no timeout is applied.
func (h *OIDCTestHelper) RunCommandWithTimeout(timeout time.Duration, args ...string) *CommandResult {
	h.t.Helper()

	var cmd *exec.Cmd
	if timeout > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		cmd = exec.CommandContext(ctx, h.binaryPath, args...)
	} else {
		cmd = exec.Command(h.binaryPath, args...)
	}

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

// RunOIDC executes an xkey oidc command with the --token-store flag.
// The --token-store flag is defined on each subcommand (not as a PersistentFlag
// on the oidc parent), so it must be placed after the subcommand name.
// Usage: h.RunOIDC("login", "--issuer", "https://example.com", ...)
// For nested subcommands like "providers add", pass them as separate args:
//
//	h.RunOIDC("providers", "add", "--name", "test", ...)
func (h *OIDCTestHelper) RunOIDC(args ...string) *CommandResult {
	h.t.Helper()

	if len(args) == 0 {
		return h.RunCommand("oidc")
	}

	// Determine where to insert --token-store.
	// For "providers" subcommands (providers add, providers list, providers remove),
	// --token-store is on the leaf subcommand, so insert after the second arg.
	// For direct subcommands (login, token, refresh, logout, status, stop),
	// insert after the first arg.
	insertIdx := 1
	if args[0] == "providers" && len(args) > 1 {
		insertIdx = 2
	}

	fullArgs := make([]string, 0, len(args)+3)
	fullArgs = append(fullArgs, "oidc")
	fullArgs = append(fullArgs, args[:insertIdx]...)
	fullArgs = append(fullArgs, "--token-store", h.tokenStorePath)
	if len(args) > insertIdx {
		fullArgs = append(fullArgs, args[insertIdx:]...)
	}

	return h.RunCommand(fullArgs...)
}

// RunOIDCWithTimeout executes an xkey oidc command with a timeout.
// Useful for commands that block (e.g., login waiting for OAuth callback).
func (h *OIDCTestHelper) RunOIDCWithTimeout(timeout time.Duration, args ...string) *CommandResult {
	h.t.Helper()

	if len(args) == 0 {
		return h.RunCommandWithTimeout(timeout, "oidc")
	}

	insertIdx := 1
	if args[0] == "providers" && len(args) > 1 {
		insertIdx = 2
	}

	fullArgs := make([]string, 0, len(args)+3)
	fullArgs = append(fullArgs, "oidc")
	fullArgs = append(fullArgs, args[:insertIdx]...)
	fullArgs = append(fullArgs, "--token-store", h.tokenStorePath)
	if len(args) > insertIdx {
		fullArgs = append(fullArgs, args[insertIdx:]...)
	}

	return h.RunCommandWithTimeout(timeout, fullArgs...)
}

// RunProviders executes an xkey oidc providers subcommand with the --token-store flag.
// Usage: h.RunProviders("add", "--name", "test", "--issuer", "https://example.com", ...)
func (h *OIDCTestHelper) RunProviders(args ...string) *CommandResult {
	h.t.Helper()

	providerArgs := make([]string, 0, len(args)+1)
	providerArgs = append(providerArgs, "providers")
	providerArgs = append(providerArgs, args...)

	return h.RunOIDC(providerArgs...)
}
