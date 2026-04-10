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

package oath

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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
	// Create a persistent temp directory for the binary
	tmpDir, err := os.MkdirTemp("", "xkey-oath-integration-*")
	if err != nil {
		return "", err
	}

	binaryPath := filepath.Join(tmpDir, "xkey")

	// Find project root by looking for go.mod
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
	// Start from current directory and walk up
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

// OATHTestHelper provides helper methods for OATH CLI integration tests.
type OATHTestHelper struct {
	t          *testing.T
	binaryPath string
	storePath  string
}

// NewOATHTestHelper creates a new test helper with a temp OATH store file.
func NewOATHTestHelper(t *testing.T) *OATHTestHelper {
	t.Helper()

	tmpDir, err := os.MkdirTemp("", "oath-cli-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}

	storePath := filepath.Join(tmpDir, "oath.json")

	t.Cleanup(func() {
		os.RemoveAll(tmpDir)
	})

	return &OATHTestHelper{
		t:          t,
		binaryPath: getBinary(t),
		storePath:  storePath,
	}
}

// StorePath returns the path to the OATH store file.
func (h *OATHTestHelper) StorePath() string {
	return h.storePath
}

// RunOATH executes an xkey oath command with the test store path.
// The --store flag is defined on each subcommand (not as a PersistentFlag
// on the oath parent), so it must be placed after the subcommand name.
func (h *OATHTestHelper) RunOATH(args ...string) *CommandResult {
	h.t.Helper()

	if len(args) == 0 {
		return h.RunCommand("oath")
	}

	// First arg is the subcommand (add, list, generate, remove, etc.)
	// Insert --store after the subcommand name
	fullArgs := []string{"oath", args[0], "--store", h.storePath}
	if len(args) > 1 {
		fullArgs = append(fullArgs, args[1:]...)
	}

	return h.RunCommand(fullArgs...)
}

// RunCommand executes the xkey binary with the given arguments.
func (h *OATHTestHelper) RunCommand(args ...string) *CommandResult {
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

// ValidTestSecrets contains well-known base32 secrets for testing.
var ValidTestSecrets = []string{
	"JBSWY3DPEHPK3PXP",                 // Common test secret
	"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", // RFC 4226 test secret
	"HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ", // Random 20-byte secret
}

// TestCredential represents a test OATH credential configuration.
type TestCredential struct {
	Name      string
	Issuer    string
	Secret    string
	Type      string // totp or hotp
	Algorithm string // SHA1, SHA256, SHA512
	Digits    int    // 6, 7, or 8
	Period    int    // TOTP period in seconds
}

// DefaultTOTPCredential returns a standard TOTP test credential.
func DefaultTOTPCredential(name string) TestCredential {
	return TestCredential{
		Name:      name,
		Issuer:    "TestIssuer",
		Secret:    "JBSWY3DPEHPK3PXP",
		Type:      "totp",
		Algorithm: "SHA1",
		Digits:    6,
		Period:    30,
	}
}

// DefaultHOTPCredential returns a standard HOTP test credential.
func DefaultHOTPCredential(name string) TestCredential {
	return TestCredential{
		Name:      name,
		Issuer:    "TestIssuer",
		Secret:    "JBSWY3DPEHPK3PXP",
		Type:      "hotp",
		Algorithm: "SHA1",
		Digits:    6,
	}
}

// AddCredential adds a credential using the CLI and returns the result.
func (h *OATHTestHelper) AddCredential(cred TestCredential) *CommandResult {
	h.t.Helper()

	args := []string{
		"add",
		"--name", cred.Name,
		"--secret", cred.Secret,
	}

	if cred.Issuer != "" {
		args = append(args, "--issuer", cred.Issuer)
	}
	if cred.Type != "" {
		args = append(args, "--type", cred.Type)
	}
	if cred.Algorithm != "" {
		args = append(args, "--algorithm", cred.Algorithm)
	}
	if cred.Digits > 0 {
		args = append(args, "--digits", intToString(cred.Digits))
	}
	if cred.Period > 0 && cred.Type == "totp" {
		args = append(args, "--period", intToString(cred.Period))
	}

	return h.RunOATH(args...)
}

// intToString converts an integer to a string.
func intToString(n int) string {
	return fmt.Sprintf("%d", n)
}

// OTPCodePattern is a regex pattern that matches valid OTP codes.
var OTPCodePattern = regexp.MustCompile(`^\d{6,8}$`)

// IsValidOTPCode checks if a string is a valid OTP code format.
func IsValidOTPCode(code string) bool {
	code = strings.TrimSpace(code)
	return OTPCodePattern.MatchString(code)
}

// ExtractOTPCode extracts the OTP code from command output.
// Returns the code and true if found, empty string and false otherwise.
func ExtractOTPCode(output string) (string, bool) {
	// Look for a 6-8 digit number in the output
	pattern := regexp.MustCompile(`\b(\d{6,8})\b`)
	matches := pattern.FindStringSubmatch(output)
	if len(matches) >= 2 {
		return matches[1], true
	}
	return "", false
}
