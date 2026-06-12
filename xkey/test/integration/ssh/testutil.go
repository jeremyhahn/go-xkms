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

// Package ssh contains end-to-end integration tests for the Phase 1c
// xkey SSH CLI surface (xkey ssh keys / host-keys / authorized-keys).
//
// The tests exercise the CLI binary the same way a user does:
//
//   - Embedded transport: each test gets an isolated XKEY_HOME temp
//     directory, so the file-backed store lives at
//     $XKEY_HOME/data/ssh and never touches the host user's store.
//   - REST transport: the CLI selects REST when XKMSD_URL is set; the
//     tests verify dispatch and the wire contract against an in-test
//     httptest server that speaks the /xkms/v1/ssh API shape (the real
//     server side is covered by go-xkms's pkg/api/rest handler tests).
package ssh

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
)

// binaryPath holds the path to the built xkey binary. It is built once
// per test run using sync.Once.
var (
	binaryPath     string
	binaryBuildErr error
	binaryOnce     sync.Once
)

// getBinary builds the xkey binary once and returns its path.
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

// cliBuildTags returns the build tags for the test-built xkey binary.
// The Makefile exports XKEY_CLI_BUILD_TAGS with the full production tag
// set; without it, codec_json is the minimum tag set required for a
// functional CLI (go-codec based DAOs).
func cliBuildTags() string {
	if tags := os.Getenv("XKEY_CLI_BUILD_TAGS"); tags != "" {
		return tags
	}
	return "codec_json"
}

// buildXkeyBinary compiles the xkey binary and returns its path.
func buildXkeyBinary() (string, error) {
	tmpDir, err := os.MkdirTemp("", "xkey-ssh-integration-*")
	if err != nil {
		return "", err
	}

	out := filepath.Join(tmpDir, "xkey")

	projectRoot, err := findProjectRoot()
	if err != nil {
		return "", err
	}

	// Use a full path to go when PATH is reset (e.g. sudo test runs).
	goBinary := "go"
	if _, err := exec.LookPath("go"); err != nil {
		for _, path := range []string{"/usr/local/go/bin/go", "/usr/bin/go"} {
			if _, err := os.Stat(path); err == nil {
				goBinary = path
				break
			}
		}
	}
	cmd := exec.Command(goBinary, "build", "-tags", cliBuildTags(), "-o", out, "./cmd/xkey")
	cmd.Dir = projectRoot

	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", &BuildError{Output: string(output), Err: err}
	}

	return out, nil
}

// BuildError represents a binary build failure.
type BuildError struct {
	Output string
	Err    error
}

// Error implements the error interface.
func (e *BuildError) Error() string {
	return "build failed: " + e.Err.Error() + "\nOutput: " + e.Output
}

// Unwrap returns the wrapped error.
func (e *BuildError) Unwrap() error {
	return e.Err
}

// findProjectRoot locates the xkey module root by searching for go.mod.
func findProjectRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
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

// OutputMatches checks if the command output matches a regex pattern.
func (r *CommandResult) OutputMatches(pattern string) bool {
	re := regexp.MustCompile(pattern)
	return re.MatchString(r.Stdout) || re.MatchString(r.Stderr)
}

// SSHTestHelper provides helper methods for SSH CLI integration tests.
// Each helper owns an isolated XKEY_HOME so the embedded file store at
// $XKEY_HOME/data/ssh never collides across tests or with the host.
type SSHTestHelper struct {
	t          *testing.T
	binaryPath string
	homeDir    string
	tempDir    string
	xkmsdURL   string // non-empty selects the REST transport
	xkmsdToken string // forwarded as XKMSD_TOKEN when set
	user       string // value for $USER inside the CLI process
}

// NewSSHTestHelper creates a helper using the embedded transport with
// an isolated XKEY_HOME.
func NewSSHTestHelper(t *testing.T) *SSHTestHelper {
	t.Helper()

	tempDir := t.TempDir()
	homeDir := filepath.Join(tempDir, "xkey-home")
	if err := os.MkdirAll(homeDir, 0700); err != nil {
		t.Fatalf("Failed to create XKEY_HOME: %v", err)
	}

	return &SSHTestHelper{
		t:          t,
		binaryPath: getBinary(t),
		homeDir:    homeDir,
		tempDir:    tempDir,
		user:       "ittest",
	}
}

// NewSSHTestHelperREST creates a helper that selects the REST transport
// by exporting XKMSD_URL into the CLI environment.
func NewSSHTestHelperREST(t *testing.T, baseURL, token string) *SSHTestHelper {
	t.Helper()

	h := NewSSHTestHelper(t)
	h.xkmsdURL = baseURL
	h.xkmsdToken = token
	return h
}

// BinaryPath returns the path to the xkey binary.
func (h *SSHTestHelper) BinaryPath() string {
	return h.binaryPath
}

// TempDir returns the temporary directory for test artifacts.
func (h *SSHTestHelper) TempDir() string {
	return h.tempDir
}

// HomeDir returns the isolated XKEY_HOME directory.
func (h *SSHTestHelper) HomeDir() string {
	return h.homeDir
}

// StoreDir returns the embedded file store root the CLI resolves for
// this helper's XKEY_HOME ($XKEY_HOME/data/ssh).
func (h *SSHTestHelper) StoreDir() string {
	return filepath.Join(h.homeDir, "data", "ssh")
}

// User returns the $USER value injected into the CLI environment, which
// is also the CLI's default --owner.
func (h *SSHTestHelper) User() string {
	return h.user
}

// CommandEnv builds the CLI environment: inherited environment minus
// any transport/home variables that would leak host state, plus the
// helper's isolated XKEY_HOME and transport selection.
func (h *SSHTestHelper) CommandEnv() []string {
	var env []string
	for _, kv := range os.Environ() {
		switch {
		case strings.HasPrefix(kv, "XKEY_HOME="),
			strings.HasPrefix(kv, "XKMSD_URL="),
			strings.HasPrefix(kv, "XKMSD_TOKEN="),
			strings.HasPrefix(kv, "USER="),
			strings.HasPrefix(kv, "LOGNAME="):
			// Dropped: replaced with test-controlled values below.
		default:
			env = append(env, kv)
		}
	}
	env = append(env, "XKEY_HOME="+h.homeDir, "USER="+h.user, "LOGNAME="+h.user)
	if h.xkmsdURL != "" {
		env = append(env, "XKMSD_URL="+h.xkmsdURL)
	}
	if h.xkmsdToken != "" {
		env = append(env, "XKMSD_TOKEN="+h.xkmsdToken)
	}
	return env
}

// RunSSH executes an xkey ssh command.
func (h *SSHTestHelper) RunSSH(args ...string) *CommandResult {
	h.t.Helper()
	return h.RunCommand(append([]string{"ssh"}, args...)...)
}

// RunSSHKeys executes an xkey ssh keys command.
func (h *SSHTestHelper) RunSSHKeys(args ...string) *CommandResult {
	h.t.Helper()
	return h.RunCommand(append([]string{"ssh", "keys"}, args...)...)
}

// RunSSHHostKeys executes an xkey ssh host-keys command.
func (h *SSHTestHelper) RunSSHHostKeys(args ...string) *CommandResult {
	h.t.Helper()
	return h.RunCommand(append([]string{"ssh", "host-keys"}, args...)...)
}

// RunSSHAuthorized executes an xkey ssh authorized-keys command.
func (h *SSHTestHelper) RunSSHAuthorized(args ...string) *CommandResult {
	h.t.Helper()
	return h.RunCommand(append([]string{"ssh", "authorized-keys"}, args...)...)
}

// RunCommand executes the xkey binary with the given arguments.
func (h *SSHTestHelper) RunCommand(args ...string) *CommandResult {
	h.t.Helper()
	return h.runWithStdin(nil, args...)
}

// RunCommandWithStdin executes the xkey binary with the given stdin
// content (used for piped passphrase input on encrypted-key import).
func (h *SSHTestHelper) RunCommandWithStdin(stdin string, args ...string) *CommandResult {
	h.t.Helper()
	return h.runWithStdin(strings.NewReader(stdin), args...)
}

// runWithStdin is the shared executor behind RunCommand and
// RunCommandWithStdin.
func (h *SSHTestHelper) runWithStdin(stdin *strings.Reader, args ...string) *CommandResult {
	h.t.Helper()

	cmd := exec.Command(h.binaryPath, args...)
	cmd.Env = h.CommandEnv()
	if stdin != nil {
		cmd.Stdin = stdin
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

// CreateTestSSHKey creates a test SSH private key via ssh-keygen for
// import testing and returns the private-key path. passphrase may be
// empty for an unencrypted key.
func (h *SSHTestHelper) CreateTestSSHKey(keyType, passphrase string) (string, error) {
	h.t.Helper()

	keyPath := filepath.Join(h.tempDir, "test_key_"+keyType)
	if passphrase != "" {
		keyPath += "_enc"
	}
	os.Remove(keyPath)
	os.Remove(keyPath + ".pub")

	var args []string
	switch keyType {
	case "ed25519":
		args = []string{"-t", "ed25519"}
	case "rsa":
		args = []string{"-t", "rsa", "-b", "2048"}
	case "ecdsa":
		args = []string{"-t", "ecdsa", "-b", "256"}
	default:
		args = []string{"-t", "ed25519"}
	}
	args = append(args, "-f", keyPath, "-N", passphrase, "-q")

	cmd := exec.Command("ssh-keygen", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", &KeygenError{Output: string(output), Err: err}
	}

	return keyPath, nil
}

// KeygenError represents a key generation failure.
type KeygenError struct {
	Output string
	Err    error
}

// Error implements the error interface.
func (e *KeygenError) Error() string {
	return "ssh-keygen failed: " + e.Err.Error() + "\nOutput: " + e.Output
}

// Unwrap returns the wrapped error.
func (e *KeygenError) Unwrap() error {
	return e.Err
}

// SSHFingerprintPattern matches OpenSSH SHA256 key fingerprints.
var SSHFingerprintPattern = regexp.MustCompile(`SHA256:[A-Za-z0-9+/=]+`)

// ExtractFingerprint extracts an SSH fingerprint from output.
func ExtractFingerprint(output string) (string, bool) {
	match := SSHFingerprintPattern.FindString(output)
	return match, match != ""
}

// SSHPublicKeyPattern matches OpenSSH authorized_keys-format public keys.
var SSHPublicKeyPattern = regexp.MustCompile(`(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp\d+)\s+[A-Za-z0-9+/=]+`)

// ExtractPublicKey extracts an SSH public key from output.
func ExtractPublicKey(output string) (string, bool) {
	match := SSHPublicKeyPattern.FindString(output)
	return match, match != ""
}
