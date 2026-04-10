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

package ssh

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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
	tmpDir, err := os.MkdirTemp("", "xkey-ssh-integration-*")
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

// OutputMatches checks if the command output matches a regex pattern.
func (r *CommandResult) OutputMatches(pattern string) bool {
	re := regexp.MustCompile(pattern)
	return re.MatchString(r.Stdout) || re.MatchString(r.Stderr)
}

// TestMode represents the mode of operation for SSH tests.
type TestMode string

const (
	// ModeStandalone tests with local key storage (no xkmsd).
	ModeStandalone TestMode = "standalone"
	// ModeUnix tests with xkmsd via Unix socket.
	ModeUnix TestMode = "unix"
	// ModeGRPC tests with xkmsd via gRPC over TCP.
	ModeGRPC TestMode = "grpc"
)

// TestBackend represents the key backend to use.
type TestBackend string

const (
	BackendSoftware TestBackend = "software"
	BackendTPM2     TestBackend = "tpm2"
)

// SSHTestConfig holds configuration for a test scenario.
type SSHTestConfig struct {
	Mode    TestMode
	Backend TestBackend
	Name    string // Human-readable name for the test
	XKMSURL string // URL for xkmsd (unix://, grpc://)
}

// SSHTestHelper provides helper methods for SSH CLI integration tests.
type SSHTestHelper struct {
	t          *testing.T
	binaryPath string
	socketPath string
	xkmsdURL   string
	configPath string
	tempDir    string
	mode       TestMode
	backend    TestBackend
	storePath  string // Local store path for standalone mode
}

// NewSSHTestHelper creates a new test helper with default standalone/software config.
func NewSSHTestHelper(t *testing.T) *SSHTestHelper {
	t.Helper()
	return NewSSHTestHelperWithConfig(t, SSHTestConfig{
		Mode:    ModeStandalone,
		Backend: BackendSoftware,
		Name:    "standalone/software",
	})
}

// NewSSHTestHelperWithConfig creates a new test helper with the specified configuration.
func NewSSHTestHelperWithConfig(t *testing.T, cfg SSHTestConfig) *SSHTestHelper {
	t.Helper()

	tempDir := t.TempDir()
	socketPath := filepath.Join(tempDir, "ssh-agent.sock")
	configPath := filepath.Join(tempDir, "config.yaml")
	storePath := filepath.Join(tempDir, "ssh-keys")

	// Create the local store directory for standalone mode
	if err := os.MkdirAll(storePath, 0700); err != nil {
		t.Fatalf("Failed to create store directory: %v", err)
	}

	// Determine xkmsd URL based on mode
	var xkmsdURL string
	switch cfg.Mode {
	case ModeUnix:
		xkmsdURL = cfg.XKMSURL
		if xkmsdURL == "" {
			xkmsdURL = "unix://" + GetUnixSocketPath()
		}
	case ModeGRPC:
		xkmsdURL = cfg.XKMSURL
		if xkmsdURL == "" {
			xkmsdURL = "grpc://" + GetGRPCAddr()
		}
	}

	// Create a config file based on the test configuration
	configContent := `ssh:
  enabled: true
  require_touch: false
  agent_socket: "` + socketPath + `"
`
	if cfg.Mode != ModeStandalone {
		configContent += `  xkmsd_url: "` + xkmsdURL + `"
  backend: "` + string(cfg.Backend) + `"
`
	} else {
		// Standalone mode - use local store
		configContent += `  store_path: "` + storePath + `"
`
	}

	if err := os.WriteFile(configPath, []byte(configContent), 0600); err != nil {
		t.Fatalf("Failed to create test config: %v", err)
	}

	return &SSHTestHelper{
		t:          t,
		binaryPath: getBinary(t),
		socketPath: socketPath,
		xkmsdURL:   xkmsdURL,
		configPath: configPath,
		tempDir:    tempDir,
		mode:       cfg.Mode,
		backend:    cfg.Backend,
		storePath:  storePath,
	}
}

// SocketPath returns the path to the SSH agent socket.
func (h *SSHTestHelper) SocketPath() string {
	return h.socketPath
}

// XKMSURL returns the xkmsd URL for the test helper.
func (h *SSHTestHelper) XKMSURL() string {
	return h.xkmsdURL
}

// BinaryPath returns the path to the xkey binary.
func (h *SSHTestHelper) BinaryPath() string {
	return h.binaryPath
}

// TempDir returns the temporary directory for test artifacts.
func (h *SSHTestHelper) TempDir() string {
	return h.tempDir
}

// StorePath returns the local key store path for standalone mode.
func (h *SSHTestHelper) StorePath() string {
	return h.storePath
}

// Mode returns the test mode.
func (h *SSHTestHelper) Mode() TestMode {
	return h.mode
}

// Backend returns the test backend.
func (h *SSHTestHelper) Backend() TestBackend {
	return h.backend
}

// CommandEnv returns the environment variables to use when running commands.
// This sets up the proper environment based on the test mode.
func (h *SSHTestHelper) CommandEnv() []string {
	env := os.Environ()
	env = append(env, "XKEY_SSH_AGENT_SOCKET="+h.socketPath)

	switch h.mode {
	case ModeUnix, ModeGRPC:
		// Server mode - use xkmsd
		if h.xkmsdURL != "" {
			env = append(env, "XKEY_SSH_XKMSD_URL="+h.xkmsdURL)
		}
		env = append(env, "XKEY_SSH_BACKEND="+string(h.backend))
	default:
		// Standalone mode - use local store
		env = append(env, "XKEY_SSH_STORE_PATH="+h.storePath)
	}

	return env
}

// ModeArgs returns the CLI arguments for the current mode.
// For standalone mode, returns --store flag.
// For server modes, the global --xkmsd-url flag should be used on the xkey command.
func (h *SSHTestHelper) ModeArgs() []string {
	switch h.mode {
	case ModeStandalone:
		return []string{"--store", h.storePath}
	case ModeUnix, ModeGRPC:
		// Server mode - no per-command args, use global flags via GlobalArgs()
		return []string{}
	default:
		return []string{"--store", h.storePath}
	}
}

// GlobalArgs returns the global CLI arguments that should be prepended to all commands.
// This includes --xkmsd-url and --backend for server modes.
func (h *SSHTestHelper) GlobalArgs() []string {
	switch h.mode {
	case ModeUnix, ModeGRPC:
		return []string{"--xkmsd-url", h.xkmsdURL, "--backend", string(h.backend)}
	default:
		return []string{}
	}
}

// RunSSH executes an xkey ssh command with the test socket path.
func (h *SSHTestHelper) RunSSH(args ...string) *CommandResult {
	h.t.Helper()

	if len(args) == 0 {
		return h.RunCommand("ssh")
	}

	// Prepend "ssh" to the args
	fullArgs := append([]string{"ssh"}, args...)

	return h.RunCommand(fullArgs...)
}

// RunSSHAgent executes an xkey ssh agent command.
func (h *SSHTestHelper) RunSSHAgent(args ...string) *CommandResult {
	h.t.Helper()

	fullArgs := []string{"ssh", "agent"}
	fullArgs = append(fullArgs, args...)

	return h.RunCommand(fullArgs...)
}

// RunSSHKeys executes an xkey ssh keys command with mode-specific arguments.
func (h *SSHTestHelper) RunSSHKeys(args ...string) *CommandResult {
	h.t.Helper()

	fullArgs := []string{"ssh", "keys"}
	fullArgs = append(fullArgs, args...)

	return h.RunCommand(fullArgs...)
}

// RunSSHKeysWithMode executes an xkey ssh keys command with mode args appended.
func (h *SSHTestHelper) RunSSHKeysWithMode(args ...string) *CommandResult {
	h.t.Helper()

	fullArgs := []string{"ssh", "keys"}
	fullArgs = append(fullArgs, args...)
	fullArgs = append(fullArgs, h.ModeArgs()...)

	return h.RunCommand(fullArgs...)
}

// RunCommand executes the xkey binary with the given arguments.
// Global args (--xkmsd-url, --backend) are automatically prepended for server modes.
func (h *SSHTestHelper) RunCommand(args ...string) *CommandResult {
	h.t.Helper()

	// Prepend global args for server modes
	fullArgs := append(h.GlobalArgs(), args...)
	cmd := exec.Command(h.binaryPath, fullArgs...)
	cmd.Env = h.CommandEnv()

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

// RunCommandWithTimeout executes a command with a specific timeout.
func (h *SSHTestHelper) RunCommandWithTimeout(timeout time.Duration, args ...string) *CommandResult {
	h.t.Helper()

	cmd := exec.Command(h.binaryPath, args...)
	cmd.Env = h.CommandEnv()

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return &CommandResult{
			ExitCode: -1,
			Err:      err,
		}
	}

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case err := <-done:
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
	case <-time.After(timeout):
		cmd.Process.Kill()
		return &CommandResult{
			Stdout:   stdout.String(),
			Stderr:   stderr.String(),
			ExitCode: -1,
			Err:      &TimeoutError{Timeout: timeout},
		}
	}
}

// TimeoutError represents a command timeout.
type TimeoutError struct {
	Timeout time.Duration
}

func (e *TimeoutError) Error() string {
	return "command timed out after " + e.Timeout.String()
}

// SocketExists checks if the SSH agent socket exists.
func (h *SSHTestHelper) SocketExists() bool {
	_, err := os.Stat(h.socketPath)
	return err == nil
}

// SocketResponds checks if the SSH agent socket is responding.
func (h *SSHTestHelper) SocketResponds() bool {
	conn, err := net.DialTimeout("unix", h.socketPath, 2*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// WaitForSocket waits for the socket to become available.
func (h *SSHTestHelper) WaitForSocket(timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if h.SocketResponds() {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

// CleanupSocket removes the socket file if it exists.
func (h *SSHTestHelper) CleanupSocket() {
	os.Remove(h.socketPath)
	os.Remove(h.socketPath + ".pid")
}

// RunSSHAdd runs ssh-add with the test socket to list or verify keys.
// Uses a 30-second timeout to prevent hanging tests.
func (h *SSHTestHelper) RunSSHAdd(args ...string) *CommandResult {
	h.t.Helper()

	// Create context with timeout to prevent hanging tests
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ssh-add", args...)
	cmd.Env = append(os.Environ(), "SSH_AUTH_SOCK="+h.socketPath)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	exitCode := 0
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return &CommandResult{
				Stdout:   stdout.String(),
				Stderr:   stderr.String() + "\n(command timed out after 30s)",
				ExitCode: -1,
				Err:      fmt.Errorf("ssh-add timed out after 30s: %w", err),
			}
		}
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

// CreateTestSSHKey creates a test SSH key file for import testing.
// Each key type gets a unique filename to avoid overwrite prompts.
func (h *SSHTestHelper) CreateTestSSHKey(keyType string) (string, error) {
	h.t.Helper()

	// Use unique filename per key type to avoid ssh-keygen overwrite prompt
	keyPath := filepath.Join(h.tempDir, "test_key_"+keyType)

	// Remove any existing key files first
	os.Remove(keyPath)
	os.Remove(keyPath + ".pub")

	var args []string
	switch keyType {
	case "ed25519":
		args = []string{"-t", "ed25519", "-f", keyPath, "-N", "", "-q"}
	case "rsa":
		args = []string{"-t", "rsa", "-b", "2048", "-f", keyPath, "-N", "", "-q"}
	case "ecdsa":
		args = []string{"-t", "ecdsa", "-b", "256", "-f", keyPath, "-N", "", "-q"}
	default:
		args = []string{"-t", "ed25519", "-f", keyPath, "-N", "", "-q"}
	}

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

func (e *KeygenError) Error() string {
	return "ssh-keygen failed: " + e.Err.Error() + "\nOutput: " + e.Output
}

func (e *KeygenError) Unwrap() error {
	return e.Err
}

// SSHFingerprintPattern is a regex pattern that matches SSH key fingerprints.
var SSHFingerprintPattern = regexp.MustCompile(`SHA256:[A-Za-z0-9+/=]+`)

// ExtractFingerprint extracts an SSH fingerprint from output.
func ExtractFingerprint(output string) (string, bool) {
	match := SSHFingerprintPattern.FindString(output)
	return match, match != ""
}

// SSHPublicKeyPattern is a regex pattern that matches SSH public keys.
var SSHPublicKeyPattern = regexp.MustCompile(`(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp\d+)\s+[A-Za-z0-9+/=]+`)

// ExtractPublicKey extracts an SSH public key from output.
func ExtractPublicKey(output string) (string, bool) {
	match := SSHPublicKeyPattern.FindString(output)
	return match, match != ""
}

// GetUnixSocketPath returns the Unix socket path for xkmsd.
func GetUnixSocketPath() string {
	// Check environment variable first
	if path := os.Getenv("XKMS_UNIX_SOCKET"); path != "" {
		return path
	}

	// Default path in devcontainer
	return "/var/run/xkms/xkms.sock"
}

// GetGRPCAddr returns the gRPC address for xkmsd.
func GetGRPCAddr() string {
	// Check environment variable first
	if addr := os.Getenv("XKMS_GRPC_ADDR"); addr != "" {
		return addr
	}

	// Default in devcontainer
	return "xkms-server:9443"
}

// IsUnixSocketAvailable checks if the Unix socket is available.
func IsUnixSocketAvailable() bool {
	socketPath := GetUnixSocketPath()
	conn, err := net.DialTimeout("unix", socketPath, 2*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// IsGRPCAvailable checks if the gRPC endpoint is available.
func IsGRPCAvailable() bool {
	addr := GetGRPCAddr()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// IsXKMSdAvailable checks if xkmsd is available via any protocol.
func IsXKMSdAvailable() bool {
	return IsUnixSocketAvailable() || IsGRPCAvailable()
}

// SkipIfNoXKMSd skips the test if xkmsd is not available.
func SkipIfNoXKMSd(t *testing.T) {
	t.Helper()
	if !IsXKMSdAvailable() {
		t.Skip("Skipping: xkmsd is not available")
	}
}

// IsTPM2Available checks if TPM2 is available for testing.
// This checks for the presence of /dev/tpmrm0 (TPM resource manager device).
func IsTPM2Available() bool {
	// Check for TPM resource manager device
	if _, err := os.Stat("/dev/tpmrm0"); err == nil {
		return true
	}

	// Check for TPM device (fallback)
	if _, err := os.Stat("/dev/tpm0"); err == nil {
		return true
	}

	// Check if TPM2_TOOLS is available and working
	cmd := exec.Command("tpm2_getcap", "properties-fixed")
	if err := cmd.Run(); err == nil {
		return true
	}

	return false
}

// SkipIfNoTPM2 skips the test if TPM2 is not available.
func SkipIfNoTPM2(t *testing.T) {
	t.Helper()
	if !IsTPM2Available() {
		t.Skip("Skipping: TPM2 is not available")
	}
}

// verifiedBackends caches which xkmsd backends have been verified to work.
var (
	verifiedBackends   = make(map[string]bool)
	verifiedBackendsMu sync.Mutex
)

// IsXKMSdBackendWorking checks if a specific xkmsd backend works for SSH operations.
// This verifies the backend is both available and properly configured.
func IsXKMSdBackendWorking(t *testing.T, xkmsdURL string, backend TestBackend) bool {
	return verifyXKMSdBackend(t, xkmsdURL, backend)
}

// verifyXKMSdBackend checks if a xkmsd backend actually works for SSH operations.
// This does a functional test by trying to generate and delete a test key.
func verifyXKMSdBackend(t *testing.T, xkmsdURL string, backend TestBackend) bool {
	t.Helper()

	cacheKey := xkmsdURL + "/" + string(backend)

	verifiedBackendsMu.Lock()
	defer verifiedBackendsMu.Unlock()

	// Check cache first
	if result, ok := verifiedBackends[cacheKey]; ok {
		return result
	}

	// Build binary path
	binaryPath := getBinary(t)

	// Use a unique test key ID
	testKeyID := fmt.Sprintf("_ssh_verify_test_%d", time.Now().UnixNano())

	// Try to generate a key - this verifies the backend is fully working
	// Use global flags (--xkmsd-url, --backend) before the subcommand
	genCmd := exec.Command(binaryPath,
		"--xkmsd-url", xkmsdURL,
		"--backend", string(backend),
		"ssh", "keys", "generate",
		"--id", testKeyID,
		"--type", "ed25519")

	output, err := genCmd.CombinedOutput()
	outputStr := string(output)

	// Check for errors that indicate the backend isn't configured or working
	if err != nil || strings.Contains(outputStr, "backend not found") ||
		strings.Contains(outputStr, "unsupported algorithm") ||
		strings.Contains(outputStr, "connection refused") ||
		strings.Contains(outputStr, "no public key data") ||
		strings.Contains(outputStr, "failed to retrieve public key") ||
		strings.Contains(outputStr, "import token cannot be empty") {
		verifiedBackends[cacheKey] = false
		t.Logf("Backend %s not available: %s", cacheKey, strings.TrimSpace(outputStr))
		return false
	}

	// Clean up the test key
	delCmd := exec.Command(binaryPath,
		"--xkmsd-url", xkmsdURL,
		"--backend", string(backend),
		"ssh", "keys", "delete", testKeyID,
		"--force")
	delCmd.Run() // Best effort cleanup, ignore errors

	// Success - the backend is working
	verifiedBackends[cacheKey] = true
	return true
}

// GetAllTestConfigs returns all available test configurations.
// This includes standalone mode (always available) and server modes (if xkmsd is running
// AND the backend is properly configured).
func GetAllTestConfigs(t *testing.T) []SSHTestConfig {
	t.Helper()

	configs := []SSHTestConfig{
		// Standalone mode is always available
		{Mode: ModeStandalone, Backend: BackendSoftware, Name: "standalone/software"},
	}

	// Add Unix socket mode if available and backend works
	if IsUnixSocketAvailable() {
		unixURL := "unix://" + GetUnixSocketPath()

		// Only add software backend if it actually works
		if verifyXKMSdBackend(t, unixURL, BackendSoftware) {
			configs = append(configs,
				SSHTestConfig{
					Mode:    ModeUnix,
					Backend: BackendSoftware,
					Name:    "unix/software",
					XKMSURL: unixURL,
				},
			)
		}

		// Add TPM2 backend if hardware exists AND backend is configured in xkmsd
		if IsTPM2Available() && verifyXKMSdBackend(t, unixURL, BackendTPM2) {
			configs = append(configs,
				SSHTestConfig{
					Mode:    ModeUnix,
					Backend: BackendTPM2,
					Name:    "unix/tpm2",
					XKMSURL: unixURL,
				},
			)
		}
	}

	// Add gRPC mode if available and backend works
	if IsGRPCAvailable() {
		grpcURL := "grpc://" + GetGRPCAddr()

		// Only add software backend if it actually works
		if verifyXKMSdBackend(t, grpcURL, BackendSoftware) {
			configs = append(configs,
				SSHTestConfig{
					Mode:    ModeGRPC,
					Backend: BackendSoftware,
					Name:    "grpc/software",
					XKMSURL: grpcURL,
				},
			)
		}

		// Add TPM2 backend if hardware exists AND backend is configured in xkmsd
		if IsTPM2Available() && verifyXKMSdBackend(t, grpcURL, BackendTPM2) {
			configs = append(configs,
				SSHTestConfig{
					Mode:    ModeGRPC,
					Backend: BackendTPM2,
					Name:    "grpc/tpm2",
					XKMSURL: grpcURL,
				},
			)
		}
	}

	return configs
}

// LogAvailableProtocols logs which protocols are available for testing.
func LogAvailableProtocols(t *testing.T) {
	t.Helper()

	t.Log("Protocol availability:")
	t.Log("  Standalone: always available")
	t.Logf("  Unix socket (%s): %v", GetUnixSocketPath(), IsUnixSocketAvailable())
	t.Logf("  gRPC (%s): %v", GetGRPCAddr(), IsGRPCAvailable())
	t.Logf("  TPM2: %v", IsTPM2Available())
}
