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

package fido2

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// cliBinaryPath holds the path to the built xkey binary for CLI E2E tests.
// It is built once per test run using sync.Once.
var (
	cliBinaryPath     string
	cliBinaryBuildErr error
	cliBinaryOnce     sync.Once
)

// getCliBinary builds the xkey binary once and returns its path.
// This ensures we only compile once per test run for efficiency.
func getCliBinary(t *testing.T) string {
	t.Helper()

	cliBinaryOnce.Do(func() {
		cliBinaryPath, cliBinaryBuildErr = buildCliBinary()
	})

	if cliBinaryBuildErr != nil {
		t.Fatalf("Failed to build xkey binary: %v", cliBinaryBuildErr)
	}

	return cliBinaryPath
}

// buildCliBinary compiles the xkey binary and returns its path.
func buildCliBinary() (string, error) {
	tmpDir, err := os.MkdirTemp("", "xkey-fido2-integration-*")
	if err != nil {
		return "", err
	}

	binaryPath := filepath.Join(tmpDir, "xkey")

	projectRoot, err := findCliProjectRoot()
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
		return "", &CLIBuildError{Output: string(output), Err: err}
	}

	return binaryPath, nil
}

// findCliProjectRoot locates the xkey module root by searching for go.mod.
func findCliProjectRoot() (string, error) {
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

// CLIBuildError represents a binary build failure with captured output.
type CLIBuildError struct {
	Output string
	Err    error
}

// Error returns a descriptive error message including build output.
func (e *CLIBuildError) Error() string {
	return "build failed: " + e.Err.Error() + "\nOutput: " + e.Output
}

// Unwrap returns the underlying error.
func (e *CLIBuildError) Unwrap() error {
	return e.Err
}

// CLICommandResult holds the result of a CLI command execution.
type CLICommandResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Err      error
}

// Success returns true if the command succeeded (exit code 0).
func (r *CLICommandResult) Success() bool {
	return r.ExitCode == 0 && r.Err == nil
}

// Combined returns stdout and stderr combined.
func (r *CLICommandResult) Combined() string {
	if r.Stderr == "" {
		return r.Stdout
	}
	if r.Stdout == "" {
		return r.Stderr
	}
	return r.Stdout + "\n" + r.Stderr
}

// OutputContains checks if the command output contains a substring
// in either stdout or stderr.
func (r *CLICommandResult) OutputContains(substr string) bool {
	return strings.Contains(r.Stdout, substr) || strings.Contains(r.Stderr, substr)
}

// OutputContainsAll checks if the combined command output contains all substrings.
func (r *CLICommandResult) OutputContainsAll(substrs ...string) bool {
	combined := r.Combined()
	for _, substr := range substrs {
		if !strings.Contains(combined, substr) {
			return false
		}
	}
	return true
}

// FIDO2TestHelper provides helper methods for FIDO2 CLI E2E integration tests.
// It manages the xkey binary, temporary storage directories, socket paths,
// and daemon lifecycle.
type FIDO2TestHelper struct {
	t           *testing.T
	binaryPath  string
	storagePath string
	socketPath  string
}

// NewFIDO2TestHelper creates a new test helper with temporary directories,
// builds the binary, and registers cleanup handlers.
func NewFIDO2TestHelper(t *testing.T) *FIDO2TestHelper {
	t.Helper()

	tmpDir, err := os.MkdirTemp("", "fido2-cli-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}

	storagePath := filepath.Join(tmpDir, "storage")
	if err := os.MkdirAll(storagePath, 0700); err != nil {
		t.Fatalf("Failed to create storage directory: %v", err)
	}

	socketDir := filepath.Join(tmpDir, "ipc")
	if err := os.MkdirAll(socketDir, 0700); err != nil {
		t.Fatalf("Failed to create socket directory: %v", err)
	}
	socketPath := filepath.Join(socketDir, "xkey.sock")

	t.Cleanup(func() {
		os.RemoveAll(tmpDir)
	})

	return &FIDO2TestHelper{
		t:           t,
		binaryPath:  getCliBinary(t),
		storagePath: storagePath,
		socketPath:  socketPath,
	}
}

// RunCommand executes the xkey binary with the given arguments and returns
// the captured result.
func (h *FIDO2TestHelper) RunCommand(args ...string) *CLICommandResult {
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

	return &CLICommandResult{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		ExitCode: exitCode,
		Err:      err,
	}
}

// RunFido2 executes `xkey fido2 <args>` and returns the result.
// This is intended for non-daemon invocations (e.g., --help, invalid args).
func (h *FIDO2TestHelper) RunFido2(args ...string) *CLICommandResult {
	h.t.Helper()

	fullArgs := append([]string{"fido2"}, args...)
	return h.RunCommand(fullArgs...)
}

// RunTouch executes `xkey touch --socket <socketPath> <args>` and returns
// the result.
func (h *FIDO2TestHelper) RunTouch(args ...string) *CLICommandResult {
	h.t.Helper()

	fullArgs := []string{"touch", "--socket", h.socketPath}
	fullArgs = append(fullArgs, args...)
	return h.RunCommand(fullArgs...)
}

// RunPin executes `xkey pin --socket <socketPath> <args>` and returns
// the result.
func (h *FIDO2TestHelper) RunPin(args ...string) *CLICommandResult {
	h.t.Helper()

	fullArgs := []string{"pin"}
	fullArgs = append(fullArgs, args...)
	return h.RunCommand(fullArgs...)
}

// StartDaemon launches the xkey fido2 daemon as a background process with
// file storage, the test socket path, no notifications, and touch not required.
// Additional args are appended to the command line. The method waits for the
// socket file to appear (poll 100ms, timeout 15s) and registers t.Cleanup
// to stop the daemon.
func (h *FIDO2TestHelper) StartDaemon(args ...string) *exec.Cmd {
	h.t.Helper()

	baseArgs := []string{
		"fido2",
		"--storage", "file",
		"--storage-path", h.storagePath,
		"--socket", h.socketPath,
		"--notify", "none",
		"--require-touch=false",
	}
	baseArgs = append(baseArgs, args...)

	cmd := exec.Command(h.binaryPath, baseArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		h.t.Fatalf("Failed to start fido2 daemon: %v", err)
	}

	// Wait for the IPC socket to appear, indicating the daemon is ready.
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(h.socketPath); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if _, err := os.Stat(h.socketPath); os.IsNotExist(err) {
		// Socket did not appear; try to clean up the process.
		_ = cmd.Process.Signal(syscall.SIGTERM)
		_ = cmd.Wait()
		h.t.Fatalf("Daemon socket did not appear within 15s at %s", h.socketPath)
	}

	h.t.Cleanup(func() {
		h.StopDaemon(cmd)
	})

	return cmd
}

// StopDaemon sends SIGTERM to the daemon process and waits for it to exit
// with a 10-second timeout. If the process does not exit within the timeout,
// it is killed with SIGKILL.
func (h *FIDO2TestHelper) StopDaemon(cmd *exec.Cmd) {
	h.t.Helper()

	if cmd == nil || cmd.Process == nil {
		return
	}

	_ = cmd.Process.Signal(syscall.SIGTERM)

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case <-done:
		// Process exited normally.
	case <-time.After(10 * time.Second):
		h.t.Logf("Daemon did not exit within 10s after SIGTERM, sending SIGKILL")
		_ = cmd.Process.Kill()
		<-done
	}
}

// WaitForDevice polls `fido2-token -L` until a device appears or the timeout
// expires. Returns the first device path found. This requires fido2-token to
// be installed.
func (h *FIDO2TestHelper) WaitForDevice(timeout time.Duration) (string, error) {
	h.t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		result := h.RunFido2Token("-L")
		if result.Err == nil && result.Stdout != "" {
			devices := parseFido2TokenList(result.Stdout)
			if len(devices) > 0 {
				return devices[0], nil
			}
		}
		time.Sleep(500 * time.Millisecond)
	}

	return "", fmt.Errorf("no FIDO2 device appeared within %v", timeout)
}

// WaitForDeviceWithName polls `fido2-token -L` until a device whose display
// name contains expectedName appears, or the timeout expires. This is useful
// when multiple FIDO2 devices may be connected and the test needs to identify
// its own device by product name.
func (h *FIDO2TestHelper) WaitForDeviceWithName(expectedName string, timeout time.Duration) (Fido2TokenDevice, error) {
	h.t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		result := h.RunFido2Token("-L")
		if result.Err == nil && result.Stdout != "" {
			devices := parseFido2TokenListWithInfo(result.Stdout)
			for _, dev := range devices {
				if strings.Contains(dev.DisplayName, expectedName) {
					return dev, nil
				}
			}
		}
		time.Sleep(500 * time.Millisecond)
	}

	return Fido2TokenDevice{}, fmt.Errorf(
		"no FIDO2 device with name containing %q appeared within %v",
		expectedName, timeout,
	)
}

// RunFido2Token executes `fido2-token <args>` and returns the result.
func (h *FIDO2TestHelper) RunFido2Token(args ...string) *CLICommandResult {
	h.t.Helper()

	fido2TokenPath, err := exec.LookPath("fido2-token")
	if err != nil {
		return &CLICommandResult{
			ExitCode: -1,
			Err:      fmt.Errorf("fido2-token not found in PATH: %w", err),
		}
	}

	cmd := exec.Command(fido2TokenPath, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()

	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}

	return &CLICommandResult{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		ExitCode: exitCode,
		Err:      err,
	}
}

// parseFido2TokenList extracts device paths from `fido2-token -L` output.
// Each line typically looks like: /dev/hidraw3: vendor=0xf1d0, product=0x0001 ...
func parseFido2TokenList(output string) []string {
	var devices []string
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		// Extract the device path (everything before the first colon).
		if idx := strings.Index(line, ":"); idx > 0 {
			devPath := strings.TrimSpace(line[:idx])
			if strings.HasPrefix(devPath, "/dev/") {
				devices = append(devices, devPath)
			}
		}
	}
	return devices
}

// Fido2TokenDevice holds parsed information from a single line of
// `fido2-token -L` output. The output format is:
//
//	/dev/hidraw7: vendor=0xf1d0, product=0x0001 (manufacturer product_name)
//
// For UHID devices without a manufacturer the parenthesized portion may
// start with a leading space:
//
//	/dev/hidraw7: vendor=0xf1d0, product=0x0001 ( product_name)
type Fido2TokenDevice struct {
	// Path is the device node path, e.g. "/dev/hidraw7".
	Path string
	// VendorID is the hex vendor identifier, e.g. "0xf1d0".
	VendorID string
	// ProductID is the hex product identifier, e.g. "0x0001".
	ProductID string
	// DisplayName is the trimmed content inside the parentheses at the end of
	// the line, e.g. "manufacturer product_name" or just "product_name".
	DisplayName string
}

// parseFido2TokenListWithInfo extracts device path, vendor/product IDs, and
// the display name from each line of `fido2-token -L` output.
func parseFido2TokenListWithInfo(output string) []Fido2TokenDevice {
	var devices []Fido2TokenDevice
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		dev := parseFido2TokenLine(line)
		if dev.Path != "" {
			devices = append(devices, dev)
		}
	}
	return devices
}

// parseFido2TokenLine parses a single line of `fido2-token -L` output into
// a Fido2TokenDevice. Returns a zero-value struct if the line cannot be
// parsed.
func parseFido2TokenLine(line string) Fido2TokenDevice {
	var dev Fido2TokenDevice

	// Extract device path (everything before the first colon).
	colonIdx := strings.Index(line, ":")
	if colonIdx <= 0 {
		return dev
	}
	devPath := strings.TrimSpace(line[:colonIdx])
	if !strings.HasPrefix(devPath, "/dev/") {
		return dev
	}
	dev.Path = devPath

	rest := line[colonIdx+1:]

	// Extract vendor ID: vendor=0xf1d0
	if idx := strings.Index(rest, "vendor="); idx >= 0 {
		after := rest[idx+len("vendor="):]
		end := strings.IndexAny(after, ", )")
		if end < 0 {
			end = len(after)
		}
		dev.VendorID = strings.TrimSpace(after[:end])
	}

	// Extract product ID: product=0x0001
	if idx := strings.Index(rest, "product="); idx >= 0 {
		after := rest[idx+len("product="):]
		end := strings.IndexAny(after, " ()")
		if end < 0 {
			end = len(after)
		}
		dev.ProductID = strings.TrimSpace(after[:end])
	}

	// Extract display name inside parentheses at the end of the line.
	openParen := strings.LastIndex(rest, "(")
	closeParen := strings.LastIndex(rest, ")")
	if openParen >= 0 && closeParen > openParen {
		dev.DisplayName = strings.TrimSpace(rest[openParen+1 : closeParen])
	}

	return dev
}

// skipIfNoFido2Token skips the test if fido2-token is not available in PATH.
func skipIfNoFido2Token(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("fido2-token"); err != nil {
		t.Skip("fido2-token not available in PATH")
	}
}
