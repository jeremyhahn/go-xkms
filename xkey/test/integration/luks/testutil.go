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

// Package luks provides integration tests for LUKS encrypted volume functionality.
package luks

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
	"github.com/stretchr/testify/require"
)

// luks2Magic is the LUKS header magic bytes for detection.
var luks2Magic = []byte{'L', 'U', 'K', 'S', 0xba, 0xbe}

// testCounter ensures unique paths across parallel tests.
var testCounter atomic.Uint64

// LUKSPaths holds paths used during LUKS testing.
type LUKSPaths struct {
	BaseDir    string // Temporary base directory
	LUKSFile   string // Path to the .luks file
	MountPoint string // Where the volume is mounted (data dir)
	DataDir    string // Original data directory (before seal)
}

// TestData represents test data created for verification.
type TestData struct {
	Files map[string][]byte // filename -> content
	Dirs  []string          // directory paths
}

// skipIfNotRoot skips the test if not running as root.
func skipIfNotRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("Test requires root privileges - skipping")
	}
}

// skipIfNoDMCrypt skips the test if dm-crypt kernel module is not available.
func skipIfNoDMCrypt(t *testing.T) {
	t.Helper()
	// Check if dm-crypt is available by looking for /dev/mapper
	if _, err := os.Stat("/dev/mapper/control"); os.IsNotExist(err) {
		t.Skip("dm-crypt not available - skipping LUKS integration tests")
	}
}

// skipIfNoMkfsExt4 skips the test if mkfs.ext4 is not available.
func skipIfNoMkfsExt4(t *testing.T) {
	t.Helper()
	_, err := exec.LookPath("mkfs.ext4")
	if err != nil {
		t.Skip("mkfs.ext4 not found - skipping LUKS integration tests")
	}
}

// skipIfDevMapperUnavailable skips if /dev/mapper is not available.
func skipIfDevMapperUnavailable(t *testing.T) {
	t.Helper()
	if _, err := os.Stat("/dev/mapper"); os.IsNotExist(err) {
		t.Skip("/dev/mapper not available - skipping LUKS integration tests")
	}
}

// requireLUKSDependencies checks all LUKS test dependencies.
func requireLUKSDependencies(t *testing.T) {
	t.Helper()
	skipIfNotRoot(t)
	skipIfNoDMCrypt(t)
	skipIfNoMkfsExt4(t)
	skipIfDevMapperUnavailable(t)
}

// ensureCleanState cleans up any leftover LUKS devices from previous tests.
// This should be called before starting any test to ensure a clean state.
func ensureCleanState(t *testing.T) {
	t.Helper()

	// Close any open xkey mapper devices
	mapperNames := []string{"xkey", "xkey_old"}
	for _, name := range mapperNames {
		if isLUKSOpen(name) {
			t.Logf("Found leftover mapper device %s, closing...", name)
			_ = luks2.Lock(name)
		}
	}

	// Detach any leftover loop devices (be careful not to detach unrelated devices)
	// Only detach loop devices that are attached to files in temp directories
	// This is a best-effort cleanup
}

// createTempLUKSPaths creates temporary paths for LUKS testing.
// Returns a LUKSPaths struct with unique paths for this test.
func createTempLUKSPaths(t *testing.T) *LUKSPaths {
	t.Helper()

	// Ensure clean state before starting
	ensureCleanState(t)

	counter := testCounter.Add(1)
	timestamp := time.Now().UnixNano()

	baseDir, err := os.MkdirTemp("", fmt.Sprintf("xkey-luks-test-%d-%d-*", counter, timestamp))
	require.NoError(t, err, "Failed to create temp base directory")

	paths := &LUKSPaths{
		BaseDir:    baseDir,
		LUKSFile:   filepath.Join(baseDir, "test.luks"),
		MountPoint: filepath.Join(baseDir, "data"),
		DataDir:    filepath.Join(baseDir, "data"),
	}

	// Create the data directory
	err = os.MkdirAll(paths.DataDir, 0700)
	require.NoError(t, err, "Failed to create data directory")

	return paths
}

// cleanupLUKS cleans up LUKS volumes and temporary paths after tests.
// This function should be called in a defer block.
func cleanupLUKS(t *testing.T, paths *LUKSPaths) {
	t.Helper()

	if paths == nil {
		return
	}

	// Try to unmount if mounted using go-luks2
	if isMountPoint(paths.MountPoint) {
		_ = luks2.Unmount(paths.MountPoint, 0) // Ignore errors, volume might not be mounted
	}

	// Try to unmount any old mount points from migration tests
	oldMountPoint := paths.MountPoint + ".old-migrate"
	if isMountPoint(oldMountPoint) {
		_ = luks2.Unmount(oldMountPoint, 0)
	}

	// Try to close LUKS devices using the correct mapper name "xkey"
	// The code uses "xkey" as the mapper name, not a derived name
	mapperNames := []string{"xkey", "xkey_old"}
	for _, mapperName := range mapperNames {
		if isLUKSOpen(mapperName) {
			_ = luks2.Lock(mapperName) // Ignore errors
		}
	}

	// Find and detach any loop devices associated with our LUKS file using go-luks2
	loopDev, err := luks2.FindLoopDevice(paths.LUKSFile)
	if err == nil && loopDev != "" {
		_ = luks2.DetachLoopDevice(loopDev)
	}

	// Also check for .old backup file (from migration tests)
	oldLUKSFile := paths.LUKSFile + ".old"
	loopDevOld, err := luks2.FindLoopDevice(oldLUKSFile)
	if err == nil && loopDevOld != "" {
		_ = luks2.DetachLoopDevice(loopDevOld)
	}

	// Remove temporary directory
	if paths.BaseDir != "" {
		err := os.RemoveAll(paths.BaseDir)
		if err != nil {
			t.Logf("Warning: failed to clean up temp directory %s: %v", paths.BaseDir, err)
		}
	}
}

// deriveMapperName generates a mapper name from the LUKS file path.
func deriveMapperName(luksPath string) string {
	// Use a test-specific mapper name to avoid conflicts
	base := filepath.Base(luksPath)
	return fmt.Sprintf("xkey-test-%s", strings.TrimSuffix(base, ".luks"))
}

// isMountPoint checks if a path is a mount point.
func isMountPoint(path string) bool {
	// Read /proc/mounts
	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return false
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		absPath = path
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[1] == absPath {
			return true
		}
	}
	return false
}

// isLUKSOpen checks if a LUKS mapper device is open.
func isLUKSOpen(mapperName string) bool {
	path := filepath.Join("/dev/mapper", mapperName)
	_, err := os.Stat(path)
	return err == nil
}

// ExecResult holds the result of executing an xkey command.
type ExecResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Err      error
}

// execXkey executes the xkey binary with the given arguments.
// The passphrase is provided via stdin if non-empty.
func execXkey(t *testing.T, binaryPath string, args []string, passphrase string) *ExecResult {
	t.Helper()

	// Verify binary exists and is executable before attempting to run
	if info, err := os.Stat(binaryPath); err != nil {
		t.Logf("ERROR: xkey binary not found at %s: %v", binaryPath, err)
		return &ExecResult{
			Stderr:   fmt.Sprintf("binary not found: %s: %v", binaryPath, err),
			ExitCode: -1,
			Err:      err,
		}
	} else if info.IsDir() {
		t.Logf("ERROR: xkey binary path is a directory: %s", binaryPath)
		return &ExecResult{
			Stderr:   fmt.Sprintf("binary path is a directory: %s", binaryPath),
			ExitCode: -1,
			Err:      fmt.Errorf("binary path is a directory: %s", binaryPath),
		}
	}

	cmd := exec.Command(binaryPath, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if passphrase != "" {
		cmd.Stdin = strings.NewReader(passphrase)
	}

	err := cmd.Run()

	result := &ExecResult{
		Stdout: stdout.String(),
		Stderr: stderr.String(),
		Err:    err,
	}

	if exitErr, ok := err.(*exec.ExitError); ok {
		result.ExitCode = exitErr.ExitCode()
	} else if err == nil {
		result.ExitCode = 0
	} else {
		result.ExitCode = -1
		t.Logf("ERROR: command execution failed for %s: %v", binaryPath, err)
	}

	return result
}

// execXkeySeal executes the luks2 seal command.
func execXkeySeal(t *testing.T, binaryPath string, paths *LUKSPaths, passphrase, size string) *ExecResult {
	t.Helper()

	args := []string{
		"luks2", "seal",
		"--path", paths.LUKSFile,
		"--mount-point", paths.MountPoint,
		"--size", size,
	}

	// For seal, we need to provide passphrase twice (enter + confirm)
	passphraseInput := passphrase + "\n" + passphrase + "\n"

	return execXkey(t, binaryPath, args, passphraseInput)
}

// execXkeyUnseal executes the luks2 unseal command.
func execXkeyUnseal(t *testing.T, binaryPath string, paths *LUKSPaths, passphrase string) *ExecResult {
	t.Helper()

	args := []string{
		"luks2", "unseal",
		"--path", paths.LUKSFile,
		"--mount-point", paths.MountPoint,
	}

	return execXkey(t, binaryPath, args, passphrase+"\n")
}

// execXkeyLock executes the luks2 lock command.
func execXkeyLock(t *testing.T, binaryPath string, paths *LUKSPaths) *ExecResult {
	t.Helper()

	args := []string{
		"luks2", "lock",
		"--path", paths.LUKSFile,
		"--mount-point", paths.MountPoint,
	}

	return execXkey(t, binaryPath, args, "")
}

// execXkeyMigrate executes the luks2 migrate command.
// If paths is provided, --source-path is set to the test LUKS file path.
func execXkeyMigrate(t *testing.T, binaryPath string, paths *LUKSPaths, passphrase string, options ...string) *ExecResult {
	t.Helper()

	args := []string{
		"luks2", "migrate",
	}

	// If paths provided, add source path for test isolation
	if paths != nil {
		args = append(args, "--source-path", paths.LUKSFile)
	}

	args = append(args, options...)

	return execXkey(t, binaryPath, args, passphrase+"\n")
}

// execXkeyWipe executes the luks2 wipe command.
// Note: wipe does not require passphrase - it uses "DESTROY" confirmation.
func execXkeyWipe(t *testing.T, binaryPath string, paths *LUKSPaths, _ string, force bool) *ExecResult {
	t.Helper()

	args := []string{
		"luks2", "wipe",
		"--path", paths.LUKSFile,
		"--mount-point", paths.MountPoint,
	}

	if force {
		args = append(args, "--force")
	}

	// Wipe requires "DESTROY" confirmation when not using --force
	var input string
	if !force {
		input = "DESTROY\n"
	}

	return execXkey(t, binaryPath, args, input)
}

// createTestData creates test files and directories in the specified path.
// Returns a TestData struct for verification after operations.
func createTestData(t *testing.T, dataDir string) *TestData {
	t.Helper()

	testData := &TestData{
		Files: make(map[string][]byte),
		Dirs:  make([]string, 0),
	}

	// Create test files with different content
	files := map[string][]byte{
		"test.txt":          []byte("Hello, LUKS integration test!"),
		"config.json":       []byte(`{"setting": "value", "number": 42}`),
		"binary.dat":        make([]byte, 1024), // 1KB of data
		"nested/file.txt":   []byte("Nested file content"),
		"nested/deep/a.txt": []byte("Deeply nested file A"),
		"nested/deep/b.txt": []byte("Deeply nested file B"),
	}

	// Initialize binary data with pattern
	for i := range files["binary.dat"] {
		files["binary.dat"][i] = byte(i % 256)
	}

	for relPath, content := range files {
		fullPath := filepath.Join(dataDir, relPath)

		// Create parent directories if needed
		dir := filepath.Dir(fullPath)
		if dir != dataDir {
			err := os.MkdirAll(dir, 0700)
			require.NoError(t, err, "Failed to create directory: %s", dir)
			testData.Dirs = append(testData.Dirs, dir)
		}

		// Write file
		err := os.WriteFile(fullPath, content, 0600)
		require.NoError(t, err, "Failed to write test file: %s", fullPath)

		testData.Files[relPath] = content
	}

	return testData
}

// verifyTestData verifies that test data exists and matches expected content.
func verifyTestData(t *testing.T, dataDir string, expected *TestData) {
	t.Helper()

	for relPath, expectedContent := range expected.Files {
		fullPath := filepath.Join(dataDir, relPath)

		actualContent, err := os.ReadFile(fullPath)
		require.NoError(t, err, "Failed to read test file: %s", fullPath)
		require.Equal(t, expectedContent, actualContent, "Content mismatch for file: %s", relPath)
	}
}

// verifyNoData verifies that the data directory is empty or doesn't exist.
func verifyNoData(t *testing.T, dataDir string) {
	t.Helper()

	info, err := os.Stat(dataDir)
	if os.IsNotExist(err) {
		return // Directory doesn't exist, which is fine
	}
	require.NoError(t, err)

	if !info.IsDir() {
		t.Fatalf("Expected %s to be a directory or not exist", dataDir)
	}

	entries, err := os.ReadDir(dataDir)
	require.NoError(t, err)

	// Directory should be empty (mount point might exist but be empty)
	require.Empty(t, entries, "Data directory should be empty when locked")
}

// findXkeyBinary locates the xkey binary for testing.
func findXkeyBinary(t *testing.T) string {
	t.Helper()

	// Try common locations relative to the test directory
	candidates := []string{
		// From test/integration/luks directory
		"../../../../xkey",
		"../../../../cmd/xkey/xkey",
		"../../../xkey",
		"../../../cmd/xkey/xkey",
		"../../xkey",
		"../../cmd/xkey/xkey",
		"../xkey",
		"./xkey",
		// Absolute paths
		"/usr/local/bin/xkey",
		"/usr/bin/xkey",
	}

	for _, path := range candidates {
		absPath, err := filepath.Abs(path)
		if err != nil {
			continue
		}
		if _, err := os.Stat(absPath); err == nil {
			return absPath
		}
	}

	return ""
}

// buildXkeyBinary builds the xkey binary for testing.
func buildXkeyBinary(t *testing.T) string {
	t.Helper()

	// Create temp directory for the binary
	tmpDir, err := os.MkdirTemp("", "xkey-binary-*")
	require.NoError(t, err)

	binaryPath := filepath.Join(tmpDir, "xkey")

	// Find project root (xkey module root)
	projectRoot, err := filepath.Abs("../../..")
	require.NoError(t, err)

	// Build the binary
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
		t.Logf("Build output: %s", string(output))
		t.Fatalf("Failed to build xkey: %v", err)
	}

	t.Cleanup(func() {
		os.RemoveAll(tmpDir)
	})

	return binaryPath
}

// getOrBuildXkey returns the xkey binary for testing.
// It first checks for a pre-built binary in standard locations (devcontainer build path),
// and only builds a fresh binary if no pre-built binary is found.
func getOrBuildXkey(t *testing.T) string {
	t.Helper()

	// Check for pre-built binary in devcontainer build path
	prebuiltPaths := []string{
		"/workspace/build/bin/xkey", // Devcontainer standard path
	}

	for _, path := range prebuiltPaths {
		if info, err := os.Stat(path); err == nil {
			// Verify it's a file (not directory) and executable
			if !info.IsDir() && info.Mode()&0111 != 0 {
				t.Logf("Using pre-built xkey binary: %s", path)
				return path
			}
		}
	}

	// Try to find existing binary
	if existing := findXkeyBinary(t); existing != "" {
		t.Logf("Found existing xkey binary: %s", existing)
		return existing
	}

	// Build fresh if no pre-built binary found
	t.Log("No pre-built xkey binary found, building...")
	return buildXkeyBinary(t)
}

// passphraseFromEnv reads passphrase from environment variable if set.
// Falls back to the provided default if not set.
func passphraseFromEnv(defaultPassphrase string) string {
	if env := os.Getenv("XKEY_TEST_PASSPHRASE"); env != "" {
		return env
	}
	return defaultPassphrase
}

// simulatePassphraseInput creates a reader that provides passphrase input.
// This is useful for testing passphrase prompts.
func simulatePassphraseInput(passphrase string, confirmPassphrase bool) io.Reader {
	input := passphrase + "\n"
	if confirmPassphrase {
		input += passphrase + "\n"
	}
	return strings.NewReader(input)
}

// waitForMount waits for a mount point to become available.
func waitForMount(t *testing.T, mountPoint string, timeout time.Duration) bool {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if isMountPoint(mountPoint) {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

// waitForUnmount waits for a mount point to become unavailable.
func waitForUnmount(t *testing.T, mountPoint string, timeout time.Duration) bool {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !isMountPoint(mountPoint) {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

// assertFileExists asserts that a file exists at the given path.
func assertFileExists(t *testing.T, path string) {
	t.Helper()
	_, err := os.Stat(path)
	require.NoError(t, err, "Expected file to exist: %s", path)
}

// assertFileNotExists asserts that a file does not exist at the given path.
func assertFileNotExists(t *testing.T, path string) {
	t.Helper()
	_, err := os.Stat(path)
	require.True(t, os.IsNotExist(err), "Expected file to not exist: %s", path)
}

// assertDirExists asserts that a directory exists at the given path.
func assertDirExists(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	require.NoError(t, err, "Expected directory to exist: %s", path)
	require.True(t, info.IsDir(), "Expected %s to be a directory", path)
}

// assertDirNotExists asserts that a directory does not exist at the given path.
func assertDirNotExists(t *testing.T, path string) {
	t.Helper()
	_, err := os.Stat(path)
	require.True(t, os.IsNotExist(err), "Expected directory to not exist: %s", path)
}

// assertMounted asserts that the path is a mount point.
func assertMounted(t *testing.T, path string) {
	t.Helper()
	require.True(t, isMountPoint(path), "Expected %s to be mounted", path)
}

// assertNotMounted asserts that the path is not a mount point.
func assertNotMounted(t *testing.T, path string) {
	t.Helper()
	require.False(t, isMountPoint(path), "Expected %s to not be mounted", path)
}

// assertLUKSOpen asserts that the LUKS device is open.
func assertLUKSOpen(t *testing.T, mapperName string) {
	t.Helper()
	require.True(t, isLUKSOpen(mapperName), "Expected LUKS device %s to be open", mapperName)
}

// assertLUKSClosed asserts that the LUKS device is closed.
func assertLUKSClosed(t *testing.T, mapperName string) {
	t.Helper()
	require.False(t, isLUKSOpen(mapperName), "Expected LUKS device %s to be closed", mapperName)
}

// isLUKSVolume checks if a file is a valid LUKS volume by reading LUKS magic header.
func isLUKSVolume(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	header := make([]byte, 6)
	n, err := f.Read(header)
	if err != nil || n < 6 {
		return false
	}

	return bytes.Equal(header, luks2Magic)
}

// getLUKSInfo returns information about a LUKS volume.
// It reads the LUKS2 header to extract basic metadata.
func getLUKSInfo(t *testing.T, path string) map[string]string {
	t.Helper()

	info := make(map[string]string)

	// Check if it's a valid LUKS volume first
	if !isLUKSVolume(path) {
		return nil
	}

	// Read LUKS2 header to determine version
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	// LUKS2 has "LUKS" magic at offset 0, version at offset 6-7
	header := make([]byte, 8)
	n, err := f.Read(header)
	if err != nil || n < 8 {
		return nil
	}

	// LUKS version is a big-endian uint16 at offset 6
	version := uint16(header[6])<<8 | uint16(header[7])
	info["Version"] = fmt.Sprintf("%d", version)

	return info
}
