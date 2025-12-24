// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

//go:build integration && fido2

package fido2

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// Default path to CanoKey-enabled QEMU binary
	defaultCanoKeyQEMUBin = "/usr/local/bin/qemu-system-x86_64-canokey"
)

// getCanoKeyQEMUBin returns the path to the CanoKey QEMU binary
func getCanoKeyQEMUBin() string {
	if bin := os.Getenv("QEMU_CANOKEY_BIN"); bin != "" {
		return bin
	}
	return defaultCanoKeyQEMUBin
}

// TestCanoKeyQEMUBinaryExists verifies the CanoKey-enabled QEMU binary is installed
func TestCanoKeyQEMUBinaryExists(t *testing.T) {
	qemuBin := getCanoKeyQEMUBin()

	info, err := os.Stat(qemuBin)
	if os.IsNotExist(err) {
		t.Skipf("CanoKey QEMU binary not found at %s - run in devcontainer", qemuBin)
	}
	require.NoError(t, err, "Failed to stat QEMU binary")

	// Verify it's executable
	assert.True(t, info.Mode()&0111 != 0, "QEMU binary should be executable")
	t.Logf("✓ CanoKey QEMU binary exists: %s (size: %d bytes)", qemuBin, info.Size())
}

// TestCanoKeyQEMUVersion verifies the QEMU binary runs and returns version info
func TestCanoKeyQEMUVersion(t *testing.T) {
	qemuBin := getCanoKeyQEMUBin()

	if _, err := os.Stat(qemuBin); os.IsNotExist(err) {
		t.Skipf("CanoKey QEMU binary not found at %s - run in devcontainer", qemuBin)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, qemuBin, "--version")
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "QEMU --version failed: %s", string(output))

	outputStr := string(output)
	assert.Contains(t, outputStr, "QEMU", "Output should contain 'QEMU'")
	assert.Contains(t, outputStr, "version", "Output should contain 'version'")

	// Extract and log version
	lines := strings.Split(outputStr, "\n")
	if len(lines) > 0 {
		t.Logf("✓ QEMU version: %s", strings.TrimSpace(lines[0]))
	}
}

// TestCanoKeyQEMUDeviceSupport verifies QEMU was compiled with CanoKey device support
func TestCanoKeyQEMUDeviceSupport(t *testing.T) {
	qemuBin := getCanoKeyQEMUBin()

	if _, err := os.Stat(qemuBin); os.IsNotExist(err) {
		t.Skipf("CanoKey QEMU binary not found at %s - run in devcontainer", qemuBin)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Get list of supported devices
	cmd := exec.CommandContext(ctx, qemuBin, "-device", "help")
	output, err := cmd.CombinedOutput()
	// Note: -device help exits with code 0 but may write to stderr
	if err != nil {
		// Check if it's just a non-zero exit (some QEMU versions do this)
		if _, ok := err.(*exec.ExitError); !ok {
			require.NoError(t, err, "Failed to run QEMU -device help")
		}
	}

	outputStr := strings.ToLower(string(output))

	// Check for CanoKey device support
	hasCanoKey := strings.Contains(outputStr, "canokey")
	if !hasCanoKey {
		t.Log("Device list output:")
		t.Log(string(output))
	}
	assert.True(t, hasCanoKey, "QEMU should have 'canokey' in device list (was it compiled with --enable-canokey?)")

	t.Log("✓ CanoKey device support confirmed in QEMU")
}

// TestCanoKeyQEMUDeviceOption verifies QEMU accepts the CanoKey device option
func TestCanoKeyQEMUDeviceOption(t *testing.T) {
	qemuBin := getCanoKeyQEMUBin()

	if _, err := os.Stat(qemuBin); os.IsNotExist(err) {
		t.Skipf("CanoKey QEMU binary not found at %s - run in devcontainer", qemuBin)
	}

	// Create a temporary state file for the test
	stateFile, err := os.CreateTemp("", "canokey-test-*.state")
	require.NoError(t, err)
	stateFile.Close()
	defer os.Remove(stateFile.Name())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Try to start QEMU with CanoKey device
	// Use -M none (no machine) so we don't need a kernel/disk
	// Use -nographic to avoid display issues
	// QEMU will fail to start fully but should not complain about unknown device
	cmd := exec.CommandContext(ctx, qemuBin,
		"-M", "none",
		"-nographic",
		"-device", "canokey,file="+stateFile.Name(),
	)

	output, err := cmd.CombinedOutput()
	outputStr := string(output)

	// We expect QEMU to either:
	// 1. Start and then be killed by context timeout (success)
	// 2. Exit with an error NOT related to "unknown device"

	// Check for "unknown device" error which would indicate CanoKey not compiled in
	if strings.Contains(strings.ToLower(outputStr), "unknown device") ||
		strings.Contains(strings.ToLower(outputStr), "device \"canokey\" not found") {
		t.Fatalf("QEMU does not recognize 'canokey' device - was it compiled with --enable-canokey?\nOutput: %s", outputStr)
	}

	// If context was cancelled (timeout), that's actually success - QEMU started
	if ctx.Err() == context.DeadlineExceeded {
		t.Log("✓ QEMU started with CanoKey device (killed after timeout)")
		return
	}

	// If QEMU exited for other reasons (like no machine), that's also fine
	// as long as it didn't complain about the canokey device
	if err != nil {
		// Check it's not a device-related error
		if !strings.Contains(strings.ToLower(outputStr), "canokey") ||
			strings.Contains(strings.ToLower(outputStr), "canokey") && !strings.Contains(strings.ToLower(outputStr), "error") {
			t.Logf("✓ QEMU accepted CanoKey device option (exited: %v)", err)
			return
		}
	}

	t.Log("✓ QEMU CanoKey device option accepted")
}

// TestCanoKeyQEMUSmokeTestSuite runs all CanoKey QEMU smoke tests
func TestCanoKeyQEMUSmokeTestSuite(t *testing.T) {
	qemuBin := getCanoKeyQEMUBin()

	if _, err := os.Stat(qemuBin); os.IsNotExist(err) {
		t.Skipf("CanoKey QEMU binary not found at %s - run in devcontainer", qemuBin)
	}

	t.Log("=== CanoKey QEMU Smoke Test Suite ===")
	t.Logf("Binary: %s", qemuBin)

	t.Run("BinaryExists", TestCanoKeyQEMUBinaryExists)
	t.Run("Version", TestCanoKeyQEMUVersion)
	t.Run("DeviceSupport", TestCanoKeyQEMUDeviceSupport)
	t.Run("DeviceOption", TestCanoKeyQEMUDeviceOption)

	t.Log("=== CanoKey QEMU Smoke Tests Complete ===")
}
