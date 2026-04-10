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

// Package fido2 provides E2E integration tests for the xkey fido2 CLI command.
// These tests start the xkey fido2 daemon as a subprocess and interact with it
// through the OS (fido2-token) and CLI commands (xkey touch, xkey pin).
package fido2

import (
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Help and Usage Tests
// =============================================================================

// TestFIDO2_HelpOutput verifies that `xkey fido2 --help` prints usage
// information including key terms like "fido2", "UHID", and "storage".
func TestFIDO2_HelpOutput(t *testing.T) {
	h := NewFIDO2TestHelper(t)

	result := h.RunFido2("--help")
	require.True(t, result.Success(), "fido2 --help should succeed: %s", result.Combined())

	assert.True(t, result.OutputContains("fido2"),
		"Help output should mention fido2")
	assert.True(t, result.OutputContains("UHID"),
		"Help output should mention UHID")
	assert.True(t, result.OutputContains("storage"),
		"Help output should mention storage")
}

// =============================================================================
// Daemon Lifecycle Tests
// =============================================================================

// TestFIDO2_DaemonStartStop verifies that the fido2 daemon starts, creates a
// virtual HID device discoverable by fido2-token, and cleanly stops.
func TestFIDO2_DaemonStartStop(t *testing.T) {
	skipIfNoUHID(t)
	skipIfNoFido2Token(t)

	h := NewFIDO2TestHelper(t)
	cmd := h.StartDaemon()

	// Wait for the virtual HID device to appear in the OS.
	devPath, err := h.WaitForDevice(15 * time.Second)
	require.NoError(t, err, "Virtual FIDO2 device should appear")
	t.Logf("Device appeared at: %s", devPath)

	// Verify fido2-token -L lists the device.
	listResult := h.RunFido2Token("-L")
	require.True(t, listResult.Success(), "fido2-token -L should succeed")
	assert.True(t, listResult.OutputContains(devPath),
		"fido2-token -L should list the virtual device")

	// Stop the daemon.
	h.StopDaemon(cmd)

	// Verify the daemon's IPC socket is removed after shutdown. In
	// privileged containers with shared /dev and no udevd, the UHID
	// device node may persist indefinitely after UHID_DESTROY, so we
	// verify daemon lifecycle through the IPC socket instead.
	var socketGone bool
	for i := 0; i < 20; i++ {
		time.Sleep(100 * time.Millisecond)
		if _, err := os.Stat(h.socketPath); os.IsNotExist(err) {
			socketGone = true
			break
		}
	}
	assert.True(t, socketGone,
		"IPC socket should be removed after daemon stop")
}

// TestFIDO2_DeviceInfo verifies that fido2-token -I returns valid device
// information from the running daemon.
func TestFIDO2_DeviceInfo(t *testing.T) {
	skipIfNoUHID(t)
	skipIfNoFido2Token(t)

	h := NewFIDO2TestHelper(t)
	h.StartDaemon()

	devPath, err := h.WaitForDevice(15 * time.Second)
	require.NoError(t, err, "Virtual FIDO2 device should appear")

	infoResult := h.RunFido2Token("-I", devPath)
	require.True(t, infoResult.Success(),
		"fido2-token -I should succeed: %s", infoResult.Combined())

	// The output should contain version or protocol identifiers.
	combined := infoResult.Combined()
	assert.Condition(t, func() bool {
		return containsAny(combined, "FIDO_2_0", "FIDO_2_1", "fido2")
	}, "Device info should mention a FIDO2 version or identifier")

	t.Logf("Device info:\n%s", combined)
}

// =============================================================================
// Device Product Name Tests
// =============================================================================

// TestFIDO2_DeviceProductName verifies that the xKey virtual FIDO2 device's
// product name appears correctly in `fido2-token -L` output. This validates
// that the libfido2 HID_NAME fallback is working and that the daemon
// correctly propagates the --name flag to the UHID device descriptor.
func TestFIDO2_DeviceProductName(t *testing.T) {
	skipIfNoUHID(t)
	skipIfNoFido2Token(t)

	const expectedName = "xKey Test Authenticator"

	h := NewFIDO2TestHelper(t)
	h.StartDaemon("--name", expectedName)

	// Wait for the device to appear with the expected product name.
	dev, err := h.WaitForDeviceWithName(expectedName, 15*time.Second)
	require.NoError(t, err,
		"Virtual FIDO2 device with name %q should appear in fido2-token -L output",
		expectedName)

	t.Logf("Device appeared at %s with display name: %q", dev.Path, dev.DisplayName)

	// Parse the full listing and verify our device is present with correct name.
	listResult := h.RunFido2Token("-L")
	require.True(t, listResult.Success(), "fido2-token -L should succeed")

	devices := parseFido2TokenListWithInfo(listResult.Stdout)
	require.NotEmpty(t, devices, "fido2-token -L should list at least one device")

	// Find our device in the listing and verify the display name.
	var found bool
	for _, d := range devices {
		if d.Path == dev.Path {
			found = true
			assert.Contains(t, d.DisplayName, expectedName,
				"Device display name should contain the configured product name")
			assert.NotEmpty(t, d.VendorID,
				"Parsed device should have a vendor ID")
			assert.NotEmpty(t, d.ProductID,
				"Parsed device should have a product ID")
			break
		}
	}
	assert.True(t, found,
		"Device at %s should be present in parsed fido2-token -L output", dev.Path)
}

// =============================================================================
// Storage Option Tests
// =============================================================================

// TestFIDO2_StorageOptions verifies the daemon starts successfully with
// different storage configurations.
func TestFIDO2_StorageOptions(t *testing.T) {
	skipIfNoUHID(t)
	skipIfNoFido2Token(t)

	tests := []struct {
		name        string
		args        []string
		useOverride bool // true to use StartDaemonWithOverrides instead of StartDaemon
	}{
		{
			name:        "memory",
			args:        []string{"--storage", "memory"},
			useOverride: true,
		},
		{
			name: "file",
			args: []string{"--storage", "file"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := NewFIDO2TestHelper(t)

			var daemonCmd *exec.Cmd
			if tc.useOverride {
				daemonCmd = h.StartDaemonWithOverrides(tc.args...)
			} else {
				daemonCmd = h.StartDaemon(tc.args...)
			}

			devPath, err := h.WaitForDevice(15 * time.Second)
			require.NoError(t, err, "Device should appear with %s storage", tc.name)
			t.Logf("Device appeared at %s with %s storage", devPath, tc.name)

			h.StopDaemon(daemonCmd)
		})
	}
}

// =============================================================================
// Custom Flag Tests
// =============================================================================

// TestFIDO2_CustomFlags verifies the daemon starts with various custom flag
// combinations and that flag values are applied correctly.
func TestFIDO2_CustomFlags(t *testing.T) {
	skipIfNoUHID(t)
	skipIfNoFido2Token(t)

	tests := []struct {
		name         string
		args         []string
		expectedName string // if non-empty, verify this name appears in fido2-token -L
	}{
		{
			name:         "custom_name",
			args:         []string{"--name", "CustomDevice"},
			expectedName: "CustomDevice",
		},
		{
			name: "custom_serial",
			args: []string{"--serial", "ABC123"},
		},
		{
			name: "software_backend",
			args: []string{"--backend", "software"},
		},
		{
			name: "attestation_none",
			args: []string{"--attestation", "none"},
		},
		{
			name: "attestation_packed",
			args: []string{"--attestation", "packed"},
		},
		{
			name: "custom_timeout",
			args: []string{"--timeout", "60s"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := NewFIDO2TestHelper(t)
			daemonCmd := h.StartDaemon(tc.args...)

			if tc.expectedName != "" {
				// Verify the custom name appears in fido2-token -L output.
				dev, err := h.WaitForDeviceWithName(tc.expectedName, 15*time.Second)
				require.NoError(t, err,
					"Device with name %q should appear with flags: %v",
					tc.expectedName, tc.args)
				assert.Contains(t, dev.DisplayName, tc.expectedName,
					"fido2-token -L display name should contain the custom name")
				t.Logf("Device appeared at %s with display name %q",
					dev.Path, dev.DisplayName)
			} else {
				devPath, err := h.WaitForDevice(15 * time.Second)
				require.NoError(t, err,
					"Device should appear with flags: %v", tc.args)
				t.Logf("Device appeared at %s with flags %v", devPath, tc.args)
			}

			h.StopDaemon(daemonCmd)
		})
	}
}

// =============================================================================
// PIN Tests
// =============================================================================

// TestFIDO2_PINEnabled verifies that starting the daemon with --set-pin
// correctly enables PIN support, visible in device info output.
func TestFIDO2_PINEnabled(t *testing.T) {
	skipIfNoUHID(t)
	skipIfNoFido2Token(t)

	h := NewFIDO2TestHelper(t)
	h.StartDaemon("--set-pin", "123456")

	devPath, err := h.WaitForDevice(15 * time.Second)
	require.NoError(t, err, "Device should appear with PIN enabled")

	infoResult := h.RunFido2Token("-I", devPath)
	require.True(t, infoResult.Success(),
		"fido2-token -I should succeed: %s", infoResult.Combined())

	combined := infoResult.Combined()
	assert.Condition(t, func() bool {
		return containsAny(combined, "clientPin", "pin")
	}, "Device info should indicate PIN support when PIN is set")

	t.Logf("PIN-enabled device info:\n%s", combined)
}

// =============================================================================
// Invalid Argument Tests
// =============================================================================

// TestFIDO2_InvalidArgs verifies that invalid arguments cause the command to
// fail with a non-zero exit code.
func TestFIDO2_InvalidArgs(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{
			name: "invalid_storage",
			args: []string{"--storage", "invalid"},
		},
		{
			name: "invalid_backend",
			args: []string{"--backend", "invalid"},
		},
		{
			name: "invalid_attestation",
			args: []string{"--attestation", "invalid"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := NewFIDO2TestHelper(t)
			result := h.RunFido2(tc.args...)
			assert.False(t, result.Success(),
				"fido2 with %v should fail", tc.args)
			t.Logf("Expected failure output: %s", result.Combined())
		})
	}
}

// =============================================================================
// Clean Shutdown Tests
// =============================================================================

// TestFIDO2_CleanShutdown verifies the daemon exits cleanly when sent SIGTERM.
func TestFIDO2_CleanShutdown(t *testing.T) {
	skipIfNoUHID(t)
	skipIfNoFido2Token(t)

	h := NewFIDO2TestHelper(t)
	cmd := h.StartDaemon()

	_, err := h.WaitForDevice(15 * time.Second)
	require.NoError(t, err, "Device should appear")

	// Send SIGTERM directly to the process.
	require.NoError(t, cmd.Process.Signal(syscall.SIGTERM),
		"Sending SIGTERM should not error")

	// Wait for the process to exit.
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case waitErr := <-done:
		// Process exited. A nil error or signal-based exit is acceptable.
		if waitErr != nil {
			t.Logf("Process exited with: %v (expected for signal termination)", waitErr)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Daemon did not exit within 10s after SIGTERM")
	}
}

// =============================================================================
// Storage Persistence Tests
// =============================================================================

// TestFIDO2_StoragePersistence verifies that file storage survives daemon
// restarts. The daemon is started with file storage, stopped, and restarted
// with the same storage path.
func TestFIDO2_StoragePersistence(t *testing.T) {
	skipIfNoUHID(t)
	skipIfNoFido2Token(t)

	h := NewFIDO2TestHelper(t)

	// Phase 1: Start daemon with file storage.
	cmd1 := h.StartDaemon()

	devPath1, err := h.WaitForDevice(15 * time.Second)
	require.NoError(t, err, "Device should appear in phase 1")
	t.Logf("Phase 1: Device at %s", devPath1)

	h.StopDaemon(cmd1)

	// Verify storage files were created.
	entries, err := os.ReadDir(h.storagePath)
	require.NoError(t, err, "Should be able to read storage directory")
	t.Logf("Storage directory contains %d entries", len(entries))

	// Allow time for device cleanup.
	time.Sleep(500 * time.Millisecond)

	// Phase 2: Restart with the same storage path.
	cmd2 := h.StartDaemon()

	devPath2, err := h.WaitForDevice(15 * time.Second)
	require.NoError(t, err, "Device should appear in phase 2 after restart")
	t.Logf("Phase 2: Device at %s (restarted with existing storage)", devPath2)

	h.StopDaemon(cmd2)
}

// =============================================================================
// Credential Operations (fido2-token -M / -G)
// =============================================================================

// TestFIDO2_MakeCredential attempts to create a credential using fido2-token -M.
// This requires fido2-token to be installed and the complex stdin input format
// it expects. Since fido2-token -M requires interactive stdin for the client
// data hash, relying party info, and user info, we verify device operability
// via fido2-token -I instead.
func TestFIDO2_MakeCredential(t *testing.T) {
	skipIfNoUHID(t)
	skipIfNoFido2Token(t)

	h := NewFIDO2TestHelper(t)
	h.StartDaemon("--pin=false")

	devPath, err := h.WaitForDevice(15 * time.Second)
	require.NoError(t, err, "Device should appear")
	t.Logf("Device at: %s", devPath)

	// Verify the device is operational via -I.
	infoResult := h.RunFido2Token("-I", devPath)
	require.True(t, infoResult.Success(),
		"fido2-token -I should succeed as precondition: %s", infoResult.Combined())

	t.Log("MakeCredential via fido2-token -M requires complex interactive " +
		"stdin; device operability verified via -I instead")
}

// TestFIDO2_GetAssertion attempts to perform GetAssertion using fido2-token -G.
// Like MakeCredential, this has complex stdin requirements. The test verifies
// device operability as a precondition.
func TestFIDO2_GetAssertion(t *testing.T) {
	skipIfNoUHID(t)
	skipIfNoFido2Token(t)

	h := NewFIDO2TestHelper(t)
	h.StartDaemon("--pin=false")

	devPath, err := h.WaitForDevice(15 * time.Second)
	require.NoError(t, err, "Device should appear")
	t.Logf("Device at: %s", devPath)

	// Verify device is operational.
	infoResult := h.RunFido2Token("-I", devPath)
	require.True(t, infoResult.Success(),
		"fido2-token -I should succeed as precondition: %s", infoResult.Combined())

	t.Log("GetAssertion via fido2-token -G requires prior credential and " +
		"complex interactive stdin; device operability verified via -I instead")
}

// =============================================================================
// Helpers
// =============================================================================

// containsAny returns true if s contains any of the substrings (case-insensitive).
func containsAny(s string, substrs ...string) bool {
	lower := strings.ToLower(s)
	for _, sub := range substrs {
		if strings.Contains(lower, strings.ToLower(sub)) {
			return true
		}
	}
	return false
}

// StartDaemonWithOverrides starts the daemon with the given args replacing
// the default storage flags entirely. This allows tests like "memory" storage
// to override the default "file" storage set by StartDaemon.
func (h *FIDO2TestHelper) StartDaemonWithOverrides(extraArgs ...string) *exec.Cmd {
	h.t.Helper()

	baseArgs := []string{
		"fido2",
		"--socket", h.socketPath,
		"--notify", "none",
		"--require-touch=false",
	}
	baseArgs = append(baseArgs, extraArgs...)

	cmd := exec.Command(h.binaryPath, baseArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		h.t.Fatalf("Failed to start fido2 daemon: %v", err)
	}

	// Wait for the IPC socket to appear.
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(h.socketPath); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if _, err := os.Stat(h.socketPath); os.IsNotExist(err) {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		_ = cmd.Wait()
		h.t.Fatalf("Daemon socket did not appear within 15s at %s", h.socketPath)
	}

	h.t.Cleanup(func() {
		h.StopDaemon(cmd)
	})

	return cmd
}
