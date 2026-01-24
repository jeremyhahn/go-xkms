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

//go:build integration && linux

package vfido2

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/uhid"
)

// testCounter ensures unique device names across tests.
var testCounter atomic.Uint64

// skipIfNoUHID skips the test if /dev/uhid is not available.
func skipIfNoUHID(t *testing.T) {
	t.Helper()

	if _, err := os.Stat(uhid.UHIDDevicePath); os.IsNotExist(err) {
		t.Skip("UHID not available at /dev/uhid - skipping integration test")
	}

	// Also check if we have permission to open the device
	file, err := os.OpenFile(uhid.UHIDDevicePath, os.O_RDWR, 0)
	if err != nil {
		t.Skipf("Cannot open /dev/uhid (permission denied?) - skipping: %v", err)
	}
	file.Close()
}

// generateUniqueSerial generates a unique serial number for testing.
func generateUniqueSerial() string {
	counter := testCounter.Add(1)
	return fmt.Sprintf("VFIDO-TEST-%06d", counter)
}

// generateUniqueName generates a unique device name for testing.
func generateUniqueName(prefix string) string {
	counter := testCounter.Add(1)
	return fmt.Sprintf("%s-%d", prefix, counter)
}

// waitForDevice waits for a FIDO2 device to appear by checking hidraw devices.
// Returns true if a FIDO2 device was detected, false on timeout.
func waitForDevice(t *testing.T, timeout time.Duration) bool {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return false
		case <-ticker.C:
			if hasFIDO2Device() {
				return true
			}
		}
	}
}

// hasFIDO2Device checks if any FIDO2 device is available.
// It uses fido2-token -L if available, otherwise falls back to checking hidraw devices.
func hasFIDO2Device() bool {
	// Try fido2-token first
	if fido2TokenPath, err := exec.LookPath("fido2-token"); err == nil {
		cmd := exec.Command(fido2TokenPath, "-L")
		output, err := cmd.Output()
		if err == nil && len(output) > 0 {
			return true
		}
	}

	// Fallback to checking hidraw devices with FIDO usage page
	matches, _ := filepath.Glob("/dev/hidraw*")
	for _, path := range matches {
		if isFIDO2HIDDevice(path) {
			return true
		}
	}

	return false
}

// isFIDO2HIDDevice checks if a hidraw device is a FIDO2 device.
// This is a basic check - proper detection would require reading the HID descriptor.
func isFIDO2HIDDevice(path string) bool {
	// Try to open the device
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return false
	}
	defer file.Close()

	// Check for corresponding sysfs entry with FIDO usage page
	// This is device-specific and may not work for all setups
	deviceName := filepath.Base(path)
	sysfsPath := filepath.Join("/sys/class/hidraw", deviceName, "device/uevent")

	content, err := os.ReadFile(sysfsPath)
	if err != nil {
		return false
	}

	// Look for FIDO-related identifiers in uevent
	contentStr := string(content)
	// FIDO Alliance VID: 0xF1D0
	return containsAny(contentStr, "VENDOR_ID=F1D0", "VENDOR_ID=f1d0", "HID_NAME=.*FIDO")
}

// containsAny checks if s contains any of the given substrings.
func containsAny(s string, substrs ...string) bool {
	for _, substr := range substrs {
		if len(s) >= len(substr) {
			for i := 0; i <= len(s)-len(substr); i++ {
				if s[i:i+len(substr)] == substr {
					return true
				}
			}
		}
	}
	return false
}

// tempDir creates a temporary directory for test storage.
func tempDir(t *testing.T) string {
	t.Helper()

	dir, err := os.MkdirTemp("", "vfido2-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}

	t.Cleanup(func() {
		os.RemoveAll(dir)
	})

	return dir
}

// findBinary searches for the vfido2 binary.
// It checks the project's cmd/vfido2 build output and common paths.
func findBinary(t *testing.T) string {
	t.Helper()

	// Try common locations
	candidates := []string{
		"./vfido2",
		"../../../vfido2",
		"../../../cmd/vfido2/vfido2",
		"/usr/local/bin/vfido2",
		"/usr/bin/vfido2",
	}

	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			absPath, err := filepath.Abs(path)
			if err == nil {
				return absPath
			}
			return path
		}
	}

	return ""
}

// buildBinary builds the vfido2 binary for testing.
// Returns the path to the built binary.
func buildBinary(t *testing.T) string {
	t.Helper()

	// Create temp directory for the binary
	tmpDir := tempDir(t)
	binaryPath := filepath.Join(tmpDir, "vfido2")

	// Build the binary from the project root
	projectRoot, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatalf("Failed to get project root: %v", err)
	}

	cmd := exec.Command("go", "build", "-o", binaryPath, "./cmd/vfido2")
	cmd.Dir = projectRoot

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("Build output: %s", string(output))
		t.Fatalf("Failed to build vfido2: %v", err)
	}

	return binaryPath
}

// processRunning checks if a process with the given PID is running.
func processRunning(pid int) bool {
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	// On Unix, FindProcess always succeeds, so we need to send signal 0
	err = process.Signal(syscall.Signal(0))
	return err == nil
}
