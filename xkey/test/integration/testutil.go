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

package xkey

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/uhid"
)

// pkgTempDir holds a package-level temporary directory for the compiled binary.
// It is created by TestMain and cleaned up after all tests complete.
var pkgTempDir string

// requireUHID fails the test if /dev/uhid is not available. The integration
// container loads the uhid module and runs with access to the device, so an
// unusable device is an environment fault rather than a reason to skip.
func requireUHID(t *testing.T) {
	t.Helper()

	if _, err := os.Stat(uhid.UHIDDevicePath); os.IsNotExist(err) {
		t.Fatalf("UHID not available at %s; run this suite via the devcontainer, "+
			"which loads the uhid module", uhid.UHIDDevicePath)
	}

	// Also check that we have permission to open the device.
	file, err := os.OpenFile(uhid.UHIDDevicePath, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("cannot open %s: %v; the integration container must run with "+
			"access to the uhid device", uhid.UHIDDevicePath, err)
	}
	file.Close()
}

// tempDir creates a temporary directory for test storage.
func tempDir(t *testing.T) string {
	t.Helper()

	dir, err := os.MkdirTemp("", "xkey-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}

	t.Cleanup(func() {
		os.RemoveAll(dir)
	})

	return dir
}

// findBinary searches for a pre-built xkey binary.
// It checks the project's cmd/xkey build output and common paths.
func findBinary(t *testing.T) string {
	t.Helper()

	candidates := []string{
		"./xkey",
		"../../../cmd/xkey/xkey",
		"/usr/local/bin/xkey",
		"/usr/bin/xkey",
	}

	for _, path := range candidates {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		// Must be a regular file (not a directory) and executable.
		if info.IsDir() {
			continue
		}
		if info.Mode()&0111 == 0 {
			continue
		}
		absPath, err := filepath.Abs(path)
		if err == nil {
			return absPath
		}
		return path
	}

	return ""
}

// cliBuildTags returns the build tags for the test-built xkey binary.
// The Makefile exports XKEY_CLI_BUILD_TAGS with the full production tag set
// (ble, production, codec_json, pkcs11, ...). Without it, the minimum tag
// set required for a functional CLI is used: codec_json is mandatory for
// the go-codec based DAOs (e.g. the authenticator RP policy store).
func cliBuildTags() string {
	if tags := os.Getenv("XKEY_CLI_BUILD_TAGS"); tags != "" {
		return tags
	}
	return "codec_json"
}

// buildBinary builds the xkey binary for testing.
// The binary is placed in the package-level pkgTempDir so it survives
// individual test cleanup. pkgTempDir is created in TestMain and removed
// after all tests complete.
func buildBinary(t *testing.T) string {
	t.Helper()

	if pkgTempDir == "" {
		t.Fatal("pkgTempDir not initialized; ensure TestMain calls setupPkgTempDir")
	}

	binaryPath := filepath.Join(pkgTempDir, "xkey")

	// Build the binary from the xkey module root (two levels up from test/integration/).
	xkeyRoot, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("Failed to get xkey root: %v", err)
	}

	cmd := exec.Command("go", "build", "-tags", cliBuildTags(), "-o", binaryPath, "./cmd/xkey")
	cmd.Dir = xkeyRoot

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("Build output: %s", string(output))
		t.Fatalf("Failed to build xkey: %v", err)
	}

	return binaryPath
}

// processRunning checks if a process with the given PID is running.
func processRunning(pid int) bool {
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	// On Unix, FindProcess always succeeds, so we need to send signal 0.
	err = process.Signal(syscall.Signal(0))
	return err == nil
}
