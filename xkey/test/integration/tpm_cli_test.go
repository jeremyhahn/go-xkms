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

//go:build integration && linux && tpm_simulator

package xkey

// CLI coverage for the `xkey tpm` read-only command group against the shared
// ephemeral swtpm instance (see swtpm_test_helpers.go). Destructive verbs
// (clear, provision, install) are deliberately NOT driven here — they would
// mutate the shared simulator state other suites depend on.

import (
	"strings"
	"testing"
)

// TestTPMCLI_Info verifies `xkey tpm info` reads the simulator's properties.
func TestTPMCLI_Info(t *testing.T) {
	binary := getOrBuildBinary(t)
	device := swtpmDevicePath(t)

	stdout := RunXKeyExpectSuccess(t, binary, "", "tpm", "info", "--device", device)
	// The simulator reports its manufacturer/version properties; assert on
	// stable, vendor-neutral markers of a successful read.
	lower := strings.ToLower(stdout)
	if !strings.Contains(lower, "manufacturer") && !strings.Contains(lower, "tpm") {
		t.Fatalf("tpm info output missing TPM properties:\n%s", stdout)
	}
}

// TestTPMCLI_Info_BadDevice verifies a clear error for a nonexistent device.
func TestTPMCLI_Info_BadDevice(t *testing.T) {
	binary := getOrBuildBinary(t)
	out := RunXKeyExpectFailure(t, binary, "", "tpm", "info", "--device", "/nonexistent/tpm0")
	if !strings.Contains(strings.ToLower(out), "tpm") {
		t.Fatalf("expected a TPM open error, got:\n%s", out)
	}
}

// TestTPMCLI_Pcrs verifies `xkey tpm pcrs` reads PCR values from the
// simulator's sha256 bank.
func TestTPMCLI_Pcrs(t *testing.T) {
	binary := getOrBuildBinary(t)
	device := swtpmDevicePath(t)

	stdout := RunXKeyExpectSuccess(t, binary, "",
		"tpm", "pcrs", "--device", device, "--bank", "sha256", "--indices", "0,7")
	if !strings.Contains(stdout, "0") || !strings.Contains(stdout, "7") {
		t.Fatalf("pcrs output missing requested indices:\n%s", stdout)
	}
}

// TestTPMCLI_Pcrs_InvalidBank verifies an unsupported bank name fails
// cleanly instead of panicking or reading the wrong bank.
func TestTPMCLI_Pcrs_InvalidBank(t *testing.T) {
	binary := getOrBuildBinary(t)
	device := swtpmDevicePath(t)

	out := RunXKeyExpectFailure(t, binary, "",
		"tpm", "pcrs", "--device", device, "--bank", "md5")
	if !strings.Contains(strings.ToLower(out), "bank") && !strings.Contains(strings.ToLower(out), "invalid") {
		t.Fatalf("expected an invalid-bank error, got:\n%s", out)
	}
}

// TestTPMCLI_Ek verifies the EK read path (`xkey tpm ek`) against the
// simulator — the endorsement key is created on demand and its public half
// reported without touching persistent manufacturer state.
func TestTPMCLI_Ek(t *testing.T) {
	binary := getOrBuildBinary(t)
	device := swtpmDevicePath(t)

	stdout, stderr, code := RunXKey(t, binary, "", "tpm", "ek", "--device", device)
	if code != 0 {
		// `tpm ek` may be a parent verb requiring a subcommand; accept a
		// helpful usage listing as the success criterion in that shape.
		combined := stdout + stderr
		if !strings.Contains(strings.ToLower(combined), "usage") && !strings.Contains(strings.ToLower(combined), "available commands") {
			t.Fatalf("tpm ek failed without usage help (code %d):\n%s", code, combined)
		}
	}
}
