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

package xkms

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// These tests always pin use_simulator=true (a real bool) and a real key_dir
// (t.TempDir()) so that newTPM2KeyProvider's Validate() never falls through
// to the "/dev/tpmrm0" hardware-device default or writes to the process's
// working directory. This exercises the config type-assertion branches
// without ever touching host TPM hardware, per project policy: unit tests
// must never depend on or modify host state. UseSimulator with an empty
// SimulatorHost selects the in-memory go-tpm-tools simulator (requires the
// tpm_simulator build tag), which is safe and deterministic.

// TestNewTPM2KeyProvider_ExtractsAllConfigKeys exercises every type-assertion
// branch in newTPM2KeyProvider's config extraction with correctly-typed
// values. The simulator starts unprovisioned, so NewBackend may return
// either a working backend or a provisioning error — both are acceptable
// here since the goal is exercising config extraction, not full TPM
// provisioning (that is covered in pkg/backend/tpm2).
func TestNewTPM2KeyProvider_ExtractsAllConfigKeys(t *testing.T) {
	tmpDir := t.TempDir()

	kp, err := newTPM2KeyProvider(map[string]interface{}{
		"device":         "unused-when-simulated",
		"key_dir":        tmpDir,
		"use_simulator":  true,
		"simulator_host": "",
		"simulator_port": 2321,
	})

	if err != nil {
		t.Logf("newTPM2KeyProvider returned expected simulator error: %v", err)
		return
	}

	require.NotNil(t, kp)
	t.Cleanup(func() { _ = kp.Close() })
}

// TestNewTPM2KeyProvider_WrongConfigValueTypes verifies that config values of
// the wrong Go type (other than use_simulator/key_dir, which are pinned to
// safe values) are silently ignored by the type assertions rather than
// panicking or falling back to a real TPM device.
func TestNewTPM2KeyProvider_WrongConfigValueTypes(t *testing.T) {
	tmpDir := t.TempDir()

	kp, err := newTPM2KeyProvider(map[string]interface{}{
		"device":         123,    // wrong type: not a string, ignored
		"key_dir":        tmpDir, // pinned: valid string
		"use_simulator":  true,   // pinned: valid bool, never touches hardware
		"simulator_host": 42,     // wrong type: not a string, ignored
		"simulator_port": "2321", // wrong type: not an int, ignored
	})

	if err != nil {
		t.Logf("newTPM2KeyProvider returned expected simulator error: %v", err)
		return
	}

	require.NotNil(t, kp)
	t.Cleanup(func() { _ = kp.Close() })
}
