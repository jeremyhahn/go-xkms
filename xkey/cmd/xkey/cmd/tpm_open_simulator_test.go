// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

//go:build tpm_simulator

// These tests exercise openTPM, openTPMForProvisioning and
// openTPMForProvisioningWithPCROverrides (tpm.go) -- the `tpm` command
// group's own TPM-opening primitives, distinct from openTPMModule which the
// barrier/PIN code paths share -- against the in-process TPM 2.0 simulator.
// The simulator is entirely in-memory; it never touches the host
// filesystem or a physical device. Every subtest saves and restores tpmCfg,
// the package-level flag state these functions read, and closes its TPM
// before returning so a later simulator open in the same test binary never
// blocks on the process-wide simulator lock (see pkg/tpm2.OpenSimulator).
package cmd

import (
	"errors"
	"path/filepath"
	"testing"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// withTPMCfg sets tpmCfg to a copy with the given mutations applied,
// restoring the original *tpmCfg contents on test cleanup.
func withTPMCfg(t *testing.T, mutate func(*tpmConfig)) {
	t.Helper()
	saved := *tpmCfg
	t.Cleanup(func() { *tpmCfg = saved })
	mutate(tpmCfg)
}

// TestOpenTPM_Simulator_NotInitialized proves openTPM's ErrTPMNotInitialized
// branch: unlike openTPMForProvisioning, openTPM requires a provisioned TPM
// and turns the SDK's ErrTPMNotInitialized into its own package sentinel of
// the same name, while still handing back a live, usable TPM handle (the
// caller may still want FixedProperties/EKAttributes to check what is
// present) rather than nil.
func TestOpenTPM_Simulator_NotInitialized(t *testing.T) {
	withTPMCfg(t, func(c *tpmConfig) {
		c.useSimulator = true
	})

	tpm, err := openTPM()
	if !errors.Is(err, ErrTPMNotInitialized) {
		t.Fatalf("openTPM() error = %v, want errors.Is ErrTPMNotInitialized", err)
	}
	if tpm == nil {
		t.Fatal("openTPM() tpm = nil, want a live handle even when not initialized")
	}
	defer func() {
		if closeErr := tpm.Close(); closeErr != nil {
			t.Errorf("tpm.Close() error = %v", closeErr)
		}
	}()

	if _, err := tpm.FixedProperties(); err != nil {
		t.Errorf("FixedProperties() error = %v, want nil", err)
	}
}

func TestOpenTPM_DeviceNotFound(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-such-tpm-device")
	withTPMCfg(t, func(c *tpmConfig) {
		c.useSimulator = false
		c.device = missing
	})

	tpm, err := openTPM()
	if err == nil {
		t.Fatal("openTPM() error = nil, want a device-open error")
	}
	if tpm != nil {
		t.Errorf("openTPM() tpm = %v, want nil on error", tpm)
	}
	if !errors.Is(err, xkms.ErrTPMOpeningDevice) {
		t.Errorf("openTPM() error = %v, want errors.Is ErrTPMOpeningDevice", err)
	}
}

func TestOpenTPMForProvisioning_Simulator_Success(t *testing.T) {
	withTPMCfg(t, func(c *tpmConfig) {
		c.useSimulator = true
	})

	tpm, err := openTPMForProvisioning()
	if err != nil {
		t.Fatalf("openTPMForProvisioning() error = %v, want nil", err)
	}
	defer func() {
		if closeErr := tpm.Close(); closeErr != nil {
			t.Errorf("tpm.Close() error = %v", closeErr)
		}
	}()

	if _, err := tpm.FixedProperties(); err != nil {
		t.Errorf("FixedProperties() error = %v, want nil", err)
	}
}

func TestOpenTPMForProvisioning_DeviceNotFound(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-such-tpm-device")
	withTPMCfg(t, func(c *tpmConfig) {
		c.useSimulator = false
		c.device = missing
	})

	tpm, err := openTPMForProvisioning()
	if err == nil {
		t.Fatal("openTPMForProvisioning() error = nil, want a device-open error")
	}
	if tpm != nil {
		t.Errorf("openTPMForProvisioning() tpm = %v, want nil on error", tpm)
	}
	if !errors.Is(err, xkms.ErrTPMOpeningDevice) {
		t.Errorf("openTPMForProvisioning() error = %v, want errors.Is ErrTPMOpeningDevice", err)
	}
}

func TestOpenTPMForProvisioningWithPCROverrides_Simulator_Success(t *testing.T) {
	withTPMCfg(t, func(c *tpmConfig) {
		c.useSimulator = true
	})

	tpm, err := openTPMForProvisioningWithPCROverrides("sha256", []uint{0, 1, 7}, 16)
	if err != nil {
		t.Fatalf("openTPMForProvisioningWithPCROverrides() error = %v, want nil", err)
	}
	defer func() {
		if closeErr := tpm.Close(); closeErr != nil {
			t.Errorf("tpm.Close() error = %v", closeErr)
		}
	}()

	if _, err := tpm.FixedProperties(); err != nil {
		t.Errorf("FixedProperties() error = %v, want nil", err)
	}
}

func TestOpenTPMForProvisioningWithPCROverrides_DeviceNotFound(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-such-tpm-device")
	withTPMCfg(t, func(c *tpmConfig) {
		c.useSimulator = false
		c.device = missing
	})

	tpm, err := openTPMForProvisioningWithPCROverrides("sha256", nil, 0)
	if err == nil {
		t.Fatal("openTPMForProvisioningWithPCROverrides() error = nil, want a device-open error")
	}
	if tpm != nil {
		t.Errorf("openTPMForProvisioningWithPCROverrides() tpm = %v, want nil on error", tpm)
	}
	if !errors.Is(err, xkms.ErrTPMOpeningDevice) {
		t.Errorf("openTPMForProvisioningWithPCROverrides() error = %v, want errors.Is ErrTPMOpeningDevice", err)
	}
}
