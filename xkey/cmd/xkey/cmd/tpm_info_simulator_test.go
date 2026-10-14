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

// These tests exercise runTPMInfo, buildTPMInfo and
// TPMInfo.checkProvisioningState (tpm_info.go) against the in-process TPM
// 2.0 simulator. The simulator is entirely in-memory; it never touches the
// host filesystem or a physical device. Each test saves and restores
// tpmCfg, the package-level flag state runTPMInfo reads, and points
// tpmInfoCmd's output at a local buffer rather than the process's real
// stdout.
package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

func TestRunTPMInfo_Simulator_JSON(t *testing.T) {
	withTPMCfg(t, func(c *tpmConfig) {
		c.useSimulator = true
		c.outputFormat = "json"
	})

	var buf bytes.Buffer
	tpmInfoCmd.SetOut(&buf)
	t.Cleanup(func() { tpmInfoCmd.SetOut(nil) })

	if err := runTPMInfo(tpmInfoCmd, nil); err != nil {
		t.Fatalf("runTPMInfo() error = %v, want nil", err)
	}

	var info TPMInfo
	if err := json.Unmarshal(buf.Bytes(), &info); err != nil {
		t.Fatalf("json.Unmarshal(%q) error = %v", buf.String(), err)
	}
	if info.Type != "Simulator" {
		t.Errorf("info.Type = %q, want %q", info.Type, "Simulator")
	}
	// A freshly opened simulator has no EK/SRK/IAK/IDevID persisted yet.
	if info.Provisioned {
		t.Error("info.Provisioned = true on a fresh simulator, want false")
	}
	if info.EKPresent || info.SRKPresent || info.IAKPresent || info.IDevIDPresent {
		t.Errorf("info = %+v, want no keys present on a fresh simulator", info)
	}
}

func TestRunTPMInfo_Simulator_Text(t *testing.T) {
	withTPMCfg(t, func(c *tpmConfig) {
		c.useSimulator = true
		c.outputFormat = "text"
	})

	var buf bytes.Buffer
	tpmInfoCmd.SetOut(&buf)
	t.Cleanup(func() { tpmInfoCmd.SetOut(nil) })

	if err := runTPMInfo(tpmInfoCmd, nil); err != nil {
		t.Fatalf("runTPMInfo() error = %v, want nil", err)
	}

	out := buf.String()
	if !strings.Contains(out, "TPM Information") {
		t.Errorf("output = %q, want a %q heading", out, "TPM Information")
	}
	if wantType := fmt.Sprintf("  Type:             %s\n", "Simulator"); !strings.Contains(out, wantType) {
		t.Errorf("output = %q, want the simulator type line %q", out, wantType)
	}
	if wantProvisioned := fmt.Sprintf("  Provisioned:      %t\n", false); !strings.Contains(out, wantProvisioned) {
		t.Errorf("output = %q, want Provisioned: false on a fresh simulator", out)
	}
}

func TestRunTPMInfo_DeviceNotFound(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-such-tpm-device")
	withTPMCfg(t, func(c *tpmConfig) {
		c.useSimulator = false
		c.device = missing
	})

	var buf bytes.Buffer
	tpmInfoCmd.SetOut(&buf)
	t.Cleanup(func() { tpmInfoCmd.SetOut(nil) })

	err := runTPMInfo(tpmInfoCmd, nil)
	if err == nil {
		t.Fatal("runTPMInfo() error = nil, want a device-open error")
	}
	if !errors.Is(err, ErrTPMDeviceNotFound) {
		t.Errorf("runTPMInfo() error = %v, want errors.Is ErrTPMDeviceNotFound", err)
	}
	if !errors.Is(err, xkms.ErrTPMOpeningDevice) {
		t.Errorf("runTPMInfo() error = %v, want errors.Is ErrTPMOpeningDevice as the wrapped cause", err)
	}
}

// TestRunTPMInfo_ProvisionedSimulator checks that info reports every key a
// provisioned TPM holds, including an IDevID created after provisioning.
func TestRunTPMInfo_ProvisionedSimulator(t *testing.T) {
	sim := withProvisionedSimulatorTPM(t)
	sim.withIDevID(t)
	setVar(t, &tpmCfg.outputFormat, "json")

	stdout, _, err := runTPMSubcommand(runTPMInfo)
	if err != nil {
		t.Fatalf("runTPMInfo() error = %v, want nil", err)
	}

	var info TPMInfo
	if err := json.Unmarshal([]byte(stdout), &info); err != nil {
		t.Fatalf("json.Unmarshal(%q) error = %v", stdout, err)
	}
	if !info.Provisioned {
		t.Error("info.Provisioned = false on a provisioned simulator, want true")
	}
	if !info.EKPresent || !info.SRKPresent || !info.IAKPresent || !info.IDevIDPresent {
		t.Errorf("info = %+v, want EK, SRK, IAK and IDevID present", info)
	}
}
