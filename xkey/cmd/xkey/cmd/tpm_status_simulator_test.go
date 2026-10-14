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

// These tests exercise runTPMStatus, buildTPMStatus, buildKeyStatus,
// buildCertStatus and buildPlatformPolicyStatus (tpm_status.go) against the
// in-process TPM 2.0 simulator. The simulator is entirely in-memory; it
// never touches the host filesystem or a physical device. Each test saves
// and restores tpmCfg, the package-level flag state runTPMStatus reads, and
// points tpmStatusCmd's output at a local buffer rather than the process's
// real stdout.
package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

func TestRunTPMStatus_Simulator_JSON(t *testing.T) {
	withTPMCfg(t, func(c *tpmConfig) {
		c.useSimulator = true
		c.outputFormat = "json"
	})

	var buf bytes.Buffer
	tpmStatusCmd.SetOut(&buf)
	t.Cleanup(func() { tpmStatusCmd.SetOut(nil) })

	if err := runTPMStatus(tpmStatusCmd, nil); err != nil {
		t.Fatalf("runTPMStatus() error = %v, want nil", err)
	}

	var status TPMStatusOutput
	if err := json.Unmarshal(buf.Bytes(), &status); err != nil {
		t.Fatalf("json.Unmarshal(%q) error = %v", buf.String(), err)
	}
	if status.Type != "Simulator" {
		t.Errorf("status.Type = %q, want %q", status.Type, "Simulator")
	}
	if status.Provisioned {
		t.Error("status.Provisioned = true on a fresh simulator, want false")
	}
	if len(status.Keys) != 4 {
		t.Fatalf("len(status.Keys) = %d, want 4 (EK, SSRK, IAK, IDevID)", len(status.Keys))
	}
	for _, key := range status.Keys {
		if key.Present {
			t.Errorf("key %s reported Present = true on a fresh simulator", key.Name)
		}
		if key.Error == "" {
			t.Errorf("key %s reported no Error on a fresh, unprovisioned simulator", key.Name)
		}
	}
	if len(status.Certificates) != 2 {
		t.Fatalf("len(status.Certificates) = %d, want 2 (EK Cert, IDevID Cert)", len(status.Certificates))
	}
	if status.PlatformPolicy.PCRBank != "sha256" {
		t.Errorf("status.PlatformPolicy.PCRBank = %q, want %q", status.PlatformPolicy.PCRBank, "sha256")
	}
	// PlatformPolicyDigest is computed directly from the golden PCR
	// configuration; it does not require a provisioned Platform SRK, so
	// even a fresh simulator reports a configured policy with a real
	// digest rather than the "(not set)" placeholder.
	if !status.PlatformPolicy.Configured {
		t.Error("status.PlatformPolicy.Configured = false, want true: PlatformPolicyDigest only needs golden PCR config")
	}
	if status.PlatformPolicy.PolicyDigest == "" || status.PlatformPolicy.PolicyDigest == "(not set)" {
		t.Errorf("status.PlatformPolicy.PolicyDigest = %q, want a computed hex digest", status.PlatformPolicy.PolicyDigest)
	}
}

func TestRunTPMStatus_Simulator_Text(t *testing.T) {
	withTPMCfg(t, func(c *tpmConfig) {
		c.useSimulator = true
		c.outputFormat = "text"
	})

	var buf bytes.Buffer
	tpmStatusCmd.SetOut(&buf)
	t.Cleanup(func() { tpmStatusCmd.SetOut(nil) })

	if err := runTPMStatus(tpmStatusCmd, nil); err != nil {
		t.Fatalf("runTPMStatus() error = %v, want nil", err)
	}

	out := buf.String()
	if out == "" {
		t.Fatal("runTPMStatus() text output is empty")
	}
	for _, want := range []string{"EK", "SSRK", "IAK", "IDevID", "EK Cert", "IDevID Cert"} {
		if !strings.Contains(out, want) {
			t.Errorf("output = %q, want it to mention %q", out, want)
		}
	}
}

func TestRunTPMStatus_DeviceNotFound(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-such-tpm-device")
	withTPMCfg(t, func(c *tpmConfig) {
		c.useSimulator = false
		c.device = missing
	})

	var buf bytes.Buffer
	tpmStatusCmd.SetOut(&buf)
	t.Cleanup(func() { tpmStatusCmd.SetOut(nil) })

	err := runTPMStatus(tpmStatusCmd, nil)
	if err == nil {
		t.Fatal("runTPMStatus() error = nil, want a device-open error")
	}
	if !errors.Is(err, ErrTPMDeviceNotFound) {
		t.Errorf("runTPMStatus() error = %v, want errors.Is ErrTPMDeviceNotFound", err)
	}
	if !errors.Is(err, xkms.ErrTPMOpeningDevice) {
		t.Errorf("runTPMStatus() error = %v, want errors.Is ErrTPMOpeningDevice as the wrapped cause", err)
	}
}

// TestRunTPMStatus_WithIDevIDCertificate checks that status reports the
// IDevID key and its NV-stored certificate once both exist.
func TestRunTPMStatus_WithIDevIDCertificate(t *testing.T) {
	sim := withProvisionedSimulatorTPM(t)
	idevidPub := sim.withIDevID(t)
	cert := issueTestCert(t, sim.caCert, sim.caKey, "xkey-001", idevidPub)
	setVar(t, &idevidCertImportForce, false)
	setVar(t, &idevidCertImportPath, writeCertPEM(t, cert))
	if _, _, err := runTPMSubcommand(runIDevIDCertImport); err != nil {
		t.Fatalf("runIDevIDCertImport() error = %v, want nil", err)
	}
	setVar(t, &tpmCfg.outputFormat, "json")

	stdout, _, err := runTPMSubcommand(runTPMStatus)
	if err != nil {
		t.Fatalf("runTPMStatus() error = %v, want nil", err)
	}

	var status TPMStatusOutput
	if err := json.Unmarshal([]byte(stdout), &status); err != nil {
		t.Fatalf("json.Unmarshal(%q) error = %v", stdout, err)
	}
	var idevid *KeyStatus
	for i := range status.Keys {
		if status.Keys[i].Name == "IDevID" {
			idevid = &status.Keys[i]
		}
	}
	if idevid == nil || !idevid.Present {
		t.Fatalf("IDevID key status = %+v, want present", idevid)
	}
	if idevid.Algorithm == "" || idevid.SignatureAlgorithm == "" || idevid.Error != "" {
		t.Errorf("IDevID key status = %+v, want an algorithm, a signature algorithm and no error", *idevid)
	}

	var idevidCert *CertStatus
	for i := range status.Certificates {
		if status.Certificates[i].Name == "IDevID Cert" {
			idevidCert = &status.Certificates[i]
		}
	}
	if idevidCert == nil || !idevidCert.Present {
		t.Fatalf("IDevID certificate status = %+v, want present", idevidCert)
	}
	if idevidCert.Subject != "CN=xkey-001" {
		t.Errorf("IDevID certificate subject = %q, want %q", idevidCert.Subject, "CN=xkey-001")
	}
	if idevidCert.Issuer != cert.Issuer.String() {
		t.Errorf("IDevID certificate issuer = %q, want %q", idevidCert.Issuer, cert.Issuer.String())
	}
	if idevidCert.NotAfter != cert.NotAfter.Format("2006-01-02") {
		t.Errorf("IDevID certificate not_after = %q, want %q", idevidCert.NotAfter, cert.NotAfter.Format("2006-01-02"))
	}
}
