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

//go:build integration && tpm_simulator

// TPMService integration tests.
//
// These run against an in-process TPM 2.0 simulator (go-tpm-tools, reached
// through the xkms SDK's OpenSimulator re-export) that is freshly provisioned
// for every test. They never open the host's /dev/tpmrm0: touching the real
// TPM from a test can lock the owner hierarchy out of a developer's machine,
// and it also made the suite's results depend on whatever state that TPM
// happened to be in. Because the simulator is provisioned by the harness, the
// assertions below are exact instead of "log a warning and pass".
//
// Run: make integration-test-tpm (or `go test -tags "integration linux
// tpm_simulator ..."` — the tpm_simulator tag is what links the simulator in).
package services

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-tpm/tpm2"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// setupSimulatedTPM returns a freshly provisioned TPM backed by the in-process
// simulator. Every test gets its own simulator instance and its own on-disk
// key store under t.TempDir(), so tests neither share state nor leave anything
// behind.
func setupSimulatedTPM(t *testing.T) xkms.TrustedPlatformModule {
	t.Helper()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	sim, err := xkms.OpenSimulator()
	if err != nil {
		t.Fatalf("opening the in-process TPM simulator: %v; build with -tags tpm_simulator", err)
	}
	t.Cleanup(func() {
		if cerr := sim.Close(); cerr != nil {
			t.Logf("closing TPM simulator: %v", cerr)
		}
	})

	storageFactory, err := xkms.NewTPMStorageFactory(logger, t.TempDir())
	if err != nil {
		t.Fatalf("creating the TPM key storage factory: %v", err)
	}

	cfg := xkms.DefaultTPMConfig
	// Device is deliberately blank and UseSimulator false: the transport is
	// supplied explicitly, which short-circuits every device-open branch in
	// NewTPM2 so no host character device can be touched.
	cfg.Device = ""
	cfg.UseSimulator = false

	tpm, err := xkms.NewTPM2(&xkms.TPMParams{
		Config:    &cfg,
		Logger:    logger,
		Transport: sim.Transport(),
		Backend:   storageFactory.KeyBackend(),
		FQDN:      "xkey.integration.test",
	})
	if err == xkms.ErrTPMNotInitialized {
		if tpm == nil {
			t.Fatal("NewTPM2 reported ErrTPMNotInitialized but returned no TPM to provision")
		}
		if perr := tpm.Provision(nil); perr != nil {
			t.Fatalf("provisioning the simulator: %v", perr)
		}
	} else if err != nil {
		t.Fatalf("creating the simulator-backed TPM: %v", err)
	}

	t.Cleanup(func() {
		if cerr := tpm.Close(); cerr != nil {
			t.Logf("closing TPM: %v", cerr)
		}
	})

	// Guard: the TPM under test must be the in-process reference simulator.
	// If a future refactor ever let NewTPM2 fall back to a device node, this
	// is what catches it before the suite starts writing to a real TPM.
	props, err := tpm.FixedProperties()
	if err != nil {
		t.Fatalf("reading fixed properties from the simulator: %v", err)
	}
	if !strings.Contains(props.Manufacturer, "Microsoft") && !strings.Contains(props.Manufacturer, "MSFT") {
		t.Fatalf("TPM manufacturer = %q; the suite must run against the in-process reference simulator, never a host TPM",
			props.Manufacturer)
	}

	return tpm
}

// setupTPMService wires a TPMService to the provisioned simulator exactly the
// way the GUI wires it to the real device.
func setupTPMService(t *testing.T) *TPMService {
	t.Helper()
	return tpmServiceFor(t, setupSimulatedTPM(t))
}

// tpmServiceFor wires a TPMService to an already-open TPM, the way the GUI
// wires it to the real device. Tests that need the TPM as well as the service
// -- to read the handles it is configured to use, say -- open it themselves
// and call this.
func tpmServiceFor(t *testing.T, tpm xkms.TrustedPlatformModule) *TPMService {
	t.Helper()

	accessor := NewTPMAccessor(func() xkms.TrustedPlatformModule {
		return tpm
	})

	svc := NewTPMService()
	svc.SetContext(context.Background())
	svc.SetTPMAccessor(accessor)
	svc.SetDataDir(t.TempDir())
	return svc
}

// setupUnprovisionedTPM returns an open but unprovisioned simulator: no EK, no
// SRK, nothing persisted. It is the state of a TPM the operator has not
// touched yet, and the state in which the GUI must still render cleanly.
func setupUnprovisionedTPM(t *testing.T) xkms.TrustedPlatformModule {
	t.Helper()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	sim, err := xkms.OpenSimulator()
	if err != nil {
		t.Fatalf("opening the in-process TPM simulator: %v; build with -tags tpm_simulator", err)
	}
	t.Cleanup(func() {
		if cerr := sim.Close(); cerr != nil {
			t.Logf("closing TPM simulator: %v", cerr)
		}
	})

	storageFactory, err := xkms.NewTPMStorageFactory(logger, t.TempDir())
	if err != nil {
		t.Fatalf("creating the TPM key storage factory: %v", err)
	}

	cfg := xkms.DefaultTPMConfig
	cfg.Device = ""
	cfg.UseSimulator = false

	tpm, err := xkms.NewTPM2(&xkms.TPMParams{
		Config:    &cfg,
		Logger:    logger,
		Transport: sim.Transport(),
		Backend:   storageFactory.KeyBackend(),
		FQDN:      "xkey.integration.test",
	})
	// ErrTPMNotInitialized is the expected outcome here: it is exactly what an
	// unprovisioned TPM reports, and the TPM it returns is usable for the
	// read-only commands under test.
	if err != nil && err != xkms.ErrTPMNotInitialized {
		t.Fatalf("creating the simulator-backed TPM: %v", err)
	}
	if tpm == nil {
		t.Fatal("NewTPM2 returned no TPM")
	}

	t.Cleanup(func() {
		if cerr := tpm.Close(); cerr != nil {
			t.Logf("closing TPM: %v", cerr)
		}
	})

	return tpm
}

// logJSON marshals a value to indented JSON and logs it. Falls back to
// fmt.Sprintf on marshal failure.
func logJSON(t *testing.T, label string, v interface{}) {
	t.Helper()
	data, err := json.MarshalIndent(v, "  ", "  ")
	if err != nil {
		t.Logf("%s: %s", label, fmt.Sprintf("%+v", v))
		return
	}
	t.Logf("%s:\n  %s", label, string(data))
}

// requireHexDigest asserts s is a hex string of exactly byteLen bytes.
func requireHexDigest(t *testing.T, label, s string, byteLen int) {
	t.Helper()
	if len(s) != byteLen*2 {
		t.Fatalf("%s = %q (%d chars), want %d hex chars", label, s, len(s), byteLen*2)
	}
	if _, err := hex.DecodeString(s); err != nil {
		t.Fatalf("%s = %q is not hex: %v", label, s, err)
	}
}

// requireKeyInfoConsistent asserts the present/absent invariant every key-info
// DTO the GUI renders must satisfy: an absent key carries no algorithm, key
// size or certificate, and a present one carries an algorithm and a key size.
// This is what stops a half-populated DTO from reaching the UI.
func requireKeyInfoConsistent(t *testing.T, label string, present bool, algorithm string, keySize int, certificate string) {
	t.Helper()
	if present {
		if algorithm == "" {
			t.Errorf("%s: present key has no algorithm", label)
		}
		if keySize <= 0 {
			t.Errorf("%s: present key has key size %d", label, keySize)
		}
		return
	}
	if algorithm != "" || keySize != 0 || certificate != "" {
		t.Errorf("%s: absent key still reports algorithm=%q key_size=%d cert_len=%d",
			label, algorithm, keySize, len(certificate))
	}
}

// requireSRKInfoConsistent is the SRK flavour of requireKeyInfoConsistent: the
// storage-root-key DTOs carry a handle instead of a key size or certificate.
// An absent SRK renders its algorithm as the "N/A" placeholder (the GUI shows
// that string verbatim), so only the handle is required to be empty.
func requireSRKInfoConsistent(t *testing.T, label string, present bool, algorithm, handle string) {
	t.Helper()
	if present {
		if algorithm == "" || algorithm == "N/A" {
			t.Errorf("%s: present key reports algorithm %q", label, algorithm)
		}
		if handle == "" {
			t.Errorf("%s: present key has no handle", label)
		}
		return
	}
	if handle != "" {
		t.Errorf("%s: absent key still reports handle %q", label, handle)
	}
	if algorithm != "" && algorithm != "N/A" {
		t.Errorf("%s: absent key still reports algorithm %q", label, algorithm)
	}
}

// requirePEMCertificate asserts an exported certificate really is a parseable
// PEM-encoded X.509 certificate rather than an arbitrary string.
func requirePEMCertificate(t *testing.T, label, data string) {
	t.Helper()
	block, rest := pem.Decode([]byte(data))
	if block == nil {
		t.Fatalf("%s: exported data is not PEM:\n%s", label, data)
	}
	if block.Type != "CERTIFICATE" {
		t.Fatalf("%s: PEM block type = %q, want CERTIFICATE", label, block.Type)
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		t.Fatalf("%s: PEM block does not parse as an X.509 certificate: %v", label, err)
	}
	if strings.TrimSpace(string(rest)) != "" {
		t.Errorf("%s: trailing data after the certificate: %q", label, string(rest))
	}
}

// --- Individual method tests ---

func TestIntegration_TPMService_GetStatus(t *testing.T) {
	svc := setupTPMService(t)

	status, err := svc.GetStatus()
	if err != nil {
		t.Fatalf("GetStatus returned unexpected error: %v", err)
	}
	if status == nil {
		t.Fatal("GetStatus returned nil status")
	}

	t.Logf("Status: available=%v provisioned=%v level=%s manufacturer=%q fw=%q device=%q init_error=%q",
		status.Available, status.Provisioned, status.StatusLevel,
		status.Manufacturer, status.FirmwareVer, status.DevicePath, status.InitError)

	if !status.Available {
		t.Fatalf("TPM reported unavailable against a live simulator (init_error=%q)", status.InitError)
	}
	if status.InitError != "" {
		t.Errorf("InitError = %q, want empty on a healthy TPM", status.InitError)
	}
	if status.Manufacturer == "" {
		t.Error("Manufacturer is empty; the GUI status card renders it")
	}

	// The harness provisions the EK and the shared SRK, so the ladder in
	// GetStatus must have climbed at least to "owner". It stops short of
	// "device_identity" because that additionally requires an IDevID
	// CERTIFICATE, which only a CA can issue.
	switch status.StatusLevel {
	case TPMStatusLevelOwner, TPMStatusLevelDeviceIdentity:
	default:
		t.Errorf("StatusLevel = %q, want at least %q after provisioning",
			status.StatusLevel, TPMStatusLevelOwner)
	}
	// Provisioned is the device-identity flag: it may only be set at the
	// device_identity level, never below it.
	if status.Provisioned && status.StatusLevel != TPMStatusLevelDeviceIdentity {
		t.Errorf("Provisioned=true at level %q, want %q", status.StatusLevel, TPMStatusLevelDeviceIdentity)
	}
}

func TestIntegration_TPMService_GetInfo(t *testing.T) {
	svc := setupTPMService(t)

	info, err := svc.GetInfo()
	if err != nil {
		t.Fatalf("GetInfo returned unexpected error: %v", err)
	}
	if info == nil {
		t.Fatal("GetInfo returned nil")
	}

	logJSON(t, "TPM Info", info)

	if info.Manufacturer == "" {
		t.Error("Manufacturer is empty")
	}
	if len(info.PCRBanks) == 0 {
		t.Error("no PCR banks reported; every TPM 2.0 has at least one")
	}
	if len(info.Algorithms) == 0 {
		t.Error("no algorithms reported")
	}
	if info.MaxRSAKeySize <= 0 {
		t.Errorf("MaxRSAKeySize = %d, want a positive value", info.MaxRSAKeySize)
	}
}

func TestIntegration_TPMService_GetEKInfo(t *testing.T) {
	svc := setupTPMService(t)

	info, err := svc.GetEKInfo()
	if err != nil {
		t.Fatalf("GetEKInfo returned unexpected error: %v", err)
	}
	if info == nil {
		t.Fatal("GetEKInfo returned nil")
	}

	logJSON(t, "EK Info", info)

	// The harness provisions the RSA EK, so it must be present.
	if !info.Present {
		t.Fatal("RSA Endorsement Key absent after provisioning")
	}
	requireKeyInfoConsistent(t, "EK", info.Present, info.Algorithm, info.KeySize, info.Certificate)
}

func TestIntegration_TPMService_GetEKECCInfo(t *testing.T) {
	svc := setupTPMService(t)

	info, err := svc.GetEKECCInfo()
	if err != nil {
		t.Fatalf("GetEKECCInfo returned unexpected error: %v", err)
	}
	if info == nil {
		t.Fatal("GetEKECCInfo returned nil")
	}

	logJSON(t, "EK ECC Info", info)

	// The default provisioning profile mints an RSA EK; whether an ECC EK
	// exists depends on the profile, so the invariant — not the presence —
	// is what this pins.
	requireKeyInfoConsistent(t, "EK ECC", info.Present, info.Algorithm, info.KeySize, info.Certificate)
}

func TestIntegration_TPMService_GetIAKInfo(t *testing.T) {
	svc := setupTPMService(t)

	info, err := svc.GetIAKInfo()
	if err != nil {
		t.Fatalf("GetIAKInfo returned unexpected error: %v", err)
	}
	if info == nil {
		t.Fatal("GetIAKInfo returned nil")
	}

	logJSON(t, "IAK Info", info)

	if !info.Present {
		t.Fatal("Initial Attestation Key absent after provisioning")
	}
	requireKeyInfoConsistent(t, "IAK", info.Present, info.Algorithm, info.KeySize, info.Certificate)
	if info.Handle == "" {
		t.Error("IAK handle is empty; the GUI shows it in the key list")
	}
}

func TestIntegration_TPMService_GetIDevIDInfo(t *testing.T) {
	svc := setupTPMService(t)

	info, err := svc.GetIDevIDInfo()
	if err != nil {
		t.Fatalf("GetIDevIDInfo returned unexpected error: %v", err)
	}
	if info == nil {
		t.Fatal("GetIDevIDInfo returned nil")
	}

	logJSON(t, "IDevID Info", info)
	requireKeyInfoConsistent(t, "IDevID", info.Present, info.Algorithm, info.KeySize, info.Certificate)
}

func TestIntegration_TPMService_GetSharedSRKInfo(t *testing.T) {
	svc := setupTPMService(t)

	info, err := svc.GetSharedSRKInfo()
	if err != nil {
		t.Fatalf("GetSharedSRKInfo returned unexpected error: %v", err)
	}
	if info == nil {
		t.Fatal("GetSharedSRKInfo returned nil")
	}

	logJSON(t, "Shared SRK Info", info)

	if !info.Present {
		t.Fatal("TCG shared SRK absent after provisioning")
	}
	if info.Algorithm == "" {
		t.Error("SSRK: present key has no algorithm")
	}
	if info.Handle == "" {
		t.Error("SSRK: present key has no handle")
	}
}

func TestIntegration_TPMService_GetPlatformSRKInfo(t *testing.T) {
	svc := setupTPMService(t)

	info, err := svc.GetPlatformSRKInfo()
	if err != nil {
		t.Fatalf("GetPlatformSRKInfo returned unexpected error: %v", err)
	}
	if info == nil {
		t.Fatal("GetPlatformSRKInfo returned nil")
	}

	logJSON(t, "Platform SRK Info", info)

	// The platform SRK is created by the platform key store, which the GUI
	// initializes separately, so only the DTO invariant is guaranteed here:
	// an absent SRK must not claim an algorithm, a handle or a policy.
	requireSRKInfoConsistent(t, "Platform SRK", info.Present, info.Algorithm, info.Handle)
	if !info.Present && info.PolicyEnabled {
		t.Error("Platform SRK: absent key reports an enabled policy")
	}
}

// TestIntegration_TPMService_GetPCRs cross-checks the PCR reader against the
// banks the TPM itself advertises: every advertised bank must be readable and
// every digest must be the right width for that bank.
func TestIntegration_TPMService_GetPCRs(t *testing.T) {
	svc := setupTPMService(t)

	info, err := svc.GetInfo()
	if err != nil {
		t.Fatalf("GetInfo: %v", err)
	}
	if len(info.PCRBanks) == 0 {
		t.Fatal("TPM advertises no PCR banks")
	}

	digestBytes := map[string]int{
		"sha1":   20,
		"sha256": 32,
		"sha384": 48,
		"sha512": 64,
	}

	for _, bank := range info.PCRBanks {
		bank := strings.ToLower(bank)
		t.Run(bank, func(t *testing.T) {
			pcrs, err := svc.GetPCRs(bank)
			if err != nil {
				t.Fatalf("GetPCRs(%s) failed even though the TPM advertises the bank: %v", bank, err)
			}
			if len(pcrs) == 0 {
				t.Fatalf("GetPCRs(%s) returned no values", bank)
			}
			want, known := digestBytes[bank]
			for _, pcr := range pcrs {
				if !known {
					if pcr.Digest == "" {
						t.Errorf("PCR[%02d] digest is empty", pcr.Index)
					}
					continue
				}
				requireHexDigest(t, fmt.Sprintf("PCR[%02d] in %s", pcr.Index, bank), pcr.Digest, want)
			}
		})
	}
}

// TestIntegration_TPMService_GetPCRsRejectsUnknownBank is the error-path
// companion: an unknown bank must be reported, never silently answered with an
// empty list the GUI would render as "no PCRs".
func TestIntegration_TPMService_GetPCRsRejectsUnknownBank(t *testing.T) {
	svc := setupTPMService(t)

	pcrs, err := svc.GetPCRs("not-a-bank")
	if err == nil {
		t.Fatalf("GetPCRs(\"not-a-bank\") returned %d values and no error", len(pcrs))
	}
	t.Logf("unknown bank rejected with: %v", err)
}

// TestIntegration_TPMService_GetEventLog asserts the shape of whatever the
// service returns. The measured-boot log is host state (securityfs), so its
// presence is not guaranteed inside a container; what IS guaranteed is that a
// returned entry is fully populated rather than a half-parsed record.
func TestIntegration_TPMService_GetEventLog(t *testing.T) {
	svc := setupTPMService(t)

	events, err := svc.GetEventLog()
	if err != nil {
		t.Logf("no measured-boot log available on this host: %v", err)
		if len(events) != 0 {
			t.Fatalf("GetEventLog returned %d entries alongside an error", len(events))
		}
		return
	}

	t.Logf("Event log: %d entries", len(events))

	withDigest := 0
	for i, ev := range events {
		if ev.EventType == "" {
			t.Fatalf("event %d has an empty event type", i)
		}
		if ev.PCRIndex > 23 {
			t.Fatalf("event %d (%s) targets PCR %d; a TPM 2.0 has 24 PCRs", i, ev.EventType, ev.PCRIndex)
		}
		// Not every record carries a digest: EV_NO_ACTION events are never
		// extended, and header/padding records parse without one. What must
		// hold is that a digest, when present, is real hex.
		if ev.DigestHex == "" {
			continue
		}
		if _, derr := hex.DecodeString(ev.DigestHex); derr != nil {
			t.Fatalf("event %d digest %q is not hex: %v", i, ev.DigestHex, derr)
		}
		withDigest++
	}
	if len(events) > 0 && withDigest == 0 {
		t.Fatalf("%d event-log entries but not one digest: the parser is dropping them", len(events))
	}
}

func TestIntegration_TPMService_GetRandomBytes(t *testing.T) {
	svc := setupTPMService(t)

	seen := make(map[string]struct{})
	for _, length := range []int{16, 32, 64} {
		t.Run(fmt.Sprintf("%d_bytes", length), func(t *testing.T) {
			hexStr, err := svc.GetRandomBytes(length)
			if err != nil {
				t.Fatalf("GetRandomBytes(%d) failed: %v", length, err)
			}
			requireHexDigest(t, fmt.Sprintf("GetRandomBytes(%d)", length), hexStr, length)
			if _, dup := seen[hexStr]; dup {
				t.Fatalf("GetRandomBytes(%d) repeated a previous value: the RNG is not live", length)
			}
			seen[hexStr] = struct{}{}
		})
	}
}

// TestIntegration_TPMService_GetRandomBytesRejectsBadLength covers the
// error path: a non-positive length must be rejected, not answered with an
// empty string the caller would treat as entropy.
func TestIntegration_TPMService_GetRandomBytesRejectsBadLength(t *testing.T) {
	svc := setupTPMService(t)

	for _, length := range []int{0, -1} {
		out, err := svc.GetRandomBytes(length)
		if err == nil {
			t.Fatalf("GetRandomBytes(%d) = %q, want an error", length, out)
		}
		if out != "" {
			t.Fatalf("GetRandomBytes(%d) returned %q alongside an error", length, out)
		}
	}
}

func TestIntegration_TPMService_ListPersistentHandles(t *testing.T) {
	svc := setupTPMService(t)

	handles, err := svc.ListPersistentHandles()
	if err != nil {
		t.Fatalf("ListPersistentHandles failed: %v", err)
	}
	if len(handles) == 0 {
		t.Fatal("no persistent handles after provisioning; the EK and SRK are persisted")
	}

	for _, h := range handles {
		t.Logf("  handle=%s type=%s desc=%q", h.Handle, h.Type, h.Description)
		if h.Handle == "" {
			t.Error("a persistent handle has an empty handle value")
		}
	}
}

func TestIntegration_TPMService_ListTransientHandles(t *testing.T) {
	svc := setupTPMService(t)

	handles, err := svc.ListTransientHandles()
	if err != nil {
		t.Fatalf("ListTransientHandles failed: %v", err)
	}

	// A count of zero is the healthy state (no leaked transient objects);
	// what matters is that every reported handle is populated.
	for _, h := range handles {
		t.Logf("  handle=%s type=%s", h.Handle, h.Type)
		if h.Handle == "" {
			t.Error("a transient handle has an empty handle value")
		}
	}
}

func TestIntegration_TPMService_GetNVSummary(t *testing.T) {
	svc := setupTPMService(t)

	nv, err := svc.GetNVSummary()
	if err != nil {
		t.Fatalf("GetNVSummary failed: %v", err)
	}
	if nv == nil {
		t.Fatal("GetNVSummary returned nil")
	}

	t.Logf("NV Summary: defined=%d max=%d", nv.IndexesDefined, nv.IndexesMax)
	if nv.IndexesDefined != len(nv.Indexes) {
		t.Errorf("IndexesDefined = %d but %d indexes were listed", nv.IndexesDefined, len(nv.Indexes))
	}
	for _, idx := range nv.Indexes {
		t.Logf("  index=%s type=%s size=%d auth_read=%v auth_write=%v",
			idx.Handle, idx.Type, idx.Size, idx.AuthRead, idx.AuthWrite)
		if idx.Handle == "" {
			t.Error("an NV index has an empty handle")
		}
	}
}

func TestIntegration_TPMService_GetLockoutInfo(t *testing.T) {
	svc := setupTPMService(t)

	lockout, err := svc.GetLockoutInfo()
	if err != nil {
		t.Fatalf("GetLockoutInfo failed: %v", err)
	}
	if lockout == nil {
		t.Fatal("GetLockoutInfo returned nil")
	}

	t.Logf("Lockout: counter=%d max_auth_fail=%d interval=%d recovery=%d",
		lockout.Counter, lockout.MaxFail, lockout.Interval, lockout.Recovery)

	if lockout.MaxFail <= 0 {
		t.Errorf("MaxFail = %d; a TPM always reports a positive lockout threshold", lockout.MaxFail)
	}
	if lockout.Counter < 0 {
		t.Errorf("Counter = %d, want >= 0", lockout.Counter)
	}
}

// TestIntegration_TPMService_ExportCerts checks every certificate export the
// GUI offers. A simulator has no manufacturer-issued certificates in NV, so
// an export either fails cleanly or produces a certificate that really parses
// — never an unparseable blob presented to the user as a certificate.
func TestIntegration_TPMService_ExportCerts(t *testing.T) {
	svc := setupTPMService(t)

	exports := []struct {
		name string
		fn   func(string) (string, error)
	}{
		{"EK", svc.ExportEKCert},
		{"EK ECC", svc.ExportEKECCCert},
		{"IAK", svc.ExportIAKCert},
		{"IDevID", svc.ExportIDevIDCert},
	}

	for _, exp := range exports {
		t.Run(exp.name, func(t *testing.T) {
			data, err := exp.fn("pem")
			if err != nil {
				t.Logf("%s certificate not available on the simulator: %v", exp.name, err)
				if data != "" {
					t.Fatalf("%s export returned data (%d bytes) alongside an error", exp.name, len(data))
				}
				return
			}
			requirePEMCertificate(t, exp.name+" certificate", data)
		})
	}
}

// TestIntegration_TPMService_ExportEKCertRejectsUnknownFormat is the export
// error path: an unsupported format must be refused rather than silently
// falling back to some other encoding.
func TestIntegration_TPMService_ExportEKCertRejectsUnknownFormat(t *testing.T) {
	svc := setupTPMService(t)

	out, err := svc.ExportEKCert("not-a-format")
	if err == nil {
		t.Fatalf("ExportEKCert(\"not-a-format\") = %q, want an error", out)
	}
}

func TestIntegration_TPMService_VerifyTPM(t *testing.T) {
	svc := setupTPMService(t)

	result, err := svc.VerifyTPM()
	if err != nil {
		t.Fatalf("VerifyTPM returned unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("VerifyTPM returned nil")
	}

	t.Logf("Verification: verified=%v issuer=%q error=%q",
		result.Verified, result.Issuer, result.ErrorMessage)

	// A simulator EK carries no manufacturer chain, so verification is
	// expected to fail — but a failure must come with a reason, otherwise
	// the GUI shows a red badge with no explanation.
	if !result.Verified && result.ErrorMessage == "" {
		t.Error("verification failed without an error message")
	}
	if result.Verified && result.Issuer == "" {
		t.Error("verification succeeded without naming an issuer")
	}
}

func TestIntegration_TPMService_GetPlatformPolicy(t *testing.T) {
	svc := setupTPMService(t)

	digest, err := svc.GetPlatformPolicy()
	if err != nil {
		t.Fatalf("GetPlatformPolicy failed: %v", err)
	}
	requireHexDigest(t, "platform policy digest", digest, 32)
}

// TestIntegration_TPMService_ListKeys requires the keys the harness just
// provisioned to appear, fully described. ListKeys shipped as a hard-coded
// empty slice, so a test that only checks the shape of whatever came back
// passes against a method that returns nothing: the count is the assertion
// that matters.
func TestIntegration_TPMService_ListKeys(t *testing.T) {
	tpm := setupSimulatedTPM(t)
	svc := tpmServiceFor(t, tpm)

	keys, err := svc.ListKeys()
	if err != nil {
		t.Fatalf("ListKeys returned unexpected error: %v", err)
	}
	if len(keys) == 0 {
		t.Fatal("ListKeys reports no keys on a provisioned TPM")
	}

	byHandle := make(map[string]TPMKey, len(keys))
	for _, k := range keys {
		t.Logf("  id=%s algo=%s size=%d persistent=%v purpose=%s",
			k.ID, k.Algorithm, k.KeySize, k.Persistent, k.Purpose)

		if _, dup := byHandle[k.ID]; dup {
			t.Errorf("handle %s listed twice", k.ID)
		}
		byHandle[k.ID] = k

		// Every field the GUI renders must carry a real value. "Unknown" is
		// the service's own marker for something the TPM did not report, and
		// on a healthy simulator nothing should be unknown.
		if k.ID == "" {
			t.Error("a listed key has an empty ID")
		}
		// A missing algorithm is not cosmetic: xkey routes delete/export by
		// it, so an empty value sends the operation to the wrong handler.
		if k.Algorithm == "" || k.Algorithm == unknownTPMValue {
			t.Errorf("key %s reports algorithm %q", k.ID, k.Algorithm)
		}
		if k.KeySize <= 0 {
			t.Errorf("key %s reports key size %d", k.ID, k.KeySize)
		}
		if k.Purpose == "" || k.Purpose == unknownTPMValue {
			t.Errorf("key %s reports purpose %q", k.ID, k.Purpose)
		}
		if !k.Persistent {
			t.Errorf("key %s enumerated from the persistent hierarchy is not marked persistent", k.ID)
		}
	}

	// The keys the harness provisioned must be among them, at the handles the
	// TPM is configured to use and with the algorithms it was told to create.
	cfg := tpm.Config()
	if cfg == nil {
		t.Fatal("the TPM reports no configuration")
	}
	for _, want := range []struct {
		label     string
		handle    string
		algorithm string
		keySize   int
	}{
		{"SSRK", formatTPMHandle(tpm2.TPMHandle(cfg.SSRK.Handle)), "RSA", 2048},
		{"EK", formatTPMHandle(tpm2.TPMHandle(cfg.EK.Handle)), "RSA", 2048},
		{"IAK", formatTPMHandle(tpm2.TPMHandle(cfg.IAK.Handle)), "RSA-PSS", 2048},
	} {
		key, ok := byHandle[want.handle]
		if !ok {
			t.Errorf("%s at %s is persisted but not listed", want.label, want.handle)
			continue
		}
		if key.Algorithm != want.algorithm {
			t.Errorf("%s at %s: algorithm = %q, want %q", want.label, want.handle, key.Algorithm, want.algorithm)
		}
		if key.KeySize != want.keySize {
			t.Errorf("%s at %s: key size = %d, want %d", want.label, want.handle, key.KeySize, want.keySize)
		}
	}

	// ListKeys and the handles tab read the same inventory, so they must agree
	// on which handles exist. A divergence means one of them is inventing or
	// dropping entries.
	handles, err := svc.ListPersistentHandles()
	if err != nil {
		t.Fatalf("ListPersistentHandles failed: %v", err)
	}
	if len(handles) != len(keys) {
		t.Errorf("ListKeys reports %d keys, ListPersistentHandles reports %d handles", len(keys), len(handles))
	}
	for _, h := range handles {
		if _, ok := byHandle[h.Handle]; !ok {
			t.Errorf("handle %s is reported by the handles tab but missing from the keys tab", h.Handle)
		}
	}
}

// TestIntegration_TPMService_ListKeysUnprovisioned pins the other half of the
// contract: a TPM with nothing persisted reports an empty list and no error,
// so the GUI renders an empty keys tab rather than an error banner.
func TestIntegration_TPMService_ListKeysUnprovisioned(t *testing.T) {
	svc := tpmServiceFor(t, setupUnprovisionedTPM(t))

	keys, err := svc.ListKeys()
	if err != nil {
		t.Fatalf("ListKeys on an unprovisioned TPM returned an error: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("ListKeys on an unprovisioned TPM returned %d keys: %+v", len(keys), keys)
	}
}

// --- Full UI Flow Test ---

// TestIntegration_TPMService_FullUIFlow walks the sequence of service calls the
// GUI makes when a user opens the dashboard and then the TPM view, in order,
// against one TPM instance. It is the regression guard for state that leaks
// between calls (unflushed sessions, exhausted handles).
func TestIntegration_TPMService_FullUIFlow(t *testing.T) {
	svc := setupTPMService(t)

	// Step 1: Dashboard calls GetStatus.
	status, err := svc.GetStatus()
	if err != nil {
		t.Fatalf("GetStatus failed: %v", err)
	}
	if !status.Available {
		t.Fatalf("dashboard status reports the TPM unavailable: %q", status.InitError)
	}
	if status.StatusLevel == TPMStatusLevelNone {
		t.Fatalf("dashboard status level = %q after provisioning", status.StatusLevel)
	}

	// Step 2: TPM view overview.
	info, err := svc.GetInfo()
	if err != nil {
		t.Fatalf("GetInfo failed: %v", err)
	}
	if info.Manufacturer == "" {
		t.Error("overview shows an empty manufacturer")
	}

	ekInfo, err := svc.GetEKInfo()
	if err != nil {
		t.Fatalf("GetEKInfo failed: %v", err)
	}
	requireKeyInfoConsistent(t, "EK", ekInfo.Present, ekInfo.Algorithm, ekInfo.KeySize, ekInfo.Certificate)

	eccInfo, err := svc.GetEKECCInfo()
	if err != nil {
		t.Fatalf("GetEKECCInfo failed: %v", err)
	}
	requireKeyInfoConsistent(t, "EK ECC", eccInfo.Present, eccInfo.Algorithm, eccInfo.KeySize, eccInfo.Certificate)

	iakInfo, err := svc.GetIAKInfo()
	if err != nil {
		t.Fatalf("GetIAKInfo failed: %v", err)
	}
	requireKeyInfoConsistent(t, "IAK", iakInfo.Present, iakInfo.Algorithm, iakInfo.KeySize, iakInfo.Certificate)

	idevidInfo, err := svc.GetIDevIDInfo()
	if err != nil {
		t.Fatalf("GetIDevIDInfo failed: %v", err)
	}
	requireKeyInfoConsistent(t, "IDevID", idevidInfo.Present, idevidInfo.Algorithm, idevidInfo.KeySize, idevidInfo.Certificate)

	sharedSRK, err := svc.GetSharedSRKInfo()
	if err != nil {
		t.Fatalf("GetSharedSRKInfo failed: %v", err)
	}
	requireSRKInfoConsistent(t, "SSRK", sharedSRK.Present, sharedSRK.Algorithm, sharedSRK.Handle)

	platformSRK, err := svc.GetPlatformSRKInfo()
	if err != nil {
		t.Fatalf("GetPlatformSRKInfo failed: %v", err)
	}
	requireSRKInfoConsistent(t, "Platform SRK", platformSRK.Present, platformSRK.Algorithm, platformSRK.Handle)

	// Step 3: PCR tab.
	pcrs, err := svc.GetPCRs("sha256")
	if err != nil {
		t.Fatalf("GetPCRs(sha256) failed: %v", err)
	}
	if len(pcrs) == 0 {
		t.Fatal("PCR tab would render an empty table")
	}

	// Step 4: Handles tab.
	persistent, err := svc.ListPersistentHandles()
	if err != nil {
		t.Fatalf("ListPersistentHandles failed: %v", err)
	}
	if len(persistent) == 0 {
		t.Error("handles tab would render an empty persistent list after provisioning")
	}
	if _, err := svc.ListTransientHandles(); err != nil {
		t.Fatalf("ListTransientHandles failed: %v", err)
	}

	// Step 5: NV + lockout tabs.
	if _, err := svc.GetNVSummary(); err != nil {
		t.Fatalf("GetNVSummary failed: %v", err)
	}
	if _, err := svc.GetLockoutInfo(); err != nil {
		t.Fatalf("GetLockoutInfo failed: %v", err)
	}

	// Step 6: Keys tab.
	if _, err := svc.ListKeys(); err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}

	// Step 7: Verification badge.
	if _, err := svc.VerifyTPM(); err != nil {
		t.Fatalf("VerifyTPM failed: %v", err)
	}
}

// --- Concurrency Test ---

// TestIntegration_TPMService_ConcurrentAccess drives every read-only service
// method at once, the way a GUI does when several panels refresh together. A
// TPM serializes commands, so the service must marshal access itself: any
// error here means two panels can collide on the device.
func TestIntegration_TPMService_ConcurrentAccess(t *testing.T) {
	svc := setupTPMService(t)

	methods := []struct {
		name string
		fn   func() error
	}{
		{"GetStatus", func() error { _, err := svc.GetStatus(); return err }},
		{"GetInfo", func() error { _, err := svc.GetInfo(); return err }},
		{"GetPCRs", func() error { _, err := svc.GetPCRs("sha256"); return err }},
		{"GetEKInfo", func() error { _, err := svc.GetEKInfo(); return err }},
		{"GetEKECCInfo", func() error { _, err := svc.GetEKECCInfo(); return err }},
		{"GetIAKInfo", func() error { _, err := svc.GetIAKInfo(); return err }},
		{"GetIDevIDInfo", func() error { _, err := svc.GetIDevIDInfo(); return err }},
		{"GetSharedSRKInfo", func() error { _, err := svc.GetSharedSRKInfo(); return err }},
		{"GetPlatformSRKInfo", func() error { _, err := svc.GetPlatformSRKInfo(); return err }},
		{"ListPersistentHandles", func() error { _, err := svc.ListPersistentHandles(); return err }},
		{"ListTransientHandles", func() error { _, err := svc.ListTransientHandles(); return err }},
		{"GetNVSummary", func() error { _, err := svc.GetNVSummary(); return err }},
		{"GetLockoutInfo", func() error { _, err := svc.GetLockoutInfo(); return err }},
		{"GetRandomBytes", func() error { _, err := svc.GetRandomBytes(16); return err }},
	}

	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		errs []string
	)
	for _, m := range methods {
		wg.Add(1)
		go func(name string, fn func() error) {
			defer wg.Done()
			if err := fn(); err != nil {
				mu.Lock()
				errs = append(errs, fmt.Sprintf("%s: %v", name, err))
				mu.Unlock()
			}
		}(m.name, m.fn)
	}
	wg.Wait()

	if len(errs) > 0 {
		t.Fatalf("concurrent service calls failed:\n  %s", strings.Join(errs, "\n  "))
	}
}

// --- Repeated Access Test ---

// TestIntegration_TPMService_RepeatedAccess simulates a user switching tabs
// rapidly. Repeated calls must keep succeeding: a leaked TPM session or handle
// shows up here as a failure on a later iteration.
func TestIntegration_TPMService_RepeatedAccess(t *testing.T) {
	svc := setupTPMService(t)

	const iterations = 5
	for i := 0; i < iterations; i++ {
		status, err := svc.GetStatus()
		if err != nil {
			t.Fatalf("iteration %d: GetStatus failed: %v", i+1, err)
		}
		if !status.Available {
			t.Fatalf("iteration %d: TPM became unavailable: %q", i+1, status.InitError)
		}

		info, err := svc.GetInfo()
		if err != nil {
			t.Fatalf("iteration %d: GetInfo failed: %v", i+1, err)
		}
		if info.Manufacturer == "" {
			t.Fatalf("iteration %d: manufacturer went empty", i+1)
		}

		if _, err := svc.GetPCRs("sha256"); err != nil {
			t.Fatalf("iteration %d: GetPCRs failed: %v", i+1, err)
		}
		if _, err := svc.GetRandomBytes(32); err != nil {
			t.Fatalf("iteration %d: GetRandomBytes failed: %v", i+1, err)
		}
	}
}
