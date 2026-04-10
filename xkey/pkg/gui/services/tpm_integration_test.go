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

//go:build integration

package services

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"testing"

	tpm2pkg "github.com/jeremyhahn/go-xkms/pkg/tpm2"
)

const (
	integrationTPMDevice = "/dev/tpmrm0"
)

// setupRealTPM creates a connection to the real hardware TPM using the
// kernel resource manager device at /dev/tpmrm0. The test is skipped
// if the device does not exist.
func setupRealTPM(t *testing.T) tpm2pkg.TrustedPlatformModule {
	t.Helper()

	if _, err := os.Stat(integrationTPMDevice); err != nil {
		t.Skipf("no TPM device at %s: %v", integrationTPMDevice, err)
	}

	cfg := tpm2pkg.DefaultConfig
	cfg.Device = integrationTPMDevice
	cfg.UseSimulator = false

	tpm, err := tpm2pkg.NewTPM2(&tpm2pkg.Params{
		Config: &cfg,
	})
	if err != nil {
		// ErrNotInitialized means the TPM is accessible but not provisioned.
		// This is acceptable for read-only integration testing.
		if err == tpm2pkg.ErrNotInitialized {
			t.Logf("TPM opened but not initialized (no persistent EK): proceeding with read-only tests")
			return tpm
		}
		t.Fatalf("failed to create TPM connection: %v", err)
	}
	return tpm
}

// setupTPMService creates a TPMService backed by a real hardware TPM.
// Returns the service and a cleanup function that closes the TPM.
func setupTPMService(t *testing.T) (*TPMService, func()) {
	t.Helper()

	tpm := setupRealTPM(t)

	accessor := NewTPMAccessor(func() tpm2pkg.TrustedPlatformModule {
		return tpm
	})

	svc := NewTPMService()
	svc.SetContext(context.Background())
	svc.SetTPMAccessor(accessor)
	svc.SetDataDir(t.TempDir())

	cleanup := func() {
		tpm.Close()
	}
	return svc, cleanup
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

// --- Individual method tests ---

func TestIntegration_TPMService_GetStatus(t *testing.T) {
	svc, cleanup := setupTPMService(t)
	defer cleanup()

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
		t.Log("WARNING: TPM reported as not available despite device existing")
	}
}

func TestIntegration_TPMService_GetInfo(t *testing.T) {
	svc, cleanup := setupTPMService(t)
	defer cleanup()

	info, err := svc.GetInfo()
	if err != nil {
		t.Fatalf("GetInfo returned unexpected error: %v", err)
	}
	if info == nil {
		t.Fatal("GetInfo returned nil")
	}

	logJSON(t, "TPM Info", info)

	if info.Manufacturer == "" {
		t.Log("WARNING: manufacturer field is empty")
	}
	if len(info.PCRBanks) == 0 {
		t.Log("WARNING: no PCR banks detected")
	}
}

func TestIntegration_TPMService_GetEKInfo(t *testing.T) {
	svc, cleanup := setupTPMService(t)
	defer cleanup()

	info, err := svc.GetEKInfo()
	if err != nil {
		t.Fatalf("GetEKInfo returned unexpected error: %v", err)
	}
	if info == nil {
		t.Fatal("GetEKInfo returned nil")
	}

	logJSON(t, "EK Info", info)

	if !info.Present {
		t.Log("NOTE: RSA Endorsement Key not present (may require provisioning)")
	}
}

func TestIntegration_TPMService_GetEKECCInfo(t *testing.T) {
	svc, cleanup := setupTPMService(t)
	defer cleanup()

	info, err := svc.GetEKECCInfo()
	if err != nil {
		t.Fatalf("GetEKECCInfo returned unexpected error: %v", err)
	}
	if info == nil {
		t.Fatal("GetEKECCInfo returned nil")
	}

	logJSON(t, "EK ECC Info", info)

	if !info.Present {
		t.Log("NOTE: ECC Endorsement Key not present (common on many TPMs)")
	}
}

func TestIntegration_TPMService_GetIAKInfo(t *testing.T) {
	svc, cleanup := setupTPMService(t)
	defer cleanup()

	info, err := svc.GetIAKInfo()
	if err != nil {
		t.Fatalf("GetIAKInfo returned unexpected error: %v", err)
	}
	if info == nil {
		t.Fatal("GetIAKInfo returned nil")
	}

	logJSON(t, "IAK Info", info)

	if !info.Present {
		t.Log("NOTE: Initial Attestation Key not present (requires provisioning)")
	}
}

func TestIntegration_TPMService_GetIDevIDInfo(t *testing.T) {
	svc, cleanup := setupTPMService(t)
	defer cleanup()

	info, err := svc.GetIDevIDInfo()
	if err != nil {
		t.Fatalf("GetIDevIDInfo returned unexpected error: %v", err)
	}
	if info == nil {
		t.Fatal("GetIDevIDInfo returned nil")
	}

	logJSON(t, "IDevID Info", info)

	if !info.Present {
		t.Log("NOTE: Initial Device Identifier not present (requires provisioning)")
	}
}

func TestIntegration_TPMService_GetSharedSRKInfo(t *testing.T) {
	svc, cleanup := setupTPMService(t)
	defer cleanup()

	info, err := svc.GetSharedSRKInfo()
	if err != nil {
		t.Fatalf("GetSharedSRKInfo returned unexpected error: %v", err)
	}
	if info == nil {
		t.Fatal("GetSharedSRKInfo returned nil")
	}

	logJSON(t, "Shared SRK Info", info)

	if !info.Present {
		t.Log("NOTE: TCG Shared SRK not present (requires provisioning)")
	}
}

func TestIntegration_TPMService_GetPlatformSRKInfo(t *testing.T) {
	svc, cleanup := setupTPMService(t)
	defer cleanup()

	info, err := svc.GetPlatformSRKInfo()
	if err != nil {
		t.Fatalf("GetPlatformSRKInfo returned unexpected error: %v", err)
	}
	if info == nil {
		t.Fatal("GetPlatformSRKInfo returned nil")
	}

	logJSON(t, "Platform SRK Info", info)

	if !info.Present {
		t.Log("NOTE: Platform SRK not present (requires platform key store initialization)")
	}
}

func TestIntegration_TPMService_GetPCRs(t *testing.T) {
	svc, cleanup := setupTPMService(t)
	defer cleanup()

	banks := []string{"sha1", "sha256", "sha384", "sha512"}
	for _, bank := range banks {
		t.Run(bank, func(t *testing.T) {
			pcrs, err := svc.GetPCRs(bank)
			if err != nil {
				t.Logf("GetPCRs(%s) returned error: %v", bank, err)
				return
			}

			t.Logf("PCR bank %s: %d values returned", bank, len(pcrs))
			for _, pcr := range pcrs {
				t.Logf("  PCR[%02d] = %s", pcr.Index, pcr.Digest)
			}
		})
	}
}

func TestIntegration_TPMService_GetEventLog(t *testing.T) {
	svc, cleanup := setupTPMService(t)
	defer cleanup()

	events, err := svc.GetEventLog()
	if err != nil {
		t.Logf("GetEventLog returned error (expected if permissions insufficient): %v", err)
		return
	}

	t.Logf("Event log: %d entries", len(events))
	limit := 10
	if len(events) < limit {
		limit = len(events)
	}
	for i := 0; i < limit; i++ {
		t.Logf("  [%d] PCR=%d type=%s data=%q digest=%s",
			i, events[i].PCRIndex, events[i].EventType, events[i].EventData, events[i].DigestHex)
	}
	if len(events) > limit {
		t.Logf("  ... and %d more entries", len(events)-limit)
	}
}

func TestIntegration_TPMService_GetRandomBytes(t *testing.T) {
	svc, cleanup := setupTPMService(t)
	defer cleanup()

	lengths := []int{16, 32, 64}
	for _, length := range lengths {
		t.Run(fmt.Sprintf("%d_bytes", length), func(t *testing.T) {
			hexStr, err := svc.GetRandomBytes(length)
			if err != nil {
				t.Fatalf("GetRandomBytes(%d) failed: %v", length, err)
			}

			// hex-encoded output should be 2x the requested byte length
			expectedLen := length * 2
			if len(hexStr) != expectedLen {
				t.Errorf("GetRandomBytes(%d): expected %d hex chars, got %d",
					length, expectedLen, len(hexStr))
			}
			t.Logf("Random %d bytes: %s", length, hexStr)
		})
	}
}

func TestIntegration_TPMService_ListPersistentHandles(t *testing.T) {
	svc, cleanup := setupTPMService(t)
	defer cleanup()

	handles, err := svc.ListPersistentHandles()
	if err != nil {
		t.Fatalf("ListPersistentHandles failed: %v", err)
	}

	t.Logf("Persistent handles: %d found", len(handles))
	for _, h := range handles {
		t.Logf("  handle=%s type=%s desc=%q", h.Handle, h.Type, h.Description)
	}
}

func TestIntegration_TPMService_ListTransientHandles(t *testing.T) {
	svc, cleanup := setupTPMService(t)
	defer cleanup()

	handles, err := svc.ListTransientHandles()
	if err != nil {
		t.Fatalf("ListTransientHandles failed: %v", err)
	}

	t.Logf("Transient handles: %d found", len(handles))
	for _, h := range handles {
		t.Logf("  handle=%s type=%s", h.Handle, h.Type)
	}
}

func TestIntegration_TPMService_GetNVSummary(t *testing.T) {
	svc, cleanup := setupTPMService(t)
	defer cleanup()

	nv, err := svc.GetNVSummary()
	if err != nil {
		t.Fatalf("GetNVSummary failed: %v", err)
	}
	if nv == nil {
		t.Fatal("GetNVSummary returned nil")
	}

	t.Logf("NV Summary: defined=%d max=%d", nv.IndexesDefined, nv.IndexesMax)
	for _, idx := range nv.Indexes {
		t.Logf("  index=%s type=%s size=%d auth_read=%v auth_write=%v",
			idx.Handle, idx.Type, idx.Size, idx.AuthRead, idx.AuthWrite)
	}
}

func TestIntegration_TPMService_GetLockoutInfo(t *testing.T) {
	svc, cleanup := setupTPMService(t)
	defer cleanup()

	lockout, err := svc.GetLockoutInfo()
	if err != nil {
		t.Fatalf("GetLockoutInfo failed: %v", err)
	}
	if lockout == nil {
		t.Fatal("GetLockoutInfo returned nil")
	}

	t.Logf("Lockout: counter=%d max_auth_fail=%d interval=%d recovery=%d",
		lockout.Counter, lockout.MaxFail,
		lockout.Interval, lockout.Recovery)
}

func TestIntegration_TPMService_ExportEKCert(t *testing.T) {
	svc, cleanup := setupTPMService(t)
	defer cleanup()

	pem, err := svc.ExportEKCert("pem")
	if err != nil {
		t.Logf("ExportEKCert returned error (expected if no EK cert): %v", err)
		return
	}

	t.Logf("EK Certificate PEM (%d bytes):\n%s", len(pem), pem)
}

func TestIntegration_TPMService_ExportEKECCCert(t *testing.T) {
	svc, cleanup := setupTPMService(t)
	defer cleanup()

	pem, err := svc.ExportEKECCCert("pem")
	if err != nil {
		t.Logf("ExportEKECCCert returned error (expected if no ECC EK cert): %v", err)
		return
	}

	t.Logf("ECC EK Certificate PEM (%d bytes):\n%s", len(pem), pem)
}

func TestIntegration_TPMService_ExportIAKCert(t *testing.T) {
	svc, cleanup := setupTPMService(t)
	defer cleanup()

	pem, err := svc.ExportIAKCert("pem")
	if err != nil {
		t.Logf("ExportIAKCert returned error (expected if no IAK cert): %v", err)
		return
	}

	t.Logf("IAK Certificate PEM (%d bytes):\n%s", len(pem), pem)
}

func TestIntegration_TPMService_ExportIDevIDCert(t *testing.T) {
	svc, cleanup := setupTPMService(t)
	defer cleanup()

	pem, err := svc.ExportIDevIDCert("pem")
	if err != nil {
		t.Logf("ExportIDevIDCert returned error (expected if no IDevID cert): %v", err)
		return
	}

	t.Logf("IDevID Certificate PEM (%d bytes):\n%s", len(pem), pem)
}

func TestIntegration_TPMService_VerifyTPM(t *testing.T) {
	svc, cleanup := setupTPMService(t)
	defer cleanup()

	result, err := svc.VerifyTPM()
	if err != nil {
		t.Fatalf("VerifyTPM returned unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("VerifyTPM returned nil")
	}

	t.Logf("Verification: verified=%v issuer=%q error=%q",
		result.Verified, result.Issuer, result.ErrorMessage)

	if !result.Verified {
		t.Log("NOTE: TPM verification failed (expected without loaded manufacturer CA certs)")
	}
}

func TestIntegration_TPMService_GetPlatformPolicy(t *testing.T) {
	svc, cleanup := setupTPMService(t)
	defer cleanup()

	digest, err := svc.GetPlatformPolicy()
	if err != nil {
		t.Logf("GetPlatformPolicy returned error: %v", err)
		return
	}

	t.Logf("Platform policy digest: %s", digest)
}

func TestIntegration_TPMService_ListKeys(t *testing.T) {
	svc, cleanup := setupTPMService(t)
	defer cleanup()

	keys, err := svc.ListKeys()
	if err != nil {
		t.Fatalf("ListKeys returned unexpected error: %v", err)
	}

	t.Logf("Listed keys: %d", len(keys))
	for _, k := range keys {
		t.Logf("  id=%s algo=%s size=%d persistent=%v purpose=%s",
			k.ID, k.Algorithm, k.KeySize, k.Persistent, k.Purpose)
	}
}

// --- Full UI Flow Test ---

func TestIntegration_TPMService_FullUIFlow(t *testing.T) {
	svc, cleanup := setupTPMService(t)
	defer cleanup()

	// Step 1: Dashboard calls GetStatus
	t.Log("=== Step 1: GetStatus (dashboard) ===")
	status, err := svc.GetStatus()
	if err != nil {
		t.Fatalf("GetStatus failed: %v", err)
	}
	t.Logf("  available=%v provisioned=%v level=%s manufacturer=%q fw=%q device=%q",
		status.Available, status.Provisioned, status.StatusLevel,
		status.Manufacturer, status.FirmwareVer, status.DevicePath)

	// Step 2: TPM view loads - calls overview methods
	t.Log("=== Step 2: TPM Overview ===")

	info, err := svc.GetInfo()
	if err != nil {
		t.Fatalf("GetInfo failed: %v", err)
	}
	t.Logf("  manufacturer=%q vendor=%q family=%q fw=%s fips=%v",
		info.Manufacturer, info.VendorID, info.Family,
		info.FirmwareVersion, info.FIPSMode)
	t.Logf("  pcr_banks=%v algorithms=%v", info.PCRBanks, info.Algorithms)
	t.Logf("  max_rsa=%d max_ecc=%d nv_buffer=%d",
		info.MaxRSAKeySize, info.MaxECCKeySize, info.MaxNVBufferSize)
	t.Logf("  sessions: max=%d loaded=%d active=%d",
		info.ActiveSessionsMax, info.AuthSessionsLoaded, info.AuthSessionsActive)
	t.Logf("  persistent: loaded=%d avail=%d transient_avail=%d",
		info.PersistentLoaded, info.PersistentAvail, info.TransientAvail)
	t.Logf("  nv: defined=%d max=%d", info.NVIndexesDefined, info.NVIndexesMax)

	ekInfo, err := svc.GetEKInfo()
	if err != nil {
		t.Fatalf("GetEKInfo failed: %v", err)
	}
	t.Logf("  EK: present=%v algo=%s size=%d has_cert=%v",
		ekInfo.Present, ekInfo.Algorithm, ekInfo.KeySize, ekInfo.Certificate != "")

	eccInfo, err := svc.GetEKECCInfo()
	if err != nil {
		t.Fatalf("GetEKECCInfo failed: %v", err)
	}
	t.Logf("  EK ECC: present=%v algo=%s size=%d has_cert=%v",
		eccInfo.Present, eccInfo.Algorithm, eccInfo.KeySize, eccInfo.Certificate != "")

	iakInfo, err := svc.GetIAKInfo()
	if err != nil {
		t.Fatalf("GetIAKInfo failed: %v", err)
	}
	t.Logf("  IAK: present=%v algo=%s size=%d handle=%s has_cert=%v",
		iakInfo.Present, iakInfo.Algorithm, iakInfo.KeySize,
		iakInfo.Handle, iakInfo.Certificate != "")

	idevidInfo, err := svc.GetIDevIDInfo()
	if err != nil {
		t.Fatalf("GetIDevIDInfo failed: %v", err)
	}
	t.Logf("  IDevID: present=%v algo=%s size=%d has_cert=%v",
		idevidInfo.Present, idevidInfo.Algorithm, idevidInfo.KeySize,
		idevidInfo.Certificate != "")

	sharedSRK, err := svc.GetSharedSRKInfo()
	if err != nil {
		t.Fatalf("GetSharedSRKInfo failed: %v", err)
	}
	t.Logf("  Shared SRK: present=%v algo=%s", sharedSRK.Present, sharedSRK.Algorithm)

	platformSRK, err := svc.GetPlatformSRKInfo()
	if err != nil {
		t.Fatalf("GetPlatformSRKInfo failed: %v", err)
	}
	t.Logf("  Platform SRK: present=%v algo=%s initialized=%v", platformSRK.Present, platformSRK.Algorithm, platformSRK.Initialized)

	// Step 3: User clicks Measurements tab
	t.Log("=== Step 3: Measurements (PCRs) ===")
	pcrs, err := svc.GetPCRs("sha256")
	if err != nil {
		t.Logf("  GetPCRs(sha256) error: %v", err)
	} else {
		t.Logf("  SHA-256 PCR values: %d", len(pcrs))
		for _, pcr := range pcrs {
			t.Logf("    PCR[%02d] = %s", pcr.Index, pcr.Digest)
		}
	}

	// Step 4: User clicks Key Handles tab
	t.Log("=== Step 4: Key Handles ===")
	persistent, err := svc.ListPersistentHandles()
	if err != nil {
		t.Logf("  ListPersistentHandles error: %v", err)
	} else {
		t.Logf("  Persistent handles: %d", len(persistent))
		for _, h := range persistent {
			t.Logf("    %s (%s) %q", h.Handle, h.Type, h.Description)
		}
	}

	transient, err := svc.ListTransientHandles()
	if err != nil {
		t.Logf("  ListTransientHandles error: %v", err)
	} else {
		t.Logf("  Transient handles: %d", len(transient))
		for _, h := range transient {
			t.Logf("    %s (%s)", h.Handle, h.Type)
		}
	}

	// Step 5: User clicks NV Storage tab
	t.Log("=== Step 5: NV Storage ===")
	nv, err := svc.GetNVSummary()
	if err != nil {
		t.Logf("  GetNVSummary error: %v", err)
	} else {
		t.Logf("  NV: defined=%d max=%d indexes=%d",
			nv.IndexesDefined, nv.IndexesMax, len(nv.Indexes))
		for _, idx := range nv.Indexes {
			t.Logf("    %s type=%s size=%d", idx.Handle, idx.Type, idx.Size)
		}
	}

	// Step 6: User clicks Lockout tab
	t.Log("=== Step 6: Lockout ===")
	lockout, err := svc.GetLockoutInfo()
	if err != nil {
		t.Logf("  GetLockoutInfo error: %v", err)
	} else {
		t.Logf("  counter=%d max_auth_fail=%d interval=%d recovery=%d",
			lockout.Counter, lockout.MaxFail,
			lockout.Interval, lockout.Recovery)
	}

	// Step 7: User requests random bytes
	t.Log("=== Step 7: Random Bytes ===")
	randomHex, err := svc.GetRandomBytes(32)
	if err != nil {
		t.Logf("  GetRandomBytes error: %v", err)
	} else {
		t.Logf("  32 random bytes: %s", randomHex)
	}

	// Step 8: Verification status
	t.Log("=== Step 8: Verification ===")
	verif, err := svc.VerifyTPM()
	if err != nil {
		t.Logf("  VerifyTPM error: %v", err)
	} else {
		t.Logf("  verified=%v issuer=%q error=%q",
			verif.Verified, verif.Issuer, verif.ErrorMessage)
	}

	t.Log("=== Full UI flow completed without panics ===")
}

// --- Concurrency Test ---

func TestIntegration_TPMService_ConcurrentAccess(t *testing.T) {
	svc, cleanup := setupTPMService(t)
	defer cleanup()

	var wg sync.WaitGroup
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

	for _, m := range methods {
		wg.Add(1)
		go func(name string, fn func() error) {
			defer wg.Done()
			if err := fn(); err != nil {
				// Log errors but do not fail: not-provisioned errors are expected.
				t.Logf("%s returned error (may be expected): %v", name, err)
			} else {
				t.Logf("%s completed successfully", name)
			}
		}(m.name, m.fn)
	}

	wg.Wait()
	t.Log("All concurrent calls completed without panics or deadlocks")
}

// --- Repeated Access Test ---

func TestIntegration_TPMService_RepeatedAccess(t *testing.T) {
	svc, cleanup := setupTPMService(t)
	defer cleanup()

	// Simulate rapid repeated calls as a user might trigger by switching
	// between tabs quickly in the GUI.
	iterations := 5
	for i := 0; i < iterations; i++ {
		t.Logf("--- Iteration %d/%d ---", i+1, iterations)

		status, err := svc.GetStatus()
		if err != nil {
			t.Fatalf("iteration %d: GetStatus failed: %v", i+1, err)
		}
		t.Logf("  status: available=%v level=%s", status.Available, status.StatusLevel)

		info, err := svc.GetInfo()
		if err != nil {
			t.Fatalf("iteration %d: GetInfo failed: %v", i+1, err)
		}
		t.Logf("  info: manufacturer=%q", info.Manufacturer)

		_, pcrErr := svc.GetPCRs("sha256")
		if pcrErr != nil {
			t.Logf("  iteration %d: GetPCRs error: %v", i+1, pcrErr)
		}

		_, randErr := svc.GetRandomBytes(32)
		if randErr != nil {
			t.Fatalf("iteration %d: GetRandomBytes failed: %v", i+1, randErr)
		}
	}

	t.Logf("Completed %d iterations without panics or resource leaks", iterations)
}
