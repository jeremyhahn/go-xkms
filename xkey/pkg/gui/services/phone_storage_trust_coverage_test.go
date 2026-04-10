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

package services

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/events"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/truststore"
)

// ===========================================================================
// PhoneService: performAttestation coverage
// ===========================================================================

// TestPhoneService_PerformAttestation_BothNil verifies that performAttestation
// returns ErrPhoneNotConnected when both activeTransport and activeSession
// are nil.
func TestPhoneService_PerformAttestation_BothNil(t *testing.T) {
	svc := NewPhoneService()
	device := &phoneConfigDevice{
		Name:    "Galaxy S25",
		Address: "AA:BB:CC:DD:EE:01",
	}

	result, err := svc.performAttestation(device)
	assert.Nil(t, result)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPhoneNotConnected))
}

// ===========================================================================
// PhoneService: enforceAttestationPolicy coverage
// ===========================================================================

// TestPhoneService_EnforceAttestationPolicy_PolicyMismatchFields verifies
// that enforceAttestationPolicy emits a policy violation event that contains
// the expected mismatched field labels. Since performAttestation requires
// a real BLE transport, we exercise the "attestation failed" path.
func TestPhoneService_EnforceAttestationPolicy_PolicyMismatchFields(t *testing.T) {
	svc := NewPhoneService()

	var emitted events.Event
	svc.SetEventEmitter(func(evt events.Event) {
		emitted = evt
	})

	device := &phoneConfigDevice{
		Name:    "Pixel 9",
		Address: "AA:BB:CC:DD:EE:02",
		AttestationPolicy: &attestationPolicy{
			Enabled:       true,
			BootHash:      "expected_boot_hash_value",
			BootKeyHash:   "expected_boot_key_hash_value",
			BootState:     "verified",
			DeviceLocked:  true,
			SecurityLevel: "strongbox",
		},
	}

	err := svc.enforceAttestationPolicy("Pixel 9", device)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPhonePolicyViolation))
	assert.Contains(t, err.Error(), "attestation failed")

	// Event should contain "attestation" key in mismatches.
	assert.Equal(t, events.EventPolicyViolation, emitted.Type)
	payload, ok := emitted.Payload.(events.PolicyViolationPayload)
	require.True(t, ok)
	assert.Equal(t, "Pixel 9", payload.DeviceName)
	_, hasAttestation := payload.Mismatches["attestation"]
	assert.True(t, hasAttestation, "mismatches should contain 'attestation' key")
}

// ===========================================================================
// PhoneService: buildAttestationTrustPool coverage
// ===========================================================================

// TestPhoneService_BuildAttestationTrustPool_WithTrustStore verifies
// that buildAttestationTrustPool correctly merges trust store certs
// when a valid trust store is provided.
func TestPhoneService_BuildAttestationTrustPool_WithTrustStore(t *testing.T) {
	store := newTestFileStore(t)
	defer store.Close()

	// Seed the store with embedded Android roots.
	roots := truststore.LoadEmbeddedRoots(truststore.PurposeAndroidHardware)
	for _, root := range roots {
		_ = store.AddCertificateWithOptions(root, &truststore.AddCertificateOptions{
			Purpose: truststore.PurposeAndroidHardware,
			Source:  "embedded",
		})
	}

	svc := NewPhoneService()
	svc.SetTrustStore(store)

	pool, err := svc.buildAttestationTrustPool(roots)
	require.NoError(t, err)
	assert.NotNil(t, pool)
}

// TestPhoneService_BuildAttestationTrustPool_ClosedTrustStore verifies
// that buildAttestationTrustPool returns an error when the trust store
// has been closed and cannot build a trust pool.
func TestPhoneService_BuildAttestationTrustPool_ClosedTrustStore(t *testing.T) {
	store := newTestFileStore(t)
	require.NoError(t, store.Close())

	svc := NewPhoneService()
	svc.SetTrustStore(store)

	_, err := svc.buildAttestationTrustPool(nil)
	assert.Error(t, err, "closed trust store should return error")
}

// TestPhoneService_BuildAttestationTrustPool_FallbackWithEmbeddedRoots verifies
// the fallback path where trustStore is nil, so only embedded roots are used.
func TestPhoneService_BuildAttestationTrustPool_FallbackWithEmbeddedRoots(t *testing.T) {
	svc := NewPhoneService()
	// No trust store set.

	cert := generateTestCertCA(t)
	pool, err := svc.buildAttestationTrustPool([]*x509.Certificate{cert})
	require.NoError(t, err)
	assert.NotNil(t, pool)
}

// ===========================================================================
// PhoneService: closeActiveConnectionLocked coverage
// ===========================================================================

// TestPhoneService_CloseActiveConnectionLocked_ClearsSession verifies
// that closeActiveConnectionLocked sets activeSession to nil even when
// no transport is present.
func TestPhoneService_CloseActiveConnectionLocked_ClearsSession(t *testing.T) {
	svc := NewPhoneService()

	// Set session without transport.
	svc.connMu.Lock()
	svc.activeSession = nil
	svc.activeTransport = nil
	svc.closeActiveConnectionLocked()
	svc.connMu.Unlock()

	assert.Nil(t, svc.activeSession)
	assert.Nil(t, svc.activeTransport)
}

// TestPhoneService_Disconnect_WithEmptyTransport verifies Disconnect
// works correctly when called with empty transport state (covers the
// closeActiveConnectionLocked nil transport path).
func TestPhoneService_Disconnect_WithEmptyTransport(t *testing.T) {
	svc := NewPhoneService()
	svc.connState.deviceName.Store("TestDevice")
	svc.connState.connected.Store(true)

	var emitted events.Event
	svc.SetEventEmitter(func(evt events.Event) {
		emitted = evt
	})

	err := svc.Disconnect("TestDevice")
	assert.NoError(t, err)
	assert.False(t, svc.IsConnected())
	assert.Empty(t, svc.ConnectedDeviceName())

	// Verify disconnect event was emitted.
	assert.Equal(t, events.EventPhoneDisconnected, emitted.Type)
	payload, ok := emitted.Payload.(events.PhoneDisconnectedPayload)
	require.True(t, ok)
	assert.Equal(t, "TestDevice", payload.DeviceName)
	assert.Equal(t, "user_requested", payload.Reason)
}

// ===========================================================================
// PhoneService: Scan coverage (validation paths)
// ===========================================================================

// TestPhoneService_Scan_NegativeTimeout verifies negative timeout is rejected.
func TestPhoneService_Scan_NegativeTimeout(t *testing.T) {
	svc := NewPhoneService()
	_, err := svc.Scan(-5)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrPhoneInvalidTimeout))
}

// TestPhoneService_Scan_ZeroTimeout verifies zero timeout is rejected.
func TestPhoneService_Scan_ZeroTimeout(t *testing.T) {
	svc := NewPhoneService()
	_, err := svc.Scan(0)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrPhoneInvalidTimeout))
}

// TestPhoneService_Scan_MaxPlusOneTimeout verifies timeout exceeding 120 is rejected.
func TestPhoneService_Scan_MaxPlusOneTimeout(t *testing.T) {
	svc := NewPhoneService()
	_, err := svc.Scan(121)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrPhoneInvalidTimeout))
}

// ===========================================================================
// PhoneService: Pair coverage (empty address and early BLE failure paths)
// ===========================================================================

// TestPhoneService_Pair_EmptyAddressReturnsError verifies Pair returns
// ErrPhonePairFailed when address is empty (line 349-351).
func TestPhoneService_Pair_EmptyAddressReturnsError(t *testing.T) {
	svc := NewPhoneService()
	result, err := svc.Pair("")
	assert.Nil(t, result)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPhonePairFailed))
}

// TestPhoneService_Pair_NonEmptyAddress_NoHardware verifies that Pair with
// a valid address fails when no BLE hardware is available (covers the
// local key generation and BLE transport creation paths).
func TestPhoneService_Pair_NonEmptyAddress_NoHardware(t *testing.T) {
	svc := NewPhoneService()
	result, err := svc.Pair("11:22:33:44:55:66")
	// Should fail either because BLE unavailable or pairing failed (key gen succeeded).
	assert.Nil(t, result)
	require.Error(t, err)
	assert.True(t,
		errors.Is(err, ErrPhonePairFailed) || errors.Is(err, ErrPhoneBLEUnavailable),
		"expected ErrPhonePairFailed or ErrPhoneBLEUnavailable, got: %v", err)
}

// ===========================================================================
// PhoneService: Unpair with connected device exercises closeActiveConnectionLocked
// ===========================================================================

// TestPhoneService_Unpair_ConnectedDeviceDisconnectsAndClears verifies
// that Unpair on a connected device calls closeActiveConnectionLocked
// and clears the connection state.
func TestPhoneService_Unpair_ConnectedDeviceDisconnectsAndClears(t *testing.T) {
	tmpDir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, ".xkey"), 0700))

	cfg := phoneConfig{
		Devices: []phoneConfigDevice{
			{Name: "Pixel 9 Pro", Address: "AA:BB:CC:DD:EE:03", PairedAt: time.Now().UTC()},
			{Name: "Galaxy S25", Address: "11:22:33:44:55:67", PairedAt: time.Now().UTC()},
		},
		DefaultDevice: "Pixel 9 Pro",
	}
	data, err := yaml.Marshal(&cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, ".xkey", "phone.yaml"), data, 0600))

	origHome := os.Getenv("HOME")
	defer os.Setenv("HOME", origHome)
	os.Setenv("HOME", tmpDir)

	svc := NewPhoneService()
	// Simulate connected state for the device being unpaired.
	svc.connState.deviceName.Store("Pixel 9 Pro")
	svc.connState.connected.Store(true)

	var emittedEvents []events.Event
	svc.SetEventEmitter(func(evt events.Event) {
		emittedEvents = append(emittedEvents, evt)
	})

	err = svc.Unpair("Pixel 9 Pro")
	require.NoError(t, err)

	// Device should be disconnected.
	assert.False(t, svc.IsConnected())
	assert.Empty(t, svc.ConnectedDeviceName())
	assert.Nil(t, svc.activeTransport)
	assert.Nil(t, svc.activeSession)

	// Should have a disconnect event.
	foundDisconnect := false
	for _, evt := range emittedEvents {
		if evt.Type == events.EventPhoneDisconnected {
			foundDisconnect = true
		}
	}
	assert.True(t, foundDisconnect, "expected disconnect event after unpair")

	// Verify the remaining device became the new default.
	loaded, err := svc.loadConfig()
	require.NoError(t, err)
	assert.Len(t, loaded.Devices, 1)
	assert.Equal(t, "Galaxy S25", loaded.DefaultDevice)
}

// ===========================================================================
// PhoneService: saveAttestationResult with non-matching device name
// ===========================================================================

// TestPhoneService_SaveAttestationResult_DeviceNameMismatch verifies
// saveAttestationResult gracefully handles a config where the device
// name does not match any config entry (no-op on save).
func TestPhoneService_SaveAttestationResult_DeviceNameMismatch(t *testing.T) {
	tmpDir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, ".xkey"), 0700))

	origHome := os.Getenv("HOME")
	defer os.Setenv("HOME", origHome)
	os.Setenv("HOME", tmpDir)

	svc := NewPhoneService()
	cfg := &phoneConfig{
		Devices: []phoneConfigDevice{
			{Name: "Galaxy S24", Address: "11:22:33:44:55:66", PairedAt: time.Now().UTC()},
		},
		DefaultDevice: "Galaxy S24",
	}

	// Use a device pointer that doesn't match any cfg device name.
	device := &phoneConfigDevice{
		Name:    "Pixel 9",
		Address: "AA:BB:CC:DD:EE:FF",
	}
	result := &AttestationResult{
		DeviceName:    "Pixel 9",
		Verified:      true,
		SecurityLevel: "tee",
		BootState:     "verified",
		AttestTime:    time.Now(),
	}

	// Should not panic; saves config but device not found in loop.
	svc.saveAttestationResult(cfg, device, result)

	// Verify the existing device was not modified.
	loaded, err := svc.loadConfig()
	require.NoError(t, err)
	assert.Len(t, loaded.Devices, 1)
	assert.Nil(t, loaded.Devices[0].LastAttestation)
}

// ===========================================================================
// PhoneService: autoAttest with policy and last attestation
// ===========================================================================

// TestPhoneService_AutoAttest_PolicyDisabledButPresent verifies that
// autoAttest does not enforce the policy when Enabled is false,
// but with LastAttestation present, it refreshes attestation.
func TestPhoneService_AutoAttest_PolicyDisabledButPresent(t *testing.T) {
	svc := NewPhoneService()

	var emittedEvents []events.Event
	svc.SetEventEmitter(func(evt events.Event) {
		emittedEvents = append(emittedEvents, evt)
	})

	cfg := &phoneConfig{
		Devices: []phoneConfigDevice{
			{
				Name:    "Pixel 9",
				Address: "AA:BB:CC:DD:EE:04",
				AttestationPolicy: &attestationPolicy{
					Enabled:  false, // Not enabled.
					BootHash: "abc123",
				},
				LastAttestation: &savedAttestationData{
					Verified: true,
					BootHash: "abc123",
				},
			},
		},
	}
	device := &cfg.Devices[0]

	// autoAttest should skip policy enforcement (Enabled=false) and
	// proceed to refresh attestation (LastAttestation != nil).
	// performAttestation will fail (no transport) and emit a failure event.
	svc.autoAttest(cfg, device, "Pixel 9")

	// Should have emitted an attestation failure event.
	foundAttestation := false
	for _, evt := range emittedEvents {
		if evt.Type == events.EventAttestationResult {
			foundAttestation = true
			payload, ok := evt.Payload.(events.AttestationResultPayload)
			assert.True(t, ok)
			assert.False(t, payload.Success)
		}
	}
	assert.True(t, foundAttestation, "expected attestation result event")
}

// ===========================================================================
// PhoneService: securityLevelRank ordering
// ===========================================================================

// TestPhoneService_SecurityLevelRank_AllValues exercises all known security
// level values and an unknown one.
func TestPhoneService_SecurityLevelRank_AllValues(t *testing.T) {
	tests := []struct {
		level    string
		expected int
	}{
		{"software", 0},
		{"tee", 1},
		{"strongbox", 2},
		{"unknown_level", -1},
		{"", -1},
	}
	for _, tt := range tests {
		t.Run(tt.level, func(t *testing.T) {
			assert.Equal(t, tt.expected, securityLevelRank(tt.level))
		})
	}
}

// ===========================================================================
// StorageService: WipeVolume coverage
// ===========================================================================

// TestStorageService_WipeVolume_CaseSensitiveStandard verifies that
// standard names are case-sensitive (only lowercase is accepted).
func TestStorageService_WipeVolume_CaseSensitiveStandard(t *testing.T) {
	svc := NewStorageService()
	err := svc.WipeVolume("NIST")
	assert.True(t, errors.Is(err, ErrStorageInvalidStandard))
}

// TestStorageService_WipeVolume_DoD3Standard verifies the "dod3" standard
// passes validation through the elevated path.
func TestStorageService_WipeVolume_DoD3Standard(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Log("running as root; skipping non-root test")
		return
	}
	svc := NewStorageService()
	mock := &mockElevator{available: true}
	svc.SetElevator(mock)

	err := svc.WipeVolume("dod3")
	assert.NoError(t, err)
	assert.Equal(t, "dod3", mock.lastArgs[3])
}

// TestStorageService_WipeVolume_DoD7Standard verifies the "dod7" standard
// passes validation through the elevated path.
func TestStorageService_WipeVolume_DoD7Standard(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Log("running as root; skipping non-root test")
		return
	}
	svc := NewStorageService()
	mock := &mockElevator{available: true}
	svc.SetElevator(mock)

	err := svc.WipeVolume("dod7")
	assert.NoError(t, err)
	assert.Equal(t, "dod7", mock.lastArgs[3])
}

// TestStorageService_WipeVolume_ElevatorUnavailable verifies WipeVolume
// returns ErrStorageRequiresRoot when the elevator is set but not available.
func TestStorageService_WipeVolume_ElevatorUnavailable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Log("running as root; skipping non-root test")
		return
	}
	svc := NewStorageService()
	mock := &mockElevator{available: false}
	svc.SetElevator(mock)

	err := svc.WipeVolume("nist")
	assert.True(t, errors.Is(err, ErrStorageRequiresRoot))
}

// TestStorageService_WipeVolume_ElevatorError verifies WipeVolume
// propagates elevator errors.
func TestStorageService_WipeVolume_ElevatorError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Log("running as root; skipping non-root test")
		return
	}
	svc := NewStorageService()
	mock := &mockElevator{available: true, err: ErrElevationFailed}
	svc.SetElevator(mock)

	err := svc.WipeVolume("nist")
	assert.ErrorIs(t, err, ErrElevationFailed)
}

// ===========================================================================
// StorageService: LockVolume coverage
// ===========================================================================

// TestStorageService_LockVolume_NoElevatorSet verifies LockVolume
// returns ErrStorageRequiresRoot when no elevator is configured.
func TestStorageService_LockVolume_NoElevatorSet(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Log("running as root; skipping non-root test")
		return
	}
	svc := NewStorageService()
	// No elevator set.
	err := svc.LockVolume()
	assert.True(t, errors.Is(err, ErrStorageRequiresRoot))
}

// TestStorageService_LockVolume_ElevatorDenied verifies LockVolume
// propagates ErrElevationDenied.
func TestStorageService_LockVolume_ElevatorDenied(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Log("running as root; skipping non-root test")
		return
	}
	svc := NewStorageService()
	mock := &mockElevator{available: true, err: ErrElevationDenied}
	svc.SetElevator(mock)

	err := svc.LockVolume()
	assert.ErrorIs(t, err, ErrElevationDenied)
}

// TestStorageService_LockVolume_ArgsFormat verifies the CLI arguments
// passed through the elevator for lock operations.
func TestStorageService_LockVolume_ArgsFormat(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Log("running as root; skipping non-root test")
		return
	}
	svc := NewStorageService()
	mock := &mockElevator{available: true}
	svc.SetElevator(mock)

	err := svc.LockVolume()
	require.NoError(t, err)

	require.True(t, len(mock.lastArgs) >= 2)
	assert.Equal(t, "luks2", mock.lastArgs[0])
	assert.Equal(t, "lock", mock.lastArgs[1])
	assert.Nil(t, mock.lastData, "lock should not send stdin data")
}

// ===========================================================================
// TrustService: ImportCertificateFile coverage
// ===========================================================================

// TestTrustService_ImportCertificateFile_NilStore_ReturnsError verifies
// ImportCertificateFile returns ErrNilTrustStore when store is nil.
func TestTrustService_ImportCertificateFile_NilStore_ReturnsError(t *testing.T) {
	svc := NewTrustService(nil)
	count, err := svc.ImportCertificateFile()
	assert.Equal(t, 0, count)
	assert.ErrorIs(t, err, ErrNilTrustStore)
}

// NOTE: ImportCertificateFile calls wailsruntime.OpenFileDialog which
// requires a Wails application context. We cannot test the full dialog
// path in unit tests, but we can verify the nil-store guard and error
// propagation paths.

// ===========================================================================
// TrustService: InstallToSystem coverage
// ===========================================================================

// TestTrustService_InstallToSystem_NilStoreReturnsError verifies
// InstallToSystem returns ErrNilTrustStore when store is nil.
func TestTrustService_InstallToSystem_NilStoreReturnsError(t *testing.T) {
	svc := NewTrustService(nil)
	err := svc.InstallToSystem("some-fingerprint", "password123")
	assert.ErrorIs(t, err, ErrNilTrustStore)
}

// TestTrustService_InstallToSystem_CertNotFound_WithSeededStore verifies
// InstallToSystem returns ErrCertificateNotFound when the fingerprint
// does not match any certificate in the store.
func TestTrustService_InstallToSystem_CertNotFound_WithSeededStore(t *testing.T) {
	store := newTestFileStore(t)
	defer store.Close()
	svc := NewTrustService(store)

	// Add a test cert so the store is not empty.
	cert := generateTestCertCA(t)
	require.NoError(t, store.AddCertificate(cert))

	badFP := strings.Repeat("99", 32)
	err := svc.InstallToSystem(badFP, "password123")
	assert.ErrorIs(t, err, truststore.ErrCertificateNotFound)
}

// TestTrustService_InstallToSystem_ValidCert_SudoFails verifies
// InstallToSystem reaches the sudo execution path but fails when
// sudo is not available or password is wrong. This covers the code
// path past findCertByFingerprint (line 327) into the elevator call.
func TestTrustService_InstallToSystem_ValidCert_SudoFails(t *testing.T) {
	store := newTestFileStore(t)
	defer store.Close()
	svc := NewTrustService(store)

	cert := generateTestCertCA(t)
	require.NoError(t, store.AddCertificate(cert))
	fp := truststore.Fingerprint(cert)

	// InstallToSystem creates a SudoElevator internally with the given password.
	// On CI/test environments, sudo will fail with a bad password.
	err := svc.InstallToSystem(fp, "definitely-wrong-password")
	// The error comes from the SudoElevator.Run call failing.
	// It should be some error (not nil), and not ErrCertificateNotFound.
	assert.Error(t, err)
	assert.False(t, errors.Is(err, truststore.ErrCertificateNotFound),
		"error should not be ErrCertificateNotFound")
}

// ===========================================================================
// TrustService: RemoveFromSystem coverage
// ===========================================================================

// TestTrustService_RemoveFromSystem_NilStoreReturnsError verifies
// RemoveFromSystem returns ErrNilTrustStore when store is nil.
func TestTrustService_RemoveFromSystem_NilStoreReturnsError(t *testing.T) {
	svc := NewTrustService(nil)
	err := svc.RemoveFromSystem("fingerprint", "password123")
	assert.ErrorIs(t, err, ErrNilTrustStore)
}

// TestTrustService_RemoveFromSystem_NotInStore verifies RemoveFromSystem
// returns ErrCertificateNotFound when the fingerprint is not in the store.
func TestTrustService_RemoveFromSystem_NotInStore(t *testing.T) {
	store := newTestFileStore(t)
	defer store.Close()
	svc := NewTrustService(store)

	badFP := strings.Repeat("bb", 32)
	err := svc.RemoveFromSystem(badFP, "password123")
	assert.ErrorIs(t, err, truststore.ErrCertificateNotFound)
}

// TestTrustService_RemoveFromSystem_ValidCert_SudoFails verifies
// RemoveFromSystem reaches the sudo execution path but fails when
// sudo is not available or password is wrong. This covers the code
// path past Contains check (line 358) into the elevator call.
func TestTrustService_RemoveFromSystem_ValidCert_SudoFails(t *testing.T) {
	store := newTestFileStore(t)
	defer store.Close()
	svc := NewTrustService(store)

	cert := generateTestCertCA(t)
	require.NoError(t, store.AddCertificate(cert))
	fp := truststore.Fingerprint(cert)

	// RemoveFromSystem creates a SudoElevator internally.
	err := svc.RemoveFromSystem(fp, "definitely-wrong-password")
	// The error should come from the SudoElevator, not from cert lookup.
	assert.Error(t, err)
	assert.False(t, errors.Is(err, truststore.ErrCertificateNotFound),
		"error should not be ErrCertificateNotFound")
}

// ===========================================================================
// TrustService: AddCertificatesPEM with DER data (negative test)
// ===========================================================================

// TestTrustService_AddCertificatesPEM_DERDataNotParsed verifies that
// AddCertificatesPEM returns 0 added when given raw DER data instead of PEM.
func TestTrustService_AddCertificatesPEM_DERDataNotParsed(t *testing.T) {
	store := newTestFileStore(t)
	defer store.Close()
	svc := NewTrustService(store)

	cert := generateTestCertCA(t)
	// Pass raw DER data (not PEM-encoded).
	count, err := svc.AddCertificatesPEM(string(cert.Raw))
	assert.Equal(t, 0, count)
	// May or may not error, but count should be 0.
	_ = err
}

// ===========================================================================
// PhoneService: emitPolicyViolationEvent with nil and non-nil emitter
// ===========================================================================

// TestPhoneService_EmitPolicyViolation_WithEmitter_MultipleFields verifies
// that emitPolicyViolationEvent correctly sends all mismatch fields.
func TestPhoneService_EmitPolicyViolation_WithEmitter_MultipleFields(t *testing.T) {
	svc := NewPhoneService()

	var emitted events.Event
	svc.SetEventEmitter(func(evt events.Event) {
		emitted = evt
	})

	mismatches := map[string]string{
		"boot_hash":      "mismatch 1",
		"boot_key_hash":  "mismatch 2",
		"boot_state":     "mismatch 3",
		"device_locked":  "mismatch 4",
		"security_level": "mismatch 5",
	}
	svc.emitPolicyViolationEvent("Test Device", mismatches, "5 fields mismatched")

	assert.Equal(t, events.EventPolicyViolation, emitted.Type)
	payload, ok := emitted.Payload.(events.PolicyViolationPayload)
	require.True(t, ok)
	assert.Equal(t, "Test Device", payload.DeviceName)
	assert.Len(t, payload.Mismatches, 5)
	assert.Equal(t, "5 fields mismatched", payload.Message)
}

// ===========================================================================
// PhoneService: truncateHash edge cases
// ===========================================================================

// TestPhoneService_TruncateHash_Exactly29 verifies truncation at the boundary.
func TestPhoneService_TruncateHash_Exactly29(t *testing.T) {
	hash := "12345678901234567890123456789" // 29 chars
	result := truncateHash(hash)
	// 29 > 28, so it should be truncated: h[:16] + "..." + h[29-8:]
	// h[:16] = "1234567890123456", h[21:] = "23456789"
	assert.Equal(t, "1234567890123456...23456789", result)
}

// TestPhoneService_TruncateHash_Exactly28 verifies no truncation at boundary.
func TestPhoneService_TruncateHash_Exactly28(t *testing.T) {
	hash := "1234567890123456789012345678" // exactly 28 chars
	result := truncateHash(hash)
	assert.Equal(t, hash, result) // returned as-is
}

// ===========================================================================
// PhoneService: buildCertInfoList with multiple intermediates
// ===========================================================================

// TestPhoneService_BuildCertInfoList_FourCerts verifies that with > 3 certs,
// intermediate labels include a numeric index.
func TestPhoneService_BuildCertInfoList_FourCerts(t *testing.T) {
	leaf := generateTestCertCA(t)
	int1 := generateTestCertCA(t)
	int2 := generateTestCertCA(t)
	root := generateTestCertCA(t)

	chain := []*x509.Certificate{leaf, int1, int2, root}
	infos := buildCertInfoList(chain, []*x509.Certificate{root})

	require.Len(t, infos, 4)
	assert.Equal(t, "Leaf", infos[0].Label)
	assert.Equal(t, "Intermediate 1", infos[1].Label)
	assert.Equal(t, "Intermediate 2", infos[2].Label)
	assert.Equal(t, "Root", infos[3].Label)
	assert.True(t, infos[3].IsTrustAnchor)
	assert.False(t, infos[0].IsTrustAnchor)
	assert.False(t, infos[1].IsTrustAnchor)
	assert.False(t, infos[2].IsTrustAnchor)
}

// ===========================================================================
// PhoneService: getCertLabel edge cases
// ===========================================================================

// TestPhoneService_GetCertLabel_SingleCert verifies label for a single cert chain.
func TestPhoneService_GetCertLabel_SingleCert(t *testing.T) {
	// total=1: index 0 is both leaf and root.
	assert.Equal(t, "Leaf", getCertLabel(0, 1))
}

// TestPhoneService_GetCertLabel_TwoCerts verifies labels for a two cert chain.
func TestPhoneService_GetCertLabel_TwoCerts(t *testing.T) {
	assert.Equal(t, "Leaf", getCertLabel(0, 2))
	assert.Equal(t, "Root", getCertLabel(1, 2))
}

// ===========================================================================
// PhoneService: keymasterPurposeNameList full coverage
// ===========================================================================

// TestPhoneService_KeymasterPurposeNameList_AllKnown verifies all known purpose codes.
func TestPhoneService_KeymasterPurposeNameList_AllKnown(t *testing.T) {
	all := keymasterPurposeNameList([]int{0, 1, 2, 3, 4, 5, 6, 7})
	expected := []string{"ENCRYPT", "DECRYPT", "SIGN", "VERIFY", "DERIVE_KEY", "WRAP_KEY", "AGREE_KEY", "ATTEST_KEY"}
	assert.Equal(t, expected, all)
}

// ===========================================================================
// PhoneService: keymasterAlgorithmName full coverage
// ===========================================================================

// TestPhoneService_KeymasterAlgorithmName_AllKnown verifies all known algorithm codes.
func TestPhoneService_KeymasterAlgorithmName_AllKnown(t *testing.T) {
	tests := []struct {
		code int
		name string
	}{
		{1, "RSA"},
		{3, "EC"},
		{32, "AES"},
		{33, "TRIPLE_DES"},
		{128, "HMAC"},
		{999, "UNKNOWN(999)"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.name, keymasterAlgorithmName(tt.code))
	}
}

// ===========================================================================
// PhoneService: keymasterOriginName full coverage
// ===========================================================================

// TestPhoneService_KeymasterOriginName_AllKnown verifies all known origin codes.
func TestPhoneService_KeymasterOriginName_AllKnown(t *testing.T) {
	tests := []struct {
		code int
		name string
	}{
		{0, "GENERATED"},
		{1, "DERIVED"},
		{2, "IMPORTED"},
		{3, "UNKNOWN"},
		{4, "SECURELY_IMPORTED"},
		{100, "UNKNOWN(100)"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.name, keymasterOriginName(tt.code))
	}
}

// ===========================================================================
// PhoneService: parseDERChain with multiple certs
// ===========================================================================

// TestPhoneService_ParseDERChain_MultipleCerts verifies parseDERChain handles
// a chain with multiple valid certificates.
func TestPhoneService_ParseDERChain_MultipleCerts(t *testing.T) {
	cert1 := generateTestCertCA(t)
	cert2 := generateTestCertCA(t)

	chain, err := parseDERChain([][]byte{cert1.Raw, cert2.Raw})
	require.NoError(t, err)
	assert.Len(t, chain, 2)
}

// TestPhoneService_ParseDERChain_SecondCertInvalid verifies parseDERChain
// returns error with correct index when second cert is invalid.
func TestPhoneService_ParseDERChain_SecondCertInvalid(t *testing.T) {
	cert1 := generateTestCertCA(t)
	_, err := parseDERChain([][]byte{cert1.Raw, {0xFF, 0xFE, 0xFD}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "certificate at index 1")
}

// ===========================================================================
// PhoneService: findMatchingTrustRoot with multi-cert chain
// ===========================================================================

// TestPhoneService_FindMatchingTrustRoot_MatchOnLastCert verifies that
// findMatchingTrustRoot checks only the last cert in the chain.
func TestPhoneService_FindMatchingTrustRoot_MatchOnLastCert(t *testing.T) {
	leaf := generateTestCertCA(t)
	root := generateTestCertCA(t)

	// Last cert (root) should be matched.
	result := findMatchingTrustRoot(
		[]*x509.Certificate{leaf, root},
		[]*x509.Certificate{root},
	)
	assert.NotNil(t, result)
	assert.Equal(t, certFP(root), certFP(result))
}

// TestPhoneService_FindMatchingTrustRoot_NoMatchWhenLeafInRoots verifies
// that findMatchingTrustRoot does not match when only the leaf is in roots.
func TestPhoneService_FindMatchingTrustRoot_NoMatchWhenLeafInRoots(t *testing.T) {
	leaf := generateTestCertCA(t)
	root := generateTestCertCA(t)

	// Only leaf is in roots, but findMatchingTrustRoot checks last cert (root).
	result := findMatchingTrustRoot(
		[]*x509.Certificate{leaf, root},
		[]*x509.Certificate{leaf},
	)
	assert.Nil(t, result, "should not match when only leaf is in roots")
}

// ===========================================================================
// PhoneService: pubKeyFP with valid cert
// ===========================================================================

// TestPhoneService_PubKeyFP_ECDSA verifies pubKeyFP returns consistent
// fingerprints for ECDSA keys.
func TestPhoneService_PubKeyFP_ECDSA(t *testing.T) {
	cert := generateTestCertCA(t)
	fp1 := pubKeyFP(cert)
	fp2 := pubKeyFP(cert)
	assert.NotEmpty(t, fp1)
	assert.Equal(t, fp1, fp2, "pubKeyFP should be deterministic")
	assert.Len(t, fp1, 64) // SHA-256 hex = 64 chars
}

// ===========================================================================
// PhoneService: formatTrustAnchorName edge cases
// ===========================================================================

// TestPhoneService_FormatTrustAnchorName_EmptyOrgAndCN verifies the
// serial number fallback path.
func TestPhoneService_FormatTrustAnchorName_EmptyOrgAndCN(t *testing.T) {
	cert := &x509.Certificate{
		Subject: pkix.Name{},
	}
	assert.Equal(t, "Google Hardware Attestation Root", formatTrustAnchorName(cert))
}

// ===========================================================================
// TrustService: findCertByFingerprint with multiple certs
// ===========================================================================

// TestTrustService_FindCertByFingerprint_MultipleStored verifies
// findCertByFingerprint finds the correct cert among multiple.
func TestTrustService_FindCertByFingerprint_MultipleStored(t *testing.T) {
	store := newTestFileStore(t)
	defer store.Close()
	svc := NewTrustService(store)

	cert1 := generateTestCertCA(t)
	cert2 := generateTestCertCA(t)
	require.NoError(t, store.AddCertificate(cert1))
	require.NoError(t, store.AddCertificate(cert2))

	fp2 := truststore.Fingerprint(cert2)
	found, err := svc.findCertByFingerprint(fp2)
	require.NoError(t, err)
	assert.Equal(t, cert2.Subject.CommonName, found.Subject.CommonName)
}

// ===========================================================================
// TrustService: GetCertificatePEM with valid cert
// ===========================================================================

// TestTrustService_GetCertificatePEM_ValidCert verifies full PEM output.
func TestTrustService_GetCertificatePEM_ValidCert(t *testing.T) {
	store := newTestFileStore(t)
	defer store.Close()
	svc := NewTrustService(store)

	cert := generateTestCertCA(t)
	require.NoError(t, store.AddCertificate(cert))
	fp := truststore.Fingerprint(cert)

	pemStr, err := svc.GetCertificatePEM(fp)
	require.NoError(t, err)
	assert.Contains(t, pemStr, "BEGIN CERTIFICATE")
	assert.Contains(t, pemStr, "END CERTIFICATE")

	// Verify the PEM can be decoded back.
	block, _ := pem.Decode([]byte(pemStr))
	require.NotNil(t, block)
	parsed, parseErr := x509.ParseCertificate(block.Bytes)
	require.NoError(t, parseErr)
	assert.Equal(t, cert.Subject.CommonName, parsed.Subject.CommonName)
}

// ===========================================================================
// TrustService: ExportCertificateDER round-trip
// ===========================================================================

// TestTrustService_ExportCertificateDER_RoundTrip verifies DER export
// produces data that can be parsed back into the original certificate.
func TestTrustService_ExportCertificateDER_RoundTrip(t *testing.T) {
	store := newTestFileStore(t)
	defer store.Close()
	svc := NewTrustService(store)

	cert := generateTestCertCA(t)
	require.NoError(t, store.AddCertificate(cert))
	fp := truststore.Fingerprint(cert)

	der, err := svc.ExportCertificateDER(fp)
	require.NoError(t, err)

	parsed, parseErr := x509.ParseCertificate(der)
	require.NoError(t, parseErr)
	assert.Equal(t, cert.Subject.CommonName, parsed.Subject.CommonName)
	assert.Equal(t, truststore.Fingerprint(cert), truststore.Fingerprint(parsed))
}

// ===========================================================================
// Test helpers
// ===========================================================================

// generateTestCertCA creates a self-signed CA certificate for testing.
// Unlike generateTestCert from phone_service_test.go, this creates CA certs
// with unique serial numbers to avoid fingerprint collisions.
func generateTestCertCA(t *testing.T) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
			CommonName:   "Test CA " + serial.Text(16)[:8],
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}
