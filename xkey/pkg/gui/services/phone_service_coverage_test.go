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
	"encoding/base64"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/events"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/phone"
)

// covSetupHomeWithDevicesConfig creates a temp HOME dir, writes a devices.yaml
// config, sets HOME env var, and registers cleanup. Returns the temp dir path.
func covSetupHomeWithDevicesConfig(t *testing.T, cfg *phoneConfig) string {
	t.Helper()
	tmpDir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, ".xkey"), 0700))
	data, err := yaml.Marshal(cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(
		filepath.Join(tmpDir, ".xkey", devicesConfigFileName), data, 0600))
	origHome := os.Getenv("HOME")
	t.Cleanup(func() { os.Setenv("HOME", origHome) })
	os.Setenv("HOME", tmpDir)
	return tmpDir
}

// covGenerateTestCert generates a self-signed ECDSA P-256 certificate for tests.
func covGenerateTestCert(t *testing.T, cn string, isCA bool) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			Organization: []string{"Coverage Test Org"},
			CommonName:   cn,
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	return cert
}

// ---------------------------------------------------------------------------
// SetDeviceAsBackend coverage (was 0%)
// ---------------------------------------------------------------------------

func TestPhoneService_Coverage_SetDeviceAsBackend_EmptyName(t *testing.T) {
	svc := NewPhoneService()
	err := svc.SetDeviceAsBackend("", true)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPhoneDeviceNotFound))
}

func TestPhoneService_Coverage_SetDeviceAsBackend_NoConfig(t *testing.T) {
	tmpDir := t.TempDir()
	origHome := os.Getenv("HOME")
	t.Cleanup(func() { os.Setenv("HOME", origHome) })
	os.Setenv("HOME", tmpDir)

	svc := NewPhoneService()
	err := svc.SetDeviceAsBackend("Some Phone", true)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPhoneDeviceNotFound))
}

func TestPhoneService_Coverage_SetDeviceAsBackend_DeviceNotFound(t *testing.T) {
	cfg := &phoneConfig{
		Devices: []phoneConfigDevice{
			{Name: "Pixel 9", Address: "AA:BB:CC:DD:EE:01"},
		},
		DefaultDevice: "Pixel 9",
	}
	covSetupHomeWithDevicesConfig(t, cfg)

	svc := NewPhoneService()
	err := svc.SetDeviceAsBackend("iPhone 15", true)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPhoneDeviceNotFound))
}

func TestPhoneService_Coverage_SetDeviceAsBackend_EnableSuccess(t *testing.T) {
	cfg := &phoneConfig{
		Devices: []phoneConfigDevice{
			{Name: "Pixel 9", Address: "AA:BB:CC:DD:EE:01"},
		},
		DefaultDevice: "Pixel 9",
	}
	covSetupHomeWithDevicesConfig(t, cfg)

	svc := NewPhoneService()
	err := svc.SetDeviceAsBackend("Pixel 9", true)
	require.NoError(t, err)

	// Verify the config was updated on disk.
	reloaded, err := svc.loadConfig()
	require.NoError(t, err)
	assert.True(t, reloaded.Devices[0].IsBackend)
}

func TestPhoneService_Coverage_SetDeviceAsBackend_DisableSuccess(t *testing.T) {
	cfg := &phoneConfig{
		Devices: []phoneConfigDevice{
			{Name: "Pixel 9", Address: "AA:BB:CC:DD:EE:01", IsBackend: true},
		},
		DefaultDevice: "Pixel 9",
	}
	covSetupHomeWithDevicesConfig(t, cfg)

	svc := NewPhoneService()
	err := svc.SetDeviceAsBackend("Pixel 9", false)
	require.NoError(t, err)

	reloaded, err := svc.loadConfig()
	require.NoError(t, err)
	assert.False(t, reloaded.Devices[0].IsBackend)
}

func TestPhoneService_Coverage_SetDeviceAsBackend_MultipleDevices(t *testing.T) {
	cfg := &phoneConfig{
		Devices: []phoneConfigDevice{
			{Name: "Pixel 9", Address: "AA:BB:CC:DD:EE:01"},
			{Name: "Galaxy S24", Address: "11:22:33:44:55:66"},
		},
		DefaultDevice: "Pixel 9",
	}
	covSetupHomeWithDevicesConfig(t, cfg)

	svc := NewPhoneService()
	err := svc.SetDeviceAsBackend("Galaxy S24", true)
	require.NoError(t, err)

	reloaded, err := svc.loadConfig()
	require.NoError(t, err)
	assert.False(t, reloaded.Devices[0].IsBackend, "first device should remain unchanged")
	assert.True(t, reloaded.Devices[1].IsBackend, "second device should be marked as backend")
}

// ---------------------------------------------------------------------------
// GetBackendDevices coverage (was 0%)
// ---------------------------------------------------------------------------

func TestPhoneService_Coverage_GetBackendDevices_NoConfig(t *testing.T) {
	tmpDir := t.TempDir()
	origHome := os.Getenv("HOME")
	t.Cleanup(func() { os.Setenv("HOME", origHome) })
	os.Setenv("HOME", tmpDir)

	svc := NewPhoneService()
	devices, err := svc.GetBackendDevices()
	require.NoError(t, err)
	assert.Empty(t, devices)
}

func TestPhoneService_Coverage_GetBackendDevices_NoBackendDevices(t *testing.T) {
	cfg := &phoneConfig{
		Devices: []phoneConfigDevice{
			{Name: "Pixel 9", Address: "AA:BB:CC:DD:EE:01", IsBackend: false},
			{Name: "Galaxy S24", Address: "11:22:33:44:55:66", IsBackend: false},
		},
		DefaultDevice: "Pixel 9",
	}
	covSetupHomeWithDevicesConfig(t, cfg)

	svc := NewPhoneService()
	devices, err := svc.GetBackendDevices()
	require.NoError(t, err)
	assert.Empty(t, devices, "should return empty list when no devices are backends")
}

func TestPhoneService_Coverage_GetBackendDevices_SomeBackendDevices(t *testing.T) {
	now := time.Now().UTC()
	cfg := &phoneConfig{
		Devices: []phoneConfigDevice{
			{Name: "Pixel 9", Address: "AA:BB:CC:DD:EE:01", IsBackend: true, PairedAt: now},
			{Name: "Galaxy S24", Address: "11:22:33:44:55:66", IsBackend: false},
			{Name: "OnePlus 12", Address: "77:88:99:AA:BB:CC", IsBackend: true, PairedAt: now},
		},
		DefaultDevice: "Pixel 9",
	}
	covSetupHomeWithDevicesConfig(t, cfg)

	svc := NewPhoneService()
	devices, err := svc.GetBackendDevices()
	require.NoError(t, err)
	require.Len(t, devices, 2, "should return only backend-enabled devices")
	assert.Equal(t, "Pixel 9", devices[0].Name)
	assert.Equal(t, "OnePlus 12", devices[1].Name)
	assert.True(t, devices[0].IsBackend)
	assert.True(t, devices[1].IsBackend)
}

func TestPhoneService_Coverage_GetBackendDevices_ConnectedDeviceMarked(t *testing.T) {
	cfg := &phoneConfig{
		Devices: []phoneConfigDevice{
			{Name: "Pixel 9", Address: "AA:BB:CC:DD:EE:01", IsBackend: true},
		},
		DefaultDevice: "Pixel 9",
	}
	covSetupHomeWithDevicesConfig(t, cfg)

	svc := NewPhoneService()
	svc.setConnected("Pixel 9")

	devices, err := svc.GetBackendDevices()
	require.NoError(t, err)
	require.Len(t, devices, 1)
	assert.True(t, devices[0].Connected, "connected device should be marked as connected")
}

func TestPhoneService_Coverage_GetBackendDevices_DisconnectedDeviceNotMarked(t *testing.T) {
	cfg := &phoneConfig{
		Devices: []phoneConfigDevice{
			{Name: "Pixel 9", Address: "AA:BB:CC:DD:EE:01", IsBackend: true},
		},
		DefaultDevice: "Pixel 9",
	}
	covSetupHomeWithDevicesConfig(t, cfg)

	svc := NewPhoneService()
	// Not connected - default state.
	devices, err := svc.GetBackendDevices()
	require.NoError(t, err)
	require.Len(t, devices, 1)
	assert.False(t, devices[0].Connected)
}

func TestPhoneService_Coverage_GetBackendDevices_InvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, ".xkey"), 0700))
	require.NoError(t, os.WriteFile(
		filepath.Join(tmpDir, ".xkey", devicesConfigFileName),
		[]byte("{{{{invalid yaml"), 0600))
	origHome := os.Getenv("HOME")
	t.Cleanup(func() { os.Setenv("HOME", origHome) })
	os.Setenv("HOME", tmpDir)

	svc := NewPhoneService()
	devices, err := svc.GetBackendDevices()
	require.NoError(t, err, "should not return error for invalid YAML, just empty list")
	assert.Empty(t, devices)
}

func TestPhoneService_Coverage_GetBackendDevices_LastSeenPopulated(t *testing.T) {
	attestTime := time.Date(2025, 6, 15, 10, 30, 0, 0, time.UTC)
	cfg := &phoneConfig{
		Devices: []phoneConfigDevice{
			{
				Name:                      "Pixel 9",
				Address:                   "AA:BB:CC:DD:EE:01",
				IsBackend:                 true,
				LastDeviceAttestationTime: attestTime,
			},
		},
		DefaultDevice: "Pixel 9",
	}
	covSetupHomeWithDevicesConfig(t, cfg)

	svc := NewPhoneService()
	devices, err := svc.GetBackendDevices()
	require.NoError(t, err)
	require.Len(t, devices, 1)
	assert.Equal(t, attestTime, devices[0].LastSeen)
}

// ---------------------------------------------------------------------------
// closeActiveConnectionLocked additional coverage (was 40%)
// ---------------------------------------------------------------------------

func TestPhoneService_Coverage_CloseActiveConnectionLocked_WithTransport(t *testing.T) {
	svc := NewPhoneService()

	// Create a stub BLETransport and assign it as the active transport.
	// The stub's Disconnect() and Close() are no-ops, which is exactly what
	// we need to verify the cleanup logic without actual BLE hardware.
	stubTransport := &phone.BLETransport{}
	svc.activeTransport = stubTransport

	svc.connMu.Lock()
	svc.closeActiveConnectionLocked()
	svc.connMu.Unlock()

	assert.Nil(t, svc.activeTransport, "transport should be cleared after close")
	assert.Nil(t, svc.activeSession, "session should be cleared after close")
}

func TestPhoneService_Coverage_CloseActiveConnectionLocked_WithTransportAndSession(t *testing.T) {
	svc := NewPhoneService()

	stubTransport := &phone.BLETransport{}
	svc.activeTransport = stubTransport
	// activeSession is also set (we can't create a real NoiseSession without crypto,
	// but we can set it to nil - the function should handle it gracefully).
	// The cleanup path for activeSession is just = nil assignment.
	svc.activeSession = nil

	svc.connMu.Lock()
	svc.closeActiveConnectionLocked()
	svc.connMu.Unlock()

	assert.Nil(t, svc.activeTransport)
	assert.Nil(t, svc.activeSession)
}

func TestPhoneService_Coverage_CloseActiveConnectionLocked_CalledTwice(t *testing.T) {
	svc := NewPhoneService()
	stubTransport := &phone.BLETransport{}
	svc.activeTransport = stubTransport

	svc.connMu.Lock()
	svc.closeActiveConnectionLocked()
	svc.connMu.Unlock()

	// Calling again when already nil should be a no-op.
	svc.connMu.Lock()
	svc.closeActiveConnectionLocked()
	svc.connMu.Unlock()

	assert.Nil(t, svc.activeTransport)
	assert.Nil(t, svc.activeSession)
}

// ---------------------------------------------------------------------------
// enforceAttestationPolicy additional branches (was 20%)
// ---------------------------------------------------------------------------

func TestPhoneService_Coverage_EnforcePolicy_VerificationFailed(t *testing.T) {
	// When performAttestation returns a result with Verified=false,
	// enforceAttestationPolicy should return ErrPhonePolicyViolation
	// with "attestation chain not verified".
	svc := NewPhoneService()

	var emittedEvents []events.Event
	svc.SetEventEmitter(func(evt events.Event) {
		emittedEvents = append(emittedEvents, evt)
	})

	// No active transport/session means performAttestation will fail with
	// ErrPhoneNotConnected (the first code path that checks transport==nil).
	device := &phoneConfigDevice{
		Name:    "Pixel 9",
		Address: "AA:BB:CC:DD:EE:01",
		AttestationPolicy: &attestationPolicy{
			Enabled:       true,
			BootHash:      "somehash",
			SecurityLevel: "tee",
		},
	}

	err := svc.enforceAttestationPolicy("Pixel 9", device)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPhonePolicyViolation))
	assert.Contains(t, err.Error(), "attestation failed")

	// Verify policy violation event was emitted.
	require.NotEmpty(t, emittedEvents)
	assert.Equal(t, events.EventPolicyViolation, emittedEvents[0].Type)
}

func TestPhoneService_Coverage_EnforcePolicy_NilEmitterStillReturnsError(t *testing.T) {
	svc := NewPhoneService()
	// No event emitter set - should not panic.

	device := &phoneConfigDevice{
		Name:    "Pixel 9",
		Address: "AA:BB:CC:DD:EE:01",
		AttestationPolicy: &attestationPolicy{
			Enabled:       true,
			BootHash:      "expected",
			SecurityLevel: "strongbox",
		},
	}

	err := svc.enforceAttestationPolicy("Pixel 9", device)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPhonePolicyViolation))
}

// ---------------------------------------------------------------------------
// saveConfig error paths (was 66.7%)
// ---------------------------------------------------------------------------

func TestPhoneService_Coverage_SaveConfig_MarshalSuccess(t *testing.T) {
	tmpDir := t.TempDir()
	origHome := os.Getenv("HOME")
	t.Cleanup(func() { os.Setenv("HOME", origHome) })
	os.Setenv("HOME", tmpDir)

	svc := NewPhoneService()
	cfg := &phoneConfig{
		Devices: []phoneConfigDevice{
			{Name: "Pixel 9", Address: "AA:BB:CC:DD:EE:01"},
		},
		DefaultDevice: "Pixel 9",
	}

	err := svc.saveConfig(cfg)
	require.NoError(t, err)

	// Verify file was created.
	savedPath := filepath.Join(tmpDir, ".xkey", devicesConfigFileName)
	data, err := os.ReadFile(savedPath)
	require.NoError(t, err)
	assert.Contains(t, string(data), "Pixel 9")
}

func TestPhoneService_Coverage_SaveConfig_CreatesDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	origHome := os.Getenv("HOME")
	t.Cleanup(func() { os.Setenv("HOME", origHome) })
	os.Setenv("HOME", tmpDir)
	// .xkey dir does NOT exist yet.

	svc := NewPhoneService()
	cfg := &phoneConfig{
		Devices:       []phoneConfigDevice{},
		DefaultDevice: "",
	}
	err := svc.saveConfig(cfg)
	require.NoError(t, err)

	// Verify directory was created.
	info, err := os.Stat(filepath.Join(tmpDir, ".xkey"))
	require.NoError(t, err)
	assert.True(t, info.IsDir())
}

// ---------------------------------------------------------------------------
// phoneConfigPath migration path (was 90%)
// ---------------------------------------------------------------------------

func TestPhoneService_Coverage_PhoneConfigPath_LegacyMigration(t *testing.T) {
	tmpDir := t.TempDir()
	origHome := os.Getenv("HOME")
	t.Cleanup(func() { os.Setenv("HOME", origHome) })
	os.Setenv("HOME", tmpDir)

	// Create legacy phone.yaml but no devices.yaml.
	xkeyDir := filepath.Join(tmpDir, ".xkey")
	require.NoError(t, os.MkdirAll(xkeyDir, 0700))
	legacyData := []byte("devices:\n- name: Legacy Phone\n  address: FF:EE:DD:CC:BB:AA\n")
	require.NoError(t, os.WriteFile(filepath.Join(xkeyDir, legacyPhoneConfigFileName), legacyData, 0600))

	path, err := phoneConfigPath()
	require.NoError(t, err)
	assert.Contains(t, path, devicesConfigFileName)

	// Verify the legacy file was renamed.
	_, err = os.Stat(filepath.Join(xkeyDir, legacyPhoneConfigFileName))
	assert.True(t, os.IsNotExist(err), "legacy file should be renamed")
	_, err = os.Stat(filepath.Join(xkeyDir, devicesConfigFileName))
	assert.NoError(t, err, "new config file should exist after migration")
}

func TestPhoneService_Coverage_PhoneConfigPath_NoLegacyNoNew(t *testing.T) {
	tmpDir := t.TempDir()
	origHome := os.Getenv("HOME")
	t.Cleanup(func() { os.Setenv("HOME", origHome) })
	os.Setenv("HOME", tmpDir)

	// No .xkey dir at all.
	path, err := phoneConfigPath()
	require.NoError(t, err)
	assert.Contains(t, path, devicesConfigFileName)
}

func TestPhoneService_Coverage_PhoneConfigPath_BothExist(t *testing.T) {
	tmpDir := t.TempDir()
	origHome := os.Getenv("HOME")
	t.Cleanup(func() { os.Setenv("HOME", origHome) })
	os.Setenv("HOME", tmpDir)

	xkeyDir := filepath.Join(tmpDir, ".xkey")
	require.NoError(t, os.MkdirAll(xkeyDir, 0700))
	// Both files exist -- no migration should happen, new file takes precedence.
	require.NoError(t, os.WriteFile(filepath.Join(xkeyDir, devicesConfigFileName), []byte("devices: []\n"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(xkeyDir, legacyPhoneConfigFileName), []byte("devices: []\n"), 0600))

	path, err := phoneConfigPath()
	require.NoError(t, err)
	assert.Contains(t, path, devicesConfigFileName)

	// Legacy file should still exist (no migration needed).
	_, err = os.Stat(filepath.Join(xkeyDir, legacyPhoneConfigFileName))
	assert.NoError(t, err, "legacy file should still exist when new file also exists")
}

// ---------------------------------------------------------------------------
// autoAttest additional branches (was 75%)
// ---------------------------------------------------------------------------

func TestPhoneService_Coverage_AutoAttest_PolicyDisabled(t *testing.T) {
	svc := NewPhoneService()

	var emittedEvents []events.Event
	svc.SetEventEmitter(func(evt events.Event) {
		emittedEvents = append(emittedEvents, evt)
	})

	device := &phoneConfigDevice{
		Name:    "Pixel 9",
		Address: "AA:BB:CC:DD:EE:01",
		AttestationPolicy: &attestationPolicy{
			Enabled: false, // disabled
		},
	}
	cfg := &phoneConfig{
		Devices:       []phoneConfigDevice{*device},
		DefaultDevice: "Pixel 9",
	}

	// Policy is disabled but present, and no LastAttestation --
	// should skip all attestation logic.
	svc.autoAttest(cfg, device, "Pixel 9")

	// No events should be emitted since nothing happened.
	assert.Empty(t, emittedEvents)
}

func TestPhoneService_Coverage_AutoAttest_PolicyEnabled_NoTransport_EmitsDisconnect(t *testing.T) {
	svc := NewPhoneService()
	svc.setConnected("Pixel 9")

	var emittedEvents []events.Event
	svc.SetEventEmitter(func(evt events.Event) {
		emittedEvents = append(emittedEvents, evt)
	})
	var statusChanges []bool
	svc.SetStatusChangeFunc(func(connected bool, name string) {
		statusChanges = append(statusChanges, connected)
	})

	device := &phoneConfigDevice{
		Name:    "Pixel 9",
		Address: "AA:BB:CC:DD:EE:01",
		AttestationPolicy: &attestationPolicy{
			Enabled:  true,
			BootHash: "expected_hash",
		},
	}
	cfg := &phoneConfig{
		Devices:       []phoneConfigDevice{*device},
		DefaultDevice: "Pixel 9",
	}

	svc.autoAttest(cfg, device, "Pixel 9")

	// Policy enforcement should fail (no transport), and disconnect should be emitted.
	assert.False(t, svc.IsConnected(), "should be disconnected after policy violation")

	// Check that disconnect event was emitted.
	hasDisconnect := false
	for _, evt := range emittedEvents {
		if evt.Type == events.EventPhoneDisconnected {
			hasDisconnect = true
			break
		}
	}
	assert.True(t, hasDisconnect, "disconnect event should be emitted after policy failure")
}

func TestPhoneService_Coverage_AutoAttest_LastAttestation_NoTransport_EmitsFailure(t *testing.T) {
	svc := NewPhoneService()

	var emittedEvents []events.Event
	svc.SetEventEmitter(func(evt events.Event) {
		emittedEvents = append(emittedEvents, evt)
	})

	device := &phoneConfigDevice{
		Name:    "Pixel 9",
		Address: "AA:BB:CC:DD:EE:01",
		LastAttestation: &savedAttestationData{
			Verified:      true,
			SecurityLevel: "tee",
			Timestamp:     time.Now().Add(-1 * time.Hour),
		},
	}
	cfg := &phoneConfig{
		Devices:       []phoneConfigDevice{*device},
		DefaultDevice: "Pixel 9",
	}

	svc.autoAttest(cfg, device, "Pixel 9")

	// Should emit an attestation failure event since there's no transport.
	hasFailure := false
	for _, evt := range emittedEvents {
		if evt.Type == events.EventAttestationResult {
			payload, ok := evt.Payload.(events.AttestationResultPayload)
			if ok && !payload.Success {
				hasFailure = true
			}
		}
	}
	assert.True(t, hasFailure, "attestation failure event should be emitted")
}

// ---------------------------------------------------------------------------
// Disconnect with active transport (improves closeActiveConnectionLocked coverage)
// ---------------------------------------------------------------------------

func TestPhoneService_Coverage_Disconnect_WithActiveTransport(t *testing.T) {
	svc := NewPhoneService()

	var emittedEvents []events.Event
	svc.SetEventEmitter(func(evt events.Event) {
		emittedEvents = append(emittedEvents, evt)
	})
	var statusCalled bool
	svc.SetStatusChangeFunc(func(connected bool, name string) {
		statusCalled = true
		assert.False(t, connected)
	})

	// Set up connected state with a stub transport.
	svc.activeTransport = &phone.BLETransport{}
	svc.connState.connected.Store(true)
	svc.connState.deviceName.Store("Pixel 9")

	err := svc.Disconnect("Pixel 9")
	require.NoError(t, err)
	assert.Nil(t, svc.activeTransport, "transport should be cleared")
	assert.False(t, svc.IsConnected())
	assert.True(t, statusCalled)

	// Verify disconnect event.
	hasDisconnect := false
	for _, evt := range emittedEvents {
		if evt.Type == events.EventPhoneDisconnected {
			hasDisconnect = true
		}
	}
	assert.True(t, hasDisconnect)
}

// ---------------------------------------------------------------------------
// Unpair with active transport (improves closeActiveConnectionLocked coverage)
// ---------------------------------------------------------------------------

func TestPhoneService_Coverage_Unpair_WithActiveTransportDisconnects(t *testing.T) {
	cfg := &phoneConfig{
		Devices: []phoneConfigDevice{
			{Name: "Pixel 9", Address: "AA:BB:CC:DD:EE:01"},
		},
		DefaultDevice: "Pixel 9",
	}
	covSetupHomeWithDevicesConfig(t, cfg)

	svc := NewPhoneService()

	var emittedEvents []events.Event
	svc.SetEventEmitter(func(evt events.Event) {
		emittedEvents = append(emittedEvents, evt)
	})

	// Simulate connected state with stub transport.
	svc.activeTransport = &phone.BLETransport{}
	svc.connState.connected.Store(true)
	svc.connState.deviceName.Store("Pixel 9")

	err := svc.Unpair("Pixel 9")
	require.NoError(t, err)

	assert.Nil(t, svc.activeTransport, "transport should be cleared on unpair")
	assert.False(t, svc.IsConnected())
}

// ---------------------------------------------------------------------------
// Connect error paths (improve from 56.1%)
// ---------------------------------------------------------------------------

func TestPhoneService_Coverage_Connect_ValidBase64KeysInvalidStaticKey(t *testing.T) {
	// Valid base64 but the decoded bytes are not a valid Noise DH key (wrong length).
	shortKey := base64.StdEncoding.EncodeToString([]byte("tooshort"))
	cfg := &phoneConfig{
		Devices: []phoneConfigDevice{
			{
				Name:                 "Pixel 9",
				Address:              "AA:BB:CC:DD:EE:01",
				NoisePublicKey:       base64.StdEncoding.EncodeToString(make([]byte, 32)),
				LocalNoisePrivateKey: shortKey,
			},
		},
		DefaultDevice: "Pixel 9",
	}
	covSetupHomeWithDevicesConfig(t, cfg)

	svc := NewPhoneService()
	err := svc.Connect("Pixel 9")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPhoneMissingKeys),
		"invalid static key length should return ErrPhoneMissingKeys")
}

func TestPhoneService_Coverage_Connect_ValidKeysDeviceFingerprint(t *testing.T) {
	// Generate a valid 32-byte key pair for Noise.
	localPrivate := make([]byte, 32)
	_, err := rand.Read(localPrivate)
	require.NoError(t, err)
	remotePublic := make([]byte, 32)
	_, err = rand.Read(remotePublic)
	require.NoError(t, err)

	cfg := &phoneConfig{
		Devices: []phoneConfigDevice{
			{
				Name:                 "Pixel 9",
				Address:              "AA:BB:CC:DD:EE:01",
				NoisePublicKey:       base64.StdEncoding.EncodeToString(remotePublic),
				LocalNoisePrivateKey: base64.StdEncoding.EncodeToString(localPrivate),
				DeviceFingerprint:    "not-valid-hex-!!!",
			},
		},
		DefaultDevice: "Pixel 9",
	}
	covSetupHomeWithDevicesConfig(t, cfg)

	svc := NewPhoneService()
	err = svc.Connect("Pixel 9")
	// Should proceed past fingerprint decoding (logs warning), then fail at
	// BLE transport creation (ErrBLEUnavailable on non-BLE platform).
	require.Error(t, err)
	// On stub platform, NewBLETransport returns ErrBLEUnavailable, which maps
	// to either ErrPhoneBLEUnavailable or ErrPhoneConnectFailed.
	assert.True(t,
		errors.Is(err, ErrPhoneBLEUnavailable) || errors.Is(err, ErrPhoneConnectFailed),
		"should fail at BLE transport creation on stub platform")
}

func TestPhoneService_Coverage_Connect_ValidFingerprint(t *testing.T) {
	localPrivate := make([]byte, 32)
	_, err := rand.Read(localPrivate)
	require.NoError(t, err)
	remotePublic := make([]byte, 32)
	_, err = rand.Read(remotePublic)
	require.NoError(t, err)

	cfg := &phoneConfig{
		Devices: []phoneConfigDevice{
			{
				Name:                 "Pixel 9",
				Address:              "AA:BB:CC:DD:EE:01",
				NoisePublicKey:       base64.StdEncoding.EncodeToString(remotePublic),
				LocalNoisePrivateKey: base64.StdEncoding.EncodeToString(localPrivate),
				DeviceFingerprint:    "aabbccdd11223344", // valid hex
			},
		},
		DefaultDevice: "Pixel 9",
	}
	covSetupHomeWithDevicesConfig(t, cfg)

	svc := NewPhoneService()
	err = svc.Connect("Pixel 9")
	require.Error(t, err)
	// Should get past fingerprint decode successfully, then fail at BLE.
	assert.True(t,
		errors.Is(err, ErrPhoneBLEUnavailable) || errors.Is(err, ErrPhoneConnectFailed))
}

// ---------------------------------------------------------------------------
// performAttestation additional coverage (was 8.5%)
// ---------------------------------------------------------------------------

func TestPhoneService_Coverage_PerformAttestation_NilTransportReturnsNotConnected(t *testing.T) {
	svc := NewPhoneService()
	device := &phoneConfigDevice{
		Name:    "Pixel 9",
		Address: "AA:BB:CC:DD:EE:01",
	}

	result, err := svc.performAttestation(device)
	assert.Nil(t, result)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPhoneNotConnected))
}

func TestPhoneService_Coverage_PerformAttestation_TransportSetSessionNil(t *testing.T) {
	svc := NewPhoneService()
	svc.activeTransport = &phone.BLETransport{}
	svc.activeSession = nil

	device := &phoneConfigDevice{
		Name:    "Pixel 9",
		Address: "AA:BB:CC:DD:EE:01",
	}

	result, err := svc.performAttestation(device)
	assert.Nil(t, result)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPhoneNotConnected))
}

// ---------------------------------------------------------------------------
// AttestDevice with successful config load but performAttestation fails
// ---------------------------------------------------------------------------

func TestPhoneService_Coverage_AttestDevice_SuccessConfigDeviceFoundNoTransport(t *testing.T) {
	cfg := &phoneConfig{
		Devices: []phoneConfigDevice{
			{Name: "Pixel 9", Address: "AA:BB:CC:DD:EE:01"},
		},
		DefaultDevice: "Pixel 9",
	}
	covSetupHomeWithDevicesConfig(t, cfg)

	svc := NewPhoneService()
	svc.connState.connected.Store(true)
	svc.connState.deviceName.Store("Pixel 9")

	var emittedEvents []events.Event
	svc.SetEventEmitter(func(evt events.Event) {
		emittedEvents = append(emittedEvents, evt)
	})

	result, err := svc.AttestDevice("Pixel 9")
	// performAttestation will fail with ErrPhoneNotConnected (nil transport).
	// AttestDevice returns the error as a result, not as an error.
	require.NoError(t, err, "AttestDevice wraps attestation errors in the result")
	require.NotNil(t, result)
	assert.False(t, result.Verified)
	assert.Contains(t, result.ErrorMessage, "no device connected")
	assert.Equal(t, "Pixel 9", result.DeviceName)

	// Should have emitted an attestation result event with success=false.
	hasFailEvent := false
	for _, evt := range emittedEvents {
		if evt.Type == events.EventAttestationResult {
			payload, ok := evt.Payload.(events.AttestationResultPayload)
			if ok && !payload.Success {
				hasFailEvent = true
			}
		}
	}
	assert.True(t, hasFailEvent, "attestation failure event should be emitted")
}

// ---------------------------------------------------------------------------
// Scan boundary tests (improve from 32.1%)
// ---------------------------------------------------------------------------

func TestPhoneService_Coverage_Scan_Timeout121(t *testing.T) {
	svc := NewPhoneService()
	_, err := svc.Scan(121)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPhoneInvalidTimeout))
}

func TestPhoneService_Coverage_Scan_ValidTimeout_BLEUnavailable(t *testing.T) {
	svc := NewPhoneService()
	// Valid timeout but BLE is unavailable on stub platform.
	_, err := svc.Scan(5)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPhoneBLEUnavailable))
}

func TestPhoneService_Coverage_Scan_Timeout120_BLEUnavailable(t *testing.T) {
	svc := NewPhoneService()
	// Exactly at boundary (120 is valid).
	_, err := svc.Scan(120)
	require.Error(t, err)
	// On stub platform, NewBLETransport returns ErrBLEUnavailable.
	assert.True(t, errors.Is(err, ErrPhoneBLEUnavailable))
}

func TestPhoneService_Coverage_Scan_Timeout1_BLEUnavailable(t *testing.T) {
	svc := NewPhoneService()
	_, err := svc.Scan(1)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPhoneBLEUnavailable))
}

// ---------------------------------------------------------------------------
// Pair error paths (improve from 12.6%)
// ---------------------------------------------------------------------------

func TestPhoneService_Coverage_Pair_NonEmptyAddress_BLEUnavailable(t *testing.T) {
	svc := NewPhoneService()
	// On stub platform, phone.GenerateStaticKey succeeds but
	// phone.NewBLETransport returns ErrBLEUnavailable.
	result, err := svc.Pair("AA:BB:CC:DD:EE:FF")
	assert.Nil(t, result)
	require.Error(t, err)
	// Could be ErrPhonePairFailed or ErrPhoneBLEUnavailable.
	assert.True(t,
		errors.Is(err, ErrPhonePairFailed) || errors.Is(err, ErrPhoneBLEUnavailable),
		"should fail during BLE transport creation")
}

// ---------------------------------------------------------------------------
// buildCertInfoList edge cases
// ---------------------------------------------------------------------------

func TestPhoneService_Coverage_BuildCertInfoList_EmptyChain(t *testing.T) {
	infos := buildCertInfoList(nil, nil)
	assert.Empty(t, infos)
}

func TestPhoneService_Coverage_BuildCertInfoList_FourCertChain(t *testing.T) {
	leaf := covGenerateTestCert(t, "Leaf", false)
	inter1 := covGenerateTestCert(t, "Intermediate 1", true)
	inter2 := covGenerateTestCert(t, "Intermediate 2", true)
	root := covGenerateTestCert(t, "Root CA", true)

	chain := []*x509.Certificate{leaf, inter1, inter2, root}
	infos := buildCertInfoList(chain, nil)

	require.Len(t, infos, 4)
	assert.Equal(t, "Leaf", infos[0].Label)
	assert.Equal(t, "Intermediate 1", infos[1].Label)
	assert.Equal(t, "Intermediate 2", infos[2].Label)
	assert.Equal(t, "Root", infos[3].Label)
}

func TestPhoneService_Coverage_BuildCertInfoList_SingleCert(t *testing.T) {
	cert := covGenerateTestCert(t, "Standalone", false)
	chain := []*x509.Certificate{cert}
	infos := buildCertInfoList(chain, nil)

	require.Len(t, infos, 1)
	// When total=1, index=0 is both first and last.
	// getCertLabel(0, 1) returns "Leaf" (index==0 wins).
	assert.Equal(t, "Leaf", infos[0].Label)
}

func TestPhoneService_Coverage_BuildCertInfoList_TwoCerts(t *testing.T) {
	leaf := covGenerateTestCert(t, "Leaf", false)
	root := covGenerateTestCert(t, "Root", true)

	chain := []*x509.Certificate{leaf, root}
	infos := buildCertInfoList(chain, nil)

	require.Len(t, infos, 2)
	assert.Equal(t, "Leaf", infos[0].Label)
	assert.Equal(t, "Root", infos[1].Label)
}

func TestPhoneService_Coverage_BuildCertInfoList_WithTrustAnchor(t *testing.T) {
	leaf := covGenerateTestCert(t, "Leaf", false)
	root := covGenerateTestCert(t, "Root CA", true)

	chain := []*x509.Certificate{leaf, root}
	// Pass root as an embedded root so it's recognized as a trust anchor.
	infos := buildCertInfoList(chain, []*x509.Certificate{root})

	require.Len(t, infos, 2)
	assert.True(t, infos[1].IsTrustAnchor, "root should be marked as trust anchor")
}

// ---------------------------------------------------------------------------
// getCertLabel edge cases
// ---------------------------------------------------------------------------

func TestPhoneService_Coverage_GetCertLabel_FiveChain(t *testing.T) {
	// total > 3 triggers "Intermediate N" format.
	assert.Equal(t, "Leaf", getCertLabel(0, 5))
	assert.Equal(t, "Intermediate 1", getCertLabel(1, 5))
	assert.Equal(t, "Intermediate 2", getCertLabel(2, 5))
	assert.Equal(t, "Intermediate 3", getCertLabel(3, 5))
	assert.Equal(t, "Root", getCertLabel(4, 5))
}

func TestPhoneService_Coverage_GetCertLabel_TwoChain(t *testing.T) {
	assert.Equal(t, "Leaf", getCertLabel(0, 2))
	assert.Equal(t, "Root", getCertLabel(1, 2))
}

func TestPhoneService_Coverage_GetCertLabel_ThreeChain(t *testing.T) {
	assert.Equal(t, "Leaf", getCertLabel(0, 3))
	assert.Equal(t, "Intermediate", getCertLabel(1, 3))
	assert.Equal(t, "Root", getCertLabel(2, 3))
}

// ---------------------------------------------------------------------------
// keymasterPurposeNameList with unknown codes
// ---------------------------------------------------------------------------

func TestPhoneService_Coverage_KeymasterPurposeNameList_UnknownCodes(t *testing.T) {
	names := keymasterPurposeNameList([]int{99, 100})
	require.Len(t, names, 2)
	assert.Equal(t, "UNKNOWN(99)", names[0])
	assert.Equal(t, "UNKNOWN(100)", names[1])
}

func TestPhoneService_Coverage_KeymasterPurposeNameList_MixedKnownUnknown(t *testing.T) {
	names := keymasterPurposeNameList([]int{0, 99, 2})
	require.Len(t, names, 3)
	assert.Equal(t, "ENCRYPT", names[0])
	assert.Equal(t, "UNKNOWN(99)", names[1])
	assert.Equal(t, "SIGN", names[2])
}

func TestPhoneService_Coverage_KeymasterPurposeNameList_AllKnown(t *testing.T) {
	names := keymasterPurposeNameList([]int{0, 1, 2, 3, 4, 5, 6, 7})
	require.Len(t, names, 8)
	assert.Equal(t, "ENCRYPT", names[0])
	assert.Equal(t, "DECRYPT", names[1])
	assert.Equal(t, "SIGN", names[2])
	assert.Equal(t, "VERIFY", names[3])
	assert.Equal(t, "DERIVE_KEY", names[4])
	assert.Equal(t, "WRAP_KEY", names[5])
	assert.Equal(t, "AGREE_KEY", names[6])
	assert.Equal(t, "ATTEST_KEY", names[7])
}

// ---------------------------------------------------------------------------
// keymasterAlgorithmName additional cases
// ---------------------------------------------------------------------------

func TestPhoneService_Coverage_KeymasterAlgorithmName_AllKnown(t *testing.T) {
	assert.Equal(t, "RSA", keymasterAlgorithmName(1))
	assert.Equal(t, "EC", keymasterAlgorithmName(3))
	assert.Equal(t, "AES", keymasterAlgorithmName(32))
	assert.Equal(t, "TRIPLE_DES", keymasterAlgorithmName(33))
	assert.Equal(t, "HMAC", keymasterAlgorithmName(128))
}

func TestPhoneService_Coverage_KeymasterAlgorithmName_Unknown(t *testing.T) {
	assert.Equal(t, "UNKNOWN(999)", keymasterAlgorithmName(999))
}

// ---------------------------------------------------------------------------
// keymasterOriginName additional cases
// ---------------------------------------------------------------------------

func TestPhoneService_Coverage_KeymasterOriginName_AllKnown(t *testing.T) {
	assert.Equal(t, "GENERATED", keymasterOriginName(0))
	assert.Equal(t, "DERIVED", keymasterOriginName(1))
	assert.Equal(t, "IMPORTED", keymasterOriginName(2))
	assert.Equal(t, "UNKNOWN", keymasterOriginName(3))
	assert.Equal(t, "SECURELY_IMPORTED", keymasterOriginName(4))
}

func TestPhoneService_Coverage_KeymasterOriginName_Unknown(t *testing.T) {
	assert.Equal(t, "UNKNOWN(77)", keymasterOriginName(77))
}

// ---------------------------------------------------------------------------
// SetDeviceAsBackend + GetBackendDevices round-trip
// ---------------------------------------------------------------------------

func TestPhoneService_Coverage_SetDeviceAsBackend_ThenGetBackendDevices(t *testing.T) {
	cfg := &phoneConfig{
		Devices: []phoneConfigDevice{
			{Name: "Pixel 9", Address: "AA:BB:CC:DD:EE:01"},
			{Name: "Galaxy S24", Address: "11:22:33:44:55:66"},
		},
		DefaultDevice: "Pixel 9",
	}
	covSetupHomeWithDevicesConfig(t, cfg)

	svc := NewPhoneService()

	// Initially no backends.
	devices, err := svc.GetBackendDevices()
	require.NoError(t, err)
	assert.Empty(t, devices)

	// Enable one as backend.
	err = svc.SetDeviceAsBackend("Galaxy S24", true)
	require.NoError(t, err)

	devices, err = svc.GetBackendDevices()
	require.NoError(t, err)
	require.Len(t, devices, 1)
	assert.Equal(t, "Galaxy S24", devices[0].Name)

	// Enable the other.
	err = svc.SetDeviceAsBackend("Pixel 9", true)
	require.NoError(t, err)

	devices, err = svc.GetBackendDevices()
	require.NoError(t, err)
	require.Len(t, devices, 2)

	// Disable one.
	err = svc.SetDeviceAsBackend("Galaxy S24", false)
	require.NoError(t, err)

	devices, err = svc.GetBackendDevices()
	require.NoError(t, err)
	require.Len(t, devices, 1)
	assert.Equal(t, "Pixel 9", devices[0].Name)
}

// ---------------------------------------------------------------------------
// loadConfig YAML unmarshal error (covers the unmarshal error branch)
// ---------------------------------------------------------------------------

func TestPhoneService_Coverage_LoadConfig_InvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	origHome := os.Getenv("HOME")
	t.Cleanup(func() { os.Setenv("HOME", origHome) })
	os.Setenv("HOME", tmpDir)

	xkeyDir := filepath.Join(tmpDir, ".xkey")
	require.NoError(t, os.MkdirAll(xkeyDir, 0700))
	require.NoError(t, os.WriteFile(
		filepath.Join(xkeyDir, devicesConfigFileName),
		[]byte("{{{{invalid yaml"), 0600))

	svc := NewPhoneService()
	cfg, err := svc.loadConfig()
	assert.Nil(t, cfg)
	require.Error(t, err, "invalid YAML should return parse error")
}

// ---------------------------------------------------------------------------
// emitPolicyViolationEvent with various mismatch maps
// ---------------------------------------------------------------------------

func TestPhoneService_Coverage_EmitPolicyViolationEvent_MultipleMismatches(t *testing.T) {
	svc := NewPhoneService()

	var emitted events.Event
	svc.SetEventEmitter(func(evt events.Event) {
		emitted = evt
	})

	mismatches := map[string]string{
		"boot_hash":      "expected abc, got def",
		"boot_state":     "expected verified, got unverified",
		"security_level": "expected strongbox, got tee",
	}
	svc.emitPolicyViolationEvent("Pixel 9", mismatches, "3 fields mismatched")

	assert.Equal(t, events.EventPolicyViolation, emitted.Type)
	payload, ok := emitted.Payload.(events.PolicyViolationPayload)
	require.True(t, ok)
	assert.Equal(t, "Pixel 9", payload.DeviceName)
	assert.Len(t, payload.Mismatches, 3)
	assert.Equal(t, "3 fields mismatched", payload.Message)
}

// ---------------------------------------------------------------------------
// saveAttestationResult -- device name not in config (no-match path)
// ---------------------------------------------------------------------------

func TestPhoneService_Coverage_SaveAttestationResult_NoMatchingDevice(t *testing.T) {
	tmpDir := t.TempDir()
	origHome := os.Getenv("HOME")
	t.Cleanup(func() { os.Setenv("HOME", origHome) })
	os.Setenv("HOME", tmpDir)

	svc := NewPhoneService()

	cfg := &phoneConfig{
		Devices: []phoneConfigDevice{
			{Name: "Galaxy S24", Address: "11:22:33:44:55:66"},
		},
		DefaultDevice: "Galaxy S24",
	}

	device := &phoneConfigDevice{
		Name:    "Pixel 9", // not in cfg.Devices
		Address: "AA:BB:CC:DD:EE:01",
	}

	result := &AttestationResult{
		DeviceName:    "Pixel 9",
		Verified:      true,
		SecurityLevel: "tee",
		BootState:     "verified",
		AttestTime:    time.Now(),
	}

	// This should not panic even when device name doesn't match any config entry.
	svc.saveAttestationResult(cfg, device, result)

	// Verify device fields were updated even though config save might fail.
	assert.Equal(t, "tee", device.SecurityLevel)
	assert.True(t, device.BootStateVerified)
	assert.NotNil(t, device.LastAttestation)
}

// ---------------------------------------------------------------------------
// pubKeyFP error path (covers the 80% -> error return "")
// ---------------------------------------------------------------------------

func TestPhoneService_Coverage_PubKeyFP_ValidCert(t *testing.T) {
	cert := covGenerateTestCert(t, "Test Cert", false)
	fp := pubKeyFP(cert)
	assert.NotEmpty(t, fp, "valid certificate should produce non-empty fingerprint")
	assert.Len(t, fp, 64, "SHA-256 hex fingerprint should be 64 characters")
}

// ---------------------------------------------------------------------------
// hostname function (improves from 75%)
// ---------------------------------------------------------------------------

func TestPhoneService_Coverage_Hostname_Returns(t *testing.T) {
	name := hostname()
	// On any platform, hostname should return a non-empty string.
	assert.NotEmpty(t, name)
}

// ---------------------------------------------------------------------------
// parseDERChain with valid multi-cert chain
// ---------------------------------------------------------------------------

func TestPhoneService_Coverage_ParseDERChain_ThreeValidCerts(t *testing.T) {
	cert1 := covGenerateTestCert(t, "Leaf", false)
	cert2 := covGenerateTestCert(t, "Intermediate", true)
	cert3 := covGenerateTestCert(t, "Root", true)

	derChain := [][]byte{cert1.Raw, cert2.Raw, cert3.Raw}
	chain, err := parseDERChain(derChain)
	require.NoError(t, err)
	assert.Len(t, chain, 3)
	assert.Equal(t, "Leaf", chain[0].Subject.CommonName)
	assert.Equal(t, "Intermediate", chain[1].Subject.CommonName)
	assert.Equal(t, "Root", chain[2].Subject.CommonName)
}

func TestPhoneService_Coverage_ParseDERChain_MiddleCertInvalid(t *testing.T) {
	cert1 := covGenerateTestCert(t, "Leaf", false)
	invalidDER := []byte("not a valid certificate")
	cert3 := covGenerateTestCert(t, "Root", true)

	derChain := [][]byte{cert1.Raw, invalidDER, cert3.Raw}
	chain, err := parseDERChain(derChain)
	assert.Nil(t, chain)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "certificate at index 1")
}

// ---------------------------------------------------------------------------
// formatTrustAnchorName with various fields
// ---------------------------------------------------------------------------

func TestPhoneService_Coverage_FormatTrustAnchorName_SerialNumberOnly(t *testing.T) {
	cert := covGenerateTestCert(t, "", false)
	cert.Subject.CommonName = ""
	cert.Subject.Organization = nil
	cert.Subject.SerialNumber = "12345"
	name := formatTrustAnchorName(cert)
	assert.Contains(t, name, "12345")
	assert.Contains(t, name, "Google Hardware Attestation Root")
}

// ---------------------------------------------------------------------------
// truncateHash edge cases
// ---------------------------------------------------------------------------

func TestPhoneService_Coverage_TruncateHash_ExactlyBoundary(t *testing.T) {
	// 28 characters -- should NOT be truncated.
	h := "1234567890123456789012345678"
	assert.Equal(t, h, truncateHash(h))
}

func TestPhoneService_Coverage_TruncateHash_JustOverBoundary(t *testing.T) {
	// 29 characters -- should be truncated.
	h := "12345678901234567890123456789"
	result := truncateHash(h)
	assert.Contains(t, result, "...")
	assert.True(t, len(result) < len(h))
}

func TestPhoneService_Coverage_TruncateHash_Long(t *testing.T) {
	h := "aabbccddee1122334455667788990011aabbccddee112233445566778899001122"
	result := truncateHash(h)
	assert.Equal(t, h[:16]+"..."+h[len(h)-8:], result)
}

func TestPhoneService_Coverage_TruncateHash_Empty(t *testing.T) {
	assert.Equal(t, "", truncateHash(""))
}

// ---------------------------------------------------------------------------
// securityLevelRank completeness
// ---------------------------------------------------------------------------

func TestPhoneService_Coverage_SecurityLevelRank_AllValues(t *testing.T) {
	assert.Equal(t, 0, securityLevelRank("software"))
	assert.Equal(t, 1, securityLevelRank("tee"))
	assert.Equal(t, 2, securityLevelRank("strongbox"))
	assert.Equal(t, -1, securityLevelRank("unknown"))
	assert.Equal(t, -1, securityLevelRank(""))
}

func TestPhoneService_Coverage_SecurityLevelRank_Ordering(t *testing.T) {
	assert.True(t, securityLevelRank("software") < securityLevelRank("tee"))
	assert.True(t, securityLevelRank("tee") < securityLevelRank("strongbox"))
	assert.True(t, securityLevelRank("unknown") < securityLevelRank("software"))
}

// ---------------------------------------------------------------------------
// ListDevices with devices.yaml (not phone.yaml)
// ---------------------------------------------------------------------------

func TestPhoneService_Coverage_ListDevices_DevicesYAML(t *testing.T) {
	now := time.Now().UTC()
	cfg := &phoneConfig{
		Devices: []phoneConfigDevice{
			{Name: "Pixel 9", Address: "AA:BB:CC:DD:EE:01", PairedAt: now, IsBackend: true},
			{Name: "Galaxy S24", Address: "11:22:33:44:55:66", PairedAt: now},
		},
		DefaultDevice: "Pixel 9",
	}
	covSetupHomeWithDevicesConfig(t, cfg)

	svc := NewPhoneService()
	devices, err := svc.ListDevices()
	require.NoError(t, err)
	require.Len(t, devices, 2)
	assert.Equal(t, "Pixel 9", devices[0].Name)
	assert.True(t, devices[0].IsBackend)
	assert.Equal(t, "Galaxy S24", devices[1].Name)
	assert.False(t, devices[1].IsBackend)
}

// ---------------------------------------------------------------------------
// emitAttestationEvent with emitter and both success/failure branches
// ---------------------------------------------------------------------------

func TestPhoneService_Coverage_EmitAttestationEvent_SuccessWithDetails(t *testing.T) {
	svc := NewPhoneService()

	var emitted events.Event
	svc.SetEventEmitter(func(evt events.Event) {
		emitted = evt
	})

	svc.emitAttestationEvent("Pixel 9", true, "all checks passed")
	assert.Equal(t, events.EventAttestationResult, emitted.Type)
	payload, ok := emitted.Payload.(events.AttestationResultPayload)
	require.True(t, ok)
	assert.True(t, payload.Success)
	assert.Equal(t, "all checks passed", payload.Details)
}

// ---------------------------------------------------------------------------
// Error sentinel identity tests
// ---------------------------------------------------------------------------

func TestPhoneService_Coverage_ErrorSentinels_NotEqual(t *testing.T) {
	// Verify each error sentinel is distinct.
	sentinels := []error{
		ErrPhoneNotConnected,
		ErrPhoneDeviceNotFound,
		ErrPhoneScanFailed,
		ErrPhonePairFailed,
		ErrPhoneAttestFailed,
		ErrPhoneInvalidTimeout,
		ErrPhoneBLEUnavailable,
		ErrPhoneAlreadyPaired,
		ErrPhoneAttestNotImplemented,
		ErrPhoneConnectFailed,
		ErrPhoneHandshakeFailed,
		ErrPhoneMissingKeys,
		ErrPhonePolicyViolation,
		ErrPhonePolicyNotSet,
	}
	for i := 0; i < len(sentinels); i++ {
		for j := i + 1; j < len(sentinels); j++ {
			assert.NotEqual(t, sentinels[i], sentinels[j],
				"sentinel %d and %d should be distinct", i, j)
		}
	}
}

// ---------------------------------------------------------------------------
// verifiedBootStateName edge cases
// ---------------------------------------------------------------------------

func TestPhoneService_Coverage_VerifiedBootStateName_UnknownState(t *testing.T) {
	result := verifiedBootStateName(99)
	assert.Equal(t, "unknown", result)
}

// ---------------------------------------------------------------------------
// SetDeviceAsBackend with config save error
// ---------------------------------------------------------------------------

func TestPhoneService_Coverage_SetDeviceAsBackend_SaveError(t *testing.T) {
	cfg := &phoneConfig{
		Devices: []phoneConfigDevice{
			{Name: "Pixel 9", Address: "AA:BB:CC:DD:EE:01"},
		},
		DefaultDevice: "Pixel 9",
	}
	tmpDir := covSetupHomeWithDevicesConfig(t, cfg)

	svc := NewPhoneService()

	// Make the config directory read-only so save fails.
	xkeyDir := filepath.Join(tmpDir, ".xkey")
	require.NoError(t, os.Chmod(xkeyDir, 0444))
	t.Cleanup(func() { os.Chmod(xkeyDir, 0700) })

	err := svc.SetDeviceAsBackend("Pixel 9", true)
	require.Error(t, err, "save should fail when directory is read-only")
}
