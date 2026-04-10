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
	"crypto/rsa"
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
)

// p5cSetupHomeWithConfig creates a temp HOME dir, writes a phone.yaml config,
// sets HOME env var, and returns a cleanup function.
func p5cSetupHomeWithConfig(t *testing.T, cfg *phoneConfig) string {
	t.Helper()
	tmpDir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, ".xkey"), 0700))
	data, err := yaml.Marshal(cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, ".xkey", "phone.yaml"), data, 0600))
	origHome := os.Getenv("HOME")
	t.Cleanup(func() { os.Setenv("HOME", origHome) })
	os.Setenv("HOME", tmpDir)
	return tmpDir
}

// p5cGenerateTestCert generates a self-signed ECDSA P-256 test certificate.
func p5cGenerateTestCert(t *testing.T, cn string, isCA bool) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			Organization: []string{"P5C Test Org"},
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

// p5cGenerateRSATestCert generates a self-signed RSA test certificate.
func p5cGenerateRSATestCert(t *testing.T, cn string, isCA bool) *x509.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			Organization: []string{"P5C RSA Test Org"},
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

// ===========================================================================
// ListDevices: YAML parse error fallback path
// ===========================================================================

// TestP5C_ListDevices_InvalidYAML verifies that ListDevices returns an empty
// list (not an error) when the config file contains invalid YAML. This covers
// the s.log.Warn path at line 257.
func TestP5C_ListDevices_InvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, ".xkey"), 0700))
	// Write invalid YAML content.
	require.NoError(t, os.WriteFile(
		filepath.Join(tmpDir, ".xkey", "phone.yaml"),
		[]byte("{{{{invalid yaml content!!!"),
		0600,
	))
	origHome := os.Getenv("HOME")
	defer os.Setenv("HOME", origHome)
	os.Setenv("HOME", tmpDir)

	svc := NewPhoneService()
	devices, err := svc.ListDevices()
	require.NoError(t, err)
	assert.Empty(t, devices)
}

// TestP5C_ListDevices_ConnectedDeviceMarked verifies that ListDevices correctly
// marks the connected device in the list while other devices are not marked.
func TestP5C_ListDevices_ConnectedDeviceMarked(t *testing.T) {
	now := time.Now().UTC()
	cfg := &phoneConfig{
		Devices: []phoneConfigDevice{
			{Name: "Device A", Address: "AA:AA:AA:AA:AA:AA", PairedAt: now},
			{Name: "Device B", Address: "BB:BB:BB:BB:BB:BB", PairedAt: now},
			{Name: "Device C", Address: "CC:CC:CC:CC:CC:CC", PairedAt: now},
		},
		DefaultDevice: "Device A",
	}
	p5cSetupHomeWithConfig(t, cfg)

	svc := NewPhoneService()
	svc.connState.deviceName.Store("Device B")
	svc.connState.connected.Store(true)

	devices, err := svc.ListDevices()
	require.NoError(t, err)
	require.Len(t, devices, 3)

	for _, d := range devices {
		if d.Name == "Device B" {
			assert.True(t, d.Connected)
		} else {
			assert.False(t, d.Connected, "device %s should not be connected", d.Name)
		}
	}
}

// ===========================================================================
// loadConfig: YAML unmarshal error path
// ===========================================================================

// TestP5C_LoadConfig_InvalidYAMLReturnsError verifies that loadConfig returns
// an error when the config file contains invalid YAML.
func TestP5C_LoadConfig_InvalidYAMLReturnsError(t *testing.T) {
	tmpDir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, ".xkey"), 0700))
	require.NoError(t, os.WriteFile(
		filepath.Join(tmpDir, ".xkey", "phone.yaml"),
		[]byte("\t\ttabs: [are: {invalid: yaml: ["),
		0600,
	))
	origHome := os.Getenv("HOME")
	defer os.Setenv("HOME", origHome)
	os.Setenv("HOME", tmpDir)

	svc := NewPhoneService()
	_, err := svc.loadConfig()
	assert.Error(t, err)
}

// ===========================================================================
// Connect: device fingerprint hex decode error path
// ===========================================================================

// TestP5C_Connect_InvalidDeviceFingerprint verifies that Connect handles an
// invalid hex device fingerprint gracefully by clearing expectedFingerprint
// to nil and proceeding (though it will fail at BLE transport creation).
func TestP5C_Connect_InvalidDeviceFingerprint(t *testing.T) {
	cfg := &phoneConfig{
		Devices: []phoneConfigDevice{
			{
				Name:                 "Test Phone",
				Address:              "AA:BB:CC:DD:EE:FF",
				NoisePublicKey:       base64.StdEncoding.EncodeToString(make([]byte, 32)),
				LocalNoisePrivateKey: base64.StdEncoding.EncodeToString(make([]byte, 32)),
				DeviceFingerprint:    "not-valid-hex-zzzz!!",
				PairedAt:             time.Now().UTC(),
			},
		},
		DefaultDevice: "Test Phone",
	}
	p5cSetupHomeWithConfig(t, cfg)

	svc := NewPhoneService()
	// Connect will parse the invalid fingerprint (log warning, set nil),
	// then fail at BLE transport creation since we have no hardware.
	err := svc.Connect("Test Phone")
	require.Error(t, err)
	// It should get past the fingerprint check and fail at LoadStaticKey or BLE.
	assert.True(t,
		errors.Is(err, ErrPhoneMissingKeys) ||
			errors.Is(err, ErrPhoneConnectFailed) ||
			errors.Is(err, ErrPhoneBLEUnavailable),
		"expected a connect-phase error, got: %v", err)
}

// ===========================================================================
// Connect: invalid base64 local private key
// ===========================================================================

// TestP5C_Connect_InvalidBase64LocalKey verifies that Connect returns
// ErrPhoneMissingKeys when the local noise private key is not valid base64.
func TestP5C_Connect_InvalidBase64LocalKey(t *testing.T) {
	cfg := &phoneConfig{
		Devices: []phoneConfigDevice{
			{
				Name:                 "Test Phone",
				Address:              "AA:BB:CC:DD:EE:FF",
				NoisePublicKey:       base64.StdEncoding.EncodeToString(make([]byte, 32)),
				LocalNoisePrivateKey: "!not-valid-base64!",
				PairedAt:             time.Now().UTC(),
			},
		},
		DefaultDevice: "Test Phone",
	}
	p5cSetupHomeWithConfig(t, cfg)

	svc := NewPhoneService()
	err := svc.Connect("Test Phone")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPhoneMissingKeys)
}

// TestP5C_Connect_InvalidBase64RemoteKey verifies that Connect returns
// ErrPhoneMissingKeys when the remote noise public key is not valid base64.
func TestP5C_Connect_InvalidBase64RemoteKey(t *testing.T) {
	cfg := &phoneConfig{
		Devices: []phoneConfigDevice{
			{
				Name:                 "Test Phone",
				Address:              "AA:BB:CC:DD:EE:FF",
				NoisePublicKey:       "!not-valid-base64!",
				LocalNoisePrivateKey: base64.StdEncoding.EncodeToString(make([]byte, 32)),
				PairedAt:             time.Now().UTC(),
			},
		},
		DefaultDevice: "Test Phone",
	}
	p5cSetupHomeWithConfig(t, cfg)

	svc := NewPhoneService()
	err := svc.Connect("Test Phone")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPhoneMissingKeys)
}

// ===========================================================================
// Connect: empty noise keys
// ===========================================================================

// TestP5C_Connect_EmptyLocalKey verifies Connect returns ErrPhoneMissingKeys
// when LocalNoisePrivateKey is empty string.
func TestP5C_Connect_EmptyLocalKey(t *testing.T) {
	cfg := &phoneConfig{
		Devices: []phoneConfigDevice{
			{
				Name:                 "Test Phone",
				Address:              "AA:BB:CC:DD:EE:FF",
				NoisePublicKey:       base64.StdEncoding.EncodeToString(make([]byte, 32)),
				LocalNoisePrivateKey: "",
				PairedAt:             time.Now().UTC(),
			},
		},
		DefaultDevice: "Test Phone",
	}
	p5cSetupHomeWithConfig(t, cfg)

	svc := NewPhoneService()
	err := svc.Connect("Test Phone")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPhoneMissingKeys)
}

// TestP5C_Connect_EmptyRemoteKey verifies Connect returns ErrPhoneMissingKeys
// when NoisePublicKey is empty string.
func TestP5C_Connect_EmptyRemoteKey(t *testing.T) {
	cfg := &phoneConfig{
		Devices: []phoneConfigDevice{
			{
				Name:                 "Test Phone",
				Address:              "AA:BB:CC:DD:EE:FF",
				NoisePublicKey:       "",
				LocalNoisePrivateKey: base64.StdEncoding.EncodeToString(make([]byte, 32)),
				PairedAt:             time.Now().UTC(),
			},
		},
		DefaultDevice: "Test Phone",
	}
	p5cSetupHomeWithConfig(t, cfg)

	svc := NewPhoneService()
	err := svc.Connect("Test Phone")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPhoneMissingKeys)
}

// ===========================================================================
// Connect: no config file
// ===========================================================================

// TestP5C_Connect_NoConfigFile verifies that Connect returns
// ErrPhoneDeviceNotFound when no config file exists.
func TestP5C_Connect_NoConfigFile(t *testing.T) {
	tmpDir := t.TempDir()
	origHome := os.Getenv("HOME")
	defer os.Setenv("HOME", origHome)
	os.Setenv("HOME", tmpDir)

	svc := NewPhoneService()
	err := svc.Connect("NonExistent")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPhoneDeviceNotFound)
}

// TestP5C_Connect_DeviceNotInConfig verifies that Connect returns
// ErrPhoneDeviceNotFound when the device name is not in the config.
func TestP5C_Connect_DeviceNotInConfig(t *testing.T) {
	cfg := &phoneConfig{
		Devices: []phoneConfigDevice{
			{Name: "Other Device", Address: "11:22:33:44:55:66"},
		},
		DefaultDevice: "Other Device",
	}
	p5cSetupHomeWithConfig(t, cfg)

	svc := NewPhoneService()
	err := svc.Connect("Missing Device")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPhoneDeviceNotFound)
}

// ===========================================================================
// Disconnect: event emission and state clearing
// ===========================================================================

// TestP5C_Disconnect_EmitsDisconnectEvent verifies that Disconnect emits a
// disconnect event with the correct device name and reason.
func TestP5C_Disconnect_EmitsDisconnectEvent(t *testing.T) {
	svc := NewPhoneService()
	svc.connState.deviceName.Store("MyPixel")
	svc.connState.connected.Store(true)

	var emittedEvents []events.Event
	svc.SetEventEmitter(func(evt events.Event) {
		emittedEvents = append(emittedEvents, evt)
	})

	var statusCalled bool
	var statusConnected bool
	var statusName string
	svc.SetStatusChangeFunc(func(connected bool, name string) {
		statusCalled = true
		statusConnected = connected
		statusName = name
	})

	err := svc.Disconnect("MyPixel")
	require.NoError(t, err)

	assert.False(t, svc.IsConnected())
	assert.Empty(t, svc.ConnectedDeviceName())

	require.Len(t, emittedEvents, 1)
	assert.Equal(t, events.EventPhoneDisconnected, emittedEvents[0].Type)
	payload, ok := emittedEvents[0].Payload.(events.PhoneDisconnectedPayload)
	require.True(t, ok)
	assert.Equal(t, "MyPixel", payload.DeviceName)
	assert.Equal(t, "user_requested", payload.Reason)

	assert.True(t, statusCalled)
	assert.False(t, statusConnected)
	assert.Empty(t, statusName)
}

// ===========================================================================
// AttestDevice: config load error path
// ===========================================================================

// TestP5C_AttestDevice_ConfigLoadError verifies that AttestDevice returns
// ErrPhoneAttestFailed when the config file cannot be loaded.
func TestP5C_AttestDevice_ConfigLoadError(t *testing.T) {
	tmpDir := t.TempDir()
	origHome := os.Getenv("HOME")
	defer os.Setenv("HOME", origHome)
	os.Setenv("HOME", tmpDir)
	// No config file exists.

	svc := NewPhoneService()
	svc.connState.deviceName.Store("Pixel 9")
	svc.connState.connected.Store(true)

	result, err := svc.AttestDevice("Pixel 9")
	assert.Nil(t, result)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPhoneAttestFailed)
}

// TestP5C_AttestDevice_DeviceNotInConfig verifies that AttestDevice returns
// ErrPhoneDeviceNotFound when the connected device is not in the config.
func TestP5C_AttestDevice_DeviceNotInConfig(t *testing.T) {
	cfg := &phoneConfig{
		Devices: []phoneConfigDevice{
			{Name: "Other Phone", Address: "11:22:33:44:55:66"},
		},
		DefaultDevice: "Other Phone",
	}
	p5cSetupHomeWithConfig(t, cfg)

	svc := NewPhoneService()
	svc.connState.deviceName.Store("Pixel 9")
	svc.connState.connected.Store(true)

	result, err := svc.AttestDevice("Pixel 9")
	assert.Nil(t, result)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPhoneDeviceNotFound)
}

// TestP5C_AttestDevice_AttestFailReturnsResultWithError verifies that when
// performAttestation fails, AttestDevice returns a result with error message
// and emits a failure event.
func TestP5C_AttestDevice_AttestFailReturnsResultWithError(t *testing.T) {
	cfg := &phoneConfig{
		Devices: []phoneConfigDevice{
			{Name: "Pixel 9", Address: "AA:BB:CC:DD:EE:FF"},
		},
		DefaultDevice: "Pixel 9",
	}
	p5cSetupHomeWithConfig(t, cfg)

	svc := NewPhoneService()
	svc.connState.deviceName.Store("Pixel 9")
	svc.connState.connected.Store(true)
	// No activeTransport/activeSession -> performAttestation returns ErrPhoneNotConnected.

	var emitted events.Event
	svc.SetEventEmitter(func(evt events.Event) {
		emitted = evt
	})

	result, err := svc.AttestDevice("Pixel 9")
	require.NoError(t, err, "AttestDevice should return nil error with result containing error message")
	require.NotNil(t, result)
	assert.False(t, result.Verified)
	assert.Equal(t, "Pixel 9", result.DeviceName)
	assert.NotEmpty(t, result.ErrorMessage)
	assert.Contains(t, result.ErrorMessage, "no device connected")

	assert.Equal(t, events.EventAttestationResult, emitted.Type)
	payload, ok := emitted.Payload.(events.AttestationResultPayload)
	require.True(t, ok)
	assert.False(t, payload.Success)
	assert.NotEmpty(t, payload.Details)
}

// ===========================================================================
// saveAttestationResult: BootState != "verified"
// ===========================================================================

// TestP5C_SaveAttestationResult_BootStateNotVerified verifies that
// saveAttestationResult sets BootStateVerified to false when the boot
// state is not "verified".
func TestP5C_SaveAttestationResult_BootStateNotVerified(t *testing.T) {
	cfg := &phoneConfig{
		Devices: []phoneConfigDevice{
			{Name: "Pixel 9", Address: "AA:BB:CC:DD:EE:FF", PairedAt: time.Now().UTC()},
		},
		DefaultDevice: "Pixel 9",
	}
	p5cSetupHomeWithConfig(t, cfg)

	svc := NewPhoneService()
	device := &cfg.Devices[0]
	result := &AttestationResult{
		DeviceName:    "Pixel 9",
		Verified:      true,
		SecurityLevel: "tee",
		BootState:     "self-signed",
		BootHash:      "aabb",
		BootKeyHash:   "ccdd",
		DeviceLocked:  false,
		AttestTime:    time.Now(),
	}

	svc.saveAttestationResult(cfg, device, result)

	loaded, err := svc.loadConfig()
	require.NoError(t, err)
	require.Len(t, loaded.Devices, 1)
	assert.False(t, loaded.Devices[0].BootStateVerified)
	require.NotNil(t, loaded.Devices[0].LastAttestation)
	assert.Equal(t, "self-signed", loaded.Devices[0].LastAttestation.BootState)
	assert.False(t, loaded.Devices[0].LastAttestation.DeviceLocked)
}

// TestP5C_SaveAttestationResult_SaveConfigError verifies that
// saveAttestationResult logs a warning (does not panic) when the
// config file cannot be written.
func TestP5C_SaveAttestationResult_SaveConfigError(t *testing.T) {
	tmpDir := t.TempDir()
	xkeyDir := filepath.Join(tmpDir, ".xkey")
	require.NoError(t, os.MkdirAll(xkeyDir, 0700))
	cfg := &phoneConfig{
		Devices: []phoneConfigDevice{
			{Name: "Pixel 9", Address: "AA:BB:CC:DD:EE:FF", PairedAt: time.Now().UTC()},
		},
		DefaultDevice: "Pixel 9",
	}
	data, err := yaml.Marshal(cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(xkeyDir, "phone.yaml"), data, 0600))
	// Make the file read-only so saving fails.
	require.NoError(t, os.Chmod(filepath.Join(xkeyDir, "phone.yaml"), 0400))
	t.Cleanup(func() {
		os.Chmod(filepath.Join(xkeyDir, "phone.yaml"), 0600)
	})

	origHome := os.Getenv("HOME")
	defer os.Setenv("HOME", origHome)
	os.Setenv("HOME", tmpDir)

	svc := NewPhoneService()
	device := &cfg.Devices[0]
	result := &AttestationResult{
		DeviceName: "Pixel 9",
		Verified:   true,
		AttestTime: time.Now(),
	}

	// Should not panic even though save fails.
	svc.saveAttestationResult(cfg, device, result)
}

// ===========================================================================
// Unpair: last device removal clears default to empty
// ===========================================================================

// TestP5C_Unpair_LastDeviceClearsDefault verifies that when the last device is
// unpaired, the default device is set to empty string.
func TestP5C_Unpair_LastDeviceClearsDefault(t *testing.T) {
	cfg := &phoneConfig{
		Devices: []phoneConfigDevice{
			{Name: "OnlyDevice", Address: "AA:BB:CC:DD:EE:FF", PairedAt: time.Now().UTC()},
		},
		DefaultDevice: "OnlyDevice",
	}
	p5cSetupHomeWithConfig(t, cfg)

	svc := NewPhoneService()
	err := svc.Unpair("OnlyDevice")
	require.NoError(t, err)

	loaded, err := svc.loadConfig()
	require.NoError(t, err)
	assert.Empty(t, loaded.Devices)
	assert.Empty(t, loaded.DefaultDevice)
}

// TestP5C_Unpair_NonDefaultDevice verifies that unpairing a device that is
// not the default does not change the default device.
func TestP5C_Unpair_NonDefaultDevice(t *testing.T) {
	cfg := &phoneConfig{
		Devices: []phoneConfigDevice{
			{Name: "Default Phone", Address: "AA:AA:AA:AA:AA:AA", PairedAt: time.Now().UTC()},
			{Name: "Other Phone", Address: "BB:BB:BB:BB:BB:BB", PairedAt: time.Now().UTC()},
		},
		DefaultDevice: "Default Phone",
	}
	p5cSetupHomeWithConfig(t, cfg)

	svc := NewPhoneService()
	err := svc.Unpair("Other Phone")
	require.NoError(t, err)

	loaded, err := svc.loadConfig()
	require.NoError(t, err)
	assert.Len(t, loaded.Devices, 1)
	assert.Equal(t, "Default Phone", loaded.DefaultDevice)
}

// TestP5C_Unpair_DefaultDeviceFallsToNext verifies that unpairing the default
// device sets the default to the first remaining device.
func TestP5C_Unpair_DefaultDeviceFallsToNext(t *testing.T) {
	cfg := &phoneConfig{
		Devices: []phoneConfigDevice{
			{Name: "Default Phone", Address: "AA:AA:AA:AA:AA:AA", PairedAt: time.Now().UTC()},
			{Name: "Backup Phone", Address: "BB:BB:BB:BB:BB:BB", PairedAt: time.Now().UTC()},
			{Name: "Third Phone", Address: "CC:CC:CC:CC:CC:CC", PairedAt: time.Now().UTC()},
		},
		DefaultDevice: "Default Phone",
	}
	p5cSetupHomeWithConfig(t, cfg)

	svc := NewPhoneService()
	err := svc.Unpair("Default Phone")
	require.NoError(t, err)

	loaded, err := svc.loadConfig()
	require.NoError(t, err)
	assert.Len(t, loaded.Devices, 2)
	assert.Equal(t, "Backup Phone", loaded.DefaultDevice)
}

// ===========================================================================
// Unpair: connected device triggers disconnect
// ===========================================================================

// TestP5C_Unpair_ConnectedDeviceEmitsDisconnect verifies that when unparing a
// currently connected device, a disconnect event is emitted with the
// "unpaired" reason.
func TestP5C_Unpair_ConnectedDeviceEmitsDisconnect(t *testing.T) {
	cfg := &phoneConfig{
		Devices: []phoneConfigDevice{
			{Name: "Connected Phone", Address: "AA:BB:CC:DD:EE:FF", PairedAt: time.Now().UTC()},
		},
		DefaultDevice: "Connected Phone",
	}
	p5cSetupHomeWithConfig(t, cfg)

	svc := NewPhoneService()
	svc.connState.deviceName.Store("Connected Phone")
	svc.connState.connected.Store(true)

	var emittedEvents []events.Event
	svc.SetEventEmitter(func(evt events.Event) {
		emittedEvents = append(emittedEvents, evt)
	})

	err := svc.Unpair("Connected Phone")
	require.NoError(t, err)

	assert.False(t, svc.IsConnected())
	assert.Empty(t, svc.ConnectedDeviceName())

	foundDisconnect := false
	for _, evt := range emittedEvents {
		if evt.Type == events.EventPhoneDisconnected {
			foundDisconnect = true
			payload, ok := evt.Payload.(events.PhoneDisconnectedPayload)
			require.True(t, ok)
			assert.Equal(t, "Connected Phone", payload.DeviceName)
			assert.Equal(t, "unpaired", payload.Reason)
		}
	}
	assert.True(t, foundDisconnect, "expected disconnect event with 'unpaired' reason")
}

// ===========================================================================
// enforceAttestationPolicy: field comparison paths
// ===========================================================================

// TestP5C_EnforceAttestationPolicy_AttestationFailed verifies that
// enforceAttestationPolicy returns ErrPhonePolicyViolation wrapping
// "attestation failed" when there is no active BLE connection.
func TestP5C_EnforceAttestationPolicy_AttestationFailed(t *testing.T) {
	svc := NewPhoneService()

	var emitted events.Event
	svc.SetEventEmitter(func(evt events.Event) {
		emitted = evt
	})

	device := &phoneConfigDevice{
		Name:    "Pixel 9",
		Address: "AA:BB:CC:DD:EE:FF",
		AttestationPolicy: &attestationPolicy{
			Enabled:       true,
			BootHash:      "abc123",
			BootState:     "verified",
			SecurityLevel: "tee",
		},
	}

	err := svc.enforceAttestationPolicy("Pixel 9", device)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPhonePolicyViolation)
	assert.Contains(t, err.Error(), "attestation failed")

	assert.Equal(t, events.EventPolicyViolation, emitted.Type)
	payload, ok := emitted.Payload.(events.PolicyViolationPayload)
	require.True(t, ok)
	assert.Equal(t, "Pixel 9", payload.DeviceName)
	assert.Contains(t, payload.Mismatches["attestation"], "attestation failed")
}

// TestP5C_EnforceAttestationPolicy_NilEmitter verifies that
// enforceAttestationPolicy does not panic when the event emitter is nil.
func TestP5C_EnforceAttestationPolicy_NilEmitter(t *testing.T) {
	svc := NewPhoneService()

	device := &phoneConfigDevice{
		Name:    "Test Phone",
		Address: "AA:BB:CC:DD:EE:FF",
		AttestationPolicy: &attestationPolicy{
			Enabled: true,
		},
	}

	err := svc.enforceAttestationPolicy("Test Phone", device)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPhonePolicyViolation)
}

// ===========================================================================
// autoAttest: all three branches
// ===========================================================================

// TestP5C_AutoAttest_PolicyEnabled_EmitsDisconnect verifies that when
// autoAttest has an enabled policy and attestation fails, it disconnects
// and emits both policy violation and disconnect events.
func TestP5C_AutoAttest_PolicyEnabled_EmitsDisconnect(t *testing.T) {
	svc := NewPhoneService()
	svc.connState.deviceName.Store("Test Phone")
	svc.connState.connected.Store(true)

	var emittedEvents []events.Event
	svc.SetEventEmitter(func(evt events.Event) {
		emittedEvents = append(emittedEvents, evt)
	})

	var statusChanges []struct {
		connected bool
		name      string
	}
	svc.SetStatusChangeFunc(func(connected bool, name string) {
		statusChanges = append(statusChanges, struct {
			connected bool
			name      string
		}{connected, name})
	})

	cfg := &phoneConfig{
		Devices: []phoneConfigDevice{
			{
				Name:    "Test Phone",
				Address: "AA:BB:CC:DD:EE:FF",
				AttestationPolicy: &attestationPolicy{
					Enabled:  true,
					BootHash: "expected-hash",
				},
			},
		},
	}
	device := &cfg.Devices[0]

	svc.autoAttest(cfg, device, "Test Phone")

	assert.False(t, svc.IsConnected())

	foundViolation := false
	foundDisconnect := false
	for _, evt := range emittedEvents {
		if evt.Type == events.EventPolicyViolation {
			foundViolation = true
		}
		if evt.Type == events.EventPhoneDisconnected {
			foundDisconnect = true
			payload, ok := evt.Payload.(events.PhoneDisconnectedPayload)
			require.True(t, ok)
			assert.Equal(t, "policy_violation", payload.Reason)
		}
	}
	assert.True(t, foundViolation, "expected policy violation event")
	assert.True(t, foundDisconnect, "expected disconnect event")

	require.NotEmpty(t, statusChanges)
	last := statusChanges[len(statusChanges)-1]
	assert.False(t, last.connected)
}

// TestP5C_AutoAttest_NoPolicy_NoAttestation verifies that autoAttest is a
// no-op when there is no policy and no previous attestation data.
func TestP5C_AutoAttest_NoPolicy_NoAttestation(t *testing.T) {
	svc := NewPhoneService()
	var emitted bool
	svc.SetEventEmitter(func(evt events.Event) {
		emitted = true
	})

	cfg := &phoneConfig{
		Devices: []phoneConfigDevice{
			{Name: "Plain Phone", Address: "AA:BB:CC:DD:EE:FF"},
		},
	}
	device := &cfg.Devices[0]

	svc.autoAttest(cfg, device, "Plain Phone")

	assert.False(t, emitted, "no events should be emitted when no policy or attestation data")
}

// TestP5C_AutoAttest_LastAttestationRefresh verifies that autoAttest
// performs a refresh attestation when LastAttestation is set but no policy.
func TestP5C_AutoAttest_LastAttestationRefresh(t *testing.T) {
	svc := NewPhoneService()

	var emittedEvents []events.Event
	svc.SetEventEmitter(func(evt events.Event) {
		emittedEvents = append(emittedEvents, evt)
	})

	cfg := &phoneConfig{
		Devices: []phoneConfigDevice{
			{
				Name:    "Refresh Phone",
				Address: "AA:BB:CC:DD:EE:FF",
				LastAttestation: &savedAttestationData{
					Verified:      true,
					SecurityLevel: "tee",
					Timestamp:     time.Now().UTC(),
				},
			},
		},
	}
	device := &cfg.Devices[0]

	svc.autoAttest(cfg, device, "Refresh Phone")

	foundAttest := false
	for _, evt := range emittedEvents {
		if evt.Type == events.EventAttestationResult {
			foundAttest = true
			payload, ok := evt.Payload.(events.AttestationResultPayload)
			require.True(t, ok)
			assert.False(t, payload.Success)
			assert.Equal(t, "Refresh Phone", payload.DeviceName)
		}
	}
	assert.True(t, foundAttest, "expected attestation result event")
}

// TestP5C_AutoAttest_PolicyDisabled_WithLastAttestation verifies that
// autoAttest skips policy enforcement when policy exists but Enabled=false,
// and proceeds to refresh attestation via LastAttestation path.
func TestP5C_AutoAttest_PolicyDisabled_WithLastAttestation(t *testing.T) {
	svc := NewPhoneService()

	var emittedEvents []events.Event
	svc.SetEventEmitter(func(evt events.Event) {
		emittedEvents = append(emittedEvents, evt)
	})

	cfg := &phoneConfig{
		Devices: []phoneConfigDevice{
			{
				Name:    "Half-Policy Phone",
				Address: "AA:BB:CC:DD:EE:FF",
				AttestationPolicy: &attestationPolicy{
					Enabled:  false,
					BootHash: "should-be-ignored",
				},
				LastAttestation: &savedAttestationData{
					Verified: true,
					BootHash: "previous",
				},
			},
		},
	}
	device := &cfg.Devices[0]

	svc.autoAttest(cfg, device, "Half-Policy Phone")

	foundAttest := false
	foundViolation := false
	for _, evt := range emittedEvents {
		if evt.Type == events.EventAttestationResult {
			foundAttest = true
		}
		if evt.Type == events.EventPolicyViolation {
			foundViolation = true
		}
	}
	assert.True(t, foundAttest, "expected attestation refresh event")
	assert.False(t, foundViolation, "should not emit policy violation when disabled")
}

// ===========================================================================
// closeActiveConnectionLocked: nil transport idempotent
// ===========================================================================

// TestP5C_CloseActiveConnectionLocked_NoTransportNoSession verifies that
// closeActiveConnectionLocked is safe to call when both transport and
// session are nil.
func TestP5C_CloseActiveConnectionLocked_NoTransportNoSession(t *testing.T) {
	svc := NewPhoneService()
	svc.connMu.Lock()
	svc.closeActiveConnectionLocked()
	svc.connMu.Unlock()
	assert.Nil(t, svc.activeTransport)
	assert.Nil(t, svc.activeSession)
}

// ===========================================================================
// saveConfig: error paths
// ===========================================================================

// TestP5C_SaveConfig_ReadOnlyDir verifies that saveConfig returns an error
// when the directory is not writable.
func TestP5C_SaveConfig_ReadOnlyDir(t *testing.T) {
	tmpDir := t.TempDir()
	xkeyDir := filepath.Join(tmpDir, ".xkey")
	require.NoError(t, os.MkdirAll(xkeyDir, 0700))
	require.NoError(t, os.Chmod(xkeyDir, 0500))
	t.Cleanup(func() {
		os.Chmod(xkeyDir, 0700)
	})

	origHome := os.Getenv("HOME")
	defer os.Setenv("HOME", origHome)
	os.Setenv("HOME", tmpDir)

	svc := NewPhoneService()
	cfg := &phoneConfig{
		Devices: []phoneConfigDevice{
			{Name: "Test", Address: "AA:BB:CC:DD:EE:FF"},
		},
	}
	err := svc.saveConfig(cfg)
	assert.Error(t, err)
}

// TestP5C_SaveConfig_Success verifies that saveConfig correctly writes
// the config file.
func TestP5C_SaveConfig_Success(t *testing.T) {
	tmpDir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, ".xkey"), 0700))
	origHome := os.Getenv("HOME")
	defer os.Setenv("HOME", origHome)
	os.Setenv("HOME", tmpDir)

	svc := NewPhoneService()
	now := time.Now().UTC()
	cfg := &phoneConfig{
		Devices: []phoneConfigDevice{
			{
				Name:     "SavedPhone",
				Address:  "AA:BB:CC:DD:EE:FF",
				PairedAt: now,
				LastAttestation: &savedAttestationData{
					Verified: true,
					BootHash: "aabb",
				},
			},
		},
		DefaultDevice: "SavedPhone",
	}

	err := svc.saveConfig(cfg)
	require.NoError(t, err)

	loaded, err := svc.loadConfig()
	require.NoError(t, err)
	require.Len(t, loaded.Devices, 1)
	assert.Equal(t, "SavedPhone", loaded.Devices[0].Name)
	assert.NotNil(t, loaded.Devices[0].LastAttestation)
	assert.True(t, loaded.Devices[0].LastAttestation.Verified)
}

// ===========================================================================
// hostname function
// ===========================================================================

// TestP5C_Hostname_ReturnsNonEmpty verifies that hostname() returns the
// OS hostname, which should be a non-empty string.
func TestP5C_Hostname_ReturnsNonEmpty(t *testing.T) {
	name := hostname()
	assert.NotEmpty(t, name)
	expected, err := os.Hostname()
	if err == nil {
		assert.Equal(t, expected, name)
	} else {
		assert.Equal(t, "xKey Desktop", name)
	}
}

// ===========================================================================
// phoneConfigPath
// ===========================================================================

// TestP5C_PhoneConfigPath_Format verifies phoneConfigPath returns the correct
// path format.
func TestP5C_PhoneConfigPath_Format(t *testing.T) {
	path, err := phoneConfigPath()
	require.NoError(t, err)
	assert.Contains(t, path, ".xkey")
	assert.Contains(t, path, "devices.yaml")
}

// ===========================================================================
// SetAttestationPolicy: complete flow
// ===========================================================================

// TestP5C_SetAttestationPolicy_SuccessfulSet verifies the full flow of
// setting an attestation policy from a previous attestation result.
func TestP5C_SetAttestationPolicy_SuccessfulSet(t *testing.T) {
	now := time.Now().UTC()
	cfg := &phoneConfig{
		Devices: []phoneConfigDevice{
			{
				Name:    "Policy Phone",
				Address: "AA:BB:CC:DD:EE:FF",
				LastAttestation: &savedAttestationData{
					Verified:      true,
					SecurityLevel: "strongbox",
					BootHash:      "deadbeef",
					BootKeyHash:   "cafebabe",
					BootState:     "verified",
					DeviceLocked:  true,
					Timestamp:     now,
				},
			},
		},
		DefaultDevice: "Policy Phone",
	}
	p5cSetupHomeWithConfig(t, cfg)

	svc := NewPhoneService()
	err := svc.SetAttestationPolicy("Policy Phone")
	require.NoError(t, err)

	policy, err := svc.GetAttestationPolicy("Policy Phone")
	require.NoError(t, err)
	require.NotNil(t, policy)
	assert.True(t, policy.Enabled)
	assert.Equal(t, "deadbeef", policy.BootHash)
	assert.Equal(t, "cafebabe", policy.BootKeyHash)
	assert.Equal(t, "verified", policy.BootState)
	assert.True(t, policy.DeviceLocked)
	assert.Equal(t, "strongbox", policy.SecurityLevel)
}

// TestP5C_SetAttestationPolicy_NoLastAttestation verifies that setting
// a policy without a previous attestation result returns ErrPhonePolicyNotSet.
func TestP5C_SetAttestationPolicy_NoLastAttestation(t *testing.T) {
	cfg := &phoneConfig{
		Devices: []phoneConfigDevice{
			{Name: "No Attest Phone", Address: "AA:BB:CC:DD:EE:FF"},
		},
		DefaultDevice: "No Attest Phone",
	}
	p5cSetupHomeWithConfig(t, cfg)

	svc := NewPhoneService()
	err := svc.SetAttestationPolicy("No Attest Phone")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPhonePolicyNotSet)
}

// ===========================================================================
// ClearAttestationPolicy: complete flow
// ===========================================================================

// TestP5C_ClearAttestationPolicy_Success verifies the full flow of
// clearing an attestation policy.
func TestP5C_ClearAttestationPolicy_Success(t *testing.T) {
	cfg := &phoneConfig{
		Devices: []phoneConfigDevice{
			{
				Name:    "Clear Phone",
				Address: "AA:BB:CC:DD:EE:FF",
				AttestationPolicy: &attestationPolicy{
					Enabled:  true,
					BootHash: "deadbeef",
				},
			},
		},
		DefaultDevice: "Clear Phone",
	}
	p5cSetupHomeWithConfig(t, cfg)

	svc := NewPhoneService()
	err := svc.ClearAttestationPolicy("Clear Phone")
	require.NoError(t, err)

	policy, err := svc.GetAttestationPolicy("Clear Phone")
	require.NoError(t, err)
	assert.Nil(t, policy)
}

// TestP5C_ClearAttestationPolicy_DeviceNotFound verifies that clearing
// a policy for a non-existent device returns ErrPhoneDeviceNotFound.
func TestP5C_ClearAttestationPolicy_DeviceNotFound(t *testing.T) {
	cfg := &phoneConfig{
		Devices: []phoneConfigDevice{
			{Name: "Other Phone", Address: "AA:BB:CC:DD:EE:FF"},
		},
	}
	p5cSetupHomeWithConfig(t, cfg)

	svc := NewPhoneService()
	err := svc.ClearAttestationPolicy("Missing Phone")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPhoneDeviceNotFound)
}

// ===========================================================================
// GetAttestationPolicy: nil policy and found policy
// ===========================================================================

// TestP5C_GetAttestationPolicy_NilPolicy verifies that GetAttestationPolicy
// returns nil (not an error) when the device has no policy set.
func TestP5C_GetAttestationPolicy_NilPolicy(t *testing.T) {
	cfg := &phoneConfig{
		Devices: []phoneConfigDevice{
			{Name: "No Policy Phone", Address: "AA:BB:CC:DD:EE:FF"},
		},
	}
	p5cSetupHomeWithConfig(t, cfg)

	svc := NewPhoneService()
	policy, err := svc.GetAttestationPolicy("No Policy Phone")
	require.NoError(t, err)
	assert.Nil(t, policy)
}

// TestP5C_GetAttestationPolicy_WithPolicy verifies that GetAttestationPolicy
// returns the stored policy when one exists.
func TestP5C_GetAttestationPolicy_WithPolicy(t *testing.T) {
	cfg := &phoneConfig{
		Devices: []phoneConfigDevice{
			{
				Name:    "Policed Phone",
				Address: "AA:BB:CC:DD:EE:FF",
				AttestationPolicy: &attestationPolicy{
					Enabled:       true,
					BootHash:      "abc",
					SecurityLevel: "tee",
				},
			},
		},
	}
	p5cSetupHomeWithConfig(t, cfg)

	svc := NewPhoneService()
	policy, err := svc.GetAttestationPolicy("Policed Phone")
	require.NoError(t, err)
	require.NotNil(t, policy)
	assert.True(t, policy.Enabled)
	assert.Equal(t, "abc", policy.BootHash)
	assert.Equal(t, "tee", policy.SecurityLevel)
}

// ===========================================================================
// Scan: timeout boundary validation
// ===========================================================================

// TestP5C_Scan_ExactBoundaryTimeout verifies Scan accepts the exact
// boundary value of 1 (min valid) and 120 (max valid). These will fail
// at BLE transport but pass validation.
func TestP5C_Scan_ExactBoundaryTimeout(t *testing.T) {
	svc := NewPhoneService()

	// timeout=1 should pass validation but fail at BLE.
	_, err := svc.Scan(1)
	assert.Error(t, err)
	assert.False(t, errors.Is(err, ErrPhoneInvalidTimeout),
		"timeout=1 should pass validation")

	// timeout=120 should pass validation but fail at BLE.
	_, err = svc.Scan(120)
	assert.Error(t, err)
	assert.False(t, errors.Is(err, ErrPhoneInvalidTimeout),
		"timeout=120 should pass validation")
}

// ===========================================================================
// Pair: empty address validation
// ===========================================================================

// TestP5C_Pair_EmptyAddressValidation verifies Pair returns ErrPhonePairFailed
// for an empty address, covering the early validation path.
func TestP5C_Pair_EmptyAddressValidation(t *testing.T) {
	svc := NewPhoneService()
	result, err := svc.Pair("")
	assert.Nil(t, result)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPhonePairFailed)
}

// ===========================================================================
// buildCertInfoList: RSA certificate algorithm display
// ===========================================================================

// TestP5C_BuildCertInfoList_RSACert verifies buildCertInfoList correctly
// formats the algorithm string for RSA certificates.
func TestP5C_BuildCertInfoList_RSACert(t *testing.T) {
	rsaCert := p5cGenerateRSATestCert(t, "RSA Test", true)
	chain := []*x509.Certificate{rsaCert}
	infos := buildCertInfoList(chain, nil)

	require.Len(t, infos, 1)
	assert.Equal(t, "Leaf", infos[0].Label)
	assert.Contains(t, infos[0].Algorithm, "RSA")
	assert.Contains(t, infos[0].Algorithm, "2048")
	assert.NotEmpty(t, infos[0].PublicKeyFP)
	assert.NotEmpty(t, infos[0].CertFP)
}

// TestP5C_BuildCertInfoList_MixedChain verifies buildCertInfoList handles
// a chain with both RSA and ECDSA certificates.
func TestP5C_BuildCertInfoList_MixedChain(t *testing.T) {
	ecdsaCert := p5cGenerateTestCert(t, "ECDSA Leaf", false)
	rsaRoot := p5cGenerateRSATestCert(t, "RSA Root", true)

	chain := []*x509.Certificate{ecdsaCert, rsaRoot}
	infos := buildCertInfoList(chain, []*x509.Certificate{rsaRoot})

	require.Len(t, infos, 2)
	assert.Equal(t, "Leaf", infos[0].Label)
	assert.Equal(t, "Root", infos[1].Label)
	assert.Contains(t, infos[0].Algorithm, "ECDSA")
	assert.Contains(t, infos[1].Algorithm, "RSA")
	assert.True(t, infos[1].IsTrustAnchor)
	assert.False(t, infos[0].IsTrustAnchor)
}

// ===========================================================================
// buildCertInfoList: size display for ECDSA with curve
// ===========================================================================

// TestP5C_BuildCertInfoList_ECDSACurveDisplay verifies that the algorithm
// string for ECDSA includes the curve name and bit size.
func TestP5C_BuildCertInfoList_ECDSACurveDisplay(t *testing.T) {
	cert := p5cGenerateTestCert(t, "ECDSA P256", false)
	chain := []*x509.Certificate{cert}
	infos := buildCertInfoList(chain, nil)
	require.Len(t, infos, 1)
	assert.Contains(t, infos[0].Algorithm, "ECDSA")
	assert.Contains(t, infos[0].Algorithm, "P-256")
	assert.Contains(t, infos[0].Algorithm, "256")
}

// ===========================================================================
// setConnected / setDisconnected: event and state management
// ===========================================================================

// TestP5C_SetConnected_FullState verifies setConnected updates all state
// fields and fires both event and status callback.
func TestP5C_SetConnected_FullState(t *testing.T) {
	svc := NewPhoneService()

	var emitted events.Event
	svc.SetEventEmitter(func(evt events.Event) {
		emitted = evt
	})

	var callbackCalled bool
	svc.SetStatusChangeFunc(func(connected bool, name string) {
		callbackCalled = true
		assert.True(t, connected)
		assert.Equal(t, "Galaxy S25", name)
	})

	svc.setConnected("Galaxy S25")

	assert.True(t, svc.IsConnected())
	assert.Equal(t, "Galaxy S25", svc.ConnectedDeviceName())
	assert.True(t, callbackCalled)

	assert.Equal(t, events.EventPhoneConnected, emitted.Type)
	payload, ok := emitted.Payload.(events.PhoneConnectedPayload)
	require.True(t, ok)
	assert.Equal(t, "Galaxy S25", payload.DeviceName)
}

// TestP5C_SetDisconnected_FullState verifies setDisconnected clears all
// state and fires both event and status callback.
func TestP5C_SetDisconnected_FullState(t *testing.T) {
	svc := NewPhoneService()
	svc.connState.deviceName.Store("Galaxy S25")
	svc.connState.connected.Store(true)

	var emitted events.Event
	svc.SetEventEmitter(func(evt events.Event) {
		emitted = evt
	})

	var callbackCalled bool
	svc.SetStatusChangeFunc(func(connected bool, name string) {
		callbackCalled = true
		assert.False(t, connected)
		assert.Empty(t, name)
	})

	svc.setDisconnected("Galaxy S25", "test_reason")

	assert.False(t, svc.IsConnected())
	assert.Empty(t, svc.ConnectedDeviceName())
	assert.True(t, callbackCalled)

	assert.Equal(t, events.EventPhoneDisconnected, emitted.Type)
	payload, ok := emitted.Payload.(events.PhoneDisconnectedPayload)
	require.True(t, ok)
	assert.Equal(t, "Galaxy S25", payload.DeviceName)
	assert.Equal(t, "test_reason", payload.Reason)
}

// ===========================================================================
// performAttestation: nil transport and session guards
// ===========================================================================

// TestP5C_PerformAttestation_TransportNilSessionNil verifies
// performAttestation returns ErrPhoneNotConnected when both are nil.
func TestP5C_PerformAttestation_TransportNilSessionNil(t *testing.T) {
	svc := NewPhoneService()
	device := &phoneConfigDevice{
		Name:    "Test Phone",
		Address: "AA:BB:CC:DD:EE:FF",
	}
	result, err := svc.performAttestation(device)
	assert.Nil(t, result)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPhoneNotConnected)
}

// ===========================================================================
// emitAttestationEvent: success and failure with details
// ===========================================================================

// TestP5C_EmitAttestationEvent_SuccessNoDetails verifies emitAttestationEvent
// emits a success event with empty details.
func TestP5C_EmitAttestationEvent_SuccessNoDetails(t *testing.T) {
	svc := NewPhoneService()
	var emitted events.Event
	svc.SetEventEmitter(func(evt events.Event) {
		emitted = evt
	})

	svc.emitAttestationEvent("TestDevice", true, "")
	assert.Equal(t, events.EventAttestationResult, emitted.Type)
	payload, ok := emitted.Payload.(events.AttestationResultPayload)
	require.True(t, ok)
	assert.True(t, payload.Success)
	assert.Empty(t, payload.Details)
}

// TestP5C_EmitAttestationEvent_FailureWithDetails verifies
// emitAttestationEvent emits a failure event with the error details.
func TestP5C_EmitAttestationEvent_FailureWithDetails(t *testing.T) {
	svc := NewPhoneService()
	var emitted events.Event
	svc.SetEventEmitter(func(evt events.Event) {
		emitted = evt
	})

	svc.emitAttestationEvent("TestDevice", false, "chain verification failed")
	payload, ok := emitted.Payload.(events.AttestationResultPayload)
	require.True(t, ok)
	assert.False(t, payload.Success)
	assert.Equal(t, "chain verification failed", payload.Details)
}

// ===========================================================================
// Unpair: config load failure
// ===========================================================================

// TestP5C_Unpair_ConfigLoadError verifies that Unpair returns
// ErrPhoneDeviceNotFound when the config cannot be loaded.
func TestP5C_Unpair_ConfigLoadError(t *testing.T) {
	tmpDir := t.TempDir()
	origHome := os.Getenv("HOME")
	defer os.Setenv("HOME", origHome)
	os.Setenv("HOME", tmpDir)

	svc := NewPhoneService()
	err := svc.Unpair("Some Device")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPhoneDeviceNotFound)
}

// TestP5C_Unpair_DeviceNotInConfig verifies that Unpair returns
// ErrPhoneDeviceNotFound when the device name is not in the config.
func TestP5C_Unpair_DeviceNotInConfig(t *testing.T) {
	cfg := &phoneConfig{
		Devices: []phoneConfigDevice{
			{Name: "Existing Phone", Address: "AA:BB:CC:DD:EE:FF"},
		},
	}
	p5cSetupHomeWithConfig(t, cfg)

	svc := NewPhoneService()
	err := svc.Unpair("Missing Phone")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPhoneDeviceNotFound)
}

// ===========================================================================
// SetAttestationPolicy / ClearAttestationPolicy / GetAttestationPolicy:
// config load error
// ===========================================================================

// TestP5C_SetAttestationPolicy_ConfigLoadError verifies that
// SetAttestationPolicy returns ErrPhoneDeviceNotFound when config is missing.
func TestP5C_SetAttestationPolicy_ConfigLoadError(t *testing.T) {
	tmpDir := t.TempDir()
	origHome := os.Getenv("HOME")
	defer os.Setenv("HOME", origHome)
	os.Setenv("HOME", tmpDir)

	svc := NewPhoneService()
	err := svc.SetAttestationPolicy("Phone")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPhoneDeviceNotFound)
}

// TestP5C_ClearAttestationPolicy_ConfigLoadError verifies that
// ClearAttestationPolicy returns ErrPhoneDeviceNotFound when config is missing.
func TestP5C_ClearAttestationPolicy_ConfigLoadError(t *testing.T) {
	tmpDir := t.TempDir()
	origHome := os.Getenv("HOME")
	defer os.Setenv("HOME", origHome)
	os.Setenv("HOME", tmpDir)

	svc := NewPhoneService()
	err := svc.ClearAttestationPolicy("Phone")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPhoneDeviceNotFound)
}

// TestP5C_GetAttestationPolicy_ConfigLoadError verifies that
// GetAttestationPolicy returns ErrPhoneDeviceNotFound when config is missing.
func TestP5C_GetAttestationPolicy_ConfigLoadError(t *testing.T) {
	tmpDir := t.TempDir()
	origHome := os.Getenv("HOME")
	defer os.Setenv("HOME", origHome)
	os.Setenv("HOME", tmpDir)

	svc := NewPhoneService()
	policy, err := svc.GetAttestationPolicy("Phone")
	assert.Nil(t, policy)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPhoneDeviceNotFound)
}

// ===========================================================================
// parseDERChain: multi-cert with error at different positions
// ===========================================================================

// TestP5C_ParseDERChain_SecondCertInvalid verifies parseDERChain returns
// an error referencing the correct index when the second certificate is invalid.
func TestP5C_ParseDERChain_SecondCertInvalid(t *testing.T) {
	validCert := p5cGenerateTestCert(t, "Valid Cert", false)
	chain, err := parseDERChain([][]byte{
		validCert.Raw,
		{0x30, 0x00}, // Invalid DER.
	})
	assert.Nil(t, chain)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "certificate at index 1")
}

// TestP5C_ParseDERChain_MultipleValidCerts verifies parseDERChain correctly
// parses multiple valid certificates.
func TestP5C_ParseDERChain_MultipleValidCerts(t *testing.T) {
	cert1 := p5cGenerateTestCert(t, "Leaf", false)
	cert2 := p5cGenerateTestCert(t, "Root", true)
	chain, err := parseDERChain([][]byte{cert1.Raw, cert2.Raw})
	require.NoError(t, err)
	require.Len(t, chain, 2)
	assert.Contains(t, chain[0].Subject.CommonName, "Leaf")
	assert.Contains(t, chain[1].Subject.CommonName, "Root")
}

// ===========================================================================
// buildAttestationTrustPool: fallback with no roots
// ===========================================================================

// TestP5C_BuildAttestationTrustPool_EmptyRoots verifies that
// buildAttestationTrustPool returns a valid (empty) pool when no roots
// are provided and no trust store is set.
func TestP5C_BuildAttestationTrustPool_EmptyRoots(t *testing.T) {
	svc := NewPhoneService()
	pool, err := svc.buildAttestationTrustPool(nil)
	require.NoError(t, err)
	assert.NotNil(t, pool)
}

// TestP5C_BuildAttestationTrustPool_WithMultipleRoots verifies that
// buildAttestationTrustPool adds multiple roots to the pool.
func TestP5C_BuildAttestationTrustPool_WithMultipleRoots(t *testing.T) {
	svc := NewPhoneService()
	root1 := p5cGenerateTestCert(t, "Root 1", true)
	root2 := p5cGenerateTestCert(t, "Root 2", true)
	pool, err := svc.buildAttestationTrustPool([]*x509.Certificate{root1, root2})
	require.NoError(t, err)
	assert.NotNil(t, pool)
}

// ===========================================================================
// findMatchingTrustRoot: chain with matching root
// ===========================================================================

// TestP5C_FindMatchingTrustRoot_MatchOnLast verifies findMatchingTrustRoot
// returns the correct root when the last cert matches.
func TestP5C_FindMatchingTrustRoot_MatchOnLast(t *testing.T) {
	leaf := p5cGenerateTestCert(t, "Leaf", false)
	root := p5cGenerateTestCert(t, "Root", true)
	other := p5cGenerateTestCert(t, "Other Root", true)

	chain := []*x509.Certificate{leaf, root}
	result := findMatchingTrustRoot(chain, []*x509.Certificate{other, root})
	require.NotNil(t, result)
	assert.Equal(t, certFP(root), certFP(result))
}

// TestP5C_FindMatchingTrustRoot_NoMatch verifies findMatchingTrustRoot
// returns nil when no root matches.
func TestP5C_FindMatchingTrustRoot_NoMatch(t *testing.T) {
	leaf := p5cGenerateTestCert(t, "Leaf", false)
	root := p5cGenerateTestCert(t, "Root", true)
	otherRoot := p5cGenerateTestCert(t, "Other Root", true)

	chain := []*x509.Certificate{leaf, root}
	result := findMatchingTrustRoot(chain, []*x509.Certificate{otherRoot})
	assert.Nil(t, result)
}

// ===========================================================================
// truncateHash: edge cases
// ===========================================================================

// TestP5C_TruncateHash_ExactBoundary verifies truncateHash behavior at
// the exact boundary (28 chars = not truncated, 29 chars = truncated).
func TestP5C_TruncateHash_ExactBoundary(t *testing.T) {
	exactly28 := "1234567890123456789012345678"
	assert.Equal(t, exactly28, truncateHash(exactly28))
	assert.Len(t, truncateHash(exactly28), 28)

	exactly29 := "12345678901234567890123456789"
	result := truncateHash(exactly29)
	assert.NotEqual(t, exactly29, result)
	assert.Contains(t, result, "...")
}

// ===========================================================================
// securityLevelRank: all values
// ===========================================================================

// TestP5C_SecurityLevelRank_Ordering verifies the ordering relationship
// between security levels.
func TestP5C_SecurityLevelRank_Ordering(t *testing.T) {
	assert.Less(t, securityLevelRank("software"), securityLevelRank("tee"))
	assert.Less(t, securityLevelRank("tee"), securityLevelRank("strongbox"))
	assert.Less(t, securityLevelRank(""), securityLevelRank("software"))
}

// ===========================================================================
// ListDevices: with attestation and policy data
// ===========================================================================

// TestP5C_ListDevices_WithAttestationData verifies that ListDevices
// correctly populates LastSeen from LastDeviceAttestationTime.
func TestP5C_ListDevices_WithAttestationData(t *testing.T) {
	attestTime := time.Date(2025, 6, 15, 10, 30, 0, 0, time.UTC)
	cfg := &phoneConfig{
		Devices: []phoneConfigDevice{
			{
				Name:                      "Pixel 9",
				Address:                   "AA:BB:CC:DD:EE:FF",
				PairedAt:                  time.Now().UTC(),
				LastDeviceAttestationTime: attestTime,
			},
		},
		DefaultDevice: "Pixel 9",
	}
	p5cSetupHomeWithConfig(t, cfg)

	svc := NewPhoneService()
	devices, err := svc.ListDevices()
	require.NoError(t, err)
	require.Len(t, devices, 1)
	assert.Equal(t, attestTime, devices[0].LastSeen)
	assert.Equal(t, "AA:BB:CC:DD:EE:FF", devices[0].Address)
}

// ===========================================================================
// saveAttestationResult: verified boot state
// ===========================================================================

// TestP5C_SaveAttestationResult_VerifiedBootState verifies that
// saveAttestationResult correctly sets BootStateVerified to true when
// boot state is "verified".
func TestP5C_SaveAttestationResult_VerifiedBootState(t *testing.T) {
	cfg := &phoneConfig{
		Devices: []phoneConfigDevice{
			{Name: "Pixel 9", Address: "AA:BB:CC:DD:EE:FF", PairedAt: time.Now().UTC()},
		},
		DefaultDevice: "Pixel 9",
	}
	p5cSetupHomeWithConfig(t, cfg)

	svc := NewPhoneService()
	device := &cfg.Devices[0]
	result := &AttestationResult{
		DeviceName:    "Pixel 9",
		Verified:      true,
		SecurityLevel: "tee",
		BootState:     "verified",
		BootHash:      "deadbeef",
		BootKeyHash:   "cafebabe",
		DeviceLocked:  true,
		AttestTime:    time.Now(),
	}

	svc.saveAttestationResult(cfg, device, result)

	loaded, err := svc.loadConfig()
	require.NoError(t, err)
	require.Len(t, loaded.Devices, 1)
	assert.True(t, loaded.Devices[0].BootStateVerified)
	assert.Equal(t, "tee", loaded.Devices[0].SecurityLevel)
	require.NotNil(t, loaded.Devices[0].LastAttestation)
	assert.True(t, loaded.Devices[0].LastAttestation.Verified)
	assert.True(t, loaded.Devices[0].LastAttestation.DeviceLocked)
}

// ===========================================================================
// pubKeyAlgoInfo: RSA key type
// ===========================================================================

// TestP5C_PubKeyAlgoInfo_RSA verifies pubKeyAlgoInfo returns correct values
// for an RSA certificate.
func TestP5C_PubKeyAlgoInfo_RSA(t *testing.T) {
	cert := p5cGenerateRSATestCert(t, "RSA Test", false)
	algo, size, curve := pubKeyAlgoInfo(cert)
	assert.Equal(t, "RSA", algo)
	assert.Equal(t, 2048, size)
	assert.Empty(t, curve)
}

// ===========================================================================
// pubKeyFP: RSA public key fingerprint
// ===========================================================================

// TestP5C_PubKeyFP_RSA verifies pubKeyFP returns a valid fingerprint for
// an RSA certificate.
func TestP5C_PubKeyFP_RSA(t *testing.T) {
	cert := p5cGenerateRSATestCert(t, "RSA FP Test", false)
	fp := pubKeyFP(cert)
	assert.NotEmpty(t, fp)
	assert.Len(t, fp, 64) // SHA-256 hex = 64 chars
}

// ===========================================================================
// certFP: fingerprint consistency
// ===========================================================================

// TestP5C_CertFP_Deterministic verifies certFP returns the same fingerprint
// for the same certificate.
func TestP5C_CertFP_Deterministic(t *testing.T) {
	cert := p5cGenerateTestCert(t, "FP Test", false)
	fp1 := certFP(cert)
	fp2 := certFP(cert)
	assert.Equal(t, fp1, fp2)
	assert.Len(t, fp1, 64)
}
