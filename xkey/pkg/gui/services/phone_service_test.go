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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/android"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/events"
)

func TestNewPhoneService(t *testing.T) {
	svc := NewPhoneService()
	assert.NotNil(t, svc)
	assert.NotNil(t, svc.log)
}

func TestPhoneService_SetContext(t *testing.T) {
	svc := NewPhoneService()
	svc.SetContext(context.Background())
}

func TestPhoneService_ListDevices_NoConfig(t *testing.T) {
	svc := NewPhoneService()
	devices, err := svc.ListDevices()
	require.NoError(t, err)
	assert.NotNil(t, devices)
}

func TestPhoneService_ListDevices_WithConfig(t *testing.T) {
	// Write a temporary config file.
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "phone.yaml")
	cfg := phoneConfig{
		Devices: []phoneConfigDevice{
			{
				Name:     "Test Phone",
				Address:  "AA:BB:CC:DD:EE:FF",
				PairedAt: time.Now().UTC(),
			},
		},
		DefaultDevice: "Test Phone",
	}
	data, err := yaml.Marshal(&cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(configPath, data, 0600))

	// Override the config path for this test.
	origHome := os.Getenv("HOME")
	defer os.Setenv("HOME", origHome)
	os.Setenv("HOME", tmpDir)

	// Create the .xkey directory structure.
	require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, ".xkey"), 0700))
	finalPath := filepath.Join(tmpDir, ".xkey", "phone.yaml")
	require.NoError(t, os.WriteFile(finalPath, data, 0600))

	svc := NewPhoneService()
	devices, err := svc.ListDevices()
	require.NoError(t, err)
	assert.Len(t, devices, 1)
	assert.Equal(t, "Test Phone", devices[0].Name)
	assert.Equal(t, "AA:BB:CC:DD:EE:FF", devices[0].Address)
}

func TestPhoneService_GetDeviceStatus(t *testing.T) {
	svc := NewPhoneService()
	_, err := svc.GetDeviceStatus("Pixel 8 Pro")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrPhoneNotConnected))
}

func TestPhoneService_GetDeviceStatus_EmptyName(t *testing.T) {
	svc := NewPhoneService()
	_, err := svc.GetDeviceStatus("")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrPhoneDeviceNotFound))
}

func TestPhoneService_Scan_InvalidTimeout(t *testing.T) {
	svc := NewPhoneService()
	tests := []int{0, -1, 121}
	for _, timeout := range tests {
		_, err := svc.Scan(timeout)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrPhoneInvalidTimeout))
	}
}

func TestPhoneService_Scan_BLEUnavailable(t *testing.T) {
	// On machines without BLE (e.g., CI), Scan returns a BLE-related error.
	svc := NewPhoneService()
	_, err := svc.Scan(1)
	// Expect either ErrPhoneBLEUnavailable or ErrPhoneScanFailed
	// depending on whether BLE hardware is present.
	if err != nil {
		assert.True(t,
			errors.Is(err, ErrPhoneBLEUnavailable) || errors.Is(err, ErrPhoneScanFailed),
			"expected BLE-related error, got: %v", err)
	}
	// If err is nil, BLE hardware is present and scan returned 0 devices (also valid).
}

func TestPhoneService_Pair_EmptyAddress(t *testing.T) {
	svc := NewPhoneService()
	_, err := svc.Pair("")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrPhonePairFailed))
}

func TestPhoneService_Pair_BLEUnavailable(t *testing.T) {
	// On machines without BLE, Pair returns a BLE-related error.
	svc := NewPhoneService()
	_, err := svc.Pair("AA:BB:CC:DD:EE:FF")
	assert.Error(t, err)
	assert.True(t,
		errors.Is(err, ErrPhonePairFailed) || errors.Is(err, ErrPhoneBLEUnavailable),
		"expected pairing or BLE error, got: %v", err)
}

func TestPhoneService_Unpair_EmptyName(t *testing.T) {
	svc := NewPhoneService()
	err := svc.Unpair("")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrPhoneDeviceNotFound))
}

func TestPhoneService_Unpair_NotFound(t *testing.T) {
	svc := NewPhoneService()
	err := svc.Unpair("NonExistent Device")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrPhoneDeviceNotFound))
}

func TestPhoneService_Unpair_WithConfig(t *testing.T) {
	tmpDir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, ".xkey"), 0700))

	cfg := phoneConfig{
		Devices: []phoneConfigDevice{
			{Name: "Test Phone", Address: "AA:BB:CC:DD:EE:FF", PairedAt: time.Now().UTC()},
		},
		DefaultDevice: "Test Phone",
	}
	data, err := yaml.Marshal(&cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, ".xkey", "phone.yaml"), data, 0600))

	origHome := os.Getenv("HOME")
	defer os.Setenv("HOME", origHome)
	os.Setenv("HOME", tmpDir)

	svc := NewPhoneService()
	err = svc.Unpair("Test Phone")
	assert.NoError(t, err)

	// Verify device was removed.
	devices, err := svc.ListDevices()
	require.NoError(t, err)
	assert.Empty(t, devices)
}

func TestPhoneService_Connect_EmptyName(t *testing.T) {
	svc := NewPhoneService()
	err := svc.Connect("")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrPhoneDeviceNotFound))
}

func TestPhoneService_Connect_NoConfig(t *testing.T) {
	tmpDir := t.TempDir()
	origHome := os.Getenv("HOME")
	defer os.Setenv("HOME", origHome)
	os.Setenv("HOME", tmpDir)

	svc := NewPhoneService()
	err := svc.Connect("NonExistent")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrPhoneDeviceNotFound))
}

func TestPhoneService_Connect_ValidDevice_BLEUnavailable(t *testing.T) {
	tmpDir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, ".xkey"), 0700))

	cfg := phoneConfig{
		Devices: []phoneConfigDevice{
			{
				Name:                 "Pixel 8",
				Address:              "AA:BB:CC:DD:EE:FF",
				NoisePublicKey:       "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
				LocalNoisePrivateKey: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
				PairedAt:             time.Now().UTC(),
			},
		},
		DefaultDevice: "Pixel 8",
	}
	data, err := yaml.Marshal(&cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, ".xkey", "phone.yaml"), data, 0600))

	origHome := os.Getenv("HOME")
	defer os.Setenv("HOME", origHome)
	os.Setenv("HOME", tmpDir)

	svc := NewPhoneService()
	err = svc.Connect("Pixel 8")
	// On CI without BLE hardware, Connect should fail with BLE-related or key errors.
	assert.Error(t, err)
	assert.True(t,
		errors.Is(err, ErrPhoneBLEUnavailable) ||
			errors.Is(err, ErrPhoneConnectFailed) ||
			errors.Is(err, ErrPhoneMissingKeys),
		"expected BLE or key error, got: %v", err)
	assert.False(t, svc.IsConnected())
}

func TestPhoneService_Connect_MissingKeys(t *testing.T) {
	tmpDir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, ".xkey"), 0700))

	cfg := phoneConfig{
		Devices: []phoneConfigDevice{
			{Name: "Pixel 8", Address: "AA:BB:CC:DD:EE:FF", PairedAt: time.Now().UTC()},
		},
		DefaultDevice: "Pixel 8",
	}
	data, err := yaml.Marshal(&cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, ".xkey", "phone.yaml"), data, 0600))

	origHome := os.Getenv("HOME")
	defer os.Setenv("HOME", origHome)
	os.Setenv("HOME", tmpDir)

	svc := NewPhoneService()
	err = svc.Connect("Pixel 8")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrPhoneMissingKeys))
	assert.False(t, svc.IsConnected())
}

func TestPhoneService_Connect_DeviceNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, ".xkey"), 0700))

	cfg := phoneConfig{
		Devices: []phoneConfigDevice{
			{Name: "Pixel 8", Address: "AA:BB:CC:DD:EE:FF", PairedAt: time.Now().UTC()},
		},
		DefaultDevice: "Pixel 8",
	}
	data, err := yaml.Marshal(&cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, ".xkey", "phone.yaml"), data, 0600))

	origHome := os.Getenv("HOME")
	defer os.Setenv("HOME", origHome)
	os.Setenv("HOME", tmpDir)

	svc := NewPhoneService()
	err = svc.Connect("Galaxy S24")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrPhoneDeviceNotFound))
}

func TestPhoneService_Connect_PolicyNotEnabled_MissingKeys(t *testing.T) {
	tmpDir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, ".xkey"), 0700))

	cfg := phoneConfig{
		Devices: []phoneConfigDevice{
			{
				Name:     "Pixel 8",
				Address:  "AA:BB:CC:DD:EE:FF",
				PairedAt: time.Now().UTC(),
				AttestationPolicy: &attestationPolicy{
					Enabled:  false,
					BootHash: "abc123",
				},
			},
		},
		DefaultDevice: "Pixel 8",
	}
	data, err := yaml.Marshal(&cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, ".xkey", "phone.yaml"), data, 0600))

	origHome := os.Getenv("HOME")
	defer os.Setenv("HOME", origHome)
	os.Setenv("HOME", tmpDir)

	// Connect requires real BLE; without keys it fails early.
	svc := NewPhoneService()
	err = svc.Connect("Pixel 8")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrPhoneMissingKeys))
}

func TestPhoneService_Connect_NoPolicySet_MissingKeys(t *testing.T) {
	tmpDir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, ".xkey"), 0700))

	cfg := phoneConfig{
		Devices: []phoneConfigDevice{
			{
				Name:              "Pixel 8",
				Address:           "AA:BB:CC:DD:EE:FF",
				PairedAt:          time.Now().UTC(),
				AttestationPolicy: nil,
			},
		},
		DefaultDevice: "Pixel 8",
	}
	data, err := yaml.Marshal(&cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, ".xkey", "phone.yaml"), data, 0600))

	origHome := os.Getenv("HOME")
	defer os.Setenv("HOME", origHome)
	os.Setenv("HOME", tmpDir)

	// Connect requires real BLE; without keys it fails early.
	svc := NewPhoneService()
	err = svc.Connect("Pixel 8")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrPhoneMissingKeys))
}

func TestPhoneService_Disconnect(t *testing.T) {
	svc := NewPhoneService()
	err := svc.Disconnect("Pixel 8 Pro")
	assert.NoError(t, err)
}

func TestPhoneService_Disconnect_EmptyName(t *testing.T) {
	svc := NewPhoneService()
	err := svc.Disconnect("")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrPhoneDeviceNotFound))
}

func TestPhoneService_AttestDevice_EmptyName(t *testing.T) {
	svc := NewPhoneService()
	_, err := svc.AttestDevice("")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrPhoneDeviceNotFound))
}

func TestPhoneService_AttestDevice_NotConnected(t *testing.T) {
	svc := NewPhoneService()
	_, err := svc.AttestDevice("Pixel 8 Pro")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrPhoneNotConnected))
}

func TestPhoneService_AttestDevice_WrongDevice(t *testing.T) {
	svc := NewPhoneService()
	// Manually set a connected state.
	svc.connState.deviceName.Store("Other Device")
	svc.connState.connected.Store(true)

	_, err := svc.AttestDevice("Pixel 8 Pro")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrPhoneNotConnected))
}

func TestPhoneService_AttestDevice_ConnectedNoConfig(t *testing.T) {
	tmpDir := t.TempDir()
	origHome := os.Getenv("HOME")
	defer os.Setenv("HOME", origHome)
	os.Setenv("HOME", tmpDir)

	svc := NewPhoneService()
	svc.connState.deviceName.Store("Pixel 8")
	svc.connState.connected.Store(true)

	// No config file exists, so loadConfig fails and AttestDevice returns
	// ErrPhoneAttestFailed before reaching performAttestation.
	_, err := svc.AttestDevice("Pixel 8")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrPhoneAttestFailed))
}

func TestPhoneService_AttestDevice_ConnectedDeviceNotInConfig(t *testing.T) {
	tmpDir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, ".xkey"), 0700))

	cfg := phoneConfig{
		Devices: []phoneConfigDevice{
			{Name: "Galaxy S24", Address: "11:22:33:44:55:66", PairedAt: time.Now().UTC()},
		},
		DefaultDevice: "Galaxy S24",
	}
	data, err := yaml.Marshal(&cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, ".xkey", "phone.yaml"), data, 0600))

	origHome := os.Getenv("HOME")
	defer os.Setenv("HOME", origHome)
	os.Setenv("HOME", tmpDir)

	svc := NewPhoneService()
	svc.connState.deviceName.Store("Pixel 8")
	svc.connState.connected.Store(true)

	// Device "Pixel 8" is connected but not in config.
	// However, performAttestation now checks active transport first
	// and returns ErrPhoneNotConnected (no active transport set).
	// AttestDevice then wraps this into a result with error.
	result, err := svc.AttestDevice("Pixel 8")
	// AttestDevice still calls loadConfig + device lookup before performAttestation.
	// "Pixel 8" is not in config -> returns ErrPhoneDeviceNotFound as an error.
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrPhoneDeviceNotFound))
	assert.Nil(t, result)
}

func TestPhoneService_AttestDevice_NoActiveConnection(t *testing.T) {
	tmpDir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, ".xkey"), 0700))

	cfg := phoneConfig{
		Devices: []phoneConfigDevice{
			{
				Name:                 "Pixel 8",
				Address:              "AA:BB:CC:DD:EE:FF",
				NoisePublicKey:       "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
				LocalNoisePrivateKey: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
				PairedAt:             time.Now().UTC(),
			},
		},
		DefaultDevice: "Pixel 8",
	}
	data, err := yaml.Marshal(&cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, ".xkey", "phone.yaml"), data, 0600))

	origHome := os.Getenv("HOME")
	defer os.Setenv("HOME", origHome)
	os.Setenv("HOME", tmpDir)

	svc := NewPhoneService()
	// Set connState to appear connected, but no active transport/session.
	svc.connState.deviceName.Store("Pixel 8")
	svc.connState.connected.Store(true)

	var emitted events.Event
	svc.SetEventEmitter(func(evt events.Event) {
		emitted = evt
	})

	// performAttestation now returns ErrPhoneNotConnected because
	// there is no active transport/session. AttestDevice wraps this
	// in a result with error message.
	result, err := svc.AttestDevice("Pixel 8")
	require.NoError(t, err) // Returns result with error, not an error.
	assert.NotNil(t, result)
	assert.Equal(t, "Pixel 8", result.DeviceName)
	assert.False(t, result.Verified)
	assert.NotEmpty(t, result.ErrorMessage)
	assert.Contains(t, result.ErrorMessage, "no device connected")

	// Should have emitted an attestation event.
	assert.Equal(t, events.EventAttestationResult, emitted.Type)
	payload, ok := emitted.Payload.(events.AttestationResultPayload)
	assert.True(t, ok)
	assert.Equal(t, "Pixel 8", payload.DeviceName)
	assert.False(t, payload.Success)
}

func TestPhoneConfigPath(t *testing.T) {
	path, err := phoneConfigPath()
	require.NoError(t, err)
	assert.Contains(t, path, ".xkey")
	assert.Contains(t, path, "devices.yaml")
}

func TestHostname(t *testing.T) {
	name := hostname()
	assert.NotEmpty(t, name)
}

func TestPhoneService_LoadConfig_NotExist(t *testing.T) {
	tmpDir := t.TempDir()
	origHome := os.Getenv("HOME")
	defer os.Setenv("HOME", origHome)
	os.Setenv("HOME", tmpDir)

	svc := NewPhoneService()
	_, err := svc.loadConfig()
	assert.Error(t, err)
	assert.True(t, errors.Is(err, os.ErrNotExist))
}

func TestPhoneService_SaveAndLoadConfig(t *testing.T) {
	tmpDir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, ".xkey"), 0700))

	origHome := os.Getenv("HOME")
	defer os.Setenv("HOME", origHome)
	os.Setenv("HOME", tmpDir)

	svc := NewPhoneService()

	cfg := &phoneConfig{
		Devices: []phoneConfigDevice{
			{Name: "Test", Address: "11:22:33:44:55:66", PairedAt: time.Now().UTC()},
		},
		DefaultDevice: "Test",
	}

	err := svc.saveConfig(cfg)
	require.NoError(t, err)

	loaded, err := svc.loadConfig()
	require.NoError(t, err)
	assert.Len(t, loaded.Devices, 1)
	assert.Equal(t, "Test", loaded.Devices[0].Name)
	assert.Equal(t, "Test", loaded.DefaultDevice)
}

// ---------------------------------------------------------------------------
// Connection state tracking
// ---------------------------------------------------------------------------

func TestPhoneService_IsConnected_Default(t *testing.T) {
	svc := NewPhoneService()
	assert.False(t, svc.IsConnected())
}

func TestPhoneService_ConnectedDeviceName_Default(t *testing.T) {
	svc := NewPhoneService()
	assert.Empty(t, svc.ConnectedDeviceName())
}

func TestPhoneService_SetConnected_UpdatesState(t *testing.T) {
	svc := NewPhoneService()
	svc.setConnected("Pixel 8")

	assert.True(t, svc.IsConnected())
	assert.Equal(t, "Pixel 8", svc.ConnectedDeviceName())
}

func TestPhoneService_SetDisconnected_UpdatesState(t *testing.T) {
	svc := NewPhoneService()
	svc.setConnected("Pixel 8")
	svc.setDisconnected("Pixel 8", "user_requested")

	assert.False(t, svc.IsConnected())
	assert.Empty(t, svc.ConnectedDeviceName())
}

// ---------------------------------------------------------------------------
// Event emission
// ---------------------------------------------------------------------------

func TestPhoneService_SetConnected_EmitsEvent(t *testing.T) {
	svc := NewPhoneService()

	var emitted events.Event
	svc.SetEventEmitter(func(evt events.Event) {
		emitted = evt
	})

	svc.setConnected("Pixel 8")

	assert.Equal(t, events.EventPhoneConnected, emitted.Type)
	payload, ok := emitted.Payload.(events.PhoneConnectedPayload)
	assert.True(t, ok)
	assert.Equal(t, "Pixel 8", payload.DeviceName)
}

func TestPhoneService_SetDisconnected_EmitsEvent(t *testing.T) {
	svc := NewPhoneService()

	var emitted events.Event
	svc.SetEventEmitter(func(evt events.Event) {
		emitted = evt
	})

	svc.setDisconnected("Pixel 8", "user_requested")

	assert.Equal(t, events.EventPhoneDisconnected, emitted.Type)
	payload, ok := emitted.Payload.(events.PhoneDisconnectedPayload)
	assert.True(t, ok)
	assert.Equal(t, "Pixel 8", payload.DeviceName)
	assert.Equal(t, "user_requested", payload.Reason)
}

func TestPhoneService_AttestDevice_EmitsEvent(t *testing.T) {
	tmpDir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, ".xkey"), 0700))

	cfg := phoneConfig{
		Devices: []phoneConfigDevice{
			{
				Name:                 "Pixel 8",
				Address:              "AA:BB:CC:DD:EE:FF",
				NoisePublicKey:       "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
				LocalNoisePrivateKey: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
				PairedAt:             time.Now().UTC(),
			},
		},
		DefaultDevice: "Pixel 8",
	}
	data, err := yaml.Marshal(&cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, ".xkey", "phone.yaml"), data, 0600))

	origHome := os.Getenv("HOME")
	defer os.Setenv("HOME", origHome)
	os.Setenv("HOME", tmpDir)

	svc := NewPhoneService()
	// Set connection state but no active transport — attestation will fail.
	svc.connState.deviceName.Store("Pixel 8")
	svc.connState.connected.Store(true)

	var emitted events.Event
	svc.SetEventEmitter(func(evt events.Event) {
		emitted = evt
	})

	result, err := svc.AttestDevice("Pixel 8")
	require.NoError(t, err) // Returns result with error, not an error.
	assert.NotNil(t, result)
	assert.False(t, result.Verified)

	assert.Equal(t, events.EventAttestationResult, emitted.Type)
	payload, ok := emitted.Payload.(events.AttestationResultPayload)
	assert.True(t, ok)
	assert.Equal(t, "Pixel 8", payload.DeviceName)
	assert.False(t, payload.Success)
}

// ---------------------------------------------------------------------------
// Status change callback
// ---------------------------------------------------------------------------

func TestPhoneService_StatusChangeFunc_Connect(t *testing.T) {
	svc := NewPhoneService()

	var calledConnected bool
	var calledName string
	svc.SetStatusChangeFunc(func(connected bool, name string) {
		calledConnected = connected
		calledName = name
	})

	svc.setConnected("Pixel 8")

	assert.True(t, calledConnected)
	assert.Equal(t, "Pixel 8", calledName)
}

func TestPhoneService_StatusChangeFunc_Disconnect(t *testing.T) {
	svc := NewPhoneService()

	var calledConnected bool
	var calledName string
	svc.SetStatusChangeFunc(func(connected bool, name string) {
		calledConnected = connected
		calledName = name
	})

	svc.setDisconnected("Pixel 8", "shutdown")

	assert.False(t, calledConnected)
	assert.Empty(t, calledName)
}

// ---------------------------------------------------------------------------
// ListDevices reflects connection state
// ---------------------------------------------------------------------------

func TestPhoneService_ListDevices_ShowsConnected(t *testing.T) {
	tmpDir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, ".xkey"), 0700))

	cfg := phoneConfig{
		Devices: []phoneConfigDevice{
			{Name: "Pixel 8", Address: "AA:BB:CC:DD:EE:FF", PairedAt: time.Now().UTC()},
			{Name: "Galaxy S24", Address: "11:22:33:44:55:66", PairedAt: time.Now().UTC()},
		},
		DefaultDevice: "Pixel 8",
	}
	data, err := yaml.Marshal(&cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, ".xkey", "phone.yaml"), data, 0600))

	origHome := os.Getenv("HOME")
	defer os.Setenv("HOME", origHome)
	os.Setenv("HOME", tmpDir)

	svc := NewPhoneService()
	svc.connState.deviceName.Store("Pixel 8")
	svc.connState.connected.Store(true)

	devices, err := svc.ListDevices()
	require.NoError(t, err)
	assert.Len(t, devices, 2)

	// Pixel 8 should show as connected.
	assert.True(t, devices[0].Connected)
	assert.Equal(t, "Pixel 8", devices[0].Name)

	// Galaxy S24 should not.
	assert.False(t, devices[1].Connected)
	assert.Equal(t, "Galaxy S24", devices[1].Name)
}

// ---------------------------------------------------------------------------
// Unpair disconnects connected device
// ---------------------------------------------------------------------------

func TestPhoneService_Unpair_DisconnectsIfConnected(t *testing.T) {
	tmpDir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, ".xkey"), 0700))

	cfg := phoneConfig{
		Devices: []phoneConfigDevice{
			{Name: "Pixel 8", Address: "AA:BB:CC:DD:EE:FF", PairedAt: time.Now().UTC()},
		},
		DefaultDevice: "Pixel 8",
	}
	data, err := yaml.Marshal(&cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, ".xkey", "phone.yaml"), data, 0600))

	origHome := os.Getenv("HOME")
	defer os.Setenv("HOME", origHome)
	os.Setenv("HOME", tmpDir)

	svc := NewPhoneService()
	svc.connState.deviceName.Store("Pixel 8")
	svc.connState.connected.Store(true)

	err = svc.Unpair("Pixel 8")
	assert.NoError(t, err)

	// Should be disconnected after unpair.
	assert.False(t, svc.IsConnected())
	assert.Empty(t, svc.ConnectedDeviceName())
	// Transport should be nil after unpair.
	assert.Nil(t, svc.activeTransport)
	assert.Nil(t, svc.activeSession)
}

// ---------------------------------------------------------------------------
// SetEventEmitter / SetStatusChangeFunc / SetTrustStore
// ---------------------------------------------------------------------------

func TestPhoneService_SetEventEmitter(t *testing.T) {
	svc := NewPhoneService()
	assert.Nil(t, svc.eventEmitter)

	svc.SetEventEmitter(func(evt events.Event) {})
	assert.NotNil(t, svc.eventEmitter)
}

func TestPhoneService_SetStatusChangeFunc(t *testing.T) {
	svc := NewPhoneService()
	assert.Nil(t, svc.statusChangeFn)

	svc.SetStatusChangeFunc(func(connected bool, name string) {})
	assert.NotNil(t, svc.statusChangeFn)
}

func TestPhoneService_SetTrustStore(t *testing.T) {
	svc := NewPhoneService()
	assert.Nil(t, svc.trustStore)

	// SetTrustStore accepts nil without panic.
	svc.SetTrustStore(nil)
	assert.Nil(t, svc.trustStore)
}

// ---------------------------------------------------------------------------
// Attestation policy management
// ---------------------------------------------------------------------------

func TestPhoneService_SetAttestationPolicy_EmptyName(t *testing.T) {
	svc := NewPhoneService()
	err := svc.SetAttestationPolicy("")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrPhoneDeviceNotFound))
}

func TestPhoneService_SetAttestationPolicy_NoConfig(t *testing.T) {
	tmpDir := t.TempDir()
	origHome := os.Getenv("HOME")
	defer os.Setenv("HOME", origHome)
	os.Setenv("HOME", tmpDir)

	svc := NewPhoneService()
	err := svc.SetAttestationPolicy("Pixel 8")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrPhoneDeviceNotFound))
}

func TestPhoneService_SetAttestationPolicy_DeviceNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, ".xkey"), 0700))

	cfg := phoneConfig{
		Devices: []phoneConfigDevice{
			{Name: "Galaxy S24", Address: "11:22:33:44:55:66", PairedAt: time.Now().UTC()},
		},
		DefaultDevice: "Galaxy S24",
	}
	data, err := yaml.Marshal(&cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, ".xkey", "phone.yaml"), data, 0600))

	origHome := os.Getenv("HOME")
	defer os.Setenv("HOME", origHome)
	os.Setenv("HOME", tmpDir)

	svc := NewPhoneService()
	err = svc.SetAttestationPolicy("Pixel 8")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrPhoneDeviceNotFound))
}

func TestPhoneService_SetAttestationPolicy_NoLastAttestation(t *testing.T) {
	tmpDir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, ".xkey"), 0700))

	cfg := phoneConfig{
		Devices: []phoneConfigDevice{
			{Name: "Pixel 8", Address: "AA:BB:CC:DD:EE:FF", PairedAt: time.Now().UTC()},
		},
		DefaultDevice: "Pixel 8",
	}
	data, err := yaml.Marshal(&cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, ".xkey", "phone.yaml"), data, 0600))

	origHome := os.Getenv("HOME")
	defer os.Setenv("HOME", origHome)
	os.Setenv("HOME", tmpDir)

	svc := NewPhoneService()
	err = svc.SetAttestationPolicy("Pixel 8")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrPhonePolicyNotSet))
}

func TestPhoneService_SetAttestationPolicy_Success(t *testing.T) {
	tmpDir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, ".xkey"), 0700))

	cfg := phoneConfig{
		Devices: []phoneConfigDevice{
			{
				Name:    "Pixel 8",
				Address: "AA:BB:CC:DD:EE:FF",
				LastAttestation: &savedAttestationData{
					Verified:      true,
					SecurityLevel: "tee",
					BootHash:      "abc123",
					BootKeyHash:   "def456",
					BootState:     "verified",
					DeviceLocked:  true,
					Timestamp:     time.Now().UTC(),
				},
				PairedAt: time.Now().UTC(),
			},
		},
		DefaultDevice: "Pixel 8",
	}
	data, err := yaml.Marshal(&cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, ".xkey", "phone.yaml"), data, 0600))

	origHome := os.Getenv("HOME")
	defer os.Setenv("HOME", origHome)
	os.Setenv("HOME", tmpDir)

	svc := NewPhoneService()
	err = svc.SetAttestationPolicy("Pixel 8")
	assert.NoError(t, err)

	// Verify policy was saved.
	policy, err := svc.GetAttestationPolicy("Pixel 8")
	require.NoError(t, err)
	require.NotNil(t, policy)
	assert.True(t, policy.Enabled)
	assert.Equal(t, "abc123", policy.BootHash)
	assert.Equal(t, "def456", policy.BootKeyHash)
	assert.Equal(t, "verified", policy.BootState)
	assert.True(t, policy.DeviceLocked)
	assert.Equal(t, "tee", policy.SecurityLevel)
}

func TestPhoneService_ClearAttestationPolicy_EmptyName(t *testing.T) {
	svc := NewPhoneService()
	err := svc.ClearAttestationPolicy("")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrPhoneDeviceNotFound))
}

func TestPhoneService_ClearAttestationPolicy_NoConfig(t *testing.T) {
	tmpDir := t.TempDir()
	origHome := os.Getenv("HOME")
	defer os.Setenv("HOME", origHome)
	os.Setenv("HOME", tmpDir)

	svc := NewPhoneService()
	err := svc.ClearAttestationPolicy("Pixel 8")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrPhoneDeviceNotFound))
}

func TestPhoneService_ClearAttestationPolicy_DeviceNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, ".xkey"), 0700))

	cfg := phoneConfig{
		Devices:       []phoneConfigDevice{},
		DefaultDevice: "",
	}
	data, err := yaml.Marshal(&cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, ".xkey", "phone.yaml"), data, 0600))

	origHome := os.Getenv("HOME")
	defer os.Setenv("HOME", origHome)
	os.Setenv("HOME", tmpDir)

	svc := NewPhoneService()
	err = svc.ClearAttestationPolicy("Pixel 8")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrPhoneDeviceNotFound))
}

func TestPhoneService_ClearAttestationPolicy_Success(t *testing.T) {
	tmpDir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, ".xkey"), 0700))

	cfg := phoneConfig{
		Devices: []phoneConfigDevice{
			{
				Name:    "Pixel 8",
				Address: "AA:BB:CC:DD:EE:FF",
				AttestationPolicy: &attestationPolicy{
					Enabled:  true,
					BootHash: "abc123",
				},
				PairedAt: time.Now().UTC(),
			},
		},
		DefaultDevice: "Pixel 8",
	}
	data, err := yaml.Marshal(&cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, ".xkey", "phone.yaml"), data, 0600))

	origHome := os.Getenv("HOME")
	defer os.Setenv("HOME", origHome)
	os.Setenv("HOME", tmpDir)

	svc := NewPhoneService()
	err = svc.ClearAttestationPolicy("Pixel 8")
	assert.NoError(t, err)

	// Verify policy was cleared.
	policy, err := svc.GetAttestationPolicy("Pixel 8")
	require.NoError(t, err)
	assert.Nil(t, policy)
}

func TestPhoneService_GetAttestationPolicy_EmptyName(t *testing.T) {
	svc := NewPhoneService()
	_, err := svc.GetAttestationPolicy("")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrPhoneDeviceNotFound))
}

func TestPhoneService_GetAttestationPolicy_NoConfig(t *testing.T) {
	tmpDir := t.TempDir()
	origHome := os.Getenv("HOME")
	defer os.Setenv("HOME", origHome)
	os.Setenv("HOME", tmpDir)

	svc := NewPhoneService()
	_, err := svc.GetAttestationPolicy("Pixel 8")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrPhoneDeviceNotFound))
}

func TestPhoneService_GetAttestationPolicy_DeviceNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, ".xkey"), 0700))

	cfg := phoneConfig{
		Devices:       []phoneConfigDevice{},
		DefaultDevice: "",
	}
	data, err := yaml.Marshal(&cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, ".xkey", "phone.yaml"), data, 0600))

	origHome := os.Getenv("HOME")
	defer os.Setenv("HOME", origHome)
	os.Setenv("HOME", tmpDir)

	svc := NewPhoneService()
	_, err = svc.GetAttestationPolicy("NonExistent")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrPhoneDeviceNotFound))
}

func TestPhoneService_GetAttestationPolicy_NilPolicy(t *testing.T) {
	tmpDir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, ".xkey"), 0700))

	cfg := phoneConfig{
		Devices: []phoneConfigDevice{
			{Name: "Pixel 8", Address: "AA:BB:CC:DD:EE:FF", PairedAt: time.Now().UTC()},
		},
		DefaultDevice: "Pixel 8",
	}
	data, err := yaml.Marshal(&cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, ".xkey", "phone.yaml"), data, 0600))

	origHome := os.Getenv("HOME")
	defer os.Setenv("HOME", origHome)
	os.Setenv("HOME", tmpDir)

	svc := NewPhoneService()
	policy, err := svc.GetAttestationPolicy("Pixel 8")
	require.NoError(t, err)
	assert.Nil(t, policy)
}

// ---------------------------------------------------------------------------
// Config persistence with new attestation fields
// ---------------------------------------------------------------------------

func TestPhoneService_SaveAndLoadConfig_WithAttestationData(t *testing.T) {
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
				Name:     "Test",
				Address:  "11:22:33:44:55:66",
				PairedAt: now,
				LastAttestation: &savedAttestationData{
					Verified:      true,
					SecurityLevel: "tee",
					BootHash:      "deadbeef",
					BootKeyHash:   "cafebabe",
					BootState:     "verified",
					DeviceLocked:  true,
					Timestamp:     now,
				},
				AttestationPolicy: &attestationPolicy{
					Enabled:       true,
					BootHash:      "deadbeef",
					BootKeyHash:   "cafebabe",
					BootState:     "verified",
					DeviceLocked:  true,
					SecurityLevel: "tee",
					SetAt:         now,
				},
			},
		},
		DefaultDevice: "Test",
	}

	err := svc.saveConfig(cfg)
	require.NoError(t, err)

	loaded, err := svc.loadConfig()
	require.NoError(t, err)
	assert.Len(t, loaded.Devices, 1)

	dev := loaded.Devices[0]
	require.NotNil(t, dev.LastAttestation)
	assert.True(t, dev.LastAttestation.Verified)
	assert.Equal(t, "tee", dev.LastAttestation.SecurityLevel)
	assert.Equal(t, "deadbeef", dev.LastAttestation.BootHash)
	assert.Equal(t, "cafebabe", dev.LastAttestation.BootKeyHash)
	assert.True(t, dev.LastAttestation.DeviceLocked)

	require.NotNil(t, dev.AttestationPolicy)
	assert.True(t, dev.AttestationPolicy.Enabled)
	assert.Equal(t, "deadbeef", dev.AttestationPolicy.BootHash)
	assert.Equal(t, "tee", dev.AttestationPolicy.SecurityLevel)
}

// ---------------------------------------------------------------------------
// Helper function tests
// ---------------------------------------------------------------------------

func TestParseDERChain_Empty(t *testing.T) {
	chain, err := parseDERChain(nil)
	require.NoError(t, err)
	assert.Empty(t, chain)
}

func TestParseDERChain_InvalidDER(t *testing.T) {
	_, err := parseDERChain([][]byte{{0x00, 0x01, 0x02}})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "certificate at index 0")
}

func TestParseDERChain_ValidCert(t *testing.T) {
	cert := generateTestCert(t)
	chain, err := parseDERChain([][]byte{cert.Raw})
	require.NoError(t, err)
	assert.Len(t, chain, 1)
	assert.Equal(t, cert.Subject.String(), chain[0].Subject.String())
}

func TestFindMatchingTrustRoot_EmptyChain(t *testing.T) {
	result := findMatchingTrustRoot(nil, nil)
	assert.Nil(t, result)
}

func TestFindMatchingTrustRoot_NoMatch(t *testing.T) {
	cert1 := generateTestCert(t)
	cert2 := generateTestCert(t)
	result := findMatchingTrustRoot([]*x509.Certificate{cert1}, []*x509.Certificate{cert2})
	assert.Nil(t, result)
}

func TestFindMatchingTrustRoot_Match(t *testing.T) {
	cert := generateTestCert(t)
	result := findMatchingTrustRoot([]*x509.Certificate{cert}, []*x509.Certificate{cert})
	assert.NotNil(t, result)
	assert.Equal(t, certFP(cert), certFP(result))
}

func TestCertFP(t *testing.T) {
	cert := generateTestCert(t)
	fp := certFP(cert)
	assert.NotEmpty(t, fp)
	assert.Len(t, fp, 64) // SHA-256 hex = 64 chars

	// Verify it matches manual computation.
	hash := sha256.Sum256(cert.Raw)
	expected := hex.EncodeToString(hash[:])
	assert.Equal(t, expected, fp)
}

func TestPubKeyFP(t *testing.T) {
	cert := generateTestCert(t)
	fp := pubKeyFP(cert)
	assert.NotEmpty(t, fp)
	assert.Len(t, fp, 64)
}

func TestFormatTrustAnchorName_Nil(t *testing.T) {
	assert.Equal(t, "Unknown", formatTrustAnchorName(nil))
}

func TestFormatTrustAnchorName_OrgAndCN(t *testing.T) {
	cert := &x509.Certificate{
		Subject: pkix.Name{
			Organization: []string{"Google LLC"},
			CommonName:   "Android Hardware Attestation Root",
		},
	}
	assert.Equal(t, "Google LLC - Android Hardware Attestation Root", formatTrustAnchorName(cert))
}

func TestFormatTrustAnchorName_CNOnly(t *testing.T) {
	cert := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "Test Root CA",
		},
	}
	assert.Equal(t, "Test Root CA", formatTrustAnchorName(cert))
}

func TestFormatTrustAnchorName_OrgOnly(t *testing.T) {
	cert := &x509.Certificate{
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
		},
	}
	assert.Equal(t, "Test Org", formatTrustAnchorName(cert))
}

func TestFormatTrustAnchorName_SerialNumber(t *testing.T) {
	cert := &x509.Certificate{
		Subject: pkix.Name{
			SerialNumber: "12345",
		},
	}
	assert.Equal(t, "Google Hardware Attestation Root (SN=12345)", formatTrustAnchorName(cert))
}

func TestFormatTrustAnchorName_Empty(t *testing.T) {
	cert := &x509.Certificate{
		Subject: pkix.Name{},
	}
	assert.Equal(t, "Google Hardware Attestation Root", formatTrustAnchorName(cert))
}

func TestGetCertLabel(t *testing.T) {
	assert.Equal(t, "Leaf", getCertLabel(0, 3))
	assert.Equal(t, "Root", getCertLabel(2, 3))
	assert.Equal(t, "Intermediate", getCertLabel(1, 3))
	assert.Equal(t, "Intermediate 1", getCertLabel(1, 5))
	assert.Equal(t, "Intermediate 2", getCertLabel(2, 5))
}

func TestPubKeyAlgoInfo_ECDSA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cert := &x509.Certificate{
		PublicKey:          &key.PublicKey,
		PublicKeyAlgorithm: x509.ECDSA,
	}
	algo, size, curve := pubKeyAlgoInfo(cert)
	assert.Equal(t, "ECDSA", algo)
	assert.Equal(t, 256, size)
	assert.Equal(t, "P-256", curve)
}

func TestBuildCertInfoList(t *testing.T) {
	cert := generateTestCert(t)
	chain := []*x509.Certificate{cert}
	infos := buildCertInfoList(chain, nil)
	require.Len(t, infos, 1)
	assert.Equal(t, "Leaf", infos[0].Label)
	assert.NotEmpty(t, infos[0].Subject)
	assert.NotEmpty(t, infos[0].CertFP)
	assert.NotEmpty(t, infos[0].NotBefore)
	assert.NotEmpty(t, infos[0].NotAfter)
}

func TestBuildCertInfoList_ThreeCerts(t *testing.T) {
	leaf := generateTestCert(t)
	intermediate := generateTestCert(t)
	root := generateTestCert(t)

	chain := []*x509.Certificate{leaf, intermediate, root}
	infos := buildCertInfoList(chain, []*x509.Certificate{root})

	require.Len(t, infos, 3)
	assert.Equal(t, "Leaf", infos[0].Label)
	assert.Equal(t, "Intermediate", infos[1].Label)
	assert.Equal(t, "Root", infos[2].Label)
	assert.True(t, infos[2].IsTrustAnchor)
	assert.False(t, infos[0].IsTrustAnchor)
}

// ---------------------------------------------------------------------------
// Keymaster name lookup tests
// ---------------------------------------------------------------------------

func TestKeymasterPurposeNameList(t *testing.T) {
	names := keymasterPurposeNameList([]int{0, 2, 3, 99})
	assert.Equal(t, []string{"ENCRYPT", "SIGN", "VERIFY", "UNKNOWN(99)"}, names)
}

func TestKeymasterPurposeNameList_Empty(t *testing.T) {
	names := keymasterPurposeNameList(nil)
	assert.Empty(t, names)
}

func TestKeymasterAlgorithmName(t *testing.T) {
	assert.Equal(t, "RSA", keymasterAlgorithmName(1))
	assert.Equal(t, "EC", keymasterAlgorithmName(3))
	assert.Equal(t, "AES", keymasterAlgorithmName(32))
	assert.Equal(t, "UNKNOWN(42)", keymasterAlgorithmName(42))
}

func TestKeymasterOriginName(t *testing.T) {
	assert.Equal(t, "GENERATED", keymasterOriginName(0))
	assert.Equal(t, "IMPORTED", keymasterOriginName(2))
	assert.Equal(t, "SECURELY_IMPORTED", keymasterOriginName(4))
	assert.Equal(t, "UNKNOWN(99)", keymasterOriginName(99))
}

func TestVerifiedBootStateName(t *testing.T) {
	assert.Equal(t, "verified", verifiedBootStateName(android.VerifiedBootVerified))
	assert.Equal(t, "self-signed", verifiedBootStateName(android.VerifiedBootSelfSigned))
	assert.Equal(t, "unverified", verifiedBootStateName(android.VerifiedBootUnverified))
	assert.Equal(t, "failed", verifiedBootStateName(android.VerifiedBootFailed))
	assert.Equal(t, "unknown", verifiedBootStateName(android.VerifiedBootState(99)))
}

// ---------------------------------------------------------------------------
// emitAttestationEvent
// ---------------------------------------------------------------------------

func TestEmitAttestationEvent_NilEmitter(t *testing.T) {
	svc := NewPhoneService()
	// Should not panic with nil emitter.
	svc.emitAttestationEvent("Pixel 8", true, "")
}

func TestEmitAttestationEvent_Success(t *testing.T) {
	svc := NewPhoneService()

	var emitted events.Event
	svc.SetEventEmitter(func(evt events.Event) {
		emitted = evt
	})

	svc.emitAttestationEvent("Pixel 8", true, "")
	assert.Equal(t, events.EventAttestationResult, emitted.Type)

	payload, ok := emitted.Payload.(events.AttestationResultPayload)
	assert.True(t, ok)
	assert.Equal(t, "Pixel 8", payload.DeviceName)
	assert.True(t, payload.Success)
	assert.Empty(t, payload.Details)
}

func TestEmitAttestationEvent_Failure(t *testing.T) {
	svc := NewPhoneService()

	var emitted events.Event
	svc.SetEventEmitter(func(evt events.Event) {
		emitted = evt
	})

	svc.emitAttestationEvent("Pixel 8", false, "chain verification failed")
	payload, ok := emitted.Payload.(events.AttestationResultPayload)
	assert.True(t, ok)
	assert.False(t, payload.Success)
	assert.Equal(t, "chain verification failed", payload.Details)
}

// ---------------------------------------------------------------------------
// buildAttestationTrustPool
// ---------------------------------------------------------------------------

func TestBuildAttestationTrustPool_NoTrustStore(t *testing.T) {
	svc := NewPhoneService()
	cert := generateTestCert(t)
	pool, err := svc.buildAttestationTrustPool([]*x509.Certificate{cert})
	require.NoError(t, err)
	assert.NotNil(t, pool)
}

func TestBuildAttestationTrustPool_EmptyRoots(t *testing.T) {
	svc := NewPhoneService()
	pool, err := svc.buildAttestationTrustPool(nil)
	require.NoError(t, err)
	assert.NotNil(t, pool)
}

// ---------------------------------------------------------------------------
// saveAttestationResult
// ---------------------------------------------------------------------------

func TestSaveAttestationResult(t *testing.T) {
	tmpDir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, ".xkey"), 0700))

	origHome := os.Getenv("HOME")
	defer os.Setenv("HOME", origHome)
	os.Setenv("HOME", tmpDir)

	svc := NewPhoneService()

	cfg := &phoneConfig{
		Devices: []phoneConfigDevice{
			{Name: "Pixel 8", Address: "AA:BB:CC:DD:EE:FF", PairedAt: time.Now().UTC()},
		},
		DefaultDevice: "Pixel 8",
	}

	device := &cfg.Devices[0]
	now := time.Now()
	result := &AttestationResult{
		DeviceName:    "Pixel 8",
		Verified:      true,
		SecurityLevel: "tee",
		BootState:     "verified",
		BootHash:      "aabb",
		BootKeyHash:   "ccdd",
		DeviceLocked:  true,
		AttestTime:    now,
	}

	svc.saveAttestationResult(cfg, device, result)

	// Reload and verify.
	loaded, err := svc.loadConfig()
	require.NoError(t, err)
	require.Len(t, loaded.Devices, 1)

	dev := loaded.Devices[0]
	require.NotNil(t, dev.LastAttestation)
	assert.True(t, dev.LastAttestation.Verified)
	assert.Equal(t, "tee", dev.LastAttestation.SecurityLevel)
	assert.Equal(t, "aabb", dev.LastAttestation.BootHash)
	assert.Equal(t, "ccdd", dev.LastAttestation.BootKeyHash)
	assert.Equal(t, "verified", dev.LastAttestation.BootState)
	assert.True(t, dev.LastAttestation.DeviceLocked)
	assert.True(t, dev.BootStateVerified)
	assert.Equal(t, "tee", dev.SecurityLevel)
}

// ---------------------------------------------------------------------------
// truncateHash
// ---------------------------------------------------------------------------

func TestTruncateHash(t *testing.T) {
	t.Run("short hash returned as-is", func(t *testing.T) {
		// 28 chars or less should be returned unchanged.
		short := "abcdef1234567890"
		assert.Equal(t, short, truncateHash(short))

		exactly28 := "1234567890123456789012345678"
		assert.Equal(t, exactly28, truncateHash(exactly28))
	})

	t.Run("long hash truncated", func(t *testing.T) {
		// 64-char hex hash (SHA-256 output).
		long := "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"
		result := truncateHash(long)
		// First 16 chars + "..." + last 8 chars.
		assert.Equal(t, "a1b2c3d4e5f6a7b8...e9f0a1b2", result)
		assert.Len(t, result, 27) // 16 + 3 + 8
	})
}

// ---------------------------------------------------------------------------
// securityLevelRank
// ---------------------------------------------------------------------------

func TestSecurityLevelRank(t *testing.T) {
	t.Run("known levels ranked correctly", func(t *testing.T) {
		assert.Equal(t, 0, securityLevelRank("software"))
		assert.Equal(t, 1, securityLevelRank("tee"))
		assert.Equal(t, 2, securityLevelRank("strongbox"))
	})

	t.Run("software less than tee less than strongbox", func(t *testing.T) {
		assert.Less(t, securityLevelRank("software"), securityLevelRank("tee"))
		assert.Less(t, securityLevelRank("tee"), securityLevelRank("strongbox"))
	})

	t.Run("unknown level returns -1", func(t *testing.T) {
		assert.Equal(t, -1, securityLevelRank("unknown"))
		assert.Equal(t, -1, securityLevelRank(""))
		assert.Equal(t, -1, securityLevelRank("invalid"))
	})
}

// ---------------------------------------------------------------------------
// emitPolicyViolationEvent
// ---------------------------------------------------------------------------

func TestPhoneService_EmitPolicyViolationEvent_NilEmitter(t *testing.T) {
	svc := NewPhoneService()
	// Should not panic when emitter is nil.
	svc.emitPolicyViolationEvent("Pixel 8", map[string]string{
		"boot_hash": "expected X, got Y",
	}, "test message")
}

func TestPhoneService_EmitPolicyViolationEvent_Emitted(t *testing.T) {
	svc := NewPhoneService()

	var emitted events.Event
	svc.SetEventEmitter(func(evt events.Event) {
		emitted = evt
	})

	mismatches := map[string]string{
		"boot_hash":     "expected abc, got def",
		"boot_state":    "expected verified, got unverified",
		"device_locked": "expected locked, got unlocked",
	}
	svc.emitPolicyViolationEvent("Pixel 8", mismatches, "3 fields mismatched")

	assert.Equal(t, events.EventPolicyViolation, emitted.Type)

	payload, ok := emitted.Payload.(events.PolicyViolationPayload)
	require.True(t, ok)
	assert.Equal(t, "Pixel 8", payload.DeviceName)
	assert.Equal(t, "3 fields mismatched", payload.Message)
	assert.Len(t, payload.Mismatches, 3)
	assert.Equal(t, "expected abc, got def", payload.Mismatches["boot_hash"])
	assert.Equal(t, "expected verified, got unverified", payload.Mismatches["boot_state"])
	assert.Equal(t, "expected locked, got unlocked", payload.Mismatches["device_locked"])
}

// ---------------------------------------------------------------------------
// closeActiveConnectionLocked
// ---------------------------------------------------------------------------

func TestPhoneService_CloseActiveConnectionLocked_NilTransport(t *testing.T) {
	svc := NewPhoneService()
	// Should not panic when transport and session are nil.
	svc.connMu.Lock()
	svc.closeActiveConnectionLocked()
	svc.connMu.Unlock()

	assert.Nil(t, svc.activeTransport)
	assert.Nil(t, svc.activeSession)
}

// ---------------------------------------------------------------------------
// Disconnect clears active connection
// ---------------------------------------------------------------------------

func TestPhoneService_Disconnect_ClearsActiveState(t *testing.T) {
	svc := NewPhoneService()
	// Set connected state.
	svc.connState.deviceName.Store("Pixel 8")
	svc.connState.connected.Store(true)

	err := svc.Disconnect("Pixel 8")
	assert.NoError(t, err)
	assert.False(t, svc.IsConnected())
	assert.Empty(t, svc.ConnectedDeviceName())
	assert.Nil(t, svc.activeTransport)
	assert.Nil(t, svc.activeSession)
}

// ---------------------------------------------------------------------------
// Connect error handling
// ---------------------------------------------------------------------------

func TestPhoneService_Connect_InvalidLocalKey(t *testing.T) {
	tmpDir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, ".xkey"), 0700))

	cfg := phoneConfig{
		Devices: []phoneConfigDevice{
			{
				Name:                 "Pixel 8",
				Address:              "AA:BB:CC:DD:EE:FF",
				NoisePublicKey:       "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
				LocalNoisePrivateKey: "not-valid-base64!!!",
				PairedAt:             time.Now().UTC(),
			},
		},
		DefaultDevice: "Pixel 8",
	}
	data, err := yaml.Marshal(&cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, ".xkey", "phone.yaml"), data, 0600))

	origHome := os.Getenv("HOME")
	defer os.Setenv("HOME", origHome)
	os.Setenv("HOME", tmpDir)

	svc := NewPhoneService()
	err = svc.Connect("Pixel 8")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrPhoneMissingKeys))
}

func TestPhoneService_Connect_InvalidRemoteKey(t *testing.T) {
	tmpDir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, ".xkey"), 0700))

	cfg := phoneConfig{
		Devices: []phoneConfigDevice{
			{
				Name:                 "Pixel 8",
				Address:              "AA:BB:CC:DD:EE:FF",
				NoisePublicKey:       "not-valid-base64!!!",
				LocalNoisePrivateKey: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
				PairedAt:             time.Now().UTC(),
			},
		},
		DefaultDevice: "Pixel 8",
	}
	data, err := yaml.Marshal(&cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, ".xkey", "phone.yaml"), data, 0600))

	origHome := os.Getenv("HOME")
	defer os.Setenv("HOME", origHome)
	os.Setenv("HOME", tmpDir)

	svc := NewPhoneService()
	err = svc.Connect("Pixel 8")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrPhoneMissingKeys))
}

// ---------------------------------------------------------------------------
// New error sentinel tests
// ---------------------------------------------------------------------------

func TestPhoneService_ErrorSentinels(t *testing.T) {
	assert.NotNil(t, ErrPhoneConnectFailed)
	assert.NotNil(t, ErrPhoneHandshakeFailed)
	assert.NotNil(t, ErrPhoneMissingKeys)
	assert.Contains(t, ErrPhoneConnectFailed.Error(), "BLE connection failed")
	assert.Contains(t, ErrPhoneHandshakeFailed.Error(), "Noise handshake failed")
	assert.Contains(t, ErrPhoneMissingKeys.Error(), "missing Noise keys")
}

// ---------------------------------------------------------------------------
// autoAttest with no policy and no last attestation (should be a no-op)
// ---------------------------------------------------------------------------

func TestPhoneService_AutoAttest_NoPolicy_NoLastAttestation(t *testing.T) {
	svc := NewPhoneService()
	cfg := &phoneConfig{
		Devices: []phoneConfigDevice{
			{Name: "Pixel 8", Address: "AA:BB:CC:DD:EE:FF"},
		},
	}
	device := &cfg.Devices[0]

	// Should not panic or do anything when there's no policy and no last attestation.
	svc.autoAttest(cfg, device, "Pixel 8")
}

// ---------------------------------------------------------------------------
// enforceAttestationPolicy - no active transport
// ---------------------------------------------------------------------------

func TestPhoneService_EnforceAttestationPolicy_NoActiveTransport(t *testing.T) {
	svc := NewPhoneService()

	var emitted events.Event
	svc.SetEventEmitter(func(evt events.Event) {
		emitted = evt
	})

	device := &phoneConfigDevice{
		Name:    "Pixel 8",
		Address: "AA:BB:CC:DD:EE:FF",
		AttestationPolicy: &attestationPolicy{
			Enabled:       true,
			BootHash:      "abc123",
			BootKeyHash:   "def456",
			BootState:     "verified",
			DeviceLocked:  true,
			SecurityLevel: "tee",
		},
	}

	err := svc.enforceAttestationPolicy("Pixel 8", device)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPhonePolicyViolation))
	assert.Contains(t, err.Error(), "attestation failed")

	// Should have emitted a policy violation event.
	assert.Equal(t, events.EventPolicyViolation, emitted.Type)
	payload, ok := emitted.Payload.(events.PolicyViolationPayload)
	require.True(t, ok)
	assert.Equal(t, "Pixel 8", payload.DeviceName)
	assert.Contains(t, payload.Mismatches["attestation"], "attestation failed")
}

// ---------------------------------------------------------------------------
// performAttestation - no active transport or session
// ---------------------------------------------------------------------------

func TestPhoneService_PerformAttestation_NilTransport(t *testing.T) {
	svc := NewPhoneService()

	device := &phoneConfigDevice{
		Name:    "Pixel 8",
		Address: "AA:BB:CC:DD:EE:FF",
	}

	result, err := svc.performAttestation(device)
	assert.Nil(t, result)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPhoneNotConnected))
}

func TestPhoneService_PerformAttestation_NilSession(t *testing.T) {
	svc := NewPhoneService()
	// Set transport but not session.
	svc.connMu.Lock()
	svc.activeSession = nil
	svc.connMu.Unlock()

	device := &phoneConfigDevice{
		Name:    "Pixel 8",
		Address: "AA:BB:CC:DD:EE:FF",
	}

	result, err := svc.performAttestation(device)
	assert.Nil(t, result)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPhoneNotConnected))
}

// ---------------------------------------------------------------------------
// autoAttest with enabled policy but no transport (disconnects on violation)
// ---------------------------------------------------------------------------

func TestPhoneService_AutoAttest_PolicyEnabled_NoTransport(t *testing.T) {
	svc := NewPhoneService()

	var emittedEvents []events.Event
	svc.SetEventEmitter(func(evt events.Event) {
		emittedEvents = append(emittedEvents, evt)
	})

	// Simulate connected state.
	svc.connState.deviceName.Store("Pixel 8")
	svc.connState.connected.Store(true)

	cfg := &phoneConfig{
		Devices: []phoneConfigDevice{
			{
				Name:    "Pixel 8",
				Address: "AA:BB:CC:DD:EE:FF",
				AttestationPolicy: &attestationPolicy{
					Enabled:       true,
					BootHash:      "abc123",
					BootKeyHash:   "def456",
					BootState:     "verified",
					DeviceLocked:  true,
					SecurityLevel: "tee",
				},
			},
		},
	}
	device := &cfg.Devices[0]

	// autoAttest with active policy but no transport -> policy enforcement fails
	// -> should disconnect.
	svc.autoAttest(cfg, device, "Pixel 8")

	// After policy failure, device should be disconnected.
	assert.False(t, svc.IsConnected())

	// Should have emitted a policy violation event and a disconnect event.
	foundViolation := false
	foundDisconnect := false
	for _, evt := range emittedEvents {
		if evt.Type == events.EventPolicyViolation {
			foundViolation = true
		}
		if evt.Type == events.EventPhoneDisconnected {
			foundDisconnect = true
		}
	}
	assert.True(t, foundViolation, "expected policy violation event")
	assert.True(t, foundDisconnect, "expected disconnect event")
}

// ---------------------------------------------------------------------------
// autoAttest with last attestation but no policy (refresh path)
// ---------------------------------------------------------------------------

func TestPhoneService_AutoAttest_LastAttestation_NoPolicy_NoTransport(t *testing.T) {
	svc := NewPhoneService()

	var emittedEvents []events.Event
	svc.SetEventEmitter(func(evt events.Event) {
		emittedEvents = append(emittedEvents, evt)
	})

	cfg := &phoneConfig{
		Devices: []phoneConfigDevice{
			{
				Name:    "Pixel 8",
				Address: "AA:BB:CC:DD:EE:FF",
				LastAttestation: &savedAttestationData{
					Verified:      true,
					SecurityLevel: "tee",
					BootHash:      "aabb",
					Timestamp:     time.Now().UTC(),
				},
			},
		},
	}
	device := &cfg.Devices[0]

	// autoAttest with last attestation but no active transport -> fails but
	// does NOT disconnect (only logs warning and emits attestation failure event).
	svc.autoAttest(cfg, device, "Pixel 8")

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

// ---------------------------------------------------------------------------
// Unpair with multiple devices sets new default
// ---------------------------------------------------------------------------

func TestPhoneService_Unpair_SetsNewDefault(t *testing.T) {
	tmpDir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, ".xkey"), 0700))

	cfg := phoneConfig{
		Devices: []phoneConfigDevice{
			{Name: "Pixel 8", Address: "AA:BB:CC:DD:EE:FF", PairedAt: time.Now().UTC()},
			{Name: "Galaxy S24", Address: "11:22:33:44:55:66", PairedAt: time.Now().UTC()},
		},
		DefaultDevice: "Pixel 8",
	}
	data, err := yaml.Marshal(&cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, ".xkey", "phone.yaml"), data, 0600))

	origHome := os.Getenv("HOME")
	defer os.Setenv("HOME", origHome)
	os.Setenv("HOME", tmpDir)

	svc := NewPhoneService()
	err = svc.Unpair("Pixel 8")
	require.NoError(t, err)

	// After removing the default device, the new default should be the remaining device.
	loaded, err := svc.loadConfig()
	require.NoError(t, err)
	assert.Len(t, loaded.Devices, 1)
	assert.Equal(t, "Galaxy S24", loaded.DefaultDevice)
}

// ---------------------------------------------------------------------------
// Connect with invalid device fingerprint (warning but continues)
// ---------------------------------------------------------------------------

func TestPhoneService_Connect_InvalidFingerprint(t *testing.T) {
	tmpDir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, ".xkey"), 0700))

	cfg := phoneConfig{
		Devices: []phoneConfigDevice{
			{
				Name:                 "Pixel 8",
				Address:              "AA:BB:CC:DD:EE:FF",
				NoisePublicKey:       "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
				LocalNoisePrivateKey: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
				DeviceFingerprint:    "not-hex!!!",
				PairedAt:             time.Now().UTC(),
			},
		},
		DefaultDevice: "Pixel 8",
	}
	data, err := yaml.Marshal(&cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, ".xkey", "phone.yaml"), data, 0600))

	origHome := os.Getenv("HOME")
	defer os.Setenv("HOME", origHome)
	os.Setenv("HOME", tmpDir)

	svc := NewPhoneService()
	err = svc.Connect("Pixel 8")
	// Will fail due to invalid key / BLE, but should not fail due to fingerprint
	// (fingerprint decode error is a warning, not a hard error).
	assert.Error(t, err)
	assert.True(t,
		errors.Is(err, ErrPhoneBLEUnavailable) ||
			errors.Is(err, ErrPhoneConnectFailed) ||
			errors.Is(err, ErrPhoneMissingKeys),
		"expected BLE or key error, got: %v", err)
}

// ---------------------------------------------------------------------------
// pubKeyAlgoInfo - RSA key
// ---------------------------------------------------------------------------

func TestPubKeyAlgoInfo_RSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	cert := &x509.Certificate{
		PublicKey:          &key.PublicKey,
		PublicKeyAlgorithm: x509.RSA,
	}
	algo, size, curve := pubKeyAlgoInfo(cert)
	assert.Equal(t, "RSA", algo)
	assert.Equal(t, 2048, size)
	assert.Empty(t, curve)
}

// ---------------------------------------------------------------------------
// pubKeyAlgoInfo - unknown key type
// ---------------------------------------------------------------------------

func TestPubKeyAlgoInfo_Unknown(t *testing.T) {
	cert := &x509.Certificate{
		PublicKey:          "not-a-real-key",
		PublicKeyAlgorithm: x509.UnknownPublicKeyAlgorithm,
	}
	algo, size, curve := pubKeyAlgoInfo(cert)
	assert.NotEmpty(t, algo)
	assert.Equal(t, 0, size)
	assert.Empty(t, curve)
}

// ---------------------------------------------------------------------------
// Scan with boundary timeout values
// ---------------------------------------------------------------------------

func TestPhoneService_Scan_BoundaryTimeouts(t *testing.T) {
	svc := NewPhoneService()

	// Max valid timeout (120) should attempt scan.
	_, err := svc.Scan(120)
	// Either succeeds (BLE available) or fails with BLE error.
	if err != nil {
		assert.True(t,
			errors.Is(err, ErrPhoneBLEUnavailable) || errors.Is(err, ErrPhoneScanFailed),
			"expected BLE-related error, got: %v", err)
	}

	// Min valid timeout (1) should attempt scan.
	_, err = svc.Scan(1)
	if err != nil {
		assert.True(t,
			errors.Is(err, ErrPhoneBLEUnavailable) || errors.Is(err, ErrPhoneScanFailed),
			"expected BLE-related error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Error sentinels coverage
// ---------------------------------------------------------------------------

func TestPhoneService_AllErrorSentinels(t *testing.T) {
	sentinels := []struct {
		err      error
		contains string
	}{
		{ErrPhoneNotConnected, "no device connected"},
		{ErrPhoneDeviceNotFound, "device not found"},
		{ErrPhoneScanFailed, "scan failed"},
		{ErrPhonePairFailed, "pairing failed"},
		{ErrPhoneAttestFailed, "attestation failed"},
		{ErrPhoneInvalidTimeout, "invalid timeout"},
		{ErrPhoneBLEUnavailable, "bluetooth unavailable"},
		{ErrPhoneAlreadyPaired, "already paired"},
		{ErrPhoneAttestNotImplemented, "attestation requires"},
		{ErrPhoneConnectFailed, "BLE connection failed"},
		{ErrPhoneHandshakeFailed, "Noise handshake failed"},
		{ErrPhoneMissingKeys, "missing Noise keys"},
		{ErrPhonePolicyViolation, "attestation policy violation"},
		{ErrPhonePolicyNotSet, "no attestation policy"},
	}
	for _, tt := range sentinels {
		assert.NotNil(t, tt.err)
		assert.Contains(t, tt.err.Error(), tt.contains, "sentinel %v", tt.err)
	}
}

// ---------------------------------------------------------------------------
// Test helper: generate a self-signed test certificate
// ---------------------------------------------------------------------------

func generateTestCert(t *testing.T) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
			CommonName:   "Test Cert",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}
