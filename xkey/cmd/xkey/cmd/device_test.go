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

package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPhoneConfig_LoadSave(t *testing.T) {
	// Create temporary directory for test
	tempDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	t.Setenv("HOME", tempDir)
	defer os.Setenv("HOME", originalHome)

	// Create the .xkey directory
	xkeyDir := filepath.Join(tempDir, ".xkey")
	err := os.MkdirAll(xkeyDir, 0700)
	require.NoError(t, err)

	// Test saving configuration
	cfg := &DevicesConfig{
		Devices: []PairedDevice{
			{
				Name:                 "Test Phone",
				Address:              "AA:BB:CC:DD:EE:FF",
				NoisePublicKey:       "dGVzdC1wdWJsaWMta2V5",
				LocalNoisePrivateKey: "dGVzdC1wcml2YXRlLWtleQ==",
				PairedAt:             time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC),
			},
		},
		DefaultDevice: "Test Phone",
	}

	err = saveDevicesConfig(cfg)
	require.NoError(t, err)

	// Verify file exists with correct permissions
	configPath := filepath.Join(xkeyDir, devicesConfigFileName)
	info, err := os.Stat(configPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())

	// Test loading configuration
	loadedCfg, err := loadDevicesConfig()
	require.NoError(t, err)

	assert.Equal(t, cfg.DefaultDevice, loadedCfg.DefaultDevice)
	require.Len(t, loadedCfg.Devices, 1)
	assert.Equal(t, cfg.Devices[0].Name, loadedCfg.Devices[0].Name)
	assert.Equal(t, cfg.Devices[0].Address, loadedCfg.Devices[0].Address)
	assert.Equal(t, cfg.Devices[0].NoisePublicKey, loadedCfg.Devices[0].NoisePublicKey)
}

func TestPhoneConfig_LoadNotExist(t *testing.T) {
	// Create temporary directory without config
	tempDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	t.Setenv("HOME", tempDir)
	defer os.Setenv("HOME", originalHome)

	// Loading should return os.ErrNotExist
	_, err := loadDevicesConfig()
	assert.True(t, os.IsNotExist(err))
}

func TestFindDeviceByName(t *testing.T) {
	cfg := &DevicesConfig{
		Devices: []PairedDevice{
			{Name: "Device 1", Address: "11:22:33:44:55:66"},
			{Name: "Device 2", Address: "AA:BB:CC:DD:EE:FF"},
		},
	}

	t.Run("found", func(t *testing.T) {
		device, err := findDeviceByName(cfg, "Device 2")
		require.NoError(t, err)
		require.NotNil(t, device)
		assert.Equal(t, "AA:BB:CC:DD:EE:FF", device.Address)
	})

	t.Run("not_found", func(t *testing.T) {
		device, err := findDeviceByName(cfg, "NonExistent")
		require.NoError(t, err)
		assert.Nil(t, device)
	})
}

// TestFindDeviceByName_Ambiguous pins #1315: two paired records sharing a
// name must refuse the lookup with ErrDeviceNameAmbiguous rather than
// silently returning whichever record happens to be first in the file.
func TestFindDeviceByName_Ambiguous(t *testing.T) {
	cfg := &DevicesConfig{
		Devices: []PairedDevice{
			{Name: "Shared", Address: "11:22:33:44:55:66"},
			{Name: "Shared", Address: "AA:BB:CC:DD:EE:FF"},
		},
	}

	device, err := findDeviceByName(cfg, "Shared")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDeviceNameAmbiguous)
	assert.Nil(t, device)
}

func TestFindDeviceByAddress(t *testing.T) {
	cfg := &DevicesConfig{
		Devices: []PairedDevice{
			{Name: "Device 1", Address: "11:22:33:44:55:66"},
			{Name: "Device 2", Address: "AA:BB:CC:DD:EE:FF"},
		},
	}

	t.Run("found", func(t *testing.T) {
		device := findDeviceByAddress(cfg, "11:22:33:44:55:66")
		require.NotNil(t, device)
		assert.Equal(t, "Device 1", device.Name)
	})

	t.Run("not_found", func(t *testing.T) {
		device := findDeviceByAddress(cfg, "00:00:00:00:00:00")
		assert.Nil(t, device)
	})
}

func TestTruncateKey(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "long_key",
			input:    "dGVzdC1wdWJsaWMta2V5LXRoYXQtaXMtdmVyeS1sb25n",
			expected: "dGVzdC1wdWJsaWMt",
		},
		{
			name:     "short_key",
			input:    "short",
			expected: "short",
		},
		{
			name:     "exactly_16",
			input:    "1234567890123456",
			expected: "1234567890123456",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := truncateKey(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestEncodeDecodePublicKey(t *testing.T) {
	originalKey := []byte{0x01, 0x02, 0x03, 0x04, 0x05}

	encoded := encodePublicKey(originalKey)
	assert.NotEmpty(t, encoded)

	decoded, err := decodePublicKey(encoded)
	require.NoError(t, err)
	assert.Equal(t, originalKey, decoded)
}

func TestDecodePublicKey_Invalid(t *testing.T) {
	_, err := decodePublicKey("not-valid-base64!!!")
	assert.Error(t, err)
}

func TestPhoneListCmd_NoDevices(t *testing.T) {
	// Create temporary directory without config
	tempDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	t.Setenv("HOME", tempDir)
	defer os.Setenv("HOME", originalHome)

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := runDeviceList(deviceListCmd, []string{})
	require.NoError(t, err)

	w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	buf.ReadFrom(r)
	assert.Contains(t, buf.String(), "No paired devices")
}

func TestPhoneListCmd_WithDevices(t *testing.T) {
	// Create temporary directory with config
	tempDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	t.Setenv("HOME", tempDir)
	defer os.Setenv("HOME", originalHome)

	// Create config directory
	xkeyDir := filepath.Join(tempDir, ".xkey")
	err := os.MkdirAll(xkeyDir, 0700)
	require.NoError(t, err)

	// Save test configuration
	cfg := &DevicesConfig{
		Devices: []PairedDevice{
			{
				Name:           "Test Phone",
				Address:        "AA:BB:CC:DD:EE:FF",
				NoisePublicKey: "dGVzdC1wdWJsaWMta2V5LWxvbmctZW5vdWdo",
				PairedAt:       time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC),
			},
		},
		DefaultDevice: "Test Phone",
	}
	err = saveDevicesConfig(cfg)
	require.NoError(t, err)

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err = runDeviceList(deviceListCmd, []string{})
	require.NoError(t, err)

	w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	assert.Contains(t, output, "Paired Devices (1)")
	assert.Contains(t, output, "Test Phone")
	assert.Contains(t, output, "AA:BB:CC:DD:EE:FF")
	assert.Contains(t, output, "(default)")
}

func TestPhoneStatusCmd_NoDevices(t *testing.T) {
	// Create temporary directory without config
	tempDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	t.Setenv("HOME", tempDir)
	defer os.Setenv("HOME", originalHome)

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := runDeviceStatus(deviceStatusCmd, []string{})
	require.NoError(t, err)

	w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	buf.ReadFrom(r)
	assert.Contains(t, buf.String(), "No paired devices")
}

func TestPhoneUnpairCmd_NotPaired(t *testing.T) {
	// Create temporary directory without config
	tempDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	t.Setenv("HOME", tempDir)
	defer os.Setenv("HOME", originalHome)

	err := runDeviceUnpair(deviceUnpairCmd, []string{"NonExistent"})
	assert.ErrorIs(t, err, ErrDeviceNotPaired)
}

func TestPhoneUnpairCmd_DeviceNotFound(t *testing.T) {
	// Create temporary directory with config
	tempDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	t.Setenv("HOME", tempDir)
	defer os.Setenv("HOME", originalHome)

	// Create config directory and file
	xkeyDir := filepath.Join(tempDir, ".xkey")
	err := os.MkdirAll(xkeyDir, 0700)
	require.NoError(t, err)

	cfg := &DevicesConfig{
		Devices: []PairedDevice{
			{Name: "Other Device", Address: "11:22:33:44:55:66"},
		},
		DefaultDevice: "Other Device",
	}
	err = saveDevicesConfig(cfg)
	require.NoError(t, err)

	err = runDeviceUnpair(deviceUnpairCmd, []string{"NonExistent"})
	assert.ErrorContains(t, err, "device not found")
}

func TestPhoneStatusCmd_WithDevices(t *testing.T) {
	tempDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	t.Setenv("HOME", tempDir)
	defer os.Setenv("HOME", originalHome)

	require.NoError(t, os.MkdirAll(filepath.Join(tempDir, ".xkey"), 0700))

	cfg := &DevicesConfig{
		Devices: []PairedDevice{
			{Name: "Office Phone", Address: "AA:BB:CC:DD:EE:FF", PairedAt: time.Now()},
			{Name: "Home Phone", Address: "11:22:33:44:55:66", PairedAt: time.Now()},
		},
		DefaultDevice: "Office Phone",
	}
	require.NoError(t, saveDevicesConfig(cfg))

	var buf bytes.Buffer
	deviceStatusCmd.SetOut(&buf)
	t.Cleanup(func() { deviceStatusCmd.SetOut(nil) })

	require.NoError(t, runDeviceStatus(deviceStatusCmd, nil))
	out := buf.String()
	assert.Contains(t, out, "Office Phone (default)")
	assert.Contains(t, out, "Home Phone")
	assert.Contains(t, out, "Paired (connection check requires BLE)")
}

func TestPhoneStatusCmd_FiltersByDeviceFlag(t *testing.T) {
	tempDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	t.Setenv("HOME", tempDir)
	defer os.Setenv("HOME", originalHome)

	require.NoError(t, os.MkdirAll(filepath.Join(tempDir, ".xkey"), 0700))
	cfg := &DevicesConfig{
		Devices: []PairedDevice{
			{Name: "Office Phone", Address: "AA:BB:CC:DD:EE:FF"},
			{Name: "Home Phone", Address: "11:22:33:44:55:66"},
		},
	}
	require.NoError(t, saveDevicesConfig(cfg))

	require.NoError(t, setFlagForTest(t, deviceStatusCmd.Flags(), "device", "Home Phone"))
	t.Cleanup(func() { _ = setFlagForTest(t, deviceStatusCmd.Flags(), "device", "") })

	var buf bytes.Buffer
	deviceStatusCmd.SetOut(&buf)
	t.Cleanup(func() { deviceStatusCmd.SetOut(nil) })

	require.NoError(t, runDeviceStatus(deviceStatusCmd, nil))
	out := buf.String()
	assert.Contains(t, out, "Home Phone")
	assert.NotContains(t, out, "Office Phone")
}

func TestPhoneUnpairCmd_ForceRemovesDevice(t *testing.T) {
	tempDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	t.Setenv("HOME", tempDir)
	defer os.Setenv("HOME", originalHome)

	require.NoError(t, os.MkdirAll(filepath.Join(tempDir, ".xkey"), 0700))
	cfg := &DevicesConfig{
		Devices: []PairedDevice{
			{Name: "Office Phone", Address: "AA:BB:CC:DD:EE:FF"},
		},
		DefaultDevice: "Office Phone",
	}
	require.NoError(t, saveDevicesConfig(cfg))

	require.NoError(t, setFlagForTest(t, deviceUnpairCmd.Flags(), "force", "true"))
	t.Cleanup(func() { _ = setFlagForTest(t, deviceUnpairCmd.Flags(), "force", "false") })

	var buf bytes.Buffer
	deviceUnpairCmd.SetOut(&buf)
	t.Cleanup(func() { deviceUnpairCmd.SetOut(nil) })

	require.NoError(t, runDeviceUnpair(deviceUnpairCmd, []string{"Office Phone"}))
	assert.Contains(t, buf.String(), "unpaired successfully")

	updated, err := loadDevicesConfig()
	require.NoError(t, err)
	assert.Empty(t, updated.Devices, "the forced unpair must remove the device")
	assert.Empty(t, updated.DefaultDevice, "removing the only device must clear the default")
}

func TestCheckDeviceStatus_ReportsPairedWithoutBLE(t *testing.T) {
	status := checkDeviceStatus(PairedDevice{Name: "Office Phone"}, nil)
	assert.Equal(t, "Paired (connection check requires BLE)", status)
}

func TestPhoneErrors(t *testing.T) {
	// Test that all errors have proper messages
	errors := []error{
		ErrDeviceBLEUnavailable,
		ErrDeviceNoDevicesFound,
		ErrDevicePairingCancelled,
		ErrDeviceNotPaired,
		ErrDeviceConfigSaveFailed,
		ErrDeviceConfigLoadFailed,
		ErrDeviceNotFound,
		ErrDeviceNotConnected,
		ErrDeviceAlreadyPaired,
	}

	for _, err := range errors {
		assert.NotEmpty(t, err.Error(), "error should have a message")
		assert.Contains(t, err.Error(), "device:", "error should be prefixed with 'device:'")
	}
}

func TestGetPhoneConfigPath(t *testing.T) {
	tempDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	t.Setenv("HOME", tempDir)
	defer os.Setenv("HOME", originalHome)

	path, err := getDevicesConfigPath()
	require.NoError(t, err)

	expected := filepath.Join(tempDir, ".xkey", devicesConfigFileName)
	assert.Equal(t, expected, path)
}

func TestPhoneConfig_MultipleDevices(t *testing.T) {
	tempDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	t.Setenv("HOME", tempDir)
	defer os.Setenv("HOME", originalHome)

	// Create config directory
	xkeyDir := filepath.Join(tempDir, ".xkey")
	err := os.MkdirAll(xkeyDir, 0700)
	require.NoError(t, err)

	// Test with multiple devices
	cfg := &DevicesConfig{
		Devices: []PairedDevice{
			{Name: "Phone 1", Address: "11:22:33:44:55:66", PairedAt: time.Now()},
			{Name: "Phone 2", Address: "AA:BB:CC:DD:EE:FF", PairedAt: time.Now()},
			{Name: "Phone 3", Address: "12:34:56:78:9A:BC", PairedAt: time.Now()},
		},
		DefaultDevice: "Phone 2",
	}

	err = saveDevicesConfig(cfg)
	require.NoError(t, err)

	loadedCfg, err := loadDevicesConfig()
	require.NoError(t, err)

	assert.Len(t, loadedCfg.Devices, 3)
	assert.Equal(t, "Phone 2", loadedCfg.DefaultDevice)
}
