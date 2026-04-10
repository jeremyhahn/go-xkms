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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Parent device command structure ---

func TestUSBDeviceCmd_Structure(t *testing.T) {
	assert.NotNil(t, usbDeviceCmd)
	assert.Equal(t, "device", usbDeviceCmd.Use)
	assert.NotEmpty(t, usbDeviceCmd.Short)
	assert.NotEmpty(t, usbDeviceCmd.Long)
}

func TestUSBDeviceCmd_RegisteredOnUSB(t *testing.T) {
	found := false
	for _, cmd := range usbCmd.Commands() {
		if cmd.Name() == "device" {
			found = true
			break
		}
	}
	assert.True(t, found, "device command should be registered on usb")
}

func TestUSBDeviceCmd_Subcommands(t *testing.T) {
	subcommands := usbDeviceCmd.Commands()

	names := make(map[string]bool)
	for _, cmd := range subcommands {
		names[cmd.Name()] = true
	}

	assert.True(t, names["start"], "device should have start subcommand")
	assert.True(t, names["stop"], "device should have stop subcommand")
	assert.True(t, names["status"], "device should have status subcommand")
}

// --- Start command structure ---

func TestUSBDeviceStartCmd_Structure(t *testing.T) {
	assert.NotNil(t, usbDeviceStartCmd)
	assert.Equal(t, "start", usbDeviceStartCmd.Use)
	assert.NotEmpty(t, usbDeviceStartCmd.Short)
	assert.NotEmpty(t, usbDeviceStartCmd.Long)
	assert.NotNil(t, usbDeviceStartCmd.RunE)
}

func TestUSBDeviceStartCmd_Flags(t *testing.T) {
	flag := usbDeviceStartCmd.Flags().Lookup("device-backend")
	require.NotNil(t, flag, "device-backend flag should exist")
	assert.Equal(t, defaultUSBDeviceBackend, flag.DefValue)
}

// --- Stop command structure ---

func TestUSBDeviceStopCmd_Structure(t *testing.T) {
	assert.NotNil(t, usbDeviceStopCmd)
	assert.Equal(t, "stop", usbDeviceStopCmd.Use)
	assert.NotEmpty(t, usbDeviceStopCmd.Short)
	assert.NotEmpty(t, usbDeviceStopCmd.Long)
	assert.NotNil(t, usbDeviceStopCmd.RunE)
}

func TestUSBDeviceStopCmd_Output(t *testing.T) {
	var buf bytes.Buffer
	usbDeviceStopCmd.SetOut(&buf)

	err := runUSBDeviceStop(usbDeviceStopCmd, nil)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "foreground")
	assert.Contains(t, output, "Ctrl+C")
	assert.Contains(t, output, "SIGTERM")
}

// --- Status command structure ---

func TestUSBDeviceStatusCmd_Structure(t *testing.T) {
	assert.NotNil(t, usbDeviceStatusCmd)
	assert.Equal(t, "status", usbDeviceStatusCmd.Use)
	assert.NotEmpty(t, usbDeviceStatusCmd.Short)
	assert.NotEmpty(t, usbDeviceStatusCmd.Long)
	assert.NotNil(t, usbDeviceStatusCmd.RunE)
}

func TestUSBDeviceStatusCmd_Output(t *testing.T) {
	var buf bytes.Buffer
	usbDeviceStatusCmd.SetOut(&buf)

	err := runUSBDeviceStatus(usbDeviceStatusCmd, nil)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "Virtual CCID Device Status")
	assert.Contains(t, output, "UHID interface")
	assert.Contains(t, output, "CCID device")
	assert.Contains(t, output, "Device name")
	assert.Contains(t, output, "xKey CCID Smartcard Reader")
	assert.Contains(t, output, "XKEYCCID001")
	assert.Contains(t, output, "0xF1D0")
	assert.Contains(t, output, "0x0004")
}

// --- Sentinel error tests ---

func TestUSBDeviceSentinelErrors_NotNil(t *testing.T) {
	errs := []struct {
		name string
		err  error
	}{
		{"ErrUSBDeviceStartFailed", ErrUSBDeviceStartFailed},
		{"ErrUSBDeviceCCIDCreateFailed", ErrUSBDeviceCCIDCreateFailed},
		{"ErrUSBDeviceBridgeCreateFailed", ErrUSBDeviceBridgeCreateFailed},
		{"ErrUSBDeviceTransportCreateFailed", ErrUSBDeviceTransportCreateFailed},
	}

	for _, tt := range errs {
		t.Run(tt.name, func(t *testing.T) {
			assert.NotNil(t, tt.err)
			assert.NotEmpty(t, tt.err.Error())
			assert.Contains(t, tt.err.Error(), "usb device:")
		})
	}
}

func TestUSBDeviceSentinelErrors_Distinct(t *testing.T) {
	errs := []error{
		ErrUSBDeviceStartFailed,
		ErrUSBDeviceCCIDCreateFailed,
		ErrUSBDeviceBridgeCreateFailed,
		ErrUSBDeviceTransportCreateFailed,
	}

	for i := 0; i < len(errs); i++ {
		for j := i + 1; j < len(errs); j++ {
			assert.NotEqual(t, errs[i].Error(), errs[j].Error(),
				"errors at index %d and %d should be distinct", i, j)
		}
	}
}

// --- LUKS exempt tests ---

func TestUSBDeviceCommandsAreLUKSExempt(t *testing.T) {
	exemptNames := []string{"device", "start", "stop"}
	for _, name := range exemptNames {
		t.Run(name, func(t *testing.T) {
			assert.True(t, luksExemptCommands[name],
				"%q should be in luksExemptCommands", name)
		})
	}
}

// --- Helper function tests ---

func TestCheckUHIDAvailable(t *testing.T) {
	// This is a best-effort test. The result depends on the host.
	// We just verify it does not panic and returns a boolean.
	result := checkUHIDAvailable()
	_ = result // Result is platform-dependent.
}

func TestCheckUSBDeviceRunning(t *testing.T) {
	// This is a best-effort test. The result depends on the host.
	// We just verify it does not panic and returns a boolean.
	result := checkUSBDeviceRunning()
	_ = result // Result is platform-dependent.
}

// --- Start command with uninitialized transport ---

func TestRunUSBDeviceStart_TransportNotInitialized(t *testing.T) {
	// The xkms singleton is not initialized in unit tests, so
	// NewEmbeddedTransport should fail.
	err := runUSBDeviceStart(usbDeviceStartCmd, nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUSBDeviceTransportCreateFailed),
		"should wrap ErrUSBDeviceTransportCreateFailed, got: %v", err)
}

// --- Default backend constant ---

func TestDefaultUSBDeviceBackend(t *testing.T) {
	assert.Equal(t, "software", defaultUSBDeviceBackend)
}
