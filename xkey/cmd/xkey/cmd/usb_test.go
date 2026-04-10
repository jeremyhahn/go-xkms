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

// --- Parent command structure ---

func TestUSBCmd_Structure(t *testing.T) {
	assert.NotNil(t, usbCmd)
	assert.Equal(t, "usb", usbCmd.Use)
	assert.NotEmpty(t, usbCmd.Short)
	assert.NotEmpty(t, usbCmd.Long)
}

func TestUSBCmd_RegisteredOnRoot(t *testing.T) {
	found := false
	for _, cmd := range RootCmd.Commands() {
		if cmd.Name() == "usb" {
			found = true
			break
		}
	}
	assert.True(t, found, "usb command should be registered on root")
}

func TestUSBCmd_Subcommands(t *testing.T) {
	subcommands := usbCmd.Commands()

	names := make(map[string]bool)
	for _, cmd := range subcommands {
		names[cmd.Name()] = true
	}

	assert.True(t, names["create"], "usb should have create subcommand")
	assert.True(t, names["status"], "usb should have status subcommand")
	assert.True(t, names["update"], "usb should have update subcommand")
}

// --- Create command structure ---

func TestUSBCreateCmd_Structure(t *testing.T) {
	assert.NotNil(t, usbCreateCmd)
	assert.Equal(t, "create <device-or-image>", usbCreateCmd.Use)
	assert.NotEmpty(t, usbCreateCmd.Short)
	assert.NotEmpty(t, usbCreateCmd.Long)
	assert.NotNil(t, usbCreateCmd.RunE)
}

func TestUSBCreateCmd_Args(t *testing.T) {
	err := usbCreateCmd.Args(usbCreateCmd, []string{})
	assert.Error(t, err, "create should require exactly 1 arg")

	err = usbCreateCmd.Args(usbCreateCmd, []string{"/tmp/test.img"})
	assert.NoError(t, err, "create should accept exactly 1 arg")

	err = usbCreateCmd.Args(usbCreateCmd, []string{"a", "b"})
	assert.Error(t, err, "create should reject more than 1 arg")
}

func TestUSBCreateCmd_Flags(t *testing.T) {
	flags := []string{"size", "binary"}
	for _, name := range flags {
		t.Run(name, func(t *testing.T) {
			flag := usbCreateCmd.Flags().Lookup(name)
			assert.NotNil(t, flag, "flag %q should exist on create command", name)
		})
	}
}

func TestUSBCreateCmd_SizeDefault(t *testing.T) {
	flag := usbCreateCmd.Flags().Lookup("size")
	require.NotNil(t, flag)
	assert.Equal(t, "4G", flag.DefValue)
}

// --- Status command structure ---

func TestUSBStatusCmd_Structure(t *testing.T) {
	assert.NotNil(t, usbStatusCmd)
	assert.Equal(t, "status [device-or-image]", usbStatusCmd.Use)
	assert.NotEmpty(t, usbStatusCmd.Short)
	assert.NotEmpty(t, usbStatusCmd.Long)
	assert.NotNil(t, usbStatusCmd.RunE)
}

func TestUSBStatusCmd_Args(t *testing.T) {
	err := usbStatusCmd.Args(usbStatusCmd, []string{})
	assert.Error(t, err, "status should require exactly 1 arg")

	err = usbStatusCmd.Args(usbStatusCmd, []string{"/tmp/test.img"})
	assert.NoError(t, err, "status should accept exactly 1 arg")

	err = usbStatusCmd.Args(usbStatusCmd, []string{"a", "b"})
	assert.Error(t, err, "status should reject more than 1 arg")
}

// --- Update command structure ---

func TestUSBUpdateCmd_Structure(t *testing.T) {
	assert.NotNil(t, usbUpdateCmd)
	assert.Equal(t, "update <device-or-image>", usbUpdateCmd.Use)
	assert.NotEmpty(t, usbUpdateCmd.Short)
	assert.NotEmpty(t, usbUpdateCmd.Long)
	assert.NotNil(t, usbUpdateCmd.RunE)
}

func TestUSBUpdateCmd_Args(t *testing.T) {
	err := usbUpdateCmd.Args(usbUpdateCmd, []string{})
	assert.Error(t, err, "update should require exactly 1 arg")

	err = usbUpdateCmd.Args(usbUpdateCmd, []string{"/tmp/test.img"})
	assert.NoError(t, err, "update should accept exactly 1 arg")

	err = usbUpdateCmd.Args(usbUpdateCmd, []string{"a", "b"})
	assert.Error(t, err, "update should reject more than 1 arg")
}

func TestUSBUpdateCmd_Flags(t *testing.T) {
	flag := usbUpdateCmd.Flags().Lookup("binary")
	assert.NotNil(t, flag, "binary flag should exist on update command")
}

// --- Error type tests ---

func TestUSBCmdError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *USBCmdError
		expected string
	}{
		{
			name: "with error and message",
			err: &USBCmdError{
				Operation: "create",
				Message:   "device busy",
				Err:       errors.New("ioctl failed"),
			},
			expected: "usb: create: device busy: ioctl failed",
		},
		{
			name: "with error only",
			err: &USBCmdError{
				Operation: "format",
				Err:       errors.New("mkfs failed"),
			},
			expected: "usb: format: mkfs failed",
		},
		{
			name: "with message only",
			err: &USBCmdError{
				Operation: "validate",
				Message:   "passphrase cannot be empty",
			},
			expected: "usb: validate: passphrase cannot be empty",
		},
		{
			name:     "operation only",
			err:      &USBCmdError{Operation: "unknown"},
			expected: "usb: unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestUSBCmdError_Unwrap(t *testing.T) {
	underlying := errors.New("base error")
	err := &USBCmdError{
		Operation: "test",
		Err:       underlying,
	}

	assert.Equal(t, underlying, err.Unwrap())
	assert.True(t, errors.Is(err, underlying))
}

func TestUSBCmdError_ErrorsAs(t *testing.T) {
	err := &USBCmdError{
		Operation: "create",
		Message:   "failed",
		Err:       errors.New("base"),
	}

	var target *USBCmdError
	assert.True(t, errors.As(err, &target))
	assert.Equal(t, "create", target.Operation)
	assert.Equal(t, "failed", target.Message)
}

// --- Sentinel error tests ---

func TestUSBSentinelErrors(t *testing.T) {
	tests := []struct {
		err      *USBCmdError
		contains string
	}{
		{ErrUSBPassphraseRead, "read_passphrase"},
		{ErrUSBCreateFailed, "create"},
		{ErrUSBStatusFailed, "status"},
		{ErrUSBUpdateFailed, "update"},
	}

	for _, tc := range tests {
		t.Run(tc.contains, func(t *testing.T) {
			assert.NotNil(t, tc.err)
			assert.Contains(t, tc.err.Error(), tc.contains)
			assert.Contains(t, tc.err.Error(), "usb:")
		})
	}
}

func TestUSBSentinelErrors_AreDistinct(t *testing.T) {
	errs := []*USBCmdError{
		ErrUSBPassphraseRead,
		ErrUSBCreateFailed,
		ErrUSBStatusFailed,
		ErrUSBUpdateFailed,
	}

	for i := 0; i < len(errs); i++ {
		for j := i + 1; j < len(errs); j++ {
			assert.NotEqual(t, errs[i].Error(), errs[j].Error(),
				"errors at index %d and %d should be distinct", i, j)
		}
	}
}

// --- LUKS exempt tests ---

func TestUSBCommandsAreLUKSExempt(t *testing.T) {
	exemptNames := []string{"usb", "create", "update"}
	for _, name := range exemptNames {
		t.Run(name, func(t *testing.T) {
			assert.True(t, luksExemptCommands[name],
				"%q should be in luksExemptCommands", name)
		})
	}
}

// --- Status command execution ---

func TestRunUSBStatus_NonExistentPath(t *testing.T) {
	var buf bytes.Buffer
	usbStatusCmd.SetOut(&buf)

	err := runUSBStatus(usbStatusCmd, []string{"/nonexistent/image.img"})
	assert.Error(t, err)

	var usbErr *USBCmdError
	assert.True(t, errors.As(err, &usbErr))
	assert.Equal(t, "get_status", usbErr.Operation)
}

// --- Create command validation ---

func TestRunUSBCreate_MissingBinary(t *testing.T) {
	// Set a binary flag to a non-existent file.
	usbBinaries = []string{"/nonexistent/binary"}
	defer func() { usbBinaries = nil }()

	var buf bytes.Buffer
	usbCreateCmd.SetOut(&buf)

	err := runUSBCreate(usbCreateCmd, []string{"/tmp/test.img"})
	assert.Error(t, err)

	var usbErr *USBCmdError
	assert.True(t, errors.As(err, &usbErr))
	assert.Equal(t, "validate_binary", usbErr.Operation)
}
