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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- PIV phone-list command structure tests ---

func TestPIVPhoneListCmd_Structure(t *testing.T) {
	assert.NotNil(t, pivDeviceListCmd)
	assert.Equal(t, "phone-list", pivDeviceListCmd.Use)
	assert.NotEmpty(t, pivDeviceListCmd.Short)
	assert.NotEmpty(t, pivDeviceListCmd.Long)
	assert.NotNil(t, pivDeviceListCmd.RunE)
}

func TestPIVPhoneListCmd_Flags(t *testing.T) {
	flags := []string{"device", "timeout"}
	for _, name := range flags {
		t.Run(name, func(t *testing.T) {
			flag := pivDeviceListCmd.Flags().Lookup(name)
			assert.NotNil(t, flag, "flag %q should exist on phone-list command", name)
		})
	}
}

func TestPIVPhoneListCmd_FlagDefaults(t *testing.T) {
	t.Run("device_default_empty", func(t *testing.T) {
		flag := pivDeviceListCmd.Flags().Lookup("device")
		require.NotNil(t, flag)
		assert.Equal(t, "", flag.DefValue)
	})

	t.Run("timeout_default_60s", func(t *testing.T) {
		flag := pivDeviceListCmd.Flags().Lookup("timeout")
		require.NotNil(t, flag)
		assert.Equal(t, "1m0s", flag.DefValue)
	})
}

// --- PIV phone-push-cert command structure tests ---

func TestPIVPhonePushCertCmd_Structure(t *testing.T) {
	assert.NotNil(t, pivDevicePushCertCmd)
	assert.Equal(t, "phone-push-cert <slot> <cert-file>", pivDevicePushCertCmd.Use)
	assert.NotEmpty(t, pivDevicePushCertCmd.Short)
	assert.NotEmpty(t, pivDevicePushCertCmd.Long)
	assert.NotNil(t, pivDevicePushCertCmd.RunE)
}

func TestPIVPhonePushCertCmd_Args(t *testing.T) {
	err := pivDevicePushCertCmd.Args(pivDevicePushCertCmd, []string{"9a"})
	assert.Error(t, err, "phone-push-cert should require exactly 2 args")

	err = pivDevicePushCertCmd.Args(pivDevicePushCertCmd, []string{"9a", "cert.pem"})
	assert.NoError(t, err, "phone-push-cert should accept exactly 2 args")

	err = pivDevicePushCertCmd.Args(pivDevicePushCertCmd, []string{"9a", "cert.pem", "extra"})
	assert.Error(t, err, "phone-push-cert should reject more than 2 args")
}

func TestPIVPhonePushCertCmd_Flags(t *testing.T) {
	flags := []string{"device", "timeout"}
	for _, name := range flags {
		t.Run(name, func(t *testing.T) {
			flag := pivDevicePushCertCmd.Flags().Lookup(name)
			assert.NotNil(t, flag, "flag %q should exist on phone-push-cert command", name)
		})
	}
}

// --- PIV phone-pull-cert command structure tests ---

func TestPIVPhonePullCertCmd_Structure(t *testing.T) {
	assert.NotNil(t, pivDevicePullCertCmd)
	assert.Equal(t, "phone-pull-cert <slot>", pivDevicePullCertCmd.Use)
	assert.NotEmpty(t, pivDevicePullCertCmd.Short)
	assert.NotEmpty(t, pivDevicePullCertCmd.Long)
	assert.NotNil(t, pivDevicePullCertCmd.RunE)
}

func TestPIVPhonePullCertCmd_Args(t *testing.T) {
	err := pivDevicePullCertCmd.Args(pivDevicePullCertCmd, []string{})
	assert.Error(t, err, "phone-pull-cert should require exactly 1 arg")

	err = pivDevicePullCertCmd.Args(pivDevicePullCertCmd, []string{"9a"})
	assert.NoError(t, err, "phone-pull-cert should accept exactly 1 arg")

	err = pivDevicePullCertCmd.Args(pivDevicePullCertCmd, []string{"9a", "extra"})
	assert.Error(t, err, "phone-pull-cert should reject more than 1 arg")
}

func TestPIVPhonePullCertCmd_Flags(t *testing.T) {
	flags := []string{"device", "timeout", "output"}
	for _, name := range flags {
		t.Run(name, func(t *testing.T) {
			flag := pivDevicePullCertCmd.Flags().Lookup(name)
			assert.NotNil(t, flag, "flag %q should exist on phone-pull-cert command", name)
		})
	}
}

func TestPIVPhonePullCertCmd_FlagDefaults(t *testing.T) {
	t.Run("output_default_empty", func(t *testing.T) {
		flag := pivDevicePullCertCmd.Flags().Lookup("output")
		require.NotNil(t, flag)
		assert.Equal(t, "", flag.DefValue)
	})
}

// --- PIV phone-generate command structure tests ---

func TestPIVPhoneGenerateKeyCmd_Structure(t *testing.T) {
	assert.NotNil(t, pivDeviceGenerateKeyCmd)
	assert.Equal(t, "phone-generate <slot>", pivDeviceGenerateKeyCmd.Use)
	assert.NotEmpty(t, pivDeviceGenerateKeyCmd.Short)
	assert.NotEmpty(t, pivDeviceGenerateKeyCmd.Long)
	assert.NotNil(t, pivDeviceGenerateKeyCmd.RunE)
}

func TestPIVPhoneGenerateKeyCmd_Args(t *testing.T) {
	err := pivDeviceGenerateKeyCmd.Args(pivDeviceGenerateKeyCmd, []string{})
	assert.Error(t, err, "phone-generate should require exactly 1 arg")

	err = pivDeviceGenerateKeyCmd.Args(pivDeviceGenerateKeyCmd, []string{"9a"})
	assert.NoError(t, err, "phone-generate should accept exactly 1 arg")

	err = pivDeviceGenerateKeyCmd.Args(pivDeviceGenerateKeyCmd, []string{"9a", "extra"})
	assert.Error(t, err, "phone-generate should reject more than 1 arg")
}

func TestPIVPhoneGenerateKeyCmd_Flags(t *testing.T) {
	flags := []string{"device", "timeout", "algorithm"}
	for _, name := range flags {
		t.Run(name, func(t *testing.T) {
			flag := pivDeviceGenerateKeyCmd.Flags().Lookup(name)
			assert.NotNil(t, flag, "flag %q should exist on phone-generate command", name)
		})
	}
}

func TestPIVPhoneGenerateKeyCmd_FlagDefaults(t *testing.T) {
	t.Run("algorithm_default_ecdsa_p256", func(t *testing.T) {
		flag := pivDeviceGenerateKeyCmd.Flags().Lookup("algorithm")
		require.NotNil(t, flag)
		assert.Equal(t, "ECDSA-P256", flag.DefValue)
	})

	t.Run("algorithm_shorthand_a", func(t *testing.T) {
		flag := pivDeviceGenerateKeyCmd.Flags().ShorthandLookup("a")
		assert.NotNil(t, flag, "algorithm flag should have -a shorthand")
		assert.Equal(t, "algorithm", flag.Name)
	})
}

// --- PIV command hierarchy tests ---

func TestPIVCmd_PhoneSyncSubcommands(t *testing.T) {
	subcommands := PIVCmd.Commands()

	names := make(map[string]bool)
	for _, cmd := range subcommands {
		names[cmd.Name()] = true
	}

	assert.True(t, names["phone-list"], "piv should have phone-list subcommand")
	assert.True(t, names["phone-push-cert"], "piv should have phone-push-cert subcommand")
	assert.True(t, names["phone-pull-cert"], "piv should have phone-pull-cert subcommand")
	assert.True(t, names["phone-generate"], "piv should have phone-generate subcommand")
}

// --- PIV phone sync error tests ---

func TestPIVPhoneSyncErrors(t *testing.T) {
	syncErrors := []struct {
		err      error
		contains string
	}{
		{ErrPIVDeviceSyncFailed, "piv: phone sync failed"},
		{ErrPIVDevicePushCertFailed, "piv: push certificate to phone failed"},
		{ErrPIVDevicePullCertFailed, "piv: pull certificate from phone failed"},
		{ErrPIVDeviceListSlotsFailed, "piv: list phone slots failed"},
		{ErrPIVDeviceGenerateKeyFailed, "piv: generate key on phone failed"},
	}

	for _, tc := range syncErrors {
		t.Run(tc.contains, func(t *testing.T) {
			assert.NotNil(t, tc.err)
			assert.Equal(t, tc.contains, tc.err.Error())
			assert.Contains(t, tc.err.Error(), "piv:")
		})
	}
}

func TestPIVPhoneSyncErrors_AreDistinct(t *testing.T) {
	errs := []error{
		ErrPIVDeviceSyncFailed,
		ErrPIVDevicePushCertFailed,
		ErrPIVDevicePullCertFailed,
		ErrPIVDeviceListSlotsFailed,
		ErrPIVDeviceGenerateKeyFailed,
	}

	for i := 0; i < len(errs); i++ {
		for j := i + 1; j < len(errs); j++ {
			assert.NotEqual(t, errs[i].Error(), errs[j].Error(),
				"errors at index %d and %d should be distinct", i, j)
		}
	}
}

// --- Helper function tests ---

func TestTruncateSlotLabel(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"short_label", "my-key", "my-key"},
		{"exactly_24", "123456789012345678901234", "123456789012345678901234"},
		{"long_label", "this-is-a-very-long-label-for-testing", "this-is-a-very-long-l..."},
		{"empty_label", "", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := truncateSlotLabel(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}
