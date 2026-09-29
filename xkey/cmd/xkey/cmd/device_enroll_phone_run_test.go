// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

//go:build ble

package cmd

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnrollPhone_NoConfig(t *testing.T) {
	deviceInfoTestHome(t)
	err := enrollPhone(context.Background(), &enrollPhoneOptions{CASource: "local"}, discardLogger())
	require.ErrorIs(t, err, ErrDeviceNotPaired)
}

func TestEnrollPhone_EmptyDevices(t *testing.T) {
	deviceInfoTestHome(t)
	require.NoError(t, saveDevicesConfig(&DevicesConfig{}))

	err := enrollPhone(context.Background(), &enrollPhoneOptions{CASource: "local"}, discardLogger())
	require.ErrorIs(t, err, ErrDeviceNotPaired)
}

func TestEnrollPhone_DeviceNotFound(t *testing.T) {
	deviceInfoTestHome(t)
	require.NoError(t, saveDevicesConfig(&DevicesConfig{Devices: []PairedDevice{brokenNoiseKeyDevice("A")}}))

	opts := &enrollPhoneOptions{CASource: "local", DeviceFilter: "Nonexistent"}
	err := enrollPhone(context.Background(), opts, discardLogger())
	require.ErrorIs(t, err, ErrDeviceNotFound)
}

func TestEnrollPhone_SessionOpenFailure(t *testing.T) {
	deviceInfoTestHome(t)
	require.NoError(t, saveDevicesConfig(&DevicesConfig{Devices: []PairedDevice{brokenNoiseKeyDevice("A")}}))

	opts := &enrollPhoneOptions{CASource: "local"}
	err := enrollPhone(context.Background(), opts, discardLogger())
	require.ErrorIs(t, err, ErrSessionKeyDecode)
}

func TestRunDeviceEnrollPhone_NoConfig(t *testing.T) {
	deviceInfoTestHome(t)
	cmd := deviceEnrollPhoneCmd
	cmd.SetContext(context.Background())

	err := runDeviceEnrollPhone(cmd, nil)
	require.ErrorIs(t, err, ErrDeviceNotPaired)
}

// TestDeviceEnrollPhoneOptionsFromFlags_ReflectsParsedFlags proves that
// every enroll-phone flag reaches enrollPhoneOptions after cobra parses
// it, rather than being silently dropped as a discarded f.GetString/
// GetDuration/GetBool/GetStringSlice error would leave it at its zero
// value.
func TestDeviceEnrollPhoneOptionsFromFlags_ReflectsParsedFlags(t *testing.T) {
	f := deviceEnrollPhoneCmd.Flags()
	t.Cleanup(func() {
		deviceEnrollPhoneDevice = ""
		deviceEnrollPhoneCA = "local"
		deviceEnrollPhoneValidity = 0
		deviceEnrollPhoneAllowPackages = nil
		deviceEnrollPhoneAllowSigners = nil
		deviceEnrollPhoneAllowUnpinned = false
		deviceEnrollPhoneMinSecurityLevel = "trusted_environment"
		deviceEnrollPhoneRequireVerifiedBoot = true
		deviceEnrollPhoneSubject = ""
	})

	require.NoError(t, f.Set("device", "my-phone"))
	require.NoError(t, f.Set("ca", "xkms"))
	require.NoError(t, f.Set("validity", "720h"))
	require.NoError(t, f.Set("allow-package", "com.automatethethings.xkey"))
	require.NoError(t, f.Set("allow-signer", "abcd1234"))
	require.NoError(t, f.Set("allow-unpinned", "true"))
	require.NoError(t, f.Set("min-security-level", "strongbox"))
	require.NoError(t, f.Set("require-verified-boot", "false"))
	require.NoError(t, f.Set("subject", "CN=test"))

	opts := deviceEnrollPhoneOptionsFromFlags()
	assert.Equal(t, "my-phone", opts.DeviceFilter)
	assert.Equal(t, "xkms", opts.CASource)
	assert.Equal(t, 720*time.Hour, opts.Validity)
	assert.Equal(t, []string{"com.automatethethings.xkey"}, opts.AllowPackages)
	assert.Equal(t, []string{"abcd1234"}, opts.AllowSigners)
	assert.True(t, opts.AllowUnpinned)
	assert.Equal(t, "strongbox", opts.MinSecurityLevel)
	assert.False(t, opts.RequireVerifiedBoot)
	assert.Equal(t, "CN=test", opts.Subject)
}
