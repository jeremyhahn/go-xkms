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
