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

// TestOpenDeviceSession_BadLocalKey exercises the failure branch that fires
// before any BLE transport is created: a LocalNoisePrivateKey that is not
// valid base64 fails at unsealDeviceLocalKey, so no Bluetooth adapter is
// ever touched.
func TestOpenDeviceSession_BadLocalKey(t *testing.T) {
	device := brokenNoiseKeyDevice("A")

	session, cleanup, err := openDeviceSession(context.Background(), &device, discardLogger())
	require.Nil(t, session)
	require.Nil(t, cleanup)
	require.ErrorIs(t, err, ErrSessionKeyDecode)
}

// TestOpenDeviceSession_BadRemoteKey covers the second decode guard: a
// syntactically valid local key but an unparseable stored NoisePublicKey,
// still short of any BLE transport creation.
func TestOpenDeviceSession_BadRemoteKey(t *testing.T) {
	device := PairedDevice{
		Name:                 "A",
		Address:              "11:22:33:44:55:66",
		LocalNoisePrivateKey: validLocalNoisePrivateKeyForTest(t),
		NoisePublicKey:       "not valid base64!!!",
	}

	session, cleanup, err := openDeviceSession(context.Background(), &device, discardLogger())
	require.Nil(t, session)
	require.Nil(t, cleanup)
	require.ErrorIs(t, err, ErrSessionKeyDecode)
}
