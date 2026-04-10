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

//go:build !ble

package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPhoneSyncStub_ReturnsBLEUnavailable(t *testing.T) {
	// In a non-BLE build, all sync commands should return
	// ErrDeviceBLEUnavailable.
	err := deviceSyncCmd.RunE(deviceSyncCmd, []string{})
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrDeviceBLEUnavailable)

	err = deviceSyncStatusCmd.RunE(deviceSyncStatusCmd, []string{})
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrDeviceBLEUnavailable)

	err = deviceSyncPushCmd.RunE(deviceSyncPushCmd, []string{})
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrDeviceBLEUnavailable)

	err = deviceSyncPullCmd.RunE(deviceSyncPullCmd, []string{})
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrDeviceBLEUnavailable)
}
