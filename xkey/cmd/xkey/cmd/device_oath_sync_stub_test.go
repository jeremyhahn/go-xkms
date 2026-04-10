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

func TestOATHSyncStub_ReturnsBLEUnavailable(t *testing.T) {
	// In a non-BLE build, sync/push/pull should return ErrDeviceBLEUnavailable.
	assert.NotNil(t, oathSyncPhoneCmd.RunE)
	assert.NotNil(t, oathPushPhoneCmd.RunE)
	assert.NotNil(t, oathPullPhoneCmd.RunE)

	err := oathSyncPhoneCmd.RunE(oathSyncPhoneCmd, []string{})
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrDeviceBLEUnavailable)

	err = oathPushPhoneCmd.RunE(oathPushPhoneCmd, []string{"test"})
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrDeviceBLEUnavailable)

	err = oathPullPhoneCmd.RunE(oathPullPhoneCmd, []string{})
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrDeviceBLEUnavailable)
}
