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

package gui

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewTrayManager verifies the constructor wires the App reference and a
// component logger without touching the systray package (which requires a
// live OS tray / display to do anything beyond field assignment).
func TestNewTrayManager(t *testing.T) {
	app := &App{log: lifecycleTestLogger()}
	tray := NewTrayManager(app)
	require.NotNil(t, tray)
	assert.Same(t, app, tray.app)
	assert.NotNil(t, tray.log)
}

// TestTrayManager_UpdateMethods_NilMenuItemsNoOp verifies every Update*
// method degrades to a safe no-op (rather than a nil-pointer panic on the
// underlying *systray.MenuItem) before onReady has run -- the state every
// TrayManager is in immediately after NewTrayManager, and for the entire
// life of a headless test process that never calls systray.Run.
func TestTrayManager_UpdateMethods_NilMenuItemsNoOp(t *testing.T) {
	app := &App{log: lifecycleTestLogger()}
	tray := NewTrayManager(app)

	assert.NotPanics(t, func() {
		tray.UpdateStatus("Ready")
		tray.UpdatePhoneStatus(true, "Pixel 8")
		tray.UpdatePhoneStatus(false, "")
		tray.UpdateKeyCount(3)
		tray.UpdateStorageStatus(true)
		tray.UpdateStorageStatus(false)
	})
}

// TestIntToLabel covers intToLabel's hand-rolled itoa: zero, positive,
// negative, and multi-digit inputs.
func TestIntToLabel(t *testing.T) {
	tests := []struct {
		name string
		n    int
		want string
	}{
		{"zero", 0, "0"},
		{"single digit", 7, "7"},
		{"multi digit", 1234, "1234"},
		{"negative", -42, "-42"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, intToLabel(tc.n))
		})
	}
}
