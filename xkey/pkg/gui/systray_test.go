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
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/services"
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

// writeDevicesYAML sandboxes PhoneService's shared config file
// (~/.xkey/devices.yaml, resolved from $HOME) under a temp directory and
// writes the given raw YAML body into it, so a test can pre-populate paired
// devices without reaching into the unexported services.phoneConfigDevice
// type from this package.
func writeDevicesYAML(t *testing.T, yamlBody string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	xkeyDir := filepath.Join(home, ".xkey")
	require.NoError(t, os.MkdirAll(xkeyDir, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(xkeyDir, "devices.yaml"), []byte(yamlBody), 0600))
}

// TestTrayManager_HandlePhoneConnect_NoPairedDevices verifies the tray
// gracefully no-ops (rather than panicking on a nil menu item) when the
// operator clicks "Connect" and no phone has ever been paired -- the state
// of a headless test process, and of any real host before first pairing.
func TestTrayManager_HandlePhoneConnect_NoPairedDevices(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	app := &App{log: lifecycleTestLogger(), phoneService: services.NewPhoneService()}
	tray := NewTrayManager(app)

	assert.NotPanics(t, func() {
		tray.handlePhoneConnect()
	})
}

// TestTrayManager_HandlePhoneConnect_MissingKeysFails verifies the error path:
// a paired device record with no Noise keys (a config file hand-edited or
// left over from a broken pairing) is reported and does not panic.
func TestTrayManager_HandlePhoneConnect_MissingKeysFails(t *testing.T) {
	writeDevicesYAML(t, `
devices:
  - name: "Test Phone"
    address: "AA:BB:CC:DD:EE:FF"
    noise_public_key: ""
    local_noise_private_key: ""
default_device: "Test Phone"
`)

	app := &App{log: lifecycleTestLogger(), phoneService: services.NewPhoneService()}
	tray := NewTrayManager(app)

	assert.NotPanics(t, func() {
		tray.handlePhoneConnect()
	})
}

// TestTrayManager_HandlePhoneDisconnect_NotConnected verifies the tray
// no-ops when "Disconnect" is clicked with no phone currently connected.
func TestTrayManager_HandlePhoneDisconnect_NotConnected(t *testing.T) {
	app := &App{log: lifecycleTestLogger(), phoneService: services.NewPhoneService()}
	tray := NewTrayManager(app)

	assert.NotPanics(t, func() {
		tray.handlePhoneDisconnect()
	})
}

// TestTrayManager_HandlePhoneAttest_NotConnected verifies the tray no-ops
// when "Attest Device" is clicked with no phone currently connected.
func TestTrayManager_HandlePhoneAttest_NotConnected(t *testing.T) {
	app := &App{log: lifecycleTestLogger(), phoneService: services.NewPhoneService()}
	tray := NewTrayManager(app)

	assert.NotPanics(t, func() {
		tray.handlePhoneAttest()
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
