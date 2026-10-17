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

package gui

import (
	"testing"

	"fyne.io/systray"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/services"
)

// The systray menu is an in-memory layout until systray.Run exports it over
// D-Bus, so onReady builds and updates a real menu here without a session
// bus or a display.

// readyTray builds the tray menu for app and starts its click loop.
func readyTray(t *testing.T, app *App) *TrayManager {
	t.Helper()
	tray := NewTrayManager(app)
	tray.onReady()
	require.NotNil(t, tray.mStatus, "onReady must build the status item")
	return tray
}

// click delivers a click to item. The click loop receives one click at a
// time, so a second click returns only after the first has been handled.
func click(item *systray.MenuItem) {
	item.ClickedCh <- struct{}{}
}

// titleOf reports whether item's title is title.
func titleOf(t *testing.T, item *systray.MenuItem, title string) {
	t.Helper()
	assert.Contains(t, item.String(), `"`+title+`"`)
}

func TestTrayManager_OnReady_BuildsMenuInDisconnectedState(t *testing.T) {
	app, _, codes := windowedApp(t)
	tray := readyTray(t, app)

	titleOf(t, tray.mStatus, "xKey: Ready")
	assert.True(t, tray.mStatus.Disabled(), "the status item is informational")
	titleOf(t, tray.mPhoneStatus, "No device connected")
	assert.False(t, tray.mPhoneConn.Disabled(), "connect is offered while no phone is connected")
	assert.True(t, tray.mPhoneDisc.Disabled())
	assert.True(t, tray.mPhoneAttest.Disabled())
	assert.False(t, tray.mBridgeStart.Disabled())
	assert.True(t, tray.mBridgeStop.Disabled(), "stop is offered only once the bridge runs")
	titleOf(t, tray.mKeyCount, "Keys: 0")
	titleOf(t, tray.mStorageStatus, "Storage: Unknown")

	quitTray(t, tray, codes)
}

func TestTrayManager_UpdateMethods_RetitleBuiltMenu(t *testing.T) {
	app, _, codes := windowedApp(t)
	tray := readyTray(t, app)

	tray.UpdateStatus("Locked")
	titleOf(t, tray.mStatus, "xKey: Locked")

	tray.UpdatePhoneStatus(true, "Pixel 9")
	titleOf(t, tray.mPhoneStatus, "Connected: Pixel 9")
	assert.True(t, tray.mPhoneConn.Disabled(), "a connected phone cannot be connected again")
	assert.False(t, tray.mPhoneDisc.Disabled())
	assert.False(t, tray.mPhoneAttest.Disabled())

	tray.UpdatePhoneStatus(false, "")
	titleOf(t, tray.mPhoneStatus, "No device connected")
	assert.False(t, tray.mPhoneConn.Disabled())
	assert.True(t, tray.mPhoneDisc.Disabled())
	assert.True(t, tray.mPhoneAttest.Disabled())

	tray.UpdateKeyCount(12)
	titleOf(t, tray.mKeyCount, "Keys: 12")

	tray.UpdateStorageStatus(true)
	titleOf(t, tray.mStorageStatus, "Storage: Mounted")
	tray.UpdateStorageStatus(false)
	titleOf(t, tray.mStorageStatus, "Storage: Locked")

	quitTray(t, tray, codes)
}

func TestTrayManager_HandleClicks_BridgeFailureKeepsMenuState(t *testing.T) {
	app, _, codes := windowedApp(t)
	app.fido2Service = services.NewFIDO2Service(nil)
	tray := readyTray(t, app)

	// No phone client is wired, so the bridge cannot start; and a bridge
	// that never started cannot be stopped.
	click(tray.mBridgeStart)
	click(tray.mBridgeStop)
	click(tray.mPhoneDisc)

	assert.False(t, tray.mBridgeStart.Disabled(), "a failed start must leave start offered")
	assert.True(t, tray.mBridgeStop.Disabled(), "a failed start must not offer stop")

	quitTray(t, tray, codes)
}

func TestTrayManager_HandleClicks_SettingsAndAuditLogShowWindow(t *testing.T) {
	app, window, codes := windowedApp(t)
	tray := readyTray(t, app)
	click(tray.mSettings)
	click(tray.mAuditLog)
	click(tray.mPhoneAttest) // handled after the audit log click returns

	shown := 0
	for _, call := range window.Calls() {
		if call == "show" {
			shown++
		}
	}
	assert.Equal(t, 2, shown, "settings and audit log each bring the window forward")

	quitTray(t, tray, codes)
}

func TestTrayManager_HandleClicks_QuitExitsTheApp(t *testing.T) {
	app, window, codes := windowedApp(t)
	tray := readyTray(t, app)

	quitTray(t, tray, codes)

	assert.True(t, app.trayQuit.Load(), "a tray quit must not be intercepted by beforeClose")
	assert.Contains(t, window.Events(), "app:shutting_down")
}

// quitTray clicks the tray's Quit item and waits for the app to exit.
func quitTray(t *testing.T, tray *TrayManager, codes <-chan int) {
	t.Helper()
	click(tray.mQuit)
	assert.Equal(t, 0, <-codes, "the tray quit must shut down and exit with status 0")
}
