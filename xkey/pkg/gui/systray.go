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
	"log/slog"

	"fyne.io/systray"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/icon"
)

// TrayManager manages the system tray icon, tooltip, and context menu.
type TrayManager struct {
	app *App
	log *slog.Logger

	// Menu items kept for dynamic updates.
	mStatus        *systray.MenuItem
	mPhoneStatus   *systray.MenuItem
	mPhoneConn     *systray.MenuItem
	mPhoneDisc     *systray.MenuItem
	mPhoneAttest   *systray.MenuItem
	mBridgeStart   *systray.MenuItem
	mBridgeStop    *systray.MenuItem
	mKeyCount      *systray.MenuItem
	mStorageStatus *systray.MenuItem
}

// NewTrayManager creates a new TrayManager bound to the given App.
func NewTrayManager(app *App) *TrayManager {
	return &TrayManager{
		app: app,
		log: slog.Default().With("component", "systray"),
	}
}

// Run starts the system tray. This call blocks until systray.Quit is called.
func (t *TrayManager) Run() {
	systray.Run(t.onReady, t.onExit)
}

// onReady is called when the systray is ready to receive menu items.
func (t *TrayManager) onReady() {
	systray.SetIcon(icon.AppIcon)
	systray.SetTooltip("xKey - Multi-protocol Authentication")

	// Left-click on the tray icon brings the main window to the foreground.
	systray.SetOnTapped(func() {
		t.app.ShowWindow()
	})

	// Status (disabled informational item).
	t.mStatus = systray.AddMenuItem("xKey: Ready", "Application status")
	t.mStatus.Disable()

	systray.AddSeparator()

	// Phone submenu.
	mPhone := systray.AddMenuItem("Phone", "Phone device management")
	t.mPhoneStatus = mPhone.AddSubMenuItem("No device connected", "Phone connection status")
	t.mPhoneStatus.Disable()
	t.mPhoneConn = mPhone.AddSubMenuItem("Connect", "Connect to paired phone")
	t.mPhoneDisc = mPhone.AddSubMenuItem("Disconnect", "Disconnect from phone")
	t.mPhoneDisc.Disable()
	t.mPhoneAttest = mPhone.AddSubMenuItem("Attest Device", "Verify phone hardware attestation")
	t.mPhoneAttest.Disable()

	// Keys.
	t.mKeyCount = systray.AddMenuItem("Keys: 0", "Managed key count")
	t.mKeyCount.Disable()

	// Storage status.
	t.mStorageStatus = systray.AddMenuItem("Storage: Unknown", "Encrypted storage status")
	t.mStorageStatus.Disable()

	systray.AddSeparator()

	// FIDO2 submenu.
	mFIDO2 := systray.AddMenuItem("FIDO2", "FIDO2/WebAuthn operations")
	t.mBridgeStart = mFIDO2.AddSubMenuItem("Start Bridge", "Start the FIDO2 phone bridge")
	t.mBridgeStop = mFIDO2.AddSubMenuItem("Stop Bridge", "Stop the FIDO2 phone bridge")
	t.mBridgeStop.Disable()
	mFIDO2.AddSubMenuItem("Credentials", "View stored credentials")

	// OATH submenu.
	mOATH := systray.AddMenuItem("OATH", "TOTP/HOTP codes")
	mOATH.AddSubMenuItem("Accounts", "View OATH accounts")

	// PIV.
	systray.AddMenuItem("PIV", "PIV certificate management")

	// TPM.
	systray.AddMenuItem("TPM", "TPM2 operations")

	systray.AddSeparator()

	// Settings.
	mSettings := systray.AddMenuItem("Settings", "Application settings")

	// Audit Log.
	mAuditLog := systray.AddMenuItem("Audit Log", "View security audit log")

	systray.AddSeparator()

	// Quit.
	mQuit := systray.AddMenuItem("Quit", "Exit xKey")

	// Handle menu clicks in a goroutine.
	go t.handleClicks(mSettings, mAuditLog, mQuit)
}

// handleClicks listens for menu item clicks and dispatches actions.
func (t *TrayManager) handleClicks(mSettings, mAuditLog, mQuit *systray.MenuItem) {
	for {
		select {
		case <-t.mPhoneConn.ClickedCh:
			t.handlePhoneConnect()
		case <-t.mPhoneDisc.ClickedCh:
			t.handlePhoneDisconnect()
		case <-t.mPhoneAttest.ClickedCh:
			t.handlePhoneAttest()
		case <-t.mBridgeStart.ClickedCh:
			t.log.Info("tray: bridge start requested")
			if err := t.app.fido2Service.StartPhoneBridge(); err != nil {
				t.log.Error("tray: bridge start failed", "error", err)
			} else {
				t.mBridgeStart.Disable()
				t.mBridgeStop.Enable()
			}
		case <-t.mBridgeStop.ClickedCh:
			t.log.Info("tray: bridge stop requested")
			if err := t.app.fido2Service.StopPhoneBridge(); err != nil {
				t.log.Error("tray: bridge stop failed", "error", err)
			} else {
				t.mBridgeStop.Disable()
				t.mBridgeStart.Enable()
			}
		case <-mSettings.ClickedCh:
			t.log.Info("tray: settings requested")
			t.app.ShowWindow()
		case <-mAuditLog.ClickedCh:
			t.log.Info("tray: audit log requested")
			t.app.ShowWindow()
		case <-mQuit.ClickedCh:
			t.log.Info("tray: quit requested")
			// Signal the Wails event loop to exit first. This sets
			// the trayQuit flag so that beforeClose does not intercept
			// the quit when AutoTray is enabled.
			t.app.Quit()
			// Then tear down the system tray. systray.Quit blocks
			// until the onExit callback completes.
			systray.Quit()
			return
		}
	}
}

// handlePhoneConnect attempts to connect to the default paired phone device.
func (t *TrayManager) handlePhoneConnect() {
	t.log.Info("tray: phone connect requested")

	devices, err := t.app.phoneService.ListDevices()
	if err != nil {
		t.log.Error("tray: failed to list phone devices", "error", err)
		return
	}
	if len(devices) == 0 {
		t.log.Warn("tray: no paired phone devices found")
		return
	}

	// Connect to the first paired device (the default).
	target := devices[0].Name
	if err := t.app.phoneService.Connect(target); err != nil {
		t.log.Error("tray: phone connect failed", "device", target, "error", err)
		return
	}
}

// handlePhoneDisconnect disconnects the currently connected phone device.
func (t *TrayManager) handlePhoneDisconnect() {
	t.log.Info("tray: phone disconnect requested")

	connName := t.app.phoneService.ConnectedDeviceName()
	if connName == "" {
		t.log.Warn("tray: no phone device connected to disconnect")
		return
	}

	if err := t.app.phoneService.Disconnect(connName); err != nil {
		t.log.Error("tray: phone disconnect failed", "device", connName, "error", err)
	}
}

// handlePhoneAttest triggers hardware attestation on the connected phone device.
func (t *TrayManager) handlePhoneAttest() {
	t.log.Info("tray: phone attestation requested")

	connName := t.app.phoneService.ConnectedDeviceName()
	if connName == "" {
		t.log.Warn("tray: no phone device connected for attestation")
		return
	}

	result, err := t.app.phoneService.AttestDevice(connName)
	if err != nil {
		t.log.Error("tray: phone attestation failed", "device", connName, "error", err)
		return
	}

	if result.Verified {
		t.log.Info("tray: phone attestation passed", "device", connName)
	} else {
		t.log.Warn("tray: phone attestation failed", "device", connName, "error_message", result.ErrorMessage)
	}
}

// onExit is called when the systray is exiting.
func (t *TrayManager) onExit() {
	t.log.Info("system tray exiting")
}

// UpdateStatus updates the status line in the tray menu.
func (t *TrayManager) UpdateStatus(status string) {
	if t.mStatus != nil {
		t.mStatus.SetTitle("xKey: " + status)
	}
}

// UpdatePhoneStatus updates the phone connection status in the tray menu.
func (t *TrayManager) UpdatePhoneStatus(connected bool, deviceName string) {
	if t.mPhoneStatus == nil {
		return
	}
	if connected {
		t.mPhoneStatus.SetTitle("Connected: " + deviceName)
		t.mPhoneConn.Disable()
		t.mPhoneDisc.Enable()
		t.mPhoneAttest.Enable()
	} else {
		t.mPhoneStatus.SetTitle("No device connected")
		t.mPhoneConn.Enable()
		t.mPhoneDisc.Disable()
		t.mPhoneAttest.Disable()
	}
}

// UpdateKeyCount updates the key count display in the tray menu.
func (t *TrayManager) UpdateKeyCount(count int) {
	if t.mKeyCount == nil {
		return
	}
	label := "Keys: " + intToLabel(count)
	t.mKeyCount.SetTitle(label)
}

// UpdateStorageStatus updates the encrypted storage status in the tray menu.
func (t *TrayManager) UpdateStorageStatus(mounted bool) {
	if t.mStorageStatus == nil {
		return
	}
	if mounted {
		t.mStorageStatus.SetTitle("Storage: Mounted")
	} else {
		t.mStorageStatus.SetTitle("Storage: Locked")
	}
}

// intToLabel formats an int as a string without importing strconv.
func intToLabel(n int) string {
	if n == 0 {
		return "0"
	}
	buf := make([]byte, 0, 10)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		buf = append(buf, byte('0'+n%10))
		n /= 10
	}
	if neg {
		buf = append(buf, '-')
	}
	for i, j := 0, len(buf)-1; i < j; i, j = i+1, j-1 {
		buf[i], buf[j] = buf[j], buf[i]
	}
	return string(buf)
}
