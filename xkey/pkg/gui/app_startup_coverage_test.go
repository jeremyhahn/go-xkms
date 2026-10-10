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

// Coverage for the post-data-dir startup sequence (postDataDirStartup,
// startIPCServer, PostUnlockInitialize, PostBarrierUnseal) that a plain-Go
// test App could not previously reach at all. See app_lifecycle_test.go's
// comment above TestApp_PostUnlockInitialize_PropagatesError for why. With
// a.ctx left nil, startIPCServer used to spawn a goroutine calling
// `<-a.ctx.Done()` on a nil context.Context -- a nil interface with no
// concrete type -- panicking the whole test binary, not just one test.
//
// startIPCServer now guards a.ctx == nil the same way EmitEvent/ShowWindow/
// HideWindow/Quit already do elsewhere in this file: it is a no-op, logging
// a warning, rather than starting a server nothing will ever cancel. In
// production a.ctx is always bound by the Wails startup hook before
// postDataDirStartup is reachable from the frontend, so this is a pure
// defensive addition there; here it is what makes the rest of the startup
// sequence observable without a live Wails runtime.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- startIPCServer ---

// TestApp_StartIPCServer_NilContext_NoOp verifies startIPCServer refuses to
// start (rather than panicking a spawned goroutine) when no Wails context has
// been bound -- the state of every App built directly in Go, including every
// other test in this file.
func TestApp_StartIPCServer_NilContext_NoOp(t *testing.T) {
	app := newMinimalApp(t)
	require.Nil(t, app.ctx, "precondition: no Wails context bound")

	assert.NotPanics(t, func() {
		app.startIPCServer()
	})
	assert.Nil(t, app.ipcServer, "no server must be created without a bound context")
}

// --- postDataDirStartup: FIDO2 virtual device switch ---

// TestApp_PostDataDirStartup_FIDO2Disabled verifies the "disabled in
// settings" branch records a reason without touching the virtual device.
func TestApp_PostDataDirStartup_FIDO2Disabled(t *testing.T) {
	app := newMinimalApp(t)
	require.NoError(t, app.initializeDataDir())
	app.config.FIDO2AuthenticatorEnabled = false

	assert.NotPanics(t, func() {
		app.postDataDirStartup()
	})

	status := app.fido2DeviceService.GetStatus()
	assert.False(t, status.Running)
	assert.Contains(t, status.Reason, "disabled in settings")
}

// TestApp_PostDataDirStartup_FIDO2EnabledStorageMissing verifies the
// "storage initialization failed" branch: FIDO2 is enabled in config, but
// initializeDataDir did not (or could not) open the credential store.
//
// The real "enabled with storage present" branch is not exercised here: it
// calls fido2DeviceService.Start, which opens /dev/uhid to create a virtual
// USB HID device. Whether that fails or succeeds is a function of the
// host's permissions (it is root-only on a typical Linux box, but nothing
// stops a CI container from running as root) -- a test that depends on that
// distinction either does nothing under normal permissions or actually
// attaches a virtual input device under elevated ones. Both outcomes are
// wrong for a unit test that must never touch the host, so that branch is
// left to the pkg/gui/services FIDO2 device suite, which exercises it
// through fakes.
func TestApp_PostDataDirStartup_FIDO2EnabledStorageMissing(t *testing.T) {
	app := newMinimalApp(t)
	require.NoError(t, app.initializeDataDir())
	app.config.FIDO2AuthenticatorEnabled = true
	app.fido2Storage = nil

	assert.NotPanics(t, func() {
		app.postDataDirStartup()
	})

	status := app.fido2DeviceService.GetStatus()
	assert.False(t, status.Running)
	assert.Contains(t, status.Reason, "storage initialization failed")
}

// --- PostUnlockInitialize / PostBarrierUnseal success paths ---

// TestApp_PostUnlockInitialize_Success verifies the full success path: the
// data directory opens, postDataDirStartup runs without panicking (no Wails
// context is bound, so startIPCServer's guard makes it a no-op), and the
// completion event is swallowed by EmitEvent's own nil-ctx guard rather than
// reaching the Wails runtime.
func TestApp_PostUnlockInitialize_Success(t *testing.T) {
	app := newMinimalApp(t)
	app.config.FIDO2AuthenticatorEnabled = false // see FIDO2EnabledStorageMissing's comment

	err := app.PostUnlockInitialize()

	require.NoError(t, err)
	assert.True(t, app.dataDirInit)
	assert.Nil(t, app.ipcServer, "no Wails context is bound; the IPC server must not start")
}

// TestApp_PostBarrierUnseal_Success verifies the full success path once the
// barrier reports unsealed: the data directory opens, the barrier-initialized
// flag and chosen strategy are persisted to the GUI config, and the shared
// postDataDirStartup sequence runs without panicking.
func TestApp_PostBarrierUnseal_Success(t *testing.T) {
	app := newMinimalApp(t)
	app.config.FIDO2AuthenticatorEnabled = false // see FIDO2EnabledStorageMissing's comment

	// configDir() (used by SaveGUIConfig) resolves from $HOME, independent
	// of XKEY_HOME; sandbox it too so nothing is written to the real host.
	t.Setenv("HOME", t.TempDir())

	require.NoError(t, app.barrierService.Initialize("test-password", "passphrase"))
	require.True(t, app.barrierService.IsUnsealed(), "precondition: barrier must unseal on Initialize")
	require.False(t, app.config.BarrierInitialized, "precondition: config must not yet record the barrier")

	err := app.PostBarrierUnseal()

	require.NoError(t, err)
	assert.True(t, app.dataDirInit)
	assert.True(t, app.config.BarrierInitialized, "the barrier-initialized flag must be persisted")
	assert.Equal(t, "passphrase", app.config.BarrierStrategy)
}

// TestApp_PostBarrierUnseal_AlreadyRecordedSkipsSave verifies the config save
// is skipped (not re-run) once BarrierInitialized is already true -- it is
// the GetSealInfo()/SaveGUIConfig block that TestApp_PostBarrierUnseal_Success
// exercises taking effect, guarded by the same flag it sets.
func TestApp_PostBarrierUnseal_AlreadyRecordedSkipsSave(t *testing.T) {
	app := newMinimalApp(t)
	app.config.FIDO2AuthenticatorEnabled = false
	app.config.BarrierInitialized = true
	app.config.BarrierStrategy = "shamir"

	t.Setenv("HOME", t.TempDir())

	require.NoError(t, app.barrierService.Initialize("test-password", "passphrase"))

	err := app.PostBarrierUnseal()

	require.NoError(t, err)
	assert.Equal(t, "shamir", app.config.BarrierStrategy,
		"an already-recorded strategy must not be overwritten from GetSealInfo")
}
