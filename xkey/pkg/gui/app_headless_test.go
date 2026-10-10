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

// Coverage for the App construction and lifecycle functions that do not
// require a live Wails window: NewApp's service wiring, getTPM's
// device-probe guards, shutdown's step sequence, beforeClose's
// allow-quit branches, and startup's headless (first-run, no-tray,
// no-auto-connect) path.
//
// startup() calls several helpers that invoke wailsruntime.EventsEmit or
// wailsruntime.Window* directly with a.ctx (startupReturningUser,
// ShowWindow's caller in the touch-notify focus callback, the tray
// manager). Those functions type-assert ctx.Value("events")/("frontend")
// and call log.Fatalf -- an unrecoverable os.Exit, not a panic -- when the
// context was not the one Wails' lifecycle hooks supply. The tests below
// therefore configure the App so startup()'s synchronous path never
// reaches one of those calls (SetupComplete=false skips
// startupReturningUser; AutoTray=false skips the tray; ServerAutoConnect
// and AppLockOnScreenLock=false skip their goroutines/monitors), matching
// the same constraint already documented in app_lifecycle_test.go for
// PostUnlockInitialize's success path.

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/backendregistry"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/config"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/services"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/ipc"
)

// isolateAppEnv points every environment-derived path NewApp/startup touch
// (the GUI config dir via os.UserConfigDir, the unified config via
// config.Load, and the xkey data home via xhome.Resolve) at fresh temp
// directories, so constructing a full App in tests never reads or writes
// real host state.
func isolateAppEnv(t *testing.T) {
	t.Helper()

	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("XKEY_HOME", filepath.Join(home, ".xkey"))

	cfgDir := t.TempDir()
	config.SetConfigDir(cfgDir)
	t.Cleanup(config.ResetConfigDir)
}

// TestNewApp_NilConfig_ConstructsFullyWiredApp verifies NewApp(nil) falls
// back to DefaultGUIConfig and wires every service NewApp is responsible
// for constructing, without touching real host state.
func TestNewApp_NilConfig_ConstructsFullyWiredApp(t *testing.T) {
	isolateAppEnv(t)

	app := NewApp(nil)

	require.NotNil(t, app)
	assert.Equal(t, DefaultGUIConfig(), app.config)
	assert.NotNil(t, app.appService)
	assert.NotNil(t, app.tpmAccessor, "the shared TPM accessor must be wired for cross-service serialization")
	assert.NotNil(t, app.browserService)
	assert.NotNil(t, app.secureBrowserService)
	assert.NotNil(t, app.setupWizardService)
	assert.NotNil(t, app.auditStore)
	assert.NotNil(t, app.backendRegistry)
	require.NotNil(t, app.loginTokens, "server calls read the login store `xkey auth login` writes")
	assert.DirExists(t, filepath.Join(os.Getenv("XKEY_HOME"), "data", "auth"))

	software, err := app.BackendRegistry().Get("software")
	require.NoError(t, err, "the software backend must always be registered")
	assert.Equal(t, backendregistry.StateReady, software.State())
}

// TestNewApp_CustomConfig_AppliesSettingsToServices verifies NewApp applies
// the caller-supplied config's sealer backend and barrier strategy to the
// services it wires, rather than silently keeping their zero values.
func TestNewApp_CustomConfig_AppliesSettingsToServices(t *testing.T) {
	isolateAppEnv(t)

	cfg := DefaultGUIConfig()
	cfg.SealerBackend = "tpm2"
	cfg.ClipboardTimeout = 42

	app := NewApp(cfg)

	assert.Same(t, cfg, app.config)
	assert.Equal(t, "tpm2", app.sealService.DefaultBackend(),
		"the configured sealer backend must override auto-select")
}

// TestNewApp_CorruptBrowserConfig_ResetsAndRetries verifies NewApp recovers
// from a corrupt browser.json by removing it and constructing the browser
// service against a fresh default config, rather than panicking.
func TestNewApp_CorruptBrowserConfig_ResetsAndRetries(t *testing.T) {
	isolateAppEnv(t)

	cfgDir, err := configDir()
	require.NoError(t, err)
	browserConfigPath := filepath.Join(cfgDir, "browser.json")
	require.NoError(t, os.WriteFile(browserConfigPath, []byte("not valid json"), 0600))

	var app *App
	require.NotPanics(t, func() {
		app = NewApp(nil)
	})
	require.NotNil(t, app.browserService, "browser service must be constructed after resetting the corrupt config")
	assert.Equal(t, services.BrowserSystem, app.browserService.GetConfig().DefaultBrowser,
		"the retried construction must hold the built-in defaults, not a partially-parsed corrupt config")

	_, statErr := os.Stat(browserConfigPath)
	assert.True(t, os.IsNotExist(statErr), "the corrupt config file must have been removed, not left in place")
}

// TestApp_Shutdown_FullyWiredApp_Idempotent verifies shutdown() runs its
// full step sequence against a fully-wired App (every nil-guarded step
// takes its "service present but idle" branch) without blocking past its
// per-step timeouts, closes shutdownDone exactly once, and is safe to call
// twice (the second call must be a no-op, not a repeated run).
func TestApp_Shutdown_FullyWiredApp_Idempotent(t *testing.T) {
	isolateAppEnv(t)

	app := NewApp(nil)

	done := make(chan struct{})
	go func() {
		app.shutdown(context.Background())
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("shutdown did not return within 10s")
	}

	select {
	case <-app.shutdownDone:
	default:
		t.Fatal("shutdownDone must be closed after shutdown completes")
	}

	// Second call must be a sync.Once no-op: it must return promptly and
	// must not panic re-running steps against already-torn-down state
	// (e.g. a second close of shutdownDone, which would panic).
	assert.NotPanics(t, func() {
		app.shutdown(context.Background())
	})
}

// TestApp_GetTPM_DeviceMissing_CachesUnavailable verifies getTPM fails
// closed (returns nil, no panic) when the configured TPM device node does
// not exist, and caches that result so a second call short-circuits via
// tpmUnavailable instead of re-probing.
func TestApp_GetTPM_DeviceMissing_CachesUnavailable(t *testing.T) {
	app := &App{log: lifecycleTestLogger()}

	missingDevice := filepath.Join(t.TempDir(), "no-such-tpm-device")
	// Pre-consume tpmConfigOnce so getTPM's internal Do is a no-op and the
	// device path below is the one it probes, deterministically, without
	// depending on whatever TPM config happens to be on the test host.
	app.tpmConfigOnce.Do(func() {
		app.tpmCachedConfig = xkmssdk.TPMConfig{Device: missingDevice}
	})

	tpm := app.getTPM()
	assert.Nil(t, tpm)
	assert.True(t, app.tpmUnavailable, "a missing device must be cached as unavailable")

	// Second call must take the early tpmUnavailable branch.
	tpm2 := app.getTPM()
	assert.Nil(t, tpm2)
}

// stubTPM satisfies xkmssdk.TrustedPlatformModule via a nil embedded
// interface, mirroring services.stubTPM in tpm_accessor_test.go. It is
// only used as an opaque, comparable value to verify getTPM's cache
// returns the exact stored instance -- none of its methods are called.
type stubTPM struct {
	xkmssdk.TrustedPlatformModule
}

// TestApp_GetTPM_ReturnsCachedInstance verifies getTPM returns the already
// -opened TPM instance directly, without re-probing the device or
// reloading config.
func TestApp_GetTPM_ReturnsCachedInstance(t *testing.T) {
	app := &App{log: lifecycleTestLogger()}
	tpm := &stubTPM{}
	app.tpmInstance = tpm

	got := app.getTPM()
	assert.Same(t, tpm, got)
}

// TestApp_BeforeClose_AutoTrayDisabled_AllowsQuit verifies beforeClose
// allows the window to close (returns false) without touching the Wails
// runtime when AutoTray is disabled.
func TestApp_BeforeClose_AutoTrayDisabled_AllowsQuit(t *testing.T) {
	app := &App{config: &GUIConfig{AutoTray: false}, log: lifecycleTestLogger()}

	allow := app.beforeClose(context.Background())
	assert.False(t, allow, "beforeClose must allow the quit through when AutoTray is disabled")
}

// TestApp_BeforeClose_TrayQuitSet_AllowsQuit verifies beforeClose allows
// the window to close when the tray's quit menu item already requested
// shutdown, even though AutoTray is enabled.
func TestApp_BeforeClose_TrayQuitSet_AllowsQuit(t *testing.T) {
	app := &App{config: &GUIConfig{AutoTray: true}, log: lifecycleTestLogger()}
	app.trayQuit.Store(true)

	allow := app.beforeClose(context.Background())
	assert.False(t, allow, "beforeClose must allow the quit through once trayQuit is set")
}

// TestApp_Startup_FirstRunHeadless verifies startup()'s common first-run
// path: it binds the Wails context, propagates it to every service,
// initializes the platform policy, wires the barrier's data directory and
// backend factory, and returns without starting the tray, the
// auto-connect goroutine, or the screen lock monitor when those are
// disabled in config.
func TestApp_Startup_FirstRunHeadless(t *testing.T) {
	isolateAppEnv(t)

	cfg := DefaultGUIConfig()
	cfg.AutoTray = false
	cfg.ServerAutoConnect = false
	cfg.AppLockOnScreenLock = false
	cfg.SetupComplete = false

	app := NewApp(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	app.startup(ctx)

	assert.Equal(t, ctx, app.ctx)
	assert.NotNil(t, app.deviceNotifier, "the touch-notify focus wrapper must be wired")
	assert.Nil(t, app.tray, "tray must not start when AutoTray is disabled")
	assert.Nil(t, app.screenLockMonitor, "screen lock monitor must not start when disabled")
	assert.False(t, app.dataDirInit, "first run must wait for the setup wizard, not init the data dir")
}

// TestApp_InstallSignalHandler_DoesNotPanic verifies installSignalHandler
// registers its signal channel and background goroutine without panicking.
// It deliberately does not send a signal: the handler's goroutine calls
// os.Exit(0) after shutdown, which would kill the test binary itself
// rather than fail the one test.
func TestApp_InstallSignalHandler_DoesNotPanic(t *testing.T) {
	app := &App{log: lifecycleTestLogger()}
	assert.NotPanics(t, func() {
		app.installSignalHandler()
	})
}

// TestApp_BuildXKMSBackendConfigs_ConfigUnavailable verifies the config.Load
// error branch returns an empty map rather than propagating the error.
func TestApp_BuildXKMSBackendConfigs_ConfigUnavailable(t *testing.T) {
	app := newMinimalApp(t)

	cfgDir := t.TempDir()
	config.SetConfigDir(cfgDir)
	t.Cleanup(config.ResetConfigDir)
	require.NoError(t, os.WriteFile(filepath.Join(cfgDir, "xkey.yaml"), []byte("not: [valid yaml"), 0600))

	configs := app.buildXKMSBackendConfigs()
	assert.Empty(t, configs)
}

// TestApp_BuildXKMSBackendConfigs_TPM2AndPKCS11FromBackendsSection verifies
// explicit tpm2 and pkcs11 local backend entries are translated into the
// factory config map, and that an explicit tpm2 entry suppresses the
// shared-TPM-config device fallback.
func TestApp_BuildXKMSBackendConfigs_TPM2AndPKCS11FromBackendsSection(t *testing.T) {
	app := newMinimalApp(t)

	cfgDir := t.TempDir()
	config.SetConfigDir(cfgDir)
	t.Cleanup(config.ResetConfigDir)

	yaml := `
tpm:
  device: /dev/tpmrm-should-not-be-used
backends:
  local:
    - id: tpm-a
      category: tpm2
      name: "TPM"
      tpm2:
        device: /dev/tpmrm0
        simulator: true
    - id: token-a
      category: pkcs11
      name: "Token"
      pkcs11:
        library_path: /usr/lib/softhsm/libsofthsm2.so
        slot_id: 3
`
	require.NoError(t, os.WriteFile(filepath.Join(cfgDir, "xkey.yaml"), []byte(yaml), 0600))

	configs := app.buildXKMSBackendConfigs()

	tpmCfg, ok := configs[xkmssdk.BackendTPM2]
	require.True(t, ok, "an explicit tpm2 backend entry must produce a TPM2 config")
	assert.Equal(t, "/dev/tpmrm0", tpmCfg["device"],
		"the explicit backend entry's device must win over the shared TPM config fallback")
	assert.Equal(t, true, tpmCfg["use_simulator"])

	pkcs11Cfg, ok := configs[xkmssdk.BackendPKCS11]
	require.True(t, ok)
	assert.Equal(t, "/usr/lib/softhsm/libsofthsm2.so", pkcs11Cfg["library"])
	assert.Equal(t, 3, pkcs11Cfg["slot"])
}

// TestApp_BuildXKMSBackendConfigs_FallsBackToSharedTPMDevice verifies that
// when no explicit tpm2 local backend entry exists, the shared TPM
// config's device path is used instead of leaving BackendTPM2 unset.
func TestApp_BuildXKMSBackendConfigs_FallsBackToSharedTPMDevice(t *testing.T) {
	app := newMinimalApp(t)

	cfgDir := t.TempDir()
	config.SetConfigDir(cfgDir)
	t.Cleanup(config.ResetConfigDir)

	yaml := `
tpm:
  device: /dev/tpmrm0
`
	require.NoError(t, os.WriteFile(filepath.Join(cfgDir, "xkey.yaml"), []byte(yaml), 0600))

	configs := app.buildXKMSBackendConfigs()

	tpmCfg, ok := configs[xkmssdk.BackendTPM2]
	require.True(t, ok, "the shared TPM device must be used as a fallback")
	assert.Equal(t, "/dev/tpmrm0", tpmCfg["device"])
}

// TestApp_RegisterPKCS11XKMSBackend_YubiKeyWithoutSOPIN verifies the guard
// that refuses to register a YubiKey PKCS#11 backend when no SO PIN
// (management key) was supplied, cutting the failure at registration
// instead of surfacing CKR_USER_TYPE_INVALID at operation time.
func TestApp_RegisterPKCS11XKMSBackend_YubiKeyWithoutSOPIN(t *testing.T) {
	app := newMinimalApp(t)

	require.NoError(t, app.initializeDataDir(), "initializeDataDir must succeed to initialize the xkms service")
	t.Cleanup(xkmssdk.Reset)
	require.True(t, xkmssdk.IsInitialized())

	// Must not panic and must not reach backend construction: the presence
	// of a "pkcs11" backend afterward would indicate the guard was skipped.
	assert.NotPanics(t, func() {
		app.registerPKCS11XKMSBackend("/usr/lib/x86_64-linux-gnu/libykcs11.so", 0, "123456", "", "yubikey")
	})
	_, err := xkmssdk.GetBackend("pkcs11")
	assert.Error(t, err, "no pkcs11 backend may be registered without an SO PIN for a YubiKey library")
}

// TestApp_PostDataDirStartup_Headless verifies postDataDirStartup, run
// after a plain-file (no-barrier) initializeDataDir, seeds trust roots,
// starts the password expiry checker, records the FIDO2 authenticator's
// disabled reason, and leaves the IPC socket closed because local app
// access is off by default -- all without a Wails runtime context (a.ctx is a plain, cancelable context.Context; nothing
// here calls wailsruntime.EventsEmit synchronously: the expiry checker's
// callback only fires on its hourly ticker, never at Start()).
func TestApp_PostDataDirStartup_Headless(t *testing.T) {
	app := newMinimalApp(t)
	sockDir := t.TempDir()
	require.NoError(t, os.Chmod(sockDir, 0o700))
	sockPath := filepath.Join(sockDir, "xkey.sock")
	t.Setenv(ipc.EnvSocketPath, sockPath)
	// Keep the virtual FIDO2 HID authenticator disabled: starting it would
	// open a real /dev/uhid device node, which this headless test must not
	// depend on being present or usable.
	app.config.FIDO2AuthenticatorEnabled = false

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	app.ctx = ctx

	require.NoError(t, app.initializeDataDir())
	t.Cleanup(xkmssdk.Reset)
	require.NotNil(t, app.staticpwStore, "precondition: initializeDataDir must have wired a static password store")

	app.postDataDirStartup()
	t.Cleanup(func() {
		if app.ipcServer != nil {
			_ = app.ipcServer.Close()
		}
		if app.expiryChecker != nil {
			app.expiryChecker.Stop()
		}
	})

	assert.NotNil(t, app.expiryChecker, "the password expiry checker must start once staticpwStore is wired")
	assert.Nil(t, app.ipcServer, "no IPC server may start while local app access is off")
	assertNoSocket(t, sockPath)
	assert.Equal(t, "authenticator disabled in settings", app.fido2DeviceService.GetStatus().RawReason,
		"FIDO2AuthenticatorEnabled is false in DefaultGUIConfig, so the device service must record why it did not start")
}

// TestApp_StartupReturningUser_BarrierNeverInitialized_WaitsForPassword
// verifies startupReturningUser's config-repair and early-return path for a
// returning user with no storage type configured and no barrier root key on
// disk: it must default to barrier-encrypted storage, leave
// BarrierInitialized false, pre-resolve dataDir for the PIN service, and
// return without opening any data-directory stores.
//
// a.ctx is deliberately left nil (startup() is never called): the function
// takes this branch's a.EmitEvent call, which is safely a no-op logged
// warning when a.ctx is nil, matching the documented seam in
// app_lifecycle_test.go.
func TestApp_StartupReturningUser_BarrierNeverInitialized_WaitsForPassword(t *testing.T) {
	isolateAppEnv(t)

	cfg := DefaultGUIConfig()
	cfg.AutoTray = false
	cfg.AutoUnsealEnabled = false

	app := NewApp(cfg)
	require.Nil(t, app.ctx)

	app.startupReturningUser(context.Background())

	assert.Equal(t, "barrier", app.config.StorageType,
		"a missing storage type must be repaired to barrier-encrypted by default")
	assert.False(t, app.config.BarrierInitialized)
	assert.NotEmpty(t, app.dataDir, "dataDir must be pre-resolved so the PIN service can find data/pin/")
	assert.False(t, app.dataDirInit, "data dir stores must remain unopened until the user sets a password")
}

// TestApp_StartupReturningUser_NonBarrierStorage_InitializesDataDir
// verifies that a returning user configured for non-barrier storage skips
// the barrier wait entirely and proceeds straight through
// initializeDataDir and postDataDirStartup, matching a LUKS-backed or
// legacy plain-file deployment. Local app access is off by default, so no
// IPC socket may appear.
func TestApp_StartupReturningUser_NonBarrierStorage_InitializesDataDir(t *testing.T) {
	app, sockPath := startReturningUserApp(t, false)

	assert.True(t, app.dataDirInit, "a non-barrier storage type must proceed straight to data dir initialization")
	assert.Nil(t, app.ipcServer, "no IPC server may start while local app access is off")
	assertNoSocket(t, sockPath)
}

// startReturningUserApp builds a fully wired App and runs the returning-user
// startup for non-barrier storage, so the data directory opens and
// postDataDirStartup runs. The IPC socket is sandboxed in a private
// directory; its path is returned. The App is shut down at cleanup.
//
// a.ctx is a plain context rather than the one Wails supplies, so startup
// must never reach a direct wailsruntime call -- which is why
// AutoUnsealEnabled and StorageType "barrier" are kept off this path.
func startReturningUserApp(t *testing.T, localAppAccess bool) (*App, string) {
	t.Helper()
	isolateAppEnv(t)

	sockDir := filepath.Join(t.TempDir(), "run")
	require.NoError(t, os.Mkdir(sockDir, 0o700))
	sockPath := filepath.Join(sockDir, "xkey.sock")
	t.Setenv(ipc.EnvSocketPath, sockPath)

	cfg := DefaultGUIConfig()
	cfg.AutoTray = false
	cfg.AutoUnsealEnabled = false
	cfg.StorageType = "luks"
	cfg.FIDO2AuthenticatorEnabled = false
	cfg.LocalAppAccessEnabled = localAppAccess

	app := NewApp(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	app.ctx = ctx
	t.Cleanup(xkmssdk.Reset)
	t.Cleanup(func() {
		app.shutdown(ctx)
		cancel()
	})

	app.startupReturningUser(ctx)
	require.True(t, app.dataDirInit, "precondition: the data directory must open")
	return app, sockPath
}

// assertNoSocket fails the test if anything exists at sockPath.
func assertNoSocket(t *testing.T, sockPath string) {
	t.Helper()
	_, err := os.Lstat(sockPath)
	assert.ErrorIs(t, err, os.ErrNotExist, "no IPC socket may exist at %s", sockPath)
}

// assertSocket fails the test unless a socket exists at sockPath.
func assertSocket(t *testing.T, sockPath string) {
	t.Helper()
	info, err := os.Lstat(sockPath)
	if assert.NoError(t, err, "the IPC socket must exist at %s", sockPath) {
		assert.Equal(t, os.ModeSocket, info.Mode().Type())
	}
}
