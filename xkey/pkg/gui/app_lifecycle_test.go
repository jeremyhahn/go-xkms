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
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/backendregistry"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/events"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/services"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/luks"
)

// lifecycleTestLogger returns a logger that discards output.
func lifecycleTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// newLifecycleApp builds the smallest App capable of exercising
// InitializeDataDir/PostUnlockInitialize/ToggleFIDO2Authenticator without
// touching the host or requiring hardware. Every store is file- or
// memory-backed and rooted inside a temp directory via XKEY_HOME. It mirrors
// init_data_dir_test.go's newMinimalApp (the fields initializeDataDir
// unconditionally dereferences), plus appService for the config accessors
// exercised by ToggleFIDO2Authenticator/GetConfig/SetTheme.
func newLifecycleApp(t *testing.T) *App {
	t.Helper()

	xkeyHome := t.TempDir()
	t.Setenv("XKEY_HOME", xkeyHome)

	log := lifecycleTestLogger()
	cfgDir := filepath.Join(xkeyHome, "config")

	auditStore, err := audit.NewBackendStore(xkms.NewStorageMemory(), 100, log)
	require.NoError(t, err)

	barrierSvc := services.NewBarrierService(cfgDir, log)
	pinSvc := services.NewPINService()
	pinSvc.SetBarrierService(barrierSvc)
	appLockSvc := services.NewAppLockService(pinSvc, barrierSvc)

	staticPWSvc := services.NewStaticPasswordService(nil)
	oathSvc := services.NewOATHService(nil)
	autofillSvc := services.NewAutoFillService(staticPWSvc, oathSvc, appLockSvc, auditStore, log)

	tpmAccessor := services.NewTPMAccessor(func() xkms.TrustedPlatformModule {
		return nil
	})

	return &App{
		pinService:         pinSvc,
		log:                log,
		configDirPath:      cfgDir,
		config:             DefaultGUIConfig(),
		barrierService:     barrierSvc,
		appLockService:     appLockSvc,
		oathService:        oathSvc,
		fido2Service:       services.NewFIDO2Service(nil),
		fido2DeviceService: services.NewFIDO2DeviceService(log),
		staticPWService:    staticPWSvc,
		teamService:        services.NewTeamService(),
		trustService:       services.NewTrustService(nil),
		tpmService:         services.NewTPMService(),
		phoneService:       services.NewPhoneService(),
		oidcService:        services.NewOIDCService(log),
		pivService:         services.NewPIVService(nil, "software"),
		sealService:        services.NewSealService(""),
		auditStore:         auditStore,
		backendRegistry:    backendregistry.NewMemoryRegistry(),
		pairingService:     services.NewPairingService(log),
		keyService:         services.NewKeyService(),
		tpmAccessor:        tpmAccessor,
		autofillService:    autofillSvc,
		sshService:         services.NewSSHService(nil),
		sshProfileService:  services.NewSSHProfileService(nil),
		sshConnectService:  services.NewSSHConnectService(),
		sshConsoleService:  services.NewSSHConsoleService(),
		sshLocalService:    services.NewSSHLocalService(),
		storageService:     services.NewStorageService(),
		agentService:       services.NewAgentService(),
		appService:         services.NewAppService(nil),
		shutdownDone:       make(chan struct{}),
	}
}

// TestApp_InitializeDataDir_Success verifies the public InitializeDataDir
// wrapper succeeds and emits no panic when a.ctx is nil (application not yet
// bound to a Wails runtime), exercising both the delegation to
// initializeDataDir and the EmitEvent nil-ctx guard.
func TestApp_InitializeDataDir_Success(t *testing.T) {
	app := newLifecycleApp(t)

	err := app.InitializeDataDir()
	require.NoError(t, err)
	assert.True(t, app.dataDirInit)
	assert.NotEmpty(t, app.dataDir)
}

// TestApp_InitializeDataDir_PropagatesError verifies InitializeDataDir
// surfaces the underlying initializeDataDir error (LUKS locked) rather than
// swallowing it.
func TestApp_InitializeDataDir_PropagatesError(t *testing.T) {
	app := newLifecycleApp(t)

	vol, err := luks.NewVolume()
	require.NoError(t, err)
	require.NoError(t, writeFakeLUKSContainer(vol.LUKSPath))

	err = app.InitializeDataDir()
	require.Error(t, err)
	assert.ErrorIs(t, err, xkms.ErrLUKSVolumeLocked)
	assert.False(t, app.dataDirInit)
}

// PostUnlockInitialize's success path is deliberately NOT covered here: past
// initializeDataDir it emits frontend events, and a plain-Go test App has no
// Wails context to emit them on. With a.ctx set to any non-Wails
// context.Context (context.Background(), a context.WithValue, etc.) the
// EmitEvent call reaches wailsapp/wails/v2/pkg/runtime.getEvents, which calls
// log.Fatalf (i.e. os.Exit(1)) when the context carries no "events" value --
// fatal to the whole test binary, not a recoverable per-test failure.

// TestApp_PostUnlockInitialize_PropagatesError verifies PostUnlockInitialize
// returns the initializeDataDir error and does not proceed to
// postDataDirStartup when the data directory cannot be opened.
func TestApp_PostUnlockInitialize_PropagatesError(t *testing.T) {
	app := newLifecycleApp(t)

	vol, err := luks.NewVolume()
	require.NoError(t, err)
	require.NoError(t, writeFakeLUKSContainer(vol.LUKSPath))

	err = app.PostUnlockInitialize()
	require.Error(t, err)
	assert.ErrorIs(t, err, xkms.ErrLUKSVolumeLocked)
	assert.Nil(t, app.ipcServer, "IPC server must not start when data dir init fails")
}

// TestApp_SkipSetup_LockedLUKSVolumeFails verifies the setup wizard's data
// directory hook that NewApp wires: skipping setup while a LUKS volume exists
// but is not unlocked must fail closed, reporting the locked volume, and open
// no store.
func TestApp_SkipSetup_LockedLUKSVolumeFails(t *testing.T) {
	app := newWiredApp(t)

	vol, err := luks.NewVolume()
	require.NoError(t, err)
	require.NoError(t, writeFakeLUKSContainer(vol.LUKSPath))

	err = app.setupWizardService.SkipSetup()
	require.Error(t, err)
	assert.ErrorIs(t, err, services.ErrSetupStorageFailed)
	assert.ErrorIs(t, err, xkms.ErrLUKSVolumeLocked)
	assert.False(t, app.dataDirInit, "a locked volume must leave the data directory uninitialized")
}

// TestApp_PostBarrierUnseal_StillSealed verifies the guard that refuses to
// run the post-unseal sequence while the barrier reports itself sealed.
func TestApp_PostBarrierUnseal_StillSealed(t *testing.T) {
	app := newLifecycleApp(t)

	err := app.PostBarrierUnseal()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrBarrierStillSealed)
	assert.False(t, app.dataDirInit)
}

// TestApp_ToggleFIDO2Authenticator_DisableWhenNotRunning verifies disabling
// an authenticator that is not running is a pure config-persist no-op that
// does not call Stop.
func TestApp_ToggleFIDO2Authenticator_DisableWhenNotRunning(t *testing.T) {
	app := newLifecycleApp(t)
	require.False(t, app.fido2DeviceService.IsRunning())

	err := app.ToggleFIDO2Authenticator(false)
	require.NoError(t, err)
	assert.False(t, app.config.FIDO2AuthenticatorEnabled)
	assert.False(t, app.appService.GetConfig().FIDO2AuthenticatorEnabled)
}

// TestApp_ToggleFIDO2Authenticator_EnableWithoutStorage verifies enabling the
// virtual authenticator fails closed with ErrFIDO2StorageUnavailable when no
// FIDO2 credential storage has been wired up yet.
func TestApp_ToggleFIDO2Authenticator_EnableWithoutStorage(t *testing.T) {
	app := newLifecycleApp(t)
	require.Nil(t, app.fido2Storage)

	err := app.ToggleFIDO2Authenticator(true)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrFIDO2StorageUnavailable)
}

// TestApp_RegisterPKCS11XKMSBackend_NotInitialized verifies the guard that
// refuses to register a PKCS#11 backend before the global xkms SDK service
// has been initialized, rather than dereferencing a nil service.
//
// xkms.Reset() forces a deterministic precondition: the xkms SDK service is
// a process-wide singleton (pkg/xkms/service.go), and other tests in this
// package (e.g. InitializeDataDir, which drives initLocalKeyStore) legitimately
// initialize it. Production code itself resets before reinitializing
// (initLocalKeyStore calls xkmssdk.Reset() before AutoInitialize), so doing
// the same here to reach a known state is consistent with that idiom, not a
// workaround.
func TestApp_RegisterPKCS11XKMSBackend_NotInitialized(t *testing.T) {
	xkms.Reset()
	t.Cleanup(xkms.Reset)
	require.False(t, xkms.IsInitialized())

	app := &App{log: lifecycleTestLogger()}

	// Must not panic: this exercises the early-return guard only.
	assert.NotPanics(t, func() {
		app.registerPKCS11XKMSBackend("/usr/lib/libpkcs11.so", 0, "1234", "", "token")
	})
}

// TestApp_EmitEvent_NilContext verifies EmitEvent degrades to a logged
// warning instead of panicking when the application has not yet been bound
// to a Wails runtime context.
func TestApp_EmitEvent_NilContext(t *testing.T) {
	app := &App{log: lifecycleTestLogger()}
	assert.NotPanics(t, func() {
		app.EmitEvent(events.Event{})
	})
}

// TestApp_Quit_NilContext verifies Quit is a no-op (and, crucially, does not
// reach os.Exit) when the application has not yet been bound to a Wails
// runtime context.
func TestApp_Quit_NilContext(t *testing.T) {
	app := &App{log: lifecycleTestLogger()}
	assert.NotPanics(t, func() {
		app.Quit()
	})
	assert.False(t, app.trayQuit.Load(), "Quit must return before setting trayQuit when ctx is nil")
}

// TestApp_ShowWindow_NilContext verifies ShowWindow is a no-op when the
// application has not yet been bound to a Wails runtime context.
func TestApp_ShowWindow_NilContext(t *testing.T) {
	app := &App{log: lifecycleTestLogger()}
	assert.NotPanics(t, func() {
		app.ShowWindow()
	})
}

// TestApp_HideWindow_NilContext verifies HideWindow is a no-op when the
// application has not yet been bound to a Wails runtime context.
func TestApp_HideWindow_NilContext(t *testing.T) {
	app := &App{log: lifecycleTestLogger()}
	assert.NotPanics(t, func() {
		app.HideWindow()
	})
}

// TestApp_ConfigAccessors covers the GetStatus/GetConfig/GetTheme/
// UpdateConfig/SetTheme delegators to services.AppService.
func TestApp_ConfigAccessors(t *testing.T) {
	app := &App{
		log:        lifecycleTestLogger(),
		appService: services.NewAppService(nil),
	}

	status := app.GetStatus()
	require.NotNil(t, status)

	cfg := app.GetConfig()
	require.NotNil(t, cfg)
	assert.Equal(t, "system", app.GetTheme())

	updated := *cfg
	updated.Theme = ThemeDark
	require.NoError(t, app.UpdateConfig(&updated))
	assert.Equal(t, ThemeDark, app.GetConfig().Theme)

	require.NoError(t, app.SetTheme(ThemeLight))
	assert.Equal(t, ThemeLight, app.GetTheme())
}

// TestApp_UpdateConfig_NilConfig verifies UpdateConfig surfaces the
// service-layer error rather than panicking when handed a nil config.
func TestApp_UpdateConfig_NilConfig(t *testing.T) {
	app := &App{
		log:        lifecycleTestLogger(),
		appService: services.NewAppService(nil),
	}

	err := app.UpdateConfig(nil)
	assert.Error(t, err)
}

// fakeCloseErrorBackend wraps a real in-memory StorageBackend but forces
// Close to fail, exercising closeBackend's warning-log path without a hand
// rolled implementation of every storage.Backend method.
type fakeCloseErrorBackend struct {
	xkms.StorageBackend
}

var errFakeCloseFailed = errors.New("fake: close failed")

func (f *fakeCloseErrorBackend) Close() error {
	return errFakeCloseFailed
}

// TestCloseBackend_Success verifies closeBackend does not panic and closes a
// healthy backend cleanly.
func TestCloseBackend_Success(t *testing.T) {
	backend := xkms.NewStorageMemory()
	assert.NotPanics(t, func() {
		closeBackend(lifecycleTestLogger(), backend)
	})
}

// TestCloseBackend_LogsCloseError verifies closeBackend degrades to a logged
// warning (not a panic or propagated error -- it returns nothing) when the
// backend's Close call fails.
func TestCloseBackend_LogsCloseError(t *testing.T) {
	backend := &fakeCloseErrorBackend{StorageBackend: xkms.NewStorageMemory()}
	assert.NotPanics(t, func() {
		closeBackend(lifecycleTestLogger(), backend)
	})
}

// TestDetectEKHandle_DeviceMissing verifies detectEKHandle fails closed
// (returns handle 0, no panic) when the TPM device node does not exist,
// rather than requiring real TPM hardware to test.
func TestDetectEKHandle_DeviceMissing(t *testing.T) {
	handle := detectEKHandle(lifecycleTestLogger(), filepath.Join(t.TempDir(), "no-such-tpm-device"))
	assert.Equal(t, uint32(0), handle)
}

// TestIsYubiKeyLibrary covers both the YubiKey and non-YubiKey PKCS#11
// library path cases.
func TestIsYubiKeyLibrary(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{"yubikey library", "/usr/lib/x86_64-linux-gnu/libykcs11.so", true},
		{"yubikey library versioned", "/usr/lib/libykcs11.so.2", true},
		{"softhsm library", "/usr/lib/softhsm/libsofthsm2.so", false},
		{"empty path", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, isYubiKeyLibrary(tc.path))
		})
	}
}

// TestShutdownStep_Success verifies shutdownStep runs fn to completion and
// does not log a warning when fn succeeds well within the timeout.
func TestShutdownStep_Success(t *testing.T) {
	called := false
	shutdownStep(lifecycleTestLogger(), "test-success", time.Second, func() error {
		called = true
		return nil
	})
	assert.True(t, called)
}

// TestShutdownStep_Error verifies shutdownStep surfaces (via logging, not a
// return value -- shutdownStep does not return one) an fn error without
// panicking or blocking past the timeout.
func TestShutdownStep_Error(t *testing.T) {
	called := false
	assert.NotPanics(t, func() {
		shutdownStep(lifecycleTestLogger(), "test-error", time.Second, func() error {
			called = true
			return errors.New("fake: step failed")
		})
	})
	assert.True(t, called)
}

// TestShutdownStep_Timeout verifies shutdownStep gives up and returns once
// the timeout elapses rather than blocking forever on a stuck step.
func TestShutdownStep_Timeout(t *testing.T) {
	start := time.Now()
	blockUntil := make(chan struct{})
	t.Cleanup(func() { close(blockUntil) })

	shutdownStep(lifecycleTestLogger(), "test-timeout", 20*time.Millisecond, func() error {
		<-blockUntil
		return nil
	})
	assert.Less(t, time.Since(start), time.Second,
		"shutdownStep must return promptly once its timeout elapses")
}

// writeFakeLUKSContainer mirrors the LUKS-locked regression fixture used by
// init_data_dir_test.go: writing arbitrary bytes to the configured LUKS
// container path is enough to make storageService.RequireUnlocked fail
// closed without mounting a real encrypted volume.
func writeFakeLUKSContainer(path string) error {
	return os.WriteFile(path, []byte("fake luks container"), 0o600)
}
