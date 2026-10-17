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
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/events"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/notify"
)

// logBuffer is a concurrency-safe log sink for asserting on App log lines.
type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *logBuffer) Contains(s string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return strings.Contains(b.buf.String(), s)
}

// captureLog routes app's log into a buffer the test can read.
func captureLog(app *App) *logBuffer {
	logs := &logBuffer{}
	app.log = slog.New(slog.NewTextHandler(logs, nil))
	return logs
}

// withoutTPM points app's TPM probe at a device that does not exist, so
// nothing reaches the host TPM.
func withoutTPM(t *testing.T, app *App) {
	t.Helper()
	app.tpmConfigOnce = sync.Once{}
	app.tpmUnavailable = false
	app.tpmConfigOnce.Do(func() {
		app.tpmCachedConfig = xkmssdk.TPMConfig{Device: filepath.Join(t.TempDir(), "no-tpm")}
	})
}

func TestApp_Startup_WiresEmittersToTheWindow(t *testing.T) {
	app, window, _ := windowedApp(t)
	app.config.SetupComplete = false
	app.config.AppLockOnScreenLock = false

	app.startup(app.ctx)

	require.NoError(t, app.deviceNotifier.NotifyTouchRequired(&notify.TouchRequest{Operation: "get_assertion"}))
	assert.Contains(t, window.Events(), "fido2:touch_required", "a touch request must reach the frontend")
	assert.Contains(t, window.Calls(), "show", "a touch request must bring the window forward")

	// Locking may fail to seal a barrier that was never created; the lock
	// itself must still be announced.
	if err := app.appLockService.Lock(); err != nil {
		t.Logf("lock: %v", err)
	}
	assert.Contains(t, window.Events(), "app:locked", "the app lock emitter must reach the frontend")
}

func TestApp_Startup_AutoConnectFailureIsLogged(t *testing.T) {
	app, _, _ := windowedApp(t)
	logs := captureLog(app)
	app.config.SetupComplete = false
	app.config.AppLockOnScreenLock = false
	app.config.ServerAutoConnect = true
	app.config.ServerAddress = "127.0.0.1:1"
	app.config.ServerTLSEnabled = false

	app.startup(app.ctx)

	require.Eventually(t, func() bool { return logs.Contains("auto-connect failed") },
		10*time.Second, 20*time.Millisecond, "an unreachable server must be reported, not ignored")
	assert.False(t, app.connectionService.IsConnected())
}

func TestApp_StartupReturningUser_MissingRootKeyDefaultsToPassphrase(t *testing.T) {
	app := newReturningUserApp(t, func(cfg *GUIConfig) {
		cfg.StorageType = "barrier"
		cfg.BarrierInitialized = true
		cfg.BarrierStrategy = ""
		cfg.SealerBackend = ""
	})

	app.startupReturningUser(t.Context())

	assert.False(t, app.config.BarrierInitialized)
	assert.Equal(t, "passphrase", app.config.BarrierStrategy,
		"a barrier with no strategy and no sealer backend must fall back to a passphrase")
	assert.Equal(t, "passphrase", persistedConfig(t).BarrierStrategy)
}

func TestApp_StartupReturningUser_BarrierAutoUnsealWithoutTPMStaysLocked(t *testing.T) {
	app, window, _ := windowedApp(t)
	app.config.StorageType = "barrier"
	app.config.BarrierInitialized = true
	app.config.BarrierStrategy = "passphrase"
	app.config.BarrierAutoUnsealEnabled = true
	withoutTPM(t, app)
	sealBarrierOnDisk(t, app)

	app.startupReturningUser(app.ctx)

	assert.True(t, app.barrierService.IsSealed(), "without a TPM the barrier must wait for its password")
	assert.Contains(t, window.Events(), string(events.EventBarrierLocked))
	assert.NotContains(t, window.Events(), string(events.EventBarrierUnlocked))
	assert.False(t, app.dataDirInit, "a sealed barrier defers data dir initialization")
}

func TestApp_Shutdown_FailedStepDoesNotStopTheSequence(t *testing.T) {
	app, _, _ := windowedApp(t)
	logs := captureLog(app)
	app.config.AutoUnsealEnabled = true
	app.config.AutoUnsealBlobID = "missing-blob"

	app.shutdown(app.ctx)

	assert.True(t, logs.Contains("step=reseal"), "a reseal that cannot find its blob must be logged")
	select {
	case <-app.shutdownDone:
	default:
		t.Fatal("a failed step must not stop the later shutdown steps")
	}
}

func TestApp_InitializeDataDir_BlockedStorePathsDegradeGracefully(t *testing.T) {
	app := newWiredApp(t)
	logs := captureLog(app)
	withoutTPM(t, app)
	require.False(t, app.dataDirInit, "precondition: NewApp must not open the data dir stores")

	// Each store path is taken by a regular file, so every file-backed store
	// fails to open. The data dir must still come up with what does open.
	dir := t.TempDir()
	for _, name := range []string{"fido2", "passwords", "teams", "trust", "oidc", "extension"} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), nil, 0o600))
	}
	// The OATH store is a single file, so a directory blocks it.
	require.NoError(t, os.Mkdir(filepath.Join(dir, "oath.json"), 0o700))
	app.dataDir = dir

	require.NoError(t, app.initializeDataDir())

	assert.True(t, app.dataDirInit)
	assert.Nil(t, app.oathStore)
	assert.Nil(t, app.fido2Storage)
	assert.Nil(t, app.staticpwStore)
	assert.Nil(t, app.trustStore)
	for _, warning := range []string{
		"failed to open OATH store",
		"failed to create FIDO2 storage backend",
		"failed to create FIDO2 RP policy backend",
		"failed to create password file store",
		"failed to create team file store",
		"failed to open trust store",
		"failed to create OIDC data directory",
		"failed to create extension pairing directory",
	} {
		assert.True(t, logs.Contains(warning), "missing warning %q", warning)
	}
	assert.ErrorIs(t, app.initializeDataDir(), ErrDataDirAlreadyInit)
}

func TestNewApp_CorruptBrowserConfigResetsToDefaults(t *testing.T) {
	isolateAppEnv(t)
	cfgDir, err := configDir()
	require.NoError(t, err)
	corrupt := []byte("{not json")
	browserConfig := filepath.Join(cfgDir, "browser.json")
	require.NoError(t, os.WriteFile(browserConfig, corrupt, 0o600))

	app := NewApp(DefaultGUIConfig())

	require.NotNil(t, app.browserService, "a corrupt browser config must not leave the app without a browser service")
	assert.False(t, app.browserService.GetConfig().IncludeTrustBundle, "the reset config must hold the defaults")
	if data, readErr := os.ReadFile(browserConfig); readErr == nil {
		assert.NotEqual(t, corrupt, data, "the corrupt config must be replaced")
	} else {
		assert.ErrorIs(t, readErr, os.ErrNotExist)
	}
}

func TestApp_BarrierInitialize_TPM2WithoutTPMFails(t *testing.T) {
	app := newWiredApp(t)
	withoutTPM(t, app)

	err := app.barrierService.Initialize("test-password", "tpm2")

	require.Error(t, err, "a tpm2 barrier cannot be created without a TPM to seal its key")
	assert.False(t, app.barrierService.IsUnsealed())
}
