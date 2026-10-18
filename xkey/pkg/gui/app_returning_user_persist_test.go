package gui

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/events"
)

// blockGUIConfigSave makes the GUI config path a non-empty directory, so
// every SaveGUIConfig fails at the atomic rename.
func blockGUIConfigSave(t *testing.T) {
	t.Helper()
	cfgPath, err := guiConfigPath()
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Join(cfgPath, "entry"), 0o700))
}

// TestApp_StartupReturningUser_RepairSurvivesUnsavableConfig verifies that
// each startup config repair still takes effect in memory, and is logged,
// when the corrected config cannot be persisted.
func TestApp_StartupReturningUser_RepairSurvivesUnsavableConfig(t *testing.T) {
	tests := []struct {
		name       string
		mutate     func(cfg *GUIConfig)
		rootKey    bool
		wantInit   bool
		wantPolicy string
	}{
		{
			name: "root key on disk restores the initialized flag",
			mutate: func(cfg *GUIConfig) {
				cfg.StorageType = "barrier"
				cfg.BarrierInitialized = false
				cfg.BarrierStrategy = ""
			},
			rootKey:    true,
			wantInit:   true,
			wantPolicy: "passphrase",
		},
		{
			name: "missing root key clears the initialized flag",
			mutate: func(cfg *GUIConfig) {
				cfg.StorageType = "barrier"
				cfg.BarrierInitialized = true
				cfg.BarrierStrategy = ""
				cfg.SealerBackend = ""
			},
			wantInit:   false,
			wantPolicy: "passphrase",
		},
		{
			name: "missing storage type defaults to the barrier",
			mutate: func(cfg *GUIConfig) {
				cfg.StorageType = ""
				cfg.BarrierStrategy = ""
				cfg.SealerBackend = ""
			},
			wantInit:   false,
			wantPolicy: "passphrase",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := newReturningUserApp(t, tt.mutate)
			if tt.rootKey {
				sealBarrierOnDisk(t, app)
			}
			blockGUIConfigSave(t)
			logs := captureLog(app)

			app.startupReturningUser(t.Context())

			assert.Equal(t, "barrier", app.config.StorageType)
			assert.Equal(t, tt.wantInit, app.config.BarrierInitialized)
			assert.Equal(t, tt.wantPolicy, app.config.BarrierStrategy)
			assert.True(t, logs.Contains("failed to persist corrected config"))
		})
	}
}

// TestApp_Startup_ReturningUserWaitsForBarrierPassword verifies that
// startup routes a returning user with a sealed barrier to the unlock
// dialog, and that enabling lock-on-screen-lock never fails startup:
// without a system bus the monitor is reported unavailable.
func TestApp_Startup_ReturningUserWaitsForBarrierPassword(t *testing.T) {
	app, window, _ := windowedApp(t)
	app.config.SetupComplete = true
	app.config.StorageType = "barrier"
	app.config.BarrierInitialized = true
	app.config.BarrierStrategy = "passphrase"
	app.config.BarrierAutoUnsealEnabled = false
	app.config.AutoUnsealEnabled = false
	app.config.AppLockOnScreenLock = true
	app.config.ServerAutoConnect = false
	app.config.AutoTray = false
	sealBarrierOnDisk(t, app)
	logs := captureLog(app)

	app.startup(app.ctx)
	t.Cleanup(func() {
		if app.screenLockMonitor != nil {
			assert.NoError(t, app.screenLockMonitor.Close())
		}
	})

	assert.Contains(t, window.Events(), string(events.EventBarrierLocked))
	assert.False(t, app.dataDirInit, "a sealed barrier defers data dir initialization")
	assert.True(t, app.screenLockMonitor != nil || logs.Contains("screen lock monitor unavailable"),
		"the screen lock monitor must either run or be reported unavailable")
}
