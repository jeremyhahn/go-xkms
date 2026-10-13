package gui

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newReturningUserApp builds a headless App for a returning user whose
// storage is the barrier, with the window context unset so no Wails call
// is reachable.
func newReturningUserApp(t *testing.T, mutate func(cfg *GUIConfig)) *App {
	t.Helper()
	isolateAppEnv(t)

	cfg := DefaultGUIConfig()
	cfg.AutoTray = false
	cfg.AutoUnsealEnabled = false
	cfg.BarrierAutoUnsealEnabled = false
	cfg.FIDO2AuthenticatorEnabled = false
	mutate(cfg)

	app := NewApp(cfg)
	require.Nil(t, app.ctx)
	return app
}

// sealBarrierOnDisk creates the barrier root key with a passphrase and seals
// it again, as a previous session would have left it.
func sealBarrierOnDisk(t *testing.T, app *App) {
	t.Helper()
	require.NoError(t, app.barrierService.Initialize("test-password", "passphrase"))
	require.NoError(t, app.barrierService.Seal())
	require.True(t, app.barrierService.IsSealed(), "precondition: the barrier must be sealed")
}

// persistedConfig reads back the GUI config that startup saved.
func persistedConfig(t *testing.T) *GUIConfig {
	t.Helper()
	cfg, err := LoadGUIConfig()
	require.NoError(t, err)
	return cfg
}

func TestApp_StartupReturningUser_MissingRootKeyPrefersSealerBackend(t *testing.T) {
	app := newReturningUserApp(t, func(cfg *GUIConfig) {
		cfg.StorageType = "barrier"
		cfg.BarrierInitialized = true
		cfg.BarrierStrategy = "passphrase"
		cfg.SealerBackend = "tpm2"
	})

	app.startupReturningUser(context.Background())

	assert.False(t, app.config.BarrierInitialized,
		"a barrier whose root key is missing must be re-initialized on first unlock")
	assert.Equal(t, "tpm2", app.config.BarrierStrategy,
		"the stale strategy must give way to the user's sealer backend")
	assert.False(t, app.dataDirInit, "data dir stores must remain unopened while the barrier is missing")

	saved := persistedConfig(t)
	assert.False(t, saved.BarrierInitialized)
	assert.Equal(t, "tpm2", saved.BarrierStrategy)
}

func TestApp_StartupReturningUser_RootKeyOnDiskRepairsConfig(t *testing.T) {
	app := newReturningUserApp(t, func(cfg *GUIConfig) {
		cfg.StorageType = "barrier"
		cfg.BarrierInitialized = false
		cfg.BarrierStrategy = ""
	})
	sealBarrierOnDisk(t, app)

	app.startupReturningUser(context.Background())

	assert.True(t, app.config.BarrierInitialized, "the config must reflect the root key found on disk")
	assert.Equal(t, "passphrase", app.config.BarrierStrategy, "the strategy must be read from disk")
	assert.False(t, app.dataDirInit, "a sealed barrier defers data dir initialization until unseal")

	saved := persistedConfig(t)
	assert.True(t, saved.BarrierInitialized)
	assert.Equal(t, "passphrase", saved.BarrierStrategy)
}

func TestApp_StartupReturningUser_NoStorageTypeWithRootKeyEnablesBarrier(t *testing.T) {
	app := newReturningUserApp(t, func(cfg *GUIConfig) {
		cfg.StorageType = ""
	})
	sealBarrierOnDisk(t, app)

	app.startupReturningUser(context.Background())

	assert.Equal(t, "barrier", app.config.StorageType)
	assert.True(t, app.config.BarrierInitialized)
	assert.Equal(t, "passphrase", app.config.BarrierStrategy)
	assert.False(t, app.dataDirInit)

	saved := persistedConfig(t)
	assert.Equal(t, "barrier", saved.StorageType)
	assert.True(t, saved.BarrierInitialized)
}

func TestApp_StartupReturningUser_NoStorageTypeDefaultsToSealerBackend(t *testing.T) {
	app := newReturningUserApp(t, func(cfg *GUIConfig) {
		cfg.StorageType = ""
		cfg.BarrierStrategy = ""
		cfg.SealerBackend = "tpm2"
	})

	app.startupReturningUser(context.Background())

	assert.Equal(t, "barrier", app.config.StorageType, "data must never be stored in plain text")
	assert.False(t, app.config.BarrierInitialized)
	assert.Equal(t, "tpm2", app.config.BarrierStrategy)

	saved := persistedConfig(t)
	assert.Equal(t, "barrier", saved.StorageType)
	assert.Equal(t, "tpm2", saved.BarrierStrategy)
}
