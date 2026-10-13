package gui

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/backendregistry"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/services"
)

// newWiredApp builds a headless App through NewApp so the service
// callbacks it wires are the ones under test.
func newWiredApp(t *testing.T) *App {
	t.Helper()
	return newReturningUserApp(t, func(cfg *GUIConfig) {
		cfg.LocalAppAccessEnabled = false
	})
}

// registerReadyBackend adds a connected local backend to the app registry.
func registerReadyBackend(t *testing.T, app *App, id string) {
	t.Helper()
	rb := &backendregistry.RegisteredBackend{
		ID:          id,
		Location:    backendregistry.LocationLocal,
		Category:    backendregistry.CategoryTPM2,
		DisplayName: id,
		Capabilities: map[backendregistry.Capability]bool{
			backendregistry.CapSealing: true,
		},
		Metadata: map[string]string{},
	}
	rb.SetState(backendregistry.StateReady)
	require.NoError(t, app.backendRegistry.Register(rb))
}

func TestNewApp_SetDefaultBackendPersistsSealerBackend(t *testing.T) {
	app := newWiredApp(t)
	registerReadyBackend(t, app, "tpm2")

	require.NoError(t, app.adminService.SetDefaultBackend("tpm2"))

	assert.Equal(t, "tpm2", app.config.SealerBackend)
	assert.Equal(t, "tpm2", app.sealService.DefaultBackend())
	assert.Equal(t, "tpm2", persistedConfig(t).SealerBackend,
		"the default backend must survive a restart")
}

func TestNewApp_SetDefaultBackendUnknownLeavesConfig(t *testing.T) {
	app := newWiredApp(t)
	before := app.config.SealerBackend

	err := app.adminService.SetDefaultBackend("missing")

	require.ErrorIs(t, err, services.ErrAdminBackendNotFound)
	assert.Equal(t, before, app.config.SealerBackend)
}

func TestNewApp_ConfigUpdaterSyncsServices(t *testing.T) {
	app := newWiredApp(t)
	data := app.appService.GetConfig()
	data.ClipboardTimeout = 45
	data.AppAutoLockMinutes = 7
	data.AppLockOnScreenLock = true
	data.SealerBackend = "software"

	require.NoError(t, app.appService.UpdateConfig(data))

	assert.Equal(t, 45, app.clipboardService.GetTimeout())
	lock := app.appLockService.GetStatus()
	assert.Equal(t, 7, lock.AutoLockMinutes)
	assert.True(t, lock.LockOnScreenLock)
	assert.Equal(t, "software", app.sealService.DefaultBackend())

	saved := persistedConfig(t)
	assert.Equal(t, 45, saved.ClipboardTimeout)
	assert.Equal(t, 7, saved.AppAutoLockMinutes)
	assert.Equal(t, "software", saved.SealerBackend)
}

func TestNewApp_ConfigUpdaterRejectsInvalidProtocol(t *testing.T) {
	app := newWiredApp(t)
	data := app.appService.GetConfig()
	data.ServerProtocol = "gopher"
	data.ClipboardTimeout = 99

	err := app.appService.UpdateConfig(data)

	require.ErrorIs(t, err, ErrInvalidProtocol)
	assert.NotEqual(t, 99, app.config.ClipboardTimeout, "a rejected config must not be applied")
	assert.NotEqual(t, 99, app.clipboardService.GetTimeout())
}

func TestNewApp_StatusReportsNothingBeforeStoresOpen(t *testing.T) {
	app := newWiredApp(t)

	status := app.appService.GetStatus()

	require.NotNil(t, status)
	assert.Zero(t, status.KeyCount)
	assert.Zero(t, status.OATHAccountCount)
	assert.Zero(t, status.FIDO2CredCount)
	assert.Zero(t, status.PIVCertCount)
	assert.Zero(t, status.RemoteKeyCount)
	assert.False(t, status.ServerConnected)
	assert.False(t, status.BridgeRunning)
	assert.False(t, status.StorageMounted)
}

func TestNewApp_ListBackendsWithoutServerFallsBackToLocal(t *testing.T) {
	app := newWiredApp(t)
	registerReadyBackend(t, app, "tpm2-lab")

	backends, err := app.adminService.ListBackends()

	require.NoError(t, err)
	ids := make([]string, 0, len(backends))
	for _, b := range backends {
		ids = append(ids, b.ID)
	}
	assert.Contains(t, ids, "tpm2-lab", "with no server the local registry must be listed")
}

func TestNewApp_RequireAuthenticationPersistsAutofillPolicy(t *testing.T) {
	app := newWiredApp(t)

	require.NoError(t, app.autofillService.SetRequireAuthentication(false))

	saved := persistedConfig(t)
	require.NotNil(t, saved.AutoFillPolicy)
	assert.False(t, saved.AutoFillPolicy.RequireAuthentication)
	assert.False(t, app.config.AutoFillPolicy.RequireAuthentication)
}
