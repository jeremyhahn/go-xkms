package gui

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/backendregistry"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/config"
)

// A settings change that carries an autofill policy is applied to the
// running autofill service, not only written to disk.
func TestApp_UpdateConfig_AppliesAutoFillPolicy(t *testing.T) {
	app := newWiredApp(t)
	policy := xkmssdk.DefaultAutoFillPolicy()
	policy.MaxFillsPerMinute = 7

	data := app.appService.GetConfig()
	data.AutoFillPolicy = policy
	require.NoError(t, app.appService.UpdateConfig(data))

	assert.Same(t, policy, app.autofillService.GetPolicy())
	assert.Same(t, policy, app.config.AutoFillPolicy)
}

// A settings change that cannot be saved leaves the running configuration
// untouched, so memory never drifts from what is on disk.
func TestApp_UpdateConfig_SaveFailureKeepsRunningConfig(t *testing.T) {
	app := newWiredApp(t)
	before := app.config

	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	require.NoError(t, os.WriteFile(blocker, nil, 0o600))
	t.Setenv("XDG_CONFIG_HOME", blocker)

	data := app.appService.GetConfig()
	data.ClipboardTimeout = before.ClipboardTimeout + 5
	err := app.appService.UpdateConfig(data)

	require.ErrorIs(t, err, ErrConfigSave)
	assert.Same(t, before, app.config)
}

// A configured backend whose id is already taken is skipped without stopping
// the rest of the configuration from loading.
func TestApp_PopulateBackendRegistry_SkipsCollidingEntries(t *testing.T) {
	app := newWiredApp(t)

	ucfg, err := config.Load()
	require.NoError(t, err)
	ucfg.Backends.Local = append(ucfg.Backends.Local,
		config.LocalBackendConfig{ID: "taken-local", Category: "software", Name: "Taken"},
		config.LocalBackendConfig{ID: "hsm-a", Category: "pkcs11", Name: "HSM"})
	ucfg.Backends.Remote = append(ucfg.Backends.Remote,
		config.RemoteBackendConfig{ID: "taken-remote", Name: "Taken", Address: "127.0.0.1:1", Protocol: "rest"},
		config.RemoteBackendConfig{ID: "remote-a", Name: "Remote", Address: "127.0.0.1:2", Protocol: "rest"})
	require.NoError(t, config.Save(ucfg))

	registry := backendregistry.NewMemoryRegistry()
	for _, id := range []string{"taken-local", "taken-remote"} {
		require.NoError(t, registry.Register(&backendregistry.RegisteredBackend{
			ID: id, Location: backendregistry.LocationLocal, Category: backendregistry.CategoryTPM2, DisplayName: "pre-existing",
		}))
	}
	app.backendRegistry = registry

	app.populateBackendRegistry()

	taken, err := registry.Get("taken-remote")
	require.NoError(t, err)
	assert.Equal(t, "pre-existing", taken.DisplayName, "a colliding entry must not replace the registered backend")
	hsm, err := registry.Get("hsm-a")
	require.NoError(t, err)
	assert.Equal(t, backendregistry.StateOffline, hsm.State(), "a PKCS#11 backend starts offline until its PIN is given")
	remote, err := registry.Get("remote-a")
	require.NoError(t, err)
	assert.Equal(t, backendregistry.LocationRemote, remote.Location)
	_, err = registry.Get("software")
	require.NoError(t, err, "the software backend is always registered")
}

// Disabling auto-unseal clears its settings from the running configuration
// even when the sealed blob is already gone.
func TestApp_DisableAutoUnseal_ClearsSavedSettings(t *testing.T) {
	app := newWiredApp(t)
	enabled := app.appService.GetConfig()
	enabled.AutoUnsealEnabled = true
	enabled.AutoUnsealBlobID = "missing-blob"
	enabled.AutoUnsealBackend = "tpm2"
	require.NoError(t, app.appService.UpdateConfig(enabled))

	require.NoError(t, app.autoUnsealService.Disable())

	assert.False(t, app.config.AutoUnsealEnabled)
	assert.Empty(t, app.config.AutoUnsealBlobID)
	assert.Empty(t, app.config.AutoUnsealBackend)
	reloaded, err := LoadGUIConfig()
	require.NoError(t, err)
	assert.Empty(t, reloaded.AutoUnsealBlobID, "the cleared settings must be persisted")
}
