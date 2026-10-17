package gui

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

// presetTPMConfig consumes the App's one-time TPM config load so getTPM
// probes exactly cfg, independent of any TPM config on the test host.
func presetTPMConfig(app *App, cfg xkmssdk.TPMConfig) {
	app.tpmConfigOnce.Do(func() {
		app.tpmCachedConfig = cfg
	})
}

// TestApp_GetTPM_DeviceUnopenable_ReturnsNilAndRetries verifies that a
// device path that exists but cannot be opened as a TPM yields no TPM,
// releases the storage factory it created, and is not cached as unavailable:
// the path is present, so a later call re-probes it.
func TestApp_GetTPM_DeviceUnopenable_ReturnsNilAndRetries(t *testing.T) {
	cfg := xkmssdk.DefaultTPMConfig
	cfg.UseSimulator = false
	cfg.Device = t.TempDir() // a directory: os.Stat succeeds, opening it read-write fails

	for _, dataDir := range []string{"", t.TempDir()} {
		app := &App{log: lifecycleTestLogger(), newTPM: xkmssdk.NewTPM2, dataDir: dataDir}
		presetTPMConfig(app, cfg)

		assert.Nil(t, app.getTPM(), "dataDir=%q", dataDir)
		assert.Nil(t, app.tpmInstance)
		assert.Nil(t, app.tpmStorageFactory, "the storage factory must be closed and dropped on open failure")
		assert.False(t, app.tpmUnavailable, "a present device must be re-probed, not cached as unavailable")

		assert.Nil(t, app.getTPM(), "the retry fails the same way")
	}
}

// TestApp_GetTPM_UnprovisionedTPMIsCached verifies that a TPM which answers
// but has no persistent EK yet is still surfaced (and cached with its
// storage factory) so the TPM view can show real device values before
// provisioning.
func TestApp_GetTPM_UnprovisionedTPMIsCached(t *testing.T) {
	cfg := xkmssdk.DefaultTPMConfig
	cfg.UseSimulator = true
	cfg.Device = t.TempDir() // present for the existence probe; the simulator serves the commands

	app := &App{log: lifecycleTestLogger(), newTPM: xkmssdk.NewTPM2, dataDir: t.TempDir()}
	presetTPMConfig(app, cfg)

	tpm := app.getTPM()
	require.NotNil(t, tpm, "a fresh simulator has no EK but must still be returned")
	t.Cleanup(func() {
		assert.NoError(t, tpm.Close())
		assert.NoError(t, app.tpmStorageFactory.Close())
	})

	assert.Same(t, tpm, app.tpmInstance)
	assert.NotNil(t, app.tpmStorageFactory, "the storage factory stays open with the cached TPM")
	assert.Same(t, tpm, app.getTPM(), "later calls return the cached TPM without re-opening")
}

// TestDetectEKHandle_DeviceNeverAnswers verifies that a device which opens
// but answers no ReadPublic reports no standard EK handle.
func TestDetectEKHandle_DeviceNeverAnswers(t *testing.T) {
	// /dev/null accepts every command and returns EOF to every read.
	assert.Zero(t, detectEKHandle(lifecycleTestLogger(), "/dev/null"))
}
