package gui

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/sdk/go/truststore"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/agent"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/services"
)

// withTrustBundleOptIn wires a browser service whose user has opted in to
// exporting the trust bundle at startup.
func withTrustBundleOptIn(t *testing.T, app *App) {
	t.Helper()
	browser, err := services.NewBrowserService(filepath.Join(t.TempDir(), "browser.json"), app.log)
	require.NoError(t, err)
	cfg := browser.GetConfig()
	cfg.IncludeTrustBundle = true
	require.NoError(t, browser.SetConfig(cfg))
	app.browserService = browser
}

// With the opt-in set, startup exports the bootstrap CAs of the trust store
// as the browser bundle under the data directory.
func TestInitializeDataDir_ExportsBrowserTrustBundleWhenOptedIn(t *testing.T) {
	app := newMinimalApp(t)
	withTrustBundleOptIn(t, app)
	dir := filepath.Join(t.TempDir(), "data")
	seed, err := truststore.NewFileStore(&truststore.FileStoreConfig{BaseDir: filepath.Join(dir, "trust")})
	require.NoError(t, err)
	require.NoError(t, seed.AddCertificateWithOptions(newPIVTestCert(t), &truststore.AddCertificateOptions{
		Purpose: truststore.PurposeBootstrapCA,
		Source:  "test",
	}))
	require.NoError(t, seed.Close())
	app.dataDir = dir

	require.NoError(t, app.initializeDataDir())

	bundle, err := os.ReadFile(filepath.Join(dir, "browser", "trust-bundle.pem"))
	require.NoError(t, err)
	assert.Contains(t, string(bundle), "-----BEGIN CERTIFICATE-----")
}

// With the opt-in set but no trust store, the export is refused and the data
// directory still initializes.
func TestInitializeDataDir_BrowserTrustBundleWithoutTrustStoreIsSkipped(t *testing.T) {
	app := newMinimalApp(t)
	withTrustBundleOptIn(t, app)
	logs := captureLog(app)
	dir := filepath.Join(t.TempDir(), "data")
	require.NoError(t, os.MkdirAll(dir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "trust"), nil, 0o600))
	app.dataDir = dir

	require.NoError(t, app.initializeDataDir())

	assert.True(t, logs.Contains("failed to export browser trust bundle"))
	assert.NoFileExists(t, filepath.Join(dir, "browser", "trust-bundle.pem"))
}

// A broken unified config, a corrupt extension pairing state, and blocked
// agent-enrollment and sealed-blob paths each disable only their own feature:
// the data directory still initializes.
func TestInitializeDataDir_BrokenConfigAndStateDisableOnlyTheirFeature(t *testing.T) {
	cfgPath := isolateUnifiedConfig(t)
	require.NoError(t, os.WriteFile(cfgPath, []byte("oidc: [unterminated\n"), 0o600))

	app := newMinimalApp(t)
	logs := captureLog(app)
	dir := filepath.Join(t.TempDir(), "data")
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "extension"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "extension", "pairing.json"), []byte("{not json"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, agent.DataSubdir), nil, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "sealed"), nil, 0o600))
	app.dataDir = dir

	require.NoError(t, app.initializeDataDir())

	assert.True(t, app.dataDirInit)
	for _, msg := range []string{
		"unified config failed to load; OIDC login is disabled until it is fixed",
		"failed to create pairing verifier",
		"agent enrollment disabled: failed to open the enrollment store",
		"failed to set seal storage directory",
	} {
		assert.True(t, logs.Contains(msg), "missing log %q", msg)
	}
}
