package gui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/services"
)

// Tests for the callbacks NewApp wires between services. Each test drives a
// service through its public method and checks the effect NewApp's wiring
// promises, so a dropped or mis-wired callback fails here.

// newBackendsServer serves a health response for every path except
// /api/v1/backends, which answers with backendsStatus and backendsBody.
func newBackendsServer(t *testing.T, backendsStatus int, backendsBody string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v1/backends" {
			w.WriteHeader(backendsStatus)
			_, _ = w.Write([]byte(backendsBody))
			return
		}
		_, _ = w.Write([]byte(`{"status":"ok","version":"v"}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// connectWiredApp connects app's ConnectionService to srv over REST. The
// connect event goes through NewApp's emitter while a.ctx is still nil (no
// Wails runtime); a.ctx is then set the way startup sets it, so server calls
// made with it carry a live context. It is cleared again before cleanup
// disconnects, so the disconnect event is not sent to a Wails runtime.
func connectWiredApp(t *testing.T, app *App, srv *httptest.Server) {
	t.Helper()
	app.connectionService.SetContext(context.Background())
	_, err := app.connectionService.Connect("rest", srv.Listener.Addr().String(), false, "", "")
	require.NoError(t, err)
	app.ctx = context.Background()
	t.Cleanup(func() {
		app.ctx = nil
		assert.NoError(t, app.connectionService.Disconnect())
	})
}

func TestNewApp_ConnectedServerListsRemoteBackends(t *testing.T) {
	app := newWiredApp(t)
	srv := newBackendsServer(t, http.StatusOK,
		`{"backends":[{"id":"hsm-1","type":"pkcs11"},{"id":"soft","type":"software"}]}`)
	connectWiredApp(t, app, srv)

	backends, err := app.adminService.ListBackends()
	require.NoError(t, err)
	require.Len(t, backends, 2)
	assert.Equal(t, "hsm-1", backends[0].ID)
	assert.Equal(t, "pkcs11", backends[0].Type)
	assert.True(t, backends[0].Enabled, "server backends are reported enabled")
	assert.Equal(t, "soft", backends[1].ID)

	status, err := app.adminService.GetServerStatus()
	require.NoError(t, err)
	assert.True(t, status.Running)
	assert.Equal(t, 2, status.BackendCount)

	dash := app.appService.GetStatus()
	assert.True(t, dash.ServerConnected, "the dashboard follows the connection service")
	assert.Equal(t, srv.Listener.Addr().String(), dash.ServerAddress)
}

func TestNewApp_RemoteBackendFailureFallsBackToLocal(t *testing.T) {
	app := newWiredApp(t)
	srv := newBackendsServer(t, http.StatusInternalServerError, `{"error":"boom"}`)
	connectWiredApp(t, app, srv)

	backends, err := app.adminService.ListBackends()
	require.NoError(t, err, "a failing server listing falls back to local backends")
	for _, b := range backends {
		assert.NotEqual(t, "hsm-1", b.ID)
	}

	status, err := app.adminService.GetServerStatus()
	require.NoError(t, err)
	assert.True(t, status.Running, "the server is still connected")
	assert.Zero(t, status.BackendCount, "no backend count when the listing failed")
}

func TestApp_Shutdown_DisconnectsTheServer(t *testing.T) {
	app := newWiredApp(t)
	srv := newBackendsServer(t, http.StatusOK, `{"backends":[]}`)
	app.connectionService.SetContext(context.Background())
	_, err := app.connectionService.Connect("rest", srv.Listener.Addr().String(), false, "", "")
	require.NoError(t, err)
	require.True(t, app.connectionService.IsConnected())

	app.shutdown(context.Background())

	assert.False(t, app.connectionService.IsConnected(), "shutdown must close the server connection")
	assert.Equal(t, "disconnected", app.connectionService.GetConnectionInfo().State)
	assert.ErrorIs(t, app.connectionService.Disconnect(), services.ErrServerNotConnected,
		"nothing is left connected after shutdown")
}

func TestNewApp_FIDO2ToggleWithoutStorageFails(t *testing.T) {
	app := newWiredApp(t)

	err := app.appService.ToggleFIDO2Authenticator(true)

	require.ErrorIs(t, err, ErrFIDO2StorageUnavailable)
	assert.False(t, app.config.FIDO2AuthenticatorEnabled, "a refused toggle must not persist")
	assert.False(t, app.appService.GetConfig().FIDO2AuthenticatorEnabled)
}

func TestNewApp_FIDO2ToggleOffPersists(t *testing.T) {
	app := newReturningUserApp(t, func(cfg *GUIConfig) {
		cfg.LocalAppAccessEnabled = false
		cfg.FIDO2AuthenticatorEnabled = true
	})

	require.NoError(t, app.appService.ToggleFIDO2Authenticator(false))

	assert.False(t, app.config.FIDO2AuthenticatorEnabled)
	assert.False(t, app.appService.GetConfig().FIDO2AuthenticatorEnabled)
	saved, err := LoadGUIConfig()
	require.NoError(t, err)
	assert.False(t, saved.FIDO2AuthenticatorEnabled, "the preference is written to the GUI config")
}

func TestNewApp_SkipSetupInitializesDataDirAndPersists(t *testing.T) {
	app := newWiredApp(t)
	require.False(t, app.setupWizardService.IsSetupComplete(), "precondition: a fresh config has not completed setup")

	require.NoError(t, app.setupWizardService.SkipSetup())
	t.Cleanup(xkmssdk.Reset)
	t.Cleanup(func() {
		if app.expiryChecker != nil {
			app.expiryChecker.Stop()
		}
	})

	assert.True(t, app.setupWizardService.IsSetupComplete())
	assert.NotEmpty(t, app.dataDir, "skipping setup creates the data directory")
	assert.True(t, app.dataReady.Load(), "a fresh data directory runs the post-data-dir startup")
	saved, err := LoadGUIConfig()
	require.NoError(t, err)
	assert.True(t, saved.SetupComplete)
	assert.Equal(t, "barrier", saved.StorageType, "skipped setup defaults to barrier storage")

	// A second skip finds the data directory ready and still succeeds.
	require.NoError(t, app.setupWizardService.SkipSetup())
}

func TestNewApp_DashboardCountsLocalCredentials(t *testing.T) {
	app := newWiredApp(t)
	require.NoError(t, app.initializeDataDir())
	t.Cleanup(xkmssdk.Reset)
	require.NotNil(t, app.oathStore, "precondition: the data directory opens the OATH store")
	require.NotNil(t, app.fido2Storage, "precondition: the data directory opens the FIDO2 store")

	_, err := app.oathService.AddAccountManual("alice@example.com", "Example", "JBSWY3DPEHPK3PXP")
	require.NoError(t, err)

	status := app.appService.GetStatus()
	assert.Equal(t, 1, status.OATHAccountCount)
	assert.Zero(t, status.FIDO2CredCount)
	assert.Equal(t, 1, status.KeyCount, "the key count sums OATH accounts and FIDO2 credentials")
}
