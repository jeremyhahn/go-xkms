package cmd

import (
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/oidc"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// TestRunOIDCLogin_OpensTheBrowser drives the browser branch of the code
// flow: the authorization URL goes to the system browser, and when the
// browser cannot start the user is told to open the printed URL by hand.
// Either way the login completes once the callback arrives.
func TestRunOIDCLogin_OpensTheBrowser(t *testing.T) {
	tests := []struct {
		name      string
		launchErr error
	}{
		{name: "opened"},
		{name: "no browser", launchErr: errors.New("no display")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			launched := withLaunchBrowser(t, tt.launchErr)
			idp := newOIDCTestIdP(t, replyWithTokens(OIDCTokenResponse{
				AccessToken: xkms.SecretBytes("browser-access"),
				ExpiresIn:   300,
			}))
			cmd, _ := oidcFlowCmd(t, map[string]string{
				"no-browser":   "false",
				"issuer":       idp.URL,
				"client-id":    "browser-client",
				"redirect-url": "http://127.0.0.1:" + freeLoopbackPort(t) + "/cb",
			})

			flow := startOIDCLogin(cmd)
			var opened string
			select {
			case opened = <-launched:
			case <-time.After(10 * time.Second):
				t.Fatalf("the browser was never launched; output:\n%s", flow.out.String())
			}
			authURL, err := url.Parse(opened)
			require.NoError(t, err)
			assert.Equal(t, "browser-client", authURL.Query().Get("client_id"))

			flow.redirect(t, authURL, url.Values{"code": {"code-1"}, "state": {authURL.Query().Get("state")}})
			require.NoError(t, flow.result(t))

			output := flow.out.String()
			assert.Contains(t, output, "Opening browser for authentication...")
			assert.Contains(t, output, "Login successful!")
			if tt.launchErr != nil {
				assert.Contains(t, output, "Failed to open browser: no display")
				assert.Contains(t, output, "Please open the following URL manually:")
			} else {
				assert.NotContains(t, output, "Please open the following URL manually:")
			}
		})
	}
}

// TestRunOIDCLogin_BackgroundRefreshHandsOffToTheWorker checks that a login
// granted a refresh token hands the refresh loop to a detached worker when
// the saved provider asks for background refresh, with the provider's
// interval, log file and token endpoint on the worker's command line.
func TestRunOIDCLogin_BackgroundRefreshHandsOffToTheWorker(t *testing.T) {
	got := withStandInWorker(t)
	idp := newOIDCTestIdP(t, replyWithTokens(OIDCTokenResponse{
		AccessToken:  xkms.SecretBytes("bg-access"),
		RefreshToken: xkms.SecretBytes("bg-refresh"),
		ExpiresIn:    600,
	}))

	cmd, store := oidcFlowCmd(t, map[string]string{"provider": "corp"})
	logFile := filepath.Join(t.TempDir(), "corp-refresh.log")
	require.NoError(t, saveOIDCConfig(getConfigPath(store), OIDCConfig{Providers: []OIDCProvider{{
		Name:        "corp",
		Issuer:      idp.URL,
		ClientID:    "corp-client",
		RedirectURL: "http://127.0.0.1:" + freeLoopbackPort(t) + "/corp/cb",
		Scopes:      []string{"openid", "offline_access"},
		AutoRefresh: 45,
		Background:  true,
		LogFile:     logFile,
	}}}))

	flow := startOIDCLogin(cmd)
	authURL := flow.authorizationURL(t, idp.URL)
	flow.redirect(t, authURL, url.Values{"code": {"code-2"}, "state": {authURL.Query().Get("state")}})
	require.NoError(t, flow.result(t))
	assert.Contains(t, flow.out.String(), "Background refresh started for 'corp'")
	waitForWorkerExit(t, getPIDFile(store, "corp"), logFile)

	target, worker := parseWorkerArgs(t, *got)
	assert.Same(t, oidcLoginCmd, target)
	interval, err := worker.Flags().GetInt("auto-refresh")
	require.NoError(t, err)
	assert.Equal(t, 45, interval)
	for flag, want := range map[string]string{
		"token-endpoint": idp.URL + "/token",
		"client-id":      "corp-client",
		"token-store":    store,
		"log-file":       logFile,
		"provider-name":  "corp",
	} {
		assert.Equal(t, want, flagString(t, worker, flag), "--%s", flag)
	}
}

// TestRunOIDCLogin_BackgroundWithoutAProviderUsesTheDefaults checks the
// flag-only background login: with no saved provider the worker runs under
// the "default" name and logs to the default log file beside the token
// store.
func TestRunOIDCLogin_BackgroundWithoutAProviderUsesTheDefaults(t *testing.T) {
	got := withStandInWorker(t)
	idp := newOIDCTestIdP(t, replyWithTokens(OIDCTokenResponse{
		AccessToken:  xkms.SecretBytes("flag-access"),
		RefreshToken: xkms.SecretBytes("flag-refresh"),
		ExpiresIn:    600,
	}))

	cmd, store := oidcFlowCmd(t, map[string]string{
		"issuer":       idp.URL,
		"client-id":    "flag-client",
		"redirect-url": "http://127.0.0.1:" + freeLoopbackPort(t) + "/cb",
		"auto-refresh": "30",
		"background":   "true",
	})

	flow := startOIDCLogin(cmd)
	authURL := flow.authorizationURL(t, idp.URL)
	flow.redirect(t, authURL, url.Values{"code": {"code-3"}, "state": {authURL.Query().Get("state")}})
	require.NoError(t, flow.result(t))
	assert.Contains(t, flow.out.String(), "Background refresh started for 'default'")

	defaultLog := getDefaultLogFile(store, "default")
	waitForWorkerExit(t, getPIDFile(store, "default"), defaultLog)

	_, worker := parseWorkerArgs(t, *got)
	assert.Equal(t, "default", flagString(t, worker, "provider-name"))
	assert.Equal(t, defaultLog, flagString(t, worker, "log-file"))
}

// withRefreshLoopStopped closes the refresh loops' stop channel for the
// test, so a loop entered under it returns on its first select instead of
// waiting for SIGINT.
func withRefreshLoopStopped(t *testing.T) {
	t.Helper()
	stop := make(chan struct{})
	close(stop)
	previous := refreshLoopStop
	refreshLoopStop = stop
	t.Cleanup(func() { refreshLoopStop = previous })
}

// TestRunOIDCLogin_ForegroundAutoRefreshRunsUntilStopped checks that a
// login granted a refresh token, without --background, announces the
// foreground refresh loop and returns cleanly when the loop is stopped.
func TestRunOIDCLogin_ForegroundAutoRefreshRunsUntilStopped(t *testing.T) {
	withRefreshLoopStopped(t)
	idp := newOIDCTestIdP(t, replyWithTokens(OIDCTokenResponse{
		AccessToken:  xkms.SecretBytes("fg-access"),
		RefreshToken: xkms.SecretBytes("fg-refresh"),
		ExpiresIn:    600,
	}))
	cmd, store := oidcFlowCmd(t, map[string]string{
		"issuer":       idp.URL,
		"client-id":    "fg-client",
		"redirect-url": "http://127.0.0.1:" + freeLoopbackPort(t) + "/cb",
		"auto-refresh": "75",
	})

	flow := startOIDCLogin(cmd)
	authURL := flow.authorizationURL(t, idp.URL)
	flow.redirect(t, authURL, url.Values{"code": {"code-4"}, "state": {authURL.Query().Get("state")}})
	require.NoError(t, flow.result(t))

	output := flow.out.String()
	assert.Contains(t, output, "Auto-refresh enabled: refreshing every 75 seconds")
	assert.NotContains(t, output, "Background refresh started")
	_, err := os.Stat(getPIDFile(store, "default"))
	assert.ErrorIs(t, err, os.ErrNotExist, "a foreground refresh never writes a PID file")
}

// TestRunOIDCLogin_AWSProviderForegroundAutoRefresh checks the AWS
// provider's foreground refresh: the credentials are written once by the
// login, the loop is announced, and it ends cleanly when stopped.
func TestRunOIDCLogin_AWSProviderForegroundAutoRefresh(t *testing.T) {
	withLaunchBrowser(t, nil)
	withRefreshLoopStopped(t)
	h := newAWSLoginHarness(t, awsTokenHandler("AKIAFOREGROUND000001", "refresh-fg"))
	provider := awsDevProvider(t)
	provider.AutoRefresh = 90

	out, err := awsProviderLogin(t, h, provider, map[string]string{"no-browser": "true"})
	require.NoError(t, err)
	assert.Contains(t, out, "AWS login successful!")
	assert.Contains(t, out, "Auto-refresh enabled: refreshing every 90 seconds")

	creds, readErr := os.ReadFile(provider.AWSCredentialsFile)
	require.NoError(t, readErr)
	assert.Contains(t, string(creds), "AKIAFOREGROUND000001")
}

// TestRunOIDCAWS_BackgroundWorkerLogsItsStartAndStops runs the AWS
// background worker against a stored session: it restores the session's
// DPoP key, writes its start banner to the log file, and ends cleanly when
// the refresh loop is stopped.
func TestRunOIDCAWS_BackgroundWorkerLogsItsStartAndStops(t *testing.T) {
	withRefreshLoopStopped(t)
	dpopKey, err := oidc.GenerateDPoPKey()
	require.NoError(t, err)
	keyPEM, err := dpopKey.SerializePrivateKey()
	require.NoError(t, err)

	tests := []struct {
		name         string
		providerName string
		wantName     string
	}{
		{name: "named provider", providerName: "aws-ops", wantName: "'aws-ops'"},
		{name: "region only", wantName: "'aws-eu-west-1'"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			store := filepath.Join(dir, "session")
			require.NoError(t, storeAWSSession(&cobra.Command{}, store, AWSStoredSession{
				Region: "eu-west-1", RefreshToken: "stored-refresh", DPoPKeyPEM: keyPEM,
			}))
			logFile := filepath.Join(dir, "worker.log")

			cmd, _ := awsTestCmd(t)
			cmd.Flags().String("provider-name", "", "")
			for flag, value := range map[string]string{
				"background-worker": "true",
				"region":            "eu-west-1",
				"profile":           "ops",
				"session-store":     store,
				"log-file":          logFile,
				"exec":              "true",
				"auto-refresh":      "120",
				"provider-name":     tt.providerName,
			} {
				require.NoError(t, cmd.Flags().Set(flag, value), "--%s", flag)
			}

			require.NoError(t, runOIDCAWS(cmd, nil))

			log, err := os.ReadFile(logFile)
			require.NoError(t, err)
			assert.Contains(t, string(log), "Background refresh started for "+tt.wantName)
			assert.Contains(t, string(log), "Region: eu-west-1")
			assert.Contains(t, string(log), "Profile: ops")
			assert.Contains(t, string(log), "Refresh interval: 120 seconds")
			assert.Contains(t, string(log), "Exec command: true")
			assert.Contains(t, string(log), "Auto-refresh stopped.")
		})
	}
}
