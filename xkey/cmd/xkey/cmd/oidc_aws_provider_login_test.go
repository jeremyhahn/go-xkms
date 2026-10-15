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

package cmd

import (
	"bytes"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// withLaunchBrowser replaces the system browser opener; every URL the
// login asks it to open is sent on the returned channel.
func withLaunchBrowser(t *testing.T, err error) <-chan string {
	t.Helper()
	launched := make(chan string, 4)
	previous := launchBrowser
	launchBrowser = func(rawURL string) error {
		launched <- rawURL
		return err
	}
	t.Cleanup(func() { launchBrowser = previous })
	return launched
}

// awsProviderLogin saves provider as the only OIDC provider and runs
// `xkey oidc login --provider <name>` against the harness, completing the
// browser redirect.
func awsProviderLogin(t *testing.T, h *awsLoginHarness, provider OIDCProvider, flags map[string]string) (string, error) {
	t.Helper()
	cmdFlags := map[string]string{
		"provider":      provider.Name,
		"callback-port": strconv.Itoa(h.callback.Port),
	}
	for name, value := range flags {
		cmdFlags[name] = value
	}
	cmd, store := oidcFlowCmd(t, cmdFlags)
	require.NoError(t, saveOIDCConfig(getConfigPath(store), OIDCConfig{Providers: []OIDCProvider{provider}}))

	var out bytes.Buffer
	cmd.SetOut(&out)
	done := make(chan error, 1)
	go func() { done <- runOIDCLogin(cmd, nil) }()
	h.redirect(t, url.Values{"code": {"auth-code"}})
	err := <-done
	return out.String(), err
}

func awsDevProvider(t *testing.T) OIDCProvider {
	t.Helper()
	dir := t.TempDir()
	return OIDCProvider{
		Name:               "aws-dev",
		Type:               OIDCProviderTypeAWS,
		AWSRegion:          "us-east-1",
		AWSProfile:         "dev",
		AWSCredentialsFile: filepath.Join(dir, "credentials"),
		AWSSessionStore:    filepath.Join(dir, "session"),
	}
}

// TestRunOIDCLogin_AWSProviderHonoursNoBrowser pins that --no-browser
// reaches a saved AWS provider's login: the URL is printed and no browser
// is started.
func TestRunOIDCLogin_AWSProviderHonoursNoBrowser(t *testing.T) {
	launched := withLaunchBrowser(t, nil)
	h := newAWSLoginHarness(t, awsTokenHandler("AKIAPROVIDERLOGIN001", "refresh-1"))
	provider := awsDevProvider(t)

	out, err := awsProviderLogin(t, h, provider, map[string]string{"no-browser": "true"})
	require.NoError(t, err)

	assert.Empty(t, launched, "--no-browser never starts a browser")
	assert.Contains(t, out, "Open the following URL in your browser:")
	assert.NotContains(t, out, "Opening browser")
	assert.Contains(t, out, "AWS login successful!")

	creds, readErr := os.ReadFile(provider.AWSCredentialsFile)
	require.NoError(t, readErr)
	assert.Contains(t, string(creds), "[dev]")
	assert.Contains(t, string(creds), "AKIAPROVIDERLOGIN001")

	session, loadErr := loadAWSSession(&cobra.Command{}, provider.AWSSessionStore)
	require.NoError(t, loadErr)
	assert.Equal(t, "refresh-1", session.RefreshToken)
	assert.Equal(t, "dev", session.Profile)
}

// TestRunOIDCLogin_AWSProviderOpensTheBrowser covers the default: the
// authorization URL goes to the browser, and when no browser can be
// started the user is told to open it by hand.
func TestRunOIDCLogin_AWSProviderOpensTheBrowser(t *testing.T) {
	tests := []struct {
		name      string
		launchErr error
		manual    bool
	}{
		{name: "opened"},
		{name: "no browser", launchErr: errors.New("no display"), manual: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			launched := withLaunchBrowser(t, tt.launchErr)
			h := newAWSLoginHarness(t, awsTokenHandler("AKIAPROVIDERLOGIN002", "refresh-2"))

			out, err := awsProviderLogin(t, h, awsDevProvider(t), map[string]string{"no-browser": "false"})
			require.NoError(t, err)

			require.Len(t, launched, 1)
			opened, parseErr := url.Parse(<-launched)
			require.NoError(t, parseErr)
			assert.Equal(t, "https", opened.Scheme)
			assert.NotEmpty(t, opened.Query().Get("state"))

			assert.Contains(t, out, "Opening browser for AWS authentication...")
			assert.Contains(t, out, "AWS login successful!")
			if tt.manual {
				assert.Contains(t, out, "Failed to open browser: no display")
				assert.Contains(t, out, "Please open the following URL manually:")
			} else {
				assert.NotContains(t, out, "Please open the following URL manually")
			}
		})
	}
}

// TestRunOIDCLogin_AWSProviderSettingsDriveTheRefresh pins that a saved
// provider's own settings fill in what the command line leaves out: its
// background auto-refresh, log file and exec hook reach the refresh worker,
// and an unset profile and output fall back to "default" and the AWS
// credentials file.
func TestRunOIDCLogin_AWSProviderSettingsDriveTheRefresh(t *testing.T) {
	withLaunchBrowser(t, nil)
	got := withStandInWorker(t)
	h := newAWSLoginHarness(t, awsTokenHandler("AKIAPROVIDERLOGIN003", "refresh-3"))
	provider := awsDevProvider(t)
	provider.AWSProfile = ""
	provider.Background = true
	provider.AutoRefresh = 120
	provider.LogFile = filepath.Join(t.TempDir(), "aws-refresh.log")
	provider.Exec = "true"

	out, err := awsProviderLogin(t, h, provider, nil)
	require.NoError(t, err)
	assert.Contains(t, out, "Background refresh started for 'aws-dev'")
	waitForWorkerExit(t, getAWSPIDFile(provider.AWSSessionStore, "us-east-1", "aws-dev"), provider.LogFile)

	creds, readErr := os.ReadFile(provider.AWSCredentialsFile)
	require.NoError(t, readErr)
	assert.Contains(t, string(creds), "[default]")

	target, worker := parseWorkerArgs(t, *got)
	assert.Same(t, oidcAWSCmd, target)
	interval, err := worker.Flags().GetInt("auto-refresh")
	require.NoError(t, err)
	assert.Equal(t, 120, interval)
	for flag, want := range map[string]string{
		"region":        "us-east-1",
		"profile":       "default",
		"output":        "aws-credentials",
		"exec":          "true",
		"log-file":      provider.LogFile,
		"session-store": provider.AWSSessionStore,
		"provider-name": "aws-dev",
	} {
		assert.Equal(t, want, flagString(t, worker, flag), "--%s", flag)
	}
}
