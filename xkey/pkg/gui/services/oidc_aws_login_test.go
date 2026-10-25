// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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

package services

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/oidc/handlers"
)

// awsTokenBody is an AWS sign-in token response carrying credentials that
// expire at expiration (an RFC 3339 string, or anything else to make the
// response unconvertible).
func awsTokenBody(expiration string) string {
	return `{
		"access_token": {
			"access_key_id": "AKIAGUITEST000000002",
			"secret_access_key": "secret",
			"session_token": "c2Vzc2lvbi10b2tlbg==",
			"expiration": "` + expiration + `"
		},
		"token_type": "DPoP",
		"expires_in": 3600,
		"refresh_token": "refresh-xyz"
	}`
}

// loginAWSAgainst runs the AWS login of entry end to end: a local token
// endpoint answers tokenBody, and the "browser" completes the loopback
// callback and then returns openErr, as a launcher that reports a failure
// after handing the URL over would.
func loginAWSAgainst(t *testing.T, tokenBody string, entry *OIDCProviderEntry, openErr error) (*OIDCService, *OIDCLoginResult) {
	t.Helper()

	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, writeErr := w.Write([]byte(tokenBody))
		assert.NoError(t, writeErr)
	}))
	t.Cleanup(tokenServer.Close)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port
	require.NoError(t, listener.Close())

	svc := NewOIDCService(nil)
	svc.SetCallback("127.0.0.1", port)
	svc.SetAWSEndpointOverrides("", tokenServer.URL)
	svc.SetBrowserOpen(func(authURL string) error {
		u, parseErr := url.Parse(authURL)
		if !assert.NoError(t, parseErr) {
			return parseErr
		}
		redirect := "http://127.0.0.1:" + strconv.Itoa(port) + "/oauth/callback" +
			"?code=test-code&state=" + url.QueryEscape(u.Query().Get("state"))
		resp, getErr := http.Get(redirect) //nolint:noctx // fixed test-local callback URL
		if assert.NoError(t, getErr) {
			assert.NoError(t, resp.Body.Close())
		}
		return openErr
	})

	entry.Type = OIDCProviderTypeAWS
	entry.AWSRegion = "us-east-1"
	require.NoError(t, svc.AddProvider(entry))

	result, err := svc.Login(entry.Name)
	require.NoError(t, err, "login failures are reported in the result, not as an error")
	require.NotNil(t, result)
	return svc, result
}

func TestOIDCService_LoginAWS_Failures(t *testing.T) {
	valid := awsTokenBody(time.Now().Add(time.Hour).UTC().Format(time.RFC3339))

	t.Run("credentials with an unreadable expiration", func(t *testing.T) {
		credentials := filepath.Join(t.TempDir(), "credentials")
		_, result := loginAWSAgainst(t, awsTokenBody("next tuesday"), &OIDCProviderEntry{
			Name: "aws-bad-expiry", AWSCredentialsFile: credentials, AWSOutput: handlers.ModeAWSCredentials,
		}, nil)

		assert.False(t, result.Success)
		assert.NotEmpty(t, result.Error)
		assert.NoFileExists(t, credentials, "nothing may be written from a token that did not convert")
	})

	t.Run("exec output without a command", func(t *testing.T) {
		_, result := loginAWSAgainst(t, valid, &OIDCProviderEntry{
			Name: "aws-exec", AWSOutput: handlers.ModeExec,
		}, nil)

		assert.False(t, result.Success)
		assert.Equal(t, handlers.ErrExecModeRequiresCommand.Error(), result.Error)
	})

	t.Run("a credentials file that cannot be written", func(t *testing.T) {
		blocker := filepath.Join(t.TempDir(), "not-a-directory")
		require.NoError(t, os.WriteFile(blocker, []byte("x"), 0o600))

		_, result := loginAWSAgainst(t, valid, &OIDCProviderEntry{
			Name:               "aws-unwritable",
			AWSCredentialsFile: filepath.Join(blocker, "credentials"),
			AWSOutput:          handlers.ModeAWSCredentials,
		}, nil)

		assert.False(t, result.Success)
		assert.NotEmpty(t, result.Error)
	})
}

// TestOIDCService_LoginAWS_StartsAutoRefresh checks that a login with
// AutoRefresh set and a refresh token in hand starts the background refresh
// for the provider, and that a browser launcher reporting an error after the
// callback completed does not fail the login.
func TestOIDCService_LoginAWS_StartsAutoRefresh(t *testing.T) {
	credentials := filepath.Join(t.TempDir(), "credentials")
	svc, result := loginAWSAgainst(t,
		awsTokenBody(time.Now().Add(time.Hour).UTC().Format(time.RFC3339)),
		&OIDCProviderEntry{
			Name:               "aws-refresh",
			AWSCredentialsFile: credentials,
			AWSOutput:          handlers.ModeAWSCredentials,
			AutoRefresh:        1800,
		},
		errors.New("no desktop session"))

	require.True(t, result.Success, "login error: %s", result.Error)
	assert.FileExists(t, credentials)

	require.Eventually(t, func() bool {
		svc.refreshMu.Lock()
		defer svc.refreshMu.Unlock()
		return svc.refreshProcs["aws-refresh"] != nil
	}, 5*time.Second, 20*time.Millisecond, "the login must start the provider's auto-refresh")
	stopAWSRefresh(t, svc, "aws-refresh")
}
