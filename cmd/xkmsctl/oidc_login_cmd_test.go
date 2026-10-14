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

// oidc_login_cmd_test.go runs oidc login end to end over a mock client, and
// covers the secret, refusal and JSON branches of the other oidc verbs.
package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
)

// oidcVerbConfig serves mock to a verb in the given output format.
func oidcVerbConfig(format string, mock client.Client) *Config {
	return &Config{OutputFormat: format, ClientFactory: func(*Config) (client.Client, error) { return mock, nil }}
}

// pendingDeviceLogin is a credential waiting for the user to approve the
// device code ABCD, polled without delay.
func pendingDeviceLogin() *client.OIDCCredential {
	pending := activeCredential("codex")
	pending.Status = "pending"
	pending.DeviceLogin = &client.OIDCDeviceLogin{
		UserCode: "ABCD", VerificationURI: "https://auth.openai.com/device",
		VerificationURIComplete: "https://auth.openai.com/device?code=ABCD",
		ExpiresAt:               time.Now().Add(time.Minute),
	}
	return pending
}

// pollFailingOIDCClient starts device logins but fails every poll.
type pollFailingOIDCClient struct {
	*mockOIDCClient
}

func (m pollFailingOIDCClient) OIDCCredentialDevicePoll(context.Context, *client.OIDCCredentialRef) (*client.OIDCCredential, error) {
	return nil, errTPMRunBoom
}

func TestOIDCLoginCmd_PrintsLoggedInCredential(t *testing.T) {
	refreshed := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	active := activeCredential("codex")
	active.Scope, active.Owner = client.OIDCCredentialScopeUser, "alice"
	active.Config.ClientID = "cli-app"
	active.StatusReason = "refreshed"
	active.LastRefresh = &refreshed
	active.LastError = "earlier timeout"
	mock := &mockOIDCClient{cred: pendingDeviceLogin(), polls: []*client.OIDCCredential{active}}

	out, code, stderr := runVerb(t, oidcVerbConfig("text", mock), oidcLoginCmd, []string{"codex"}, verbFlag{"scope", "user"})
	require.Equal(t, -1, code, stderr)
	assert.Contains(t, stderr, "Open https://auth.openai.com/device?code=ABCD\nand enter the code: ABCD", "the complete URI is preferred")
	assert.Equal(t, &client.OIDCCredentialRef{Scope: "user", Name: "codex"}, mock.requests["device"])
	assert.Contains(t, out, "OIDC Credential Logged In:")
	assert.Contains(t, out, "  Scope:       personal (alice)")
	assert.Contains(t, out, "  Client ID:   cli-app")
	assert.Contains(t, out, "  Status:      active (refreshed)")
	assert.Contains(t, out, "  Refreshed:   2026-09-01T00:00:00Z")
	assert.Contains(t, out, "  Last error:  earlier timeout")
}

func TestOIDCLoginCmd_JSON(t *testing.T) {
	mock := &mockOIDCClient{cred: pendingDeviceLogin(), polls: []*client.OIDCCredential{activeCredential("codex")}}

	out, code, stderr := runVerb(t, oidcVerbConfig("json", mock), oidcLoginCmd, []string{"codex"})
	require.Equal(t, -1, code, stderr)
	assert.Equal(t, "active", lastJSONObject(t, out)["status"])
}

func TestOIDCLoginCmd_Failures(t *testing.T) {
	cases := []struct {
		name     string
		cfg      *Config
		sentinel error
	}{
		{"client factory", &Config{OutputFormat: "text", ClientFactory: func(*Config) (client.Client, error) { return nil, errTPMRunBoom }}, ErrCreateClientFailed},
		{"connect", oidcVerbConfig("text", &mockOIDCClient{mockBackendsClient: mockBackendsClient{connectErr: errTPMRunBoom}}), ErrConnectFailed},
		{"device start refused", oidcVerbConfig("text", &mockOIDCClient{err: errTPMRunBoom}), ErrOIDCLoginFailed},
		{"poll refused", oidcVerbConfig("text", pollFailingOIDCClient{&mockOIDCClient{cred: pendingDeviceLogin()}}), ErrOIDCLoginFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, code, stderr := runVerb(t, tc.cfg, oidcLoginCmd, []string{"codex"})
			assert.Equal(t, 1, code)
			assert.Contains(t, stderr, tc.sentinel.Error())
			assert.NotContains(t, out, "Logged In")
		})
	}
}

func TestOIDCCreateCmd_ClientSecretFromStdin(t *testing.T) {
	withSecretStdin(t, "s3cret\n")
	mock := &mockOIDCClient{cred: activeCredential("api")}

	_, code, stderr := runVerb(t, oidcVerbConfig("text", mock), oidcCreateCmd, []string{"api"},
		verbFlag{"issuer", "https://idp.example.com"}, verbFlag{"client-id", "svc"}, verbFlag{"client-secret", "-"})
	require.Equal(t, -1, code, stderr)
	assert.Equal(t, "s3cret", mock.requests["create"].(*client.OIDCCredentialCreateRequest).Config.ClientSecret)
}

func TestOIDCSecretRefusals(t *testing.T) {
	cases := []struct {
		name  string
		verb  func() (string, int, string)
		label string
	}{
		{"client secret", func() (string, int, string) {
			return runVerb(t, oidcVerbConfig("text", &mockOIDCClient{}), oidcCreateCmd, []string{"api"}, verbFlag{"client-secret", "-"})
		}, "create"},
		{"access token", func() (string, int, string) {
			return runVerb(t, oidcVerbConfig("text", &mockOIDCClient{}), oidcImportCmd, []string{"corp"}, verbFlag{"access-token", "-"})
		}, "import"},
		{"refresh token", func() (string, int, string) {
			return runVerb(t, oidcVerbConfig("text", &mockOIDCClient{}), oidcImportCmd, []string{"corp"},
				verbFlag{"access-token", "at"}, verbFlag{"refresh-token", "-"})
		}, "import"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			original := secretStdin
			secretStdin = failingReader{}
			t.Cleanup(func() { secretStdin = original })

			_, code, stderr := tc.verb()
			assert.Equal(t, 1, code)
			assert.Contains(t, stderr, ErrReadSecretFailed.Error())
		})
	}
}

func TestOIDCImportCmd_RefusesMalformedCodexAuth(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.json")
	require.NoError(t, os.WriteFile(path, []byte("not json"), 0o600))
	mock := &mockOIDCClient{}

	_, code, _ := runVerb(t, oidcVerbConfig("text", mock), oidcImportCmd, []string{"codex"}, verbFlag{"codex-auth", path})
	assert.Equal(t, 1, code)
	assert.Empty(t, mock.requests, "nothing is imported from a malformed auth.json")
}

func TestOIDCTokenCmd_RefusesUnwritableCodexAuthOut(t *testing.T) {
	notDir := filepath.Join(t.TempDir(), "plain.txt")
	require.NoError(t, os.WriteFile(notDir, []byte("x"), 0o600))
	mock := &mockOIDCClient{token: &client.OIDCAccessToken{AccessToken: "at", IDToken: "a.e30.c", TokenType: "Bearer"}}

	_, code, stderr := runVerb(t, oidcVerbConfig("text", mock), oidcTokenCmd, []string{"codex"},
		verbFlag{"codex-auth-out", filepath.Join(notDir, "auth.json")})
	assert.Equal(t, 1, code)
	assert.Contains(t, stderr, ErrOIDCCodexAuthWrite.Error())
}

func TestOIDCVerbs_JSON(t *testing.T) {
	exp := time.Now().Add(time.Hour)
	mock := &mockOIDCClient{
		list:  &client.OIDCCredentialListResponse{Credentials: []client.OIDCCredential{*activeCredential("codex")}},
		token: &client.OIDCAccessToken{AccessToken: "at-123", IDToken: "a.e30.c", TokenType: "Bearer", ExpiresAt: &exp},
	}
	cfg := oidcVerbConfig("json", mock)

	out, code, stderr := runVerb(t, cfg, oidcDeleteCmd, []string{"codex"})
	require.Equal(t, -1, code, stderr)
	assert.Equal(t, "OIDC credential codex deleted", lastJSONObject(t, out)["message"])

	out, code, stderr = runVerb(t, cfg, oidcTokenCmd, []string{"corp"})
	require.Equal(t, -1, code, stderr)
	assert.Equal(t, "at-123", lastJSONObject(t, out)["access_token"])

	path := filepath.Join(t.TempDir(), "auth.json")
	out, code, stderr = runVerb(t, cfg, oidcTokenCmd, []string{"codex"}, verbFlag{"codex-auth-out", path})
	require.Equal(t, -1, code, stderr)
	assert.Equal(t, "codex auth.json written to "+path, lastJSONObject(t, out)["message"])

	out, code, stderr = runVerb(t, cfg, oidcListCmd, nil)
	require.Equal(t, -1, code, stderr)
	assert.Contains(t, out, `"codex"`)
}

func TestOIDCDeleteCmd_ServerError(t *testing.T) {
	_, code, stderr := runVerb(t, oidcVerbConfig("text", &mockOIDCClient{err: errTPMRunBoom}), oidcDeleteCmd, []string{"codex"})
	assert.Equal(t, 1, code)
	assert.Contains(t, stderr, ErrOIDCCredentialDeleteFailed.Error())
}

func TestOIDCListCmd_ClientFailures(t *testing.T) {
	cases := []struct {
		name     string
		cfg      *Config
		sentinel error
	}{
		{"client factory", &Config{OutputFormat: "text", ClientFactory: func(*Config) (client.Client, error) { return nil, errTPMRunBoom }}, ErrCreateClientFailed},
		{"connect", oidcVerbConfig("text", &mockOIDCClient{mockBackendsClient: mockBackendsClient{connectErr: errTPMRunBoom}}), ErrConnectFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, code, stderr := runVerb(t, tc.cfg, oidcListCmd, nil)
			assert.Equal(t, 1, code)
			assert.Contains(t, stderr, tc.sentinel.Error())
			assert.Empty(t, out)
		})
	}
}
