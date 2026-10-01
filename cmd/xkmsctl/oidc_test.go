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

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
)

// mockOIDCClient records the OIDC credential calls of a command.
type mockOIDCClient struct {
	mockBackendsClient

	cred  *client.OIDCCredential
	polls []*client.OIDCCredential
	list  *client.OIDCCredentialListResponse
	token *client.OIDCAccessToken
	err   error

	requests map[string]any
}

func (m *mockOIDCClient) record(method string, req any) error {
	if m.requests == nil {
		m.requests = map[string]any{}
	}
	m.requests[method] = req
	return m.err
}

func (m *mockOIDCClient) OIDCCredentialCreate(_ context.Context, req *client.OIDCCredentialCreateRequest) (*client.OIDCCredential, error) {
	return m.cred, m.record("create", req)
}

func (m *mockOIDCClient) OIDCCredentialImport(_ context.Context, req *client.OIDCCredentialImportRequest) (*client.OIDCCredential, error) {
	return m.cred, m.record("import", req)
}

func (m *mockOIDCClient) OIDCCredentialGet(_ context.Context, req *client.OIDCCredentialRef) (*client.OIDCCredential, error) {
	return m.cred, m.record("get", req)
}

func (m *mockOIDCClient) OIDCCredentialList(_ context.Context, req *client.OIDCCredentialListRequest) (*client.OIDCCredentialListResponse, error) {
	return m.list, m.record("list", req)
}

func (m *mockOIDCClient) OIDCCredentialDelete(_ context.Context, req *client.OIDCCredentialRef) error {
	return m.record("delete", req)
}

func (m *mockOIDCClient) OIDCCredentialRefresh(_ context.Context, req *client.OIDCCredentialRef) (*client.OIDCCredential, error) {
	return m.cred, m.record("refresh", req)
}

func (m *mockOIDCClient) OIDCCredentialGetAccessToken(_ context.Context, req *client.OIDCCredentialRef) (*client.OIDCAccessToken, error) {
	return m.token, m.record("token", req)
}

func (m *mockOIDCClient) OIDCCredentialDeviceStart(_ context.Context, req *client.OIDCCredentialRef) (*client.OIDCCredential, error) {
	return m.cred, m.record("device", req)
}

func (m *mockOIDCClient) OIDCCredentialDevicePoll(_ context.Context, req *client.OIDCCredentialRef) (*client.OIDCCredential, error) {
	if err := m.record("poll", req); err != nil {
		return nil, err
	}
	next := m.polls[0]
	m.polls = m.polls[1:]
	return next, nil
}

// runOIDCCmd runs cmd over mock with flags.
func runOIDCCmd(t *testing.T, mock *mockOIDCClient, cmd *cobra.Command, args []string, flags map[string]string) (string, int) {
	t.Helper()
	resetTPMCmdFlags(t, cmd)
	t.Cleanup(func() { resetTPMCmdFlags(t, cmd) })
	withGlobalConfig(t, &Config{
		OutputFormat:  "text",
		ClientFactory: func(*Config) (client.Client, error) { return mock, nil },
	})
	for name, value := range flags {
		require.NoError(t, cmd.Flags().Set(name, value))
	}
	code := -1
	out := captureStdout(t, func() {
		code = captureExit(t, func() { cmd.Run(cmd, args) })
	})
	return out, code
}

func activeCredential(name string) *client.OIDCCredential {
	exp := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	return &client.OIDCCredential{
		OIDCCredentialRef: client.OIDCCredentialRef{Scope: "tenant", Name: name, TenantID: "acme"},
		Config:            client.OIDCCredentialConfig{Template: "openai", Issuer: "https://auth.openai.com"},
		Status:            "active",
		ExpiresAt:         &exp,
		Refreshable:       true,
	}
}

func TestOIDCCreateCmd(t *testing.T) {
	mock := &mockOIDCClient{cred: activeCredential("codex")}
	out, code := runOIDCCmd(t, mock, oidcCreateCmd, []string{"codex"},
		map[string]string{"template": "openai", "scope": "tenant", "refresh-margin": "10m", "scopes": "openid,offline_access"})
	assert.Equal(t, -1, code)
	req := mock.requests["create"].(*client.OIDCCredentialCreateRequest)
	assert.Equal(t, client.OIDCCredentialRef{Scope: "tenant", Name: "codex"}, req.OIDCCredentialRef)
	assert.Equal(t, "openai", req.Config.Template)
	assert.Equal(t, int64(600), req.Config.RefreshMarginSeconds)
	assert.Equal(t, []string{"openid", "offline_access"}, req.Config.Scopes)
	assert.Nil(t, req.Tokens)
	assert.Contains(t, out, "OIDC Credential Created")
	assert.Contains(t, out, "Scope:       shared")
}

func TestOIDCCreateCmd_ServerError(t *testing.T) {
	mock := &mockOIDCClient{err: errTPMRunBoom}
	_, code := runOIDCCmd(t, mock, oidcCreateCmd, []string{"codex"}, nil)
	assert.Equal(t, 1, code)
}

// codexAuthFile writes a codex auth.json and returns its path.
func codexAuthFile(t *testing.T) string {
	t.Helper()
	enc := base64.RawURLEncoding
	jwt := func(claims string) string {
		return enc.EncodeToString([]byte(`{"alg":"none"}`)) + "." + enc.EncodeToString([]byte(claims)) + ".sig"
	}
	data, err := json.Marshal(map[string]any{
		"OPENAI_API_KEY": nil,
		"tokens": map[string]any{
			"id_token":      jwt(`{"https://api.openai.com/auth":{"chatgpt_account_id":"acct"}}`),
			"access_token":  jwt(`{"exp":1893456000}`),
			"refresh_token": "rt-codex",
			"account_id":    "acct",
		},
	})
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "auth.json")
	require.NoError(t, os.WriteFile(path, data, 0o600))
	return path
}

func TestOIDCImportCmd_CodexAuthCreates(t *testing.T) {
	mock := &mockOIDCClient{cred: activeCredential("codex")}
	_, code := runOIDCCmd(t, mock, oidcImportCmd, []string{"codex"},
		map[string]string{"codex-auth": codexAuthFile(t), "create": "true", "scope": "tenant"})
	assert.Equal(t, -1, code)
	req := mock.requests["create"].(*client.OIDCCredentialCreateRequest)
	assert.Equal(t, "openai", req.Config.Template, "a codex login is an openai credential")
	require.NotNil(t, req.Tokens)
	assert.Equal(t, "rt-codex", req.Tokens.RefreshToken)
	require.NotNil(t, req.Tokens.ExpiresAt)
	assert.Equal(t, int64(1893456000), req.Tokens.ExpiresAt.Unix())
}

func TestOIDCImportCmd_TokensIntoExisting(t *testing.T) {
	mock := &mockOIDCClient{cred: activeCredential("corp")}
	_, code := runOIDCCmd(t, mock, oidcImportCmd, []string{"corp"},
		map[string]string{"access-token": "at", "refresh-token": "rt", "expires-at": "2026-12-01T00:00:00Z"})
	assert.Equal(t, -1, code)
	req := mock.requests["import"].(*client.OIDCCredentialImportRequest)
	assert.Equal(t, "at", req.Tokens.AccessToken)
	assert.Equal(t, "rt", req.Tokens.RefreshToken)
	assert.Equal(t, "user", req.Scope, "personal is the default scope")
}

func TestOIDCImportTokens_Refusals(t *testing.T) {
	_, err := oidcImportTokens("", "", "", "", "")
	assert.ErrorIs(t, err, ErrOIDCAccessTokenRequired)
	_, err = oidcImportTokens("x.json", "at", "", "", "")
	assert.ErrorIs(t, err, ErrOIDCImportSourceConflict)
	_, err = oidcImportTokens(filepath.Join(t.TempDir(), "missing.json"), "", "", "", "")
	assert.ErrorIs(t, err, ErrOIDCCodexAuthRead)
	_, err = oidcImportTokens("", "at", "", "", "yesterday")
	assert.ErrorIs(t, err, ErrOIDCInvalidExpiry)
}

func TestOIDCLoginPollsUntilActive(t *testing.T) {
	pending := activeCredential("codex")
	pending.Status = "pending"
	pending.DeviceLogin = &client.OIDCDeviceLogin{
		UserCode: "ABCD", VerificationURI: "https://auth.openai.com/codex/device",
		IntervalSeconds: 0, ExpiresAt: time.Now().Add(time.Minute),
	}
	mock := &mockOIDCClient{cred: pending, polls: []*client.OIDCCredential{pending, activeCredential("codex")}}
	ref := &client.OIDCCredentialRef{Scope: "tenant", Name: "codex"}

	out, err := os.CreateTemp(t.TempDir(), "login")
	require.NoError(t, err)
	defer func() { require.NoError(t, out.Close()) }()

	cred, err := oidcDeviceLogin(context.Background(), mock, ref, out)
	require.NoError(t, err)
	assert.Equal(t, "active", cred.Status)
	assert.Empty(t, mock.polls, "it polled until the login was active")
	printed, err := os.ReadFile(out.Name())
	require.NoError(t, err)
	assert.Contains(t, string(printed), "ABCD")
}

func TestOIDCLoginExpires(t *testing.T) {
	pending := activeCredential("codex")
	pending.Status = "pending"
	pending.DeviceLogin = &client.OIDCDeviceLogin{UserCode: "X", VerificationURI: "https://idp.example.com", ExpiresAt: time.Now().Add(-time.Second)}
	mock := &mockOIDCClient{cred: pending}
	out, err := os.CreateTemp(t.TempDir(), "login")
	require.NoError(t, err)
	defer func() { require.NoError(t, out.Close()) }()
	_, err = oidcDeviceLogin(context.Background(), mock, &client.OIDCCredentialRef{Name: "codex"}, out)
	assert.ErrorIs(t, err, ErrOIDCLoginExpired)

	mock.cred = activeCredential("codex")
	_, err = oidcDeviceLogin(context.Background(), mock, &client.OIDCCredentialRef{Name: "codex"}, out)
	assert.ErrorIs(t, err, ErrOIDCNoDeviceLogin)
}

func TestOIDCTokenCmd(t *testing.T) {
	exp := time.Now().Add(time.Hour)
	mock := &mockOIDCClient{token: &client.OIDCAccessToken{AccessToken: "at-123", TokenType: "Bearer", ExpiresAt: &exp}}
	out, code := runOIDCCmd(t, mock, oidcTokenCmd, []string{"corp"}, nil)
	assert.Equal(t, -1, code)
	assert.Equal(t, "at-123\n", out, "the token alone, for shell capture")
}

func TestOIDCTokenCmd_CodexAuthOut(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.json")
	mock := &mockOIDCClient{token: &client.OIDCAccessToken{AccessToken: "at", IDToken: "a.e30.c", TokenType: "Bearer"}}
	out, code := runOIDCCmd(t, mock, oidcTokenCmd, []string{"codex"}, map[string]string{"codex-auth-out": path})
	assert.Equal(t, -1, code)
	assert.Contains(t, out, "codex auth.json written")
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Contains(t, string(data), `"auth_mode": "chatgptAuthTokens"`)

	noID := &mockOIDCClient{token: &client.OIDCAccessToken{AccessToken: "at"}}
	_, code = runOIDCCmd(t, noID, oidcTokenCmd, []string{"codex"}, map[string]string{"codex-auth-out": path})
	assert.Equal(t, 1, code, "codex needs the ID token")
}

func TestOIDCListGetRefreshDeleteCmds(t *testing.T) {
	personal := activeCredential("mine")
	personal.Scope, personal.Owner = "user", "alice"
	mock := &mockOIDCClient{
		cred: activeCredential("codex"),
		list: &client.OIDCCredentialListResponse{Credentials: []client.OIDCCredential{*activeCredential("codex"), *personal}},
	}

	out, code := runOIDCCmd(t, mock, oidcListCmd, nil, map[string]string{"tenant": "acme"})
	assert.Equal(t, -1, code)
	assert.Equal(t, "acme", mock.requests["list"].(*client.OIDCCredentialListRequest).TenantID)
	assert.Contains(t, out, "codex")
	assert.Contains(t, out, "personal (alice)")

	out, code = runOIDCCmd(t, mock, oidcGetCmd, []string{"codex"}, map[string]string{"scope": "tenant"})
	assert.Equal(t, -1, code)
	assert.Contains(t, out, "Issuer:      https://auth.openai.com")

	out, code = runOIDCCmd(t, mock, oidcRefreshCmd, []string{"codex"}, nil)
	assert.Equal(t, -1, code)
	assert.Contains(t, out, "OIDC Credential Refreshed")

	out, code = runOIDCCmd(t, mock, oidcDeleteCmd, []string{"codex"}, nil)
	assert.Equal(t, -1, code)
	assert.Contains(t, out, "deleted")

	empty := &mockOIDCClient{list: &client.OIDCCredentialListResponse{}}
	out, _ = runOIDCCmd(t, empty, oidcListCmd, nil, nil)
	assert.Contains(t, out, "No OIDC credentials")
}

func TestOIDCTemplatesCmd(t *testing.T) {
	withGlobalConfig(t, &Config{OutputFormat: "text"})
	out := captureStdout(t, func() { oidcTemplatesCmd.Run(oidcTemplatesCmd, nil) })
	assert.Contains(t, out, "openai")
	assert.Contains(t, out, "anthropic")
	assert.Contains(t, out, "(xkey-local only)", "aws is an xkey-local login")
}
