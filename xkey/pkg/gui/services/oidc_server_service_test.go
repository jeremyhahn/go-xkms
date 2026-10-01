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

package services

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/oidc"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// errOIDCServerFake is the error the fake server returns when told to fail.
var errOIDCServerFake = errors.New("fake xkmsd: refused")

// fakeOIDCServer is a connected xkmsd serving the OIDC credential API: it
// records the requests it receives and answers with cred, or err.
type fakeOIDCServer struct {
	transport.Client

	cred  *transport.OIDCCredential
	token *transport.OIDCAccessToken
	err   error

	calls   []string
	ref     *transport.OIDCCredentialRef
	create  *transport.OIDCCredentialCreateRequest
	imports *transport.OIDCCredentialImportRequest
	list    *transport.OIDCCredentialListRequest
}

func (f *fakeOIDCServer) answer(call string, ref *transport.OIDCCredentialRef) (*transport.OIDCCredential, error) {
	f.calls = append(f.calls, call)
	f.ref = ref
	if f.err != nil {
		return nil, f.err
	}
	return f.cred, nil
}

func (f *fakeOIDCServer) OIDCCredentialCreate(_ context.Context, req *transport.OIDCCredentialCreateRequest) (*transport.OIDCCredential, error) {
	f.create = req
	return f.answer("create", &req.OIDCCredentialRef)
}

func (f *fakeOIDCServer) OIDCCredentialImport(_ context.Context, req *transport.OIDCCredentialImportRequest) (*transport.OIDCCredential, error) {
	f.imports = req
	return f.answer("import", &req.OIDCCredentialRef)
}

func (f *fakeOIDCServer) OIDCCredentialGet(_ context.Context, ref *transport.OIDCCredentialRef) (*transport.OIDCCredential, error) {
	return f.answer("get", ref)
}

func (f *fakeOIDCServer) OIDCCredentialList(_ context.Context, req *transport.OIDCCredentialListRequest) (*transport.OIDCCredentialListResponse, error) {
	f.calls = append(f.calls, "list")
	f.list = req
	if f.err != nil {
		return nil, f.err
	}
	return &transport.OIDCCredentialListResponse{Credentials: []transport.OIDCCredential{*f.cred}}, nil
}

func (f *fakeOIDCServer) OIDCCredentialDelete(_ context.Context, ref *transport.OIDCCredentialRef) error {
	_, err := f.answer("delete", ref)
	return err
}

func (f *fakeOIDCServer) OIDCCredentialRefresh(_ context.Context, ref *transport.OIDCCredentialRef) (*transport.OIDCCredential, error) {
	return f.answer("refresh", ref)
}

func (f *fakeOIDCServer) OIDCCredentialGetAccessToken(_ context.Context, ref *transport.OIDCCredentialRef) (*transport.OIDCAccessToken, error) {
	f.calls = append(f.calls, "token")
	f.ref = ref
	if f.err != nil {
		return nil, f.err
	}
	return f.token, nil
}

func (f *fakeOIDCServer) OIDCCredentialDeviceStart(_ context.Context, ref *transport.OIDCCredentialRef) (*transport.OIDCCredential, error) {
	return f.answer("device-start", ref)
}

func (f *fakeOIDCServer) OIDCCredentialDevicePoll(_ context.Context, ref *transport.OIDCCredentialRef) (*transport.OIDCCredential, error) {
	return f.answer("device-poll", ref)
}

// fakeClipboard records what is copied.
type fakeClipboard struct {
	copied string
	err    error
}

func (c *fakeClipboard) CopyWithClear(text string) error {
	if c.err != nil {
		return c.err
	}
	c.copied = text
	return nil
}

var (
	oidcTestExpiry  = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	oidcTestCreated = time.Date(2026, 9, 30, 8, 0, 0, 0, time.UTC)
)

// newConnectedOIDCServerService returns a service connected to a fake
// server answering with an active openai credential.
func newConnectedOIDCServerService() (*OIDCServerService, *fakeOIDCServer, *fakeClipboard) {
	fake := &fakeOIDCServer{
		cred: &transport.OIDCCredential{
			OIDCCredentialRef: transport.OIDCCredentialRef{Scope: transport.OIDCCredentialScopeTenant, Name: "codex"},
			Config:            transport.OIDCCredentialConfig{Template: "openai", Issuer: "https://auth.openai.com"},
			Status:            transport.OIDCCredentialStatusActive,
			ExpiresAt:         &oidcTestExpiry,
			Refreshable:       true,
			CreatedAt:         oidcTestCreated,
		},
		token: &transport.OIDCAccessToken{AccessToken: "at-secret", TokenType: "Bearer"},
	}
	clip := &fakeClipboard{}
	s := NewOIDCServerService(nil)
	s.clipboard = clip
	s.SetClient(fake)
	return s, fake, clip
}

var tenantRef = transport.OIDCCredentialRef{Scope: transport.OIDCCredentialScopeTenant, Name: "codex"}

func TestOIDCServerService_ConnectedFollowsSetClient(t *testing.T) {
	s := NewOIDCServerService(nil)
	assert.False(t, s.Connected())
	s.SetClient(&fakeOIDCServer{})
	assert.True(t, s.Connected())
	s.SetClient(nil)
	assert.False(t, s.Connected())
}

func TestOIDCServerService_NotConnected(t *testing.T) {
	s := NewOIDCServerService(nil)
	s.clipboard = &fakeClipboard{}

	_, err := s.ListServerCredentials("")
	assert.ErrorIs(t, err, ErrOIDCServerNotConnected)
	_, err = s.CreateServerCredential(tenantRef, transport.OIDCCredentialConfig{Template: "openai"})
	assert.ErrorIs(t, err, ErrOIDCServerNotConnected)
	_, err = s.ImportServerTokens(tenantRef, OIDCServerTokens{AccessToken: "at"}, "", false)
	assert.ErrorIs(t, err, ErrOIDCServerNotConnected)
	_, err = s.ImportCodexAuth(tenantRef, codexAuthJSON(t), true)
	assert.ErrorIs(t, err, ErrOIDCServerNotConnected)
	_, err = s.StartServerDeviceLogin(tenantRef)
	assert.ErrorIs(t, err, ErrOIDCServerNotConnected)
	_, err = s.PollServerDeviceLogin(tenantRef)
	assert.ErrorIs(t, err, ErrOIDCServerNotConnected)
	_, err = s.RefreshServerCredential(tenantRef)
	assert.ErrorIs(t, err, ErrOIDCServerNotConnected)
	assert.ErrorIs(t, s.DeleteServerCredential(tenantRef), ErrOIDCServerNotConnected)
	assert.ErrorIs(t, s.CopyServerAccessToken(tenantRef), ErrOIDCServerNotConnected)
}

func TestOIDCServerService_ServerTemplates(t *testing.T) {
	templates := NewOIDCServerService(nil).ServerTemplates()
	byName := map[string]OIDCServerTemplateInfo{}
	for i, tmpl := range templates {
		byName[tmpl.Name] = tmpl
		if i > 0 {
			assert.Less(t, templates[i-1].Name, tmpl.Name, "templates are sorted by name")
		}
	}
	assert.NotContains(t, byName, "aws", "region-bound templates are local-only")
	assert.NotContains(t, byName, "aws-exec")

	openai := byName["openai"]
	assert.True(t, openai.SupportsDevice)
	assert.True(t, openai.SupportsImport)
	assert.False(t, openai.NoRefresh)

	anthropic := byName["anthropic"]
	assert.False(t, anthropic.SupportsDevice, "anthropic is import only")
	assert.True(t, anthropic.SupportsImport)
	assert.True(t, anthropic.NoRefresh, "anthropic tokens are never refreshed")

	assert.True(t, byName["okta"].RequiresIssuer)
}

func TestOIDCServerService_ListServerCredentials(t *testing.T) {
	s, fake, _ := newConnectedOIDCServerService()
	list, err := s.ListServerCredentials(" acme ")
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, "acme", fake.list.TenantID)
	got := list[0]
	assert.Equal(t, "codex", got.Name)
	assert.Equal(t, "tenant", got.Scope)
	assert.Equal(t, "active", got.Status)
	assert.Equal(t, "2026-10-01T12:00:00Z", got.ExpiresAt)
	assert.Equal(t, "2026-09-30T08:00:00Z", got.CreatedAt)
	assert.Empty(t, got.LastRefresh, "an absent time renders empty")
	assert.True(t, got.SupportsDevice, "the openai template offers a device login")
}

func TestOIDCServerService_ListServerCredentialsServerError(t *testing.T) {
	s, fake, _ := newConnectedOIDCServerService()
	fake.err = errOIDCServerFake
	_, err := s.ListServerCredentials("")
	assert.ErrorIs(t, err, errOIDCServerFake)
}

func TestOIDCServerService_CreateServerCredential(t *testing.T) {
	s, fake, _ := newConnectedOIDCServerService()
	cfg := transport.OIDCCredentialConfig{Template: "openai", Scopes: []string{"openid"}}
	info, err := s.CreateServerCredential(transport.OIDCCredentialRef{Name: " codex "}, cfg)
	require.NoError(t, err)
	assert.Equal(t, "codex", info.Name)
	assert.Equal(t, transport.OIDCCredentialRef{Scope: "user", Name: "codex"}, fake.create.OIDCCredentialRef,
		"the name is trimmed and an empty scope is personal")
	assert.Equal(t, cfg, fake.create.Config)
	assert.Nil(t, fake.create.Tokens, "a created credential awaits a login")
}

func TestOIDCServerService_CreateServerCredentialInvalidRef(t *testing.T) {
	s, fake, _ := newConnectedOIDCServerService()
	_, err := s.CreateServerCredential(transport.OIDCCredentialRef{Scope: "tenant"}, transport.OIDCCredentialConfig{})
	assert.ErrorIs(t, err, ErrOIDCServerNameRequired)
	_, err = s.CreateServerCredential(transport.OIDCCredentialRef{Scope: "global", Name: "x"}, transport.OIDCCredentialConfig{})
	assert.ErrorIs(t, err, ErrOIDCServerScopeInvalid)
	assert.Empty(t, fake.calls, "an invalid reference never reaches the server")
}

func TestOIDCServerService_CreateServerCredentialServerError(t *testing.T) {
	s, fake, _ := newConnectedOIDCServerService()
	fake.err = errOIDCServerFake
	_, err := s.CreateServerCredential(tenantRef, transport.OIDCCredentialConfig{Template: "openai"})
	assert.ErrorIs(t, err, errOIDCServerFake)
}

func TestOIDCServerService_ImportServerTokensIntoExisting(t *testing.T) {
	s, fake, _ := newConnectedOIDCServerService()
	_, err := s.ImportServerTokens(tenantRef, OIDCServerTokens{
		AccessToken: " at ", RefreshToken: "rt", ExpiresAt: "2026-10-01T12:00:00Z",
	}, "", false)
	require.NoError(t, err)
	assert.Equal(t, []string{"import"}, fake.calls)
	assert.Equal(t, "at", fake.imports.Tokens.AccessToken)
	assert.Equal(t, "rt", fake.imports.Tokens.RefreshToken)
	require.NotNil(t, fake.imports.Tokens.ExpiresAt)
	assert.True(t, oidcTestExpiry.Equal(*fake.imports.Tokens.ExpiresAt))
}

func TestOIDCServerService_ImportServerTokensCreates(t *testing.T) {
	s, fake, _ := newConnectedOIDCServerService()
	_, err := s.ImportServerTokens(tenantRef, OIDCServerTokens{AccessToken: "sk-ant"}, "anthropic", true)
	require.NoError(t, err)
	assert.Equal(t, []string{"create"}, fake.calls)
	assert.Equal(t, "anthropic", fake.create.Config.Template)
	require.NotNil(t, fake.create.Tokens)
	assert.Equal(t, "sk-ant", fake.create.Tokens.AccessToken)
	assert.Nil(t, fake.create.Tokens.ExpiresAt, "no expiry lets the server date the token")
}

func TestOIDCServerService_ImportServerTokensInvalid(t *testing.T) {
	s, fake, _ := newConnectedOIDCServerService()
	_, err := s.ImportServerTokens(tenantRef, OIDCServerTokens{AccessToken: "  "}, "", false)
	assert.ErrorIs(t, err, ErrOIDCServerAccessTokenRequired)
	_, err = s.ImportServerTokens(tenantRef, OIDCServerTokens{AccessToken: "at", ExpiresAt: "tomorrow"}, "", false)
	assert.ErrorIs(t, err, ErrOIDCServerExpiryInvalid)
	_, err = s.ImportServerTokens(transport.OIDCCredentialRef{}, OIDCServerTokens{AccessToken: "at"}, "", false)
	assert.ErrorIs(t, err, ErrOIDCServerNameRequired)
	assert.Empty(t, fake.calls)

	fake.err = errOIDCServerFake
	_, err = s.ImportServerTokens(tenantRef, OIDCServerTokens{AccessToken: "at"}, "", false)
	assert.ErrorIs(t, err, errOIDCServerFake)
}

// testJWT returns an unsigned JWT carrying claims.
func testJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	require.NoError(t, err)
	enc := base64.RawURLEncoding
	return enc.EncodeToString([]byte(`{"alg":"none"}`)) + "." + enc.EncodeToString(payload) + ".sig"
}

// codexAuthJSON returns a codex auth.json holding a ChatGPT login whose
// access token expires at oidcTestExpiry.
func codexAuthJSON(t *testing.T) string {
	t.Helper()
	data, err := json.Marshal(map[string]any{
		"auth_mode":      oidc.CodexAuthModeChatGPT,
		"OPENAI_API_KEY": nil,
		"tokens": map[string]any{
			"id_token":      testJWT(t, map[string]any{"sub": "u"}),
			"access_token":  testJWT(t, map[string]any{"exp": oidcTestExpiry.Unix()}),
			"refresh_token": "rt-codex",
			"account_id":    "acct",
		},
	})
	require.NoError(t, err)
	return string(data)
}

func TestOIDCServerService_ImportCodexAuth(t *testing.T) {
	s, fake, _ := newConnectedOIDCServerService()
	_, err := s.ImportCodexAuth(tenantRef, codexAuthJSON(t), true)
	require.NoError(t, err)
	assert.Equal(t, []string{"create"}, fake.calls)
	assert.Equal(t, "openai", fake.create.Config.Template, "a codex login is an openai credential")
	require.NotNil(t, fake.create.Tokens)
	assert.Equal(t, "rt-codex", fake.create.Tokens.RefreshToken)
	assert.NotEmpty(t, fake.create.Tokens.IDToken)
	require.NotNil(t, fake.create.Tokens.ExpiresAt)
	assert.True(t, oidcTestExpiry.Equal(*fake.create.Tokens.ExpiresAt), "the expiry is the access token's exp")

	fake.calls = nil
	_, err = s.ImportCodexAuth(tenantRef, codexAuthJSON(t), false)
	require.NoError(t, err)
	assert.Equal(t, []string{"import"}, fake.calls)
}

func TestOIDCServerService_ImportCodexAuthInvalid(t *testing.T) {
	s, fake, _ := newConnectedOIDCServerService()
	_, err := s.ImportCodexAuth(tenantRef, " ", true)
	assert.ErrorIs(t, err, ErrOIDCServerCodexAuthRequired)
	_, err = s.ImportCodexAuth(tenantRef, "{not json", true)
	assert.ErrorIs(t, err, oidc.ErrCodexAuthInvalid)
	_, err = s.ImportCodexAuth(tenantRef, `{"auth_mode":"apikey","OPENAI_API_KEY":"sk"}`, true)
	assert.ErrorIs(t, err, oidc.ErrCodexAuthMode)
	assert.Empty(t, fake.calls)
}

func TestOIDCServerService_DeviceLogin(t *testing.T) {
	s, fake, _ := newConnectedOIDCServerService()
	fake.cred.Status = transport.OIDCCredentialStatusPending
	fake.cred.DeviceLogin = &transport.OIDCDeviceLogin{
		UserCode: "ABCD-1234", VerificationURI: "https://auth.example.com/device",
		IntervalSeconds: 5, ExpiresAt: oidcTestExpiry,
	}
	info, err := s.StartServerDeviceLogin(tenantRef)
	require.NoError(t, err)
	require.NotNil(t, info.DeviceLogin)
	assert.Equal(t, "ABCD-1234", info.DeviceLogin.UserCode)
	assert.Equal(t, int64(5), info.DeviceLogin.IntervalSeconds)
	assert.Equal(t, "2026-10-01T12:00:00Z", info.DeviceLogin.ExpiresAt)

	fake.cred.Status = transport.OIDCCredentialStatusActive
	fake.cred.DeviceLogin = nil
	info, err = s.PollServerDeviceLogin(tenantRef)
	require.NoError(t, err)
	assert.Equal(t, "active", info.Status)
	assert.Nil(t, info.DeviceLogin)
	assert.Equal(t, []string{"device-start", "device-poll"}, fake.calls)
	assert.Equal(t, tenantRef, *fake.ref)
}

func TestOIDCServerService_DeviceLoginErrors(t *testing.T) {
	s, fake, _ := newConnectedOIDCServerService()
	_, err := s.StartServerDeviceLogin(transport.OIDCCredentialRef{})
	assert.ErrorIs(t, err, ErrOIDCServerNameRequired)
	_, err = s.PollServerDeviceLogin(transport.OIDCCredentialRef{Name: "x", Scope: "bad"})
	assert.ErrorIs(t, err, ErrOIDCServerScopeInvalid)

	fake.err = errOIDCServerFake
	_, err = s.StartServerDeviceLogin(tenantRef)
	assert.ErrorIs(t, err, errOIDCServerFake)
	_, err = s.PollServerDeviceLogin(tenantRef)
	assert.ErrorIs(t, err, errOIDCServerFake)
}

func TestOIDCServerService_RefreshServerCredential(t *testing.T) {
	s, fake, _ := newConnectedOIDCServerService()
	info, err := s.RefreshServerCredential(tenantRef)
	require.NoError(t, err)
	assert.Equal(t, "codex", info.Name)
	assert.Equal(t, []string{"refresh"}, fake.calls)

	fake.cred.Status = transport.OIDCCredentialStatusReloginRequired
	fake.cred.StatusReason = "refresh token revoked"
	info, err = s.RefreshServerCredential(tenantRef)
	require.NoError(t, err)
	assert.Equal(t, "relogin_required", info.Status)
	assert.Equal(t, "refresh token revoked", info.StatusReason)
}

func TestOIDCServerService_RefreshServerCredentialErrors(t *testing.T) {
	s, fake, _ := newConnectedOIDCServerService()
	_, err := s.RefreshServerCredential(transport.OIDCCredentialRef{})
	assert.ErrorIs(t, err, ErrOIDCServerNameRequired)
	fake.err = errOIDCServerFake
	_, err = s.RefreshServerCredential(tenantRef)
	assert.ErrorIs(t, err, errOIDCServerFake)
}

func TestOIDCServerService_DeleteServerCredential(t *testing.T) {
	s, fake, _ := newConnectedOIDCServerService()
	require.NoError(t, s.DeleteServerCredential(tenantRef))
	assert.Equal(t, []string{"delete"}, fake.calls)
	assert.Equal(t, tenantRef, *fake.ref)
}

func TestOIDCServerService_DeleteServerCredentialErrors(t *testing.T) {
	s, fake, _ := newConnectedOIDCServerService()
	assert.ErrorIs(t, s.DeleteServerCredential(transport.OIDCCredentialRef{Scope: "tenant"}), ErrOIDCServerNameRequired)
	fake.err = errOIDCServerFake
	assert.ErrorIs(t, s.DeleteServerCredential(tenantRef), errOIDCServerFake)
}

func TestOIDCServerService_CopyServerAccessToken(t *testing.T) {
	s, fake, clip := newConnectedOIDCServerService()
	require.NoError(t, s.CopyServerAccessToken(tenantRef))
	assert.Equal(t, "at-secret", clip.copied)
	assert.Equal(t, []string{"token"}, fake.calls)
}

func TestOIDCServerService_CopyServerAccessTokenErrors(t *testing.T) {
	s, fake, clip := newConnectedOIDCServerService()
	assert.ErrorIs(t, s.CopyServerAccessToken(transport.OIDCCredentialRef{}), ErrOIDCServerNameRequired)

	clip.err = ErrClipboardToolUnavailable
	assert.ErrorIs(t, s.CopyServerAccessToken(tenantRef), ErrClipboardToolUnavailable)

	fake.err = errOIDCServerFake
	assert.ErrorIs(t, s.CopyServerAccessToken(tenantRef), errOIDCServerFake)
	assert.Empty(t, clip.copied, "nothing reaches the clipboard on failure")

	noClip := NewOIDCServerService(nil)
	noClip.SetClient(fake)
	assert.ErrorIs(t, noClip.CopyServerAccessToken(tenantRef), ErrOIDCServerClipboardUnavailable)
}

func TestOIDCServerService_SupportsDeviceFromConfig(t *testing.T) {
	info := serverCredentialInfo(&transport.OIDCCredential{
		Config: transport.OIDCCredentialConfig{Issuer: "https://idp.example.com", DeviceAuthorizationEndpoint: "https://idp.example.com/device"},
	})
	assert.True(t, info.SupportsDevice, "a configured device endpoint offers a device login")

	info = serverCredentialInfo(&transport.OIDCCredential{Config: transport.OIDCCredentialConfig{Template: "anthropic"}})
	assert.False(t, info.SupportsDevice, "an import-only template offers none")
}

func TestOIDCServerService_RecoversPanics(t *testing.T) {
	s := NewOIDCServerService(nil)
	// A nil credential from a misbehaving server panics in the conversion.
	s.SetClient(&fakeOIDCServer{})
	_, err := s.RefreshServerCredential(tenantRef)
	var msg *MessageError
	assert.ErrorAs(t, err, &msg)
}
