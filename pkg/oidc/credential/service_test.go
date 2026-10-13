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

package credential

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/oidc"
	"github.com/jeremyhahn/go-xkms/pkg/scope"
)

func TestCreateDiscoversAndImports(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	alice := user(tenantA, "alice")

	c, err := e.svc.Create(ctx, alice, shared("ci"), e.customConfig(), nil)
	require.NoError(t, err)
	assert.Equal(t, StatusPending, c.Status)
	assert.Equal(t, tenantA, c.TenantID)
	assert.Equal(t, e.idp.URL()+"/token", c.Config.TokenEndpoint, "endpoints are discovered once, at creation")
	assert.Equal(t, e.idp.URL()+"/device", c.Config.DeviceAuthorizationEndpoint)

	_, err = e.svc.GetAccessToken(ctx, alice, shared("ci"))
	assert.ErrorIs(t, err, ErrNoLogin)

	_, err = e.svc.Create(ctx, alice, shared("ci"), e.customConfig(), nil)
	assert.ErrorIs(t, err, ErrExists)

	c, err = e.svc.ImportTokens(ctx, alice, shared("ci"), Tokens{AccessToken: "at-imported", RefreshToken: "rt-0", ExpiresAt: time.Now().Add(time.Hour)})
	require.NoError(t, err)
	assert.Equal(t, StatusActive, c.Status)
	assert.True(t, c.Refreshable)

	tok, err := e.svc.GetAccessToken(ctx, alice, shared("ci"))
	require.NoError(t, err)
	assert.Equal(t, "at-imported", tok.AccessToken)
	assert.Equal(t, 0, e.idp.refreshCount(), "a token outside its margin is served without a refresh")
}

func TestGetAccessTokenRefreshesAndPersistsRotation(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	alice := user(tenantA, "alice")
	e.importDue(t, alice, shared("codex"))

	tok, err := e.svc.GetAccessToken(ctx, alice, shared("codex"))
	require.NoError(t, err)
	assert.Equal(t, "at-1", tok.AccessToken)
	assert.Equal(t, 1, e.idp.refreshCount())

	// The rotated refresh token was persisted: the next forced refresh
	// presents rt-1, which the provider accepts, not the spent rt-0.
	c, err := e.svc.Refresh(ctx, alice, shared("codex"))
	require.NoError(t, err)
	assert.Equal(t, StatusActive, c.Status)
	tok, err = e.svc.GetAccessToken(ctx, alice, shared("codex"))
	require.NoError(t, err)
	assert.Equal(t, "at-2", tok.AccessToken)
	assert.Equal(t, 2, e.idp.refreshCount())
}

// TestConcurrentRefreshHasOneWinner proves concurrent consumers of a due
// credential cause exactly one refresh: a second would present the spent,
// rotated refresh token and lose the login.
func TestConcurrentRefreshHasOneWinner(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	alice := user(tenantA, "alice")
	e.importDue(t, alice, shared("codex"))

	gate := make(chan struct{})
	e.idp.set(func(f *fakeIdP) { f.refreshGate = gate })

	const callers = 16
	var started, done sync.WaitGroup
	started.Add(callers)
	done.Add(callers)
	tokens := make([]string, callers)
	errs := make([]error, callers)
	for i := range callers {
		go func() {
			defer done.Done()
			started.Done()
			tok, err := e.svc.GetAccessToken(ctx, alice, shared("codex"))
			errs[i] = err
			if tok != nil {
				tokens[i] = tok.AccessToken
			}
		}()
	}
	started.Wait()
	close(gate)
	done.Wait()

	for i := range callers {
		require.NoError(t, errs[i])
		assert.Equal(t, "at-1", tokens[i], "every caller gets the one winner's token")
	}
	assert.Equal(t, 1, e.idp.refreshCount())
	c, err := e.svc.Get(ctx, alice, shared("codex"))
	require.NoError(t, err)
	assert.Equal(t, StatusActive, c.Status)
}

func TestRejectedRefreshNeedsRelogin(t *testing.T) {
	for _, code := range []string{"invalid_grant", "refresh_token_reused", "refresh_token_expired"} {
		t.Run(code, func(t *testing.T) {
			e := newEnv(t)
			ctx := context.Background()
			alice := user(tenantA, "alice")
			e.importDue(t, alice, shared("codex"))

			events := make(chan Event, 4)
			unsubscribe := e.svc.Subscribe(func(ev Event) { events <- ev })
			defer unsubscribe()
			e.idp.set(func(f *fakeIdP) { f.rejectCode = code })

			_, err := e.svc.GetAccessToken(ctx, alice, shared("codex"))
			require.ErrorIs(t, err, ErrReloginRequired)
			var refreshErr *RefreshError
			require.ErrorAs(t, err, &refreshErr)
			assert.True(t, refreshErr.Relogin)
			assert.Equal(t, code, refreshErr.Reason)

			ev := <-events
			assert.Equal(t, EventReloginRequired, ev.Type)
			assert.Equal(t, code, ev.Reason)
			assert.Equal(t, "codex", ev.Ref.Name)

			c, err := e.svc.Get(ctx, alice, shared("codex"))
			require.NoError(t, err)
			assert.Equal(t, StatusReloginRequired, c.Status)
			assert.Equal(t, code, c.StatusReason)

			// The dead credential is not hammered: no further refresh.
			_, err = e.svc.GetAccessToken(ctx, alice, shared("codex"))
			assert.ErrorIs(t, err, ErrReloginRequired)
			assert.Equal(t, 1, e.idp.refreshCount())

			// An import restores it.
			e.idp.set(func(f *fakeIdP) { f.rejectCode = "" })
			_, err = e.svc.ImportTokens(ctx, alice, shared("codex"), Tokens{AccessToken: "at-new", RefreshToken: e.idp.currentToken(), ExpiresAt: time.Now().Add(time.Hour)})
			require.NoError(t, err)
			tok, err := e.svc.GetAccessToken(ctx, alice, shared("codex"))
			require.NoError(t, err)
			assert.Equal(t, "at-new", tok.AccessToken)
		})
	}
}

func TestTransientRefreshFailureServesValidToken(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	alice := user(tenantA, "alice")
	e.importDue(t, alice, shared("codex"))
	e.idp.set(func(f *fakeIdP) { f.failRefresh = http.StatusServiceUnavailable })

	tok, err := e.svc.GetAccessToken(ctx, alice, shared("codex"))
	require.NoError(t, err, "a still-valid token is served when the provider is down")
	assert.Equal(t, "at-0", tok.AccessToken)

	c, err := e.svc.Get(ctx, alice, shared("codex"))
	require.NoError(t, err)
	assert.Equal(t, StatusActive, c.Status)
	assert.NotEmpty(t, c.LastError)

	_, err = e.svc.Refresh(ctx, alice, shared("codex"))
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrReloginRequired)

	// Past expiry the token is no longer served.
	e.clock.advance(2 * time.Minute)
	_, err = e.svc.GetAccessToken(ctx, alice, shared("codex"))
	assert.ErrorIs(t, err, ErrTokenExpired)

	// The provider recovers; the next refresh clears the error.
	e.idp.set(func(f *fakeIdP) { f.failRefresh = 0 })
	tok, err = e.svc.GetAccessToken(ctx, alice, shared("codex"))
	require.NoError(t, err)
	assert.Equal(t, "at-1", tok.AccessToken)
	c, err = e.svc.Get(ctx, alice, shared("codex"))
	require.NoError(t, err)
	assert.Empty(t, c.LastError)
}

func TestDeviceLogin(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	alice := user(tenantA, "alice")
	_, err := e.svc.Create(ctx, alice, personal("google"), e.customConfig(), nil)
	require.NoError(t, err)

	_, err = e.svc.PollDeviceLogin(ctx, alice, personal("google"))
	assert.ErrorIs(t, err, ErrNoDeviceLogin)

	c, err := e.svc.StartDeviceLogin(ctx, alice, personal("google"))
	require.NoError(t, err)
	require.NotNil(t, c.DeviceLogin)
	assert.Equal(t, "USER-CODE", c.DeviceLogin.UserCode)
	assert.Equal(t, e.idp.URL()+"/activate", c.DeviceLogin.VerificationURI)

	c, err = e.svc.PollDeviceLogin(ctx, alice, personal("google"))
	require.NoError(t, err)
	assert.Equal(t, StatusPending, c.Status, "pending until the user approves")

	e.idp.set(func(f *fakeIdP) { f.deviceGranted = true })
	c, err = e.svc.PollDeviceLogin(ctx, alice, personal("google"))
	require.NoError(t, err)
	assert.Equal(t, StatusActive, c.Status)
	assert.Nil(t, c.DeviceLogin)

	tok, err := e.svc.GetAccessToken(ctx, alice, personal("google"))
	require.NoError(t, err)
	assert.Equal(t, "at-device", tok.AccessToken)
	assert.Equal(t, "id-device", tok.IDToken)
}

func TestNonRefreshableTokenExpires(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	alice := user(tenantA, "alice")
	events := make(chan Event, 4)
	defer e.svc.Subscribe(func(ev Event) { events <- ev })()

	c, err := e.svc.Create(ctx, alice, shared("claude"), Config{Template: "anthropic"}, &Tokens{AccessToken: "sk-ant-oat01-x", RefreshToken: "ignored"})
	require.NoError(t, err)
	assert.Equal(t, StatusActive, c.Status)
	assert.False(t, c.Refreshable, "a no-refresh provider never stores a refresh token")
	assert.WithinDuration(t, time.Now().Add(365*24*time.Hour), c.ExpiresAt, time.Minute, "the template's lifetime dates an opaque token")

	_, err = e.svc.Refresh(ctx, alice, shared("claude"))
	assert.ErrorIs(t, err, ErrNotRefreshable)

	tok, err := e.svc.GetAccessToken(ctx, alice, shared("claude"))
	require.NoError(t, err)
	assert.Equal(t, "sk-ant-oat01-x", tok.AccessToken)

	e.clock.advance(366 * 24 * time.Hour)
	n, err := e.svc.RefreshDue(ctx)
	require.NoError(t, err)
	assert.Zero(t, n)
	ev := <-events
	assert.Equal(t, EventExpired, ev.Type)

	c, err = e.svc.Get(ctx, alice, shared("claude"))
	require.NoError(t, err)
	assert.Equal(t, StatusExpired, c.Status)
	_, err = e.svc.GetAccessToken(ctx, alice, shared("claude"))
	assert.ErrorIs(t, err, ErrTokenExpired)
}

func TestScopeIsolation(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	alice := user(tenantA, "alice")
	bob := user(tenantA, "bob")
	mallory := user(tenantB, "mallory")
	admin := platform("root")

	_, err := e.svc.Create(ctx, alice, personal("mine"), Config{Template: "anthropic"}, &Tokens{AccessToken: "secret"})
	require.NoError(t, err)
	_, err = e.svc.Create(ctx, alice, shared("team"), Config{Template: "anthropic"}, &Tokens{AccessToken: "shared-secret"})
	require.NoError(t, err)

	// Bob, in the same tenant, sees the shared credential and not Alice's.
	tok, err := e.svc.GetAccessToken(ctx, bob, shared("team"))
	require.NoError(t, err)
	assert.Equal(t, "shared-secret", tok.AccessToken)
	_, err = e.svc.GetAccessToken(ctx, bob, Ref{Scope: scope.User, Owner: "alice", Name: "mine"})
	assert.ErrorIs(t, err, scope.ErrRefused)
	_, err = e.svc.GetAccessToken(ctx, bob, personal("mine"))
	assert.ErrorIs(t, err, ErrNotFound, "Bob's own namespace has no such credential")
	list, err := e.svc.List(ctx, bob, "")
	require.NoError(t, err)
	assert.Equal(t, []string{"team"}, names(list))

	// Alice lists both.
	list, err = e.svc.List(ctx, alice, "")
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"team", "mine"}, names(list))

	// Another tenant sees nothing of tenant A.
	_, err = e.svc.Get(ctx, mallory, Ref{TenantID: tenantA, Scope: scope.Tenant, Name: "team"})
	assert.ErrorIs(t, err, scope.ErrRefused)
	_, err = e.svc.List(ctx, mallory, tenantA)
	assert.ErrorIs(t, err, scope.ErrRefused)

	// The system tenant is confined to its own tenant: it reaches none of
	// tenant A's credentials.
	_, err = e.svc.Get(ctx, admin, Ref{TenantID: tenantA, Scope: scope.Tenant, Name: "team"})
	assert.ErrorIs(t, err, scope.ErrRefused)
	_, err = e.svc.GetAccessToken(ctx, admin, Ref{TenantID: tenantA, Scope: scope.User, Owner: "alice", Name: "mine"})
	assert.ErrorIs(t, err, scope.ErrRefused)
	_, err = e.svc.List(ctx, admin, tenantA)
	assert.ErrorIs(t, err, scope.ErrRefused)

	// No identity reaches nothing.
	_, err = e.svc.Get(ctx, scope.Principal{}, Ref{TenantID: tenantA, Scope: scope.Tenant, Name: "team"})
	assert.ErrorIs(t, err, scope.ErrRefused)

	// Deletion follows the same rule.
	assert.ErrorIs(t, e.svc.Delete(ctx, bob, Ref{Scope: scope.User, Owner: "alice", Name: "mine"}), scope.ErrRefused)
	require.NoError(t, e.svc.Delete(ctx, alice, personal("mine")))
	_, err = e.svc.Get(ctx, alice, personal("mine"))
	assert.ErrorIs(t, err, ErrNotFound)
}

func TestValidation(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	alice := user(tenantA, "alice")

	_, err := e.svc.Create(ctx, alice, shared("../x"), e.customConfig(), nil)
	assert.ErrorIs(t, err, ErrInvalidName)
	_, err = e.svc.Create(ctx, alice, Ref{Scope: scope.Service, Name: "x"}, e.customConfig(), nil)
	assert.ErrorIs(t, err, ErrScopeUnsupported)
	_, err = e.svc.Create(ctx, alice, shared("aws"), Config{Template: "aws"}, nil)
	assert.ErrorIs(t, err, ErrInvalidConfig, "AWS console credentials stay an xkey-local login")
	_, err = e.svc.Create(ctx, alice, shared("x"), Config{Template: "nope"}, nil)
	assert.ErrorIs(t, err, ErrInvalidConfig)
	_, err = e.svc.Create(ctx, alice, shared("x"), Config{ClientID: "c"}, nil)
	assert.ErrorIs(t, err, ErrInvalidConfig)
	_, err = e.svc.Create(ctx, alice, shared("x"), Config{Issuer: e.idp.URL()}, nil)
	assert.ErrorIs(t, err, ErrInvalidConfig, "a refreshable provider needs a client ID")
	_, err = e.svc.Create(ctx, alice, shared("x"), Config{Issuer: "https://idp.example.com", ClientID: "c", TokenEndpoint: "http://idp.example.com/token"}, nil)
	assert.ErrorIs(t, err, ErrInvalidConfig, "plain-http endpoints are refused")
	_, err = e.svc.Create(ctx, alice, shared("x"), e.customConfig(), &Tokens{})
	assert.ErrorIs(t, err, ErrInvalidTokens)
	_, err = e.svc.Create(ctx, alice, shared("x"), Config{Template: "anthropic", RefreshMargin: -time.Second}, nil)
	assert.ErrorIs(t, err, ErrInvalidConfig)

	_, err = e.svc.StartDeviceLogin(ctx, alice, shared("missing"))
	assert.ErrorIs(t, err, ErrNotFound)
	_, err = e.svc.Create(ctx, alice, shared("claude"), Config{Template: "anthropic"}, nil)
	require.NoError(t, err)
	_, err = e.svc.StartDeviceLogin(ctx, alice, shared("claude"))
	assert.ErrorIs(t, err, ErrFlowUnsupported, "anthropic tokens are imported only")

	_, err = New(nil)
	assert.ErrorIs(t, err, ErrNilBarriers)
}

func TestOpenAITemplateConfig(t *testing.T) {
	e := newEnv(t)
	c, err := e.svc.Create(context.Background(), user(tenantA, "alice"), shared("codex"), Config{Template: "openai"}, nil)
	require.NoError(t, err)
	assert.Equal(t, "https://auth.openai.com", c.Config.Issuer)
	assert.Equal(t, "app_EMoamEEZ73f0CkXaXp7hrann", c.Config.ClientID)
	assert.Equal(t, "https://auth.openai.com/oauth/token", c.Config.TokenEndpoint)
	assert.Equal(t, oidc.TokenEncodingJSON, c.Config.TokenEncoding)
	assert.Equal(t, oidc.DeviceStyleOpenAI, c.Config.DeviceStyle)
}

func names(list []*Credential) []string {
	out := make([]string, len(list))
	for i, c := range list {
		out[i] = c.Name
	}
	return out
}
