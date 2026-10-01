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

package xkms

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/oidc/credential"
	"github.com/jeremyhahn/go-xkms/pkg/scope"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/barriertest"
)

// oidcTestService returns the service with an OIDC credential service over
// real barriers of tenant acme, and a context carrying user alice of acme.
func oidcTestService(t *testing.T) (*XKMSService, context.Context) {
	t.Helper()
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)
	registry := barriertest.NewRegistry(t)
	barriertest.RegisterTenant(t, registry, "acme")
	creds, err := credential.New(credential.RegistryBarriers(registry))
	require.NoError(t, err)
	svc.SetOIDCCredentialService(creds)
	t.Cleanup(func() { svc.SetOIDCCredentialService(nil) })
	ctx := auth.WithIdentity(context.Background(), &auth.Identity{Subject: "alice", TenantID: "acme"})
	return svc, ctx
}

func TestOIDCCredential_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)
	svc.SetOIDCCredentialService(nil)
	ctx := context.Background()
	ref := &transport.OIDCCredentialRef{Scope: "user", Name: "x"}

	_, err = svc.OIDCCredentialGet(ctx, ref)
	assert.ErrorIs(t, err, ErrNotConfigured)
	_, err = svc.OIDCCredentialList(ctx, &transport.OIDCCredentialListRequest{})
	assert.ErrorIs(t, err, ErrNotConfigured)
	assert.ErrorIs(t, svc.OIDCCredentialDelete(ctx, ref), ErrNotConfigured)
	_, err = svc.OIDCCredentialGetAccessToken(ctx, ref)
	assert.ErrorIs(t, err, ErrNotConfigured)
	assert.Nil(t, svc.OIDCCredentialService())
}

func TestOIDCCredential_NilRequests(t *testing.T) {
	svc, ctx := oidcTestService(t)
	_, err := svc.OIDCCredentialCreate(ctx, nil)
	assert.ErrorIs(t, err, ErrNilRequest)
	_, err = svc.OIDCCredentialImport(ctx, nil)
	assert.ErrorIs(t, err, ErrNilRequest)
	_, err = svc.OIDCCredentialGet(ctx, nil)
	assert.ErrorIs(t, err, ErrNilRequest)
	_, err = svc.OIDCCredentialList(ctx, nil)
	assert.ErrorIs(t, err, ErrNilRequest)
	assert.ErrorIs(t, svc.OIDCCredentialDelete(ctx, nil), ErrNilRequest)
	_, err = svc.OIDCCredentialGetAccessToken(ctx, nil)
	assert.ErrorIs(t, err, ErrNilRequest)
	_, err = svc.OIDCCredentialRefresh(ctx, nil)
	assert.ErrorIs(t, err, ErrNilRequest)
	_, err = svc.OIDCCredentialDeviceStart(ctx, nil)
	assert.ErrorIs(t, err, ErrNilRequest)
	_, err = svc.OIDCCredentialDevicePoll(ctx, nil)
	assert.ErrorIs(t, err, ErrNilRequest)
}

func TestOIDCCredential_RoundTrip(t *testing.T) {
	svc, ctx := oidcTestService(t)
	expires := time.Now().Add(time.Hour).Truncate(time.Second)
	ref := transport.OIDCCredentialRef{Scope: "user", Name: "claude"}

	created, err := svc.OIDCCredentialCreate(ctx, &transport.OIDCCredentialCreateRequest{
		OIDCCredentialRef: ref,
		Config:            transport.OIDCCredentialConfig{Template: "anthropic", RefreshMarginSeconds: 60},
		Tokens:            &transport.OIDCCredentialTokens{AccessToken: "sk-ant-oat01-x", ExpiresAt: &expires},
	})
	require.NoError(t, err)
	assert.Equal(t, "acme", created.TenantID)
	assert.Equal(t, "alice", created.Owner, "a personal credential belongs to the caller")
	assert.Equal(t, transport.OIDCCredentialStatusActive, created.Status)
	assert.Equal(t, int64(60), created.Config.RefreshMarginSeconds)
	assert.Equal(t, int64(365*24*3600), created.Config.TokenLifetimeSeconds)
	require.NotNil(t, created.ExpiresAt)
	assert.True(t, created.ExpiresAt.Equal(expires))

	got, err := svc.OIDCCredentialGet(ctx, &ref)
	require.NoError(t, err)
	assert.Equal(t, created.Name, got.Name)

	list, err := svc.OIDCCredentialList(ctx, &transport.OIDCCredentialListRequest{})
	require.NoError(t, err)
	require.Len(t, list.Credentials, 1)

	tok, err := svc.OIDCCredentialGetAccessToken(ctx, &ref)
	require.NoError(t, err)
	assert.Equal(t, "sk-ant-oat01-x", tok.AccessToken)
	assert.Equal(t, "Bearer", tok.TokenType)

	imported, err := svc.OIDCCredentialImport(ctx, &transport.OIDCCredentialImportRequest{
		OIDCCredentialRef: ref,
		Tokens:            transport.OIDCCredentialTokens{AccessToken: "sk-ant-oat01-y"},
	})
	require.NoError(t, err)
	assert.Equal(t, transport.OIDCCredentialStatusActive, imported.Status)

	_, err = svc.OIDCCredentialRefresh(ctx, &ref)
	assert.ErrorIs(t, err, credential.ErrNotRefreshable)
	_, err = svc.OIDCCredentialDeviceStart(ctx, &ref)
	assert.ErrorIs(t, err, credential.ErrFlowUnsupported)
	_, err = svc.OIDCCredentialDevicePoll(ctx, &ref)
	assert.ErrorIs(t, err, credential.ErrNoDeviceLogin)

	require.NoError(t, svc.OIDCCredentialDelete(ctx, &ref))
	_, err = svc.OIDCCredentialGet(ctx, &ref)
	assert.ErrorIs(t, err, credential.ErrNotFound)
}

func TestOIDCCredential_RefusesOtherUsersAndBadScopes(t *testing.T) {
	svc, ctx := oidcTestService(t)
	_, err := svc.OIDCCredentialCreate(ctx, &transport.OIDCCredentialCreateRequest{
		OIDCCredentialRef: transport.OIDCCredentialRef{Scope: "user", Name: "mine"},
		Config:            transport.OIDCCredentialConfig{Template: "anthropic"},
		Tokens:            &transport.OIDCCredentialTokens{AccessToken: "x"},
	})
	require.NoError(t, err)

	bob := auth.WithIdentity(context.Background(), &auth.Identity{Subject: "bob", TenantID: "acme"})
	_, err = svc.OIDCCredentialGetAccessToken(bob, &transport.OIDCCredentialRef{Scope: "user", Owner: "alice", Name: "mine"})
	assert.ErrorIs(t, err, scope.ErrRefused)

	_, err = svc.OIDCCredentialGet(ctx, &transport.OIDCCredentialRef{Scope: "bogus", Name: "mine"})
	var invalid *scope.InvalidScopeError
	assert.ErrorAs(t, err, &invalid)
}

func TestOIDCCredentialToTransport_DeviceLogin(t *testing.T) {
	expires := time.Now().Add(time.Minute)
	out := OIDCCredentialToTransport(&credential.Credential{
		Ref:    credential.Ref{TenantID: "acme", Scope: scope.Tenant, Name: "g"},
		Status: credential.StatusPending,
		DeviceLogin: &credential.DeviceLogin{
			UserCode: "CODE", VerificationURI: "https://idp.example.com/device", Interval: 5 * time.Second, ExpiresAt: expires,
		},
	})
	require.NotNil(t, out.DeviceLogin)
	assert.Equal(t, int64(5), out.DeviceLogin.IntervalSeconds)
	assert.Equal(t, "CODE", out.DeviceLogin.UserCode)
	assert.Nil(t, out.ExpiresAt, "an unknown expiry is absent, not the zero time")
	assert.Nil(t, out.LastRefresh)
}
