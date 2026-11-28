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

package webauthn

import (
	"bytes"
	"context"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	routerTestSystem  = "system"
	routerTestTenantB = "tenant-b"
	routerTestHostB   = "b.example.com"
)

type routerFixture struct {
	router *TenantRouter
	system *Service
	builds atomic.Int32
}

func newRouterFixture(t *testing.T) *routerFixture {
	t.Helper()
	cfg := validTestConfig()
	cfg.RPOrigins = append(cfg.RPOrigins, "https://"+routerTestHostB)
	cfg.TenantHosts = map[string]string{routerTestHostB: routerTestTenantB}
	cfg.AllowPublicRegistration = openRegistration()
	users, creds := newTestStores(t)
	system, err := NewService(ServiceParams{
		Config: cfg, UserStore: users, SessionStore: NewMemorySessionStore(), CredentialStore: creds,
		TenantID: routerTestSystem,
	})
	require.NoError(t, err)

	f := &routerFixture{system: system}
	f.router, err = NewTenantRouter(TenantRouterParams{
		SystemTenant: routerTestSystem,
		System:       system,
		TenantExists: func(_ context.Context, tenantID string) (bool, error) {
			return tenantID == routerTestTenantB, nil
		},
		Build: func(tenantID string) (*Service, error) {
			f.builds.Add(1)
			u, c := newTestStores(t)
			return NewService(ServiceParams{
				Config: cfg, UserStore: u, SessionStore: NewMemorySessionStore(), CredentialStore: c,
				TenantID: tenantID,
			})
		},
	})
	require.NoError(t, err)
	return f
}

func TestTenantRouter_SystemAndEmptyTenantUseSystemService(t *testing.T) {
	f := newRouterFixture(t)
	ctx := context.Background()
	for _, tenant := range []string{"", routerTestSystem} {
		svc, err := f.router.For(ctx, tenant)
		require.NoError(t, err)
		require.Same(t, f.system, svc)
	}
	require.Zero(t, f.builds.Load())
	require.Zero(t, f.router.CachedTenants())
}

func TestTenantRouter_BuildsKnownTenantOnce(t *testing.T) {
	f := newRouterFixture(t)
	ctx := context.Background()
	first, err := f.router.For(ctx, routerTestTenantB)
	require.NoError(t, err)
	second, err := f.router.For(ctx, routerTestTenantB)
	require.NoError(t, err)
	require.Same(t, first, second)
	require.NotSame(t, f.system, first)
	require.Equal(t, int32(1), f.builds.Load())
	require.Equal(t, 1, f.router.CachedTenants())
}

func TestTenantRouter_UnknownTenantIsNeverBuiltOrCached(t *testing.T) {
	f := newRouterFixture(t)
	ctx := context.Background()
	for _, tenant := range []string{"tenant-x", "tenant-y", "tenant-x"} {
		svc, err := f.router.For(ctx, tenant)
		require.NoError(t, err)
		require.NotNil(t, svc)
		require.NotSame(t, f.system, svc)
	}
	require.Zero(t, f.builds.Load())
	require.Zero(t, f.router.CachedTenants())
}

func TestTenantRouter_DecoyNeverResolvesARealAccount(t *testing.T) {
	f := newRouterFixture(t)
	ctx := context.Background()
	const email = "alice@example.com"
	_, _, err := f.system.BeginRegistration(ctx, email, "Alice")
	require.NoError(t, err)
	_, err = f.system.GetUserByEmail(ctx, email)
	require.NoError(t, err)

	decoy, err := f.router.For(ctx, "tenant-x")
	require.NoError(t, err)
	_, err = decoy.GetUserByEmail(ctx, email)
	require.True(t, IsUserNotFound(err), "decoy resolved an account: %v", err)

	opts, sessionID, err := decoy.BeginLoginForEmail(ctx, email)
	require.NoError(t, err)
	require.NotEmpty(t, sessionID)
	require.NotEmpty(t, opts.Response.AllowedCredentials)
}

func TestTenantRouter_DecoyIsDeterministicPerTenant(t *testing.T) {
	f := newRouterFixture(t)
	ctx := context.Background()
	const email = "nobody@example.com"
	allowed := func(tenant string) []byte {
		svc, err := f.router.For(ctx, tenant)
		require.NoError(t, err)
		opts, _, err := svc.BeginLoginForEmail(ctx, email)
		require.NoError(t, err)
		require.NotEmpty(t, opts.Response.AllowedCredentials)
		return opts.Response.AllowedCredentials[0].CredentialID
	}
	require.Equal(t, allowed("tenant-x"), allowed("tenant-x"))
	require.False(t, bytes.Equal(allowed("tenant-x"), allowed("tenant-y")))
	require.Equal(t, allowed(routerTestTenantB), allowed(routerTestTenantB))
}

func TestTenantRouter_ForRequestHostRule(t *testing.T) {
	f := newRouterFixture(t)
	ctx := context.Background()
	b, err := f.router.For(ctx, routerTestTenantB)
	require.NoError(t, err)

	got, err := f.router.ForRequest(ctx, routerTestHostB, "")
	require.NoError(t, err)
	require.Same(t, b, got)

	got, err = f.router.ForRequest(ctx, routerTestHostB+":443", routerTestTenantB)
	require.NoError(t, err)
	require.Same(t, b, got)

	// An explicit tenant that contradicts the host is an unknown tenant.
	got, err = f.router.ForRequest(ctx, routerTestHostB, routerTestSystem)
	require.NoError(t, err)
	require.NotSame(t, f.system, got)
	require.NotSame(t, b, got)

	// A host the config does not map falls back to the explicit tenant.
	got, err = f.router.ForRequest(ctx, "example.com", routerTestTenantB)
	require.NoError(t, err)
	require.Same(t, b, got)
	got, err = f.router.ForRequest(ctx, "example.com", "")
	require.NoError(t, err)
	require.Same(t, f.system, got)
	require.Equal(t, 1, f.router.CachedTenants())
}

func TestConfig_TenantHostsMustBeOrigins(t *testing.T) {
	cfg := validTestConfig()
	cfg.TenantHosts = map[string]string{"other.example.com": routerTestTenantB}
	cfg.SetDefaults()
	require.Error(t, cfg.Validate())

	cfg.RPOrigins = append(cfg.RPOrigins, "https://other.example.com")
	require.NoError(t, cfg.Validate())

	cfg.TenantHosts = map[string]string{"other.example.com": ""}
	require.Error(t, cfg.Validate())
}

func TestQRDBAdapter_GetByID_OtherTenantIsNotFound(t *testing.T) {
	ctx := context.Background()
	factory := newTestDAOFactory()
	systemUsers, _, client := newTestAdapterWith(t, factory)
	tenantUsers, _, err := NewQRDBUserStoreAdapter(QRDBUserStoreOptions{
		Users: client, DAOFactory: factory, TenantID: routerTestTenantB,
	})
	require.NoError(t, err)

	user, err := tenantUsers.Create(ctx, "carol@example.com", "Carol")
	require.NoError(t, err)
	_, err = tenantUsers.GetByID(ctx, user.WebAuthnID())
	require.NoError(t, err)

	_, err = systemUsers.GetByID(ctx, user.WebAuthnID())
	require.ErrorIs(t, err, ErrUserNotFound)
}
