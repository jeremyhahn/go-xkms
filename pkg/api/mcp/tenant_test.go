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

package mcp

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// tenantTestLogger returns a discard logger for tenant gate tests.
func tenantTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// tenantTestRegistry creates an initialized and unsealed BarrierRegistry
// backed by in-memory storage for tenant gate tests.
func tenantTestRegistry(t *testing.T) *seal.BarrierRegistry {
	t.Helper()
	base := storage.NewMemory()
	barrier, err := seal.NewBarrier(
		tenantTestLogger(),
		base,
		seal.BarrierConfig{
			RootKeyPath:     "core/seal",
			PreferenceOrder: []seal.StrategyID{seal.StrategyPassphrase},
		},
		seal.NewSoftwareStrategy(),
	)
	require.NoError(t, err)

	ctx := context.Background()
	require.NoError(t, barrier.Initialize(ctx, seal.Credentials{Secret: []byte("test-password")}))

	registry, err := seal.NewBarrierRegistry(barrier)
	require.NoError(t, err)
	return registry
}

// tenantTestRegisteredTenant registers and initializes a tenant, returning
// its unsealed TenantBarrier.
func tenantTestRegisteredTenant(t *testing.T, registry *seal.BarrierRegistry, tenantID string) *seal.TenantBarrier {
	t.Helper()
	tb, err := registry.RegisterTenant(tenantID)
	require.NoError(t, err)

	ctx := context.Background()
	require.NoError(t, registry.InitializeTenant(ctx, tenantID, seal.Credentials{Secret: []byte("tenant-password")}))
	require.False(t, tb.IsSealed(), "tenant barrier should be unsealed after initialization")

	return tb
}

func TestServerTenantAccess_NoIdentity(t *testing.T) {
	registry := tenantTestRegistry(t)
	s := &Server{logger: tenantTestLogger(), barrierRegistry: registry}

	ctx, err := s.tenantAccess(context.Background(), "xkms.listKeys")
	require.NoError(t, err)
	assert.Nil(t, auth.GetTenantBarrier(ctx))
}

func TestServerTenantAccess_EmptyTenantID(t *testing.T) {
	registry := tenantTestRegistry(t)
	s := &Server{logger: tenantTestLogger(), barrierRegistry: registry}

	identity := &auth.Identity{Subject: "system-admin", TenantID: ""}
	ctx := auth.WithIdentity(context.Background(), identity)

	ctx, err := s.tenantAccess(ctx, "xkms.listKeys")
	require.NoError(t, err)
	assert.Nil(t, auth.GetTenantBarrier(ctx))
}

// TestServerTenantAccess_SystemTenantID is the MCP regression test for the
// reported bug: a "system"-tenant identity (e.g. a WebAuthn-registered user,
// see pkg/server.webAuthnSystemTenant) must pass the tenant gate exactly like
// an empty-TenantID identity. MCP carried NO tenant enforcement at all before
// this change, so this test also proves the gate now exists on this
// transport.
func TestServerTenantAccess_SystemTenantID(t *testing.T) {
	registry := tenantTestRegistry(t)
	s := &Server{logger: tenantTestLogger(), barrierRegistry: registry}

	identity := &auth.Identity{Subject: "webauthn-user", TenantID: "system"}
	ctx := auth.WithIdentity(context.Background(), identity)

	ctx, err := s.tenantAccess(ctx, "xkms.listKeys")
	require.NoError(t, err)
	assert.Nil(t, auth.GetTenantBarrier(ctx))
}

func TestServerTenantAccess_SORole(t *testing.T) {
	registry := tenantTestRegistry(t)
	s := &Server{logger: tenantTestLogger(), barrierRegistry: registry}

	identity := &auth.Identity{Subject: "so-admin", TenantID: "nonexistent-tenant", Roles: []string{"so"}}
	ctx := auth.WithIdentity(context.Background(), identity)

	ctx, err := s.tenantAccess(ctx, "xkms.listKeys")
	require.NoError(t, err)
	assert.Nil(t, auth.GetTenantBarrier(ctx))
}

func TestServerTenantAccess_NoRegistry(t *testing.T) {
	s := &Server{logger: tenantTestLogger()} // no registry

	identity := &auth.Identity{Subject: "tenant-user", TenantID: "some-tenant"}
	ctx := auth.WithIdentity(context.Background(), identity)

	ctx, err := s.tenantAccess(ctx, "xkms.listKeys")
	require.NoError(t, err)
	assert.Nil(t, auth.GetTenantBarrier(ctx))
}

func TestServerTenantAccess_TenantNotFound(t *testing.T) {
	registry := tenantTestRegistry(t)
	s := &Server{logger: tenantTestLogger(), barrierRegistry: registry}

	identity := &auth.Identity{Subject: "tenant-user", TenantID: "nonexistent-tenant", Roles: []string{"user"}}
	ctx := auth.WithIdentity(context.Background(), identity)

	_, err := s.tenantAccess(ctx, "xkms.listKeys")
	require.Error(t, err)

	var keyOpErr *KeyOpError
	require.ErrorAs(t, err, &keyOpErr)
	assert.Equal(t, ErrCodeForbidden, keyOpErr.Code)
}

func TestServerTenantAccess_TenantSealed(t *testing.T) {
	registry := tenantTestRegistry(t)
	_, err := registry.RegisterTenant("sealed-tenant")
	require.NoError(t, err)

	s := &Server{logger: tenantTestLogger(), barrierRegistry: registry}

	identity := &auth.Identity{Subject: "tenant-user", TenantID: "sealed-tenant", Roles: []string{"operator"}}
	ctx := auth.WithIdentity(context.Background(), identity)

	_, err = s.tenantAccess(ctx, "xkms.listKeys")
	require.Error(t, err)

	var keyOpErr *KeyOpError
	require.ErrorAs(t, err, &keyOpErr)
	assert.Equal(t, ErrCodeServiceUnavailable, keyOpErr.Code)
}

func TestServerTenantAccess_Success(t *testing.T) {
	registry := tenantTestRegistry(t)
	tenantTestRegisteredTenant(t, registry, "active-tenant")

	s := &Server{logger: tenantTestLogger(), barrierRegistry: registry}

	identity := &auth.Identity{Subject: "tenant-user", TenantID: "active-tenant", Roles: []string{"operator"}}
	ctx := auth.WithIdentity(context.Background(), identity)

	ctx, err := s.tenantAccess(ctx, "xkms.listKeys")
	require.NoError(t, err)

	tb, ok := auth.GetTenantBarrier(ctx).(*seal.TenantBarrier)
	require.True(t, ok, "expected *seal.TenantBarrier")
	assert.Equal(t, "active-tenant", tb.TenantID())
}

// TestHandleRequest_TenantGate proves the tenant gate is wired into
// handleRequest's dispatch path (not just unit-tested in isolation): a
// tenant-scoped caller whose tenant is unregistered is denied before
// dispatch, mirroring the REST/gRPC/QUIC 403.
func TestHandleRequest_TenantGate(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	server.barrierRegistry = tenantTestRegistry(t)

	identity := &auth.Identity{Subject: "tenant-user", TenantID: "nonexistent-tenant"}
	ctx := auth.WithIdentity(context.Background(), identity)

	req := &JSONRPCRequest{JSONRPC: "2.0", Method: "health", ID: 1}
	resp := server.handleRequest(ctx, req, nil)

	require.NotNil(t, resp)
	require.NotNil(t, resp.Error)
	assert.Equal(t, ErrCodeForbidden, resp.Error.Code)
}

// TestHandleRequest_TenantGateSystemTenantPasses proves a "system"-tenant
// caller reaches dispatch instead of being denied by the tenant gate.
func TestHandleRequest_TenantGateSystemTenantPasses(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	server.barrierRegistry = tenantTestRegistry(t)

	identity := &auth.Identity{Subject: "webauthn-user", TenantID: "system"}
	ctx := auth.WithIdentity(context.Background(), identity)

	req := &JSONRPCRequest{JSONRPC: "2.0", Method: "health", ID: 1}
	resp := server.handleRequest(ctx, req, nil)

	require.NotNil(t, resp)
	assert.Nil(t, resp.Error)
}
