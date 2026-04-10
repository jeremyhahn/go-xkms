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

package grpc

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// testTenantRegistry creates an initialized and unsealed BarrierRegistry
// backed by in-memory storage for use in interceptor tests.
func testTenantRegistry(t *testing.T) *seal.BarrierRegistry {
	t.Helper()
	base := storage.NewMemory()
	barrier, err := seal.NewBarrier(
		discardLogger(),
		base,
		seal.BarrierConfig{
			RootKeyPath:     "core/seal",
			PreferenceOrder: []seal.StrategyID{seal.StrategySoftware},
		},
		seal.NewSoftwareStrategy(),
	)
	require.NoError(t, err)

	ctx := context.Background()
	creds := seal.Credentials{Secret: "test-password"}
	err = barrier.Initialize(ctx, creds)
	require.NoError(t, err)

	registry, err := seal.NewBarrierRegistry(barrier)
	require.NoError(t, err)
	return registry
}

// testTenantRegisteredTenant registers and initializes a tenant in the given
// registry, returning the unsealed TenantBarrier. Each tenant barrier has its
// own independent barrier that must be initialized separately from the system
// barrier.
func testTenantRegisteredTenant(t *testing.T, registry *seal.BarrierRegistry, tenantID string) *seal.TenantBarrier {
	t.Helper()
	tb, err := registry.RegisterTenant(tenantID)
	require.NoError(t, err)

	ctx := context.Background()
	creds := seal.Credentials{Secret: "tenant-password"}
	err = registry.InitializeTenant(ctx, tenantID, creds)
	require.NoError(t, err)
	require.False(t, tb.IsSealed(), "tenant barrier should be unsealed after initialization")

	return tb
}

// passthroughUnaryHandler is a handler that returns the request as-is.
func passthroughUnaryHandler(ctx context.Context, req interface{}) (interface{}, error) {
	return "ok", nil
}

// contextCaptureUnaryHandler captures the context for inspection.
func contextCaptureUnaryHandler(captured *context.Context) grpc.UnaryHandler {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		*captured = ctx
		return "ok", nil
	}
}

func TestTenantUnaryInterceptor_NoIdentity(t *testing.T) {
	t.Run("passes through when no identity in context", func(t *testing.T) {
		registry := testTenantRegistry(t)
		// Save and restore package-level barrier registry.
		old := GetBarrierRegistry()
		SetBarrierRegistry(registry)
		defer SetBarrierRegistry(old)

		srv := &Server{logger: discardLogger()}
		info := &grpc.UnaryServerInfo{FullMethod: "/test/Method"}

		resp, err := srv.tenantUnaryInterceptor(
			context.Background(), "req", info, passthroughUnaryHandler,
		)
		require.NoError(t, err)
		assert.Equal(t, "ok", resp)
	})
}

func TestTenantUnaryInterceptor_EmptyTenantID(t *testing.T) {
	t.Run("passes through when identity has empty tenant ID", func(t *testing.T) {
		registry := testTenantRegistry(t)
		old := GetBarrierRegistry()
		SetBarrierRegistry(registry)
		defer SetBarrierRegistry(old)

		srv := &Server{logger: discardLogger()}
		info := &grpc.UnaryServerInfo{FullMethod: "/test/Method"}

		identity := &auth.Identity{Subject: "admin", TenantID: ""}
		ctx := auth.WithIdentity(context.Background(), identity)

		resp, err := srv.tenantUnaryInterceptor(ctx, "req", info, passthroughUnaryHandler)
		require.NoError(t, err)
		assert.Equal(t, "ok", resp)
	})
}

func TestTenantUnaryInterceptor_SORolePassesThrough(t *testing.T) {
	t.Run("SO role gets cross-tenant access", func(t *testing.T) {
		registry := testTenantRegistry(t)
		old := GetBarrierRegistry()
		SetBarrierRegistry(registry)
		defer SetBarrierRegistry(old)

		srv := &Server{logger: discardLogger()}
		info := &grpc.UnaryServerInfo{FullMethod: "/test/Method"}

		identity := &auth.Identity{Subject: "so-admin", TenantID: "any-tenant", Claims: map[string]interface{}{"roles": []string{"so"}}}
		ctx := auth.WithIdentity(context.Background(), identity)

		resp, err := srv.tenantUnaryInterceptor(ctx, "req", info, passthroughUnaryHandler)
		require.NoError(t, err)
		assert.Equal(t, "ok", resp)
	})
}

func TestTenantUnaryInterceptor_NoRegistry(t *testing.T) {
	t.Run("passes through when no barrier registry configured", func(t *testing.T) {
		old := GetBarrierRegistry()
		SetBarrierRegistry(nil)
		defer SetBarrierRegistry(old)

		srv := &Server{logger: discardLogger()}
		info := &grpc.UnaryServerInfo{FullMethod: "/test/Method"}

		identity := &auth.Identity{Subject: "user", TenantID: "tenant-a"}
		ctx := auth.WithIdentity(context.Background(), identity)

		resp, err := srv.tenantUnaryInterceptor(ctx, "req", info, passthroughUnaryHandler)
		require.NoError(t, err)
		assert.Equal(t, "ok", resp)
	})
}

func TestTenantUnaryInterceptor_TenantNotFound(t *testing.T) {
	t.Run("returns PermissionDenied when tenant not found", func(t *testing.T) {
		registry := testTenantRegistry(t)
		old := GetBarrierRegistry()
		SetBarrierRegistry(registry)
		defer SetBarrierRegistry(old)

		srv := &Server{logger: discardLogger()}
		info := &grpc.UnaryServerInfo{FullMethod: "/test/Method"}

		identity := &auth.Identity{Subject: "user", TenantID: "nonexistent"}
		ctx := auth.WithIdentity(context.Background(), identity)

		resp, err := srv.tenantUnaryInterceptor(ctx, "req", info, passthroughUnaryHandler)
		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.PermissionDenied, st.Code())
	})
}

func TestTenantUnaryInterceptor_TenantSealed(t *testing.T) {
	t.Run("returns Unavailable when tenant barrier is sealed", func(t *testing.T) {
		registry := testTenantRegistry(t)
		old := GetBarrierRegistry()
		SetBarrierRegistry(registry)
		defer SetBarrierRegistry(old)

		// Register and initialize tenant, then seal it.
		tb := testTenantRegisteredTenant(t, registry, "sealed-tenant")
		err := tb.Seal()
		require.NoError(t, err)

		srv := &Server{logger: discardLogger()}
		info := &grpc.UnaryServerInfo{FullMethod: "/test/Method"}

		identity := &auth.Identity{Subject: "user", TenantID: "sealed-tenant"}
		ctx := auth.WithIdentity(context.Background(), identity)

		resp, err := srv.tenantUnaryInterceptor(ctx, "req", info, passthroughUnaryHandler)
		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Unavailable, st.Code())
	})
}

func TestTenantUnaryInterceptor_Success(t *testing.T) {
	t.Run("injects tenant barrier into context", func(t *testing.T) {
		registry := testTenantRegistry(t)
		old := GetBarrierRegistry()
		SetBarrierRegistry(registry)
		defer SetBarrierRegistry(old)

		testTenantRegisteredTenant(t, registry, "active-tenant")

		srv := &Server{logger: discardLogger()}
		info := &grpc.UnaryServerInfo{FullMethod: "/test/Method"}

		identity := &auth.Identity{Subject: "user", TenantID: "active-tenant"}
		ctx := auth.WithIdentity(context.Background(), identity)

		var captured context.Context
		resp, err := srv.tenantUnaryInterceptor(
			ctx, "req", info, contextCaptureUnaryHandler(&captured),
		)
		require.NoError(t, err)
		assert.Equal(t, "ok", resp)

		// Verify tenant barrier was injected into context.
		tb := auth.GetTenantBarrier(captured)
		assert.NotNil(t, tb)
	})
}
