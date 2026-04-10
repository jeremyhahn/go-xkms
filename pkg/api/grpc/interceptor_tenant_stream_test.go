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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	grpcmetadata "google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// fakeServerStream implements grpc.ServerStream for testing the stream interceptor.
type fakeServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (f *fakeServerStream) Context() context.Context {
	return f.ctx
}

func (f *fakeServerStream) SendMsg(interface{}) error  { return nil }
func (f *fakeServerStream) RecvMsg(interface{}) error   { return nil }
func (f *fakeServerStream) SetHeader(grpcmetadata.MD) error { return nil }
func (f *fakeServerStream) SendHeader(grpcmetadata.MD) error { return nil }
func (f *fakeServerStream) SetTrailer(grpcmetadata.MD)      {}

// passthroughStreamHandler is a stream handler that returns nil.
func passthroughStreamHandler(_ interface{}, _ grpc.ServerStream) error {
	return nil
}

// contextCaptureStreamHandler captures the context from the stream.
func contextCaptureStreamHandler(captured *context.Context) grpc.StreamHandler {
	return func(_ interface{}, ss grpc.ServerStream) error {
		*captured = ss.Context()
		return nil
	}
}

func TestTenantStreamInterceptor_NoIdentity(t *testing.T) {
	t.Run("passes through when no identity in context", func(t *testing.T) {
		registry := testTenantRegistry(t)
		old := GetBarrierRegistry()
		SetBarrierRegistry(registry)
		defer SetBarrierRegistry(old)

		srv := &Server{logger: discardLogger()}
		info := &grpc.StreamServerInfo{FullMethod: "/test/Stream"}
		stream := &fakeServerStream{ctx: context.Background()}

		err := srv.tenantStreamInterceptor("srv", stream, info, passthroughStreamHandler)
		require.NoError(t, err)
	})
}

func TestTenantStreamInterceptor_EmptyTenantID(t *testing.T) {
	t.Run("passes through when identity has empty tenant ID", func(t *testing.T) {
		registry := testTenantRegistry(t)
		old := GetBarrierRegistry()
		SetBarrierRegistry(registry)
		defer SetBarrierRegistry(old)

		srv := &Server{logger: discardLogger()}
		info := &grpc.StreamServerInfo{FullMethod: "/test/Stream"}

		identity := &auth.Identity{Subject: "admin", TenantID: ""}
		ctx := auth.WithIdentity(context.Background(), identity)
		stream := &fakeServerStream{ctx: ctx}

		err := srv.tenantStreamInterceptor("srv", stream, info, passthroughStreamHandler)
		require.NoError(t, err)
	})
}

func TestTenantStreamInterceptor_SORolePassesThrough(t *testing.T) {
	t.Run("SO role gets cross-tenant access", func(t *testing.T) {
		registry := testTenantRegistry(t)
		old := GetBarrierRegistry()
		SetBarrierRegistry(registry)
		defer SetBarrierRegistry(old)

		srv := &Server{logger: discardLogger()}
		info := &grpc.StreamServerInfo{FullMethod: "/test/Stream"}

		identity := &auth.Identity{
			Subject:  "so-admin",
			TenantID: "any-tenant",
			Claims:   map[string]interface{}{"roles": []string{"so"}},
		}
		ctx := auth.WithIdentity(context.Background(), identity)
		stream := &fakeServerStream{ctx: ctx}

		err := srv.tenantStreamInterceptor("srv", stream, info, passthroughStreamHandler)
		require.NoError(t, err)
	})
}

func TestTenantStreamInterceptor_NoRegistry(t *testing.T) {
	t.Run("passes through when no barrier registry configured", func(t *testing.T) {
		old := GetBarrierRegistry()
		SetBarrierRegistry(nil)
		defer SetBarrierRegistry(old)

		srv := &Server{logger: discardLogger()}
		info := &grpc.StreamServerInfo{FullMethod: "/test/Stream"}

		identity := &auth.Identity{Subject: "user", TenantID: "tenant-a"}
		ctx := auth.WithIdentity(context.Background(), identity)
		stream := &fakeServerStream{ctx: ctx}

		err := srv.tenantStreamInterceptor("srv", stream, info, passthroughStreamHandler)
		require.NoError(t, err)
	})
}

func TestTenantStreamInterceptor_TenantNotFound(t *testing.T) {
	t.Run("returns PermissionDenied when tenant not found", func(t *testing.T) {
		registry := testTenantRegistry(t)
		old := GetBarrierRegistry()
		SetBarrierRegistry(registry)
		defer SetBarrierRegistry(old)

		srv := &Server{logger: discardLogger()}
		info := &grpc.StreamServerInfo{FullMethod: "/test/Stream"}

		identity := &auth.Identity{Subject: "user", TenantID: "nonexistent"}
		ctx := auth.WithIdentity(context.Background(), identity)
		stream := &fakeServerStream{ctx: ctx}

		err := srv.tenantStreamInterceptor("srv", stream, info, passthroughStreamHandler)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.PermissionDenied, st.Code())
	})
}

func TestTenantStreamInterceptor_TenantSealed(t *testing.T) {
	t.Run("returns Unavailable when tenant barrier is sealed", func(t *testing.T) {
		registry := testTenantRegistry(t)
		old := GetBarrierRegistry()
		SetBarrierRegistry(registry)
		defer SetBarrierRegistry(old)

		tb := testTenantRegisteredTenant(t, registry, "sealed-stream-tenant")
		err := tb.Seal()
		require.NoError(t, err)

		srv := &Server{logger: discardLogger()}
		info := &grpc.StreamServerInfo{FullMethod: "/test/Stream"}

		identity := &auth.Identity{Subject: "user", TenantID: "sealed-stream-tenant"}
		ctx := auth.WithIdentity(context.Background(), identity)
		stream := &fakeServerStream{ctx: ctx}

		err = srv.tenantStreamInterceptor("srv", stream, info, passthroughStreamHandler)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Unavailable, st.Code())
	})
}

func TestTenantStreamInterceptor_Success(t *testing.T) {
	t.Run("injects tenant barrier into stream context", func(t *testing.T) {
		registry := testTenantRegistry(t)
		old := GetBarrierRegistry()
		SetBarrierRegistry(registry)
		defer SetBarrierRegistry(old)

		testTenantRegisteredTenant(t, registry, "stream-tenant")

		srv := &Server{logger: discardLogger()}
		info := &grpc.StreamServerInfo{FullMethod: "/test/Stream"}

		identity := &auth.Identity{Subject: "user", TenantID: "stream-tenant"}
		ctx := auth.WithIdentity(context.Background(), identity)
		stream := &fakeServerStream{ctx: ctx}

		var captured context.Context
		err := srv.tenantStreamInterceptor("srv", stream, info, contextCaptureStreamHandler(&captured))
		require.NoError(t, err)

		tb := auth.GetTenantBarrier(captured)
		assert.NotNil(t, tb)
	})
}

func TestTenantServerStream_Context(t *testing.T) {
	t.Run("returns wrapped context", func(t *testing.T) {
		parentCtx := context.WithValue(context.Background(), "test-key", "test-value") //nolint:staticcheck
		innerStream := &fakeServerStream{ctx: context.Background()}
		wrapped := &tenantServerStream{
			ServerStream: innerStream,
			ctx:          parentCtx,
		}

		assert.Equal(t, "test-value", wrapped.Context().Value("test-key"))
	})
}
