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
	"errors"
	"log/slog"

	"github.com/jeremyhahn/go-xkms/pkg/api/tenantgate"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// tenantAccessStatus resolves the tenant gate for the identity on ctx against
// registry and maps the tenantgate error, if any, onto the gRPC status this
// transport has always returned: PermissionDenied for an unregistered
// tenant, Unavailable for a sealed one. It is the shared core behind both
// TenantUnaryInterceptor and TenantStreamInterceptor.
func tenantAccessStatus(ctx context.Context, method string, registry *seal.BarrierRegistry, logger *slog.Logger) (context.Context, error) {
	identity := auth.GetIdentity(ctx)

	tb, err := tenantgate.Access(identity, registry)
	if err != nil {
		var notFound *tenantgate.ErrTenantNotFound
		var sealed *tenantgate.ErrTenantSealed
		switch {
		case errors.As(err, &notFound):
			logger.Warn("tenant barrier not found",
				slog.String("method", method),
				slog.String("tenant_id", notFound.TenantID),
				slog.String("error", notFound.Err.Error()))
			return ctx, status.Error(codes.PermissionDenied, "tenant not found")
		case errors.As(err, &sealed):
			logger.Warn("tenant barrier is sealed",
				slog.String("method", method),
				slog.String("tenant_id", sealed.TenantID))
			return ctx, status.Error(codes.Unavailable, "tenant barrier is sealed")
		default:
			logger.Error("tenant access check failed",
				slog.String("method", method),
				slog.String("error", err.Error()))
			return ctx, status.Error(codes.Internal, "tenant access check failed")
		}
	}

	if tb != nil {
		ctx = auth.WithTenantBarrier(ctx, tb)
	}

	return ctx, nil
}

// TenantUnaryInterceptor builds a unary interceptor that enforces tenant
// isolation against registry. It extracts the identity the authentication
// interceptor placed on the context, validates cross-tenant access via
// tenantgate.Access, and injects the resolved TenantBarrier into the context
// for downstream handlers.
//
// Behavior:
//   - Cross-tenant-scoped identity (nil, empty TenantID, or the reserved
//     system tenant): passes through (system-level or bootstrap access)
//   - SO role: passes through with cross-tenant access
//   - No barrier registry configured: passes through
//   - Tenant not found in registry: returns PermissionDenied
//   - Tenant barrier is sealed: returns Unavailable
//   - Otherwise: injects TenantBarrier into context and continues
//
// Both the network gRPC server (registry resolved per call from
// GetBarrierRegistry, so tests may swap it with SetBarrierRegistry) and the
// Unix domain socket gRPC server (registry fixed at construction time --
// see pkg/api/unix/grpc_server.go) chain this interceptor, so tenant scoping
// behaves identically on every gRPC-shaped listener.
func TenantUnaryInterceptor(registry *seal.BarrierRegistry, logger *slog.Logger) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		ctx, err := tenantAccessStatus(ctx, info.FullMethod, registry, logger)
		if err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

// TenantStreamInterceptor is the streaming counterpart of
// TenantUnaryInterceptor. See its doc for the shared behavior.
func TenantStreamInterceptor(registry *seal.BarrierRegistry, logger *slog.Logger) grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		ctx, err := tenantAccessStatus(ss.Context(), info.FullMethod, registry, logger)
		if err != nil {
			return err
		}
		wrappedStream := &tenantServerStream{
			ServerStream: ss,
			ctx:          ctx,
		}
		return handler(srv, wrappedStream)
	}
}

// tenantUnaryInterceptor enforces tenant isolation for unary gRPC calls on
// the network gRPC server. It resolves the registry from GetBarrierRegistry
// on every call (rather than capturing it once), which is what lets
// SetBarrierRegistry reconfigure tenant enforcement -- and tests swap the
// registry -- after the server is already running.
func (s *Server) tenantUnaryInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	return TenantUnaryInterceptor(GetBarrierRegistry(), s.logger)(ctx, req, info, handler)
}

// tenantStreamInterceptor enforces tenant isolation for streaming gRPC calls
// on the network gRPC server. See tenantUnaryInterceptor for why the registry
// is resolved per call.
func (s *Server) tenantStreamInterceptor(
	srv interface{},
	ss grpc.ServerStream,
	info *grpc.StreamServerInfo,
	handler grpc.StreamHandler,
) error {
	return TenantStreamInterceptor(GetBarrierRegistry(), s.logger)(srv, ss, info, handler)
}

// tenantServerStream wraps ServerStream with a tenant-scoped context.
type tenantServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

// Context returns the tenant-scoped context.
func (s *tenantServerStream) Context() context.Context {
	return s.ctx
}
