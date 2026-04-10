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
	"log/slog"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// tenantUnaryInterceptor enforces tenant isolation for unary gRPC calls.
// It extracts tenant context from the authenticated identity, validates
// cross-tenant access, and injects the TenantBarrier into the request
// context for downstream handlers.
//
// Behavior:
//   - No identity or empty TenantID: passes through (system-level or bootstrap access)
//   - SO role: passes through with cross-tenant access
//   - No barrier registry configured: passes through
//   - Tenant not found in registry: returns PermissionDenied
//   - Tenant barrier is sealed: returns Unavailable
//   - Otherwise: injects TenantBarrier into context and continues
func (s *Server) tenantUnaryInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	identity := auth.GetIdentity(ctx)

	// System-level or unauthenticated requests pass through.
	if identity == nil || identity.TenantID == "" {
		return handler(ctx, req)
	}

	// Security Officer role gets cross-tenant access.
	if identity.HasRole("so") {
		return handler(ctx, req)
	}

	// No barrier registry configured; tenant enforcement disabled.
	registry := GetBarrierRegistry()
	if registry == nil {
		return handler(ctx, req)
	}

	// Look up the tenant barrier from the registry.
	tb, err := registry.Tenant(identity.TenantID)
	if err != nil {
		s.logger.Warn("tenant barrier not found",
			slog.String("method", info.FullMethod),
			slog.String("tenant_id", identity.TenantID),
			slog.String("error", err.Error()))
		return nil, status.Error(codes.PermissionDenied, "tenant not found")
	}

	// Reject requests when the tenant barrier is sealed.
	if tb.IsSealed() {
		s.logger.Warn("tenant barrier is sealed",
			slog.String("method", info.FullMethod),
			slog.String("tenant_id", identity.TenantID))
		return nil, status.Error(codes.Unavailable, "tenant barrier is sealed")
	}

	// Inject tenant barrier into context for downstream handlers.
	ctx = auth.WithTenantBarrier(ctx, tb)
	return handler(ctx, req)
}

// tenantStreamInterceptor enforces tenant isolation for streaming gRPC calls.
// It follows the same tenant enforcement logic as the unary interceptor.
func (s *Server) tenantStreamInterceptor(
	srv interface{},
	ss grpc.ServerStream,
	info *grpc.StreamServerInfo,
	handler grpc.StreamHandler,
) error {
	ctx := ss.Context()
	identity := auth.GetIdentity(ctx)

	// System-level or unauthenticated requests pass through.
	if identity == nil || identity.TenantID == "" {
		return handler(srv, ss)
	}

	// Security Officer role gets cross-tenant access.
	if identity.HasRole("so") {
		return handler(srv, ss)
	}

	// No barrier registry configured; tenant enforcement disabled.
	registry := GetBarrierRegistry()
	if registry == nil {
		return handler(srv, ss)
	}

	// Look up the tenant barrier from the registry.
	tb, err := registry.Tenant(identity.TenantID)
	if err != nil {
		s.logger.Warn("tenant barrier not found",
			slog.String("method", info.FullMethod),
			slog.String("tenant_id", identity.TenantID),
			slog.String("error", err.Error()))
		return status.Error(codes.PermissionDenied, "tenant not found")
	}

	// Reject requests when the tenant barrier is sealed.
	if tb.IsSealed() {
		s.logger.Warn("tenant barrier is sealed",
			slog.String("method", info.FullMethod),
			slog.String("tenant_id", identity.TenantID))
		return status.Error(codes.Unavailable, "tenant barrier is sealed")
	}

	// Inject tenant barrier into context and wrap the stream.
	ctx = auth.WithTenantBarrier(ctx, tb)
	wrappedStream := &tenantServerStream{
		ServerStream: ss,
		ctx:          ctx,
	}

	return handler(srv, wrappedStream)
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
