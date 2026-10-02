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

package correlation

import (
	"context"
	"log/slog"
	"net/http"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// Middleware returns HTTP middleware that gives every request a correlation
// ID. The ID is taken from the X-Correlation-ID header, then X-Request-ID,
// and generated when neither is present. It is stored in the request context
// (GetCorrelationID reads it) and echoed in the X-Correlation-ID response
// header so a client can quote it.
func Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := firstNonEmpty(r.Header.Get(CorrelationIDHeader), r.Header.Get(RequestIDHeader))
			w.Header().Set(CorrelationIDHeader, id)
			next.ServeHTTP(w, r.WithContext(WithCorrelationID(r.Context(), id)))
		})
	}
}

// UnaryServerInterceptor returns a gRPC unary interceptor that gives every
// call a correlation ID, read from the x-correlation-id metadata key, then
// x-request-id, and generated when neither is present. The ID is stored in
// the handler's context and sent back in the x-correlation-id response
// header. A failure to send that header is logged to logger (slog.Default
// when nil) and does not fail the call: the ID is already established for
// the server's own logs.
func UnaryServerInterceptor(logger *slog.Logger) grpc.UnaryServerInterceptor {
	logger = loggerOrDefault(logger)
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		id := idFromMetadata(ctx)
		ctx = WithCorrelationID(ctx, id)
		if err := grpc.SetHeader(ctx, metadata.Pairs(GRPCCorrelationIDKey, id)); err != nil {
			logger.Warn("correlation: failed to set the correlation ID response header", "error", err)
		}
		return handler(ctx, req)
	}
}

// StreamServerInterceptor is UnaryServerInterceptor for streaming calls: the
// stream's context carries the correlation ID for the handler's lifetime.
func StreamServerInterceptor(logger *slog.Logger) grpc.StreamServerInterceptor {
	logger = loggerOrDefault(logger)
	return func(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		id := idFromMetadata(ss.Context())
		if err := ss.SetHeader(metadata.Pairs(GRPCCorrelationIDKey, id)); err != nil {
			logger.Warn("correlation: failed to set the correlation ID stream response header", "error", err)
		}
		return handler(srv, &serverStream{ServerStream: ss, ctx: WithCorrelationID(ss.Context(), id)})
	}
}

// idFromMetadata returns the correlation ID the incoming gRPC metadata
// carries, or a new one.
func idFromMetadata(ctx context.Context) string {
	md, _ := metadata.FromIncomingContext(ctx)
	return firstNonEmpty(first(md.Get(GRPCCorrelationIDKey)), first(md.Get(GRPCRequestIDKey)))
}

// first returns the first value, or "".
func first(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

// firstNonEmpty returns the first non-empty candidate, or a new ID.
func firstNonEmpty(candidates ...string) string {
	for _, c := range candidates {
		if c != "" {
			return c
		}
	}
	return NewID()
}

// loggerOrDefault returns logger, or slog.Default when it is nil.
func loggerOrDefault(logger *slog.Logger) *slog.Logger {
	if logger == nil {
		return slog.Default()
	}
	return logger
}

// serverStream carries a correlated context for a stream's handler.
type serverStream struct {
	grpc.ServerStream
	ctx context.Context
}

// Context returns the correlated context.
func (s *serverStream) Context() context.Context { return s.ctx }
