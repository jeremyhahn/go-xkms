// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package metrics

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
)

const (
	// Protocol identifiers
	ProtocolHTTP = "http"
	ProtocolGRPC = "grpc"
	ProtocolQUIC = "quic"
	ProtocolMCP  = "mcp"
)

// HTTPMiddleware returns an HTTP middleware that records request metrics.
// It tracks request duration, total requests, and active connections.
//
// Usage:
//
//	router := chi.NewRouter()
//	router.Use(metrics.HTTPMiddleware)
func HTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !IsEnabled() {
			next.ServeHTTP(w, r)
			return
		}

		start := time.Now()

		// Increment active connections
		IncrementActiveConnections(ProtocolHTTP)
		defer DecrementActiveConnections(ProtocolHTTP)

		// Create a response writer wrapper to capture status code
		wrapper := &responseWriter{
			ResponseWriter: w,
			statusCode:     http.StatusOK, // Default to 200
		}

		// Call the next handler
		next.ServeHTTP(wrapper, r)

		// Record metrics
		duration := time.Since(start).Seconds()
		statusCode := strconv.Itoa(wrapper.statusCode)
		RecordHTTPRequest(r.Method, statusCode, duration)
	})
}

// responseWriter is a wrapper around http.ResponseWriter that captures the status code.
type responseWriter struct {
	http.ResponseWriter
	statusCode int
	written    bool
}

// WriteHeader captures the status code and delegates to the underlying ResponseWriter.
func (rw *responseWriter) WriteHeader(statusCode int) {
	if !rw.written {
		rw.statusCode = statusCode
		rw.written = true
	}
	rw.ResponseWriter.WriteHeader(statusCode)
}

// Write ensures WriteHeader is called if not already done.
func (rw *responseWriter) Write(b []byte) (int, error) {
	if !rw.written {
		rw.WriteHeader(http.StatusOK)
	}
	return rw.ResponseWriter.Write(b)
}

// GRPCUnaryServerInterceptor returns a gRPC unary server interceptor that records request metrics.
// It tracks request duration, total requests, and active connections.
//
// Usage:
//
//	server := grpc.NewServer(
//	    grpc.UnaryInterceptor(metrics.GRPCUnaryServerInterceptor()),
//	)
func GRPCUnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		if !IsEnabled() {
			return handler(ctx, req)
		}

		start := time.Now()

		// Increment active connections
		IncrementActiveConnections(ProtocolGRPC)
		defer DecrementActiveConnections(ProtocolGRPC)

		// Call the handler
		resp, err := handler(ctx, req)

		// Record metrics
		duration := time.Since(start).Seconds()
		statusCode := status.Code(err).String()
		RecordGRPCRequest(info.FullMethod, statusCode, duration)

		return resp, err
	}
}

// GRPCStreamServerInterceptor returns a gRPC stream server interceptor that records connection metrics.
// For streaming RPCs, it only tracks active connections without duration metrics.
//
// Usage:
//
//	server := grpc.NewServer(
//	    grpc.StreamInterceptor(metrics.GRPCStreamServerInterceptor()),
//	)
func GRPCStreamServerInterceptor() grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		if !IsEnabled() {
			return handler(srv, ss)
		}

		start := time.Now()

		// Increment active connections
		IncrementActiveConnections(ProtocolGRPC)
		defer DecrementActiveConnections(ProtocolGRPC)

		// Call the handler
		err := handler(srv, ss)

		// Record metrics
		duration := time.Since(start).Seconds()
		statusCode := status.Code(err).String()
		RecordGRPCRequest(info.FullMethod, statusCode, duration)

		return err
	}
}

// ConnectionTracker provides a simple way to track protocol connections.
// It should be used for protocols that don't have built-in middleware support (QUIC, MCP).
type ConnectionTracker struct {
	protocol string
	started  time.Time
}

// NewConnectionTracker creates a new connection tracker for the specified protocol.
// It automatically increments the active connections counter.
//
// Usage:
//
//	tracker := metrics.NewConnectionTracker(metrics.ProtocolQUIC)
//	defer tracker.Close()
func NewConnectionTracker(protocol string) *ConnectionTracker {
	if IsEnabled() {
		IncrementActiveConnections(protocol)
	}
	return &ConnectionTracker{
		protocol: protocol,
		started:  time.Now(),
	}
}

// Close decrements the active connections counter for this protocol.
// It should be called when the connection is closed, typically via defer.
func (ct *ConnectionTracker) Close() {
	if IsEnabled() {
		DecrementActiveConnections(ct.protocol)
	}
}

// Duration returns the time elapsed since the connection was established.
func (ct *ConnectionTracker) Duration() time.Duration {
	return time.Since(ct.started)
}
