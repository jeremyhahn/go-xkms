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

package grpc

import (
	"context"

	"github.com/jeremyhahn/go-keychain/pkg/correlation"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// correlationUnaryInterceptor extracts or generates correlation IDs for unary RPC calls.
// It checks for correlation IDs in the following order:
// 1. x-correlation-id metadata key
// 2. x-request-id metadata key
// 3. Generates a new UUID if neither is present
//
// The correlation ID is:
// - Added to the request context for use in handlers
// - Included in the response metadata for client tracking
// - Available for logging and distributed tracing
func (s *Server) correlationUnaryInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	// Extract metadata from context
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		md = metadata.MD{}
	}

	// Try to get correlation ID from metadata
	var correlationID string
	if values := md.Get(correlation.GRPCCorrelationIDKey); len(values) > 0 {
		correlationID = values[0]
	} else if values := md.Get(correlation.GRPCRequestIDKey); len(values) > 0 {
		correlationID = values[0]
	} else {
		// Generate a new correlation ID if none provided
		correlationID = correlation.NewID()
	}

	// Add correlation ID to context
	ctx = correlation.WithCorrelationID(ctx, correlationID)

	// Add correlation ID to outgoing metadata for response
	outMD := metadata.Pairs(correlation.GRPCCorrelationIDKey, correlationID)
	if err := grpc.SetHeader(ctx, outMD); err != nil {
		s.logger.Warn("Failed to set correlation ID in response metadata")
	}

	return handler(ctx, req)
}

// correlationStreamInterceptor extracts or generates correlation IDs for streaming RPC calls.
// It checks for correlation IDs in the following order:
// 1. x-correlation-id metadata key
// 2. x-request-id metadata key
// 3. Generates a new UUID if neither is present
//
// The correlation ID is:
// - Added to the stream context for use in handlers
// - Included in the response metadata for client tracking
// - Available for logging and distributed tracing
func (s *Server) correlationStreamInterceptor(
	srv interface{},
	ss grpc.ServerStream,
	info *grpc.StreamServerInfo,
	handler grpc.StreamHandler,
) error {
	ctx := ss.Context()

	// Extract metadata from context
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		md = metadata.MD{}
	}

	// Try to get correlation ID from metadata
	var correlationID string
	if values := md.Get(correlation.GRPCCorrelationIDKey); len(values) > 0 {
		correlationID = values[0]
	} else if values := md.Get(correlation.GRPCRequestIDKey); len(values) > 0 {
		correlationID = values[0]
	} else {
		// Generate a new correlation ID if none provided
		correlationID = correlation.NewID()
	}

	// Add correlation ID to context
	ctx = correlation.WithCorrelationID(ctx, correlationID)

	// Add correlation ID to outgoing metadata for response
	outMD := metadata.Pairs(correlation.GRPCCorrelationIDKey, correlationID)
	if err := ss.SetHeader(outMD); err != nil {
		s.logger.Warn("Failed to set correlation ID in stream response metadata")
	}

	// Wrap the stream with the new context
	wrappedStream := &correlatedServerStream{
		ServerStream: ss,
		ctx:          ctx,
	}

	return handler(srv, wrappedStream)
}

// correlatedServerStream wraps ServerStream with a correlation-enabled context
type correlatedServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *correlatedServerStream) Context() context.Context {
	return s.ctx
}
