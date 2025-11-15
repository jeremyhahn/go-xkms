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

package correlation

import (
	"context"

	"github.com/google/uuid"
)

// contextKey is a custom type for context keys to avoid collisions
type contextKey string

const (
	// CorrelationIDKey is the context key for storing correlation IDs
	CorrelationIDKey contextKey = "correlation-id"

	// RequestIDHeader is the HTTP header for request IDs
	RequestIDHeader = "X-Request-ID"

	// CorrelationIDHeader is the HTTP header for correlation IDs
	CorrelationIDHeader = "X-Correlation-ID"

	// GRPCCorrelationIDKey is the gRPC metadata key for correlation IDs
	GRPCCorrelationIDKey = "x-correlation-id"

	// GRPCRequestIDKey is the gRPC metadata key for request IDs
	GRPCRequestIDKey = "x-request-id"
)

// WithCorrelationID adds a correlation ID to the context.
// This is used to track requests across multiple services and protocols.
func WithCorrelationID(ctx context.Context, id string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, CorrelationIDKey, id)
}

// GetCorrelationID retrieves the correlation ID from context.
// Returns an empty string if no correlation ID is found.
func GetCorrelationID(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if id, ok := ctx.Value(CorrelationIDKey).(string); ok {
		return id
	}
	return ""
}

// NewID generates a new UUID v4 correlation ID.
// This provides a globally unique identifier for distributed tracing.
func NewID() string {
	return uuid.New().String()
}

// GetOrGenerate retrieves an existing correlation ID from context
// or generates a new one if none exists.
// This is useful for middleware/interceptors that need to ensure
// a correlation ID is always present.
func GetOrGenerate(ctx context.Context) string {
	if id := GetCorrelationID(ctx); id != "" {
		return id
	}
	return NewID()
}
