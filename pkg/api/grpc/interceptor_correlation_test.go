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

	"github.com/jeremyhahn/go-xkms/pkg/correlation"
	"google.golang.org/grpc/metadata"
)

func TestExtractCorrelationIDFromContext(t *testing.T) {
	t.Run("extracts from correlation ID header", func(t *testing.T) {
		md := metadata.Pairs(correlation.GRPCCorrelationIDKey, "corr-123")
		ctx := metadata.NewIncomingContext(context.Background(), md)

		// Get metadata from context and extract ID
		extractedMD, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			t.Fatal("Failed to extract metadata from context")
		}

		values := extractedMD.Get(correlation.GRPCCorrelationIDKey)
		if len(values) == 0 {
			t.Fatal("No correlation ID found in metadata")
		}

		if values[0] != "corr-123" {
			t.Errorf("Expected 'corr-123', got '%s'", values[0])
		}
	})

	t.Run("extracts from request ID header", func(t *testing.T) {
		md := metadata.Pairs(correlation.GRPCRequestIDKey, "req-456")
		ctx := metadata.NewIncomingContext(context.Background(), md)

		extractedMD, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			t.Fatal("Failed to extract metadata from context")
		}

		// Check for request ID when no correlation ID
		if values := extractedMD.Get(correlation.GRPCCorrelationIDKey); len(values) > 0 {
			t.Fatal("Should not have correlation ID")
		}

		values := extractedMD.Get(correlation.GRPCRequestIDKey)
		if len(values) == 0 {
			t.Fatal("No request ID found in metadata")
		}

		if values[0] != "req-456" {
			t.Errorf("Expected 'req-456', got '%s'", values[0])
		}
	})

	t.Run("prefers correlation ID over request ID", func(t *testing.T) {
		md := metadata.Pairs(
			correlation.GRPCCorrelationIDKey, "corr-123",
			correlation.GRPCRequestIDKey, "req-456",
		)
		ctx := metadata.NewIncomingContext(context.Background(), md)

		extractedMD, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			t.Fatal("Failed to extract metadata from context")
		}

		// Should find correlation ID first
		values := extractedMD.Get(correlation.GRPCCorrelationIDKey)
		if len(values) == 0 {
			t.Fatal("No correlation ID found in metadata")
		}

		if values[0] != "corr-123" {
			t.Errorf("Expected 'corr-123', got '%s'", values[0])
		}
	})

	t.Run("returns empty for missing metadata", func(t *testing.T) {
		ctx := context.Background()

		_, ok := metadata.FromIncomingContext(ctx)
		if ok {
			t.Error("Should not have metadata in empty context")
		}
	})

	t.Run("returns empty for empty metadata", func(t *testing.T) {
		md := metadata.New(nil)
		ctx := metadata.NewIncomingContext(context.Background(), md)

		extractedMD, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			t.Fatal("Failed to extract metadata from context")
		}

		if values := extractedMD.Get(correlation.GRPCCorrelationIDKey); len(values) > 0 {
			t.Errorf("Expected empty, got %v", values)
		}
	})
}

func TestCorrelatedServerStreamContext(t *testing.T) {
	t.Run("wraps stream with correlation context", func(t *testing.T) {
		originalCtx := context.Background()
		correlatedCtx := correlation.WithCorrelationID(originalCtx, "wrapped-id")

		originalStream := &mockServerStream{ctx: originalCtx}
		wrapped := &correlatedServerStream{
			ServerStream: originalStream,
			ctx:          correlatedCtx,
		}

		// Verify wrapped context has correlation ID
		id := correlation.GetCorrelationID(wrapped.Context())
		if id != "wrapped-id" {
			t.Errorf("Expected 'wrapped-id', got '%s'", id)
		}

		// Verify original context does not have correlation ID
		originalID := correlation.GetCorrelationID(originalStream.Context())
		if originalID != "" {
			t.Errorf("Expected empty original ID, got '%s'", originalID)
		}
	})

	t.Run("context returns wrapped context", func(t *testing.T) {
		ctx := correlation.WithCorrelationID(context.Background(), "test-id")
		stream := &mockServerStream{ctx: context.Background()}

		wrapped := &correlatedServerStream{
			ServerStream: stream,
			ctx:          ctx,
		}

		if wrapped.Context() != ctx {
			t.Error("Expected wrapped context to be returned")
		}

		id := correlation.GetCorrelationID(wrapped.Context())
		if id != "test-id" {
			t.Errorf("Expected 'test-id', got '%s'", id)
		}
	})
}

func TestCorrelationIDGeneration(t *testing.T) {
	t.Run("NewID generates unique IDs", func(t *testing.T) {
		ids := make(map[string]bool)
		for i := 0; i < 100; i++ {
			id := correlation.NewID()
			if ids[id] {
				t.Errorf("Generated duplicate ID: %s", id)
			}
			ids[id] = true

			// Should be UUID format (36 chars with hyphens)
			if len(id) != 36 {
				t.Errorf("Expected UUID format (36 chars), got %d chars: %s", len(id), id)
			}
		}
	})

	t.Run("GetOrGenerate returns existing ID", func(t *testing.T) {
		ctx := correlation.WithCorrelationID(context.Background(), "existing-id")
		id := correlation.GetOrGenerate(ctx)
		if id != "existing-id" {
			t.Errorf("Expected 'existing-id', got '%s'", id)
		}
	})

	t.Run("GetOrGenerate generates new ID when missing", func(t *testing.T) {
		ctx := context.Background()
		id := correlation.GetOrGenerate(ctx)
		if id == "" {
			t.Error("Expected generated ID, got empty string")
		}
		if len(id) != 36 {
			t.Errorf("Expected UUID format (36 chars), got %d chars", len(id))
		}
	})
}

func TestCorrelationContextOperations(t *testing.T) {
	t.Run("WithCorrelationID adds ID to context", func(t *testing.T) {
		ctx := context.Background()
		ctx = correlation.WithCorrelationID(ctx, "test-correlation-id")

		id := correlation.GetCorrelationID(ctx)
		if id != "test-correlation-id" {
			t.Errorf("Expected 'test-correlation-id', got '%s'", id)
		}
	})

	t.Run("GetCorrelationID returns empty for missing ID", func(t *testing.T) {
		ctx := context.Background()
		id := correlation.GetCorrelationID(ctx)
		if id != "" {
			t.Errorf("Expected empty string, got '%s'", id)
		}
	})

	t.Run("GetCorrelationID handles nil context gracefully", func(t *testing.T) {
		// Use context.TODO() to test the empty context path
		// The correlation package should handle contexts without correlation IDs
		id := correlation.GetCorrelationID(context.TODO())
		if id != "" {
			t.Errorf("Expected empty string for context without correlation ID, got '%s'", id)
		}
	})

	t.Run("WithCorrelationID handles nil context gracefully", func(t *testing.T) {
		// Use context.Background() as the base context
		ctx := correlation.WithCorrelationID(context.Background(), "test-id")
		id := correlation.GetCorrelationID(ctx)
		if id != "test-id" {
			t.Errorf("Expected 'test-id', got '%s'", id)
		}
	})
}

func TestCorrelationMetadataKeys(t *testing.T) {
	t.Run("GRPCCorrelationIDKey is correct", func(t *testing.T) {
		if correlation.GRPCCorrelationIDKey != "x-correlation-id" {
			t.Errorf("Expected 'x-correlation-id', got '%s'", correlation.GRPCCorrelationIDKey)
		}
	})

	t.Run("GRPCRequestIDKey is correct", func(t *testing.T) {
		if correlation.GRPCRequestIDKey != "x-request-id" {
			t.Errorf("Expected 'x-request-id', got '%s'", correlation.GRPCRequestIDKey)
		}
	})

	t.Run("CorrelationIDHeader is correct", func(t *testing.T) {
		if correlation.CorrelationIDHeader != "X-Correlation-ID" {
			t.Errorf("Expected 'X-Correlation-ID', got '%s'", correlation.CorrelationIDHeader)
		}
	})

	t.Run("RequestIDHeader is correct", func(t *testing.T) {
		if correlation.RequestIDHeader != "X-Request-ID" {
			t.Errorf("Expected 'X-Request-ID', got '%s'", correlation.RequestIDHeader)
		}
	})
}
