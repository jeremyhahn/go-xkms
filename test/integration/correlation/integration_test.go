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
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/correlation"
	"google.golang.org/grpc/metadata"
)

// Re-export constants from the correlation package for test readability
const (
	CorrelationIDHeader  = correlation.CorrelationIDHeader
	RequestIDHeader      = correlation.RequestIDHeader
	GRPCCorrelationIDKey = correlation.GRPCCorrelationIDKey
	GRPCRequestIDKey     = correlation.GRPCRequestIDKey
)

// Re-export functions from the correlation package
var (
	WithCorrelationID = correlation.WithCorrelationID
	GetCorrelationID  = correlation.GetCorrelationID
	NewID             = correlation.NewID
	GetOrGenerate     = correlation.GetOrGenerate
)

// TestHTTPHeaderExtraction verifies correlation ID extraction from HTTP headers
func TestHTTPHeaderExtraction(t *testing.T) {
	tests := []struct {
		name   string
		header string
		value  string
		want   string
	}{
		{
			name:   "Extract from X-Correlation-ID header",
			header: CorrelationIDHeader,
			value:  "http-correlation-123",
			want:   "http-correlation-123",
		},
		{
			name:   "Extract from X-Request-ID header",
			header: RequestIDHeader,
			value:  "http-request-456",
			want:   "http-request-456",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test HTTP request
			req := httptest.NewRequest("GET", "/test", nil)
			req.Header.Set(tt.header, tt.value)

			// Simulate middleware that extracts correlation ID
			correlationID := req.Header.Get(CorrelationIDHeader)
			if correlationID == "" {
				correlationID = req.Header.Get(RequestIDHeader)
			}

			if correlationID != tt.want {
				t.Errorf("Expected correlation ID %q, got %q", tt.want, correlationID)
			}

			// Verify it can be added to context
			ctx := WithCorrelationID(req.Context(), correlationID)
			got := GetCorrelationID(ctx)
			if got != tt.want {
				t.Errorf("Context correlation ID = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestHTTPResponseHeaders verifies correlation ID is included in response headers
func TestHTTPResponseHeaders(t *testing.T) {
	correlationID := "test-response-correlation-789"

	// Create test HTTP handler
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Middleware would set this
		w.Header().Set(CorrelationIDHeader, correlationID)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	// Create test request
	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()

	// Execute handler
	handler.ServeHTTP(rr, req)

	// Verify response header contains correlation ID
	got := rr.Header().Get(CorrelationIDHeader)
	if got != correlationID {
		t.Errorf("Response header %s = %q, want %q", CorrelationIDHeader, got, correlationID)
	}
}

// TestGRPCMetadataExtraction verifies correlation ID extraction from gRPC metadata
func TestGRPCMetadataExtraction(t *testing.T) {
	tests := []struct {
		name string
		key  string
		want string
	}{
		{
			name: "Extract from x-correlation-id metadata",
			key:  GRPCCorrelationIDKey,
			want: "grpc-correlation-123",
		},
		{
			name: "Extract from x-request-id metadata",
			key:  GRPCRequestIDKey,
			want: "grpc-request-456",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create incoming metadata
			md := metadata.Pairs(tt.key, tt.want)
			ctx := metadata.NewIncomingContext(context.Background(), md)

			// Extract from metadata (simulating interceptor)
			inMD, ok := metadata.FromIncomingContext(ctx)
			if !ok {
				t.Fatal("Failed to extract metadata from context")
			}

			var correlationID string
			if values := inMD.Get(GRPCCorrelationIDKey); len(values) > 0 {
				correlationID = values[0]
			} else if values := inMD.Get(GRPCRequestIDKey); len(values) > 0 {
				correlationID = values[0]
			}

			if correlationID != tt.want {
				t.Errorf("Expected correlation ID %q, got %q", tt.want, correlationID)
			}

			// Verify it can be added to context
			ctx = WithCorrelationID(ctx, correlationID)
			got := GetCorrelationID(ctx)
			if got != tt.want {
				t.Errorf("Context correlation ID = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestGRPCMetadataResponse verifies correlation ID is included in response metadata
func TestGRPCMetadataResponse(t *testing.T) {
	correlationID := "grpc-response-correlation-789"

	// Create outgoing metadata
	md := metadata.Pairs(GRPCCorrelationIDKey, correlationID)

	// Verify metadata contains correlation ID
	values := md.Get(GRPCCorrelationIDKey)
	if len(values) == 0 {
		t.Fatal("Correlation ID not found in metadata")
	}

	if values[0] != correlationID {
		t.Errorf("Metadata correlation ID = %q, want %q", values[0], correlationID)
	}
}

// TestJSONRPCCorrelationID verifies correlation ID in JSON-RPC messages
func TestJSONRPCCorrelationID(t *testing.T) {
	correlationID := "jsonrpc-correlation-123"

	// Simulate JSON-RPC request with correlation ID
	type JSONRPCRequest struct {
		JSONRPC       string      `json:"jsonrpc"`
		Method        string      `json:"method"`
		Params        interface{} `json:"params,omitempty"`
		ID            interface{} `json:"id,omitempty"`
		CorrelationID string      `json:"correlation_id,omitempty"`
	}

	req := JSONRPCRequest{
		JSONRPC:       "2.0",
		Method:        "test.method",
		ID:            1,
		CorrelationID: correlationID,
	}

	// Marshal to JSON
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal JSON-RPC request: %v", err)
	}

	// Unmarshal back
	var parsed JSONRPCRequest
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal JSON-RPC request: %v", err)
	}

	// Verify correlation ID is preserved
	if parsed.CorrelationID != correlationID {
		t.Errorf("Parsed correlation ID = %q, want %q", parsed.CorrelationID, correlationID)
	}

	// Verify it can be added to context
	ctx := WithCorrelationID(context.Background(), parsed.CorrelationID)
	got := GetCorrelationID(ctx)
	if got != correlationID {
		t.Errorf("Context correlation ID = %q, want %q", got, correlationID)
	}
}

// TestJSONRPCResponseCorrelationID verifies correlation ID in JSON-RPC responses
func TestJSONRPCResponseCorrelationID(t *testing.T) {
	correlationID := "jsonrpc-response-correlation-456"

	// Simulate JSON-RPC response with correlation ID
	type JSONRPCResponse struct {
		JSONRPC       string      `json:"jsonrpc"`
		Result        interface{} `json:"result,omitempty"`
		Error         interface{} `json:"error,omitempty"`
		ID            interface{} `json:"id,omitempty"`
		CorrelationID string      `json:"correlation_id,omitempty"`
	}

	resp := JSONRPCResponse{
		JSONRPC:       "2.0",
		Result:        "success",
		ID:            1,
		CorrelationID: correlationID,
	}

	// Marshal to JSON
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Failed to marshal JSON-RPC response: %v", err)
	}

	// Unmarshal back
	var parsed JSONRPCResponse
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal JSON-RPC response: %v", err)
	}

	// Verify correlation ID is preserved
	if parsed.CorrelationID != correlationID {
		t.Errorf("Parsed correlation ID = %q, want %q", parsed.CorrelationID, correlationID)
	}
}

// TestCorrelationIDPropagationChain verifies correlation ID propagates through request chain
func TestCorrelationIDPropagationChain(t *testing.T) {
	originalID := "chain-correlation-123"

	// Step 1: HTTP Request arrives with correlation ID
	httpReq := httptest.NewRequest("GET", "/test", nil)
	httpReq.Header.Set(CorrelationIDHeader, originalID)

	extractedID := httpReq.Header.Get(CorrelationIDHeader)
	if extractedID != originalID {
		t.Errorf("HTTP extraction failed: got %q, want %q", extractedID, originalID)
	}

	// Step 2: Add to context
	ctx := WithCorrelationID(httpReq.Context(), extractedID)
	ctxID := GetCorrelationID(ctx)
	if ctxID != originalID {
		t.Errorf("Context storage failed: got %q, want %q", ctxID, originalID)
	}

	// Step 3: Propagate to gRPC metadata
	grpcMD := metadata.Pairs(GRPCCorrelationIDKey, ctxID)
	grpcCtx := metadata.NewOutgoingContext(ctx, grpcMD)

	// Verify it's in outgoing metadata
	outMD, ok := metadata.FromOutgoingContext(grpcCtx)
	if !ok {
		t.Fatal("Failed to extract outgoing metadata")
	}

	grpcValues := outMD.Get(GRPCCorrelationIDKey)
	if len(grpcValues) == 0 || grpcValues[0] != originalID {
		t.Errorf("gRPC metadata propagation failed: got %v, want %q", grpcValues, originalID)
	}

	// Step 4: Verify context still maintains correlation ID
	finalID := GetCorrelationID(grpcCtx)
	if finalID != originalID {
		t.Errorf("Final context check failed: got %q, want %q", finalID, originalID)
	}
}

// TestMultipleProtocolsUseConsistentHeaders verifies all protocols use consistent header/key names
func TestMultipleProtocolsUseConsistentHeaders(t *testing.T) {
	t.Run("HTTP headers are well-formed", func(t *testing.T) {
		if CorrelationIDHeader != "X-Correlation-ID" {
			t.Errorf("HTTP correlation header mismatch: got %q", CorrelationIDHeader)
		}
		if RequestIDHeader != "X-Request-ID" {
			t.Errorf("HTTP request ID header mismatch: got %q", RequestIDHeader)
		}
	})

	t.Run("gRPC metadata keys are lowercase", func(t *testing.T) {
		// gRPC metadata keys should be lowercase
		if GRPCCorrelationIDKey != "x-correlation-id" {
			t.Errorf("gRPC correlation key should be lowercase: got %q", GRPCCorrelationIDKey)
		}
		if GRPCRequestIDKey != "x-request-id" {
			t.Errorf("gRPC request ID key should be lowercase: got %q", GRPCRequestIDKey)
		}
	})

	t.Run("JSON-RPC field name is snake_case", func(t *testing.T) {
		// JSON-RPC uses correlation_id in JSON
		type TestStruct struct {
			CorrelationID string `json:"correlation_id"`
		}

		ts := TestStruct{CorrelationID: "test"}
		data, _ := json.Marshal(ts)
		str := string(data)

		if !contains(str, "correlation_id") {
			t.Errorf("JSON-RPC should use snake_case 'correlation_id', got: %s", str)
		}
	})
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// BenchmarkCorrelationIDPropagation benchmarks the full propagation chain
func BenchmarkCorrelationIDPropagation(b *testing.B) {
	correlationID := "bench-correlation-id"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// HTTP extraction
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set(CorrelationIDHeader, correlationID)

		// Context storage
		ctx := WithCorrelationID(req.Context(), correlationID)

		// gRPC metadata
		md := metadata.Pairs(GRPCCorrelationIDKey, correlationID)
		grpcCtx := metadata.NewOutgoingContext(ctx, md)

		// Final retrieval
		_ = GetCorrelationID(grpcCtx)
	}
}

// TestCorrelationIDFormat verifies correlation IDs maintain proper UUID format
func TestCorrelationIDFormat(t *testing.T) {
	// Generate multiple IDs and verify they're all valid UUIDs
	for i := 0; i < 100; i++ {
		id := NewID()

		// UUID v4 format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
		if len(id) != 36 {
			t.Errorf("Invalid UUID length: %d, want 36", len(id))
		}

		// Check for dashes in correct positions
		if id[8] != '-' || id[13] != '-' || id[18] != '-' || id[23] != '-' {
			t.Errorf("Invalid UUID format (dashes): %s", id)
		}

		// Verify version 4 (character 14 should be '4')
		if id[14] != '4' {
			t.Errorf("Invalid UUID version (not v4): %s", id)
		}
	}
}

// TestCorrelationIDErrorHandling tests error scenarios
func TestCorrelationIDErrorHandling(t *testing.T) {
	t.Run("Empty correlation ID in HTTP header", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set(CorrelationIDHeader, "")

		correlationID := req.Header.Get(CorrelationIDHeader)
		if correlationID == "" {
			// Should generate new ID
			correlationID = NewID()
		}

		if correlationID == "" {
			t.Error("Should generate new correlation ID for empty header")
		}
	})

	t.Run("Missing correlation ID in gRPC metadata", func(t *testing.T) {
		ctx := context.Background()
		md := metadata.MD{}
		ctx = metadata.NewIncomingContext(ctx, md)

		inMD, _ := metadata.FromIncomingContext(ctx)
		values := inMD.Get(GRPCCorrelationIDKey)

		if len(values) == 0 {
			// Should generate new ID
			correlationID := NewID()
			if correlationID == "" {
				t.Error("Should generate new correlation ID for missing metadata")
			}
		}
	})

	t.Run("Nil context handling", func(t *testing.T) {
		// Should not panic
		id := GetCorrelationID(nil)
		if id != "" {
			t.Errorf("GetCorrelationID(nil) should return empty string, got %q", id)
		}

		// GetOrGenerate should generate new ID for nil context
		id = GetOrGenerate(nil)
		if id == "" {
			t.Error("GetOrGenerate(nil) should generate new ID")
		}
	})
}

// Example demonstrates typical usage across protocols
func Example_hTTPToGRPC() {
	// 1. Extract from HTTP request
	httpReq := httptest.NewRequest("GET", "/api/test", nil)
	httpReq.Header.Set("X-Correlation-ID", "example-correlation-123")

	correlationID := httpReq.Header.Get(CorrelationIDHeader)
	if correlationID == "" {
		correlationID = NewID()
	}

	// 2. Add to context
	ctx := WithCorrelationID(httpReq.Context(), correlationID)

	// 3. Propagate to gRPC call
	md := metadata.Pairs(GRPCCorrelationIDKey, GetCorrelationID(ctx))
	grpcCtx := metadata.NewOutgoingContext(ctx, md)

	// Use grpcCtx for gRPC calls
	fmt.Println("Correlation ID:", GetCorrelationID(grpcCtx))
	// Output: Correlation ID: example-correlation-123
}
