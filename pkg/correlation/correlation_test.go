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
	"testing"

	"github.com/google/uuid"
)

func TestWithCorrelationID(t *testing.T) {
	tests := []struct {
		name          string
		ctx           context.Context
		correlationID string
		want          string
	}{
		{
			name:          "Add correlation ID to context",
			ctx:           context.Background(),
			correlationID: "test-correlation-id",
			want:          "test-correlation-id",
		},
		{
			name:          "Add correlation ID to nil context",
			ctx:           nil,
			correlationID: "test-correlation-id-2",
			want:          "test-correlation-id-2",
		},
		{
			name:          "Add empty correlation ID",
			ctx:           context.Background(),
			correlationID: "",
			want:          "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := WithCorrelationID(tt.ctx, tt.correlationID)
			if ctx == nil {
				t.Fatal("WithCorrelationID returned nil context")
			}
			got := GetCorrelationID(ctx)
			if got != tt.want {
				t.Errorf("GetCorrelationID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetCorrelationID(t *testing.T) {
	tests := []struct {
		name string
		ctx  context.Context
		want string
	}{
		{
			name: "Get correlation ID from context",
			ctx:  WithCorrelationID(context.Background(), "test-id"),
			want: "test-id",
		},
		{
			name: "Get from context without correlation ID",
			ctx:  context.Background(),
			want: "",
		},
		{
			name: "Get from nil context",
			ctx:  nil,
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetCorrelationID(tt.ctx)
			if got != tt.want {
				t.Errorf("GetCorrelationID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewID(t *testing.T) {
	tests := []struct {
		name string
	}{
		{
			name: "Generate new correlation ID",
		},
		{
			name: "Generate another new correlation ID",
		},
	}

	seen := make(map[string]bool)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewID()

			// Verify it's a valid UUID
			if _, err := uuid.Parse(got); err != nil {
				t.Errorf("NewID() returned invalid UUID: %v, error: %v", got, err)
			}

			// Verify it's unique
			if seen[got] {
				t.Errorf("NewID() returned duplicate ID: %v", got)
			}
			seen[got] = true

			// Verify it's not empty
			if got == "" {
				t.Error("NewID() returned empty string")
			}
		})
	}
}

func TestGetOrGenerate(t *testing.T) {
	existingID := "existing-correlation-id"

	tests := []struct {
		name      string
		ctx       context.Context
		wantExact string
		wantNew   bool
	}{
		{
			name:      "Get existing correlation ID",
			ctx:       WithCorrelationID(context.Background(), existingID),
			wantExact: existingID,
			wantNew:   false,
		},
		{
			name:      "Generate new correlation ID from context without one",
			ctx:       context.Background(),
			wantExact: "",
			wantNew:   true,
		},
		{
			name:      "Generate new correlation ID from nil context",
			ctx:       nil,
			wantExact: "",
			wantNew:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetOrGenerate(tt.ctx)

			if tt.wantNew {
				// Should generate a new UUID
				if _, err := uuid.Parse(got); err != nil {
					t.Errorf("GetOrGenerate() returned invalid UUID: %v, error: %v", got, err)
				}
				if got == "" {
					t.Error("GetOrGenerate() returned empty string when new ID expected")
				}
			} else {
				// Should return the exact existing ID
				if got != tt.wantExact {
					t.Errorf("GetOrGenerate() = %v, want %v", got, tt.wantExact)
				}
			}
		})
	}
}

func TestCorrelationIDPropagation(t *testing.T) {
	// Test that correlation ID propagates through context chain
	correlationID := "parent-correlation-id"

	parentCtx := WithCorrelationID(context.Background(), correlationID)

	// Create child context with additional values
	childCtx := context.WithValue(parentCtx, "test-key", "test-value")

	// Verify correlation ID is still accessible in child context
	got := GetCorrelationID(childCtx)
	if got != correlationID {
		t.Errorf("Correlation ID not propagated to child context, got %v, want %v", got, correlationID)
	}
}

func TestContextKeyIsolation(t *testing.T) {
	// Verify that correlation ID doesn't conflict with other context values
	correlationID := "test-correlation-id"

	ctx := context.Background()
	ctx = context.WithValue(ctx, "correlation-id", "wrong-value") // String key collision test
	ctx = WithCorrelationID(ctx, correlationID)

	got := GetCorrelationID(ctx)
	if got != correlationID {
		t.Errorf("Context key collision detected, got %v, want %v", got, correlationID)
	}
}

func TestConstants(t *testing.T) {
	// Verify constant values are set correctly
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{
			name:  "RequestIDHeader",
			value: RequestIDHeader,
			want:  "X-Request-ID",
		},
		{
			name:  "CorrelationIDHeader",
			value: CorrelationIDHeader,
			want:  "X-Correlation-ID",
		},
		{
			name:  "GRPCCorrelationIDKey",
			value: GRPCCorrelationIDKey,
			want:  "x-correlation-id",
		},
		{
			name:  "GRPCRequestIDKey",
			value: GRPCRequestIDKey,
			want:  "x-request-id",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.value != tt.want {
				t.Errorf("%s = %v, want %v", tt.name, tt.value, tt.want)
			}
		})
	}
}

func BenchmarkNewID(b *testing.B) {
	for i := 0; i < b.N; i++ {
		NewID()
	}
}

func BenchmarkWithCorrelationID(b *testing.B) {
	ctx := context.Background()
	id := NewID()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		WithCorrelationID(ctx, id)
	}
}

func BenchmarkGetCorrelationID(b *testing.B) {
	ctx := WithCorrelationID(context.Background(), NewID())
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		GetCorrelationID(ctx)
	}
}

func BenchmarkGetOrGenerate(b *testing.B) {
	ctx := context.Background()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		GetOrGenerate(ctx)
	}
}
