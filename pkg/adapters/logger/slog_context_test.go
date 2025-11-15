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

package logger

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/correlation"
)

func TestSlogAdapter_ContextAwareLogging(t *testing.T) {
	// Create a buffer to capture log output
	var buf bytes.Buffer

	// Create a JSON handler for easier parsing
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})

	// Create slog adapter
	adapter := NewSlogAdapter(&SlogConfig{
		Logger: slog.New(handler),
	})

	correlationID := "test-correlation-id-12345"
	ctx := correlation.WithCorrelationID(context.Background(), correlationID)

	tests := []struct {
		name    string
		logFunc func()
		level   string
		message string
	}{
		{
			name: "DebugContext includes correlation ID",
			logFunc: func() {
				adapter.DebugContext(ctx, "debug message", String("key", "value"))
			},
			level:   "DEBUG",
			message: "debug message",
		},
		{
			name: "InfoContext includes correlation ID",
			logFunc: func() {
				adapter.InfoContext(ctx, "info message", String("key", "value"))
			},
			level:   "INFO",
			message: "info message",
		},
		{
			name: "WarnContext includes correlation ID",
			logFunc: func() {
				adapter.WarnContext(ctx, "warn message", String("key", "value"))
			},
			level:   "WARN",
			message: "warn message",
		},
		{
			name: "ErrorContext includes correlation ID",
			logFunc: func() {
				adapter.ErrorContext(ctx, "error message", String("key", "value"))
			},
			level:   "ERROR",
			message: "error message",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf.Reset()
			tt.logFunc()

			output := buf.String()
			if output == "" {
				t.Fatal("No log output captured")
			}

			// Parse JSON log entry
			var logEntry map[string]interface{}
			if err := json.Unmarshal([]byte(output), &logEntry); err != nil {
				t.Fatalf("Failed to parse log output as JSON: %v", err)
			}

			// Verify message
			if msg, ok := logEntry["msg"].(string); !ok || msg != tt.message {
				t.Errorf("Expected message %q, got %q", tt.message, msg)
			}

			// Verify correlation ID is present
			if corrID, ok := logEntry["correlation_id"].(string); !ok || corrID != correlationID {
				t.Errorf("Expected correlation_id %q, got %q", correlationID, corrID)
			}

			// Verify custom field
			if val, ok := logEntry["key"].(string); !ok || val != "value" {
				t.Errorf("Expected key=value, got key=%q", val)
			}
		})
	}
}

func TestSlogAdapter_ContextAwareLoggingWithoutCorrelationID(t *testing.T) {
	// Create a buffer to capture log output
	var buf bytes.Buffer

	// Create a JSON handler for easier parsing
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})

	// Create slog adapter
	adapter := NewSlogAdapter(&SlogConfig{
		Logger: slog.New(handler),
	})

	// Context without correlation ID
	ctx := context.Background()

	adapter.InfoContext(ctx, "test message")
	output := buf.String()

	if output == "" {
		t.Fatal("No log output captured")
	}

	// Parse JSON log entry
	var logEntry map[string]interface{}
	if err := json.Unmarshal([]byte(output), &logEntry); err != nil {
		t.Fatalf("Failed to parse log output as JSON: %v", err)
	}

	// Verify correlation_id is not present when not in context
	if _, exists := logEntry["correlation_id"]; exists {
		t.Error("correlation_id should not be present when not in context")
	}
}

func TestSlogAdapter_ContextAwareLoggingWithNilContext(t *testing.T) {
	// Create a buffer to capture log output
	var buf bytes.Buffer

	// Create a JSON handler for easier parsing
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})

	// Create slog adapter
	adapter := NewSlogAdapter(&SlogConfig{
		Logger: slog.New(handler),
	})

	// Nil context should not cause panic
	adapter.InfoContext(nil, "test message")
	output := buf.String()

	if output == "" {
		t.Fatal("No log output captured")
	}

	// Parse JSON log entry
	var logEntry map[string]interface{}
	if err := json.Unmarshal([]byte(output), &logEntry); err != nil {
		t.Fatalf("Failed to parse log output as JSON: %v", err)
	}

	// Verify correlation_id is not present
	if _, exists := logEntry["correlation_id"]; exists {
		t.Error("correlation_id should not be present with nil context")
	}
}

func TestSlogAdapter_AddCorrelationID(t *testing.T) {
	adapter := NewSlogAdapter(&SlogConfig{
		Level: LevelInfo,
	})

	tests := []struct {
		name              string
		ctx               context.Context
		fields            []Field
		expectCorrelation bool
		expectedID        string
	}{
		{
			name:              "Add correlation ID to empty fields",
			ctx:               correlation.WithCorrelationID(context.Background(), "test-id-1"),
			fields:            []Field{},
			expectCorrelation: true,
			expectedID:        "test-id-1",
		},
		{
			name:              "Add correlation ID to existing fields",
			ctx:               correlation.WithCorrelationID(context.Background(), "test-id-2"),
			fields:            []Field{String("key", "value")},
			expectCorrelation: true,
			expectedID:        "test-id-2",
		},
		{
			name:              "No correlation ID in context",
			ctx:               context.Background(),
			fields:            []Field{String("key", "value")},
			expectCorrelation: false,
		},
		{
			name:              "Nil context",
			ctx:               nil,
			fields:            []Field{String("key", "value")},
			expectCorrelation: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := adapter.addCorrelationID(tt.ctx, tt.fields)

			if tt.expectCorrelation {
				// Should have one more field than input
				if len(result) != len(tt.fields)+1 {
					t.Errorf("Expected %d fields, got %d", len(tt.fields)+1, len(result))
				}

				// Last field should be correlation_id
				lastField := result[len(result)-1]
				if lastField.Key != "correlation_id" {
					t.Errorf("Expected last field key to be correlation_id, got %s", lastField.Key)
				}

				if lastField.Value != tt.expectedID {
					t.Errorf("Expected correlation_id value %s, got %v", tt.expectedID, lastField.Value)
				}
			} else {
				// Should have same number of fields as input
				if len(result) != len(tt.fields) {
					t.Errorf("Expected %d fields, got %d", len(tt.fields), len(result))
				}

				// Should not contain correlation_id
				for _, field := range result {
					if field.Key == "correlation_id" {
						t.Error("correlation_id should not be present")
					}
				}
			}
		})
	}
}

func TestSlogAdapter_ContextLoggingIntegration(t *testing.T) {
	// Integration test that verifies full logging flow with correlation ID
	var buf bytes.Buffer

	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})

	adapter := NewSlogAdapter(&SlogConfig{
		Logger: slog.New(handler),
	})

	// Simulate a request flow
	correlationID := "request-12345"
	ctx := correlation.WithCorrelationID(context.Background(), correlationID)

	// Log at different levels
	adapter.DebugContext(ctx, "Processing request")
	adapter.InfoContext(ctx, "Request authenticated", String("user", "john"))
	adapter.WarnContext(ctx, "Slow query detected", Int("duration_ms", 1500))
	adapter.ErrorContext(ctx, "Operation failed", String("error", "timeout"))

	// Verify all log entries contain the correlation ID
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 4 {
		t.Fatalf("Expected 4 log entries, got %d", len(lines))
	}

	for i, line := range lines {
		var logEntry map[string]interface{}
		if err := json.Unmarshal([]byte(line), &logEntry); err != nil {
			t.Fatalf("Failed to parse log entry %d: %v", i, err)
		}

		if corrID, ok := logEntry["correlation_id"].(string); !ok || corrID != correlationID {
			t.Errorf("Log entry %d: expected correlation_id %q, got %q", i, correlationID, corrID)
		}
	}
}

func BenchmarkSlogAdapter_InfoContext(b *testing.B) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})

	adapter := NewSlogAdapter(&SlogConfig{
		Logger: slog.New(handler),
	})

	ctx := correlation.WithCorrelationID(context.Background(), "bench-correlation-id")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		adapter.InfoContext(ctx, "benchmark message", String("key", "value"))
	}
}

func BenchmarkSlogAdapter_InfoContextNoCorrelation(b *testing.B) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})

	adapter := NewSlogAdapter(&SlogConfig{
		Logger: slog.New(handler),
	})

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		adapter.InfoContext(ctx, "benchmark message", String("key", "value"))
	}
}
