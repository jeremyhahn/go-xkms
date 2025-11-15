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
	"errors"
	"log/slog"
	"strings"
	"testing"
)

func TestNewSlogAdapter_NilConfig(t *testing.T) {
	adapter := NewSlogAdapter(nil)

	if adapter == nil {
		t.Fatal("NewSlogAdapter() returned nil")
	}

	if adapter.logger == nil {
		t.Error("logger should not be nil")
	}

	if adapter.fields == nil {
		t.Error("fields should not be nil")
	}
}

func TestNewSlogAdapter_CustomConfig(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelWarn,
	})
	customLogger := slog.New(handler)

	adapter := NewSlogAdapter(&SlogConfig{
		Logger: customLogger,
		Level:  LevelWarn,
	})

	if adapter == nil {
		t.Fatal("NewSlogAdapter() returned nil")
	}
}

func TestNewSlogAdapter_WithJSONHandler(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})

	adapter := NewSlogAdapter(&SlogConfig{
		Handler: handler,
		Level:   LevelInfo,
	})

	if adapter == nil {
		t.Fatal("NewSlogAdapter() returned nil")
	}

	adapter.Info("test message", String("key", "value"))

	output := buf.String()
	if !strings.Contains(output, "test message") {
		t.Errorf("output should contain message, got: %s", output)
	}
	if !strings.Contains(output, `"key":"value"`) {
		t.Errorf("output should contain JSON field, got: %s", output)
	}
}

func TestSlogAdapter_Debug(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})

	adapter := NewSlogAdapter(&SlogConfig{
		Handler: handler,
		Level:   LevelDebug,
	})

	adapter.Debug("debug message", String("key", "value"))

	output := buf.String()

	if !strings.Contains(output, "DEBUG") {
		t.Errorf("output should contain DEBUG, got: %s", output)
	}

	if !strings.Contains(output, "debug message") {
		t.Errorf("output should contain message, got: %s", output)
	}

	if !strings.Contains(output, "key=value") {
		t.Errorf("output should contain field, got: %s", output)
	}
}

func TestSlogAdapter_Info(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})

	adapter := NewSlogAdapter(&SlogConfig{
		Handler: handler,
		Level:   LevelInfo,
	})

	adapter.Info("info message", Int("count", 42))

	output := buf.String()

	if !strings.Contains(output, "INFO") {
		t.Errorf("output should contain INFO, got: %s", output)
	}

	if !strings.Contains(output, "info message") {
		t.Errorf("output should contain message, got: %s", output)
	}

	if !strings.Contains(output, "count=42") {
		t.Errorf("output should contain field, got: %s", output)
	}
}

func TestSlogAdapter_Warn(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelWarn,
	})

	adapter := NewSlogAdapter(&SlogConfig{
		Handler: handler,
		Level:   LevelWarn,
	})

	adapter.Warn("warning message", Bool("critical", true))

	output := buf.String()

	if !strings.Contains(output, "WARN") {
		t.Errorf("output should contain WARN, got: %s", output)
	}

	if !strings.Contains(output, "warning message") {
		t.Errorf("output should contain message, got: %s", output)
	}

	if !strings.Contains(output, "critical=true") {
		t.Errorf("output should contain field, got: %s", output)
	}
}

func TestSlogAdapter_Error(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelError,
	})

	adapter := NewSlogAdapter(&SlogConfig{
		Handler: handler,
		Level:   LevelError,
	})

	testErr := errors.New("test error")
	adapter.Error("error message", Error(testErr))

	output := buf.String()

	if !strings.Contains(output, "ERROR") {
		t.Errorf("output should contain ERROR, got: %s", output)
	}

	if !strings.Contains(output, "error message") {
		t.Errorf("output should contain message, got: %s", output)
	}

	if !strings.Contains(output, "test error") {
		t.Errorf("output should contain error value, got: %s", output)
	}
}

func TestSlogAdapter_LevelFiltering(t *testing.T) {
	tests := []struct {
		name          string
		level         Level
		logFunc       func(Logger)
		shouldContain string
		shouldLog     bool
	}{
		{
			name:          "info level filters debug",
			level:         LevelInfo,
			logFunc:       func(l Logger) { l.Debug("debug msg") },
			shouldContain: "debug msg",
			shouldLog:     false,
		},
		{
			name:          "info level allows info",
			level:         LevelInfo,
			logFunc:       func(l Logger) { l.Info("info msg") },
			shouldContain: "info msg",
			shouldLog:     true,
		},
		{
			name:          "warn level filters info",
			level:         LevelWarn,
			logFunc:       func(l Logger) { l.Info("info msg") },
			shouldContain: "info msg",
			shouldLog:     false,
		},
		{
			name:          "warn level allows warn",
			level:         LevelWarn,
			logFunc:       func(l Logger) { l.Warn("warn msg") },
			shouldContain: "warn msg",
			shouldLog:     true,
		},
		{
			name:          "error level filters warn",
			level:         LevelError,
			logFunc:       func(l Logger) { l.Warn("warn msg") },
			shouldContain: "warn msg",
			shouldLog:     false,
		},
		{
			name:          "error level allows error",
			level:         LevelError,
			logFunc:       func(l Logger) { l.Error("error msg") },
			shouldContain: "error msg",
			shouldLog:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{
				Level: levelToSlogLevel(tt.level),
			})

			adapter := NewSlogAdapter(&SlogConfig{
				Handler: handler,
				Level:   tt.level,
			})

			tt.logFunc(adapter)

			output := buf.String()
			contains := strings.Contains(output, tt.shouldContain)

			if tt.shouldLog && !contains {
				t.Errorf("expected output to contain '%s', got: %s", tt.shouldContain, output)
			}

			if !tt.shouldLog && contains {
				t.Errorf("expected output to NOT contain '%s', got: %s", tt.shouldContain, output)
			}
		})
	}
}

func TestSlogAdapter_With(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})

	adapter := NewSlogAdapter(&SlogConfig{
		Handler: handler,
		Level:   LevelInfo,
	})

	childAdapter := adapter.With(String("service", "test"), String("version", "1.0"))

	childAdapter.Info("child message")

	output := buf.String()

	if !strings.Contains(output, "child message") {
		t.Errorf("output should contain message, got: %s", output)
	}

	if !strings.Contains(output, "service=test") {
		t.Errorf("output should contain service field, got: %s", output)
	}

	if !strings.Contains(output, "version=1.0") {
		t.Errorf("output should contain version field, got: %s", output)
	}
}

func TestSlogAdapter_WithError(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})

	adapter := NewSlogAdapter(&SlogConfig{
		Handler: handler,
		Level:   LevelInfo,
	})

	testErr := errors.New("test error")
	childAdapter := adapter.WithError(testErr)

	childAdapter.Info("message with error")

	output := buf.String()

	if !strings.Contains(output, "message with error") {
		t.Errorf("output should contain message, got: %s", output)
	}

	if !strings.Contains(output, "test error") {
		t.Errorf("output should contain error value, got: %s", output)
	}
}

func TestSlogAdapter_WithChaining(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})

	adapter := NewSlogAdapter(&SlogConfig{
		Handler: handler,
		Level:   LevelInfo,
	})

	// Chain multiple With calls
	childAdapter := adapter.With(String("level1", "value1"))
	grandChildAdapter := childAdapter.With(String("level2", "value2"))

	grandChildAdapter.Info("nested message")

	output := buf.String()

	if !strings.Contains(output, "nested message") {
		t.Errorf("output should contain message, got: %s", output)
	}

	if !strings.Contains(output, "level1=value1") {
		t.Errorf("output should contain level1 field, got: %s", output)
	}

	if !strings.Contains(output, "level2=value2") {
		t.Errorf("output should contain level2 field, got: %s", output)
	}
}

func TestSlogAdapter_MultipleFields(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})

	adapter := NewSlogAdapter(&SlogConfig{
		Handler: handler,
		Level:   LevelInfo,
	})

	adapter.Info("message",
		String("str", "text"),
		Int("int", 123),
		Bool("bool", true),
		Float64("float", 3.14),
	)

	output := buf.String()

	expectedParts := []string{
		"message",
		"str=text",
		"int=123",
		"bool=true",
		"float=3.14",
	}

	for _, part := range expectedParts {
		if !strings.Contains(output, part) {
			t.Errorf("output should contain '%s', got: %s", part, output)
		}
	}
}

func TestSlogAdapter_EmptyFields(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})

	adapter := NewSlogAdapter(&SlogConfig{
		Handler: handler,
		Level:   LevelInfo,
	})

	adapter.Info("message with no fields")

	output := buf.String()

	if !strings.Contains(output, "message with no fields") {
		t.Errorf("output should contain message, got: %s", output)
	}
}

func TestSlogAdapter_AllFieldTypes(t *testing.T) {
	tests := []struct {
		name          string
		field         Field
		shouldContain string
	}{
		{
			name:          "string field",
			field:         String("key", "value"),
			shouldContain: "key=value",
		},
		{
			name:          "int field",
			field:         Int("count", 42),
			shouldContain: "count=42",
		},
		{
			name:          "int64 field",
			field:         Int64("big", 9223372036854775807),
			shouldContain: "big=9223372036854775807",
		},
		{
			name:          "float64 field",
			field:         Float64("pi", 3.14159),
			shouldContain: "pi=3.14159",
		},
		{
			name:          "bool field",
			field:         Bool("active", true),
			shouldContain: "active=true",
		},
		{
			name:          "error field",
			field:         Error(errors.New("test error")),
			shouldContain: "test error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{
				Level: slog.LevelInfo,
			})

			adapter := NewSlogAdapter(&SlogConfig{
				Handler: handler,
				Level:   LevelInfo,
			})

			adapter.Info("test", tt.field)

			output := buf.String()

			if !strings.Contains(output, tt.shouldContain) {
				t.Errorf("output should contain '%s', got: %s", tt.shouldContain, output)
			}
		})
	}
}

func TestSlogAdapter_SliceFields(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})

	adapter := NewSlogAdapter(&SlogConfig{
		Handler: handler,
		Level:   LevelInfo,
	})

	adapter.Info("test",
		Strings("items", []string{"a", "b", "c"}),
		Ints("nums", []int{1, 2, 3}),
	)

	output := buf.String()

	// slog formats slices differently, just check they're present
	if !strings.Contains(output, "items") {
		t.Errorf("output should contain 'items' field, got: %s", output)
	}

	if !strings.Contains(output, "nums") {
		t.Errorf("output should contain 'nums' field, got: %s", output)
	}
}

type CustomStruct struct {
	Name  string
	Value int
}

func TestSlogAdapter_CustomType(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})

	adapter := NewSlogAdapter(&SlogConfig{
		Handler: handler,
		Level:   LevelInfo,
	})

	adapter.Info("test", Any("custom", CustomStruct{Name: "test", Value: 42}))

	output := buf.String()

	if !strings.Contains(output, "custom") {
		t.Errorf("output should contain 'custom' field, got: %s", output)
	}
}

func TestSlogAdapter_AddSource(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{
		Level:     slog.LevelInfo,
		AddSource: true,
	})

	adapter := NewSlogAdapter(&SlogConfig{
		Handler:   handler,
		AddSource: true,
	})

	adapter.Info("test with source")

	output := buf.String()

	if !strings.Contains(output, "test with source") {
		t.Errorf("output should contain message, got: %s", output)
	}

	// Check for source location (should contain file name and line)
	if !strings.Contains(output, "source") {
		t.Errorf("output should contain source information, got: %s", output)
	}
}
