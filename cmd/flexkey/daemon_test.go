//go:build ignore

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

package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSetupLogger(t *testing.T) {
	t.Run("creates logger with stdout output", func(t *testing.T) {
		cfg := &Config{
			LogLevel: "info",
			LogFile:  "", // stdout
		}

		logger, err := setupLogger(cfg)
		if err != nil {
			t.Fatalf("setupLogger() error = %v", err)
		}

		if logger == nil {
			t.Error("setupLogger() returned nil logger")
		}
	})

	t.Run("creates logger with file output", func(t *testing.T) {
		tempDir := t.TempDir()
		logPath := filepath.Join(tempDir, "test.log")

		cfg := &Config{
			LogLevel: "debug",
			LogFile:  logPath,
		}

		logger, err := setupLogger(cfg)
		if err != nil {
			t.Fatalf("setupLogger() error = %v", err)
		}

		if logger == nil {
			t.Error("setupLogger() returned nil logger")
		}

		// Verify log file was created
		if _, err := os.Stat(logPath); os.IsNotExist(err) {
			t.Error("log file was not created")
		}

		// Write a test log entry
		logger.Info("test message")

		// Verify log file has content
		content, err := os.ReadFile(logPath)
		if err != nil {
			t.Fatalf("failed to read log file: %v", err)
		}

		if !strings.Contains(string(content), "test message") {
			t.Error("log file does not contain expected message")
		}
	})

	t.Run("creates logger with different log levels", func(t *testing.T) {
		levels := []string{"debug", "info", "warn", "error", ""}

		for _, level := range levels {
			t.Run("level_"+level, func(t *testing.T) {
				cfg := &Config{
					LogLevel: level,
					LogFile:  "",
				}

				logger, err := setupLogger(cfg)
				if err != nil {
					t.Fatalf("setupLogger() error = %v for level %q", err, level)
				}

				if logger == nil {
					t.Errorf("setupLogger() returned nil logger for level %q", level)
				}
			})
		}
	})

	t.Run("appends to existing log file", func(t *testing.T) {
		tempDir := t.TempDir()
		logPath := filepath.Join(tempDir, "test.log")

		// Create initial log file with content
		initialContent := "existing log entry\n"
		if err := os.WriteFile(logPath, []byte(initialContent), 0644); err != nil {
			t.Fatalf("failed to create initial log file: %v", err)
		}

		cfg := &Config{
			LogLevel: "info",
			LogFile:  logPath,
		}

		logger, err := setupLogger(cfg)
		if err != nil {
			t.Fatalf("setupLogger() error = %v", err)
		}

		// Write new entry
		logger.Info("new message")

		// Verify both entries exist
		content, err := os.ReadFile(logPath)
		if err != nil {
			t.Fatalf("failed to read log file: %v", err)
		}

		if !strings.Contains(string(content), "existing log entry") {
			t.Error("existing log content was overwritten")
		}

		if !strings.Contains(string(content), "new message") {
			t.Error("new log message was not written")
		}
	})

	t.Run("fails with invalid log file path", func(t *testing.T) {
		cfg := &Config{
			LogLevel: "info",
			LogFile:  "/nonexistent/directory/that/cannot/exist/test.log",
		}

		_, err := setupLogger(cfg)
		if err == nil {
			t.Error("setupLogger() expected error for invalid path")
		}

		if !errors.Is(err, ErrLogFileOpenFailed) {
			t.Errorf("setupLogger() error should wrap ErrLogFileOpenFailed, got: %v", err)
		}
	})
}

func TestParseLogLevel(t *testing.T) {
	tests := []struct {
		name     string
		level    string
		expected slog.Level
	}{
		{
			name:     "debug level",
			level:    "debug",
			expected: slog.LevelDebug,
		},
		{
			name:     "info level",
			level:    "info",
			expected: slog.LevelInfo,
		},
		{
			name:     "warn level",
			level:    "warn",
			expected: slog.LevelWarn,
		},
		{
			name:     "error level",
			level:    "error",
			expected: slog.LevelError,
		},
		{
			name:     "empty defaults to info",
			level:    "",
			expected: slog.LevelInfo,
		},
		{
			name:     "unknown defaults to info",
			level:    "unknown",
			expected: slog.LevelInfo,
		},
		{
			name:     "trace defaults to info",
			level:    "trace",
			expected: slog.LevelInfo,
		},
		{
			name:     "WARNING (uppercase) defaults to info",
			level:    "WARNING",
			expected: slog.LevelInfo,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseLogLevel(tt.level)

			if result != tt.expected {
				t.Errorf("parseLogLevel(%q) = %v, want %v", tt.level, result, tt.expected)
			}
		})
	}
}

func TestSetupSignalHandler(t *testing.T) {
	t.Run("returns valid context and cancel function", func(t *testing.T) {
		logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError + 1}))

		ctx, cancel := setupSignalHandler(logger)
		defer cancel()

		if ctx == nil {
			t.Error("setupSignalHandler() returned nil context")
		}

		if cancel == nil {
			t.Error("setupSignalHandler() returned nil cancel function")
		}

		// Context should not be cancelled initially
		select {
		case <-ctx.Done():
			t.Error("context should not be cancelled initially")
		default:
			// Expected
		}
	})

	t.Run("cancel function cancels context", func(t *testing.T) {
		logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError + 1}))

		ctx, cancel := setupSignalHandler(logger)

		// Cancel the context
		cancel()

		// Context should be cancelled
		select {
		case <-ctx.Done():
			if ctx.Err() != context.Canceled {
				t.Errorf("context error = %v, want %v", ctx.Err(), context.Canceled)
			}
		case <-time.After(100 * time.Millisecond):
			t.Error("context was not cancelled within timeout")
		}
	})

	t.Run("context can be used with timeout", func(t *testing.T) {
		logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError + 1}))

		ctx, cancel := setupSignalHandler(logger)
		defer cancel()

		// Create child context with timeout
		childCtx, childCancel := context.WithTimeout(ctx, 50*time.Millisecond)
		defer childCancel()

		// Wait for timeout
		<-childCtx.Done()

		if childCtx.Err() != context.DeadlineExceeded {
			t.Errorf("child context error = %v, want %v", childCtx.Err(), context.DeadlineExceeded)
		}

		// Parent context should still be valid
		select {
		case <-ctx.Done():
			t.Error("parent context should not be cancelled")
		default:
			// Expected
		}
	})
}

func TestServiceLifecycle(t *testing.T) {
	t.Run("logger and signal handler lifecycle", func(t *testing.T) {
		tempDir := t.TempDir()
		logPath := filepath.Join(tempDir, "service.log")

		cfg := &Config{
			StorageType: StorageTypeMemory,
			LogLevel:    "debug",
			LogFile:     logPath,
		}

		logger, err := setupLogger(cfg)
		if err != nil {
			t.Fatalf("setupLogger() error = %v", err)
		}

		// Setup signal handler
		ctx, cancel := setupSignalHandler(logger)

		// Simulate shutdown
		cancel()

		// Wait for context cancellation
		select {
		case <-ctx.Done():
			// Expected
		case <-time.After(100 * time.Millisecond):
			t.Error("context was not cancelled")
		}

		// Verify log file exists and has content
		if _, err := os.Stat(logPath); os.IsNotExist(err) {
			t.Error("log file was not created")
		}
	})
}

func TestLoggerJSONFormat(t *testing.T) {
	t.Run("logger outputs JSON format", func(t *testing.T) {
		tempDir := t.TempDir()
		logPath := filepath.Join(tempDir, "json.log")

		cfg := &Config{
			LogLevel: "info",
			LogFile:  logPath,
		}

		logger, err := setupLogger(cfg)
		if err != nil {
			t.Fatalf("setupLogger() error = %v", err)
		}

		// Write a structured log entry
		logger.Info("test message",
			slog.String("key", "value"),
			slog.Int("count", 42),
		)

		// Read and verify JSON format
		content, err := os.ReadFile(logPath)
		if err != nil {
			t.Fatalf("failed to read log file: %v", err)
		}

		logStr := string(content)

		// Verify JSON structure
		if !strings.Contains(logStr, `"msg":"test message"`) {
			t.Error("log output missing message field")
		}

		if !strings.Contains(logStr, `"key":"value"`) {
			t.Error("log output missing key field")
		}

		if !strings.Contains(logStr, `"count":42`) {
			t.Error("log output missing count field")
		}
	})
}
