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
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
)

// writePIDFile writes the current process ID to a file.
// It creates parent directories if they do not exist.
func writePIDFile(path string) error {
	// Create directory if it doesn't exist
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("%w: %v", ErrPIDFileWriteFailed, err)
	}

	// Write PID to file
	pid := os.Getpid()
	content := []byte(strconv.Itoa(pid) + "\n")

	// #nosec G306 - PID file should be readable by all
	if err := os.WriteFile(path, content, 0644); err != nil {
		return fmt.Errorf("%w: %v", ErrPIDFileWriteFailed, err)
	}

	return nil
}

// removePIDFile removes the PID file at the specified path.
// It logs a warning if removal fails but does not return an error.
func removePIDFile(path string, logger *slog.Logger) {
	if err := os.Remove(path); err != nil {
		logger.Warn("Failed to remove PID file",
			slog.String("path", path),
			slog.Any("error", err))
	}
}

// setupSignalHandler creates a context that is cancelled when SIGTERM or SIGINT
// is received, enabling graceful shutdown.
func setupSignalHandler(logger *slog.Logger) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	go func() {
		select {
		case sig := <-sigCh:
			logger.Info("Received shutdown signal",
				slog.String("signal", sig.String()))
			cancel()
		case <-ctx.Done():
			return
		}
	}()

	return ctx, cancel
}

// setupLogger creates a structured JSON logger with the configured level and output.
func setupLogger(cfg *Config) (*slog.Logger, error) {
	// Determine log level
	level := parseLogLevel(cfg.LogLevel)

	// Determine output destination
	var output *os.File
	if cfg.LogFile == "" {
		output = os.Stdout
	} else {
		// #nosec G304 - Log file path is from configuration
		f, err := os.OpenFile(cfg.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrLogFileOpenFailed, err)
		}
		output = f
	}

	handler := slog.NewJSONHandler(output, &slog.HandlerOptions{
		Level: level,
	})

	return slog.New(handler), nil
}

// parseLogLevel converts a string log level to slog.Level.
func parseLogLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "info", "":
		return slog.LevelInfo
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
