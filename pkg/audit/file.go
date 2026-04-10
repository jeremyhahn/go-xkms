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

package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// FileLogger writes audit events as JSON lines to a file.
// Append-only for tamper evidence. Thread-safe via mutex.
type FileLogger struct {
	file   *os.File
	mu     sync.Mutex
	closed bool
}

// FileLoggerConfig configures the file-based audit logger.
type FileLoggerConfig struct {
	// Path is the file path for the audit log.
	Path string
}

// NewFileLogger creates a new file-based audit logger.
// The file is opened in append-only mode with 0600 permissions.
func NewFileLogger(cfg *FileLoggerConfig) (*FileLogger, error) {
	if cfg == nil || cfg.Path == "" {
		return nil, fmt.Errorf("audit log path is required")
	}

	f, err := os.OpenFile(cfg.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open audit log: %w", err)
	}

	return &FileLogger{file: f}, nil
}

// Log records an audit event as a JSON line to the log file.
// If the event timestamp is zero, it is set to the current UTC time.
func (l *FileLogger) Log(ctx context.Context, event *Event) error {
	if event == nil {
		return ErrNilEvent
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.closed {
		return ErrLoggerClosed
	}

	// Set timestamp if not provided
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal audit event: %w", err)
	}

	// Write JSON line with newline delimiter
	data = append(data, '\n')
	if _, err := l.file.Write(data); err != nil {
		return fmt.Errorf("failed to write audit event: %w", err)
	}

	// Sync to ensure durability
	if err := l.file.Sync(); err != nil {
		return fmt.Errorf("failed to sync audit log: %w", err)
	}

	return nil
}

// Close flushes and closes the underlying file. Subsequent calls are no-ops.
func (l *FileLogger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.closed {
		return nil
	}

	l.closed = true
	return l.file.Close()
}

// Compile-time interface compliance check
var _ Logger = (*FileLogger)(nil)
