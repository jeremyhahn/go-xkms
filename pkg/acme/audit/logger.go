// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
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
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/jeremyhahn/go-codec"
	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
	"github.com/vmihailenco/msgpack/v5"
	"gopkg.in/natefinch/lumberjack.v2"
)

// Codec provides serialization/deserialization for audit events.
type Codec interface {
	Marshal(v any) ([]byte, error)
	Unmarshal(data []byte, v any) error
	Type() codec.Type
}

// auditCodec implements Codec using go-codec.
type auditCodec struct {
	codecType codec.Type
}

// NewCodec creates a new Codec with the specified type.
func NewCodec(codecType codec.Type) Codec {
	return &auditCodec{codecType: codecType}
}

// DefaultCodec returns a JSON codec.
func DefaultCodec() Codec {
	return &auditCodec{codecType: codec.JSON}
}

func (c *auditCodec) Marshal(v any) ([]byte, error) {
	switch c.codecType {
	case codec.JSON:
		return json.Marshal(v)
	case codec.CBOR:
		return cbor.Marshal(v)
	case codec.MsgPack:
		return msgpack.Marshal(v)
	default:
		return json.Marshal(v)
	}
}

func (c *auditCodec) Unmarshal(data []byte, v any) error {
	switch c.codecType {
	case codec.JSON:
		return json.Unmarshal(data, v)
	case codec.CBOR:
		return cbor.Unmarshal(data, v)
	case codec.MsgPack:
		return msgpack.Unmarshal(data, v)
	default:
		return json.Unmarshal(data, v)
	}
}

func (c *auditCodec) Type() codec.Type {
	return c.codecType
}

// syncer is an interface for types that support syncing to disk
type syncer interface {
	Sync() error
}

// compile-time check to silence unused warning (interface reserved for future use)
var _ syncer = (*os.File)(nil)

// FileAuditLogger implements AuditLogger with file-based storage and rotation
type FileAuditLogger struct {
	config      *Config
	writer      io.WriteCloser
	codec       Codec
	buffer      chan *AuditEvent
	flushTicker *time.Ticker
	flushChan   chan chan error // Channel to request flush operations
	closed      atomic.Bool
	wg          sync.WaitGroup
	mu          sync.Mutex
	enabled     bool
	logPath     string // Store path for potential direct file operations
}

// NewFileAuditLogger creates a new file-based audit logger
func NewFileAuditLogger(config *Config) (AuditLogger, error) {
	if config == nil {
		return nil, caerrors.MalformedError("audit: config cannot be nil")
	}

	if err := config.Validate(); err != nil {
		return nil, caerrors.MalformedError("audit: invalid config: %v", err)
	}

	if !config.Enabled {
		return NewNoOpLogger(), nil
	}

	// Make the log path absolute to avoid path resolution issues
	absLogPath, err := filepath.Abs(config.LogPath)
	if err != nil {
		return nil, caerrors.InternalServerError("failed to resolve absolute log path: %v", err)
	}
	config.LogPath = absLogPath

	// Ensure the log directory exists
	logDir := filepath.Dir(config.LogPath)
	if err := os.MkdirAll(logDir, 0750); err != nil {
		return nil, caerrors.StorageFailureError("failed to create audit log directory: %v", err)
	}

	// Create the log file immediately to ensure it exists at the specified path
	f, err := os.OpenFile(config.LogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, caerrors.StorageFailureError("failed to create audit log file: %v", err)
	}
	_ = f.Close()

	// Configure lumberjack for log rotation
	writer := &lumberjack.Logger{
		Filename:   config.LogPath,
		MaxSize:    config.MaxSizeMB,
		MaxAge:     config.MaxAgeDays,
		MaxBackups: config.MaxBackups,
		Compress:   config.Compress,
		LocalTime:  false, // Use UTC
	}

	logger := &FileAuditLogger{
		config:      config,
		writer:      writer,
		codec:       DefaultCodec(),
		buffer:      make(chan *AuditEvent, config.BufferSize),
		flushTicker: time.NewTicker(time.Duration(config.FlushIntervalSeconds) * time.Second),
		flushChan:   make(chan chan error),
		enabled:     true,
		logPath:     config.LogPath,
	}

	// Start background writer goroutine
	logger.wg.Add(1)
	go logger.processEvents()

	return logger, nil
}

// Log records an audit event
func (l *FileAuditLogger) Log(ctx context.Context, event *AuditEvent) error {
	if l.closed.Load() {
		return ErrLoggerClosed
	}

	if event == nil {
		return caerrors.MalformedError("audit: event cannot be nil")
	}

	// Set timestamp if not already set
	if event.Timestamp.IsZero() {
		event.Timestamp = getCurrentTime()
	}

	// Validate event
	if err := event.Validate(); err != nil {
		return caerrors.MalformedError("audit: invalid event: %v", err)
	}

	// Try to send to buffer with context timeout
	select {
	case l.buffer <- event:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	default:
		// Buffer is full, write synchronously to avoid dropping the event
		return l.writeEvent(event)
	}
}

// LogWithContext logs an event with context extraction
func (l *FileAuditLogger) LogWithContext(
	ctx context.Context,
	eventType EventType,
	actor, resource, action string,
	result Result,
	details map[string]interface{}) error {

	event := &AuditEvent{
		Timestamp: getCurrentTime(),
		EventType: eventType,
		Actor:     actor,
		Resource:  resource,
		Action:    action,
		Result:    result,
		Details:   details,
	}

	// Extract context values if available
	if requestID := extractRequestID(ctx); requestID != "" {
		event.RequestID = requestID
	}
	if sourceIP := extractSourceIP(ctx); sourceIP != "" {
		event.SourceIP = sourceIP
	}
	if userAgent := extractUserAgent(ctx); userAgent != "" {
		event.UserAgent = userAgent
	}

	return l.Log(ctx, event)
}

// Flush ensures all buffered events are written to disk
func (l *FileAuditLogger) Flush() error {
	if l.closed.Load() {
		return ErrLoggerClosed
	}

	// Send flush request to processor and wait for completion
	doneChan := make(chan error, 1)
	select {
	case l.flushChan <- doneChan:
		err := <-doneChan
		if err != nil {
			return err
		}
	default:
		// Flush channel full or processor not ready, drain directly
		if err := l.drainBufferSync(); err != nil {
			return err
		}
	}

	// Acquire write mutex to ensure any in-progress write has completed
	// This is critical for the race where processEvents picked up an event
	// but hasn't finished writing it yet
	l.mu.Lock()
	defer l.mu.Unlock()

	// Now sync the writer to disk
	return l.syncWriterLocked()
}

// syncWriterLocked syncs the writer to disk (caller must hold mutex)
func (l *FileAuditLogger) syncWriterLocked() error {
	// Try to open the file directly and sync it to ensure OS buffers are flushed
	// This addresses potential race conditions in tests where file reads happen
	// immediately after flush
	if l.logPath != "" {
		f, err := os.OpenFile(l.logPath, os.O_RDWR, 0600)
		if err == nil {
			defer func() { _ = f.Close() }()
			_ = f.Sync()
		}
	}

	return nil
}

// drainBufferSync drains the buffer synchronously (used as fallback)
func (l *FileAuditLogger) drainBufferSync() error {
	for {
		select {
		case event := <-l.buffer:
			if err := l.writeEvent(event); err != nil {
				return err
			}
		default:
			return nil
		}
	}
}

// Close flushes remaining events and closes the logger
func (l *FileAuditLogger) Close() error {
	if !l.closed.CompareAndSwap(false, true) {
		return nil // Already closed
	}

	// Stop the flush ticker
	l.flushTicker.Stop()

	// Close the buffer channel to signal the processor to stop
	close(l.buffer)

	// Wait for the processor to finish
	l.wg.Wait()

	// Close the writer
	if l.writer != nil {
		return l.writer.Close()
	}

	return nil
}

// Enabled returns true if audit logging is enabled
func (l *FileAuditLogger) Enabled() bool {
	return l.enabled
}

// processEvents runs in a background goroutine to process buffered events
func (l *FileAuditLogger) processEvents() {
	defer l.wg.Done()

	for {
		select {
		case event, ok := <-l.buffer:
			if !ok {
				// Channel closed, exit
				return
			}
			if err := l.writeEvent(event); err != nil {
				// Log error but continue processing
				fmt.Fprintf(os.Stderr, "audit: failed to write event: %v\n", err)
			}

		case doneChan := <-l.flushChan:
			// Flush request received - drain buffer and signal completion
			err := l.drainBufferInternal()
			doneChan <- err

		case <-l.flushTicker.C:
			// Periodic flush - drain any pending events
			if !l.closed.Load() {
				l.drainBuffer()
			}
		}
	}
}

// drainBuffer writes all buffered events to disk
func (l *FileAuditLogger) drainBuffer() {
	for {
		select {
		case event, ok := <-l.buffer:
			if !ok {
				// Channel closed
				return
			}
			if err := l.writeEvent(event); err != nil {
				fmt.Fprintf(os.Stderr, "audit: failed to write event during drain: %v\n", err)
			}
		default:
			return
		}
	}
}

// drainBufferInternal drains the buffer and returns any error
func (l *FileAuditLogger) drainBufferInternal() error {
	for {
		select {
		case event, ok := <-l.buffer:
			if !ok {
				// Channel closed
				return nil
			}
			if err := l.writeEvent(event); err != nil {
				return err
			}
		default:
			return nil
		}
	}
}

// writeEvent writes a single event to the log file
func (l *FileAuditLogger) writeEvent(event *AuditEvent) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	data, err := l.codec.Marshal(event)
	if err != nil {
		return caerrors.SerializationFailureError("audit: failed to marshal event: %v", err)
	}

	// Write data with newline for JSON-lines format (each event on its own line)
	if _, err := l.writer.Write(data); err != nil {
		return caerrors.StorageFailureError("audit: failed to write event data: %v", err)
	}
	if _, err := l.writer.Write([]byte("\n")); err != nil {
		return caerrors.StorageFailureError("audit: failed to write event newline: %v", err)
	}

	return nil
}

// Context key types for extracting values from context.Context
type contextKey string

const (
	requestIDKey contextKey = "requestID"
	sourceIPKey  contextKey = "sourceIP"
	userAgentKey contextKey = "userAgent"
)

// ContextWithRequestID adds a request ID to the context
func ContextWithRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, requestIDKey, requestID)
}

// ContextWithSourceIP adds a source IP to the context
func ContextWithSourceIP(ctx context.Context, sourceIP string) context.Context {
	return context.WithValue(ctx, sourceIPKey, sourceIP)
}

// ContextWithUserAgent adds a user agent to the context
func ContextWithUserAgent(ctx context.Context, userAgent string) context.Context {
	return context.WithValue(ctx, userAgentKey, userAgent)
}

// extractRequestID extracts the request ID from context
func extractRequestID(ctx context.Context) string {
	if v := ctx.Value(requestIDKey); v != nil {
		if str, ok := v.(string); ok {
			return str
		}
	}
	return ""
}

// extractSourceIP extracts the source IP from context
func extractSourceIP(ctx context.Context) string {
	if v := ctx.Value(sourceIPKey); v != nil {
		if str, ok := v.(string); ok {
			return str
		}
	}
	return ""
}

// extractUserAgent extracts the user agent from context
func extractUserAgent(ctx context.Context) string {
	if v := ctx.Value(userAgentKey); v != nil {
		if str, ok := v.(string); ok {
			return str
		}
	}
	return ""
}

// getCurrentTime returns the current time in UTC
// This is a separate function to enable testing with mocked time
var getCurrentTime = func() time.Time {
	return time.Now().UTC()
}
