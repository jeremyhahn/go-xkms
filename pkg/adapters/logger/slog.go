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
	"context"
	"log/slog"
	"os"

	"github.com/jeremyhahn/go-keychain/pkg/correlation"
)

// SlogAdapter wraps a slog.Logger to implement the Logger interface
type SlogAdapter struct {
	logger *slog.Logger
	fields []Field
}

// SlogConfig configures the slog adapter
type SlogConfig struct {
	// Logger is the underlying slog logger
	// If nil, a new logger will be created
	Logger *slog.Logger

	// Level is the minimum log level to output
	Level Level

	// Handler is the slog handler to use (e.g., JSONHandler, TextHandler)
	// If nil and Logger is nil, a TextHandler writing to os.Stderr will be used
	Handler slog.Handler

	// AddSource adds source code position to log records
	AddSource bool
}

// NewSlogAdapter creates a new slog adapter
func NewSlogAdapter(config *SlogConfig) *SlogAdapter {
	if config == nil {
		config = &SlogConfig{}
	}

	// Create logger if not provided
	if config.Logger == nil {
		// Create handler if not provided
		if config.Handler == nil {
			opts := &slog.HandlerOptions{
				Level:     levelToSlogLevel(config.Level),
				AddSource: config.AddSource,
			}
			config.Handler = slog.NewTextHandler(os.Stderr, opts)
		}
		config.Logger = slog.New(config.Handler)
	}

	return &SlogAdapter{
		logger: config.Logger,
		fields: make([]Field, 0),
	}
}

// Debug logs a debug message
func (l *SlogAdapter) Debug(msg string, fields ...Field) {
	l.log(context.Background(), slog.LevelDebug, msg, fields...)
}

// Info logs an informational message
func (l *SlogAdapter) Info(msg string, fields ...Field) {
	l.log(context.Background(), slog.LevelInfo, msg, fields...)
}

// Warn logs a warning message
func (l *SlogAdapter) Warn(msg string, fields ...Field) {
	l.log(context.Background(), slog.LevelWarn, msg, fields...)
}

// Error logs an error message
func (l *SlogAdapter) Error(msg string, fields ...Field) {
	l.log(context.Background(), slog.LevelError, msg, fields...)
}

// Fatal logs a fatal message and exits
func (l *SlogAdapter) Fatal(msg string, fields ...Field) {
	l.log(context.Background(), slog.LevelError, msg, fields...)
	os.Exit(1)
}

// DebugContext logs a debug message with correlation ID from context
func (l *SlogAdapter) DebugContext(ctx context.Context, msg string, fields ...Field) {
	fields = l.addCorrelationID(ctx, fields)
	l.log(ctx, slog.LevelDebug, msg, fields...)
}

// InfoContext logs an informational message with correlation ID from context
func (l *SlogAdapter) InfoContext(ctx context.Context, msg string, fields ...Field) {
	fields = l.addCorrelationID(ctx, fields)
	l.log(ctx, slog.LevelInfo, msg, fields...)
}

// WarnContext logs a warning message with correlation ID from context
func (l *SlogAdapter) WarnContext(ctx context.Context, msg string, fields ...Field) {
	fields = l.addCorrelationID(ctx, fields)
	l.log(ctx, slog.LevelWarn, msg, fields...)
}

// ErrorContext logs an error message with correlation ID from context
func (l *SlogAdapter) ErrorContext(ctx context.Context, msg string, fields ...Field) {
	fields = l.addCorrelationID(ctx, fields)
	l.log(ctx, slog.LevelError, msg, fields...)
}

// addCorrelationID adds correlation ID from context to log fields if present
func (l *SlogAdapter) addCorrelationID(ctx context.Context, fields []Field) []Field {
	if ctx == nil {
		return fields
	}
	if correlationID := correlation.GetCorrelationID(ctx); correlationID != "" {
		fields = append(fields, String("correlation_id", correlationID))
	}
	return fields
}

// With creates a child logger with the given fields
func (l *SlogAdapter) With(fields ...Field) Logger {
	allFields := make([]Field, 0, len(l.fields)+len(fields))
	allFields = append(allFields, l.fields...)
	allFields = append(allFields, fields...)

	// Convert fields to slog.Attr
	attrs := make([]slog.Attr, 0, len(allFields))
	for _, f := range allFields {
		attrs = append(attrs, fieldToAttr(f))
	}

	return &SlogAdapter{
		logger: l.logger.With(attrsToAny(attrs)...),
		fields: allFields,
	}
}

// WithError creates a child logger with an error field
func (l *SlogAdapter) WithError(err error) Logger {
	return l.With(Error(err))
}

// log is the internal logging method
func (l *SlogAdapter) log(ctx context.Context, level slog.Level, msg string, fields ...Field) {
	// Combine permanent fields with message fields
	allFields := make([]Field, 0, len(l.fields)+len(fields))
	allFields = append(allFields, l.fields...)
	allFields = append(allFields, fields...)

	// Convert to slog.Attr
	attrs := make([]slog.Attr, 0, len(allFields))
	for _, f := range allFields {
		attrs = append(attrs, fieldToAttr(f))
	}

	l.logger.LogAttrs(ctx, level, msg, attrs...)
}

// fieldToAttr converts a Field to slog.Attr
func fieldToAttr(field Field) slog.Attr {
	switch v := field.Value.(type) {
	case string:
		return slog.String(field.Key, v)
	case int:
		return slog.Int(field.Key, v)
	case int64:
		return slog.Int64(field.Key, v)
	case float64:
		return slog.Float64(field.Key, v)
	case bool:
		return slog.Bool(field.Key, v)
	case error:
		return slog.Any(field.Key, v)
	case []string:
		return slog.Any(field.Key, v)
	case []int:
		return slog.Any(field.Key, v)
	default:
		return slog.Any(field.Key, v)
	}
}

// attrsToAny converts slog.Attr slice to []any for With method
func attrsToAny(attrs []slog.Attr) []any {
	result := make([]any, len(attrs))
	for i, attr := range attrs {
		result[i] = attr
	}
	return result
}

// levelToSlogLevel converts our Level to slog.Level
func levelToSlogLevel(level Level) slog.Level {
	switch level {
	case LevelDebug:
		return slog.LevelDebug
	case LevelInfo:
		return slog.LevelInfo
	case LevelWarn:
		return slog.LevelWarn
	case LevelError, LevelFatal:
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
