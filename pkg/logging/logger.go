// Package logging provides a simple logging interface for go-tpm
package logging

import (
	"fmt"
	"log"
	"log/slog"
	"os"
)

// Logger provides logging functionality for TPM operations
type Logger struct {
	logger *slog.Logger
	debug  bool
}

// NewLogger creates a new logger instance
func NewLogger(debug bool) *Logger {
	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})
	if debug {
		handler = slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		})
	}
	return &Logger{
		logger: slog.New(handler),
		debug:  debug,
	}
}

// Info logs an informational message
func (l *Logger) Info(msg string, args ...any) {
	l.logger.Info(msg, args...)
}

// Infof logs a formatted informational message
func (l *Logger) Infof(format string, args ...any) {
	l.logger.Info(fmt.Sprintf(format, args...))
}

// Debug logs a debug message
func (l *Logger) Debug(msg string) {
	if l.debug {
		l.logger.Debug(msg)
	}
}

// Debugf logs a formatted debug message
func (l *Logger) Debugf(format string, args ...any) {
	if l.debug {
		l.logger.Debug(fmt.Sprintf(format, args...))
	}
}

// Warn logs a warning message
func (l *Logger) Warn(msg string) {
	l.logger.Warn(msg)
}

// Warnf logs a formatted warning message
func (l *Logger) Warnf(format string, args ...any) {
	l.logger.Warn(fmt.Sprintf(format, args...))
}

// Error logs an error
func (l *Logger) Error(err error) {
	l.logger.Error(err.Error())
}

// Errorf logs a formatted error message
func (l *Logger) Errorf(format string, args ...any) {
	l.logger.Error(fmt.Sprintf(format, args...))
}

// FatalError logs a fatal error and exits
func (l *Logger) FatalError(err error) {
	log.Fatal(err)
}

// Fatalf logs a formatted fatal message and exits
func (l *Logger) Fatalf(format string, args ...any) {
	log.Fatalf(format, args...)
}

// MaybeError logs an error if it's not nil
func (l *Logger) MaybeError(err error) {
	if err != nil {
		l.logger.Error(err.Error())
	}
}

// DefaultLogger returns a default logger instance with debug=false
func DefaultLogger() *Logger {
	return NewLogger(false)
}
