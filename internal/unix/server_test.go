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

package unix

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/adapters/logger"
	"github.com/jeremyhahn/go-keychain/pkg/health"
)

func TestNewServer_NilConfig(t *testing.T) {
	_, err := NewServer(nil)
	if err == nil {
		t.Error("Expected error for nil config")
	}
}

func TestNewServer_DefaultConfig(t *testing.T) {
	cfg := &Config{}
	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	if server.config.SocketPath != DefaultSocketPath {
		t.Errorf("SocketPath = %v, want %v", server.config.SocketPath, DefaultSocketPath)
	}

	if server.config.SocketMode != 0660 {
		t.Errorf("SocketMode = %v, want 0660", server.config.SocketMode)
	}

	if server.config.ReadTimeout != 30*time.Second {
		t.Errorf("ReadTimeout = %v, want 30s", server.config.ReadTimeout)
	}

	if server.config.WriteTimeout != 30*time.Second {
		t.Errorf("WriteTimeout = %v, want 30s", server.config.WriteTimeout)
	}
}

func TestNewServer_CustomConfig(t *testing.T) {
	cfg := &Config{
		SocketPath:   "/tmp/custom.sock",
		SocketMode:   0600,
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 60 * time.Second,
		Version:      "1.0.0",
	}

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	if server.config.SocketPath != "/tmp/custom.sock" {
		t.Errorf("SocketPath = %v, want /tmp/custom.sock", server.config.SocketPath)
	}

	if server.config.SocketMode != 0600 {
		t.Errorf("SocketMode = %v, want 0600", server.config.SocketMode)
	}
}

func TestServer_SocketPath(t *testing.T) {
	cfg := &Config{
		SocketPath: "/tmp/test.sock",
	}

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	if server.SocketPath() != "/tmp/test.sock" {
		t.Errorf("SocketPath() = %v, want /tmp/test.sock", server.SocketPath())
	}
}

func TestServer_SetHealthChecker(t *testing.T) {
	cfg := &Config{
		SocketPath: "/tmp/test.sock",
	}

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	checker := health.NewChecker()
	server.SetHealthChecker(checker)

	if server.healthChecker == nil {
		t.Error("Expected healthChecker to be set")
	}
}

func TestServer_StartStop(t *testing.T) {
	// Create temp directory for socket
	tmpDir, err := os.MkdirTemp("", "keychain-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	socketPath := filepath.Join(tmpDir, "test.sock")

	cfg := &Config{
		SocketPath: socketPath,
		Version:    "1.0.0",
	}

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	// Start server in goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Start()
	}()

	// Wait for socket file to exist (indicating server started)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(socketPath); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Check socket file exists
	if _, err := os.Stat(socketPath); os.IsNotExist(err) {
		t.Error("Socket file was not created")
	}

	// Additional wait to ensure http.Server is assigned
	time.Sleep(50 * time.Millisecond)

	// Stop server
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Stop(ctx); err != nil {
		t.Errorf("Stop() error = %v", err)
	}

	// Check for server errors
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("Server error: %v", err)
		}
	case <-time.After(2 * time.Second):
		// Timeout is OK, server stopped
	}
}

func TestServer_StartExistingSocket(t *testing.T) {
	// Create temp directory for socket
	tmpDir, err := os.MkdirTemp("", "keychain-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	socketPath := filepath.Join(tmpDir, "test.sock")

	// Create an existing socket file
	f, err := os.Create(socketPath)
	if err != nil {
		t.Fatalf("Failed to create socket file: %v", err)
	}
	_ = f.Close()

	// Get initial file info
	initialInfo, err := os.Stat(socketPath)
	if err != nil {
		t.Fatalf("Failed to stat initial socket file: %v", err)
	}

	cfg := &Config{
		SocketPath: socketPath,
		Version:    "1.0.0",
	}

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	// Start server in goroutine - should remove existing file
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Start()
	}()

	// Wait for socket to be recreated (new socket will have different inode)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		newInfo, err := os.Stat(socketPath)
		if err == nil && !os.SameFile(initialInfo, newInfo) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Additional wait to ensure http.Server is assigned
	time.Sleep(50 * time.Millisecond)

	// Stop server
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Stop(ctx); err != nil {
		t.Errorf("Stop() error = %v", err)
	}
}

func TestNoOpLogger(t *testing.T) {
	l := &noOpLogger{}

	// Test that none of these panic
	l.Debug("test")
	l.DebugContext(context.Background(), "test")
	l.Info("test")
	l.InfoContext(context.Background(), "test")
	l.Warn("test")
	l.WarnContext(context.Background(), "test")
	l.Error("test")
	l.ErrorContext(context.Background(), "test")
	l.Fatal("test")

	// Test With returns self
	result := l.With()
	if result != l {
		t.Error("With() should return self")
	}

	// Test WithError returns self
	result = l.WithError(nil)
	if result != l {
		t.Error("WithError() should return self")
	}
}

func TestDefaultSocketPath(t *testing.T) {
	if DefaultSocketPath != "/var/run/keychain/keychain.sock" {
		t.Errorf("DefaultSocketPath = %v, want /var/run/keychain/keychain.sock", DefaultSocketPath)
	}
}

func TestNoOpLogger_AllMethods(t *testing.T) {
	l := &noOpLogger{}

	// Test all methods with various arguments
	l.Debug("debug message", logger.String("key", "value"))
	l.DebugContext(context.Background(), "debug context", logger.Int("num", 42))
	l.Info("info message", logger.Bool("flag", true))
	l.InfoContext(context.Background(), "info context", logger.String("test", "value"))
	l.Warn("warn message", logger.String("warning", "test"))
	l.WarnContext(context.Background(), "warn context", logger.Int("code", 123))
	l.Error("error message", logger.String("error", "test"))
	l.ErrorContext(context.Background(), "error context", logger.Bool("critical", false))
	l.Fatal("fatal message", logger.String("fatal", "error"))

	// Test chaining methods
	l2 := l.With(logger.String("component", "test"))
	if l2 != l {
		t.Error("With() should return self")
	}

	l3 := l.WithError(errors.New("test error"))
	if l3 != l {
		t.Error("WithError() should return self")
	}
}

func TestServer_StartWithReadOnlyDir(t *testing.T) {
	// Skip on systems where we can't reliably test read-only directories
	if os.Getuid() == 0 {
		t.Skip("Skipping test when running as root")
	}

	// Try to create socket in a read-only directory
	cfg := &Config{
		SocketPath: "/proc/test.sock", // /proc is typically read-only
		Version:    "1.0.0",
	}

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	err = server.Start()
	if err == nil {
		_ = server.Stop(context.Background())
		t.Error("Expected error when creating socket in read-only directory")
	}
}

func TestServer_StopWithoutStart(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "keychain-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	cfg := &Config{
		SocketPath: filepath.Join(tmpDir, "test.sock"),
		Version:    "1.0.0",
	}

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	// Stop server without starting - should not error
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Stop(ctx); err != nil {
		t.Errorf("Stop() error = %v", err)
	}
}

func TestServer_SetupRoutesWithHealthChecker(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "keychain-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	cfg := &Config{
		SocketPath: filepath.Join(tmpDir, "test.sock"),
		Version:    "1.0.0",
	}

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	// Set health checker before calling setupRoutes (simulated by starting server)
	checker := health.NewChecker()
	server.SetHealthChecker(checker)

	// Start server to trigger setupRoutes with health checker
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Start()
	}()

	// Wait for socket
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(cfg.SocketPath); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Additional wait to ensure http.Server is assigned
	time.Sleep(50 * time.Millisecond)

	// Stop server
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Stop(ctx); err != nil {
		t.Errorf("Stop() error = %v", err)
	}
}

func TestServer_StartInvalidSocketPath(t *testing.T) {
	// Use a path under /dev/null which cannot have subdirectories
	// This will fail even when running as root since /dev/null is a device file
	cfg := &Config{
		SocketPath: "/dev/null/test.sock",
		Version:    "1.0.0",
	}

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	err = server.Start()
	if err == nil {
		_ = server.Stop(context.Background())
		t.Error("Expected error when creating socket with invalid path")
	}
}
