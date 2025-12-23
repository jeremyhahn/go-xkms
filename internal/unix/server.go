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

// Package unix provides a Unix domain socket server for local IPC.
package unix

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jeremyhahn/go-keychain/pkg/adapters/logger"
	"github.com/jeremyhahn/go-keychain/pkg/health"
	"github.com/jeremyhahn/go-keychain/pkg/keychain"
	"github.com/jeremyhahn/go-keychain/pkg/user"
)

// noOpLogger is a simple no-op logger implementation
type noOpLogger struct{}

func (l *noOpLogger) Debug(msg string, fields ...logger.Field) {}
func (l *noOpLogger) DebugContext(ctx context.Context, msg string, fields ...logger.Field) {
}
func (l *noOpLogger) Info(msg string, fields ...logger.Field) {}
func (l *noOpLogger) InfoContext(ctx context.Context, msg string, fields ...logger.Field) {
}
func (l *noOpLogger) Warn(msg string, fields ...logger.Field) {}
func (l *noOpLogger) WarnContext(ctx context.Context, msg string, fields ...logger.Field) {
}
func (l *noOpLogger) Error(msg string, fields ...logger.Field) {}
func (l *noOpLogger) ErrorContext(ctx context.Context, msg string, fields ...logger.Field) {
}
func (l *noOpLogger) Fatal(msg string, fields ...logger.Field)  {}
func (l *noOpLogger) With(fields ...logger.Field) logger.Logger { return l }
func (l *noOpLogger) WithError(err error) logger.Logger         { return l }

// DefaultSocketPath is the default path for the Unix socket
const DefaultSocketPath = "/var/run/keychain/keychain.sock"

// Config holds the Unix socket server configuration
type Config struct {
	// SocketPath is the path to the Unix socket file
	SocketPath string

	// Backends is a map of backend ID to KeyStore instances
	Backends map[string]keychain.KeyStore

	// DefaultBackend is the default backend to use when not specified
	DefaultBackend string

	// Version is the API version string
	Version string

	// Logger is the logging adapter
	Logger logger.Logger

	// UserStore is the user store (optional)
	UserStore user.Store

	// SocketMode is the file mode for the socket (default: 0660)
	SocketMode os.FileMode

	// ReadTimeout is the maximum duration for reading requests
	ReadTimeout time.Duration

	// WriteTimeout is the maximum duration for writing responses
	WriteTimeout time.Duration
}

// Server represents the Unix domain socket server
type Server struct {
	config        *Config
	server        *http.Server
	listener      net.Listener
	router        chi.Router
	logger        logger.Logger
	healthChecker *health.Checker
	mu            sync.RWMutex
}

// NewServer creates a new Unix socket server
func NewServer(cfg *Config) (*Server, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}

	if cfg.SocketPath == "" {
		cfg.SocketPath = DefaultSocketPath
	}

	if cfg.SocketMode == 0 {
		cfg.SocketMode = 0660
	}

	if cfg.ReadTimeout == 0 {
		cfg.ReadTimeout = 30 * time.Second
	}

	if cfg.WriteTimeout == 0 {
		cfg.WriteTimeout = 30 * time.Second
	}

	if cfg.Logger == nil {
		// Create a no-op logger that does nothing
		cfg.Logger = &noOpLogger{}
	}

	// Note: Backends are already registered with the keychain service by the main
	// server via keychain.Initialize(). The REST handlers that we delegate to
	// use the global keychain service to look up backends by name.

	s := &Server{
		config: cfg,
		logger: cfg.Logger,
		router: chi.NewRouter(),
	}

	s.setupRoutes()

	return s, nil
}

// setupRoutes configures the HTTP routes
func (s *Server) setupRoutes() {
	// Middleware
	s.router.Use(middleware.Recoverer)
	s.router.Use(middleware.RequestID)
	s.router.Use(middleware.RealIP)

	// Create handler context
	handlers := NewHandlerContext(s.config.Version, s.config.Backends, s.config.DefaultBackend)
	if s.healthChecker != nil {
		handlers.SetHealthChecker(s.healthChecker)
	}

	// Health endpoints
	s.router.Get("/health", handlers.HealthHandler)
	s.router.Get("/health/live", handlers.LiveHandler)
	s.router.Get("/health/ready", handlers.ReadyHandler)
	s.router.Get("/health/startup", handlers.StartupHandler)

	// API v1 routes
	s.router.Route("/api/v1", func(r chi.Router) {
		// Backend operations
		r.Get("/backends", handlers.ListBackendsHandler)
		r.Get("/backends/{id}", handlers.GetBackendHandler)

		// Key operations
		r.Post("/keys", handlers.GenerateKeyHandler)
		r.Get("/keys", handlers.ListKeysHandler)
		r.Get("/keys/{id}", handlers.GetKeyHandler)
		r.Delete("/keys/{id}", handlers.DeleteKeyHandler)

		// Cryptographic operations
		r.Post("/keys/{id}/sign", handlers.SignHandler)
		r.Post("/keys/{id}/verify", handlers.VerifyHandler)
		r.Post("/keys/{id}/encrypt", handlers.EncryptHandler)
		r.Post("/keys/{id}/decrypt", handlers.DecryptHandler)

		// Certificate operations
		r.Get("/keys/{id}/certificate", handlers.GetCertificateHandler)
		r.Put("/keys/{id}/certificate", handlers.SetCertificateHandler)
		r.Delete("/keys/{id}/certificate", handlers.DeleteCertificateHandler)

		// Import/Export operations
		r.Post("/keys/import", handlers.ImportKeyHandler)
		r.Get("/keys/{id}/export", handlers.ExportKeyHandler)

		// FROST threshold signature endpoints
		r.Route("/frost", func(r chi.Router) {
			// Key management
			r.Post("/keys", handlers.FrostGenerateKeyHandler)
			r.Post("/keys/import", handlers.FrostImportKeyHandler)
			r.Get("/keys", handlers.FrostListKeysHandler)
			r.Get("/keys/{id}", handlers.FrostGetKeyHandler)
			r.Delete("/keys/{id}", handlers.FrostDeleteKeyHandler)

			// Signing operations
			r.Post("/keys/{id}/nonces", handlers.FrostGenerateNoncesHandler)
			r.Post("/keys/{id}/sign", handlers.FrostSignRoundHandler)

			// Aggregation and verification
			r.Post("/aggregate", handlers.FrostAggregateHandler)
			r.Post("/verify", handlers.FrostVerifyHandler)
		})
	})
}

// SetHealthChecker sets the health checker for the server
func (s *Server) SetHealthChecker(checker *health.Checker) {
	s.healthChecker = checker
}

// Start starts the Unix socket server
func (s *Server) Start() error {
	// Ensure the socket directory exists
	socketDir := filepath.Dir(s.config.SocketPath)
	if err := os.MkdirAll(socketDir, 0750); err != nil {
		return fmt.Errorf("failed to create socket directory: %w", err)
	}

	// Remove existing socket file if present
	if err := os.Remove(s.config.SocketPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove existing socket: %w", err)
	}

	// Create Unix socket listener
	listener, err := net.Listen("unix", s.config.SocketPath)
	if err != nil {
		return fmt.Errorf("failed to create Unix socket listener: %w", err)
	}
	s.listener = listener

	// Set socket permissions
	if err := os.Chmod(s.config.SocketPath, s.config.SocketMode); err != nil {
		_ = s.listener.Close()
		return fmt.Errorf("failed to set socket permissions: %w", err)
	}

	s.logger.Info("Unix socket created", logger.String("path", s.config.SocketPath))

	// Create HTTP server
	s.mu.Lock()
	s.server = &http.Server{
		Handler:           s.router,
		ReadTimeout:       s.config.ReadTimeout,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      s.config.WriteTimeout,
		IdleTimeout:       120 * time.Second,
	}
	s.mu.Unlock()

	s.logger.Info("Starting Unix socket server", logger.String("socket", s.config.SocketPath))

	// Start serving
	if err := s.server.Serve(s.listener); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("unix socket server error: %w", err)
	}

	return nil
}

// Stop gracefully stops the Unix socket server
func (s *Server) Stop(ctx context.Context) error {
	s.logger.Info("Stopping Unix socket server...")

	s.mu.RLock()
	srv := s.server
	s.mu.RUnlock()

	if srv != nil {
		if err := srv.Shutdown(ctx); err != nil {
			s.logger.Error("Error shutting down Unix socket server", logger.Error(err))
			return err
		}
	}

	// Remove socket file
	if err := os.Remove(s.config.SocketPath); err != nil && !os.IsNotExist(err) {
		s.logger.Warn("Failed to remove socket file", logger.Error(err))
	}

	s.logger.Info("Unix socket server stopped")
	return nil
}

// SocketPath returns the path to the Unix socket
func (s *Server) SocketPath() string {
	return s.config.SocketPath
}
