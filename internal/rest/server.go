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

package rest

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jeremyhahn/go-keychain/pkg/adapters/auth"
	"github.com/jeremyhahn/go-keychain/pkg/adapters/logger"
	"github.com/jeremyhahn/go-keychain/pkg/keychain"
	"github.com/jeremyhahn/go-keychain/pkg/metrics"
)

// Server represents the REST API server.
type Server struct {
	server        *http.Server
	handlers      *HandlerContext
	port          int
	tlsConfig     *tls.Config
	authenticator auth.Authenticator
	logger        logger.Logger
}

// BackendRegistry is defined in handlers.go

// Config holds the REST server configuration.
type Config struct {
	// Port is the HTTP port to listen on (default: 8443)
	Port int

	// Backends is a map of backend ID to KeyStore instances
	Backends map[string]keychain.KeyStore

	// DefaultBackend is the default backend to use when not specified (optional)
	DefaultBackend string

	// Version is the API version string
	Version string

	// TLSConfig is the TLS configuration for HTTPS (optional)
	TLSConfig *tls.Config

	// Authenticator is the authentication adapter (optional, defaults to NoOp)
	Authenticator auth.Authenticator

	// Logger is the logging adapter (optional, uses stdlib if not provided)
	Logger logger.Logger

	// ReadTimeout is the maximum duration for reading the entire request
	ReadTimeout time.Duration

	// WriteTimeout is the maximum duration before timing out writes
	WriteTimeout time.Duration

	// IdleTimeout is the maximum amount of time to wait for the next request
	IdleTimeout time.Duration
}

// NewServer creates a new REST API server.
func NewServer(cfg *Config) (*Server, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}

	if cfg.Backends == nil || len(cfg.Backends) == 0 {
		return nil, fmt.Errorf("at least one backend is required")
	}

	// Set defaults
	if cfg.Port == 0 {
		cfg.Port = 8443
	}
	if cfg.Version == "" {
		cfg.Version = "1.0.0"
	}
	if cfg.ReadTimeout == 0 {
		cfg.ReadTimeout = 15 * time.Second
	}
	if cfg.WriteTimeout == 0 {
		cfg.WriteTimeout = 15 * time.Second
	}
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = 60 * time.Second
	}

	// Set up authenticator (default to NoOp if not provided)
	authenticator := cfg.Authenticator
	if authenticator == nil {
		authenticator = auth.NewNoOpAuthenticator()
	}

	// Set up logger (default to stdlib if not provided)
	log := cfg.Logger
	if log == nil {
		log = logger.NewSlogAdapter(&logger.SlogConfig{
			Level: logger.LevelInfo,
		})
	}

	// Determine default backend
	defaultBackend := cfg.DefaultBackend
	if defaultBackend == "" && len(cfg.Backends) > 0 {
		// Use first backend as default if not specified
		for name := range cfg.Backends {
			defaultBackend = name
			break
		}
	}

	// Create backend registry
	backendRegistry := NewBackendRegistry(cfg.Backends, defaultBackend)

	// Create handler context
	handlers := NewHandlerContext(backendRegistry, cfg.Version)

	// Create server instance
	server := &Server{
		handlers:      handlers,
		port:          cfg.Port,
		tlsConfig:     cfg.TLSConfig,
		authenticator: authenticator,
		logger:        log,
	}

	// Create router with middleware
	router := server.setupRouter()

	// Create HTTP server
	httpServer := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Port),
		Handler:      router,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		IdleTimeout:  cfg.IdleTimeout,
		TLSConfig:    cfg.TLSConfig,
	}

	server.server = httpServer

	return server, nil
}

// setupRouter configures the chi router with all routes and middleware.
func (s *Server) setupRouter() *chi.Mux {
	r := chi.NewRouter()

	// Apply global middleware
	r.Use(s.RecoveryMiddleware())
	r.Use(s.CorrelationMiddleware()) // Add correlation ID before logging
	r.Use(s.LoggingMiddleware())
	r.Use(metrics.HTTPMiddleware) // Metrics middleware
	r.Use(CORSMiddleware)

	// Legacy health endpoint (backwards compatibility)
	r.Get("/health", s.handlers.HealthHandler)
	r.Head("/health", s.handlers.HealthHandler)

	// Kubernetes-style health probes (no auth required)
	r.Get("/health/live", s.handlers.LivenessHandler)
	r.Get("/health/ready", s.handlers.ReadinessHandler)
	r.Get("/health/startup", s.handlers.StartupHandler)

	// API v1 routes with authentication
	r.Route("/api/v1", func(r chi.Router) {
		// Apply authentication middleware to all API routes
		r.Use(s.AuthenticationMiddleware())

		// Backend endpoints
		r.Get("/backends", s.handlers.ListBackendsHandler)
		r.Get("/backends/{id}", s.handlers.GetBackendHandler)

		// Key endpoints
		r.Post("/keys", s.handlers.GenerateKeyHandler)
		r.Get("/keys", s.handlers.ListKeysHandler)
		r.Get("/keys/{id}", s.handlers.GetKeyHandler)
		r.Delete("/keys/{id}", s.handlers.DeleteKeyHandler)

		// Crypto operation endpoints
		r.Post("/keys/{id}/sign", s.handlers.SignHandler)
		r.Post("/keys/{id}/verify", s.handlers.VerifyHandler)
		r.Post("/keys/{id}/rotate", s.handlers.RotateKeyHandler)
		r.Post("/keys/{id}/encrypt", s.handlers.EncryptHandler)
		r.Post("/keys/{id}/decrypt", s.handlers.DecryptHandler)

		// Import/Export endpoints
		r.Post("/keys/import-params", s.handlers.GetImportParametersHandler)
		r.Post("/keys/wrap", s.handlers.WrapKeyHandler)
		r.Post("/keys/unwrap", s.handlers.UnwrapKeyHandler)
		r.Post("/keys/import", s.handlers.ImportKeyHandler)
		r.Post("/keys/{id}/export", s.handlers.ExportKeyHandler)
		r.Post("/keys/copy", s.handlers.CopyKeyHandler)

		// Certificate endpoints
		r.Post("/certs", s.handlers.SaveCertHandler)
		r.Get("/certs", s.handlers.ListCertsHandler)
		r.Get("/certs/{id}", s.handlers.GetCertHandler)
		r.Delete("/certs/{id}", s.handlers.DeleteCertHandler)
		r.Head("/certs/{id}", s.handlers.CertExistsHandler)
		r.Post("/certs/{id}/chain", s.handlers.SaveCertChainHandler)
		r.Get("/certs/{id}/chain", s.handlers.GetCertChainHandler)

		// TLS helper endpoint
		r.Get("/tls/{id}", s.handlers.GetTLSCertificateHandler)
	})

	return r
}

// Start starts the REST API server.
func (s *Server) Start() error {
	if s.tlsConfig != nil {
		s.logger.Info("Starting HTTPS server",
			logger.Int("port", s.port),
			logger.String("auth", s.authenticator.Name()))

		if err := s.server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("failed to start HTTPS server: %w", err)
		}
	} else {
		s.logger.Info("Starting HTTP server",
			logger.Int("port", s.port),
			logger.String("auth", s.authenticator.Name()))

		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("failed to start HTTP server: %w", err)
		}
	}

	return nil
}

// Stop gracefully stops the REST API server.
func (s *Server) Stop(ctx context.Context) error {
	s.logger.Info("Shutting down server")

	if err := s.server.Shutdown(ctx); err != nil {
		s.logger.Error("Failed to shutdown server", logger.Error(err))
		return fmt.Errorf("failed to shutdown server: %w", err)
	}

	s.logger.Info("Server stopped")
	return nil
}

// Port returns the port the server is listening on.
func (s *Server) Port() int {
	return s.port
}

// SetHealthChecker sets the health checker for the server.
func (s *Server) SetHealthChecker(checker HealthChecker) {
	s.handlers.SetHealthChecker(checker)
}
