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
	"github.com/jeremyhahn/go-keychain/pkg/adapters/rbac"
	"github.com/jeremyhahn/go-keychain/pkg/keychain"
	"github.com/jeremyhahn/go-keychain/pkg/metrics"
	"github.com/jeremyhahn/go-keychain/pkg/ratelimit"
	"github.com/jeremyhahn/go-keychain/pkg/user"
	"github.com/jeremyhahn/go-keychain/pkg/webauthn"
	webauthnhttp "github.com/jeremyhahn/go-keychain/pkg/webauthn/http"
)

// Server represents the REST API server.
type Server struct {
	server          *http.Server
	handlers        *HandlerContext
	port            int
	tlsConfig       *tls.Config
	authenticator   auth.Authenticator
	logger          logger.Logger
	rateLimiter     *ratelimit.Limiter
	webauthnHandler *webauthnhttp.Handler
	webauthnStores  *WebAuthnStores
	userHandlers    *UserHandlers
	userStore       user.Store
	rbacAdapter     rbac.RBACAdapter
	rbacMiddleware  *RBACMiddleware
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

	// WebAuthnConfig is the WebAuthn configuration (optional, enables WebAuthn if provided)
	WebAuthnConfig *webauthn.Config

	// RateLimiter is the rate limiter instance (optional, disables rate limiting if not provided)
	RateLimiter *ratelimit.Limiter

	// UserStore is the user store (optional, enables user management if provided)
	UserStore user.Store

	// RBACAdapter is the RBAC adapter (optional, enables RBAC if provided)
	// If UserStore is provided but RBACAdapter is not, a UserRBACAdapter will be created automatically.
	RBACAdapter rbac.RBACAdapter

	// EnableRBAC enables role-based access control on API endpoints (default: false)
	// When enabled, users must have appropriate permissions for each operation.
	EnableRBAC bool
}

// NewServer creates a new REST API server.
func NewServer(cfg *Config) (*Server, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}

	if len(cfg.Backends) == 0 {
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

	// Create handler context (uses keychain service)
	handlers := NewHandlerContext(cfg.Version)

	// Create server instance
	server := &Server{
		handlers:      handlers,
		port:          cfg.Port,
		tlsConfig:     cfg.TLSConfig,
		authenticator: authenticator,
		logger:        log,
		rateLimiter:   cfg.RateLimiter,
	}

	// Set up user handlers if user store is configured
	if cfg.UserStore != nil {
		server.userStore = cfg.UserStore
		server.userHandlers = NewUserHandlers(cfg.UserStore)
		log.Info("User management enabled")
	}

	// Set up RBAC if enabled
	if cfg.EnableRBAC {
		if cfg.RBACAdapter != nil {
			server.rbacAdapter = cfg.RBACAdapter
		} else if cfg.UserStore != nil {
			// Create UserRBACAdapter automatically if user store is provided
			server.rbacAdapter = user.NewUserRBACAdapter(cfg.UserStore)
		} else {
			// Use default in-memory adapter
			server.rbacAdapter = rbac.NewMemoryRBACAdapter(true)
		}

		server.rbacMiddleware = NewRBACMiddleware(&RBACConfig{
			Adapter: server.rbacAdapter,
			Logger:  log,
			SkipPaths: map[string]bool{
				"/health":         true,
				"/health/live":    true,
				"/health/ready":   true,
				"/health/startup": true,
			},
		})
		log.Info("RBAC enabled")
	}

	// Set up WebAuthn if configured
	if cfg.WebAuthnConfig != nil {
		var webauthnUserStore webauthn.UserStore
		var sessionStore webauthn.SessionStore
		var credentialStore webauthn.CredentialStore

		// If user store is configured, use user-backed WebAuthn stores
		// This ensures WebAuthn users are persisted
		if cfg.UserStore != nil {
			webauthnUserStore = user.NewWebAuthnUserAdapter(cfg.UserStore)
			sessionStore = user.NewWebAuthnSessionAdapter(cfg.UserStore, 5*time.Minute)
			credentialStore = user.NewWebAuthnCredentialAdapter(cfg.UserStore)
			log.Info("WebAuthn using user store for persistence")
		} else {
			// Fall back to in-memory stores for development/testing
			stores := NewWebAuthnStores(&WebAuthnStoresConfig{
				SessionTTL: 5 * time.Minute,
			})
			webauthnUserStore = stores.UserStore()
			sessionStore = stores.SessionStore()
			credentialStore = stores.CredentialStore()
			server.webauthnStores = stores
			log.Info("WebAuthn using in-memory stores")
		}

		svc, err := webauthn.NewService(webauthn.ServiceParams{
			Config:          cfg.WebAuthnConfig,
			UserStore:       webauthnUserStore,
			SessionStore:    sessionStore,
			CredentialStore: credentialStore,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create webauthn service: %w", err)
		}

		server.webauthnHandler = webauthnhttp.NewHandler(svc)

		log.Info("WebAuthn enabled",
			logger.String("rpid", cfg.WebAuthnConfig.RPID))
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

	// Rate limiting middleware (if configured)
	if s.rateLimiter != nil && s.rateLimiter.IsEnabled() {
		r.Use(ratelimit.Middleware(s.rateLimiter))
		s.logger.Info("Rate limiting enabled for REST API")
	}

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
		if s.rbacMiddleware != nil {
			r.With(s.rbacMiddleware.RequirePermission(rbac.ResourceBackends, rbac.ActionList)).
				Get("/backends", s.handlers.ListBackendsHandler)
			r.With(s.rbacMiddleware.RequirePermission(rbac.ResourceBackends, rbac.ActionRead)).
				Get("/backends/{id}", s.handlers.GetBackendHandler)
		} else {
			r.Get("/backends", s.handlers.ListBackendsHandler)
			r.Get("/backends/{id}", s.handlers.GetBackendHandler)
		}

		// Key endpoints
		if s.rbacMiddleware != nil {
			r.With(s.rbacMiddleware.RequirePermission(rbac.ResourceKeys, rbac.ActionCreate)).
				Post("/keys", s.handlers.GenerateKeyHandler)
			r.With(s.rbacMiddleware.RequirePermission(rbac.ResourceKeys, rbac.ActionList)).
				Get("/keys", s.handlers.ListKeysHandler)
			r.With(s.rbacMiddleware.RequirePermission(rbac.ResourceKeys, rbac.ActionRead)).
				Get("/keys/{id}", s.handlers.GetKeyHandler)
			r.With(s.rbacMiddleware.RequirePermission(rbac.ResourceKeys, rbac.ActionDelete)).
				Delete("/keys/{id}", s.handlers.DeleteKeyHandler)

			// Crypto operation endpoints
			r.With(s.rbacMiddleware.RequirePermission(rbac.ResourceKeys, rbac.ActionSign)).
				Post("/keys/{id}/sign", s.handlers.SignHandler)
			r.With(s.rbacMiddleware.RequirePermission(rbac.ResourceKeys, rbac.ActionVerify)).
				Post("/keys/{id}/verify", s.handlers.VerifyHandler)
			r.With(s.rbacMiddleware.RequirePermission(rbac.ResourceKeys, rbac.ActionRotate)).
				Post("/keys/{id}/rotate", s.handlers.RotateKeyHandler)
			r.With(s.rbacMiddleware.RequirePermission(rbac.ResourceKeys, rbac.ActionEncrypt)).
				Post("/keys/{id}/encrypt", s.handlers.EncryptHandler)
			r.With(s.rbacMiddleware.RequirePermission(rbac.ResourceKeys, rbac.ActionDecrypt)).
				Post("/keys/{id}/decrypt", s.handlers.DecryptHandler)

			// Import/Export endpoints
			r.With(s.rbacMiddleware.RequirePermission(rbac.ResourceKeys, rbac.ActionImport)).
				Post("/keys/import-params", s.handlers.GetImportParametersHandler)
			r.With(s.rbacMiddleware.RequirePermission(rbac.ResourceKeys, rbac.ActionEncrypt)).
				Post("/keys/wrap", s.handlers.WrapKeyHandler)
			r.With(s.rbacMiddleware.RequirePermission(rbac.ResourceKeys, rbac.ActionDecrypt)).
				Post("/keys/unwrap", s.handlers.UnwrapKeyHandler)
			r.With(s.rbacMiddleware.RequirePermission(rbac.ResourceKeys, rbac.ActionImport)).
				Post("/keys/import", s.handlers.ImportKeyHandler)
			r.With(s.rbacMiddleware.RequirePermission(rbac.ResourceKeys, rbac.ActionExport)).
				Post("/keys/{id}/export", s.handlers.ExportKeyHandler)
			r.With(s.rbacMiddleware.RequirePermission(rbac.ResourceKeys, rbac.ActionCreate)).
				Post("/keys/copy", s.handlers.CopyKeyHandler)
		} else {
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
			r.Post("/keys/{id}/encrypt-asym", s.handlers.EncryptAsymHandler)

			// Import/Export endpoints
			r.Post("/keys/import-params", s.handlers.GetImportParametersHandler)
			r.Post("/keys/wrap", s.handlers.WrapKeyHandler)
			r.Post("/keys/unwrap", s.handlers.UnwrapKeyHandler)
			r.Post("/keys/import", s.handlers.ImportKeyHandler)
			r.Post("/keys/{id}/export", s.handlers.ExportKeyHandler)
			r.Post("/keys/copy", s.handlers.CopyKeyHandler)
		}

		// Certificate endpoints
		if s.rbacMiddleware != nil {
			r.With(s.rbacMiddleware.RequirePermission(rbac.ResourceCertificates, rbac.ActionCreate)).
				Post("/certs", s.handlers.SaveCertHandler)
			r.With(s.rbacMiddleware.RequirePermission(rbac.ResourceCertificates, rbac.ActionList)).
				Get("/certs", s.handlers.ListCertsHandler)
			r.With(s.rbacMiddleware.RequirePermission(rbac.ResourceCertificates, rbac.ActionRead)).
				Get("/certs/{id}", s.handlers.GetCertHandler)
			r.With(s.rbacMiddleware.RequirePermission(rbac.ResourceCertificates, rbac.ActionDelete)).
				Delete("/certs/{id}", s.handlers.DeleteCertHandler)
			r.With(s.rbacMiddleware.RequirePermission(rbac.ResourceCertificates, rbac.ActionRead)).
				Head("/certs/{id}", s.handlers.CertExistsHandler)
			r.With(s.rbacMiddleware.RequirePermission(rbac.ResourceCertificates, rbac.ActionCreate)).
				Post("/certs/{id}/chain", s.handlers.SaveCertChainHandler)
			r.With(s.rbacMiddleware.RequirePermission(rbac.ResourceCertificates, rbac.ActionRead)).
				Get("/certs/{id}/chain", s.handlers.GetCertChainHandler)

			// TLS helper endpoint
			r.With(s.rbacMiddleware.RequirePermission(rbac.ResourceCertificates, rbac.ActionRead)).
				Get("/tls/{id}", s.handlers.GetTLSCertificateHandler)
		} else {
			r.Post("/certs", s.handlers.SaveCertHandler)
			r.Get("/certs", s.handlers.ListCertsHandler)
			r.Get("/certs/{id}", s.handlers.GetCertHandler)
			r.Delete("/certs/{id}", s.handlers.DeleteCertHandler)
			r.Head("/certs/{id}", s.handlers.CertExistsHandler)
			r.Post("/certs/{id}/chain", s.handlers.SaveCertChainHandler)
			r.Get("/certs/{id}/chain", s.handlers.GetCertChainHandler)

			// TLS helper endpoint
			r.Get("/tls/{id}", s.handlers.GetTLSCertificateHandler)
		}

		// FROST threshold signature endpoints
		r.Route("/frost", func(r chi.Router) {
			// Key management
			r.Post("/keys", s.handlers.FrostGenerateKeyHandler)
			r.Post("/keys/import", s.handlers.FrostImportKeyHandler)
			r.Get("/keys", s.handlers.FrostListKeysHandler)
			r.Get("/keys/{id}", s.handlers.FrostGetKeyHandler)
			r.Delete("/keys/{id}", s.handlers.FrostDeleteKeyHandler)

			// Signing operations
			r.Post("/keys/{id}/nonces", s.handlers.FrostGenerateNoncesHandler)
			r.Post("/keys/{id}/sign", s.handlers.FrostSignRoundHandler)

			// Aggregation and verification
			r.Post("/aggregate", s.handlers.FrostAggregateHandler)
			r.Post("/verify", s.handlers.FrostVerifyHandler)
		})
	})

	// WebAuthn routes (no auth required - WebAuthn IS the auth mechanism)
	if s.webauthnHandler != nil {
		r.Route("/api/v1/webauthn", func(r chi.Router) {
			webauthnhttp.MountChi(r, s.webauthnHandler)
		})
	}

	// User management routes
	if s.userHandlers != nil {
		// Bootstrap status endpoint (unauthenticated - used to check if setup is required)
		r.Get("/api/v1/users/bootstrap/status", s.userHandlers.BootstrapStatusHandler)

		// Authenticated user management routes
		r.Route("/api/v1/users", func(r chi.Router) {
			r.Use(s.AuthenticationMiddleware())

			if s.rbacMiddleware != nil {
				r.With(s.rbacMiddleware.RequirePermission(rbac.ResourceUsers, rbac.ActionList)).
					Get("/", s.userHandlers.ListUsersHandler)
				r.With(s.rbacMiddleware.RequirePermission(rbac.ResourceUsers, rbac.ActionRead)).
					Get("/{id}", s.userHandlers.GetUserHandler)
				r.With(s.rbacMiddleware.RequirePermission(rbac.ResourceUsers, rbac.ActionUpdate)).
					Put("/{id}", s.userHandlers.UpdateUserHandler)
				r.With(s.rbacMiddleware.RequirePermission(rbac.ResourceUsers, rbac.ActionDelete)).
					Delete("/{id}", s.userHandlers.DeleteUserHandler)
			} else {
				r.Get("/", s.userHandlers.ListUsersHandler)
				r.Get("/{id}", s.userHandlers.GetUserHandler)
				r.Put("/{id}", s.userHandlers.UpdateUserHandler)
				r.Delete("/{id}", s.userHandlers.DeleteUserHandler)
			}
		})
	}

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
