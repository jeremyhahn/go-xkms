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

package quic

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"sync"

	"github.com/jeremyhahn/go-keychain/pkg/adapters/auth"
	"github.com/jeremyhahn/go-keychain/pkg/adapters/logger"
	"github.com/jeremyhahn/go-keychain/pkg/correlation"
	"github.com/jeremyhahn/go-keychain/pkg/keychain"
	"github.com/quic-go/quic-go/http3"
)

// Server represents a QUIC/HTTP3 server
type Server struct {
	addr          string
	keystore      keychain.KeyStore // Default keystore for backward compatibility
	tlsConfig     *tls.Config
	authenticator auth.Authenticator
	logger        logger.Logger
	server        *http3.Server
	handler       http.Handler
	ctx           context.Context
	cancel        context.CancelFunc
	wg            sync.WaitGroup
}

// Config holds the QUIC server configuration
type Config struct {
	Addr          string
	TLSConfig     *tls.Config
	Authenticator auth.Authenticator
	Logger        logger.Logger
}

// NewServer creates a new QUIC/HTTP3 server
// The server uses the global keychain facade for backend management
func NewServer(config *Config) (*Server, error) {
	if !keychain.IsInitialized() {
		return nil, fmt.Errorf("keychain facade must be initialized before creating QUIC server")
	}

	if config.Addr == "" {
		config.Addr = "localhost:8444"
	}

	// Set up authenticator (default to NoOp if not provided)
	authenticator := config.Authenticator
	if authenticator == nil {
		authenticator = auth.NewNoOpAuthenticator()
	}

	// Set up logger (default to stdlib if not provided)
	log := config.Logger
	if log == nil {
		log = logger.NewSlogAdapter(&logger.SlogConfig{
			Level: logger.LevelInfo,
		})
	}

	// Use provided TLS config or create a default one
	tlsConfig := config.TLSConfig
	if tlsConfig == nil {
		// Generate a self-signed certificate for testing
		tlsConfig = &tls.Config{
			MinVersion: tls.VersionTLS13,
			NextProtos: []string{"h3"},
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	s := &Server{
		addr:          config.Addr,
		tlsConfig:     tlsConfig,
		authenticator: authenticator,
		logger:        log,
		ctx:           ctx,
		cancel:        cancel,
	}

	// Set default keystore from default backend for backward compatibility
	keystore, err := keychain.DefaultBackend()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to get default keystore: %w", err)
	}
	s.keystore = keystore

	// Set up HTTP handler with routes
	mux := http.NewServeMux()
	s.setupRoutes(mux)

	// Wrap with middleware (correlation first, then auth, then logging)
	s.handler = s.correlationMiddleware(s.authenticationMiddleware(s.loggingMiddleware(mux)))

	return s, nil
}

// setupRoutes configures the HTTP routes
func (s *Server) setupRoutes(mux *http.ServeMux) {
	// Health endpoint
	mux.HandleFunc("/health", s.handleHealth)

	// API v1 endpoints
	mux.HandleFunc("/api/v1/backends", s.handleListBackends)
	mux.HandleFunc("/api/v1/keys", s.handleKeys)
	mux.HandleFunc("/api/v1/keys/", s.handleKeyOperations)
	mux.HandleFunc("/api/v1/keys/copy", s.handleCopyKey)
	mux.HandleFunc("/api/v1/certs", s.handleCerts)
	mux.HandleFunc("/api/v1/certs/", s.handleCertOperations)
	mux.HandleFunc("/api/v1/tls/", s.handleTLSCertificate)
}

// Start starts the QUIC server
func (s *Server) Start() error {
	s.server = &http3.Server{
		Addr:      s.addr,
		Handler:   s.handler,
		TLSConfig: s.tlsConfig,
	}

	s.logger.Info("Starting QUIC/HTTP3 server",
		logger.String("addr", s.addr),
		logger.String("auth", s.authenticator.Name()))

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.logger.Error("QUIC server error", logger.Error(err))
		}
	}()

	return nil
}

// Stop stops the QUIC server
func (s *Server) Stop() error {
	s.logger.Info("Stopping QUIC server")
	s.cancel()

	if s.server != nil {
		if err := s.server.Close(); err != nil {
			s.logger.Error("Failed to close server", logger.Error(err))
			return err
		}
	}

	s.wg.Wait()
	s.logger.Info("QUIC server stopped")
	return nil
}

// Middleware

// correlationMiddleware extracts or generates a correlation ID for request tracing
func (s *Server) correlationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Try to get correlation ID from headers
		correlationID := r.Header.Get(correlation.CorrelationIDHeader)
		if correlationID == "" {
			correlationID = r.Header.Get(correlation.RequestIDHeader)
		}
		if correlationID == "" {
			// Generate a new correlation ID if none provided
			correlationID = correlation.NewID()
		}

		// Add correlation ID to request context
		ctx := correlation.WithCorrelationID(r.Context(), correlationID)
		r = r.WithContext(ctx)

		// Add correlation ID to response headers for client tracking
		w.Header().Set(correlation.CorrelationIDHeader, correlationID)

		next.ServeHTTP(w, r)
	})
}

// loggingMiddleware logs HTTP requests
func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Get identity from context if available
		identity := auth.GetIdentity(ctx)
		subject := "anonymous"
		if identity != nil {
			subject = identity.Subject
		}

		// Use context-aware logging to include correlation ID
		if slogAdapter, ok := s.logger.(*logger.SlogAdapter); ok {
			slogAdapter.InfoContext(ctx, "Request",
				logger.String("method", r.Method),
				logger.String("path", r.URL.Path),
				logger.String("subject", subject))
		} else {
			s.logger.Info("Request",
				logger.String("method", r.Method),
				logger.String("path", r.URL.Path),
				logger.String("subject", subject))
		}

		next.ServeHTTP(w, r)
	})
}

// authenticationMiddleware authenticates HTTP requests
func (s *Server) authenticationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip authentication for health endpoint
		if r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}

		// Authenticate the request
		identity, err := s.authenticator.AuthenticateHTTP(r)
		if err != nil {
			s.logger.Warn("Authentication failed",
				logger.String("method", r.Method),
				logger.String("path", r.URL.Path),
				logger.Error(err))
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Store identity in context
		ctx := auth.WithIdentity(r.Context(), identity)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}

// Addr returns the server address
func (s *Server) Addr() string {
	return s.addr
}
