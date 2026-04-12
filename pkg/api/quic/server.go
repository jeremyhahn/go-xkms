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

package quic

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/audit"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/authz"
	"github.com/jeremyhahn/go-xkms/pkg/correlation"
	"github.com/jeremyhahn/go-xkms/pkg/pin"
	"github.com/jeremyhahn/go-xkms/pkg/ratelimit"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/staticpw"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/quic-go/quic-go/http3"
)

var (
	// ErrAuthorizationFailed is returned when the authorizer encounters
	// an internal error while evaluating the request.
	ErrAuthorizationFailed = errors.New("authorization error")

	// ErrAccessDenied is returned when the authorizer denies access to the
	// requested resource.
	ErrAccessDenied = errors.New("access denied")
)

// Server represents a QUIC/HTTP3 server
type Server struct {
	addr            string
	version         string
	keystore        xkms.Backend // Default keystore for backward compatibility
	tlsConfig       *tls.Config
	authenticator   auth.Authenticator
	authorizer      authz.Authorizer
	auditLogger     audit.Logger
	logger          *slog.Logger
	rateLimiter     *ratelimit.Limiter
	barrier         *seal.Barrier
	pinManager      pin.PINBackend
	passwordStore   staticpw.Store
	passwordManager *staticpw.TenantPasswordStoreManager
	server          *http3.Server
	handler         http.Handler
	ctx             context.Context
	cancel          context.CancelFunc
	wg              sync.WaitGroup
}

// Config holds the QUIC server configuration
type Config struct {
	Addr            string
	Version         string
	TLSConfig       *tls.Config
	Authenticator   auth.Authenticator
	Authorizer      authz.Authorizer
	AuditLogger     audit.Logger
	Logger          *slog.Logger
	RateLimiter     *ratelimit.Limiter
	Barrier         *seal.Barrier
	PINManager      pin.PINBackend
	PasswordStore   staticpw.Store
	PasswordManager *staticpw.TenantPasswordStoreManager
}

// NewServer creates a new QUIC/HTTP3 server
// The server uses the global xkms service for backend management
func NewServer(config *Config) (*Server, error) {
	if !xkms.IsInitialized() {
		return nil, fmt.Errorf("xkms service must be initialized before creating QUIC server")
	}

	if config.Addr == "" {
		config.Addr = "localhost:8444"
	}

	// Set up authenticator (default to NoOp if not provided)
	authenticator := config.Authenticator
	if authenticator == nil {
		authenticator = auth.NewNoOpAuthenticator()
	}

	// Set up authorizer (default to NoOp if not provided)
	authorizer := config.Authorizer
	if authorizer == nil {
		authorizer = &authz.NoOpAuthorizer{}
	}

	// Set up audit logger (default to NoOp if not provided)
	auditLogger := config.AuditLogger
	if auditLogger == nil {
		auditLogger = &audit.NoOpLogger{}
	}

	// Set up logger (default to stdlib if not provided)
	log := config.Logger
	if log == nil {
		log = slog.Default()
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
		addr:            config.Addr,
		version:         config.Version,
		tlsConfig:       tlsConfig,
		authenticator:   authenticator,
		authorizer:      authorizer,
		auditLogger:     auditLogger,
		logger:          log,
		rateLimiter:     config.RateLimiter,
		barrier:         config.Barrier,
		pinManager:      config.PINManager,
		passwordStore:   config.PasswordStore,
		passwordManager: config.PasswordManager,
		ctx:             ctx,
		cancel:          cancel,
	}

	// Set default keystore from default backend for backward compatibility
	keystore, err := xkms.DefaultBackend()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to get default keystore: %w", err)
	}
	s.keystore = keystore

	// Set up HTTP handler with routes
	mux := http.NewServeMux()
	s.setupRoutes(mux)

	// Wrap with middleware (correlation first, then rate limit, then auth, then logging)
	var handler http.Handler = mux
	handler = s.loggingMiddleware(handler)
	handler = s.authenticationMiddleware(handler)

	// Rate limiting middleware (if configured)
	if s.rateLimiter != nil && s.rateLimiter.IsEnabled() {
		handler = ratelimit.Middleware(s.rateLimiter)(handler)
		log.Info("Rate limiting enabled for QUIC")
	}

	handler = s.correlationMiddleware(handler)
	s.handler = handler

	return s, nil
}

// setupRoutes configures the HTTP routes
func (s *Server) setupRoutes(mux *http.ServeMux) {
	// Health endpoint
	mux.HandleFunc("/health", s.handleHealth)

	// API v1 endpoints
	mux.HandleFunc("/api/v1/backends", s.handleListBackends)
	mux.HandleFunc("/api/v1/backends/", s.handleBackendOperations)
	mux.HandleFunc("/api/v1/keys", s.handleKeys)
	mux.HandleFunc("/api/v1/keys/", s.handleKeyOperations)
	mux.HandleFunc("/api/v1/keys/copy", s.handleCopyKey)
	mux.HandleFunc("/api/v1/keys/import-params", s.handleGetImportParams)
	mux.HandleFunc("/api/v1/certs", s.handleCerts)
	mux.HandleFunc("/api/v1/certs/", s.handleCertOperations)
	mux.HandleFunc("/api/v1/tls/", s.handleTLSCertificate)

	// CA endpoints
	mux.HandleFunc("/api/v1/ca/bundle", s.handleGetCABundle)
	mux.HandleFunc("/api/v1/ca/certificate", s.handleGetCACertificate)
	mux.HandleFunc("/api/v1/ca/sign-csr", s.handleSignCSR)
	mux.HandleFunc("/api/v1/ca/issue", s.handleIssueCertificate)
	mux.HandleFunc("/api/v1/ca/revoke", s.handleRevokeCertificate)
	mux.HandleFunc("/api/v1/ca/crl", s.handleGenerateCRL)
	mux.HandleFunc("/api/v1/ca/revoked/", s.handleIsRevoked)

	// TCG CA endpoints
	mux.HandleFunc("/api/v1/ca/tcg/ek", s.handleIssueEKCertificate)
	mux.HandleFunc("/api/v1/ca/tcg/ak", s.handleIssueAKCertificate)
	mux.HandleFunc("/api/v1/ca/tcg/sign-csr", s.handleSignTCGCSR)
	mux.HandleFunc("/api/v1/ca/tcg/enroll", s.handleEnrollDevice)

	// Sealing endpoints
	mux.HandleFunc("/api/v1/seal", s.handleSeal)
	mux.HandleFunc("/api/v1/unseal", s.handleUnseal)
	mux.HandleFunc("/api/v1/seal/capability", s.handleCanSeal)

	// Init ceremony endpoints
	mux.HandleFunc("/api/v1/init/status", s.handleGetInitStatus)
	mux.HandleFunc("/api/v1/init/claim-cert/begin", s.handleClaimCertBegin)
	mux.HandleFunc("/api/v1/init/claim-cert/complete", s.handleClaimCertComplete)
	mux.HandleFunc("/api/v1/init/claim-share", s.handleClaimShare)
	mux.HandleFunc("/api/v1/init/sign-csr", s.handleSignCSRInit)

	// Credential management endpoints
	mux.HandleFunc("/api/v1/credentials/submit", s.handleCredentialSubmit)
	mux.HandleFunc("/api/v1/credentials/strategy", s.handleCredentialStrategy)

	// PIV endpoints
	s.setupPIVRoutes(mux)

	// FROST threshold signature endpoints
	s.setupFrostRoutes(mux)

	// Barrier and PIN endpoints
	s.setupBarrierPINRoutes(mux)

	// Password management endpoints
	s.setupPasswordRoutes(mux)
}

// SetBarrier sets the barrier on the server. This allows the barrier to be
// configured after server creation.
func (s *Server) SetBarrier(barrier *seal.Barrier) {
	s.barrier = barrier
}

// SetPINManager sets the PIN backend on the server. This allows the PIN
// backend to be configured after server creation.
func (s *Server) SetPINManager(manager pin.PINBackend) {
	s.pinManager = manager
}

// SetPasswordStore sets the password store on the server. This allows the
// password store to be configured after server creation.
func (s *Server) SetPasswordStore(store staticpw.Store) {
	s.passwordStore = store
}

// SetPasswordManager sets the tenant password store manager on the server.
// This allows the password manager to be configured after server creation.
func (s *Server) SetPasswordManager(manager *staticpw.TenantPasswordStoreManager) {
	s.passwordManager = manager
}

// Start starts the QUIC server
func (s *Server) Start() error {
	s.server = &http3.Server{
		Addr:      s.addr,
		Handler:   s.handler,
		TLSConfig: s.tlsConfig,
	}

	s.logger.Info("Starting QUIC/HTTP3 server",
		slog.String("addr", s.addr),
		slog.String("auth", s.authenticator.Name()))

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.logger.Error("QUIC server error", slog.String("error", err.Error()))
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
			s.logger.Error("Failed to close server", slog.String("error", err.Error()))
			return err
		}
	}

	s.wg.Wait()
	s.logger.Info("QUIC server stopped")
	return nil
}

// authorize checks whether the current request is authorized to perform the
// given action on the specified resource. It extracts the caller identity from
// the request context, delegates to the configured authz.Authorizer, and
// records an audit event. Returns true when the request is allowed to proceed.
// On denial or error the appropriate HTTP status is written to w.
func (s *Server) authorize(w http.ResponseWriter, r *http.Request, resource, action string) bool {
	identity := auth.GetIdentity(r.Context())

	subject := ""
	role := ""
	if identity != nil {
		subject = identity.Subject
		role = extractRole(identity)
	}

	authzReq := &authz.AuthorizationRequest{
		Subject:  subject,
		Role:     role,
		Resource: resource,
		Action:   action,
		Context:  make(map[string]string),
	}

	decision, err := s.authorizer.Authorize(r.Context(), authzReq)

	// Determine outcome for audit logging
	outcome := audit.OutcomeAllow
	if err != nil || (decision != nil && !decision.Allowed) {
		outcome = audit.OutcomeDeny
	}

	// Build and log audit event (best effort - errors are intentionally
	// discarded to avoid disrupting the request pipeline)
	auditEvent := &audit.Event{
		Timestamp:  time.Now(),
		Subject:    subject,
		Action:     action,
		Resource:   resource,
		ResourceID: r.URL.Path,
		Outcome:    outcome,
		Details: map[string]string{
			"method":      r.Method,
			"remote_addr": r.RemoteAddr,
		},
	}
	if role != "" {
		auditEvent.Details["role"] = role
	}
	_ = s.auditLogger.Log(r.Context(), auditEvent)

	// Handle authorization errors
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, ErrAuthorizationFailed.Error())
		return false
	}

	// Handle denied decisions
	if decision != nil && !decision.Allowed {
		reason := ErrAccessDenied.Error()
		if decision.Reason != "" {
			reason = decision.Reason
		}
		s.sendError(w, http.StatusForbidden, reason)
		return false
	}

	return true
}

// extractRole extracts the first role from an identity's claims.
// It handles roles stored as []string, []interface{}, or string.
func extractRole(identity *auth.Identity) string {
	if identity == nil || identity.Claims == nil {
		return ""
	}

	roles, ok := identity.Claims["roles"]
	if !ok {
		return ""
	}

	switch r := roles.(type) {
	case []string:
		if len(r) > 0 {
			return r[0]
		}
	case []interface{}:
		if len(r) > 0 {
			if s, ok := r[0].(string); ok {
				return s
			}
		}
	case string:
		return r
	}

	return ""
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
		s.logger.InfoContext(ctx, "Request",
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.String("subject", subject))

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
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.String("error", err.Error()))
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
