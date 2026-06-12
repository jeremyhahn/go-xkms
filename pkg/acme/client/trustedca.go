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

// Package trustedca provides the main entry point for the Trusted CA library.
// It integrates ACME server functionality with multi-tenant support, using
// QRDB for storage, and QRDB for authentication.
//
// Usage:
//
//	tca, err := trustedca.New(
//	    trustedca.WithQRDB(qrdbService),
//	    trustedca.WithAuthClient(authClient),
//	    trustedca.WithConfig(config),
//	    trustedca.WithMultiTenant(),
//	)
//	tca.Serve(ctx)
package client

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-xkms/pkg/acme/admin"
	"github.com/jeremyhahn/go-xkms/pkg/acme/auth"
	acmecommon "github.com/jeremyhahn/go-xkms/pkg/acme/common"
	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
	"github.com/jeremyhahn/go-xkms/pkg/acme/kms"
	"github.com/jeremyhahn/go-xkms/pkg/acme/qrdb"
	"github.com/jeremyhahn/go-xkms/pkg/acme/server"
	"github.com/jeremyhahn/go-xkms/pkg/acme/server/handlers"
	"github.com/jeremyhahn/go-xkms/pkg/acme/server/metrics"
	"github.com/jeremyhahn/go-xkms/pkg/acme/storage"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Version is the library version.
const Version = "0.1.0"

// Default network addresses and URL prefixes.
const (
	DefaultACMEAddr          = ":8443"
	DefaultExternalURLPrefix = "https://localhost"
	DefaultAdminAddr         = ":9443"
)

// Common errors.
var (
	ErrNotInitialized = errors.New("trustedca: not initialized")
	ErrAlreadyStarted = errors.New("trustedca: already started")
	ErrMissingCA      = errors.New("trustedca: certificate authority is required")
	ErrMissingStorage = errors.New("trustedca: storage factory is required")
	ErrMissingQRDB    = errors.New("trustedca: QRDB service is required for multi-tenant mode")
)

// TrustedCA is the main entry point for the Trusted CA library.
// It orchestrates ACME server, admin API, and multi-tenant functionality.
type TrustedCA struct {
	// Configuration
	config          *TrustedCAConfig
	version         string
	multiTenant     bool
	listenAddr      string
	adminListenAddr string
	externalURL     string

	// Core components
	ca             ca.TCGCA
	storageFactory storage.Factory
	qrdbService    qrdb.Service
	authClient     auth.Client
	kmsService     kms.KMSService
	challengeMap   map[string]acmecommon.ChallengeVerifierFunc
	logger         *slog.Logger

	// Rate limiting
	rateLimitRequests int
	rateLimitInterval time.Duration

	// Admin components
	adminService admin.Service

	// HTTP servers
	acmeServer  *http.Server
	adminServer *http.Server

	// ACME service
	restService handlers.RestServicer

	// State
	mu          sync.RWMutex
	initialized bool
	started     bool
}

// New creates a new TrustedCA instance with the provided options.
func New(opts ...Option) (*TrustedCA, error) {
	tca := &TrustedCA{
		config:            DefaultTrustedCAConfig(),
		version:           Version,
		logger:            slog.Default(),
		rateLimitRequests: 20,
		rateLimitInterval: time.Second,
	}

	// Apply options
	for _, opt := range opts {
		if err := opt(tca); err != nil {
			return nil, caerrors.InternalServerError("failed to apply option: %v", err)
		}
	}

	// Validate required components
	if err := tca.validate(); err != nil {
		return nil, err
	}

	// Initialize components
	if err := tca.initialize(); err != nil {
		return nil, caerrors.InternalServerError("failed to initialize: %v", err)
	}

	return tca, nil
}

// validate checks that all required components are configured.
func (tca *TrustedCA) validate() error {
	if tca.ca == nil {
		return ErrMissingCA
	}
	if tca.storageFactory == nil {
		return ErrMissingStorage
	}
	if tca.multiTenant && tca.qrdbService == nil {
		return ErrMissingQRDB
	}
	return nil
}

// initialize sets up internal components.
func (tca *TrustedCA) initialize() error {
	tca.mu.Lock()
	defer tca.mu.Unlock()

	if tca.logger == nil {
		tca.logger = slog.New(slog.NewTextHandler(os.Stdout, nil))
	}

	// Set up admin service
	if tca.multiTenant && tca.qrdbService != nil {
		// Multi-tenant mode with QRDB
		tca.adminService = admin.NewTenantAwareAdminService(
			tca.ca,
			tca.storageFactory,
			tca.qrdbService,
			tca.logger,
			tca.version,
		)
	} else {
		// Single-tenant mode
		tca.adminService = admin.NewAdminService(
			tca.ca,
			tca.storageFactory,
			tca.logger,
			tca.version,
		)
	}

	tca.initialized = true
	return nil
}

// CA returns the Certificate Authority.
func (tca *TrustedCA) CA() ca.TCGCA {
	return tca.ca
}

// QRDBService returns the QRDB service if configured.
func (tca *TrustedCA) QRDBService() qrdb.Service {
	return tca.qrdbService
}

// AdminService returns the admin service.
func (tca *TrustedCA) AdminService() admin.Service {
	return tca.adminService
}

// TenantService returns the tenant service if multi-tenant mode is enabled.
// Returns nil if not in multi-tenant mode.
func (tca *TrustedCA) TenantService() admin.TenantService {
	if ts, ok := tca.adminService.(admin.TenantService); ok {
		return ts
	}
	return nil
}

// IsMultiTenant returns whether multi-tenant mode is enabled.
func (tca *TrustedCA) IsMultiTenant() bool {
	return tca.multiTenant
}

// IsInitialized returns whether the instance is initialized.
func (tca *TrustedCA) IsInitialized() bool {
	tca.mu.RLock()
	defer tca.mu.RUnlock()
	return tca.initialized
}

// Version returns the version string.
func (tca *TrustedCA) Version() string {
	return tca.version
}

// Config returns the configuration.
func (tca *TrustedCA) Config() *TrustedCAConfig {
	return tca.config
}

// KMSService returns the KMS service if configured.
func (tca *TrustedCA) KMSService() kms.KMSService {
	return tca.kmsService
}

// RestService returns the ACME REST service.
// Returns nil if Serve() has not been called.
func (tca *TrustedCA) RestService() handlers.RestServicer {
	return tca.restService
}

// Serve starts the ACME and admin HTTP servers.
// This method blocks until the servers are stopped.
func (tca *TrustedCA) Serve(ctx context.Context) error {
	tca.mu.Lock()
	if !tca.initialized {
		tca.mu.Unlock()
		return ErrNotInitialized
	}
	if tca.started {
		tca.mu.Unlock()
		return ErrAlreadyStarted
	}
	tca.started = true
	tca.mu.Unlock()

	// Determine HTTPS listen address
	acmeListenAddr := tca.listenAddr
	if acmeListenAddr == "" {
		acmeListenAddr = tca.config.ACME.HTTPSAddr
	}
	if acmeListenAddr == "" {
		acmeListenAddr = DefaultACMEAddr
	}

	// Determine external URL
	externalURL := tca.externalURL
	if externalURL == "" {
		externalURL = tca.config.ACME.ExternalURL
	}
	if externalURL == "" {
		externalURL = DefaultExternalURLPrefix + acmeListenAddr
	}

	// Get TLS config from CA (TLS 1.3 enforced)
	tlsConfig, err := tca.ca.TLSConfig(ctx, nil)
	if err != nil {
		return caerrors.TLSErrorCreate("failed to get TLS config from CA: %v", err)
	}
	// Enforce TLS 1.3
	tlsConfig.MinVersion = tls.VersionTLS13
	tlsConfig.MaxVersion = tls.VersionTLS13

	// Initialize ACME REST service
	restService, err := handlers.NewRestService(&handlers.Params{
		BaseRESTURI:    externalURL,
		CA:             tca.ca,
		CAAIdentities:  tca.config.ACME.CAIdentifiers,
		ChallengeMap:   tca.challengeMap,
		KMSService:     tca.kmsService,
		Logger:         tca.logger,
		StorageFactory: tca.storageFactory,
		TermsOfService: tca.config.ACME.TermsOfService,
	})
	if err != nil {
		return caerrors.InternalServerError("failed to initialize ACME service: %v", err)
	}
	tca.restService = restService

	// Initialize Prometheus metrics
	metrics.Init()

	// Set up rate limiter
	rateLimiter := server.NewRateLimiter(tca.rateLimitRequests, tca.rateLimitInterval)
	rateLimitMiddleware := rateLimiter.MiddlewareFunc(server.ClientID)

	// Set up ACME router
	router := mux.NewRouter()
	acmeRouter := router.PathPrefix("/acme").Subrouter()
	acmeRouter.Use(rateLimitMiddleware)

	// Register ACME endpoints
	acmeRouter.HandleFunc("/directory", restService.DirectoryHandler).Methods("GET", "HEAD")
	acmeRouter.HandleFunc("/new-nonce", restService.NewNonceHandler).Methods("HEAD", "GET")
	acmeRouter.HandleFunc("/new-account", restService.NewAccountHandler).Methods("POST")
	acmeRouter.HandleFunc("/account/{id}", restService.AccountHandler).Methods("POST")
	acmeRouter.HandleFunc("/new-order", restService.NewOrderHandler).Methods("POST")
	acmeRouter.HandleFunc("/order/{id}", restService.OrderHandler).Methods("POST", "GET")
	acmeRouter.HandleFunc("/order/{id}/finalize", restService.OrderFinalizeHandler).Methods("POST")
	acmeRouter.HandleFunc("/authz/{id}", restService.AuthorizationHandler).Methods("POST", "GET")
	acmeRouter.HandleFunc("/challenge/{id}", restService.ChallengeHandler).Methods("POST", "GET")
	acmeRouter.HandleFunc("/cert/{id}", restService.CertificateHandler).Methods("POST", "GET")
	acmeRouter.HandleFunc("/revoke-cert", restService.RevokeCertHandler).Methods("POST")
	acmeRouter.HandleFunc("/key-change", restService.KeyChangeHandler).Methods("POST")
	acmeRouter.HandleFunc("/orders/{id}", restService.OrdersListHandler).Methods("POST", "GET")
	acmeRouter.HandleFunc("/ca-bundle", restService.CABundleHandler).Methods("GET")

	// Health and metrics endpoints
	router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("healthy"))
	}).Methods("GET")
	router.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	}).Methods("GET")
	router.Handle("/metrics", promhttp.HandlerFor(metrics.Registry, promhttp.HandlerOpts{})).Methods("GET")

	// Clone TLS config for admin server BEFORE starting any server
	// This prevents race conditions where http2ConfigureServer modifies
	// tls.Config.NextProtos concurrently
	adminTLSConfig := tlsConfig.Clone()

	// Create ACME HTTPS server with TLS 1.3
	acmeServer := &http.Server{
		Addr:         acmeListenAddr,
		Handler:      router,
		TLSConfig:    tlsConfig,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Store server reference under lock to avoid race with Shutdown()
	tca.mu.Lock()
	tca.acmeServer = acmeServer
	tca.mu.Unlock()

	// Start servers in goroutines
	errCh := make(chan error, 2)

	// ACME HTTPS server (TLS 1.3 enforced)
	go func() {
		tca.logger.Info("starting ACME HTTPS server",
			slog.String("addr", acmeListenAddr),
			slog.String("external_url", externalURL),
			slog.String("tls", "1.3"))
		// ListenAndServeTLS with empty cert/key paths uses TLSConfig's GetCertificate
		if err := acmeServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			errCh <- caerrors.InternalServerError("ACME HTTPS server error: %v", err)
			return
		}
		errCh <- nil
	}()

	// Admin HTTPS server (if enabled)
	if tca.config.Admin.Enabled {
		go func() {
			adminListenAddr := tca.adminListenAddr
			if adminListenAddr == "" {
				adminListenAddr = tca.config.Admin.HTTPSAddr
			}
			if adminListenAddr == "" {
				adminListenAddr = DefaultAdminAddr
			}

			// Set up admin router
			adminRouter := mux.NewRouter()
			adminHandlers := admin.NewHandlers(tca.adminService, tca.logger)

			// Use auth middleware if available, otherwise use simple auth
			if tca.authClient != nil && tca.multiTenant {
				// Multi-tenant: use auth client
				authMiddleware := admin.NewAuthMiddleware(tca.authClient)
				adminHandlers.RegisterRoutes(adminRouter, authMiddleware)

				// Register tenant-specific routes if TenantService is available
				if tenantService, ok := tca.adminService.(admin.TenantAwareService); ok {
					tenantHandlers := admin.NewTenantHandlers(tenantService, tca.logger)
					tenantHandlers.RegisterRoutes(adminRouter, authMiddleware)
				}
			} else {
				// Single-tenant: use basic auth middleware or nil
				adminHandlers.RegisterRoutes(adminRouter, nil)
			}

			// Create admin HTTPS server with TLS 1.3
			adminServer := &http.Server{
				Addr:         adminListenAddr,
				Handler:      adminRouter,
				TLSConfig:    adminTLSConfig,
				ReadTimeout:  30 * time.Second,
				WriteTimeout: 30 * time.Second,
				IdleTimeout:  120 * time.Second,
			}

			// Store server reference under lock to avoid race with Shutdown()
			tca.mu.Lock()
			tca.adminServer = adminServer
			tca.mu.Unlock()

			tca.logger.Info("starting admin HTTPS server",
				slog.String("addr", adminListenAddr),
				slog.String("tls", "1.3"))
			if err := adminServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				errCh <- caerrors.InternalServerError("admin HTTPS server error: %v", err)
				return
			}
			errCh <- nil
		}()
	}

	// Wait for context cancellation or error
	select {
	case <-ctx.Done():
		return tca.Shutdown(context.Background())
	case err := <-errCh:
		if err != nil {
			return err
		}
	}

	return nil
}

// Shutdown gracefully shuts down the servers.
func (tca *TrustedCA) Shutdown(ctx context.Context) error {
	tca.mu.Lock()
	defer tca.mu.Unlock()

	var errs []error

	if tca.acmeServer != nil {
		if err := tca.acmeServer.Shutdown(ctx); err != nil {
			errs = append(errs, caerrors.InternalServerError("ACME server shutdown: %v", err))
		}
	}

	if tca.adminServer != nil {
		if err := tca.adminServer.Shutdown(ctx); err != nil {
			errs = append(errs, caerrors.InternalServerError("admin server shutdown: %v", err))
		}
	}

	tca.started = false

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// Close releases all resources.
func (tca *TrustedCA) Close() error {
	return tca.Shutdown(context.Background())
}
