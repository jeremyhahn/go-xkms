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

package rest

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/authz"
	"github.com/jeremyhahn/go-xkms/pkg/bootstrap"
	"github.com/jeremyhahn/go-xkms/pkg/custodian"
	initialize "github.com/jeremyhahn/go-xkms/pkg/init"
	"github.com/jeremyhahn/go-xkms/pkg/metrics"
	"github.com/jeremyhahn/go-xkms/pkg/pin"
	"github.com/jeremyhahn/go-xkms/pkg/ratelimit"
	"github.com/jeremyhahn/go-xkms/pkg/rbac"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/seal/policy"
	credentialspkg "github.com/jeremyhahn/go-xkms/pkg/server/credentials"
	"github.com/jeremyhahn/go-xkms/pkg/sharestore"
	"github.com/jeremyhahn/go-xkms/pkg/staticpw"
	"github.com/jeremyhahn/go-xkms/pkg/user"
	"github.com/jeremyhahn/go-xkms/pkg/webauthn"
	webauthnhttp "github.com/jeremyhahn/go-xkms/pkg/webauthn/http"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// Server represents the REST API server.
type Server struct {
	server          *http.Server
	handlers        *HandlerContext
	port            int
	tlsConfig       *tls.Config
	authenticator   auth.Authenticator
	logger          *slog.Logger
	rateLimiter     *ratelimit.Limiter
	barrierRegistry *seal.BarrierRegistry
	webauthnHandler *webauthnhttp.Handler
	webauthnStores  *WebAuthnStores
	userHandlers    *UserHandlers
	userStore       user.Store
	rbacAdapter     rbac.RBACAdapter
	rbacMiddleware  *RBACMiddleware

	// Bootstrap and custodian handlers
	bootstrapHandlers  *BootstrapHandlers
	custodianHandlers  *CustodianHandlers
	shareHandlers      *ShareHandlers
	tenantHandlers     *TenantHandlers
	passwordHandlers   *PasswordHandlers
	platformHandlers   *SealStoreHandlers
	policyHandlers     *PolicyHandlers
	initHandlers       *InitHandlers
	credentialHandlers *CredentialHandlers
	caHandlers         *CAHandlers
}

// BackendRegistry is defined in handlers.go

// Config holds the REST server configuration.
type Config struct {
	// Port is the HTTP port to listen on (default: 8443)
	Port int

	// Backends is a map of backend ID to Backend instances
	Backends map[string]xkms.Backend

	// DefaultBackend is the default backend to use when not specified (optional)
	DefaultBackend string

	// Version is the API version string
	Version string

	// TLSConfig is the TLS configuration for HTTPS (optional)
	TLSConfig *tls.Config

	// Authenticator is the authentication adapter (optional, defaults to NoOp)
	Authenticator auth.Authenticator

	// Authorizer is the authorization adapter (optional)
	Authorizer authz.Authorizer

	// Logger is the logging adapter (optional, uses stdlib if not provided)
	Logger *slog.Logger

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

	// AuditLogger is the audit logger (optional)
	AuditLogger interface{}

	// Barrier is the optional barrier for seal/unseal lifecycle management
	Barrier *seal.Barrier

	// PINManager is the optional PIN manager for SO/User PIN operations
	PINManager pin.PINManager //nolint:staticcheck // TODO: migrate to PINBackend

	// PasswordStore is the optional static password store
	PasswordStore *staticpw.BackendStore

	// PlatformStore is the optional sealed platform credential store
	PlatformStore seal.PlatformStore

	// PolicyManager is the optional policy manager
	PolicyManager *policy.Manager

	// BootstrapService is the optional bootstrap service
	BootstrapService *bootstrap.Service

	// BarrierRegistry is the optional barrier registry for multi-tenant isolation
	BarrierRegistry *seal.BarrierRegistry

	// CustodianService is the optional custodian group management service
	CustodianService *custodian.Service

	// ShareStore is the optional share store for Shamir shares
	ShareStore sharestore.ShareStore

	// CeremonyService is the optional init ceremony service
	CeremonyService *initialize.CeremonyService

	// CredentialService is the optional credential management service
	CredentialService *credentialspkg.Service

	// CA is the optional CA instance for certificate authority operations.
	// Stored as any to break import cycles. Must implement caServicer methods.
	CA any
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
		log = slog.Default()
	}

	// Create handler context (uses xkms service)
	handlers := NewHandlerContext(cfg.Version)

	// Set barrier on handler context if provided
	if cfg.Barrier != nil {
		handlers.SetBarrier(cfg.Barrier)
	}

	// Set PIN manager on handler context if provided
	if cfg.PINManager != nil {
		handlers.SetPINManager(cfg.PINManager)
	}

	// Create server instance
	server := &Server{
		handlers:        handlers,
		port:            cfg.Port,
		tlsConfig:       cfg.TLSConfig,
		authenticator:   authenticator,
		logger:          log,
		rateLimiter:     cfg.RateLimiter,
		barrierRegistry: cfg.BarrierRegistry,
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
			slog.String("rpid", cfg.WebAuthnConfig.RPID))
	}

	// Set up bootstrap handlers if bootstrap service is configured
	if cfg.BootstrapService != nil {
		server.bootstrapHandlers = NewBootstrapHandlers(cfg.BootstrapService, log)
		log.Info("Bootstrap handlers enabled")
	}

	// Set up custodian handlers if custodian service is configured
	if cfg.CustodianService != nil {
		server.custodianHandlers = NewCustodianHandlers(cfg.CustodianService)
		log.Info("Custodian handlers enabled")
	}

	// Set up share handlers if share store is configured
	if cfg.ShareStore != nil {
		server.shareHandlers = NewShareHandlers(cfg.ShareStore)
		log.Info("Share handlers enabled")
	}

	// Set up tenant handlers if barrier registry is configured
	if cfg.BarrierRegistry != nil {
		server.tenantHandlers = NewTenantHandlers(cfg.BarrierRegistry)
		log.Info("Tenant handlers enabled")
	}

	// Set up password handlers if password store is configured
	if cfg.PasswordStore != nil {
		var pwManager *staticpw.TenantPasswordStoreManager
		if cfg.BarrierRegistry != nil {
			var managerErr error
			pwManager, managerErr = staticpw.NewTenantPasswordStoreManager(cfg.BarrierRegistry, cfg.PasswordStore)
			if managerErr != nil {
				log.Warn("Failed to create tenant password store manager", "error", managerErr)
			} else {
				log.Info("Tenant password store manager enabled")
			}
		}
		server.passwordHandlers = NewPasswordHandlers(cfg.PasswordStore, pwManager)
		log.Info("Password handlers enabled")
	}

	// Set up platform store handlers if platform store is configured
	if cfg.PlatformStore != nil {
		server.platformHandlers = NewSealStoreHandlers(cfg.PlatformStore)
		log.Info("Platform store handlers enabled")
	}

	// Set up policy handlers if policy manager is configured
	if cfg.PolicyManager != nil {
		server.policyHandlers = NewPolicyHandlers(cfg.PolicyManager)
		log.Info("Policy handlers enabled")
	}

	// Set up init ceremony handlers if ceremony service is configured
	if cfg.CeremonyService != nil {
		server.initHandlers = NewInitHandlers(cfg.CeremonyService, log)
		log.Info("Init ceremony handlers enabled")
	}

	// Set up credential handlers if credential service is configured
	if cfg.CredentialService != nil {
		server.credentialHandlers = NewCredentialHandlers(cfg.CredentialService, log)
		log.Info("Credential handlers enabled")
	}

	// Set up CA handlers if CA is configured
	if cfg.CA != nil {
		if caSvc, ok := cfg.CA.(caServicer); ok {
			server.caHandlers = NewCAHandlers(caSvc, log)
			log.Info("CA handlers enabled")
		}
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

	// Public algorithm discovery endpoint (no auth required)
	r.Get("/api/v1/algorithms", s.handlers.AlgorithmsHandler)

	// API v1 routes with authentication
	r.Route("/api/v1", func(r chi.Router) {
		// Apply authentication middleware to all API routes
		r.Use(s.AuthenticationMiddleware())

		// Apply tenant enforcement middleware after authentication
		r.Use(s.TenantMiddleware())

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

		// Sealing endpoints (hardware-backed data protection)
		if s.rbacMiddleware != nil {
			r.With(s.rbacMiddleware.RequirePermission(rbac.ResourceKeys, rbac.ActionEncrypt)).
				Post("/seal", s.handlers.SealHandler)
			r.With(s.rbacMiddleware.RequirePermission(rbac.ResourceKeys, rbac.ActionDecrypt)).
				Post("/unseal", s.handlers.UnsealHandler)
			r.With(s.rbacMiddleware.RequirePermission(rbac.ResourceKeys, rbac.ActionRead)).
				Get("/seal/capability", s.handlers.CanSealHandler)
		} else {
			r.Post("/seal", s.handlers.SealHandler)
			r.Post("/unseal", s.handlers.UnsealHandler)
			r.Get("/seal/capability", s.handlers.CanSealHandler)
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

		// Barrier management endpoints
		r.Route("/barrier", func(r chi.Router) {
			r.Post("/initialize", s.handlers.BarrierInitializeHandler)
			r.Post("/unseal", s.handlers.BarrierUnsealHandler)
			r.Post("/seal", s.handlers.BarrierSealHandler)
			r.Get("/status", s.handlers.BarrierStatusHandler)

			// Shamir secret sharing endpoints
			r.Post("/shamir/initialize", s.handlers.BarrierInitializeShamirHandler)
			r.Post("/shamir/unseal-share", s.handlers.BarrierUnsealShareHandler)
			r.Post("/shamir/unseal-shares", s.handlers.BarrierUnsealSharesHandler)
			r.Get("/shamir/shares", s.handlers.BarrierShamirListSharesHandler)
			r.Delete("/shamir/shares/{index}", s.handlers.BarrierShamirDeleteShareHandler)
			r.Delete("/shamir/shares", s.handlers.BarrierShamirDeleteAllSharesHandler)
			r.Post("/shamir/verify", s.handlers.BarrierShamirVerifyHandler)

			// Rekey and recovery endpoints
			r.Post("/rekey", s.handlers.BarrierRekeyHandler)
			r.Post("/recovery/generate", s.handlers.BarrierGenerateRecoveryKeysHandler)
			r.Post("/recovery/recover", s.handlers.BarrierRecoverWithKeysHandler)
			r.Delete("/recovery/keys", s.handlers.BarrierDeleteRecoveryKeysHandler)
			r.Post("/recovery/root-token", s.handlers.BarrierGenerateRootTokenHandler)
		})

		// PIN management endpoints
		r.Route("/pin", func(r chi.Router) {
			r.Post("/so/set", s.handlers.SetSOPINHandler)
			r.Post("/user/set", s.handlers.SetUserPINHandler)
			r.Post("/so/change", s.handlers.ChangeSOPINHandler)
			r.Post("/user/change", s.handlers.ChangeUserPINHandler)
			r.Post("/so/verify", s.handlers.VerifySOPINHandler)
			r.Post("/user/verify", s.handlers.VerifyUserPINHandler)
			r.Get("/lockout", s.handlers.GetLockoutStatusHandler)
			r.Post("/lockout/reset", s.handlers.ResetLockoutHandler)
		})

		// PIV endpoints
		r.Route("/piv", func(r chi.Router) {
			r.Get("/slots", s.handlers.ListPIVSlotsHandler)
			r.Get("/slots/{slot}/certificate", s.handlers.GetPIVCertificateHandler)
			r.Post("/slots/{slot}/certificate", s.handlers.StorePIVCertificateHandler)
			r.Delete("/slots/{slot}/certificate", s.handlers.DeletePIVCertificateHandler)
			r.Post("/slots/{slot}/generate", s.handlers.GeneratePIVKeyHandler)
			r.Post("/slots/{slot}/import", s.handlers.ImportPIVCertificateHandler)
			r.Get("/slots/{slot}/export", s.handlers.ExportPIVCertificateHandler)
			r.Post("/slots/{slot}/csr", s.handlers.GeneratePIVCSRHandler)
		})

		// CA endpoints
		if s.caHandlers != nil {
			r.Route("/ca", func(r chi.Router) {
				r.Get("/bundle", s.caHandlers.HandleGetCABundle)
				r.Get("/certificate", s.caHandlers.HandleGetCACertificate)
				r.Post("/sign-csr", s.caHandlers.HandleSignCSR)
				r.Post("/issue", s.caHandlers.HandleIssueCertificate)
				r.Post("/revoke", s.caHandlers.HandleRevokeCertificate)
				r.Post("/crl", s.caHandlers.HandleGenerateCRL)
				r.Get("/revoked/{serial}", s.caHandlers.HandleIsRevoked)

				// TCG CA endpoints
				r.Post("/tcg/ek", s.caHandlers.HandleIssueEKCertificate)
				r.Post("/tcg/ak", s.caHandlers.HandleIssueAKCertificate)
				r.Post("/tcg/sign-csr", s.caHandlers.HandleSignTCGCSR)
				r.Post("/tcg/enroll", s.caHandlers.HandleEnrollDevice)
			})
		} else {
			// Fallback: legacy CA bundle endpoint (bootstrap only)
			r.Get("/ca/bundle", s.handlers.GetCABundleHandler)
		}

		// Custodian group endpoints
		if s.custodianHandlers != nil {
			r.Route("/custodian/groups", func(r chi.Router) {
				r.Post("/", s.custodianHandlers.CreateGroupHandler)
				r.Get("/", s.custodianHandlers.ListGroupsHandler)
				r.Get("/{id}", s.custodianHandlers.GetGroupHandler)
				r.Delete("/{id}", s.custodianHandlers.DeleteGroupHandler)
				r.Post("/{id}/members", s.custodianHandlers.AddMemberHandler)
				r.Delete("/{id}/members/{userID}", s.custodianHandlers.RemoveMemberHandler)
				r.Post("/{id}/distribute", s.custodianHandlers.DistributeSharesHandler)
			})
		}

		// Share endpoints
		if s.shareHandlers != nil {
			r.Route("/shares", func(r chi.Router) {
				r.Post("/submit", s.shareHandlers.SubmitShareHandler)
				r.Get("/", s.shareHandlers.ListSharesHandler)
				r.Get("/{serverURL}/{groupID}/{shareIndex}", s.shareHandlers.GetShareHandler)
				r.Delete("/{serverURL}/{groupID}/{shareIndex}", s.shareHandlers.DeleteShareHandler)
				r.Get("/status/{groupID}", s.shareHandlers.GetShareCollectionStatusHandler)
			})
		}

		// Tenant endpoints
		if s.tenantHandlers != nil {
			r.Route("/tenants", func(r chi.Router) {
				r.Post("/", s.tenantHandlers.CreateTenantHandler)
				r.Get("/", s.tenantHandlers.ListTenantsHandler)
				r.Get("/{tenantID}", s.tenantHandlers.GetTenantHandler)
				r.Delete("/{tenantID}", s.tenantHandlers.DeleteTenantHandler)
				r.Get("/{tenantID}/barrier/status", s.tenantHandlers.TenantBarrierStatusHandler)
				r.Post("/{tenantID}/barrier/init", s.tenantHandlers.TenantBarrierInitHandler)
				r.Post("/{tenantID}/barrier/unseal", s.tenantHandlers.TenantBarrierUnsealHandler)
			})
		}

		// Password management endpoints
		if s.passwordHandlers != nil {
			r.Route("/passwords", func(r chi.Router) {
				r.Post("/", s.passwordHandlers.AddPasswordHandler)
				r.Get("/", s.passwordHandlers.ListPasswordsHandler)
				r.Get("/{id}", s.passwordHandlers.GetPasswordHandler)
				r.Put("/{id}", s.passwordHandlers.UpdatePasswordHandler)
				r.Delete("/{id}", s.passwordHandlers.DeletePasswordHandler)
				r.Post("/unlock", s.passwordHandlers.UnlockHandler)
				r.Post("/lock", s.passwordHandlers.LockHandler)
				r.Get("/status", s.passwordHandlers.StatusHandler)
				r.Post("/access-mode", s.passwordHandlers.SetAccessModeHandler)
				r.Post("/generate", s.passwordHandlers.GeneratePasswordHandler)
			})
		}

		// Platform store endpoints
		if s.platformHandlers != nil {
			r.Route("/platform", func(r chi.Router) {
				r.Put("/secrets/{key}", s.platformHandlers.PutSecretHandler)
				r.Get("/secrets/{key}", s.platformHandlers.GetSecretHandler)
				r.Delete("/secrets/{key}", s.platformHandlers.DeleteSecretHandler)
				r.Get("/secrets", s.platformHandlers.ListSecretsHandler)
				r.Post("/secrets/{key}/reseal", s.platformHandlers.ResealSecretHandler)
				r.Get("/status", s.platformHandlers.StatusHandler)
			})
		}

		// Policy management endpoints
		if s.policyHandlers != nil {
			r.Route("/policies", func(r chi.Router) {
				r.Post("/", s.policyHandlers.CreatePolicyHandler)
				r.Get("/", s.policyHandlers.ListPoliciesHandler)
				r.Get("/{id}", s.policyHandlers.GetPolicyHandler)
				r.Delete("/{id}", s.policyHandlers.DeletePolicyHandler)
				r.Post("/{id}/refresh", s.policyHandlers.RefreshPolicyHandler)
				r.Post("/{id}/verify", s.policyHandlers.VerifyPolicyHandler)
				r.Get("/{id}/export", s.policyHandlers.ExportPolicyHandler)
			})
		}

		// Init ceremony endpoints
		if s.initHandlers != nil {
			r.Route("/init", func(r chi.Router) {
				r.Get("/status", s.initHandlers.HandleGetStatus)
				r.Post("/claim-cert/begin", s.initHandlers.HandleClaimCertBegin)
				r.Post("/claim-cert/complete", s.initHandlers.HandleClaimCertComplete)
				r.Post("/claim-share", s.initHandlers.HandleClaimShare)
			})
		}

		// Credential management endpoints
		if s.credentialHandlers != nil {
			r.Route("/credentials", func(r chi.Router) {
				r.Post("/submit", s.credentialHandlers.HandleSubmit)
				r.Get("/strategy", s.credentialHandlers.HandleGetStrategy)
			})
		}
	})

	// Bootstrap routes (unauthenticated - needed for initial setup)
	if s.bootstrapHandlers != nil {
		r.Route("/api/v1/bootstrap", func(r chi.Router) {
			r.Get("/status", s.bootstrapHandlers.HandleGetStatus)
			r.Post("/init", s.bootstrapHandlers.HandleInit)
			r.Post("/threshold-init", s.bootstrapHandlers.HandleThresholdInit)
		})
	}

	// go-truststrap bootstrap endpoint (unauthenticated - serves CA bundle for
	// DANE/TLSA and SPKI-pin trust establishment). The upstream go-truststrap
	// library hardcodes this path.
	if s.caHandlers != nil {
		r.Get("/v1/ca/bootstrap", s.caHandlers.HandleGetCABundle)
	} else {
		r.Get("/v1/ca/bootstrap", s.handlers.GetCABundleHandler)
	}

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
			slog.Int("port", s.port),
			slog.String("auth", s.authenticator.Name()))

		if err := s.server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("failed to start HTTPS server: %w", err)
		}
	} else {
		s.logger.Info("Starting HTTP server",
			slog.Int("port", s.port),
			slog.String("auth", s.authenticator.Name()))

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
		s.logger.Error("Failed to shutdown server", slog.String("error", err.Error()))
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
