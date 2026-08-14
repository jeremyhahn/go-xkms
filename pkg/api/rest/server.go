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
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/go-chi/chi/v5"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/pkg/audit"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/auth/token"
	initialize "github.com/jeremyhahn/go-xkms/pkg/init"
	"github.com/jeremyhahn/go-xkms/pkg/metrics"
	"github.com/jeremyhahn/go-xkms/pkg/ratelimit"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/seal/policy"
	credentialspkg "github.com/jeremyhahn/go-xkms/pkg/server/credentials"
	"github.com/jeremyhahn/go-xkms/pkg/staticpw"
	"github.com/jeremyhahn/go-xkms/pkg/webauthn"
	webauthnhttp "github.com/jeremyhahn/go-xkms/pkg/webauthn/http"
	"github.com/jeremyhahn/go-xkms/pkg/webui"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
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
	xkmsService     *xkms.XKMSService
	webauthnHandler *webauthnhttp.Handler
	webauthnStores  *WebAuthnStores
	rbacMiddleware  *RBACMiddleware

	// Custodian handlers
	custodianHandlers   *CustodianHandlers
	shareHandlers       *ShareHandlers
	tenantHandlers      *TenantHandlers
	passwordHandlers    *PasswordHandlers
	pkcs11StateHandlers *PKCS11StateHandlers
	platformHandlers    *SealStoreHandlers
	policyHandlers      *PolicyHandlers
	initHandlers        *InitHandlers
	credentialHandlers  *CredentialHandlers
	authFactorHandlers  *AuthFactorHandlers
	auditHandlers       *AuditHandlers
	caHandlers          *CAHandlers
	clusterHandlers     *ClusterHandlers
	sshHandlers         *SSHHandlers
	sshClient           sdkssh.Client

	// cors carries the CORS policy for the router; nil disables CORS
	// entirely (no headers emitted — correct for the same-origin web UI).
	cors *CORSOptions

	// tokenIssuer mints and rotates the session token pairs behind the
	// /api/v1/auth endpoints. Nil leaves the session surface unmounted.
	tokenIssuer *token.Issuer

	// authUsers resolves TLS client certificates to users via the canonical
	// SPKI-thumbprint binding (PIV/mTLS cert login).
	authUsers auth.UserStore

	// pivLogin configures the cert-login exchange endpoint.
	pivLogin *PIVLoginOptions

	// rbacAuthorizer evaluates the /auth/me UI permission matrix. Nil when
	// RBAC is disabled.
	rbacAuthorizer *auth.Authorizer

	// auditor records authentication-plane audit events when the configured
	// audit logger implements audit.Logger.
	auditor audit.Logger

	// authRateLimiter throttles the login/refresh/ceremony endpoints.
	authRateLimiter *ratelimit.Limiter

	// ui carries the embedded web UI mount options; nil leaves the UI
	// unmounted.
	ui *UIOptions

	// listener, when non-nil, is served directly by Start instead of binding
	// the configured address (loopback launcher: pre-bound 127.0.0.1:0).
	listener net.Listener
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

	// WebAuthnService is an optional, pre-built WebAuthn relying-party service.
	// When provided (together with WebAuthnConfig), the REST server mounts its
	// browser handlers on this exact instance instead of constructing its own.
	// This lets the server share a single WebAuthn service between the REST
	// browser ceremony and the SDK ceremony (via XKMSService.SetWebAuthn), so
	// sessions and credentials live in one place.
	WebAuthnService *webauthn.Service

	// RateLimiter is the rate limiter instance (optional, disables rate limiting if not provided)
	RateLimiter *ratelimit.Limiter

	// WebAuthnUsers is the qrdb user client used to persist WebAuthn users
	// (optional). When set together with WebAuthnKV, the WebAuthn relying
	// party persists users and credentials on qrdb instead of in memory.
	WebAuthnUsers qrdbtransport.UserClient

	// WebAuthnKV is the qrdb KV client used to persist WebAuthn credentials.
	WebAuthnKV qrdbtransport.KVClient

	// WebAuthnTenantID scopes qrdb-backed WebAuthn user creation and lookup.
	WebAuthnTenantID string

	// RBACAuthorizer is the qrdb-backed authorizer. When EnableRBAC is true it
	// is mandatory and gates every protected endpoint against the hosted
	// go-qrdb node's RBAC service, scoped to the request identity's tenant.
	// NewServer fails closed with ErrAuthorizerRequired when EnableRBAC is
	// true and the authorizer is nil or has no backing RBAC client — a server
	// must never run believing it enforces RBAC while allowing every request.
	// Production wiring passes auth.NewAuthorizer with the node's RBAC client;
	// deployments that really want an open gate leave EnableRBAC false.
	RBACAuthorizer *auth.Authorizer

	// EnableRBAC enables role-based access control on API endpoints (default: false)
	// When enabled, users must have appropriate permissions for each operation.
	EnableRBAC bool

	// AuditLogger is the audit logger (optional)
	AuditLogger interface{}

	// Barrier is the optional barrier for seal/unseal lifecycle management
	Barrier *seal.Barrier

	// PINManager is the optional PIN backend for SO/User PIN operations
	PINManager qrdbsdk.PINBackend

	// PasswordStore is the optional static password store
	PasswordStore *staticpw.BackendStore

	// PlatformStore is the optional sealed platform credential store
	PlatformStore seal.PlatformStore

	// PolicyManager is the optional policy manager
	PolicyManager *policy.Manager

	// BarrierRegistry is the optional barrier registry for multi-tenant isolation
	BarrierRegistry *seal.BarrierRegistry

	// CustodianEnabled enables the custodian group REST endpoints. The
	// handlers delegate to the XKMSService servicer, which passes calls
	// through to the embedded go-qrdb node's custodian client. Set true only
	// when the node is available.
	CustodianEnabled bool

	// ShareEnabled enables the Shamir share REST endpoints. The handlers
	// delegate to the XKMSService servicer, which passes calls through to the
	// embedded go-qrdb node's share client. Set true only when the node is
	// available.
	ShareEnabled bool

	// CeremonyService is the optional init ceremony service
	CeremonyService *initialize.CeremonyService

	// CredentialService is the optional credential management service
	CredentialService *credentialspkg.Service

	// CA is the optional CA instance for certificate authority operations.
	// Stored as any to break import cycles. Must implement caServicer methods.
	CA any

	// XKMSService is the injected XKMS service; replaces the package singleton
	// lookup. When set, all handler methods that previously called xkms.Get()
	// will use this service directly.
	XKMSService *xkms.XKMSService

	// SSHClient is the SSH SDK client backing the /xkms/v1/ssh routes. When
	// nil the SSH routes are not mounted. The server composition wires this
	// with a backend provider so SSH key generation honors configured
	// crypto backends.
	SSHClient sdkssh.Client

	// CORS is the cross-origin policy for the REST router. Nil (the default)
	// disables CORS: no CORS headers are emitted and browsers enforce the
	// same-origin policy. The embedded web UI is served same-origin and
	// needs no CORS; only deployments intentionally serving browser clients
	// from another origin should set this.
	CORS *CORSOptions

	// TokenIssuer mints the session token pairs behind the /api/v1/auth
	// endpoints (login, refresh, logout). Nil leaves the session surface
	// unmounted.
	TokenIssuer *token.Issuer

	// AuthUserStore resolves TLS client certificates to users via the
	// canonical SPKI-thumbprint binding for the PIV/mTLS cert-login
	// exchange. Required for PIVLogin.
	AuthUserStore auth.UserStore

	// PIVLogin configures the TLS-client-certificate login exchange at
	// POST /api/v1/auth/login/piv.
	PIVLogin *PIVLoginOptions

	// AuthRateLimiter is a dedicated (stricter) rate limiter applied to the
	// login, refresh, and WebAuthn ceremony endpoints. Optional.
	AuthRateLimiter *ratelimit.Limiter

	// UI configures the embedded single-page web UI. Nil (the default)
	// leaves the UI unmounted and the router serves the API only.
	UI *UIOptions

	// Host is the bind address for the listener (default: all interfaces).
	// The loopback launcher sets "127.0.0.1" so the embedded desktop engine
	// is never reachable off-box.
	Host string

	// Listener, when set, is served directly instead of binding Addr. It lets
	// a caller pre-bind (e.g. 127.0.0.1:0 for an ephemeral port read back via
	// Addr) before Start. Ownership transfers to the server.
	Listener net.Listener
}

// UIOptions configures the embedded single-page web UI served by the REST
// router. The UI mounts after every API route so API paths always win.
type UIOptions struct {
	// Enabled turns the UI mount on. Both Enabled and a non-nil Assets
	// filesystem are required for the UI to be served.
	Enabled bool

	// PathPrefix is the URL prefix the UI is mounted under. Empty selects
	// the default "/ui/".
	PathPrefix string

	// Assets is the compiled SPA filesystem rooted at the vite dist output.
	Assets fs.FS

	// RedirectRoot redirects GET / to the UI prefix with a 302.
	RedirectRoot bool
}

// NewServer creates a new REST API server.
func NewServer(cfg *Config) (*Server, error) {
	if cfg == nil {
		return nil, &errs.Message{Msg: "config is required"}
	}

	if len(cfg.Backends) == 0 {
		return nil, &errs.Message{Msg: "at least one backend is required"}
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

	// The authenticator is mandatory. Substituting a NoOp authenticator for a
	// missing one would silently disable authentication for every route, so an
	// omitted authenticator is an error: selecting auth.NewNoOpAuthenticator()
	// must always be an explicit caller decision.
	authenticator := cfg.Authenticator
	if authenticator == nil {
		return nil, ErrAuthenticatorRequired
	}

	// Set up logger (default to stdlib if not provided)
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}

	// Create handler context and wire the injected XKMS service.
	handlers := NewHandlerContext(cfg.Version)

	// Wire the injected XKMS service so handlers do not use the global singleton.
	if cfg.XKMSService != nil {
		handlers.SetXKMSService(cfg.XKMSService)
	}

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
		xkmsService:     cfg.XKMSService,
		cors:            cfg.CORS,
		tokenIssuer:     cfg.TokenIssuer,
		authUsers:       cfg.AuthUserStore,
		pivLogin:        cfg.PIVLogin,
		rbacAuthorizer:  cfg.RBACAuthorizer,
		authRateLimiter: cfg.AuthRateLimiter,
		ui:              cfg.UI,
	}

	// Authentication-plane audit events flow through the same logger as the
	// rest of the server when it implements the audit contract.
	if al, ok := cfg.AuditLogger.(audit.Logger); ok {
		server.auditor = al
	}

	// User management is served by the qrdb node's native user API; xkms no
	// longer hosts a duplicate user-CRUD surface.

	// Set up RBAC if enabled. Authorization is delegated to the hosted
	// go-qrdb node's RBAC service via the xkms Authorizer; xkms keeps no local
	// role or permission model. The authorizer is mandatory whenever RBAC is
	// enabled: a nil (or RBAC-client-less) authorizer under EnableRBAC would
	// authorize every request while the operator believes RBAC is enforced,
	// so the constructor fails closed instead, mirroring mcp.NewServer. With
	// EnableRBAC false no middleware is wired (rbacMiddleware stays nil and
	// routes register undecorated), which is the documented open-gate
	// configuration.
	if cfg.EnableRBAC {
		if !cfg.RBACAuthorizer.Enabled() {
			return nil, ErrAuthorizerRequired
		}
		server.rbacMiddleware = NewRBACMiddleware(&RBACConfig{
			Authorizer: cfg.RBACAuthorizer,
			Logger:     log,
			SkipPaths: map[string]bool{
				"/health":         true,
				"/health/live":    true,
				"/health/ready":   true,
				"/health/startup": true,
			},
		})
		log.Info("RBAC enabled")
	}

	// Set up WebAuthn if configured.
	if cfg.WebAuthnConfig != nil {
		// Prefer a pre-built service shared with the SDK ceremony (via
		// XKMSService.SetWebAuthn) so sessions and credentials live in one
		// place. Only construct stores + a service locally when the caller did
		// not supply one (e.g. standalone REST usage / tests).
		svc := cfg.WebAuthnService
		if svc == nil {
			var webauthnUserStore webauthn.UserStore
			var sessionStore webauthn.SessionStore
			var credentialStore webauthn.CredentialStore

			// Sessions are ephemeral and always live in memory; persistence
			// applies to users and credentials only.
			stores := NewWebAuthnStores(&WebAuthnStoresConfig{
				SessionTTL: 5 * time.Minute,
			})
			sessionStore = stores.SessionStore()
			server.webauthnStores = stores

			// When the qrdb clients are configured, persist WebAuthn users and
			// credentials on the qrdb node — the single source of identity.
			// Otherwise fall back to in-memory stores for development/testing.
			if cfg.WebAuthnUsers != nil && cfg.WebAuthnKV != nil {
				qrdbUsers, qrdbCreds, qerr := webauthn.NewQRDBUserStoreAdapter(webauthn.QRDBUserStoreOptions{
					Users:    cfg.WebAuthnUsers,
					KV:       cfg.WebAuthnKV,
					TenantID: cfg.WebAuthnTenantID,
				})
				if qerr != nil {
					return nil, &errs.Wrapped{Msg: "failed to create qrdb webauthn stores", Err: qerr}
				}
				webauthnUserStore = qrdbUsers
				credentialStore = qrdbCreds
				log.Info("WebAuthn using qrdb stores for persistence")
			} else {
				webauthnUserStore = stores.UserStore()
				credentialStore = stores.CredentialStore()
				log.Info("WebAuthn using in-memory stores")
			}

			var err error
			svc, err = webauthn.NewService(webauthn.ServiceParams{
				Config:          cfg.WebAuthnConfig,
				UserStore:       webauthnUserStore,
				SessionStore:    sessionStore,
				CredentialStore: credentialStore,
			})
			if err != nil {
				return nil, &errs.Wrapped{Msg: "failed to create webauthn service", Err: err}
			}
		} else {
			log.Info("WebAuthn using shared service instance")
		}

		server.webauthnHandler = webauthnhttp.NewHandler(svc)

		log.Info("WebAuthn enabled",
			slog.String("rpid", cfg.WebAuthnConfig.RPID))
	}

	// Set up custodian handlers when the embedded qrdb node is available.
	if cfg.CustodianEnabled {
		server.custodianHandlers = NewCustodianHandlers(cfg.XKMSService)
		log.Info("Custodian handlers enabled")
	}

	// Cluster handlers are always available: the read-only cluster surface
	// reports a single-node, non-clustered status when the node runs
	// standalone, so callers (CLI, GUI, health probes) work uniformly.
	server.clusterHandlers = NewClusterHandlers(cfg.XKMSService)

	// Set up SSH handlers when an SSH SDK client is wired.
	if cfg.SSHClient != nil {
		sshHandlers, err := NewSSHHandlers(cfg.SSHClient, log)
		if err != nil {
			return nil, err
		}
		server.sshHandlers = sshHandlers
		server.sshClient = cfg.SSHClient
		log.Info("SSH handlers enabled")
	}

	// Set up share handlers when the embedded qrdb node is available.
	if cfg.ShareEnabled {
		server.shareHandlers = NewShareHandlers(cfg.XKMSService)
		log.Info("Share handlers enabled")
	}

	// Set up tenant handlers if barrier registry is configured
	if cfg.BarrierRegistry != nil {
		server.tenantHandlers = NewTenantHandlers(cfg.BarrierRegistry, cfg.XKMSService)
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
		if cfg.XKMSService != nil {
			server.passwordHandlers.SetServicer(cfg.XKMSService)
		}
		log.Info("Password handlers enabled")
	}

	// PKCS#11 remote-state handlers are enabled whenever the service is present;
	// the servicer itself refuses the RPCs if the store was not configured.
	if cfg.XKMSService != nil {
		server.pkcs11StateHandlers = NewPKCS11StateHandlers(cfg.XKMSService)
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

	// Set up auth-factor handlers when the embedded qrdb node is available.
	// Factor state belongs to qrdb; xkms proxies the surface so an operator
	// reaches identity through the same endpoint it uses for keys.
	if cfg.XKMSService != nil {
		server.authFactorHandlers = NewAuthFactorHandlers(cfg.XKMSService, log)
		log.Info("Auth factor handlers enabled")
	}

	// Set up audit handlers alongside them. The chain itself belongs to the
	// qrdb node; this exposes only the read half.
	if cfg.XKMSService != nil {
		server.auditHandlers = NewAuditHandlers(cfg.XKMSService, log)
		log.Info("Audit handlers enabled")
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

	// Create HTTP server. Host defaults to all interfaces; the loopback
	// launcher pins 127.0.0.1.
	httpServer := &http.Server{
		Addr:         net.JoinHostPort(cfg.Host, fmt.Sprintf("%d", cfg.Port)),
		Handler:      router,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		IdleTimeout:  cfg.IdleTimeout,
		TLSConfig:    cfg.TLSConfig,
	}

	server.server = httpServer
	server.listener = cfg.Listener

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
	r.Use(NewCORSMiddleware(s.cors))

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

	// Public capability discovery endpoint (no auth required). It serves
	// only the coarse flags a login page needs to render; the full
	// capability map stays behind authentication at /api/v1/auth/me.
	r.Get("/api/v1/capabilities", s.handleCapabilities)

	// API v1 routes with authentication
	r.Route("/api/v1", func(r chi.Router) {
		// Apply authentication middleware to all API routes
		r.Use(s.AuthenticationMiddleware())

		// Apply tenant enforcement middleware after authentication
		r.Use(s.TenantMiddleware())

		// Backend endpoints
		if s.rbacMiddleware != nil {
			r.With(s.rbacMiddleware.RequirePermission(auth.ResourceBackends, auth.ActionList)).
				Get("/backends", s.handlers.ListBackendsHandler)
			r.With(s.rbacMiddleware.RequirePermission(auth.ResourceBackends, auth.ActionRead)).
				Get("/backends/{id}", s.handlers.GetBackendHandler)
		} else {
			r.Get("/backends", s.handlers.ListBackendsHandler)
			r.Get("/backends/{id}", s.handlers.GetBackendHandler)
		}

		// Key endpoints
		if s.rbacMiddleware != nil {
			r.With(s.rbacMiddleware.RequirePermission(auth.ResourceKeys, auth.ActionCreate)).
				Post("/keys", s.handlers.GenerateKeyHandler)
			r.With(s.rbacMiddleware.RequirePermission(auth.ResourceKeys, auth.ActionList)).
				Get("/keys", s.handlers.ListKeysHandler)
			r.With(s.rbacMiddleware.RequirePermission(auth.ResourceKeys, auth.ActionGet)).
				Get("/keys/{id}", s.handlers.GetKeyHandler)
			r.With(s.rbacMiddleware.RequirePermission(auth.ResourceKeys, auth.ActionDelete)).
				Delete("/keys/{id}", s.handlers.DeleteKeyHandler)

			// Crypto operation endpoints
			r.With(s.rbacMiddleware.RequirePermission(auth.ResourceKeys, auth.ActionSign)).
				Post("/keys/{id}/sign", s.handlers.SignHandler)
			r.With(s.rbacMiddleware.RequirePermission(auth.ResourceKeys, auth.ActionVerify)).
				Post("/keys/{id}/verify", s.handlers.VerifyHandler)
			r.With(s.rbacMiddleware.RequirePermission(auth.ResourceKeys, auth.ActionRotate)).
				Post("/keys/{id}/rotate", s.handlers.RotateKeyHandler)
			r.With(s.rbacMiddleware.RequirePermission(auth.ResourceKeys, auth.ActionEncrypt)).
				Post("/keys/{id}/encrypt", s.handlers.EncryptHandler)
			r.With(s.rbacMiddleware.RequirePermission(auth.ResourceKeys, auth.ActionDecrypt)).
				Post("/keys/{id}/decrypt", s.handlers.DecryptHandler)
			r.With(s.rbacMiddleware.RequirePermission(auth.ResourceKeys, auth.ActionEncrypt)).
				Post("/keys/{id}/encrypt-asym", s.handlers.EncryptAsymHandler)

			// Import/Export endpoints
			r.With(s.rbacMiddleware.RequirePermission(auth.ResourceKeys, auth.ActionImport)).
				Post("/keys/import-params", s.handlers.GetImportParametersHandler)
			r.With(s.rbacMiddleware.RequirePermission(auth.ResourceKeys, auth.ActionEncrypt)).
				Post("/keys/wrap", s.handlers.WrapKeyHandler)
			r.With(s.rbacMiddleware.RequirePermission(auth.ResourceKeys, auth.ActionDecrypt)).
				Post("/keys/unwrap", s.handlers.UnwrapKeyHandler)
			r.With(s.rbacMiddleware.RequirePermission(auth.ResourceKeys, auth.ActionImport)).
				Post("/keys/import", s.handlers.ImportKeyHandler)
			r.With(s.rbacMiddleware.RequirePermission(auth.ResourceKeys, auth.ActionExport)).
				Post("/keys/{id}/export", s.handlers.ExportKeyHandler)
			r.With(s.rbacMiddleware.RequirePermission(auth.ResourceKeys, auth.ActionCreate)).
				Post("/keys/copy", s.handlers.CopyKeyHandler)

			// Hardware-capability key operation endpoints (attestation, ECDH
			// derive, raw key-material export, server-side wrap/unwrap by key
			// ID). "wrap", "unwrap", and "derive" are not exported auth.Action*
			// constants; they are the canonical go-qrdb keys:wrap / keys:unwrap
			// / keys:derive permissions, matching pkg/api/grpc/service.go's
			// s.authorize(ctx, "keys", "wrap"|"unwrap"|"derive", id) calls.
			r.With(s.rbacMiddleware.RequirePermission(auth.ResourceKeys, auth.ActionGet)).
				Post("/attest", s.handlers.AttestKeyHandler)
			r.With(s.rbacMiddleware.RequirePermission(auth.ResourceKeys, "derive")).
				Post("/keys/derive-ecdh", s.handlers.DeriveKeyECDHHandler)
			r.With(s.rbacMiddleware.RequirePermission(auth.ResourceKeys, auth.ActionExport)).
				Post("/keys/{id}/export-material", s.handlers.ExportKeyMaterialHandler)
			r.With(s.rbacMiddleware.RequirePermission(auth.ResourceKeys, "wrap")).
				Post("/keys/wrap-by-id", s.handlers.WrapKeyByIDHandler)
			r.With(s.rbacMiddleware.RequirePermission(auth.ResourceKeys, "unwrap")).
				Post("/keys/unwrap-by-id", s.handlers.UnwrapKeyByIDHandler)
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

			// Hardware-capability key operation endpoints (attestation, ECDH
			// derive, raw key-material export, server-side wrap/unwrap by key
			// ID). See the rbacMiddleware arm above for the authorization
			// resource/action pairs these routes carry when RBAC is enabled.
			r.Post("/attest", s.handlers.AttestKeyHandler)
			r.Post("/keys/derive-ecdh", s.handlers.DeriveKeyECDHHandler)
			r.Post("/keys/{id}/export-material", s.handlers.ExportKeyMaterialHandler)
			r.Post("/keys/wrap-by-id", s.handlers.WrapKeyByIDHandler)
			r.Post("/keys/unwrap-by-id", s.handlers.UnwrapKeyByIDHandler)
		}

		// Certificate endpoints
		if s.rbacMiddleware != nil {
			r.With(s.rbacMiddleware.RequirePermission(auth.ResourceCerts, auth.ActionGenerate)).
				Post("/certs", s.handlers.SaveCertHandler)
			r.With(s.rbacMiddleware.RequirePermission(auth.ResourceCerts, auth.ActionList)).
				Get("/certs", s.handlers.ListCertsHandler)
			r.With(s.rbacMiddleware.RequirePermission(auth.ResourceCerts, auth.ActionRead)).
				Get("/certs/{id}", s.handlers.GetCertHandler)
			r.With(s.rbacMiddleware.RequirePermission(auth.ResourceCerts, auth.ActionRevoke)).
				Delete("/certs/{id}", s.handlers.DeleteCertHandler)
			r.With(s.rbacMiddleware.RequirePermission(auth.ResourceCerts, auth.ActionRead)).
				Head("/certs/{id}", s.handlers.CertExistsHandler)
			r.With(s.rbacMiddleware.RequirePermission(auth.ResourceCerts, auth.ActionGenerate)).
				Post("/certs/{id}/chain", s.handlers.SaveCertChainHandler)
			r.With(s.rbacMiddleware.RequirePermission(auth.ResourceCerts, auth.ActionRead)).
				Get("/certs/{id}/chain", s.handlers.GetCertChainHandler)

			// TLS helper endpoint
			r.With(s.rbacMiddleware.RequirePermission(auth.ResourceCerts, auth.ActionRead)).
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
			r.With(s.rbacMiddleware.RequirePermission(auth.ResourceKeys, auth.ActionEncrypt)).
				Post("/seal", s.handlers.SealHandler)
			r.With(s.rbacMiddleware.RequirePermission(auth.ResourceKeys, auth.ActionDecrypt)).
				Post("/unseal", s.handlers.UnsealHandler)
			r.With(s.rbacMiddleware.RequirePermission(auth.ResourceKeys, auth.ActionGet)).
				Get("/seal/capability", s.handlers.CanSealHandler)
		} else {
			r.Post("/seal", s.handlers.SealHandler)
			r.Post("/unseal", s.handlers.UnsealHandler)
			r.Get("/seal/capability", s.handlers.CanSealHandler)
		}

		// FROST threshold signature endpoints. FROST operates on threshold key
		// material, so every route carries the keys:* permission its
		// single-key equivalent above carries: the three signing rounds
		// (nonces, sign, aggregate) are steps of producing a signature and take
		// keys:sign, exactly as the QUIC handlers (pkg/api/quic/handlers_frost.go)
		// and the MCP frost.* methodPermissions map (pkg/api/mcp/authz.go) gate
		// them. Registering these without the decorator let any authenticated
		// caller generate, import, sign with, and delete threshold shares.
		r.Route("/frost", func(r chi.Router) {
			if s.rbacMiddleware != nil {
				// Key management
				r.With(s.rbacMiddleware.RequirePermission(auth.ResourceKeys, auth.ActionCreate)).
					Post("/keys", s.handlers.FrostGenerateKeyHandler)
				r.With(s.rbacMiddleware.RequirePermission(auth.ResourceKeys, auth.ActionImport)).
					Post("/keys/import", s.handlers.FrostImportKeyHandler)
				r.With(s.rbacMiddleware.RequirePermission(auth.ResourceKeys, auth.ActionList)).
					Get("/keys", s.handlers.FrostListKeysHandler)
				r.With(s.rbacMiddleware.RequirePermission(auth.ResourceKeys, auth.ActionGet)).
					Get("/keys/{id}", s.handlers.FrostGetKeyHandler)
				r.With(s.rbacMiddleware.RequirePermission(auth.ResourceKeys, auth.ActionDelete)).
					Delete("/keys/{id}", s.handlers.FrostDeleteKeyHandler)

				// Signing operations
				r.With(s.rbacMiddleware.RequirePermission(auth.ResourceKeys, auth.ActionSign)).
					Post("/keys/{id}/nonces", s.handlers.FrostGenerateNoncesHandler)
				r.With(s.rbacMiddleware.RequirePermission(auth.ResourceKeys, auth.ActionSign)).
					Post("/keys/{id}/sign", s.handlers.FrostSignRoundHandler)

				// Aggregation and verification
				r.With(s.rbacMiddleware.RequirePermission(auth.ResourceKeys, auth.ActionSign)).
					Post("/aggregate", s.handlers.FrostAggregateHandler)
				r.With(s.rbacMiddleware.RequirePermission(auth.ResourceKeys, auth.ActionVerify)).
					Post("/verify", s.handlers.FrostVerifyHandler)
			} else {
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
			}
		})

		// Barrier management endpoints. The resource:action pairs mirror the
		// MCP barrier.* methodPermissions map (pkg/api/mcp/authz.go) and the
		// QUIC barrier handlers one-for-one.
		r.Route("/barrier", func(r chi.Router) {
			if s.rbacMiddleware != nil {
				r.With(s.rbacMiddleware.RequirePermission(auth.ResourceSeal, auth.ActionBootstrap)).
					Post("/initialize", s.handlers.BarrierInitializeHandler)
				r.With(s.rbacMiddleware.RequirePermission(auth.ResourceSeal, auth.ActionUnseal)).
					Post("/unseal", s.handlers.BarrierUnsealHandler)
				r.With(s.rbacMiddleware.RequirePermission(auth.ResourceSeal, auth.ActionSeal)).
					Post("/seal", s.handlers.BarrierSealHandler)
				r.With(s.rbacMiddleware.RequirePermission(auth.ResourceSeal, auth.ActionStatus)).
					Get("/status", s.handlers.BarrierStatusHandler)

				// Shamir secret sharing endpoints
				r.With(s.rbacMiddleware.RequirePermission(auth.ResourceSeal, auth.ActionInitializeShamir)).
					Post("/shamir/initialize", s.handlers.BarrierInitializeShamirHandler)
				r.With(s.rbacMiddleware.RequirePermission(auth.ResourceBarrier, auth.ActionUnsealShare)).
					Post("/shamir/unseal-share", s.handlers.BarrierUnsealShareHandler)
				r.With(s.rbacMiddleware.RequirePermission(auth.ResourceSeal, auth.ActionUnseal)).
					Post("/shamir/unseal-shares", s.handlers.BarrierUnsealSharesHandler)

				// Rekey and recovery endpoints
				r.With(s.rbacMiddleware.RequirePermission(auth.ResourceSeal, auth.ActionRekey)).
					Post("/rekey", s.handlers.BarrierRekeyHandler)
				r.With(s.rbacMiddleware.RequirePermission(auth.ResourceSeal, auth.ActionGenerateRecovery)).
					Post("/recovery/generate", s.handlers.BarrierGenerateRecoveryKeysHandler)
				r.With(s.rbacMiddleware.RequirePermission(auth.ResourceSeal, auth.ActionRecoverWithKeys)).
					Post("/recovery/recover", s.handlers.BarrierRecoverWithKeysHandler)
				r.With(s.rbacMiddleware.RequirePermission(auth.ResourceSeal, auth.ActionGenerateRecovery)).
					Delete("/recovery/keys", s.handlers.BarrierDeleteRecoveryKeysHandler)
				r.With(s.rbacMiddleware.RequirePermission(auth.ResourceSeal, auth.ActionRotateRootKey)).
					Post("/recovery/root-token", s.handlers.BarrierGenerateRootTokenHandler)

				// Enable at-rest encryption on an unencrypted barrier (migration).
				r.With(s.rbacMiddleware.RequirePermission(auth.ResourceSeal, auth.ActionEnableEncryption)).
					Post("/enable-encryption", s.handlers.BarrierEnableEncryptionHandler)
			} else {
				r.Post("/initialize", s.handlers.BarrierInitializeHandler)
				r.Post("/unseal", s.handlers.BarrierUnsealHandler)
				r.Post("/seal", s.handlers.BarrierSealHandler)
				r.Get("/status", s.handlers.BarrierStatusHandler)

				// Shamir secret sharing endpoints
				r.Post("/shamir/initialize", s.handlers.BarrierInitializeShamirHandler)
				r.Post("/shamir/unseal-share", s.handlers.BarrierUnsealShareHandler)
				r.Post("/shamir/unseal-shares", s.handlers.BarrierUnsealSharesHandler)

				// Rekey and recovery endpoints
				r.Post("/rekey", s.handlers.BarrierRekeyHandler)
				r.Post("/recovery/generate", s.handlers.BarrierGenerateRecoveryKeysHandler)
				r.Post("/recovery/recover", s.handlers.BarrierRecoverWithKeysHandler)
				r.Delete("/recovery/keys", s.handlers.BarrierDeleteRecoveryKeysHandler)
				r.Post("/recovery/root-token", s.handlers.BarrierGenerateRootTokenHandler)

				// Enable at-rest encryption on an unencrypted barrier (migration).
				r.Post("/enable-encryption", s.handlers.BarrierEnableEncryptionHandler)
			}
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

		// Cluster endpoints. Reads are gated with backends:read when RBAC is
		// enabled, mirroring the read-protection on the backends surface; the
		// servicer reports single-node status when the node runs standalone, so
		// the read routes are always registered and reachable.
		//
		// Membership mutation (add/remove replica) is privileged and is gated on
		// the canonical qrdb admin:add_member / admin:remove_member permissions
		// via auth.ResourceClusterAdmin. Unlike the read routes, mutation FAILS
		// CLOSED when RBAC is not wired: it reconfigures the Raft group, so an
		// operator running without RBAC gets an explicit 403
		// (denyClusterMutationHandler) rather than an ungated reconfiguration
		// endpoint.
		if s.clusterHandlers != nil {
			r.Route("/cluster", func(r chi.Router) {
				if s.rbacMiddleware != nil {
					r.With(s.rbacMiddleware.RequirePermission(auth.ResourceClusterAdmin, auth.ActionClusterStatus)).
						Get("/status", s.clusterHandlers.StatusHandler)
					r.With(s.rbacMiddleware.RequirePermission(auth.ResourceClusterAdmin, auth.ActionClusterPeers)).
						Get("/members", s.clusterHandlers.MembersHandler)
					r.With(s.rbacMiddleware.RequirePermission(auth.ResourceClusterAdmin, auth.ActionAddMember)).
						Post("/members", s.clusterHandlers.AddReplicaHandler)
					r.With(s.rbacMiddleware.RequirePermission(auth.ResourceClusterAdmin, auth.ActionRemoveMember)).
						Delete("/members/{replicaID}", s.clusterHandlers.RemoveReplicaHandler)
				} else {
					r.Get("/status", s.clusterHandlers.StatusHandler)
					r.Get("/members", s.clusterHandlers.MembersHandler)
					r.Post("/members", denyClusterMutationHandler)
					r.Delete("/members/{replicaID}", denyClusterMutationHandler)
				}
			})
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
				r.Put("/{tenantID}/entitlements", s.tenantHandlers.UpdateTenantEntitlementsHandler)
				r.Put("/{tenantID}/quotas", s.tenantHandlers.UpdateTenantQuotasHandler)
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

		// PKCS#11 remote-state endpoints. Records are a token's key/object
		// state, so they gate on the keys resource. All POST with a JSON body so
		// an opaque binary value never rides in a URL.
		if s.pkcs11StateHandlers != nil {
			r.Route("/pkcs11state", func(r chi.Router) {
				r.With(s.rbacMiddleware.RequirePermission(auth.ResourceKeys, auth.ActionCreate)).
					Post("/put", s.pkcs11StateHandlers.PutHandler)
				r.With(s.rbacMiddleware.RequirePermission(auth.ResourceKeys, auth.ActionCreate)).
					Post("/put-if-absent", s.pkcs11StateHandlers.PutIfAbsentHandler)
				r.With(s.rbacMiddleware.RequirePermission(auth.ResourceKeys, auth.ActionUpdate)).
					Post("/compare-and-swap", s.pkcs11StateHandlers.CASHandler)
				r.With(s.rbacMiddleware.RequirePermission(auth.ResourceKeys, auth.ActionGet)).
					Post("/get", s.pkcs11StateHandlers.GetHandler)
				r.With(s.rbacMiddleware.RequirePermission(auth.ResourceKeys, auth.ActionDelete)).
					Post("/delete", s.pkcs11StateHandlers.DeleteHandler)
				r.With(s.rbacMiddleware.RequirePermission(auth.ResourceKeys, auth.ActionList)).
					Post("/list", s.pkcs11StateHandlers.ListHandler)
			})
		}

		// Platform store endpoints
		if s.platformHandlers != nil {
			r.Route("/platform", func(r chi.Router) {
				// Placeholder must be {name}: the handlers read
				// chi.URLParam(r, "name") — a mismatched placeholder hands
				// every keyed operation an empty secret name.
				r.Put("/secrets/{name}", s.platformHandlers.PutSecretHandler)
				r.Get("/secrets/{name}", s.platformHandlers.GetSecretHandler)
				r.Delete("/secrets/{name}", s.platformHandlers.DeleteSecretHandler)
				r.Get("/secrets", s.platformHandlers.ListSecretsHandler)
				r.Post("/secrets/{name}/reseal", s.platformHandlers.ResealSecretHandler)
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

		// Init ceremony endpoints.
		//
		// status, claim-cert/begin, claim-cert/complete and both halves of
		// claim-share are reachable without an *account* while the ceremony
		// has not yet reached the operational state -- see
		// publicCeremonyPaths in middleware_init_public.go. The two
		// claim-share routes still require a client certificate: the officer
		// certificate thumbprint IS their authentication, and the handlers
		// refuse a request that carries no verified mTLS peer certificate.
		// sign-csr is NOT in that allowlist: it stays behind authentication
		// (and RBAC, when enabled) exactly as the QUIC and MCP transports
		// gate it.
		if s.initHandlers != nil {
			r.Route("/init", func(r chi.Router) {
				r.Get("/status", s.initHandlers.HandleGetStatus)
				r.Post("/claim-cert/begin", s.initHandlers.HandleClaimCertBegin)
				r.Post("/claim-cert/complete", s.initHandlers.HandleClaimCertComplete)
				r.Post("/claim-share/begin", s.initHandlers.HandleClaimShareBegin)
				r.Post("/claim-share/complete", s.initHandlers.HandleClaimShareComplete)

				if s.rbacMiddleware != nil {
					r.With(s.rbacMiddleware.RequirePermission(auth.ResourceCeremony, auth.ActionSignCSR)).
						Post("/sign-csr", s.initHandlers.HandleSignCSRInit)
				} else {
					r.Post("/sign-csr", s.initHandlers.HandleSignCSRInit)
				}

				// Security Officer enrolment. Like sign-csr these are NOT in
				// the public ceremony allowlist: registering an officer binds
				// a Shamir share index to a certificate, so it stays behind
				// authentication (and RBAC, when enabled) on every transport.
				if s.rbacMiddleware != nil {
					r.With(s.rbacMiddleware.RequirePermission(auth.ResourceCeremony, auth.ActionSignCSR)).
						Post("/officer/register", s.initHandlers.HandleOfficerRegister)
					r.With(s.rbacMiddleware.RequirePermission(auth.ResourceCeremony, auth.ActionSignCSR)).
						Post("/enroll-external-officer", s.initHandlers.HandleEnrollExternalOfficer)
				} else {
					r.Post("/officer/register", s.initHandlers.HandleOfficerRegister)
					r.Post("/enroll-external-officer", s.initHandlers.HandleEnrollExternalOfficer)
				}

				// Status is read-only public metadata (never share bytes), so
				// it sits alongside the other read verbs.
				r.Get("/officer/status", s.initHandlers.HandleOfficerStatus)
			})
		}

		// Credential management endpoints
		if s.credentialHandlers != nil {
			r.Route("/credentials", func(r chi.Router) {
				r.Post("/submit", s.credentialHandlers.HandleSubmit)
				r.Get("/strategy", s.credentialHandlers.HandleGetStrategy)
				r.Get("/", s.credentialHandlers.HandleList)
			})
		}

		// User-side N-factor endpoints. Factor state is qrdb's; these proxy
		// it so identity is reachable on the same endpoint as everything
		// else. Reads are users:read, mutations users:update — enrolling or
		// revoking someone's factor changes who can log in as them.
		if s.authFactorHandlers != nil {
			r.Route("/factors", func(r chi.Router) {
				if s.rbacMiddleware != nil {
					r.With(s.rbacMiddleware.RequirePermission(auth.ResourceUsers, auth.ActionRead)).
						Get("/", s.authFactorHandlers.ListHandler)
					r.With(s.rbacMiddleware.RequirePermission(auth.ResourceUsers, auth.ActionUpdate)).
						Post("/", s.authFactorHandlers.AddHandler)
					r.With(s.rbacMiddleware.RequirePermission(auth.ResourceUsers, auth.ActionRead)).
						Post("/login", s.authFactorHandlers.LoginHandler)
					r.With(s.rbacMiddleware.RequirePermission(auth.ResourceUsers, auth.ActionRead)).
						Get("/{factorID}", s.authFactorHandlers.GetHandler)
					r.With(s.rbacMiddleware.RequirePermission(auth.ResourceUsers, auth.ActionUpdate)).
						Delete("/{factorID}", s.authFactorHandlers.RemoveHandler)
					r.With(s.rbacMiddleware.RequirePermission(auth.ResourceUsers, auth.ActionUpdate)).
						Patch("/{factorID}", s.authFactorHandlers.RelabelHandler)
					r.With(s.rbacMiddleware.RequirePermission(auth.ResourceUsers, auth.ActionUpdate)).
						Post("/{factorID}/rotate", s.authFactorHandlers.RotateHandler)
				} else {
					r.Get("/", s.authFactorHandlers.ListHandler)
					r.Post("/", s.authFactorHandlers.AddHandler)
					r.Post("/login", s.authFactorHandlers.LoginHandler)
					r.Get("/{factorID}", s.authFactorHandlers.GetHandler)
					r.Delete("/{factorID}", s.authFactorHandlers.RemoveHandler)
					r.Patch("/{factorID}", s.authFactorHandlers.RelabelHandler)
					r.Post("/{factorID}/rotate", s.authFactorHandlers.RotateHandler)
				}
			})
		}

		// Audit chain, read-only. The log records who did what to the rest of
		// this API, so reading it is its own permission rather than a freebie
		// for anyone already authenticated — audit:read, never keys:* or
		// users:*. There is no write route by design.
		if s.auditHandlers != nil {
			r.Route("/audit", func(r chi.Router) {
				if s.rbacMiddleware != nil {
					r.With(s.rbacMiddleware.RequirePermission(auth.ResourceAudit, auth.ActionRead)).
						Get("/", s.auditHandlers.QueryHandler)
				} else {
					r.Get("/", s.auditHandlers.QueryHandler)
				}
			})
		}
	})

	// go-truststrap bootstrap endpoint (unauthenticated - serves CA bundle for
	// DANE/TLSA and SPKI-pin trust establishment). The upstream go-truststrap
	// library hardcodes this path and expects raw PEM (Content-Type
	// application/pem-certificate-chain), not the JSON envelope that the
	// CAHandlers path returns.
	r.Get("/v1/ca/bootstrap", s.handlers.GetCABundleHandler)

	// Session endpoints. The exchange endpoints (cert login, refresh) are
	// unauthenticated — they ARE the authentication; the introspection
	// endpoints (me, validate, logout) require a live session. All of them
	// sit behind the dedicated login rate limiter.
	if s.tokenIssuer != nil {
		r.Route("/api/v1/auth", func(ar chi.Router) {
			if s.authRateLimiter != nil && s.authRateLimiter.IsEnabled() {
				ar.Use(ratelimit.Middleware(s.authRateLimiter))
			}

			ar.Post("/login/piv", s.handlePIVLogin)
			ar.Post("/refresh", s.handleAuthRefresh)

			ar.Group(func(g chi.Router) {
				g.Use(s.AuthenticationMiddleware())
				g.Get("/me", s.handleAuthMe)
				g.Get("/validate", s.handleAuthValidate)
				g.Post("/logout", s.handleAuthLogout)
			})
		})
	}

	// WebAuthn routes (no auth required - WebAuthn IS the auth mechanism)
	if s.webauthnHandler != nil {
		r.Route("/api/v1/webauthn", func(r chi.Router) {
			if s.authRateLimiter != nil && s.authRateLimiter.IsEnabled() {
				r.Use(ratelimit.Middleware(s.authRateLimiter))
			}
			webauthnhttp.MountChi(r, s.webauthnHandler)

			// SDK registration ceremony: lossless JSON options + attestation,
			// delegated to the XKMSService (which shares the same WebAuthn
			// service instance as the browser handlers above).
			r.Post("/sdk/registration/begin", s.handleSDKBeginRegistration)
			r.Post("/sdk/registration/finish", s.handleSDKFinishRegistration)

			// SDK authentication ceremony: lossless JSON options + assertion,
			// symmetric to the registration ceremony above.
			r.Post("/sdk/authentication/begin", s.handleSDKBeginAuthentication)
			r.Post("/sdk/authentication/finish", s.handleSDKFinishAuthentication)
		})
	}

	// User management. xkms presents its own user API; the backing store is
	// the embedded qrdb node (reached via the XKMSService). The CLI/webui drive
	// these endpoints through the xkms SDK.
	r.Route("/api/v1/users", func(r chi.Router) {
		r.Use(s.AuthenticationMiddleware())

		if s.rbacMiddleware != nil {
			r.With(s.rbacMiddleware.RequirePermission(auth.ResourceUsers, auth.ActionCreate)).
				Post("/", s.handleCreateUser)
			r.With(s.rbacMiddleware.RequirePermission(auth.ResourceUsers, auth.ActionList)).
				Get("/", s.handleListUsers)
			r.With(s.rbacMiddleware.RequirePermission(auth.ResourceUsers, auth.ActionRead)).
				Get("/{username}", s.handleGetUser)
			r.With(s.rbacMiddleware.RequirePermission(auth.ResourceUsers, auth.ActionRead)).
				Get("/{username}/credentials", s.handleListUserCredentials)
			r.With(s.rbacMiddleware.RequirePermission(auth.ResourceUsers, auth.ActionUpdate)).
				Put("/{username}", s.handleUpdateUser)
			r.With(s.rbacMiddleware.RequirePermission(auth.ResourceUsers, auth.ActionUpdate)).
				Post("/{username}/cert-bindings", s.handleBindUserCert)
			r.With(s.rbacMiddleware.RequirePermission(auth.ResourceUsers, auth.ActionDelete)).
				Delete("/{username}", s.handleDeleteUser)
		} else {
			r.Post("/", s.handleCreateUser)
			r.Get("/", s.handleListUsers)
			r.Get("/{username}", s.handleGetUser)
			r.Get("/{username}/credentials", s.handleListUserCredentials)
			r.Put("/{username}", s.handleUpdateUser)
			r.Post("/{username}/cert-bindings", s.handleBindUserCert)
			r.Delete("/{username}", s.handleDeleteUser)
		}
	})

	// SSH routes register under their own /xkms/v1/ssh prefix at the root.
	// They carry the same authentication and tenant enforcement as /api/v1,
	// plus a blanket ssh:use RBAC gate when RBAC is enabled — SSH key
	// generation and signing are privileged operations and must never be
	// reachable anonymously.
	if s.sshHandlers != nil {
		r.Group(func(g chi.Router) {
			g.Use(s.AuthenticationMiddleware())
			g.Use(s.TenantMiddleware())
			if s.rbacMiddleware != nil {
				g.Use(s.rbacMiddleware.RequirePermission(auth.ResourceSSH, auth.ActionUse))
			}
			s.sshHandlers.Register(g)
		})

		// No interactive SSH console is served here, by design. xkmsd is a key
		// vault and CA: it stores SSH keys and signs authentication challenges
		// with them (POST /keys/{scope}/{owner}/{name}/sign), and the SSH
		// session itself is established by the client (xkey) that holds the
		// connection. Terminating SSH on the vault would let any authenticated
		// caller make the appliance open outbound connections to arbitrary
		// hosts and proxy an interactive shell through them — server-side
		// request forgery, a network pivot, and remote code execution against
		// the target, all from the one host that must not offer them.
	}

	// Embedded web UI. Mounted last so every API route above always wins;
	// the SPA handler only ever sees paths under its own prefix (plus the
	// optional root redirect). All UI responses carry the browser security
	// headers via the UI-scoped middleware.
	if s.ui != nil && s.ui.Enabled && s.ui.Assets != nil {
		prefix, err := webui.NormalizePrefix(s.ui.PathPrefix)
		if err != nil {
			s.logger.Error("web UI not mounted: invalid path prefix",
				slog.String("prefix", s.ui.PathPrefix), slog.Any("error", err))
			return r
		}

		r.Group(func(g chi.Router) {
			g.Use(SecurityHeadersMiddleware)
			if mountErr := webui.MountChi(g, s.ui.Assets, prefix, s.logger); mountErr != nil {
				s.logger.Error("failed to mount web UI", slog.Any("error", mountErr))
			}
		})

		if s.ui.RedirectRoot {
			r.Get("/", func(w http.ResponseWriter, req *http.Request) {
				http.Redirect(w, req, prefix, http.StatusFound)
			})
		}
	}

	return r
}

// Start starts the REST API server.
func (s *Server) Start() error {
	// Prefer a caller-supplied pre-bound listener (loopback launcher). When
	// absent, bind the configured address.
	if s.listener != nil {
		s.logger.Info("Starting HTTP server on injected listener",
			slog.String("addr", s.listener.Addr().String()),
			slog.Bool("tls", s.tlsConfig != nil),
			slog.String("auth", s.authenticator.Name()))
		var err error
		if s.tlsConfig != nil {
			err = s.server.ServeTLS(s.listener, "", "")
		} else {
			err = s.server.Serve(s.listener)
		}
		if err != nil && err != http.ErrServerClosed {
			return &errs.Wrapped{Msg: "failed to serve on injected listener", Err: err}
		}
		return nil
	}

	if s.tlsConfig != nil {
		s.logger.Info("Starting HTTPS server",
			slog.Int("port", s.port),
			slog.String("auth", s.authenticator.Name()))

		if err := s.server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			return &errs.Wrapped{Msg: "failed to start HTTPS server", Err: err}
		}
	} else {
		s.logger.Info("Starting HTTP server",
			slog.Int("port", s.port),
			slog.String("auth", s.authenticator.Name()))

		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			return &errs.Wrapped{Msg: "failed to start HTTP server", Err: err}
		}
	}

	return nil
}

// Addr returns the address the server is bound to. When an injected listener
// is in use (loopback launcher with an ephemeral port), it reports the real
// resolved address; otherwise the configured bind address.
func (s *Server) Addr() net.Addr {
	if s.listener != nil {
		return s.listener.Addr()
	}
	return nil
}

// Handler returns the server's fully configured HTTP handler, with every
// route, middleware, and RBAC decorator attached. It lets callers exercise the
// real routing stack — including out-of-package tests that must reach the
// routes without binding a port.
func (s *Server) Handler() http.Handler {
	return s.server.Handler
}

// Stop gracefully stops the REST API server.
func (s *Server) Stop(ctx context.Context) error {
	s.logger.Info("Shutting down server")

	if err := s.server.Shutdown(ctx); err != nil {
		s.logger.Error("Failed to shutdown server", slog.String("error", err.Error()))
		return &errs.Wrapped{Msg: "failed to shutdown server", Err: err}
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
