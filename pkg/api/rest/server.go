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
	"strings"
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
	bootstrapHandlers   *BootstrapHandlers
	caHandlers          *CAHandlers
	sshHandlers         *SSHHandlers
	sshClient           sdkssh.Client
	clusterHandlers     *ClusterHandlers

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

	// trustedProxies resolves the client IP both rate limiters key on; nil
	// trusts no forwarding header.
	trustedProxies *ratelimit.TrustedProxies

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

	// ReadHeaderTimeout is the maximum duration for reading the request
	// headers (default: 10s). It bounds a slow-header (Slowloris) client
	// independently of the whole-request ReadTimeout.
	ReadHeaderTimeout time.Duration

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

	// TrustedProxies are the reverse proxies allowed to name the client in
	// X-Forwarded-For / X-Real-IP for the rate limiters. Nil (the default)
	// trusts none: every request is keyed on its transport peer's IP.
	TrustedProxies *ratelimit.TrustedProxies

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
	if cfg.ReadHeaderTimeout == 0 {
		cfg.ReadHeaderTimeout = 10 * time.Second
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
		trustedProxies:  cfg.TrustedProxies,
		ui:              cfg.UI,
		// Cluster status/membership reads must work on a standalone node
		// (degrading gracefully rather than requiring an "enabled" gate), so
		// unlike the other optional handler groups below, clusterHandlers is
		// constructed unconditionally, exactly like handlers above.
		clusterHandlers: NewClusterHandlers(cfg.XKMSService),
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
				AuditLogger:     server.auditor,
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

	// Set up tenant handlers if barrier registry is configured. TenantService
	// must already be composed on cfg.XKMSService; NewTenantHandlers rejects
	// a barrier registry without one rather than falling back to direct
	// barrier-registry tenant operations.
	if cfg.BarrierRegistry != nil {
		tenantHandlers, err := NewTenantHandlers(cfg.BarrierRegistry, cfg.XKMSService)
		if err != nil {
			return nil, err
		}
		server.tenantHandlers = tenantHandlers
		log.Info("Tenant handlers enabled")
	}

	// Set up password handlers if password store is configured. pwManager
	// here is used only to resolve the correctly-scoped store for the CRUD
	// handlers (add/list/get/update/delete/generate), which need no session
	// state. Session-affecting operations (unlock, lock, status) are handled
	// entirely through the servicer set below via SetServicer: XKMSService
	// owns the TenantPasswordStoreManager instance session state is tracked
	// against (wired by the process composition root), so routing those three
	// through a second, independently constructed manager here would risk
	// reporting state that has drifted from what the servicer actually did.
	//
	// staticpw.NewTenantPasswordStoreManager can only fail on a nil registry
	// or nil store, both already excluded by the surrounding conditions, so
	// managerErr is unreachable today; it stays a checked error rather than a
	// silent construction because that invariant belongs to staticpw, not to
	// this wiring.
	if cfg.PasswordStore != nil {
		var pwManager *staticpw.TenantPasswordStoreManager
		if cfg.BarrierRegistry != nil {
			var managerErr error
			pwManager, managerErr = staticpw.NewTenantPasswordStoreManager(cfg.BarrierRegistry, cfg.PasswordStore)
			if managerErr != nil {
				log.Warn("Failed to create tenant password store manager; per-tenant password CRUD routing unavailable", "error", managerErr)
			} else {
				log.Info("Tenant password store manager enabled for per-tenant CRUD routing")
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

	// Set up bootstrap-listener-key handlers. The listener publishes its own
	// public keys into cfg.XKMSService once started (pkg/server); the
	// handler here only ever reads them.
	if cfg.XKMSService != nil {
		server.bootstrapHandlers = NewBootstrapHandlers(cfg.XKMSService, log)
		log.Info("Bootstrap listener key handlers enabled")
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
		Addr:              net.JoinHostPort(cfg.Host, fmt.Sprintf("%d", cfg.Port)),
		Handler:           router,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
		TLSConfig:         cfg.TLSConfig,
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
		r.Use(ratelimit.Middleware(s.rateLimiter, s.trustedProxies))
		s.logger.Info("Rate limiting enabled for REST API")
	}

	// Innermost global middleware: binds the request to the ResponseWriter
	// so writeError can log an internal error it withholds from the client
	// with the request's method, path and correlation ID (go-xkms#1118).
	r.Use(s.errorLogMiddleware())

	// Route registration is table-driven: Routes() (routes.go) is the
	// single source of truth for the REST surface, shared with the
	// unified-API-server ServiceModule (pkg/apimodule). Routes are grouped
	// by middleware profile; a route whose Enabled guard reports false is
	// not served.
	s.registerRoutes(r)

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

// registerRoutes registers the full table-driven route surface onto r,
// applying each RouteGroup's middleware profile and the per-route RBAC
// decorator. Routes whose Enabled guard reports false are skipped: their
// backing subsystem is not configured on this server.
func (s *Server) registerRoutes(r chi.Router) {
	byGroup := map[RouteGroup][]RouteSpec{}
	for _, spec := range Routes() {
		if spec.Enabled != nil && !spec.Enabled(s) {
			continue
		}
		byGroup[spec.Group] = append(byGroup[spec.Group], spec)
	}

	// Every route's body is bounded (BodyLimitMiddleware, RouteSpec
	// MaxBodyBytes); permission routes are additionally RBAC-decorated.
	register := func(g chi.Router, spec RouteSpec) {
		var chain []func(http.Handler) http.Handler
		if spec.Auth == RouteAuthPermission && s.rbacMiddleware != nil {
			chain = append(chain, s.rbacMiddleware.RequirePermission(spec.Resource, spec.Action))
		}
		chain = append(chain, BodyLimitMiddleware(spec.bodyLimit()))
		g.With(chain...).MethodFunc(spec.Method, spec.Pattern, spec.Handler(s))
	}

	// Root routes: no group middleware (health, discovery, bootstrap).
	for _, spec := range byGroup[GroupRoot] {
		register(r, spec)
	}

	// /api/v1 is a mounted sub-router so its authentication + tenant
	// middleware run for every request under the prefix — an unmatched
	// /api/v1/* path answers 401 before 404, exactly as before the
	// table-driven conversion (the init-ceremony exemption tests pin this).
	relative := func(spec RouteSpec, prefix string) string {
		return strings.TrimPrefix(spec.Pattern, prefix)
	}
	r.Route("/api/v1", func(g chi.Router) {
		g.Use(s.AuthenticationMiddleware())
		g.Use(s.TenantMiddleware())
		for _, spec := range byGroup[GroupAPIv1] {
			spec.Pattern = relative(spec, "/api/v1")
			register(g, spec)
		}
	})

	// Session endpoints: login rate limiter; the exchange endpoints are
	// unauthenticated, introspection requires a live session.
	if specs := byGroup[GroupAuthSession]; len(specs) > 0 {
		r.Route("/api/v1/auth", func(g chi.Router) {
			if s.authRateLimiter != nil && s.authRateLimiter.IsEnabled() {
				g.Use(ratelimit.Middleware(s.authRateLimiter, s.trustedProxies))
			}
			for _, spec := range specs {
				spec.Pattern = relative(spec, "/api/v1/auth")
				if spec.Auth == RouteAuthSession {
					g.With(s.AuthenticationMiddleware(), BodyLimitMiddleware(spec.bodyLimit())).
						MethodFunc(spec.Method, spec.Pattern, spec.Handler(s))
					continue
				}
				register(g, spec)
			}
		})
	}

	// WebAuthn: rate-limited, unauthenticated (WebAuthn IS the auth).
	if specs := byGroup[GroupWebAuthn]; len(specs) > 0 {
		r.Route("/api/v1/webauthn", func(g chi.Router) {
			if s.authRateLimiter != nil && s.authRateLimiter.IsEnabled() {
				g.Use(ratelimit.Middleware(s.authRateLimiter, s.trustedProxies))
			}
			for _, spec := range specs {
				spec.Pattern = relative(spec, "/api/v1/webauthn")
				register(g, spec)
			}
		})
	}

	// Users: authentication only.
	if specs := byGroup[GroupUsers]; len(specs) > 0 {
		r.Route("/api/v1/users", func(g chi.Router) {
			g.Use(s.AuthenticationMiddleware())
			for _, spec := range specs {
				spec.Pattern = relative(spec, "/api/v1/users")
				register(g, spec)
			}
		})
	}

	// SSH: authentication + tenant enforcement; each route additionally
	// carries the blanket ssh:use permission via the standard decorator.
	if specs := byGroup[GroupSSH]; len(specs) > 0 {
		r.Group(func(g chi.Router) {
			g.Use(s.AuthenticationMiddleware())
			g.Use(s.TenantMiddleware())
			for _, spec := range specs {
				register(g, spec)
			}
		})
	}
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
